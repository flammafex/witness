//! Persistent auditor state.
//!
//! The auditor's whole job is to remember what it has seen across restarts —
//! without persistence, an attacker could delete an STH from the gateway
//! between audit runs and we'd never notice.  Two tables:
//!
//! - `audited_sths` — every successfully-verified STH, keyed by
//!   `(gateway_url, tree_size)`.  Used to find the last-known size to ask
//!   for a consistency proof against on the next tick.
//! - `audit_failures` — append-only failure log so anomalies are visible
//!   even after the gateway is "fixed" or comes back online.

use anyhow::{Context, Result};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqliteSynchronous},
    Row,
};
use std::str::FromStr;
use witness_core::{SignedAttestation, SignedTreeHead, TreeHead};

/// Why an audit run failed.  Stored as a string so adding new variants is
/// not a schema migration.
#[derive(Debug, Clone, Copy)]
pub enum FailureType {
    /// Could not reach the gateway / parse its response.
    Fetch,
    /// STH signature did not verify against the network config.
    SthSignature,
    /// Consistency proof did not link the previous STH to the new one.
    Consistency,
    /// New STH had `tree_size < last_known` — the operator rolled back.
    TreeSizeRegression,
    /// New STH at the same tree_size has a different root hash.
    RootMismatch,
}

impl FailureType {
    pub fn as_str(&self) -> &'static str {
        match self {
            FailureType::Fetch => "fetch",
            FailureType::SthSignature => "sth_signature",
            FailureType::Consistency => "consistency",
            FailureType::TreeSizeRegression => "tree_size_regression",
            FailureType::RootMismatch => "root_mismatch",
        }
    }
}

#[derive(Clone)]
pub struct Storage {
    pool: SqlitePool,
}

impl Storage {
    pub async fn new(database_url: &str) -> Result<Self> {
        let opts = SqliteConnectOptions::from_str(database_url)?
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .create_if_missing(true);
        let pool = SqlitePool::connect_with(opts).await?;
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|e| anyhow::anyhow!("auditor migration failed: {}", e))?;
        Ok(())
    }

    /// Persist a verified STH for `gateway_url`.  Returning `Ok(())` is the
    /// auditor's positive ack: this STH happened, this is the chain we're
    /// committing to.
    pub async fn record_sth(&self, gateway_url: &str, sth: &SignedTreeHead) -> Result<()> {
        let signed_json = serde_json::to_string(&sth.signed_attestation)
            .context("serializing signed attestation")?;
        let now = unix_now() as i64;

        sqlx::query(
            r#"
            INSERT OR IGNORE INTO audited_sths (
                gateway_url, network_id, tree_size, timestamp,
                root_hash, signed_attestation_json, audited_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
        )
        .bind(gateway_url)
        .bind(&sth.tree_head.network_id)
        .bind(sth.tree_head.tree_size as i64)
        .bind(sth.tree_head.timestamp as i64)
        .bind(&sth.tree_head.root_hash[..])
        .bind(&signed_json)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Most-recent STH this auditor has accepted for `gateway_url`, or
    /// `None` if this is a fresh gateway.
    pub async fn latest_sth(&self, gateway_url: &str) -> Result<Option<SignedTreeHead>> {
        let row = sqlx::query(
            r#"
            SELECT network_id, tree_size, timestamp, root_hash, signed_attestation_json
            FROM audited_sths
            WHERE gateway_url = ?1
            ORDER BY tree_size DESC
            LIMIT 1
            "#,
        )
        .bind(gateway_url)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        Self::row_to_sth(row).map(Some)
    }

    /// STH at exactly `tree_size`, used to spot a root-hash mismatch when a
    /// gateway re-issues an STH for a tree size we already accepted.
    pub async fn sth_at(
        &self,
        gateway_url: &str,
        tree_size: u64,
    ) -> Result<Option<SignedTreeHead>> {
        let row = sqlx::query(
            r#"
            SELECT network_id, tree_size, timestamp, root_hash, signed_attestation_json
            FROM audited_sths
            WHERE gateway_url = ?1 AND tree_size = ?2
            "#,
        )
        .bind(gateway_url)
        .bind(tree_size as i64)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };
        Self::row_to_sth(row).map(Some)
    }

    pub async fn record_failure(
        &self,
        gateway_url: &str,
        failure_type: FailureType,
        tree_size: Option<u64>,
        detail: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO audit_failures (gateway_url, failure_type, tree_size, detected_at, detail)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
        )
        .bind(gateway_url)
        .bind(failure_type.as_str())
        .bind(tree_size.map(|s| s as i64))
        .bind(unix_now() as i64)
        .bind(detail)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Last `limit` STHs across all gateways, newest first.  Used by
    /// `witness-auditor history` for a quick look at chain progress.
    pub async fn recent_sths(&self, limit: usize) -> Result<Vec<(String, SignedTreeHead, u64)>> {
        let rows = sqlx::query(
            r#"
            SELECT gateway_url, network_id, tree_size, timestamp,
                   root_hash, signed_attestation_json, audited_at
            FROM audited_sths
            ORDER BY audited_at DESC
            LIMIT ?1
            "#,
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let gateway_url: String = row.get("gateway_url");
            let audited_at: i64 = row.get("audited_at");
            let sth = Self::row_to_sth(row)?;
            out.push((gateway_url, sth, audited_at as u64));
        }
        Ok(out)
    }

    /// Last `limit` failures across all gateways, newest first.
    pub async fn recent_failures(&self, limit: usize) -> Result<Vec<RecordedFailure>> {
        let rows = sqlx::query(
            r#"
            SELECT gateway_url, failure_type, tree_size, detected_at, detail
            FROM audit_failures
            ORDER BY detected_at DESC
            LIMIT ?1
            "#,
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| RecordedFailure {
                gateway_url: row.get("gateway_url"),
                failure_type: row.get("failure_type"),
                tree_size: row.get::<Option<i64>, _>("tree_size").map(|s| s as u64),
                detected_at: row.get::<i64, _>("detected_at") as u64,
                detail: row.get("detail"),
            })
            .collect())
    }

    fn row_to_sth(row: sqlx::sqlite::SqliteRow) -> Result<SignedTreeHead> {
        let network_id: String = row.get("network_id");
        let tree_size: i64 = row.get("tree_size");
        let timestamp: i64 = row.get("timestamp");
        let root_vec: Vec<u8> = row.get("root_hash");
        let root_hash: [u8; 32] = root_vec
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid root_hash length"))?;
        let signed_json: String = row.get("signed_attestation_json");
        let signed_attestation: SignedAttestation = serde_json::from_str(&signed_json)?;

        Ok(SignedTreeHead {
            tree_head: TreeHead {
                network_id,
                tree_size: tree_size as u64,
                timestamp: timestamp as u64,
                root_hash,
            },
            signed_attestation,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RecordedFailure {
    pub gateway_url: String,
    pub failure_type: String,
    pub tree_size: Option<u64>,
    pub detected_at: u64,
    pub detail: String,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
