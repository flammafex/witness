//! The [`WitnessClient`] HTTP surface and [`PollConfig`] polling semantics.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use reqwest::{Client, RequestBuilder, StatusCode};
use serde::de::{DeserializeOwned, Error as _};
use witness_core::types::{AttestationJobResponse, AttestationJobStatus, CreateAttestationRequest};
use witness_core::{
    ExternalAnchorProof, FreebirdToken, LogConsistencyProof, LogInclusionProofResponse,
    MerkleProofResponse, NetworkConfig, NetworkConfigPublic, ProofBundle, SignedAttestation,
    SignedTreeHead, VerifyRequest, VerifyResponse,
};

use crate::error::{Error, Result};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);
const DEFAULT_POLL_TIMEOUT: Duration = Duration::from_secs(180);

/// Configuration for [`WitnessClient::wait_for_confirmation`].
#[derive(Debug, Clone)]
pub struct PollConfig {
    /// Base polling interval. The effective wait is never below the server's
    /// `next_attempt_at` hint when `respect_next_attempt_at` is set.
    pub interval: Duration,
    /// Overall deadline for confirmation.
    pub timeout: Duration,
    /// Whether to honor the server's `next_attempt_at` hint.
    pub respect_next_attempt_at: bool,
}

impl Default for PollConfig {
    fn default() -> Self {
        Self {
            interval: DEFAULT_POLL_INTERVAL,
            timeout: DEFAULT_POLL_TIMEOUT,
            respect_next_attempt_at: true,
        }
    }
}

/// Builder for [`WitnessClient`] with configurable timeout and user-agent.
pub struct WitnessClientBuilder {
    gateway_url: String,
    timeout: Duration,
    user_agent: Option<String>,
}

impl WitnessClientBuilder {
    /// Set the per-request timeout (default 30s).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the HTTP `User-Agent` header.
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Build the client.
    pub fn build(self) -> Result<WitnessClient> {
        let mut builder = Client::builder().timeout(self.timeout);
        if let Some(ua) = self.user_agent {
            builder = builder.user_agent(ua);
        }
        let client = builder.build()?;
        Ok(WitnessClient {
            client,
            gateway_url: self.gateway_url.trim_end_matches('/').to_string(),
        })
    }
}

/// A typed, keyless client for the Witness gateway.
///
/// Covers the full attestation lifecycle, the transparency-log read surface,
/// optional WebSocket push events, and local verification. The client performs
/// **no** URL filtering — the gateway-side SSRF hardening protects
/// server-initiated traffic, not client endpoint choice.
pub struct WitnessClient {
    client: Client,
    gateway_url: String,
}

impl WitnessClient {
    /// Create a client with a 30s default timeout.
    pub fn new(gateway_url: &str) -> Result<Self> {
        Self::builder(gateway_url).build()
    }

    /// Start building a client with custom timeout / user-agent.
    pub fn builder(gateway_url: &str) -> WitnessClientBuilder {
        WitnessClientBuilder {
            gateway_url: gateway_url.to_string(),
            timeout: DEFAULT_TIMEOUT,
            user_agent: None,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.gateway_url, path)
    }

    fn hash_path(hash: &[u8; 32]) -> String {
        hex::encode(hash)
    }

    /// Classify a non-2xx response. 404 on read endpoints → `NotFound`;
    /// other non-2xx → `Http`.
    async fn check_status(
        &self,
        response: reqwest::Response,
        read: bool,
    ) -> Result<reqwest::Response> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let body = response.text().await.unwrap_or_default();
        if read && status == StatusCode::NOT_FOUND {
            Err(Error::NotFound(body))
        } else {
            Err(Error::Http {
                status: status.as_u16(),
                body,
            })
        }
    }

    async fn send_json<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
        read: bool,
    ) -> Result<T> {
        let response = self.check_status(request.send().await?, read).await?;
        let bytes = response.bytes().await?;
        serde_json::from_slice(&bytes).map_err(Error::Decode)
    }

    // ========================================================================
    // Write path
    // ========================================================================

    /// Submit a hash for attestation. Idempotent: duplicate hashes return the
    /// canonical existing job.
    pub async fn create_attestation(
        &self,
        hash: [u8; 32],
        freebird_token: Option<FreebirdToken>,
    ) -> Result<AttestationJobResponse> {
        let request = CreateAttestationRequest {
            hash: Self::hash_path(&hash),
            freebird_token,
        };
        let req = self
            .client
            .post(self.url("/v1/attestations"))
            .json(&request);
        #[cfg(feature = "tracing")]
        tracing::debug!(hash = %request.hash, "submitting attestation");
        self.send_json(req, false).await
    }

    // ========================================================================
    // Read path
    // ========================================================================

    /// Fetch the canonical attestation job for a hash.
    pub async fn get_attestation(&self, hash: [u8; 32]) -> Result<AttestationJobResponse> {
        let path = format!("/v1/attestations/{}", Self::hash_path(&hash));
        let req = self.client.get(self.url(&path));
        self.send_json(req, true).await
    }

    /// Poll `get_attestation` until the job reaches a terminal state.
    ///
    /// - `confirmed` with a `signed_attestation` → `Ok(signed)`.
    /// - `confirmed` **without** a signed attestation is a protocol violation
    ///   and returns a `Decode` error (never a silent success).
    /// - `failed` → `Error::JobFailed`.
    /// - Timeout → `Error::ConfirmationTimeout` carrying the last status.
    ///
    /// The effective sleep per iteration is `max(poll.interval,
    /// next_attempt_at - now)` when `respect_next_attempt_at` is set, clamped
    /// to the remaining timeout. Dropping the returned future stops polling
    /// (no detached tasks).
    pub async fn wait_for_confirmation(
        &self,
        hash: [u8; 32],
        poll: PollConfig,
    ) -> Result<SignedAttestation> {
        let start = Instant::now();
        let mut last_status = AttestationJobStatus::Pending;

        loop {
            let elapsed = start.elapsed();
            if elapsed >= poll.timeout {
                return Err(Error::ConfirmationTimeout {
                    hash: Self::hash_path(&hash),
                    elapsed,
                    last_status,
                });
            }

            let job = self.get_attestation(hash).await?;
            last_status = job.status;

            match job.status {
                AttestationJobStatus::Confirmed => {
                    return job.signed_attestation.ok_or_else(|| {
                        Error::Decode(serde_json::Error::custom(format!(
                            "job for hash {} reported confirmed without a signed_attestation",
                            Self::hash_path(&hash)
                        )))
                    });
                }
                AttestationJobStatus::Failed => {
                    return Err(Error::JobFailed {
                        hash: Self::hash_path(&hash),
                        attempts: job.attempts,
                        last_error: job.last_error,
                    });
                }
                AttestationJobStatus::Pending | AttestationJobStatus::Retryable => {}
            }

            let remaining = poll.timeout.saturating_sub(elapsed);
            let mut sleep = poll.interval;
            if poll.respect_next_attempt_at {
                if let Some(next) = job.next_attempt_at {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let hint = Duration::from_secs(next.saturating_sub(now));
                    sleep = sleep.max(hint);
                }
            }
            sleep = sleep.min(remaining);
            #[cfg(feature = "tracing")]
            tracing::debug!(hash = %Self::hash_path(&hash), ?sleep, "polling attestation job");
            tokio::time::sleep(sleep).await;
        }
    }

    /// Fetch a self-contained [`ProofBundle`] for a hash.
    pub async fn get_bundle(&self, hash: [u8; 32]) -> Result<ProofBundle> {
        let path = format!("/v1/bundle/{}", Self::hash_path(&hash));
        let req = self.client.get(self.url(&path));
        self.send_json(req, true).await
    }

    /// Fetch a Merkle inclusion proof for a hash.
    pub async fn get_proof(&self, hash: [u8; 32]) -> Result<MerkleProofResponse> {
        let path = format!("/v1/proof/{}", Self::hash_path(&hash));
        let req = self.client.get(self.url(&path));
        self.send_json(req, true).await
    }

    /// Fetch external anchor proofs for a hash.
    ///
    /// An unknown attestation returns `Error::NotFound` (404); a known but
    /// unbatched attestation returns an empty list (200 with `[]`). The SDK
    /// does **not** normalize 404 to empty.
    pub async fn get_anchors(&self, hash: [u8; 32]) -> Result<Vec<ExternalAnchorProof>> {
        let path = format!("/v1/anchors/{}", Self::hash_path(&hash));
        let req = self.client.get(self.url(&path));
        self.send_json(req, true).await
    }

    /// Check gateway health (`{"status":"ok"}`).
    pub async fn health(&self) -> Result<()> {
        let req = self.client.get(self.url("/health"));
        let response = self.check_status(req.send().await?, true).await?;
        let bytes = response.bytes().await?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(Error::Decode)?;
        if value.get("status").and_then(|s| s.as_str()) == Some("ok") {
            Ok(())
        } else {
            Err(Error::Decode(serde_json::Error::custom(
                "unexpected health response",
            )))
        }
    }

    // ========================================================================
    // Config surfaces
    // ========================================================================

    /// Fetch the public config (`GET /v1/config`).
    ///
    /// This is **informational only** (witness count, scheme, threshold). It is
    /// **not** a trust anchor and is insufficient for verification — use
    /// [`WitnessClient::network`] for a full witness pubkey set.
    pub async fn public_config(&self) -> Result<NetworkConfigPublic> {
        let req = self.client.get(self.url("/v1/config"));
        self.send_json(req, true).await
    }

    /// Fetch the full [`NetworkConfig`] (`GET /v1/network`): witness pubkeys,
    /// threshold, scheme, federation peers. Auth tokens are stripped
    /// server-side. This is the trust-anchor fetch.
    pub async fn network(&self) -> Result<NetworkConfig> {
        self.network_from(&self.gateway_url).await
    }

    /// Fetch a [`NetworkConfig`] from an arbitrary gateway URL — used to fetch
    /// peer network configs for cross-anchor (Federated) verification.
    pub async fn network_from(&self, gateway_url: &str) -> Result<NetworkConfig> {
        let url = format!("{}/v1/network", gateway_url.trim_end_matches('/'));
        let req = self.client.get(url);
        self.send_json(req, true).await
    }

    // ========================================================================
    // Transparency log
    // ========================================================================

    /// Latest signed tree head for the gateway's home network.
    pub async fn sth(&self) -> Result<SignedTreeHead> {
        let req = self.client.get(self.url("/v1/log/sth"));
        self.send_json(req, true).await
    }

    /// Look up a historical STH at a specific tree size.
    pub async fn sth_at_size(&self, tree_size: u64) -> Result<SignedTreeHead> {
        let path = format!("/v1/log/sth/{}", tree_size);
        let req = self.client.get(self.url(&path));
        self.send_json(req, true).await
    }

    /// Consistency proof linking two prior STHs (`first ≥ 1`, `first ≤ second`).
    pub async fn consistency(&self, first: u64, second: u64) -> Result<LogConsistencyProof> {
        let path = format!("/v1/log/consistency?first={}&second={}", first, second);
        let req = self.client.get(self.url(&path));
        self.send_json(req, true).await
    }

    /// RFC 9162 inclusion proof for `hash` against the STH at `tree_size`.
    pub async fn log_proof(
        &self,
        hash: [u8; 32],
        tree_size: u64,
    ) -> Result<LogInclusionProofResponse> {
        let path = format!(
            "/v1/log/proof?hash={}&tree_size={}",
            Self::hash_path(&hash),
            tree_size
        );
        let req = self.client.get(self.url(&path));
        self.send_json(req, true).await
    }

    // ========================================================================
    // Push (feature = "ws")
    // ========================================================================

    /// Subscribe to attestation events over WebSocket.
    ///
    /// If a token is supplied, performs the first-message auth handshake
    /// (`{"type":"auth_required"}` → reply `{"token": ...}` within the server's
    /// 5s window). A close code of 4001 indicates an auth failure.
    #[cfg(feature = "ws")]
    pub async fn subscribe_events(
        &self,
        token: Option<String>,
    ) -> Result<impl futures_util::Stream<Item = Result<crate::AttestationEvent>>> {
        crate::ws::subscribe_events(&self.gateway_url, token).await
    }

    // ========================================================================
    // Remote verification (non-authoritative)
    // ========================================================================

    /// Ask the gateway to verify an attestation (`POST /v1/verify`).
    ///
    /// **Non-authoritative**: this is the gateway's opinion. Prefer
    /// [`crate::verify`] for a trust-minimizing verdict.
    pub async fn verify_remote(&self, signed: &SignedAttestation) -> Result<VerifyResponse> {
        let request = VerifyRequest {
            attestation: signed.clone(),
        };
        let req = self.client.post(self.url("/v1/verify")).json(&request);
        self.send_json(req, false).await
    }
}
