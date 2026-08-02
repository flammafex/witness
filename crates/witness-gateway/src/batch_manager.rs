use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use witness_core::{
    log::TreeHead, merkle::merkle_tree_hash, signature_scheme::AttestationSignatures,
    AttestationBatch, MerkleTree, NetworkConfig, SignatureScheme, SignedAttestation,
    SignedTreeHead,
};

use crate::anchor_manager::AnchorManager;
use crate::epoch::epoch_secs;
use crate::federation_client::FederationClient;
use crate::metrics;
use crate::server::collect_signatures_until_threshold;
use crate::storage::Storage;
use crate::traits::WitnessClientTrait;

/// Manages periodic batch closing for federation
pub struct BatchManager {
    config: Arc<NetworkConfig>,
    storage: Arc<Storage>,
    witness_client: Arc<dyn WitnessClientTrait>,
    last_batch_close_time: Arc<tokio::sync::Mutex<u64>>,
    anchor_manager: Option<Arc<AnchorManager>>,
    federation_client: Option<Arc<FederationClient>>,
}

impl BatchManager {
    pub fn new(
        config: Arc<NetworkConfig>,
        storage: Arc<Storage>,
        witness_client: Arc<dyn WitnessClientTrait>,
    ) -> Self {
        let now = epoch_secs();

        Self {
            config,
            storage,
            witness_client,
            last_batch_close_time: Arc::new(tokio::sync::Mutex::new(now)),
            anchor_manager: None,
            federation_client: None,
        }
    }

    /// Set the anchor manager (must be called before start)
    pub fn with_anchor_manager(mut self, anchor_manager: Arc<AnchorManager>) -> Self {
        self.anchor_manager = Some(anchor_manager);
        self
    }

    /// Set the federation client for cross-anchoring (must be called before start)
    pub fn with_federation_client(mut self, federation_client: Arc<FederationClient>) -> Self {
        self.federation_client = Some(federation_client);
        self
    }

    /// Start the batch manager background task
    pub fn start(self: Arc<Self>) {
        let batch_period = self.config.federation.batch_period;

        if !self.config.federation.enabled || batch_period == 0 {
            tracing::info!("Batch manager disabled (federation not enabled)");
            return;
        }

        tracing::info!(
            "Starting batch manager with period: {} seconds",
            batch_period
        );

        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(batch_period));

            loop {
                interval.tick().await;

                if let Err(e) = self.close_batch().await {
                    tracing::error!("Failed to close batch: {}", e);
                }
            }
        });
    }

    /// Close the current batch and create a new one
    async fn close_batch(&self) -> anyhow::Result<Option<AttestationBatch>> {
        let mut last_batch_close_time = self.last_batch_close_time.lock().await;
        let now = epoch_secs();

        // No timestamp watermark is used: jobs that confirm after a long retry
        // remain eligible even when their persisted timestamp predates prior
        // batches. Storage returns deterministic `(sequence, hash)` order.
        let candidates = self
            .storage
            .get_unbatched_attestations(&self.config.id)
            .await?;
        let attestations: Vec<_> = candidates
            .into_iter()
            .filter(|attestation| {
                match witness_core::verify_signed_attestation(attestation, &self.config) {
                    Ok(_) => true,
                    Err(error) => {
                        tracing::error!(
                            hash = %hex::encode(attestation.attestation.hash),
                            "Skipping invalid confirmed batch candidate: {error}"
                        );
                        false
                    }
                }
            })
            .collect();

        if attestations.is_empty() {
            tracing::debug!("No attestations to batch");
            return Ok(None);
        }

        tracing::info!(
            "Closing batch with {} attestations (period: {} - {})",
            attestations.len(),
            *last_batch_close_time,
            now
        );

        // Build merkle tree from attestation hashes
        let leaves: Vec<[u8; 32]> = attestations.iter().map(|a| a.attestation.hash).collect();

        let merkle_tree = MerkleTree::new(leaves.clone());
        let merkle_root = merkle_tree.root();

        // Create batch
        let batch = AttestationBatch {
            id: 0, // Will be set by database
            network_id: self.config.id.clone(),
            merkle_root,
            period_start: *last_batch_close_time,
            period_end: now,
            attestation_count: attestations.len() as u64,
        };

        // Store batch
        let batch_id = self.storage.store_batch(&batch, &leaves).await?;

        // Record metrics
        metrics::record_batch();

        tracing::info!(
            "Batch {} created: {} attestations, root: {}",
            batch_id,
            attestations.len(),
            hex::encode(merkle_root)
        );

        // Update period metadata; candidate eligibility is independent of it.
        *last_batch_close_time = now;

        let final_batch = AttestationBatch {
            id: batch_id as u64,
            ..batch
        };

        // RFC 9162: produce a Signed Tree Head over the entire log up to and
        // including this batch.  The STH is a synthetic Attestation signed
        // by the same witness threshold, so failures here log loudly but do
        // not roll back the batch — clients can still verify per-batch
        // proofs without an STH, and the next batch closure will catch up.
        if let Err(e) = self.sign_and_store_sth(batch_id, now).await {
            tracing::error!("Failed to produce STH for batch {}: {}", batch_id, e);
        }

        // Trigger external anchoring if enabled
        if let Some(anchor_manager) = &self.anchor_manager {
            anchor_manager
                .clone()
                .anchor_batch_async(final_batch.clone());
        }

        // Trigger federation cross-anchoring if enabled
        if let Some(federation_client) = &self.federation_client {
            let fc = federation_client.clone();
            let batch = final_batch.clone();
            tokio::spawn(async move {
                if let Err(e) = fc.cross_anchor_batch(&batch).await {
                    tracing::error!("Cross-anchor failed for batch {}: {}", batch.id, e);
                }
            });
        }

        Ok(Some(final_batch))
    }

    /// Compute the global RFC 9162 Merkle Tree Hash over every closed-batch
    /// leaf in append order, build a [`TreeHead`], collect a witness
    /// threshold of signatures over its digest, and persist the resulting
    /// [`SignedTreeHead`].
    async fn sign_and_store_sth(&self, batch_id: i64, timestamp: u64) -> anyhow::Result<()> {
        let leaves = self.storage.get_log_leaves(&self.config.id).await?;
        if leaves.is_empty() {
            return Ok(());
        }

        let tree_head = TreeHead {
            network_id: self.config.id.clone(),
            tree_size: leaves.len() as u64,
            timestamp,
            root_hash: merkle_tree_hash(&leaves),
        };
        let attestation = tree_head.to_attestation();

        let responses = collect_signatures_until_threshold(
            &self.config.witnesses,
            &attestation,
            &self.witness_client,
            self.config.threshold,
        )
        .await;

        if responses.len() < self.config.threshold {
            anyhow::bail!(
                "STH signing got {} of {} required signatures",
                responses.len(),
                self.config.threshold
            );
        }

        let signed_attestation = match self.config.signature_scheme {
            SignatureScheme::Ed25519 => {
                let mut signed = SignedAttestation::new(attestation.clone());
                for r in responses {
                    signed.add_signature(r.witness_id, r.signature);
                }
                signed
            }
            SignatureScheme::BLS => {
                let signer_ids: Vec<String> =
                    responses.iter().map(|r| r.witness_id.clone()).collect();
                let sigs: Vec<Vec<u8>> = responses.into_iter().map(|r| r.signature).collect();
                let aggregated = witness_core::aggregate_signatures_bls(&sigs)?;
                SignedAttestation {
                    attestation: attestation.clone(),
                    signatures: AttestationSignatures::Aggregated {
                        signature: aggregated,
                        signers: signer_ids,
                    },
                }
            }
        };

        // Defence in depth: refuse to persist an STH whose signatures don't
        // pass the same verifier clients will use.
        witness_core::verify_signed_attestation(&signed_attestation, &self.config)?;

        let sth = SignedTreeHead {
            tree_head,
            signed_attestation,
        };
        self.storage.store_sth(&sth, batch_id).await?;

        tracing::info!(
            "STH issued: tree_size={} root={}",
            sth.tree_head.tree_size,
            hex::encode(sth.tree_head.root_hash)
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use blst::min_sig::SecretKey as BlsSecretKey;
    use ed25519_dalek::SigningKey;
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Mutex;
    use witness_core::{
        encode_public_key, generate_keypair, sign_attestation, Attestation, SignResponse,
        WitnessInfo, WitnessSignature,
    };

    /// Per-witness response script for the [`MockWitnessClient`]. Mirrors the
    /// `reconciler` tests: real signatures for the configured scheme, garbage
    /// bytes, or a hard error.
    #[derive(Clone)]
    enum Action {
        Valid(Arc<SigningKey>),
        BlsValid(Arc<BlsSecretKey>),
        Invalid,
        Error,
    }

    /// Deterministic [`WitnessClientTrait`] fake. A witness with no queued
    /// action (or an exhausted queue) fails the request, matching the
    /// fail-closed behavior of the real client. `calls` counts every
    /// `request_signature` invocation regardless of outcome.
    struct MockWitnessClient {
        actions: Mutex<HashMap<String, VecDeque<Action>>>,
        calls: AtomicUsize,
    }

    impl MockWitnessClient {
        fn new(actions: HashMap<String, VecDeque<Action>>) -> Self {
            Self {
                actions: Mutex::new(actions),
                calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl WitnessClientTrait for MockWitnessClient {
        async fn request_signature(
            &self,
            witness: &WitnessInfo,
            attestation: &Attestation,
        ) -> anyhow::Result<SignResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let action = self
                .actions
                .lock()
                .await
                .get_mut(&witness.id)
                .and_then(VecDeque::pop_front)
                .unwrap_or(Action::Error);
            match action {
                Action::Valid(key) => Ok(SignResponse {
                    witness_id: witness.id.clone(),
                    signature: sign_attestation(attestation, &key),
                }),
                Action::BlsValid(key) => Ok(SignResponse {
                    witness_id: witness.id.clone(),
                    signature: witness_core::sign_attestation_bls(attestation, &key),
                }),
                Action::Invalid => Ok(SignResponse {
                    witness_id: witness.id.clone(),
                    signature: vec![0; 64],
                }),
                Action::Error => anyhow::bail!("mock witness unavailable"),
            }
        }
    }

    fn ed25519_config(keys: &[SigningKey], threshold: usize) -> Arc<NetworkConfig> {
        let witnesses = keys
            .iter()
            .enumerate()
            .map(|(index, key)| WitnessInfo {
                id: format!("w{}", index + 1),
                pubkey: encode_public_key(&key.verifying_key()),
                endpoint: format!("http://w{}.local", index + 1),
                auth_token: Some("token".to_string()),
            })
            .collect();
        Arc::new(NetworkConfig {
            id: "network".to_string(),
            witnesses,
            threshold,
            signature_scheme: SignatureScheme::Ed25519,
            federation: Default::default(),
            external_anchors: Default::default(),
            federation_peers: vec![],
        })
    }

    fn bls_config(keys: &[BlsSecretKey], threshold: usize) -> Arc<NetworkConfig> {
        let witnesses = keys
            .iter()
            .enumerate()
            .map(|(index, key)| WitnessInfo {
                id: format!("w{}", index + 1),
                pubkey: witness_core::encode_bls_public_key(&key.sk_to_pk()),
                endpoint: format!("http://w{}.local", index + 1),
                auth_token: Some("token".to_string()),
            })
            .collect();
        Arc::new(NetworkConfig {
            id: "network".to_string(),
            witnesses,
            threshold,
            signature_scheme: SignatureScheme::BLS,
            federation: Default::default(),
            external_anchors: Default::default(),
            federation_peers: vec![],
        })
    }

    /// Create a fresh in-memory storage, seed `leaves` as confirmed,
    /// unbatched attestations, close them into one batch, and return the
    /// storage plus the batch id. Uses the same fixture writer as the
    /// storage unit tests (`store_attestation` is test-only).
    async fn storage_with_log(config: &NetworkConfig, leaves: &[[u8; 32]]) -> (Arc<Storage>, i64) {
        let storage = Arc::new(Storage::new("sqlite::memory:").await.unwrap());
        storage.migrate().await.unwrap();

        for (index, leaf) in leaves.iter().enumerate() {
            let attestation = Attestation {
                hash: *leaf,
                timestamp: 1,
                network_id: config.id.clone(),
                sequence: index as u64 + 1,
            };
            let signed = SignedAttestation {
                attestation,
                signatures: AttestationSignatures::MultiSig {
                    signatures: vec![WitnessSignature {
                        witness_id: "w1".to_string(),
                        signature: vec![0u8; 64],
                    }],
                },
            };
            storage
                .store_attestation(&signed, Some("confirmed"))
                .await
                .unwrap();
        }

        let batch = AttestationBatch {
            id: 0,
            network_id: config.id.clone(),
            merkle_root: MerkleTree::new(leaves.to_vec()).root(),
            period_start: 1,
            period_end: 2,
            attestation_count: leaves.len() as u64,
        };
        let batch_id = storage.store_batch(&batch, leaves).await.unwrap();
        (storage, batch_id)
    }

    #[tokio::test]
    async fn ed25519_sth_is_signed_and_persisted_when_threshold_met() {
        let (key1, _) = generate_keypair();
        let (key2, _) = generate_keypair();
        let (key3, _) = generate_keypair();
        let config = ed25519_config(&[key1.clone(), key2.clone(), key3.clone()], 3);
        let leaves = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let (storage, batch_id) = storage_with_log(&config, &leaves).await;

        let client = Arc::new(MockWitnessClient::new(HashMap::from([
            (
                "w1".to_string(),
                VecDeque::from([Action::Valid(Arc::new(key1))]),
            ),
            (
                "w2".to_string(),
                VecDeque::from([Action::Valid(Arc::new(key2))]),
            ),
            (
                "w3".to_string(),
                VecDeque::from([Action::Valid(Arc::new(key3))]),
            ),
        ])));
        let bm = BatchManager::new(config.clone(), storage.clone(), client);

        bm.sign_and_store_sth(batch_id, 12345).await.unwrap();

        let sth = storage
            .get_latest_sth(&config.id)
            .await
            .unwrap()
            .expect("STH should be persisted");
        assert_eq!(sth.tree_head.tree_size, leaves.len() as u64);
        assert_eq!(sth.tree_head.root_hash, merkle_tree_hash(&leaves));
        assert_eq!(sth.tree_head.timestamp, 12345);
        assert!(
            witness_core::verify_signed_attestation(&sth.signed_attestation, &config).is_ok(),
            "persisted Ed25519 STH must pass the client-facing verifier"
        );
    }

    #[tokio::test]
    async fn bls_sth_is_signed_and_persisted_when_threshold_met() {
        let (key1, _) = witness_core::generate_bls_keypair();
        let (key2, _) = witness_core::generate_bls_keypair();
        let (key3, _) = witness_core::generate_bls_keypair();
        let config = bls_config(&[key1.clone(), key2.clone(), key3.clone()], 3);
        let leaves = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let (storage, batch_id) = storage_with_log(&config, &leaves).await;

        let client = Arc::new(MockWitnessClient::new(HashMap::from([
            (
                "w1".to_string(),
                VecDeque::from([Action::BlsValid(Arc::new(key1))]),
            ),
            (
                "w2".to_string(),
                VecDeque::from([Action::BlsValid(Arc::new(key2))]),
            ),
            (
                "w3".to_string(),
                VecDeque::from([Action::BlsValid(Arc::new(key3))]),
            ),
        ])));
        let bm = BatchManager::new(config.clone(), storage.clone(), client);

        bm.sign_and_store_sth(batch_id, 12345).await.unwrap();

        let sth = storage
            .get_latest_sth(&config.id)
            .await
            .unwrap()
            .expect("STH should be persisted");
        assert!(sth.signed_attestation.is_aggregated());
        assert_eq!(sth.tree_head.tree_size, leaves.len() as u64);
        assert_eq!(sth.tree_head.root_hash, merkle_tree_hash(&leaves));
        assert_eq!(sth.tree_head.timestamp, 12345);
        assert!(
            witness_core::verify_signed_attestation(&sth.signed_attestation, &config).is_ok(),
            "persisted BLS STH must pass the client-facing verifier"
        );
    }

    #[tokio::test]
    async fn sth_signing_fails_and_persists_nothing_when_threshold_not_met() {
        let (key1, _) = generate_keypair();
        let (key2, _) = generate_keypair();
        let (key3, _) = generate_keypair();
        let config = ed25519_config(&[key1.clone(), key2.clone(), key3.clone()], 3);
        let leaves = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let (storage, batch_id) = storage_with_log(&config, &leaves).await;

        // Only one of three witnesses returns a valid signature.
        let client = Arc::new(MockWitnessClient::new(HashMap::from([
            (
                "w1".to_string(),
                VecDeque::from([Action::Valid(Arc::new(key1))]),
            ),
            ("w2".to_string(), VecDeque::from([Action::Error])),
            ("w3".to_string(), VecDeque::from([Action::Error])),
        ])));
        let bm = BatchManager::new(config.clone(), storage.clone(), client);

        assert!(bm.sign_and_store_sth(batch_id, 12345).await.is_err());
        assert!(
            storage.get_latest_sth(&config.id).await.unwrap().is_none(),
            "no STH may be persisted below threshold"
        );
    }

    #[tokio::test]
    async fn sth_signing_rejects_garbage_signatures_and_persists_nothing() {
        let (key1, _) = generate_keypair();
        let (key2, _) = generate_keypair();
        let (key3, _) = generate_keypair();
        let config = ed25519_config(&[key1.clone(), key2.clone(), key3.clone()], 3);
        let leaves = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let (storage, batch_id) = storage_with_log(&config, &leaves).await;

        // All witnesses "succeed" but return non-signature garbage; the
        // defense-in-depth verification in sign_and_store_sth must reject it.
        let client = Arc::new(MockWitnessClient::new(HashMap::from([
            ("w1".to_string(), VecDeque::from([Action::Invalid])),
            ("w2".to_string(), VecDeque::from([Action::Invalid])),
            ("w3".to_string(), VecDeque::from([Action::Invalid])),
        ])));
        let bm = BatchManager::new(config.clone(), storage.clone(), client);

        assert!(bm.sign_and_store_sth(batch_id, 12345).await.is_err());
        assert!(
            storage.get_latest_sth(&config.id).await.unwrap().is_none(),
            "no STH may be persisted with unverifiable signatures"
        );
    }

    #[tokio::test]
    async fn empty_log_short_circuits_without_calling_witnesses() {
        let (key1, _) = generate_keypair();
        let config = ed25519_config(&[key1], 1);
        let storage = Arc::new(Storage::new("sqlite::memory:").await.unwrap());
        storage.migrate().await.unwrap();

        let client = Arc::new(MockWitnessClient::new(HashMap::new()));
        let bm = BatchManager::new(config.clone(), storage.clone(), client.clone());

        // No batch/leaves exist; the empty-log shortcut must return Ok without
        // ever reaching a witness.
        bm.sign_and_store_sth(1, 12345).await.unwrap();
        assert_eq!(client.calls.load(Ordering::SeqCst), 0);
        assert!(storage.get_latest_sth(&config.id).await.unwrap().is_none());
    }
}
