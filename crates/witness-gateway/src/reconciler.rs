use anyhow::{Context, Result};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use witness_core::{
    signature_scheme::AttestationSignatures, Attestation, NetworkConfig, SignResponse,
    SignatureScheme, SignedAttestation, WitnessSignature,
};

use crate::epoch::epoch_secs;
use crate::storage::{JobClaim, Storage};
use crate::traits::WitnessClientTrait;

const DEFAULT_LEASE_SECS: u64 = 30;
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_IDLE_INTERVAL: Duration = Duration::from_secs(1);

pub trait JobClock: Send + Sync {
    fn now(&self) -> u64;
}

#[derive(Default)]
pub struct SystemJobClock;

impl JobClock for SystemJobClock {
    fn now(&self) -> u64 {
        epoch_secs()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    Idle,
    Confirmed,
    RetryScheduled,
    Failed,
    LeaseLost,
}

/// Leased attestation worker. Witness networking is performed only after
/// `claim_job` has committed, and finalization uses a fresh clock reading.
pub struct AttestationWorker {
    config: Arc<NetworkConfig>,
    storage: Arc<Storage>,
    witness_client: Arc<dyn WitnessClientTrait>,
    clock: Arc<dyn JobClock>,
    lease_secs: u64,
    request_timeout: Duration,
}

impl AttestationWorker {
    pub fn new(
        config: Arc<NetworkConfig>,
        storage: Arc<Storage>,
        witness_client: Arc<dyn WitnessClientTrait>,
    ) -> Self {
        Self {
            config,
            storage,
            witness_client,
            clock: Arc::new(SystemJobClock),
            lease_secs: DEFAULT_LEASE_SECS,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }

    pub fn with_clock(mut self, clock: Arc<dyn JobClock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn with_lease_secs(mut self, lease_secs: u64) -> Self {
        self.lease_secs = lease_secs;
        self
    }

    pub fn with_request_timeout(mut self, request_timeout: Duration) -> Self {
        self.request_timeout = request_timeout;
        self
    }

    pub async fn run_once(&self) -> Result<RunOutcome> {
        let now = self.clock.now();
        let Some(claim) = self
            .storage
            .claim_job(&self.config.id, now, self.lease_secs)
            .await?
        else {
            return Ok(RunOutcome::Idle);
        };

        if let Err(error) = self.validate_claim(&claim) {
            let failed = self
                .storage
                .fail_job(
                    &claim.attestation.hash,
                    &claim.lease_token,
                    self.clock.now(),
                    &format!("configuration invariant: {error}"),
                )
                .await?;
            return Ok(if failed {
                RunOutcome::Failed
            } else {
                RunOutcome::LeaseLost
            });
        }

        match self.collect_verified_result(&claim.attestation).await {
            Ok(signed) => {
                let verification_config = self
                    .config
                    .verification_config()
                    .context("invalid verification configuration")?;
                let verification =
                    witness_core::verify_signed_attestation(&signed, &verification_config)
                        .context("final threshold verification failed")
                        .and_then(|verified| {
                            if verified < self.config.threshold {
                                anyhow::bail!("final result below configured threshold");
                            }
                            Ok(())
                        });
                if let Err(error) = verification {
                    return self.reschedule_claim(&claim, &error.to_string()).await;
                }

                let completed = self
                    .storage
                    .complete_verified_job(&signed, &claim.lease_token, self.clock.now())
                    .await?;
                if completed {
                    crate::metrics::record_attestation();
                    Ok(RunOutcome::Confirmed)
                } else {
                    Ok(RunOutcome::LeaseLost)
                }
            }
            Err(error) => self.reschedule_claim(&claim, &error.to_string()).await,
        }
    }

    async fn reschedule_claim(&self, claim: &JobClaim, error: &str) -> Result<RunOutcome> {
        let rescheduled = self
            .storage
            .reschedule_job(
                &claim.attestation.hash,
                &claim.lease_token,
                self.clock.now(),
                &format!("transient quorum failure: {error}"),
            )
            .await?;
        Ok(if rescheduled {
            RunOutcome::RetryScheduled
        } else {
            RunOutcome::LeaseLost
        })
    }

    fn validate_claim(&self, claim: &JobClaim) -> Result<()> {
        self.config
            .validate()
            .context("invalid network configuration")?;
        if claim.attestation.network_id != self.config.id {
            anyhow::bail!("persisted tuple belongs to a different network");
        }
        self.attempt_deadline()?;

        let mut witness_ids = HashSet::new();
        let mut witness_keys: HashSet<Vec<u8>> = HashSet::new();
        for witness in &self.config.witnesses {
            if !witness_ids.insert(&witness.id) {
                anyhow::bail!("duplicate witness identifier");
            }
            if witness.auth_token.as_deref().unwrap_or_default().is_empty() {
                anyhow::bail!("missing witness authentication token");
            }
            let canonical_key = match self.config.signature_scheme {
                SignatureScheme::Ed25519 => witness_core::decode_public_key(&witness.pubkey)
                    .context("invalid Ed25519 witness public key")?
                    .to_bytes()
                    .to_vec(),
                SignatureScheme::BLS => witness_core::decode_bls_public_key(&witness.pubkey)
                    .context("invalid BLS witness public key")?
                    .to_bytes()
                    .to_vec(),
            };
            if !witness_keys.insert(canonical_key) {
                anyhow::bail!("duplicate canonical witness public key");
            }
        }
        Ok(())
    }

    fn attempt_deadline(&self) -> Result<Duration> {
        let lease = Duration::from_secs(self.lease_secs);
        let below_lease = lease
            .checked_sub(Duration::from_millis(1))
            .filter(|deadline| !deadline.is_zero())
            .ok_or_else(|| anyhow::anyhow!("lease must exceed one millisecond"))?;
        if self.request_timeout.is_zero() {
            anyhow::bail!("attempt deadline must be nonzero");
        }
        Ok(self.request_timeout.min(below_lease))
    }

    async fn collect_verified_result(
        &self,
        attestation: &Attestation,
    ) -> Result<SignedAttestation> {
        let mut witnesses = self.config.witnesses.clone();
        witnesses.sort_by(|left, right| left.id.cmp(&right.id));
        let mut responses = Vec::with_capacity(self.config.threshold);
        let mut accepted_ids = HashSet::new();
        let mut requests = tokio::task::JoinSet::new();

        for witness in witnesses {
            let client = self.witness_client.clone();
            let request_attestation = attestation.clone();
            requests.spawn(async move {
                let response = client
                    .request_signature(&witness, &request_attestation)
                    .await;
                (witness, response)
            });
        }

        let collection = tokio::time::timeout(self.attempt_deadline()?, async {
            while let Some(result) = requests.join_next().await {
                let Ok((witness, response)) = result else {
                    continue;
                };
                let response = match response {
                    Ok(response) => response,
                    Err(error) => {
                        tracing::warn!(witness = %witness.id, "Witness request failed: {error}");
                        continue;
                    }
                };

                if response.witness_id != witness.id
                    || !accepted_ids.insert(response.witness_id.clone())
                {
                    tracing::warn!(witness = %witness.id, "Rejected mismatched or duplicate witness response");
                    continue;
                }
                if self
                    .verify_individual_response(attestation, &witness, &response)
                    .is_err()
                {
                    tracing::warn!(witness = %witness.id, "Rejected invalid witness signature");
                    continue;
                }

                crate::metrics::record_signatures(&response.witness_id);
                responses.push(response);
                if responses.len() == self.config.threshold {
                    break;
                }
            }
        })
        .await;
        requests.abort_all();
        if collection.is_err() {
            tracing::warn!("Witness collection reached its total attempt deadline");
        }

        if responses.len() < self.config.threshold {
            anyhow::bail!(
                "only {} valid unique signatures; {} required",
                responses.len(),
                self.config.threshold
            );
        }

        responses.sort_by(|left, right| left.witness_id.cmp(&right.witness_id));
        match self.config.signature_scheme {
            SignatureScheme::Ed25519 => Ok(SignedAttestation {
                attestation: attestation.clone(),
                signatures: AttestationSignatures::MultiSig {
                    signatures: responses
                        .into_iter()
                        .map(|response| WitnessSignature {
                            witness_id: response.witness_id,
                            signature: response.signature,
                        })
                        .collect(),
                },
            }),
            SignatureScheme::BLS => {
                let signers = responses
                    .iter()
                    .map(|response| response.witness_id.clone())
                    .collect();
                let signatures = responses
                    .into_iter()
                    .map(|response| response.signature)
                    .collect::<Vec<_>>();
                let aggregate = witness_core::aggregate_signatures_bls(&signatures)
                    .context("BLS aggregation failed")?;
                Ok(SignedAttestation::new_with_aggregated(
                    attestation.clone(),
                    aggregate,
                    signers,
                ))
            }
        }
    }

    fn verify_individual_response(
        &self,
        attestation: &Attestation,
        witness: &witness_core::WitnessInfo,
        response: &SignResponse,
    ) -> Result<()> {
        match self.config.signature_scheme {
            SignatureScheme::Ed25519 => {
                let public_key = witness_core::decode_public_key(&witness.pubkey)?;
                witness_core::verify_signature(attestation, &response.signature, &public_key)?;
            }
            SignatureScheme::BLS => {
                let public_key = witness_core::decode_bls_public_key(&witness.pubkey)?;
                witness_core::verify_signature_bls(attestation, &response.signature, &public_key)?;
            }
        }
        Ok(())
    }
}

pub struct Reconciler {
    worker: AttestationWorker,
    cancel: CancellationToken,
    idle_interval: Duration,
}

impl Reconciler {
    pub fn new(worker: AttestationWorker, cancel: CancellationToken) -> Self {
        Self {
            worker,
            cancel,
            idle_interval: DEFAULT_IDLE_INTERVAL,
        }
    }

    #[cfg(test)]
    fn with_interval(mut self, idle_interval: Duration) -> Self {
        self.idle_interval = idle_interval;
        self
    }

    pub async fn run(self) {
        loop {
            let outcome = tokio::select! {
                biased;
                _ = self.cancel.cancelled() => break,
                outcome = self.worker.run_once() => outcome,
            };

            match outcome {
                Ok(RunOutcome::Idle) => {}
                Ok(outcome) => tracing::debug!(?outcome, "Attestation worker pass completed"),
                Err(error) => tracing::warn!("Attestation worker pass failed: {error}"),
            }

            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => break,
                _ = tokio::time::sleep(self.idle_interval) => {}
            }
        }
        tracing::info!("Attestation worker shutting down gracefully");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use blst::min_sig::SecretKey as BlsSecretKey;
    use ed25519_dalek::SigningKey;
    use std::collections::{HashMap, VecDeque};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use tokio::sync::Mutex;
    use witness_core::{encode_public_key, generate_keypair, sign_attestation, WitnessInfo};

    struct ManualClock(AtomicU64);

    impl ManualClock {
        fn new(now: u64) -> Self {
            Self(AtomicU64::new(now))
        }

        fn set(&self, now: u64) {
            self.0.store(now, Ordering::SeqCst);
        }
    }

    impl JobClock for ManualClock {
        fn now(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn file_test_db(label: &str) -> (String, PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "witness-worker-{label}-{}-{}.sqlite",
            std::process::id(),
            rand::random::<u64>()
        ));
        (format!("sqlite://{}", path.display()), path)
    }

    fn remove_test_db(path: &PathBuf) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    }

    #[derive(Clone)]
    enum Action {
        Valid(Arc<SigningKey>),
        BlsValid(Arc<BlsSecretKey>),
        Invalid,
        Mismatched(Arc<SigningKey>),
        Error,
        Hang,
    }

    struct MockWitnessClient {
        actions: Mutex<HashMap<String, VecDeque<Action>>>,
        signing_bytes: Mutex<Vec<Vec<u8>>>,
        cancelled_requests: Arc<AtomicUsize>,
    }

    struct CancellationGuard(Arc<AtomicUsize>);

    impl Drop for CancellationGuard {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl WitnessClientTrait for MockWitnessClient {
        async fn request_signature(
            &self,
            witness: &WitnessInfo,
            attestation: &Attestation,
        ) -> Result<SignResponse> {
            self.signing_bytes.lock().await.push(attestation.to_bytes());
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
                Action::Mismatched(key) => Ok(SignResponse {
                    witness_id: format!("{}-other", witness.id),
                    signature: sign_attestation(attestation, &key),
                }),
                Action::Error => anyhow::bail!("mock witness unavailable"),
                Action::Hang => {
                    let _guard = CancellationGuard(self.cancelled_requests.clone());
                    std::future::pending::<Result<SignResponse>>().await
                }
            }
        }
    }

    async fn setup_worker(
        action_sets: Vec<Vec<Action>>,
        threshold: usize,
    ) -> (
        Arc<Storage>,
        Arc<ManualClock>,
        Arc<MockWitnessClient>,
        Arc<NetworkConfig>,
    ) {
        let storage = Arc::new(Storage::new("sqlite::memory:").await.unwrap());
        storage.migrate().await.unwrap();
        let mut witnesses = Vec::new();
        let mut actions = HashMap::new();
        for (index, witness_actions) in action_sets.into_iter().enumerate() {
            let id = format!("w{}", index + 1);
            let public_key = witness_actions
                .iter()
                .find_map(|action| match action {
                    Action::Valid(key) | Action::Mismatched(key) => Some(key.verifying_key()),
                    _ => None,
                })
                .unwrap_or_else(|| generate_keypair().1);
            witnesses.push(WitnessInfo {
                id: id.clone(),
                pubkey: encode_public_key(&public_key),
                endpoint: format!("http://{id}"),
                auth_token: Some("token".to_string()),
            });
            actions.insert(id, witness_actions.into());
        }
        let config = Arc::new(NetworkConfig {
            id: "network".to_string(),
            witnesses,
            threshold,
            signature_scheme: SignatureScheme::Ed25519,
            federation: Default::default(),
            external_anchors: Default::default(),
            federation_peers: vec![],
        });
        let clock = Arc::new(ManualClock::new(100));
        let client = Arc::new(MockWitnessClient {
            actions: Mutex::new(actions),
            signing_bytes: Mutex::new(Vec::new()),
            cancelled_requests: Arc::new(AtomicUsize::new(0)),
        });
        (storage, clock, client, config)
    }

    async fn setup_bls_worker(
        action_sets: Vec<Vec<Action>>,
        threshold: usize,
    ) -> (
        Arc<Storage>,
        Arc<ManualClock>,
        Arc<MockWitnessClient>,
        Arc<NetworkConfig>,
    ) {
        let storage = Arc::new(Storage::new("sqlite::memory:").await.unwrap());
        storage.migrate().await.unwrap();
        let mut witnesses = Vec::new();
        let mut actions = HashMap::new();
        for (index, witness_actions) in action_sets.into_iter().enumerate() {
            let id = format!("w{}", index + 1);
            let public_key = witness_actions
                .iter()
                .find_map(|action| match action {
                    Action::BlsValid(key) => Some(key.sk_to_pk()),
                    _ => None,
                })
                .unwrap_or_else(|| witness_core::generate_bls_keypair().1);
            witnesses.push(WitnessInfo {
                id: id.clone(),
                pubkey: witness_core::encode_bls_public_key(&public_key),
                endpoint: format!("http://{id}"),
                auth_token: Some("token".to_string()),
            });
            actions.insert(id, witness_actions.into());
        }
        let config = Arc::new(NetworkConfig {
            id: "network".to_string(),
            witnesses,
            threshold,
            signature_scheme: SignatureScheme::BLS,
            federation: Default::default(),
            external_anchors: Default::default(),
            federation_peers: vec![],
        });
        let clock = Arc::new(ManualClock::new(100));
        let client = Arc::new(MockWitnessClient {
            actions: Mutex::new(actions),
            signing_bytes: Mutex::new(Vec::new()),
            cancelled_requests: Arc::new(AtomicUsize::new(0)),
        });
        (storage, clock, client, config)
    }

    #[tokio::test]
    async fn invalid_responses_retry_then_valid_quorum_confirms_same_tuple() {
        let (key2, _) = generate_keypair();
        let (key3, _) = generate_keypair();
        let (storage, clock, client, config) = setup_worker(
            vec![
                vec![Action::Invalid, Action::Invalid],
                vec![
                    Action::Valid(Arc::new(key2.clone())),
                    Action::Valid(Arc::new(key2)),
                ],
                vec![Action::Error, Action::Valid(Arc::new(key3))],
            ],
            2,
        )
        .await;
        let hash = [1u8; 32];
        let reserved = storage.reserve_job(&hash, "network", 100).await.unwrap();
        let worker = AttestationWorker::new(config, storage.clone(), client.clone())
            .with_clock(clock.clone())
            .with_lease_secs(30)
            .with_request_timeout(Duration::from_millis(50));

        assert_eq!(worker.run_once().await.unwrap(), RunOutcome::RetryScheduled);
        assert!(storage
            .get_job(&hash)
            .await
            .unwrap()
            .unwrap()
            .signed_attestation
            .is_none());
        clock.set(102);
        assert_eq!(worker.run_once().await.unwrap(), RunOutcome::Confirmed);
        let confirmed = storage.get_job(&hash).await.unwrap().unwrap();
        let signed = confirmed.signed_attestation.unwrap();
        match signed.signatures {
            AttestationSignatures::MultiSig { signatures } => assert_eq!(
                signatures
                    .iter()
                    .map(|signature| signature.witness_id.as_str())
                    .collect::<Vec<_>>(),
                vec!["w2", "w3"]
            ),
            _ => panic!("expected Ed25519 signatures"),
        }
        assert_eq!(confirmed.attestation, reserved.job.attestation);

        let bytes = client.signing_bytes.lock().await;
        let canonical_bytes = bytes.first().unwrap();
        assert!(bytes.iter().all(|bytes| bytes == canonical_bytes));
    }

    #[tokio::test]
    async fn pending_job_is_recovered_by_a_new_worker_instance() {
        let (key, _) = generate_keypair();
        let key = Arc::new(key);
        let (storage, clock, first_client, config) =
            setup_worker(vec![vec![Action::Error]], 1).await;
        let mut config = config;
        Arc::make_mut(&mut config).witnesses[0].pubkey = encode_public_key(&key.verifying_key());
        let hash = [2u8; 32];
        storage.reserve_job(&hash, "network", 100).await.unwrap();
        let first = AttestationWorker::new(config.clone(), storage.clone(), first_client)
            .with_clock(clock.clone());
        assert_eq!(first.run_once().await.unwrap(), RunOutcome::RetryScheduled);
        drop(first);

        clock.set(102);
        let second_client = Arc::new(MockWitnessClient {
            actions: Mutex::new(HashMap::from([(
                "w1".to_string(),
                VecDeque::from([Action::Valid(key)]),
            )])),
            signing_bytes: Mutex::new(Vec::new()),
            cancelled_requests: Arc::new(AtomicUsize::new(0)),
        });
        let second =
            AttestationWorker::new(config, storage.clone(), second_client).with_clock(clock);
        assert_eq!(second.run_once().await.unwrap(), RunOutcome::Confirmed);
        assert!(storage
            .get_job(&hash)
            .await
            .unwrap()
            .unwrap()
            .signed_attestation
            .is_some());
    }

    #[tokio::test]
    async fn file_database_recovers_after_close_and_reopen() {
        let (url, path) = file_test_db("reopen");
        let (key, _) = generate_keypair();
        let key = Arc::new(key);
        let (_, clock, first_client, mut config) = setup_worker(vec![vec![Action::Error]], 1).await;
        Arc::make_mut(&mut config).witnesses[0].pubkey = encode_public_key(&key.verifying_key());
        let hash = [9u8; 32];

        {
            let storage = Arc::new(Storage::new(&url).await.unwrap());
            storage.migrate().await.unwrap();
            storage.reserve_job(&hash, "network", 100).await.unwrap();
            let worker = AttestationWorker::new(config.clone(), storage, first_client)
                .with_clock(clock.clone());
            assert_eq!(worker.run_once().await.unwrap(), RunOutcome::RetryScheduled);
        }

        clock.set(102);
        let storage = Arc::new(Storage::new(&url).await.unwrap());
        storage.migrate().await.unwrap();
        let second_client = Arc::new(MockWitnessClient {
            actions: Mutex::new(HashMap::from([(
                "w1".to_string(),
                VecDeque::from([Action::Valid(key)]),
            )])),
            signing_bytes: Mutex::new(Vec::new()),
            cancelled_requests: Arc::new(AtomicUsize::new(0)),
        });
        let worker =
            AttestationWorker::new(config, storage.clone(), second_client).with_clock(clock);
        assert_eq!(worker.run_once().await.unwrap(), RunOutcome::Confirmed);
        assert!(storage
            .get_job(&hash)
            .await
            .unwrap()
            .unwrap()
            .signed_attestation
            .is_some());
        drop(worker);
        drop(storage);
        remove_test_db(&path);
    }

    #[tokio::test]
    async fn cancelling_hanging_attempt_allows_expiry_reclaim_of_same_tuple() {
        let (key, _) = generate_keypair();
        let key = Arc::new(key);
        let (storage, clock, hanging_client, mut config) =
            setup_worker(vec![vec![Action::Hang]], 1).await;
        Arc::make_mut(&mut config).witnesses[0].pubkey = encode_public_key(&key.verifying_key());
        let hash = [10u8; 32];
        let reserved = storage.reserve_job(&hash, "network", 100).await.unwrap();
        let worker =
            AttestationWorker::new(config.clone(), storage.clone(), hanging_client.clone())
                .with_clock(clock.clone())
                .with_lease_secs(2)
                .with_request_timeout(Duration::from_millis(1_500));
        let handle = tokio::spawn(async move { worker.run_once().await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        handle.abort();
        assert!(handle.await.unwrap_err().is_cancelled());
        tokio::task::yield_now().await;
        assert!(hanging_client.cancelled_requests.load(Ordering::SeqCst) > 0);

        clock.set(102);
        let valid_client = Arc::new(MockWitnessClient {
            actions: Mutex::new(HashMap::from([(
                "w1".to_string(),
                VecDeque::from([Action::Valid(key)]),
            )])),
            signing_bytes: Mutex::new(Vec::new()),
            cancelled_requests: Arc::new(AtomicUsize::new(0)),
        });
        let worker = AttestationWorker::new(config, storage.clone(), valid_client)
            .with_clock(clock)
            .with_lease_secs(2);
        assert_eq!(worker.run_once().await.unwrap(), RunOutcome::Confirmed);
        let confirmed = storage.get_job(&hash).await.unwrap().unwrap();
        assert_eq!(confirmed.attestation, reserved.job.attestation);
    }

    #[tokio::test]
    async fn configuration_invariant_is_terminal() {
        let (storage, clock, client, mut config) = setup_worker(vec![vec![Action::Error]], 1).await;
        Arc::make_mut(&mut config).witnesses[0].pubkey = "not-a-public-key".to_string();
        let hash = [3u8; 32];
        storage.reserve_job(&hash, "network", 100).await.unwrap();
        let worker = AttestationWorker::new(config, storage.clone(), client).with_clock(clock);

        assert_eq!(worker.run_once().await.unwrap(), RunOutcome::Failed);
        let job = storage.get_job(&hash).await.unwrap().unwrap();
        assert_eq!(
            job.status,
            witness_core::types::AttestationJobStatus::Failed
        );
        assert!(job.signed_attestation.is_none());
    }

    #[tokio::test]
    async fn many_hanging_witnesses_are_cancelled_after_valid_threshold() {
        let (key1, _) = generate_keypair();
        let (key2, _) = generate_keypair();
        let mut actions = vec![
            vec![Action::Valid(Arc::new(key1))],
            vec![Action::Valid(Arc::new(key2))],
        ];
        actions.extend((0..20).map(|_| vec![Action::Hang]));
        let (storage, clock, client, config) = setup_worker(actions, 2).await;
        storage
            .reserve_job(&[4u8; 32], "network", 100)
            .await
            .unwrap();
        let worker = AttestationWorker::new(config, storage, client.clone())
            .with_clock(clock)
            .with_lease_secs(2)
            .with_request_timeout(Duration::from_millis(500));

        let started = tokio::time::Instant::now();
        assert_eq!(worker.run_once().await.unwrap(), RunOutcome::Confirmed);
        assert!(started.elapsed() < Duration::from_millis(400));
        tokio::task::yield_now().await;
        assert!(client.cancelled_requests.load(Ordering::SeqCst) > 0);
    }

    #[tokio::test]
    async fn canonical_key_dedup_accepts_uppercase_but_rejects_same_key_twice() {
        let (key, public_key) = generate_keypair();
        let (storage, clock, client, mut config) =
            setup_worker(vec![vec![Action::Valid(Arc::new(key.clone()))]], 1).await;
        Arc::make_mut(&mut config).witnesses[0].pubkey =
            encode_public_key(&public_key).to_ascii_uppercase();
        storage
            .reserve_job(&[5u8; 32], "network", 100)
            .await
            .unwrap();
        let worker = AttestationWorker::new(config, storage, client).with_clock(clock);
        assert_eq!(worker.run_once().await.unwrap(), RunOutcome::Confirmed);

        let (storage, clock, client, mut config) = setup_worker(
            vec![
                vec![Action::Valid(Arc::new(key.clone()))],
                vec![Action::Valid(Arc::new(key))],
            ],
            1,
        )
        .await;
        Arc::make_mut(&mut config).witnesses[0].pubkey = encode_public_key(&public_key);
        Arc::make_mut(&mut config).witnesses[1].pubkey =
            encode_public_key(&public_key).to_ascii_uppercase();
        let hash = [6u8; 32];
        storage.reserve_job(&hash, "network", 100).await.unwrap();
        let worker = AttestationWorker::new(config, storage.clone(), client).with_clock(clock);
        assert_eq!(worker.run_once().await.unwrap(), RunOutcome::Failed);
        assert_eq!(
            storage.get_job(&hash).await.unwrap().unwrap().status,
            witness_core::types::AttestationJobStatus::Failed
        );
    }

    #[tokio::test]
    async fn bls_canonical_key_dedup_rejects_alternate_text_encoding() {
        let (key, public_key) = witness_core::generate_bls_keypair();
        let (storage, clock, client, mut config) = setup_bls_worker(
            vec![
                vec![Action::BlsValid(Arc::new(key.clone()))],
                vec![Action::BlsValid(Arc::new(key))],
            ],
            1,
        )
        .await;
        Arc::make_mut(&mut config).witnesses[0].pubkey =
            witness_core::encode_bls_public_key(&public_key);
        Arc::make_mut(&mut config).witnesses[1].pubkey =
            witness_core::encode_bls_public_key(&public_key).to_ascii_uppercase();
        let hash = [11u8; 32];
        storage.reserve_job(&hash, "network", 100).await.unwrap();
        let worker = AttestationWorker::new(config, storage.clone(), client).with_clock(clock);
        assert_eq!(worker.run_once().await.unwrap(), RunOutcome::Failed);
        assert_eq!(
            storage.get_job(&hash).await.unwrap().unwrap().status,
            witness_core::types::AttestationJobStatus::Failed
        );
    }

    #[tokio::test]
    async fn mismatched_returned_witness_id_is_rejected() {
        let (key, _) = generate_keypair();
        let (storage, clock, client, config) =
            setup_worker(vec![vec![Action::Mismatched(Arc::new(key))]], 1).await;
        let hash = [7u8; 32];
        storage.reserve_job(&hash, "network", 100).await.unwrap();
        let worker = AttestationWorker::new(config, storage.clone(), client).with_clock(clock);
        assert_eq!(worker.run_once().await.unwrap(), RunOutcome::RetryScheduled);
        assert!(storage
            .get_job(&hash)
            .await
            .unwrap()
            .unwrap()
            .signed_attestation
            .is_none());
    }

    #[tokio::test]
    async fn bls_individual_and_aggregate_verification_gate_confirmation() {
        let (key2, _) = witness_core::generate_bls_keypair();
        let (key3, _) = witness_core::generate_bls_keypair();
        let (storage, clock, client, config) = setup_bls_worker(
            vec![
                vec![Action::Invalid, Action::Invalid],
                vec![
                    Action::BlsValid(Arc::new(key2.clone())),
                    Action::BlsValid(Arc::new(key2)),
                ],
                vec![Action::Error, Action::BlsValid(Arc::new(key3))],
            ],
            2,
        )
        .await;
        let hash = [8u8; 32];
        storage.reserve_job(&hash, "network", 100).await.unwrap();
        let worker = AttestationWorker::new(config.clone(), storage.clone(), client)
            .with_clock(clock.clone());

        assert_eq!(worker.run_once().await.unwrap(), RunOutcome::RetryScheduled);
        assert!(storage
            .get_job(&hash)
            .await
            .unwrap()
            .unwrap()
            .signed_attestation
            .is_none());
        clock.set(102);
        assert_eq!(worker.run_once().await.unwrap(), RunOutcome::Confirmed);
        let signed = storage
            .get_job(&hash)
            .await
            .unwrap()
            .unwrap()
            .signed_attestation
            .unwrap();
        assert!(signed.is_aggregated());
        assert!(witness_core::verify_signed_attestation(
            &signed,
            &config.verification_config().unwrap()
        )
        .is_ok());
    }

    #[tokio::test]
    async fn reconciler_stops_during_worker_wait() {
        let (key, _) = generate_keypair();
        let (storage, clock, client, mut config) =
            setup_worker(vec![vec![Action::Valid(Arc::new(key.clone()))]], 1).await;
        Arc::make_mut(&mut config).witnesses[0].pubkey = encode_public_key(&key.verifying_key());
        let worker = AttestationWorker::new(config, storage, client).with_clock(clock);
        let cancel = CancellationToken::new();
        let handle = tokio::spawn(
            Reconciler::new(worker, cancel.clone())
                .with_interval(Duration::from_secs(60))
                .run(),
        );
        tokio::task::yield_now().await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap();
    }
}
