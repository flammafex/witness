use serde::{Deserialize, Serialize};
use std::fmt;

/// Core attestation: what gets signed by witnesses
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Attestation {
    /// SHA-256 hash of the content being timestamped
    #[serde(with = "crate::serde_hex::array32")]
    #[schemars(with = "String")]
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub hash: [u8; 32],

    /// Unix timestamp in seconds
    pub timestamp: u64,

    /// Which Witness network this attestation is from
    pub network_id: String,

    /// Monotonic sequence number for ordering
    pub sequence: u64,
}

impl Attestation {
    pub fn new(hash: [u8; 32], network_id: String, sequence: u64) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            hash,
            timestamp,
            network_id,
            sequence,
        }
    }

    /// Get canonical bytes for signing
    ///
    /// Format: hash (32) || timestamp (8 LE) || network_id_len (4 LE) || network_id || sequence (8 LE)
    ///
    /// The length prefix on network_id prevents collisions between attestations
    /// with different network_id/sequence pairs that could otherwise produce
    /// identical byte representations.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 8 + 4 + self.network_id.len() + 8);
        bytes.extend_from_slice(&self.hash);
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(&(self.network_id.len() as u32).to_le_bytes());
        bytes.extend_from_slice(self.network_id.as_bytes());
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes
    }
}

impl fmt::Display for Attestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Attestation(hash={}, ts={}, net={}, seq={})",
            hex::encode(self.hash),
            self.timestamp,
            self.network_id,
            self.sequence
        )
    }
}

/// A single witness's signature on an attestation
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WitnessSignature {
    /// ID of the witness that signed
    pub witness_id: String,

    /// Signature bytes (Ed25519 64 bytes or BLS 48 bytes / 96 lowercase hex
    /// characters, depending on network configuration).
    #[serde(with = "crate::serde_hex::vec")]
    #[schemars(with = "String")]
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub signature: Vec<u8>,
}

/// Complete signed attestation with all witness signatures
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SignedAttestation {
    pub attestation: Attestation,

    /// Signatures (multi-sig or aggregated)
    pub signatures: crate::signature_scheme::AttestationSignatures,
}

impl SignedAttestation {
    /// Create new attestation with Ed25519 multi-sig
    pub fn new(attestation: Attestation) -> Self {
        Self {
            attestation,
            signatures: crate::signature_scheme::AttestationSignatures::new_multisig(),
        }
    }

    /// Create new attestation with BLS aggregated signature
    pub fn new_with_aggregated(
        attestation: Attestation,
        signature: Vec<u8>,
        signers: Vec<String>,
    ) -> Self {
        Self {
            attestation,
            signatures: crate::signature_scheme::AttestationSignatures::new_aggregated(
                signature, signers,
            ),
        }
    }

    /// Add a signature (only works for multi-sig)
    pub fn add_signature(&mut self, witness_id: String, signature: Vec<u8>) {
        self.signatures
            .add_signature_multisig(witness_id, signature);
    }

    /// Get count of signers
    pub fn signature_count(&self) -> usize {
        self.signatures.signer_count()
    }

    /// Check if using aggregated signatures
    pub fn is_aggregated(&self) -> bool {
        self.signatures.is_aggregated()
    }
}

/// Information about a witness node
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WitnessInfo {
    /// Unique identifier for this witness
    pub id: String,

    /// Public key (Ed25519 32 bytes or BLS 96 bytes / 192 lowercase hex
    /// characters, hex encoded).
    pub pubkey: String,

    /// HTTP endpoint for this witness
    pub endpoint: String,

    /// Bearer token used by gateways when calling this witness's signing endpoint.
    /// Never serialized in public API responses.
    #[serde(default, skip_serializing)]
    #[schemars(skip)]
    pub auth_token: Option<String>,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NetworkConfig {
    /// Network identifier
    pub id: String,

    /// List of witnesses in this network
    pub witnesses: Vec<WitnessInfo>,

    /// Minimum number of signatures required
    pub threshold: usize,

    /// Signature scheme (ed25519 or bls)
    #[serde(default)]
    pub signature_scheme: crate::signature_scheme::SignatureScheme,

    /// Federation configuration (Phase 2)
    #[serde(default)]
    pub federation: crate::federation::FederationConfig,

    /// External anchors configuration (Phase 3)
    #[serde(default)]
    pub external_anchors: crate::external_anchors::ExternalAnchorsConfig,

    /// Deprecated: Use federation.peer_networks instead
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub federation_peers: Vec<String>,
}

impl NetworkConfig {
    pub fn validate(&self) -> crate::Result<()> {
        self.verification_config().map(|_| ())
    }

    /// Project the operational configuration into the public trust anchor used
    /// by all offline verification paths.  This projection is intentionally
    /// explicit so endpoints, witness bearer tokens, inbound federation
    /// secrets, and external-anchor provider configuration cannot cross the
    /// verification boundary.
    pub fn verification_config(&self) -> crate::Result<NetworkVerificationConfig> {
        let config = NetworkVerificationConfig {
            id: self.id.clone(),
            witnesses: self
                .witnesses
                .iter()
                .map(|witness| VerificationWitnessInfo {
                    id: witness.id.clone(),
                    pubkey: witness.pubkey.clone(),
                })
                .collect(),
            threshold: self.threshold,
            signature_scheme: self.signature_scheme,
            federation: crate::federation::FederationVerificationConfig {
                enabled: self.federation.enabled,
                peer_networks: self
                    .federation
                    .peer_networks
                    .iter()
                    .map(|peer| crate::federation::PeerNetworkVerificationInfo {
                        id: peer.id.clone(),
                        gateway: peer.gateway.clone(),
                        min_witnesses: peer.min_witnesses,
                    })
                    .collect(),
                cross_anchor_threshold: self.federation.cross_anchor_threshold,
            },
        };
        config.validate()?;
        Ok(config)
    }

    pub fn find_witness(&self, id: &str) -> Option<&WitnessInfo> {
        self.witnesses.iter().find(|w| w.id == id)
    }
}

/// Public witness identity used by a [`NetworkVerificationConfig`].
///
/// Unlike [`WitnessInfo`], this DTO has no endpoint or authentication token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VerificationWitnessInfo {
    /// Unique witness identifier.
    pub id: String,

    /// Public key (Ed25519 32 bytes or BLS 96 bytes / 192 lowercase hex
    /// characters, hex encoded).
    pub pubkey: String,
}

/// Compatibility alias for the public witness verification DTO.
pub type NetworkVerificationWitness = VerificationWitnessInfo;

/// Secret-free trust anchor for verifying attestations, STHs, and proof
/// bundles.  Operator `network.json` files are intentionally accepted as a
/// superset when deserializing this type: unknown operational fields are
/// ignored by serde, allowing offline tools to load existing files without
/// exposing those fields in the verification model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NetworkVerificationConfig {
    /// Network identifier pinned into signed attestations.
    pub id: String,

    /// Witness identities and public keys.
    pub witnesses: Vec<VerificationWitnessInfo>,

    /// Minimum number of witness signatures required.
    pub threshold: usize,

    /// Signature scheme used by this network.
    #[serde(default)]
    pub signature_scheme: crate::signature_scheme::SignatureScheme,

    /// Public federation discovery and policy.
    #[serde(default)]
    pub federation: crate::federation::FederationVerificationConfig,
}

impl NetworkVerificationConfig {
    /// Validate every invariant needed before using this config as a trust
    /// anchor.
    pub fn validate(&self) -> crate::Result<()> {
        if self.id.trim().is_empty() {
            return Err(crate::WitnessError::InvalidVerificationConfig(
                "network id must be nonempty".to_string(),
            ));
        }
        if self.witnesses.is_empty() {
            return Err(crate::WitnessError::InvalidVerificationConfig(
                "at least one witness is required".to_string(),
            ));
        }
        if self.threshold == 0 || self.threshold > self.witnesses.len() {
            return Err(crate::WitnessError::InvalidVerificationConfig(format!(
                "threshold {} must be between 1 and {}",
                self.threshold,
                self.witnesses.len()
            )));
        }

        let mut witness_ids = std::collections::HashSet::new();
        let mut decoded_keys = std::collections::HashSet::new();
        for witness in &self.witnesses {
            if witness.id.trim().is_empty() {
                return Err(crate::WitnessError::InvalidVerificationConfig(
                    "witness id must be nonempty".to_string(),
                ));
            }
            if !witness_ids.insert(witness.id.clone()) {
                return Err(crate::WitnessError::InvalidVerificationConfig(format!(
                    "duplicate witness id '{}'",
                    witness.id
                )));
            }

            let decoded = match self.signature_scheme {
                crate::signature_scheme::SignatureScheme::Ed25519 => {
                    crate::decode_public_key(&witness.pubkey)?
                        .to_bytes()
                        .to_vec()
                }
                crate::signature_scheme::SignatureScheme::BLS => {
                    crate::decode_bls_public_key(&witness.pubkey)?
                        .to_bytes()
                        .to_vec()
                }
            };
            if !decoded_keys.insert(decoded) {
                return Err(crate::WitnessError::InvalidVerificationConfig(format!(
                    "duplicate decoded public key for witness '{}'",
                    witness.id
                )));
            }
        }

        self.federation.validate(&self.id)
    }

    /// Look up a public witness identity by ID.
    pub fn find_witness(&self, id: &str) -> Option<&VerificationWitnessInfo> {
        self.witnesses.iter().find(|witness| witness.id == id)
    }
}

/// Request to timestamp a hash
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TimestampRequest {
    /// SHA-256 hash to timestamp (hex encoded)
    pub hash: String,

    /// Optional Freebird token for Sybil resistance
    #[serde(default)]
    pub freebird_token: Option<FreebirdToken>,
}

/// Request to create or retrieve the canonical attestation job for a hash.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateAttestationRequest {
    /// SHA-256 hash to attest (hex encoded).
    pub hash: String,

    /// Optional Freebird token for Sybil resistance.
    #[serde(default)]
    pub freebird_token: Option<FreebirdToken>,
}

/// Durable lifecycle state of an attestation job.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AttestationJobStatus {
    Pending,
    Retryable,
    Confirmed,
    Failed,
}

/// Stable snapshot returned when creating or reading an attestation job.
///
/// The canonical tuple is always present. `signed_attestation` is present only
/// after the job has reached `confirmed`; pending and failed jobs never expose
/// an unsigned `SignedAttestation` placeholder.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AttestationJobResponse {
    pub attestation: Attestation,
    pub status: AttestationJobStatus,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_attestation: Option<SignedAttestation>,

    /// Number of leases issued for this job.
    pub attempts: u32,

    /// Unix timestamp at which a pending/retryable job is next eligible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Freebird token for anonymous authorization
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FreebirdToken {
    /// Base64url-encoded Freebird redemption token.
    pub token_b64: String,
}

/// Configuration for Freebird integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreebirdConfig {
    /// Freebird verifier URL (e.g., "http://localhost:8082")
    pub verifier_url: Option<String>,

    /// Whether Freebird is required (false = permissive mode for dev)
    #[serde(default)]
    pub required: bool,

    /// Whether to consume tokens on verification (default: true)
    ///
    /// If true, uses /v1/verify which records the nullifier and prevents reuse.
    /// If false, uses /v1/check which validates without consumption.
    /// Non-consuming mode should only be used for explicit proof-of-possession
    /// use cases and requires strict rate limiting.
    #[serde(default = "default_freebird_consume_tokens")]
    pub consume_tokens: bool,

    /// Permit local plaintext Freebird verifier URLs for development smoke tests.
    ///
    /// This must remain false for public deployments.
    #[serde(default)]
    pub allow_insecure_local: bool,
}

fn default_freebird_consume_tokens() -> bool {
    true
}

/// Response from successful timestamp request
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TimestampResponse {
    pub attestation: SignedAttestation,
    #[serde(default = "default_status_confirmed")]
    pub status: String,
}

fn default_status_confirmed() -> String {
    "confirmed".to_string()
}

/// Request to verify an attestation
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VerifyRequest {
    pub attestation: SignedAttestation,
}

/// Response from verification
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VerifyResponse {
    pub valid: bool,
    pub verified_signatures: usize,
    pub required_signatures: usize,
    pub message: String,
}

/// Internal request from gateway to witness for signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub attestation: Attestation,
}

/// Response from witness with signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    pub witness_id: String,
    #[serde(with = "crate::serde_hex::vec")]
    pub signature: Vec<u8>,
}

/// Public-facing subset of [`NetworkConfig`] — excludes internal endpoints,
/// peer URLs, and auth tokens. Returned by `GET /v1/config`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NetworkConfigPublic {
    pub id: String,
    pub threshold: usize,
    pub signature_scheme: crate::signature_scheme::SignatureScheme,
    pub witness_count: usize,
}

/// Event broadcast to WebSocket clients when an attestation is created.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AttestationEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub hash: String,
    pub timestamp: u64,
}

/// Response for a Merkle inclusion proof (`GET /v1/proof/:hash`).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MerkleProofResponse {
    pub hash: String,
    pub proof: Vec<String>,
    pub index: usize,
    pub merkle_root: String,
    pub batch_id: u64,
}

/// RFC 9162 §4.11 inclusion proof response (`GET /v1/log/proof`).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LogInclusionProofResponse {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub audit_path: Vec<String>,
    pub sth: crate::log::SignedTreeHead,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_serialization_roundtrip() {
        let attestation = Attestation {
            hash: [0u8; 32],
            timestamp: 1700000000,
            network_id: "test-network".to_string(),
            sequence: 42,
        };

        // Serialize to JSON
        let json = serde_json::to_string(&attestation).unwrap();
        assert!(json.contains(
            r#""hash":"0000000000000000000000000000000000000000000000000000000000000000""#
        ));

        // Deserialize back
        let deserialized: Attestation = serde_json::from_str(&json).unwrap();

        assert_eq!(attestation, deserialized);
    }

    #[test]
    fn test_attestation_to_bytes_deterministic() {
        let attestation = Attestation {
            hash: [1u8; 32],
            timestamp: 1700000000,
            network_id: "test".to_string(),
            sequence: 1,
        };

        let bytes1 = attestation.to_bytes();
        let bytes2 = attestation.to_bytes();

        assert_eq!(bytes1, bytes2);
        assert!(!bytes1.is_empty());
    }

    #[test]
    fn test_signed_attestation_with_multisig() {
        let attestation = Attestation {
            hash: [2u8; 32],
            timestamp: 1700000000,
            network_id: "test".to_string(),
            sequence: 1,
        };

        let mut signed = SignedAttestation::new(attestation);
        signed.add_signature("witness-1".to_string(), vec![1, 2, 3, 4]);
        signed.add_signature("witness-2".to_string(), vec![5, 6, 7, 8]);

        assert_eq!(signed.signature_count(), 2);
        assert!(!signed.is_aggregated());

        // Serialize and deserialize
        let json = serde_json::to_string(&signed).unwrap();
        assert!(json.contains(r#""signature":"01020304""#));
        let deserialized: SignedAttestation = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.signature_count(), 2);
        assert!(!deserialized.is_aggregated());
    }

    #[test]
    fn test_signed_attestation_with_aggregated() {
        let attestation = Attestation {
            hash: [3u8; 32],
            timestamp: 1700000000,
            network_id: "test".to_string(),
            sequence: 1,
        };

        let signed = SignedAttestation::new_with_aggregated(
            attestation,
            vec![10, 20, 30, 40],
            vec!["witness-1".to_string(), "witness-2".to_string()],
        );

        assert_eq!(signed.signature_count(), 2);
        assert!(signed.is_aggregated());

        // Serialize and deserialize
        let json = serde_json::to_string(&signed).unwrap();
        assert!(json.contains(r#""signature":"0a141e28""#));
        let deserialized: SignedAttestation = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.signature_count(), 2);
        assert!(deserialized.is_aggregated());
    }

    #[test]
    fn test_network_config_validation() {
        let valid_pubkey = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[1u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        // Valid config
        let config = NetworkConfig {
            id: "test".to_string(),
            witnesses: vec![WitnessInfo {
                id: "w1".to_string(),
                pubkey: valid_pubkey.clone(),
                endpoint: "http://localhost:3001".to_string(),
                auth_token: Some("token-1".to_string()),
            }],
            threshold: 1,
            signature_scheme: Default::default(),
            federation: Default::default(),
            external_anchors: Default::default(),
            federation_peers: vec![],
        };

        assert!(config.validate().is_ok());

        // Empty witnesses
        let bad_config = NetworkConfig {
            id: "test".to_string(),
            witnesses: vec![],
            threshold: 1,
            signature_scheme: Default::default(),
            federation: Default::default(),
            external_anchors: Default::default(),
            federation_peers: vec![],
        };

        assert!(bad_config.validate().is_err());

        // Threshold too high
        let bad_threshold = NetworkConfig {
            id: "test".to_string(),
            witnesses: vec![WitnessInfo {
                id: "w1".to_string(),
                pubkey: valid_pubkey,
                endpoint: "http://localhost:3001".to_string(),
                auth_token: Some("token-1".to_string()),
            }],
            threshold: 5, // Only 1 witness
            signature_scheme: Default::default(),
            federation: Default::default(),
            external_anchors: Default::default(),
            federation_peers: vec![],
        };

        assert!(bad_threshold.validate().is_err());
    }

    #[test]
    fn verification_config_projects_only_public_fields() {
        let mut config = sample_config_with_tokens();
        config.witnesses[0].pubkey = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[2u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        config.witnesses[1].pubkey = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[3u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        config
            .federation
            .peer_networks
            .push(crate::federation::PeerNetworkInfo {
                id: "peer".to_string(),
                gateway: "https://peer.example".to_string(),
                min_witnesses: 1,
                auth_token: Some("peer-secret".to_string()),
            });
        config.federation.inbound_auth_token = Some("inbound-secret".to_string());
        config.external_anchors.enabled = true;
        config
            .external_anchors
            .providers
            .push(crate::external_anchors::AnchorProviderConfig {
                provider_type: crate::external_anchors::AnchorProviderType::Trillian,
                enabled: true,
                priority: 1,
                config: serde_json::json!({"api_key": "provider-secret"}),
            });

        let projected = config.verification_config().unwrap();
        let json = serde_json::to_string(&projected).unwrap();
        assert!(!json.contains("endpoint"));
        assert!(!json.contains("auth_token"));
        assert!(!json.contains("inbound-secret"));
        assert!(!json.contains("provider-secret"));
        assert!(json.contains("peer.example"));
        assert!(serde_json::from_str::<NetworkVerificationConfig>(&json).is_ok());

        // Existing operator files are accepted as a superset for offline use;
        // their operational fields are ignored by the verification DTO.
        let operator_json = serde_json::to_string(&config).unwrap();
        let parsed_operator: NetworkVerificationConfig =
            serde_json::from_str(&operator_json).unwrap();
        assert_eq!(parsed_operator.id, config.id);
        assert_eq!(parsed_operator.witnesses.len(), config.witnesses.len());
    }

    #[test]
    fn verification_config_rejects_invalid_invariants() {
        let key_a = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[4u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        let key_b = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[5u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        let base = NetworkVerificationConfig {
            id: "net".to_string(),
            witnesses: vec![
                VerificationWitnessInfo {
                    id: "w1".to_string(),
                    pubkey: key_a.clone(),
                },
                VerificationWitnessInfo {
                    id: "w2".to_string(),
                    pubkey: key_b,
                },
            ],
            threshold: 1,
            signature_scheme: crate::SignatureScheme::Ed25519,
            federation: Default::default(),
        };
        assert!(base.validate().is_ok());

        for threshold in [0, 3] {
            let invalid = NetworkVerificationConfig {
                threshold,
                ..base.clone()
            };
            assert!(invalid.validate().is_err());
        }

        let duplicate_id = NetworkVerificationConfig {
            witnesses: vec![
                base.witnesses[0].clone(),
                VerificationWitnessInfo {
                    id: "w1".to_string(),
                    pubkey: base.witnesses[1].pubkey.clone(),
                },
            ],
            ..base.clone()
        };
        assert!(duplicate_id.validate().is_err());

        let duplicate_key = NetworkVerificationConfig {
            witnesses: vec![
                base.witnesses[0].clone(),
                VerificationWitnessInfo {
                    id: "w2".to_string(),
                    pubkey: base.witnesses[0].pubkey.clone(),
                },
            ],
            ..base.clone()
        };
        assert!(duplicate_key.validate().is_err());

        let invalid_scheme_key = NetworkVerificationConfig {
            witnesses: vec![VerificationWitnessInfo {
                id: "w1".to_string(),
                pubkey: "not-hex".to_string(),
            }],
            ..base.clone()
        };
        assert!(invalid_scheme_key.validate().is_err());

        let mut with_peer = base.clone();
        with_peer.federation = crate::federation::FederationVerificationConfig {
            enabled: true,
            cross_anchor_threshold: 1,
            peer_networks: vec![crate::federation::PeerNetworkVerificationInfo {
                id: "peer".to_string(),
                gateway: "https://peer.example".to_string(),
                min_witnesses: 1,
            }],
        };
        assert!(with_peer.validate().is_ok());
        for gateway in [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
            "http://example.com",
            "https://user:pass@example.com",
            "https://example.com/path?token=secret",
            "https://example.com/path#fragment",
        ] {
            let mut invalid_url = with_peer.clone();
            invalid_url.federation.peer_networks[0].gateway = gateway.to_string();
            let valid = matches!(
                gateway,
                "http://localhost:8080"
                    | "http://127.0.0.1:8080"
                    | "http://[::1]:8080"
                    | "https://peer.example"
            );
            assert_eq!(invalid_url.validate().is_ok(), valid, "gateway {gateway}");
        }
    }

    #[test]
    fn test_find_witness() {
        let config = NetworkConfig {
            id: "test".to_string(),
            witnesses: vec![
                WitnessInfo {
                    id: "w1".to_string(),
                    pubkey: "key1".to_string(),
                    endpoint: "http://localhost:3001".to_string(),
                    auth_token: Some("token-1".to_string()),
                },
                WitnessInfo {
                    id: "w2".to_string(),
                    pubkey: "key2".to_string(),
                    endpoint: "http://localhost:3002".to_string(),
                    auth_token: Some("token-2".to_string()),
                },
            ],
            threshold: 1,
            signature_scheme: Default::default(),
            federation: Default::default(),
            external_anchors: Default::default(),
            federation_peers: vec![],
        };

        assert!(config.find_witness("w1").is_some());
        assert!(config.find_witness("w2").is_some());
        assert!(config.find_witness("w3").is_none());
    }

    fn sample_config_with_tokens() -> NetworkConfig {
        NetworkConfig {
            id: "test".to_string(),
            witnesses: vec![
                WitnessInfo {
                    id: "w1".to_string(),
                    pubkey: "key1".to_string(),
                    endpoint: "http://localhost:3001".to_string(),
                    auth_token: Some("super-secret-token-1".to_string()),
                },
                WitnessInfo {
                    id: "w2".to_string(),
                    pubkey: "key2".to_string(),
                    endpoint: "http://localhost:3002".to_string(),
                    auth_token: Some("super-secret-token-2".to_string()),
                },
            ],
            threshold: 1,
            signature_scheme: Default::default(),
            federation: Default::default(),
            external_anchors: Default::default(),
            federation_peers: vec![],
        }
    }

    /// Accepted: a full `NetworkConfig` carrying `auth_token` values
    /// round-trips locally (deserialize -> serialize -> deserialize) without
    /// error. The token is only ever stripped at the serialization boundary,
    /// never on the in-memory value.
    #[test]
    fn test_network_config_with_tokens_roundtrips_locally() {
        let config = sample_config_with_tokens();

        // Serialize -> deserialize -> serialize: must never error, even with
        // tokens present in memory.
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: NetworkConfig = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&deserialized).unwrap();
        let _deserialized2: NetworkConfig = serde_json::from_str(&json2).unwrap();

        // The in-memory value still carries its tokens (they are only stripped
        // from the serialized public wire form).
        assert_eq!(
            config.witnesses[0].auth_token.as_deref(),
            Some("super-secret-token-1")
        );
        assert_eq!(
            config.witnesses[1].auth_token.as_deref(),
            Some("super-secret-token-2")
        );
    }

    /// Rejected: serializing a full `NetworkConfig` must never leak the
    /// `auth_token` value onto the wire.
    #[test]
    fn test_network_config_serialization_strips_auth_tokens() {
        let config = sample_config_with_tokens();

        let json = serde_json::to_string(&config).unwrap();

        assert!(
            !json.contains("super-secret-token-1"),
            "serialized NetworkConfig leaked auth_token: {json}"
        );
        assert!(
            !json.contains("super-secret-token-2"),
            "serialized NetworkConfig leaked auth_token: {json}"
        );
        assert!(
            !json.contains("auth_token"),
            "serialized NetworkConfig leaked auth_token field: {json}"
        );
    }

    /// Rejected: the public `/v1/config` response type must never contain a
    /// token value.
    #[test]
    fn test_network_config_public_serialization_contains_no_token() {
        let config = sample_config_with_tokens();
        let public = NetworkConfigPublic {
            id: config.id.clone(),
            threshold: config.threshold,
            signature_scheme: config.signature_scheme,
            witness_count: config.witnesses.len(),
        };

        let json = serde_json::to_string(&public).unwrap();

        assert!(
            !json.contains("super-secret-token-1"),
            "serialized NetworkConfigPublic leaked auth_token: {json}"
        );
        assert!(
            !json.contains("super-secret-token-2"),
            "serialized NetworkConfigPublic leaked auth_token: {json}"
        );
        assert!(
            !json.contains("auth_token"),
            "serialized NetworkConfigPublic leaked auth_token field: {json}"
        );
    }
}
