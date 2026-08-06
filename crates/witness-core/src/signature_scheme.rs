use serde::{Deserialize, Deserializer, Serialize};

/// Signature scheme used by the network
#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default, schemars::JsonSchema,
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum SignatureScheme {
    /// Ed25519 signatures (Phase 1, multi-sig)
    #[default]
    Ed25519,

    /// BLS signatures (Phase 4, aggregated)
    #[serde(rename = "bls")]
    BLS,
}

impl std::fmt::Display for SignatureScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureScheme::Ed25519 => write!(f, "ed25519"),
            SignatureScheme::BLS => write!(f, "bls"),
        }
    }
}

/// Signatures on an attestation (multi-sig or aggregated)
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(untagged)]
pub enum AttestationSignatures {
    /// Ed25519 multi-signature (one signature per witness)
    MultiSig {
        signatures: Vec<crate::WitnessSignature>,
    },

    /// BLS aggregated signature (single signature from multiple witnesses)
    Aggregated {
        /// Aggregated BLS signature
        #[serde(with = "crate::serde_hex::vec")]
        #[schemars(with = "String")]
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        signature: Vec<u8>,

        /// List of witness IDs that participated
        signers: Vec<String>,
    },
}

/// Manual `Deserialize` implementing the §3.5 discrimination rule.
///
/// The union is discriminated by key presence: a `signatures` array ⇒
/// `MultiSig`; both `signature` and `signers` ⇒ `Aggregated`; anything else —
/// including payloads carrying *both* shapes' keys — is a `DecodeError`.
/// This is stricter than `#[serde(untagged)]` (which would accept ambiguous
/// payloads as `MultiSig`, first-variant-wins). `Serialize` is unchanged, so
/// the wire format is byte-identical.
impl<'de> Deserialize<'de> for AttestationSignatures {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Probe {
            #[serde(default)]
            signatures: Option<Vec<crate::WitnessSignature>>,
            #[serde(default)]
            signature: Option<String>, // hex string; decode after discrimination
            #[serde(default)]
            signers: Option<Vec<String>>,
        }
        let p = Probe::deserialize(d)?;
        match (p.signatures, p.signature, p.signers) {
            (Some(signatures), None, None) => Ok(Self::MultiSig { signatures }),
            (None, Some(sig_hex), Some(signers)) => Ok(Self::Aggregated {
                signature: hex::decode(sig_hex).map_err(serde::de::Error::custom)?,
                signers,
            }),
            // ambiguous (signatures + either aggregated key), partial
            // aggregated (exactly one of signature/signers), or neither shape
            _ => Err(serde::de::Error::custom(
                "ambiguous or malformed attestation signatures: \
                 expected `signatures` OR both of `signature`+`signers`",
            )),
        }
    }
}

impl AttestationSignatures {
    pub fn new_multisig() -> Self {
        AttestationSignatures::MultiSig {
            signatures: Vec::new(),
        }
    }

    pub fn new_aggregated(signature: Vec<u8>, signers: Vec<String>) -> Self {
        AttestationSignatures::Aggregated { signature, signers }
    }

    pub fn add_signature_multisig(&mut self, witness_id: String, signature: Vec<u8>) {
        if let AttestationSignatures::MultiSig { signatures } = self {
            signatures.push(crate::WitnessSignature {
                witness_id,
                signature,
            });
        }
    }

    pub fn signer_count(&self) -> usize {
        match self {
            AttestationSignatures::MultiSig { signatures } => signatures.len(),
            AttestationSignatures::Aggregated { signers, .. } => signers.len(),
        }
    }

    pub fn is_aggregated(&self) -> bool {
        matches!(self, AttestationSignatures::Aggregated { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn multisig_json() -> &'static str {
        r#"{"signatures":[{"witness_id":"w1","signature":"0102030405"},{"witness_id":"w2","signature":"aabbcc"}]}"#
    }

    fn aggregated_json() -> &'static str {
        r#"{"signature":"deadbeef","signers":["w1","w2","w3"]}"#
    }

    #[test]
    fn accepts_canonical_multisig() {
        let v: AttestationSignatures = serde_json::from_str(multisig_json()).unwrap();
        assert!(matches!(v, AttestationSignatures::MultiSig { .. }));
    }

    #[test]
    fn accepts_canonical_aggregated() {
        let v: AttestationSignatures = serde_json::from_str(aggregated_json()).unwrap();
        assert!(matches!(v, AttestationSignatures::Aggregated { .. }));
    }

    #[test]
    fn accepts_empty_multisig() {
        let v: AttestationSignatures = serde_json::from_str(r#"{"signatures":[]}"#).unwrap();
        assert!(
            matches!(v, AttestationSignatures::MultiSig { signatures } if signatures.is_empty())
        );
    }

    #[test]
    fn accepts_multisig_with_unknown_key() {
        // Unknown non-discriminative keys stay tolerated (no deny_unknown_fields).
        let v: AttestationSignatures =
            serde_json::from_str(r#"{"signatures":[],"extra":"ignored"}"#).unwrap();
        assert!(matches!(v, AttestationSignatures::MultiSig { .. }));
    }

    #[test]
    fn rejects_both_shapes_ambiguous() {
        let res: Result<AttestationSignatures, _> = serde_json::from_str(
            r#"{"signatures":[{"witness_id":"w1","signature":"0102"}],"signature":"deadbeef","signers":["w1"]}"#,
        );
        assert!(res.is_err());
    }

    #[test]
    fn rejects_signatures_plus_signature() {
        let res: Result<AttestationSignatures, _> =
            serde_json::from_str(r#"{"signatures":[],"signature":"deadbeef"}"#);
        assert!(res.is_err());
    }

    #[test]
    fn rejects_signatures_plus_signers() {
        let res: Result<AttestationSignatures, _> =
            serde_json::from_str(r#"{"signatures":[],"signers":["w1"]}"#);
        assert!(res.is_err());
    }

    #[test]
    fn rejects_partial_aggregated_signature_only() {
        let res: Result<AttestationSignatures, _> =
            serde_json::from_str(r#"{"signature":"deadbeef"}"#);
        assert!(res.is_err());
    }

    #[test]
    fn rejects_partial_aggregated_signers_only() {
        let res: Result<AttestationSignatures, _> = serde_json::from_str(r#"{"signers":["w1"]}"#);
        assert!(res.is_err());
    }

    #[test]
    fn rejects_empty_object() {
        let res: Result<AttestationSignatures, _> = serde_json::from_str(r#"{}"#);
        assert!(res.is_err());
    }

    #[test]
    fn rejects_non_hex_aggregated_signature() {
        let res: Result<AttestationSignatures, _> =
            serde_json::from_str(r#"{"signature":"ZZ","signers":["w1"]}"#);
        assert!(res.is_err());
    }

    #[test]
    fn rejects_signatures_wrong_type() {
        let res: Result<AttestationSignatures, _> =
            serde_json::from_str(r#"{"signatures":"not-an-array"}"#);
        assert!(res.is_err());
    }

    #[test]
    fn round_trip_both_variants() {
        let ms = AttestationSignatures::MultiSig {
            signatures: vec![crate::WitnessSignature {
                witness_id: "w1".to_string(),
                signature: vec![0x01, 0x02],
            }],
        };
        let agg = AttestationSignatures::Aggregated {
            signature: vec![0xde, 0xad, 0xbe, 0xef],
            signers: vec!["w1".to_string(), "w2".to_string()],
        };
        for v in [ms, agg] {
            let json = serde_json::to_string(&v).unwrap();
            let back: AttestationSignatures = serde_json::from_str(&json).unwrap();
            assert_eq!(serde_json::to_string(&back).unwrap(), json);
        }
    }
}
