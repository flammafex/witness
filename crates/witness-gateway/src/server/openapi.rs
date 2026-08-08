//! OpenAPI document for the client-facing gateway surface.
//!
//! This module is compiled only when the `openapi` feature is enabled. It
//! aggregates the `#[utoipa::path]` annotations on the client-facing handlers
//! into a single [`ApiDoc`], which the `gen_openapi` binary serializes to
//! `docs/openapi.yaml`.
//!
//! Operator-facing routes (`/v1/federation/anchor`, `/metrics`, `/admin/*`)
//! are intentionally excluded — they are auth-gated peer/ops surfaces, not
//! part of the client SDK surface (spec §7.2–7.3).

use utoipa::openapi::{schema::Object, OpenApi as OpenApiDocument, RefOr, Schema};
use utoipa::OpenApi;

use witness_core::types::{AttestationJobResponse, AttestationJobStatus, CreateAttestationRequest};
use witness_core::{
    Attestation, AttestationBatch, AttestationSignatures, BatchInclusion, CrossAnchor,
    ExternalAnchorProof, FederationVerificationConfig, FreebirdToken, LogConsistencyProof,
    LogInclusionProofResponse, MerkleProof, MerkleProofResponse, NetworkConfigPublic,
    NetworkVerificationConfig, PeerNetworkVerificationInfo, ProofBundle, SignatureScheme,
    SignedAttestation, SignedTreeHead, TreeHead, VerificationWitnessInfo, VerifyRequest,
    VerifyResponse, WitnessSignature,
};

use super::routes::HealthResponse;

/// The client-facing Witness Gateway OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Witness Gateway API",
        description = "Client-facing HTTP API for the Witness quorum timestamper.\n\n\
            All hashes and signatures are lowercase hex strings (no `0x` prefix). \
            `AttestationSignatures` is an untagged union: a `signatures` array means \
            Ed25519 multi-sig; both `signature` and `signers` means BLS aggregated. \
            See docs/sdk-enhancement-spec.md §3.4–3.5 for the normative encoding rules.\n\n\
            Operator-facing routes (`/v1/federation/anchor`, `/metrics`, `/admin/*`) are \
            intentionally not documented here. The WebSocket event stream is documented in \
            docs/asyncapi.yaml.",
        version = env!("CARGO_PKG_VERSION")
    ),
    paths(
        super::routes::health_handler,
        super::routes::config_handler,
        super::routes::network_config_handler,
        super::routes::create_attestation_handler,
        super::routes::get_attestation_handler,
        super::routes::verify_handler,
        super::routes::get_proof_handler,
        super::routes::get_proof_bundle_handler,
        super::routes::get_anchors_handler,
        super::routes::get_latest_sth_handler,
        super::routes::get_sth_at_size_handler,
        super::routes::get_consistency_handler,
        super::routes::get_log_proof_handler,
        super::ws::ws_events_handler,
    ),
    components(
        schemas(
            HealthResponse,
            NetworkConfigPublic,
            NetworkVerificationConfig,
            VerificationWitnessInfo,
            SignatureScheme,
            FederationVerificationConfig,
            PeerNetworkVerificationInfo,
            CreateAttestationRequest,
            FreebirdToken,
            AttestationJobResponse,
            AttestationJobStatus,
            Attestation,
            SignedAttestation,
            AttestationSignatures,
            WitnessSignature,
            VerifyRequest,
            VerifyResponse,
            MerkleProofResponse,
            ProofBundle,
            BatchInclusion,
            AttestationBatch,
            MerkleProof,
            CrossAnchor,
            ExternalAnchorProof,
            SignedTreeHead,
            TreeHead,
            LogConsistencyProof,
            LogInclusionProofResponse,
        )
    ),
    tags(
        (name = "health", description = "Liveness"),
        (name = "config", description = "Network configuration"),
        (name = "attestations", description = "Attestation lifecycle"),
        (name = "verify", description = "Gateway verification opinion"),
        (name = "proofs", description = "Merkle / proof bundle retrieval"),
        (name = "anchors", description = "External anchor proofs"),
        (name = "log", description = "RFC 9162 transparency log"),
        (name = "events", description = "WebSocket event stream (see docs/asyncapi.yaml)")
    )
)]
pub struct ApiDoc;

/// Utoipa's schema model does not expose JSON Schema's `not` keyword. An empty
/// enum is the equivalent always-failing property schema and lets the two
/// untagged signature arms reject the other arm's discriminator keys while
/// leaving unknown forward-compatible fields allowed.
fn impossible_property_schema() -> RefOr<Schema> {
    let mut object = Object::new();
    object.enum_values = Some(Vec::new());
    RefOr::T(Schema::Object(object))
}

fn harden_attestation_signatures_schema(document: &mut OpenApiDocument) {
    let Some(components) = document.components.as_mut() else {
        return;
    };
    let Some(RefOr::T(schema)) = components.schemas.get_mut("AttestationSignatures") else {
        return;
    };

    let items = match schema {
        Schema::AnyOf(any_of) => &mut any_of.items,
        Schema::OneOf(one_of) => &mut one_of.items,
        _ => return,
    };

    for arm in items {
        let RefOr::T(Schema::Object(object)) = arm else {
            continue;
        };
        if object.properties.contains_key("signatures") {
            object
                .properties
                .entry("signature".to_string())
                .or_insert_with(impossible_property_schema);
            object
                .properties
                .entry("signers".to_string())
                .or_insert_with(impossible_property_schema);
        } else if object.properties.contains_key("signature")
            && object.properties.contains_key("signers")
        {
            object
                .properties
                .entry("signatures".to_string())
                .or_insert_with(impossible_property_schema);
        }
    }
}

/// Serialize the OpenAPI document to YAML.
pub fn to_yaml() -> Result<String, Box<dyn std::error::Error>> {
    let mut document = ApiDoc::openapi();
    harden_attestation_signatures_schema(&mut document);
    Ok(document.to_yaml()?)
}

#[cfg(all(test, feature = "openapi"))]
mod tests {
    use super::*;

    /// Drift gate: regenerating `docs/openapi.yaml` must produce zero diff.
    ///
    /// Run with `cargo test -p witness-gateway --features openapi`. If this
    /// fails, regenerate with:
    ///   cargo run -p witness-gateway --bin gen_openapi --features openapi
    #[test]
    fn openapi_drift() {
        let generated = to_yaml().expect("failed to serialize OpenAPI to YAML");

        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
        let repo_root = std::path::PathBuf::from(&manifest_dir)
            .join("..")
            .join("..")
            .canonicalize()
            .expect("failed to resolve repo root");
        let checked_in_path = repo_root.join("docs").join("openapi.yaml");

        let checked_in = std::fs::read_to_string(&checked_in_path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", checked_in_path.display()));

        assert_eq!(
            generated, checked_in,
            "docs/openapi.yaml is out of date. Regenerate with:\n  \
             cargo run -p witness-gateway --bin gen_openapi --features openapi"
        );
    }

    #[test]
    fn signature_schema_rejects_mixed_discriminator_keys() {
        let mut document = ApiDoc::openapi();
        harden_attestation_signatures_schema(&mut document);
        let schema = document
            .components
            .as_ref()
            .unwrap()
            .schemas
            .get("AttestationSignatures")
            .unwrap();
        let RefOr::T(schema) = schema else {
            panic!("expected inline AttestationSignatures schema");
        };
        let items = match schema {
            Schema::AnyOf(any_of) => &any_of.items,
            Schema::OneOf(one_of) => &one_of.items,
            _ => panic!("expected AttestationSignatures union schema"),
        };
        let RefOr::T(Schema::Object(multisig)) = &items[0] else {
            panic!("expected multisig object schema");
        };
        let RefOr::T(Schema::Object(aggregate)) = &items[1] else {
            panic!("expected aggregate object schema");
        };
        assert!(matches!(
            multisig.properties.get("signature"),
            Some(RefOr::T(Schema::Object(Object {
                enum_values: Some(values),
                ..
            }))) if values.is_empty()
        ));
        assert!(matches!(
            multisig.properties.get("signers"),
            Some(RefOr::T(Schema::Object(Object {
                enum_values: Some(values),
                ..
            }))) if values.is_empty()
        ));
        assert!(matches!(
            aggregate.properties.get("signatures"),
            Some(RefOr::T(Schema::Object(Object {
                enum_values: Some(values),
                ..
            }))) if values.is_empty()
        ));
    }
}
