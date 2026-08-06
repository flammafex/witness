//! JSON Schema generator for the `@witness/sdk` TypeScript type pipeline.
//!
//! This binary derives JSON Schema directly from the `witness-core` serde wire
//! types (via `schemars::JsonSchema`) and emits a single combined schema
//! document into `sdk/ts/schema/schema.json`. The Node script
//! `sdk/ts/scripts/gen-types.mjs` then runs `json-schema-to-typescript` over
//! that document to produce `sdk/ts/src/types.generated.ts`.
//!
//! The generated TS types are checked in, and CI enforces a zero-diff drift
//! gate: any change to the serde wire types that alters the schema must be
//! accompanied by a regenerated `types.generated.ts`, otherwise CI fails.
//!
//! Run from the workspace root:
//!   cargo run -p witness-core --bin gen_ts_types

use schemars::schema::{RootSchema, Schema};
use std::collections::BTreeMap;
use std::path::PathBuf;

use witness_core::types::{AttestationJobResponse, AttestationJobStatus, CreateAttestationRequest};
use witness_core::{
    Attestation, AttestationBatch, AttestationEvent, AttestationSignatures, BatchInclusion,
    CrossAnchor, ExternalAnchorProof, FreebirdToken, LogConsistencyProof,
    LogInclusionProofResponse, MerkleProof, MerkleProofResponse, NetworkConfig,
    NetworkConfigPublic, ProofBundle, ProofBundleVerification, ProofVerificationConfig,
    SignatureScheme, SignedAttestation, SignedTreeHead, TimestampRequest, TimestampResponse,
    TreeHead, VerificationLevel, VerifyRequest, VerifyResponse, WitnessInfo, WitnessSignature,
};

/// Register a wire type as a named definition in the combined schema.
fn add<T: schemars::JsonSchema>(root: &mut RootSchema, name: &str) {
    let s = schemars::schema_for!(T);
    // Merge any referenced definitions first (deduplicated by name).
    for (k, v) in s.definitions {
        root.definitions.entry(k).or_insert(v);
    }
    // The root schema of `s` is the type itself; expose it under `name`.
    root.definitions
        .insert(name.to_string(), Schema::Object(s.schema));
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut root = RootSchema {
        meta_schema: None,
        schema: schemars::schema::SchemaObject {
            metadata: Some(Box::new(schemars::schema::Metadata {
                title: Some("WitnessWireTypes".to_string()),
                ..Default::default()
            })),
            ..Default::default()
        },
        definitions: BTreeMap::new(),
    };

    // Client surface (§6.2) + endpoint coverage matrix (§8).
    add::<Attestation>(&mut root, "Attestation");
    add::<SignedAttestation>(&mut root, "SignedAttestation");
    add::<WitnessSignature>(&mut root, "WitnessSignature");
    add::<WitnessInfo>(&mut root, "WitnessInfo");
    add::<NetworkConfig>(&mut root, "NetworkConfig");
    add::<NetworkConfigPublic>(&mut root, "NetworkConfigPublic");
    add::<AttestationJobResponse>(&mut root, "AttestationJobResponse");
    add::<AttestationJobStatus>(&mut root, "AttestationJobStatus");
    add::<FreebirdToken>(&mut root, "FreebirdToken");
    add::<VerifyResponse>(&mut root, "VerifyResponse");
    add::<VerifyRequest>(&mut root, "VerifyRequest");
    add::<CreateAttestationRequest>(&mut root, "CreateAttestationRequest");
    add::<TimestampRequest>(&mut root, "TimestampRequest");
    add::<TimestampResponse>(&mut root, "TimestampResponse");
    add::<AttestationEvent>(&mut root, "AttestationEvent");
    add::<MerkleProofResponse>(&mut root, "MerkleProofResponse");
    add::<LogInclusionProofResponse>(&mut root, "LogInclusionProofResponse");

    // Signature schemes.
    add::<AttestationSignatures>(&mut root, "AttestationSignatures");
    add::<SignatureScheme>(&mut root, "SignatureScheme");

    // Merkle / log.
    add::<MerkleProof>(&mut root, "MerkleProof");
    add::<SignedTreeHead>(&mut root, "SignedTreeHead");
    add::<TreeHead>(&mut root, "TreeHead");
    add::<LogConsistencyProof>(&mut root, "LogConsistencyProof");

    // Federation / external anchors.
    add::<ProofBundle>(&mut root, "ProofBundle");
    add::<ProofBundleVerification>(&mut root, "ProofBundleVerification");
    add::<ProofVerificationConfig>(&mut root, "ProofVerificationConfig");
    add::<VerificationLevel>(&mut root, "VerificationLevel");
    add::<BatchInclusion>(&mut root, "BatchInclusion");
    add::<CrossAnchor>(&mut root, "CrossAnchor");
    add::<AttestationBatch>(&mut root, "AttestationBatch");
    add::<ExternalAnchorProof>(&mut root, "ExternalAnchorProof");

    // Reference every definition from the root so json-schema-to-typescript
    // emits an interface for each wire type (it only generates definitions
    // that are reachable from the root schema).
    let refs: Vec<Schema> = root
        .definitions
        .keys()
        .map(|name| {
            Schema::Object(schemars::schema::SchemaObject {
                reference: Some(format!("#/definitions/{name}")),
                ..Default::default()
            })
        })
        .collect();
    root.schema = schemars::schema::SchemaObject {
        metadata: Some(Box::new(schemars::schema::Metadata {
            title: Some("WitnessWireTypes".to_string()),
            ..Default::default()
        })),
        subschemas: Some(Box::new(schemars::schema::SubschemaValidation {
            any_of: Some(refs),
            ..Default::default()
        })),
        ..Default::default()
    };

    // Resolve output path relative to the crate manifest so the binary works
    // regardless of the invoking working directory.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let repo_root = PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .canonicalize()?;
    let schema_dir = repo_root.join("sdk").join("ts").join("schema");
    std::fs::create_dir_all(&schema_dir)?;
    let schema_path = schema_dir.join("schema.json");

    let json = serde_json::to_string_pretty(&root)?;
    std::fs::write(&schema_path, json + "\n")?;

    println!(
        "Wrote combined JSON Schema for {} wire types to {}",
        root.definitions.len(),
        schema_path.display()
    );
    Ok(())
}
