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
    CrossAnchor, ExternalAnchorProof, FederationVerificationConfig, FreebirdToken,
    LogConsistencyProof, LogInclusionProofResponse, MerkleProof, MerkleProofResponse,
    NetworkConfig, NetworkConfigPublic, NetworkVerificationConfig, PeerNetworkVerificationInfo,
    ProofBundle, ProofBundleVerification, ProofVerificationConfig, SignatureScheme,
    SignedAttestation, SignedTreeHead, TimestampRequest, TimestampResponse, TreeHead,
    VerificationLevel, VerificationWitnessInfo, VerifyRequest, VerifyResponse, WitnessInfo,
    WitnessSignature,
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

/// `json-schema-to-typescript` supports the `tsType` extension as an escape
/// hatch for values whose JSON Schema representation is more precise than a
/// plain TypeScript `number`. Schemars exposes extensions as JSON values, so
/// apply this after the combined schema has been assembled. `uint64` is used
/// by schemars specifically for Rust `u64`; `uint` remains the ordinary
/// bounded-number mapping for `usize` and similar fields.
fn mark_u64_ts_types(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            if object.get("format") == Some(&serde_json::Value::String("uint64".to_string()))
                && !object.contains_key("tsType")
            {
                let nullable = object
                    .get("type")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|types| types.iter().any(|ty| ty == "null"));
                object.insert(
                    "tsType".to_string(),
                    serde_json::Value::String(if nullable {
                        "U64 | null".to_string()
                    } else {
                        "U64".to_string()
                    }),
                );
            }
            for child in object.values_mut() {
                mark_u64_ts_types(child);
            }
        }
        serde_json::Value::Array(array) => {
            for child in array {
                mark_u64_ts_types(child);
            }
        }
        _ => {}
    }
}

/// Schemars cannot express the discriminator-key exclusion for an untagged
/// enum while retaining forward-compatible unknown fields. Add an impossible
/// schema to each forbidden discriminator property instead: an absent field
/// remains valid, but its presence cannot validate either union arm.
fn harden_attestation_signatures_schema(value: &mut serde_json::Value) {
    let Some(definitions) = value
        .get_mut("definitions")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    let Some(any_of) = definitions
        .get_mut("AttestationSignatures")
        .and_then(|schema| schema.get_mut("anyOf"))
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };

    for arm in any_of {
        let Some(properties) = arm
            .get_mut("properties")
            .and_then(serde_json::Value::as_object_mut)
        else {
            continue;
        };
        let forbidden = if properties.contains_key("signatures") {
            ["signature", "signers"].as_slice()
        } else if properties.contains_key("signature") && properties.contains_key("signers") {
            ["signatures"].as_slice()
        } else {
            continue;
        };
        for property in forbidden {
            properties
                .entry((*property).to_string())
                .or_insert_with(|| serde_json::json!({ "not": {}, "tsType": "never" }));
        }
    }
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
    add::<NetworkVerificationConfig>(&mut root, "NetworkVerificationConfig");
    add::<VerificationWitnessInfo>(&mut root, "VerificationWitnessInfo");
    add::<FederationVerificationConfig>(&mut root, "FederationVerificationConfig");
    add::<PeerNetworkVerificationInfo>(&mut root, "PeerNetworkVerificationInfo");
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

    // Shared TypeScript alias used by every Rust `u64` wire field. Keep this
    // separate from ordinary bounded integer fields (`usize`, `u32`, etc.).
    root.definitions.insert(
        "U64".to_string(),
        Schema::Object(schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::Integer.into()),
            format: Some("uint64".to_string()),
            number: Some(Box::new(schemars::schema::NumberValidation {
                minimum: Some(0.0),
                ..Default::default()
            })),
            extensions: {
                let mut extensions = BTreeMap::new();
                extensions.insert(
                    "tsType".to_string(),
                    serde_json::Value::String("number | bigint".to_string()),
                );
                extensions
            },
            ..Default::default()
        }),
    );

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

    let mut document = serde_json::to_value(&root)?;
    harden_attestation_signatures_schema(&mut document);
    mark_u64_ts_types(&mut document);
    let json = serde_json::to_string_pretty(&document)?;
    std::fs::write(&schema_path, json + "\n")?;

    println!(
        "Wrote combined JSON Schema for {} wire types to {}",
        root.definitions.len(),
        schema_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::harden_attestation_signatures_schema;
    use serde_json::json;

    #[test]
    fn signature_schema_rejects_mixed_discriminator_keys_without_closing_objects() {
        let mut schema = json!({
            "definitions": {
                "AttestationSignatures": {
                    "anyOf": [
                        { "properties": { "signatures": {} } },
                        { "properties": { "signature": {}, "signers": {} } }
                    ]
                }
            }
        });

        harden_attestation_signatures_schema(&mut schema);

        let arms = schema["definitions"]["AttestationSignatures"]["anyOf"]
            .as_array()
            .unwrap();
        assert_eq!(arms[0]["properties"]["signature"]["not"], json!({}));
        assert_eq!(arms[0]["properties"]["signers"]["not"], json!({}));
        assert_eq!(arms[1]["properties"]["signatures"]["not"], json!({}));
        assert!(arms[0].get("additionalProperties").is_none());
        assert!(arms[1].get("additionalProperties").is_none());
    }
}
