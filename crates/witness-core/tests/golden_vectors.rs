//! Golden-vector conformance test (docs/sdk-enhancement-spec.md §4.1).
//!
//! Reads the checked-in JSON vector files under `sdk/vectors/` (produced by
//! `crates/witness-core/src/bin/gen_vectors.rs`) and verifies each one:
//! recomputes `to_bytes`, verifies Ed25519/BLS signatures, verifies Merkle
//! inclusion/consistency proofs, verifies STH digests and threshold-signed
//! STHs, and checks wire encodings round-trip.
//!
//! These vectors are the conformance contract the TypeScript SDK
//! (`@witness/sdk`, Phase 2) is tested against. Regenerate with:
//! ```text
//! cargo run -p witness-core --bin gen_vectors
//! ```

use std::path::PathBuf;

use serde_json::Value;
use witness_core::merkle::{merkle_tree_hash, verify_consistency, verify_inclusion};
use witness_core::types::AttestationJobStatus;
use witness_core::{
    Attestation, AttestationSignatures, NetworkConfig, SignatureScheme, SignedAttestation,
    SignedTreeHead, TreeHead, WitnessInfo, WitnessSignature,
};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdk/vectors")
}

fn load(name: &str) -> Value {
    let path = vectors_dir().join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path:?}: {e}"))
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let b = hex::decode(s).unwrap();
    b.try_into().unwrap()
}

fn assert_expect<T: std::fmt::Debug>(name: &str, expect: &str, result: witness_core::Result<T>) {
    match expect {
        "accept" => assert!(result.is_ok(), "case {name} should accept: {result:?}"),
        "reject" => assert!(result.is_err(), "case {name} should reject"),
        other => panic!("unknown expect {other}"),
    }
}

/// §4.1.1 — `to_bytes` vectors.
#[test]
fn to_bytes_vectors() {
    let v = load("to_bytes.json");
    assert_eq!(v["version"], 2);
    for vec in v["vectors"].as_array().unwrap() {
        let a: Attestation = serde_json::from_value(vec["attestation"].clone()).unwrap();
        let expected = vec["to_bytes_hex"].as_str().unwrap();
        assert_eq!(hex::encode(a.to_bytes()), expected, "case {}", vec["name"]);
    }
}

/// §4.1.2 — Ed25519 sign/verify, accepted + rejected.
#[test]
fn ed25519_vectors() {
    let v = load("ed25519.json");
    let threshold = v["threshold"].as_u64().unwrap() as usize;
    let witnesses: Vec<WitnessInfo> = serde_json::from_value(v["witnesses"].clone()).unwrap();
    let config = NetworkConfig {
        id: "ed25519-net".to_string(),
        witnesses,
        threshold,
        signature_scheme: SignatureScheme::Ed25519,
        federation: Default::default(),
        external_anchors: Default::default(),
        federation_peers: vec![],
    };

    for case in v["cases"].as_array().unwrap() {
        let attestation: Attestation = serde_json::from_value(case["attestation"].clone()).unwrap();
        let signatures: Vec<WitnessSignature> =
            serde_json::from_value(case["signatures"].clone()).unwrap();
        let signed = SignedAttestation {
            attestation,
            signatures: AttestationSignatures::MultiSig { signatures },
        };
        let expect = case["expect"].as_str().unwrap();
        let result = witness_core::verify_signed_attestation(&signed, &config);
        assert_expect(case["name"].as_str().unwrap(), expect, result);
    }
}

/// §4.1.3 — BLS keygen/sign/aggregate/verify, accepted + rejected.
#[test]
fn bls_vectors() {
    let v = load("bls.json");

    // Keygen vectors: recompute from fixed IKM and compare.
    for k in v["ikms"].as_array().unwrap() {
        let ikm = hex::decode(k["ikm_hex"].as_str().unwrap()).unwrap();
        let sk = blst::min_sig::SecretKey::key_gen(&ikm, &[]).unwrap();
        assert_eq!(
            hex::encode(sk.to_bytes()),
            k["secret_key_hex"].as_str().unwrap(),
            "secret key {}",
            k["name"]
        );
        assert_eq!(
            hex::encode(sk.sk_to_pk().to_bytes()),
            k["public_key_hex"].as_str().unwrap(),
            "public key {}",
            k["name"]
        );
    }

    for case in v["cases"].as_array().unwrap() {
        let attestation: Attestation = serde_json::from_value(case["attestation"].clone()).unwrap();
        let expect = case["expect"].as_str().unwrap();
        let name = case["name"].as_str().unwrap();

        let result = if case.get("aggregate_signature").is_some() {
            let agg = hex::decode(case["aggregate_signature"].as_str().unwrap()).unwrap();
            let pks: Vec<blst::min_sig::PublicKey> = case["public_keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| {
                    blst::min_sig::PublicKey::from_bytes(&hex::decode(p.as_str().unwrap()).unwrap())
                        .unwrap()
                })
                .collect();
            witness_core::verify_aggregated_signature_bls(&attestation, &agg, &pks)
        } else {
            let sig = hex::decode(case["signature"].as_str().unwrap()).unwrap();
            let pk = blst::min_sig::PublicKey::from_bytes(
                &hex::decode(case["public_key"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
            witness_core::verify_signature_bls(&attestation, &sig, &pk)
        };
        assert_expect(name, expect, result);
    }
}

/// §4.1.4 — Merkle roots/inclusion/consistency for sizes 0..=17 + rejected.
#[test]
fn merkle_vectors() {
    let v = load("merkle.json");

    for tree in v["trees"].as_array().unwrap() {
        let size = tree["size"].as_u64().unwrap() as usize;
        let leaves: Vec<[u8; 32]> = tree["leaves"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| hex_to_32(l.as_str().unwrap()))
            .collect();
        let root = hex_to_32(tree["root"].as_str().unwrap());
        assert_eq!(merkle_tree_hash(&leaves), root, "root for size {size}");

        if let Some(inclusion) = tree.get("inclusion") {
            for p in inclusion.as_array().unwrap() {
                let idx = p["leaf_index"].as_u64().unwrap();
                let siblings: Vec<[u8; 32]> = p["siblings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|h| hex_to_32(h.as_str().unwrap()))
                    .collect();
                assert!(
                    verify_inclusion(&leaves[idx as usize], idx, size as u64, &siblings, &root),
                    "inclusion idx {idx} size {size}"
                );
            }
        }

        if let Some(consistency) = tree.get("consistency") {
            for p in consistency.as_array().unwrap() {
                let first = p["first_size"].as_u64().unwrap() as usize;
                let old_root = merkle_tree_hash(&leaves[..first]);
                let hashes: Vec<[u8; 32]> = p["hashes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|h| hex_to_32(h.as_str().unwrap()))
                    .collect();
                assert!(
                    verify_consistency(first as u64, size as u64, &old_root, &root, &hashes),
                    "consistency first {first} size {size}"
                );
            }
        }
    }

    for r in v["rejected"].as_array().unwrap() {
        let leaf = hex_to_32(r["leaf"].as_str().unwrap());
        let idx = r["leaf_index"].as_u64().unwrap();
        let size = r["tree_size"].as_u64().unwrap();
        let siblings: Vec<[u8; 32]> = r["siblings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| hex_to_32(h.as_str().unwrap()))
            .collect();
        let root = hex_to_32(r["root"].as_str().unwrap());
        assert!(
            !verify_inclusion(&leaf, idx, size, &siblings, &root),
            "rejected case {} should fail",
            r["name"]
        );
    }
}

/// §4.1.5 — STH digest construction + threshold-signed STHs per scheme.
#[test]
fn sth_vectors() {
    let v = load("sth.json");

    for d in v["digests"].as_array().unwrap() {
        let th: TreeHead = serde_json::from_value(d["tree_head"].clone()).unwrap();
        assert_eq!(
            hex::encode(th.signing_digest()),
            d["digest_hex"].as_str().unwrap(),
            "digest {}",
            d["name"]
        );
    }

    for (key, scheme) in [
        ("ed25519", SignatureScheme::Ed25519),
        ("bls", SignatureScheme::BLS),
    ] {
        let sec = &v[key];
        let threshold = sec["threshold"].as_u64().unwrap() as usize;
        let witnesses: Vec<WitnessInfo> = serde_json::from_value(sec["witnesses"].clone()).unwrap();
        let sth: SignedTreeHead = serde_json::from_value(sec["sth"].clone()).unwrap();
        let config = NetworkConfig {
            id: sth.tree_head.network_id.clone(),
            witnesses,
            threshold,
            signature_scheme: scheme,
            federation: Default::default(),
            external_anchors: Default::default(),
            federation_peers: vec![],
        };
        let result = witness_core::verify_signed_tree_head(&sth, &config);
        assert!(result.is_ok(), "{key} sth should verify: {result:?}");
    }
}

/// §4.1.6 — Wire encodings: both `AttestationSignatures` variants, hex
/// adapters, all enums, ambiguous/malformed union payloads.
#[test]
fn wire_vectors() {
    let v = load("wire.json");

    // MultiSig round-trip.
    let ms: AttestationSignatures =
        serde_json::from_str(v["multisig_json"].as_str().unwrap()).expect("multisig parses");
    assert!(matches!(ms, AttestationSignatures::MultiSig { .. }));
    assert_eq!(
        serde_json::to_value(&ms).unwrap(),
        serde_json::from_str::<Value>(v["multisig_json"].as_str().unwrap()).unwrap()
    );

    // Aggregated round-trip.
    let agg: AttestationSignatures =
        serde_json::from_str(v["aggregated_json"].as_str().unwrap()).expect("aggregated parses");
    assert!(matches!(agg, AttestationSignatures::Aggregated { .. }));
    assert_eq!(
        serde_json::to_value(&agg).unwrap(),
        serde_json::from_str::<Value>(v["aggregated_json"].as_str().unwrap()).unwrap()
    );

    // Malformed payloads rejected, including the ambiguous both-shapes payload
    // (spec §3.5: ambiguous → DecodeError).
    for m in v["malformed"].as_array().unwrap() {
        let res: Result<AttestationSignatures, _> =
            serde_json::from_str(m["json"].as_str().unwrap());
        assert!(res.is_err(), "malformed case {} should reject", m["name"]);
    }

    // Enums: SignatureScheme (lowercase).
    let schemes = &v["enums"]["signature_scheme"];
    assert_eq!(
        serde_json::to_string(&SignatureScheme::Ed25519).unwrap(),
        format!("\"{}\"", schemes["ed25519"].as_str().unwrap())
    );
    assert_eq!(
        serde_json::to_string(&SignatureScheme::BLS).unwrap(),
        format!("\"{}\"", schemes["bls"].as_str().unwrap())
    );
    assert_eq!(
        serde_json::from_str::<SignatureScheme>(&format!(
            "\"{}\"",
            schemes["ed25519"].as_str().unwrap()
        ))
        .unwrap(),
        SignatureScheme::Ed25519
    );
    assert_eq!(
        serde_json::from_str::<SignatureScheme>(&format!(
            "\"{}\"",
            schemes["bls"].as_str().unwrap()
        ))
        .unwrap(),
        SignatureScheme::BLS
    );

    // Enums: AttestationJobStatus (snake_case).
    let statuses = &v["enums"]["attestation_job_status"];
    for (variant, expected) in [
        (AttestationJobStatus::Pending, "pending"),
        (AttestationJobStatus::Retryable, "retryable"),
        (AttestationJobStatus::Confirmed, "confirmed"),
        (AttestationJobStatus::Failed, "failed"),
    ] {
        assert_eq!(
            serde_json::to_string(&variant).unwrap(),
            format!("\"{expected}\"")
        );
        assert_eq!(
            serde_json::from_str::<AttestationJobStatus>(&format!("\"{expected}\"")).unwrap(),
            variant
        );
        assert_eq!(statuses[expected].as_str().unwrap(), expected);
    }

    // Hex adapters: array32 (Attestation.hash) and vec (WitnessSignature).
    let a32 = &v["hex_adapters"]["array32"];
    let att: Attestation = serde_json::from_str(a32["json"].as_str().unwrap()).unwrap();
    assert_eq!(
        serde_json::to_string(&att).unwrap(),
        a32["json"].as_str().unwrap()
    );

    let vec = &v["hex_adapters"]["vec"];
    let ws: WitnessSignature = serde_json::from_str(vec["json"].as_str().unwrap()).unwrap();
    assert_eq!(
        serde_json::to_string(&ws).unwrap(),
        vec["json"].as_str().unwrap()
    );

    // Hex decode rule (spec §3.4): decoders accept mixed-case hex and reject
    // odd-length strings and non-hex characters (matching `hex::decode`); all
    // emitters produce lowercase. `bytes` pins the decoded bytes; `reserialize`
    // pins that Rust re-serialization emits lowercase (a double assertion).
    let decode = &v["hex_adapters"]["decode"];
    for a in decode["accept"].as_array().unwrap() {
        let decoded = hex::decode(a["input"].as_str().unwrap())
            .unwrap_or_else(|e| panic!("accept {} should decode: {e}", a["name"]));
        assert_eq!(
            hex::encode(&decoded),
            a["bytes"].as_str().unwrap(),
            "decoded bytes for {}",
            a["name"]
        );
        assert_eq!(
            hex::encode(&decoded),
            a["reserialize"].as_str().unwrap(),
            "re-serialization for {} must be lowercase",
            a["name"]
        );
    }
    for r in decode["reject"].as_array().unwrap() {
        assert!(
            hex::decode(r["input"].as_str().unwrap()).is_err(),
            "reject case {} should fail to decode",
            r["name"]
        );
    }
}
