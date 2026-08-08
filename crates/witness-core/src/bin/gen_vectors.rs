//! Deterministic golden-vector generator for the Witness SDK conformance
//! contract (docs/sdk-enhancement-spec.md §4.1).
//!
//! Emits checked-in JSON vector files under `sdk/vectors/`. Every value is
//! derived from fixed seeds / fixed IKM — **no `OsRng`** — so regeneration is
//! byte-for-byte reproducible. The companion integration test
//! `crates/witness-core/tests/golden_vectors.rs` reads these files back and
//! verifies them.
//!
//! These vectors are the conformance contract the TypeScript SDK
//! (`@witness/sdk`, Phase 2) is tested against. Any change to the pinned wire
//! or crypto parameters in spec §3 requires regenerating them (see
//! `sdk/vectors/README.md`).
//!
//! Usage:
//! ```text
//! cargo run -p witness-core --bin gen_vectors [OUTPUT_DIR]
//! ```
//! `OUTPUT_DIR` defaults to `sdk/vectors` relative to the current directory.

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use witness_core::merkle::{consistency_path, inclusion_path, merkle_tree_hash};
use witness_core::{
    aggregate_signatures_bls, Attestation, AttestationSignatures, SignedAttestation, TreeHead,
    WitnessSignature,
};

/// Bump whenever the vector format or the pinned §3 parameters change.
const VERSION: u64 = 2;

fn main() {
    let out_dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("sdk/vectors"));

    std::fs::create_dir_all(&out_dir).expect("create output dir");

    write(&out_dir, "to_bytes.json", to_bytes_vectors());
    write(&out_dir, "ed25519.json", ed25519_vectors());
    write(&out_dir, "bls.json", bls_vectors());
    write(&out_dir, "merkle.json", merkle_vectors());
    write(&out_dir, "sth.json", sth_vectors());
    write(&out_dir, "wire.json", wire_vectors());

    println!("wrote vectors to {}", out_dir.display());
}

fn write(dir: &Path, name: &str, value: Value) {
    let path = dir.join(name);
    let json = serde_json::to_string_pretty(&value).expect("serialize vector");
    std::fs::write(&path, json + "\n").expect("write vector file");
    println!("  {}", path.display());
}

fn attestation_json(a: &Attestation) -> Value {
    json!({
        "hash": hex::encode(a.hash),
        "timestamp": a.timestamp,
        "network_id": a.network_id,
        "sequence": a.sequence,
    })
}

fn tree_head_json(th: &TreeHead) -> Value {
    json!({
        "network_id": th.network_id,
        "tree_size": th.tree_size,
        "timestamp": th.timestamp,
        "root_hash": hex::encode(th.root_hash),
    })
}

/// §4.1.1 — `to_bytes` vectors: fixed attestations including empty, multibyte
/// (CJK/emoji), and length-prefix-boundary `network_id`s.
fn to_bytes_vectors() -> Value {
    let attestations = vec![
        (
            "empty_network_id",
            Attestation {
                hash: [0x11; 32],
                timestamp: 1_700_000_000,
                network_id: String::new(),
                sequence: 0,
            },
        ),
        (
            "ascii",
            Attestation {
                hash: [0x22; 32],
                timestamp: 1_700_000_001,
                network_id: "test-network".to_string(),
                sequence: 1,
            },
        ),
        (
            "cjk",
            Attestation {
                hash: [0x33; 32],
                timestamp: 1_700_000_002,
                network_id: "网络-测试".to_string(),
                sequence: 2,
            },
        ),
        (
            "emoji",
            Attestation {
                hash: [0x44; 32],
                timestamp: 1_700_000_003,
                network_id: "witness🚀🌍".to_string(),
                sequence: 3,
            },
        ),
        // Length-prefix boundary: 255 vs 256 bytes (u8 boundary of the u32
        // length prefix). Guards against truncation to a single byte.
        (
            "boundary_255",
            Attestation {
                hash: [0x55; 32],
                timestamp: 1_700_000_004,
                network_id: "a".repeat(255),
                sequence: 4,
            },
        ),
        (
            "boundary_256",
            Attestation {
                hash: [0x66; 32],
                timestamp: 1_700_000_005,
                network_id: "b".repeat(256),
                sequence: 5,
            },
        ),
    ];

    let vectors: Vec<Value> = attestations
        .into_iter()
        .map(|(name, a)| {
            json!({
                "name": name,
                "attestation": attestation_json(&a),
                "to_bytes_hex": hex::encode(a.to_bytes()),
            })
        })
        .collect();

    json!({ "version": VERSION, "vectors": vectors })
}

/// §4.1.2 — Ed25519 sign/verify with accepted + rejected cases.
fn ed25519_vectors() -> Value {
    // Fixed per-witness seeds (no OsRng).
    let keys: Vec<(String, SigningKey)> = (1..=3)
        .map(|i| (format!("w{i}"), SigningKey::from_bytes(&[i as u8; 32])))
        .collect();
    // A key that is NOT registered for any witness (used for wrong-key cases).
    let evil = SigningKey::from_bytes(&[0xEE; 32]);

    let witnesses: Vec<Value> = keys
        .iter()
        .map(|(id, sk)| {
            json!({
                "id": id,
                "pubkey": hex::encode(sk.verifying_key().as_bytes()),
                "endpoint": "http://localhost",
            })
        })
        .collect();

    let threshold = 2;
    let attestation = Attestation {
        hash: [0xAB; 32],
        timestamp: 1_700_000_000,
        network_id: "ed25519-net".to_string(),
        sequence: 7,
    };

    let sign = |sk: &SigningKey| sk.sign(&attestation.to_bytes()).to_bytes().to_vec();

    let sig_w1 = sign(&keys[0].1);
    let sig_w2 = sign(&keys[1].1);
    let sig_w3 = sign(&keys[2].1);
    let sig_evil = sign(&evil);

    let multisig = |sigs: Vec<(String, Vec<u8>)>| -> Value {
        json!(sigs
            .into_iter()
            .map(|(id, s)| json!({ "witness_id": id, "signature": hex::encode(s) }))
            .collect::<Vec<_>>())
    };

    let mut cases = Vec::new();

    // Accepted: two valid signatures meet threshold.
    cases.push(json!({
        "name": "valid",
        "attestation": attestation_json(&attestation),
        "signatures": multisig(vec![("w1".into(), sig_w1.clone()), ("w2".into(), sig_w2.clone())]),
        "expect": "accept",
    }));

    // Rejected: below threshold (single signature).
    cases.push(json!({
        "name": "below_threshold",
        "attestation": attestation_json(&attestation),
        "signatures": multisig(vec![("w1".into(), sig_w1.clone())]),
        "expect": "reject",
    }));

    // Rejected: duplicate signer.
    cases.push(json!({
        "name": "duplicate_signer",
        "attestation": attestation_json(&attestation),
        "signatures": multisig(vec![("w1".into(), sig_w1.clone()), ("w1".into(), sig_w1.clone())]),
        "expect": "reject",
    }));

    // Rejected: unknown witness (id not present in the config).
    cases.push(json!({
        "name": "unknown_witness",
        "attestation": attestation_json(&attestation),
        "signatures": multisig(vec![("w1".into(), sig_w1.clone()), ("ghost".into(), sig_w3.clone())]),
        "expect": "reject",
    }));

    // Rejected: wrong key (signature made by a key not registered for w1).
    cases.push(json!({
        "name": "wrong_key",
        "attestation": attestation_json(&attestation),
        "signatures": multisig(vec![("w1".into(), sig_evil.clone()), ("w2".into(), sig_w2.clone())]),
        "expect": "reject",
    }));

    // Rejected: tampered message (attestation differs from what was signed).
    let tampered = Attestation {
        sequence: 999,
        ..attestation.clone()
    };
    cases.push(json!({
        "name": "tampered_message",
        "attestation": attestation_json(&tampered),
        "signatures": multisig(vec![("w1".into(), sig_w1.clone()), ("w2".into(), sig_w2.clone())]),
        "expect": "reject",
    }));

    json!({
        "version": VERSION,
        "threshold": threshold,
        "witnesses": witnesses,
        "cases": cases,
    })
}

/// §4.1.3 — BLS keygen (fixed IKM), sign, aggregate, aggregated verify;
/// rejected: DST mismatch, tampered aggregate, wrong signer set, invalid
/// subgroup encodings.
fn bls_vectors() -> Value {
    use blst::min_sig::SecretKey;

    // Fixed IKMs (no OsRng).
    let ikms: Vec<(String, [u8; 32])> = (1..=3).map(|i| (format!("w{i}"), [i as u8; 32])).collect();

    let keys: Vec<(String, SecretKey)> = ikms
        .iter()
        .map(|(id, ikm)| (id.clone(), SecretKey::key_gen(ikm, &[]).unwrap()))
        .collect();

    let keygen: Vec<Value> = keys
        .iter()
        .map(|(id, sk)| {
            json!({
                "name": id,
                "ikm_hex": hex::encode(ikms.iter().find(|(n, _)| n == id).unwrap().1),
                "secret_key_hex": hex::encode(sk.to_bytes()),
                "public_key_hex": hex::encode(sk.sk_to_pk().to_bytes()),
            })
        })
        .collect();

    let attestation = Attestation {
        hash: [0xCD; 32],
        timestamp: 1_700_000_000,
        network_id: "bls-net".to_string(),
        sequence: 9,
    };
    let msg = attestation.to_bytes();
    let dst: &[u8] = b"WITNESS_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_";

    let sigs: Vec<Vec<u8>> = keys
        .iter()
        .map(|(_, sk)| sk.sign(&msg, dst, &[]).to_bytes().to_vec())
        .collect();
    let pks: Vec<Vec<u8>> = keys
        .iter()
        .map(|(_, sk)| sk.sk_to_pk().to_bytes().to_vec())
        .collect();

    let aggregate = aggregate_signatures_bls(&sigs).unwrap();

    // Signature produced under a *different* DST — must fail the normal
    // (correct-DST) verifier.
    let wrong_dst_sig = keys[0].1.sign(&msg, b"WRONG_DST", &[]).to_bytes().to_vec();

    // Invalid subgroup encoding: the point at infinity (48 zero bytes) is not
    // a valid G1 signature under the subgroup check.
    let invalid_subgroup = vec![0u8; 48];

    let mut cases = Vec::new();

    // Accepted: single signature.
    cases.push(json!({
        "name": "valid_single",
        "attestation": attestation_json(&attestation),
        "signature": hex::encode(&sigs[0]),
        "public_key": hex::encode(&pks[0]),
        "expect": "accept",
    }));

    // Accepted: aggregated signature over all three keys.
    cases.push(json!({
        "name": "valid_aggregate",
        "attestation": attestation_json(&attestation),
        "aggregate_signature": hex::encode(&aggregate),
        "public_keys": pks.iter().map(hex::encode).collect::<Vec<_>>(),
        "expect": "accept",
    }));

    // Rejected: DST mismatch.
    cases.push(json!({
        "name": "wrong_dst",
        "attestation": attestation_json(&attestation),
        "signature": hex::encode(&wrong_dst_sig),
        "public_key": hex::encode(&pks[0]),
        "expect": "reject",
    }));

    // Rejected: tampered aggregate (flip a byte).
    let mut tampered = aggregate.clone();
    tampered[0] ^= 0x01;
    cases.push(json!({
        "name": "tampered_aggregate",
        "attestation": attestation_json(&attestation),
        "aggregate_signature": hex::encode(&tampered),
        "public_keys": pks.iter().map(hex::encode).collect::<Vec<_>>(),
        "expect": "reject",
    }));

    // Rejected: wrong signer set (aggregate verified against unrelated keys).
    let wrong_pks: Vec<Vec<u8>> = (0..3)
        .map(|i| {
            SecretKey::key_gen(&[0x90 + i as u8; 32], &[])
                .unwrap()
                .sk_to_pk()
                .to_bytes()
                .to_vec()
        })
        .collect();
    cases.push(json!({
        "name": "wrong_signer_set",
        "attestation": attestation_json(&attestation),
        "aggregate_signature": hex::encode(&aggregate),
        "public_keys": wrong_pks.iter().map(hex::encode).collect::<Vec<_>>(),
        "expect": "reject",
    }));

    // Rejected: invalid subgroup encoding.
    cases.push(json!({
        "name": "invalid_subgroup",
        "attestation": attestation_json(&attestation),
        "signature": hex::encode(&invalid_subgroup),
        "public_key": hex::encode(&pks[0]),
        "expect": "reject",
    }));

    json!({ "version": VERSION, "ikms": keygen, "cases": cases })
}

/// §4.1.4 — Merkle roots/inclusion/consistency for tree sizes 0..=17 plus
/// rejected inclusion cases.
fn merkle_vectors() -> Value {
    let mut trees = Vec::new();

    for size in 0..=17usize {
        let leaves: Vec<[u8; 32]> = (0..size).map(|i| [i as u8; 32]).collect();
        let root = merkle_tree_hash(&leaves);

        let mut tree = json!({
            "size": size,
            "leaves": leaves.iter().map(hex::encode).collect::<Vec<_>>(),
            "root": hex::encode(root),
        });

        if size > 0 {
            let inclusion: Vec<Value> = (0..size)
                .map(|i| {
                    let path = inclusion_path(i, &leaves).unwrap();
                    json!({
                        "leaf_index": i,
                        "siblings": path.iter().map(hex::encode).collect::<Vec<_>>(),
                    })
                })
                .collect();
            tree["inclusion"] = Value::Array(inclusion);

            let consistency: Vec<Value> = (1..size)
                .map(|first| {
                    let hashes = consistency_path(first, &leaves).unwrap();
                    json!({
                        "first_size": first,
                        "hashes": hashes.iter().map(hex::encode).collect::<Vec<_>>(),
                    })
                })
                .collect();
            tree["consistency"] = Value::Array(consistency);
        }

        trees.push(tree);
    }

    // Rejected inclusion cases (tree size 7, leaf index 3).
    let leaves7: Vec<[u8; 32]> = (0..7).map(|i| [i as u8; 32]).collect();
    let root7 = merkle_tree_hash(&leaves7);
    let path3 = inclusion_path(3, &leaves7).unwrap();
    let leaf3 = leaves7[3];

    let mut truncated = path3.clone();
    truncated.pop();

    let rejected = vec![
        json!({
            "name": "tampered_root",
            "leaf": hex::encode(leaf3),
            "leaf_index": 3,
            "tree_size": 7,
            "siblings": path3.iter().map(hex::encode).collect::<Vec<_>>(),
            "root": hex::encode([0xFFu8; 32]),
        }),
        json!({
            "name": "wrong_index",
            "leaf": hex::encode(leaf3),
            "leaf_index": 4,
            "tree_size": 7,
            "siblings": path3.iter().map(hex::encode).collect::<Vec<_>>(),
            "root": hex::encode(root7),
        }),
        json!({
            "name": "wrong_tree_size",
            "leaf": hex::encode(leaf3),
            "leaf_index": 3,
            "tree_size": 9,
            "siblings": path3.iter().map(hex::encode).collect::<Vec<_>>(),
            "root": hex::encode(root7),
        }),
        json!({
            "name": "truncated_path",
            "leaf": hex::encode(leaf3),
            "leaf_index": 3,
            "tree_size": 7,
            "siblings": truncated.iter().map(hex::encode).collect::<Vec<_>>(),
            "root": hex::encode(root7),
        }),
    ];

    json!({ "version": VERSION, "trees": trees, "rejected": rejected })
}

/// §4.1.5 — STH digest construction vectors + threshold-signed STHs per scheme.
fn sth_vectors() -> Value {
    let digests = vec![
        (
            "empty_network",
            TreeHead {
                network_id: String::new(),
                tree_size: 0,
                timestamp: 1_700_000_000,
                root_hash: [0x01; 32],
            },
        ),
        (
            "typical",
            TreeHead {
                network_id: "sth-net".to_string(),
                tree_size: 42,
                timestamp: 1_700_000_001,
                root_hash: [0x02; 32],
            },
        ),
        (
            "multibyte",
            TreeHead {
                network_id: "网络".to_string(),
                tree_size: 7,
                timestamp: 1_700_000_002,
                root_hash: [0x03; 32],
            },
        ),
    ];
    let digest_vectors: Vec<Value> = digests
        .into_iter()
        .map(|(name, th)| {
            json!({
                "name": name,
                "tree_head": tree_head_json(&th),
                "digest_hex": hex::encode(th.signing_digest()),
            })
        })
        .collect();

    // Ed25519 threshold-signed STH.
    let ed_keys: Vec<(String, SigningKey)> = (1..=3)
        .map(|i| {
            (
                format!("w{i}"),
                SigningKey::from_bytes(&[0x10 + i as u8; 32]),
            )
        })
        .collect();
    let ed_witnesses: Vec<Value> = ed_keys
        .iter()
        .map(|(id, sk)| {
            json!({
                "id": id,
                "pubkey": hex::encode(sk.verifying_key().as_bytes()),
                "endpoint": "http://localhost",
            })
        })
        .collect();
    let ed_head = TreeHead {
        network_id: "sth-ed25519".to_string(),
        tree_size: 5,
        timestamp: 1_700_000_010,
        root_hash: merkle_tree_hash(&[[0xAA; 32], [0xBB; 32], [0xCC; 32], [0xDD; 32], [0xEE; 32]]),
    };
    let ed_att = ed_head.to_attestation();
    let ed_sigs: Vec<WitnessSignature> = ed_keys[..2]
        .iter()
        .map(|(id, sk)| WitnessSignature {
            witness_id: id.clone(),
            signature: sk.sign(&ed_att.to_bytes()).to_bytes().to_vec(),
        })
        .collect();
    let ed_signed = SignedAttestation {
        attestation: ed_att,
        signatures: AttestationSignatures::MultiSig {
            signatures: ed_sigs,
        },
    };
    let ed_sth = witness_core::SignedTreeHead {
        tree_head: ed_head,
        signed_attestation: ed_signed,
    };

    // BLS threshold-signed STH.
    let bls_keys: Vec<(String, blst::min_sig::SecretKey)> = (1..=3)
        .map(|i| {
            (
                format!("w{i}"),
                blst::min_sig::SecretKey::key_gen(&[0x20 + i as u8; 32], &[]).unwrap(),
            )
        })
        .collect();
    let bls_witnesses: Vec<Value> = bls_keys
        .iter()
        .map(|(id, sk)| {
            json!({
                "id": id,
                "pubkey": hex::encode(sk.sk_to_pk().to_bytes()),
                "endpoint": "http://localhost",
            })
        })
        .collect();
    let bls_head = TreeHead {
        network_id: "sth-bls".to_string(),
        tree_size: 4,
        timestamp: 1_700_000_011,
        root_hash: merkle_tree_hash(&[[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32]]),
    };
    let bls_att = bls_head.to_attestation();
    let bls_msg = bls_att.to_bytes();
    let dst: &[u8] = b"WITNESS_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_";
    let bls_sigs: Vec<Vec<u8>> = bls_keys[..2]
        .iter()
        .map(|(_, sk)| sk.sign(&bls_msg, dst, &[]).to_bytes().to_vec())
        .collect();
    let bls_agg = aggregate_signatures_bls(&bls_sigs).unwrap();
    let bls_signed = SignedAttestation::new_with_aggregated(
        bls_att,
        bls_agg,
        vec!["w1".to_string(), "w2".to_string()],
    );
    let bls_sth = witness_core::SignedTreeHead {
        tree_head: bls_head,
        signed_attestation: bls_signed,
    };

    json!({
        "version": VERSION,
        "digests": digest_vectors,
        "ed25519": {
            "threshold": 2,
            "witnesses": ed_witnesses,
            "sth": serde_json::to_value(&ed_sth).unwrap(),
            "expect": "accept",
        },
        "bls": {
            "threshold": 2,
            "witnesses": bls_witnesses,
            "sth": serde_json::to_value(&bls_sth).unwrap(),
            "expect": "accept",
        },
    })
}

/// §4.1.6 — Wire encodings: both `AttestationSignatures` variants, hex
/// adapters, all enums, ambiguous/malformed union payloads.
fn wire_vectors() -> Value {
    // Valid MultiSig JSON.
    let multisig = json!({
        "signatures": [
            { "witness_id": "w1", "signature": "0102030405" },
            { "witness_id": "w2", "signature": "aabbcc" }
        ]
    });

    // Valid Aggregated JSON.
    let aggregated = json!({
        "signature": "deadbeef",
        "signers": ["w1", "w2", "w3"]
    });

    // Ambiguous: both shapes' keys present. Per the normative §3.5 rule this
    // must be a DecodeError (the Rust `AttestationSignatures` decoder now
    // rejects it), so it lives in `malformed[]`.
    let ambiguous = json!({
        "signatures": [ { "witness_id": "w1", "signature": "0102" } ],
        "signature": "deadbeef",
        "signers": ["w1"]
    });

    // Malformed payloads that genuinely fail to deserialize.
    let malformed_empty = json!({});
    let malformed_partial_aggregated = json!({ "signature": "deadbeef" });
    let malformed_partial_multisig = json!({ "signatures": "not-an-array" });
    let malformed_multisig_plus_signature = json!({ "signatures": [], "signature": "deadbeef" });
    let malformed_multisig_plus_signers = json!({ "signatures": [], "signers": ["w1"] });
    let malformed_aggregate_plus_signatures = json!({
        "signature": "deadbeef",
        "signers": ["w1"],
        "signatures": []
    });
    let malformed_bad_hex = json!({
        "signatures": [ { "witness_id": "w1", "signature": "ZZ" } ]
    });

    // Hex-adapter wire format, pinned through concrete types: an `Attestation`
    // (array32 hash) and a `WitnessSignature` (vec signature). The generator
    // serializes them so the stored JSON is exactly what serde emits.
    let att = Attestation {
        hash: [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff,
        ],
        timestamp: 1_700_000_000,
        network_id: "hex-net".to_string(),
        sequence: 1,
    };
    let ws = WitnessSignature {
        witness_id: "w1".to_string(),
        signature: vec![0xde, 0xad, 0xbe, 0xef],
    };

    // Hex decode rule (spec §3.4): decoders accept mixed-case hex and reject
    // odd-length strings and non-hex characters (matching `hex::decode`); all
    // emitters produce lowercase. `bytes` pins the decoded bytes; `reserialize`
    // pins that Rust re-serialization emits lowercase (a double assertion).
    let hex_decode_accept = vec![
        json!({
            "name": "uppercase",
            "input": "DEADBEEF",
            "bytes": "deadbeef",
            "reserialize": "deadbeef",
        }),
        json!({
            "name": "mixed_case",
            "input": "DeAdBeEf",
            "bytes": "deadbeef",
            "reserialize": "deadbeef",
        }),
    ];
    let hex_decode_reject = vec![
        json!({ "name": "odd_length", "input": "abc" }),
        json!({ "name": "non_hex", "input": "zz" }),
    ];

    json!({
        "version": VERSION,
        "multisig_json": multisig.to_string(),
        "aggregated_json": aggregated.to_string(),
        "malformed": [
            { "name": "empty", "json": malformed_empty.to_string(), "expect": "reject" },
            { "name": "partial_aggregated", "json": malformed_partial_aggregated.to_string(), "expect": "reject" },
            { "name": "partial_multisig", "json": malformed_partial_multisig.to_string(), "expect": "reject" },
            { "name": "multisig_plus_signature", "json": malformed_multisig_plus_signature.to_string(), "expect": "reject" },
            { "name": "multisig_plus_signers", "json": malformed_multisig_plus_signers.to_string(), "expect": "reject" },
            { "name": "aggregate_plus_signatures", "json": malformed_aggregate_plus_signatures.to_string(), "expect": "reject" },
            { "name": "bad_hex", "json": malformed_bad_hex.to_string(), "expect": "reject" },
            { "name": "ambiguous_both_shapes", "json": ambiguous.to_string(), "expect": "reject" }
        ],
        "enums": {
            "signature_scheme": { "ed25519": "ed25519", "bls": "bls" },
            "attestation_job_status": {
                "pending": "pending",
                "retryable": "retryable",
                "confirmed": "confirmed",
                "failed": "failed"
            }
        },
        "hex_adapters": {
            "array32": { "json": serde_json::to_string(&att).unwrap() },
            "vec": { "json": serde_json::to_string(&ws).unwrap() },
            "decode": {
                "accept": hex_decode_accept,
                "reject": hex_decode_reject
            }
        }
    })
}
