//! WASM export surface for `witness-core` verification.
//!
//! This crate is the **single trust root** for the TypeScript `@witness/sdk`
//! local verifier (spec §4.3, Path A — WASM). It exposes the `witness-core`
//! verification functions to `wasm32-unknown-unknown` via a minimal
//! `#[no_mangle]` extern "C" ABI (no wasm-bindgen glue), so the resulting
//! module can be loaded from both Node 18+ and browsers with a small hand-rolled
//! loader (`sdk/ts/src/wasm/loader.ts`).
//!
//! # ABI
//!
//! Every exported function takes input byte buffers as `(ptr, len)` pairs into
//! the module's linear memory (allocated by the JS side via [`alloc`]) and
//! returns an `i32` status code. The JSON result is written to a module-global
//! buffer readable via [`result_ptr`] / [`result_len`]:
//!
//! - success: `{"ok": <value>}`
//! - failure: `{"err": {"reason": "<machine-readable>", "message": "<detail>"}}`
//!
//! No key generation is exposed here: verification never touches `OsRng`, so
//! the `getrandom` wasm limitation is irrelevant to this surface (the
//! `witness-core` `keygen` feature is disabled).

// These `#[no_mangle] extern "C"` exports are the FFI boundary: the JS loader
// (which allocates the buffers) guarantees the pointers are valid for the
// given lengths, so dereferencing them here is sound by contract.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::cell::RefCell;

use witness_core::{
    merkle::{
        merkle_tree_hash as core_merkle_tree_hash, verify_consistency as merkle_verify_consistency,
        verify_inclusion as merkle_verify_inclusion,
    },
    Attestation, AttestationSignatures, NetworkVerificationConfig, ProofBundle,
    ProofVerificationConfig, SignedAttestation, SignedTreeHead, TreeHead, WitnessError,
};

// ---------------------------------------------------------------------------
// Result buffer
// ---------------------------------------------------------------------------

thread_local! {
    static RESULT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Pointer to the JSON result buffer (valid until the next exported call).
#[no_mangle]
pub extern "C" fn result_ptr() -> *const u8 {
    RESULT.with(|r| r.borrow().as_ptr())
}

/// Length of the JSON result buffer.
#[no_mangle]
pub extern "C" fn result_len() -> usize {
    RESULT.with(|r| r.borrow().len())
}

fn set_result_json(json: String) -> i32 {
    RESULT.with(|r| {
        let mut r = r.borrow_mut();
        r.clear();
        r.extend_from_slice(json.as_bytes());
    });
    0
}

fn set_ok<T: serde::Serialize>(value: &T) -> i32 {
    match serde_json::to_string(&serde_json::json!({ "ok": value })) {
        Ok(json) => set_result_json(json),
        Err(e) => set_err("bad-signature", &e.to_string()),
    }
}

fn set_err(reason: &str, message: &str) -> i32 {
    let json = serde_json::json!({ "err": { "reason": reason, "message": message } });
    set_result_json(json.to_string())
}

/// Map a `witness-core` error to a machine-readable `VerificationFailureReason`
/// (spec §6.3) plus a human-readable message.
fn map_error(e: &WitnessError) -> (String, String) {
    let reason = match e {
        WitnessError::InvalidSignature => "bad-signature",
        WitnessError::InsufficientSignatures { .. } => "sub-threshold",
        WitnessError::InvalidPublicKey(_) => "bad-signature",
        WitnessError::InvalidVerificationConfig(_) => "invalid-config",
        WitnessError::NetworkIdMismatch { .. } => "wrong-network",
        WitnessError::WitnessNotFound(_) => "unknown-witness",
        WitnessError::DuplicateSigner(_) => "duplicate-signer",
        _ => "bad-signature",
    };
    (reason.to_string(), e.to_string())
}

fn set_witness_err(e: &WitnessError) -> i32 {
    let (reason, message) = map_error(e);
    set_err(&reason, &message)
}

// ---------------------------------------------------------------------------
// Memory allocator (JS side allocates input buffers)
// ---------------------------------------------------------------------------

/// Allocate `len` bytes in the module's linear memory; returns a pointer.
#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Free a buffer previously returned by [`alloc`].
#[no_mangle]
pub extern "C" fn dealloc(ptr: *mut u8, len: usize) {
    if len == 0 {
        return;
    }
    unsafe {
        let _ = Vec::from_raw_parts(ptr, 0, len);
    }
}

unsafe fn read_bytes(ptr: *const u8, len: usize) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }
    std::slice::from_raw_parts(ptr, len).to_vec()
}

unsafe fn read_str(ptr: *const u8, len: usize) -> String {
    String::from_utf8_lossy(&read_bytes(ptr, len)).into_owned()
}

fn hex_to_32(s: &str) -> Result<[u8; 32], String> {
    let b = hex::decode(s).map_err(|e| e.to_string())?;
    b.try_into().map_err(|_| "invalid 32-byte hex".to_string())
}

fn hex_vec(json: &str) -> Result<Vec<[u8; 32]>, String> {
    let arr: Vec<String> = serde_json::from_str(json).map_err(|e| e.to_string())?;
    arr.iter().map(|s| hex_to_32(s)).collect()
}

// ---------------------------------------------------------------------------
// Attestation verification
// ---------------------------------------------------------------------------

/// `verify_signed_attestation(signed_json, config_json) -> {"ok": count}`
#[no_mangle]
pub extern "C" fn verify_signed_attestation(
    signed_ptr: *const u8,
    signed_len: usize,
    config_ptr: *const u8,
    config_len: usize,
) -> i32 {
    let signed_json = unsafe { read_str(signed_ptr, signed_len) };
    let config_json = unsafe { read_str(config_ptr, config_len) };
    let signed: SignedAttestation = match serde_json::from_str(&signed_json) {
        Ok(v) => v,
        Err(e) => return set_err("ambiguous-signature-encoding", &e.to_string()),
    };
    let config: NetworkVerificationConfig = match serde_json::from_str(&config_json) {
        Ok(v) => v,
        Err(e) => return set_err("bad-signature", &e.to_string()),
    };
    match witness_core::verify_signed_attestation(&signed, &config) {
        Ok(count) => set_ok(&count),
        Err(e) => set_witness_err(&e),
    }
}

/// `verify_signed_tree_head(sth_json, config_json) -> {"ok": count}`
#[no_mangle]
pub extern "C" fn verify_signed_tree_head(
    sth_ptr: *const u8,
    sth_len: usize,
    config_ptr: *const u8,
    config_len: usize,
) -> i32 {
    let sth_json = unsafe { read_str(sth_ptr, sth_len) };
    let config_json = unsafe { read_str(config_ptr, config_len) };
    let sth: SignedTreeHead = match serde_json::from_str(&sth_json) {
        Ok(v) => v,
        Err(e) => return set_err("bad-signature", &e.to_string()),
    };
    let config: NetworkVerificationConfig = match serde_json::from_str(&config_json) {
        Ok(v) => v,
        Err(e) => return set_err("bad-signature", &e.to_string()),
    };
    match witness_core::verify_signed_tree_head(&sth, &config) {
        Ok(count) => set_ok(&count),
        Err(e) => set_witness_err(&e),
    }
}

/// `verify_log_consistency(proof_json, config_json) -> {"ok": true}`
#[no_mangle]
pub extern "C" fn verify_log_consistency(
    proof_ptr: *const u8,
    proof_len: usize,
    config_ptr: *const u8,
    config_len: usize,
) -> i32 {
    let proof_json = unsafe { read_str(proof_ptr, proof_len) };
    let config_json = unsafe { read_str(config_ptr, config_len) };
    let proof: witness_core::LogConsistencyProof = match serde_json::from_str(&proof_json) {
        Ok(v) => v,
        Err(e) => return set_err("bad-signature", &e.to_string()),
    };
    let config: NetworkVerificationConfig = match serde_json::from_str(&config_json) {
        Ok(v) => v,
        Err(e) => return set_err("bad-signature", &e.to_string()),
    };
    match witness_core::verify_log_consistency(&proof, &config) {
        Ok(()) => set_ok(&true),
        Err(e) => set_witness_err(&e),
    }
}

/// `verify_proof_bundle(bundle_json, network_json, peers_json) -> {"ok": ProofBundleVerification}`
#[no_mangle]
pub extern "C" fn verify_proof_bundle(
    bundle_ptr: *const u8,
    bundle_len: usize,
    network_ptr: *const u8,
    network_len: usize,
    peers_ptr: *const u8,
    peers_len: usize,
) -> i32 {
    let bundle_json = unsafe { read_str(bundle_ptr, bundle_len) };
    let network_json = unsafe { read_str(network_ptr, network_len) };
    let peers_json = unsafe { read_str(peers_ptr, peers_len) };
    let bundle: ProofBundle = match serde_json::from_str(&bundle_json) {
        Ok(v) => v,
        Err(e) => return set_err("bad-signature", &e.to_string()),
    };
    let network: NetworkVerificationConfig = match serde_json::from_str(&network_json) {
        Ok(v) => v,
        Err(e) => return set_err("bad-signature", &e.to_string()),
    };
    let peers: Vec<NetworkVerificationConfig> = match serde_json::from_str(&peers_json) {
        Ok(v) => v,
        Err(e) => return set_err("bad-signature", &e.to_string()),
    };
    let config = ProofVerificationConfig { network, peers };
    match witness_core::verify_proof_bundle(&bundle, &config) {
        Ok(result) => set_ok(&result),
        Err(e) => set_witness_err(&e),
    }
}

// ---------------------------------------------------------------------------
// BLS verification
// ---------------------------------------------------------------------------

/// `verify_signature_bls(attestation_json, sig_hex, pk_hex) -> {"ok": true}`
#[no_mangle]
pub extern "C" fn verify_signature_bls(
    att_ptr: *const u8,
    att_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
    pk_ptr: *const u8,
    pk_len: usize,
) -> i32 {
    let att_json = unsafe { read_str(att_ptr, att_len) };
    let sig_hex = unsafe { read_str(sig_ptr, sig_len) };
    let pk_hex = unsafe { read_str(pk_ptr, pk_len) };
    let attestation: Attestation = match serde_json::from_str(&att_json) {
        Ok(v) => v,
        Err(e) => return set_err("bad-signature", &e.to_string()),
    };
    let sig = match hex::decode(&sig_hex) {
        Ok(v) => v,
        Err(e) => return set_err("bad-signature", &e.to_string()),
    };
    let pk = match witness_core::decode_bls_public_key(&pk_hex) {
        Ok(v) => v,
        Err(e) => return set_witness_err(&e),
    };
    match witness_core::verify_signature_bls(&attestation, &sig, &pk) {
        Ok(()) => set_ok(&true),
        Err(e) => set_witness_err(&e),
    }
}

/// `verify_aggregated_signature_bls(attestation_json, agg_sig_hex, pks_json) -> {"ok": true}`
/// where `pks_json` is a JSON array of hex public keys.
#[no_mangle]
pub extern "C" fn verify_aggregated_signature_bls(
    att_ptr: *const u8,
    att_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
    pks_ptr: *const u8,
    pks_len: usize,
) -> i32 {
    let att_json = unsafe { read_str(att_ptr, att_len) };
    let sig_hex = unsafe { read_str(sig_ptr, sig_len) };
    let pks_json = unsafe { read_str(pks_ptr, pks_len) };
    let attestation: Attestation = match serde_json::from_str(&att_json) {
        Ok(v) => v,
        Err(e) => return set_err("bad-signature", &e.to_string()),
    };
    let sig = match hex::decode(&sig_hex) {
        Ok(v) => v,
        Err(e) => return set_err("bad-signature", &e.to_string()),
    };
    let pk_hexes: Vec<String> = match serde_json::from_str(&pks_json) {
        Ok(v) => v,
        Err(e) => return set_err("bad-signature", &e.to_string()),
    };
    let mut pks = Vec::with_capacity(pk_hexes.len());
    for h in &pk_hexes {
        match witness_core::decode_bls_public_key(h) {
            Ok(pk) => pks.push(pk),
            Err(e) => return set_witness_err(&e),
        }
    }
    match witness_core::verify_aggregated_signature_bls(&attestation, &sig, &pks) {
        Ok(()) => set_ok(&true),
        Err(e) => set_witness_err(&e),
    }
}

// ---------------------------------------------------------------------------
// Merkle verification
// ---------------------------------------------------------------------------

/// `verify_inclusion(leaf_hex, leaf_index, tree_size, siblings_json, root_hex) -> {"ok": bool}`
#[no_mangle]
pub extern "C" fn verify_inclusion(
    leaf_ptr: *const u8,
    leaf_len: usize,
    leaf_index: u64,
    tree_size: u64,
    siblings_ptr: *const u8,
    siblings_len: usize,
    root_ptr: *const u8,
    root_len: usize,
) -> i32 {
    let leaf_hex = unsafe { read_str(leaf_ptr, leaf_len) };
    let siblings_json = unsafe { read_str(siblings_ptr, siblings_len) };
    let root_hex = unsafe { read_str(root_ptr, root_len) };
    let leaf = match hex_to_32(&leaf_hex) {
        Ok(v) => v,
        Err(e) => return set_err("bad-signature", &e),
    };
    let siblings = match hex_vec(&siblings_json) {
        Ok(v) => v,
        Err(e) => return set_err("bad-signature", &e),
    };
    let root = match hex_to_32(&root_hex) {
        Ok(v) => v,
        Err(e) => return set_err("bad-signature", &e),
    };
    let ok = merkle_verify_inclusion(&leaf, leaf_index, tree_size, &siblings, &root);
    set_ok(&ok)
}

/// `verify_consistency(first, second, first_hash_hex, second_hash_hex, proof_json) -> {"ok": bool}`
#[no_mangle]
pub extern "C" fn verify_consistency(
    first: u64,
    second: u64,
    first_hash_ptr: *const u8,
    first_hash_len: usize,
    second_hash_ptr: *const u8,
    second_hash_len: usize,
    proof_ptr: *const u8,
    proof_len: usize,
) -> i32 {
    let first_hash_hex = unsafe { read_str(first_hash_ptr, first_hash_len) };
    let second_hash_hex = unsafe { read_str(second_hash_ptr, second_hash_len) };
    let proof_json = unsafe { read_str(proof_ptr, proof_len) };
    let first_hash = match hex_to_32(&first_hash_hex) {
        Ok(v) => v,
        Err(e) => return set_err("bad-signature", &e),
    };
    let second_hash = match hex_to_32(&second_hash_hex) {
        Ok(v) => v,
        Err(e) => return set_err("bad-signature", &e),
    };
    let proof = match hex_vec(&proof_json) {
        Ok(v) => v,
        Err(e) => return set_err("bad-signature", &e),
    };
    let ok = merkle_verify_consistency(first, second, &first_hash, &second_hash, &proof);
    set_ok(&ok)
}

// ---------------------------------------------------------------------------
// Digest / serialization helpers (used by the conformance gate)
// ---------------------------------------------------------------------------

/// `attestation_to_bytes(attestation_json) -> {"ok": "<hex>"}` — §3.1 canonical bytes.
#[no_mangle]
pub extern "C" fn attestation_to_bytes(att_ptr: *const u8, att_len: usize) -> i32 {
    let att_json = unsafe { read_str(att_ptr, att_len) };
    let attestation: Attestation = match serde_json::from_str(&att_json) {
        Ok(v) => v,
        Err(e) => return set_err("bad-signature", &e.to_string()),
    };
    set_ok(&hex::encode(attestation.to_bytes()))
}

/// `merkle_tree_hash(leaves_json) -> {"ok": "<hex>"}` — RFC 9162 MTH.
/// `leaves_json` is a JSON array of 32-byte hex leaves.
#[no_mangle]
pub extern "C" fn merkle_tree_hash(leaves_ptr: *const u8, leaves_len: usize) -> i32 {
    let leaves_json = unsafe { read_str(leaves_ptr, leaves_len) };
    let leaves = match hex_vec(&leaves_json) {
        Ok(v) => v,
        Err(e) => return set_err("bad-signature", &e),
    };
    set_ok(&hex::encode(core_merkle_tree_hash(&leaves)))
}

/// `tree_head_digest(tree_head_json) -> {"ok": "<hex>"}` — STH signing digest.
#[no_mangle]
pub extern "C" fn tree_head_digest(th_ptr: *const u8, th_len: usize) -> i32 {
    let th_json = unsafe { read_str(th_ptr, th_len) };
    let th: TreeHead = match serde_json::from_str(&th_json) {
        Ok(v) => v,
        Err(e) => return set_err("bad-signature", &e.to_string()),
    };
    set_ok(&hex::encode(th.signing_digest()))
}

// ---------------------------------------------------------------------------
// §3.5 discriminating decode
// ---------------------------------------------------------------------------/// `decode_attestation_signatures(json) -> {"ok": <decoded>}` or `{"err": ...}`.
///
/// Uses `witness-core`'s strict `AttestationSignatures` decoder (spec §3.5):
/// a `signatures` array ⇒ MultiSig; both `signature` + `signers` ⇒ Aggregated;
/// anything else (including both shapes' keys) is a `DecodeError`.
#[no_mangle]
pub extern "C" fn decode_attestation_signatures(json_ptr: *const u8, json_len: usize) -> i32 {
    let json = unsafe { read_str(json_ptr, json_len) };
    let decoded: AttestationSignatures = match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(e) => return set_err("ambiguous-signature-encoding", &e.to_string()),
    };
    set_ok(&decoded)
}
