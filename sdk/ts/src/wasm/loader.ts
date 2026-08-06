// WASM module loader for the `@witness/sdk` local verifier.
//
// Loads `witness_core_wasm.wasm` (the compiled `witness-core` verification
// surface — the single trust root, spec §4.3 Path A) and wraps its
// `#[no_mangle]` extern "C" exports in a typed, ergonomic API.
//
// Works in Node 18+ (via `node:fs`) and browsers (via `fetch`). The `.wasm`
// binary is checked in next to this file and copied to `dist/wasm/` on build.

export type WasmResult<T> = { ok: T } | { err: { reason: string; message: string } };

interface WasmExports {
  memory: WebAssembly.Memory;
  alloc(len: number): number;
  dealloc(ptr: number, len: number): void;
  result_ptr(): number;
  result_len(): number;
  verify_signed_attestation(
    a: number,
    al: number,
    b: number,
    bl: number,
  ): number;
  verify_signed_tree_head(a: number, al: number, b: number, bl: number): number;
  verify_log_consistency(a: number, al: number, b: number, bl: number): number;
  verify_proof_bundle(
    a: number,
    al: number,
    b: number,
    bl: number,
    c: number,
    cl: number,
  ): number;
  verify_signature_bls(
    a: number,
    al: number,
    b: number,
    bl: number,
    c: number,
    cl: number,
  ): number;
  verify_aggregated_signature_bls(
    a: number,
    al: number,
    b: number,
    bl: number,
    c: number,
    cl: number,
  ): number;
  verify_inclusion(
    a: number,
    al: number,
    idx: bigint,
    size: bigint,
    b: number,
    bl: number,
    c: number,
    cl: number,
  ): number;
  verify_consistency(
    first: bigint,
    second: bigint,
    a: number,
    al: number,
    b: number,
    bl: number,
    c: number,
    cl: number,
  ): number;
  attestation_to_bytes(a: number, al: number): number;
  merkle_tree_hash(a: number, al: number): number;
  tree_head_digest(a: number, al: number): number;
  decode_attestation_signatures(a: number, al: number): number;
}

type Arg = { kind: 'bytes'; data: Uint8Array } | { kind: 'u64'; value: number };

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function bytes(s: string): Arg {
  return { kind: 'bytes', data: encoder.encode(s) };
}

function u64(value: number): Arg {
  return { kind: 'u64', value };
}

let cachedInstance: WebAssembly.Instance | null = null;
let cachedModule: WitnessCoreModule | null = null;

async function loadWasmBytes(): Promise<Uint8Array> {
  const url = new URL('./witness_core_wasm.wasm', import.meta.url);
  // Node 18+: `readFileSync` accepts a file URL.
  try {
    const { readFileSync } = await import('node:fs');
    return readFileSync(url);
  } catch {
    // Browser: fetch the module URL.
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`failed to fetch wasm module: ${res.status}`);
    }
    return new Uint8Array(await res.arrayBuffer());
  }
}

async function getInstance(): Promise<WebAssembly.Instance> {
  if (cachedInstance) return cachedInstance;
  const bytes = await loadWasmBytes();
  const { instance } = await WebAssembly.instantiate(bytes as BufferSource, {});
  cachedInstance = instance;
  return instance;
}

function invoke(exports: WasmExports, fnName: string, args: Arg[]): WasmResult<unknown> {
  const { memory, alloc, dealloc, result_ptr, result_len } = exports;
  const ptrs: number[] = [];
  try {
    const callArgs: (number | bigint)[] = [];
    for (const arg of args) {
      if (arg.kind === 'u64') {
        callArgs.push(BigInt(arg.value));
      } else {
        const ptr = alloc(arg.data.length);
        new Uint8Array(memory.buffer, ptr, arg.data.length).set(arg.data);
        ptrs.push(ptr);
        callArgs.push(ptr, arg.data.length);
      }
    }
    const fn = exports[fnName as keyof WasmExports] as (...a: (number | bigint)[]) => number;
    fn(...callArgs);
    const len = result_len();
    const ptr = result_ptr();
    const text = decoder.decode(new Uint8Array(memory.buffer, ptr, len));
    return JSON.parse(text) as WasmResult<unknown>;
  } finally {
    for (const ptr of ptrs) {
      dealloc(ptr, 0);
    }
  }
}

/** The typed WASM verification surface. */
export interface WitnessCoreModule {
  verifySignedAttestation(signedJson: string, configJson: string): WasmResult<number>;
  verifySignedTreeHead(sthJson: string, configJson: string): WasmResult<number>;
  verifyLogConsistency(proofJson: string, configJson: string): WasmResult<true>;
  verifyProofBundle(
    bundleJson: string,
    networkJson: string,
    peersJson: string,
  ): WasmResult<unknown>;
  verifySignatureBls(attestationJson: string, sigHex: string, pkHex: string): WasmResult<true>;
  verifyAggregatedSignatureBls(
    attestationJson: string,
    aggSigHex: string,
    pksJson: string,
  ): WasmResult<true>;
  verifyInclusion(
    leafHex: string,
    leafIndex: number,
    treeSize: number,
    siblingsJson: string,
    rootHex: string,
  ): WasmResult<boolean>;
  verifyConsistency(
    first: number,
    second: number,
    firstHashHex: string,
    secondHashHex: string,
    proofJson: string,
  ): WasmResult<boolean>;
  attestationToBytes(attestationJson: string): WasmResult<string>;
  merkleTreeHash(leavesJson: string): WasmResult<string>;
  treeHeadDigest(treeHeadJson: string): WasmResult<string>;
  decodeAttestationSignatures(json: string): WasmResult<unknown>;
}

/**
 * Load (once) and return the typed WASM verification module.
 *
 * The module is cached after the first load. Callers that need to guarantee
 * the module is ready before use should `await loadWitnessCore()`.
 */
export async function loadWitnessCore(): Promise<WitnessCoreModule> {
  if (cachedModule) return cachedModule;
  const instance = await getInstance();
  const exports = instance.exports as unknown as WasmExports;

  const module: WitnessCoreModule = {
    verifySignedAttestation(signedJson, configJson) {
      return invoke(exports, 'verify_signed_attestation', [
        bytes(signedJson),
        bytes(configJson),
      ]) as WasmResult<number>;
    },
    verifySignedTreeHead(sthJson, configJson) {
      return invoke(exports, 'verify_signed_tree_head', [
        bytes(sthJson),
        bytes(configJson),
      ]) as WasmResult<number>;
    },
    verifyLogConsistency(proofJson, configJson) {
      return invoke(exports, 'verify_log_consistency', [
        bytes(proofJson),
        bytes(configJson),
      ]) as WasmResult<true>;
    },
    verifyProofBundle(bundleJson, networkJson, peersJson) {
      return invoke(exports, 'verify_proof_bundle', [
        bytes(bundleJson),
        bytes(networkJson),
        bytes(peersJson),
      ]) as WasmResult<unknown>;
    },
    verifySignatureBls(attestationJson, sigHex, pkHex) {
      return invoke(exports, 'verify_signature_bls', [
        bytes(attestationJson),
        bytes(sigHex),
        bytes(pkHex),
      ]) as WasmResult<true>;
    },
    verifyAggregatedSignatureBls(attestationJson, aggSigHex, pksJson) {
      return invoke(exports, 'verify_aggregated_signature_bls', [
        bytes(attestationJson),
        bytes(aggSigHex),
        bytes(pksJson),
      ]) as WasmResult<true>;
    },
    verifyInclusion(leafHex, leafIndex, treeSize, siblingsJson, rootHex) {
      return invoke(exports, 'verify_inclusion', [
        bytes(leafHex),
        u64(leafIndex),
        u64(treeSize),
        bytes(siblingsJson),
        bytes(rootHex),
      ]) as WasmResult<boolean>;
    },
    verifyConsistency(first, second, firstHashHex, secondHashHex, proofJson) {
      return invoke(exports, 'verify_consistency', [
        u64(first),
        u64(second),
        bytes(firstHashHex),
        bytes(secondHashHex),
        bytes(proofJson),
      ]) as WasmResult<boolean>;
    },
    attestationToBytes(attestationJson) {
      return invoke(exports, 'attestation_to_bytes', [
        bytes(attestationJson),
      ]) as WasmResult<string>;
    },
    merkleTreeHash(leavesJson) {
      return invoke(exports, 'merkle_tree_hash', [
        bytes(leavesJson),
      ]) as WasmResult<string>;
    },
    treeHeadDigest(treeHeadJson) {
      return invoke(exports, 'tree_head_digest', [
        bytes(treeHeadJson),
      ]) as WasmResult<string>;
    },
    decodeAttestationSignatures(json) {
      return invoke(exports, 'decode_attestation_signatures', [
        bytes(json),
      ]) as WasmResult<unknown>;
    },
  };

  cachedModule = module;
  return module;
}

/**
 * Synchronously return the already-loaded WASM module, or `null` if it has
 * not been loaded yet. Used by the synchronous `WitnessVerifier` methods.
 */
export function getLoadedModule(): WitnessCoreModule | null {
  return cachedModule;
}
