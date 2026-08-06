// §3.5 discriminating decoder for `AttestationSignatures`.
//
// The union is discriminated by key presence (matching `witness-core`'s
// explicit decoder in `signature_scheme.rs`):
//
// - a `signatures` array ⇒ MultiSig
// - both `signature` and `signers` ⇒ Aggregated
// - anything else (including payloads carrying *both* shapes' keys, partial
//   shapes, or neither) ⇒ `DecodeError`
//
// This is stricter than implicit JSON-schema union coercion and is the same
// rule the WASM verifier enforces when deserializing a `SignedAttestation`.
//
// Hex handling follows spec §3.4: decoders accept mixed-case hex and reject
// odd-length strings and non-hexadecimal characters (matching `hex::decode`);
// all emitters produce lowercase.

import { DecodeError } from './errors.js';

/** A single decoded multi-sig entry (signature as raw bytes). */
export interface DecodedWitnessSignature {
  witness_id: string;
  signature: Uint8Array;
}

/** The discriminated result of decoding an `AttestationSignatures` payload. */
export type DecodedAttestationSignatures =
  | { kind: 'multisig'; signatures: DecodedWitnessSignature[] }
  | { kind: 'aggregated'; signature: Uint8Array; signers: string[] };

function hexVal(c: number): number {
  if (c >= 0x30 && c <= 0x39) return c - 0x30; // 0-9
  if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10; // A-F
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10; // a-f
  return -1; // any non-hex char
}

/** Decode mixed-case hex; rejects odd-length and non-hex characters. */
export function decodeHex(s: string): Uint8Array {
  if (s.length % 2 !== 0) {
    throw new DecodeError(`invalid hex: odd length ${s.length}`);
  }
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < s.length; i += 2) {
    const hi = hexVal(s.charCodeAt(i));
    const lo = hexVal(s.charCodeAt(i + 1));
    if (hi < 0 || lo < 0) {
      throw new DecodeError('invalid hex: non-hexadecimal character');
    }
    out[i / 2] = (hi << 4) | lo;
  }
  return out;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function decodeWitnessSignature(v: unknown): DecodedWitnessSignature {
  if (!isRecord(v)) {
    throw new DecodeError('ambiguous or malformed attestation signatures');
  }
  if (typeof v.witness_id !== 'string' || typeof v.signature !== 'string') {
    throw new DecodeError('ambiguous or malformed attestation signatures');
  }
  return { witness_id: v.witness_id, signature: decodeHex(v.signature) };
}

/**
 * Decode an `AttestationSignatures` JSON payload per spec §3.5.
 *
 * Throws `DecodeError` for ambiguous, partial, or malformed payloads.
 */
export function decodeAttestationSignatures(json: string): DecodedAttestationSignatures {
  let obj: unknown;
  try {
    obj = JSON.parse(json);
  } catch {
    throw new DecodeError('invalid JSON');
  }
  if (!isRecord(obj)) {
    throw new DecodeError('ambiguous or malformed attestation signatures');
  }

  const hasSignatures = 'signatures' in obj;
  const hasSignature = 'signature' in obj;
  const hasSigners = 'signers' in obj;

  if (hasSignatures && !hasSignature && !hasSigners) {
    // MultiSig
    if (!Array.isArray(obj.signatures)) {
      throw new DecodeError('ambiguous or malformed attestation signatures');
    }
    return { kind: 'multisig', signatures: obj.signatures.map(decodeWitnessSignature) };
  }

  if (!hasSignatures && hasSignature && hasSigners) {
    // Aggregated
    if (typeof obj.signature !== 'string' || !Array.isArray(obj.signers)) {
      throw new DecodeError('ambiguous or malformed attestation signatures');
    }
    const signers = obj.signers.map((s) => {
      if (typeof s !== 'string') {
        throw new DecodeError('ambiguous or malformed attestation signatures');
      }
      return s;
    });
    return { kind: 'aggregated', signature: decodeHex(obj.signature), signers };
  }

  // Ambiguous (both shapes' keys), partial, or neither shape.
  throw new DecodeError('ambiguous or malformed attestation signatures');
}
