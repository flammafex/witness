// Conformance gate (§4.2): runs every golden vector in `sdk/vectors/` against
// the TypeScript implementation (WASM verifier + explicit §3.5 decoder) and
// asserts **100% parity** with the expected accepted/rejected results.
//
// This is the release gate: the package is not releasable until this suite
// passes. The WASM module is the single trust root — no crypto is hand-ported
// to JS.

import { beforeAll, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadWitnessCore, type WitnessCoreModule } from '../src/wasm/loader';
import { decodeAttestationSignatures, decodeHex } from '../src/decode';
import { DecodeError } from '../src/errors';

const vectorsDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'vectors');

function loadVector(name: string): any {
  return JSON.parse(readFileSync(join(vectorsDir, name), 'utf8'));
}

function hex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

let core: WitnessCoreModule;

beforeAll(async () => {
  core = await loadWitnessCore();
});

function expectAccept(result: { ok?: unknown; err?: unknown }, label: string): void {
  expect(result, label).toHaveProperty('ok');
}

function expectReject(result: { ok?: unknown; err?: unknown }, label: string): void {
  expect(result, label).toHaveProperty('err');
}

describe('conformance: to_bytes (§4.1.1)', () => {
  it('matches every canonical-byte vector', () => {
    const v = loadVector('to_bytes.json');
    expect(v.version).toBe(2);
    for (const vec of v.vectors) {
      const result = core.attestationToBytes(JSON.stringify(vec.attestation));
      expect(result, `case ${vec.name}`).toMatchObject({ ok: vec.to_bytes_hex });
    }
  });
});

describe('conformance: ed25519 (§4.1.2)', () => {
  it('matches accepted + rejected cases', () => {
    const v = loadVector('ed25519.json');
    const config = {
      id: 'ed25519-net',
      witnesses: v.witnesses,
      threshold: v.threshold,
      signature_scheme: 'ed25519',
    };
    for (const case_ of v.cases) {
      const signed = {
        attestation: case_.attestation,
        signatures: { signatures: case_.signatures },
      };
      const result = core.verifySignedAttestation(
        JSON.stringify(signed),
        JSON.stringify(config),
      );
      if (case_.expect === 'accept') expectAccept(result, case_.name);
      else expectReject(result, case_.name);
    }
  });
});

describe('conformance: bls (§4.1.3)', () => {
  it('matches accepted + rejected cases', () => {
    const v = loadVector('bls.json');
    for (const case_ of v.cases) {
      const att = JSON.stringify(case_.attestation);
      const result = case_.aggregate_signature
        ? core.verifyAggregatedSignatureBls(
            att,
            case_.aggregate_signature,
            JSON.stringify(case_.public_keys),
          )
        : core.verifySignatureBls(att, case_.signature, case_.public_key);
      if (case_.expect === 'accept') expectAccept(result, case_.name);
      else expectReject(result, case_.name);
    }
  });
});

describe('conformance: merkle (§4.1.4)', () => {
  it('matches roots, inclusion, consistency for sizes 0..=17', () => {
    const v = loadVector('merkle.json');
    for (const tree of v.trees) {
      const leavesJson = JSON.stringify(tree.leaves);
      const rootResult = core.merkleTreeHash(leavesJson);
      expect(rootResult, `root for size ${tree.size}`).toMatchObject({ ok: tree.root });

      for (const p of tree.inclusion ?? []) {
        const res = core.verifyInclusion(
          tree.leaves[p.leaf_index],
          p.leaf_index,
          tree.size,
          JSON.stringify(p.siblings),
          tree.root,
        );
        expect(res, `inclusion idx ${p.leaf_index} size ${tree.size}`).toMatchObject({ ok: true });
      }

      for (const p of tree.consistency ?? []) {
        const oldRoot = core.merkleTreeHash(JSON.stringify(tree.leaves.slice(0, p.first_size)));
        expect(oldRoot).toHaveProperty('ok');
        const res = core.verifyConsistency(
          p.first_size,
          tree.size,
          (oldRoot as { ok: string }).ok,
          tree.root,
          JSON.stringify(p.hashes),
        );
        expect(res, `consistency first ${p.first_size} size ${tree.size}`).toMatchObject({
          ok: true,
        });
      }
    }
  });

  it('rejects tampered/wrong-index/wrong-size/truncated proofs', () => {
    const v = loadVector('merkle.json');
    for (const r of v.rejected) {
      const res = core.verifyInclusion(
        r.leaf,
        r.leaf_index,
        r.tree_size,
        JSON.stringify(r.siblings),
        r.root,
      );
      expect(res, `rejected ${r.name}`).toMatchObject({ ok: false });
    }
  });
});

describe('conformance: sth (§4.1.5)', () => {
  it('matches digest construction and threshold-signed STHs', () => {
    const v = loadVector('sth.json');
    for (const d of v.digests) {
      const res = core.treeHeadDigest(JSON.stringify(d.tree_head));
      expect(res, `digest ${d.name}`).toMatchObject({ ok: d.digest_hex });
    }
    for (const key of ['ed25519', 'bls']) {
      const sec = v[key];
      const config = {
        id: sec.sth.tree_head.network_id,
        witnesses: sec.witnesses,
        threshold: sec.threshold,
        signature_scheme: key,
      };
      const res = core.verifySignedTreeHead(JSON.stringify(sec.sth), JSON.stringify(config));
      expect(res, `${key} sth`).toHaveProperty('ok');
    }
  });
});

describe('conformance: wire (§4.1.6)', () => {
  it('decodes both AttestationSignatures variants', () => {
    const v = loadVector('wire.json');
    const ms = decodeAttestationSignatures(v.multisig_json);
    expect(ms.kind).toBe('multisig');
    const agg = decodeAttestationSignatures(v.aggregated_json);
    expect(agg.kind).toBe('aggregated');
  });

  it('rejects malformed/ambiguous union payloads (TS decoder)', () => {
    const v = loadVector('wire.json');
    for (const m of v.malformed) {
      expect(() => decodeAttestationSignatures(m.json), `malformed ${m.name}`).toThrow(DecodeError);
    }
  });

  it('TS decoder agrees with the WASM (single trust root) decoder', () => {
    const v = loadVector('wire.json');
    // Accepted shapes: both decoders accept.
    for (const json of [v.multisig_json, v.aggregated_json]) {
      expect(core.decodeAttestationSignatures(json)).toHaveProperty('ok');
      expect(() => decodeAttestationSignatures(json)).not.toThrow();
    }
    // Malformed shapes: both decoders reject.
    for (const m of v.malformed) {
      expect(core.decodeAttestationSignatures(m.json), `wasm malformed ${m.name}`).toHaveProperty(
        'err',
      );
    }
  });

  it('matches enum wire values', () => {
    const v = loadVector('wire.json');
    expect(v.enums.signature_scheme.ed25519).toBe('ed25519');
    expect(v.enums.signature_scheme.bls).toBe('bls');
    expect(v.enums.attestation_job_status.pending).toBe('pending');
    expect(v.enums.attestation_job_status.retryable).toBe('retryable');
    expect(v.enums.attestation_job_status.confirmed).toBe('confirmed');
    expect(v.enums.attestation_job_status.failed).toBe('failed');
  });

  it('hex adapters are lowercase hex on the wire', () => {
    const v = loadVector('wire.json');
    const a32 = JSON.parse(v.hex_adapters.array32.json);
    expect(a32.hash).toMatch(/^[0-9a-f]{64}$/);
    const vec = JSON.parse(v.hex_adapters.vec.json);
    expect(vec.signature).toMatch(/^[0-9a-f]+$/);
  });

  it('hex decode accepts mixed-case and rejects odd-length/non-hex', () => {
    const v = loadVector('wire.json');
    const decode = v.hex_adapters.decode;
    for (const a of decode.accept) {
      const decoded = decodeHex(a.input);
      expect(hex(decoded), `accept ${a.name} decoded bytes`).toBe(a.bytes);
      expect(hex(decoded), `accept ${a.name} re-serialization`).toBe(a.reserialize);
    }
    for (const r of decode.reject) {
      expect(() => decodeHex(r.input), `reject ${r.name}`).toThrow(DecodeError);
    }
  });
});
