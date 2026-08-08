import { describe, expect, it, vi } from 'vitest';
import type { LogInclusionProofResponse, U64 } from '../src/types.generated';
import { VerificationError } from '../src/errors';

vi.mock('../src/wasm/loader', () => ({
  getLoadedModule: () => ({
    verifySignedTreeHead: () => ({ ok: 1 }),
    verifyInclusion: () => ({ ok: true }),
  }),
  loadWitnessCore: async () => ({}),
}));

import { WitnessVerifier } from '../src/verify/index';

const HASH = '00'.repeat(32);

function makeProof(proofTreeSize: U64, sthTreeSize: U64): LogInclusionProofResponse {
  return {
    audit_path: [],
    leaf_index: 0,
    tree_size: proofTreeSize,
    sth: {
      tree_head: {
        network_id: 'net',
        root_hash: HASH,
        timestamp: 1,
        tree_size: sthTreeSize,
      },
      signed_attestation: {
        attestation: {
          hash: HASH,
          network_id: 'net',
          sequence: 1,
          timestamp: 1,
        },
        signatures: { signatures: [] },
      },
    },
  };
}

function verifier(): WitnessVerifier {
  return new WitnessVerifier({ id: 'net', threshold: 1, witnesses: [] });
}

describe('WitnessVerifier u64 tree-size comparison', () => {
  it('accepts equivalent safe-number and bigint tree sizes', () => {
    expect(() => verifier().verifyLogInclusion(makeProof(1, 1n), HASH)).not.toThrow();
    expect(() => verifier().verifyLogInclusion(makeProof(1n, 1), HASH)).not.toThrow();
  });

  it('still rejects mismatches and invalid u64 values', () => {
    expect(() => verifier().verifyLogInclusion(makeProof(1, 2n), HASH)).toThrow(
      VerificationError,
    );
    expect(() => verifier().verifyLogInclusion(makeProof(-1 as U64, 1), HASH)).toThrow(TypeError);
    expect(() =>
      verifier().verifyLogInclusion(makeProof(1, 18_446_744_073_709_551_616n), HASH),
    ).toThrow(TypeError);
  });
});
