import { describe, expect, it } from 'vitest';
import {
  formatU64,
  parseWitnessJson,
  stringifyWitnessJson,
  U64_MAX,
} from '../src/json';
import { DecodeError } from '../src/errors';
import { loadWitnessCore } from '../src/wasm/loader';

describe('Witness JSON codec', () => {
  it('preserves the u64 boundaries without a reviver', () => {
    const value = parseWitnessJson<{
      zero: number;
      safe: number;
      above_safe: bigint;
      max: bigint;
    }>(
      `{"zero":0,"safe":9007199254740991,"above_safe":9007199254740992,"max":18446744073709551615}`,
    );

    expect(value.zero).toBe(0);
    expect(value.safe).toBe(Number.MAX_SAFE_INTEGER);
    expect(value.above_safe).toBe(BigInt(Number.MAX_SAFE_INTEGER) + 1n);
    expect(value.max).toBe(U64_MAX);
  });

  it('rejects unsafe numeric tokens and out-of-range integers', () => {
    expect(() => parseWitnessJson('9007199254740993.1')).toThrow(DecodeError);
    expect(() => parseWitnessJson('-9007199254740992')).toThrow(DecodeError);
    expect(() => parseWitnessJson('18446744073709551616')).toThrow(DecodeError);
    expect(() => parseWitnessJson('{"timestamp":-1}')).toThrow(DecodeError);
    expect(() => parseWitnessJson('{"tree_size":1.5}')).toThrow(DecodeError);
  });

  it('emits bigint as an unquoted decimal and rejects unsafe numbers', () => {
    expect(stringifyWitnessJson({ value: U64_MAX })).toBe(
      '{"value":18446744073709551615}',
    );
    expect(() => stringifyWitnessJson({ value: Number.MAX_SAFE_INTEGER + 1 })).toThrow(DecodeError);
    expect(() => formatU64(-1)).toThrow(TypeError);
    expect(() => formatU64(1.5)).toThrow(TypeError);
    expect(() => formatU64(Number.MAX_SAFE_INTEGER + 1)).toThrow(TypeError);
    expect(formatU64(0)).toBe('0');
    expect(formatU64(Number.MAX_SAFE_INTEGER)).toBe('9007199254740991');
    expect(formatU64(U64_MAX)).toBe('18446744073709551615');
  });

  it('keeps exact u64 tokens on the WASM JSON input path', async () => {
    const core = await loadWitnessCore();
    const result = core.attestationToBytes(
      `{"hash":"${'00'.repeat(32)}","timestamp":18446744073709551615,"network_id":"net","sequence":9007199254740993}`,
    );

    expect(result).toHaveProperty('ok');
    expect((result as { ok: string }).ok).toBe(
      `${'00'.repeat(32)}${'ff'.repeat(8)}030000006e65740100000000002000`,
    );
  });
});
