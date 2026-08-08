// The single JSON codec used by the TypeScript SDK.
//
// Native JSON.parse cannot be used for Witness wire data: it rounds integer
// tokens before the caller gets a chance to inspect them.  lossless-json gives
// this codec the original number token, so no reviver (and no already-rounded
// JavaScript number) is involved in u64 handling.

import {
  isSafeNumber,
  parse,
  stringify,
  type NumberParser,
} from 'lossless-json';
import type { U64 } from './types.generated.js';
import { DecodeError } from './errors.js';

/** The largest value representable by a Rust `u64`. */
export const U64_MAX = 18_446_744_073_709_551_615n;

const MAX_SAFE_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);
const MIN_SAFE_BIGINT = -MAX_SAFE_BIGINT;
const INTEGER_TOKEN = /^(-?)(0|[1-9]\d*)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/;
const INTEGER_TOO_LARGE = Symbol('integer-too-large');
const U64_WIRE_KEYS = new Set([
  'anchor_period',
  'attestation_count',
  'batch_id',
  'batch_period',
  'first_size',
  'id',
  'leaf_index',
  'next_attempt_at',
  'period_end',
  'period_start',
  'second_size',
  'sequence',
  'timestamp',
  'tree_size',
]);

type ExactInteger = bigint | null | typeof INTEGER_TOO_LARGE;

/**
 * Return the exact integer represented by a JSON number token, if it is an
 * integer.  This also handles exponent notation without first converting to
 * a lossy JavaScript number.
 */
function exactInteger(token: string): ExactInteger {
  const match = token.match(INTEGER_TOKEN);
  if (!match) return null;

  const sign = match[1] === '-' ? -1 : 1;
  const whole = match[2];
  const fraction = match[3] ?? '';
  const exponentText = match[4];
  const exponent = exponentText === undefined ? 0 : Number(exponentText);

  // An exponent this large cannot describe a u64.  Avoid constructing a very
  // large temporary string for hostile input.
  if (!Number.isSafeInteger(exponent) || Math.abs(exponent) > 10_000) {
    return INTEGER_TOO_LARGE;
  }

  let digits = `${whole}${fraction}`.replace(/^0+/, '');
  if (digits.length === 0) return 0n;

  const shift = exponent - fraction.length;
  if (shift >= 0) {
    if (digits.length + shift > 20) return INTEGER_TOO_LARGE;
    digits += '0'.repeat(shift);
  } else {
    const fractionalDigits = -shift;
    if (fractionalDigits >= digits.length) return null;
    const split = digits.length - fractionalDigits;
    if (!/^0+$/.test(digits.slice(split))) return null;
    digits = digits.slice(0, split);
  }

  if (digits.length > 20) return INTEGER_TOO_LARGE;
  const value = BigInt(digits) * BigInt(sign);
  return value;
}

const parseWitnessNumber: NumberParser = (token) => {
  const integer = exactInteger(token);
  if (integer === INTEGER_TOO_LARGE) {
    throw new Error(`integer token is outside the supported u64 range: ${token}`);
  }

  if (integer !== null) {
    if (integer < MIN_SAFE_BIGINT) {
      throw new Error(`unsafe negative integer token: ${token}`);
    }
    if (integer < 0n) return Number(integer);
    if (integer > U64_MAX) {
      throw new Error(`integer token is outside the supported u64 range: ${token}`);
    }
    return integer <= MAX_SAFE_BIGINT ? Number(integer) : integer;
  }

  const number = Number(token);
  if (!Number.isFinite(number) || !isSafeNumber(token, { approx: false })) {
    throw new Error(`unsafe numeric token: ${token}`);
  }
  return number;
};

function validateSerializable(value: unknown, seen: Set<object>): void {
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
      throw new DecodeError(`unsafe JavaScript number: ${String(value)}`);
    }
    return;
  }

  if (typeof value === 'bigint') {
    if (value < 0n || value > U64_MAX) {
      throw new DecodeError(`invalid u64 bigint: ${value}`);
    }
    return;
  }

  if (value === null || typeof value !== 'object') return;
  if (seen.has(value)) throw new DecodeError('cannot serialize circular JSON');
  seen.add(value);

  if (typeof (value as { toJSON?: unknown }).toJSON === 'function') {
    validateSerializable((value as { toJSON: () => unknown }).toJSON(), seen);
  } else if (Array.isArray(value)) {
    for (const item of value) validateSerializable(item, seen);
  } else {
    for (const item of Object.values(value)) validateSerializable(item, seen);
  }
  seen.delete(value);
}

function validateU64WireFields(value: unknown): void {
  if (Array.isArray(value)) {
    for (const item of value) validateU64WireFields(item);
    return;
  }
  if (value === null || typeof value !== 'object') return;

  for (const [key, item] of Object.entries(value)) {
    if (U64_WIRE_KEYS.has(key)) {
      // `next_attempt_at` is the only nullable u64 in the public wire DTOs.
      if (item === null && key === 'next_attempt_at') continue;
      // Network and peer identifiers are also named `id`; those wire fields
      // are strings, while `AttestationBatch.id` is the numeric u64 variant.
      if (key === 'id' && typeof item === 'string') continue;
      if (typeof item === 'bigint') {
        if (item < 0n || item > U64_MAX) {
          throw new DecodeError(`${key} is outside the u64 range`);
        }
      } else if (
        typeof item !== 'number' ||
        !Number.isSafeInteger(item) ||
        item < 0
      ) {
        throw new DecodeError(`${key} must be a non-negative integer u64`);
      }
    }

    // External-anchor provider data is an opaque serde_json::Value. Its
    // numbers are not Witness u64 fields and must not be interpreted by this
    // structural check.
    if (key !== 'proof') validateU64WireFields(item);
  }
}

/**
 * Parse Witness JSON without losing numeric information.
 *
 * Safe integer tokens become `number`; exact positive integers above
 * `Number.MAX_SAFE_INTEGER` become `bigint` through `u64::MAX`.  Unsafe
 * numeric tokens are rejected rather than rounded.
 */
export function parseWitnessJson<T = unknown>(text: string): T {
  try {
    const value = parse(text, null, { parseNumber: parseWitnessNumber });
    validateU64WireFields(value);
    return value as T;
  } catch (error) {
    if (error instanceof DecodeError) throw error;
    throw new DecodeError(error instanceof Error ? error.message : String(error));
  }
}

/**
 * Serialize Witness JSON. Bigints are emitted as unquoted decimal tokens.
 * Unsafe JavaScript numbers are rejected before lossless-json sees them.
 */
export function stringifyWitnessJson(value: unknown): string {
  validateSerializable(value, new Set<object>());
  validateU64WireFields(value);
  try {
    const text = stringify(value);
    if (text === undefined) throw new Error('value is not JSON serializable');
    return text;
  } catch (error) {
    if (error instanceof DecodeError) throw error;
    throw new DecodeError(error instanceof Error ? error.message : String(error));
  }
}

/** Canonicalize raw JSON through the Witness codec before passing it onward. */
export function canonicalizeWitnessJson(text: string): string {
  return stringifyWitnessJson(parseWitnessJson(text));
}

/** Convert a generated `U64` value to an exact, canonical decimal token. */
export function formatU64(value: U64, field = 'u64'): string {
  if (typeof value === 'bigint') {
    if (value < 0n || value > U64_MAX) {
      throw new TypeError(`${field} must be an integer in [0, u64::MAX]`);
    }
    return value.toString(10);
  }
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${field} must be a safe integer in [0, u64::MAX]`);
  }
  return String(value);
}

/** Convert a generated `U64` value to bigint after validating its range. */
export function toBigIntU64(value: U64, field = 'u64'): bigint {
  return BigInt(formatU64(value, field));
}
