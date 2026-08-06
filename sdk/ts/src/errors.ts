// Typed error model for `@witness/sdk` (§6.5).
//
// Every gateway failure mode a consumer must branch on is mapped to a typed
// error class; consumers never string-match on error messages.

import type { AttestationJobStatus } from './types.generated.js';

/** Machine-readable error codes for the whole SDK. */
export type WitnessErrorCode =
  | 'transport'
  | 'http'
  | 'not_found'
  | 'job_failed'
  | 'confirmation_timeout'
  | 'decode'
  | 'verification'
  | 'auth_required';

/** Machine-readable reason for a local verification failure (§6.3). */
export type VerificationFailureReason =
  | 'sub-threshold'
  | 'duplicate-signer'
  | 'unknown-witness'
  | 'bad-signature'
  | 'index-size-mismatch'
  | 'ambiguous-signature-encoding';

/** Base class for all SDK errors. */
export class WitnessError extends Error {
  readonly code: WitnessErrorCode;

  constructor(code: WitnessErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
    this.code = code;
  }
}

/** A transport-level failure (connect, TLS, timeout, abort, etc.). */
export class TransportError extends WitnessError {
  constructor(message: string, options?: ErrorOptions) {
    super('transport', message, options);
  }
}

/** The gateway returned a non-2xx status that is not a 404 on a read endpoint. */
export class HttpStatusError extends WitnessError {
  readonly status: number;
  readonly body: string;

  constructor(status: number, body: string) {
    super('http', `gateway returned ${status}: ${body}`);
    this.status = status;
    this.body = body;
  }
}

/** The gateway returned 404 on a read endpoint (e.g. unknown attestation). */
export class NotFoundError extends WitnessError {
  constructor(body: string) {
    super('not_found', `not found: ${body}`);
  }
}

/** An attestation job reached the terminal `failed` state. */
export class JobFailedError extends WitnessError {
  readonly attempts: number;
  readonly lastError?: string;

  constructor(attempts: number, lastError?: string) {
    super(
      'job_failed',
      `attestation job failed after ${attempts} attempt(s): ${lastError ?? 'unknown'}`,
    );
    this.attempts = attempts;
    this.lastError = lastError;
  }
}

/** `waitForConfirmation` exceeded its timeout before the job reached a terminal state. */
export class ConfirmationTimeoutError extends WitnessError {
  readonly lastStatus: AttestationJobStatus;

  constructor(lastStatus: AttestationJobStatus) {
    super('confirmation_timeout', `timed out waiting for confirmation; last status: ${lastStatus}`);
    this.lastStatus = lastStatus;
  }
}

/** The gateway returned a response that could not be decoded, or a protocol violation. */
export class DecodeError extends WitnessError {
  constructor(message: string) {
    super('decode', `failed to decode gateway response: ${message}`);
  }
}

/** Local verification failed (see `reason` for the machine-readable cause). */
export class VerificationError extends WitnessError {
  readonly reason: VerificationFailureReason;

  constructor(reason: VerificationFailureReason, message?: string) {
    super('verification', message ?? `verification failed: ${reason}`);
    this.reason = reason;
  }
}

/** WebSocket auth failed (close code 4001, or the token was wrong/absent). */
export class AuthRequiredError extends WitnessError {
  constructor(message = 'authentication required') {
    super('auth_required', message);
  }
}
