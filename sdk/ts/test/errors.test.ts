import { describe, it, expect } from 'vitest';
import {
  WitnessError,
  TransportError,
  HttpStatusError,
  NotFoundError,
  JobFailedError,
  ConfirmationTimeoutError,
  DecodeError,
  VerificationError,
  AuthRequiredError,
} from '../src/errors';

describe('error hierarchy', () => {
  it('each error class carries the right code', () => {
    expect(new TransportError('x').code).toBe('transport');
    expect(new HttpStatusError(500, 'x').code).toBe('http');
    expect(new NotFoundError('x').code).toBe('not_found');
    expect(new JobFailedError(3, 'boom').code).toBe('job_failed');
    expect(new ConfirmationTimeoutError('pending').code).toBe('confirmation_timeout');
    expect(new DecodeError('x').code).toBe('decode');
    expect(new VerificationError('bad-signature').code).toBe('verification');
    expect(new AuthRequiredError().code).toBe('auth_required');
  });

  it('all errors are instances of WitnessError and Error', () => {
    const errors = [
      new TransportError('x'),
      new HttpStatusError(500, 'x'),
      new NotFoundError('x'),
      new JobFailedError(1),
      new ConfirmationTimeoutError('failed'),
      new DecodeError('x'),
      new VerificationError('sub-threshold'),
      new AuthRequiredError(),
    ];
    for (const e of errors) {
      expect(e).toBeInstanceOf(WitnessError);
      expect(e).toBeInstanceOf(Error);
    }
  });

  it('carries structured payloads', () => {
    const http = new HttpStatusError(503, 'busy');
    expect(http.status).toBe(503);
    expect(http.body).toBe('busy');

    const job = new JobFailedError(4, 'timeout');
    expect(job.attempts).toBe(4);
    expect(job.lastError).toBe('timeout');

    const timeout = new ConfirmationTimeoutError('retryable');
    expect(timeout.lastStatus).toBe('retryable');

    const verify = new VerificationError('duplicate-signer');
    expect(verify.reason).toBe('duplicate-signer');
  });

  it('VerificationFailureReason is a closed string union', () => {
    const reasons = [
      'sub-threshold',
      'duplicate-signer',
      'unknown-witness',
      'bad-signature',
      'index-size-mismatch',
      'ambiguous-signature-encoding',
    ] as const;
    for (const r of reasons) {
      expect(new VerificationError(r).reason).toBe(r);
    }
  });
});
