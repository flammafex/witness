// The `WitnessClient` HTTP surface and `PollConfig` polling semantics (§6.2).
//
// ESM-first, `fetch` injectable (Node 18+ and browsers), no Node-only APIs in
// the core path. The client performs **no** URL filtering — the gateway-side
// SSRF hardening protects server-initiated traffic, not client endpoint choice.

import type {
  AttestationJobResponse,
  AttestationJobStatus,
  ExternalAnchorProof,
  FreebirdToken,
  LogConsistencyProof,
  LogInclusionProofResponse,
  MerkleProofResponse,
  NetworkConfig,
  NetworkConfigPublic,
  ProofBundle,
  SignedAttestation,
  SignedTreeHead,
  VerifyResponse,
} from './types.generated.js';
import {
  ConfirmationTimeoutError,
  DecodeError,
  HttpStatusError,
  JobFailedError,
  NotFoundError,
  TransportError,
} from './errors.js';
import { subscribeEvents, type EventsSubscription, type SubscribeOptions } from './ws.js';

/** Freebird token input: a bare string is sugar for `{ tokenB64 }`. */
export type FreebirdTokenInput = string | { tokenB64: string };

/** Configuration for [`WitnessClient::waitForConfirmation`]. */
export type PollConfig = {
  /** Base polling interval (ms). Default 2000. */
  intervalMs?: number;
  /** Overall deadline for confirmation (ms). Default 180_000. */
  timeoutMs?: number;
  /** Abort signal; aborting stops polling. */
  signal?: AbortSignal;
};

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_POLL_INTERVAL_MS = 2_000;
const DEFAULT_POLL_TIMEOUT_MS = 180_000;

function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

function normalizeFreebirdToken(input?: FreebirdTokenInput): FreebirdToken | undefined {
  if (input === undefined) return undefined;
  if (typeof input === 'string') return { token_b64: input };
  return { token_b64: input.tokenB64 };
}

/**
 * A typed, keyless client for the Witness gateway.
 *
 * Covers the full attestation lifecycle, the transparency-log read surface,
 * optional WebSocket push events, and remote (non-authoritative) verification.
 */
export class WitnessClient {
  private readonly gatewayUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(config: { gatewayUrl: string; fetch?: typeof fetch; timeoutMs?: number }) {
    this.gatewayUrl = config.gatewayUrl.replace(/\/+$/, '');
    this.fetchImpl = config.fetch ?? globalThis.fetch;
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  private url(path: string): string {
    return `${this.gatewayUrl}${path}`;
  }

  private static assertHash(hash: Uint8Array): void {
    if (hash.length !== 32) {
      throw new TypeError(`expected a 32-byte hash, got ${hash.length} bytes`);
    }
  }

  /**
   * Perform an HTTP request and decode the JSON response.
   *
   * HTTP classification: 404 on a read endpoint → `NotFoundError`; any other
   * non-2xx → `HttpStatusError`. Transport failures → `TransportError`.
   * Undecodable bodies → `DecodeError`.
   */
  private async request<T>(url: string, init: RequestInit, read: boolean): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await this.fetchImpl(url, { ...init, signal: controller.signal });
    } catch (err) {
      throw new TransportError(err instanceof Error ? err.message : String(err));
    } finally {
      clearTimeout(timer);
    }

    if (!response.ok) {
      const body = await response.text().catch(() => '');
      if (read && response.status === 404) throw new NotFoundError(body);
      throw new HttpStatusError(response.status, body);
    }

    try {
      return (await response.json()) as T;
    } catch (err) {
      throw new DecodeError(err instanceof Error ? err.message : String(err));
    }
  }

  private sleep(ms: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      if (signal?.aborted) {
        reject(signal.reason ?? new DOMException('aborted', 'AbortError'));
        return;
      }
      const onAbort = () => {
        clearTimeout(timer);
        reject(signal?.reason ?? new DOMException('aborted', 'AbortError'));
      };
      const timer = setTimeout(() => {
        signal?.removeEventListener('abort', onAbort);
        resolve();
      }, ms);
      signal?.addEventListener('abort', onAbort, { once: true });
    });
  }

  // ========================================================================
  // Write path
  // ========================================================================

  /**
   * Submit a hash for attestation. Idempotent: duplicate hashes return the
   * canonical existing job.
   */
  async createAttestation(
    hash: Uint8Array,
    opts?: { freebirdToken?: FreebirdTokenInput },
  ): Promise<AttestationJobResponse> {
    WitnessClient.assertHash(hash);
    const body = {
      hash: toHex(hash),
      freebird_token: normalizeFreebirdToken(opts?.freebirdToken),
    };
    return this.request<AttestationJobResponse>(
      this.url('/v1/attestations'),
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      },
      false,
    );
  }

  // ========================================================================
  // Read path
  // ========================================================================

  /** Fetch the canonical attestation job for a hash. */
  async getAttestation(hash: Uint8Array): Promise<AttestationJobResponse> {
    WitnessClient.assertHash(hash);
    return this.request<AttestationJobResponse>(
      this.url(`/v1/attestations/${toHex(hash)}`),
      { method: 'GET' },
      true,
    );
  }

  /**
   * Poll `getAttestation` until the job reaches a terminal state.
   *
   * - `confirmed` with a `signed_attestation` → resolves with it.
   * - `confirmed` **without** a signed attestation is a protocol violation and
   *   throws `DecodeError` (never a silent success).
   * - `failed` → `JobFailedError`.
   * - Timeout → `ConfirmationTimeoutError` carrying the last status.
   * - `signal` abort stops polling.
   *
   * The effective sleep per iteration is `max(intervalMs, next_attempt_at -
   * now)` (honoring the server hint), clamped to the remaining timeout.
   */
  async waitForConfirmation(hash: Uint8Array, poll?: PollConfig): Promise<SignedAttestation> {
    WitnessClient.assertHash(hash);
    const intervalMs = poll?.intervalMs ?? DEFAULT_POLL_INTERVAL_MS;
    const timeoutMs = poll?.timeoutMs ?? DEFAULT_POLL_TIMEOUT_MS;
    const signal = poll?.signal;
    const start = Date.now();
    let lastStatus: AttestationJobStatus = 'pending';

    for (;;) {
      if (signal?.aborted) {
        throw signal.reason ?? new DOMException('aborted', 'AbortError');
      }
      const elapsed = Date.now() - start;
      if (elapsed >= timeoutMs) {
        throw new ConfirmationTimeoutError(lastStatus);
      }

      const job = await this.getAttestation(hash);
      lastStatus = job.status;

      if (job.status === 'confirmed') {
        if (!job.signed_attestation) {
          throw new DecodeError(
            `job for hash ${toHex(hash)} reported confirmed without a signed_attestation`,
          );
        }
        return job.signed_attestation;
      }
      if (job.status === 'failed') {
        throw new JobFailedError(job.attempts, job.last_error ?? undefined);
      }

      // pending / retryable
      const remaining = timeoutMs - elapsed;
      let sleepMs = intervalMs;
      if (job.next_attempt_at != null) {
        const hint = job.next_attempt_at * 1000 - Date.now();
        if (hint > sleepMs) sleepMs = hint;
      }
      sleepMs = Math.min(sleepMs, remaining);
      await this.sleep(sleepMs, signal);
    }
  }

  /** Fetch a self-contained `ProofBundle` for a hash. */
  async getBundle(hash: Uint8Array): Promise<ProofBundle> {
    WitnessClient.assertHash(hash);
    return this.request<ProofBundle>(this.url(`/v1/bundle/${toHex(hash)}`), { method: 'GET' }, true);
  }

  /** Fetch a Merkle inclusion proof for a hash. */
  async getProof(hash: Uint8Array): Promise<MerkleProofResponse> {
    WitnessClient.assertHash(hash);
    return this.request<MerkleProofResponse>(
      this.url(`/v1/proof/${toHex(hash)}`),
      { method: 'GET' },
      true,
    );
  }

  /**
   * Fetch external anchor proofs for a hash.
   *
   * An unknown attestation throws `NotFoundError` (404); a known but unbatched
   * attestation returns an empty list (200 with `[]`). The SDK does **not**
   * normalize 404 to empty.
   */
  async getAnchors(hash: Uint8Array): Promise<ExternalAnchorProof[]> {
    WitnessClient.assertHash(hash);
    return this.request<ExternalAnchorProof[]>(
      this.url(`/v1/anchors/${toHex(hash)}`),
      { method: 'GET' },
      true,
    );
  }

  /** Check gateway health (`{"status":"ok"}`). */
  async health(): Promise<void> {
    const value = await this.request<{ status?: string }>(this.url('/health'), { method: 'GET' }, true);
    if (value.status !== 'ok') {
      throw new DecodeError('unexpected health response');
    }
  }

  // ========================================================================
  // Config surfaces
  // ========================================================================

  /**
   * Fetch the public config (`GET /v1/config`).
   *
   * This is **informational only** (witness count, scheme, threshold). It is
   * **not** a trust anchor and is insufficient for verification — use
   * [`WitnessClient#network`] for a full witness pubkey set.
   */
  async publicConfig(): Promise<NetworkConfigPublic> {
    return this.request<NetworkConfigPublic>(this.url('/v1/config'), { method: 'GET' }, true);
  }

  /** Fetch the full `NetworkConfig` (`GET /v1/network`): the trust-anchor fetch. */
  async network(): Promise<NetworkConfig> {
    return this.networkFrom(this.gatewayUrl);
  }

  /**
   * Fetch a `NetworkConfig` from an arbitrary gateway URL — used to fetch peer
   * network configs for cross-anchor (Federated) verification.
   */
  async networkFrom(gatewayUrl: string): Promise<NetworkConfig> {
    const base = gatewayUrl.replace(/\/+$/, '');
    return this.request<NetworkConfig>(`${base}/v1/network`, { method: 'GET' }, true);
  }

  // ========================================================================
  // Transparency log
  // ========================================================================

  /** Latest signed tree head for the gateway's home network. */
  async sth(): Promise<SignedTreeHead> {
    return this.request<SignedTreeHead>(this.url('/v1/log/sth'), { method: 'GET' }, true);
  }

  /** Look up a historical STH at a specific tree size. */
  async sthAtSize(treeSize: number): Promise<SignedTreeHead> {
    return this.request<SignedTreeHead>(
      this.url(`/v1/log/sth/${treeSize}`),
      { method: 'GET' },
      true,
    );
  }

  /** Consistency proof linking two prior STHs (`first ≥ 1`, `first ≤ second`). */
  async consistency(first: number, second: number): Promise<LogConsistencyProof> {
    return this.request<LogConsistencyProof>(
      this.url(`/v1/log/consistency?first=${first}&second=${second}`),
      { method: 'GET' },
      true,
    );
  }

  /** RFC 9162 inclusion proof for `hash` against the STH at `treeSize`. */
  async logProof(hash: Uint8Array, treeSize: number): Promise<LogInclusionProofResponse> {
    WitnessClient.assertHash(hash);
    return this.request<LogInclusionProofResponse>(
      this.url(`/v1/log/proof?hash=${toHex(hash)}&tree_size=${treeSize}`),
      { method: 'GET' },
      true,
    );
  }

  // ========================================================================
  // Push (WebSocket)
  // ========================================================================

  /** Subscribe to attestation events over WebSocket (§6.4). */
  subscribeEvents(opts?: SubscribeOptions): EventsSubscription {
    return subscribeEvents(this.gatewayUrl, opts ?? { onEvent: () => {} });
  }

  // ========================================================================
  // Remote verification (non-authoritative)
  // ========================================================================

  /**
   * Ask the gateway to verify an attestation (`POST /v1/verify`).
   *
   * **Non-authoritative**: this is the gateway's opinion. Prefer local
   * verification for a trust-minimizing verdict.
   */
  async verifyRemote(signed: SignedAttestation): Promise<VerifyResponse> {
    return this.request<VerifyResponse>(
      this.url('/v1/verify'),
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ attestation: signed }),
      },
      false,
    );
  }
}
