// WebSocket push events (§6.4).
//
// Connects to `/ws/events` using the browser `WebSocket` API (available in
// Node 22+ and browsers). Implements the first-message auth handshake: the
// server may first send `{"type":"auth_required"}`, to which the client
// replies `{"token": ...}` within the server's 5s window. A close code of
// 4001 indicates an auth failure and is **not** retried.

import type { AttestationEvent } from './types.generated.js';
import { AuthRequiredError, DecodeError, TransportError, WitnessError } from './errors.js';

/** Options for [`subscribeEvents`]. */
export type SubscribeOptions = {
  /** Optional bearer token for the auth handshake. */
  token?: string;
  /** Abort signal; aborting closes the subscription. */
  signal?: AbortSignal;
  /** Reconnect policy. Default: infinite retries with exponential backoff + jitter. */
  reconnect?: { maxRetries?: number; baseDelayMs?: number };
  /** Called for each decoded `AttestationEvent`. */
  onEvent: (ev: AttestationEvent) => void;
  /** Called for non-fatal errors (decode failures, transport errors, auth failures). */
  onError?: (err: WitnessError) => void;
};

/** Handle returned by [`subscribeEvents`]; call `close()` to stop. */
export interface EventsSubscription {
  close(): void;
}

const AUTH_REQUIRED = 'auth_required';
const DEFAULT_BASE_DELAY_MS = 1_000;

function decodeMessage(data: unknown): string {
  if (typeof data === 'string') return data;
  if (data instanceof ArrayBuffer) return new TextDecoder().decode(data);
  if (ArrayBuffer.isView(data)) return new TextDecoder().decode(data);
  return String(data);
}

/**
 * Subscribe to attestation events over WebSocket.
 *
 * If `token` is supplied, performs the first-message auth handshake. A close
 * code of 4001 raises `AuthRequiredError` (no auto-retry). Other unexpected
 * closes are retried per the reconnect policy.
 */
export function subscribeEvents(gatewayUrl: string, opts: SubscribeOptions): EventsSubscription {
  const base = gatewayUrl.replace(/\/+$/, '');
  const url = `${base}/ws/events`;
  const maxRetries = opts.reconnect?.maxRetries ?? Infinity;
  const baseDelayMs = opts.reconnect?.baseDelayMs ?? DEFAULT_BASE_DELAY_MS;

  let closed = false;
  let retries = 0;
  let ws: WebSocket | null = null;

  const onAbort = () => close();
  opts.signal?.addEventListener('abort', onAbort, { once: true });

  function close(): void {
    if (closed) return;
    closed = true;
    opts.signal?.removeEventListener('abort', onAbort);
    ws?.close();
  }

  function connect(): void {
    if (closed) return;
    ws = new WebSocket(url);
    let authed = !opts.token; // without a token there is no handshake

    ws.onopen = () => {
      // Nothing to do; events (or an auth_required probe) arrive via onmessage.
    };

    ws.onmessage = (event) => {
      const data = decodeMessage(event.data);

      if (!authed) {
        // First message: perform the auth handshake.
        let value: unknown;
        try {
          value = JSON.parse(data);
        } catch {
          value = undefined;
        }
        if (
          value !== null &&
          typeof value === 'object' &&
          (value as { type?: unknown }).type === AUTH_REQUIRED
        ) {
          ws?.send(JSON.stringify({ token: opts.token ?? '' }));
          authed = true;
          return;
        }
        // The server did not require auth; treat this as a normal event.
        authed = true;
      }

      try {
        const ev = JSON.parse(data) as AttestationEvent;
        opts.onEvent(ev);
      } catch (err) {
        opts.onError?.(new DecodeError(err instanceof Error ? err.message : String(err)));
      }
    };

    ws.onclose = (event) => {
      if (closed) return;
      if (event.code === 4001) {
        opts.onError?.(new AuthRequiredError('authentication required (close code 4001)'));
        close();
        return;
      }
      if (retries >= maxRetries) {
        opts.onError?.(new TransportError('websocket closed unexpectedly'));
        close();
        return;
      }
      retries += 1;
      const delay = baseDelayMs * 2 ** (retries - 1) + Math.random() * baseDelayMs;
      setTimeout(connect, delay);
    };

    ws.onerror = () => {
      // `onclose` always follows `onerror`; nothing to do here.
    };
  }

  connect();
  return { close };
}
