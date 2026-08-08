// WebSocket push events (§6.4).
//
// Connects to `/ws/events` using the browser `WebSocket` API (available in
// Node 22+ and browsers). Implements the first-message auth handshake: the
// server may first send `{"type":"auth_required"}`, to which the client
// replies `{"token": ...}` within the server's 5s window. A close code of
// 4001 indicates an auth failure and is **not** retried.

import type { AttestationEvent } from './types.generated.js';
import { AuthRequiredError, DecodeError, TransportError, WitnessError } from './errors.js';
import { parseWitnessJson, stringifyWitnessJson } from './json.js';

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

function isAuthRequired(value: unknown): boolean {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    (value as { type?: unknown }).type === AUTH_REQUIRED
  );
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
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  const onAbort = () => close();
  opts.signal?.addEventListener('abort', onAbort, { once: true });

  function close(): void {
    if (closed) return;
    closed = true;
    opts.signal?.removeEventListener('abort', onAbort);
    if (reconnectTimer !== null) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    ws?.close();
  }

  function connect(): void {
    if (closed) return;
    ws = new WebSocket(url);
    let authReplied = false;

    ws.onopen = () => {
      // Nothing to do; events (or an auth_required probe) arrive via onmessage.
    };

    ws.onmessage = (event) => {
      const data = decodeMessage(event.data);

      try {
        const value = parseWitnessJson<unknown>(data);
        // Authentication is a protocol message, not an event. Recognize it
        // regardless of whether it is the first message and regardless of
        // whether the caller supplied a token.
        if (isAuthRequired(value)) {
          if (!opts.token) {
            opts.onError?.(new AuthRequiredError());
            close();
            return;
          }
          if (!authReplied) {
            ws?.send(stringifyWitnessJson({ token: opts.token }));
            authReplied = true;
          }
          return;
        }
        // A server that does not require authentication may send an event as
        // the first message even when a token was supplied.
        const ev = value as AttestationEvent;
        opts.onEvent(ev);
      } catch (err) {
        opts.onError?.(
          err instanceof WitnessError
            ? err
            : new DecodeError(err instanceof Error ? err.message : String(err)),
        );
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
      reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        connect();
      }, delay);
    };

    ws.onerror = () => {
      // `onclose` always follows `onerror`; nothing to do here.
    };
  }

  if (opts.signal?.aborted) close();
  else connect();
  return { close };
}
