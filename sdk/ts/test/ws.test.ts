import { afterEach, describe, expect, it, vi } from 'vitest';
import { AuthRequiredError } from '../src/errors';
import { subscribeEvents } from '../src/ws';

type MessageHandler = (event: { data: string }) => void;
type CloseHandler = (event: { code: number }) => void;

class MockWebSocket {
  static instances: MockWebSocket[] = [];
  onopen: (() => void) | null = null;
  onmessage: MessageHandler | null = null;
  onclose: CloseHandler | null = null;
  onerror: (() => void) | null = null;
  readonly sent: string[] = [];
  closed = false;

  constructor(_url: string) {
    MockWebSocket.instances.push(this);
  }

  send(value: string): void {
    this.sent.push(value);
  }

  close(): void {
    this.closed = true;
  }

  message(value: unknown): void {
    this.onmessage?.({ data: typeof value === 'string' ? value : JSON.stringify(value) });
  }

  closeUnexpectedly(): void {
    this.onclose?.({ code: 1006 });
  }
}

afterEach(() => {
  vi.useRealTimers();
  MockWebSocket.instances = [];
  delete (globalThis as { WebSocket?: unknown }).WebSocket;
});

function installWebSocketMock(): void {
  (globalThis as { WebSocket: unknown }).WebSocket = MockWebSocket;
}

describe('WebSocket authentication and reconnect state', () => {
  it('reports auth_required without a token and stops', () => {
    installWebSocketMock();
    const errors: unknown[] = [];
    const subscription = subscribeEvents('http://gw', {
      onEvent: () => {},
      onError: (error) => errors.push(error),
    });

    MockWebSocket.instances[0].message({ type: 'auth_required' });

    expect(errors[0]).toBeInstanceOf(AuthRequiredError);
    expect(MockWebSocket.instances[0].closed).toBe(true);
    subscription.close();
  });

  it('delivers the first event when a token is supplied but no challenge is sent', () => {
    installWebSocketMock();
    const events: unknown[] = [];
    subscribeEvents('http://gw', {
      token: 'secret',
      onEvent: (event) => events.push(event),
    });

    MockWebSocket.instances[0].message({ type: 'attestation', timestamp: 0 });

    expect(events).toEqual([{ type: 'attestation', timestamp: 0 }]);
    expect(MockWebSocket.instances[0].sent).toEqual([]);
  });

  it('replies to auth_required and then continues with events', () => {
    installWebSocketMock();
    const events: unknown[] = [];
    const subscription = subscribeEvents('http://gw', {
      token: 'secret',
      onEvent: (event) => events.push(event),
    });
    const socket = MockWebSocket.instances[0];

    socket.message({ type: 'auth_required' });
    socket.message({ type: 'attestation', timestamp: 0 });

    expect(socket.sent).toEqual(['{"token":"secret"}']);
    expect(events).toEqual([{ type: 'attestation', timestamp: 0 }]);
    subscription.close();
  });

  it('cancels a scheduled reconnect when closed', () => {
    vi.useFakeTimers();
    installWebSocketMock();
    const subscription = subscribeEvents('http://gw', {
      onEvent: () => {},
      reconnect: { baseDelayMs: 10 },
    });
    MockWebSocket.instances[0].closeUnexpectedly();
    subscription.close();
    vi.advanceTimersByTime(60_000);

    expect(MockWebSocket.instances).toHaveLength(1);
  });
});
