import { describe, it, expect, vi } from 'vitest';
import { WitnessClient } from '../src/client';
import {
  AbortError,
  ConfirmationTimeoutError,
  DecodeError,
  JobFailedError,
  NotFoundError,
} from '../src/errors';
import { mockFetch, HASH_32, HASH_HEX } from './helpers';
import type { AttestationJobResponse } from '../src/types.generated';
import { U64_MAX } from '../src/json';

const pendingJob = (over: Partial<AttestationJobResponse> = {}): AttestationJobResponse => ({
  attestation: {
    hash: HASH_HEX,
    timestamp: 1,
    network_id: 'net',
    sequence: 1,
  },
  status: 'pending',
  attempts: 1,
  ...over,
});

const confirmedJob = (): AttestationJobResponse =>
  pendingJob({
    status: 'confirmed',
    signed_attestation: {
      attestation: {
        hash: HASH_HEX,
        timestamp: 1,
        network_id: 'net',
        sequence: 1,
      },
      signatures: { signatures: [] },
    },
  });

describe('WitnessClient', () => {
  it('createAttestation posts hex hash + freebird_token wire shape', async () => {
    let captured: { url: string; body: unknown } | undefined;
    const fetchImpl = mockFetch({
      '/v1/attestations': async (req) => {
        captured = { url: req.url, body: await req.json() };
        return Response.json(confirmedJob(), { status: 200 });
      },
    });
    const client = new WitnessClient({ gatewayUrl: 'http://gw', fetch: fetchImpl });

    const job = await client.createAttestation(HASH_32, { freebirdToken: 'tok' });

    expect(job.status).toBe('confirmed');
    expect(captured?.url).toBe('http://gw/v1/attestations');
    expect(captured?.body).toEqual({ hash: HASH_HEX, freebird_token: { token_b64: 'tok' } });
  });

  it('createAttestation omits freebird_token when not provided', async () => {
    let body: unknown;
    const fetchImpl = mockFetch({
      '/v1/attestations': async (req) => {
        body = await req.json();
        return Response.json(pendingJob(), { status: 200 });
      },
    });
    const client = new WitnessClient({ gatewayUrl: 'http://gw', fetch: fetchImpl });
    await client.createAttestation(HASH_32);
    expect(body).toEqual({ hash: HASH_HEX });
  });

  it('createAttestation rejects a non-32-byte hash', async () => {
    const client = new WitnessClient({ gatewayUrl: 'http://gw', fetch: mockFetch({}) });
    await expect(client.createAttestation(new Uint8Array(4))).rejects.toThrow(TypeError);
  });

  it('getAttestation fetches the job for a hash', async () => {
    const fetchImpl = mockFetch({
      [`/v1/attestations/${HASH_HEX}`]: () => Response.json(confirmedJob(), { status: 200 }),
    });
    const client = new WitnessClient({ gatewayUrl: 'http://gw', fetch: fetchImpl });
    const job = await client.getAttestation(HASH_32);
    expect(job.status).toBe('confirmed');
  });

  it('waitForConfirmation resolves on pending -> confirmed', async () => {
    let calls = 0;
    const fetchImpl = mockFetch({
      [`/v1/attestations/${HASH_HEX}`]: () => {
        calls += 1;
        return Response.json(calls === 1 ? pendingJob() : confirmedJob(), { status: 200 });
      },
    });
    const client = new WitnessClient({ gatewayUrl: 'http://gw', fetch: fetchImpl });
    const signed = await client.waitForConfirmation(HASH_32, { intervalMs: 5, timeoutMs: 1000 });
    expect(signed.attestation.hash).toBe(HASH_HEX);
    expect(calls).toBe(2);
  });

  it('waitForConfirmation throws JobFailedError on failed', async () => {
    const fetchImpl = mockFetch({
      [`/v1/attestations/${HASH_HEX}`]: () =>
        Response.json(pendingJob({ status: 'failed', attempts: 3, last_error: 'boom' }), {
          status: 200,
        }),
    });
    const client = new WitnessClient({ gatewayUrl: 'http://gw', fetch: fetchImpl });
    await expect(client.waitForConfirmation(HASH_32, { intervalMs: 5, timeoutMs: 1000 })).rejects.toBeInstanceOf(
      JobFailedError,
    );
  });

  it('waitForConfirmation throws ConfirmationTimeoutError on timeout', async () => {
    const fetchImpl = mockFetch({
      [`/v1/attestations/${HASH_HEX}`]: () => Response.json(pendingJob(), { status: 200 }),
    });
    const client = new WitnessClient({ gatewayUrl: 'http://gw', fetch: fetchImpl });
    await expect(
      client.waitForConfirmation(HASH_32, { intervalMs: 5, timeoutMs: 30 }),
    ).rejects.toBeInstanceOf(ConfirmationTimeoutError);
  });

  it('waitForConfirmation deadline covers a hanging response body', async () => {
    const response = {
      ok: true,
      status: 200,
      text: () => new Promise<string>(() => {}),
    } as Response;
    const fetchImpl = vi.fn(async () => response) as unknown as typeof fetch;
    const client = new WitnessClient({ gatewayUrl: 'http://gw', fetch: fetchImpl });

    await expect(
      client.waitForConfirmation(HASH_32, { intervalMs: 1, timeoutMs: 20 }),
    ).rejects.toBeInstanceOf(ConfirmationTimeoutError);
  });

  it('waitForConfirmation throws DecodeError on confirmed without signed_attestation', async () => {
    const fetchImpl = mockFetch({
      [`/v1/attestations/${HASH_HEX}`]: () =>
        Response.json(pendingJob({ status: 'confirmed' }), { status: 200 }),
    });
    const client = new WitnessClient({ gatewayUrl: 'http://gw', fetch: fetchImpl });
    await expect(
      client.waitForConfirmation(HASH_32, { intervalMs: 5, timeoutMs: 1000 }),
    ).rejects.toBeInstanceOf(DecodeError);
  });

  it('waitForConfirmation aborts on signal', async () => {
    const controller = new AbortController();
    const fetchImpl = mockFetch({
      [`/v1/attestations/${HASH_HEX}`]: () => Response.json(pendingJob(), { status: 200 }),
    });
    const client = new WitnessClient({ gatewayUrl: 'http://gw', fetch: fetchImpl });
    const p = client.waitForConfirmation(HASH_32, {
      intervalMs: 1000,
      timeoutMs: 60_000,
      signal: controller.signal,
    });
    setTimeout(() => controller.abort(), 10);
    await expect(p).rejects.toBeInstanceOf(AbortError);
  });

  it('getAnchors throws NotFoundError on 404', async () => {
    const fetchImpl = mockFetch({
      [`/v1/anchors/${HASH_HEX}`]: () => new Response('unknown', { status: 404 }),
    });
    const client = new WitnessClient({ gatewayUrl: 'http://gw', fetch: fetchImpl });
    await expect(client.getAnchors(HASH_32)).rejects.toBeInstanceOf(NotFoundError);
  });

  it('getAnchors returns empty list on 200 []', async () => {
    const fetchImpl = mockFetch({
      [`/v1/anchors/${HASH_HEX}`]: () => Response.json([], { status: 200 }),
    });
    const client = new WitnessClient({ gatewayUrl: 'http://gw', fetch: fetchImpl });
    await expect(client.getAnchors(HASH_32)).resolves.toEqual([]);
  });

  it('network fetches from the configured gateway', async () => {
    const fetchImpl = mockFetch({
      '/v1/network': () =>
        Response.json({ id: 'net', threshold: 1, witnesses: [] }, { status: 200 }),
    });
    const client = new WitnessClient({ gatewayUrl: 'http://gw', fetch: fetchImpl });
    const cfg = await client.network();
    expect(cfg.id).toBe('net');
  });

  it('networkFrom fetches from an arbitrary gateway', async () => {
    const fetchImpl = mockFetch({
      '/v1/network': () =>
        Response.json({ id: 'peer', threshold: 2, witnesses: [] }, { status: 200 }),
    });
    const client = new WitnessClient({ gatewayUrl: 'http://gw', fetch: fetchImpl });
    const cfg = await client.networkFrom('http://peer.example');
    expect(cfg.id).toBe('peer');
  });

  it('verifyRemote posts to /v1/verify', async () => {
    let captured: { url: string; body: unknown } | undefined;
    const fetchImpl = mockFetch({
      '/v1/verify': async (req) => {
        captured = { url: req.url, body: await req.json() };
        return Response.json(
          { valid: true, verified_signatures: 1, required_signatures: 1, message: 'ok' },
          { status: 200 },
        );
      },
    });
    const client = new WitnessClient({ gatewayUrl: 'http://gw', fetch: fetchImpl });
    const signed = confirmedJob().signed_attestation!;
    const res = await client.verifyRemote(signed);
    expect(res.valid).toBe(true);
    expect(captured?.url).toBe('http://gw/v1/verify');
    expect(captured?.body).toEqual({ attestation: signed });
  });

  it('formats exact u64 log query values and rejects unsafe numbers', async () => {
    let requested = '';
    const fetchImpl = mockFetch({
      [`/v1/log/sth/${U64_MAX}`]: (request) => {
        requested = request.url;
        return new Response('{}', { status: 200 });
      },
    });
    const client = new WitnessClient({ gatewayUrl: 'http://gw', fetch: fetchImpl });

    await client.sthAtSize(U64_MAX);
    expect(requested).toBe(`http://gw/v1/log/sth/${U64_MAX}`);
    await expect(client.sthAtSize(Number.MAX_SAFE_INTEGER + 1)).rejects.toThrow(TypeError);
  });

  it('maps non-2xx to HttpStatusError and 404-on-read to NotFoundError', async () => {
    const fetchImpl = mockFetch({
      '/v1/config': () => new Response('nope', { status: 500 }),
      '/v1/log/sth': () => new Response('gone', { status: 404 }),
    });
    const client = new WitnessClient({ gatewayUrl: 'http://gw', fetch: fetchImpl });
    await expect(client.publicConfig()).rejects.toMatchObject({ code: 'http', status: 500 });
    await expect(client.sth()).rejects.toBeInstanceOf(NotFoundError);
  });

  it('maps transport failures to TransportError', async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;
    const client = new WitnessClient({ gatewayUrl: 'http://gw', fetch: fetchImpl });
    await expect(client.health()).rejects.toMatchObject({ code: 'transport' });
  });
});
