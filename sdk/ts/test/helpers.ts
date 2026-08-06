// Shared test helpers: a mock `fetch` that routes by URL path.

export type RouteHandler = (req: Request) => Response | Promise<Response>;

export function mockFetch(routes: Record<string, RouteHandler>): typeof fetch {
  return async (input, init) => {
    const url = typeof input === 'string' ? input : input.url;
    const u = new URL(url);
    const key = u.pathname + u.search;
    const handler = routes[key];
    if (!handler) {
      return new Response(`no route for ${key}`, { status: 404 });
    }
    return handler(new Request(url, init));
  };
}

export const HASH_32 = new Uint8Array(32).fill(0xab);

export function hex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export const HASH_HEX = hex(HASH_32);
