import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api';

function response({ body, contentType = 'application/json', status = 200 }) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Not Found',
    headers: { get: name => name.toLowerCase() === 'content-type' ? contentType : null },
    text: vi.fn().mockResolvedValue(body),
  };
}

describe('API response handling', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    localStorage.setItem('token', 'test-token');
  });

  it('reports an HTML response clearly instead of exposing a JSON parse error', async () => {
    global.fetch = vi.fn().mockResolvedValue(
      response({ body: '<!doctype html><html><body>Vite</body></html>', contentType: 'text/html' }),
    );

    await expect(api.conversations()).rejects.toThrow(
      'Expected JSON from /conversations?limit=30&offset=0, but received HTML (HTTP 200). Check that the API server is running and the Vite proxy is configured.',
    );
  });

  it('decodes a successful JSON conversation response', async () => {
    global.fetch = vi.fn().mockResolvedValue(response({ body: '{"items":[]}' }));

    await expect(api.conversations()).resolves.toEqual({ items: [] });
  });
});
