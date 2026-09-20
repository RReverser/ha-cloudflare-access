/*
 * Test-host Worker: the origin the live tests talk to, on a hostname you own that is
 * served through Cloudflare (a route or a Workers custom domain). It answers every
 * request with its path, method and headers as JSON, so the tests can see what Access
 * forwarded. The Access applications in front of it are provisioned by the
 * integration's own code during the tests.
 */
export default {
  async fetch(request) {
    const url = new URL(request.url);
    const headers = {};
    for (const [k, v] of request.headers) headers[k] = v;
    return new Response(JSON.stringify({ path: url.pathname, method: request.method, headers }, null, 2), {
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  },
};
