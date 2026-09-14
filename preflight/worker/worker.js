/*
 * Test-host Worker. Deployed as `test-host` on the permanent test hostname
 * (see README, "Test host"). It is the origin the live tests and the pre-flight
 * checks talk to; the Access applications in front of it are provisioned by the
 * integration's own code.
 *
 *   POST <any>/setcookie  -> answers Set-Cookie: CF_Authorization=<body.v>  (cookie passthrough check)
 *   GET  <any>/page       -> static page with a link to /api/echo            (browser check)
 *   <anything else>       -> request path, method and headers as JSON       (echo)
 */
export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname.endsWith("/setcookie") && request.method === "POST") {
      const { v } = await request.json();
      return new Response(JSON.stringify({ ok: true }), {
        headers: {
          "content-type": "application/json",
          "set-cookie": `CF_Authorization=${v}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600`,
        },
      });
    }
    if (url.pathname.endsWith("/page")) {
      return new Response(
        `<!doctype html><title>ha-cloudflare-access test host</title><p>Tap the link. The system browser should open on the team domain and this page should stay.</p><p><a href="/api/echo">/api/echo (gated)</a></p>`,
        { headers: { "content-type": "text/html" } },
      );
    }
    const headers = {};
    for (const [k, v] of request.headers) headers[k] = v;
    return new Response(JSON.stringify({ path: url.pathname, method: request.method, headers }, null, 2), {
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  },
};
