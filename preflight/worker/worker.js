/*
 * Pre-flight Worker (plan section 7). Deploy on a throwaway hostname that is
 * NOT Home Assistant, put a self-hosted Access application in front of it, and
 * run ../preflight.sh.
 *
 *   GET  /echo        -> request headers as JSON (gated)
 *   POST /setcookie   -> body {"v": "..."}; answers Set-Cookie: CF_Authorization=<v> (bypassed)
 *   GET  /page        -> static page with a link to /echo (bypassed)
 */
export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/echo") {
      const headers = {};
      for (const [k, v] of request.headers) headers[k] = v;
      return new Response(JSON.stringify({ headers }, null, 2), {
        headers: { "content-type": "application/json" },
      });
    }
    if (url.pathname === "/setcookie" && request.method === "POST") {
      const { v } = await request.json();
      return new Response(JSON.stringify({ ok: true }), {
        headers: {
          "content-type": "application/json",
          "set-cookie": `CF_Authorization=${v}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600`,
        },
      });
    }
    if (url.pathname === "/page") {
      return new Response(
        `<!doctype html><title>preflight</title><p>P7: tap the link. The system browser should open on the team domain and this page should stay.</p><p><a href="/echo">/echo (gated)</a></p>`,
        { headers: { "content-type": "text/html" } },
      );
    }
    return new Response("not found", { status: 404 });
  },
};
