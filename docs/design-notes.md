# Design notes

- The Access API field `self_hosted_domains` is deprecated (support ended 21 Nov 2025); the
  integration uses `destinations: [{type: "public", uri: …}]`.
- Nothing is derived from Home Assistant's router. An earlier design bypassed every endpoint
  registered without authentication and hand-listed the exceptions in both directions (the
  vendor endpoints that require a token, the session entry points that do not); the two lists
  were the only vendor knowledge in the code and are gone with the bypass.
- An earlier design relayed the Access cookie into the companion app around a bypassed login;
  with the login gated, the app obtains the cookie from Access itself and nothing needs
  relaying. The integration's domain, `cloudflare_access_relay`, dates from that design.
- The allow policy is derived from the Home Assistant users rather than entered, because the
  two lists mean the same thing (an address that is not a user cannot log in anyway) and an
  entered list drifts. A user without an address in the field cannot be a policy subject and
  is left out; the options page and the setup form show who is in.
- Signing in uses Cloudflare's self-managed OAuth clients, which exist on every plan. A client
  is private to the account that created it until its owner publishes it (name, logo, a
  client URL whose domain is verified by DNS), which this project has done, so the client ID
  ships in the code like any "Sign in with" integration's. Cloudflare's OAuth server offers no
  dynamic client registration, and creating a client through the API already needs an
  authenticated token, so a per-installation client could not be automatic.
- Registered clients are Access for SaaS applications because Google's and Amazon's consoles
  take a static client id and secret and fixed endpoints and offer no discovery or dynamic
  registration (checked against their documentation on 20 Sep 2026). MCP clients do both,
  through managed OAuth.
