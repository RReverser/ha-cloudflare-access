# Cloudflare Access for Home Assistant

A Home Assistant custom integration that puts **Cloudflare Access in front of a whole Home
Assistant hostname**, with nothing carved out, and keeps every kind of client working:

- **People** log in to Access in the browser, and in the companion app, which shares the Access
  cookie between its WebView and its native requests (Android; see *iOS* below).
- **Token-bearing clients** (Google Assistant, Alexa, MCP clients such as Claude, your own
  scripts) authenticate **with Access** instead of Home Assistant: Access issues their tokens,
  validates them at the edge, and Home Assistant recognises the Access identity.
- **Nothing is bypassed** unless you list it. There is no built-in list of special paths.

The integration provisions the Access applications through the Cloudflare API, idempotently,
from its options; it never needs a change to the companion apps, to Home Assistant core, or to
any login integration.

Status: implementation complete with an automated test suite, and the Cloudflare behaviour it
depends on verified on a real account against Access applications created from the
integration's own code (see *Verified Cloudflare behaviour*). Not yet validated with a real
Google Home or Alexa link, nor on a real phone.

## Requirements

- Home Assistant 2026.9 or newer (tested against core 2026.9.2, Python 3.14).
- The hostname is served through Cloudflare (Cloudflare Tunnel or proxied DNS) and belongs to a
  zone in the account.
- A Zero Trust organization with an identity provider. Everything used is documented by
  Cloudflare without a plan restriction; managed OAuth is marked beta by Cloudflare.
- A Cloudflare **account-level API token** with two permissions: **Access: Apps and Policies:
  Edit** and **Access: Organizations, Identity Providers, and Groups: Read** (only to read the
  team domain). The integration stores it in the config entry and uses it for nothing else.
- Home Assistant users whose identity can be matched to the Access identity (by default: the
  built-in login username equals the identity provider e-mail; see *Options*).
- Behind Cloudflare, configure `http.use_x_forwarded_for` with Cloudflare's ranges as
  `trusted_proxies`, as for any reverse proxy, so Home Assistant's IP ban sees clients and not
  the edge.

## How it works

One Access application, the **gate**, covers the hostname. Its allow policy lists the people
(or an Access group) who may log in. Every request for the hostname goes through it: the
frontend, the login pages, the API, the WebSocket, webhooks, media, everything.

**Browsers and the companion app.** The browser lands on the Access login page, logs in with
the identity provider, then reaches Home Assistant's own login with the Access cookie set.
Home Assistant's login is unchanged (hass-openid or similar can make it single sign-on). The
Android companion app does the same in its WebView and sends the cookie with its native
requests too, so its API calls and its device webhook pass the gate.

**Token-bearing clients.** A client that cannot hold the cookie authenticates with Access,
which validates its token at the edge on every request and forwards the request to Home
Assistant with the same signed assertion a browser session gets. Access's own policies decide
who may link, and revoking a person in Access ends their clients at the next token refresh.
Two ways to obtain such a token, one mechanism behind both:

- **Clients that discover and register themselves** (MCP clients): the gate has *managed
  OAuth* enabled, which makes Access the OAuth server for the hostname. An unauthenticated
  non-browser request gets a 401 pointing at Access's discovery document at
  `/.well-known/oauth-authorization-server`; the client registers dynamically, sends the
  person through the Access login, and receives a token. Access accepts a dynamic registration
  only for redirect URIs listed in the option *Redirect URIs allowed for self-registering
  clients* (Claude: `https://claude.ai/api/mcp/auth_callback`).
- **Clients with a console that asks for a client id and secret** (Google Home account
  linking, an Alexa skill): *Add OAuth client* on the integration entry, with a name and the
  redirect URI the console shows. The integration creates an Access for SaaS OIDC application,
  which is that client's registration with Access, shows the client id, secret, authorization
  and token URLs to enter in the console, and adds a rule to the gate that accepts the tokens
  of that application. The client's refresh token lives as long as an Access session of the
  gate. Removing the client removes both. Nothing in the integration knows what Google or
  Alexa are; they need the same four values they need today when linked to Home Assistant
  directly, only now those values are Access's.

**At the origin**, one rule turns the edge identity into a Home Assistant user: a request that
came through Cloudflare for the hostname, carries a bearer Home Assistant did not accept, and
carries a valid Access assertion (verified against the team's public keys, issuer, audience
and expiry) is authenticated as the Home Assistant user whose configured field equals the
identity claim. No bearer, or a Home Assistant token: Home Assistant decides as usual. The
rule runs in a middleware that has to be installed before the web server starts, so the first
setup after installing the integration needs a restart, which a repair issue asks for; until
then Home Assistant rejects those requests with 401. Requests on the local network never see
the rule.

**Bypassed paths.** Callers that can hold neither a cookie nor a bearer, such as a third-party
service posting to a webhook or a media player fetching audio by signed URL from the public
hostname, stop working once the gate is on. If you need one, list its path prefix under
*Bypassed paths*; the integration then maintains a second, *bypass* application with those
paths. Nothing is bypassed by default, and nothing is detected: an attacker probing paths must
never turn into a suggestion to open them.

**iOS.** The iOS companion app never sends cookies with its native requests, so with the gate
on it can only render the WebView; sensors, location and notification actions do not reach
Home Assistant. Use Home Assistant in the browser on iOS, or a build of the app that presents
the WebView's cookies on native requests.

### What the integration creates in Cloudflare

Applications are named with the prefix `ha-access:` and looked up by name if the stored ids
are lost. They are the only objects the integration writes, and it is meant to be their only
writer; an application edited outside the integration is repaired on the next reload.

| Application | Exists | Destinations | Policies | Other |
|---|---|---|---|---|
| `ha-access: gate <host>` | while the gate is enabled | `<host>` | `allow` for the listed e-mails or group; *Service Auth* for listed service tokens; *Service Auth* accepting the tokens of every registered client | session duration from the options; binding cookie **off** (it would tie the cookie to the WebView alone); managed OAuth on, with dynamic registration for the listed redirect URIs |
| `ha-access: bypass <host>` | while *Bypassed paths* is non-empty | the listed paths | `bypass` for everyone | |
| `ha-access: client <host> <name>` | one per registered client | (SaaS OIDC application) | `allow`, same rule as the gate | authorization code and refresh token grants, refresh token lifetime = session duration, scopes `openid email profile` |

Cloudflare precedence: a more specific path rule wins over the hostname-wide application. That
is what makes the bypass list work; the live test asserts it on every run.

Removing the integration deletes every application it created (option, default on), which
restores the un-gated state. Turning the gate off in the options deletes the gate application
and keeps everything else.

## Installation

1. HACS → Integrations → three dots → *Custom repositories* → add this repository as an
   *Integration*, then install **Cloudflare Access**. Restart Home Assistant.
2. Settings → Devices & services → *Add integration* → **Cloudflare Access**.
3. Fill in the form: the Cloudflare API token (permissions above), the account ID (Cloudflare
   dashboard, right column of any zone overview), the hostname (pre-filled from the external
   URL), and the allowed e-mail addresses or an Access group ID.
4. The integration validates the token by reading the team domain and creates nothing yet:
   the gate starts **off**. Read *Rollout* before enabling it.

## Rollout

1. Gate off: run `tests/contract/check_edge.sh` with `MODE=off` (the script header lists its
   inputs) to confirm the hostname behaves as before.
2. Enable the gate in the options. **This is the exposure change.** Rollback is the same
   switch, or removing the integration. Run `check_edge.sh` with `MODE=gated`.
3. Browser: open the hostname, log in to Access, then to Home Assistant.
4. Android: add the server in the app, log in to Access in the app's WebView when it appears,
   then to Home Assistant. Confirm the dashboard, camera images and notification tap-throughs
   load, and that background sensor updates keep arriving (they use the device webhook, which
   is gated, so they prove the cookie travels with native requests). Every Access session
   expiry (the *Access session duration* option, default one month) brings the WebView back to
   the Access login page.
5. Re-link Google Assistant, Alexa and MCP clients against Access (see *Token-bearing
   clients*). Links made against Home Assistant's own OAuth stop working at the gate.
6. If something that neither logs in nor carries a token broke, list its path under *Bypassed
   paths*.

## Options

| Option | Default | Meaning |
|---|---|---|
| Gate the whole hostname | off | The exposure switch. On: the gate application covers the hostname. Off: no gate application |
| Allowed e-mail addresses / Access group ID | | Who the gate lets in, and who may link a registered client |
| Service token IDs allowed through the gate | empty | Adds a Service Auth policy so callers presenting `CF-Access-Client-Id/Secret` pass the gate. Used by the live tests; an alternative for your own machine callers |
| Access session duration | `720h` | Lifetime of an Access session, `<n>h` or `<n>m`, and of a registered client's refresh token. The dashboard offers up to one month; the API accepted `8760h` and Access honoured it (verified) |
| Redirect URIs allowed for self-registering clients | empty | `https://` URLs, optionally ending in `/*`, that a dynamically registering client may use. Without an entry here, managed OAuth registers no client |
| Bypassed paths | empty | Hostname-relative path prefixes reachable without Access. Nothing is bypassed unless listed |
| Identity claim | `email` | Claim of the Access assertion compared with the Home Assistant user |
| Home Assistant user field | `username` | Which user field must equal the claim (case-insensitive): `username` (built-in login), `name` (display name), or any credential field a login integration stores, e.g. `email` |
| Delete the Access applications when the integration is removed | on | Registered clients' applications included |

Changing the options reloads the entry and re-provisions; so does reloading the integration
(Settings → Devices & services → Cloudflare Access → Reload), which is the way to repair
applications edited outside the integration. Unchanged applications are never written.

Registered OAuth clients are subentries of the integration entry (*Add OAuth client*); each
stores its application id, client id and secret, and *Reconfigure* shows the credentials
again. For Google Home account linking enter the client id, client secret, authorization URL
and token URL shown; for an Alexa skill the same four under account linking, with credentials
in the request body.

## Verified Cloudflare behaviour

Verified on the test host below with Access applications created from the integration's own
provisioning code, and re-checked by `tests/live` in CI on every push to `main`.

| Assumption | Result |
|---|---|
| A path-specific bypass application takes precedence over the hostname-wide gate application, prefix inheritance included | verified 14 Sep 2026 |
| Token lifetime (`exp − iat`) equals the configured session duration; the API accepts and honours `8760h` | verified 14 Sep 2026 |
| The header token equals the cookie token | verified 14 Sep 2026 |
| Access accepts a `CF_Authorization` cookie obtained by another client (different User-Agent): the companion app's native client can reuse the WebView's cookie | verified 14 Sep 2026 |
| With *Binding Cookie* enabled a copied cookie is refused, so it must stay off | verified 14 Sep 2026 |
| Managed OAuth can be enabled through the API on the gate; Access then serves `/.well-known/oauth-authorization-server` on the hostname itself and answers a non-browser client with 401 + `WWW-Authenticate` | verified 20 Sep 2026 |
| An Access for SaaS OIDC application can be created through the API with the client secret returned once (a refresh-token lifetime is mandatory), its key endpoint goes live at the team domain within about a minute, and a `linked_app_token` rule naming it is accepted on the gate | verified 20 Sep 2026 |
| The gate refuses any write that still names a deleted application, so the rule must be dropped before the client's application is deleted | verified 20 Sep 2026 |
| A bearer Access admitted reaches the origin unchanged, with the assertion alongside; the origin rule accepts a real assertion against the real JWKS and refuses a tampered one | verified 20 Sep 2026 |
| A registered client's token, presented as a bearer on the hostname, passes the gate with an assertion whose audience is the gate's | **still open**: needs a real account-linking login (Google Home or Alexa) |
| The Android app's WebView completes the Access login and its native client sends the cookie | **still open**: needs a phone. The app's cookie support was added for Cloudflare Access; the origin side is covered by the tests |

Also observed: a service-token login answers with the application token both as the header and
as a `Set-Cookie`; its JWT carries `aud` as a string (identity logins use a list), `sub` empty
and `common_name` instead of `email`. The integration accepts both `aud` shapes.

### Test host

The live test needs no hostname of its own: it deploys the echo Worker in `tests/live/worker`
on the account's `workers.dev` subdomain under a run-scoped name, which Access accepts as an
application domain like any hostname, drives the integration through Home Assistant against
it with a run-scoped Access service token, and deletes the Worker, the token and every
application it created; a CI step that always runs afterwards (`tests/live/cleanup.py`)
deletes them by name even when the job was cancelled, and sweeps leftovers of older runs.
CI reads the credentials from the secrets `CF_API_TOKEN` (the two
Access permissions above plus **Access: Service Tokens: Edit** and **Workers Scripts: Edit**)
and `CF_ACCOUNT_ID`; without them the live job is skipped, as on forks.

## Security properties

- Access is the only way in from the public hostname: every path, including the login pages,
  requires an Access session, an Access-issued token, or a listed service token.
- Home Assistant's own authentication is untouched and still applies behind the gate: a
  browser or app session needs a Home Assistant login too (or single sign-on through a login
  integration), and a Home Assistant token alone does not pass the edge.
- The origin rule authenticates only requests that carry a bearer Home Assistant did not
  accept, and only with a valid assertion from the edge; it never authenticates a bare
  request. Fail closed: wrong signature, issuer, audience or expiry, an unknown key, a
  missing claim or an unmapped identity give a 401 with the reason logged at INFO. The
  assertion is never logged.
- Access issues, validates and revokes the tokens of Google, Alexa and MCP clients; Home
  Assistant issues them none.
- Bypassed paths are exactly what you listed; there is no discovery and no default.

## Out of scope by design

- No change to the companion apps, no custom headers, no core patch, no change to any login
  integration.
- No support for hand-maintained Access applications on the hostname: the integration assumes it
  is the only writer of the applications it names.
- LAN behaviour is unchanged: an internal URL never touches Cloudflare, and the origin rule
  stays silent when a request did not come through Cloudflare.
- Home Assistant sessions keep their own lifetime; the edge is the gate. If Access refuses a
  person, their browser and app break at the next request, and their token-bearing clients at
  their next token refresh.

## Development

```sh
uv sync
uv run pytest -q        # unit tests against a fake Cloudflare API and a fake JWKS
uv run ruff check . && uv run ruff format --check . && uv run mypy
CF_API_TOKEN=… CF_ACCOUNT_ID=… uv run pytest -q tests/live   # the real edge
```

## Publishing to HACS

The repository needs a description, topics and a LICENSE file before HACS accepts it; the
`hacs` CI job reports these until they exist.

## Design notes

- The Access API field `self_hosted_domains` is deprecated (support ended 21 Nov 2025); the
  integration uses `destinations: [{type: "public", uri: …}]`.
- Nothing is derived from Home Assistant's router. An earlier design bypassed every endpoint
  registered without authentication and hand-listed the exceptions in both directions (the
  vendor endpoints that require a token, the session entry points that do not); the two lists
  were the only vendor knowledge in the code and are gone with the bypass.
- An earlier design relayed the Access cookie into the companion app around a bypassed login;
  with the login gated, the app obtains the cookie from Access itself and nothing needs
  relaying. The integration's domain, `cloudflare_access_relay`, dates from that design.
- Registered clients are Access for SaaS applications because Google's and Amazon's consoles
  take a static client id and secret and fixed endpoints and offer no discovery or dynamic
  registration (checked against their documentation on 20 Sep 2026). MCP clients do both,
  through managed OAuth.
