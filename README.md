# Cloudflare Access relay for the Home Assistant companion app

A Home Assistant custom integration that lets you put **Cloudflare Access in front of a whole
Home Assistant hostname, `/api/*` included**, while the companion app keeps working with no app
modification, no custom headers, no Home Assistant core patch and no change to any login
integration.

It does two things:

1. **Provisions the Cloudflare Access applications** the hostname needs (a *gate* and a
   *bypass*) through the Cloudflare API, idempotently, from your Home Assistant options.
2. **Relays the Access application token into the app.** The companion app hands the Access
   login redirect to the system browser, so the app itself never receives the
   `CF_Authorization` cookie. The relay captures the token Cloudflare forwards to Home Assistant
   after that browser login and hands it, once, to the app's own cookie jar. The app's WebView
   and its native HTTP client share one jar, so from then on every app request passes the gate.

Status: implementation complete with an automated test suite, and the Cloudflare behaviour it
depends on verified on a real account against Access applications created from the
integration's own code (see *Verified Cloudflare behaviour*). **Not yet validated on a real
device** (Android WebView handoff, iOS). Follow *Rollout* below in order.

## Requirements

- Home Assistant 2026.9 or newer (tested against core 2026.9.2, Python 3.14).
- The hostname is served through Cloudflare (Cloudflare Tunnel or proxied DNS) and belongs to a
  zone in the account.
- A Zero Trust organization with an identity provider.
- A Cloudflare **account-level API token** with two permissions: **Access: Apps and Policies:
  Edit** (the applications) and **Access: Organizations, Identity Providers, and Groups: Read**
  (only to read the team domain). The integration stores it in the config entry and uses it for
  nothing else.
- Home Assistant users whose identity can be matched to the Access identity (by default: the
  built-in login username equals the identity provider e-mail; see *Options*).

## How it works

```
app WebView ──GET /cloudflare_access_relay/connect (bypassed)──▶ HA: connect page
   │  page gets an HA token from the app bridge, POSTs /api/cloudflare_access_relay/flow
   │  (bypassed, HA auth) → flow id bound to the HA user
   │  user taps "Sign in with Cloudflare" → /cloudflare_access_relay/callback?flow=… (GATED)
   ▼
Cloudflare Access: 302 → https://<team>.cloudflareaccess.com  ── app hands it to the browser
   │  browser logs in (or passes straight through), returns to the callback path,
   │  Access forwards the request to HA with Cf-Access-Jwt-Assertion
   ▼
HA CallbackView: verifies the JWT against the team JWKS (RS256, issuer, audience, expiry),
   checks the identity claim matches the HA user who created the flow, stores the token
   under the flow, shows "Connected" with a deep link back into the app
   │
app WebView (still on the connect page, or reopened by the deep link):
   polls GET /api/cloudflare_access_relay/status?flow=… (bypassed, HA auth, same user)
   → 200 {"ok": true} + Set-Cookie: CF_Authorization=<jwt>; Path=/; Secure; HttpOnly; SameSite=Lax
   → the flow is wiped; the page reloads /
```

A frontend module (`relay.js`) loaded into the Home Assistant frontend asks
`/api/cloudflare_access_relay/session` how long the app's cookie is still valid. Inside the
companion app it sends the WebView to the connect page when there is no cookie, and shows a
banner (plus a persistent notification) when fewer than `renew_days` remain. In a browser it
does nothing: Access renews the browser's own cookie.

### What the integration creates in Cloudflare

Two self-hosted Access applications, named with the prefix `ha-relay:` and looked up by name
if the stored ids are lost. They are the only objects the integration writes, and it is meant
to be their only writer.

| Application | Destinations | Policy |
|---|---|---|
| `ha-relay: gate <host>` | gate **disabled**: `<host>/cloudflare_access_relay/callback` only. Gate **enabled**: `<host>` | `allow` for the listed e-mails, or an Access group |
| `ha-relay: bypass <host>` | the paths below | `bypass` for everyone |

Gate application settings: session duration from the options (default `720h`; Cloudflare's
ceiling is one month), binding cookie **off** (it would tie the token to the browser),
path cookie attribute off, HttpOnly on, SameSite lax, hidden from the App Launcher.

Bypassed paths (all are prefixes; Access inherits a path rule to everything below it):

| Path | Why |
|---|---|
| Every view Home Assistant registers **without its own authentication**, read from the router. In core that is the login surface (`/auth/login_flow`, `/auth/providers`, `/auth/token`, `/auth/revoke`, `/auth/external/callback`) and the inbound endpoints other systems call (`/api/webhook`, the TTS, stream, image and camera proxies, integration-specific receivers); login integrations add theirs (hass-openid's `/auth/openid/*`) | A client that can reach these has no Home Assistant session, so it cannot hold the Access cookie either. Each endpoint carries its own protection: a webhook id, a signed URL, a shared secret. Gating them would only break the callers |
| Every static file an integration serves from **its own package directory**, read from the router: the frontend's `/auth/authorize`, `/frontend_latest`, `/frontend_es5`, `/static`, service worker files, `/onboarding.html`, `/robots.txt`; a login integration's pages and scripts (hass-openid's `/openid/*`) | The login page and its assets are fetched before any cookie exists. Only code is bypassed: user content mounted from the configuration directory (`/local`, `/hacsfiles`) stays gated |
| `/cloudflare_access_relay/connect`, `/cloudflare_access_relay/static` | The connect page and the relay's own JavaScript |
| `/api/cloudflare_access_relay` | Flow creation, status poll, session check; every view there requires Home Assistant authentication |
| **except** `/api/webhook/<id>` of every companion-app device | Gated, not bypassed: the exact path goes on the gate application and beats the bypassed prefix (see *Companion-app device webhooks*) |
| *extra bypassed paths* option | Anything else a token-bearing external caller must reach, e.g. a Prometheus scraper on `/api/prometheus` |

Not bypassed although registered without authentication: the WebSocket, onboarding, the
Supervisor proxy and ingress, map tiles and the web manifest. They are entry points of the
frontend session, so the client always holds the cookie, and the relay's own callback must be
gated by definition. The OAuth discovery documents under `/.well-known/` stay gated too: Access
serves its own there (see *Token-bearing clients*). Everything else, including `/`, `/api/*`
(Google Assistant, Alexa and MCP endpoints included), `/api/websocket`, `/local/*`, `/media/*`
and `/hacsfiles/*`, is gated once the gate is enabled.

The router is read again once Home Assistant has finished starting and after every component
load, so an integration installed later (or set up after this entry during the same start) has
its endpoints bypassed within seconds without a reload; only a real change rewrites the
bypass application.

### Token-bearing clients

Google's and Amazon's servers, MCP clients and scripts authenticate with a bearer token and
can never hold the cookie. They are not bypassed: they authenticate **with Access**, which
issues them a token and validates it at the edge on every request, then forwards the request
to Home Assistant with the same signed assertion a browser session gets. Access's own policies
decide who may link, and revoking a person in Access ends their clients at the next token
refresh. Two ways to obtain such a token, one mechanism behind both:

- **Clients that discover and register themselves** (MCP clients such as Claude): the gate
  application has *managed OAuth* enabled, which makes Access the OAuth server for the
  hostname. An unauthenticated non-browser request gets a 401 pointing at Access's discovery
  document at `/.well-known/oauth-authorization-server`, the client registers dynamically,
  sends the person through the Access login, and receives a token. Access accepts a dynamic
  registration only for redirect URIs listed in the option *Redirect URIs allowed for
  self-registering clients* (Claude: `https://claude.ai/api/mcp/auth_callback`).
- **Clients with a console that asks for a client id and secret** (Google Home account
  linking, an Alexa skill): *Add OAuth client* on the integration entry, with a name and the
  redirect URI the console shows. The integration creates an Access for SaaS OIDC application,
  which is that client's registration with Access, shows the client id, secret, authorization
  and token URLs to enter in the console, and adds a rule to the gate that accepts the tokens
  of that application. Removing the client removes both. Nothing in the integration knows
  what Google or Alexa are.

At the origin, one rule turns the edge identity into a Home Assistant user: a request that
came through Cloudflare for the hostname, carries a bearer Home Assistant did not accept, and
carries a valid Access assertion is authenticated as the Home Assistant user whose configured
field equals the identity claim (the same mapping the relay uses). No bearer, or a Home
Assistant token: Home Assistant decides as usual. The rule runs in a middleware that has to be
installed before the web server starts, so the first setup after installing the integration
needs a restart, which a repair issue asks for; until then Home Assistant rejects those
requests with 401. Requests on the local network never see the rule.

Home Assistant's own OAuth server keeps serving the browser and the companion app on the
bypassed `/auth/*` paths; only the discovery documents move to Access, since a client that
finds Home Assistant's would obtain a Home Assistant token that the gate does not accept.
Links made before the integration was installed must be made again against Access.

### Companion-app device webhooks

The companion app reports location, sensors and events through `/api/webhook/<id>`, whose only
credential is the id in the URL, and that webhook accepts any service call and template. Every
other webhook caller is a foreign server that cannot hold the cookie, but the app can: the relay
gave it one, and the Android app sends it with every native request. So each registered
device's webhook path is added to the gate application, where its longer path wins over the
bypassed `/api/webhook` prefix, and the device webhook requires the Access cookie like the rest
of the app's traffic. Devices are read from the mobile_app entries and followed as they register
and unregister; the gate application is rewritten only when the set changes, and only while
the gate is enabled.

The iOS app never sends cookies with its native requests, so an iOS device's webhook stops
working once gated. On iOS use Home Assistant in the browser, or a build of the app that
presents the WebView's cookies on native requests.

Cloudflare precedence: a more specific path rule wins over the hostname-wide application, and
an exact path on the gate application wins over a bypassed prefix above it. That is what makes
the bypass list and the device-webhook exception work; the live test asserts both on every run.

Removing the integration deletes both applications (option, default on), which restores the
un-gated state. Flipping the gate off in the options takes seconds and keeps everything else.

## Installation

1. HACS → Integrations → three dots → *Custom repositories* → add this repository as an
   *Integration*, then install **Cloudflare Access Relay**. Restart Home Assistant.
2. Settings → Devices & services → *Add integration* → **Cloudflare Access Relay**.
3. Fill in the form:
   - **Cloudflare API token** (permissions above) and **account ID** (Cloudflare dashboard,
     right column of any zone overview).
   - **Hostname**, pre-filled from the external URL.
   - **Allowed e-mail addresses** (one per line) *or* an **Access group ID**.
   - Leave the advanced fields at their defaults unless you know why.
4. The integration validates the token by reading the team domain, then creates the two
   applications with the gate **disabled**: only the callback path is protected, nothing else
   changes. Read the *Rollout* section before enabling the gate.

## Options

| Option | Default | Meaning |
|---|---|---|
| Gate the whole hostname | off | The exposure switch. On: the gate application covers `<host>`. Off: it covers only the relay callback path |
| Allowed e-mail addresses / Access group ID | | Who the gate lets in |
| Extra bypassed paths | empty | Additional hostname-relative prefixes on the bypass application |
| Access session duration | `720h` | Lifetime of the application token, `<n>h` or `<n>m`. The dashboard offers up to one month; the API accepted `8760h` and Access honoured it (token valid 365 days, verified). Longer means fewer renewals in the app, which can only renew while it is open, against a longer-lived bearer token if a device is lost. Nothing else in the relay assumes a duration: cookie `Max-Age` and renewal timing come from the token's own `exp` |
| Service token IDs allowed through the gate | empty | Adds a Service Auth policy so callers presenting `CF-Access-Client-Id/Secret` pass the gate and receive an application token. Used by the live tests; also a safer alternative to bypassing a path for your own machine callers |
| Cookie name | `CF_Authorization` | Do not change unless Cloudflare does |
| Identity claim | `email` | JWT claim compared with the Home Assistant user |
| Home Assistant user field | `username` | Which user field must equal the claim (case-insensitive): `username` (built-in login), `name` (display name), or any credential field a login integration stores, e.g. `email` |
| Renew when fewer days remain | 3 | Lead time for the renewal banner and notification |
| Check interval | 60 min | How often an open frontend re-checks the session |
| Delete the Access applications when the integration is removed | on | Registered clients' applications included |
| Redirect URIs allowed for self-registering clients | empty | See *Token-bearing clients*. `https://` URLs, optionally ending in `/*` |

Registered OAuth clients are subentries of the integration entry (*Add OAuth client*); each
stores its application id, client id and secret, and *Reconfigure* shows the credentials
again.

Changing the options reloads the entry and re-provisions; so does reloading the integration
(Settings → Devices & services → Cloudflare Access Relay → Reload), which is the way to repair
applications edited outside the integration. Unchanged applications are never written.

## Verified Cloudflare behaviour

The design rests on a few facts about Cloudflare Access and the Android WebView that only a
real account and a real device can settle. The Cloudflare ones were verified on 14 Sep 2026 on
the test host below, with Access applications created from the integration's own provisioning
code, and are re-checked by `tests/live` in CI.

| Assumption | Result |
|---|---|
| An origin `Set-Cookie: CF_Authorization=…` passes through Cloudflare unmodified | verified: byte-identical |
| Access accepts a `CF_Authorization` cookie it did not set in that client | verified: token obtained by one client, presented as a cookie by another (different User-Agent, no other state) → 200, origin receives the same `Cf-Access-Jwt-Assertion` |
| Token lifetime (`exp − iat`) equals the configured session duration | verified for `1h` and `8760h` |
| The header token equals the cookie token | verified |
| With *Binding Cookie* enabled a copied cookie is refused, so it must stay off | verified: cookie alone → redirect to login |
| Session duration ceiling | the API accepts and honours `8760h`; the dashboard shows up to one month |
| A path-specific bypass application takes precedence over the hostname-wide gate application | verified, including prefix inheritance (`/api/cloudflare_access_relay/echo`) |
| An exact path on the gate application takes precedence over a bypassed prefix above it (`/api/webhook/<id>` under `/api/webhook`) | verified 19 Sep 2026, re-checked by `tests/live` |
| Managed OAuth can be enabled through the API on the gate application; Access then serves `/.well-known/oauth-authorization-server` on the hostname itself and answers a non-browser client with 401 + `WWW-Authenticate` | verified 20 Sep 2026, re-checked by `tests/live` |
| An Access for SaaS OIDC application can be created through the API with the client secret returned once, and a `linked_app_token` rule naming it is accepted on the gate application | verified 20 Sep 2026, re-checked by `tests/live` |
| A registered client's token, presented as a bearer on the hostname, passes the gate and reaches the origin with an assertion whose audience is the gate's | **still open**: needs a real account-linking login (Google Home or Alexa); the origin rule is exercised in the unit tests with a minted assertion |
| Access forwards the `CF_Authorization` cookie to the origin on bypassed paths (needed by the session endpoint) | verified |
| The relay's verifier accepts a real token against the real JWKS and rejects a wrong audience and a tampered signature | verified |
| The app's WebView hands only the Access redirect to the browser and stays on the page | **still open**. The app's WebView only loads its own server, so this is observed on the Home Assistant hostname itself during rollout step 3 (gate off, callback path gated): tap *Sign in with Cloudflare* on the connect page and watch whether the system browser opens while the app stays on the page. Either outcome works: if the WebView follows the redirect itself, the login lands the cookie in the shared jar directly |

Also observed: a service-token login answers with the application token both as the header and
as a `Set-Cookie`; its JWT carries `aud` as a string (identity logins use a list), `sub` empty
and `common_name` instead of `email`. The integration accepts both `aud` shapes.

### Test host

`test-host.example.com` is a permanent test hostname: a Cloudflare Worker
(`preflight/worker`, deployed as `test-host` with a Workers custom domain) that echoes
requests and answers `POST */setcookie` with a `CF_Authorization` cookie. The zone has one custom WAF rule scoped to this host that skips bot protection, so
curl and CI can reach it (the zone's Super Bot Fight Mode blocks automated clients otherwise;
Home Assistant's own machine paths are already exempted by an older rule). The Access
applications on it are the integration's `ha-relay:` pair; the live test puts its run-scoped
service token on the gate's Service Auth policy so it can log in without a browser.

`tests/live/test_live_edge.py` runs the whole lifecycle on every push, through Home Assistant
itself: it creates a run-scoped Access service token, sets the integration up via the config
flow (which provisions the applications), enables the gate via the options flow, checks the
edge behaviour above, relays a real token through the integration's own HTTP views and
uses the released cookie at the edge, injects drift and reloads the entry to repair it,
checks that a reload writes nothing, removes the entry with "delete objects" off so the
applications stay for the next run, and deletes the token. It needs two repository secrets
and is skipped without them:

| Secret | Value |
|---|---|
| `CF_API_TOKEN` | account token with *Access: Apps and Policies: Edit*, *Access: Organizations, Identity Providers, and Groups: Read* and *Access: Service Tokens: Edit* |
| `CF_ACCOUNT_ID` | the Cloudflare account id |

The test host and the placeholder address on its allow policy are fixed in the test; the test
logs in with its run-scoped service token, so nobody can open the test host in a browser.

`preflight/preflight.sh` is the same set of checks for a shell with curl.

## Rollout

1. Everything automatable is verified (see *Verified Cloudflare behaviour*); the WebView
   handoff is observed in step 3.
2. Install the integration and complete the config flow with the gate **off**. Run
   `tests/contract/check_edge.sh` with `MODE=staged` (header of the script lists the inputs).
3. Android, gate still off: sign in to the app, confirm the connect page appears, tap *Sign in
   with Cloudflare* (the system browser should open on the team domain and the app should stay
   on the connect page), complete the login, come back, confirm the page reports
   "Connected". Only the callback path is gated at this point, so nothing else can break, and
   removing the entry undoes everything.
4. Enable the gate in the options. Run `check_edge.sh` with `MODE=gated`. **This is the exposure
   change.** Rollback is the same switch, or removing the integration.
   Re-link Google Assistant, Alexa and MCP clients against Access (see *Token-bearing
   clients*); links made against Home Assistant's own OAuth stop working at the gate.
5. Device acceptance, gate on: dashboard, HACS panel, camera images and notification
   tap-throughs load; the device's refresh token `last_used_ip` keeps updating; kill and
   relaunch the app, background sensor updates (which arrive on the device's gated
   `/api/webhook/<id>`, so they prove the cookie travels with native requests) continue.
   `check_edge.sh` with `DEVICE_WEBHOOK=<id>` confirms the path is gated at the edge.
6. Expiry rehearsal: set the session duration to `15m`, wait, confirm the banner and the
   notification appear and that *Connect* restores service. Set the duration back.

`tests/contract/check_edge.sh` probes the Home Assistant hostname itself; note that the zone's
bot protection blocks curl on paths outside the existing machine-path exemption, so probe those
from a browser or extend the exemption for the duration of the check.

iOS: **unverified.** Whether the iOS app shares `WKWebView`'s cookie store with `URLSession`,
and whether its in-app browser hands the Access redirect out and returns, must be tested with
steps 3 and 5 on an iPhone before any household with an iPhone gates the hostname.

## Recovery when a device is locked out

If the app's token expires while the app is closed (the renewal needs the frontend open), the
app's requests get 302s and the frontend cannot load. The connect page is bypassed, so it can
still be reached inside the app:

- open a browser on the phone, log in to the Home Assistant hostname (Cloudflare Access
  will prompt), then open the link `homeassistant://navigate/cloudflare_access_relay/connect`
  — for example from a bookmark or a note; or
- open `https://<host>/cloudflare_access_relay/connect` in the app's WebView through any
  notification action or dashboard link that targets that relative URL.

The connect page obtains a Home Assistant token from the app's own bridge (the same call the
frontend uses), so no password is needed; if no bridge is available it falls back to Home
Assistant's own login page. Everything it needs is bypassed.

## Security properties

- The relayed JWT is a bearer credential for the whole hostname. It is released only to an
  authenticated Home Assistant request whose user created the flow, exactly once, and the
  flow is then wiped. Flow ids are 256-bit random values that live ten minutes.
- Fail closed: no `Cf-Access-Jwt-Assertion` header, bad signature, wrong audience or issuer,
  unknown key, non-RS256 algorithm, expired token, identity mismatch: no cookie, a readable
  error page naming the likely cause, an INFO log with the reason and `kid`, a persistent
  notification. The token itself is never logged or shown.
- The session endpoint reports the expiry only; the token never appears in a response body.
- The cookie is host-only, `Secure`, `HttpOnly`, `SameSite=Lax`, `Max-Age` = remaining lifetime.
- The callback never sets a cookie itself; the browser already holds one from Access. The relay
  creates no Home Assistant users or tokens; it only copies an Access token the user earned.
- The relay endpoints under `/api/cloudflare_access_relay` are bypassed at the edge but require
  Home Assistant authentication; the contract script checks both.
- What the gate adds, and what it does not: Access becomes a second factor in front of every
  surface that a Home Assistant session reaches (the frontend, the API, the WebSocket, user
  content). Endpoints Home Assistant exposes without a session keep exactly the protection
  they have without Access (a webhook id, a signed URL, an OAuth token); they are not
  weakened, and not strengthened either, except the companion app's own device webhooks,
  which are gated. Token-bearing clients (Google, Alexa, MCP) are gated and authenticate with
  Access. Your own machine callers (scripts, Prometheus) can do the same through managed OAuth,
  use an Access service token, or have their path listed in the extra bypassed paths.
- Home Assistant's IP ban counts a 401 as a failed login. Behind Cloudflare, configure
  `http.use_x_forwarded_for` with Cloudflare's ranges as `trusted_proxies`, as for any reverse
  proxy, so a misbehaving client bans itself and not the edge.
- If Access is also an OIDC identity provider for a login integration, that SaaS application
  is separate and untouched.

## After go-live

- Every relay verification failure raises a persistent notification with the reason (never the
  token); the Home Assistant log has the same line at INFO with the `kid`.
- Zero Trust → Logs → Access: every native request through the gate is an Access decision;
  check the log retention of your plan.
- Worth automating: each `mobile_app` device should keep updating its refresh token's
  `last_used_ip` through the gated API; alert on 24 h of silence. The integration does not do
  this itself.

## Out of scope by design

- No change to the companion apps, no custom headers, no core patch, no change to any login
  integration.
- No support for hand-maintained Access applications on the hostname: the integration assumes it
  is the only writer of the two objects it names.
- LAN behaviour is unchanged: an internal URL never touches Cloudflare, and the relay stays
  silent when a request did not come through Cloudflare.
- No revocation coupling for the companion app: Home Assistant refresh tokens keep their own
  lifetime; the edge is the gate. If Access refuses a user, their app breaks at the next request
  regardless of token state, and their token-bearing clients at their next token refresh.

## Development

```
uv sync                                  # Python 3.14, Home Assistant and the test tools, from uv.lock
uv run playwright install chromium       # or set RELAY_TEST_CHROMIUM to an existing binary
uv run ruff check . && uv run ruff format --check . && uv run mypy
uv run pytest
```

Tests: `tests/test_jwks.py` (verification against a fake JWKS endpoint, rotation),
`tests/test_views.py` (the whole relay over HTTP with two Home Assistant users),
`tests/test_provision.py` (a fake Cloudflare API recording every write),
`tests/test_config_flow.py`, and `tests/test_frontend.py` (Playwright: `relay.js` and the
connect page against a stubbed frontend and app bridge). CI runs lint, mypy, the suite against
the versions in `uv.lock`, the live test, hassfest and the HACS action. Newer Home Assistant
releases are taken up by updating the lock, never by installing something the lock does not
pin.

## Publishing to HACS

The HACS action needs, beyond this code: a repository description and topics on GitHub, a
`LICENSE` file, and the code on the default branch (it reads `hacs.json` and the manifest from
there). Until those exist the `hacs` CI job is marked non-blocking.

## Design notes

Facts checked on 14 Sep 2026 that shaped the implementation:

- The Access API field `self_hosted_domains` is deprecated (support ended 21 Nov 2025); the
  integration uses `destinations: [{type: "public", uri: …}]`.
- A "gate disabled" state that keeps the gate application on a bypass-everyone policy would
  make the callback path unreachable for the relay, so the staged state keeps the allow policy
  and narrows the application to the callback path instead. The application id and audience
  are the same in both states.
- The connect page is a standalone bypassed page (not the full frontend), because the frontend
  index itself is gated and could never load in a cookie-less WebView. It obtains a Home
  Assistant token through the app's `getExternalAuth` bridge (which only accepts the callback
  name `externalAuthSetToken`), with Home Assistant's own login flow as the fallback. This is
  also what makes the lock-out recovery above possible.
- The bypass list is not hand-written: Home Assistant's router marks what it serves without a
  session (views registered without authentication, static files served from integration
  packages), and the integration reads it at setup, once start-up is complete and after
  every component load. A core release that adds a login endpoint, or an integration
  installed later, is picked up without configuration. Nothing under `/api` is declared open:
  token-bearing clients authenticate with Access (managed OAuth for those that register
  themselves, an Access for SaaS registration made by the integration for the rest), so the
  integration never names a vendor.
