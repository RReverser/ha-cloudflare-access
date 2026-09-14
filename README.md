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
depends on (pre-flight P1–P6, P8) verified on a real account against Access applications
created from the integration's own code (see *Test host*). **Not yet validated on a real
device** (P7, iOS). Sections *Pre-flight* and *Rollout* below are the required order.

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
| `/auth` | Login page, login flow, token exchange and refresh: all happen before or independently of the cookie. Also covers login integrations that live under `/auth/…` such as hass-openid |
| `/frontend_latest`, `/frontend_es5`, `/static` | Login page and frontend assets (static JavaScript, fonts, icons) |
| `/cloudflare_access_relay/connect`, `/cloudflare_access_relay/static` | The connect page and the relay's own JavaScript |
| `/api/cloudflare_access_relay` | Flow creation, status poll, session check. The only bypassed prefix under `/api/`; every view there requires Home Assistant authentication |
| `/openid` | Only when the `openid` (hass-openid) integration is loaded |
| `/api/google_assistant`, `/api/alexa` | Only when those integrations are loaded (server-to-server callers cannot carry the cookie) |
| *extra bypassed paths* option | Anything else that must stay reachable without a cookie, e.g. specific webhooks |

The integration-derived entries are computed when the entry is set up; after installing one of
those integrations, reload this entry so the bypass list picks it up.

Everything else, including `/`, `/api/*`, `/api/websocket`, `/api/webhook/*`, `/local/*`,
`/media/*` and `/hacsfiles/*`, is gated once the gate is enabled.

Cloudflare precedence: a more specific path rule wins over the hostname-wide application. That
is what makes the bypass list work; pre-flight test P8 asserts it.

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
| Delete the Access applications when the integration is removed | on | |

Changing the options reloads the entry and re-provisions; so does reloading the integration
(Settings → Devices & services → Cloudflare Access Relay → Reload), which is the way to repair
applications edited outside the integration. Unchanged applications are never written.

## Pre-flight: the Cloudflare behaviour the design rests on

These are assumptions about Cloudflare and the Android WebView that only a real account and a
real device can settle. All but P7 were verified on 14 Sep 2026 on the test host below, with
Access applications created from the integration's own provisioning code, and are re-checked
by `tests/live` in CI.

| # | Assumption | Result |
|---|---|---|
| P1 | An origin `Set-Cookie: CF_Authorization=…` passes through Cloudflare unmodified | verified: byte-identical |
| P2 | Access accepts a `CF_Authorization` cookie it did not set in that client | verified: token obtained by one client, presented as a cookie by another (different User-Agent, no other state) → 200, origin receives the same `Cf-Access-Jwt-Assertion` |
| P3 | JWT `exp − iat` equals the configured session duration | verified for `1h` and `8760h` |
| P4 | The header token equals the cookie token | verified |
| P5 | With *Binding Cookie* enabled P2 fails, so it must stay off | verified: cookie alone → redirect to login |
| P6 | Session ceiling | the API accepts and honours `8760h`; the dashboard shows up to one month |
| P7 | The app's WebView hands only the Access redirect to the browser and stays on the page | **still open**. The app's WebView only loads its own server, so this is observed on the Home Assistant hostname itself during rollout step 3 (gate off, callback path gated): tap *Sign in with Cloudflare* on the connect page and watch whether the system browser opens while the app stays on the page. Either outcome works: if the WebView follows the redirect itself, the login lands the cookie in the shared jar directly |
| P8 | A path-specific bypass application takes precedence over the hostname-wide gate application | verified, including prefix inheritance (`/api/cloudflare_access_relay/echo`) |
| — | Access forwards the `CF_Authorization` cookie to the origin on bypassed paths (needed by the session endpoint) | verified |
| — | The relay's verifier accepts a real token against the real JWKS and rejects a wrong audience and a tampered signature | verified |

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
flow (which provisions the applications), enables the gate via the options flow, runs
P1–P5 and P8 at the edge, relays a real token through the integration's own HTTP views and
uses the released cookie at the edge, injects drift and reloads the entry to repair it,
checks that a reload writes nothing, removes the entry with "delete objects" off so the
applications stay for the next run, and deletes the token. It needs two repository secrets
and is skipped without them:

| Secret | Value |
|---|---|
| `CF_API_TOKEN` | account token with *Access: Apps and Policies: Edit*, *Access: Organizations, Identity Providers, and Groups: Read* and *Access: Service Tokens: Edit* |
| `CF_ACCOUNT_ID` | the Cloudflare account id |

The address on the test host's allow policy is the author of the commit being tested, which is
who can open the test host in a browser between runs (the test itself logs in with its service
token).

`preflight/preflight.sh` is the same set of checks for a shell with curl.

## Rollout

1. Everything automatable is verified (see *Pre-flight*); P7 is observed in step 3.
2. Install the integration and complete the config flow with the gate **off**. Run
   `tests/contract/check_edge.sh` with `MODE=staged` (header of the script lists the inputs).
3. Android, gate still off: sign in to the app, confirm the connect page appears, tap *Sign in
   with Cloudflare* (this is P7: the system browser should open on the team domain and the app
   should stay on the connect page), complete the login, come back, confirm the page reports
   "Connected". Only the callback path is gated at this point, so nothing else can break, and
   removing the entry undoes everything.
4. Enable the gate in the options. Run `check_edge.sh` with `MODE=gated`. **This is the exposure
   change.** Rollback is the same switch, or removing the integration.
5. Device acceptance, gate on: dashboard, HACS panel, camera images and notification
   tap-throughs load; the Home Assistant access log shows 200s on the device's
   `/api/webhook/<id>` while the path is gated; the device's refresh token `last_used_ip` keeps
   updating; kill and relaunch the app, background sensor updates continue.
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
- If Access is also an OIDC identity provider for a login integration, that SaaS application
  is separate and untouched.

## After go-live

- Every relay verification failure raises a persistent notification with the reason (never the
  token); the Home Assistant log has the same line at INFO with the `kid`.
- Zero Trust → Logs → Access: every native request through the gate is an Access decision;
  check the log retention of your plan.
- Worth automating: each `mobile_app` device should keep producing 200s on its gated webhook
  path; alert on 24 h of silence. The integration does not do this itself.

## Out of scope by design

- No change to the companion apps, no custom headers, no core patch, no change to any login
  integration.
- No support for hand-maintained Access applications on the hostname: the integration assumes it
  is the only writer of the two objects it names.
- LAN behaviour is unchanged: an internal URL never touches Cloudflare, and the relay stays
  silent when a request did not come through Cloudflare.
- No revocation coupling: Home Assistant refresh tokens keep their own lifetime; the edge is the
  gate. If Access refuses a user, their app breaks at the next request regardless of token state.

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

## Deviations from the original plan

Facts checked on 14 Sep 2026 that changed the implementation:

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
- `/auth` is bypassed as a prefix rather than four individual paths; every endpoint under it
  is part of the login surface that Home Assistant protects itself.
