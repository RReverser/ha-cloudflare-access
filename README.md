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

Status: implementation complete with an automated test suite; the Cloudflare behaviour it
depends on is verified on a real account against Access applications created from the
integration's own code (see *Verified Cloudflare behaviour*), and the sign-in has been taken
through Cloudflare's consent page with the published client. Not yet validated with a real
Google Home or Alexa link, nor on a real phone.

## Requirements

- Home Assistant 2026.9 or newer (tested against core 2026.9.2, Python 3.14).
- The hostname is served through Cloudflare (Cloudflare Tunnel or proxied DNS) and belongs to a
  zone in the account.
- A Zero Trust organization. Its [login
  methods](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/)
  (Zero Trust → Integrations → Identity providers) decide how people prove the e-mail address
  the gate admits; a new organization comes with Cloudflare's own login for account members,
  and the one-time PIN needs no setup either. Everything used is documented by Cloudflare
  without a plan restriction; managed OAuth is marked beta by Cloudflare.
- Nothing else to prepare: the integration **signs in with Cloudflare** through the project's
  published OAuth client, asking for exactly the permissions it uses (see *Sign-in*). The
  token set is stored in the config entry and used for nothing else.
- At least one Home Assistant user with an e-mail address; the integration refuses to set up
  without one, since nobody could pass the gate. Home Assistant has no e-mail field and no
  login provider stores one (the OIDC integrations record only a subject id), so an address
  is either the login username or a **login e-mail** the integration keeps itself, entered
  under *People* in the options (and at setup): every person is listed there, read-only when
  their username is an address, with an e-mail field otherwise. Users without a person (an
  add-on's API user) are not people and are not listed. Those addresses are the gate's allow
  policy, and the address of an admitted request picks the user.
- Behind Cloudflare, configure `http.use_x_forwarded_for` with Cloudflare's ranges as
  `trusted_proxies`, as for any reverse proxy, so Home Assistant's IP ban sees clients and not
  the edge.

## How it works

One Access application, the **gate**, covers the hostname. Its allow policy lists the e-mail
addresses of the Home Assistant users, and follows them: a user added, removed, deactivated or
renamed in Home Assistant is reflected in the policy within seconds, without a reload. Every
request for the hostname goes through it: the frontend, the login pages, the API, the
WebSocket, webhooks, media, everything.

**Browsers and the companion app.** The browser lands on the Access login page, logs in with
the identity provider, then reaches Home Assistant's own login with the Access cookie set.
Home Assistant's login is unchanged (hass-openid or similar can make it single sign-on). The
Android companion app does the same in its WebView and sends the cookie with its native
requests too, so its API calls and its device webhook pass the gate.

**Token-bearing clients.** A client that cannot hold the cookie authenticates with Access,
which validates its token at the edge on every request and forwards the request to Home
Assistant with the same signed assertion a browser session gets. At the origin the
integration's request hook maps that assertion to the Home Assistant user, so Home
Assistant's own authentication is satisfied without a second token. (Home Assistant starts
its web server before any integration entry loads and the server's middleware list is
frozen by then, so the hook is added to the running server's chain; it is covered by a test
against a started server.) Access's own policies decide
who may link, and revoking a person in Access ends their clients at the next token refresh.
Every such client is added under *Add client* on the integration entry as *a client that
logs people in*, with a name and the callback URL(s) the client's own side shows; the
callback belongs to the client and cannot be derived, but the form offers the published
callbacks of well-known clients (Claude, ChatGPT, Cursor, VS Code, Gemini Enterprise,
Antigravity, Perplexity, Copilot Studio) as choices. Clients that run on a person's own
computer (Claude Code, Cursor's desktop app, VS Code, Gemini CLI) call back on localhost,
which Access does not take as a list entry; they are not supported yet. Two kinds, one
mechanism behind both:

- **Clients that discover and register themselves** (MCP clients): the gate has *managed
  OAuth* enabled, which makes Access the OAuth server for the hostname. An unauthenticated
  non-browser request gets a 401 pointing at Access's discovery document at
  `/.well-known/oauth-authorization-server`; the client registers dynamically, sends the
  person through the Access login, and receives a token. Access accepts a dynamic registration
  only for a callback URL of a listed client (Claude: `https://claude.ai/api/mcp/auth_callback`).
- **Clients with a console that asks for a client id and secret** (Google Home account
  linking, an Alexa skill): the same entry with *The client asks for a client ID and secret*
  switched on. The integration creates an Access for SaaS OIDC application, which is that
  client's registration with Access, shows the client id, secret, authorization, token and
  user-info URLs to paste into the console, and adds a rule to the gate accepting that
  application's tokens. Google Home and Alexa need the same four values they need today when
  linked to Home Assistant directly, only now those values are Access's.

**Bypassed paths.** Callers that can hold neither a cookie nor a bearer, such as a third-party
service posting to a webhook or a media player fetching audio by signed URL from the public
hostname, stop working once the gate is on. If you need one, list its path prefix under
*Paths open without Access*; the integration then maintains a second, *bypass* application
with those paths. Nothing is bypassed by default, and nothing is detected: an attacker probing
paths must never turn into a suggestion to open them.

**iOS.** The iOS companion app never sends cookies with its native requests, so with the gate
on it can only render the WebView; sensors, location and notification actions do not reach
Home Assistant. Use Home Assistant in the browser on iOS, or a build of the app that presents
the WebView's cookies on native requests.

### What the integration creates in Cloudflare

Applications are named with the prefix `ha-access:` and carry an Access tag naming the config
entry (`hass-<entry id>`), created on first use. The integration updates or deletes only
applications with its own entry's tag: a stored id that turns out to point at an untagged
application, or a same-named application without the tag, is left alone and a new one is
created. Lost ids are recovered by name and tag. The applications are the only objects the
integration writes, and it is meant to be their only writer; an application edited outside the
integration is repaired on the next reload.

| Application | Exists | Destinations | Policies | Other |
|---|---|---|---|---|
| `ha-access: gate <host>` | while the gate is enabled | `<host>` | `allow` for the Home Assistant users' addresses; *Service Auth* for listed service tokens; *Service Auth* accepting the tokens of every registered client | session duration from the options; binding cookie **off** (it would tie the cookie to the WebView alone); managed OAuth on, with dynamic registration for the clients' callback URLs; with exactly one login method in the organization, people are sent straight to it (no picker page); a deny message that names the People option |
| `ha-access: bypass <host>` | while *Paths open without Access* is non-empty | the listed paths | `bypass` for everyone | |
| `ha-access: client <host> <name>` | one per client whose console needs credentials | (SaaS OIDC application) | `allow`, same rule as the gate | authorization code and refresh token grants, refresh token lifetime = session duration, scopes `openid email profile` |

Cloudflare precedence: a more specific path rule wins over the hostname-wide application. That
is what makes the bypass list work; the live test asserts it on every run.

Removing the integration deletes every application it created (option, default on), which
restores the un-gated state. Turning the gate off in the options deletes the gate application
and keeps everything else.

## Installation

1. HACS → Integrations → three dots → *Custom repositories* → add this repository as an
   *Integration*, then install **Cloudflare Access**. Restart Home Assistant.
2. Settings → Devices & services → *Add integration* → **Cloudflare Access**, **from a
   desktop browser**. The browser is sent to Cloudflare's consent page, which shows the three
   permissions; allow, and the popup closes. (From the Android companion app the consent works
   but the return trip does not: the app claims every `my.home-assistant.io` link, loads the
   OAuth callback inside its own web view in place of the frontend, and the setup dialog is
   lost. This is how the app handles the callback of any OAuth integration.)
3. Back in Home Assistant, the account is picked if the sign-in reaches one, asked for
   otherwise. Then the people's addresses and the advanced options. The hostname is the one
   of Home Assistant's External URL (Settings → System → Network); without one the setup
   stops and says so. A later change of the External URL renames the Access applications and
   the service tokens to the new hostname; removing it leaves them as they are and raises a
   repair issue, whose fix takes the URL, until it is back. A hostname Cloudflare refuses, such as one outside the
   account's zones (`domain does not belong to zone`), is reported like any other refusal:
   at setup the entry shows Cloudflare's answer; on a later change the gate keeps the last
   hostname and a repair issue quotes the answer.
   The form shows which users' addresses the gate would let in.
4. The integration validates the credential by listing the Access applications and reading
   the team domain, and creates nothing yet: the gate starts **off**. Read *Rollout* before
   enabling it.

### Sign-in

Cloudflare's OAuth lets the integration ask for exactly the permissions it uses, on the
consent page, instead of a token you assemble by hand: `access.write` (Access: Apps and
Policies Write), `access-acct.read` (Access: Organizations, Identity Providers and Groups
Read), `access-service-token.write` (Access: Service Tokens Write, for script clients),
`access-org.revoke` (Access: Organizations Revoke, to log removed people out),
`access-audit-log.read` (Access: Audit Logs Read, for the login history),
`memberships.read` (Memberships Read, to find the account you granted on the consent page,
since the token itself does not say) and `offline_access` (a refresh token, so the sign-in
lasts). The integration ships the
client ID of the project's public OAuth client (PKCE, no secret), so there is nothing to
register. The token set is refreshed before every API call; when Cloudflare stops accepting
it, the integration asks to sign in again.

To sign in through a client of your own instead, create one in the Cloudflare dashboard
(*Manage Account* → *OAuth clients*: redirect URL `https://my.home-assistant.io/redirect/oauth`,
grant types *authorization code* and *refresh token*, token endpoint authentication *none*,
the scopes above) and add its client ID under Home Assistant's *Application credentials*; the
sign-in then asks which client to use.

An API token (permissions **Access: Apps and Policies: Edit** and **Access: Organizations,
Identity Providers, and Groups: Read**, **Access: Service Tokens: Edit** for script
clients, **Access: Organizations: Revoke** to log removed people out, and **Access: Audit Logs:
Read** for the login history) can replace the sign-in where a browser cannot reach the consent page, as in this
project's CI: start the flow with the source `api_token`.

## Rollout

1. Gate off: run the rollout checks against your hostname with `MODE=off` to confirm it
   behaves as before (`HA_HOST=… CF_JWT=… HA_TOKEN=… MODE=off uv run pytest tests/rollout`;
   the module's header lists the inputs).
2. Enable the gate in the options. **This is the exposure change.** Rollback is the same
   switch, or removing the integration. Run the rollout checks again with `MODE=gated`.
3. Browser: open the hostname, log in to Access, then to Home Assistant.
4. Android: add the server in the app, log in to Access in the app's WebView when it appears,
   then to Home Assistant. Confirm the dashboard, camera images and notification tap-throughs
   load, and that background sensor updates keep arriving (they use the device webhook, which
   is gated, so they prove the cookie travels with native requests). Every Access session
   expiry (the *Session duration* option, default one month) brings the WebView back to
   the Access login page.
5. Re-link Google Assistant, Alexa and MCP clients against Access (see *Token-bearing
   clients*). Links made against Home Assistant's own OAuth stop working at the gate.
6. If something that neither logs in nor carries a token broke, list its path under *Paths open
   without Access*.

## Options

| Option | Default | Meaning |
|---|---|---|
| Enabled | off | The exposure switch. On: the gate application covers the hostname. Off: no gate application, and the other settings can be prepared first. The switch stays an option rather than the entry's own enable/disable because Home Assistant hides the options dialog of a disabled entry |
| People → one field per person | | The e-mail address Access knows the person by: shown read-only when it is their login username, editable otherwise. Empty means the person cannot log in |
| Bypass policies → Paths open without Access | empty | Hostname-relative path prefixes reachable without a login. The form offers the registered webhooks (by name) and the public resource routes under `/api/` (camera and image proxies, text-to-speech audio, map tiles) as choices; anything can be typed. Nothing is open unless picked |
| Session duration | 30 days | Lifetime of an Access session and of a registered client's refresh token, picked as days, hours and minutes (stored as `<n>h` or `<n>m`). Cloudflare's dashboard stops at one month; the API accepted `8760h` and Access honoured it (verified) |
| Delete the Access applications when the integration is removed | on | Registered clients' applications included |

Disabling the integration entry takes the gate and the bypass application down, so the
hostname is as it was without the integration; enabling it provisions them again. Registered
clients' applications stay through a disable, so their consoles keep their credentials. A
reload or a restart of Home Assistant leaves the edge alone. An entry disabled while it is in
an error state, or during a shutdown, is taken down at the next start.

### Login history

Access logs every login attempt at the gate and at the clients' applications. The integration
reads those logs on Home Assistant's polling schedule (every 15 minutes by default; the
integration's system options can turn polling off, and a reload forces a read) from a stored
cursor, so nothing is replayed after a restart, and turns each new entry into:

- a `cloudflare_access_relay_login` event on the bus (`email`, `allowed`, `user_id` when the address
  belongs to a person, `app`, `login_method`, `ip_address`, `when`), for automations and the
  logbook;
- a repair issue when someone logged in at the identity provider and was refused because the
  address is not on the allow list; it names the address and the time, and its fix gives the
  address to a person of your choice as their login e-mail.

The Free plan keeps these logs for 24 hours, so the first read looks back that far. A
credential that cannot read them (a sign-in from before the permission was asked for, an
API token without it) starts the sign-in again, and everything else keeps working meanwhile.

Changing the options reloads the entry and re-provisions; so does reloading the integration
(Settings → Devices & services → Cloudflare Access → Reload), which is the way to repair
applications edited outside the integration. Unchanged applications are never written.

The integration does not set up, and the options cannot be saved, while no user has an e-mail
address: nobody could log in. If the last such user goes while the gate is on, the policy keeps
its last subjects and a repair issue says so. Any other change Cloudflare refuses or cannot take
leaves the applications in their last state and raises a repair issue quoting Cloudflare's
answer; the next change retries, and the issue's fix retries at once. A sign-in Cloudflare no
longer accepts, or one that lacks a permission the integration uses, starts the sign-in again.

Every repair issue whose remedy is an action offers it as its fix: retrying a failed update,
setting the External URL, giving a refused address to a person, and settling HA-MCP's login
mode against the gate.

Clients are subentries of the integration entry (*Add client*), of two kinds:

- **A client that logs people in** (above); one whose console needs credentials stores its
  application id, client id and secret, and *Reconfigure* shows the credentials again. For
  Google Home account linking enter the client id, client secret, authorization URL and token
  URL shown; for an Alexa skill the same four under account linking, with credentials in the
  request body.
- **A script or service with its own credentials**: a machine with nobody behind it, for
  example a backup job or a monitoring probe on another host. The integration creates an
  Access service token named `ha-access: client <host> <name>` and shows its Client ID and
  secret, which the script sends as the `CF-Access-Client-Id` and `CF-Access-Client-Secret`
  request headers together with its usual Home Assistant token; the gate's *Service Auth*
  policy names the token. *Reconfigure* renames the token, extends its validity (Cloudflare's
  default is a year) and shows the credentials again. A token deleted outside the integration
  is replaced with new credentials at the next reload, and removing the client, or the
  integration, deletes the token. Service tokens of an earlier version's option are turned
  into script clients at setup. Both the sign-in and an API token need **Access: Service
  Tokens: Edit** for this; a sign-in granted before the scope was added asks to sign in again
  when a script client is added.

## Using with other integrations

The integration knows nothing about how the hostname reaches Home Assistant or what serves
on it; it only guards the hostname. The three things people run next to it that deserve a
precise account are the Cloudflared add-on, which usually provides the hostname, and the two
MCP servers, which are the main users of the login clients. Everything below was traced from
the sources (core 2026.9.2, HA-MCP 2.2.x, the add-on's configuration schema) and Cloudflare's
documentation; what was not exercised on a live instance is marked.

### The Cloudflared add-on

The add-on's `external_hostname` and Home Assistant's External URL name the same hostname,
and the gate guards the latter. Nothing else is needed for the gate: the add-on carries
the request to Home Assistant, and the gate is enforced at Cloudflare's edge before that. The
add-on's own [Home Assistant configuration](https://github.com/homeassistant-apps/app-cloudflared/blob/main/cloudflared/DOCS.md#home-assistant-configuration)
steps apply as they are.

One optional interaction between the two: cloudflared can refuse any request that lacks a
valid Access assertion for the hostname, so the hostname stays closed even if the Access
application is edited or deleted outside the integration. This is the origin setting
Cloudflare calls *Protect with Access*, and it can only be turned on where the tunnel's
ingress is configured. With the add-on in its remote-managed mode (`tunnel_token` set), it is
in the Zero Trust dashboard under the tunnel's public hostname → Additional application
settings → Access, choosing the application `ha-access: gate <host>`. In the add-on's
default, locally managed mode there is no way to set it: the add-on generates the ingress
from its options, which have no origin settings, and its `run_parameters` option accepts only
a fixed list of daemon flags. The gate alone is the full protection in that mode.

### The built-in `mcp_server` integration

Endpoint `POST /api/mcp` (also `/api/mcp/<api>`), stateless streamable HTTP, guarded by
Home Assistant's own authentication.

| Where | Setting | Why |
|---|---|---|
| `mcp_server` | Defaults | Its own 401 metadata is built from the External URL, which is the guarded hostname |
| Here | The MCP client added as *a client that logs people in* (its callback is in the list; Claude's is `https://claude.ai/api/mcp/auth_callback`); `/api/mcp` **not** an open path | The client's first call gets Access's 401 with OAuth metadata, registers dynamically and completes PKCE against Access; every later call carries an Access token that the origin rule maps to the person, and the server runs the call as that person (admin required outside the Assist API, the person's group policy on every service call, the Assist exposure list on every entity) |
| Client | `https://<host>/api/mcp`, OAuth client ID and secret left empty | Home Assistant's own OAuth never runs, which sidesteps its two gaps: no dynamic registration and no PKCE |

Alternatives:

- **A script or service with no login** (a cron job, a header-only client): a script client
  (Client ID and secret as headers) **plus** a Home Assistant long-lived token as the bearer.
  The token alone never passes the edge; the script client alone never passes Home
  Assistant. Calls run as the token's user.
- **A client on a person's own computer** (Claude Code, Cursor's desktop app, VS Code,
  Gemini CLI) calls back on localhost, which the gate does not admit yet.
- **Opening `/api/mcp` as an open path** hands the login to Home Assistant's own OAuth,
  which cannot register clients dynamically and has no PKCE, and leaves a Home Assistant
  token as the only credential at the edge. Not recommended.
- **The legacy `GET /mcp_server/sse`** binds a session to an unguessable id only, so any
  authenticated principal who learns the id can post into it. Use `/api/mcp`.

Not exercised live: claude.ai's hosted connector end to end (a June 2026 report has it
failing against Cloudflare managed OAuth; it blamed a missing `WWW-Authenticate` header,
which the live test shows present).

### The HA-MCP custom component

Endpoint `/api/webhook/mcp_<secret>`, an ordinary Home Assistant webhook (no Home Assistant
authentication of its own), stateless streamable HTTP. Its authentication mode is one of
`none`, its *secret URL* mode (the random webhook URL itself is the credential; an
auto-approving OAuth surface satisfies clients that insist on OAuth), `ha_auth` (the client logs in through Home Assistant's OAuth,
administrators only) or `legacy` (its own OAuth with a static client ID and secret). In
every mode the component strips the caller's bearer and performs the calls with its own
provisioned admin user, so its login is a gate, never per-person attribution.

| Where | Setting | Why |
|---|---|---|
| HA-MCP | Authentication mode `none` (the secret URL); remote access via webhook on; "Network access" set to `127.0.0.1` | Behind the gate the person's Access login is the credential and the secret URL a second factor; `none` is the only mode whose OAuth surface does not fight Access's (see below); the loopback setting closes the LAN port 9584 that the component otherwise opens |
| Here | The MCP client added as *a client that logs people in*; the webhook **not** an open path | Same flow as above: the client registers and logs in at Access; the origin rule maps the identity (used for the login history and the events), and the component runs the call as its admin user as it always does |
| Client | `https://<host>/api/webhook/mcp_<secret>`, OAuth client ID and secret left empty | |

Alternatives:

- **A script or service with no login**: a script client alone (Client ID and secret as
  headers); no Home Assistant token is needed since the webhook has no Home Assistant
  authentication.
- **A client that cannot do OAuth at all**: list the webhook under Bypass policies. That is
  HA-MCP's own default posture, the URL as the password, with the edge no longer asking
  anything. Weakest option; the form offers the webhook by name so it is a deliberate choice.
- **`ha_auth` or `legacy` mode with the gate on the webhook does not work**: a client holds
  one bearer, Access refuses the component's tokens and the component refuses Access's, so
  each side's login page blocks the other. The integration raises a repair issue when it
  sees this combination, whose fix switches HA-MCP to `none` or lists the webhook under
  Bypass policies. Those modes are usable only with the webhook listed as an open
  path, where the component's own login is then the only gate and the issue is not raised; `ha_auth` also still
  requires the Home Assistant External URL to match and dynamic registration on the
  client's side, which claude.ai has failed at in the component's own issue tracker.
- The component updates its server package from PyPI on its own every six hours, so its
  behaviour can change without a HACS update.

### Cloudflare's MCP servers and portals

Zero Trust > AI controls can register an MCP server object for either MCP server above and
put a portal in front of it, purely for auditing. What it adds on the Free plan: tool
synchronisation, per-call portal logs (tool name, status, duration; the caller's e-mail
only through Enterprise Logpush; arguments never), daily call counts, and optional Gateway
routing with 24-hour HTTP logs. What it costs: the portal reaches Home Assistant with one
static credential, so with the built-in server the per-person attribution above is lost; a
new token scope (MCP Portals Write) and zone DNS write for the portal hostname; an extra
Access login and seat per person; server state to keep in sync. Direct connections to the
hostname are invisible to it. The integration does not create these objects.

Recipe, with a script client's Client ID and secret:

- HA-MCP: server authentication `bearer` with the credentials
  `{"headers":{"cf-access-client-id":"<id>","cf-access-client-secret":"<secret>"}}`, the
  form Cloudflare documents for exactly this.
- Built-in server: the same headers plus `"Authorization":"Bearer <long-lived token>"`, the
  multi-header form Cloudflare documents; calls run as the token's user.

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
| Cloudflare refuses a self-hosted application for a hostname outside the account's zones (`12130: access.api.error.invalid_request: domain does not belong to zone`), so a wrong External URL cannot create a gate that guards nothing | verified 23 Sep 2026 |
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
Access permissions above plus **Workers Scripts: Edit**)
and `CF_ACCOUNT_ID`; without them the live job is skipped, as on forks.

## Security properties

- Access is the only way in from the public hostname: every path, including the login pages,
  requires an Access session, an Access-issued token, or a listed service token.
- Losing access ends the session: Access re-checks a person against the policy only when
  their session expires, so when an address leaves the allow rule (a user removed or
  deactivated, an address changed) the integration also revokes that person's Access
  sessions and tokens across the organization, which Cloudflare applies within about
  30 seconds. Addresses dropped while Home Assistant was down are found on the gate at the
  next start. A credential that cannot revoke starts the sign-in again instead.
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
- Who may log in is not a list to maintain in two places: the people who have a Home Assistant
  account are the people the gate lets in, and nobody else.
- The Cloudflare credential is scoped to what the integration does. With the sign-in, the
  consent page shows the scopes; the token set lives in the config entry like any other
  Home Assistant OAuth integration's.

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

## The project's OAuth client

`scripts/oauth_client.py` (run by the *OAuth client* workflow with the repository's Cloudflare
token) creates and maintains the Cloudflare OAuth client the integration signs in with: name,
logo (`logo.png`), redirect URL, grant types, PKCE, scopes, the client URL's DNS verification
record, and the promotion to public visibility, which Cloudflare makes permanent. Its client
ID is `OAUTH_CLIENT_ID` in `const.py`.

The integration's icon in Home Assistant is the same drawing, shipped in the integration's
`brand/` directory (Home Assistant 2026.3 and newer serve it from there; older versions show
no icon). It is deliberately not Cloudflare's logo: this is a third-party project, and the
brand mark belongs to Cloudflare.

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
