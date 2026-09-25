# Verified Cloudflare behaviour

Verified on the CI test host (see [CONTRIBUTING.md](../CONTRIBUTING.md), *Test host*) with Access
applications created from the integration's own provisioning code, and re-checked by
`tests/live` in CI on every push to `main`.

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
| The gate's managed-OAuth authorization endpoint accepts a client id obtained by dynamic registration and refuses the client id of an Access for SaaS application, so a self-registering client cannot be pointed at the application's credentials | verified 24 Sep 2026 |
| A self-registered client appears nowhere the API lists: not on the gate, not in the login logs or sessions, and not in the account's OAuth-clients listing, so it cannot be enumerated or revoked on its own | verified 24 Sep 2026 |
| Cloudflare refuses a self-hosted application for a hostname outside the account's zones (`12130: access.api.error.invalid_request: domain does not belong to zone`), so a wrong External URL cannot create a gate that guards nothing | verified 23 Sep 2026 |
| A bearer Access admitted reaches the origin unchanged, with the assertion alongside; the origin rule accepts a real assertion against the real JWKS and refuses a tampered one | verified 20 Sep 2026 |
| A self-registered client's grant (`tests/live/grant_probe.py`, one real login): the access token stops at the origin after the default 15 minutes (`expires_in` 900), but refreshing keeps working after the client's callback is removed from the gate's allowed list, and every refreshed token is admitted, for the 26 minutes observed; the grant is bounded only by the gate's OAuth grant `session_duration` | verified 25 Sep 2026 |
| Once the callback is removed, a fresh authorization for that client is refused at once: the authorization endpoint sends the browser back to the callback with `invalid_request: Redirect URI not allowed by application configuration`. The allowed list is checked live, not at registration | verified 25 Sep 2026 |
| Revoking the person (`revoke_user`) leaves a managed-OAuth grant intact: refresh still succeeds and the new token is admitted. Revoking the application's tokens (`revoke_tokens`) still lets refresh hand out a token, but the origin refuses it | verified 25 Sep 2026 (one observation each) |
| An authorization code is still exchangeable six hours after the login | observed 25 Sep 2026 |

Also observed: a service-token login answers with the application token both as the header and
as a `Set-Cookie`; its JWT carries `aud` as a string (identity logins use a list), `sub` empty
and `common_name` instead of `email`. The integration accepts both `aud` shapes.

## Not verified yet

- A registered client's token, presented as a bearer on the hostname, passes the gate with an assertion whose audience is the gate's: not verified yet, needs a real account-linking login (Google Home or Alexa)
- The Android app's WebView completes the Access login and its native client sends the cookie: not verified yet, needs a phone. The app's cookie support was added for Cloudflare Access; the origin side is covered by the tests
