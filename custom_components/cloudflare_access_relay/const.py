"""Constants for the Cloudflare Access integration."""

from __future__ import annotations

from typing import Final

DOMAIN: Final = "cloudflare_access_relay"
VERSION: Final = "0.2.0"

# Config entry data (credentials + derived values). An entry holds either an OAuth
# token set (Home Assistant's `token` and `auth_implementation` keys) or an API token.
CONF_API_TOKEN: Final = "api_token"
CONF_ACCOUNT_ID: Final = "account_id"
DATA_TOKEN: Final = "token"
DATA_TEAM_DOMAIN: Final = "team_domain"
DATA_POLICY_AUD: Final = "policy_aud"
DATA_GATE_APP_ID: Final = "gate_app_id"
DATA_BYPASS_APP_ID: Final = "bypass_app_id"

# Options
CONF_HOSTNAME: Final = "hostname"
CONF_GATE_ENABLED: Final = "gate_enabled"
CONF_SERVICE_TOKEN_IDS: Final = "service_token_ids"
CONF_SESSION_DURATION: Final = "session_duration"
# Derived from the OAuth client subentries at provisioning time, never edited directly.
CONF_CLIENT_REDIRECT_URIS: Final = "client_redirect_uris"
CONF_EXTRA_BYPASS_PATHS: Final = "extra_bypass_paths"
CONF_DELETE_OBJECTS_ON_REMOVE: Final = "delete_objects_on_remove"
# The form groups the two ways around the login in a collapsed section; storage stays flat.
SECTION_BYPASS: Final = "bypass"

DEFAULT_GATE_ENABLED: Final = False
# Cloudflare documents the application session ceiling as "one month".
DEFAULT_SESSION_DURATION: Final = "720h"
DEFAULT_DELETE_OBJECTS_ON_REMOVE: Final = True

# Claims of the Access application token that name the person: `email` for an identity
# provider login, `common_name` for a service token (which carries no e-mail).
CLAIM_EMAIL: Final = "email"
CLAIM_COMMON_NAME: Final = "common_name"

# Signing in with Cloudflare: a self-managed Cloudflare OAuth client with PKCE (no
# secret), asking for exactly what the integration does. `access.write` creates and
# maintains the Access applications, `access-acct.read` reads the team domain,
# `memberships.read` finds the account the consent page granted, `offline_access` gives
# a refresh token so the sign-in lasts.
OAUTH_AUTHORIZE_URL: Final = "https://dash.cloudflare.com/oauth2/auth"
OAUTH_TOKEN_URL: Final = "https://dash.cloudflare.com/oauth2/token"
OAUTH_SCOPES: Final[tuple[str, ...]] = (
    "access.write",
    "access-acct.read",
    "memberships.read",
    "offline_access",
)
# The project's public OAuth client (PKCE, no secret), maintained by scripts/oauth_client.py.
# A credential added under Settings → Application credentials takes its place.
OAUTH_CLIENT_ID: Final = "2743d292a690169c8ed4dc4473382227"

# Repair issues
ISSUE_NO_ALLOWED_USERS: Final = "no_allowed_users"

# Edge identity (see edge_auth.py): the middleware must be installed before the web
# server starts, so the first setup after installation asks for a restart.
ISSUE_RESTART_REQUIRED: Final = "restart_required"
HEADER_JWT: Final = "Cf-Access-Jwt-Assertion"
HEADER_CF_RAY: Final = "CF-Ray"

# Login e-mail subentries: the address Access knows a Home Assistant user by, for users
# whose login username is not one. One per user.
SUBENTRY_TYPE_LOGIN_EMAIL: Final = "login_email"
CONF_USER_ID: Final = "user_id"
CONF_EMAIL: Final = "email"

# OAuth clients (config subentries): every client's redirect URLs are allowed for
# self-registration on the gate; a client whose console asks for a client id and secret
# gets an Access for SaaS OIDC application of its own, whose tokens the gate accepts.
SUBENTRY_TYPE_CLIENT: Final = "oauth_client"
CONF_CLIENT_NAME: Final = "name"
CONF_REDIRECT_URIS: Final = "redirect_uris"
CONF_NEEDS_CREDENTIALS: Final = "needs_credentials"
DATA_CLIENT_APP_ID: Final = "app_id"
DATA_CLIENT_ID: Final = "client_id"
DATA_CLIENT_SECRET: Final = "client_secret"

# Every application the integration creates carries an Access tag naming the config
# entry (derived from its id at provisioning time, `OPTION_APP_TAG`). Only applications
# with this entry's tag are ever updated or deleted; a stored id or a matching name
# without the tag is somebody else's.
APP_TAG_FMT: Final = "ha-access-{entry_id}"
OPTION_APP_TAG: Final = "app_tag"

# Access application names: readable in the dashboard, and the way an application is
# found again when the stored ids are lost (together with the tag).
APP_NAME_PREFIX: Final = "ha-access:"
GATE_APP_NAME_FMT: Final = APP_NAME_PREFIX + " gate {hostname}"
BYPASS_APP_NAME_FMT: Final = APP_NAME_PREFIX + " bypass {hostname}"
CLIENT_APP_NAME_FMT: Final = APP_NAME_PREFIX + " client {hostname} {name}"
GATE_POLICY_NAME: Final = APP_NAME_PREFIX + " allow"
GATE_SERVICE_POLICY_NAME: Final = APP_NAME_PREFIX + " service tokens"
GATE_LINKED_POLICY_NAME: Final = APP_NAME_PREFIX + " registered clients"
BYPASS_POLICY_NAME: Final = APP_NAME_PREFIX + " bypass everyone"

# Entry changes (client subentries) come in bursts; reconciliation runs once they settle.
RECONCILE_COOLDOWN_SECONDS: Final = 5

# Links and example URLs shown in the forms. Home Assistant forbids URLs inside the
# translated strings, so they travel as description placeholders.
_CF_DOCS: Final = "https://developers.cloudflare.com/cloudflare-one/"
FORM_PLACEHOLDERS: Final[dict[str, str]] = {
    "docs_policies": _CF_DOCS + "access-controls/policies/",
    "docs_service_tokens": _CF_DOCS + "access-controls/service-credentials/service-tokens/",
    "docs_session": _CF_DOCS
    + "access-controls/access-settings/session-management/#application-session-duration",
    "docs_managed_oauth": _CF_DOCS + "access-controls/applications/http-apps/managed-oauth/",
    "example_mcp_redirect": "https://claude.ai/api/mcp/auth_callback",
    "example_wildcard_redirect": "https://example.com/*",
    "example_console_redirect": "https://oauth-redirect.googleusercontent.com/r/my-project",
    "docs_change_username": "https://www.home-assistant.io/docs/configuration/user-configuration/"
    "#changing-a-username",
    "docs_identity_providers": _CF_DOCS + "integrations/identity-providers/",
    "docs_saas_apps": "https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/saas-apps/",
}
DOCS_OAUTH_CLIENTS: Final = (
    "https://developers.cloudflare.com/fundamentals/api/how-to/oauth-clients/"
)
