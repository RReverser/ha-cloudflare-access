"""Constants for the Cloudflare Access integration."""

from __future__ import annotations

from typing import Any, Final

from homeassistant.util.event_type import EventType

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

# Options. The hostname is not an option: it is Home Assistant's External URL, read at
# provisioning time (`CONF_HOSTNAME` is the provisioning key; earlier versions stored it).
CONF_HOSTNAME: Final = "hostname"
CONF_GATE_ENABLED: Final = "gate_enabled"
CONF_SESSION_DURATION: Final = "session_duration"
# Derived from the client subentries at provisioning time, never edited directly: the
# login clients' redirect URLs, and the script clients' service token ids (which an
# earlier version kept as an option).
CONF_CLIENT_REDIRECT_URIS: Final = "client_redirect_uris"
CONF_SERVICE_TOKEN_IDS: Final = "service_token_ids"
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

# Signing in with Cloudflare: a self-managed OAuth client with PKCE and no secret, asking
# for exactly what the integration does (README, "Sign-in", explains each scope).
OAUTH_AUTHORIZE_URL: Final = "https://dash.cloudflare.com/oauth2/auth"
OAUTH_TOKEN_URL: Final = "https://dash.cloudflare.com/oauth2/token"
OAUTH_SCOPES: Final[tuple[str, ...]] = (
    "access.write",
    "access-acct.read",
    "access-service-token.write",
    "access-org.revoke",
    "access-audit-log.read",
    "memberships.read",
    "offline_access",
)
# The project's public OAuth client (PKCE, no secret), maintained by scripts/oauth_client.py.
# A credential added under Settings → Application credentials is offered next to it.
OAUTH_CLIENT_ID: Final = "2743d292a690169c8ed4dc4473382227"

# Repair issues. Each one whose remedy is an action offers it as a fix flow (repairs.py);
# the issue's data names the entry and carries what the flow needs. A credential that
# lacks a permission (an older sign-in, an API token without it) starts the
# re-authentication flow instead of an issue: signing in again is the remedy.
ISSUE_NO_ALLOWED_USERS: Final = "no_allowed_users"
# Someone logged in at the identity provider but is not on the allow list.
ISSUE_DENIED_LOGIN: Final = "denied_login"
# HA-MCP demands its own login on a webhook the gate also guards.
ISSUE_MCP_AUTH_CONFLICT: Final = "mcp_auth_conflict"
# Home Assistant's External URL was removed after setup.
ISSUE_NO_EXTERNAL_URL: Final = "no_external_url"
# Cloudflare refused or could not take an update of the applications after a change.
ISSUE_UPDATE_FAILED: Final = "update_failed"

# The HA-MCP custom component, whose login modes clash with the gate (README, "MCP servers
# behind the gate"): its config entry domain, the option holding the mode and the value
# that works behind the gate, and the entry data holding its webhook id.
HA_MCP_DOMAIN: Final = "ha_mcp_tools"
HA_MCP_OPT_AUTH: Final = "webhook_auth"
HA_MCP_AUTH_NONE: Final = "none"
HA_MCP_OPT_WEBHOOK_ENABLED: Final = "enable_webhook"
HA_MCP_DATA_WEBHOOK_ID: Final = "webhook_id"

# Login history: Access's authentication logs are polled (Cloudflare pushes nothing on the
# Free plan, which keeps them for 24 hours) and turned into an event per login attempt and
# a repair issue for a denied login. The interval is the coordinator's default; Home
# Assistant's system options can turn polling off.
EVENT_LOGIN = EventType[dict[str, Any]]("cloudflare_access_relay_login")
LOG_POLL_INTERVAL_SECONDS: Final = 15 * 60
LOGS_STORE_VERSION: Final = 1

# Edge identity (see edge_auth.py): raised when the running web server cannot take the
# middleware, which no restart fixes.
ISSUE_MIDDLEWARE_UNAVAILABLE: Final = "middleware_unavailable"
# Raised by versions before 0.2.0 after every start; deleted once at setup.
LEGACY_ISSUE_RESTART_REQUIRED: Final = "restart_required"
HEADER_JWT: Final = "Cf-Access-Jwt-Assertion"
HEADER_CF_RAY: Final = "CF-Ray"

# Login e-mails: the address Access knows a person by, for people whose login username
# is not one. Kept in the options by user id; the form shows a "People" section with a
# field per person, named after them (an untranslated field is labelled with its name).
CONF_LOGIN_EMAILS: Final = "login_emails"
SECTION_PEOPLE: Final = "people"
# Earlier versions kept the addresses as subentries of this type; they are migrated.
SUBENTRY_TYPE_LOGIN_EMAIL: Final = "login_email"
CONF_USER_ID: Final = "user_id"
CONF_EMAIL: Final = "email"

# Clients are config subentries, one subentry type per kind so the entry page labels each
# row with its kind. A self-registering app (an MCP client: Claude, ChatGPT) finds the
# login by discovery on the hostname and registers with the gate's managed OAuth; the gate
# starts a login only for a listed callback URL, and nothing else about such a client
# exists on Cloudflare (docs/verified-cloudflare-behaviour.md). A console app (Google Home,
# Alexa) takes a client id, secret and endpoints: it gets an Access for SaaS OIDC
# application of its own, whose tokens the gate accepts through a rule naming it. A script
# is a machine with nobody behind it: it gets an Access service token, whose Client ID and
# secret it sends as request headers, and the gate's Service Auth policy names it.
SUBENTRY_TYPE_SELF_REGISTERING: Final = "self_registering_app"
SUBENTRY_TYPE_CONSOLE: Final = "console_app"
SUBENTRY_TYPE_SCRIPT: Final = "script"
CLIENT_SUBENTRY_TYPES: Final = (
    SUBENTRY_TYPE_SELF_REGISTERING,
    SUBENTRY_TYPE_CONSOLE,
    SUBENTRY_TYPE_SCRIPT,
)
# before 0.3.0 every client was one subentry type, with the kind in its data
LEGACY_SUBENTRY_TYPE_CLIENT: Final = "oauth_client"
LEGACY_CONF_CLIENT_KIND: Final = "kind"
CONF_CLIENT_NAME: Final = "name"
CONF_REDIRECT_URIS: Final = "redirect_uris"
DATA_CLIENT_APP_ID: Final = "app_id"
DATA_CLIENT_ID: Final = "client_id"
DATA_CLIENT_SECRET: Final = "client_secret"
DATA_TOKEN_ID: Final = "token_id"
DATA_TOKEN_EXPIRES_AT: Final = "expires_at"

# Every application the integration creates carries an Access tag naming the config
# entry (derived from its id at provisioning time, `OPTION_APP_TAG`). Only applications
# with this entry's tag are ever updated or deleted; a stored id or a matching name
# without the tag is somebody else's. Cloudflare caps a tag name at 35 characters; the
# entry id is 26.
APP_TAG_FMT: Final = "hass-{entry_id}"
OPTION_APP_TAG: Final = "app_tag"
# The organization's identity providers, read at provisioning time: with exactly one, the
# gate sends people straight to it instead of showing Cloudflare's picker page.
OPTION_IDP_IDS: Final = "idp_ids"
# Shown by Access to a person who logged in but is not on the allow list. Cloudflare
# allows at most 75 characters and refuses punctuation (", . ! : @ ? -" by its own
# message; a semicolon was refused too), so letters, digits and spaces only.
DENY_MESSAGE: Final = "Not allowed in yet ask the Home Assistant owner to add you under People"

# Access application names: readable in the dashboard, and the way an application is
# found again when the stored ids are lost (together with the tag).
APP_NAME_PREFIX: Final = "ha-access:"
GATE_APP_NAME_FMT: Final = APP_NAME_PREFIX + " gate {hostname}"
BYPASS_APP_NAME_FMT: Final = APP_NAME_PREFIX + " bypass {hostname}"
CLIENT_APP_NAME_FMT: Final = APP_NAME_PREFIX + " client {hostname} {name}"
# A script client's service token is named the same way; the name is how a token of a
# removed client is found again (tokens carry no tags).
SERVICE_TOKEN_NAME_FMT: Final = CLIENT_APP_NAME_FMT
GATE_POLICY_NAME: Final = APP_NAME_PREFIX + " allow"
GATE_SERVICE_POLICY_NAME: Final = APP_NAME_PREFIX + " service tokens"
GATE_LINKED_POLICY_NAME: Final = APP_NAME_PREFIX + " registered clients"
BYPASS_POLICY_NAME: Final = APP_NAME_PREFIX + " bypass everyone"

# Entry changes (client subentries) come in bursts; reconciliation runs once they settle.
RECONCILE_COOLDOWN_SECONDS: Final = 5

# Callback URLs of the agent apps that register themselves at the gate, offered as choices
# for a self-registering client's callback URLs (any URL can still be typed). Only fixed
# URLs the vendor publishes are listed, with the page they come from. A console client
# (Google Home, Alexa) shows its own exact callback, with a project or vendor id in it,
# which is typed on its own page. Tools that run on a person's own computer (Claude Code,
# Cursor, VS Code) call back on localhost, which is not a list entry at Access.
KNOWN_REDIRECT_URIS: Final[tuple[tuple[str, str], ...]] = (
    # https://claude.com/docs/connectors/building/authentication
    ("https://claude.ai/api/mcp/auth_callback", "Claude"),
    # https://developers.openai.com/apps-sdk/build/auth
    ("https://chatgpt.com/connector_platform_oauth_redirect", "ChatGPT"),
    ("https://chatgpt.com/connector/oauth/*", "ChatGPT (per-connection callbacks)"),
)

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
    "docs_external_url": "https://www.home-assistant.io/docs/configuration/basic/#editing-the-network-settings",
}
DOCS_OAUTH_CLIENTS: Final = (
    "https://developers.cloudflare.com/fundamentals/api/how-to/oauth-clients/"
)
