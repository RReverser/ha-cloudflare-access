"""Constants for the Cloudflare Access relay integration."""

from __future__ import annotations

from typing import Final

DOMAIN: Final = "cloudflare_access_relay"
VERSION: Final = "0.1.0"

# Config entry data (immutable credentials + derived values)
CONF_API_TOKEN: Final = "api_token"
CONF_ACCOUNT_ID: Final = "account_id"
DATA_TEAM_DOMAIN: Final = "team_domain"
DATA_POLICY_AUD: Final = "policy_aud"
DATA_GATE_APP_ID: Final = "gate_app_id"
DATA_BYPASS_APP_ID: Final = "bypass_app_id"

# Options
CONF_HOSTNAME: Final = "hostname"
CONF_ALLOWED_EMAILS: Final = "allowed_emails"
CONF_ACCESS_GROUP_ID: Final = "access_group_id"
CONF_EXTRA_BYPASS_PATHS: Final = "extra_bypass_paths"
CONF_SERVICE_TOKEN_IDS: Final = "service_token_ids"
CONF_COOKIE_NAME: Final = "cookie_name"
CONF_IDENTITY_CLAIM: Final = "identity_claim"
CONF_USER_MATCH: Final = "user_match"
CONF_RENEW_DAYS: Final = "renew_days"
CONF_CHECK_INTERVAL_MIN: Final = "check_interval_min"
CONF_DELETE_OBJECTS_ON_REMOVE: Final = "delete_objects_on_remove"
CONF_GATE_ENABLED: Final = "gate_enabled"
CONF_SESSION_DURATION: Final = "session_duration"

DEFAULT_COOKIE_NAME: Final = "CF_Authorization"
DEFAULT_IDENTITY_CLAIM: Final = "email"
DEFAULT_USER_MATCH: Final = "username"
DEFAULT_RENEW_DAYS: Final = 3
DEFAULT_CHECK_INTERVAL_MIN: Final = 60
DEFAULT_DELETE_OBJECTS_ON_REMOVE: Final = True
DEFAULT_GATE_ENABLED: Final = False
# Cloudflare documents the application session ceiling as "one month".
DEFAULT_SESSION_DURATION: Final = "720h"

USER_MATCH_NAME: Final = "name"

# HTTP surface
URL_BASE: Final = "/cloudflare_access_relay"
URL_CONNECT: Final = f"{URL_BASE}/connect"
URL_CALLBACK: Final = f"{URL_BASE}/callback"
URL_STATIC: Final = f"{URL_BASE}/static"
URL_RELAY_JS: Final = f"{URL_STATIC}/relay.js"
API_BASE: Final = f"/api/{DOMAIN}"
API_FLOW: Final = f"{API_BASE}/flow"
API_STATUS: Final = f"{API_BASE}/status"
API_SESSION: Final = f"{API_BASE}/session"

HEADER_JWT: Final = "Cf-Access-Jwt-Assertion"
HEADER_CF_RAY: Final = "CF-Ray"

# Paths (hostname-relative) that must never require the Access cookie.
# Every path is a prefix: Access inherits a path rule to everything below it.
BASE_BYPASS_PATHS: Final[tuple[str, ...]] = (
    "/auth",
    "/frontend_latest",
    "/frontend_es5",
    "/static",
    URL_CONNECT,
    URL_STATIC,
    API_BASE,
)

# Bypass paths added automatically when the named integration is loaded.
INTEGRATION_BYPASS_PATHS: Final[dict[str, tuple[str, ...]]] = {
    "openid": ("/openid",),
    "google_assistant": ("/api/google_assistant",),
    "alexa": ("/api/alexa",),
}

APP_NAME_PREFIX: Final = "ha-relay:"
GATE_APP_NAME_FMT: Final = APP_NAME_PREFIX + " gate {hostname}"
BYPASS_APP_NAME_FMT: Final = APP_NAME_PREFIX + " bypass {hostname}"
GATE_POLICY_NAME: Final = APP_NAME_PREFIX + " allow"
GATE_SERVICE_POLICY_NAME: Final = APP_NAME_PREFIX + " service tokens"
BYPASS_POLICY_NAME: Final = APP_NAME_PREFIX + " bypass everyone"

FLOW_TTL_SECONDS: Final = 600
FLOW_SWEEP_INTERVAL_SECONDS: Final = 60

NOTIFICATION_ID_ERROR: Final = f"{DOMAIN}_error"
NOTIFICATION_ID_RENEW: Final = f"{DOMAIN}_renew"
