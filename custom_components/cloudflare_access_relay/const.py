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
CONF_CLIENT_REDIRECT_URIS: Final = "client_redirect_uris"

DEFAULT_COOKIE_NAME: Final = "CF_Authorization"
DEFAULT_IDENTITY_CLAIM: Final = "email"
DEFAULT_USER_MATCH: Final = "username"
DEFAULT_RENEW_DAYS: Final = 3
DEFAULT_CHECK_INTERVAL_MIN: Final = 60
DEFAULT_DELETE_OBJECTS_ON_REMOVE: Final = True
DEFAULT_GATE_ENABLED: Final = False
# Cloudflare documents the application session ceiling as "one month".
DEFAULT_SESSION_DURATION: Final = "720h"

# Edge identity (see edge_auth.py): the middleware must be installed before the web
# server starts, so the first setup after installation asks for a restart.
ISSUE_RESTART_REQUIRED: Final = "restart_required"

# Registered OAuth clients (config subentries): clients that cannot register themselves
# get an Access for SaaS OIDC application each, whose tokens the gate accepts.
SUBENTRY_TYPE_CLIENT: Final = "oauth_client"
CONF_CLIENT_NAME: Final = "name"
CONF_REDIRECT_URIS: Final = "redirect_uris"
DATA_CLIENT_APP_ID: Final = "app_id"
DATA_CLIENT_ID: Final = "client_id"
DATA_CLIENT_SECRET: Final = "client_secret"

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

# The integration's own paths that must never require the Access cookie: the connect
# page and its JavaScript (loaded by a cookie-less WebView) and the relay API (called
# from that page with Home Assistant's own authentication). Core's login surface is
# discovered from the router instead (see paths.py). Every path is a prefix: Access
# inherits a path rule to everything below it.
OWN_BYPASS_PATHS: Final[tuple[str, ...]] = (URL_CONNECT, URL_STATIC, API_BASE)

# Unauthenticated at the HTTP level but reached only by a client that holds the frontend
# session (and therefore the cookie): these stay gated even though Home Assistant registers
# them with requires_auth = False. The relay's own callback must be gated by definition.
# The OAuth discovery documents stay gated because Access serves its own at these paths
# (managed OAuth): a self-registering client must find Access, not Home Assistant.
GATED_OPEN_PATHS: Final[tuple[str, ...]] = (
    "/api/websocket",
    "/api/onboarding",
    "/api/hassio",
    "/api/hassio_ingress",
    "/api/map_tiles",
    "/manifest.json",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    URL_CALLBACK,
)

# The companion app reports through a webhook whose only credential is its id in the URL.
# Unlike other webhook callers the app holds the Access cookie (the relay gave it one, and
# the Android app sends it with every request), so each device's webhook path is added to
# the gate application: a path longer than the bypassed `/api/webhook` prefix wins in
# Access. Discovered from the mobile_app config entries and kept in step as devices come
# and go.
MOBILE_APP_DOMAIN: Final = "mobile_app"
WEBHOOK_PATH: Final = "/api/webhook"

APP_NAME_PREFIX: Final = "ha-relay:"
GATE_APP_NAME_FMT: Final = APP_NAME_PREFIX + " gate {hostname}"
BYPASS_APP_NAME_FMT: Final = APP_NAME_PREFIX + " bypass {hostname}"
CLIENT_APP_NAME_FMT: Final = APP_NAME_PREFIX + " client {hostname} {name}"
GATE_POLICY_NAME: Final = APP_NAME_PREFIX + " allow"
GATE_SERVICE_POLICY_NAME: Final = APP_NAME_PREFIX + " service tokens"
GATE_LINKED_POLICY_NAME: Final = APP_NAME_PREFIX + " registered clients"
BYPASS_POLICY_NAME: Final = APP_NAME_PREFIX + " bypass everyone"

FLOW_TTL_SECONDS: Final = 600
FLOW_SWEEP_INTERVAL_SECONDS: Final = 60
# Component loads come in bursts during start-up; discovery re-runs once the burst settles.
REDISCOVER_COOLDOWN_SECONDS: Final = 5

NOTIFICATION_ID_ERROR: Final = f"{DOMAIN}_error"
NOTIFICATION_ID_RENEW: Final = f"{DOMAIN}_renew"
