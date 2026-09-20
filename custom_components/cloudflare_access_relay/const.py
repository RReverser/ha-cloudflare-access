"""Constants for the Cloudflare Access integration."""

from __future__ import annotations

from typing import Final

DOMAIN: Final = "cloudflare_access_relay"
VERSION: Final = "0.2.0"

# Config entry data (immutable credentials + derived values)
CONF_API_TOKEN: Final = "api_token"
CONF_ACCOUNT_ID: Final = "account_id"
DATA_TEAM_DOMAIN: Final = "team_domain"
DATA_POLICY_AUD: Final = "policy_aud"
DATA_GATE_APP_ID: Final = "gate_app_id"
DATA_BYPASS_APP_ID: Final = "bypass_app_id"

# Options
CONF_HOSTNAME: Final = "hostname"
CONF_GATE_ENABLED: Final = "gate_enabled"
CONF_ALLOWED_EMAILS: Final = "allowed_emails"
CONF_ACCESS_GROUP_ID: Final = "access_group_id"
CONF_SERVICE_TOKEN_IDS: Final = "service_token_ids"
CONF_SESSION_DURATION: Final = "session_duration"
CONF_CLIENT_REDIRECT_URIS: Final = "client_redirect_uris"
CONF_EXTRA_BYPASS_PATHS: Final = "extra_bypass_paths"
CONF_IDENTITY_CLAIM: Final = "identity_claim"
CONF_USER_MATCH: Final = "user_match"
CONF_DELETE_OBJECTS_ON_REMOVE: Final = "delete_objects_on_remove"

DEFAULT_GATE_ENABLED: Final = False
# Cloudflare documents the application session ceiling as "one month".
DEFAULT_SESSION_DURATION: Final = "720h"
DEFAULT_IDENTITY_CLAIM: Final = "email"
DEFAULT_USER_MATCH: Final = "username"
DEFAULT_DELETE_OBJECTS_ON_REMOVE: Final = True

USER_MATCH_NAME: Final = "name"

# Edge identity (see edge_auth.py): the middleware must be installed before the web
# server starts, so the first setup after installation asks for a restart.
ISSUE_RESTART_REQUIRED: Final = "restart_required"
HEADER_JWT: Final = "Cf-Access-Jwt-Assertion"
HEADER_CF_RAY: Final = "CF-Ray"

# Registered OAuth clients (config subentries): clients that cannot register themselves
# get an Access for SaaS OIDC application each, whose tokens the gate accepts.
SUBENTRY_TYPE_CLIENT: Final = "oauth_client"
CONF_CLIENT_NAME: Final = "name"
CONF_REDIRECT_URIS: Final = "redirect_uris"
DATA_CLIENT_APP_ID: Final = "app_id"
DATA_CLIENT_ID: Final = "client_id"
DATA_CLIENT_SECRET: Final = "client_secret"

# Access application names: the integration owns every application with this prefix
# for its hostname, and looks them up by name when the stored ids are lost.
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
