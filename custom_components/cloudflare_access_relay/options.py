"""Option defaults and the API client for an entry."""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.httpx_client import get_async_client

from .cloudflare_api import CloudflareAccessApi
from .const import (
    CONF_ACCOUNT_ID,
    CONF_API_TOKEN,
    CONF_CLIENT_REDIRECT_URIS,
    CONF_DELETE_OBJECTS_ON_REMOVE,
    CONF_EXTRA_BYPASS_PATHS,
    CONF_GATE_ENABLED,
    CONF_IDENTITY_CLAIM,
    CONF_SERVICE_TOKEN_IDS,
    CONF_SESSION_DURATION,
    CONF_USER_MATCH,
    DEFAULT_DELETE_OBJECTS_ON_REMOVE,
    DEFAULT_GATE_ENABLED,
    DEFAULT_IDENTITY_CLAIM,
    DEFAULT_SESSION_DURATION,
    DEFAULT_USER_MATCH,
)

DEFAULT_OPTIONS: dict[str, Any] = {
    CONF_GATE_ENABLED: DEFAULT_GATE_ENABLED,
    CONF_SERVICE_TOKEN_IDS: [],
    CONF_SESSION_DURATION: DEFAULT_SESSION_DURATION,
    CONF_CLIENT_REDIRECT_URIS: [],
    CONF_EXTRA_BYPASS_PATHS: [],
    CONF_IDENTITY_CLAIM: DEFAULT_IDENTITY_CLAIM,
    CONF_USER_MATCH: DEFAULT_USER_MATCH,
    CONF_DELETE_OBJECTS_ON_REMOVE: DEFAULT_DELETE_OBJECTS_ON_REMOVE,
}


def effective_options(entry: ConfigEntry) -> dict[str, Any]:
    """Return the entry options with defaults filled in."""
    return {**DEFAULT_OPTIONS, **entry.options}


def api_for(hass: HomeAssistant, entry: ConfigEntry) -> CloudflareAccessApi:
    """Return the Cloudflare API client for the entry's credentials."""
    return CloudflareAccessApi(
        entry.data[CONF_API_TOKEN],
        entry.data[CONF_ACCOUNT_ID],
        http_client=get_async_client(hass),
    )
