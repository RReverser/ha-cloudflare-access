"""Option defaults and the API client for an entry."""

from __future__ import annotations

from typing import Any

from aiohttp import ClientResponseError
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_entry_oauth2_flow
from homeassistant.helpers.httpx_client import get_async_client

from .cloudflare_api import CloudflareAccessApi, CloudflareAuthError
from .const import (
    CONF_ACCOUNT_ID,
    CONF_API_TOKEN,
    CONF_CLIENT_REDIRECT_URIS,
    CONF_DELETE_OBJECTS_ON_REMOVE,
    CONF_EXTRA_BYPASS_PATHS,
    CONF_GATE_ENABLED,
    CONF_SERVICE_TOKEN_IDS,
    CONF_SESSION_DURATION,
    DATA_TOKEN,
    DEFAULT_DELETE_OBJECTS_ON_REMOVE,
    DEFAULT_GATE_ENABLED,
    DEFAULT_SESSION_DURATION,
)

DEFAULT_OPTIONS: dict[str, Any] = {
    CONF_GATE_ENABLED: DEFAULT_GATE_ENABLED,
    CONF_SERVICE_TOKEN_IDS: [],
    CONF_SESSION_DURATION: DEFAULT_SESSION_DURATION,
    CONF_CLIENT_REDIRECT_URIS: [],
    CONF_EXTRA_BYPASS_PATHS: [],
    CONF_DELETE_OBJECTS_ON_REMOVE: DEFAULT_DELETE_OBJECTS_ON_REMOVE,
}


def effective_options(entry: ConfigEntry) -> dict[str, Any]:
    """Return the entry options with defaults filled in."""
    return {**DEFAULT_OPTIONS, **entry.options}


async def api_for(hass: HomeAssistant, entry: ConfigEntry) -> CloudflareAccessApi:
    """Return the Cloudflare API client for the entry's credentials.

    An entry created by signing in with Cloudflare holds an OAuth token set, refreshed
    before every call; one created with an API token holds the token.
    """
    if DATA_TOKEN not in entry.data:
        return CloudflareAccessApi(
            entry.data[CONF_API_TOKEN],
            entry.data[CONF_ACCOUNT_ID],
            http_client=get_async_client(hass),
        )
    implementation = await config_entry_oauth2_flow.async_get_config_entry_implementation(
        hass, entry
    )
    session = config_entry_oauth2_flow.OAuth2Session(hass, entry, implementation)

    async def access_token() -> str:
        try:
            await session.async_ensure_token_valid()
        except ClientResponseError as err:
            if err.status in (400, 401):
                raise CloudflareAuthError(
                    f"Cloudflare refused to refresh the sign-in: {err}"
                ) from err
            raise
        return str(session.token["access_token"])

    return CloudflareAccessApi(
        str(session.token["access_token"]),
        entry.data[CONF_ACCOUNT_ID],
        http_client=get_async_client(hass),
        token_source=access_token,
    )
