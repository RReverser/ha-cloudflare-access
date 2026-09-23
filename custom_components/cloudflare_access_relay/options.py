"""Option defaults and the API client for an entry."""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry, ConfigSubentry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import (
    OAuth2TokenRequestReauthError,
    OAuth2TokenRequestTransientError,
)
from homeassistant.helpers import config_entry_oauth2_flow
from homeassistant.helpers.httpx_client import get_async_client

from .cloudflare_api import (
    CloudflareAccessApi,
    CloudflareAuthError,
    CloudflareUnavailableError,
)
from .const import (
    APP_TAG_FMT,
    CLIENT_KIND_LOGIN,
    CLIENT_KIND_SCRIPT,
    CONF_ACCOUNT_ID,
    CONF_API_TOKEN,
    CONF_CLIENT_KIND,
    CONF_CLIENT_REDIRECT_URIS,
    CONF_DELETE_OBJECTS_ON_REMOVE,
    CONF_EXTRA_BYPASS_PATHS,
    CONF_GATE_ENABLED,
    CONF_NEEDS_CREDENTIALS,
    CONF_REDIRECT_URIS,
    CONF_SERVICE_TOKEN_IDS,
    CONF_SESSION_DURATION,
    DATA_TOKEN,
    DATA_TOKEN_ID,
    DEFAULT_DELETE_OBJECTS_ON_REMOVE,
    DEFAULT_GATE_ENABLED,
    DEFAULT_SESSION_DURATION,
    OPTION_APP_TAG,
    OPTION_IDP_IDS,
    SUBENTRY_TYPE_CLIENT,
)

DEFAULT_OPTIONS: dict[str, Any] = {
    CONF_GATE_ENABLED: DEFAULT_GATE_ENABLED,
    CONF_SESSION_DURATION: DEFAULT_SESSION_DURATION,
    CONF_EXTRA_BYPASS_PATHS: [],
    CONF_DELETE_OBJECTS_ON_REMOVE: DEFAULT_DELETE_OBJECTS_ON_REMOVE,
}


def effective_options(entry: ConfigEntry) -> dict[str, Any]:
    """Return the entry options with defaults filled in."""
    return {**DEFAULT_OPTIONS, **entry.options}


def app_tag(entry: ConfigEntry) -> str:
    """Return the Access tag marking the applications of this entry."""
    return APP_TAG_FMT.format(entry_id=entry.entry_id.lower())


def client_subentries(entry: ConfigEntry, kind: str | None = None) -> dict[str, ConfigSubentry]:
    """Return the client subentries by subentry id, of one kind when given."""
    return {
        sid: sub
        for sid, sub in entry.subentries.items()
        if sub.subentry_type == SUBENTRY_TYPE_CLIENT
        and (kind is None or sub.data.get(CONF_CLIENT_KIND) == kind)
    }


def login_clients(entry: ConfigEntry) -> dict[str, ConfigSubentry]:
    """Return the clients that log people in."""
    return client_subentries(entry, CLIENT_KIND_LOGIN)


def script_clients(entry: ConfigEntry) -> dict[str, ConfigSubentry]:
    """Return the clients that run on their own with a service token."""
    return client_subentries(entry, CLIENT_KIND_SCRIPT)


def credentialed_clients(entry: ConfigEntry) -> dict[str, ConfigSubentry]:
    """Return the login clients that hold an Access application of their own."""
    return {
        sid: sub
        for sid, sub in login_clients(entry).items()
        if sub.data.get(CONF_NEEDS_CREDENTIALS)
    }


def client_redirect_uris(entry: ConfigEntry) -> list[str]:
    """Return every login client's redirect URLs: what the gate lets register itself."""
    return sorted(
        {uri for sub in login_clients(entry).values() for uri in sub.data[CONF_REDIRECT_URIS]}
    )


def service_token_ids(entry: ConfigEntry) -> list[str]:
    """Return the script clients' service token ids: what the gate's Service Auth rule names."""
    return sorted(
        {
            sub.data[DATA_TOKEN_ID]
            for sub in script_clients(entry).values()
            if sub.data.get(DATA_TOKEN_ID)
        }
    )


def provisioning_options(entry: ConfigEntry) -> dict[str, Any]:
    """Return the options as provisioning sees them: what the clients add, and the tag."""
    return {
        **effective_options(entry),
        CONF_CLIENT_REDIRECT_URIS: client_redirect_uris(entry),
        CONF_SERVICE_TOKEN_IDS: service_token_ids(entry),
        OPTION_APP_TAG: app_tag(entry),
    }


async def async_provisioning_options(
    entry: ConfigEntry, api: CloudflareAccessApi
) -> dict[str, Any]:
    """Return the provisioning options with what only Cloudflare knows: the login methods."""
    return {
        **provisioning_options(entry),
        OPTION_IDP_IDS: [idp["id"] for idp in await api.list_identity_providers() if idp.get("id")],
    }


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
        except OAuth2TokenRequestReauthError as err:
            raise CloudflareAuthError(f"Cloudflare refused to refresh the sign-in: {err}") from err
        except OAuth2TokenRequestTransientError as err:
            raise CloudflareUnavailableError(
                f"Cloudflare could not refresh the sign-in right now: {err}"
            ) from err
        return str(session.token["access_token"])

    return CloudflareAccessApi(
        str(session.token["access_token"]),
        entry.data[CONF_ACCOUNT_ID],
        http_client=get_async_client(hass),
        token_source=access_token,
    )
