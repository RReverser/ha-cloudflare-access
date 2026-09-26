"""Option defaults and the API client for an entry."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import (
    OAuth2TokenRequestReauthError,
    OAuth2TokenRequestTransientError,
)
from homeassistant.helpers import config_entry_oauth2_flow
from homeassistant.helpers.httpx_client import get_async_client
from homeassistant.helpers.network import NoURLAvailableError, get_url

from .cloudflare_api import (
    CloudflareAccessApi,
    CloudflareAuthError,
    CloudflareUnavailableError,
)
from .const import (
    APP_TAG_FMT,
    CONF_ACCOUNT_ID,
    CONF_API_TOKEN,
    CONF_CLIENT_REDIRECT_URIS,
    CONF_CONSOLE_APPS,
    CONF_DELETE_OBJECTS_ON_REMOVE,
    CONF_EXTRA_BYPASS_PATHS,
    CONF_GATE_ENABLED,
    CONF_HOSTNAME,
    CONF_LOGIN_EMAILS,
    CONF_SCRIPTS,
    CONF_SERVICE_TOKEN_IDS,
    CONF_SESSION_DURATION,
    DATA_TOKEN,
    DATA_TOKEN_ID,
    DEFAULT_DELETE_OBJECTS_ON_REMOVE,
    DEFAULT_GATE_ENABLED,
    DEFAULT_SESSION_DURATION,
    OPTION_APP_TAG,
    OPTION_IDP_IDS,
)

DEFAULT_OPTIONS: dict[str, Any] = {
    CONF_GATE_ENABLED: DEFAULT_GATE_ENABLED,
    CONF_SESSION_DURATION: DEFAULT_SESSION_DURATION,
    CONF_EXTRA_BYPASS_PATHS: [],
    CONF_DELETE_OBJECTS_ON_REMOVE: DEFAULT_DELETE_OBJECTS_ON_REMOVE,
    CONF_CLIENT_REDIRECT_URIS: [],
    CONF_CONSOLE_APPS: {},
    CONF_SCRIPTS: {},
}


# every key the options may hold: the defaults' plus what has no default (the login
# addresses by user id) and what a migration reads and removes
KNOWN_OPTIONS: frozenset[str] = frozenset(
    {*DEFAULT_OPTIONS, CONF_LOGIN_EMAILS, CONF_SERVICE_TOKEN_IDS, CONF_HOSTNAME}
)


def effective_options(entry: ConfigEntry) -> dict[str, Any]:
    """Return the entry options with defaults filled in."""
    return {**DEFAULT_OPTIONS, **entry.options}


def normalise_hostname(raw: str) -> str:
    """Accept 'ha.example.com', 'https://ha.example.com/' or with a path."""
    raw = raw.strip()
    if "://" in raw:
        raw = urlparse(raw).netloc
    return raw.split("/")[0].split(":")[0].strip().lower()


@callback
def external_hostname(hass: HomeAssistant) -> str:
    """Return the hostname of Home Assistant's External URL, the hostname the gate guards.

    Raises NoURLAvailableError when no External URL is configured.
    """
    # An internal address or a bare IP is not a hostname Cloudflare serves, and get_url
    # allows both by default (homeassistant.helpers.network.get_url).
    hostname = normalise_hostname(get_url(hass, allow_internal=False, allow_ip=False))
    if not hostname:
        raise NoURLAvailableError
    return hostname


def app_tag(entry: ConfigEntry) -> str:
    """Return the Access tag marking the applications of this entry."""
    return APP_TAG_FMT.format(entry_id=entry.entry_id.lower())


def console_clients(entry: ConfigEntry) -> dict[str, dict[str, Any]]:
    """Return the apps whose console takes a client id and secret, by id: each has an application."""
    return {cid: dict(app) for cid, app in (entry.options.get(CONF_CONSOLE_APPS) or {}).items()}


def script_clients(entry: ConfigEntry) -> dict[str, dict[str, Any]]:
    """Return the scripts, by id: each has a service token."""
    return {sid: dict(s) for sid, s in (entry.options.get(CONF_SCRIPTS) or {}).items()}


def client_redirect_uris(entry: ConfigEntry) -> list[str]:
    """Return the self-registering apps' callbacks: what the gate lets register."""
    return sorted({u.strip() for u in entry.options.get(CONF_CLIENT_REDIRECT_URIS) or [] if u})


def service_token_ids(entry: ConfigEntry) -> list[str]:
    """Return the script clients' service token ids: what the gate's Service Auth rule names."""
    return sorted(
        {s[DATA_TOKEN_ID] for s in script_clients(entry).values() if s.get(DATA_TOKEN_ID)}
    )


def provisioning_options(hass: HomeAssistant, entry: ConfigEntry) -> dict[str, Any]:
    """Return the options as provisioning sees them: the hostname, the clients' part, the tag.

    Raises NoURLAvailableError when Home Assistant has no External URL.
    """
    return {
        **effective_options(entry),
        CONF_HOSTNAME: external_hostname(hass),
        CONF_CLIENT_REDIRECT_URIS: client_redirect_uris(entry),
        CONF_SERVICE_TOKEN_IDS: service_token_ids(entry),
        OPTION_APP_TAG: app_tag(entry),
    }


async def async_provisioning_options(
    hass: HomeAssistant, entry: ConfigEntry, api: CloudflareAccessApi
) -> dict[str, Any]:
    """Return the provisioning options with what only Cloudflare knows: the login methods."""
    return {
        **provisioning_options(hass, entry),
        OPTION_IDP_IDS: [idp["id"] for idp in await api.list_identity_providers() if idp.get("id")],
    }


async def api_for(hass: HomeAssistant, entry: ConfigEntry) -> CloudflareAccessApi:
    """Return the Cloudflare API client for the entry's credentials.

    An entry created by signing in with Cloudflare holds an OAuth token set; one created
    with an API token holds the token.
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
        # Only the errors are mapped: a refused refresh already starts the reauth flow in
        # OAuth2Session.async_ensure_token_valid (homeassistant.helpers.config_entry_oauth2_flow).
        try:
            await session.async_ensure_token_valid()
        except OAuth2TokenRequestReauthError as err:
            raise CloudflareAuthError(f"Cloudflare refused to refresh the sign-in: {err}") from err
        except OAuth2TokenRequestTransientError as err:
            raise CloudflareUnavailableError(
                f"Cloudflare could not refresh the sign-in right now: {err}"
            ) from err
        return str(session.token["access_token"])

    # The client refreshes through token_source before every call; the first argument
    # only seeds it.
    return CloudflareAccessApi(
        str(session.token["access_token"]),
        entry.data[CONF_ACCOUNT_ID],
        http_client=get_async_client(hass),
        token_source=access_token,
    )
