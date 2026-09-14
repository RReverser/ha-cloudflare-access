"""Cloudflare Access relay for the Home Assistant companion app.

Copies the Cloudflare Access application token a user earned in the system
browser into the companion app's shared cookie jar, and provisions the Access
applications (gate + bypass) that make the hostname safe to gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import logging
from pathlib import Path
from typing import Any

from homeassistant.components.frontend import add_extra_js_url, remove_extra_js_url
from homeassistant.components.http.server import StaticPathConfig
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import (
    ConfigEntryAuthFailed,
    ConfigEntryError,
    ConfigEntryNotReady,
)
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.httpx_client import get_async_client

from .cloudflare_api import (
    CloudflareAccessApi,
    CloudflareApiError,
    CloudflareAuthError,
    CloudflareUnavailableError,
)
from .const import (
    CONF_ACCOUNT_ID,
    CONF_API_TOKEN,
    CONF_CHECK_INTERVAL_MIN,
    CONF_COOKIE_NAME,
    CONF_DELETE_OBJECTS_ON_REMOVE,
    CONF_EXTRA_BYPASS_PATHS,
    CONF_GATE_ENABLED,
    CONF_IDENTITY_CLAIM,
    CONF_RENEW_DAYS,
    CONF_SERVICE_TOKEN_IDS,
    CONF_SESSION_DURATION,
    CONF_USER_MATCH,
    DATA_BYPASS_APP_ID,
    DATA_GATE_APP_ID,
    DATA_POLICY_AUD,
    DATA_TEAM_DOMAIN,
    DEFAULT_CHECK_INTERVAL_MIN,
    DEFAULT_COOKIE_NAME,
    DEFAULT_DELETE_OBJECTS_ON_REMOVE,
    DEFAULT_GATE_ENABLED,
    DEFAULT_IDENTITY_CLAIM,
    DEFAULT_RENEW_DAYS,
    DEFAULT_SESSION_DURATION,
    DEFAULT_USER_MATCH,
    DOMAIN,
    FLOW_SWEEP_INTERVAL_SECONDS,
    URL_RELAY_JS,
    URL_STATIC,
    VERSION,
)
from .flows import FlowStore
from .jwks import JwksVerifier
from .paths import discover_login_paths
from .provision import async_delete_apps, async_provision
from .views import CallbackView, ConnectView, FlowCreateView, SessionView, StatusView

_LOGGER = logging.getLogger(__name__)

DEFAULT_OPTIONS: dict[str, Any] = {
    CONF_EXTRA_BYPASS_PATHS: [],
    CONF_SERVICE_TOKEN_IDS: [],
    CONF_COOKIE_NAME: DEFAULT_COOKIE_NAME,
    CONF_IDENTITY_CLAIM: DEFAULT_IDENTITY_CLAIM,
    CONF_USER_MATCH: DEFAULT_USER_MATCH,
    CONF_RENEW_DAYS: DEFAULT_RENEW_DAYS,
    CONF_CHECK_INTERVAL_MIN: DEFAULT_CHECK_INTERVAL_MIN,
    CONF_DELETE_OBJECTS_ON_REMOVE: DEFAULT_DELETE_OBJECTS_ON_REMOVE,
    CONF_GATE_ENABLED: DEFAULT_GATE_ENABLED,
    CONF_SESSION_DURATION: DEFAULT_SESSION_DURATION,
}

_HTTP_REGISTERED = f"{DOMAIN}_http_registered"
_WWW_DIR = Path(__file__).parent / "www"


@dataclass
class RelayData:
    """Runtime state of one config entry."""

    entry: ConfigEntry
    options: dict[str, Any]
    api: CloudflareAccessApi
    verifier: JwksVerifier
    flows: FlowStore
    policy_aud: str
    team_domain: str


type RelayConfigEntry = ConfigEntry[RelayData]


def effective_options(entry: ConfigEntry) -> dict[str, Any]:
    """Return the entry options with defaults filled in."""
    return {**DEFAULT_OPTIONS, **entry.options}


def _api_for(hass: HomeAssistant, entry: ConfigEntry) -> CloudflareAccessApi:
    return CloudflareAccessApi(
        entry.data[CONF_API_TOKEN],
        entry.data[CONF_ACCOUNT_ID],
        http_client=get_async_client(hass),
    )


async def async_setup_entry(hass: HomeAssistant, entry: RelayConfigEntry) -> bool:
    """Provision the Access applications and expose the relay endpoints."""
    options = effective_options(entry)
    api = _api_for(hass, entry)
    try:
        result = await async_provision(
            api,
            options,
            set(hass.config.components),
            discover_login_paths(hass),
            gate_app_id=entry.data.get(DATA_GATE_APP_ID),
            bypass_app_id=entry.data.get(DATA_BYPASS_APP_ID),
            team_domain=entry.data.get(DATA_TEAM_DOMAIN),
        )
    except CloudflareAuthError as err:
        raise ConfigEntryAuthFailed(str(err)) from err
    except CloudflareUnavailableError as err:
        raise ConfigEntryNotReady(str(err)) from err
    except CloudflareApiError as err:
        raise ConfigEntryError(f"Cloudflare rejected the configuration: {err}") from err

    derived = {
        DATA_TEAM_DOMAIN: result.team_domain,
        DATA_POLICY_AUD: result.policy_aud,
        DATA_GATE_APP_ID: result.gate_app_id,
        DATA_BYPASS_APP_ID: result.bypass_app_id,
    }
    if any(entry.data.get(k) != v for k, v in derived.items()):
        hass.config_entries.async_update_entry(entry, data={**entry.data, **derived})
    if result.writes:
        _LOGGER.info("Cloudflare Access objects written: %s", ", ".join(result.writes))

    data = RelayData(
        entry=entry,
        options=options,
        api=api,
        verifier=JwksVerifier(get_async_client(hass), result.team_domain),
        flows=FlowStore(),
        policy_aud=result.policy_aud,
        team_domain=result.team_domain,
    )
    entry.runtime_data = data
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = data

    await _async_register_http(hass)

    js_url = f"{URL_RELAY_JS}?v={VERSION}"
    add_extra_js_url(hass, js_url)
    entry.async_on_unload(lambda: remove_extra_js_url(hass, js_url))

    @callback
    def _sweep(_now: Any) -> None:
        if removed := data.flows.sweep():
            _LOGGER.debug("Swept %d expired relay flows", removed)

    entry.async_on_unload(
        async_track_time_interval(hass, _sweep, timedelta(seconds=FLOW_SWEEP_INTERVAL_SECONDS))
    )
    return True


async def _async_register_http(hass: HomeAssistant) -> None:
    """Register views and the static path once per HA run."""
    if hass.data.get(_HTTP_REGISTERED):
        return
    hass.data[_HTTP_REGISTERED] = True
    await hass.http.async_register_static_paths(
        [StaticPathConfig(URL_STATIC, str(_WWW_DIR), False)]
    )
    hass.http.register_view(FlowCreateView())
    hass.http.register_view(StatusView())
    hass.http.register_view(SessionView())
    hass.http.register_view(CallbackView())
    hass.http.register_view(ConnectView(_WWW_DIR))


async def async_unload_entry(hass: HomeAssistant, entry: RelayConfigEntry) -> bool:
    """Unload the entry; views stay registered but answer 503."""
    entries: dict[str, RelayData] = hass.data.get(DOMAIN) or {}
    entries.pop(entry.entry_id, None)
    return True


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Delete the Cloudflare objects when the entry is removed, if asked to."""
    options = effective_options(entry)
    if not options[CONF_DELETE_OBJECTS_ON_REMOVE]:
        return
    api = _api_for(hass, entry)
    try:
        await async_delete_apps(
            api, entry.data.get(DATA_GATE_APP_ID), entry.data.get(DATA_BYPASS_APP_ID)
        )
    except (CloudflareAuthError, CloudflareUnavailableError, CloudflareApiError) as err:
        _LOGGER.warning("Could not delete the Access applications; remove them by hand: %s", err)
