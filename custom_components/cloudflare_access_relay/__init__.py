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
from homeassistant.config_entries import (
    SIGNAL_CONFIG_ENTRY_CHANGED,
    ConfigEntry,
    ConfigEntryChange,
)
from homeassistant.const import (
    CONF_WEBHOOK_ID,
    EVENT_COMPONENT_LOADED,
    EVENT_HOMEASSISTANT_STOP,
)
from homeassistant.core import Event, HomeAssistant, callback
from homeassistant.exceptions import (
    ConfigEntryAuthFailed,
    ConfigEntryError,
    ConfigEntryNotReady,
)
from homeassistant.helpers.debounce import Debouncer
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.httpx_client import get_async_client
from homeassistant.helpers.start import async_at_started

from .bound import BoundTokens, async_install_middleware
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
    CONF_REQUIRE_BOUND_TOKENS,
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
    DEFAULT_REQUIRE_BOUND_TOKENS,
    DEFAULT_SESSION_DURATION,
    DEFAULT_USER_MATCH,
    DOMAIN,
    FLOW_SWEEP_INTERVAL_SECONDS,
    MOBILE_APP_DOMAIN,
    REDISCOVER_COOLDOWN_SECONDS,
    URL_RELAY_JS,
    URL_STATIC,
    VERSION,
    WEBHOOK_PATH,
)
from .flows import FlowStore
from .jwks import JwksVerifier
from .paths import discover_open_paths
from .provision import ProvisionResult, async_delete_apps, async_provision
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
    CONF_REQUIRE_BOUND_TOKENS: DEFAULT_REQUIRE_BOUND_TOKENS,
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
    open_paths: list[str]
    # Companion-app device webhook paths, gated although they lie under a bypassed prefix.
    gated_paths: list[str]
    bound: BoundTokens
    # Whether the vendor endpoints are bypassed at the edge (see async_setup_entry).
    vendor_bypass: bool


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


async def _async_provision_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    api: CloudflareAccessApi,
    options: dict[str, Any],
    open_paths: list[str],
    gated_paths: list[str],
    *,
    vendor_paths: bool,
) -> ProvisionResult:
    """Reconcile the Access applications and persist what Cloudflare derived."""
    result = await async_provision(
        api,
        options,
        open_paths,
        gate_app_id=entry.data.get(DATA_GATE_APP_ID),
        bypass_app_id=entry.data.get(DATA_BYPASS_APP_ID),
        team_domain=entry.data.get(DATA_TEAM_DOMAIN),
        vendor_paths=vendor_paths,
        gated_paths=gated_paths,
    )
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
    return result


async def async_setup_entry(hass: HomeAssistant, entry: RelayConfigEntry) -> bool:
    """Provision the Access applications and expose the relay endpoints."""
    options = effective_options(entry)
    api = _api_for(hass, entry)
    await _async_register_http(hass)
    # With Access-bound tokens required, the vendor endpoints are bypassed at the edge only
    # while the origin can enforce the rule on them; otherwise they stay gated until a
    # restart installs the middleware.
    require_bound = bool(options[CONF_REQUIRE_BOUND_TOKENS])
    vendor_bypass = not require_bound or async_install_middleware(hass)
    bound = BoundTokens(hass)
    await bound.async_load()
    open_paths = discover_open_paths(hass)
    gated_paths = device_webhook_paths(hass)
    try:
        result = await _async_provision_entry(
            hass, entry, api, options, open_paths, gated_paths, vendor_paths=vendor_bypass
        )
    except CloudflareAuthError as err:
        raise ConfigEntryAuthFailed(str(err)) from err
    except CloudflareUnavailableError as err:
        raise ConfigEntryNotReady(str(err)) from err
    except CloudflareApiError as err:
        raise ConfigEntryError(f"Cloudflare rejected the configuration: {err}") from err

    data = RelayData(
        entry=entry,
        options=options,
        api=api,
        verifier=JwksVerifier(get_async_client(hass), result.team_domain),
        flows=FlowStore(),
        policy_aud=result.policy_aud,
        team_domain=result.team_domain,
        open_paths=open_paths,
        gated_paths=gated_paths,
        bound=bound,
        vendor_bypass=vendor_bypass,
    )
    entry.runtime_data = data
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = data

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
    _async_track_surface(hass, entry, data)
    return True


@callback
def device_webhook_paths(hass: HomeAssistant) -> list[str]:
    """Return the webhook path of every companion-app device, sorted."""
    return sorted(
        f"{WEBHOOK_PATH}/{entry.data[CONF_WEBHOOK_ID]}"
        for entry in hass.config_entries.async_entries(MOBILE_APP_DOMAIN)
        if CONF_WEBHOOK_ID in entry.data
    )


@callback
def _async_track_surface(hass: HomeAssistant, entry: ConfigEntry, data: RelayData) -> None:
    """Keep the applications in step with the router and the registered devices.

    Integrations set up after this entry (later in the same start, or installed
    afterwards) register their own unauthenticated views and package assets, and
    companion-app devices register and unregister at any time. Discovery is re-run
    once Home Assistant has started and, debounced, after every component load and
    every mobile_app entry change; an application is rewritten only when its desired
    content changed.
    """

    async def _refresh() -> None:
        open_paths = discover_open_paths(hass)
        gated_paths = device_webhook_paths(hass)
        if open_paths == data.open_paths and gated_paths == data.gated_paths:
            return
        _LOGGER.info(
            "Surface changed (open paths added %s, removed %s; devices added %d, removed %d)",
            sorted(set(open_paths) - set(data.open_paths)),
            sorted(set(data.open_paths) - set(open_paths)),
            len(set(gated_paths) - set(data.gated_paths)),
            len(set(data.gated_paths) - set(gated_paths)),
        )
        try:
            await _async_provision_entry(
                hass,
                entry,
                data.api,
                data.options,
                open_paths,
                gated_paths,
                vendor_paths=data.vendor_bypass,
            )
        except (CloudflareAuthError, CloudflareUnavailableError, CloudflareApiError) as err:
            _LOGGER.warning(
                "Could not update the Access applications; reload the integration to retry: %s",
                err,
            )
            return
        data.open_paths = open_paths
        data.gated_paths = gated_paths

    debouncer = Debouncer(
        hass,
        _LOGGER,
        cooldown=REDISCOVER_COOLDOWN_SECONDS,
        immediate=False,
        function=_refresh,
        background=True,
    )

    @callback
    def _schedule(_event_or_hass: Event | HomeAssistant) -> None:
        debouncer.async_schedule_call()

    @callback
    def _entry_changed(_change: ConfigEntryChange, changed: ConfigEntry) -> None:
        if changed.domain == MOBILE_APP_DOMAIN:
            debouncer.async_schedule_call()

    @callback
    def _stop(_event: Event) -> None:
        debouncer.async_shutdown()

    entry.async_on_unload(debouncer.async_shutdown)
    entry.async_on_unload(hass.bus.async_listen(EVENT_COMPONENT_LOADED, _schedule))
    entry.async_on_unload(
        async_dispatcher_connect(hass, SIGNAL_CONFIG_ENTRY_CHANGED, _entry_changed)
    )
    entry.async_on_unload(hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _stop))
    entry.async_on_unload(async_at_started(hass, _schedule))


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
