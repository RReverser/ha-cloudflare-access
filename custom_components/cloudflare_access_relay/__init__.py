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
    ConfigSubentry,
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

from .cloudflare_api import (
    CloudflareAccessApi,
    CloudflareApiError,
    CloudflareAuthError,
    CloudflareUnavailableError,
)
from .const import (
    CLIENT_APP_NAME_FMT,
    CONF_CLIENT_NAME,
    CONF_DELETE_OBJECTS_ON_REMOVE,
    CONF_HOSTNAME,
    CONF_REDIRECT_URIS,
    DATA_BYPASS_APP_ID,
    DATA_CLIENT_APP_ID,
    DATA_CLIENT_ID,
    DATA_CLIENT_SECRET,
    DATA_GATE_APP_ID,
    DATA_POLICY_AUD,
    DATA_TEAM_DOMAIN,
    DOMAIN,
    FLOW_SWEEP_INTERVAL_SECONDS,
    MOBILE_APP_DOMAIN,
    REDISCOVER_COOLDOWN_SECONDS,
    SUBENTRY_TYPE_CLIENT,
    URL_RELAY_JS,
    URL_STATIC,
    VERSION,
    WEBHOOK_PATH,
)
from .edge_auth import async_install_middleware
from .flows import FlowStore
from .jwks import JwksVerifier
from .options import api_for, effective_options
from .paths import discover_open_paths
from .provision import (
    ProvisionResult,
    async_delete_apps,
    async_provision,
    desired_client_app,
    reconcile_app,
)
from .views import CallbackView, ConnectView, FlowCreateView, SessionView, StatusView

_LOGGER = logging.getLogger(__name__)


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
    # Registered clients' Access applications, by subentry id, as last reconciled.
    client_apps: dict[str, str]


type RelayConfigEntry = ConfigEntry[RelayData]


def client_subentries(entry: ConfigEntry) -> dict[str, ConfigSubentry]:
    """Return the registered-client subentries by subentry id."""
    return {
        sid: sub
        for sid, sub in entry.subentries.items()
        if sub.subentry_type == SUBENTRY_TYPE_CLIENT
    }


async def _async_reconcile_clients(
    hass: HomeAssistant,
    entry: ConfigEntry,
    api: CloudflareAccessApi,
    options: dict[str, Any],
) -> dict[str, str]:
    """Bring the registered clients' applications in line with the subentries.

    A client whose application was lost outside the integration gets a new one,
    with new credentials that its console must be given again (the subentry is
    updated and a warning logged). Applications of removed clients are deleted by
    `_async_delete_stale_clients`, once the gate no longer refers to them.
    """
    current = client_subentries(entry)
    apps: dict[str, str] = {}
    for sid, sub in current.items():
        desired = desired_client_app(
            options, sub.data[CONF_CLIENT_NAME], list(sub.data[CONF_REDIRECT_URIS])
        )
        writes: list[str] = []
        app = await reconcile_app(api, sub.data.get(DATA_CLIENT_APP_ID), desired, writes)
        apps[sid] = app["id"]
        saas = app.get("saas_app") or {}
        derived = {DATA_CLIENT_APP_ID: app["id"], DATA_CLIENT_ID: saas.get("client_id")}
        if saas.get("client_secret"):
            derived[DATA_CLIENT_SECRET] = saas["client_secret"]
            _LOGGER.warning(
                "The Access application of client %s was recreated; give its console the new "
                "client id and secret shown in the client's settings",
                sub.title,
            )
        if any(sub.data.get(k) != v for k, v in derived.items()):
            hass.config_entries.async_update_subentry(entry, sub, data={**sub.data, **derived})
        if writes:
            _LOGGER.info("Cloudflare Access objects written: %s", ", ".join(writes))
    return apps


async def _async_delete_stale_clients(
    api: CloudflareAccessApi,
    options: dict[str, Any],
    previous: dict[str, str] | None,
    current: dict[str, str],
) -> None:
    """Delete the applications of removed clients.

    Runs after the gate was written without their rules: Cloudflare accepts the
    deletion of a still-referenced application but refuses every later write of the
    gate that carries the stale rule. `previous` is None at setup, when a client
    removed while Home Assistant was down is found by its application name instead.
    """
    if previous is not None:
        for sid, app_id in previous.items():
            if sid not in current:
                _LOGGER.info("Deleting the Access application of removed client %s", sid)
                await api.delete_app(app_id)
        return
    prefix = CLIENT_APP_NAME_FMT.format(hostname=options[CONF_HOSTNAME], name="")
    for app in await api.list_apps():
        if app.get("name", "").startswith(prefix) and app["id"] not in current.values():
            _LOGGER.info("Deleting the orphaned client application %s", app["name"])
            await api.delete_app(app["id"])


async def _async_provision_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    api: CloudflareAccessApi,
    options: dict[str, Any],
    open_paths: list[str],
    gated_paths: list[str],
    client_apps: dict[str, str],
) -> ProvisionResult:
    """Reconcile the Access applications and persist what Cloudflare derived."""
    result = await async_provision(
        api,
        options,
        open_paths,
        gate_app_id=entry.data.get(DATA_GATE_APP_ID),
        bypass_app_id=entry.data.get(DATA_BYPASS_APP_ID),
        team_domain=entry.data.get(DATA_TEAM_DOMAIN),
        gated_paths=gated_paths,
        linked_app_ids=list(client_apps.values()),
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
    api = api_for(hass, entry)
    await _async_register_http(hass)
    # Token-bearing clients are authenticated at the origin from the edge assertion; the
    # middleware can only be installed before the web server starts (repair issue otherwise).
    async_install_middleware(hass)
    open_paths = discover_open_paths(hass)
    gated_paths = device_webhook_paths(hass)
    try:
        client_apps = await _async_reconcile_clients(hass, entry, api, options)
        result = await _async_provision_entry(
            hass, entry, api, options, open_paths, gated_paths, client_apps
        )
        await _async_delete_stale_clients(api, options, None, client_apps)
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
        client_apps=client_apps,
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
    """Keep the applications in step with the router, the devices and the clients.

    Integrations set up after this entry (later in the same start, or installed
    afterwards) register their own unauthenticated views and package assets,
    companion-app devices register and unregister at any time, and clients are
    registered and removed through subentries. Discovery is re-run once Home
    Assistant has started and, debounced, after every component load, every
    mobile_app entry change and every change to this entry; an application is
    rewritten only when its desired content changed.
    """

    async def _refresh() -> None:
        open_paths = discover_open_paths(hass)
        gated_paths = device_webhook_paths(hass)
        clients = set(client_subentries(entry))
        if (
            open_paths == data.open_paths
            and gated_paths == data.gated_paths
            and clients == set(data.client_apps)
        ):
            return
        _LOGGER.info(
            "Surface changed (open paths added %s, removed %s; devices added %d, removed %d; "
            "clients added %d, removed %d)",
            sorted(set(open_paths) - set(data.open_paths)),
            sorted(set(data.open_paths) - set(open_paths)),
            len(set(gated_paths) - set(data.gated_paths)),
            len(set(data.gated_paths) - set(gated_paths)),
            len(clients - set(data.client_apps)),
            len(set(data.client_apps) - clients),
        )
        try:
            client_apps = await _async_reconcile_clients(hass, entry, data.api, data.options)
            await _async_provision_entry(
                hass, entry, data.api, data.options, open_paths, gated_paths, client_apps
            )
            await _async_delete_stale_clients(data.api, data.options, data.client_apps, client_apps)
            data.client_apps = client_apps
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
        if changed.domain == MOBILE_APP_DOMAIN or changed.entry_id == entry.entry_id:
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
    api = api_for(hass, entry)
    try:
        await async_delete_apps(
            api, entry.data.get(DATA_GATE_APP_ID), entry.data.get(DATA_BYPASS_APP_ID)
        )
        for sub in client_subentries(entry).values():
            if app_id := sub.data.get(DATA_CLIENT_APP_ID):
                await api.delete_app(app_id)
    except (CloudflareAuthError, CloudflareUnavailableError, CloudflareApiError) as err:
        _LOGGER.warning("Could not delete the Access applications; remove them by hand: %s", err)
