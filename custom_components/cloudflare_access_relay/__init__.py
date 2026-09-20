"""Cloudflare Access for Home Assistant.

Gates a Home Assistant hostname with Cloudflare Access: provisions the Access
application for the hostname, lets token-bearing clients (Google, Alexa, MCP
clients) authenticate with Access and be recognised at the origin, and registers
with Access the clients that cannot register themselves.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any

from homeassistant.auth import EVENT_USER_ADDED, EVENT_USER_REMOVED, EVENT_USER_UPDATED
from homeassistant.config_entries import (
    SIGNAL_CONFIG_ENTRY_CHANGED,
    ConfigEntry,
    ConfigEntryChange,
    ConfigSubentry,
)
from homeassistant.const import EVENT_HOMEASSISTANT_STOP
from homeassistant.core import Event, HomeAssistant, callback
from homeassistant.exceptions import (
    ConfigEntryAuthFailed,
    ConfigEntryError,
    ConfigEntryNotReady,
)
from homeassistant.helpers import config_entry_oauth2_flow, issue_registry as ir
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.debounce import Debouncer
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.httpx_client import get_async_client
from homeassistant.helpers.typing import ConfigType

from .application_credentials import CloudflareOAuth2Implementation
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
    CONF_GATE_ENABLED,
    CONF_HOSTNAME,
    CONF_REDIRECT_URIS,
    CONF_USER_MATCH,
    DATA_BYPASS_APP_ID,
    DATA_CLIENT_APP_ID,
    DATA_CLIENT_ID,
    DATA_CLIENT_SECRET,
    DATA_GATE_APP_ID,
    DATA_POLICY_AUD,
    DATA_TEAM_DOMAIN,
    DOMAIN,
    ISSUE_NO_ALLOWED_USERS,
    OAUTH_AUTHORIZE_URL,
    OAUTH_CLIENT_ID,
    OAUTH_TOKEN_URL,
    RECONCILE_COOLDOWN_SECONDS,
    SUBENTRY_TYPE_CLIENT,
)
from .edge_auth import async_install_middleware
from .jwks import JwksVerifier
from .options import api_for, effective_options
from .provision import (
    ProvisionResult,
    async_delete_apps,
    async_provision,
    desired_client_app,
    reconcile_app,
)
from .users import allowed_emails

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Offer the project's public OAuth client, when one is published."""
    if OAUTH_CLIENT_ID:
        config_entry_oauth2_flow.async_register_implementation(
            hass,
            DOMAIN,
            CloudflareOAuth2Implementation(
                hass, DOMAIN, OAUTH_CLIENT_ID, OAUTH_AUTHORIZE_URL, OAUTH_TOKEN_URL
            ),
        )
    return True


@dataclass
class EntryData:
    """Runtime state of one config entry."""

    entry: ConfigEntry
    options: dict[str, Any]
    api: CloudflareAccessApi
    verifier: JwksVerifier
    team_domain: str
    # The gate's audience tag while the gate exists; None while it is disabled.
    policy_aud: str | None
    # The users' e-mail addresses on the allow policies, as last reconciled.
    emails: list[str]
    # Registered clients' Access applications, by subentry id, as last reconciled.
    client_apps: dict[str, str]


type AccessConfigEntry = ConfigEntry[EntryData]


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
    emails: list[str],
) -> dict[str, str]:
    """Bring the registered clients' applications in line with the subentries.

    A client whose application was lost outside the integration gets a new one,
    with new credentials that its console must be given again (the subentry is
    updated and a warning logged). Applications of removed clients are deleted by
    `_async_delete_stale_clients`, once the gate no longer refers to them.
    """
    apps: dict[str, str] = {}
    for sid, sub in client_subentries(entry).items():
        desired = desired_client_app(
            options, emails, sub.data[CONF_CLIENT_NAME], list(sub.data[CONF_REDIRECT_URIS])
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
    emails: list[str],
    client_apps: dict[str, str],
) -> ProvisionResult:
    """Reconcile the Access applications and persist what Cloudflare derived."""
    result = await async_provision(
        api,
        options,
        emails,
        gate_app_id=entry.data.get(DATA_GATE_APP_ID),
        bypass_app_id=entry.data.get(DATA_BYPASS_APP_ID),
        team_domain=entry.data.get(DATA_TEAM_DOMAIN),
        linked_app_ids=list(client_apps.values()),
    )
    derived = {
        DATA_TEAM_DOMAIN: result.team_domain,
        DATA_POLICY_AUD: result.policy_aud,
        DATA_GATE_APP_ID: result.gate_app_id,
        DATA_BYPASS_APP_ID: result.bypass_app_id,
    }
    if any(k not in entry.data or entry.data[k] != v for k, v in derived.items()):
        hass.config_entries.async_update_entry(entry, data={**entry.data, **derived})
    if result.writes:
        _LOGGER.info("Cloudflare Access objects written: %s", ", ".join(result.writes))
    return result


async def async_setup_entry(hass: HomeAssistant, entry: AccessConfigEntry) -> bool:
    """Provision the Access applications and recognise Access identities at the origin."""
    options = effective_options(entry)
    # Token-bearing clients are authenticated at the origin from the edge assertion; the
    # middleware can only be installed before the web server starts (repair issue otherwise).
    async_install_middleware(hass)
    emails = allowed_emails(hass, options)
    if not emails and (options[CONF_GATE_ENABLED] or client_subentries(entry)):
        # An allow policy without subjects is a lock-out (and Cloudflare refuses it).
        raise ConfigEntryError(
            f"No Home Assistant user has an e-mail address in the field "
            f"{options[CONF_USER_MATCH]!r}; nobody could log in, so nothing is provisioned"
        )
    try:
        api = await api_for(hass, entry)
        client_apps = await _async_reconcile_clients(hass, entry, api, options, emails)
        result = await _async_provision_entry(hass, entry, api, options, emails, client_apps)
        await _async_delete_stale_clients(api, options, None, client_apps)
    except CloudflareAuthError as err:
        raise ConfigEntryAuthFailed(str(err)) from err
    except CloudflareUnavailableError as err:
        raise ConfigEntryNotReady(str(err)) from err
    except CloudflareApiError as err:
        raise ConfigEntryError(f"Cloudflare rejected the configuration: {err}") from err

    data = EntryData(
        entry=entry,
        options=options,
        api=api,
        verifier=JwksVerifier(get_async_client(hass), result.team_domain),
        team_domain=result.team_domain,
        policy_aud=result.policy_aud,
        emails=emails,
        client_apps=client_apps,
    )
    entry.runtime_data = data
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = data
    _async_track_changes(hass, entry, data)
    return True


@callback
def _async_track_changes(hass: HomeAssistant, entry: ConfigEntry, data: EntryData) -> None:
    """Keep the applications in step with the users and the registered clients.

    Users come and go, and clients are registered and removed through subentries at
    any time; every such change schedules a debounced reconciliation, which rewrites
    an application only when its desired content changed.
    """

    async def _refresh() -> None:
        emails = allowed_emails(hass, data.options)
        if emails == data.emails and set(client_subentries(entry)) == set(data.client_apps):
            return
        if not emails and (data.options[CONF_GATE_ENABLED] or client_subentries(entry)):
            _LOGGER.warning(
                "No Home Assistant user has an e-mail address in the field %r any more; "
                "the Access allow policy keeps its last subjects",
                data.options[CONF_USER_MATCH],
            )
            ir.async_create_issue(
                hass,
                DOMAIN,
                ISSUE_NO_ALLOWED_USERS,
                is_fixable=False,
                severity=ir.IssueSeverity.ERROR,
                translation_key=ISSUE_NO_ALLOWED_USERS,
                translation_placeholders={CONF_USER_MATCH: data.options[CONF_USER_MATCH]},
            )
            return
        ir.async_delete_issue(hass, DOMAIN, ISSUE_NO_ALLOWED_USERS)
        try:
            client_apps = await _async_reconcile_clients(
                hass, entry, data.api, data.options, emails
            )
            await _async_provision_entry(hass, entry, data.api, data.options, emails, client_apps)
            await _async_delete_stale_clients(data.api, data.options, data.client_apps, client_apps)
            data.emails = emails
            data.client_apps = client_apps
        except (CloudflareAuthError, CloudflareUnavailableError, CloudflareApiError) as err:
            _LOGGER.warning(
                "Could not update the Access applications; reload the integration to retry: %s",
                err,
            )

    debouncer = Debouncer(
        hass,
        _LOGGER,
        cooldown=RECONCILE_COOLDOWN_SECONDS,
        immediate=False,
        function=_refresh,
        background=True,
    )

    @callback
    def _entry_changed(_change: ConfigEntryChange, changed: ConfigEntry) -> None:
        if changed.entry_id == entry.entry_id:
            debouncer.async_schedule_call()

    @callback
    def _schedule(_event: Event) -> None:
        debouncer.async_schedule_call()

    @callback
    def _stop(_event: Event) -> None:
        debouncer.async_shutdown()

    entry.async_on_unload(debouncer.async_shutdown)
    entry.async_on_unload(
        async_dispatcher_connect(hass, SIGNAL_CONFIG_ENTRY_CHANGED, _entry_changed)
    )
    for event in (EVENT_USER_ADDED, EVENT_USER_REMOVED, EVENT_USER_UPDATED):
        entry.async_on_unload(hass.bus.async_listen(event, _schedule))
    entry.async_on_unload(hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _stop))


async def async_unload_entry(hass: HomeAssistant, entry: AccessConfigEntry) -> bool:
    """Unload the entry; the middleware stays but no longer finds it."""
    entries: dict[str, EntryData] = hass.data.get(DOMAIN) or {}
    entries.pop(entry.entry_id, None)
    return True


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Delete the Cloudflare objects when the entry is removed, if asked to."""
    options = effective_options(entry)
    if not options[CONF_DELETE_OBJECTS_ON_REMOVE]:
        return
    try:
        api = await api_for(hass, entry)
        await async_delete_apps(
            api,
            entry.data.get(DATA_GATE_APP_ID),
            entry.data.get(DATA_BYPASS_APP_ID),
            *(sub.data.get(DATA_CLIENT_APP_ID) for sub in client_subentries(entry).values()),
        )
    except (CloudflareAuthError, CloudflareUnavailableError, CloudflareApiError) as err:
        _LOGGER.warning("Could not delete the Access applications; remove them by hand: %s", err)
