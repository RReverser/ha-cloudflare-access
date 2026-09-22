"""Cloudflare Access for Home Assistant.

Gates a Home Assistant hostname with Cloudflare Access: provisions the Access
application for the hostname, lets token-bearing clients (Google, Alexa, MCP
clients) authenticate with Access and be recognised at the origin, and registers
with Access the clients that cannot register themselves.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
from types import MappingProxyType
from typing import Any
from urllib.parse import urlparse

from homeassistant.auth import EVENT_USER_ADDED, EVENT_USER_REMOVED, EVENT_USER_UPDATED
from homeassistant.config_entries import (
    SIGNAL_CONFIG_ENTRY_CHANGED,
    ConfigEntry,
    ConfigEntryChange,
    ConfigEntryState,
    ConfigSubentry,
)
from homeassistant.const import EVENT_HOMEASSISTANT_STOP
from homeassistant.core import Event, HomeAssistant, callback
from homeassistant.exceptions import (
    ConfigEntryAuthFailed,
    ConfigEntryError,
    ConfigEntryNotReady,
)
from homeassistant.helpers import issue_registry as ir
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.debounce import Debouncer
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.httpx_client import get_async_client
from homeassistant.helpers.typing import ConfigType

from .application_credentials import async_register_project_client
from .cloudflare_api import (
    CloudflareAccessApi,
    CloudflareApiError,
    CloudflareAuthError,
    CloudflareError,
    CloudflareUnavailableError,
)
from .const import (
    CLIENT_APP_NAME_FMT,
    CLIENT_KIND_LOGIN,
    CLIENT_KIND_SCRIPT,
    CONF_CLIENT_KIND,
    CONF_CLIENT_NAME,
    CONF_CLIENT_REDIRECT_URIS,
    CONF_DELETE_OBJECTS_ON_REMOVE,
    CONF_EMAIL,
    CONF_HOSTNAME,
    CONF_LOGIN_EMAILS,
    CONF_NEEDS_CREDENTIALS,
    CONF_REDIRECT_URIS,
    CONF_SERVICE_TOKEN_IDS,
    CONF_USER_ID,
    DATA_BYPASS_APP_ID,
    DATA_CLIENT_APP_ID,
    DATA_CLIENT_ID,
    DATA_CLIENT_SECRET,
    DATA_GATE_APP_ID,
    DATA_POLICY_AUD,
    DATA_TEAM_DOMAIN,
    DATA_TOKEN_EXPIRES_AT,
    DATA_TOKEN_ID,
    DOMAIN,
    FORM_PLACEHOLDERS,
    ISSUE_NO_ALLOWED_USERS,
    OPTION_APP_TAG,
    RECONCILE_COOLDOWN_SECONDS,
    SERVICE_TOKEN_NAME_FMT,
    SUBENTRY_TYPE_CLIENT,
    SUBENTRY_TYPE_LOGIN_EMAIL,
)
from .edge_auth import async_install_middleware
from .jwks import JwksVerifier
from .options import (
    api_for,
    app_tag,
    client_redirect_uris,
    client_subentries,
    credentialed_clients,
    effective_options,
    provisioning_options,
    script_clients,
)
from .provision import (
    ProvisionResult,
    async_delete_apps,
    async_provision,
    desired_client_app,
    owned,
    reconcile_app,
)
from .users import allowed_emails, login_emails

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Offer the project's public OAuth client; take the gate down for disabled entries.

    Disabling a loaded entry unloads it, and the unload takes the gate down. An entry
    that is disabled while it is not loaded (in an error state) is never unloaded, and
    one disabled during a shutdown is unloaded too late to talk to Cloudflare; both are
    caught here, on the state change and at the next start.
    """
    async_register_project_client(hass)

    def _take_down(entry: ConfigEntry) -> None:
        hass.async_create_task(
            _async_take_gate_down(hass, entry), f"{DOMAIN}: gate down for {entry.title}"
        )

    @callback
    def _entry_changed(change: ConfigEntryChange, entry: ConfigEntry) -> None:
        if (
            change is ConfigEntryChange.UPDATED
            and entry.domain == DOMAIN
            and entry.disabled_by is not None
            and entry.state is ConfigEntryState.NOT_LOADED
            and _has_gate(entry)
            and not hass.is_stopping
        ):
            _take_down(entry)

    async_dispatcher_connect(hass, SIGNAL_CONFIG_ENTRY_CHANGED, _entry_changed)
    for entry in hass.config_entries.async_entries(DOMAIN):
        if entry.disabled_by is not None and _has_gate(entry):
            _take_down(entry)
    return True


def _has_gate(entry: ConfigEntry) -> bool:
    return bool(entry.data.get(DATA_GATE_APP_ID) or entry.data.get(DATA_BYPASS_APP_ID))


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
    # Login clients' Access applications, by subentry id, as last reconciled.
    client_apps: dict[str, str]
    # Script clients' service tokens, by subentry id, as last reconciled.
    script_tokens: dict[str, str]


type AccessConfigEntry = ConfigEntry[EntryData]


@callback
def _async_migrate_login_email_rows(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Move the login e-mails an earlier version kept as subentries into the options."""
    rows = [
        sub for sub in entry.subentries.values() if sub.subentry_type == SUBENTRY_TYPE_LOGIN_EMAIL
    ]
    if not rows:
        return
    emails = dict(entry.options.get(CONF_LOGIN_EMAILS) or {})
    for sub in rows:
        if sub.data.get(CONF_EMAIL) and sub.data.get(CONF_USER_ID):
            emails.setdefault(sub.data[CONF_USER_ID], sub.data[CONF_EMAIL])
        hass.config_entries.async_remove_subentry(entry, sub.subentry_id)
    hass.config_entries.async_update_entry(
        entry, options={**entry.options, CONF_LOGIN_EMAILS: emails}
    )


@callback
def _async_migrate_redirect_uris(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Turn the former redirect-URL option into client subentries, one per URL."""
    if not (uris := entry.options.get(CONF_CLIENT_REDIRECT_URIS)):
        if CONF_CLIENT_REDIRECT_URIS in entry.options:
            options = {k: v for k, v in entry.options.items() if k != CONF_CLIENT_REDIRECT_URIS}
            hass.config_entries.async_update_entry(entry, options=options)
        return
    known = set(client_redirect_uris(entry))
    for uri in uris:
        if uri in known:
            continue
        hass.config_entries.async_add_subentry(
            entry,
            ConfigSubentry(
                data=MappingProxyType(
                    {
                        CONF_CLIENT_NAME: urlparse(uri).hostname or uri,
                        CONF_REDIRECT_URIS: [uri],
                        CONF_NEEDS_CREDENTIALS: False,
                    }
                ),
                subentry_type=SUBENTRY_TYPE_CLIENT,
                title=urlparse(uri).hostname or uri,
                unique_id=None,
            ),
        )
    options = {k: v for k, v in entry.options.items() if k != CONF_CLIENT_REDIRECT_URIS}
    hass.config_entries.async_update_entry(entry, options=options)


@callback
def _async_migrate_client_kinds(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Mark the clients an earlier version created, which were all login clients."""
    for sub in client_subentries(entry).values():
        if CONF_CLIENT_KIND not in sub.data:
            hass.config_entries.async_update_subentry(
                entry, sub, data={**sub.data, CONF_CLIENT_KIND: CLIENT_KIND_LOGIN}
            )


async def _async_migrate_service_token_option(
    hass: HomeAssistant, entry: ConfigEntry, api: CloudflareAccessApi
) -> None:
    """Turn the former service token option into script clients, one per token.

    The token's name and Client ID are read from Cloudflare; its secret was never known
    to the integration, so the client's page shows it as unknown until the token is
    replaced. A token that no longer exists is dropped.
    """
    if CONF_SERVICE_TOKEN_IDS not in entry.options:
        return
    known = {sub.data.get(DATA_TOKEN_ID) for sub in script_clients(entry).values()}
    for token_id in entry.options.get(CONF_SERVICE_TOKEN_IDS) or []:
        if token_id in known:
            continue
        token = await api.get_service_token(token_id)
        if token is None:
            _LOGGER.warning("Service token %s no longer exists; it is dropped", token_id)
            continue
        hass.config_entries.async_add_subentry(
            entry,
            ConfigSubentry(
                data=MappingProxyType(
                    {
                        CONF_CLIENT_NAME: token.get("name") or token_id,
                        CONF_CLIENT_KIND: CLIENT_KIND_SCRIPT,
                        DATA_TOKEN_ID: token_id,
                        DATA_CLIENT_ID: token.get("client_id"),
                        DATA_CLIENT_SECRET: None,
                        DATA_TOKEN_EXPIRES_AT: token.get("expires_at"),
                    }
                ),
                subentry_type=SUBENTRY_TYPE_CLIENT,
                title=token.get("name") or token_id,
                unique_id=None,
            ),
        )
    options = {k: v for k, v in entry.options.items() if k != CONF_SERVICE_TOKEN_IDS}
    hass.config_entries.async_update_entry(entry, options=options)


def _token_name(options: dict[str, Any], name: str) -> str:
    return SERVICE_TOKEN_NAME_FMT.format(hostname=options[CONF_HOSTNAME], name=name)


async def _async_reconcile_scripts(
    hass: HomeAssistant, entry: ConfigEntry, api: CloudflareAccessApi, options: dict[str, Any]
) -> dict[str, str]:
    """Bring the script clients' service tokens in line with the subentries.

    A client whose token was deleted outside the integration gets a new one, with a
    new Client ID and secret that the script must be given again (the subentry is
    updated and a warning logged). Tokens of removed clients are deleted by
    `_async_delete_stale_tokens`, once the gate no longer refers to them.
    """
    tokens: dict[str, str] = {}
    for sid, sub in script_clients(entry).items():
        token_id = sub.data.get(DATA_TOKEN_ID)
        if token_id and await api.get_service_token(token_id) is not None:
            tokens[sid] = token_id
            continue
        created = await api.create_service_token(_token_name(options, sub.data[CONF_CLIENT_NAME]))
        _LOGGER.warning(
            "The service token of client %s was gone and has been replaced; give the script "
            "the new Client ID and secret shown in the client's settings",
            sub.title,
        )
        tokens[sid] = created["id"]
        hass.config_entries.async_update_subentry(
            entry,
            sub,
            data={
                **sub.data,
                DATA_TOKEN_ID: created["id"],
                DATA_CLIENT_ID: created.get("client_id"),
                DATA_CLIENT_SECRET: created.get("client_secret"),
                DATA_TOKEN_EXPIRES_AT: created.get("expires_at"),
            },
        )
    return tokens


async def _async_delete_stale_tokens(
    api: CloudflareAccessApi,
    options: dict[str, Any],
    previous: dict[str, str] | None,
    current: dict[str, str],
) -> None:
    """Delete the service tokens of removed script clients.

    Runs after the gate was written without their rules, as Cloudflare refuses to
    delete a token a policy still names. `previous` is None at setup, when a client
    removed while Home Assistant was down is found by its token's name instead.
    """
    if previous is not None:
        for sid, token_id in previous.items():
            if sid not in current:
                _LOGGER.info("Deleting the service token of removed client %s", sid)
                await api.delete_service_token(token_id)
        return
    prefix = _token_name(options, "")
    for token in await api.list_service_tokens():
        if token.get("name", "").startswith(prefix) and token["id"] not in current.values():
            _LOGGER.info("Deleting the orphaned service token %s", token["name"])
            await api.delete_service_token(token["id"])


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
    for sid, sub in credentialed_clients(entry).items():
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
        if (
            owned(app, options[OPTION_APP_TAG])
            and app.get("name", "").startswith(prefix)
            and app["id"] not in current.values()
        ):
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
    _async_migrate_redirect_uris(hass, entry)
    _async_migrate_login_email_rows(hass, entry)
    _async_migrate_client_kinds(hass, entry)
    options = provisioning_options(entry)
    # Token-bearing clients are authenticated at the origin from the edge assertion; the
    # middleware can only be installed before the web server starts (repair issue otherwise).
    async_install_middleware(hass)
    emails = allowed_emails(hass, login_emails(entry))
    if not emails:
        # An allow policy without subjects is a lock-out (and Cloudflare refuses it).
        raise ConfigEntryError(
            "No Home Assistant user carries an e-mail address, so nobody could log in. "
            "Give a person one under the integration's options, People"
        )
    try:
        api = await api_for(hass, entry)
        await _async_migrate_service_token_option(hass, entry, api)
        options = provisioning_options(entry)
        await api.ensure_tag(options[OPTION_APP_TAG])
        client_apps = await _async_reconcile_clients(hass, entry, api, options, emails)
        script_tokens = await _async_reconcile_scripts(hass, entry, api, options)
        options = provisioning_options(entry)  # a replaced token has a new id
        result = await _async_provision_entry(hass, entry, api, options, emails, client_apps)
        await _async_delete_stale_clients(api, options, None, client_apps)
        await _async_delete_stale_tokens(api, options, None, script_tokens)
    except CloudflareAuthError as err:
        raise ConfigEntryAuthFailed(str(err)) from err
    except CloudflareUnavailableError as err:
        raise ConfigEntryNotReady(str(err)) from err
    except CloudflareApiError as err:
        if any(e.get("code") == 11010 for e in err.errors):
            raise ConfigEntryError(
                "An Access application for this hostname already exists but does not carry "
                f"this entry's tag ({options[OPTION_APP_TAG]}), so it is not touched; delete "
                f"it or give it the tag in the Cloudflare dashboard, then reload: {err}"
            ) from err
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
        script_tokens=script_tokens,
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
        emails = allowed_emails(hass, login_emails(entry))
        options = provisioning_options(entry)
        if (
            emails == data.emails
            and set(credentialed_clients(entry)) == set(data.client_apps)
            and set(script_clients(entry)) == set(data.script_tokens)
            and options[CONF_CLIENT_REDIRECT_URIS] == data.options[CONF_CLIENT_REDIRECT_URIS]
            and options[CONF_SERVICE_TOKEN_IDS] == data.options[CONF_SERVICE_TOKEN_IDS]
        ):
            return
        data.options = options
        if not emails:
            _LOGGER.warning(
                "No Home Assistant user carries an e-mail address any more; "
                "the Access allow policy keeps its last subjects"
            )
            ir.async_create_issue(
                hass,
                DOMAIN,
                ISSUE_NO_ALLOWED_USERS,
                is_fixable=False,
                severity=ir.IssueSeverity.ERROR,
                translation_key=ISSUE_NO_ALLOWED_USERS,
                translation_placeholders=FORM_PLACEHOLDERS,
            )
            return
        ir.async_delete_issue(hass, DOMAIN, ISSUE_NO_ALLOWED_USERS)
        try:
            client_apps = await _async_reconcile_clients(
                hass, entry, data.api, data.options, emails
            )
            script_tokens = await _async_reconcile_scripts(hass, entry, data.api, data.options)
            data.options = provisioning_options(entry)
            await _async_provision_entry(hass, entry, data.api, data.options, emails, client_apps)
            await _async_delete_stale_clients(data.api, data.options, data.client_apps, client_apps)
            await _async_delete_stale_tokens(
                data.api, data.options, data.script_tokens, script_tokens
            )
            data.emails = emails
            data.client_apps = client_apps
            data.script_tokens = script_tokens
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
    """Unload the entry; the middleware stays but no longer finds it.

    A disabled entry also takes the gate down: with the integration off, the hostname
    goes back to how it was without it, and the origin no longer recognises Access
    identities anyway. Re-enabling provisions everything again. Registered clients'
    applications stay, so their consoles keep their credentials. A plain unload (a
    reload, a restart) leaves the edge alone.
    """
    entries: dict[str, EntryData] = hass.data.get(DOMAIN) or {}
    entries.pop(entry.entry_id, None)
    if entry.disabled_by is not None and not hass.is_stopping:
        await _async_take_gate_down(hass, entry)
    return True


async def _async_take_gate_down(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Delete the gate and bypass applications and forget them."""
    try:
        api = await api_for(hass, entry)
        await async_delete_apps(
            api,
            app_tag(entry),
            entry.data.get(DATA_GATE_APP_ID),
            entry.data.get(DATA_BYPASS_APP_ID),
        )
    except CloudflareError as err:
        _LOGGER.warning(
            "The integration is disabled but the Access gate could not be taken down; "
            "it stays until the integration is enabled or removed: %s",
            err,
        )
        return
    if _has_gate(entry):
        _LOGGER.info("Integration disabled: the Access gate for %s is down", entry.title)
    hass.config_entries.async_update_entry(
        entry,
        data={
            **entry.data,
            DATA_GATE_APP_ID: None,
            DATA_BYPASS_APP_ID: None,
            DATA_POLICY_AUD: None,
        },
    )


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Delete the Cloudflare objects when the entry is removed, if asked to."""
    options = effective_options(entry)
    if not options[CONF_DELETE_OBJECTS_ON_REMOVE]:
        return
    try:
        api = await api_for(hass, entry)
        await async_delete_apps(
            api,
            app_tag(entry),
            entry.data.get(DATA_GATE_APP_ID),
            entry.data.get(DATA_BYPASS_APP_ID),
            *(sub.data.get(DATA_CLIENT_APP_ID) for sub in credentialed_clients(entry).values()),
        )
        for sub in script_clients(entry).values():
            if sub.data.get(DATA_TOKEN_ID):
                await api.delete_service_token(sub.data[DATA_TOKEN_ID])
    except (CloudflareAuthError, CloudflareUnavailableError, CloudflareApiError) as err:
        _LOGGER.warning("Could not delete the Access objects; remove them by hand: %s", err)
