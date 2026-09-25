"""Cloudflare Access for Home Assistant.

Gates a Home Assistant hostname with Cloudflare Access: provisions the Access
application for the hostname, lets token-bearing clients (Google, Alexa, MCP
clients) authenticate with Access and be recognised at the origin, and registers
with Access the clients that cannot register themselves.
"""

from __future__ import annotations

from collections.abc import Sequence
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
from homeassistant.const import EVENT_CORE_CONFIG_UPDATE, EVENT_HOMEASSISTANT_STOP
from homeassistant.core import Event, HomeAssistant, callback
from homeassistant.exceptions import (
    ConfigEntryAuthFailed,
    ConfigEntryError,
    ConfigEntryNotReady,
)
from homeassistant.helpers import device_registry as dr, entity_registry as er, issue_registry as ir
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.debounce import Debouncer
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.httpx_client import get_async_client
from homeassistant.helpers.network import NoURLAvailableError
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
    CONF_CLIENT_NAME,
    CONF_CLIENT_REDIRECT_URIS,
    CONF_DELETE_OBJECTS_ON_REMOVE,
    CONF_EMAIL,
    CONF_HOSTNAME,
    CONF_LOGIN_EMAILS,
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
    HA_MCP_DOMAIN,
    ISSUE_MCP_AUTH_CONFLICT,
    ISSUE_NO_ALLOWED_USERS,
    ISSUE_NO_EXTERNAL_URL,
    ISSUE_UPDATE_FAILED,
    KNOWN_REDIRECT_URIS,
    LEGACY_CONF_CLIENT_KIND,
    LEGACY_ISSUE_RESTART_REQUIRED,
    LEGACY_SUBENTRY_TYPE_CLIENT,
    OPTION_APP_TAG,
    OPTION_IDP_IDS,
    RECONCILE_COOLDOWN_SECONDS,
    SERVICE_TOKEN_NAME_FMT,
    SUBENTRY_TYPE_CONSOLE,
    SUBENTRY_TYPE_LOGIN_EMAIL,
    SUBENTRY_TYPE_SCRIPT,
    SUBENTRY_TYPE_SELF_REGISTERING,
)
from .edge_auth import async_install_middleware
from .issues import issue_id
from .jwks import JwksVerifier
from .logins import LoginCoordinator, async_remove_login_history
from .mcp import async_check_mcp_login_conflict
from .options import (
    api_for,
    app_tag,
    async_provisioning_options,
    client_redirect_uris,
    console_clients,
    effective_options,
    provisioning_options,
    script_clients,
)
from .provision import (
    ProvisionResult,
    allowed_emails_of,
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

    Disabling a loaded entry unloads it, and the unload takes the gate down. The two
    cases the unload cannot cover are caught here, on the state change and at the next
    start.
    """
    async_register_project_client(hass)
    ir.async_delete_issue(hass, DOMAIN, LEGACY_ISSUE_RESTART_REQUIRED)

    def _take_down(entry: ConfigEntry) -> None:
        hass.async_create_background_task(
            _async_take_gate_down(hass, entry), f"{DOMAIN}: gate down for {entry.title}"
        )

    @callback
    def _entry_changed(change: ConfigEntryChange, entry: ConfigEntry) -> None:
        # An entry disabled while not loaded (an error state) goes straight to NOT_LOADED
        # without `async_unload_entry` (config_entries.ConfigEntry.async_unload), so its
        # gate would stay up. A disable during shutdown waits for the next start.
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
    # disabled entries are never set up, so this is their only chance after a restart
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
    logins: LoginCoordinator


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
                    }
                ),
                subentry_type=SUBENTRY_TYPE_SELF_REGISTERING,
                title=urlparse(uri).hostname or uri,
                unique_id=None,
            ),
        )
    options = {k: v for k, v in entry.options.items() if k != CONF_CLIENT_REDIRECT_URIS}
    hass.config_entries.async_update_entry(entry, options=options)


@callback
def _async_migrate_client_types(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Give the clients of an earlier version the subentry type of their kind.

    Until 0.3.0 every client was one subentry type with the kind in its data, and every
    client that logged people in got an application. A subentry's type cannot change, so
    each is replaced by one of the new type. A client whose callbacks are all published
    ones of a self-registering app becomes that; its application, which such an app
    cannot use, is dropped here and deleted at the next setup as an orphan. Anything else
    that logged people in keeps its application as a console app.
    """
    published = {uri for uri, _ in KNOWN_REDIRECT_URIS}
    for sub in list(entry.subentries.values()):
        if sub.subentry_type != LEGACY_SUBENTRY_TYPE_CLIENT:
            continue
        data = {k: v for k, v in sub.data.items() if k != LEGACY_CONF_CLIENT_KIND}
        kind = sub.data.get(LEGACY_CONF_CLIENT_KIND)
        uris = set(sub.data.get(CONF_REDIRECT_URIS) or [])
        if kind == "script":
            subentry_type = SUBENTRY_TYPE_SCRIPT
        elif kind == "console":
            subentry_type = SUBENTRY_TYPE_CONSOLE
        elif kind == "self_registering" or (uris and uris <= published):
            subentry_type = SUBENTRY_TYPE_SELF_REGISTERING
            for key in (DATA_CLIENT_APP_ID, DATA_CLIENT_ID, DATA_CLIENT_SECRET):
                data.pop(key, None)
        else:
            subentry_type = SUBENTRY_TYPE_CONSOLE
        hass.config_entries.async_remove_subentry(entry, sub.subentry_id)
        hass.config_entries.async_add_subentry(
            entry,
            ConfigSubentry(
                data=MappingProxyType(data),
                subentry_type=subentry_type,
                title=sub.title,
                unique_id=None,
            ),
        )


async def _async_migrate_service_token_option(
    hass: HomeAssistant, entry: ConfigEntry, api: CloudflareAccessApi
) -> None:
    """Turn the former service token option into script clients, one per token.

    Needs Cloudflare, so it runs at setup rather than in `async_migrate_entry`.
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
                        DATA_TOKEN_ID: token_id,
                        DATA_CLIENT_ID: token.get("client_id"),
                        # the earlier version never stored the secret and Cloudflare
                        # cannot return it, so the client shows it as unknown until
                        # the token is replaced
                        DATA_CLIENT_SECRET: None,
                        DATA_TOKEN_EXPIRES_AT: token.get("expires_at"),
                    }
                ),
                subentry_type=SUBENTRY_TYPE_SCRIPT,
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

    Tokens of removed clients are left to `_async_delete_stale_tokens`, which runs
    once the gate no longer names them.
    """
    tokens: dict[str, str] = {}
    for sid, sub in script_clients(entry).items():
        token_id = sub.data.get(DATA_TOKEN_ID)
        if token_id and (token := await api.get_service_token(token_id)) is not None:
            tokens[sid] = token_id
            wanted = _token_name(options, sub.data[CONF_CLIENT_NAME])
            if token.get("name") != wanted:  # the hostname or the client's name changed
                await api.rename_service_token(token_id, wanted)
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

    Runs after the gate was written without their rules: Cloudflare refuses to delete
    a token a policy still names.
    """
    if previous is not None:
        for sid, token_id in previous.items():
            if sid not in current:
                _LOGGER.info("Deleting the service token of removed client %s", sid)
                await api.delete_service_token(token_id)
        return
    # At setup there is no previous state: a client removed while Home Assistant was
    # down is found by the name pattern the integration gives its tokens.
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
    """Bring the console clients' applications in line with the subentries.

    Applications of removed clients are left to `_async_delete_stale_clients`, which
    runs once the gate no longer names them.
    """
    apps: dict[str, str] = {}
    for sid, sub in console_clients(entry).items():
        desired = desired_client_app(
            options, emails, sub.data[CONF_CLIENT_NAME], list(sub.data[CONF_REDIRECT_URIS])
        )
        writes: list[str] = []
        app = await reconcile_app(api, sub.data.get(DATA_CLIENT_APP_ID), desired, writes)
        apps[sid] = app["id"]
        saas = app.get("saas_app") or {}
        derived = {DATA_CLIENT_APP_ID: app["id"], DATA_CLIENT_ID: saas.get("client_id")}
        # Cloudflare returns the secret only in the create response (docs/verified-cloudflare-behaviour.md), so its presence means the application was (re)created.
        if saas.get("client_secret"):
            derived[DATA_CLIENT_SECRET] = saas["client_secret"]
            if sub.data.get(DATA_CLIENT_APP_ID):
                _LOGGER.warning(
                    "The Access application of client %s was recreated; give its console the "
                    "new client id and secret shown in the client's settings",
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
    gate that carries the stale rule (docs/verified-cloudflare-behaviour.md).
    """
    if previous is not None:
        for sid, app_id in previous.items():
            if sid not in current:
                _LOGGER.info("Deleting the Access application of removed client %s", sid)
                await api.delete_app(app_id)
        return
    # At setup there is no previous state: a client removed while Home Assistant was
    # down is found by the tag and the name pattern the integration gives its apps.
    prefix = CLIENT_APP_NAME_FMT.format(hostname=options[CONF_HOSTNAME], name="")
    for app in await api.list_apps():
        if (
            owned(app, options[OPTION_APP_TAG])
            and app.get("name", "").startswith(prefix)
            and app["id"] not in current.values()
        ):
            _LOGGER.info("Deleting the orphaned client application %s", app["name"])
            await api.delete_app(app["id"])


async def _async_revoke_removed(
    hass: HomeAssistant,
    entry: ConfigEntry,
    api: CloudflareAccessApi,
    previous: set[str],
    current: Sequence[str],
) -> None:
    """End the Access sessions of the addresses that just left the allow list.

    Access re-checks a person against the policy only when their session expires
    (README, "Security properties"), so dropping an address from the rule alone would
    leave their sessions valid until then. A self-registered client's grant needs no
    revoke: its refresh is checked against the rule and refused once the address is gone
    (docs/verified-cloudflare-behaviour.md).
    """
    removed = sorted(previous - {e.strip().lower() for e in current})
    for email in removed:
        try:
            await api.revoke_user(email)
        except CloudflareAuthError as err:
            # A sign-in granted before the revoke scope existed lacks the permission;
            # signing in again grants it. The rest would fail the same way, so stop.
            _LOGGER.warning(
                "The Access sessions of %s could not be ended; they last until they expire: %s",
                email,
                err,
            )
            entry.async_start_reauth(hass)
            return
        _LOGGER.info("Ended the Access sessions of %s, no longer on the allow list", email)


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


async def async_migrate_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Bring an entry of an earlier version up to date.

    The service token option of an earlier version needs Cloudflare and is migrated at
    setup instead (`_async_migrate_service_token_option`), where a failure is retried
    like any other.
    """
    # a newer major version: refusing keeps Home Assistant from loading it
    if entry.version > 1:
        return False
    if entry.minor_version < 2:
        _async_migrate_redirect_uris(hass, entry)
        _async_migrate_login_email_rows(hass, entry)
        hass.config_entries.async_update_entry(entry, minor_version=2)
    if entry.minor_version < 3:
        # the hostname is Home Assistant's External URL now, not an option
        options = {k: v for k, v in entry.options.items() if k != CONF_HOSTNAME}
        hass.config_entries.async_update_entry(entry, options=options, minor_version=3)
    if entry.minor_version < 4:
        # 0.2.0 created a "last login" sensor per person on a service device; the
        # registries keep both until they are removed here
        ent_reg = er.async_get(hass)
        for entity in er.async_entries_for_config_entry(ent_reg, entry.entry_id):
            ent_reg.async_remove(entity.entity_id)
        dev_reg = dr.async_get(hass)
        for device in dr.async_entries_for_config_entry(dev_reg, entry.entry_id):
            dev_reg.async_remove_device(device.id)
        hass.config_entries.async_update_entry(entry, minor_version=4)
    if entry.minor_version < 5:
        _async_migrate_client_types(hass, entry)
        hass.config_entries.async_update_entry(entry, minor_version=5)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: AccessConfigEntry) -> bool:
    """Provision the Access applications and recognise Access identities at the origin."""
    try:
        options = provisioning_options(hass, entry)
    except NoURLAvailableError as err:
        raise ConfigEntryError(
            "Home Assistant has no External URL, so there is no hostname to guard. Set it "
            "under Settings, System, Network"
        ) from err
    for key in (ISSUE_NO_EXTERNAL_URL, ISSUE_UPDATE_FAILED):
        ir.async_delete_issue(hass, DOMAIN, issue_id(entry, key))
    # The web server is already running by now, so the origin hook goes into aiohttp's
    # prepared chain (see edge_auth.async_install_middleware); a repair issue reports an
    # aiohttp that moved it, and the entry still loads.
    async_install_middleware(hass)
    emails = await allowed_emails(hass, login_emails(entry))
    if not emails:
        # An allow policy without subjects is a lock-out (and Cloudflare refuses it).
        raise ConfigEntryError(
            "No Home Assistant user carries an e-mail address, so nobody could log in. "
            "Give a person one under the integration's options, People"
        )
    try:
        api = await api_for(hass, entry)
        # here rather than in async_migrate_entry: it needs Cloudflare
        await _async_migrate_service_token_option(hass, entry, api)
        options = await async_provisioning_options(hass, entry, api)
        await api.ensure_tag(options[OPTION_APP_TAG])
        # who the gate admitted before this run: anyone dropped since is logged out below
        previous = allowed_emails_of(
            await api.get_app(gate_id) if (gate_id := entry.data.get(DATA_GATE_APP_ID)) else None
        )
        client_apps = await _async_reconcile_clients(hass, entry, api, options, emails)
        script_tokens = await _async_reconcile_scripts(hass, entry, api, options)
        # reread: a replaced token has a new id, which the gate's Service Auth rule names
        options = await async_provisioning_options(hass, entry, api)
        result = await _async_provision_entry(hass, entry, api, options, emails, client_apps)
        # only after the gate write: Cloudflare refuses later writes that name deleted objects
        await _async_delete_stale_clients(api, options, None, client_apps)
        await _async_delete_stale_tokens(api, options, None, script_tokens)
        await _async_revoke_removed(hass, entry, api, previous, emails)
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
        raise ConfigEntryError(
            f"Cloudflare refused the Access configuration for {options[CONF_HOSTNAME]}: {err}"
        ) from err

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
        logins=LoginCoordinator(hass, entry, api),
    )
    _async_set_watched_apps(data)
    async_check_mcp_login_conflict(hass, entry, options)
    entry.runtime_data = data
    _async_track_changes(hass, entry, data)
    # `async_refresh`, not `async_config_entry_first_refresh`: the latter raises
    # ConfigEntryNotReady on failure (helpers.update_coordinator), and the login history
    # is a convenience that must not hold up the gate.
    await data.logins.async_load()
    await data.logins.async_refresh()
    # A coordinator schedules its next poll only while it has a listener
    # (helpers.update_coordinator), and nothing subscribes to this one: no entity is
    # built from the logs, only events and repair issues.
    entry.async_on_unload(data.logins.async_add_listener(lambda: None))
    return True


@callback
def _async_set_watched_apps(data: EntryData) -> None:
    """Tell the login watcher which applications are this entry's."""
    data.logins.app_ids = {
        app_id
        for app_id in (data.entry.data.get(DATA_GATE_APP_ID), *data.client_apps.values())
        if app_id
    }


@callback
def _async_track_changes(hass: HomeAssistant, entry: ConfigEntry, data: EntryData) -> None:
    """Keep the applications in step with the users, the clients and the External URL.

    Every such change schedules one debounced reconciliation.
    """

    async def _refresh() -> None:
        emails = await allowed_emails(hass, login_emails(entry))
        try:
            # the last known login methods are enough to tell whether anything changed;
            # Cloudflare is asked again only when a write follows
            options = {
                **provisioning_options(hass, entry),
                OPTION_IDP_IDS: data.options[OPTION_IDP_IDS],
            }
        except NoURLAvailableError:
            # nothing to guard any more; the applications stay as they are until it is back
            _LOGGER.warning("Home Assistant's External URL is gone; the Access gate stays as it is")
            ir.async_create_issue(
                hass,
                DOMAIN,
                issue_id(entry, ISSUE_NO_EXTERNAL_URL),
                is_fixable=True,
                severity=ir.IssueSeverity.ERROR,
                translation_key=ISSUE_NO_EXTERNAL_URL,
                translation_placeholders=FORM_PLACEHOLDERS,
                data={"key": ISSUE_NO_EXTERNAL_URL, "entry_id": entry.entry_id},
            )
            return
        ir.async_delete_issue(hass, DOMAIN, issue_id(entry, ISSUE_NO_EXTERNAL_URL))
        async_check_mcp_login_conflict(hass, entry, options)
        if (
            emails == data.emails
            and options[CONF_HOSTNAME] == data.options[CONF_HOSTNAME]
            and set(console_clients(entry)) == set(data.client_apps)
            and set(script_clients(entry)) == set(data.script_tokens)
            and options[CONF_CLIENT_REDIRECT_URIS] == data.options[CONF_CLIENT_REDIRECT_URIS]
            and options[CONF_SERVICE_TOKEN_IDS] == data.options[CONF_SERVICE_TOKEN_IDS]
        ):
            return
        previous_options = data.options
        data.options = options
        if not emails:
            _LOGGER.warning(
                "No Home Assistant user carries an e-mail address any more; "
                "the Access allow policy keeps its last subjects"
            )
            ir.async_create_issue(
                hass,
                DOMAIN,
                issue_id(entry, ISSUE_NO_ALLOWED_USERS),
                is_fixable=False,
                severity=ir.IssueSeverity.ERROR,
                translation_key=ISSUE_NO_ALLOWED_USERS,
                translation_placeholders=FORM_PLACEHOLDERS,
            )
            return
        ir.async_delete_issue(hass, DOMAIN, issue_id(entry, ISSUE_NO_ALLOWED_USERS))
        try:
            client_apps = await _async_reconcile_clients(
                hass, entry, data.api, data.options, emails
            )
            script_tokens = await _async_reconcile_scripts(hass, entry, data.api, data.options)
            # reread: a replaced token has a new id, and the login methods may have changed
            data.options = await async_provisioning_options(hass, entry, data.api)
            await _async_provision_entry(hass, entry, data.api, data.options, emails, client_apps)
            if entry.title != data.options[CONF_HOSTNAME]:
                # the External URL changed and the gate now guards it; the unique id
                # follows too, so a second entry for the old hostname is not refused
                hass.config_entries.async_update_entry(
                    entry, title=data.options[CONF_HOSTNAME], unique_id=data.options[CONF_HOSTNAME]
                )
            await _async_delete_stale_clients(data.api, data.options, data.client_apps, client_apps)
            await _async_delete_stale_tokens(
                data.api, data.options, data.script_tokens, script_tokens
            )
            await _async_revoke_removed(
                hass, entry, data.api, {e.strip().lower() for e in data.emails}, emails
            )
            data.emails = emails
            data.client_apps = client_apps
            data.script_tokens = script_tokens
            _async_set_watched_apps(data)
        except CloudflareAuthError as err:
            data.options = previous_options
            _LOGGER.warning("Cloudflare no longer accepts the sign-in: %s", err)
            entry.async_start_reauth(hass)
            return
        except (CloudflareUnavailableError, CloudflareApiError) as err:
            # the next change tries again from the last state Cloudflare accepted
            data.options = previous_options
            _LOGGER.warning("Could not update the Access applications: %s", err)
            ir.async_create_issue(
                hass,
                DOMAIN,
                issue_id(entry, ISSUE_UPDATE_FAILED),
                is_fixable=True,
                severity=ir.IssueSeverity.ERROR,
                translation_key=ISSUE_UPDATE_FAILED,
                translation_placeholders={
                    "hostname": previous_options[CONF_HOSTNAME],
                    "error": str(err),
                },
                data={"key": ISSUE_UPDATE_FAILED, "entry_id": entry.entry_id},
            )
            return
        ir.async_delete_issue(hass, DOMAIN, issue_id(entry, ISSUE_UPDATE_FAILED))

    debouncer = Debouncer(
        hass,
        _LOGGER,
        cooldown=RECONCILE_COOLDOWN_SECONDS,
        immediate=False,
        function=_refresh,
        # a reconciliation in flight must not hold up startup or shutdown
        background=True,
    )

    @callback
    def _entry_changed(_change: ConfigEntryChange, changed: ConfigEntry) -> None:
        # this entry's subentries, and HA-MCP's login mode (see mcp.py)
        if changed.entry_id == entry.entry_id or changed.domain == HA_MCP_DOMAIN:
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
    # the External URL is the hostname; core_config.Config.async_update fires this on a change
    entry.async_on_unload(hass.bus.async_listen(EVENT_CORE_CONFIG_UPDATE, _schedule))
    # entries are not unloaded at shutdown (config_entries.ConfigEntries._async_shutdown
    # only cancels setup retries), so the on_unload above does not stop the debouncer then
    entry.async_on_unload(hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _stop))


async def async_unload_entry(hass: HomeAssistant, entry: AccessConfigEntry) -> bool:
    """Unload the entry; a disabled entry also takes the gate down.

    With the integration off the origin no longer recognises Access identities, so the
    hostname goes back to how it was without it. Registered clients' applications stay,
    so their consoles keep their credentials. A plain unload (a reload, a restart)
    leaves the edge alone.
    """
    # a disable during shutdown is too late to talk to Cloudflare; async_setup catches
    # it at the next start
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
    await async_remove_login_history(hass, entry)
    for key in (
        ISSUE_NO_ALLOWED_USERS,
        ISSUE_MCP_AUTH_CONFLICT,
        ISSUE_NO_EXTERNAL_URL,
        ISSUE_UPDATE_FAILED,
    ):
        ir.async_delete_issue(hass, DOMAIN, issue_id(entry, key))
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
            *(sub.data.get(DATA_CLIENT_APP_ID) for sub in console_clients(entry).values()),
        )
        for sub in script_clients(entry).values():
            if sub.data.get(DATA_TOKEN_ID):
                await api.delete_service_token(sub.data[DATA_TOKEN_ID])
    except (CloudflareAuthError, CloudflareUnavailableError, CloudflareApiError) as err:
        _LOGGER.warning("Could not delete the Access objects; remove them by hand: %s", err)
