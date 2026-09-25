"""Config, options and subentry flows."""

from __future__ import annotations

from collections.abc import Mapping
import logging
import re
from typing import Any

from homeassistant.config_entries import (
    SOURCE_REAUTH,
    SOURCE_RECONFIGURE,
    ConfigEntry,
    ConfigFlowResult,
    ConfigSubentryFlow,
    OptionsFlowWithReload,
    SubentryFlowResult,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import section
from homeassistant.helpers.config_entry_oauth2_flow import AbstractOAuth2FlowHandler
from homeassistant.helpers.httpx_client import get_async_client
from homeassistant.helpers.network import NoURLAvailableError
from homeassistant.helpers.selector import (
    BooleanSelector,
    DurationSelector,
    DurationSelectorConfig,
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)
import voluptuous as vol

from .application_credentials import async_register_project_client
from .bypass import async_bypass_candidates
from .cloudflare_api import (
    CloudflareAccessApi,
    CloudflareApiError,
    CloudflareAuthError,
    CloudflareUnavailableError,
)
from .const import (
    CONF_ACCOUNT_ID,
    CONF_API_TOKEN,
    CONF_CLIENT_NAME,
    CONF_DELETE_OBJECTS_ON_REMOVE,
    CONF_EXTRA_BYPASS_PATHS,
    CONF_GATE_ENABLED,
    CONF_HOSTNAME,
    CONF_LOGIN_EMAILS,
    CONF_REDIRECT_URIS,
    CONF_SESSION_DURATION,
    DATA_CLIENT_APP_ID,
    DATA_CLIENT_ID,
    DATA_CLIENT_SECRET,
    DATA_TEAM_DOMAIN,
    DATA_TOKEN,
    DATA_TOKEN_EXPIRES_AT,
    DATA_TOKEN_ID,
    DEFAULT_DELETE_OBJECTS_ON_REMOVE,
    DEFAULT_GATE_ENABLED,
    DEFAULT_SESSION_DURATION,
    DOMAIN,
    FORM_PLACEHOLDERS,
    KNOWN_REDIRECT_URIS,
    OPTION_APP_TAG,
    SECTION_BYPASS,
    SECTION_PEOPLE,
    SERVICE_TOKEN_NAME_FMT,
    SUBENTRY_TYPE_CONSOLE,
    SUBENTRY_TYPE_SCRIPT,
    SUBENTRY_TYPE_SELF_REGISTERING,
)
from .options import (
    api_for,
    async_provisioning_options,
    effective_options,
    external_hostname,
    provisioning_options,
)
from .provision import desired_client_app
from .users import (
    allowed_emails,
    login_emails,
    person_users,
    username_address,
    users_without_address,
)

_LOGGER = logging.getLogger(__name__)

# the published callbacks of the self-registering apps as choices, any URL typed
_PUBLISHED_REDIRECT_URIS = SelectSelector(
    SelectSelectorConfig(
        options=[
            SelectOptionDict(value=uri, label=f"{label}: {uri}")
            for uri, label in KNOWN_REDIRECT_URIS
        ],
        multiple=True,
        custom_value=True,
        mode=SelectSelectorMode.DROPDOWN,
    )
)
# a console shows its own exact callback: typed, nothing to pick from
_TYPED_REDIRECT_URIS = SelectSelector(
    SelectSelectorConfig(
        options=[], multiple=True, custom_value=True, mode=SelectSelectorMode.DROPDOWN
    )
)
_PASSWORD = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))
# Access takes `<n>h` or `<n>m`; the form shows days, hours and minutes.
_SESSION_DURATION = DurationSelector(DurationSelectorConfig(enable_day=True, enable_second=False))
_DURATION_RE = re.compile(r"([1-9][0-9]*)([mh])")


def _duration_to_form(value: Any) -> dict[str, int]:
    """Turn a stored `<n>h`/`<n>m` into the duration selector's value."""
    if isinstance(value, dict):
        return value  # re-shown after a validation error
    match = _DURATION_RE.fullmatch(str(value or "").strip())
    minutes = int(match[1]) * (60 if match[2] == "h" else 1) if match else 0
    days, rest = divmod(minutes, 24 * 60)
    hours, minutes = divmod(rest, 60)
    return {"days": days, "hours": hours, "minutes": minutes}


def _duration_from_form(value: Any) -> str | None:
    """Turn the selector's value (or a `<n>h`/`<n>m` string) into what Access takes."""
    if isinstance(value, str):
        return value.strip() if _DURATION_RE.fullmatch(value.strip()) else None
    if not isinstance(value, dict):
        return None
    # The selector validates with `cv.positive_time_period_dict`, which lets `seconds`
    # through even with the seconds field off; Access takes whole minutes.
    minutes = round(
        value.get("days", 0) * 24 * 60
        + value.get("hours", 0) * 60
        + value.get("minutes", 0)
        + value.get("seconds", 0) / 60
    )
    if minutes < 1:
        return None
    return f"{minutes // 60}h" if minutes % 60 == 0 else f"{minutes}m"


# A flow started with this source (tests, CI) goes to `async_step_api_token` instead of
# the sign-in; it is also the reauth path of an entry created with a token.
SOURCE_API_TOKEN = "api_token"


def _clean_list(values: list[str] | None) -> list[str]:
    return [v.strip() for v in values or [] if v and v.strip()]


async def _people_section(
    hass: HomeAssistant, extra: Mapping[str, str], defaults: Mapping[str, Any]
) -> tuple[dict[Any, Any], dict[str, str]]:
    """Return the People section, one e-mail field per person, and the name-to-user map."""
    fields: dict[Any, Any] = {}
    names: dict[str, str] = {}
    entered = defaults.get(SECTION_PEOPLE) or {}
    for user in await person_users(hass):
        # The key is the label: these fields have no translation, so the frontend shows it.
        name = user.name or user.id
        if (address := username_address(user)) is not None:
            # Read-only: the frontend drops the value on submit, so no name-to-user entry.
            fields[vol.Optional(name, default=address)] = TextSelector(
                TextSelectorConfig(type=TextSelectorType.EMAIL, read_only=True)
            )
            continue
        names[name] = user.id
        fields[vol.Optional(name, default=entered.get(name, extra.get(user.id, "")))] = (
            TextSelector(TextSelectorConfig(type=TextSelectorType.EMAIL))
        )
    schema = {
        vol.Optional(SECTION_PEOPLE, default={}): section(vol.Schema(fields), {"collapsed": False})
    }
    return schema, names


def _parse_people(
    user_input: dict[str, Any], names: Mapping[str, str], errors: dict[str, str]
) -> dict[str, str]:
    """Turn the People section back into login e-mails by user id."""
    emails: dict[str, str] = {}
    for name, user_id in names.items():
        value = str((user_input.get(SECTION_PEOPLE) or {}).get(name) or "").strip()
        if not value:
            continue
        if "@" not in value or " " in value:
            errors["base"] = "invalid_email"
            continue
        emails[user_id] = value
    return emails


async def _advanced_schema(hass: HomeAssistant, defaults: Mapping[str, Any]) -> dict[Any, Any]:
    # Defaults are flat (stored options) or nested (a submitted form shown again).
    bypass = defaults.get(SECTION_BYPASS) or {}
    return {
        vol.Optional(
            CONF_SESSION_DURATION,
            default=_duration_to_form(
                defaults.get(CONF_SESSION_DURATION, DEFAULT_SESSION_DURATION)
            ),
        ): _SESSION_DURATION,
        vol.Optional(
            CONF_DELETE_OBJECTS_ON_REMOVE,
            default=defaults.get(CONF_DELETE_OBJECTS_ON_REMOVE, DEFAULT_DELETE_OBJECTS_ON_REMOVE),
        ): BooleanSelector(),
        vol.Optional(SECTION_BYPASS, default={}): section(
            vol.Schema(
                {
                    vol.Optional(
                        CONF_EXTRA_BYPASS_PATHS,
                        default=list(
                            bypass.get(CONF_EXTRA_BYPASS_PATHS)
                            or defaults.get(CONF_EXTRA_BYPASS_PATHS)
                            or []
                        ),
                    ): SelectSelector(
                        SelectSelectorConfig(
                            options=await async_bypass_candidates(hass),
                            multiple=True,
                            custom_value=True,
                            mode=SelectSelectorMode.DROPDOWN,
                        )
                    ),
                }
            ),
            {"collapsed": True},
        ),
    }


def _validate_options(user_input: dict[str, Any], errors: dict[str, str]) -> dict[str, Any]:
    """Normalise the option values and record validation errors."""
    out = dict(user_input)
    # Options are stored flat; the People section becomes `CONF_LOGIN_EMAILS` (`_parse_people`).
    out.update(out.pop(SECTION_BYPASS, None) or {})
    out.pop(SECTION_PEOPLE, None)
    out[CONF_EXTRA_BYPASS_PATHS] = _clean_list(out.get(CONF_EXTRA_BYPASS_PATHS))
    if CONF_SESSION_DURATION in out:
        duration = _duration_from_form(out[CONF_SESSION_DURATION])
        if duration is None:
            errors[CONF_SESSION_DURATION] = "invalid_duration"
        else:
            out[CONF_SESSION_DURATION] = duration
    return out


async def _validate_credential(api: CloudflareAccessApi, errors: dict[str, str]) -> str | None:
    """Check the credential's two permissions; return the team domain on success."""
    try:
        await api.list_apps()
    except CloudflareAuthError:
        errors["base"] = "invalid_auth"
        return None
    except CloudflareUnavailableError:
        errors["base"] = "cannot_connect"
        return None
    except CloudflareApiError as err:
        _LOGGER.warning("Cloudflare API error during validation: %s", err)
        errors["base"] = "api_error"
        return None
    try:
        return await api.get_team_domain()
    except CloudflareAuthError as err:
        _LOGGER.warning("Credential cannot read the Zero Trust organization: %s", err)
        errors["base"] = "missing_org_read"
    except CloudflareUnavailableError:
        errors["base"] = "cannot_connect"
    except CloudflareApiError as err:
        _LOGGER.warning("Cloudflare API error during validation: %s", err)
        errors["base"] = "api_error"
    return None


async def _users_placeholders(hass: HomeAssistant, extra: Mapping[str, str]) -> dict[str, str]:
    """Return a note naming the people who cannot log in, empty when there are none."""
    missing = await users_without_address(hass, extra)
    if not missing:
        return {"no_address_note": ""}
    names = ", ".join(u.name or u.id for u in missing)
    verb = "has" if len(missing) == 1 else "have"
    # Appended to the section's description, which renders as plain text: a leading
    # space and no markup.
    return {"no_address_note": f" {names} {verb} none yet."}


class CloudflareAccessRelayConfigFlow(AbstractOAuth2FlowHandler, domain=DOMAIN):
    """Initial setup: sign in with Cloudflare, pick the account, then the hostname."""

    DOMAIN = DOMAIN
    VERSION = 1
    # 2: options and subentries of earlier versions are migrated; 3: the hostname is the
    # External URL, no longer an option (`async_migrate_entry`).
    MINOR_VERSION = 5

    def __init__(self) -> None:
        """Start with no credential."""
        super().__init__()
        self._credential: dict[str, Any] = {}
        self._accounts: list[dict[str, Any]] = []
        self._people: dict[str, str] = {}

    @property
    def logger(self) -> logging.Logger:
        """Return the logger."""
        return _LOGGER

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlowHandler:
        """Return the options flow."""
        return OptionsFlowHandler()

    @classmethod
    @callback
    def async_get_supported_subentry_types(
        cls, config_entry: ConfigEntry
    ) -> dict[str, type[ConfigSubentryFlow]]:
        """Return the subentry flows: one per client kind, so each row is labelled with it.

        The login e-mail rows have no flow of their own: a row is created per person by
        the integration, filled in through a repair issue, and cleared by deleting it.
        Listing the type here would put an "add" button on the page that has no use.
        """
        return {
            SUBENTRY_TYPE_SELF_REGISTERING: SelfRegisteringAppFlow,
            SUBENTRY_TYPE_CONSOLE: ConsoleAppFlow,
            SUBENTRY_TYPE_SCRIPT: ScriptFlow,
        }

    # ----------------------------------------------------------------- credentials

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Sign in with Cloudflare: the consent page asks for the integration's scopes."""
        # A flow can start before the integration's setup registered the project's client,
        # and `async_step_pick_implementation` only offers what is registered by then.
        async_register_project_client(self.hass)
        return await self.async_step_pick_implementation()

    async def async_oauth_create_entry(self, data: dict[str, Any]) -> ConfigFlowResult:
        """Signed in: pick the account (or verify the re-authenticated one)."""
        self._credential = data
        # The base method (`AbstractOAuth2FlowHandler.async_oauth_create_entry`) would create
        # a second entry on reauth; update the existing one once the new token is checked.
        if self.source == SOURCE_REAUTH:
            entry = self._get_reauth_entry()
            errors: dict[str, str] = {}
            api = self._api(entry.data[CONF_ACCOUNT_ID])
            if await _validate_credential(api, errors) is None:
                return self.async_abort(reason=errors["base"])
            return self.async_update_reload_and_abort(entry, data_updates=data)
        return await self.async_step_account()

    def _api(self, account_id: str) -> CloudflareAccessApi:
        token = self._credential.get(DATA_TOKEN)
        secret = token["access_token"] if token else self._credential[CONF_API_TOKEN]
        return CloudflareAccessApi(secret, account_id, http_client=get_async_client(self.hass))

    async def async_step_account(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Find the account the consent page granted; ask only when there are several.

        The grant is per account and the token reveals nothing about it, so every account
        the user is a member of is tried: the ones where the token can read the Access
        applications and the Zero Trust organization are the granted ones.
        """
        errors: dict[str, str] = {}
        if not self._accounts:
            try:
                # memberships are a user-level listing: no account id yet
                memberships = await self._api("").list_memberships()
            except CloudflareAuthError:
                return self.async_abort(reason="invalid_auth")
            except CloudflareUnavailableError:
                return self.async_abort(reason="cannot_connect")
            except CloudflareApiError as err:
                _LOGGER.warning("Cloudflare API error listing memberships: %s", err)
                return self.async_abort(reason="api_error")
            for account in memberships:
                probe: dict[str, str] = {}
                team_domain = await _validate_credential(self._api(account["id"]), probe)
                # An auth error only means the grant does not cover this account; an
                # outage is the one failure that aborts.
                if probe.get("base") == "cannot_connect":
                    return self.async_abort(reason="cannot_connect")
                if team_domain:
                    self._accounts.append({**account, DATA_TEAM_DOMAIN: team_domain})
            if not self._accounts:
                return self.async_abort(reason="no_accounts")
        if user_input is None and len(self._accounts) == 1:
            user_input = {CONF_ACCOUNT_ID: self._accounts[0]["id"]}
        if user_input is not None:
            chosen = next(a for a in self._accounts if a["id"] == user_input[CONF_ACCOUNT_ID])
            self._credential[CONF_ACCOUNT_ID] = chosen["id"]
            self._credential[DATA_TEAM_DOMAIN] = chosen[DATA_TEAM_DOMAIN]
            return await self.async_step_settings()
        options = [
            SelectOptionDict(value=a["id"], label=f"{a['name']} ({a['id']})")
            for a in self._accounts
        ]
        return self.async_show_form(
            step_id="account",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_ACCOUNT_ID): SelectSelector(
                        SelectSelectorConfig(options=options, mode=SelectSelectorMode.DROPDOWN)
                    )
                }
            ),
            errors=errors,
        )

    async def async_step_api_token(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Use an API token instead of signing in (source "api_token", or reauth)."""
        errors: dict[str, str] = {}
        if user_input is not None:
            self._credential = {
                CONF_API_TOKEN: user_input[CONF_API_TOKEN].strip(),
                CONF_ACCOUNT_ID: user_input[CONF_ACCOUNT_ID].strip(),
            }
            team_domain = await _validate_credential(
                self._api(self._credential[CONF_ACCOUNT_ID]), errors
            )
            if team_domain:
                self._credential[DATA_TEAM_DOMAIN] = team_domain
                if self.source == SOURCE_REAUTH:
                    return self.async_update_reload_and_abort(
                        self._get_reauth_entry(), data_updates=self._credential
                    )
                return await self.async_step_settings()
        defaults: dict[str, Any] = dict(user_input or {})
        if self.source == SOURCE_REAUTH:
            defaults.setdefault(CONF_ACCOUNT_ID, self._get_reauth_entry().data[CONF_ACCOUNT_ID])
        return self.async_show_form(
            step_id=SOURCE_API_TOKEN,
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_API_TOKEN, default=defaults.get(CONF_API_TOKEN, "")
                    ): _PASSWORD,
                    vol.Required(CONF_ACCOUNT_ID, default=defaults.get(CONF_ACCOUNT_ID, "")): str,
                }
            ),
            errors=errors,
        )

    # -------------------------------------------------------------------- settings

    async def async_step_settings(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for the people's addresses and the advanced options, then create the entry."""
        errors: dict[str, str] = {}
        # The hostname is Home Assistant's External URL; without one there is nothing to
        # guard, so the flow stops and says where to set it.
        try:
            hostname = external_hostname(self.hass)
        except NoURLAvailableError:
            return self.async_abort(
                reason="no_external_url", description_placeholders=FORM_PLACEHOLDERS
            )
        if user_input is not None:
            emails = _parse_people(user_input, self._people, errors)
            options = _validate_options(user_input, errors)
            options[CONF_LOGIN_EMAILS] = emails
            if not errors and not await allowed_emails(self.hass, emails):
                errors["base"] = "no_allowed_users"
            if not errors:
                # one entry per hostname: two would fight over the same gate
                await self.async_set_unique_id(hostname)
                self._abort_if_unique_id_configured()
                # The gate starts off: turning it on is the exposure change, done in the
                # options after the rollout checks (README, Rollout).
                return self.async_create_entry(
                    title=hostname,
                    data=self._credential,
                    options={CONF_GATE_ENABLED: DEFAULT_GATE_ENABLED, **options},
                )
        defaults: dict[str, Any] = dict(user_input or {})
        people, self._people = await _people_section(self.hass, {}, defaults)
        schema = vol.Schema({**people, **await _advanced_schema(self.hass, defaults)})
        return self.async_show_form(
            step_id="settings",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                **FORM_PLACEHOLDERS,
                CONF_HOSTNAME: hostname,
                **await _users_placeholders(self.hass, {}),
            },
        )

    # ---------------------------------------------------------------------- reauth

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        """Credential rejected: sign in again, or enter a new API token."""
        # only an entry created by signing in holds a token set
        if DATA_TOKEN in entry_data:
            return await self.async_step_reauth_confirm()
        return await self.async_step_api_token()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm before the browser is sent to Cloudflare again."""
        if user_input is None:
            return self.async_show_form(step_id="reauth_confirm", data_schema=vol.Schema({}))
        # as in `async_step_user`: register before the implementations are gathered
        async_register_project_client(self.hass)
        return await self.async_step_pick_implementation()


class OptionsFlowHandler(OptionsFlowWithReload):
    """Everything but the credentials; saving reloads and re-provisions."""

    def __init__(self) -> None:
        """Start with no people known."""
        super().__init__()
        self._people: dict[str, str] = {}

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Show and process the options form."""
        errors: dict[str, str] = {}
        current = effective_options(self.config_entry)
        if user_input is not None:
            emails = _parse_people(user_input, self._people, errors)
            options = _validate_options(user_input, errors)
            options[CONF_LOGIN_EMAILS] = emails
            if not errors and not await allowed_emails(self.hass, emails):
                errors["base"] = "no_allowed_users"
            if not errors:
                return self.async_create_entry(data=options)
            current = {**current, **user_input}
        people, self._people = await _people_section(
            self.hass, login_emails(self.config_entry), current
        )
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_GATE_ENABLED,
                    default=bool(current.get(CONF_GATE_ENABLED, DEFAULT_GATE_ENABLED)),
                ): BooleanSelector(),
                **people,
                **await _advanced_schema(self.hass, current),
            }
        )
        return self.async_show_form(
            step_id="init",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                **FORM_PLACEHOLDERS,
                CONF_HOSTNAME: self.config_entry.title,
                **await _users_placeholders(self.hass, login_emails(self.config_entry)),
            },
        )


# ------------------------------------------------------------------ OAuth clients


def _client_endpoints(team_domain: str, client_id: str) -> dict[str, str]:
    base = f"https://{team_domain}/cdn-cgi/access/sso/oidc/{client_id}"
    return {
        "authorization_url": f"{base}/authorization",
        "token_url": f"{base}/token",
        "userinfo_url": f"{base}/userinfo",
    }


class _ClientFlow(ConfigSubentryFlow):
    """What the three client kinds share: a name, and how a finished client is stored."""

    _data: dict[str, Any]

    def _store(self, data: dict[str, Any]) -> SubentryFlowResult:
        """Create or update the subentry."""
        if self.source == SOURCE_RECONFIGURE:
            entry = self._get_entry()
            sub = self._get_reconfigure_subentry()
            # Merge, skipping None: an updated console app's secret is not returned again
            # and the stored one must stay.
            return self.async_update_and_abort(
                entry,
                sub,
                title=data[CONF_CLIENT_NAME],
                data_updates={k: v for k, v in data.items() if v is not None},
            )
        return self.async_create_entry(title=data[CONF_CLIENT_NAME], data=data)


class _AppFlow(_ClientFlow):
    """An app that logs people in: a name and the callback URLs its own side shows."""

    _selector: SelectSelector

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> SubentryFlowResult:
        """Add the app."""
        return await self._async_handle("user", user_input, {})

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> SubentryFlowResult:
        """Rename the app or change its callbacks."""
        return await self._async_handle(
            "reconfigure", user_input, self._get_reconfigure_subentry().data
        )

    async def _async_handle(
        self, step_id: str, user_input: dict[str, Any] | None, current: Mapping[str, Any]
    ) -> SubentryFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            uris = _clean_list(user_input.get(CONF_REDIRECT_URIS))
            if not uris:
                errors[CONF_REDIRECT_URIS] = "required"
            elif any(not u.startswith("https://") for u in uris):
                errors[CONF_REDIRECT_URIS] = "invalid_redirect_uri"
            name = user_input.get(CONF_CLIENT_NAME, "").strip()
            if not name:
                errors[CONF_CLIENT_NAME] = "required"
            if not errors:
                data = {**current, CONF_CLIENT_NAME: name, CONF_REDIRECT_URIS: uris}
                result = await self._async_finish(data, errors)
                if result is not None:
                    return result
        defaults = user_input or current
        return self.async_show_form(
            step_id=step_id,
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_CLIENT_NAME, default=defaults.get(CONF_CLIENT_NAME, "")): str,
                    vol.Required(
                        CONF_REDIRECT_URIS, default=list(defaults.get(CONF_REDIRECT_URIS) or [])
                    ): self._selector,
                }
            ),
            errors=errors,
            description_placeholders=FORM_PLACEHOLDERS,
        )

    async def _async_finish(
        self, data: dict[str, Any], errors: dict[str, str]
    ) -> SubentryFlowResult | None:
        """Finish with a valid name and callbacks; None (with errors set) shows the form again."""
        raise NotImplementedError


class SelfRegisteringAppFlow(_AppFlow):
    """An app that registers itself (Claude, ChatGPT).

    Nothing is created: the callbacks reach the gate's allowed list at the next
    reconcile, and that list is all Cloudflare keeps about such an app.
    """

    _selector = _PUBLISHED_REDIRECT_URIS

    async def _async_finish(
        self, data: dict[str, Any], errors: dict[str, str]
    ) -> SubentryFlowResult | None:
        return self._store(data)


class ConsoleAppFlow(_AppFlow):
    """An app whose console asks for a client ID and secret (Google Home, Alexa).

    It gets an Access for SaaS application; the page after the form shows the
    credentials the console takes.
    """

    _selector = _TYPED_REDIRECT_URIS

    async def _async_finish(
        self, data: dict[str, Any], errors: dict[str, str]
    ) -> SubentryFlowResult | None:
        registered = await self._async_register(data, errors, data.get(DATA_CLIENT_APP_ID))
        if registered is None:
            return None
        self._data = registered
        return self._credentials(registered)

    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> SubentryFlowResult:
        """Store the app once its credentials were shown."""
        if user_input is None:
            return self._credentials(self._data)
        return self._store(self._data)

    async def _async_register(
        self, data: dict[str, Any], errors: dict[str, str], app_id: str | None
    ) -> dict[str, Any] | None:
        """Create or update the app's Access application; return the data to store."""
        entry = self._get_entry()
        emails = await allowed_emails(self.hass, login_emails(entry))
        try:
            api = await api_for(self.hass, entry)
            options = await async_provisioning_options(self.hass, entry, api)
            desired = desired_client_app(
                options, emails, data[CONF_CLIENT_NAME], data[CONF_REDIRECT_URIS]
            )
            # ordering: the tag exists before the application that carries it is written
            await api.ensure_tag(options[OPTION_APP_TAG])
            app = await (api.update_app(app_id, desired) if app_id else api.create_app(desired))
        except CloudflareAuthError:
            errors["base"] = "invalid_auth"
        except CloudflareUnavailableError:
            errors["base"] = "cannot_connect"
        except CloudflareApiError as err:
            _LOGGER.warning("Cloudflare rejected the client registration: %s", err)
            errors["base"] = "api_error"
        else:
            saas = app.get("saas_app") or {}
            # The secret comes back only when the application is created (docs/verified-cloudflare-behaviour.md); after an update it is None here.
            return {
                **data,
                DATA_CLIENT_APP_ID: app["id"],
                DATA_CLIENT_ID: saas.get("client_id"),
                DATA_CLIENT_SECRET: saas.get("client_secret"),
            }
        return None

    def _credentials(self, data: Mapping[str, Any]) -> SubentryFlowResult:
        team_domain = self._get_entry().data[DATA_TEAM_DOMAIN]
        return self.async_show_form(
            step_id="credentials",
            data_schema=vol.Schema({}),
            description_placeholders={
                CONF_CLIENT_NAME: data[CONF_CLIENT_NAME],
                DATA_CLIENT_ID: data[DATA_CLIENT_ID] or "",
                # None after an update: Cloudflare returns the secret once, at creation
                DATA_CLIENT_SECRET: data.get(DATA_CLIENT_SECRET) or "(unchanged)",
                **_client_endpoints(team_domain, data[DATA_CLIENT_ID] or ""),
            },
        )


class ScriptFlow(_ClientFlow):
    """A script or service with nobody behind it: an Access service token."""

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> SubentryFlowResult:
        """Ask for the name, then create the token and show the credentials."""
        errors: dict[str, str] = {}
        if user_input is not None:
            name = user_input.get(CONF_CLIENT_NAME, "").strip()
            if not name:
                errors[CONF_CLIENT_NAME] = "required"
            else:
                self._data = {CONF_CLIENT_NAME: name}
                return await self._async_create_token(errors)
        return self._form("user", (user_input or {}).get(CONF_CLIENT_NAME, ""), errors)

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> SubentryFlowResult:
        """Rename the script; its token is renamed and its validity extended."""
        current = self._get_reconfigure_subentry().data
        errors: dict[str, str] = {}
        if user_input is not None:
            name = user_input.get(CONF_CLIENT_NAME, "").strip()
            if not name:
                errors[CONF_CLIENT_NAME] = "required"
            else:
                self._data = {**current, CONF_CLIENT_NAME: name}
                return await self._async_renew_token(errors)
        defaults = user_input or current
        return self._form("reconfigure", defaults.get(CONF_CLIENT_NAME, ""), errors)

    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> SubentryFlowResult:
        """Store the script once its credentials were shown."""
        if user_input is None:
            return self._credentials(self._data)
        return self._store(self._data)

    def _form(self, step_id: str, name: str, errors: dict[str, str]) -> SubentryFlowResult:
        return self.async_show_form(
            step_id=step_id,
            data_schema=vol.Schema({vol.Required(CONF_CLIENT_NAME, default=name): str}),
            errors=errors,
            description_placeholders=FORM_PLACEHOLDERS,
        )

    async def _async_create_token(self, errors: dict[str, str]) -> SubentryFlowResult:
        """Create the service token and show its credentials."""
        entry = self._get_entry()
        options = provisioning_options(self.hass, entry)
        name = SERVICE_TOKEN_NAME_FMT.format(
            hostname=options[CONF_HOSTNAME], name=self._data[CONF_CLIENT_NAME]
        )
        try:
            api = await api_for(self.hass, entry)
            token = await api.create_service_token(name)
        except CloudflareAuthError as err:
            _LOGGER.warning("The credential cannot manage service tokens: %s", err)
            errors["base"] = "missing_service_tokens_edit"
            # The credential lacks the Service Tokens permission (README, Sign-in); only a
            # new one can fix that, so the entry's reauth is started from here.
            entry.async_start_reauth(self.hass)
        except CloudflareUnavailableError:
            errors["base"] = "cannot_connect"
        except CloudflareApiError as err:
            _LOGGER.warning("Cloudflare refused to create the service token: %s", err)
            errors["base"] = "api_error"
        else:
            self._data.update(
                {
                    DATA_TOKEN_ID: token["id"],
                    DATA_CLIENT_ID: token.get("client_id"),
                    DATA_CLIENT_SECRET: token.get("client_secret"),
                    DATA_TOKEN_EXPIRES_AT: token.get("expires_at"),
                }
            )
            return self._credentials(self._data)
        return self._form("user", self._data[CONF_CLIENT_NAME], errors)

    async def _async_renew_token(self, errors: dict[str, str]) -> SubentryFlowResult:
        """Rename the token and extend its validity, then show the credentials again."""
        entry = self._get_entry()
        options = provisioning_options(self.hass, entry)
        token_id = self._data.get(DATA_TOKEN_ID)
        name = SERVICE_TOKEN_NAME_FMT.format(
            hostname=options[CONF_HOSTNAME], name=self._data[CONF_CLIENT_NAME]
        )
        try:
            api = await api_for(self.hass, entry)
            # a token deleted on Cloudflare is replaced, and the new secret shown
            if token_id and await api.get_service_token(token_id) is not None:
                await api.rename_service_token(token_id, name)
                token = await api.refresh_service_token(token_id)
                self._data[DATA_TOKEN_EXPIRES_AT] = token.get("expires_at")
            else:
                token = await api.create_service_token(name)
                self._data.update(
                    {
                        DATA_TOKEN_ID: token["id"],
                        DATA_CLIENT_ID: token.get("client_id"),
                        DATA_CLIENT_SECRET: token.get("client_secret"),
                        DATA_TOKEN_EXPIRES_AT: token.get("expires_at"),
                    }
                )
        except CloudflareAuthError as err:
            _LOGGER.warning("The credential cannot manage service tokens: %s", err)
            errors["base"] = "missing_service_tokens_edit"
            # as in `_async_create_token`: a new credential is needed
            entry.async_start_reauth(self.hass)
        except CloudflareUnavailableError:
            errors["base"] = "cannot_connect"
        except CloudflareApiError as err:
            _LOGGER.warning("Cloudflare refused to update the service token: %s", err)
            errors["base"] = "api_error"
        else:
            return self._credentials(self._data)
        return self._form("reconfigure", self._data[CONF_CLIENT_NAME], errors)

    def _credentials(self, data: Mapping[str, Any]) -> SubentryFlowResult:
        return self.async_show_form(
            step_id="credentials",
            data_schema=vol.Schema({}),
            description_placeholders={
                **FORM_PLACEHOLDERS,
                CONF_CLIENT_NAME: data[CONF_CLIENT_NAME],
                DATA_CLIENT_ID: data.get(DATA_CLIENT_ID) or "",
                DATA_CLIENT_SECRET: data.get(DATA_CLIENT_SECRET) or "(unknown)",
                DATA_TOKEN_EXPIRES_AT: _date_only(data.get(DATA_TOKEN_EXPIRES_AT)),
            },
        )


def _date_only(value: Any) -> str:
    """Return the date part of an ISO timestamp, for the credentials page."""
    return str(value or "")[:10]
