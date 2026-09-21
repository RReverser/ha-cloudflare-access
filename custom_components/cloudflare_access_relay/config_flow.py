"""Config, options and subentry flows."""

from __future__ import annotations

from collections.abc import Mapping
import logging
import re
from typing import Any
from urllib.parse import urlparse

from homeassistant.config_entries import (
    SOURCE_REAUTH,
    ConfigEntry,
    ConfigFlowResult,
    ConfigSubentryData,
    ConfigSubentryFlow,
    OptionsFlowWithReload,
    SubentryFlowResult,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import section
from homeassistant.helpers.config_entry_oauth2_flow import AbstractOAuth2FlowHandler
from homeassistant.helpers.httpx_client import get_async_client
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
    CONF_EMAIL,
    CONF_EXTRA_BYPASS_PATHS,
    CONF_GATE_ENABLED,
    CONF_HOSTNAME,
    CONF_NEEDS_CREDENTIALS,
    CONF_REDIRECT_URIS,
    CONF_SERVICE_TOKEN_IDS,
    CONF_SESSION_DURATION,
    CONF_USER_ID,
    DATA_CLIENT_APP_ID,
    DATA_CLIENT_ID,
    DATA_CLIENT_SECRET,
    DATA_TEAM_DOMAIN,
    DATA_TOKEN,
    DEFAULT_DELETE_OBJECTS_ON_REMOVE,
    DEFAULT_GATE_ENABLED,
    DEFAULT_SESSION_DURATION,
    DOMAIN,
    FORM_PLACEHOLDERS,
    SECTION_BYPASS,
    SUBENTRY_TYPE_CLIENT,
    SUBENTRY_TYPE_LOGIN_EMAIL,
)
from .options import api_for, effective_options
from .provision import desired_client_app
from .users import allowed_emails, login_emails, users_without_address

_LOGGER = logging.getLogger(__name__)

_MULTI_TEXT = TextSelector(TextSelectorConfig(multiple=True))
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
    minutes = round(
        value.get("days", 0) * 24 * 60
        + value.get("hours", 0) * 60
        + value.get("minutes", 0)
        + value.get("seconds", 0) / 60
    )
    if minutes < 1:
        return None
    return f"{minutes // 60}h" if minutes % 60 == 0 else f"{minutes}m"


# Started with this source (tests, automation) instead of the sign-in; also the reauth
# path of an entry created with a token.
SOURCE_API_TOKEN = "api_token"


def normalise_hostname(raw: str) -> str:
    """Accept 'ha.example.com', 'https://ha.example.com/' or with a path."""
    raw = raw.strip()
    if "://" in raw:
        raw = urlparse(raw).netloc
    return raw.split("/")[0].split(":")[0].strip().lower()


def _clean_list(values: list[str] | None) -> list[str]:
    return [v.strip() for v in values or [] if v and v.strip()]


async def _advanced_schema(hass: HomeAssistant, defaults: Mapping[str, Any]) -> dict[Any, Any]:
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
                    vol.Optional(
                        CONF_SERVICE_TOKEN_IDS,
                        default=list(
                            bypass.get(CONF_SERVICE_TOKEN_IDS)
                            or defaults.get(CONF_SERVICE_TOKEN_IDS)
                            or []
                        ),
                    ): _MULTI_TEXT,
                }
            ),
            {"collapsed": True},
        ),
    }


def _validate_options(user_input: dict[str, Any], errors: dict[str, str]) -> dict[str, Any]:
    """Normalise option values and record validation errors; the section is flattened."""
    out = dict(user_input)
    out.update(out.pop(SECTION_BYPASS, None) or {})
    out[CONF_EXTRA_BYPASS_PATHS] = _clean_list(out.get(CONF_EXTRA_BYPASS_PATHS))
    out[CONF_SERVICE_TOKEN_IDS] = _clean_list(out.get(CONF_SERVICE_TOKEN_IDS))
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


def _users_placeholder(emails: list[str]) -> str:
    return ", ".join(emails) if emails else "(none)"


class CloudflareAccessRelayConfigFlow(AbstractOAuth2FlowHandler, domain=DOMAIN):
    """Initial setup: sign in with Cloudflare, pick the account, then the hostname."""

    DOMAIN = DOMAIN
    VERSION = 1

    def __init__(self) -> None:
        """Start with no credential."""
        super().__init__()
        self._credential: dict[str, Any] = {}
        self._accounts: list[dict[str, Any]] = []

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
        """Return the subentry flows: login e-mails and registered OAuth clients."""
        return {
            SUBENTRY_TYPE_LOGIN_EMAIL: LoginEmailSubentryFlow,
            SUBENTRY_TYPE_CLIENT: ClientSubentryFlow,
        }

    # ----------------------------------------------------------------- credentials

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Sign in with Cloudflare: the consent page asks for the integration's scopes."""
        async_register_project_client(self.hass)
        return await self.async_step_pick_implementation()

    async def async_oauth_create_entry(self, data: dict[str, Any]) -> ConfigFlowResult:
        """Signed in: pick the account (or verify the re-authenticated one)."""
        self._credential = data
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

    def _default_hostname(self) -> str:
        if self.hass.config.external_url:
            return normalise_hostname(self.hass.config.external_url)
        return ""

    async def async_step_settings(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Hostname and the advanced options; the gate starts disabled.

        Nobody can pass the gate without an e-mail address, so when no user has one the
        step also asks which user gets one, and stores it as a login e-mail subentry.
        """
        errors: dict[str, str] = {}
        nobody = not allowed_emails(self.hass, {})
        if user_input is not None:
            hostname = normalise_hostname(user_input[CONF_HOSTNAME])
            if not hostname:
                errors[CONF_HOSTNAME] = "invalid_hostname"
            options = _validate_options(user_input, errors)
            options[CONF_HOSTNAME] = hostname
            subentries: list[ConfigSubentryData] = []
            if nobody:
                login = await _validate_login_email(self.hass, {}, user_input, errors)
                if login is not None:
                    subentries.append(
                        ConfigSubentryData(
                            data=login,
                            subentry_type=SUBENTRY_TYPE_LOGIN_EMAIL,
                            title=await _login_email_title(self.hass, login),
                            unique_id=login[CONF_USER_ID],
                        )
                    )
            if not errors:
                await self.async_set_unique_id(hostname)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=hostname,
                    data=self._credential,
                    options={CONF_GATE_ENABLED: DEFAULT_GATE_ENABLED, **options},
                    subentries=subentries,
                )
        defaults: dict[str, Any] = dict(user_input or {})
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_HOSTNAME, default=defaults.get(CONF_HOSTNAME) or self._default_hostname()
                ): str,
                **(_login_email_schema(self.hass, {}, defaults) if nobody else {}),
                **await _advanced_schema(self.hass, defaults),
            }
        )
        return self.async_show_form(
            step_id="settings",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                **FORM_PLACEHOLDERS,
                "allowed_users": _users_placeholder(allowed_emails(self.hass, {})),
            },
        )

    # ---------------------------------------------------------------------- reauth

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        """Credential rejected: sign in again, or enter a new API token."""
        if DATA_TOKEN in entry_data:
            return await self.async_step_reauth_confirm()
        return await self.async_step_api_token()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm before the browser is sent to Cloudflare again."""
        if user_input is None:
            return self.async_show_form(step_id="reauth_confirm", data_schema=vol.Schema({}))
        async_register_project_client(self.hass)
        return await self.async_step_pick_implementation()


class OptionsFlowHandler(OptionsFlowWithReload):
    """Everything but the credentials; saving reloads and re-provisions."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Show and process the options form."""
        errors: dict[str, str] = {}
        current = effective_options(self.config_entry)
        if user_input is not None:
            options = _validate_options(user_input, errors)
            if not errors:
                options[CONF_HOSTNAME] = current[CONF_HOSTNAME]
                if not allowed_emails(self.hass, login_emails(self.config_entry)):
                    errors["base"] = "no_allowed_users"
            if not errors:
                return self.async_create_entry(data=options)
            current = {**current, **user_input}
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_GATE_ENABLED,
                    default=bool(current.get(CONF_GATE_ENABLED, DEFAULT_GATE_ENABLED)),
                ): BooleanSelector(),
                **await _advanced_schema(self.hass, current),
            }
        )
        return self.async_show_form(
            step_id="init",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                **FORM_PLACEHOLDERS,
                CONF_HOSTNAME: current.get(CONF_HOSTNAME, ""),
                "allowed_users": _users_placeholder(
                    allowed_emails(self.hass, login_emails(self.config_entry))
                ),
            },
        )


# ------------------------------------------------------------------ login e-mails


def _login_email_schema(
    hass: HomeAssistant, extra: Mapping[str, str], defaults: Mapping[str, Any]
) -> dict[Any, Any]:
    """Fields naming a user and the address Access knows them by."""
    candidates = users_without_address(hass, extra)
    if (chosen := defaults.get(CONF_USER_ID)) and all(u.id != chosen for u in candidates):
        candidates = [*candidates, *(u for u in hass.auth._store._users.values() if u.id == chosen)]
    users = SelectSelector(
        SelectSelectorConfig(
            options=[SelectOptionDict(value=u.id, label=u.name or u.id) for u in candidates],
            mode=SelectSelectorMode.DROPDOWN,
        )
    )
    user_field = (
        vol.Required(CONF_USER_ID, default=chosen) if chosen else vol.Required(CONF_USER_ID)
    )
    return {
        user_field: users,
        vol.Required(CONF_EMAIL, default=defaults.get(CONF_EMAIL, "")): TextSelector(
            TextSelectorConfig(type=TextSelectorType.EMAIL)
        ),
    }


async def _validate_login_email(
    hass: HomeAssistant,
    extra: Mapping[str, str],
    user_input: Mapping[str, Any],
    errors: dict[str, str],
    *,
    current_user: str | None = None,
) -> dict[str, str] | None:
    """Check the user exists and the address is one; return the subentry data."""
    user_id = str(user_input.get(CONF_USER_ID) or "")
    email = str(user_input.get(CONF_EMAIL) or "").strip()
    user = await hass.auth.async_get_user(user_id) if user_id else None
    if user is None or not user.is_active or user.system_generated:
        errors[CONF_USER_ID] = "unknown_user"
    elif user_id in extra and user_id != current_user:
        errors[CONF_USER_ID] = "user_taken"
    if "@" not in email or " " in email:
        errors[CONF_EMAIL] = "invalid_email"
    if errors:
        return None
    return {CONF_USER_ID: user_id, CONF_EMAIL: email}


async def _login_email_title(hass: HomeAssistant, data: Mapping[str, str]) -> str:
    user = await hass.auth.async_get_user(data[CONF_USER_ID])
    return f"{user.name if user and user.name else data[CONF_USER_ID]}: {data[CONF_EMAIL]}"


class LoginEmailSubentryFlow(ConfigSubentryFlow):
    """The e-mail address a Home Assistant user is known by at Access.

    For users whose login username is not their address (Home Assistant has no e-mail
    field). Saving re-provisions the allow policy through the entry's change listener.
    """

    async def _async_form(
        self, step_id: str, defaults: Mapping[str, Any], errors: dict[str, str]
    ) -> SubentryFlowResult:
        entry = self._get_entry()
        return self.async_show_form(
            step_id=step_id,
            data_schema=vol.Schema(_login_email_schema(self.hass, login_emails(entry), defaults)),
            errors=errors,
            description_placeholders=FORM_PLACEHOLDERS,
        )

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> SubentryFlowResult:
        """Give a user an address."""
        errors: dict[str, str] = {}
        if user_input is not None:
            entry = self._get_entry()
            data = await _validate_login_email(self.hass, login_emails(entry), user_input, errors)
            if data is not None:
                return self.async_create_entry(
                    title=await _login_email_title(self.hass, data),
                    data=data,
                    unique_id=data[CONF_USER_ID],
                )
        return await self._async_form("user", user_input or {}, errors)

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> SubentryFlowResult:
        """Change the address (or the user it belongs to)."""
        errors: dict[str, str] = {}
        entry = self._get_entry()
        sub = self._get_reconfigure_subentry()
        if user_input is not None:
            data = await _validate_login_email(
                self.hass,
                login_emails(entry),
                user_input,
                errors,
                current_user=sub.data[CONF_USER_ID],
            )
            if data is not None:
                return self.async_update_and_abort(
                    entry,
                    sub,
                    title=await _login_email_title(self.hass, data),
                    data=data,
                    unique_id=data[CONF_USER_ID],
                )
        return await self._async_form("reconfigure", user_input or dict(sub.data), errors)


# ------------------------------------------------------------------ OAuth clients


def _client_endpoints(team_domain: str, client_id: str) -> dict[str, str]:
    base = f"https://{team_domain}/cdn-cgi/access/sso/oidc/{client_id}"
    return {
        "authorization_url": f"{base}/authorization",
        "token_url": f"{base}/token",
        "userinfo_url": f"{base}/userinfo",
    }


class ClientSubentryFlow(ConfigSubentryFlow):
    """A client that logs people in through Access and calls Home Assistant with the token.

    Every client's redirect URLs are what the gate lets a self-registering client (an MCP
    client) use. A client whose console asks for a client id and secret (Google Home,
    the Alexa developer console) gets an Access for SaaS application as well, and this
    flow shows the credentials and Access's endpoints to enter in that console.
    """

    _created: dict[str, Any]

    def _validate(self, user_input: dict[str, Any], errors: dict[str, str]) -> dict[str, Any]:
        name = user_input.get(CONF_CLIENT_NAME, "").strip()
        uris = _clean_list(user_input.get(CONF_REDIRECT_URIS))
        if not name:
            errors[CONF_CLIENT_NAME] = "required"
        if not uris:
            errors[CONF_REDIRECT_URIS] = "required"
        elif any(not u.startswith("https://") for u in uris):
            errors[CONF_REDIRECT_URIS] = "invalid_redirect_uri"
        return {
            CONF_CLIENT_NAME: name,
            CONF_REDIRECT_URIS: uris,
            CONF_NEEDS_CREDENTIALS: bool(user_input.get(CONF_NEEDS_CREDENTIALS)),
        }

    async def _async_register(
        self, data: dict[str, Any], errors: dict[str, str], app_id: str | None
    ) -> dict[str, Any] | None:
        """Create or update the client's Access application; return the data to store."""
        entry = self._get_entry()
        emails = allowed_emails(self.hass, login_emails(entry))
        desired = desired_client_app(
            effective_options(entry), emails, data[CONF_CLIENT_NAME], data[CONF_REDIRECT_URIS]
        )
        try:
            api = await api_for(self.hass, entry)
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
            return {
                **data,
                DATA_CLIENT_APP_ID: app["id"],
                DATA_CLIENT_ID: saas.get("client_id"),
                DATA_CLIENT_SECRET: saas.get("client_secret"),
            }
        return None

    def _form(
        self, step_id: str, defaults: Mapping[str, Any], errors: dict[str, str]
    ) -> SubentryFlowResult:
        schema = vol.Schema(
            {
                vol.Required(CONF_CLIENT_NAME, default=defaults.get(CONF_CLIENT_NAME, "")): str,
                vol.Required(
                    CONF_REDIRECT_URIS, default=list(defaults.get(CONF_REDIRECT_URIS) or [])
                ): _MULTI_TEXT,
                vol.Required(
                    CONF_NEEDS_CREDENTIALS, default=bool(defaults.get(CONF_NEEDS_CREDENTIALS))
                ): BooleanSelector(),
            }
        )
        return self.async_show_form(
            step_id=step_id,
            data_schema=schema,
            errors=errors,
            description_placeholders=FORM_PLACEHOLDERS,
        )

    def _credentials(self, data: Mapping[str, Any]) -> SubentryFlowResult:
        team_domain = self._get_entry().data[DATA_TEAM_DOMAIN]
        return self.async_show_form(
            step_id="credentials",
            data_schema=vol.Schema({}),
            description_placeholders={
                CONF_CLIENT_NAME: data[CONF_CLIENT_NAME],
                DATA_CLIENT_ID: data[DATA_CLIENT_ID] or "",
                DATA_CLIENT_SECRET: data.get(DATA_CLIENT_SECRET) or "(unchanged)",
                **_client_endpoints(team_domain, data[DATA_CLIENT_ID] or ""),
            },
        )

    def _store(self, data: dict[str, Any]) -> SubentryFlowResult:
        """Create or update the subentry; a lost application is replaced on reconciliation."""
        if self.source == "reconfigure":
            entry = self._get_entry()
            sub = self._get_reconfigure_subentry()
            if not data[CONF_NEEDS_CREDENTIALS]:
                # the application, if any, is deleted by the entry's reconciliation
                data = {
                    k: v
                    for k, v in data.items()
                    if k not in (DATA_CLIENT_APP_ID, DATA_CLIENT_ID, DATA_CLIENT_SECRET)
                }
                return self.async_update_and_abort(
                    entry, sub, title=data[CONF_CLIENT_NAME], data=data
                )
            return self.async_update_and_abort(
                entry,
                sub,
                title=data[CONF_CLIENT_NAME],
                data_updates={k: v for k, v in data.items() if v is not None},
            )
        return self.async_create_entry(title=data[CONF_CLIENT_NAME], data=data)

    async def _async_handle(
        self, step_id: str, user_input: dict[str, Any] | None, current: Mapping[str, Any]
    ) -> SubentryFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            data = self._validate(user_input, errors)
            if not errors and not data[CONF_NEEDS_CREDENTIALS]:
                return self._store(data)
            if not errors:
                registered = await self._async_register(
                    data, errors, current.get(DATA_CLIENT_APP_ID)
                )
                if registered is not None:
                    self._created = registered
                    return self._credentials(registered)
        return self._form(step_id, user_input or current, errors)

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> SubentryFlowResult:
        """Name, redirect URLs and whether the client's console needs credentials."""
        return await self._async_handle("user", user_input, {})

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> SubentryFlowResult:
        """Change the client; a console client's application follows."""
        return await self._async_handle(
            "reconfigure", user_input, self._get_reconfigure_subentry().data
        )

    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> SubentryFlowResult:
        """Store the registration once the credentials were shown."""
        if user_input is None:
            return self._credentials(self._created)
        return self._store(self._created)
