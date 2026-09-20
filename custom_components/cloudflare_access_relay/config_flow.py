"""Config, options and subentry flows."""

from __future__ import annotations

from collections.abc import Mapping
import logging
from typing import Any
from urllib.parse import urlparse

from homeassistant.config_entries import (
    SOURCE_REAUTH,
    ConfigEntry,
    ConfigFlowResult,
    ConfigSubentryFlow,
    OptionsFlowWithReload,
    SubentryFlowResult,
)
from homeassistant.core import callback
from homeassistant.helpers.config_entry_oauth2_flow import AbstractOAuth2FlowHandler
from homeassistant.helpers.httpx_client import get_async_client
from homeassistant.helpers.selector import (
    BooleanSelector,
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)
import voluptuous as vol

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
    CONF_CLIENT_REDIRECT_URIS,
    CONF_DELETE_OBJECTS_ON_REMOVE,
    CONF_EXTRA_BYPASS_PATHS,
    CONF_GATE_ENABLED,
    CONF_HOSTNAME,
    CONF_IDENTITY_CLAIM,
    CONF_REDIRECT_URIS,
    CONF_SERVICE_TOKEN_IDS,
    CONF_SESSION_DURATION,
    CONF_USER_MATCH,
    DATA_CLIENT_APP_ID,
    DATA_CLIENT_ID,
    DATA_CLIENT_SECRET,
    DATA_TEAM_DOMAIN,
    DATA_TOKEN,
    DEFAULT_DELETE_OBJECTS_ON_REMOVE,
    DEFAULT_GATE_ENABLED,
    DEFAULT_IDENTITY_CLAIM,
    DEFAULT_SESSION_DURATION,
    DEFAULT_USER_MATCH,
    DOMAIN,
    SUBENTRY_TYPE_CLIENT,
)
from .options import DEFAULT_OPTIONS, api_for, effective_options
from .provision import desired_client_app
from .users import allowed_emails

_LOGGER = logging.getLogger(__name__)

_MULTI_TEXT = TextSelector(TextSelectorConfig(multiple=True))
_PASSWORD = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))

STEP_OAUTH = "oauth"
STEP_API_TOKEN = "api_token"


def normalise_hostname(raw: str) -> str:
    """Accept 'ha.example.com', 'https://ha.example.com/' or with a path."""
    raw = raw.strip()
    if "://" in raw:
        raw = urlparse(raw).netloc
    return raw.split("/")[0].split(":")[0].strip().lower()


def _clean_list(values: list[str] | None) -> list[str]:
    return [v.strip() for v in values or [] if v and v.strip()]


def _advanced_schema(defaults: Mapping[str, Any]) -> dict[Any, Any]:
    return {
        vol.Optional(
            CONF_EXTRA_BYPASS_PATHS, default=list(defaults.get(CONF_EXTRA_BYPASS_PATHS) or [])
        ): _MULTI_TEXT,
        vol.Optional(
            CONF_SERVICE_TOKEN_IDS, default=list(defaults.get(CONF_SERVICE_TOKEN_IDS) or [])
        ): _MULTI_TEXT,
        vol.Optional(
            CONF_SESSION_DURATION,
            default=defaults.get(CONF_SESSION_DURATION, DEFAULT_SESSION_DURATION),
        ): str,
        vol.Optional(
            CONF_IDENTITY_CLAIM, default=defaults.get(CONF_IDENTITY_CLAIM, DEFAULT_IDENTITY_CLAIM)
        ): str,
        vol.Optional(
            CONF_USER_MATCH, default=defaults.get(CONF_USER_MATCH, DEFAULT_USER_MATCH)
        ): str,
        vol.Optional(
            CONF_DELETE_OBJECTS_ON_REMOVE,
            default=defaults.get(CONF_DELETE_OBJECTS_ON_REMOVE, DEFAULT_DELETE_OBJECTS_ON_REMOVE),
        ): BooleanSelector(),
        vol.Optional(
            CONF_CLIENT_REDIRECT_URIS,
            default=list(defaults.get(CONF_CLIENT_REDIRECT_URIS) or []),
        ): _MULTI_TEXT,
    }


def _validate_options(user_input: dict[str, Any], errors: dict[str, str]) -> dict[str, Any]:
    """Normalise option values and record validation errors."""
    out = dict(user_input)
    out[CONF_EXTRA_BYPASS_PATHS] = _clean_list(out.get(CONF_EXTRA_BYPASS_PATHS))
    out[CONF_SERVICE_TOKEN_IDS] = _clean_list(out.get(CONF_SERVICE_TOKEN_IDS))
    out[CONF_CLIENT_REDIRECT_URIS] = _clean_list(out.get(CONF_CLIENT_REDIRECT_URIS))
    if any(not u.startswith("https://") for u in out[CONF_CLIENT_REDIRECT_URIS]):
        errors[CONF_CLIENT_REDIRECT_URIS] = "invalid_redirect_uri"
    for key in (CONF_SESSION_DURATION, CONF_IDENTITY_CLAIM, CONF_USER_MATCH):
        if key in out:
            out[key] = str(out[key]).strip()
            if not out[key]:
                errors[key] = "required"
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
    """Initial setup: sign in with Cloudflare (or paste an API token), then the hostname."""

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
        """Return the subentry flows: registered OAuth clients."""
        return {SUBENTRY_TYPE_CLIENT: ClientSubentryFlow}

    # ----------------------------------------------------------------- credentials

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Choose how to authenticate with Cloudflare."""
        return self.async_show_menu(step_id="user", menu_options=[STEP_OAUTH, STEP_API_TOKEN])

    async def async_step_oauth(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Sign in with Cloudflare: the consent page asks for the integration's scopes."""
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
        """Pick the Cloudflare account the sign-in reaches; skipped when there is one."""
        errors: dict[str, str] = {}
        if not self._accounts:
            try:
                self._accounts = await self._api("").list_accounts()
            except CloudflareAuthError:
                return self.async_abort(reason="invalid_auth")
            except CloudflareUnavailableError:
                return self.async_abort(reason="cannot_connect")
            except CloudflareApiError as err:
                _LOGGER.warning("Cloudflare API error listing accounts: %s", err)
                return self.async_abort(reason="api_error")
            if not self._accounts:
                return self.async_abort(reason="no_accounts")
        if user_input is None and len(self._accounts) == 1:
            user_input = {CONF_ACCOUNT_ID: self._accounts[0]["id"]}
        if user_input is not None:
            account_id = user_input[CONF_ACCOUNT_ID]
            team_domain = await _validate_credential(self._api(account_id), errors)
            if team_domain:
                self._credential[CONF_ACCOUNT_ID] = account_id
                self._credential[DATA_TEAM_DOMAIN] = team_domain
                return await self.async_step_settings()
            if len(self._accounts) == 1:
                return self.async_abort(reason=errors["base"])
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
        """Use an API token instead of signing in."""
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
            step_id=STEP_API_TOKEN,
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
        """Hostname and the advanced options; the gate starts disabled."""
        errors: dict[str, str] = {}
        if user_input is not None:
            hostname = normalise_hostname(user_input[CONF_HOSTNAME])
            if not hostname:
                errors[CONF_HOSTNAME] = "invalid_hostname"
            options = _validate_options(user_input, errors)
            options[CONF_HOSTNAME] = hostname
            if not errors:
                await self.async_set_unique_id(hostname)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=hostname,
                    data=self._credential,
                    options={CONF_GATE_ENABLED: DEFAULT_GATE_ENABLED, **options},
                )
        defaults: dict[str, Any] = dict(user_input or {})
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_HOSTNAME, default=defaults.get(CONF_HOSTNAME) or self._default_hostname()
                ): str,
                **_advanced_schema(defaults),
            }
        )
        return self.async_show_form(
            step_id="settings",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                "allowed_users": _users_placeholder(
                    allowed_emails(self.hass, {**DEFAULT_OPTIONS, **defaults})
                )
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
                if options[CONF_GATE_ENABLED] and not allowed_emails(
                    self.hass, {**DEFAULT_OPTIONS, **options}
                ):
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
                **_advanced_schema(current),
            }
        )
        return self.async_show_form(
            step_id="init",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                CONF_HOSTNAME: current.get(CONF_HOSTNAME, ""),
                "allowed_users": _users_placeholder(allowed_emails(self.hass, current)),
            },
        )


def _client_endpoints(team_domain: str, client_id: str) -> dict[str, str]:
    base = f"https://{team_domain}/cdn-cgi/access/sso/oidc/{client_id}"
    return {
        "authorization_url": f"{base}/authorization",
        "token_url": f"{base}/token",
        "userinfo_url": f"{base}/userinfo",
    }


class ClientSubentryFlow(ConfigSubentryFlow):
    """Register an OAuth client that cannot register itself.

    The client's console (Google Home, the Alexa developer console, any service that
    asks for a client id and secret) gets Access's endpoints and the credentials this
    flow shows; nothing about the client is known to the integration beyond the name
    and redirect URIs entered here.
    """

    _created: dict[str, Any]

    async def _async_register(
        self, user_input: dict[str, Any], errors: dict[str, str], app_id: str | None
    ) -> dict[str, Any] | None:
        entry = self._get_entry()
        name = user_input[CONF_CLIENT_NAME].strip()
        uris = _clean_list(user_input.get(CONF_REDIRECT_URIS))
        if not name:
            errors[CONF_CLIENT_NAME] = "required"
        if not uris:
            errors[CONF_REDIRECT_URIS] = "required"
        elif any(not u.startswith("https://") for u in uris):
            errors[CONF_REDIRECT_URIS] = "invalid_redirect_uri"
        if errors:
            return None
        options = effective_options(entry)
        desired = desired_client_app(options, allowed_emails(self.hass, options), name, uris)
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
                CONF_CLIENT_NAME: name,
                CONF_REDIRECT_URIS: uris,
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
            }
        )
        return self.async_show_form(step_id=step_id, data_schema=schema, errors=errors)

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

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> SubentryFlowResult:
        """Name and redirect URIs; then Access issues the credentials."""
        errors: dict[str, str] = {}
        if user_input is not None:
            created = await self._async_register(user_input, errors, None)
            if created:
                self._created = created
                return self._credentials(created)
        return self._form("user", user_input or {}, errors)

    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> SubentryFlowResult:
        """Store the registration once the credentials were shown."""
        if user_input is None:
            return self._credentials(self._created)
        if self.source == "reconfigure":
            return self.async_update_and_abort(
                self._get_entry(),
                self._get_reconfigure_subentry(),
                title=self._created[CONF_CLIENT_NAME],
                data_updates={k: v for k, v in self._created.items() if v is not None},
            )
        return self.async_create_entry(title=self._created[CONF_CLIENT_NAME], data=self._created)

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> SubentryFlowResult:
        """Change the name or redirect URIs, and show the credentials again."""
        errors: dict[str, str] = {}
        sub = self._get_reconfigure_subentry()
        if user_input is not None:
            updated = await self._async_register(user_input, errors, sub.data[DATA_CLIENT_APP_ID])
            if updated:
                self._created = {
                    **dict(sub.data),
                    **{k: v for k, v in updated.items() if v is not None},
                }
                return self._credentials(self._created)
        return self._form("reconfigure", user_input or sub.data, errors)
