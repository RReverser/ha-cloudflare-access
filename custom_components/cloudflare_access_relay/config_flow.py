"""Config and options flows."""

from __future__ import annotations

from collections.abc import Mapping
import logging
from typing import Any
from urllib.parse import urlparse

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    ConfigSubentryFlow,
    OptionsFlowWithReload,
    SubentryFlowResult,
)
from homeassistant.core import callback
from homeassistant.helpers.httpx_client import get_async_client
from homeassistant.helpers.selector import (
    BooleanSelector,
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
    CONF_ACCESS_GROUP_ID,
    CONF_ACCOUNT_ID,
    CONF_ALLOWED_EMAILS,
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
    DEFAULT_DELETE_OBJECTS_ON_REMOVE,
    DEFAULT_GATE_ENABLED,
    DEFAULT_IDENTITY_CLAIM,
    DEFAULT_SESSION_DURATION,
    DEFAULT_USER_MATCH,
    DOMAIN,
    SUBENTRY_TYPE_CLIENT,
)
from .options import api_for, effective_options
from .provision import desired_client_app

_LOGGER = logging.getLogger(__name__)

_MULTI_TEXT = TextSelector(TextSelectorConfig(multiple=True))
_PASSWORD = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))


def normalise_hostname(raw: str) -> str:
    """Accept 'ha.example.com', 'https://ha.example.com/' or with a path."""
    raw = raw.strip()
    if "://" in raw:
        raw = urlparse(raw).netloc
    return raw.split("/")[0].split(":")[0].strip().lower()


def _clean_list(values: list[str] | None) -> list[str]:
    return [v.strip() for v in values or [] if v and v.strip()]


def _policy_schema(defaults: Mapping[str, Any]) -> dict[Any, Any]:
    return {
        vol.Optional(
            CONF_ALLOWED_EMAILS, default=list(defaults.get(CONF_ALLOWED_EMAILS) or [])
        ): _MULTI_TEXT,
        vol.Optional(CONF_ACCESS_GROUP_ID, default=defaults.get(CONF_ACCESS_GROUP_ID) or ""): str,
    }


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
    out[CONF_ALLOWED_EMAILS] = _clean_list(out.get(CONF_ALLOWED_EMAILS))
    out[CONF_ACCESS_GROUP_ID] = (out.get(CONF_ACCESS_GROUP_ID) or "").strip()
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
    if not out[CONF_ALLOWED_EMAILS] and not out[CONF_ACCESS_GROUP_ID]:
        errors["base"] = "no_policy_subject"
    if any("@" not in e for e in out[CONF_ALLOWED_EMAILS]):
        errors[CONF_ALLOWED_EMAILS] = "invalid_email"
    return out


async def _validate_token(api: CloudflareAccessApi, errors: dict[str, str]) -> str | None:
    """Check the token's two permissions; return the team domain on success."""
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
        _LOGGER.warning("Token cannot read the Zero Trust organization: %s", err)
        errors["base"] = "missing_org_read"
    except CloudflareUnavailableError:
        errors["base"] = "cannot_connect"
    except CloudflareApiError as err:
        _LOGGER.warning("Cloudflare API error during validation: %s", err)
        errors["base"] = "api_error"
    return None


class CloudflareAccessRelayConfigFlow(ConfigFlow, domain=DOMAIN):
    """Initial setup: credentials, hostname and who may log in."""

    VERSION = 1

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

    def _default_hostname(self) -> str:
        if self.hass.config.external_url:
            return normalise_hostname(self.hass.config.external_url)
        return ""

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Handle the single setup form."""
        errors: dict[str, str] = {}
        if user_input is not None:
            hostname = normalise_hostname(user_input[CONF_HOSTNAME])
            if not hostname:
                errors[CONF_HOSTNAME] = "invalid_hostname"
            options = _validate_options(
                {k: v for k, v in user_input.items() if k not in (CONF_API_TOKEN, CONF_ACCOUNT_ID)},
                errors,
            )
            options[CONF_HOSTNAME] = hostname
            team_domain = None
            if not errors:
                api = CloudflareAccessApi(
                    user_input[CONF_API_TOKEN].strip(),
                    user_input[CONF_ACCOUNT_ID].strip(),
                    http_client=get_async_client(self.hass),
                )
                team_domain = await _validate_token(api, errors)
            if not errors and team_domain:
                await self.async_set_unique_id(hostname)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=hostname,
                    data={
                        CONF_API_TOKEN: user_input[CONF_API_TOKEN].strip(),
                        CONF_ACCOUNT_ID: user_input[CONF_ACCOUNT_ID].strip(),
                        DATA_TEAM_DOMAIN: team_domain,
                    },
                    options={CONF_GATE_ENABLED: DEFAULT_GATE_ENABLED, **options},
                )
        defaults: dict[str, Any] = dict(user_input or {})
        schema = vol.Schema(
            {
                vol.Required(CONF_API_TOKEN, default=defaults.get(CONF_API_TOKEN, "")): _PASSWORD,
                vol.Required(CONF_ACCOUNT_ID, default=defaults.get(CONF_ACCOUNT_ID, "")): str,
                vol.Required(
                    CONF_HOSTNAME, default=defaults.get(CONF_HOSTNAME) or self._default_hostname()
                ): str,
                **_policy_schema(defaults),
                **_advanced_schema(defaults),
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        """Token rejected: ask for a new one."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Validate and store a replacement token."""
        errors: dict[str, str] = {}
        entry = self._get_reauth_entry()
        if user_input is not None:
            api = CloudflareAccessApi(
                user_input[CONF_API_TOKEN].strip(),
                entry.data[CONF_ACCOUNT_ID],
                http_client=get_async_client(self.hass),
            )
            if await _validate_token(api, errors):
                return self.async_update_reload_and_abort(
                    entry, data_updates={CONF_API_TOKEN: user_input[CONF_API_TOKEN].strip()}
                )
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_API_TOKEN): _PASSWORD}),
            errors=errors,
        )


class OptionsFlowHandler(OptionsFlowWithReload):
    """Everything but the credentials; saving reloads and re-provisions."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Show and process the options form."""
        errors: dict[str, str] = {}
        current = dict(self.config_entry.options)
        if user_input is not None:
            options = _validate_options(user_input, errors)
            if not errors:
                options[CONF_HOSTNAME] = current[CONF_HOSTNAME]
                return self.async_create_entry(data=options)
            current = {**current, **user_input}
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_GATE_ENABLED,
                    default=bool(current.get(CONF_GATE_ENABLED, DEFAULT_GATE_ENABLED)),
                ): BooleanSelector(),
                **_policy_schema(current),
                **_advanced_schema(current),
            }
        )
        return self.async_show_form(
            step_id="init",
            data_schema=schema,
            errors=errors,
            description_placeholders={CONF_HOSTNAME: current.get(CONF_HOSTNAME, "")},
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
        api = api_for(self.hass, entry)
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
        desired = desired_client_app(effective_options(entry), name, uris)
        try:
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
