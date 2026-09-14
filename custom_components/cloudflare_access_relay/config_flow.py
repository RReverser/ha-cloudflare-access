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
    OptionsFlowWithReload,
)
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    BooleanSelector,
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
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
    CONF_CHECK_INTERVAL_MIN,
    CONF_COOKIE_NAME,
    CONF_DELETE_OBJECTS_ON_REMOVE,
    CONF_EXTRA_BYPASS_PATHS,
    CONF_GATE_ENABLED,
    CONF_HOSTNAME,
    CONF_IDENTITY_CLAIM,
    CONF_RENEW_DAYS,
    CONF_SESSION_DURATION,
    CONF_USER_MATCH,
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
)

_LOGGER = logging.getLogger(__name__)

_MULTI_TEXT = TextSelector(TextSelectorConfig(multiple=True))
_PASSWORD = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))
_DAYS = NumberSelector(
    NumberSelectorConfig(
        min=0, max=30, step=1, mode=NumberSelectorMode.BOX, unit_of_measurement="d"
    )
)
_MINUTES = NumberSelector(
    NumberSelectorConfig(
        min=1, max=1440, step=1, mode=NumberSelectorMode.BOX, unit_of_measurement="min"
    )
)


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
            CONF_SESSION_DURATION,
            default=defaults.get(CONF_SESSION_DURATION, DEFAULT_SESSION_DURATION),
        ): str,
        vol.Optional(
            CONF_COOKIE_NAME, default=defaults.get(CONF_COOKIE_NAME, DEFAULT_COOKIE_NAME)
        ): str,
        vol.Optional(
            CONF_IDENTITY_CLAIM, default=defaults.get(CONF_IDENTITY_CLAIM, DEFAULT_IDENTITY_CLAIM)
        ): str,
        vol.Optional(
            CONF_USER_MATCH, default=defaults.get(CONF_USER_MATCH, DEFAULT_USER_MATCH)
        ): str,
        vol.Optional(
            CONF_RENEW_DAYS, default=defaults.get(CONF_RENEW_DAYS, DEFAULT_RENEW_DAYS)
        ): _DAYS,
        vol.Optional(
            CONF_CHECK_INTERVAL_MIN,
            default=defaults.get(CONF_CHECK_INTERVAL_MIN, DEFAULT_CHECK_INTERVAL_MIN),
        ): _MINUTES,
        vol.Optional(
            CONF_DELETE_OBJECTS_ON_REMOVE,
            default=defaults.get(CONF_DELETE_OBJECTS_ON_REMOVE, DEFAULT_DELETE_OBJECTS_ON_REMOVE),
        ): BooleanSelector(),
    }


def _validate_options(user_input: dict[str, Any], errors: dict[str, str]) -> dict[str, Any]:
    """Normalise option values and record validation errors."""
    out = dict(user_input)
    out[CONF_ALLOWED_EMAILS] = _clean_list(out.get(CONF_ALLOWED_EMAILS))
    out[CONF_ACCESS_GROUP_ID] = (out.get(CONF_ACCESS_GROUP_ID) or "").strip()
    out[CONF_EXTRA_BYPASS_PATHS] = _clean_list(out.get(CONF_EXTRA_BYPASS_PATHS))
    for key in (CONF_RENEW_DAYS, CONF_CHECK_INTERVAL_MIN):
        if key in out:
            out[key] = int(out[key])
    for key in (CONF_SESSION_DURATION, CONF_COOKIE_NAME, CONF_IDENTITY_CLAIM, CONF_USER_MATCH):
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
    try:
        return await api.get_team_domain()
    except CloudflareAuthError:
        errors["base"] = "invalid_auth"
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
                    async_get_clientsession(self.hass),
                    user_input[CONF_API_TOKEN].strip(),
                    user_input[CONF_ACCOUNT_ID].strip(),
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
                async_get_clientsession(self.hass),
                user_input[CONF_API_TOKEN].strip(),
                entry.data[CONF_ACCOUNT_ID],
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
