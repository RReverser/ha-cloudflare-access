"""Repair flows: every issue whose remedy is an action offers it.

An issue's data names its key and the config entry, plus what the flow needs. The
fix flows: apply a failed update again (a reload), set Home Assistant's External URL,
give a refused address to a person, and settle HA-MCP's login mode against the gate.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from homeassistant import data_entry_flow
from homeassistant.components.repairs import ConfirmRepairFlow, RepairsFlow
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.selector import (
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)
import voluptuous as vol

from .const import (
    CONF_EXTRA_BYPASS_PATHS,
    CONF_LOGIN_EMAILS,
    HA_MCP_AUTH_NONE,
    HA_MCP_OPT_AUTH,
    ISSUE_DENIED_LOGIN,
    ISSUE_MCP_AUTH_CONFLICT,
    ISSUE_NO_EXTERNAL_URL,
    ISSUE_UPDATE_FAILED,
)
from .options import normalise_hostname
from .users import login_emails, person_users


async def async_create_fix_flow(
    hass: HomeAssistant, issue_id: str, data: dict[str, Any] | None
) -> RepairsFlow:
    """Return the fix flow of the issue."""
    data = data or {}
    key, entry_id = data.get("key"), str(data.get("entry_id") or "")
    if key == ISSUE_UPDATE_FAILED:
        return ReloadFlow(entry_id)
    if key == ISSUE_NO_EXTERNAL_URL:
        return ExternalUrlFlow(entry_id)
    if key == ISSUE_DENIED_LOGIN:
        return DeniedLoginFlow(entry_id, str(data.get("email") or ""))
    if key == ISSUE_MCP_AUTH_CONFLICT:
        return McpConflictFlow(
            entry_id,
            [str(i) for i in json.loads(str(data.get("mcp_entry_ids") or "[]"))],
            [str(p) for p in json.loads(str(data.get("webhook_paths") or "[]"))],
        )
    # A key with no flow of its own: confirming still clears the issue.
    return ConfirmRepairFlow()


class _EntryFlow(RepairsFlow):
    """A fix flow acting on one config entry.

    The subclasses' `async_step_init` skip straight to their real step: the first
    step of a repair flow receives the flow's init data, the issue id, as its
    `user_input` (homeassistant/data_entry_flow.py, `FlowManager.async_init`), so it
    cannot tell a submitted form from the start of the flow.
    """

    def __init__(self, entry_id: str) -> None:
        """Remember the entry."""
        self._entry_id = entry_id

    def _placeholders(self) -> dict[str, str] | None:
        # The forms repeat the issue's own text, so one set of placeholders serves both.
        issue = ir.async_get(self.hass).async_get_issue(self.handler, self.issue_id)
        return issue.translation_placeholders if issue else None

    def _reload(self) -> None:
        if self.hass.config_entries.async_get_entry(self._entry_id):
            self.hass.config_entries.async_schedule_reload(self._entry_id)


class ReloadFlow(_EntryFlow):
    """Apply the failed change again by reloading the entry."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> data_entry_flow.FlowResult:
        """Skip to the real step; `_EntryFlow` says why."""
        return await self.async_step_confirm()

    async def async_step_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> data_entry_flow.FlowResult:
        """Confirm, then reload."""
        if user_input is not None:
            self._reload()
            return self.async_create_entry(data={})
        return self.async_show_form(
            step_id="confirm",
            data_schema=vol.Schema({}),
            description_placeholders=self._placeholders(),
        )


class ExternalUrlFlow(_EntryFlow):
    """Set Home Assistant's External URL, the hostname the gate guards."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> data_entry_flow.FlowResult:
        """Skip to the real step; `_EntryFlow` says why."""
        return await self.async_step_url()

    async def async_step_url(
        self, user_input: dict[str, Any] | None = None
    ) -> data_entry_flow.FlowResult:
        """Take the URL, store it, and let the entry follow it."""
        errors: dict[str, str] = {}
        if user_input is not None:
            url = str(user_input["external_url"]).strip()
            parsed = urlparse(url)
            if parsed.scheme != "https" or not normalise_hostname(parsed.hostname or ""):
                errors["external_url"] = "invalid_url"
            else:
                await self.hass.config.async_update(external_url=url)
                self._reload()
                return self.async_create_entry(data={})
        return self.async_show_form(
            step_id="url",
            data_schema=vol.Schema(
                {
                    vol.Required("external_url"): TextSelector(
                        TextSelectorConfig(type=TextSelectorType.URL)
                    )
                }
            ),
            errors=errors,
            description_placeholders=self._placeholders(),
        )


class DeniedLoginFlow(_EntryFlow):
    """Give the refused address to a person, as their login e-mail."""

    def __init__(self, entry_id: str, email: str) -> None:
        """Remember the entry and the address."""
        super().__init__(entry_id)
        self._email = email

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> data_entry_flow.FlowResult:
        """Skip to the real step; `_EntryFlow` says why."""
        return await self.async_step_person()

    async def async_step_person(
        self, user_input: dict[str, Any] | None = None
    ) -> data_entry_flow.FlowResult:
        """Pick the person; the address becomes their login e-mail."""
        entry = self.hass.config_entries.async_get_entry(self._entry_id)
        if entry is None or not self._email:
            return self.async_abort(reason="entry_gone")
        people = await person_users(self.hass)
        if not people:
            return self.async_abort(reason="no_people")
        if user_input is not None:
            emails = {**login_emails(entry), str(user_input["user_id"]): self._email}
            self.hass.config_entries.async_update_entry(
                entry, options={**entry.options, CONF_LOGIN_EMAILS: emails}
            )
            self._reload()
            return self.async_create_entry(data={})
        return self.async_show_form(
            step_id="person",
            data_schema=vol.Schema(
                {
                    vol.Required("user_id"): SelectSelector(
                        SelectSelectorConfig(
                            options=[
                                SelectOptionDict(value=user.id, label=user.name or user.id)
                                for user in people
                            ],
                            mode=SelectSelectorMode.DROPDOWN,
                        )
                    )
                }
            ),
            description_placeholders=self._placeholders(),
        )


class McpConflictFlow(_EntryFlow):
    """Settle HA-MCP's login mode against the gate, one way or the other."""

    def __init__(self, entry_id: str, mcp_entry_ids: list[str], webhook_paths: list[str]) -> None:
        """Remember the entry, HA-MCP's entries and their webhook paths."""
        super().__init__(entry_id)
        self._mcp_entry_ids = mcp_entry_ids
        self._webhook_paths = webhook_paths

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> data_entry_flow.FlowResult:
        """Offer the two ways out."""
        return self.async_show_menu(
            step_id="init",
            menu_options=["secret_url", "bypass"],
            description_placeholders=self._placeholders(),
        )

    async def async_step_secret_url(
        self, user_input: dict[str, Any] | None = None
    ) -> data_entry_flow.FlowResult:
        """Switch HA-MCP to its secret-URL mode; HA-MCP reloads itself on the change."""
        for entry_id in self._mcp_entry_ids:
            if mcp := self.hass.config_entries.async_get_entry(entry_id):
                self.hass.config_entries.async_update_entry(
                    mcp, options={**mcp.options, HA_MCP_OPT_AUTH: HA_MCP_AUTH_NONE}
                )
        return self.async_create_entry(data={})

    async def async_step_bypass(
        self, user_input: dict[str, Any] | None = None
    ) -> data_entry_flow.FlowResult:
        """List the webhooks as open paths; HA-MCP's own login is then the only gate."""
        entry = self.hass.config_entries.async_get_entry(self._entry_id)
        if entry is None:
            return self.async_abort(reason="entry_gone")
        current = [str(p) for p in entry.options.get(CONF_EXTRA_BYPASS_PATHS) or []]
        paths = current + [p for p in self._webhook_paths if p not in current]
        self.hass.config_entries.async_update_entry(
            entry, options={**entry.options, CONF_EXTRA_BYPASS_PATHS: paths}
        )
        self._reload()
        return self.async_create_entry(data={})
