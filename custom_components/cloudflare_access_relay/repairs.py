"""Repair flows: give a person who cannot log in an e-mail address."""

from __future__ import annotations

from typing import Any

from homeassistant import data_entry_flow
from homeassistant.components.repairs import RepairsFlow
from homeassistant.core import HomeAssistant
from homeassistant.helpers.selector import TextSelector, TextSelectorConfig, TextSelectorType
import voluptuous as vol

from .const import CONF_EMAIL, CONF_USER_ID, FORM_PLACEHOLDERS, SUBENTRY_TYPE_LOGIN_EMAIL


class LoginEmailFixFlow(RepairsFlow):
    """Ask for the address and store it on the person's row."""

    def __init__(self, entry_id: str, user_id: str) -> None:
        """Remember which person the issue is about."""
        self._entry_id = entry_id
        self._user_id = user_id

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> data_entry_flow.FlowResult:
        """Show the form, then fill in the row."""
        errors: dict[str, str] = {}
        entry = self.hass.config_entries.async_get_entry(self._entry_id)
        user = await self.hass.auth.async_get_user(self._user_id)
        if entry is None or user is None:
            return self.async_abort(reason="gone")
        if user_input is not None:
            email = str(user_input.get(CONF_EMAIL) or "").strip()
            if "@" not in email or " " in email:
                errors[CONF_EMAIL] = "invalid_email"
            else:
                row = next(
                    (
                        sub
                        for sub in entry.subentries.values()
                        if sub.subentry_type == SUBENTRY_TYPE_LOGIN_EMAIL
                        and sub.data.get(CONF_USER_ID) == self._user_id
                    ),
                    None,
                )
                if row is not None:
                    self.hass.config_entries.async_update_subentry(
                        entry,
                        row,
                        title=f"{user.name or user.id}: {email}",
                        data={CONF_USER_ID: self._user_id, CONF_EMAIL: email},
                    )
                return self.async_create_entry(data={})
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_EMAIL, default=""): TextSelector(
                        TextSelectorConfig(type=TextSelectorType.EMAIL)
                    )
                }
            ),
            errors=errors,
            description_placeholders={"user": user.name or user.id, **FORM_PLACEHOLDERS},
        )


async def async_create_fix_flow(
    hass: HomeAssistant, issue_id: str, data: dict[str, str | int | float | None] | None
) -> RepairsFlow:
    """Create the fix flow for a person without an address."""
    data = data or {}
    return LoginEmailFixFlow(str(data.get("entry_id") or ""), str(data.get("user_id") or ""))
