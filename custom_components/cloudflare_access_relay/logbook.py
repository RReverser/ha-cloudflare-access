"""Login attempts in the logbook, attached to the person when the address is theirs."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from homeassistant.components.logbook.const import (
    LOGBOOK_ENTRY_CONTEXT_ID,
    LOGBOOK_ENTRY_ENTITY_ID,
    LOGBOOK_ENTRY_MESSAGE,
    LOGBOOK_ENTRY_NAME,
)
from homeassistant.components.logbook.models import LazyEventPartialState
from homeassistant.components.person import ATTR_USER_ID
from homeassistant.core import HomeAssistant, callback

from .const import DOMAIN, EVENT_LOGIN


@callback
def async_describe_events(
    hass: HomeAssistant,
    async_describe_event: Callable[
        [str, str, Callable[[LazyEventPartialState], dict[str, Any]]], None
    ],
) -> None:
    """Register the description of the login event."""

    @callback
    def _describe(event: LazyEventPartialState) -> dict[str, Any]:
        data = event.data
        person = None
        if user_id := data.get("user_id"):
            person = next(
                (
                    state
                    for state in hass.states.async_all("person")
                    if state.attributes.get(ATTR_USER_ID) == user_id
                ),
                None,
            )
        where = data.get("app") or "Cloudflare Access"
        return {
            LOGBOOK_ENTRY_NAME: person.name if person else data.get("email") or "Someone",
            LOGBOOK_ENTRY_MESSAGE: (
                f"logged in at {where}" if data.get("allowed") else f"was refused at {where}"
            ),
            LOGBOOK_ENTRY_ENTITY_ID: person.entity_id if person else None,
            LOGBOOK_ENTRY_CONTEXT_ID: event.context_id,
        }

    async_describe_event(DOMAIN, str(EVENT_LOGIN), _describe)
