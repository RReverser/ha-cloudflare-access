"""Login events described for the logbook."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from homeassistant.core import HomeAssistant

from custom_components.cloudflare_access_relay.const import DOMAIN, EVENT_LOGIN
from custom_components.cloudflare_access_relay.logbook import async_describe_events

from .conftest import Access


async def test_a_login_is_described_on_the_person(hass: HomeAssistant, access: Access) -> None:
    registered: dict[tuple[str, str], Any] = {}
    async_describe_events(hass, lambda domain, name, fn: registered.__setitem__((domain, name), fn))
    describe = registered[(DOMAIN, EVENT_LOGIN)]
    alice = next(u for u in await hass.auth.async_get_users() if u.name == "Alice")

    entry = describe(
        SimpleNamespace(
            context_id="ctx",
            data={
                "email": "alice@example.com",
                "allowed": True,
                "user_id": alice.id,
                "app": "ha.example.com",
            },
        )
    )
    assert entry == {
        "name": "Alice",
        "message": "logged in at ha.example.com",
        "entity_id": "person.alice",
        "context_id": "ctx",
    }

    entry = describe(
        SimpleNamespace(
            context_id="ctx",
            data={
                "email": "eve@example.com",
                "allowed": False,
                "user_id": None,
                "app": "ha.example.com",
            },
        )
    )
    assert (
        entry["name"] == "eve@example.com" and entry["message"] == "was refused at ha.example.com"
    )
    assert entry["entity_id"] is None
