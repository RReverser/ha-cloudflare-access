"""Login history: the authentication logs become events, sensors and a repair issue."""

from __future__ import annotations

from datetime import timedelta

from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import (
    async_capture_events,
    async_fire_time_changed,
)

from custom_components.cloudflare_access_relay.const import (
    DATA_GATE_APP_ID,
    DOMAIN,
    EVENT_LOGIN,
    LOG_POLL_INTERVAL_SECONDS,
)

from .conftest import ALICE, Access, add_user


def _entry(app_uid: str, email: str, allowed: bool, when: str) -> dict:
    return {
        "action": "login",
        "allowed": allowed,
        "app_domain": "ha.example.com",
        "app_uid": app_uid,
        "connection": "onetimepin",
        "created_at": when,
        "ip_address": "203.0.113.7",
        "ray_id": "ray-" + when,
        "user_email": email,
    }


async def _poll(hass: HomeAssistant) -> None:
    """Let the coordinator's scheduled read run (it runs as a background task)."""
    async_fire_time_changed(
        hass, dt_util.utcnow() + timedelta(seconds=LOG_POLL_INTERVAL_SECONDS + 1)
    )
    await hass.async_block_till_done(wait_background_tasks=True)


async def test_logins_become_events_sensors_and_a_denied_login_issue(
    hass: HomeAssistant, access: Access
) -> None:
    cf = access.cloudflare
    gate = access.entry.data[DATA_GATE_APP_ID]
    now = dt_util.utcnow().replace(microsecond=0)
    stamp = lambda minutes: (now - timedelta(minutes=minutes)).isoformat()  # noqa: E731
    events = async_capture_events(hass, EVENT_LOGIN)

    cf.access_logs += [
        _entry(gate, "Alice@example.com", True, stamp(30)),
        _entry("someone-elses-app", "alice@example.com", True, stamp(20)),
        _entry(gate, "eve@example.com", False, stamp(10)),
    ]
    await _poll(hass)
    assert [(e.data["email"], e.data["allowed"]) for e in events] == [
        ("alice@example.com", True),
        ("eve@example.com", False),
    ], "only this entry's applications count"
    alice = next(u for u in await hass.auth.async_get_users() if u.name == "Alice")
    assert events[0].data["user_id"] == alice.id and events[1].data["user_id"] is None
    state = hass.states.get("sensor.ha_example_com_alice_last_login")
    assert state is not None and state.state == stamp(30)
    assert hass.states.get("sensor.ha_example_com_bob_last_login").state == "unknown"
    issue = ir.async_get(hass).async_get_issue(DOMAIN, "denied_login")
    assert issue is not None and issue.translation_placeholders["email"] == "eve@example.com"

    # nothing new: nothing repeated
    await _poll(hass)
    assert len(events) == 2

    # a newer login moves the sensor; a person who arrives later gets a sensor too
    carol = await add_user(hass, "carol@example.com", name="Carol")
    cf.access_logs.append(_entry(gate, ALICE, True, stamp(5)))
    cf.access_logs.append(_entry(gate, "carol@example.com", True, stamp(4)))
    await _poll(hass)
    assert hass.states.get("sensor.ha_example_com_alice_last_login").state == stamp(5)
    assert events[-1].data["user_id"] == carol.id

    # the cursor survives a reload: the old entries are not replayed
    assert await hass.config_entries.async_reload(access.entry.entry_id)
    await hass.async_block_till_done()
    assert len(events) == 4
    assert hass.states.get("sensor.ha_example_com_alice_last_login").state == stamp(5)


async def test_logs_that_cannot_be_read_raise_an_issue_and_nothing_else(
    hass: HomeAssistant, access: Access
) -> None:
    cf = access.cloudflare
    cf.fail_status, cf.fail_predicate = 403, lambda _m, path: path.endswith("/access_requests")
    await _poll(hass)
    assert ir.async_get(hass).async_get_issue(DOMAIN, "logs_unavailable") is not None
    assert access.entry.state.value == "loaded"
    cf.fail_status = cf.fail_predicate = None
    await _poll(hass)
    assert ir.async_get(hass).async_get_issue(DOMAIN, "logs_unavailable") is None
