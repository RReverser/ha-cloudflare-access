"""HTTP view tests (plan section 8, items 4-11)."""

from __future__ import annotations

import time
from typing import Any

from aiohttp.test_utils import TestClient
from homeassistant.auth.models import User
from homeassistant.core import HomeAssistant
import pytest

from custom_components.cloudflare_access_relay.const import (
    API_FLOW,
    API_SESSION,
    API_STATUS,
    DOMAIN,
    NOTIFICATION_ID_ERROR,
    NOTIFICATION_ID_RENEW,
    URL_CALLBACK,
    URL_CONNECT,
    URL_RELAY_JS,
)
from custom_components.cloudflare_access_relay.flows import FlowStore
from custom_components.cloudflare_access_relay.views import user_matches

from .conftest import ALICE, BOB, Relay, add_user

HDR = "Cf-Access-Jwt-Assertion"


def _relay_data(hass: HomeAssistant, relay: Relay) -> Any:
    return hass.data[DOMAIN][relay.entry.entry_id]


async def _create_flow(client: TestClient) -> tuple[str, str]:
    resp = await client.post(API_FLOW)
    assert resp.status == 200
    body = await resp.json()
    return body["flow"], body["callback"]


async def test_flow_create_requires_auth_and_binds_user(
    hass: HomeAssistant, relay: Relay, alice: User, user_client: Any, hass_client_no_auth: Any
) -> None:
    anon = await hass_client_no_auth()
    resp = await anon.post(API_FLOW)
    assert resp.status == 401

    client = await user_client(alice)
    flow_id, callback = await _create_flow(client)
    assert len(flow_id) == 43
    assert callback == f"{URL_CALLBACK}?flow={flow_id}"
    flow = _relay_data(hass, relay).flows.get(flow_id)
    assert flow is not None and flow.user_id == alice.id and flow.jwt is None


async def test_full_relay_releases_cookie_once(
    hass: HomeAssistant, relay: Relay, alice: User, user_client: Any, hass_client_no_auth: Any
) -> None:
    client = await user_client(alice)
    flow_id, callback = await _create_flow(client)

    pending = await client.get(f"{API_STATUS}?flow={flow_id}")
    assert pending.status == 200 and (await pending.json()) == {"ok": False}
    assert "Set-Cookie" not in pending.headers

    exp = int(time.time()) + 6 * 3600
    token = relay.mint(ALICE, exp=exp)
    anon = await hass_client_no_auth()
    cb = await anon.get(callback, headers={HDR: token})
    assert cb.status == 200
    html = await cb.text()
    assert "homeassistant://navigate" in html
    assert token not in html
    assert cb.headers["Cache-Control"] == "no-store"
    flow = _relay_data(hass, relay).flows.get(flow_id)
    assert flow is not None and flow.jwt == token and flow.exp == exp

    before = int(time.time())
    done = await client.get(f"{API_STATUS}?flow={flow_id}")
    assert done.status == 200
    assert (await done.json()) == {"ok": True, "exp": exp}
    cookies = done.headers.getall("Set-Cookie")
    assert len(cookies) == 1
    cookie = cookies[0]
    assert cookie.startswith(f"CF_Authorization={token};")
    attrs = {p.strip().split("=")[0].lower(): p.strip() for p in cookie.split(";")[1:]}
    assert attrs["path"] == "Path=/"
    assert "secure" in attrs and "httponly" in attrs
    assert attrs["samesite"] == "SameSite=Lax"
    assert "domain" not in attrs
    max_age = int(attrs["max-age"].split("=")[1])
    assert abs(max_age - (exp - before)) <= 2

    again = await client.get(f"{API_STATUS}?flow={flow_id}")
    assert again.status == 404
    assert "Set-Cookie" not in again.headers
    assert flow_id not in _relay_data(hass, relay).flows

    # a second callback for the used flow is refused too
    cb2 = await anon.get(callback, headers={HDR: token})
    assert cb2.status == 404


async def test_callback_without_header_names_bypass_misconfiguration(
    hass: HomeAssistant, relay: Relay, alice: User, user_client: Any, hass_client_no_auth: Any
) -> None:
    client = await user_client(alice)
    flow_id, callback = await _create_flow(client)
    anon = await hass_client_no_auth()
    resp = await anon.get(callback)
    assert resp.status == 403
    assert resp.content_type == "text/html"
    html = await resp.text()
    assert "Cf-Access-Jwt-Assertion" in html
    assert "bypass" in html
    assert _relay_data(hass, relay).flows.get(flow_id).jwt is None


async def test_callback_identity_mismatch(
    hass: HomeAssistant, relay: Relay, alice: User, user_client: Any, hass_client_no_auth: Any
) -> None:
    client = await user_client(alice)
    flow_id, callback = await _create_flow(client)
    anon = await hass_client_no_auth()
    resp = await anon.get(callback, headers={HDR: relay.mint(BOB)})
    assert resp.status == 403
    assert "Identity mismatch" in await resp.text()
    assert _relay_data(hass, relay).flows.get(flow_id).jwt is None
    assert hass.states.get(f"persistent_notification.{NOTIFICATION_ID_ERROR}") is None
    notifications = hass.data["persistent_notification"]
    assert NOTIFICATION_ID_ERROR in notifications
    assert relay.mint(BOB) not in notifications[NOTIFICATION_ID_ERROR]["message"]


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"aud": "f" * 64}, "audience mismatch"),
        ({"exp": int(time.time()) - 10}, "token expired"),
        ({"kid": "rogue"}, "unknown signing key"),
        ({"alg": "none"}, "unsupported alg"),
    ],
)
async def test_callback_rejects_bad_tokens(
    hass: HomeAssistant,
    relay: Relay,
    alice: User,
    user_client: Any,
    hass_client_no_auth: Any,
    caplog: pytest.LogCaptureFixture,
    kwargs: dict[str, Any],
    reason: str,
) -> None:
    client = await user_client(alice)
    flow_id, callback = await _create_flow(client)
    anon = await hass_client_no_auth()
    token = relay.mint(ALICE, **kwargs)
    resp = await anon.get(callback, headers={HDR: token})
    assert resp.status == 403
    assert reason in await resp.text()
    assert _relay_data(hass, relay).flows.get(flow_id).jwt is None
    assert reason in caplog.text
    assert token not in caplog.text


async def test_status_from_other_user_is_forbidden(
    hass: HomeAssistant,
    relay: Relay,
    alice: User,
    bob: User,
    user_client: Any,
    hass_client_no_auth: Any,
) -> None:
    alice_client = await user_client(alice)
    bob_client = await user_client(bob)
    flow_id, callback = await _create_flow(alice_client)
    anon = await hass_client_no_auth()
    assert (await anon.get(callback, headers={HDR: relay.mint(ALICE)})).status == 200
    resp = await bob_client.get(f"{API_STATUS}?flow={flow_id}")
    assert resp.status == 403
    assert "Set-Cookie" not in resp.headers
    # still available to Alice
    assert (await alice_client.get(f"{API_STATUS}?flow={flow_id}")).status == 200


async def test_status_unknown_and_expired_flow(
    hass: HomeAssistant, relay: Relay, alice: User, user_client: Any
) -> None:
    client = await user_client(alice)
    resp = await client.get(f"{API_STATUS}?flow=doesnotexist")
    assert resp.status == 404 and "Set-Cookie" not in resp.headers
    assert (await client.get(API_STATUS)).status == 400
    flow_id, _ = await _create_flow(client)
    _relay_data(hass, relay).flows.get(flow_id).created -= 601
    resp = await client.get(f"{API_STATUS}?flow={flow_id}")
    assert resp.status == 404 and "Set-Cookie" not in resp.headers


async def test_session_view(
    hass: HomeAssistant, relay: Relay, alice: User, user_client: Any, hass_client_no_auth: Any
) -> None:
    anon = await hass_client_no_auth()
    assert (await anon.get(API_SESSION)).status == 401

    client = await user_client(alice)
    resp = await client.get(API_SESSION)
    assert resp.status == 200
    body = await resp.json()
    assert body["exp"] is None and body["renew"] is False
    assert body["cloudflare"] is False
    assert body["connect_url"] == URL_CONNECT

    exp = int(time.time()) + 10 * 86400
    token = relay.mint(ALICE, exp=exp)
    resp = await client.get(
        f"{API_SESSION}?app=1",
        headers={
            "Cookie": f"CF_Authorization={token}",
            "CF-Ray": "abc-LHR",
            "Host": "ha.example.com",
        },
    )
    body = await resp.json()
    assert body == {
        "exp": exp,
        "renew": False,
        "cloudflare": True,
        "host_match": True,
        "renew_days": 3,
        "check_interval_min": 60,
        "connect_url": URL_CONNECT,
    }
    assert token not in await resp.text()
    assert NOTIFICATION_ID_RENEW not in hass.data.get("persistent_notification", {})

    # near expiry, in app, via Cloudflare: renew flag and a notification
    soon = int(time.time()) + 2 * 86400
    resp = await client.get(
        f"{API_SESSION}?app=1",
        headers={
            "Cookie": f"CF_Authorization={relay.mint(ALICE, exp=soon)}",
            "CF-Ray": "abc",
            "Host": "ha.example.com",
        },
    )
    body = await resp.json()
    assert body["exp"] == soon and body["renew"] is True
    assert NOTIFICATION_ID_RENEW in hass.data["persistent_notification"]

    # a cookie for another application's audience counts as no session
    resp = await client.get(
        API_SESSION, headers={"Cookie": f"CF_Authorization={relay.mint(ALICE, aud='0' * 64)}"}
    )
    assert (await resp.json())["exp"] is None

    # healthy again: notification dismissed
    resp = await client.get(
        f"{API_SESSION}?app=1",
        headers={"Cookie": f"CF_Authorization={token}", "CF-Ray": "abc", "Host": "ha.example.com"},
    )
    assert NOTIFICATION_ID_RENEW not in hass.data["persistent_notification"]


async def test_connect_page_and_static_module(relay: Relay, hass_client_no_auth: Any) -> None:
    anon = await hass_client_no_auth()
    page = await anon.get(URL_CONNECT)
    assert page.status == 200
    text = await page.text()
    assert "externalAuthSetToken" in text and "/api/cloudflare_access_relay" in text
    js = await anon.get(URL_RELAY_JS)
    assert js.status == 200
    assert "cloudflare_access_relay/session" in await js.text()


def test_flow_sweep_removes_old_entries() -> None:
    store = FlowStore()
    fresh = store.create("u1")
    old = store.create("u2")
    now = time.time()
    store.get(old).created = now - 601
    assert store.sweep(now) == 1
    assert old not in store and fresh in store
    assert store.get(fresh, now) is not None
    store.discard(fresh)
    assert len(store) == 0


async def test_user_matches_modes(hass: HomeAssistant) -> None:
    user = await add_user(hass, "Carol@Example.com", name="Carol Smith")
    assert user_matches(user, "username", "carol@example.com")
    assert not user_matches(user, "username", "dave@example.com")
    assert user_matches(user, "name", "carol smith")
    assert not user_matches(user, "email", "carol@example.com")
    assert not user_matches(user, "username", "")


async def test_views_answer_503_when_unloaded(
    hass: HomeAssistant, relay: Relay, alice: User, user_client: Any, hass_client_no_auth: Any
) -> None:
    client = await user_client(alice)
    assert await hass.config_entries.async_unload(relay.entry.entry_id)
    await hass.async_block_till_done()
    assert (await client.post(API_FLOW)).status == 503
    anon = await hass_client_no_auth()
    assert (await anon.get(f"{URL_CALLBACK}?flow=x", headers={HDR: "t"})).status == 503
