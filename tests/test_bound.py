"""Access-bound tokens: the origin rule for requests the edge does not gate."""

from __future__ import annotations

from typing import Any

from aiohttp.test_utils import TestClient
from homeassistant.auth.models import User
from homeassistant.auth.providers import homeassistant as ha_provider
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.setup import async_setup_component
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.cloudflare_access_relay.const import (
    API_SESSION,
    CONF_REQUIRE_BOUND_TOKENS,
    DOMAIN,
    ISSUE_RESTART_REQUIRED,
)

from .conftest import ALICE, HOSTNAME, FakeCloudflare, FakeJwks, Relay, make_entry, token_for

HDR = "Cf-Access-Jwt-Assertion"
CLIENT_ID = "https://vendor.example.com/app"
REDIRECT = "https://vendor.example.com/app/callback"


def edge(**extra: str) -> dict[str, str]:
    """Headers of a request that came through Cloudflare for the gated hostname."""
    return {"Host": HOSTNAME, "CF-Ray": "8000abcd-LHR", **extra}


async def _login(client: TestClient, headers: dict[str, str]) -> str:
    """Run Home Assistant's login flow for `user`/`pass`; return the authorization code."""
    resp = await client.post(
        "/auth/login_flow",
        json={"client_id": CLIENT_ID, "handler": ["homeassistant", None], "redirect_uri": REDIRECT},
        headers=headers,
    )
    assert resp.status == 200, await resp.text()
    flow_id = (await resp.json())["flow_id"]
    resp = await client.post(
        f"/auth/login_flow/{flow_id}",
        json={"client_id": CLIENT_ID, "username": "user", "password": "pass"},
        headers=headers,
    )
    body = await resp.json()
    assert resp.status == 200 and body["type"] == "create_entry", body
    return body["result"]


async def _exchange(client: TestClient, code: str) -> str:
    """Exchange the code the way a vendor's server does: no cookie, no Access token."""
    resp = await client.post(
        "/auth/token",
        data={"grant_type": "authorization_code", "code": code, "client_id": CLIENT_ID},
        headers=edge(),
    )
    assert resp.status == 200, await resp.text()
    return (await resp.json())["access_token"]


async def test_unbound_bearer_rejected_only_through_the_edge(
    hass: HomeAssistant, relay: Relay, alice: User, hass_client_no_auth: Any
) -> None:
    assert await async_setup_component(hass, "api", {})
    client = await hass_client_no_auth()
    token = await token_for(hass, alice)
    auth = {"Authorization": f"Bearer {token}"}

    resp = await client.get("/api/", headers=auth)
    assert resp.status == 200, "local network: untouched"
    resp = await client.get("/api/", headers={**auth, **edge()})
    assert resp.status == 401, "through the edge without an Access token: rejected"
    assert "Cloudflare Access" in (await resp.json())["message"]
    resp = await client.get("/api/", headers={**auth, **edge(**{HDR: relay.mint(ALICE)})})
    assert resp.status == 200, "the Access token in the header satisfies the rule"
    client.session.cookie_jar.update_cookies({"CF_Authorization": relay.mint(ALICE)})
    resp = await client.get("/api/", headers={**auth, **edge()})
    assert resp.status == 200, "so does the cookie"

    resp = await client.get(API_SESSION, headers={**auth, "Host": HOSTNAME, "CF-Ray": "x"})
    assert resp.status == 200, "the relay's own API is exempt: the connect page has no cookie yet"


async def test_login_under_access_binds_the_refresh_token(
    hass: HomeAssistant,
    relay: Relay,
    local_auth: ha_provider.HassAuthProvider,
    hass_client_no_auth: Any,
) -> None:
    assert await async_setup_component(hass, "api", {})
    await local_auth.async_add_auth("user", "pass")
    client = await hass_client_no_auth()

    code = await _login(client, edge(**{HDR: relay.mint(ALICE)}))
    token = await _exchange(client, code)
    resp = await client.get("/api/", headers={"Authorization": f"Bearer {token}", **edge()})
    assert resp.status == 200, "issued under Access: accepted without one"

    code = await _login(client, edge())
    token = await _exchange(client, code)
    resp = await client.get("/api/", headers={"Authorization": f"Bearer {token}", **edge()})
    assert resp.status == 401, "issued without Access: rejected without one"

    data = hass.data[DOMAIN][relay.entry.entry_id]
    assert len(data.bound.ids) == 1
    assert await hass.config_entries.async_reload(relay.entry.entry_id)
    assert hass.data[DOMAIN][relay.entry.entry_id].bound.ids == data.bound.ids, "persisted"


async def test_option_off_disables_the_rule(
    hass: HomeAssistant,
    fake_cloudflare: FakeCloudflare,
    jwks_server: FakeJwks,
    alice: User,
    hass_client_no_auth: Any,
) -> None:
    entry = make_entry(**{CONF_REQUIRE_BOUND_TOKENS: False})
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    assert await async_setup_component(hass, "api", {})
    client = await hass_client_no_auth()
    token = await token_for(hass, alice)
    resp = await client.get("/api/", headers={"Authorization": f"Bearer {token}", **edge()})
    assert resp.status == 200
    uris = [
        d["uri"] for d in fake_cloudflare.by_name(f"ha-relay: bypass {HOSTNAME}")["destinations"]
    ]
    assert f"{HOSTNAME}/api/google_assistant" in uris, "vendor paths bypassed, HA auth alone"


async def test_server_already_started_keeps_vendor_paths_gated(
    hass: HomeAssistant,
    fake_cloudflare: FakeCloudflare,
    jwks_server: FakeJwks,
    hass_client_no_auth: Any,
    config_entry: MockConfigEntry,
) -> None:
    await async_setup_component(hass, "http", {})
    await hass_client_no_auth()  # starts the server: the app is frozen from here on
    assert hass.http.app.frozen
    config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(config_entry.entry_id)
    uris = [
        d["uri"] for d in fake_cloudflare.by_name(f"ha-relay: bypass {HOSTNAME}")["destinations"]
    ]
    assert f"{HOSTNAME}/api/google_assistant" not in uris
    assert ir.async_get(hass).async_get_issue(DOMAIN, ISSUE_RESTART_REQUIRED) is not None
