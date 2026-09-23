"""Rollout checks against the real Cloudflare edge in front of your own Home Assistant.

Where tests/live proves the edge behaviour on a throw-away host in CI, this checks the
hostname the integration manages for you, before and after the gate is enabled. Run it
from a shell with:

  HA_HOST=ha.example.com          the hostname of Home Assistant's External URL
  CF_JWT=<application token>      copy the CF_Authorization cookie from browser devtools
  HA_TOKEN=<long-lived token>     a Home Assistant long-lived access token
  MODE=gated | off                whether the integration's Enabled option is on (default gated)
  BYPASS="/api/webhook/abc /api/tts_proxy"   optional: the bypassed paths listed in the options

  uv run pytest tests/rollout

Without HA_HOST, CF_JWT and HA_TOKEN the module is skipped.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
import os

import aiohttp
import httpx
import pytest

from ..conftest import is_access_redirect

pytestmark = pytest.mark.skipif(
    not (os.environ.get("HA_HOST") and os.environ.get("CF_JWT") and os.environ.get("HA_TOKEN")),
    reason="rollout inputs not set (HA_HOST, CF_JWT, HA_TOKEN)",
)

HOST = os.environ.get("HA_HOST", "")
BEARER = {"Authorization": f"Bearer {os.environ.get('HA_TOKEN', '')}"}
COOKIE = {"CF_Authorization": os.environ.get("CF_JWT", "")}
GATED = os.environ.get("MODE", "gated") != "off"
BYPASS = os.environ.get("BYPASS", "").split()
TIMEOUT = 20

# everything a client could reach, the login surface and the token-bearing endpoints included
GATED_PATHS = (
    "/",
    "/api/",
    "/api/websocket",
    "/auth/providers",
    "/auth/token",
    "/frontend_latest/",
    "/static/",
    "/local/",
    "/api/webhook/definitely-not-a-real-webhook-id",
    "/api/google_assistant",
    "/api/alexa/smart_home",
    "/api/mcp",
)


@pytest.fixture
async def edge(internet: None) -> AsyncIterator[httpx.AsyncClient]:
    """Client for the hostname: no redirects followed, no cookies remembered."""
    async with httpx.AsyncClient(
        base_url=f"https://{HOST}", follow_redirects=False, timeout=TIMEOUT
    ) as http:
        yield http


@pytest.mark.skipif(GATED, reason="MODE=gated")
async def test_gate_off_home_assistant_answers_directly(edge: httpx.AsyncClient) -> None:
    for path in ("/", "/api/", "/auth/providers", "/api/websocket"):
        resp = await edge.get(path)
        assert not is_access_redirect(resp), f"{path} is still gated: {resp.status_code}"
    assert (await edge.get("/api/")).status_code == 401
    assert (await edge.get("/api/", headers=BEARER)).status_code == 200


@pytest.mark.skipif(not GATED, reason="MODE=off")
async def test_gate_on_everything_requires_access(edge: httpx.AsyncClient) -> None:
    for path in GATED_PATHS:
        resp = await edge.get(path)
        assert is_access_redirect(resp), f"{path} reaches Home Assistant: {resp.status_code}"


@pytest.mark.skipif(not GATED, reason="MODE=off")
async def test_a_home_assistant_bearer_alone_does_not_pass_the_edge(
    edge: httpx.AsyncClient,
) -> None:
    assert is_access_redirect(await edge.get("/api/", headers=BEARER))


@pytest.mark.skipif(not GATED, reason="MODE=off")
async def test_with_the_access_cookie_home_assistant_authentication_applies(
    edge: httpx.AsyncClient,
) -> None:
    resp = await edge.get("/api/", cookies=COOKIE, headers=BEARER)
    assert resp.status_code == 200, (resp.status_code, resp.headers.get("location"))
    resp = await edge.get("/api/", cookies=COOKIE)
    assert resp.status_code == 401, "Home Assistant's own login still applies behind the gate"


@pytest.mark.skipif(not GATED, reason="MODE=off")
async def test_access_serves_the_oauth_discovery_document(edge: httpx.AsyncClient) -> None:
    resp = await edge.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200, resp.status_code
    assert "authorization_endpoint" in resp.json(), "not Access's document"


@pytest.mark.skipif(not GATED, reason="MODE=off")
async def test_websocket_upgrade_with_the_cookie(internet: None) -> None:
    async with (
        aiohttp.ClientSession(cookies=COOKIE) as session,
        session.ws_connect(f"wss://{HOST}/api/websocket", timeout=TIMEOUT) as ws,
    ):
        assert (await ws.receive_json())["type"] == "auth_required"


@pytest.mark.skipif(not (GATED and BYPASS), reason="no bypassed paths listed")
async def test_listed_paths_are_bypassed(edge: httpx.AsyncClient) -> None:
    for path in BYPASS:
        resp = await edge.get(path)
        assert not is_access_redirect(resp), f"{path} is gated: {resp.status_code}"
