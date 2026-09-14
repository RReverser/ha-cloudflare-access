"""Live integration test: the whole lifecycle through Home Assistant against real Cloudflare.

Everything the integration is responsible for is driven the way a user drives it:
the config flow creates the entry (which provisions the Access applications), the
options flow enables the gate and re-saves after drift, a reload must write
nothing, and removal with "delete objects" off keeps the applications. The relay
itself is exercised through its real HTTP views with a real Cloudflare token
verified against the real JWKS, and the released cookie is then used at the edge.

The raw Cloudflare API is used only to create and delete this run's service
token, to observe the applications, and to inject drift.

Environment (GitHub Actions repository secrets):
  CF_API_TOKEN    account token with "Access: Apps and Policies: Edit",
                  "Access: Organizations, Identity Providers, and Groups: Read"
                  and "Access: Service Tokens: Edit"
  CF_ACCOUNT_ID

Prerequisites that already exist and are not touched: the Worker on the test
hostname with its custom domain, and the zone WAF rule exempting that host from
bot protection.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Iterator
import contextlib
import json
import os
import socket
import time
from typing import Any

from homeassistant import config_entries
from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers.httpx_client import get_async_client
import httpx
import pytest
import pytest_socket

from custom_components.cloudflare_access_relay.cloudflare_api import (
    CloudflareAccessApi,
    CloudflareApiError,
)
from custom_components.cloudflare_access_relay.const import (
    API_FLOW,
    API_SESSION,
    API_STATUS,
    CONF_ACCESS_GROUP_ID,
    CONF_ACCOUNT_ID,
    CONF_ALLOWED_EMAILS,
    CONF_API_TOKEN,
    CONF_DELETE_OBJECTS_ON_REMOVE,
    CONF_GATE_ENABLED,
    CONF_HOSTNAME,
    CONF_IDENTITY_CLAIM,
    CONF_SERVICE_TOKEN_IDS,
    CONF_SESSION_DURATION,
    CONF_USER_MATCH,
    DATA_BYPASS_APP_ID,
    DATA_GATE_APP_ID,
    DATA_POLICY_AUD,
    DATA_TEAM_DOMAIN,
    DOMAIN,
    HEADER_JWT,
    URL_CALLBACK,
)

from ..conftest import add_user, token_for

pytestmark = pytest.mark.skipif(
    not (os.environ.get("CF_API_TOKEN") and os.environ.get("CF_ACCOUNT_ID")),
    reason="live Cloudflare credentials not set (CF_API_TOKEN, CF_ACCOUNT_ID)",
)

HOST = "test-host.example.com"
# the allow policy needs a subject; the test logs in with its service token instead
EMAIL = "nobody@example.com"
BASE = f"https://{HOST}"
SESSION = "1h"
TOKEN_PREFIX = "ha-relay-ci"
STALE_TOKEN_AGE = 6 * 3600
EDGE_TIMEOUT = 120


def _claims(token: str) -> dict[str, Any]:
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def _is_access_redirect(resp: httpx.Response) -> bool:
    return resp.status_code in (
        301,
        302,
        303,
        307,
    ) and ".cloudflareaccess.com/" in resp.headers.get("location", "")


def _set_cookie_token(resp: httpx.Response) -> str | None:
    for value in resp.headers.get_list("set-cookie"):
        if value.startswith("CF_Authorization="):
            return value.split(";")[0].split("=", 1)[1]
    return None


async def _until(check: Callable[[], Any], what: str, timeout: float = EDGE_TIMEOUT) -> Any:
    """Poll `check` (sync or async) every 3 s until it returns a truthy value."""
    deadline = time.time() + timeout
    while True:
        result = check()
        if hasattr(result, "__await__"):
            result = await result
        if result or time.time() > deadline:
            return result
        time.sleep(3)


@pytest.fixture
def internet() -> Iterator[None]:
    """Allow real network access for this test.

    The Home Assistant test plugin blocks sockets, restricts connections to
    127.0.0.1 and refuses DNS names on every test; `socket_enabled` alone only
    lifts the first of those.
    """
    saved = (socket.socket, socket.socket.connect, socket.getaddrinfo, socket.gethostbyname)
    pytest_socket._remove_restrictions()
    socket.getaddrinfo = pytest_socket._true_getaddrinfo
    socket.gethostbyname = pytest_socket._true_gethostbyname
    try:
        yield
    finally:
        socket.socket, socket.socket.connect, socket.getaddrinfo, socket.gethostbyname = saved


class Edge:
    """HTTP client for the test host; no redirects followed, no cookies remembered."""

    def __init__(self, http: httpx.AsyncClient) -> None:
        self.http = http

    async def get(self, path: str, **kw: Any) -> httpx.Response:
        self.http.cookies.clear()
        return await self.http.get(f"{BASE}{path}", **kw)

    async def post(self, path: str, **kw: Any) -> httpx.Response:
        self.http.cookies.clear()
        return await self.http.post(f"{BASE}{path}", **kw)

    async def wait_gate(self, path: str, gated: bool) -> None:
        async def check() -> bool:
            return _is_access_redirect(await self.get(path)) == gated

        assert await _until(check, path), (
            f"{path} did not become {'gated' if gated else 'open'} in {EDGE_TIMEOUT}s"
        )


async def _login_until_forwarded(edge: Edge, headers: dict[str, str]) -> tuple[str, int]:
    """Service-token login, retried until the origin echoes the Access header.

    Returns the token and the number of attempts; more than one attempt means the
    edge needed time to apply an application update.
    """
    attempts = 0
    last: httpx.Response | None = None

    async def check() -> str | None:
        nonlocal attempts, last
        attempts += 1
        last = await edge.get("/api/echo", headers=headers)
        body = last.json() if last.status_code == 200 else {}
        return body.get("headers", {}).get("cf-access-jwt-assertion")

    token = await _until(check, "login")
    assert token, f"login never produced Cf-Access-Jwt-Assertion at the origin (last: {last})"
    return token, attempts


async def _service_token(api: CloudflareAccessApi) -> dict[str, Any]:
    """Create this run's token; sweep tokens left behind by aborted runs."""
    now = time.time()
    for tok in await api.list_service_tokens():
        name, created = tok.get("name") or "", tok.get("created_at") or ""
        if name.startswith(TOKEN_PREFIX) and created:
            age = (
                now - time.mktime(time.strptime(created[:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
            )
            if age > STALE_TOKEN_AGE:
                # may still be referenced by the gate policy of an aborted run; this
                # run's provisioning replaces that reference, the next sweep gets it
                with contextlib.suppress(CloudflareApiError):
                    await api.delete_service_token(tok["id"])
    run = os.environ.get("GITHUB_RUN_ID", str(int(now)))
    created_tok: dict[str, Any] = await api.create_service_token(f"{TOKEN_PREFIX} {run}", "24h")
    return created_tok


async def _save_options(hass: HomeAssistant, entry: ConfigEntry, **changes: Any) -> None:
    """Re-save the options through the options flow (reloads and re-provisions)."""
    flow = await hass.config_entries.options.async_init(entry.entry_id)
    assert flow["type"] is FlowResultType.FORM
    current = dict(entry.options)
    user_input = {
        CONF_GATE_ENABLED: current[CONF_GATE_ENABLED],
        CONF_ALLOWED_EMAILS: current[CONF_ALLOWED_EMAILS],
        CONF_ACCESS_GROUP_ID: current.get(CONF_ACCESS_GROUP_ID, ""),
        CONF_SERVICE_TOKEN_IDS: current[CONF_SERVICE_TOKEN_IDS],
        CONF_SESSION_DURATION: current[CONF_SESSION_DURATION],
        CONF_IDENTITY_CLAIM: current[CONF_IDENTITY_CLAIM],
        CONF_USER_MATCH: current[CONF_USER_MATCH],
        CONF_DELETE_OBJECTS_ON_REMOVE: current[CONF_DELETE_OBJECTS_ON_REMOVE],
        **changes,
    }
    result = await hass.config_entries.options.async_configure(flow["flow_id"], user_input)
    assert result["type"] is FlowResultType.CREATE_ENTRY, result
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.LOADED, entry.reason


def _gate_summary(gate: dict[str, Any] | None) -> str:
    if not gate:
        return "<missing>"
    return f"updated_at={gate.get('updated_at')} binding={gate.get('enable_binding_cookie')}"


async def _app_updated_at(api: CloudflareAccessApi, entry: ConfigEntry) -> tuple[str, str]:
    gate = await api.get_app(entry.data[DATA_GATE_APP_ID])
    bypass = await api.get_app(entry.data[DATA_BYPASS_APP_ID])
    assert gate and bypass
    return gate["updated_at"], bypass["updated_at"]


async def test_live_lifecycle(
    hass: HomeAssistant,
    hass_client: Any,
    hass_client_no_auth: Any,
    internet: None,
    disable_mock_zeroconf_resolver: None,
) -> None:
    api = CloudflareAccessApi(
        os.environ["CF_API_TOKEN"], os.environ["CF_ACCOUNT_ID"], http_client=get_async_client(hass)
    )
    token = await _service_token(api)
    try:
        await _lifecycle(hass, hass_client, hass_client_no_auth, api, token)
    finally:
        await _release_and_delete_token(hass, api, token["id"])


async def _release_and_delete_token(
    hass: HomeAssistant, api: CloudflareAccessApi, token_id: str
) -> None:
    """Drop the token from any surviving entry's options, then delete it.

    Runs after a failed step too, so the token never stays referenced by the gate
    policy (Cloudflare refuses to delete a referenced token).
    """
    for entry in hass.config_entries.async_entries(DOMAIN):
        with contextlib.suppress(Exception):
            if entry.state is ConfigEntryState.LOADED:
                await _save_options(
                    hass,
                    entry,
                    **{CONF_SERVICE_TOKEN_IDS: [], CONF_DELETE_OBJECTS_ON_REMOVE: False},
                )
            await hass.config_entries.async_remove(entry.entry_id)
            await hass.async_block_till_done()
    await api.delete_service_token(token_id)


async def _lifecycle(
    hass: HomeAssistant,
    hass_client: Any,
    hass_client_no_auth: Any,
    api: CloudflareAccessApi,
    token: dict[str, Any],
) -> None:
    service_headers = {
        "CF-Access-Client-Id": token["client_id"],
        "CF-Access-Client-Secret": token["client_secret"],
    }
    async with httpx.AsyncClient(follow_redirects=False, timeout=30) as http:
        edge = Edge(http)

        print(
            "== config flow creates the entry and provisions (gate off: only the callback is gated)"
        )
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": config_entries.SOURCE_USER}
        )
        assert result["type"] is FlowResultType.FORM
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_API_TOKEN: os.environ["CF_API_TOKEN"],
                CONF_ACCOUNT_ID: os.environ["CF_ACCOUNT_ID"],
                CONF_HOSTNAME: HOST,
                CONF_ALLOWED_EMAILS: [EMAIL],
                CONF_ACCESS_GROUP_ID: "",
                CONF_SERVICE_TOKEN_IDS: [token["id"]],
                CONF_SESSION_DURATION: SESSION,
                # a service-token JWT identifies itself by common_name (its client id);
                # the HA user created below carries that as its display name
                CONF_IDENTITY_CLAIM: "common_name",
                CONF_USER_MATCH: "name",
            },
        )
        assert result["type"] is FlowResultType.CREATE_ENTRY, result
        entry: ConfigEntry = result["result"]
        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.LOADED, entry.reason
        assert entry.options[CONF_GATE_ENABLED] is False
        aud, team = entry.data[DATA_POLICY_AUD], entry.data[DATA_TEAM_DOMAIN]
        assert len(aud) == 64 and team.endswith(".cloudflareaccess.com")
        await edge.wait_gate("/api/echo", False)
        assert _is_access_redirect(await edge.get(f"{URL_CALLBACK}?flow=bogus")), (
            "staged: the callback path is gated"
        )

        print("== options flow enables the gate; audience survives")
        await _save_options(hass, entry, **{CONF_GATE_ENABLED: True})
        assert entry.data[DATA_POLICY_AUD] == aud
        await edge.wait_gate("/api/echo", True)

        print("== P8 precedence and P1 Set-Cookie passthrough at the edge")
        # the widened gate reaches the edge per path; wait for the root too
        await edge.wait_gate("/", True)
        resp = await edge.get("/api/cloudflare_access_relay/echo")
        assert resp.status_code == 200, (
            "P8: bypassed prefix under /api beats the hostname-wide gate"
        )
        assert (await edge.get("/auth/token")).status_code == 200
        resp = await edge.post("/auth/token/setcookie", json={"v": "probe-value"})
        assert resp.status_code == 200
        assert resp.headers.get_list("set-cookie") == [
            "CF_Authorization=probe-value; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600"
        ], "P1: origin Set-Cookie must pass through unmodified"

        print("== a real login at the edge yields the token as header and cookie (P3, P4)")
        resp = await edge.get("/api/echo", headers=service_headers)
        assert resp.status_code == 200, (resp.status_code, resp.headers.get("location"))
        real_jwt = resp.json()["headers"]["cf-access-jwt-assertion"]
        assert real_jwt == _set_cookie_token(resp), "P4"
        claims = _claims(real_jwt)
        assert claims["aud"] in ([aud], aud) and claims["iss"] == f"https://{team}"
        assert abs((claims["exp"] - claims["iat"]) - 3600) <= 5, "P3"

        print("== the relay itself, through its HTTP views, with the real token")
        user = await add_user(hass, "ci@example.com", name=claims["common_name"])
        client = await hass_client(await token_for(hass, user))
        anon = await hass_client_no_auth()
        resp = await client.post(API_FLOW)
        assert resp.status == 200
        flow = await resp.json()
        resp = await anon.get(flow["callback"], headers={HEADER_JWT: real_jwt})
        assert resp.status == 200, await resp.text()
        resp = await client.get(f"{API_STATUS}?flow={flow['flow']}")
        assert resp.status == 200 and (await resp.json())["exp"] == claims["exp"]
        released = [
            c for c in resp.headers.getall("Set-Cookie") if c.startswith("CF_Authorization=")
        ]
        assert len(released) == 1
        relayed = released[0].split(";")[0].split("=", 1)[1]
        assert relayed == real_jwt
        resp = await client.get(
            API_SESSION,
            headers={"Cookie": f"CF_Authorization={relayed}", "CF-Ray": "x", "Host": HOST},
        )
        assert (await resp.json())["exp"] == claims["exp"], (
            "session endpoint reads the relayed cookie"
        )
        for bad in (
            {HEADER_JWT: real_jwt[:-2] + ("AA" if real_jwt[-2:] != "AA" else "BB")},
            {},
        ):
            resp = await client.post(API_FLOW)
            resp = await anon.get((await resp.json())["callback"], headers=bad)
            assert resp.status == 403

        print("== P2: the relayed cookie alone passes the gate from a client Access never saw")
        cookie = {"CF_Authorization": relayed}
        resp = await edge.get("/api/echo", cookies=cookie, headers={"User-Agent": "okhttp/4.12.0"})
        assert resp.status_code == 200, "P2"
        assert resp.json()["headers"].get("cf-access-jwt-assertion") == relayed
        ws = {
            "Connection": "Upgrade",
            "Upgrade": "websocket",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        }
        resp = await edge.get("/api/echo", cookies=cookie, headers=ws)
        assert not _is_access_redirect(resp), "websocket-style upgrade carries the cookie"
        resp = await edge.get("/api/cloudflare_access_relay/echo", cookies=cookie)
        assert "CF_Authorization=" in resp.json()["headers"].get("cookie", ""), (
            "cookie reaches the origin on bypassed paths"
        )

        print(
            "== P5: drift outside the integration (binding cookie on) breaks reuse; a reload repairs it"
        )
        gate_id = entry.data[DATA_GATE_APP_ID]
        gate = await api.get_app(gate_id)
        assert gate
        print(f"   before drift: {_gate_summary(gate)}")
        keep = (
            "type",
            "name",
            "domain",
            "destinations",
            "session_duration",
            "http_only_cookie_attribute",
            "same_site_cookie_attribute",
            "app_launcher_visible",
        )
        drift = {k: gate[k] for k in keep if k in gate}
        drift["policies"] = [
            {k: p[k] for k in ("id", "name", "decision", "precedence", "include") if k in p}
            for p in gate["policies"]
        ]
        drifted = await api.update_app(gate_id, {**drift, "enable_binding_cookie": True})
        print(f"   drift update response: {_gate_summary(drifted)}")

        async def drift_visible() -> bool:
            app = await api.get_app(gate_id)
            return bool(app) and app.get("enable_binding_cookie") is True

        assert await _until(drift_visible, "drift visible", 60), "drift never became readable"
        print(f"   drift readable: {_gate_summary(await api.get_app(gate_id))}")
        bound, attempts = await _login_until_forwarded(edge, service_headers)
        print(f"   login after the binding-cookie update succeeded on attempt {attempts}")

        async def refused() -> bool:
            return _is_access_redirect(
                await edge.get("/api/echo", cookies={"CF_Authorization": bound})
            )

        assert await _until(refused, "binding refusal"), (
            "P5: with the binding cookie on a copied token is refused"
        )
        # the documented repair: reload the integration (saving unchanged options
        # does not reload the entry, so it would not re-provision)
        assert await hass.config_entries.async_reload(entry.entry_id)
        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.LOADED, entry.reason
        print(f"   after reload: {_gate_summary(await api.get_app(gate_id))}")

        async def reconciled() -> bool:
            app = await api.get_app(gate_id)
            return bool(app) and not app.get("enable_binding_cookie", False)

        assert await _until(reconciled, "reconciled", 60), (
            f"reload did not reconcile the drift: {_gate_summary(await api.get_app(gate_id))}"
        )

        async def reuse_works() -> bool:
            return (await edge.get("/api/echo", cookies=cookie)).status_code == 200

        assert await _until(reuse_works, "reuse"), "reuse works again after reconciliation"

        print("== reload writes nothing")
        before = await _app_updated_at(api, entry)
        assert await hass.config_entries.async_reload(entry.entry_id)
        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.LOADED
        assert await _app_updated_at(api, entry) == before

        print("== dropping the service token from the options removes it from the gate policy")
        await _save_options(
            hass, entry, **{CONF_SERVICE_TOKEN_IDS: [], CONF_DELETE_OBJECTS_ON_REMOVE: False}
        )

        async def token_gone() -> bool:
            app = await api.get_app(gate_id)
            return bool(app) and [p["decision"] for p in app["policies"]] == ["allow"]

        assert await _until(token_gone, "policy without service token", 60)

        print("== removal with 'delete objects' off keeps the applications for the next run")
        ids = (entry.data[DATA_GATE_APP_ID], entry.data[DATA_BYPASS_APP_ID])
        await hass.config_entries.async_remove(entry.entry_id)
        await hass.async_block_till_done()
        for app_id in ids:
            assert await api.get_app(app_id) is not None
