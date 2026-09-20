"""Live integration test: the whole lifecycle through Home Assistant against real Cloudflare.

Everything the integration is responsible for is driven the way a user drives it:
the config flow creates the entry, the options flow enables the gate (which
provisions the Access application with managed OAuth), registers a client, lists a
bypassed path, re-saves after drift, a reload must write nothing, and removal with
"delete objects" off keeps the application. The origin rule is exercised with a
real Access assertion verified against the real JWKS.

The raw Cloudflare API is used only to create and delete this run's service
token, to observe the applications, and to inject drift.

Environment (GitHub Actions repository secrets and variables):
  CF_API_TOKEN    account token with "Access: Apps and Policies: Edit",
                  "Access: Organizations, Identity Providers, and Groups: Read"
                  and "Access: Service Tokens: Edit"
  CF_ACCOUNT_ID
  CF_TEST_HOST    a hostname in a zone of that account, served by tests/live/worker

Prerequisites that already exist and are not touched: the Worker on the test
hostname, and whatever exempts that host from the zone's bot protection.
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
from homeassistant.setup import async_setup_component
import httpx
import pytest
import pytest_socket

from custom_components.cloudflare_access_relay.cloudflare_api import (
    CloudflareAccessApi,
    CloudflareApiError,
)
from custom_components.cloudflare_access_relay.const import (
    CONF_ACCESS_GROUP_ID,
    CONF_ACCOUNT_ID,
    CONF_ALLOWED_EMAILS,
    CONF_API_TOKEN,
    CONF_DELETE_OBJECTS_ON_REMOVE,
    CONF_EXTRA_BYPASS_PATHS,
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
)

from ..conftest import add_user

pytestmark = pytest.mark.skipif(
    not all(os.environ.get(k) for k in ("CF_API_TOKEN", "CF_ACCOUNT_ID", "CF_TEST_HOST")),
    reason="live Cloudflare settings not set (CF_API_TOKEN, CF_ACCOUNT_ID, CF_TEST_HOST)",
)

HOST = os.environ.get("CF_TEST_HOST", "")
# the allow policy needs a subject; the test logs in with its service token instead
EMAIL = "nobody@example.com"
BASE = f"https://{HOST}"
SESSION = "1h"
TOKEN_PREFIX = "ha-access-ci"
# application name prefixes of this and the previous design; leftovers of both are swept
APP_PREFIXES = ("ha-access:", "ha-relay:")
STALE_TOKEN_AGE = 6 * 3600
EDGE_TIMEOUT = 120


def _claims(token: str) -> dict[str, Any]:
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def _is_access_redirect(resp: httpx.Response) -> bool:
    """Access's answer to an unauthenticated request: a redirect to the login page for a
    browser, or (managed OAuth) a 401 pointing a non-browser client at its OAuth metadata."""
    if resp.status_code == 401 and "www-authenticate" in resp.headers:
        return True
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


async def _app_updated_at(api: CloudflareAccessApi, entry: ConfigEntry) -> str:
    gate = await api.get_app(entry.data[DATA_GATE_APP_ID])
    assert gate
    return gate["updated_at"]


async def test_live_lifecycle(
    hass: HomeAssistant,
    hass_client_no_auth: Any,
    internet: None,
    disable_mock_zeroconf_resolver: None,
) -> None:
    api = CloudflareAccessApi(
        os.environ["CF_API_TOKEN"], os.environ["CF_ACCOUNT_ID"], http_client=get_async_client(hass)
    )
    await _sweep_previous_design(api)
    token = await _service_token(api)
    try:
        await _lifecycle(hass, hass_client_no_auth, api, token)
    finally:
        await _release_and_delete_token(hass, api, token["id"])


async def _sweep_previous_design(api: CloudflareAccessApi) -> None:
    """Delete applications a previous design of the integration left on the test host."""
    for app in await api.list_apps():
        name = app.get("name") or ""
        if name.startswith("ha-relay:") and HOST in name:
            await api.delete_app(app["id"])


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
    hass_client_no_auth: Any,
    api: CloudflareAccessApi,
    token: dict[str, Any],
) -> None:
    service_headers = {
        "CF-Access-Client-Id": token["client_id"],
        "CF-Access-Client-Secret": token["client_secret"],
    }
    assert await async_setup_component(hass, "api", {})
    async with httpx.AsyncClient(follow_redirects=False, timeout=30) as http:
        edge = Edge(http)

        print("== config flow creates the entry; gate off: nothing at the edge changes")
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
        team = entry.data[DATA_TEAM_DOMAIN]
        assert team.endswith(".cloudflareaccess.com")
        assert entry.data[DATA_POLICY_AUD] is None and entry.data[DATA_GATE_APP_ID] is None
        await edge.wait_gate("/api/echo", False)

        print("== options flow enables the gate over the whole hostname")
        await _save_options(hass, entry, **{CONF_GATE_ENABLED: True})
        aud = entry.data[DATA_POLICY_AUD]
        assert isinstance(aud, str) and len(aud) == 64
        gate_id = entry.data[DATA_GATE_APP_ID]
        gate = await api.get_app(gate_id)
        assert gate and gate["domain"] == HOST
        assert gate.get("oauth_configuration", {}).get("enabled") is True, gate
        await edge.wait_gate("/api/echo", True)
        await edge.wait_gate("/", True)
        assert _is_access_redirect(await edge.get("/auth/token")), "the login surface is gated too"

        print("== the gate is an OAuth server: Access serves the discovery document itself")
        resp = await edge.get("/.well-known/oauth-authorization-server")
        assert resp.status_code == 200, (resp.status_code, resp.text[:300])
        metadata = resp.json()
        assert "authorization_endpoint" in metadata and "headers" not in metadata, (
            "the document must come from Access, not from the origin"
        )
        resp = await edge.get("/api/echo", headers={"Accept": "application/json"})
        assert resp.status_code == 401 and "www-authenticate" in resp.headers, (
            "a non-browser client is pointed at the OAuth metadata instead of the login page"
        )

        print("== a real login at the edge yields the token as header and cookie")
        real_jwt, _ = await _login_until_forwarded(edge, service_headers)
        resp = await edge.get("/api/echo", headers=service_headers)
        assert real_jwt == _set_cookie_token(resp), "header token must equal the cookie token"
        claims = _claims(real_jwt)
        assert claims["aud"] in ([aud], aud) and claims["iss"] == f"https://{team}"
        assert abs((claims["exp"] - claims["iat"]) - 3600) <= 5, (
            "token lifetime must equal the configured session duration"
        )

        print(
            "== a bearer Access admitted reaches the origin with the assertion; the origin maps it"
        )
        resp = await edge.get(
            "/api/echo", headers={**service_headers, "Authorization": "Bearer not-a-ha-token"}
        )
        assert resp.status_code == 200
        seen = resp.json()["headers"]
        assert seen.get("authorization") == "Bearer not-a-ha-token", "bearer passed through"
        assert seen.get("cf-access-jwt-assertion"), "assertion forwarded alongside it"
        await add_user(hass, "ci@example.com", name=claims["common_name"])
        origin = await hass_client_no_auth()
        headers = {
            "Authorization": "Bearer not-a-ha-token",
            "Host": HOST,
            "CF-Ray": "live",
            HEADER_JWT: real_jwt,
        }
        resp = await origin.get("/api/", headers=headers)
        assert resp.status == 200, await resp.text()
        resp = await origin.get("/api/", headers={**headers, HEADER_JWT: real_jwt[:-2] + "AA"})
        assert resp.status == 401, "a tampered assertion is refused"
        resp = await origin.get(
            "/api/", headers={k: v for k, v in headers.items() if k != "CF-Ray"}
        )
        assert resp.status == 401, "not through the edge: not trusted"

        print("== the cookie obtained by one client passes the gate from another client")
        cookie = {"CF_Authorization": real_jwt}
        resp = await edge.get("/api/echo", cookies=cookie, headers={"User-Agent": "okhttp/4.12.0"})
        assert resp.status_code == 200, (
            "the companion app's native client reuses the WebView's cookie"
        )
        assert resp.json()["headers"].get("cf-access-jwt-assertion") == real_jwt

        print("== a registered client gets an Access for SaaS application the gate accepts")
        flow = await hass.config_entries.subentries.async_init(
            (entry.entry_id, "oauth_client"), context={"source": "user"}
        )
        result = await hass.config_entries.subentries.async_configure(
            flow["flow_id"],
            {"name": "Live client", "redirect_uris": ["https://example.com/oauth/callback"]},
        )
        assert result["type"] is FlowResultType.FORM and result["step_id"] == "credentials", result
        shown = result["description_placeholders"]
        assert shown["client_id"] and shown["client_secret"], shown
        result = await hass.config_entries.subentries.async_configure(flow["flow_id"], {})
        assert result["type"] is FlowResultType.CREATE_ENTRY, result
        subentry = next(iter(entry.subentries.values()))
        client_app = await api.get_app(subentry.data["app_id"])
        assert client_app and client_app["type"] == "saas", client_app
        assert client_app["saas_app"]["client_id"] == shown["client_id"]
        jwks_url = f"https://{team}/cdn-cgi/access/sso/oidc/{shown['client_id']}/jwks"

        async def client_keys_served() -> bool:
            resp = await http.get(jwks_url)
            return resp.status_code == 200 and bool(resp.json().get("keys"))

        assert await _until(client_keys_served, "the client's own key endpoint"), (
            "the registration must be live at the team domain"
        )

        async def gate_links_client() -> bool:
            app = await api.get_app(gate_id)
            return bool(app) and any(
                rule.get("linked_app_token", {}).get("app_uid") == subentry.data["app_id"]
                for pol in app["policies"]
                for rule in pol.get("include", [])
            )

        assert await _until(gate_links_client, "linked client rule on the gate", 60)
        hass.config_entries.async_remove_subentry(entry, subentry.subentry_id)

        async def client_gone() -> bool:
            return await api.get_app(subentry.data["app_id"]) is None

        assert await _until(client_gone, "client application deleted", 60)

        print("== a listed path is bypassed; clearing the list removes the bypass")
        await _save_options(hass, entry, **{CONF_EXTRA_BYPASS_PATHS: ["/api/open"]})
        bypass_id = entry.data[DATA_BYPASS_APP_ID]
        assert bypass_id and await api.get_app(bypass_id)
        await edge.wait_gate("/api/open/echo", False)
        assert _is_access_redirect(await edge.get("/api/echo")), "everything else stays gated"
        await _save_options(hass, entry, **{CONF_EXTRA_BYPASS_PATHS: []})
        assert entry.data[DATA_BYPASS_APP_ID] is None and await api.get_app(bypass_id) is None
        await edge.wait_gate("/api/open/echo", True)

        print("== a reload writes nothing")
        before = await _app_updated_at(api, entry)
        assert await hass.config_entries.async_reload(entry.entry_id)
        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.LOADED
        assert await _app_updated_at(api, entry) == before

        print(
            "== drift outside the integration (binding cookie on) breaks reuse; a reload repairs it"
        )
        gate = await api.get_app(gate_id)
        assert gate
        keep = (
            "type",
            "name",
            "domain",
            "destinations",
            "session_duration",
            "http_only_cookie_attribute",
            "same_site_cookie_attribute",
            "app_launcher_visible",
            "oauth_configuration",
        )
        drift = {k: gate[k] for k in keep if k in gate}
        drift["policies"] = [
            {k: p[k] for k in ("id", "name", "decision", "precedence", "include") if k in p}
            for p in gate["policies"]
        ]
        await api.update_app(gate_id, {**drift, "enable_binding_cookie": True})

        async def refused() -> bool:
            return _is_access_redirect(await edge.get("/api/echo", cookies=cookie))

        assert await _until(refused, "binding refusal"), (
            "with the binding cookie on, a copied token must be refused"
        )
        assert await hass.config_entries.async_reload(entry.entry_id)
        await hass.async_block_till_done()

        async def repaired() -> bool:
            app = await api.get_app(gate_id)
            return bool(app) and app.get("enable_binding_cookie") is not True

        assert await _until(repaired, "drift repaired", 60)

        async def reusable() -> bool:
            return (await edge.get("/api/echo", cookies=cookie)).status_code == 200

        assert await _until(reusable, "cookie reuse restored")

        print("== dropping the service token from the options removes it from the gate policy")
        await _save_options(
            hass, entry, **{CONF_SERVICE_TOKEN_IDS: [], CONF_DELETE_OBJECTS_ON_REMOVE: False}
        )

        async def token_gone() -> bool:
            app = await api.get_app(gate_id)
            return bool(app) and [p["decision"] for p in app["policies"]] == ["allow"]

        assert await _until(token_gone, "policy without service token", 60)

        print("== removal with 'delete objects' off keeps the application for the next run")
        await hass.config_entries.async_remove(entry.entry_id)
        await hass.async_block_till_done()
        assert await api.get_app(gate_id) is not None
