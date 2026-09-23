"""Live integration test: the whole lifecycle through Home Assistant against real Cloudflare.

Everything the integration is responsible for is driven the way a user drives it:
the config flow creates the entry, the options flow enables the gate (which
provisions the Access application with managed OAuth), registers a client, lists a
bypassed path, re-saves after drift, a reload must write nothing, and removal with
"delete objects" off keeps the application. The origin rule is exercised with a
real Access assertion verified against the real JWKS.

The raw Cloudflare API is used only to create and delete this run's service
token, to observe the applications, and to inject drift.

The test host is a throwaway Worker the test deploys on the account's workers.dev
subdomain (tests/live/worker), which Access accepts as an application domain like
any hostname; it is deleted at the end. Nothing has to exist beforehand.

Environment (GitHub Actions repository secrets):
  CF_API_TOKEN    account token with "Access: Apps and Policies: Edit",
                  "Access: Organizations, Identity Providers, and Groups: Read",
                  "Access: Service Tokens: Edit", "Access: Organizations: Revoke"
                  and "Workers Scripts: Edit" (the oauth-client workflow's `grant`
                  command adds the Access ones to the token itself)
  CF_ACCOUNT_ID
"""

from __future__ import annotations

import base64
from collections.abc import AsyncIterator, Callable, Iterator
import contextlib
import json
import os
from pathlib import Path
import socket
import time
from typing import Any

from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.httpx_client import get_async_client
from homeassistant.setup import async_setup_component
import httpx
import pytest
import pytest_socket

from custom_components.cloudflare_access_relay.cloudflare_api import (
    CloudflareAccessApi,
)
from custom_components.cloudflare_access_relay.const import (
    CONF_ACCOUNT_ID,
    CONF_API_TOKEN,
    CONF_DELETE_OBJECTS_ON_REMOVE,
    CONF_EXTRA_BYPASS_PATHS,
    CONF_GATE_ENABLED,
    CONF_HOSTNAME,
    CONF_SESSION_DURATION,
    DATA_BYPASS_APP_ID,
    DATA_GATE_APP_ID,
    DATA_POLICY_AUD,
    DATA_TEAM_DOMAIN,
    DOMAIN,
    HEADER_JWT,
)

from ..conftest import add_user
from .cleanup import delete_run, run_names, sweep_stale

pytestmark = pytest.mark.skipif(
    not (os.environ.get("CF_API_TOKEN") and os.environ.get("CF_ACCOUNT_ID")),
    reason="live Cloudflare credentials not set (CF_API_TOKEN, CF_ACCOUNT_ID)",
)

# the allow policy needs a subject; the test logs in with its service token instead
EMAIL = "nobody@example.com"
SESSION_FORM = {"hours": 1}  # what Access stores as "1h"
# this run's service token, Worker and applications carry the run id (tests/live/cleanup.py)
RUN = os.environ.get("GITHUB_RUN_ID", str(int(time.time())))
WORKER_NAME, _, _ = run_names(RUN)
WORKER_SOURCE = Path(__file__).with_name("worker") / "worker.js"
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

    def __init__(self, http: httpx.AsyncClient, host: str) -> None:
        self.http = http
        self.host = host

    async def get(self, path: str, **kw: Any) -> httpx.Response:
        self.http.cookies.clear()
        return await self.http.get(f"https://{self.host}{path}", **kw)

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


@contextlib.asynccontextmanager
async def _ephemeral_host(api: CloudflareAccessApi, http: httpx.AsyncClient) -> AsyncIterator[str]:
    """Deploy this run's echo Worker on workers.dev; yield its hostname; delete it after.

    Leftovers of aborted earlier runs are swept first. The CI step that runs
    tests/live/cleanup.py after the job is the primary safety net; this is the second.
    """
    await sweep_stale(api)
    sdk, account = api.sdk, api.account_id
    subdomain = (await sdk.workers.subdomains.get(account_id=account)).subdomain
    await sdk.workers.scripts.update(
        WORKER_NAME,
        account_id=account,
        metadata={"main_module": "worker.js", "compatibility_date": "2026-09-01"},
        files=[("worker.js", WORKER_SOURCE.read_bytes(), "application/javascript+module")],
    )
    await sdk.workers.scripts.subdomain.create(WORKER_NAME, account_id=account, enabled=True)
    host = f"{WORKER_NAME}.{subdomain}.workers.dev"

    async def serving() -> bool:
        try:
            resp = await http.get(f"https://{host}/api/echo")
        except httpx.HTTPError:
            return False
        return resp.status_code == 200 and resp.json().get("path") == "/api/echo"

    try:
        assert await _until(serving, "test host"), f"{host} did not come up in {EDGE_TIMEOUT}s"
        yield host
    finally:
        await delete_run(api, RUN)


async def _save_options(hass: HomeAssistant, entry: ConfigEntry, **changes: Any) -> None:
    """Re-save the options through the options flow (reloads and re-provisions)."""
    flow = await hass.config_entries.options.async_init(entry.entry_id)
    assert flow["type"] is FlowResultType.FORM
    current = dict(entry.options)
    user_input = {
        CONF_GATE_ENABLED: current[CONF_GATE_ENABLED],
        "bypass": {CONF_EXTRA_BYPASS_PATHS: current.get(CONF_EXTRA_BYPASS_PATHS, [])},
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
    async with (
        httpx.AsyncClient(follow_redirects=False, timeout=30) as http,
        _ephemeral_host(api, http) as host,
    ):
        try:
            await _lifecycle(hass, hass_client_no_auth, api, Edge(http, host))
        finally:
            await _remove_entry(hass)


async def _remove_entry(hass: HomeAssistant) -> None:
    """Remove any surviving entry with its applications (the Home Assistant side).

    Runs after a failed step too; the Cloudflare side is then cleaned by name
    (`delete_run`), which never depends on Home Assistant's state.
    """
    for entry in hass.config_entries.async_entries(DOMAIN):
        with contextlib.suppress(Exception):
            await hass.config_entries.async_remove(entry.entry_id)
            await hass.async_block_till_done()


async def _register_script(hass: HomeAssistant, entry: ConfigEntry, name: str) -> dict[str, Any]:
    """Add a script client through the subentry flow; return the credentials page's values."""
    flow = await hass.config_entries.subentries.async_init(
        (entry.entry_id, "oauth_client"), context={"source": "user"}
    )
    result = await hass.config_entries.subentries.async_configure(
        flow["flow_id"], {"name": name, "kind": "script"}
    )
    assert result["type"] is FlowResultType.FORM and result["step_id"] == "script_credentials", (
        result
    )
    shown = dict(result["description_placeholders"])
    result = await hass.config_entries.subentries.async_configure(flow["flow_id"], {})
    assert result["type"] is FlowResultType.CREATE_ENTRY, result
    await hass.async_block_till_done()
    return shown


async def _lifecycle(
    hass: HomeAssistant,
    hass_client_no_auth: Any,
    api: CloudflareAccessApi,
    edge: Edge,
) -> None:
    http, host = edge.http, edge.host
    assert await async_setup_component(hass, "api", {})
    if True:
        print("== config flow creates the entry; gate off: nothing at the edge changes")
        # the allow policy is derived from the Home Assistant users: one with an address
        await add_user(hass, EMAIL, name=EMAIL)
        # CI cannot click a consent page: the token path, started by its source
        result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "api_token"})
        assert result["type"] is FlowResultType.FORM and result["step_id"] == "api_token"
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_API_TOKEN: os.environ["CF_API_TOKEN"],
                CONF_ACCOUNT_ID: os.environ["CF_ACCOUNT_ID"],
            },
        )
        assert result["type"] is FlowResultType.FORM and result["step_id"] == "settings", result
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {CONF_HOSTNAME: host, CONF_SESSION_DURATION: SESSION_FORM},
        )
        assert result["type"] is FlowResultType.CREATE_ENTRY, result
        entry: ConfigEntry = result["result"]
        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.LOADED, entry.reason

        print("== a script client is a service token, created by the integration")
        shown = await _register_script(hass, entry, "CI runner")
        service_headers = {
            "CF-Access-Client-Id": shown["client_id"],
            "CF-Access-Client-Secret": shown["client_secret"],
        }
        (script,) = [sub for sub in entry.subentries.values() if sub.data.get("kind") == "script"]
        token_id = script.data["token_id"]
        assert (await api.get_service_token(token_id) or {}).get("client_id") == shown["client_id"]
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
        assert gate and gate["domain"] == host
        assert gate.get("oauth_configuration", {}).get("enabled") is True, gate
        assert gate["policies"][0]["include"] == [{"email": {"email": EMAIL}}], (
            "the allow policy is the Home Assistant users' addresses"
        )

        print("== a new Home Assistant user joins the allow policy without a reload")
        await add_user(hass, "second@example.com", name="second@example.com")

        async def second_allowed() -> bool:
            app = await api.get_app(gate_id)
            return bool(app) and app["policies"][0]["include"] == [
                {"email": {"email": EMAIL}},
                {"email": {"email": "second@example.com"}},
            ]

        assert await _until(second_allowed, "allow policy follows the users", 60)
        idps = await api.list_identity_providers()
        gate_now = await api.get_app(gate_id)
        assert gate_now is not None
        assert gate_now.get("auto_redirect_to_identity", False) is (len(idps) == 1), (
            "with one login method people skip the picker page"
        )
        assert "People" in gate_now.get("custom_deny_message", "")

        print("== a removed user leaves the allow policy and is logged out of Access")
        second = next(
            u for u in await hass.auth.async_get_users() if u.name == "second@example.com"
        )
        await hass.auth.async_remove_user(second)

        async def second_gone() -> bool:
            app = await api.get_app(gate_id)
            return bool(app) and app["policies"][0]["include"] == [{"email": {"email": EMAIL}}]

        assert await _until(second_gone, "allow policy without the removed user", 60)
        assert not ir.async_get(hass).async_get_issue(DOMAIN, "revoke_unavailable"), (
            "the credential must be able to revoke sessions"
        )
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
        await add_user(hass, claims["common_name"], name="CI runner")
        origin = await hass_client_no_auth()
        headers = {
            "Authorization": "Bearer not-a-ha-token",
            "Host": host,
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
            flow["flow_id"], {"name": "Live client", "kind": "login"}
        )
        assert result["type"] is FlowResultType.FORM and result["step_id"] == "login", result
        result = await hass.config_entries.subentries.async_configure(
            flow["flow_id"],
            {"redirect_uris": ["https://example.com/oauth/callback"], "needs_credentials": True},
        )
        assert result["type"] is FlowResultType.FORM and result["step_id"] == "credentials", result
        shown = result["description_placeholders"]
        assert shown["client_id"] and shown["client_secret"], shown
        result = await hass.config_entries.subentries.async_configure(flow["flow_id"], {})
        assert result["type"] is FlowResultType.CREATE_ENTRY, result
        subentry = next(
            s
            for s in entry.subentries.values()
            if s.subentry_type == "oauth_client" and s.data.get("kind") == "login"
        )  # user rows are subentries too
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
        await _save_options(hass, entry, **{"bypass": {CONF_EXTRA_BYPASS_PATHS: ["/api/open"]}})
        bypass_id = entry.data[DATA_BYPASS_APP_ID]
        assert bypass_id and await api.get_app(bypass_id)
        await edge.wait_gate("/api/open/echo", False)
        assert _is_access_redirect(await edge.get("/api/echo")), "everything else stays gated"
        await _save_options(hass, entry, **{"bypass": {CONF_EXTRA_BYPASS_PATHS: []}})
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
            "tags",  # a dashboard edit keeps the tag; an API PUT without it would strip it
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

        print("== removing the script client drops its rule from the gate and deletes its token")
        hass.config_entries.async_remove_subentry(entry, script.subentry_id)

        async def token_gone() -> bool:
            app = await api.get_app(gate_id)
            return (
                bool(app)
                and [p["decision"] for p in app["policies"]] == ["allow"]
                and await api.get_service_token(token_id) is None
            )

        assert await _until(token_gone, "policy and token gone", 60)

        print("== removal deletes the application")
        await hass.config_entries.async_remove(entry.entry_id)
        await hass.async_block_till_done()
        assert await api.get_app(gate_id) is None
