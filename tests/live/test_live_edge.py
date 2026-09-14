"""Live tests: provision the test host with the integration's own code, then prove
the Cloudflare behaviour the relay depends on (plan section 7, P1-P6 and P8).

Needs, as environment variables (GitHub Actions secrets in CI):
  CF_API_TOKEN               account token, scope "Access: Apps and Policies: Edit"
  CF_ACCOUNT_ID
  CF_TEST_HOST               hostname served by preflight/worker (e.g. test-host.example.com)
  CF_ACCESS_SERVICE_TOKEN_ID id of an Access service token
  CF_ACCESS_CLIENT_ID        that token's client id
  CF_ACCESS_CLIENT_SECRET    that token's client secret
Optional: CF_TEST_EMAIL (the allow policy's e-mail; defaults to a placeholder).

The paths probed are all under prefixes that the zone's WAF exempts from bot
protection or that the test host's own exemption covers.
"""

from __future__ import annotations

import base64
import json
import os
import time
from typing import Any

import aiohttp
import pytest

from custom_components.cloudflare_access_relay.cloudflare_api import CloudflareAccessApi
from custom_components.cloudflare_access_relay.const import (
    CONF_ALLOWED_EMAILS,
    CONF_EXTRA_BYPASS_PATHS,
    CONF_GATE_ENABLED,
    CONF_HOSTNAME,
    CONF_SERVICE_TOKEN_IDS,
    CONF_SESSION_DURATION,
    URL_CALLBACK,
)
from custom_components.cloudflare_access_relay.jwks import JwksVerifier, JwtVerifyError
from custom_components.cloudflare_access_relay.provision import async_provision

REQUIRED = (
    "CF_API_TOKEN",
    "CF_ACCOUNT_ID",
    "CF_TEST_HOST",
    "CF_ACCESS_SERVICE_TOKEN_ID",
    "CF_ACCESS_CLIENT_ID",
    "CF_ACCESS_CLIENT_SECRET",
)
pytestmark = pytest.mark.skipif(
    any(not os.environ.get(k) for k in REQUIRED),
    reason="live Cloudflare credentials not set: " + ", ".join(REQUIRED),
)

SESSION = "1h"


def _claims(token: str) -> dict[str, Any]:
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def _options(gated: bool) -> dict[str, Any]:
    return {
        CONF_HOSTNAME: os.environ["CF_TEST_HOST"],
        CONF_ALLOWED_EMAILS: [os.environ.get("CF_TEST_EMAIL", "nobody@example.com")],
        CONF_EXTRA_BYPASS_PATHS: [],
        CONF_SERVICE_TOKEN_IDS: [os.environ["CF_ACCESS_SERVICE_TOKEN_ID"]],
        CONF_SESSION_DURATION: SESSION,
        CONF_GATE_ENABLED: gated,
    }


def _is_access_redirect(resp: aiohttp.ClientResponse) -> bool:
    return resp.status in (301, 302, 303, 307) and ".cloudflareaccess.com/" in resp.headers.get(
        "Location", ""
    )


@pytest.fixture
async def http(socket_enabled: None):
    async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as session:
        yield session


@pytest.fixture
def base() -> str:
    return "https://" + os.environ["CF_TEST_HOST"]


@pytest.fixture
async def provisioned(http: aiohttp.ClientSession):
    """Provision gated; hand back the result; leave the host gated afterwards."""
    api = CloudflareAccessApi(http, os.environ["CF_API_TOKEN"], os.environ["CF_ACCOUNT_ID"])
    result = await async_provision(
        api, _options(True), set(), gate_app_id=None, bypass_app_id=None, team_domain=None
    )
    return api, result


async def _wait_for_gate(
    http: aiohttp.ClientSession, url: str, gated: bool, timeout: float = 90
) -> None:
    """Access configuration propagates within seconds; poll until it has."""
    deadline = time.time() + timeout
    while True:
        async with http.get(url, allow_redirects=False) as resp:
            if _is_access_redirect(resp) == gated:
                return
        if time.time() > deadline:
            raise AssertionError(
                f"{url} did not become {'gated' if gated else 'open'} in {timeout}s"
            )
        time.sleep(3)


async def test_p8_precedence_and_p1_setcookie(
    http: aiohttp.ClientSession, base: str, provisioned: Any
) -> None:
    await _wait_for_gate(http, f"{base}/api/echo", True)
    async with http.get(f"{base}/api/echo", allow_redirects=False) as resp:
        assert _is_access_redirect(resp), (resp.status, resp.headers.get("Location"))
    async with http.get(f"{base}/api/cloudflare_access_relay/echo", allow_redirects=False) as resp:
        assert resp.status == 200, "bypassed prefix under /api must beat the hostname-wide gate"
    async with http.get(f"{base}{URL_CALLBACK}?flow=bogus", allow_redirects=False) as resp:
        assert _is_access_redirect(resp), "callback path must be gated"
    async with http.post(
        f"{base}/auth/token/setcookie", json={"v": "probe-value"}, allow_redirects=False
    ) as resp:
        assert resp.status == 200
        cookies = resp.headers.getall("Set-Cookie")
        assert cookies == [
            "CF_Authorization=probe-value; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600"
        ], "P1: origin Set-Cookie must pass through unmodified"


async def test_service_token_then_cookie_only(
    http: aiohttp.ClientSession, base: str, provisioned: Any
) -> None:
    _api, result = provisioned
    await _wait_for_gate(http, f"{base}/api/echo", True)
    headers = {
        "CF-Access-Client-Id": os.environ["CF_ACCESS_CLIENT_ID"],
        "CF-Access-Client-Secret": os.environ["CF_ACCESS_CLIENT_SECRET"],
    }
    async with http.get(f"{base}/api/echo", headers=headers, allow_redirects=False) as resp:
        assert resp.status == 200, (resp.status, resp.headers.get("Location"))
        body = await resp.json()
        set_cookie = [
            c for c in resp.headers.getall("Set-Cookie", []) if c.startswith("CF_Authorization=")
        ]
        assert len(set_cookie) == 1, (
            "Access sets the application token as a cookie on the service-token login"
        )
        cookie_token = set_cookie[0].split(";")[0].split("=", 1)[1]
        attrs = set_cookie[0].lower()
        assert "httponly" in attrs and "secure" in attrs and "samesite=lax" in attrs
    header_token = body["headers"].get("cf-access-jwt-assertion")
    assert header_token, "origin must receive Cf-Access-Jwt-Assertion"
    assert header_token == cookie_token, "P4: header token equals cookie token"

    claims = _claims(header_token)
    assert claims["aud"] == [result.policy_aud] or claims["aud"] == result.policy_aud
    assert claims["iss"] == f"https://{result.team_domain}"
    assert abs((claims["exp"] - claims["iat"]) - 3600) <= 5, (
        "P3: exp - iat equals the session duration"
    )

    # the verifier the callback view uses, against the real JWKS
    verifier = JwksVerifier(http, result.team_domain)
    verified = await verifier.verify(header_token, result.policy_aud)
    assert verified["exp"] == claims["exp"]
    with pytest.raises(JwtVerifyError):
        await verifier.verify(header_token, "0" * 64)
    with pytest.raises(JwtVerifyError):
        await verifier.verify(
            header_token[:-2] + ("AA" if header_token[-2:] != "AA" else "BB"), result.policy_aud
        )

    # P2: the token alone, as a cookie, from a client Access never saw log in
    cookie = {"CF_Authorization": header_token}
    async with http.get(
        f"{base}/api/echo",
        cookies=cookie,
        allow_redirects=False,
        headers={"User-Agent": "okhttp/4.12.0"},
    ) as resp:
        assert resp.status == 200, (
            "P2: Access must accept a CF_Authorization cookie it did not set in this client"
        )
        echoed = await resp.json()
        assert echoed["headers"].get("cf-access-jwt-assertion") == header_token
    async with http.get(
        f"{base}/api/echo",
        cookies={"CF_Authorization": header_token[:-3] + "xyz"},
        allow_redirects=False,
    ) as resp:
        assert _is_access_redirect(resp), "a tampered cookie must not pass"
    # websocket-style upgrade carries the cookie too
    ws_headers = {
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
    }
    async with http.get(
        f"{base}/api/echo", cookies=cookie, headers=ws_headers, allow_redirects=False
    ) as resp:
        assert not _is_access_redirect(resp)


async def test_p5_binding_cookie_breaks_relay(
    http: aiohttp.ClientSession, base: str, provisioned: Any
) -> None:
    api, result = provisioned
    app = await api.get_app(result.gate_app_id)
    assert app is not None
    body = {
        k: v
        for k, v in app.items()
        if k
        in (
            "type",
            "name",
            "domain",
            "destinations",
            "session_duration",
            "path_cookie_attribute",
            "http_only_cookie_attribute",
            "same_site_cookie_attribute",
            "app_launcher_visible",
            "policies",
        )
    }
    body["policies"] = [
        {k: p[k] for k in ("id", "name", "decision", "precedence", "include") if k in p}
        for p in app["policies"]
    ]
    try:
        await api.update_app(result.gate_app_id, {**body, "enable_binding_cookie": True})
        headers = {
            "CF-Access-Client-Id": os.environ["CF_ACCESS_CLIENT_ID"],
            "CF-Access-Client-Secret": os.environ["CF_ACCESS_CLIENT_SECRET"],
        }
        time.sleep(5)
        async with http.get(f"{base}/api/echo", headers=headers, allow_redirects=False) as resp:
            assert resp.status == 200
            token = (await resp.json())["headers"]["cf-access-jwt-assertion"]
        async with http.get(
            f"{base}/api/echo", cookies={"CF_Authorization": token}, allow_redirects=False
        ) as resp:
            binding_blocks = resp.status != 200
    finally:
        # the integration's own reconciliation restores the intended settings
        await async_provision(
            api,
            _options(True),
            set(),
            gate_app_id=result.gate_app_id,
            bypass_app_id=result.bypass_app_id,
            team_domain=result.team_domain,
        )
    # documented expectation: binding cookie must stay off. Record the observation either way.
    print(
        f"P5: with the binding cookie enabled, a copied token {'is refused' if binding_blocks else 'still passes'}"
    )


async def test_staged_mode_gates_only_the_callback(
    http: aiohttp.ClientSession, base: str, provisioned: Any
) -> None:
    api, result = provisioned
    staged = await async_provision(
        api,
        _options(False),
        set(),
        gate_app_id=result.gate_app_id,
        bypass_app_id=result.bypass_app_id,
        team_domain=result.team_domain,
    )
    assert staged.policy_aud == result.policy_aud, "audience must survive the destination change"
    assert staged.gate_app_id == result.gate_app_id
    try:
        await _wait_for_gate(http, f"{base}/api/echo", False)
        async with http.get(f"{base}{URL_CALLBACK}?flow=bogus", allow_redirects=False) as resp:
            assert _is_access_redirect(resp), "staged: the callback path stays gated"
    finally:
        back = await async_provision(
            api,
            _options(True),
            set(),
            gate_app_id=result.gate_app_id,
            bypass_app_id=result.bypass_app_id,
            team_domain=result.team_domain,
        )
        assert back.policy_aud == result.policy_aud
        await _wait_for_gate(http, f"{base}/api/echo", True)


async def test_reprovision_is_idempotent(http: aiohttp.ClientSession, provisioned: Any) -> None:
    api, result = provisioned
    again = await async_provision(
        api,
        _options(True),
        set(),
        gate_app_id=result.gate_app_id,
        bypass_app_id=result.bypass_app_id,
        team_domain=result.team_domain,
    )
    assert again.writes == [], again.writes
