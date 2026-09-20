"""Shared fixtures: RSA keys, a fake JWKS endpoint, a fake Cloudflare API."""

from __future__ import annotations

import base64
from collections.abc import AsyncGenerator, Callable, Generator
import contextlib
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import time
from typing import Any
from unittest.mock import patch
import uuid

from aiohttp import web
from aiohttp.test_utils import TestServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from homeassistant.auth.models import Credentials, User
from homeassistant.core import HomeAssistant
import jwt
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry, MockUser

from custom_components.cloudflare_access_relay.const import (
    CONF_ACCOUNT_ID,
    CONF_ALLOWED_EMAILS,
    CONF_API_TOKEN,
    CONF_DELETE_OBJECTS_ON_REMOVE,
    CONF_GATE_ENABLED,
    CONF_HOSTNAME,
    DOMAIN,
)

TEAM_DOMAIN = "team.cloudflareaccess.com"
ISSUER = f"https://{TEAM_DOMAIN}"
HOSTNAME = "ha.example.com"
ACCOUNT_ID = "0123456789abcdef0123456789abcdef"
ALICE = "alice@example.com"
BOB = "bob@example.com"
CLIENT_ID = "https://ha.example.com/"


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(request: pytest.FixtureRequest) -> None:
    """Make custom_components discoverable whenever the HA plugin is active."""
    with contextlib.suppress(pytest.FixtureLookupError):
        request.getfixturevalue("enable_custom_integrations")


# --------------------------------------------------------------------------- keys


@dataclass
class RsaKey:
    kid: str
    private: rsa.RSAPrivateKey

    @property
    def private_pem(self) -> bytes:
        return self.private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    @property
    def public_pem(self) -> bytes:
        return self.private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def jwk(self) -> dict[str, Any]:
        data = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.private.public_key()))
        data.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return data


@pytest.fixture(scope="session")
def rsa_keys() -> dict[str, RsaKey]:
    """Three keys: current, previous (still valid) and one Access never published."""
    return {
        kid: RsaKey(kid, rsa.generate_private_key(public_exponent=65537, key_size=2048))
        for kid in ("current", "previous", "rogue")
    }


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@dataclass
class Minter:
    keys: dict[str, RsaKey]
    aud: str

    def __call__(
        self,
        email: str = ALICE,
        *,
        aud: str | list[str] | None = None,
        exp: int | None = None,
        iat: int | None = None,
        kid: str = "current",
        iss: str = ISSUER,
        alg: str = "RS256",
        extra: dict[str, Any] | None = None,
    ) -> str:
        now = int(time.time())
        payload: dict[str, Any] = {
            "aud": [self.aud] if aud is None else aud,
            "email": email,
            "exp": now + 3600 if exp is None else exp,
            "iat": now - 5 if iat is None else iat,
            "nbf": now - 5,
            "iss": iss,
            "sub": "user-" + hashlib.sha1(email.encode()).hexdigest()[:8],
            "type": "app",
            "identity_nonce": "abc",
            "country": "GB",
        }
        payload.update(extra or {})
        key = self.keys[kid]
        if alg == "RS256":
            return jwt.encode(payload, key.private_pem, algorithm="RS256", headers={"kid": kid})
        header = {"alg": alg, "kid": kid, "typ": "JWT"}
        signing = b64url(json.dumps(header).encode()) + "." + b64url(json.dumps(payload).encode())
        if alg == "none":
            return signing + "."
        if alg == "HS256":
            sig = hmac.new(key.public_pem, signing.encode(), hashlib.sha256).digest()
            return signing + "." + b64url(sig)
        raise ValueError(alg)


# --------------------------------------------------------------------------- JWKS


@dataclass
class FakeJwks:
    keys: dict[str, RsaKey]
    published: list[str] = field(default_factory=lambda: ["current", "previous"])
    fetches: int = 0
    status: int = 200
    server: TestServer | None = None

    @property
    def url(self) -> str:
        assert self.server is not None
        return str(self.server.make_url("/cdn-cgi/access/certs"))

    async def handle(self, _request: web.Request) -> web.Response:
        self.fetches += 1
        if self.status != 200:
            return web.Response(status=self.status)
        keys = [self.keys[k].jwk() for k in self.published]
        return web.json_response({"keys": keys, "public_cert": {}, "public_certs": []})


@pytest.fixture
async def jwks_server(
    socket_enabled: None, rsa_keys: dict[str, RsaKey]
) -> AsyncGenerator[FakeJwks]:
    """Serve a JWKS document like <team>.cloudflareaccess.com/cdn-cgi/access/certs."""
    fake = FakeJwks(rsa_keys)
    app = web.Application()
    app.router.add_get("/cdn-cgi/access/certs", fake.handle)
    server = TestServer(app)
    await server.start_server()
    fake.server = server
    with patch(
        "custom_components.cloudflare_access_relay.jwks.CERTS_URL_FMT",
        fake.url,
    ):
        yield fake
    await server.close()


# --------------------------------------------------------------------------- Cloudflare


@dataclass
class FakeCloudflare:
    """Records every request; behaves like the Access applications API."""

    apps: dict[str, dict[str, Any]] = field(default_factory=dict)
    secrets: dict[str, str] = field(default_factory=dict)
    requests: list[tuple[str, str, dict[str, Any] | None]] = field(default_factory=list)
    auth_fail: bool = False
    org_auth_fail: bool = False
    fail_status: int | None = None
    fail_predicate: Callable[[str, str], bool] | None = None
    team_domain: str = TEAM_DOMAIN
    server: TestServer | None = None

    def writes(self, method: str | None = None) -> list[tuple[str, str, dict[str, Any] | None]]:
        return [
            r
            for r in self.requests
            if r[0] in ("POST", "PUT", "DELETE") and (method is None or r[0] == method)
        ]

    def by_name(self, name: str) -> dict[str, Any] | None:
        return next((a for a in self.apps.values() if a["name"] == name), None)

    @property
    def base_url(self) -> str:
        assert self.server is not None
        return str(self.server.make_url("")).rstrip("/")

    def _fail(self, method: str, path: str) -> web.Response | None:
        if self.auth_fail:
            return web.json_response(
                {
                    "success": False,
                    "errors": [{"code": 10000, "message": "Authentication error"}],
                    "result": None,
                },
                status=403,
            )
        if self.fail_status and (self.fail_predicate is None or self.fail_predicate(method, path)):
            return web.Response(status=self.fail_status, text="upstream error")
        return None

    def _ok(self, result: Any, status: int = 200, **extra: Any) -> web.Response:
        return web.json_response(
            {"success": True, "errors": [], "messages": [], "result": result, **extra},
            status=status,
        )

    async def _record(self, request: web.Request) -> dict[str, Any] | None:
        body = await request.json() if request.can_read_body else None
        self.requests.append((request.method, request.path, body))
        return body

    async def organizations(self, request: web.Request) -> web.Response:
        await self._record(request)
        if fail := self._fail(request.method, request.path):
            return fail
        if self.org_auth_fail:
            return web.json_response(
                {
                    "success": False,
                    "errors": [{"code": 10000, "message": "Authentication error"}],
                    "result": None,
                },
                status=403,
            )
        return self._ok({"auth_domain": self.team_domain, "name": "Team"})

    async def list_apps(self, request: web.Request) -> web.Response:
        await self._record(request)
        if fail := self._fail(request.method, request.path):
            return fail
        # honour paging: the SDK keeps asking for the next page until one comes back empty
        page = int(request.query.get("page", "1"))
        per_page = int(request.query.get("per_page", "20"))
        apps = list(self.apps.values())[(page - 1) * per_page : page * per_page]
        return self._ok(
            apps,
            result_info={
                "page": page,
                "per_page": per_page,
                "total_pages": max(1, -(-len(self.apps) // per_page)),
                "count": len(apps),
                "total_count": len(self.apps),
            },
        )

    def _stored(
        self, body: dict[str, Any], app_id: str, existing: dict[str, Any] | None
    ) -> dict[str, Any]:
        app = {**body, "id": app_id, "aud": hashlib.sha256(app_id.encode()).hexdigest()}
        policies = []
        for i, pol in enumerate(body.get("policies") or []):
            pid = pol.get("id") or uuid.uuid4().hex
            policies.append(
                {
                    **pol,
                    "id": pid,
                    "precedence": pol.get("precedence", i + 1),
                    "exclude": pol.get("exclude", []),
                    "require": pol.get("require", []),
                }
            )
        app["policies"] = policies
        if existing:
            app["created_at"] = existing.get("created_at")
        if body.get("type") == "saas":
            # Cloudflare assigns the OIDC client id once; the secret is returned only on POST
            saas = dict(app.get("saas_app") or {})
            saas["client_id"] = (existing or {}).get("saas_app", {}).get(
                "client_id"
            ) or uuid.uuid4().hex
            saas.pop("client_secret", None)
            app["saas_app"] = saas
        return app

    async def create_app(self, request: web.Request) -> web.Response:
        body = await self._record(request)
        if fail := self._fail(request.method, request.path):
            return fail
        assert body is not None
        app_id = str(uuid.uuid4())
        self.apps[app_id] = self._stored(body, app_id, None)
        created = self.apps[app_id]
        if body.get("type") == "saas":
            self.secrets[app_id] = uuid.uuid4().hex
            created = {
                **created,
                "saas_app": {**created["saas_app"], "client_secret": self.secrets[app_id]},
            }
        return self._ok(created, status=201)

    async def get_app(self, request: web.Request) -> web.Response:
        await self._record(request)
        if fail := self._fail(request.method, request.path):
            return fail
        app = self.apps.get(request.match_info["app_id"])
        if app is None:
            return web.json_response(
                {
                    "success": False,
                    "errors": [{"code": 12130, "message": "not found"}],
                    "result": None,
                },
                status=404,
            )
        return self._ok(app)

    async def update_app(self, request: web.Request) -> web.Response:
        body = await self._record(request)
        if fail := self._fail(request.method, request.path):
            return fail
        app_id = request.match_info["app_id"]
        if app_id not in self.apps:
            return web.json_response(
                {
                    "success": False,
                    "errors": [{"code": 12130, "message": "not found"}],
                    "result": None,
                },
                status=404,
            )
        assert body is not None
        self.apps[app_id] = self._stored(body, app_id, self.apps[app_id])
        return self._ok(self.apps[app_id])

    async def delete_app(self, request: web.Request) -> web.Response:
        await self._record(request)
        if fail := self._fail(request.method, request.path):
            return fail
        app_id = request.match_info["app_id"]
        if app_id not in self.apps:
            return web.json_response(
                {
                    "success": False,
                    "errors": [{"code": 12130, "message": "not found"}],
                    "result": None,
                },
                status=404,
            )
        del self.apps[app_id]
        return self._ok({"id": app_id})


@pytest.fixture
async def fake_cloudflare(socket_enabled: None) -> AsyncGenerator[FakeCloudflare]:
    fake = FakeCloudflare()
    app = web.Application()
    base = f"/accounts/{ACCOUNT_ID}/access"
    app.router.add_get(f"{base}/organizations", fake.organizations)
    app.router.add_get(f"{base}/apps", fake.list_apps)
    app.router.add_post(f"{base}/apps", fake.create_app)
    app.router.add_get(f"{base}/apps/{{app_id}}", fake.get_app)
    app.router.add_put(f"{base}/apps/{{app_id}}", fake.update_app)
    app.router.add_delete(f"{base}/apps/{{app_id}}", fake.delete_app)
    server = TestServer(app)
    await server.start_server()
    fake.server = server
    with (
        patch("custom_components.cloudflare_access_relay.cloudflare_api.API_URL", fake.base_url),
        patch("custom_components.cloudflare_access_relay.cloudflare_api.MAX_RETRIES", 0),
    ):
        yield fake
    await server.close()


# --------------------------------------------------------------------------- HA entry


def make_entry(**options: Any) -> MockConfigEntry:
    opts: dict[str, Any] = {
        CONF_HOSTNAME: HOSTNAME,
        CONF_ALLOWED_EMAILS: [ALICE, BOB],
        CONF_GATE_ENABLED: False,
        CONF_DELETE_OBJECTS_ON_REMOVE: True,
    }
    opts.update(options)
    return MockConfigEntry(
        domain=DOMAIN,
        title=HOSTNAME,
        unique_id=HOSTNAME,
        data={CONF_API_TOKEN: "cf-token", CONF_ACCOUNT_ID: ACCOUNT_ID},
        options=opts,
    )


@dataclass
class Access:
    entry: MockConfigEntry
    cloudflare: FakeCloudflare
    jwks: FakeJwks
    mint: Minter

    @property
    def aud(self) -> str:
        return self.mint.aud


@pytest.fixture
async def access(
    hass: HomeAssistant,
    fake_cloudflare: FakeCloudflare,
    jwks_server: FakeJwks,
    rsa_keys: dict[str, RsaKey],
) -> Access:
    """Set the integration up against the fake servers with the gate enabled."""
    entry = make_entry(**{CONF_GATE_ENABLED: True})
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    aud = entry.data["policy_aud"]
    return Access(entry, fake_cloudflare, jwks_server, Minter(rsa_keys, aud))


async def add_user(hass: HomeAssistant, username: str, *, name: str | None = None) -> User:
    """Create an HA user whose built-in credential username is `username`."""
    user = MockUser(name=name or username.split("@")[0]).add_to_hass(hass)
    cred = Credentials(
        auth_provider_type="homeassistant",
        auth_provider_id=None,
        data={"username": username},
        is_new=False,
    )
    await hass.auth.async_link_user(user, cred)
    return user


async def token_for(hass: HomeAssistant, user: User) -> str:
    refresh = await hass.auth.async_create_refresh_token(user, CLIENT_ID)
    return hass.auth.async_create_access_token(refresh)


@pytest.fixture
async def alice(hass: HomeAssistant) -> User:
    return await add_user(hass, ALICE, name="Alice")


@pytest.fixture
async def bob(hass: HomeAssistant) -> User:
    return await add_user(hass, BOB, name="Bob")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def no_socket_guard() -> Generator[None]:
    yield
