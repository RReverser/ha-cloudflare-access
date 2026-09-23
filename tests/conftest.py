"""Shared fixtures: RSA keys, a fake JWKS endpoint, a fake Cloudflare API."""

from __future__ import annotations

import base64
from collections.abc import Awaitable, Callable, Generator
import contextlib
from dataclasses import dataclass, field
import functools
import hashlib
import hmac
import json
import re
import socket
import time
from typing import Any
from unittest.mock import patch
import uuid

from cloudflare import AsyncCloudflare
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from homeassistant.auth.models import Credentials, User
from homeassistant.core import HomeAssistant
from homeassistant.helpers.httpx_client import DATA_ASYNC_CLIENT, create_async_httpx_client
from homeassistant.util.ssl import SSL_ALPN_HTTP11
import httpx
import jwt
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
import pytest_socket

from custom_components.cloudflare_access_relay.const import (
    CONF_ACCOUNT_ID,
    CONF_API_TOKEN,
    CONF_DELETE_OBJECTS_ON_REMOVE,
    CONF_GATE_ENABLED,
    DOMAIN,
)

TEAM_DOMAIN = "team.cloudflareaccess.com"
ISSUER = f"https://{TEAM_DOMAIN}"
HOSTNAME = "ha.example.com"
ACCOUNT_ID = "0123456789abcdef0123456789abcdef"
API_HOST = "api.cloudflare.com"
API_PREFIX = "/client/v4"
ALICE = "alice@example.com"
BOB = "bob@example.com"
CLIENT_ID = "https://ha.example.com/"


@pytest.fixture(autouse=True)
def external_url(hass: HomeAssistant) -> None:
    """The instance's External URL: the hostname the gate guards."""
    hass.config.external_url = f"https://{HOSTNAME}"


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(request: pytest.FixtureRequest) -> None:
    """Make custom_components discoverable whenever the HA plugin is active."""
    with contextlib.suppress(pytest.FixtureLookupError):
        request.getfixturevalue("enable_custom_integrations")


# --------------------------------------------------------------------------- transport

Handler = Callable[[httpx.Request], Awaitable[httpx.Response]]


def _json(data: Any, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=data)


@dataclass
class FakeInternet:
    """An httpx transport answering in-process, by host: no sockets, no servers.

    Installed as Home Assistant's shared httpx client, which is what the integration
    (the Cloudflare SDK through `http_client`, and the JWKS fetch) uses.
    """

    hosts: dict[str, Handler] = field(default_factory=dict)

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        handler = self.hosts.get(request.url.host)
        if handler is None:
            return httpx.Response(502, text=f"no fake for {request.url.host}")
        return await handler(request)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)


@pytest.fixture
def fake_internet(hass: HomeAssistant) -> FakeInternet:
    fake = FakeInternet()
    hass.data[DATA_ASYNC_CLIENT] = {
        (True, SSL_ALPN_HTTP11): create_async_httpx_client(hass, transport=fake.transport)
    }
    return fake


def _route(pattern: str) -> re.Pattern[str]:
    """`/apps/{app_id}` style patterns; `{tail:.*}` matches across slashes."""
    regex = re.sub(
        r"{(\w+)(:[^}]*)?}",
        lambda m: f"(?P<{m[1]}>.*)" if m[2] else f"(?P<{m[1]}>[^/]+)",
        pattern,
    )
    return re.compile(f"^{regex}$")


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

    async def handle(self, request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/cdn-cgi/access/certs", request.url
        self.fetches += 1
        if self.status != 200:
            return httpx.Response(self.status)
        keys = [self.keys[k].jwk() for k in self.published]
        return _json({"keys": keys, "public_cert": {}, "public_certs": []})


@pytest.fixture
def jwks_server(fake_internet: FakeInternet, rsa_keys: dict[str, RsaKey]) -> FakeJwks:
    """Serve the JWKS document at <team>.cloudflareaccess.com/cdn-cgi/access/certs."""
    fake = FakeJwks(rsa_keys)
    fake_internet.hosts[TEAM_DOMAIN] = fake.handle
    return fake


# --------------------------------------------------------------------------- Cloudflare


@dataclass
class FakeCloudflare:
    """Records every request; behaves like the Access applications API."""

    apps: dict[str, dict[str, Any]] = field(default_factory=dict)
    tags: set[str] = field(default_factory=set)
    secrets: dict[str, str] = field(default_factory=dict)
    requests: list[tuple[str, str, dict[str, Any] | None]] = field(default_factory=list)
    auth_fail: bool = False
    tokens_seen: set[str] = field(default_factory=set)
    accounts: dict[str, str] = field(default_factory=lambda: {ACCOUNT_ID: "Example"})
    org_auth_fail: bool = False
    fail_status: int | None = None
    fail_predicate: Callable[[str, str], bool] | None = None
    team_domain: str = TEAM_DOMAIN
    # zones of the account: a self-hosted application for a hostname outside them is refused
    zones: list[str] = field(default_factory=lambda: ["example.com"])
    # service tokens by id, without their secrets (which are returned once, at creation)
    service_tokens: dict[str, dict[str, Any]] = field(default_factory=dict)
    identity_providers: list[dict[str, Any]] = field(
        default_factory=lambda: [
            {"id": "otp-1", "name": "One-time PIN", "type": "onetimepin", "config": {}}
        ]
    )
    # addresses whose sessions were revoked, in order
    revoked: list[str] = field(default_factory=list)
    # authentication log entries, as Cloudflare would return them
    access_logs: list[dict[str, Any]] = field(default_factory=list)

    def writes(self, method: str | None = None) -> list[tuple[str, str, dict[str, Any] | None]]:
        """Application writes; the entry's tag (created once, never an edge change) is not one."""
        return [
            r
            for r in self.requests
            if r[0] in ("POST", "PUT", "DELETE")
            and (method is None or r[0] == method)
            and "/access/tags" not in r[1]
            and "/revoke_user" not in r[1]
        ]

    def by_name(self, name: str) -> dict[str, Any] | None:
        return next((a for a in self.apps.values() if a["name"] == name), None)

    def _fail(self, method: str, path: str) -> httpx.Response | None:
        if self.auth_fail:
            return _json(
                {
                    "success": False,
                    "errors": [{"code": 10000, "message": "Authentication error"}],
                    "result": None,
                },
                status=403,
            )
        if self.fail_status and (self.fail_predicate is None or self.fail_predicate(method, path)):
            return httpx.Response(self.fail_status, text="upstream error")
        return None

    def _ok(self, result: Any, status: int = 200, **extra: Any) -> httpx.Response:
        return _json(
            {"success": True, "errors": [], "messages": [], "result": result, **extra},
            status=status,
        )

    async def handle(self, request: httpx.Request) -> httpx.Response:
        """Dispatch like the API's router; paths are recorded without the /client/v4 prefix."""
        path = request.url.path.removeprefix(API_PREFIX)
        for method, pattern, handler in self.routes:
            if method == request.method and (match := pattern.match(path)):
                return await handler(request, **match.groupdict())
        return _json(
            {
                "success": False,
                "errors": [{"code": 7003, "message": f"no route for {request.method} {path}"}],
                "result": None,
            },
            status=404,
        )

    @functools.cached_property
    def routes(
        self,
    ) -> list[tuple[str, re.Pattern[str], Callable[..., Awaitable[httpx.Response]]]]:
        base = f"/accounts/{ACCOUNT_ID}/access"
        table: list[tuple[str, str, Callable[..., Awaitable[httpx.Response]]]] = [
            ("GET", "/memberships", self.list_memberships),
            ("GET", f"{base}/organizations", self.organizations),
            ("POST", f"{base}/organizations/revoke_user", self.revoke_user),
            ("GET", f"{base}/identity_providers", self.list_identity_providers),
            ("GET", f"{base}/logs/access_requests", self.list_access_logs),
            ("GET", f"{base}/service_tokens", self.list_service_tokens),
            ("POST", f"{base}/service_tokens", self.create_service_token),
            ("GET", f"{base}/service_tokens/{{token_id}}", self.get_service_token),
            ("PUT", f"{base}/service_tokens/{{token_id}}", self.update_service_token),
            ("DELETE", f"{base}/service_tokens/{{token_id}}", self.delete_service_token),
            ("POST", f"{base}/service_tokens/{{token_id}}/refresh", self.refresh_service_token),
            ("GET", f"{base}/tags", self.list_tags),
            ("POST", f"{base}/tags", self.create_tag),
            ("GET", f"{base}/tags/{{tag_name}}", self.get_tag),
            ("GET", f"{base}/apps", self.list_apps),
            ("POST", f"{base}/apps", self.create_app),
            ("GET", f"{base}/apps/{{app_id}}", self.get_app),
            ("PUT", f"{base}/apps/{{app_id}}", self.update_app),
            ("DELETE", f"{base}/apps/{{app_id}}", self.delete_app),
            ("GET", "/accounts/{account_id}/access/{tail:.*}", self.other_account),
        ]
        return [(m, _route(p), h) for m, p, h in table]

    def _record(self, request: httpx.Request) -> dict[str, Any] | None:
        body = json.loads(request.content) if request.content else None
        self.requests.append((request.method, request.url.path.removeprefix(API_PREFIX), body))
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            self.tokens_seen.add(auth.removeprefix("Bearer "))
        return body

    async def list_memberships(self, request: httpx.Request) -> httpx.Response:
        self._record(request)
        if fail := self._fail(request.method, request.url.path.removeprefix(API_PREFIX)):
            return fail
        page = int(request.url.params.get("page", "1"))
        per_page = int(request.url.params.get("per_page", "20"))
        rows = [
            {
                "id": f"m-{a}",
                "status": "accepted",
                "account": {"id": a, "name": n, "type": "standard"},
            }
            for a, n in self.accounts.items()
        ]
        return self._ok(
            rows[(page - 1) * per_page : page * per_page],
            result_info={
                "page": page,
                "per_page": per_page,
                "total_pages": max(1, -(-len(rows) // per_page)),
                "count": len(rows),
                "total_count": len(rows),
            },
        )

    async def other_account(
        self, request: httpx.Request, account_id: str, tail: str
    ) -> httpx.Response:
        """Any account but the one the fake serves: the credential is not granted there."""
        self._record(request)
        return _json(
            {
                "success": False,
                "errors": [{"code": 10000, "message": "Authentication error"}],
                "result": None,
            },
            status=403,
        )

    async def organizations(self, request: httpx.Request) -> httpx.Response:
        self._record(request)
        if fail := self._fail(request.method, request.url.path.removeprefix(API_PREFIX)):
            return fail
        if self.org_auth_fail:
            return _json(
                {
                    "success": False,
                    "errors": [{"code": 10000, "message": "Authentication error"}],
                    "result": None,
                },
                status=403,
            )
        return self._ok({"auth_domain": self.team_domain, "name": "Team"})

    async def list_apps(self, request: httpx.Request) -> httpx.Response:
        self._record(request)
        if fail := self._fail(request.method, request.url.path.removeprefix(API_PREFIX)):
            return fail
        # honour paging: the SDK keeps asking for the next page until one comes back empty
        page = int(request.url.params.get("page", "1"))
        per_page = int(request.url.params.get("per_page", "20"))
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

    def _foreign_domain(self, body: dict[str, Any]) -> httpx.Response | None:
        domain = body.get("domain")
        if domain is None or any(
            host == zone or host.endswith("." + zone)
            for host in [domain.split("/", 1)[0]]
            for zone in self.zones
        ):
            return None
        return _json(
            {
                "success": False,
                "errors": [
                    {
                        "code": 12130,
                        "message": "access.api.error.invalid_request: domain does not belong to zone",
                    }
                ],
                "result": None,
            },
            status=400,
        )

    def _unknown_tags(self, body: dict[str, Any]) -> httpx.Response | None:
        if unknown := set(body.get("tags") or []) - self.tags:
            return _json(
                {
                    "success": False,
                    "errors": [{"code": 12132, "message": f"unknown tag {sorted(unknown)}"}],
                    "result": None,
                },
                status=400,
            )
        return None

    def _token_not_found(self) -> httpx.Response:
        return _json(
            {"success": False, "errors": [{"code": 12130, "message": "not found"}], "result": None},
            status=404,
        )

    async def list_service_tokens(self, request: httpx.Request) -> httpx.Response:
        self._record(request)
        if fail := self._fail(request.method, request.url.path.removeprefix(API_PREFIX)):
            return fail
        page = int(request.url.params.get("page", "1"))
        return self._ok(list(self.service_tokens.values()) if page == 1 else [])

    async def create_service_token(self, request: httpx.Request) -> httpx.Response:
        body = self._record(request)
        if fail := self._fail(request.method, request.url.path.removeprefix(API_PREFIX)):
            return fail
        assert body is not None
        token_id = str(uuid.uuid4())
        self.service_tokens[token_id] = {
            "id": token_id,
            "name": body["name"],
            "client_id": f"{uuid.uuid4().hex}.access",
            "duration": body.get("duration", "8760h"),
            "expires_at": "2027-09-22T00:00:00Z",
            "created_at": "2026-09-22T00:00:00Z",
        }
        secret = uuid.uuid4().hex
        return self._ok({**self.service_tokens[token_id], "client_secret": secret}, status=201)

    async def get_service_token(self, request: httpx.Request, token_id: str) -> httpx.Response:
        self._record(request)
        if fail := self._fail(request.method, request.url.path.removeprefix(API_PREFIX)):
            return fail
        token = self.service_tokens.get(token_id)
        return self._ok(token) if token else self._token_not_found()

    async def update_service_token(self, request: httpx.Request, token_id: str) -> httpx.Response:
        body = self._record(request)
        if fail := self._fail(request.method, request.url.path.removeprefix(API_PREFIX)):
            return fail
        token = self.service_tokens.get(token_id)
        if token is None:
            return self._token_not_found()
        assert body is not None
        token.update({k: v for k, v in body.items() if k in ("name", "duration")})
        return self._ok(token)

    async def refresh_service_token(self, request: httpx.Request, token_id: str) -> httpx.Response:
        self._record(request)
        if fail := self._fail(request.method, request.url.path.removeprefix(API_PREFIX)):
            return fail
        token = self.service_tokens.get(token_id)
        if token is None:
            return self._token_not_found()
        year = int(token["expires_at"][:4]) + 1
        token["expires_at"] = f"{year}{token['expires_at'][4:]}"
        return self._ok(token)

    async def delete_service_token(self, request: httpx.Request, token_id: str) -> httpx.Response:
        self._record(request)
        if fail := self._fail(request.method, request.url.path.removeprefix(API_PREFIX)):
            return fail
        token_id = token_id
        if token_id not in self.service_tokens:
            return self._token_not_found()
        if any(
            r.get("service_token", {}).get("token_id") == token_id
            for app in self.apps.values()
            for pol in app.get("policies") or []
            for r in pol.get("include") or []
        ):
            return _json(
                {
                    "success": False,
                    "errors": [{"code": 12132, "message": "service token in use by a policy"}],
                    "result": None,
                },
                status=400,
            )
        return self._ok(self.service_tokens.pop(token_id))

    async def list_identity_providers(self, request: httpx.Request) -> httpx.Response:
        self._record(request)
        if fail := self._fail(request.method, request.url.path.removeprefix(API_PREFIX)):
            return fail
        page = int(request.url.params.get("page", "1"))
        return self._ok(self.identity_providers if page == 1 else [])

    async def revoke_user(self, request: httpx.Request) -> httpx.Response:
        body = self._record(request)
        if fail := self._fail(request.method, request.url.path.removeprefix(API_PREFIX)):
            return fail
        assert body is not None and body.get("email")
        self.revoked.append(body["email"])
        return self._ok(True)

    async def list_access_logs(self, request: httpx.Request) -> httpx.Response:
        self._record(request)
        if fail := self._fail(request.method, request.url.path.removeprefix(API_PREFIX)):
            return fail
        since = request.url.params.get("since")
        page = int(request.url.params.get("page", "1"))
        entries = sorted(
            (e for e in self.access_logs if not since or e["created_at"] > since),
            key=lambda e: e["created_at"],
        )
        return self._ok(entries if page == 1 else [])

    async def list_tags(self, request: httpx.Request) -> httpx.Response:
        self._record(request)
        return self._ok([{"name": t} for t in sorted(self.tags)])

    async def get_tag(self, request: httpx.Request, tag_name: str) -> httpx.Response:
        self._record(request)
        name = tag_name
        if name not in self.tags:
            return _json(
                {
                    "success": False,
                    "errors": [{"code": 12130, "message": "not found"}],
                    "result": None,
                },
                status=404,
            )
        return self._ok({"name": name})

    async def create_tag(self, request: httpx.Request) -> httpx.Response:
        body = self._record(request)
        if fail := self._fail(request.method, request.url.path.removeprefix(API_PREFIX)):
            return fail
        assert body is not None
        self.tags.add(body["name"])
        return self._ok({"name": body["name"]}, status=201)

    async def create_app(self, request: httpx.Request) -> httpx.Response:
        body = self._record(request)
        if fail := self._fail(request.method, request.url.path.removeprefix(API_PREFIX)):
            return fail
        assert body is not None
        if bad := self._unknown_tags(body) or self._foreign_domain(body):
            return bad
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

    async def get_app(self, request: httpx.Request, app_id: str) -> httpx.Response:
        self._record(request)
        if fail := self._fail(request.method, request.url.path.removeprefix(API_PREFIX)):
            return fail
        app = self.apps.get(app_id)
        if app is None:
            return _json(
                {
                    "success": False,
                    "errors": [{"code": 12130, "message": "not found"}],
                    "result": None,
                },
                status=404,
            )
        return self._ok(app)

    async def update_app(self, request: httpx.Request, app_id: str) -> httpx.Response:
        body = self._record(request)
        if fail := self._fail(request.method, request.url.path.removeprefix(API_PREFIX)):
            return fail
        app_id = app_id
        if app_id not in self.apps:
            return _json(
                {
                    "success": False,
                    "errors": [{"code": 12130, "message": "not found"}],
                    "result": None,
                },
                status=404,
            )
        assert body is not None
        if bad := self._unknown_tags(body) or self._foreign_domain(body):
            return bad
        self.apps[app_id] = self._stored(body, app_id, self.apps[app_id])
        return self._ok(self.apps[app_id])

    async def delete_app(self, request: httpx.Request, app_id: str) -> httpx.Response:
        self._record(request)
        if fail := self._fail(request.method, request.url.path.removeprefix(API_PREFIX)):
            return fail
        app_id = app_id
        if app_id not in self.apps:
            return _json(
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
def fake_cloudflare(fake_internet: FakeInternet) -> Generator[FakeCloudflare]:
    """The Cloudflare API at its real address, answered by the fake.

    The SDK validates every response against its own types (strict mode), so a shape
    the fake gets wrong fails the test instead of passing silently.
    """
    fake = FakeCloudflare()
    fake_internet.hosts[API_HOST] = fake.handle
    strict = functools.partial(AsyncCloudflare, _strict_response_validation=True)
    with (
        patch("custom_components.cloudflare_access_relay.cloudflare_api.AsyncCloudflare", strict),
        patch("custom_components.cloudflare_access_relay.cloudflare_api.MAX_RETRIES", 0),
    ):
        yield fake


# --------------------------------------------------------------------------- HA entry


def make_entry(**options: Any) -> MockConfigEntry:
    opts: dict[str, Any] = {
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
    alice: User,
    bob: User,
) -> Access:
    """Set the integration up against the fake servers with the gate enabled.

    Alice and Bob are the Home Assistant users, so they are the gate's allow policy.
    """
    entry = make_entry(**{CONF_GATE_ENABLED: True})
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    aud = entry.data["policy_aud"]
    return Access(entry, fake_cloudflare, jwks_server, Minter(rsa_keys, aud))


async def add_user(
    hass: HomeAssistant, username: str, *, name: str | None = None, person: bool = True
) -> User:
    """Create an HA user whose built-in credential username is `username`.

    Through the auth manager, as the UI does, so the user events fire. A person is
    linked to the user unless `person` is False (an add-on's API user, say).
    """
    from homeassistant.components.person import async_create_person
    from homeassistant.setup import async_setup_component

    user = await hass.auth.async_create_user(name or username.split("@")[0])
    cred = Credentials(
        auth_provider_type="homeassistant",
        auth_provider_id=None,
        data={"username": username},
        is_new=False,
    )
    await hass.auth.async_link_user(user, cred)
    if person:
        assert await async_setup_component(hass, "person", {})
        await async_create_person(hass, user.name or username, user_id=user.id)
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


# ---- talking to a real Cloudflare edge (tests/live, tests/rollout)


def is_access_redirect(resp: httpx.Response) -> bool:
    """Access's answer to an unauthenticated request.

    A redirect to the login page for a browser, or (managed OAuth) a 401 pointing a
    non-browser client at its OAuth metadata.
    """
    if resp.status_code == 401 and "www-authenticate" in resp.headers:
        return True
    return resp.status_code in (
        301,
        302,
        303,
        307,
    ) and ".cloudflareaccess.com/" in resp.headers.get("location", "")


@pytest.fixture
def internet() -> Generator[None]:
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
