"""Access-bound Home Assistant tokens.

Paths that Cloudflare Access does not gate (the bypass application: everything the
router serves without a session, plus the vendor endpoints Google, Alexa and MCP
clients call with a bearer token) are reached by requests that carry no Access
identity. On those requests a Home Assistant bearer token is accepted only if it is
*bound*: its refresh token was issued by a login whose final step carried a valid
Access token, i.e. by a browser that had already passed Access. Every other request
through the edge either carries an Access token itself, or is rejected here.

The rule applies uniformly: no client id and no path is named. A cookie-less login
(the companion app's first sign-in) simply yields an unbound token, which the app
never uses without the cookie it gains from the relay.

The check only runs on requests that came through the edge for the configured
hostname; requests on the local network are untouched.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import logging
import time
from typing import Any

from aiohttp import hdrs, web
from aiohttp.typedefs import Handler
from homeassistant.components.http.const import KEY_HASS_REFRESH_TOKEN_ID
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.storage import Store

from .const import (
    AUTH_CODE_TTL_SECONDS,
    CONF_COOKIE_NAME,
    CONF_HOSTNAME,
    CONF_REQUIRE_BOUND_TOKENS,
    DOMAIN,
    HEADER_CF_RAY,
    HEADER_JWT,
    ISSUE_RESTART_REQUIRED,
    STORAGE_KEY_BOUND,
    STORAGE_VERSION_BOUND,
)
from .jwks import JwtVerifyError
from .paths import view_of
from .views import _relay_data

_LOGGER = logging.getLogger(__name__)

_MIDDLEWARE_INSTALLED = f"{DOMAIN}_middleware"
_LOGIN_FLOW_PREFIX = "/auth/login_flow/"
_TOKEN_PATH = "/auth/token"


@dataclass
class BoundTokens:
    """Refresh-token ids issued under an Access identity, persisted across restarts."""

    hass: HomeAssistant
    ids: set[str] = field(default_factory=set)
    _codes: dict[str, float] = field(default_factory=dict)
    _store: Store[dict[str, Any]] = field(init=False)

    def __post_init__(self) -> None:
        """Open the store."""
        self._store = Store(self.hass, STORAGE_VERSION_BOUND, STORAGE_KEY_BOUND)

    async def async_load(self) -> None:
        """Load the persisted ids and drop the ones whose refresh token is gone."""
        data = await self._store.async_load() or {}
        loaded = {str(i) for i in data.get("refresh_token_ids") or []}
        self.ids = {i for i in loaded if self.hass.auth.async_get_refresh_token(i)}
        if self.ids != loaded:
            await self._async_save()

    async def _async_save(self) -> None:
        await self._store.async_save({"refresh_token_ids": sorted(self.ids)})

    def is_bound(self, refresh_token_id: str) -> bool:
        """Return whether the refresh token was issued under an Access identity."""
        return refresh_token_id in self.ids

    async def async_bind(self, refresh_token_id: str) -> None:
        """Record a refresh token as Access-bound."""
        if refresh_token_id not in self.ids:
            self.ids.add(refresh_token_id)
            await self._async_save()

    def remember_code(self, code: str) -> None:
        """Remember an authorization code that a login under Access produced."""
        now = time.monotonic()
        self._codes = {c: t for c, t in self._codes.items() if t > now}
        self._codes[code] = now + AUTH_CODE_TTL_SECONDS

    def pop_code(self, code: str) -> bool:
        """Return whether the code came from a login under Access; forget it."""
        return self._codes.pop(code, 0.0) > time.monotonic()


def _via_edge(request: web.Request, hostname: str) -> bool:
    """Return whether the request came through Cloudflare for the gated hostname."""
    if HEADER_CF_RAY not in request.headers:
        return False
    return request.host.split(":")[0].lower() == hostname.lower()


def _bearer(request: web.Request) -> bool:
    return request.headers.get(hdrs.AUTHORIZATION, "").startswith("Bearer ")


def _json_body(response: web.StreamResponse) -> dict[str, Any] | None:
    if not isinstance(response, web.Response) or response.status != 200:
        return None
    if not (response.content_type or "").startswith("application/json"):
        return None
    try:
        body = json.loads(response.body or b"")  # type: ignore[arg-type]
    except TypeError, ValueError:
        return None
    return body if isinstance(body, dict) else None


async def _carries_access_token(request: web.Request, data: Any) -> bool:
    """Return whether the request presents a valid Access token (header or cookie)."""
    token = request.headers.get(HEADER_JWT) or request.cookies.get(data.options[CONF_COOKIE_NAME])
    if not token:
        return False
    try:
        await data.verifier.verify(token, data.policy_aud)
    except JwtVerifyError as err:
        _LOGGER.debug("Access token on %s not accepted: %s", request.path, err)
        return False
    return True


def _reject(request: web.Request, client_id: str | None) -> web.Response:
    _LOGGER.info(
        "Rejected bearer token for client %s on %s: not issued under a Cloudflare Access "
        "identity and the request carries none; sign in again through %s",
        client_id or "?",
        request.path,
        request.host,
    )
    return web.json_response(
        {
            "message": "This token was not issued under a Cloudflare Access identity. "
            "Sign in again through the public hostname, or present the Access token."
        },
        status=401,
        headers={"Cache-Control": "no-store"},
    )


@web.middleware
async def _middleware(request: web.Request, handler: Handler) -> web.StreamResponse:
    ctx = _relay_data(request)
    if ctx is None or not ctx.data.options.get(CONF_REQUIRE_BOUND_TOKENS, True):
        return await handler(request)
    data = ctx.data
    if not _via_edge(request, data.options[CONF_HOSTNAME]):
        return await handler(request)

    if request.method == "POST" and request.path.startswith(_LOGIN_FLOW_PREFIX):
        # The final login step returns the authorization code; remember it when the
        # browser proved an Access identity.
        under_access = await _carries_access_token(request, data)
        response = await handler(request)
        body = _json_body(response)
        if under_access and body and body.get("type") == "create_entry":
            code = body.get("result")
            if isinstance(code, str) and code:
                data.bound.remember_code(code)
        return response

    if request.method == "POST" and request.path == _TOKEN_PATH:
        form = await request.post()
        response = await handler(request)
        if form.get("grant_type") == "authorization_code":
            body = _json_body(response)
            code = form.get("code")
            if body and isinstance(code, str) and data.bound.pop_code(code):
                token = body.get("refresh_token")
                refresh = (
                    ctx.hass.auth.async_get_refresh_token_by_token(token)
                    if isinstance(token, str)
                    else None
                )
                if refresh is not None:
                    await data.bound.async_bind(refresh.id)
        return response

    refresh_token_id = request.get(KEY_HASS_REFRESH_TOKEN_ID)
    if refresh_token_id and _bearer(request):
        view = view_of(request.match_info.handler)
        exempt = bool(getattr(view, "access_bound_exempt", False))
        if (
            not exempt
            and not data.bound.is_bound(refresh_token_id)
            and not await _carries_access_token(request, data)
        ):
            refresh = ctx.hass.auth.async_get_refresh_token(refresh_token_id)
            return _reject(request, refresh.client_id if refresh else None)
    return await handler(request)


@callback
def async_install_middleware(hass: HomeAssistant) -> bool:
    """Install the middleware once per run; False when the server already started."""
    if hass.data.get(_MIDDLEWARE_INSTALLED):
        return True
    app = hass.http.app
    if app.frozen:
        ir.async_create_issue(
            hass,
            DOMAIN,
            ISSUE_RESTART_REQUIRED,
            is_fixable=False,
            severity=ir.IssueSeverity.WARNING,
            translation_key=ISSUE_RESTART_REQUIRED,
        )
        return False
    app.middlewares.append(_middleware)
    hass.data[_MIDDLEWARE_INSTALLED] = True
    ir.async_delete_issue(hass, DOMAIN, ISSUE_RESTART_REQUIRED)
    return True
