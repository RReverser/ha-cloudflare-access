"""Edge identity for token-bearing clients.

The whole hostname is gated by Access. A client that cannot hold the Access cookie
(Google's and Amazon's servers, MCP clients, scripts) authenticates with Access
instead: it obtains a token from Access, through managed OAuth or through a
registration made by this integration, and presents it as a bearer. Access validates
that token at the edge and forwards the request with the signed assertion it
forwards for a browser session.

Home Assistant does not know such a bearer. This middleware recognises the case
(request through the edge, a bearer Home Assistant did not accept, a valid Access
assertion), maps the Access identity to the Home Assistant user the options
describe, and authenticates the request as that user. Nothing else is touched: a
request without a bearer, or with a Home Assistant token, is left to Home Assistant.
Requests on the local network never see the rule.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import TYPE_CHECKING

from aiohttp import hdrs, web, web_app
from aiohttp.typedefs import Handler
from homeassistant.components.http.ban import process_wrong_login
from homeassistant.components.http.const import KEY_HASS_USER
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.http import KEY_AUTHENTICATED, KEY_HASS
from homeassistant.util.hass_dict import HassKey

from .const import (
    CLAIM_COMMON_NAME,
    CLAIM_EMAIL,
    CONF_HOSTNAME,
    DOMAIN,
    HEADER_CF_RAY,
    HEADER_JWT,
    ISSUE_MIDDLEWARE_UNAVAILABLE,
)
from .jwks import JwtVerifyError
from .users import async_find_user, login_emails

if TYPE_CHECKING:
    from . import EntryData

_LOGGER = logging.getLogger(__name__)

_MIDDLEWARE_INSTALLED: HassKey[bool] = HassKey(f"{DOMAIN}_middleware")


@dataclass
class _Ctx:
    hass: HomeAssistant
    data: EntryData


def entry_for(request: web.Request) -> _Ctx | None:
    """Pick the entry serving this request's host (or the only entry)."""
    hass: HomeAssistant = request.app[KEY_HASS]
    loaded: list[EntryData] = [
        entry.runtime_data for entry in hass.config_entries.async_loaded_entries(DOMAIN)
    ]
    if not loaded:
        return None
    host = request.host.split(":")[0].lower()
    for data in loaded:
        if data.options[CONF_HOSTNAME].lower() == host:
            return _Ctx(hass, data)
    if len(loaded) == 1:
        return _Ctx(hass, loaded[0])
    return None


def _via_edge(request: web.Request, hostname: str) -> bool:
    """Return whether the request came through Cloudflare for the gated hostname."""
    if HEADER_CF_RAY not in request.headers:
        return False
    return request.host.split(":")[0].lower() == hostname.lower()


async def _reject(request: web.Request, reason: str) -> web.Response:
    """Refuse the request; it counts as a failed login, like a bad bearer does in core."""
    _LOGGER.info("Rejected edge-authenticated bearer on %s: %s", request.path, reason)
    await process_wrong_login(request)
    return web.json_response(
        {"message": f"Cloudflare Access identity not accepted: {reason}"},
        status=401,
        headers={"Cache-Control": "no-store"},
    )


@web.middleware
async def _middleware(request: web.Request, handler: Handler) -> web.StreamResponse:
    if request.get(KEY_AUTHENTICATED) or not request.headers.get(hdrs.AUTHORIZATION, "").startswith(
        "Bearer "
    ):
        return await handler(request)
    ctx = entry_for(request)
    if ctx is None or ctx.data.policy_aud is None:
        return await handler(request)
    if not _via_edge(request, ctx.data.options[CONF_HOSTNAME]):
        return await handler(request)
    assertion = request.headers.get(HEADER_JWT)
    if not assertion:
        return await handler(request)
    try:
        claims = await ctx.data.verifier.verify(assertion, ctx.data.policy_aud)
    except JwtVerifyError as err:
        return await _reject(request, f"the Access assertion did not verify ({err})")
    # An identity-provider login is named by its e-mail address; a service token has no
    # address and is named by its common name.
    identity = claims.get(CLAIM_EMAIL) or claims.get(CLAIM_COMMON_NAME)
    if not isinstance(identity, str) or not identity:
        return await _reject(
            request, f"the assertion carries neither {CLAIM_EMAIL} nor {CLAIM_COMMON_NAME}"
        )
    user = await async_find_user(ctx.hass, login_emails(ctx.data.entry), identity)
    if user is None:
        return await _reject(request, f"no single Home Assistant user is {identity!r}")
    request[KEY_AUTHENTICATED] = True
    request[KEY_HASS_USER] = user
    _LOGGER.debug("Authenticated %s as %s via the Access assertion", request.path, user.name)
    return await handler(request)


@callback
def async_install_middleware(hass: HomeAssistant) -> bool:
    """Install the middleware once per run; False when the web server cannot take it.

    Home Assistant starts its web server as soon as the frontend is up, before any
    config entry loads, and aiohttp freezes an application's middleware list when the
    server starts. So the list is always frozen here, and the middleware goes into the
    chain aiohttp prepared instead (`_inject`).
    """
    if hass.data.get(_MIDDLEWARE_INSTALLED):
        return True
    app = hass.http.app
    if not app.frozen:
        app.middlewares.append(_middleware)
    elif not _inject(app):
        ir.async_create_issue(
            hass,
            DOMAIN,
            ISSUE_MIDDLEWARE_UNAVAILABLE,
            is_fixable=False,
            severity=ir.IssueSeverity.ERROR,
            translation_key=ISSUE_MIDDLEWARE_UNAVAILABLE,
        )
        return False
    hass.data[_MIDDLEWARE_INSTALLED] = True
    ir.async_delete_issue(hass, DOMAIN, ISSUE_MIDDLEWARE_UNAVAILABLE)
    return True


def _inject(app: web.Application) -> bool:
    """Add the middleware to a started application's prepared chain.

    aiohttp keeps the chain in the application's `_middlewares_handlers`, innermost
    first, and caches the chain it builds per handler; both are private, so they are
    checked before use and the tests install into a started server, where an aiohttp
    that moved them fails the suite. Innermost is the right place: Home Assistant's
    own authentication has run by then, and the rule only acts where it declined.
    """
    handlers = getattr(app, "_middlewares_handlers", None)
    cache_clear = getattr(getattr(web_app, "_cached_build_middleware", None), "cache_clear", None)
    if not isinstance(handlers, tuple) or not callable(cache_clear):
        return False
    app._middlewares_handlers = ((_middleware, True), *handlers)
    app._run_middlewares = True
    cache_clear()
    return True
