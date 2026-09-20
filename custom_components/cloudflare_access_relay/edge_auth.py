"""Edge identity for token-bearing clients.

Every path that requires a Home Assistant session is gated by Access. A client that
cannot hold the Access cookie (Google's and Amazon's servers, MCP clients, scripts)
authenticates with Access instead: it obtains a token from Access, through managed
OAuth or through a registration made by this integration, and presents it as a
bearer. Access validates that token at the edge and forwards the request with the
signed assertion it forwards for a browser session.

Home Assistant does not know such a bearer. This middleware recognises the case
(request through the edge, a bearer Home Assistant did not accept, a valid Access
assertion), maps the Access identity to the Home Assistant user the options
describe, and authenticates the request as that user. Nothing else is touched: a
request without a bearer, or with a Home Assistant token, is left to Home Assistant.
Requests on the local network never see the rule.
"""

from __future__ import annotations

import logging

from aiohttp import hdrs, web
from aiohttp.typedefs import Handler
from homeassistant.components.http.const import KEY_HASS_USER
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.http import KEY_AUTHENTICATED

from .const import (
    CONF_HOSTNAME,
    CONF_IDENTITY_CLAIM,
    CONF_USER_MATCH,
    DOMAIN,
    HEADER_CF_RAY,
    HEADER_JWT,
    ISSUE_RESTART_REQUIRED,
)
from .jwks import JwtVerifyError
from .views import _relay_data, user_matches

_LOGGER = logging.getLogger(__name__)

_MIDDLEWARE_INSTALLED = f"{DOMAIN}_middleware"


def _via_edge(request: web.Request, hostname: str) -> bool:
    """Return whether the request came through Cloudflare for the gated hostname."""
    if HEADER_CF_RAY not in request.headers:
        return False
    return request.host.split(":")[0].lower() == hostname.lower()


def _reject(request: web.Request, reason: str) -> web.Response:
    _LOGGER.info("Rejected edge-authenticated bearer on %s: %s", request.path, reason)
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
    ctx = _relay_data(request)
    if ctx is None or not _via_edge(request, ctx.data.options[CONF_HOSTNAME]):
        return await handler(request)
    assertion = request.headers.get(HEADER_JWT)
    if not assertion:
        return await handler(request)
    options = ctx.data.options
    try:
        claims = await ctx.data.verifier.verify(assertion, ctx.data.policy_aud)
    except JwtVerifyError as err:
        return _reject(request, f"the Access assertion did not verify ({err})")
    claim_name = options[CONF_IDENTITY_CLAIM]
    identity = claims.get(claim_name)
    if not isinstance(identity, str) or not identity:
        return _reject(request, f"the assertion carries no {claim_name} claim")
    mode = options[CONF_USER_MATCH]
    user = next(
        (
            u
            for u in await ctx.hass.auth.async_get_users()
            if u.is_active and not u.system_generated and user_matches(u, mode, identity)
        ),
        None,
    )
    if user is None:
        return _reject(request, f"no Home Assistant user has {mode} = {identity!r}")
    request[KEY_AUTHENTICATED] = True
    request[KEY_HASS_USER] = user
    _LOGGER.debug("Authenticated %s as %s via the Access assertion", request.path, user.name)
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
