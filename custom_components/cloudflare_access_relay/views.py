"""HTTP views of the relay."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from pathlib import Path
import time
from typing import TYPE_CHECKING, Any

from aiohttp import web
from homeassistant.auth.models import User
from homeassistant.components import persistent_notification
from homeassistant.components.http.const import KEY_HASS_USER
from homeassistant.core import HomeAssistant
from homeassistant.helpers.http import KEY_HASS, HomeAssistantView

from . import pages
from .const import (
    API_FLOW,
    API_SESSION,
    API_STATUS,
    CONF_CHECK_INTERVAL_MIN,
    CONF_COOKIE_NAME,
    CONF_HOSTNAME,
    CONF_IDENTITY_CLAIM,
    CONF_RENEW_DAYS,
    CONF_USER_MATCH,
    DOMAIN,
    HEADER_CF_RAY,
    HEADER_JWT,
    NOTIFICATION_ID_ERROR,
    NOTIFICATION_ID_RENEW,
    URL_CALLBACK,
    URL_CONNECT,
    USER_MATCH_NAME,
)
from .jwks import JwtVerifyError, unverified_claims

if TYPE_CHECKING:
    from . import RelayData

_LOGGER = logging.getLogger(__name__)
_NO_STORE = {"Cache-Control": "no-store"}


@dataclass
class _Ctx:
    hass: HomeAssistant
    data: RelayData


def _relay_data(request: web.Request) -> _Ctx | None:
    """Pick the entry serving this request's host (or the only entry)."""
    hass: HomeAssistant = request.app[KEY_HASS]
    entries: dict[str, RelayData] = hass.data.get(DOMAIN) or {}
    if not entries:
        return None
    host = request.host.split(":")[0].lower()
    for data in entries.values():
        if data.options[CONF_HOSTNAME].lower() == host:
            return _Ctx(hass, data)
    if len(entries) == 1:
        return _Ctx(hass, next(iter(entries.values())))
    return None


def user_matches(user: User, mode: str, value: str) -> bool:
    """Return whether the identity claim value belongs to the HA user.

    `mode` is "name" (the user's display name) or the key of a credential data
    field, such as "username" (the built-in provider) or "email" (OIDC providers
    that store it).
    """
    wanted = value.strip().casefold()
    if not wanted:
        return False
    if mode == USER_MATCH_NAME:
        return (user.name or "").strip().casefold() == wanted
    for cred in user.credentials:
        stored = cred.data.get(mode)
        if isinstance(stored, str) and stored.strip().casefold() == wanted:
            return True
    return False


def _html(text: str, status: int = 200) -> web.Response:
    return web.Response(text=text, status=status, content_type="text/html", headers=_NO_STORE)


class FlowCreateView(HomeAssistantView):
    """Create a relay flow bound to the calling user."""

    url = API_FLOW
    name = f"api:{DOMAIN}:flow"
    requires_auth = True
    # Reached by the connect page with a token the device holds before it has a cookie.
    access_bound_exempt = True

    async def post(self, request: web.Request) -> web.Response:
        """Return a new flow id and the callback path to visit."""
        ctx = _relay_data(request)
        if ctx is None:
            return self.json_message("relay not configured", 503)
        user: User = request[KEY_HASS_USER]
        flow_id = ctx.data.flows.create(user.id)
        return self.json(
            {"flow": flow_id, "callback": f"{URL_CALLBACK}?flow={flow_id}"},
            headers=_NO_STORE,
        )


class StatusView(HomeAssistantView):
    """Poll a flow; release the captured token once, as a cookie."""

    url = API_STATUS
    name = f"api:{DOMAIN}:status"
    requires_auth = True
    # Reached by the connect page with a token the device holds before it has a cookie.
    access_bound_exempt = True

    async def get(self, request: web.Request) -> web.Response:
        """Return {"ok": false} until the callback filled the flow."""
        ctx = _relay_data(request)
        if ctx is None:
            return self.json_message("relay not configured", 503)
        flow_id = request.query.get("flow", "")
        if not flow_id:
            return self.json_message("missing flow", 400)
        flow = ctx.data.flows.get(flow_id)
        if flow is None:
            return self.json_message("unknown or expired flow", 404)
        user: User = request[KEY_HASS_USER]
        if flow.user_id != user.id:
            return self.json_message("flow belongs to another user", 403)
        if flow.jwt is None or flow.exp is None:
            return self.json({"ok": False}, headers=_NO_STORE)
        token, exp = flow.jwt, flow.exp
        ctx.data.flows.discard(flow_id)
        response = self.json({"ok": True, "exp": exp}, headers=_NO_STORE)
        response.set_cookie(
            ctx.data.options[CONF_COOKIE_NAME],
            token,
            max_age=max(0, exp - int(time.time())),
            path="/",
            secure=True,
            httponly=True,
            samesite="Lax",
        )
        _LOGGER.info("Released Access token to user %s (exp %s)", user.id, exp)
        return response


class SessionView(HomeAssistantView):
    """Report the expiry of the Access cookie the client holds."""

    url = API_SESSION
    name = f"api:{DOMAIN}:session"
    requires_auth = True
    # Reached by the connect page with a token the device holds before it has a cookie.
    access_bound_exempt = True

    async def get(self, request: web.Request) -> web.Response:
        """Return expiry and context flags; never the token."""
        ctx = _relay_data(request)
        if ctx is None:
            return self.json_message("relay not configured", 503)
        opts = ctx.data.options
        cookie = request.cookies.get(opts[CONF_COOKIE_NAME])
        exp: int | None = None
        if cookie:
            claims = unverified_claims(cookie)
            if claims and _aud_matches(claims.get("aud"), ctx.data.policy_aud):
                raw_exp = claims.get("exp")
                if isinstance(raw_exp, int | float):
                    exp = int(raw_exp)
        now = int(time.time())
        renew_days = int(opts[CONF_RENEW_DAYS])
        renew = exp is not None and exp - now < renew_days * 86400
        via_cloudflare = HEADER_CF_RAY in request.headers
        host_match = request.host.split(":")[0].lower() == opts[CONF_HOSTNAME].lower()
        in_app = request.query.get("app") == "1"
        if in_app and via_cloudflare and host_match:
            _update_renew_notification(ctx.hass, exp, renew)
        return self.json(
            {
                "exp": exp,
                "renew": renew,
                "cloudflare": via_cloudflare,
                "host_match": host_match,
                "renew_days": renew_days,
                "check_interval_min": int(opts[CONF_CHECK_INTERVAL_MIN]),
                "connect_url": URL_CONNECT,
            },
            headers=_NO_STORE,
        )


def _aud_matches(aud: Any, wanted: str) -> bool:
    if isinstance(aud, str):
        return aud == wanted
    if isinstance(aud, list):
        return wanted in aud
    return False


def _update_renew_notification(hass: HomeAssistant, exp: int | None, renew: bool) -> None:
    if exp is None or renew:
        when = (
            "has no Cloudflare Access session"
            if exp is None
            else f"Cloudflare Access session expires at {time.strftime('%Y-%m-%d %H:%M', time.localtime(exp))}"
        )
        persistent_notification.async_create(
            hass,
            f"The companion app {when}. Open the app; the connect page appears "
            f"automatically, or open [the connect page]({URL_CONNECT}) yourself.",
            title="Cloudflare Access relay",
            notification_id=NOTIFICATION_ID_RENEW,
        )
    else:
        persistent_notification.async_dismiss(hass, NOTIFICATION_ID_RENEW)


class CallbackView(HomeAssistantView):
    """Gated path: Access forwards the JWT here after the browser login."""

    url = URL_CALLBACK
    name = f"{DOMAIN}:callback"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Verify the forwarded token and file it under the flow."""
        ctx = _relay_data(request)
        if ctx is None:
            return _html(pages.callback_error("Relay not available", "", pages.HINT_DISABLED), 503)
        flow_id = request.query.get("flow", "")
        token = request.headers.get(HEADER_JWT)
        if not token:
            _LOGGER.info("Callback without %s header (flow %s)", HEADER_JWT, flow_id[:8])
            return _html(
                pages.callback_error(
                    "Not behind Cloudflare Access",
                    "The request reached Home Assistant without an Access token.",
                    pages.HINT_NO_HEADER,
                ),
                403,
            )
        flow = ctx.data.flows.get(flow_id) if flow_id else None
        if flow is None or flow.jwt is not None:
            _LOGGER.info("Callback for unknown, used or expired flow %s", flow_id[:8])
            return _html(
                pages.callback_error(
                    "Unknown connect attempt",
                    "This link is not tied to a live connect attempt.",
                    pages.HINT_UNKNOWN_FLOW,
                ),
                404,
            )
        try:
            claims = await ctx.data.verifier.verify(token, ctx.data.policy_aud)
        except JwtVerifyError as err:
            _LOGGER.info("Rejected Access token: %s (kid %s)", err.reason, err.kid)
            _notify_error(ctx.hass, f"Rejected an Access token: {err.reason} (kid {err.kid}).")
            return _html(
                pages.callback_error(
                    "Token rejected", f"Reason: {err.reason}.", pages.HINT_REJECTED
                ),
                403,
            )
        claim_name = ctx.data.options[CONF_IDENTITY_CLAIM]
        identity = claims.get(claim_name)
        user = await ctx.hass.auth.async_get_user(flow.user_id)
        if (
            not isinstance(identity, str)
            or user is None
            or not user_matches(user, ctx.data.options[CONF_USER_MATCH], identity)
        ):
            _LOGGER.info(
                "Identity claim %r=%r does not match HA user %s", claim_name, identity, flow.user_id
            )
            _notify_error(
                ctx.hass,
                f"Access identity {claim_name}={identity!r} does not match the Home Assistant user who started the connect attempt.",
            )
            return _html(
                pages.callback_error(
                    "Identity mismatch",
                    f"Cloudflare Access reported {claim_name} = {identity!r}.",
                    pages.HINT_IDENTITY,
                ),
                403,
            )
        flow.jwt = token
        flow.exp = int(claims["exp"])
        persistent_notification.async_dismiss(ctx.hass, NOTIFICATION_ID_ERROR)
        _LOGGER.info("Captured Access token for user %s (exp %s)", flow.user_id, flow.exp)
        return _html(pages.callback_success(flow_id))


def _notify_error(hass: HomeAssistant, message: str) -> None:
    persistent_notification.async_create(
        hass,
        message + " The token itself is never logged.",
        title="Cloudflare Access relay: verification failed",
        notification_id=NOTIFICATION_ID_ERROR,
    )


class ConnectView(HomeAssistantView):
    """Bypassed page that drives the connect flow inside the app's WebView."""

    url = URL_CONNECT
    name = f"{DOMAIN}:connect"
    requires_auth = False

    def __init__(self, www_dir: Path) -> None:
        """Remember where connect.html lives."""
        self._path = www_dir / "connect.html"
        self._cache: str | None = None

    async def get(self, request: web.Request) -> web.Response:
        """Serve the connect page."""
        if self._cache is None:
            hass: HomeAssistant = request.app[KEY_HASS]
            self._cache = await hass.async_add_executor_job(self._path.read_text, "utf-8")
        return _html(self._cache)
