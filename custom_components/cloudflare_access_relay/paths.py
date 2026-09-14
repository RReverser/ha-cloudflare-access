"""Derive, from Home Assistant's own router, the paths a client needs before it holds a cookie.

Two classes of core endpoints are reached by a client that cannot yet present the
Access cookie, and Home Assistant marks both in a machine-readable way:

- static files served from the frontend package (`hass_frontend`): the login page
  (`/auth/authorize`), its JavaScript bundles and static assets;
- views under `/auth/` that Home Assistant registers with `requires_auth = False`:
  the login flow, the provider list and the token endpoint.

Everything else that skips Home Assistant's HTTP authentication (the WebSocket, webhooks,
the frontend index) is reached by clients that do hold the cookie, and stays gated.
"""

from __future__ import annotations

from functools import partial
import inspect
from pathlib import Path

from aiohttp.web_urldispatcher import StaticResource
from homeassistant.core import HomeAssistant
from homeassistant.helpers.http import HomeAssistantView

LOGIN_PREFIX = "/auth/"


def _frontend_root() -> Path | None:
    try:
        import hass_frontend
    except ImportError:  # pragma: no cover - the frontend is a dependency of this integration
        return None
    return Path(hass_frontend.where()).resolve()


def _inside(path: object, root: Path) -> bool:
    try:
        return Path(str(path)).resolve().is_relative_to(root)
    except OSError, ValueError:
        return False


def _static_prefix(canonical: str) -> str:
    """Return the fixed part of a route pattern (`/auth/login_flow/{flow_id}` -> `/auth/login_flow`)."""
    return canonical.split("{", 1)[0].rstrip("/") or "/"


def _view_of(handler: object) -> HomeAssistantView | None:
    try:
        view = inspect.getclosurevars(handler).nonlocals.get("view")  # type: ignore[arg-type]
    except TypeError, ValueError:
        return None
    return view if isinstance(view, HomeAssistantView) else None


def discover_login_paths(hass: HomeAssistant) -> list[str]:
    """Return the sorted path prefixes a cookie-less client must be able to reach."""
    root = _frontend_root()
    found: set[str] = set()
    for resource in hass.http.app.router.resources():
        canonical = resource.canonical
        if isinstance(resource, StaticResource):
            if root and _inside(getattr(resource, "_directory", ""), root):
                found.add(_static_prefix(canonical))
            continue
        for route in resource:
            handler = route.handler
            if isinstance(handler, partial):
                if root and handler.args and _inside(handler.args[0], root):
                    found.add(_static_prefix(canonical))
                continue
            view = _view_of(handler)
            if view is not None and not view.requires_auth and canonical.startswith(LOGIN_PREFIX):
                found.add(_static_prefix(canonical))
    return collapse_prefixes(found)


def collapse_prefixes(paths: set[str]) -> list[str]:
    """Drop paths already covered by a shorter prefix; Access inherits rules downwards."""
    result: list[str] = []
    for path in sorted(paths):
        if not any(path == kept or path.startswith(kept + "/") for kept in result):
            result.append(path)
    return result
