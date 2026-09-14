"""Derive, from Home Assistant's own router, the paths a client reaches without a cookie.

Home Assistant marks the endpoints it serves to clients that have no Home Assistant
session, and such clients cannot present the Access cookie either:

- views registered with `requires_auth = False`: the login flow, provider list and
  token endpoint, OAuth callbacks and discovery documents, webhooks, the TTS, stream
  and image proxies fetched by media players, integration-specific inbound endpoints.
  Each carries its own protection (a webhook id, a signed URL, a shared secret);
- static files an integration serves from its own package directory: the frontend's
  login page and bundles, a login integration's pages and scripts. User content mounted
  from the configuration directory (`/local`, `/hacsfiles`) is not code and stays gated.

A few unauthenticated views are entry points of the frontend session rather than
endpoints for outside callers (the WebSocket, onboarding, the Supervisor proxy and
ingress, map tiles, the manifest); those are listed in `GATED_OPEN_PATHS` and stay
gated, as does the relay's own callback. Server-to-server callers that authenticate
with a Home Assistant token (Google Assistant, Alexa) look like any other API view here
and are declared separately.
"""

from __future__ import annotations

from functools import partial
import inspect
from pathlib import Path

from aiohttp.web_urldispatcher import StaticResource
import homeassistant.components
from homeassistant.core import HomeAssistant
from homeassistant.helpers.http import HomeAssistantView

from .const import GATED_OPEN_PATHS


def _package_roots(hass: HomeAssistant) -> list[Path]:
    """Directories whose files are integration code rather than user content."""
    roots = [
        Path(homeassistant.components.__file__).parent.resolve(),
        Path(hass.config.path("custom_components")).resolve(),
    ]
    # Where custom integrations are actually imported from: the same directory in a
    # normal install, the checkout under a test harness.
    import custom_components

    roots.extend(Path(p).resolve() for p in custom_components.__path__)
    try:
        import hass_frontend
    except ImportError:  # pragma: no cover - the frontend is a dependency of this integration
        pass
    else:
        roots.append(Path(hass_frontend.where()).resolve())
    return roots


def _inside_any(path: object, roots: list[Path]) -> bool:
    try:
        resolved = Path(str(path)).resolve()
    except OSError, ValueError:
        return False
    return any(resolved.is_relative_to(root) for root in roots)


def _static_prefix(canonical: str) -> str:
    """Return the fixed part of a route pattern (`/auth/login_flow/{flow_id}` -> `/auth/login_flow`)."""
    return canonical.split("{", 1)[0].rstrip("/") or "/"


def view_of(handler: object) -> HomeAssistantView | None:
    """Return the HomeAssistantView behind a registered route handler, if any."""
    try:
        view = inspect.getclosurevars(handler).nonlocals.get("view")  # type: ignore[arg-type]
    except TypeError, ValueError:
        return None
    return view if isinstance(view, HomeAssistantView) else None


def is_gated_anyway(path: str) -> bool:
    """Return whether a path is a frontend-session surface that stays gated."""
    return any(path == g or path.startswith(g + "/") for g in GATED_OPEN_PATHS)


def discover_open_paths(hass: HomeAssistant) -> list[str]:
    """Return the sorted path prefixes a cookie-less client must be able to reach."""
    roots = _package_roots(hass)
    found: set[str] = set()
    for resource in hass.http.app.router.resources():
        prefix = _static_prefix(resource.canonical)
        if prefix == "/" or is_gated_anyway(prefix):
            continue
        if isinstance(resource, StaticResource):
            if _inside_any(getattr(resource, "_directory", ""), roots):
                found.add(prefix)
            continue
        for route in resource:
            handler = route.handler
            if isinstance(handler, partial):
                if handler.args and _inside_any(handler.args[0], roots):
                    found.add(prefix)
                continue
            view = view_of(handler)
            if view is not None and not view.requires_auth:
                found.add(prefix)
    return collapse_prefixes(found)


def collapse_prefixes(paths: set[str]) -> list[str]:
    """Drop paths already covered by a shorter prefix; Access inherits rules downwards."""
    result: list[str] = []
    for path in sorted(paths):
        if not any(path == kept or path.startswith(kept + "/") for kept in result):
            result.append(path)
    return result
