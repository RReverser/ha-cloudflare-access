"""Derive, from Home Assistant's own router, the paths a client needs before it holds a cookie.

Two classes of endpoints are reached by a client that cannot yet present the Access
cookie, and Home Assistant marks both in a machine-readable way:

- static files that an integration serves from its own package directory: the
  frontend package's login page (`/auth/authorize`), its JavaScript bundles and
  assets, and the pages and scripts of login integrations such as hass-openid.
  User content mounted from the configuration directory (`/local`, `/hacsfiles`)
  is not code and stays gated;
- views under `/auth/` registered with `requires_auth = False`: core's login flow,
  provider list and token endpoint, and the login views of login integrations.

Everything else that skips Home Assistant's HTTP authentication (the WebSocket,
webhooks, the frontend index) is reached by clients that do hold the cookie, and
stays gated. Server-to-server callers that authenticate with a Home Assistant token
(Google Assistant, Alexa) are indistinguishable from any other API view here and
are declared separately.
"""

from __future__ import annotations

from functools import partial
import inspect
from pathlib import Path

from aiohttp.web_urldispatcher import StaticResource
import homeassistant.components
from homeassistant.core import HomeAssistant
from homeassistant.helpers.http import HomeAssistantView

LOGIN_PREFIX = "/auth/"


def _package_roots(hass: HomeAssistant) -> list[Path]:
    """Directories whose files are integration code rather than user content."""
    roots = [
        Path(homeassistant.components.__file__).parent.resolve(),
        Path(hass.config.path("custom_components")).resolve(),
    ]
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


def _view_of(handler: object) -> HomeAssistantView | None:
    try:
        view = inspect.getclosurevars(handler).nonlocals.get("view")  # type: ignore[arg-type]
    except TypeError, ValueError:
        return None
    return view if isinstance(view, HomeAssistantView) else None


def discover_login_paths(hass: HomeAssistant) -> list[str]:
    """Return the sorted path prefixes a cookie-less client must be able to reach."""
    roots = _package_roots(hass)
    found: set[str] = set()
    for resource in hass.http.app.router.resources():
        canonical = resource.canonical
        if isinstance(resource, StaticResource):
            if _inside_any(getattr(resource, "_directory", ""), roots):
                found.add(_static_prefix(canonical))
            continue
        for route in resource:
            handler = route.handler
            if isinstance(handler, partial):
                if handler.args and _inside_any(handler.args[0], roots):
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
