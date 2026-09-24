"""Paths a caller may need open, derived from what Home Assistant serves without a login.

Nothing is opened by itself: the options form offers these as choices, and only what
the person picks (or types) is bypassed. The sources are the registered webhooks and the
routes under /api/ that Home Assistant serves to anyone who knows the URL (camera and
image proxies, text-to-speech audio, map tiles).
"""

from __future__ import annotations

from typing import Any

from homeassistant.components import webhook
from homeassistant.core import HomeAssistant
from homeassistant.helpers.http import HomeAssistantView
from homeassistant.helpers.selector import SelectOptionDict
from homeassistant.loader import async_get_integrations

API_PREFIX = "/api/"
# Copied from homeassistant.components.mobile_app.const (DOMAIN, DATA_DELETED_IDS):
# importing that package pulls in half of Home Assistant.
MOBILE_APP = "mobile_app"
DATA_DELETED_IDS = "deleted_ids"


def _view_of(handler: Any) -> HomeAssistantView | None:
    """Return the view behind a registered route handler.

    Home Assistant registers a wrapper, not the view's method, and the wrapper keeps the
    view in its closure (homeassistant.helpers.http.request_handler_factory); there is
    no public way from a route back to its view.
    """
    for cell in getattr(handler, "__closure__", None) or ():
        try:
            value = cell.cell_contents
        except ValueError:  # empty cell
            continue
        if isinstance(value, HomeAssistantView):
            return value
    return None


def _domain_of(view: HomeAssistantView) -> str | None:
    """Return the integration a view's class was defined in."""
    parts = type(view).__module__.split(".")
    if len(parts) >= 3 and parts[0] == "homeassistant" and parts[1] == "components":
        return parts[2]
    if len(parts) >= 2 and parts[0] == "custom_components":
        return parts[1]
    return None


def _widen(prefix: str, domain: str | None, routes: list[tuple[str, bool, str | None]]) -> str:
    """Climb to the parent directory while everything under it is open and the same source.

    Sibling routes then become one entry (the four map-tile routes are one choice). A
    parent that also serves something that needs a login, or another integration, stops
    the climb, and /api/ itself is never offered.
    """
    while True:
        parent = prefix[: prefix.rstrip("/").rfind("/") + 1]
        if parent in (API_PREFIX, prefix):
            return prefix
        under = [r for r in routes if r[0].startswith(parent)]
        paths = {r[0] for r in under}
        if len(paths) < 2 or any(r[1] or r[2] != domain for r in under):
            return prefix
        prefix = parent


async def async_bypass_candidates(hass: HomeAssistant) -> list[SelectOptionDict]:
    """Return the paths worth offering, webhooks first, then resource prefixes."""
    # The mobile app keeps the webhooks of deleted registrations, only to answer them
    # 410 Gone (homeassistant.components.mobile_app.webhook); they are not worth opening.
    dead = set(hass.data.get(MOBILE_APP, {}).get(DATA_DELETED_IDS) or ())
    handlers: dict[str, webhook.WebhookData] = hass.data.get(webhook.DOMAIN) or {}
    hooks = [
        (webhook_id, data)
        for webhook_id, data in handlers.items()
        if webhook_id not in dead and not data.local_only  # local-only never reaches the edge
    ]
    routes: list[tuple[str, bool, str | None]] = []  # path, needs a login, integration
    for resource in hass.http.app.router.resources():
        info = resource.get_info()
        # aiohttp describes a parameterised resource by "formatter" and a plain one by "path".
        path = info.get("formatter") or info.get("path") or ""
        if not path.startswith(API_PREFIX):
            continue
        for route in resource:
            if route.method == "OPTIONS":
                continue  # the CORS preflight aiohttp_cors adds (homeassistant.components.http.cors)
            view = _view_of(route.handler)
            # Fail closed: a route whose view cannot be found counts as one that needs a login.
            routes.append(
                (
                    path,
                    view is None or view.requires_auth,
                    None if view is None else _domain_of(view),
                )
            )
    prefixes: dict[str, str | None] = {}
    for path, needs_login, domain in routes:
        if needs_login or "{" not in path:
            continue
        prefix = path[: path.index("{")]
        if prefix == webhook.async_generate_path(""):
            continue  # webhooks are offered one by one
        prefixes.setdefault(_widen(prefix, domain, routes), domain)
    domains = {d.domain for _, d in hooks} | {d for d in prefixes.values() if d}
    integrations = await async_get_integrations(hass, domains)
    names = {
        domain: (result.name if not isinstance(result, Exception) else domain)
        for domain, result in integrations.items()
    }

    options: list[SelectOptionDict] = []
    for webhook_id, data in sorted(hooks, key=lambda kv: (kv[1].name.casefold(), kv[0])):
        source = names[data.domain]
        # Many webhook names already start with the integration's name.
        label = (
            data.name
            if data.name.casefold().startswith(source.casefold())
            else f"{data.name} ({source})"
        )
        options.append({"value": webhook.async_generate_path(webhook_id), "label": label})
    options.extend(
        {"value": prefix, "label": f"{names[domain]}: {prefix}*" if domain else f"{prefix}*"}
        for prefix, domain in sorted(
            prefixes.items(), key=lambda kv: (names.get(kv[1] or "", "") if kv[1] else "", kv[0])
        )
    )
    return options
