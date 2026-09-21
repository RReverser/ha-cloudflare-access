"""Paths a caller may need open, derived from what Home Assistant serves without a login.

Nothing is opened by itself: the options form offers these as choices, and only what
the person picks (or types) is bypassed. Two sources: the webhooks integrations have
registered, each with its concrete path, and the resource routes Home Assistant serves
under /api/ to anyone who knows the URL (camera and image proxies, text-to-speech
audio, map tiles), as path prefixes.
"""

from __future__ import annotations

from typing import Any

from homeassistant.components import webhook
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.http import HomeAssistantView
from homeassistant.helpers.selector import SelectOptionDict

API_PREFIX = "/api/"


def _view_of(handler: Any) -> HomeAssistantView | None:
    """Return the view behind a registered route handler (kept in its closure)."""
    for cell in getattr(handler, "__closure__", None) or ():
        try:
            value = cell.cell_contents
        except ValueError:  # empty cell
            continue
        if isinstance(value, HomeAssistantView):
            return value
    return None


@callback
def bypass_candidates(hass: HomeAssistant) -> list[SelectOptionDict]:
    """Return the paths worth offering, webhooks first, then resource prefixes."""
    options: list[SelectOptionDict] = []
    handlers: dict[str, webhook.WebhookData] = hass.data.get(webhook.DOMAIN) or {}
    for webhook_id, data in sorted(handlers.items(), key=lambda kv: (kv[1].name, kv[0])):
        if data.local_only:
            continue  # refused from outside the local network anyway
        options.append(
            {
                "value": webhook.async_generate_path(webhook_id),
                "label": f"{data.name} ({data.domain} webhook)",
            }
        )
    prefixes: dict[str, str] = {}
    for resource in hass.http.app.router.resources():
        info = resource.get_info()
        path = info.get("formatter") or info.get("path") or ""
        if not path.startswith(API_PREFIX) or "{" not in path:
            continue
        prefix = path[: path.index("{")]
        if prefix == webhook.async_generate_path(""):
            continue  # webhooks are offered one by one above
        for route in resource:
            view = _view_of(route.handler)
            if view is not None and not view.requires_auth:
                prefixes.setdefault(prefix, getattr(view, "name", None) or prefix)
    options.extend(
        {"value": prefix, "label": f"{prefix}* ({name})"}
        for prefix, name in sorted(prefixes.items())
    )
    return options
