"""Paths a caller may need open, derived from what Home Assistant serves without a login.

Nothing is opened by itself: the options form offers these as choices, and only what
the person picks (or types) is bypassed. Two sources: the webhooks integrations have
registered, each with its concrete path, and the resource routes Home Assistant serves
under /api/ to anyone who knows the URL (camera and image proxies, text-to-speech
audio, map tiles), as path prefixes. Each is labelled with the integration it belongs to.
"""

from __future__ import annotations

from typing import Any

from homeassistant.components import webhook
from homeassistant.core import HomeAssistant
from homeassistant.helpers.http import HomeAssistantView
from homeassistant.helpers.selector import SelectOptionDict
from homeassistant.loader import async_get_integrations

API_PREFIX = "/api/"
# Where the mobile app keeps the webhook ids of deleted registrations (its const.py:
# DOMAIN and DATA_DELETED_IDS); importing that package pulls in half of Home Assistant.
MOBILE_APP = "mobile_app"
DATA_DELETED_IDS = "deleted_ids"


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


def _domain_of(view: HomeAssistantView) -> str | None:
    """Return the integration a view's class was defined in."""
    parts = type(view).__module__.split(".")
    if len(parts) >= 3 and parts[0] == "homeassistant" and parts[1] == "components":
        return parts[2]
    if len(parts) >= 2 and parts[0] == "custom_components":
        return parts[1]
    return None


async def async_bypass_candidates(hass: HomeAssistant) -> list[SelectOptionDict]:
    """Return the paths worth offering, webhooks first, then resource prefixes."""
    # The mobile app keeps the ids of deleted registrations to answer them 410 Gone.
    dead = set(hass.data.get(MOBILE_APP, {}).get(DATA_DELETED_IDS) or ())
    handlers: dict[str, webhook.WebhookData] = hass.data.get(webhook.DOMAIN) or {}
    hooks = [
        (webhook_id, data)
        for webhook_id, data in handlers.items()
        if webhook_id not in dead and not data.local_only  # local-only never reaches the edge
    ]
    prefixes: dict[str, str | None] = {}
    for resource in hass.http.app.router.resources():
        info = resource.get_info()
        path = info.get("formatter") or info.get("path") or ""
        if not path.startswith(API_PREFIX) or "{" not in path:
            continue
        prefix = path[: path.index("{")]
        if prefix == webhook.async_generate_path(""):
            continue  # webhooks are offered one by one
        for route in resource:
            view = _view_of(route.handler)
            if view is not None and not view.requires_auth:
                prefixes.setdefault(prefix, _domain_of(view))
    domains = {d.domain for _, d in hooks} | {d for d in prefixes.values() if d}
    integrations = await async_get_integrations(hass, domains)
    names = {
        domain: (result.name if not isinstance(result, Exception) else domain)
        for domain, result in integrations.items()
    }

    options: list[SelectOptionDict] = []
    for webhook_id, data in sorted(hooks, key=lambda kv: (kv[1].name.casefold(), kv[0])):
        source = names[data.domain]
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
