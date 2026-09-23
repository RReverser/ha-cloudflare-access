"""The HA-MCP custom component's login modes against the gate.

HA-MCP serves MCP on a Home Assistant webhook. In its `ha_auth` and `legacy` modes it
demands its own OAuth login on that webhook; with the gate guarding the same path a client
can satisfy only one of the two logins, so the combination never works. The check below
raises a repair issue for it, unless the webhook is listed as an open path, where HA-MCP's
own login is the only gate. Mode `none` works behind the gate as is.
"""

from __future__ import annotations

from typing import Any

from homeassistant.components.webhook import async_generate_path
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import issue_registry as ir

from .const import (
    CONF_EXTRA_BYPASS_PATHS,
    CONF_GATE_ENABLED,
    DOMAIN,
    HA_MCP_AUTH_NONE,
    HA_MCP_DATA_WEBHOOK_ID,
    HA_MCP_DOMAIN,
    HA_MCP_OPT_AUTH,
    HA_MCP_OPT_WEBHOOK_ENABLED,
    ISSUE_MCP_AUTH_CONFLICT,
)
from .issues import issue_id


def _open(path: str, open_paths: list[str]) -> bool:
    return any(path == prefix or path.startswith(prefix.rstrip("*")) for prefix in open_paths)


@callback
def async_check_mcp_login_conflict(
    hass: HomeAssistant, entry: ConfigEntry, options: dict[str, Any]
) -> None:
    """Raise or clear the repair issue for an HA-MCP login mode that fights the gate."""
    conflicts: list[str] = []
    if options.get(CONF_GATE_ENABLED):
        open_paths = [str(p) for p in options.get(CONF_EXTRA_BYPASS_PATHS) or []]
        for mcp in hass.config_entries.async_entries(HA_MCP_DOMAIN):
            mode = str(mcp.options.get(HA_MCP_OPT_AUTH, HA_MCP_AUTH_NONE))
            webhook_id = mcp.data.get(HA_MCP_DATA_WEBHOOK_ID)
            if (
                mode == HA_MCP_AUTH_NONE
                or not mcp.options.get(HA_MCP_OPT_WEBHOOK_ENABLED, True)
                or not webhook_id
                or _open(async_generate_path(str(webhook_id)), open_paths)
            ):
                continue
            conflicts.append(mode)
    if not conflicts:
        ir.async_delete_issue(hass, DOMAIN, issue_id(entry, ISSUE_MCP_AUTH_CONFLICT))
        return
    ir.async_create_issue(
        hass,
        DOMAIN,
        issue_id(entry, ISSUE_MCP_AUTH_CONFLICT),
        is_fixable=False,
        severity=ir.IssueSeverity.ERROR,
        translation_key=ISSUE_MCP_AUTH_CONFLICT,
        translation_placeholders={"mode": ", ".join(sorted(set(conflicts)))},
    )
