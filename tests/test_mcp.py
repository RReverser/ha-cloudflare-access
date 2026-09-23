"""HA-MCP's login modes against the gate."""

from __future__ import annotations

from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.cloudflare_access_relay.const import CONF_EXTRA_BYPASS_PATHS, DOMAIN

from .conftest import Access
from .test_provision import _save_options, _settle


def _issue(hass: HomeAssistant, access: Access) -> ir.IssueEntry | None:
    return ir.async_get(hass).async_get_issue(DOMAIN, f"mcp_auth_conflict_{access.entry.entry_id}")


async def test_ha_mcp_login_mode_that_fights_the_gate_raises_an_issue(
    hass: HomeAssistant, access: Access
) -> None:
    mcp = MockConfigEntry(
        domain="ha_mcp_tools", data={"webhook_id": "mcp_abc"}, options={"webhook_auth": "none"}
    )
    mcp.add_to_hass(hass)
    assert await hass.config_entries.async_reload(access.entry.entry_id)
    await hass.async_block_till_done()
    assert _issue(hass, access) is None, "the secret-URL mode works behind the gate"

    # switching HA-MCP to its own login is noticed without a reload
    hass.config_entries.async_update_entry(mcp, options={"webhook_auth": "ha_auth"})
    await _settle(hass)
    issue = _issue(hass, access)
    assert issue is not None and issue.translation_placeholders == {"mode": "ha_auth"}

    # listing the webhook as an open path leaves HA-MCP's login as the only gate: no conflict
    await _save_options(
        hass, access.entry, **{"bypass": {CONF_EXTRA_BYPASS_PATHS: ["/api/webhook/mcp_abc"]}}
    )
    assert _issue(hass, access) is None

    # and with the gate off there is nothing to fight
    hass.config_entries.async_update_entry(mcp, options={"webhook_auth": "legacy"})
    await _save_options(hass, access.entry, **{"gate_enabled": False})
    assert _issue(hass, access) is None
