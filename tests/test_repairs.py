"""Repair issues offer their remedy as an action."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from homeassistant.components.repairs import repairs_flow_manager
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import issue_registry as ir
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.cloudflare_access_relay.const import (
    CONF_EXTRA_BYPASS_PATHS,
    DATA_BYPASS_APP_ID,
    DATA_GATE_APP_ID,
    DOMAIN,
)
from custom_components.cloudflare_access_relay.issues import issue_id

from .conftest import ALICE, BOB, HOSTNAME, Access, add_user
from .test_logins import _entry, _poll
from .test_provision import _save_options, _settle


def _issue(hass: HomeAssistant, access: Access, key: str) -> ir.IssueEntry | None:
    return ir.async_get(hass).async_get_issue(DOMAIN, issue_id(access.entry, key))


async def _fix(hass: HomeAssistant, access: Access, key: str) -> dict[str, Any]:
    manager = repairs_flow_manager(hass)
    assert manager is not None
    return await manager.async_init(DOMAIN, data={"issue_id": issue_id(access.entry, key)})


async def _submit(hass: HomeAssistant, flow_id: str, user_input: dict[str, Any] | None) -> Any:
    manager = repairs_flow_manager(hass)
    assert manager is not None
    result = await manager.async_configure(flow_id, user_input)
    await hass.async_block_till_done(wait_background_tasks=True)
    return result


async def test_a_failed_update_is_applied_again_from_the_repair(
    hass: HomeAssistant, access: Access
) -> None:
    cf = access.cloudflare
    gate_id = access.entry.data[DATA_GATE_APP_ID]
    cf.fail_status, cf.fail_predicate = 503, lambda method, _path: method == "PUT"
    await hass.config.async_update(external_url="https://new.example.com")
    await _settle(hass)
    issue = _issue(hass, access, "update_failed")
    assert issue is not None and issue.is_fixable

    cf.fail_status = cf.fail_predicate = None
    result = await _fix(hass, access, "update_failed")
    assert result["type"] is FlowResultType.FORM and result["step_id"] == "confirm"
    assert "error" in (result["description_placeholders"] or {})
    result = await _submit(hass, result["flow_id"], {})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert cf.apps[gate_id]["domain"] == "new.example.com", "the reload applied the change"
    assert _issue(hass, access, "update_failed") is None


async def test_the_external_url_is_set_from_the_repair(hass: HomeAssistant, access: Access) -> None:
    cf = access.cloudflare
    gate_id = access.entry.data[DATA_GATE_APP_ID]
    await hass.config.async_update(external_url=None)
    await _settle(hass)
    assert (issue := _issue(hass, access, "no_external_url")) is not None and issue.is_fixable

    result = await _fix(hass, access, "no_external_url")
    assert result["type"] is FlowResultType.FORM
    result = await _submit(hass, result["flow_id"], {"external_url": "http://plain.example.com"})
    assert result["type"] is FlowResultType.FORM and result["errors"] == {
        "external_url": "invalid_url"
    }
    result = await _submit(hass, result["flow_id"], {"external_url": "https://again.example.com/"})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert hass.config.external_url == "https://again.example.com/"
    await _settle(hass)
    assert cf.apps[gate_id]["domain"] == "again.example.com"
    assert _issue(hass, access, "no_external_url") is None


async def test_a_refused_address_is_given_to_a_person_from_the_repair(
    hass: HomeAssistant, access: Access
) -> None:
    cf = access.cloudflare
    gate_id = access.entry.data[DATA_GATE_APP_ID]
    carol = await add_user(hass, "carol", name="Carol")  # no address of her own
    await _settle(hass)
    when = (dt_util.utcnow() - timedelta(minutes=5)).replace(microsecond=0).isoformat()
    cf.access_logs.append(_entry(gate_id, "eve@example.com", False, when))
    await _poll(hass)
    assert (issue := _issue(hass, access, "denied_login")) is not None and issue.is_fixable

    result = await _fix(hass, access, "denied_login")
    assert result["type"] is FlowResultType.FORM
    options = result["data_schema"].schema["user_id"].config["options"]
    assert {o["label"] for o in options} >= {"Alice", "Bob", "Carol"}
    result = await _submit(hass, result["flow_id"], {"user_id": carol.id})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert access.entry.options["login_emails"] == {carol.id: "eve@example.com"}
    allowed = {r["email"]["email"] for r in cf.apps[gate_id]["policies"][0]["include"]}
    assert allowed == {ALICE, BOB, "eve@example.com"}
    assert _issue(hass, access, "denied_login") is None


async def _mcp_conflict(hass: HomeAssistant, access: Access) -> MockConfigEntry:
    mcp = MockConfigEntry(
        domain="ha_mcp_tools", data={"webhook_id": "mcp_abc"}, options={"webhook_auth": "ha_auth"}
    )
    mcp.add_to_hass(hass)
    await _settle(hass)
    assert (issue := _issue(hass, access, "mcp_auth_conflict")) is not None and issue.is_fixable
    return mcp


async def test_the_mcp_conflict_is_settled_by_switching_ha_mcp(
    hass: HomeAssistant, access: Access
) -> None:
    mcp = await _mcp_conflict(hass, access)
    result = await _fix(hass, access, "mcp_auth_conflict")
    assert result["type"] is FlowResultType.MENU and set(result["menu_options"]) == {
        "secret_url",
        "bypass",
    }
    result = await _submit(hass, result["flow_id"], {"next_step_id": "secret_url"})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert mcp.options["webhook_auth"] == "none"
    await _settle(hass)
    assert _issue(hass, access, "mcp_auth_conflict") is None


async def test_the_mcp_conflict_is_settled_by_opening_the_webhook(
    hass: HomeAssistant, access: Access
) -> None:
    cf = access.cloudflare
    mcp = await _mcp_conflict(hass, access)
    await _save_options(hass, access.entry, **{"bypass": {CONF_EXTRA_BYPASS_PATHS: ["/api/x"]}})
    result = await _fix(hass, access, "mcp_auth_conflict")
    result = await _submit(hass, result["flow_id"], {"next_step_id": "bypass"})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert access.entry.options[CONF_EXTRA_BYPASS_PATHS] == ["/api/x", "/api/webhook/mcp_abc"]
    assert mcp.options["webhook_auth"] == "ha_auth", "HA-MCP is left as it was"
    bypass = cf.apps[access.entry.data[DATA_BYPASS_APP_ID]]
    assert any(d["uri"].endswith("/api/webhook/mcp_abc") for d in bypass["destinations"])
    assert _issue(hass, access, "mcp_auth_conflict") is None
    assert HOSTNAME in bypass["destinations"][0]["uri"]
