"""Config flow tests."""

from __future__ import annotations

from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType

from custom_components.cloudflare_access_relay.config_flow import normalise_hostname
from custom_components.cloudflare_access_relay.const import (
    CONF_ACCESS_GROUP_ID,
    CONF_ACCOUNT_ID,
    CONF_ALLOWED_EMAILS,
    CONF_API_TOKEN,
    CONF_GATE_ENABLED,
    CONF_HOSTNAME,
    DATA_TEAM_DOMAIN,
    DOMAIN,
)

from .conftest import ACCOUNT_ID, ALICE, HOSTNAME, TEAM_DOMAIN, FakeCloudflare, FakeJwks, make_entry

USER_INPUT = {
    CONF_API_TOKEN: "cf-token",
    CONF_ACCOUNT_ID: ACCOUNT_ID,
    CONF_HOSTNAME: f"https://{HOSTNAME}/",
    CONF_ALLOWED_EMAILS: [ALICE],
    CONF_ACCESS_GROUP_ID: "",
}


def test_normalise_hostname() -> None:
    assert normalise_hostname("HA.Example.com") == "ha.example.com"
    assert normalise_hostname("https://ha.example.com:8123/lovelace") == "ha.example.com"
    assert normalise_hostname(" ha.example.com/ ") == "ha.example.com"
    assert normalise_hostname("") == ""


async def test_user_flow_creates_entry(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks
) -> None:
    hass.config.external_url = f"https://{HOSTNAME}"
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["type"] is FlowResultType.FORM
    assert (
        result["data_schema"]({CONF_API_TOKEN: "t", CONF_ACCOUNT_ID: "a"})[CONF_HOSTNAME]
        == HOSTNAME
    )

    result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["type"] is FlowResultType.CREATE_ENTRY
    entry = result["result"]
    assert entry.title == HOSTNAME
    assert entry.unique_id == HOSTNAME
    assert entry.data[CONF_API_TOKEN] == "cf-token"
    assert entry.data[DATA_TEAM_DOMAIN] == TEAM_DOMAIN
    assert entry.options[CONF_HOSTNAME] == HOSTNAME
    assert entry.options[CONF_ALLOWED_EMAILS] == [ALICE]
    assert entry.options[CONF_GATE_ENABLED] is False, "gate starts disabled"
    await hass.async_block_till_done()
    assert entry.state is config_entries.ConfigEntryState.LOADED
    assert fake_cloudflare.apps == {}, "gate disabled: nothing at the edge yet"
    assert entry.data["policy_aud"] is None and entry.data["gate_app_id"] is None

    # second entry for the same hostname aborts
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_user_flow_invalid_token_creates_nothing(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare
) -> None:
    fake_cloudflare.auth_fail = True
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "invalid_auth"}
    assert fake_cloudflare.writes() == []
    assert hass.config_entries.async_entries(DOMAIN) == []


async def test_user_flow_token_without_org_read(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare
) -> None:
    fake_cloudflare.org_auth_fail = True
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["errors"] == {"base": "missing_org_read"}
    assert fake_cloudflare.writes() == []


async def test_user_flow_cannot_connect(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare
) -> None:
    fake_cloudflare.fail_status = 503
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["errors"] == {"base": "cannot_connect"}


async def test_user_flow_validation_errors(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare
) -> None:
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {**USER_INPUT, CONF_ALLOWED_EMAILS: [], CONF_HOSTNAME: ""}
    )
    assert result["errors"] == {CONF_HOSTNAME: "invalid_hostname", "base": "no_policy_subject"}
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {**USER_INPUT, CONF_ALLOWED_EMAILS: ["not-an-email"]}
    )
    assert result["errors"] == {CONF_ALLOWED_EMAILS: "invalid_email"}
    assert fake_cloudflare.requests == []


async def test_reauth_flow(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks
) -> None:
    entry = make_entry()
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    result = await entry.start_reauth_flow(hass)
    assert result["step_id"] == "reauth_confirm"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_API_TOKEN: "new-token"}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data[CONF_API_TOKEN] == "new-token"
