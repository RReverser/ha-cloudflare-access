"""Config flow tests: the API-token path, the sign-in path, reauth."""

from __future__ import annotations

from typing import Any

from homeassistant import config_entries
from homeassistant.auth.models import User
from homeassistant.components.application_credentials import (
    ClientCredential,
    async_import_client_credential,
)
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import config_entry_oauth2_flow
from homeassistant.setup import async_setup_component
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
from pytest_homeassistant_custom_component.test_util.aiohttp import AiohttpClientMocker

from custom_components.cloudflare_access_relay.config_flow import normalise_hostname
from custom_components.cloudflare_access_relay.const import (
    CONF_ACCOUNT_ID,
    CONF_API_TOKEN,
    CONF_GATE_ENABLED,
    CONF_HOSTNAME,
    DATA_TEAM_DOMAIN,
    DATA_TOKEN,
    DOMAIN,
    OAUTH_AUTHORIZE_URL,
    OAUTH_SCOPES,
    OAUTH_TOKEN_URL,
)

from .conftest import ACCOUNT_ID, ALICE, HOSTNAME, TEAM_DOMAIN, FakeCloudflare, FakeJwks, make_entry

TOKEN_INPUT = {CONF_API_TOKEN: "cf-token", CONF_ACCOUNT_ID: ACCOUNT_ID}
SETTINGS_INPUT = {CONF_HOSTNAME: f"https://{HOSTNAME}/"}
OAUTH_CLIENT_ID = "cf-oauth-client"


def test_normalise_hostname() -> None:
    assert normalise_hostname("HA.Example.com") == "ha.example.com"
    assert normalise_hostname("https://ha.example.com:8123/lovelace") == "ha.example.com"
    assert normalise_hostname(" ha.example.com/ ") == "ha.example.com"
    assert normalise_hostname("") == ""


async def _start(hass: HomeAssistant, next_step: str) -> dict[str, Any]:
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["type"] is FlowResultType.MENU
    assert result["menu_options"] == ["oauth", "api_token"]
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"next_step_id": next_step}
    )
    assert result["type"] is FlowResultType.FORM, result
    return result


async def test_token_flow_creates_entry(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks, alice: User
) -> None:
    hass.config.external_url = f"https://{HOSTNAME}"
    result = await _start(hass, "api_token")
    assert result["step_id"] == "api_token"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], TOKEN_INPUT)
    assert result["type"] is FlowResultType.FORM and result["step_id"] == "settings", result
    assert result["data_schema"]({})[CONF_HOSTNAME] == HOSTNAME, "external URL prefilled"
    assert result["description_placeholders"]["allowed_users"] == ALICE

    result = await hass.config_entries.flow.async_configure(result["flow_id"], SETTINGS_INPUT)
    assert result["type"] is FlowResultType.CREATE_ENTRY, result
    entry = result["result"]
    assert entry.title == HOSTNAME
    assert entry.unique_id == HOSTNAME
    assert entry.data == {
        CONF_API_TOKEN: "cf-token",
        CONF_ACCOUNT_ID: ACCOUNT_ID,
        DATA_TEAM_DOMAIN: TEAM_DOMAIN,
        "policy_aud": None,
        "gate_app_id": None,
        "bypass_app_id": None,
    }
    assert entry.options[CONF_HOSTNAME] == HOSTNAME
    assert entry.options[CONF_GATE_ENABLED] is False, "gate starts disabled"
    await hass.async_block_till_done()
    assert entry.state is config_entries.ConfigEntryState.LOADED
    assert fake_cloudflare.apps == {}, "gate disabled: nothing at the edge yet"

    # second entry for the same hostname aborts
    result = await _start(hass, "api_token")
    result = await hass.config_entries.flow.async_configure(result["flow_id"], TOKEN_INPUT)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], SETTINGS_INPUT)
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_token_flow_invalid_token_creates_nothing(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare
) -> None:
    fake_cloudflare.auth_fail = True
    result = await _start(hass, "api_token")
    result = await hass.config_entries.flow.async_configure(result["flow_id"], TOKEN_INPUT)
    assert result["type"] is FlowResultType.FORM and result["step_id"] == "api_token"
    assert result["errors"] == {"base": "invalid_auth"}
    assert fake_cloudflare.writes() == []
    assert hass.config_entries.async_entries(DOMAIN) == []


async def test_token_flow_token_without_org_read(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare
) -> None:
    fake_cloudflare.org_auth_fail = True
    result = await _start(hass, "api_token")
    result = await hass.config_entries.flow.async_configure(result["flow_id"], TOKEN_INPUT)
    assert result["errors"] == {"base": "missing_org_read"}
    assert fake_cloudflare.writes() == []


async def test_token_flow_cannot_connect(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare
) -> None:
    fake_cloudflare.fail_status = 503
    result = await _start(hass, "api_token")
    result = await hass.config_entries.flow.async_configure(result["flow_id"], TOKEN_INPUT)
    assert result["errors"] == {"base": "cannot_connect"}


async def test_settings_validation_errors(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare
) -> None:
    result = await _start(hass, "api_token")
    result = await hass.config_entries.flow.async_configure(result["flow_id"], TOKEN_INPUT)
    reads = len(fake_cloudflare.requests)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOSTNAME: "", "client_redirect_uris": ["http://x"]}
    )
    assert result["errors"] == {
        CONF_HOSTNAME: "invalid_hostname",
        "client_redirect_uris": "invalid_redirect_uri",
    }
    assert len(fake_cloudflare.requests) == reads
    assert hass.config_entries.async_entries(DOMAIN) == []


async def test_token_reauth_flow(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks
) -> None:
    entry = make_entry()
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    result = await entry.start_reauth_flow(hass)
    assert result["step_id"] == "api_token"
    assert result["data_schema"]({CONF_API_TOKEN: "x"})[CONF_ACCOUNT_ID] == ACCOUNT_ID
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_API_TOKEN: "new-token", CONF_ACCOUNT_ID: ACCOUNT_ID}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data[CONF_API_TOKEN] == "new-token"


# --------------------------------------------------------------------------- sign-in

OAUTH_TOKEN = {
    "access_token": "cf-access-token",
    "refresh_token": "cf-refresh-token",
    "token_type": "Bearer",
    "expires_in": 3600,
}


@pytest.fixture
async def oauth_credentials(hass: HomeAssistant) -> None:
    """The user's own Cloudflare OAuth client, added under Application credentials."""
    assert await async_setup_component(hass, "application_credentials", {})
    await async_import_client_credential(hass, DOMAIN, ClientCredential(OAUTH_CLIENT_ID, ""))


async def _sign_in(
    hass: HomeAssistant,
    hass_client_no_auth: Any,
    aioclient_mock: AiohttpClientMocker,
    result: dict[str, Any],
) -> dict[str, Any]:
    """Play Cloudflare's side of the authorization code flow."""
    assert result["type"] is FlowResultType.EXTERNAL_STEP, result
    state = config_entry_oauth2_flow._encode_jwt(
        hass,
        {
            "flow_id": result["flow_id"],
            "redirect_uri": "https://example.com/auth/external/callback",
        },
    )
    assert result["url"].startswith(f"{OAUTH_AUTHORIZE_URL}?")
    assert f"client_id={OAUTH_CLIENT_ID}" in result["url"]
    assert "code_challenge_method=S256" in result["url"], "PKCE"
    assert f"scope={'+'.join(OAUTH_SCOPES)}" in result["url"]
    assert f"state={state}" in result["url"]
    client = await hass_client_no_auth()
    resp = await client.get(f"/auth/external/callback?code=abcd&state={state}")
    assert resp.status == 200
    aioclient_mock.post(OAUTH_TOKEN_URL, json=OAUTH_TOKEN)
    return await hass.config_entries.flow.async_configure(result["flow_id"])


async def test_sign_in_flow_creates_entry(
    hass: HomeAssistant,
    hass_client_no_auth: Any,
    aioclient_mock: AiohttpClientMocker,
    current_request_with_host: None,
    oauth_credentials: None,
    fake_cloudflare: FakeCloudflare,
    jwks_server: FakeJwks,
) -> None:
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"next_step_id": "oauth"}
    )
    result = await _sign_in(hass, hass_client_no_auth, aioclient_mock, result)
    assert result["type"] is FlowResultType.FORM and result["step_id"] == "settings", (
        "a single account is picked without asking"
    )
    assert any(path == "/accounts" for _, path, _ in fake_cloudflare.requests)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], SETTINGS_INPUT)
    assert result["type"] is FlowResultType.CREATE_ENTRY, result
    entry: MockConfigEntry = result["result"]
    assert entry.data["auth_implementation"] == DOMAIN
    assert entry.data[DATA_TOKEN]["access_token"] == "cf-access-token"
    assert entry.data[CONF_ACCOUNT_ID] == ACCOUNT_ID
    assert entry.data[DATA_TEAM_DOMAIN] == TEAM_DOMAIN
    assert CONF_API_TOKEN not in entry.data
    await hass.async_block_till_done()
    assert entry.state is config_entries.ConfigEntryState.LOADED

    # every Cloudflare call carried the OAuth access token
    assert fake_cloudflare.tokens_seen == {"cf-access-token"}


async def test_sign_in_flow_asks_which_account(
    hass: HomeAssistant,
    hass_client_no_auth: Any,
    aioclient_mock: AiohttpClientMocker,
    current_request_with_host: None,
    oauth_credentials: None,
    fake_cloudflare: FakeCloudflare,
    jwks_server: FakeJwks,
) -> None:
    fake_cloudflare.accounts["other"] = "Other account"
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"next_step_id": "oauth"}
    )
    result = await _sign_in(hass, hass_client_no_auth, aioclient_mock, result)
    assert result["type"] is FlowResultType.FORM and result["step_id"] == "account"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_ACCOUNT_ID: "other"}
    )
    assert result["type"] is FlowResultType.FORM and result["step_id"] == "account"
    assert result["errors"] == {"base": "api_error"}, "the fake only knows one account"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_ACCOUNT_ID: ACCOUNT_ID}
    )
    assert result["type"] is FlowResultType.FORM and result["step_id"] == "settings"


async def test_sign_in_without_credentials_aborts(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare
) -> None:
    assert await async_setup_component(hass, DOMAIN, {})
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"next_step_id": "oauth"}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "missing_credentials", (
        "Home Assistant points at Application credentials"
    )


async def test_sign_in_reauth_flow(
    hass: HomeAssistant,
    hass_client_no_auth: Any,
    aioclient_mock: AiohttpClientMocker,
    current_request_with_host: None,
    oauth_credentials: None,
    fake_cloudflare: FakeCloudflare,
    jwks_server: FakeJwks,
) -> None:
    entry = MockConfigEntry(
        domain=DOMAIN,
        title=HOSTNAME,
        unique_id=HOSTNAME,
        data={
            "auth_implementation": DOMAIN,
            DATA_TOKEN: {**OAUTH_TOKEN, "access_token": "old", "expires_at": 4102444800},
            CONF_ACCOUNT_ID: ACCOUNT_ID,
            DATA_TEAM_DOMAIN: TEAM_DOMAIN,
        },
        options={CONF_HOSTNAME: HOSTNAME},
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    assert fake_cloudflare.tokens_seen == {"old"}

    result = await entry.start_reauth_flow(hass)
    assert result["type"] is FlowResultType.FORM and result["step_id"] == "reauth_confirm"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    result = await _sign_in(hass, hass_client_no_auth, aioclient_mock, result)
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data[DATA_TOKEN]["access_token"] == "cf-access-token"
    assert entry.data[CONF_ACCOUNT_ID] == ACCOUNT_ID
    await hass.async_block_till_done()
    assert "cf-access-token" in fake_cloudflare.tokens_seen, "the reloaded entry uses the new token"


async def test_refused_refresh_triggers_reauth(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    oauth_credentials: None,
    fake_cloudflare: FakeCloudflare,
    jwks_server: FakeJwks,
) -> None:
    """An expired token set whose refresh Cloudflare refuses ends in reauth, not retry."""
    aioclient_mock.post(OAUTH_TOKEN_URL, status=400, json={"error": "invalid_grant"})
    entry = MockConfigEntry(
        domain=DOMAIN,
        title=HOSTNAME,
        unique_id=HOSTNAME,
        data={
            "auth_implementation": DOMAIN,
            DATA_TOKEN: {**OAUTH_TOKEN, "expires_at": 0},
            CONF_ACCOUNT_ID: ACCOUNT_ID,
            DATA_TEAM_DOMAIN: TEAM_DOMAIN,
        },
        options={CONF_HOSTNAME: HOSTNAME},
    )
    entry.add_to_hass(hass)
    assert not await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.state is config_entries.ConfigEntryState.SETUP_ERROR
    assert fake_cloudflare.requests == [], "nothing was tried with the stale token"
    assert any(
        f["context"].get("source") == "reauth"
        for f in hass.config_entries.flow.async_progress_by_handler(DOMAIN)
    )
