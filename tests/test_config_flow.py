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

from custom_components.cloudflare_access_relay.config_flow import (
    _duration_from_form,
    _duration_to_form,
    normalise_hostname,
)
from custom_components.cloudflare_access_relay.const import (
    CONF_ACCOUNT_ID,
    CONF_API_TOKEN,
    CONF_EXTRA_BYPASS_PATHS,
    CONF_GATE_ENABLED,
    CONF_HOSTNAME,
    CONF_LOGIN_EMAILS,
    DATA_TEAM_DOMAIN,
    DATA_TOKEN,
    DOMAIN,
    OAUTH_AUTHORIZE_URL,
    OAUTH_CLIENT_ID,
    OAUTH_SCOPES,
    OAUTH_TOKEN_URL,
)

from .conftest import ACCOUNT_ID, HOSTNAME, TEAM_DOMAIN, FakeCloudflare, FakeJwks, make_entry

TOKEN_INPUT = {CONF_API_TOKEN: "cf-token", CONF_ACCOUNT_ID: ACCOUNT_ID}
SETTINGS_INPUT = {CONF_HOSTNAME: f"https://{HOSTNAME}/"}


def test_normalise_hostname() -> None:
    assert normalise_hostname("HA.Example.com") == "ha.example.com"
    assert normalise_hostname("https://ha.example.com:8123/lovelace") == "ha.example.com"
    assert normalise_hostname(" ha.example.com/ ") == "ha.example.com"
    assert normalise_hostname("") == ""


def test_duration_round_trip() -> None:
    assert _duration_to_form("720h") == {"days": 30, "hours": 0, "minutes": 0}
    assert _duration_to_form("90m") == {"days": 0, "hours": 1, "minutes": 30}
    assert _duration_from_form({"days": 1, "hours": 12}) == "36h"
    assert _duration_from_form({"hours": 1, "minutes": 30}) == "90m"
    assert _duration_from_form({"minutes": 0}) is None, "Access needs at least a minute"
    assert _duration_from_form("8760h") == "8760h", "automation input keeps the API form"
    assert _duration_from_form("1d") is None


async def test_open_paths_are_offered_from_what_home_assistant_serves(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks, alice: User
) -> None:
    """Registered webhooks and unauthenticated /api/ resources become choices, not defaults."""
    from homeassistant.components import webhook
    from homeassistant.helpers.http import HomeAssistantView

    class Audio(HomeAssistantView):
        url = "/api/audio_proxy/{filename}"
        name = "api:audio"
        requires_auth = False

        async def get(self, request: Any, filename: str) -> Any:
            return None

    def view(url: str, requires_auth: bool, module: str = __name__) -> HomeAssistantView:
        attrs = {"url": url, "name": url, "requires_auth": requires_auth, "get": Audio.get}
        return type("V", (HomeAssistantView,), {**attrs, "__module__": module})()

    assert await async_setup_component(hass, "webhook", {})
    hass.http.register_view(Audio())
    for url, auth in (
        ("/api/glyphs/fonts/{name}", False),  # two open siblings and nothing else: combined
        ("/api/glyphs/sprites/{name}", False),
        ("/api/tiles/raster/{z}", False),  # a sibling that needs a login: kept apart
        ("/api/tiles/admin", True),
    ):
        hass.http.register_view(view(url, auth))
    # a view defined by a core integration is labelled with that integration's name
    hass.http.register_view(
        view("/api/camera_proxy/{entity_id}", False, "homeassistant.components.camera")
    )
    webhook.async_register(hass, "my_doorbell", "Front door", "hook-1", lambda *_: None)
    webhook.async_register(hass, "local", "LAN only", "hook-2", lambda *_: None, local_only=True)
    webhook.async_register(hass, "mobile_app", "Mobile App: Old phone", "hook-3", lambda *_: None)
    webhook.async_register(hass, "mobile_app", "Deleted Webhook", "hook-4", lambda *_: None)
    hass.data["mobile_app"] = {"deleted_ids": ["hook-4"]}

    result = await _start(hass, "api_token")
    result = await hass.config_entries.flow.async_configure(result["flow_id"], TOKEN_INPUT)
    bypass = result["data_schema"].schema[
        next(k for k in result["data_schema"].schema if k == "bypass")
    ]
    field = next(k for k in bypass.schema.schema if k == CONF_EXTRA_BYPASS_PATHS)
    config = bypass.schema.schema[field].config
    assert config["multiple"] and config["custom_value"]
    choices = {o["value"]: o["label"] for o in config["options"]}
    assert choices["/api/webhook/hook-1"] == "Front door (my_doorbell)", "unknown domain: as is"
    assert "/api/webhook/hook-2" not in choices, "a local-only webhook never reaches the edge"
    assert choices["/api/webhook/hook-3"] == "Mobile App: Old phone", (
        "integration name not repeated"
    )
    assert "/api/webhook/hook-4" not in choices, "a deleted registration answers 410 anyway"
    assert choices["/api/audio_proxy/"] == "/api/audio_proxy/*", "a view from no integration"
    assert choices["/api/camera_proxy/"] == "Camera: /api/camera_proxy/*"
    assert "/api/glyphs/" in choices and not any(v.startswith("/api/glyphs/f") for v in choices)
    assert "/api/tiles/raster/" in choices and "/api/tiles/" not in choices
    assert not any(v.startswith("/auth/") or v == "/api/websocket" for v in choices)
    assert field.default() == [], "nothing is open unless picked"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            **SETTINGS_INPUT,
            "bypass": {CONF_EXTRA_BYPASS_PATHS: ["/api/webhook/hook-1", "/custom/typed"]},
        },
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY, result
    assert result["result"].options[CONF_EXTRA_BYPASS_PATHS] == [
        "/api/webhook/hook-1",
        "/custom/typed",
    ]


async def test_setup_asks_for_the_people_addresses(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks
) -> None:
    """A People section lists every person: read-only when the username is an address."""
    from .conftest import add_user

    plain = await add_user(hass, "plain-username", name="Plain")
    await add_user(hass, "eve@example.com", name="Eve")
    await add_user(hass, "addon-api", name="Add-on API", person=False)
    result = await _start(hass, "api_token")
    result = await hass.config_entries.flow.async_configure(result["flow_id"], TOKEN_INPUT)
    people = result["data_schema"].schema[
        next(k for k in result["data_schema"].schema if k == "people")
    ]
    fields = {str(k): v for k, v in people.schema.schema.items()}
    assert set(fields) == {"Plain", "Eve"}, "users without a person are not people"
    assert fields["Eve"].config["read_only"] is True
    assert next(k for k in people.schema.schema if k == "Eve").default() == "eve@example.com"
    assert "read_only" not in fields["Plain"].config
    assert "**Plain**: no e-mail address" in result["description_placeholders"]["no_address_note"]

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {**SETTINGS_INPUT, "people": {"Plain": "not-an-address"}}
    )
    assert result["type"] is FlowResultType.FORM and result["errors"] == {"base": "invalid_email"}
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {**SETTINGS_INPUT, "people": {"Plain": "Plain@Example.com "}}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY, result
    entry = result["result"]
    assert entry.options[CONF_LOGIN_EMAILS] == {plain.id: "Plain@Example.com"}
    await hass.async_block_till_done()
    assert entry.runtime_data.emails == ["eve@example.com", "plain@example.com"]


async def test_setup_refuses_when_nobody_could_log_in(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks
) -> None:
    from .conftest import add_user

    await add_user(hass, "plain-username", name="Plain")
    result = await _start(hass, "api_token")
    result = await hass.config_entries.flow.async_configure(result["flow_id"], TOKEN_INPUT)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], SETTINGS_INPUT)
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "no_allowed_users"}


async def _start(hass: HomeAssistant, source: str) -> dict[str, Any]:
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": source})
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
    assert result["description_placeholders"]["no_address_note"] == ""

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
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, alice: User
) -> None:
    result = await _start(hass, "api_token")
    result = await hass.config_entries.flow.async_configure(result["flow_id"], TOKEN_INPUT)
    reads = len(fake_cloudflare.requests)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOSTNAME: "", "session_duration": {"minutes": 0}}
    )
    assert result["errors"] == {
        CONF_HOSTNAME: "invalid_hostname",
        "session_duration": "invalid_duration",
    }
    assert len(fake_cloudflare.requests) == reads
    assert hass.config_entries.async_entries(DOMAIN) == []


async def test_token_reauth_flow(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks, alice: User
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
    """Application credentials loaded (the integration depends on it), nothing added.

    The project's own client is offered by the flow itself, before any entry exists.
    """
    assert await async_setup_component(hass, "application_credentials", {})


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
    alice: User,
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
    result = await _sign_in(hass, hass_client_no_auth, aioclient_mock, result)
    assert result["type"] is FlowResultType.FORM and result["step_id"] == "settings", (
        "a single account is picked without asking"
    )
    assert any(path == "/memberships" for _, path, _ in fake_cloudflare.requests)
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


async def test_sign_in_picks_the_granted_account_among_memberships(
    hass: HomeAssistant,
    alice: User,
    hass_client_no_auth: Any,
    aioclient_mock: AiohttpClientMocker,
    current_request_with_host: None,
    oauth_credentials: None,
    fake_cloudflare: FakeCloudflare,
    jwks_server: FakeJwks,
) -> None:
    """The user belongs to two accounts; the consent covered one: no question asked."""
    fake_cloudflare.accounts["other"] = "Other account"
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    result = await _sign_in(hass, hass_client_no_auth, aioclient_mock, result)
    assert result["type"] is FlowResultType.FORM and result["step_id"] == "settings", result
    probed = {path.split("/")[2] for _, path, _ in fake_cloudflare.requests if "/access/" in path}
    assert probed == {ACCOUNT_ID, "other"}, "every membership is tried"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], SETTINGS_INPUT)
    assert result["type"] is FlowResultType.CREATE_ENTRY, result
    assert result["result"].data[CONF_ACCOUNT_ID] == ACCOUNT_ID


async def test_sign_in_with_no_granted_account_aborts(
    hass: HomeAssistant,
    hass_client_no_auth: Any,
    aioclient_mock: AiohttpClientMocker,
    current_request_with_host: None,
    oauth_credentials: None,
    fake_cloudflare: FakeCloudflare,
    jwks_server: FakeJwks,
) -> None:
    fake_cloudflare.accounts = {"other": "Other account"}
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    result = await _sign_in(hass, hass_client_no_auth, aioclient_mock, result)
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "no_accounts"


async def test_own_credentials_replace_the_built_in_client(
    hass: HomeAssistant, oauth_credentials: None, current_request_with_host: None
) -> None:
    """A client of the user's own (Application credentials) takes the project's place."""
    await async_import_client_credential(hass, DOMAIN, ClientCredential("mine", ""))
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["type"] is FlowResultType.EXTERNAL_STEP
    assert "client_id=mine&" in result["url"]


async def test_sign_in_reauth_flow(
    hass: HomeAssistant,
    alice: User,
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
    alice: User,
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
