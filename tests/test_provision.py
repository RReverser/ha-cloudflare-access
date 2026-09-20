"""Provisioning tests against the fake Cloudflare API."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from homeassistant.auth.models import User
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import issue_registry as ir
from homeassistant.util.dt import utcnow
from pytest_homeassistant_custom_component.common import MockConfigEntry, async_fire_time_changed

from custom_components.cloudflare_access_relay.const import (
    CONF_DELETE_OBJECTS_ON_REMOVE,
    CONF_EXTRA_BYPASS_PATHS,
    CONF_GATE_ENABLED,
    CONF_SERVICE_TOKEN_IDS,
    CONF_SESSION_DURATION,
    DATA_BYPASS_APP_ID,
    DATA_GATE_APP_ID,
    DATA_POLICY_AUD,
    DATA_TEAM_DOMAIN,
    DOMAIN,
    ISSUE_NO_ALLOWED_USERS,
    RECONCILE_COOLDOWN_SECONDS,
)
from custom_components.cloudflare_access_relay.provision import (
    app_matches,
    desired_bypass_app,
    desired_gate_app,
)

from .conftest import (
    ALICE,
    BOB,
    HOSTNAME,
    TEAM_DOMAIN,
    Access,
    FakeCloudflare,
    FakeJwks,
    add_user,
    make_entry,
)

GATE = f"ha-access: gate {HOSTNAME}"
BYPASS = f"ha-access: bypass {HOSTNAME}"


def _uris(app: dict[str, Any]) -> list[str]:
    return [d["uri"] for d in app["destinations"]]


async def _save_options(hass: HomeAssistant, entry: MockConfigEntry, **changes: Any) -> None:
    flow = await hass.config_entries.options.async_init(entry.entry_id)
    assert flow["type"] is FlowResultType.FORM
    current = {CONF_GATE_ENABLED: entry.options[CONF_GATE_ENABLED]}
    result = await hass.config_entries.options.async_configure(
        flow["flow_id"], {**current, **changes}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY, result
    await hass.async_block_till_done()


async def _settle(hass: HomeAssistant, rounds: int = 1) -> None:
    """Let the debounced reconciliation run."""
    async_fire_time_changed(
        hass, utcnow() + timedelta(seconds=rounds * (RECONCILE_COOLDOWN_SECONDS + 1))
    )
    await hass.async_block_till_done(wait_background_tasks=True)


# --------------------------------------------------------------------------- gate


async def test_gate_disabled_creates_nothing(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks
) -> None:
    """Installing changes nothing at the edge until the gate is enabled."""
    entry = make_entry()
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    assert fake_cloudflare.writes() == []
    assert fake_cloudflare.apps == {}
    assert entry.data[DATA_TEAM_DOMAIN] == TEAM_DOMAIN
    assert entry.data[DATA_POLICY_AUD] is None
    assert entry.state is ConfigEntryState.LOADED


async def test_enabling_the_gate_creates_it_and_disabling_deletes_it(
    hass: HomeAssistant,
    fake_cloudflare: FakeCloudflare,
    jwks_server: FakeJwks,
    alice: User,
    bob: User,
) -> None:
    cf = fake_cloudflare
    entry = make_entry()
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)

    await _save_options(hass, entry, **{CONF_GATE_ENABLED: True})
    posts = cf.writes("POST")
    assert [p[2]["name"] for p in posts] == [GATE]
    gate = posts[0][2]
    assert gate["type"] == "self_hosted"
    assert gate["domain"] == HOSTNAME and _uris(gate) == [HOSTNAME], "the whole hostname"
    assert gate["session_duration"] == "720h"
    assert gate["enable_binding_cookie"] is False
    assert gate["path_cookie_attribute"] is False
    assert gate["http_only_cookie_attribute"] is True
    assert gate["same_site_cookie_attribute"] == "lax"
    assert gate["policies"] == [
        {
            "name": "ha-access: allow",
            "decision": "allow",
            "precedence": 1,
            "include": [{"email": {"email": ALICE}}, {"email": {"email": BOB}}],
        }
    ]
    assert gate["oauth_configuration"]["enabled"] is True
    assert entry.data[DATA_GATE_APP_ID] == cf.by_name(GATE)["id"]
    assert entry.data[DATA_POLICY_AUD] == cf.by_name(GATE)["aud"]

    await _save_options(hass, entry, **{CONF_GATE_ENABLED: False})
    assert cf.writes("DELETE") and cf.by_name(GATE) is None
    assert entry.data[DATA_GATE_APP_ID] is None and entry.data[DATA_POLICY_AUD] is None


async def test_second_setup_writes_nothing(hass: HomeAssistant, access: Access) -> None:
    cf = access.cloudflare
    assert len(cf.writes()) == 1
    assert await hass.config_entries.async_reload(access.entry.entry_id)
    await hass.async_block_till_done()
    assert len(cf.writes()) == 1


async def test_recovers_gate_by_name_when_id_lost(hass: HomeAssistant, access: Access) -> None:
    cf = access.cloudflare
    hass.config_entries.async_update_entry(
        access.entry, data={**access.entry.data, DATA_GATE_APP_ID: "lost"}
    )
    assert await hass.config_entries.async_reload(access.entry.entry_id)
    await hass.async_block_till_done()
    assert len(cf.writes()) == 1
    assert access.entry.data[DATA_GATE_APP_ID] == cf.by_name(GATE)["id"]


async def test_drift_is_repaired_on_reload(hass: HomeAssistant, access: Access) -> None:
    cf = access.cloudflare
    gate = cf.by_name(GATE)
    gate["enable_binding_cookie"] = True
    policy_id = gate["policies"][0]["id"]
    assert await hass.config_entries.async_reload(access.entry.entry_id)
    await hass.async_block_till_done()
    puts = cf.writes("PUT")
    assert [p[2]["name"] for p in puts] == [GATE]
    assert puts[0][2]["enable_binding_cookie"] is False
    assert puts[0][2]["policies"][0]["id"] == policy_id, "inline policy id reused"


async def test_service_token_policy(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks, alice: User
) -> None:
    entry = make_entry(**{CONF_GATE_ENABLED: True, CONF_SERVICE_TOKEN_IDS: ["tok-1"]})
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    gate = fake_cloudflare.by_name(GATE)
    assert [(p["name"], p["decision"]) for p in gate["policies"]] == [
        ("ha-access: allow", "allow"),
        ("ha-access: service tokens", "non_identity"),
    ]
    assert gate["policies"][0]["include"] == [{"email": {"email": ALICE}}]
    assert gate["policies"][1]["include"] == [{"service_token": {"token_id": "tok-1"}}]


# --------------------------------------------------------------------------- users


async def test_gate_needs_at_least_one_user_with_an_address(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks
) -> None:
    """A gate nobody could pass is a lock-out: it is refused, not provisioned."""
    await add_user(hass, "plain-username")
    entry = make_entry(**{CONF_GATE_ENABLED: True})
    entry.add_to_hass(hass)
    assert not await hass.config_entries.async_setup(entry.entry_id)
    assert entry.state is ConfigEntryState.SETUP_ERROR
    assert fake_cloudflare.writes() == []

    # the options flow refuses to enable the gate for the same reason
    entry = make_entry()
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    flow = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        flow["flow_id"], {CONF_GATE_ENABLED: True}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "no_allowed_users"}


async def test_allow_policy_follows_the_users(hass: HomeAssistant, access: Access) -> None:
    cf = access.cloudflare
    assert cf.by_name(GATE)["policies"][0]["include"] == [
        {"email": {"email": ALICE}},
        {"email": {"email": BOB}},
    ]

    carol = await add_user(hass, "Carol@Example.com")
    await add_user(hass, "no-address")  # a plain username is not a policy subject
    await _settle(hass)
    assert cf.by_name(GATE)["policies"][0]["include"] == [
        {"email": {"email": ALICE}},
        {"email": {"email": BOB}},
        {"email": {"email": "carol@example.com"}},
    ]
    assert len(cf.writes("PUT")) == 1, "one write for the burst of user changes"

    await hass.auth.async_update_user(carol, is_active=False)
    await _settle(hass)
    assert cf.by_name(GATE)["policies"][0]["include"] == [
        {"email": {"email": ALICE}},
        {"email": {"email": BOB}},
    ]
    assert access.entry.data[DATA_POLICY_AUD] == access.aud, "audience survives the updates"


async def test_last_user_leaving_keeps_the_policy_and_raises_an_issue(
    hass: HomeAssistant, access: Access, alice: User, bob: User
) -> None:
    cf = access.cloudflare
    await hass.auth.async_remove_user(alice)
    await hass.auth.async_remove_user(bob)
    await _settle(hass)
    assert cf.by_name(GATE)["policies"][0]["include"] == [
        {"email": {"email": ALICE}},
        {"email": {"email": BOB}},
    ], "an empty allow policy would lock everyone out: the last subjects stay"
    assert ir.async_get(hass).async_get_issue(DOMAIN, ISSUE_NO_ALLOWED_USERS) is not None

    await add_user(hass, ALICE)
    await _settle(hass)
    assert cf.by_name(GATE)["policies"][0]["include"] == [{"email": {"email": ALICE}}]
    assert ir.async_get(hass).async_get_issue(DOMAIN, ISSUE_NO_ALLOWED_USERS) is None


def test_gate_is_an_oauth_server_for_self_registering_clients() -> None:
    opts = {
        "hostname": HOSTNAME,
        "gate_enabled": True,
        "client_redirect_uris": ["https://claude.ai/api/mcp/auth_callback", " "],
    }
    gate = desired_gate_app(opts, [ALICE])
    assert gate is not None
    assert gate["oauth_configuration"] == {
        "enabled": True,
        "dynamic_client_registration": {
            "enabled": True,
            "allow_any_on_localhost": False,
            "allow_any_on_loopback": False,
            "allowed_uris": ["https://claude.ai/api/mcp/auth_callback"],
        },
    }
    assert [p["name"] for p in gate["policies"]] == ["ha-access: allow"]
    gate = desired_gate_app(opts, [ALICE], linked_app_ids=["app-b", "app-a"])
    assert gate is not None
    assert gate["policies"][-1] == {
        "name": "ha-access: registered clients",
        "decision": "non_identity",
        "precedence": 3,
        "include": [
            {"linked_app_token": {"app_uid": "app-a"}},
            {"linked_app_token": {"app_uid": "app-b"}},
        ],
    }
    existing = {**gate, "id": "x", "policies": [{**p, "id": "p"} for p in gate["policies"]]}
    assert app_matches(existing, gate)
    existing["oauth_configuration"] = {**gate["oauth_configuration"], "enabled": False}
    assert not app_matches(existing, gate)
    assert desired_gate_app({**opts, "gate_enabled": False}, [ALICE]) is None


def test_app_matches_treats_absent_fields_as_cloudflare_defaults() -> None:
    """Cloudflare's GET omits path_cookie_attribute (and others) when they are default."""
    desired = desired_gate_app({"hostname": HOSTNAME, "gate_enabled": True}, [ALICE])
    assert desired is not None
    existing = {k: v for k, v in desired.items() if k != "path_cookie_attribute"}
    existing["policies"] = [
        {**p, "id": "p1", "exclude": [], "require": []} for p in desired["policies"]
    ]
    existing.update({"id": "x", "aud": "y", "created_at": "now"})
    assert app_matches(existing, desired)
    existing["path_cookie_attribute"] = True
    assert not app_matches(existing, desired)
    existing["path_cookie_attribute"] = False
    existing["policies"][0]["include"] = [{"email": {"email": BOB}}]
    assert not app_matches(existing, desired)


# --------------------------------------------------------------------------- bypass


def test_nothing_is_bypassed_unless_listed() -> None:
    assert desired_bypass_app({"hostname": HOSTNAME}) is None
    assert desired_bypass_app({"hostname": HOSTNAME, "extra_bypass_paths": [" ", "/"]}) is None
    app = desired_bypass_app(
        {"hostname": HOSTNAME, "extra_bypass_paths": ["api/webhook/abc/", "/api/tts_proxy"]}
    )
    assert app is not None
    assert _uris(app) == [f"{HOSTNAME}/api/tts_proxy", f"{HOSTNAME}/api/webhook/abc"]
    assert app["domain"] == _uris(app)[0]
    assert app["policies"] == [
        {
            "name": "ha-access: bypass everyone",
            "decision": "bypass",
            "precedence": 1,
            "include": [{"everyone": {}}],
        }
    ]


async def test_bypass_application_follows_the_option(hass: HomeAssistant, access: Access) -> None:
    cf = access.cloudflare
    await _save_options(hass, access.entry, **{CONF_EXTRA_BYPASS_PATHS: ["/api/webhook/abc123"]})
    bypass = cf.by_name(BYPASS)
    assert bypass is not None and _uris(bypass) == [f"{HOSTNAME}/api/webhook/abc123"]
    assert access.entry.data[DATA_BYPASS_APP_ID] == bypass["id"]
    assert [p[2]["name"] for p in cf.writes("POST")] == [GATE, BYPASS]

    await _save_options(hass, access.entry, **{CONF_EXTRA_BYPASS_PATHS: []})
    assert cf.by_name(BYPASS) is None
    assert access.entry.data[DATA_BYPASS_APP_ID] is None


async def test_session_duration_change_updates_gate_only(
    hass: HomeAssistant, access: Access
) -> None:
    cf = access.cloudflare
    await _save_options(hass, access.entry, **{CONF_SESSION_DURATION: "24h"})
    puts = cf.writes("PUT")
    assert [p[2]["name"] for p in puts] == [GATE]
    assert puts[0][2]["session_duration"] == "24h"
    assert access.entry.data[DATA_POLICY_AUD] == access.aud, "audience survives an update"


# --------------------------------------------------------------------------- clients


async def _register_client(
    hass: HomeAssistant, entry: MockConfigEntry, name: str, uris: list[str]
) -> dict[str, Any]:
    """Drive the subentry flow; return the credentials page's placeholders."""
    flow = await hass.config_entries.subentries.async_init(
        (entry.entry_id, "oauth_client"), context={"source": "user"}
    )
    assert flow["type"] is FlowResultType.FORM and flow["step_id"] == "user"
    result = await hass.config_entries.subentries.async_configure(
        flow["flow_id"], {"name": name, "redirect_uris": uris}
    )
    assert result["type"] is FlowResultType.FORM and result["step_id"] == "credentials", result
    placeholders = dict(result["description_placeholders"])
    result = await hass.config_entries.subentries.async_configure(flow["flow_id"], {})
    assert result["type"] is FlowResultType.CREATE_ENTRY, result
    await hass.async_block_till_done()
    return placeholders


async def test_registered_client_gets_an_access_application_and_the_gate_accepts_it(
    hass: HomeAssistant, access: Access
) -> None:
    cf = access.cloudflare
    shown = await _register_client(
        hass, access.entry, "Google Home", ["https://oauth-redirect.googleusercontent.com/r/p"]
    )
    client = cf.by_name(f"ha-access: client {HOSTNAME} Google Home")
    assert client is not None
    assert client["type"] == "saas"
    assert client["saas_app"]["auth_type"] == "oidc"
    assert client["saas_app"]["redirect_uris"] == [
        "https://oauth-redirect.googleusercontent.com/r/p"
    ]
    assert set(client["saas_app"]["grant_types"]) == {"authorization_code", "refresh_tokens"}
    assert client["saas_app"]["refresh_token_options"] == {"lifetime": "720h"}, (
        "a client's refresh token lives as long as an Access session of the gate"
    )
    assert client["policies"][0]["include"] == [
        {"email": {"email": ALICE}},
        {"email": {"email": BOB}},
    ]
    # the credentials page carries what the client's console asks for
    assert shown["client_id"] == client["saas_app"]["client_id"]
    assert shown["client_secret"] == cf.secrets[client["id"]]
    assert shown["authorization_url"] == (
        f"https://{TEAM_DOMAIN}/cdn-cgi/access/sso/oidc/{shown['client_id']}/authorization"
    )
    sub = next(iter(access.entry.subentries.values()))
    assert (
        sub.data["app_id"] == client["id"] and sub.data["client_secret"] == shown["client_secret"]
    )

    # the entry change is picked up without a reload: the gate accepts the client's tokens
    await _settle(hass)
    gate = cf.by_name(GATE)
    assert gate["policies"][-1]["include"] == [{"linked_app_token": {"app_uid": client["id"]}}]

    # removing the client removes its application and the rule, in that order of safety
    hass.config_entries.async_remove_subentry(access.entry, sub.subentry_id)
    await _settle(hass, 2)
    assert cf.by_name(f"ha-access: client {HOSTNAME} Google Home") is None
    assert [p["name"] for p in cf.by_name(GATE)["policies"]] == ["ha-access: allow"]
    writes = cf.writes()
    gate_put = max(i for i, w in enumerate(writes) if w[0] == "PUT" and w[2]["name"] == GATE)
    delete = next(i for i, w in enumerate(writes) if w[0] == "DELETE" and client["id"] in w[1])
    assert gate_put < delete, "the gate drops its rule before the application goes"


async def test_client_registration_survives_a_reload_and_a_lost_application(
    hass: HomeAssistant, access: Access
) -> None:
    cf = access.cloudflare
    shown = await _register_client(
        hass, access.entry, "Alexa", ["https://layla.amazon.com/api/skill/link/x"]
    )
    await _settle(hass)
    client_id = cf.by_name(f"ha-access: client {HOSTNAME} Alexa")["id"]
    writes = len(cf.writes())

    assert await hass.config_entries.async_reload(access.entry.entry_id)
    await hass.async_block_till_done()
    assert len(cf.writes()) == writes, "a reload writes nothing"
    assert access.entry.runtime_data.client_apps == {next(iter(access.entry.subentries)): client_id}

    # the application was deleted in the dashboard: recreated, with new credentials
    del cf.apps[client_id]
    assert await hass.config_entries.async_reload(access.entry.entry_id)
    await hass.async_block_till_done()
    recreated = cf.by_name(f"ha-access: client {HOSTNAME} Alexa")
    assert recreated is not None and recreated["id"] != client_id
    sub = next(iter(access.entry.subentries.values()))
    assert sub.data["app_id"] == recreated["id"]
    assert sub.data["client_secret"] == cf.secrets[recreated["id"]] != shown["client_secret"]
    gate = cf.by_name(GATE)
    assert gate["policies"][-1]["include"] == [{"linked_app_token": {"app_uid": recreated["id"]}}]

    # an application left behind by a client removed while Home Assistant was down
    cf.apps["stray"] = {**recreated, "id": "stray", "name": f"ha-access: client {HOSTNAME} Old"}
    assert await hass.config_entries.async_reload(access.entry.entry_id)
    await hass.async_block_till_done()
    assert "stray" not in cf.apps


# --------------------------------------------------------------------------- removal, failures


async def test_remove_entry_deletes_every_application(hass: HomeAssistant, access: Access) -> None:
    cf = access.cloudflare
    await _save_options(hass, access.entry, **{CONF_EXTRA_BYPASS_PATHS: ["/api/webhook/x"]})
    await _register_client(hass, access.entry, "Google Home", ["https://example.com/cb"])
    assert len(cf.apps) == 3
    await hass.config_entries.async_remove(access.entry.entry_id)
    await hass.async_block_till_done()
    assert cf.apps == {}


async def test_remove_entry_keeps_apps_when_asked(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks, alice: User
) -> None:
    entry = make_entry(**{CONF_GATE_ENABLED: True, CONF_DELETE_OBJECTS_ON_REMOVE: False})
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.config_entries.async_remove(entry.entry_id)
    await hass.async_block_till_done()
    assert fake_cloudflare.by_name(GATE) is not None


async def test_auth_failure_triggers_reauth(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks, alice: User
) -> None:
    fake_cloudflare.auth_fail = True
    entry = make_entry(**{CONF_GATE_ENABLED: True})
    entry.add_to_hass(hass)
    assert not await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.SETUP_ERROR
    assert any(
        f["context"].get("source") == "reauth"
        for f in hass.config_entries.flow.async_progress_by_handler(entry.domain)
    )


async def test_5xx_during_setup_retries_and_writes_nothing(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks, alice: User
) -> None:
    fake_cloudflare.fail_status = 503
    entry = make_entry(**{CONF_GATE_ENABLED: True})
    entry.add_to_hass(hass)
    assert not await hass.config_entries.async_setup(entry.entry_id)
    assert entry.state is ConfigEntryState.SETUP_RETRY
    assert fake_cloudflare.writes() == []


async def test_4xx_config_error(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks, alice: User
) -> None:
    fake_cloudflare.fail_status = 400
    entry = make_entry(**{CONF_GATE_ENABLED: True})
    entry.add_to_hass(hass)
    assert not await hass.config_entries.async_setup(entry.entry_id)
    assert entry.state is ConfigEntryState.SETUP_ERROR
