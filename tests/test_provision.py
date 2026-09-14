"""Provisioning tests against the fake Cloudflare API."""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.cloudflare_access_relay.const import (
    CONF_ACCESS_GROUP_ID,
    CONF_ALLOWED_EMAILS,
    CONF_DELETE_OBJECTS_ON_REMOVE,
    CONF_EXTRA_BYPASS_PATHS,
    CONF_GATE_ENABLED,
    CONF_SESSION_DURATION,
    DATA_BYPASS_APP_ID,
    DATA_GATE_APP_ID,
    DATA_POLICY_AUD,
    DATA_TEAM_DOMAIN,
)
from custom_components.cloudflare_access_relay.provision import (
    app_matches,
    bypass_paths,
    desired_bypass_app,
    desired_gate_app,
)

from .conftest import ALICE, BOB, HOSTNAME, TEAM_DOMAIN, FakeCloudflare, FakeJwks, Relay, make_entry

GATE = f"ha-relay: gate {HOSTNAME}"
BYPASS = f"ha-relay: bypass {HOSTNAME}"
EXPECTED_BYPASS = [
    f"{HOSTNAME}/auth",
    f"{HOSTNAME}/frontend_latest",
    f"{HOSTNAME}/frontend_es5",
    f"{HOSTNAME}/static",
    f"{HOSTNAME}/cloudflare_access_relay/connect",
    f"{HOSTNAME}/cloudflare_access_relay/static",
    f"{HOSTNAME}/api/cloudflare_access_relay",
]


def _uris(app: dict[str, Any]) -> list[str]:
    return [d["uri"] for d in app["destinations"]]


async def test_fresh_account_creates_two_apps(hass: HomeAssistant, relay: Relay) -> None:
    cf = relay.cloudflare
    posts = cf.writes("POST")
    assert [p[2]["name"] for p in posts] == [BYPASS, GATE], "bypass app is created first"
    assert cf.writes("PUT") == [] and cf.writes("DELETE") == []

    bypass = posts[0][2]
    assert bypass["type"] == "self_hosted"
    assert _uris(bypass) == EXPECTED_BYPASS
    assert bypass["domain"] == EXPECTED_BYPASS[0]
    assert bypass["policies"] == [
        {
            "name": "ha-relay: bypass everyone",
            "decision": "bypass",
            "precedence": 1,
            "include": [{"everyone": {}}],
        }
    ]

    gate = posts[1][2]
    assert gate["domain"] == f"{HOSTNAME}/cloudflare_access_relay/callback", (
        "gate disabled: callback only"
    )
    assert _uris(gate) == [gate["domain"]]
    assert gate["session_duration"] == "720h"
    assert gate["enable_binding_cookie"] is False
    assert gate["path_cookie_attribute"] is False
    assert gate["http_only_cookie_attribute"] is True
    assert gate["same_site_cookie_attribute"] == "lax"
    assert gate["policies"] == [
        {
            "name": "ha-relay: allow",
            "decision": "allow",
            "precedence": 1,
            "include": [{"email": {"email": ALICE}}, {"email": {"email": BOB}}],
        }
    ]

    entry = relay.entry
    assert entry.data[DATA_TEAM_DOMAIN] == TEAM_DOMAIN
    assert entry.data[DATA_POLICY_AUD] == cf.by_name(GATE)["aud"]
    assert entry.data[DATA_GATE_APP_ID] == cf.by_name(GATE)["id"]
    assert entry.data[DATA_BYPASS_APP_ID] == cf.by_name(BYPASS)["id"]
    assert entry.state is ConfigEntryState.LOADED


async def test_second_setup_writes_nothing(hass: HomeAssistant, relay: Relay) -> None:
    cf = relay.cloudflare
    assert len(cf.writes()) == 2
    assert await hass.config_entries.async_reload(relay.entry.entry_id)
    await hass.async_block_till_done()
    assert relay.entry.state is ConfigEntryState.LOADED
    assert len(cf.writes()) == 2


async def test_recovers_apps_by_name_when_ids_lost(hass: HomeAssistant, relay: Relay) -> None:
    cf = relay.cloudflare
    hass.config_entries.async_update_entry(
        relay.entry,
        data={
            k: v
            for k, v in relay.entry.data.items()
            if k not in (DATA_GATE_APP_ID, DATA_BYPASS_APP_ID)
        },
    )
    assert await hass.config_entries.async_reload(relay.entry.entry_id)
    await hass.async_block_till_done()
    assert len(cf.writes()) == 2
    assert relay.entry.data[DATA_GATE_APP_ID] == cf.by_name(GATE)["id"]


async def test_options_change_updates_bypass_only(hass: HomeAssistant, relay: Relay) -> None:
    cf = relay.cloudflare
    flow = await hass.config_entries.options.async_init(relay.entry.entry_id)
    assert flow["type"] is FlowResultType.FORM
    result = await hass.config_entries.options.async_configure(
        flow["flow_id"],
        {
            CONF_GATE_ENABLED: False,
            CONF_ALLOWED_EMAILS: [ALICE, BOB],
            CONF_ACCESS_GROUP_ID: "",
            CONF_EXTRA_BYPASS_PATHS: ["/api/webhook/abc123", "api/google_assistant/"],
            CONF_SESSION_DURATION: "720h",
        },
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()
    puts = cf.writes("PUT")
    assert len(puts) == 1
    assert puts[0][2]["name"] == BYPASS
    assert _uris(puts[0][2]) == [
        *EXPECTED_BYPASS,
        f"{HOSTNAME}/api/webhook/abc123",
        f"{HOSTNAME}/api/google_assistant",
    ]
    assert len(cf.writes("POST")) == 2
    # inline policy id reused on update
    assert puts[0][2]["policies"][0]["id"] == cf.by_name(BYPASS)["policies"][0]["id"]


async def test_enable_gate_widens_gate_app(hass: HomeAssistant, relay: Relay) -> None:
    cf = relay.cloudflare
    aud_before = relay.entry.data[DATA_POLICY_AUD]
    flow = await hass.config_entries.options.async_init(relay.entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        flow["flow_id"],
        {CONF_GATE_ENABLED: True, CONF_ALLOWED_EMAILS: [ALICE], CONF_ACCESS_GROUP_ID: ""},
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()
    puts = cf.writes("PUT")
    assert [p[2]["name"] for p in puts] == [GATE]
    assert puts[0][2]["domain"] == HOSTNAME
    assert _uris(puts[0][2]) == [HOSTNAME]
    assert puts[0][2]["policies"][0]["include"] == [{"email": {"email": ALICE}}]
    assert relay.entry.data[DATA_POLICY_AUD] == aud_before


async def test_access_group_replaces_emails(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks
) -> None:
    entry = make_entry(**{CONF_ALLOWED_EMAILS: [], CONF_ACCESS_GROUP_ID: "grp-1"})
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    gate = fake_cloudflare.by_name(GATE)
    assert gate["policies"][0]["include"] == [{"group": {"id": "grp-1"}}]


async def test_openid_paths_only_when_loaded(hass: HomeAssistant) -> None:
    opts = {CONF_EXTRA_BYPASS_PATHS: []}
    assert "/openid" not in bypass_paths(opts, set())
    assert "/openid" in bypass_paths(opts, {"openid"})
    assert "/api/google_assistant" in bypass_paths(opts, {"google_assistant"})
    assert "/api/alexa" in bypass_paths(opts, {"alexa"})
    # de-duplicated and normalised
    assert (
        bypass_paths({CONF_EXTRA_BYPASS_PATHS: ["/static/", "static", "/x/"]}, set()).count(
            "/static"
        )
        == 1
    )
    assert bypass_paths({CONF_EXTRA_BYPASS_PATHS: ["/x/"]}, set())[-1] == "/x"


async def test_openid_loaded_at_setup(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks
) -> None:
    hass.config.components.add("openid")
    entry = make_entry()
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    assert f"{HOSTNAME}/openid" in _uris(fake_cloudflare.by_name(BYPASS))


async def test_remove_entry_deletes_apps(hass: HomeAssistant, relay: Relay) -> None:
    cf = relay.cloudflare
    await hass.config_entries.async_remove(relay.entry.entry_id)
    await hass.async_block_till_done()
    deletes = cf.writes("DELETE")
    assert len(deletes) == 2
    assert deletes[0][1].endswith(relay.entry.data[DATA_GATE_APP_ID]), "gate deleted first"
    assert cf.apps == {}


async def test_remove_entry_keeps_apps_when_asked(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks
) -> None:
    entry = make_entry(**{CONF_DELETE_OBJECTS_ON_REMOVE: False})
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.config_entries.async_remove(entry.entry_id)
    await hass.async_block_till_done()
    assert fake_cloudflare.writes("DELETE") == []
    assert len(fake_cloudflare.apps) == 2


async def test_auth_failure_triggers_reauth(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks
) -> None:
    fake_cloudflare.auth_fail = True
    entry = make_entry()
    entry.add_to_hass(hass)
    assert not await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.SETUP_ERROR
    assert fake_cloudflare.writes() == []
    flows = hass.config_entries.flow.async_progress_by_handler("cloudflare_access_relay")
    assert flows and flows[0]["context"]["source"] == "reauth"


async def test_5xx_during_setup_retries_and_writes_nothing(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks
) -> None:
    fake_cloudflare.fail_status = 503
    entry = make_entry()
    entry.add_to_hass(hass)
    assert not await hass.config_entries.async_setup(entry.entry_id)
    assert entry.state is ConfigEntryState.SETUP_RETRY
    assert fake_cloudflare.apps == {}


async def test_gate_failure_after_bypass_is_recovered(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks
) -> None:
    fake_cloudflare.fail_status = 502
    fake_cloudflare.fail_predicate = lambda method, path: (
        method == "POST" and any(r[0] == "POST" for r in fake_cloudflare.requests[:-1])
    )
    entry = make_entry()
    entry.add_to_hass(hass)
    assert not await hass.config_entries.async_setup(entry.entry_id)
    assert entry.state is ConfigEntryState.SETUP_RETRY
    assert [a["name"] for a in fake_cloudflare.apps.values()] == [BYPASS]
    fake_cloudflare.fail_status = None
    assert await hass.config_entries.async_reload(entry.entry_id)
    assert entry.state is ConfigEntryState.LOADED
    assert sorted(a["name"] for a in fake_cloudflare.apps.values()) == [BYPASS, GATE]
    created = [w[2]["name"] for w in fake_cloudflare.writes("POST")]
    assert created.count(BYPASS) == 1, "bypass app reused, not duplicated"
    assert len(fake_cloudflare.apps) == 2


async def test_4xx_config_error(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks
) -> None:
    fake_cloudflare.fail_status = 400
    entry = make_entry()
    entry.add_to_hass(hass)
    assert not await hass.config_entries.async_setup(entry.entry_id)
    assert entry.state is ConfigEntryState.SETUP_ERROR


def test_app_matches_ignores_server_side_fields() -> None:
    opts = {"hostname": HOSTNAME, "allowed_emails": [ALICE], "gate_enabled": True}
    desired = desired_gate_app(opts)
    existing = {
        **desired,
        "id": "x",
        "aud": "y",
        "created_at": "now",
        "policies": [
            {
                **desired["policies"][0],
                "id": "p",
                "exclude": [],
                "require": [],
                "session_duration": "24h",
            }
        ],
    }
    assert app_matches(existing, desired)
    existing["session_duration"] = "24h"
    assert not app_matches(existing, desired)
    existing["session_duration"] = desired["session_duration"]
    existing["policies"][0]["include"] = [{"email": {"email": BOB}}]
    assert not app_matches(existing, desired)


def test_app_matches_treats_absent_fields_as_cloudflare_defaults() -> None:
    """Cloudflare's GET omits path_cookie_attribute (and others) when they are default."""
    opts = {"hostname": HOSTNAME, "allowed_emails": [ALICE], "gate_enabled": True}
    desired = desired_gate_app(opts)
    existing = {k: v for k, v in desired.items() if k != "path_cookie_attribute"}
    existing["policies"] = [{**p, "id": "p1"} for p in desired["policies"]]
    assert app_matches(existing, desired)
    existing["path_cookie_attribute"] = True
    assert not app_matches(existing, desired)


def test_desired_bypass_uses_destinations_not_deprecated_field() -> None:
    app = desired_bypass_app({"hostname": HOSTNAME, "extra_bypass_paths": []}, set())
    assert "self_hosted_domains" not in app
    assert all(d["type"] == "public" for d in app["destinations"])


def test_entry_type(config_entry: MockConfigEntry) -> None:
    assert config_entry.domain == "cloudflare_access_relay"
