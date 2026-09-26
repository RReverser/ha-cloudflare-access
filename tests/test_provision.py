"""Provisioning tests against the fake Cloudflare API."""

from __future__ import annotations

from datetime import timedelta
from types import MappingProxyType
from typing import Any

from homeassistant.auth.models import User
from homeassistant.config_entries import ConfigEntryState, ConfigSubentry
from homeassistant.core import CoreState, HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import issue_registry as ir
from homeassistant.util.dt import utcnow
from pytest_homeassistant_custom_component.common import MockConfigEntry, async_fire_time_changed

from custom_components.cloudflare_access_relay.const import (
    CONF_DELETE_OBJECTS_ON_REMOVE,
    CONF_EXTRA_BYPASS_PATHS,
    CONF_GATE_ENABLED,
    CONF_SESSION_DURATION,
    DATA_BYPASS_APP_ID,
    DATA_GATE_APP_ID,
    DATA_POLICY_AUD,
    DATA_TEAM_DOMAIN,
    DOMAIN,
    ISSUE_NO_ALLOWED_USERS,
    RECONCILE_COOLDOWN_SECONDS,
)
from custom_components.cloudflare_access_relay.issues import issue_id
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


CLIENT_TYPES = ("self_registering_app", "console_app", "script")


def _client_sub(entry: MockConfigEntry) -> Any:
    """The one client subentry (user rows are subentries too)."""
    (sub,) = [s for s in entry.subentries.values() if s.subentry_type in CLIENT_TYPES]
    return sub


async def _settle(hass: HomeAssistant, rounds: int = 1) -> None:
    """Let the debounced reconciliation run.

    A reconciliation that writes the entry (subentry data, title) schedules another
    one; `rounds=2` lets that one run too.
    """
    async_fire_time_changed(
        hass, utcnow() + timedelta(seconds=rounds * (RECONCILE_COOLDOWN_SECONDS + 1))
    )
    await hass.async_block_till_done(wait_background_tasks=True)


# --------------------------------------------------------------------------- gate


async def test_gate_disabled_creates_nothing(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks, alice: User
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


async def test_a_script_client_gets_a_service_token_the_gate_accepts(
    hass: HomeAssistant, access: Access
) -> None:
    """A script client is a service token named like the applications; the gate names it."""
    cf = access.cloudflare
    shown = await _register_script(hass, access.entry, "Backup job")
    (token,) = cf.service_tokens.values()
    assert token["name"] == f"ha-access: client {HOSTNAME} Backup job"
    assert shown["client_id"] == token["client_id"] and len(shown["client_secret"]) == 32
    assert shown["expires_at"] == "2027-09-22", "the date the script stops working"
    sub = _client_sub(access.entry)
    assert sub.title == "Backup job" and sub.subentry_type == "script"
    assert (
        sub.data["token_id"] == token["id"] and sub.data["client_secret"] == shown["client_secret"]
    )
    await _settle(hass)
    gate = cf.by_name(GATE)
    assert [(p["name"], p["decision"]) for p in gate["policies"]] == [
        ("ha-access: allow", "allow"),
        ("ha-access: service tokens", "non_identity"),
    ]
    assert gate["policies"][1]["include"] == [{"service_token": {"token_id": token["id"]}}]

    # reconfiguring renames the token, extends its validity and shows the credentials again
    flow = await hass.config_entries.subentries.async_init(
        (access.entry.entry_id, "script"),
        context={"source": "reconfigure", "subentry_id": sub.subentry_id},
    )
    assert flow["type"] is FlowResultType.FORM and flow["step_id"] == "reconfigure"
    result = await hass.config_entries.subentries.async_configure(
        flow["flow_id"], {"name": "Nightly backup"}
    )
    assert result["type"] is FlowResultType.FORM and result["step_id"] == "credentials"
    assert result["description_placeholders"]["client_secret"] == shown["client_secret"]
    assert result["description_placeholders"]["expires_at"] == "2028-09-22"
    result = await hass.config_entries.subentries.async_configure(flow["flow_id"], {})
    assert result["type"] is FlowResultType.ABORT, result
    assert token["name"] == f"ha-access: client {HOSTNAME} Nightly backup"
    await _settle(hass)
    assert cf.by_name(GATE)["policies"][1]["include"] == [
        {"service_token": {"token_id": token["id"]}}
    ], "the same token, so the gate is not rewritten"

    # removing the client removes its rule from the gate and then deletes the token
    hass.config_entries.async_remove_subentry(access.entry, sub.subentry_id)
    await _settle(hass)
    assert [p["name"] for p in cf.by_name(GATE)["policies"]] == ["ha-access: allow"]
    assert cf.service_tokens == {}


async def test_a_lost_service_token_is_replaced_and_an_orphan_deleted(
    hass: HomeAssistant, access: Access
) -> None:
    cf = access.cloudflare
    await _register_script(hass, access.entry, "Probe")
    await _settle(hass)
    sub = _client_sub(access.entry)
    old_id = sub.data["token_id"]
    # deleted in the dashboard: replaced at the next reload, with new credentials
    cf.service_tokens.clear()
    cf.service_tokens["orphan"] = {
        "id": "orphan",
        "name": f"ha-access: client {HOSTNAME} Removed while HA was down",
        "client_id": "x.access",
        "expires_at": "2027-01-01T00:00:00Z",
    }
    cf.service_tokens["theirs"] = {"id": "theirs", "name": "unrelated", "client_id": "y.access"}
    assert await hass.config_entries.async_reload(access.entry.entry_id)
    await hass.async_block_till_done()
    sub = _client_sub(access.entry)
    assert sub.data["token_id"] != old_id and sub.data["token_id"] in cf.service_tokens
    assert set(cf.service_tokens) == {sub.data["token_id"], "theirs"}, (
        "the orphan of a client removed while Home Assistant was down goes; foreign tokens stay"
    )
    assert cf.by_name(GATE)["policies"][1]["include"] == [
        {"service_token": {"token_id": sub.data["token_id"]}}
    ]

    await hass.config_entries.async_remove(access.entry.entry_id)
    await hass.async_block_till_done()
    assert set(cf.service_tokens) == {"theirs"} and cf.apps == {}


async def test_legacy_service_token_option_becomes_script_clients(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks, alice: User
) -> None:
    cf = fake_cloudflare
    cf.service_tokens["tok-1"] = {
        "id": "tok-1",
        "name": "Garage script",
        "client_id": "abc.access",
        "expires_at": "2027-03-01T00:00:00Z",
    }
    entry = make_entry(**{CONF_GATE_ENABLED: True, "service_token_ids": ["tok-1", "gone"]})
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert "service_token_ids" not in entry.options
    sub = _client_sub(entry)
    assert sub.title == "Garage script" and sub.subentry_type == "script"
    assert sub.data["token_id"] == "tok-1" and sub.data["client_secret"] is None
    assert cf.by_name(GATE)["policies"][1]["include"] == [{"service_token": {"token_id": "tok-1"}}]
    assert "tok-1" in cf.service_tokens, "a token the integration did not create is kept"


# --------------------------------------------------------------------------- users


async def test_a_person_with_an_address_is_required(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks
) -> None:
    """Nobody could pass the gate: setup is refused until a person gets an address."""
    from custom_components.cloudflare_access_relay.const import CONF_LOGIN_EMAILS

    plain = await add_user(hass, "plain-username", name="Plain")
    await add_user(hass, "addon-api", name="Add-on API", person=False)
    entry = make_entry()
    entry.add_to_hass(hass)
    assert not await hass.config_entries.async_setup(entry.entry_id)
    assert entry.state is ConfigEntryState.SETUP_ERROR
    assert fake_cloudflare.writes() == []

    # the options' People section takes the address, even while the entry is in error
    flow = await hass.config_entries.options.async_init(entry.entry_id)
    people = flow["data_schema"].schema[
        next(k for k in flow["data_schema"].schema if k == "people")
    ]
    assert [str(k) for k in people.schema.schema] == ["Plain"], (
        "users without a person are not people"
    )
    result = await hass.config_entries.options.async_configure(
        flow["flow_id"], {CONF_GATE_ENABLED: False, "people": {"Plain": "plain@example.com"}}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY, result
    await hass.async_block_till_done()
    assert entry.options[CONF_LOGIN_EMAILS] == {plain.id: "plain@example.com"}
    assert entry.state is ConfigEntryState.LOADED
    assert entry.runtime_data.emails == ["plain@example.com"]

    # the gate lists the address; the form shows it again, and refuses to drop the last one
    await _save_options(hass, entry, **{CONF_GATE_ENABLED: True})
    assert fake_cloudflare.by_name(GATE)["policies"][0]["include"] == [
        {"email": {"email": "plain@example.com"}}
    ]
    flow = await hass.config_entries.options.async_init(entry.entry_id)
    people = flow["data_schema"].schema[
        next(k for k in flow["data_schema"].schema if k == "people")
    ]
    assert next(k for k in people.schema.schema if k == "Plain").default() == "plain@example.com"
    result = await hass.config_entries.options.async_configure(
        flow["flow_id"], {CONF_GATE_ENABLED: True, "people": {"Plain": ""}}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "no_allowed_users"}

    # a person whose username is an address is shown read-only and needs nothing; with
    # them present, Plain's address can be dropped and the policy follows
    await add_user(hass, "eve@example.com", name="Eve")
    await _settle(hass)
    flow = await hass.config_entries.options.async_init(entry.entry_id)
    people = flow["data_schema"].schema[
        next(k for k in flow["data_schema"].schema if k == "people")
    ]
    fields = {str(k): v for k, v in people.schema.schema.items()}
    assert fields["Eve"].config["read_only"] is True
    result = await hass.config_entries.options.async_configure(
        flow["flow_id"], {CONF_GATE_ENABLED: True, "people": {"Plain": ""}}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY, result
    await hass.async_block_till_done()
    assert fake_cloudflare.by_name(GATE)["policies"][0]["include"] == [
        {"email": {"email": "eve@example.com"}}
    ]


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
    assert (
        ir.async_get(hass).async_get_issue(DOMAIN, issue_id(access.entry, ISSUE_NO_ALLOWED_USERS))
        is not None
    )

    await add_user(hass, ALICE)
    await _settle(hass)
    assert cf.by_name(GATE)["policies"][0]["include"] == [{"email": {"email": ALICE}}]
    assert (
        ir.async_get(hass).async_get_issue(DOMAIN, issue_id(access.entry, ISSUE_NO_ALLOWED_USERS))
        is None
    )


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
        "grant": {"session_duration": "720h"},
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
    await _save_options(
        hass, access.entry, **{"bypass": {CONF_EXTRA_BYPASS_PATHS: ["/api/webhook/abc123"]}}
    )
    bypass = cf.by_name(BYPASS)
    assert bypass is not None and _uris(bypass) == [f"{HOSTNAME}/api/webhook/abc123"]
    assert access.entry.data[DATA_BYPASS_APP_ID] == bypass["id"]
    assert [p[2]["name"] for p in cf.writes("POST")] == [GATE, BYPASS]

    await _save_options(hass, access.entry, **{"bypass": {CONF_EXTRA_BYPASS_PATHS: []}})
    assert cf.by_name(BYPASS) is None
    assert access.entry.data[DATA_BYPASS_APP_ID] is None


async def test_session_duration_change_updates_gate_only(
    hass: HomeAssistant, access: Access
) -> None:
    cf = access.cloudflare
    await _save_options(hass, access.entry, **{CONF_SESSION_DURATION: {"hours": 24}})
    puts = cf.writes("PUT")
    assert [p[2]["name"] for p in puts] == [GATE]
    assert puts[0][2]["session_duration"] == "24h"
    assert puts[0][2]["oauth_configuration"]["grant"] == {"session_duration": "24h"}, (
        "a self-registered client's login lasts as long as a browser session"
    )
    assert access.entry.data[DATA_POLICY_AUD] == access.aud, "audience survives an update"


# --------------------------------------------------------------------------- clients


def access_entry_types(entry: MockConfigEntry) -> set[str]:
    """The subentry types the entry offers an "Add" item for: one per client kind."""
    return set(entry.supported_subentry_types)


async def _register_client(
    hass: HomeAssistant, entry: MockConfigEntry, name: str, uris: list[str]
) -> dict[str, Any]:
    """Drive the subentry flow for a console app; return the credentials page's placeholders."""
    assert access_entry_types(entry) == set(CLIENT_TYPES)
    flow = await hass.config_entries.subentries.async_init(
        (entry.entry_id, "console_app"), context={"source": "user"}
    )
    assert flow["type"] is FlowResultType.FORM and flow["step_id"] == "user", flow
    result = await hass.config_entries.subentries.async_configure(
        flow["flow_id"], {"name": name, "redirect_uris": uris}
    )
    assert result["type"] is FlowResultType.FORM and result["step_id"] == "credentials", result
    placeholders = dict(result["description_placeholders"])
    result = await hass.config_entries.subentries.async_configure(flow["flow_id"], {})
    assert result["type"] is FlowResultType.CREATE_ENTRY, result
    await hass.async_block_till_done()
    return placeholders


async def _register_script(
    hass: HomeAssistant, entry: MockConfigEntry, name: str
) -> dict[str, Any]:
    """Drive the subentry flow for a script client; return the credentials page's placeholders."""
    flow = await hass.config_entries.subentries.async_init(
        (entry.entry_id, "script"), context={"source": "user"}
    )
    assert flow["type"] is FlowResultType.FORM and flow["step_id"] == "user", flow
    result = await hass.config_entries.subentries.async_configure(flow["flow_id"], {"name": name})
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
    sub = _client_sub(access.entry)
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


async def test_only_applications_tagged_for_this_entry_are_touched(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks, alice: User
) -> None:
    """Same name, or even the stored id, without this entry's tag: somebody else's."""
    cf = fake_cloudflare
    foreign = {
        "id": "foreign",
        "type": "self_hosted",
        "name": GATE,
        "domain": HOSTNAME,
        "aud": "x",
        "policies": [{"name": "theirs", "decision": "allow", "include": [{"everyone": {}}]}],
    }
    cf.apps["foreign"] = dict(foreign)
    entry = make_entry(**{CONF_GATE_ENABLED: True})
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    tag = f"hass-{entry.entry_id.lower()}"
    assert tag in cf.tags, "the entry's tag is created on first use"
    assert cf.apps["foreign"] == foreign, "the foreign application was not updated"
    ours = [a for a in cf.apps.values() if a["name"] == GATE and a["id"] != "foreign"]
    assert len(ours) == 1 and ours[0]["tags"] == [tag]
    assert entry.data[DATA_GATE_APP_ID] == ours[0]["id"]

    # a stored id that points at a foreign application (a restored backup, say)
    hass.config_entries.async_update_entry(entry, data={**entry.data, DATA_GATE_APP_ID: "foreign"})
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done()
    assert cf.apps["foreign"] == foreign
    assert entry.data[DATA_GATE_APP_ID] == ours[0]["id"], "found again by name and tag"

    await hass.config_entries.async_remove(entry.entry_id)
    await hass.async_block_till_done()
    assert list(cf.apps) == ["foreign"]


async def test_self_registering_client_is_a_redirect_url_on_the_gate(
    hass: HomeAssistant, access: Access
) -> None:
    """A self-registering app gets no application: its URL is allowed to register, no more."""
    cf = access.cloudflare
    dcr = lambda: cf.by_name(GATE)["oauth_configuration"]["dynamic_client_registration"]  # noqa: E731
    assert dcr()["allowed_uris"] == []
    assert cf.by_name(GATE)["oauth_configuration"]["grant"] == {"session_duration": "720h"}
    apps_before = len(cf.apps)
    flow = await hass.config_entries.subentries.async_init(
        (access.entry.entry_id, "self_registering_app"), context={"source": "user"}
    )
    assert flow["type"] is FlowResultType.FORM and flow["step_id"] == "user", flow
    result = await hass.config_entries.subentries.async_configure(
        flow["flow_id"],
        {"name": "Claude", "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]},
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY, result
    await _settle(hass)
    assert dcr()["allowed_uris"] == ["https://claude.ai/api/mcp/auth_callback"]
    assert len(cf.apps) == apps_before, "nothing is created for a self-registering app"
    assert [p["name"] for p in cf.by_name(GATE)["policies"]] == ["ha-access: allow"]
    sub = _client_sub(access.entry)
    assert sub.title == "Claude" and sub.subentry_type == "self_registering_app"
    assert dict(sub.data) == {
        "name": "Claude",
        "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
    }

    # a changed URL follows on the gate
    flow = await hass.config_entries.subentries.async_init(
        (access.entry.entry_id, "self_registering_app"),
        context={"source": "reconfigure", "subentry_id": sub.subentry_id},
    )
    assert flow["type"] is FlowResultType.FORM and flow["step_id"] == "reconfigure"
    result = await hass.config_entries.subentries.async_configure(
        flow["flow_id"], {"name": "Claude", "redirect_uris": ["https://claude.ai/*"]}
    )
    assert result["type"] is FlowResultType.ABORT, result
    await _settle(hass)
    assert dcr()["allowed_uris"] == ["https://claude.ai/*"]

    # removal takes the URL off the list: no new registration, nothing else to revoke
    hass.config_entries.async_remove_subentry(access.entry, sub.subentry_id)
    await _settle(hass)
    assert dcr()["allowed_uris"] == []


async def test_clients_of_an_earlier_version_are_sorted_into_kinds(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks, alice: User
) -> None:
    """0.2.x had one client type with the kind in its data and gave every client that
    logged people in an application; a self-registering app cannot use one, so a client
    with published callbacks becomes one and its application is deleted as an orphan;
    any other client keeps its application as a console app."""
    cf = fake_cloudflare
    entry = make_entry(**{CONF_GATE_ENABLED: True}, minor_version=4)
    entry.add_to_hass(hass)
    for name, uris in (
        ("Claude", ["https://claude.ai/api/mcp/auth_callback"]),
        ("Google Home", ["https://oauth-redirect.googleusercontent.com/r/p"]),
    ):
        hass.config_entries.async_add_subentry(
            entry,
            ConfigSubentry(
                data=MappingProxyType(
                    {
                        "kind": "login",
                        "name": name,
                        "redirect_uris": uris,
                        "app_id": f"old-{name}",
                        "client_id": "cid",
                        "client_secret": "sec",
                    }
                ),
                subentry_type="oauth_client",  # the type of every client before 0.3.0
                title=name,
                unique_id=None,
            ),
        )
    tag = f"hass-{entry.entry_id.lower()}"
    for name in ("Claude", "Google Home"):
        cf.apps[f"old-{name}"] = {
            "id": f"old-{name}",
            "type": "saas",
            "name": f"ha-access: client {HOSTNAME} {name}",
            "tags": [tag],
            "saas_app": {"auth_type": "oidc", "client_id": "cid"},
            "policies": [],
        }
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.minor_version == 7
    subs = {s.title: s for s in entry.subentries.values()}
    assert subs["Claude"].subentry_type == "self_registering_app"
    assert dict(subs["Claude"].data) == {
        "name": "Claude",
        "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
    }
    assert subs["Google Home"].subentry_type == "console_app"
    assert subs["Google Home"].data["app_id"] == "old-Google Home"
    assert "kind" not in subs["Google Home"].data
    assert "old-Claude" not in cf.apps, "the application a self-registering app cannot use"
    assert "old-Google Home" in cf.apps
    gate = cf.by_name(GATE)
    assert gate["oauth_configuration"]["dynamic_client_registration"]["allowed_uris"] == [
        "https://claude.ai/api/mcp/auth_callback"
    ]
    assert gate["policies"][-1]["include"] == [{"linked_app_token": {"app_uid": "old-Google Home"}}]


async def test_options_based_clients_become_subentries_again(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks, alice: User
) -> None:
    """One release kept clients in the options instead of subentries: a callback-URL
    list, and a console-app / script dict each keyed by a generated id, in the same
    field shapes subentries use. Each becomes a subentry of the matching kind; a
    leftover option this storage's own bug could produce (a stray top-level copy of a
    dict entry) is dropped along with everything else not recognised."""
    cf = fake_cloudflare
    entry = make_entry(
        **{
            CONF_GATE_ENABLED: True,
            "client_redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
            "console_apps": {
                "app1": {
                    "name": "Google Home",
                    "redirect_uris": ["https://example.com/cb"],
                    "app_id": "old-app",
                    "client_id": "cid",
                    "client_secret": "sec",
                }
            },
            "scripts": {
                "script1": {
                    "name": "Backup job",
                    "token_id": "tok-1",
                    "client_id": "tid.access",
                    "client_secret": "tsec",
                    "expires_at": "2027-01-01T00:00:00Z",
                }
            },
            # the bug this migration also cleans up: a stray top-level copy
            "app1": {"name": "Google Home", "redirect_uris": ["https://example.com/cb"]},
        },
        minor_version=6,
    )
    entry.add_to_hass(hass)
    cf.apps["old-app"] = {
        "id": "old-app",
        "type": "saas",
        "name": f"ha-access: client {HOSTNAME} Google Home",
        "tags": [f"hass-{entry.entry_id.lower()}"],
        "saas_app": {"auth_type": "oidc", "client_id": "cid"},
        "policies": [],
    }
    cf.service_tokens["tok-1"] = {
        "id": "tok-1",
        "name": f"ha-access: client {HOSTNAME} Backup job",
        "client_id": "tid.access",
        "expires_at": "2027-01-01T00:00:00Z",
    }
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.minor_version == 7
    assert "app1" not in entry.options and "console_apps" not in entry.options
    assert "client_redirect_uris" not in entry.options and "scripts" not in entry.options
    subs = {s.title: s for s in entry.subentries.values()}
    assert subs["claude.ai"].subentry_type == "self_registering_app"
    assert subs["Google Home"].subentry_type == "console_app"
    assert dict(subs["Google Home"].data) == {
        "name": "Google Home",
        "redirect_uris": ["https://example.com/cb"],
        "app_id": "old-app",
        "client_id": "cid",
        "client_secret": "sec",
    }
    assert subs["Backup job"].subentry_type == "script"
    assert subs["Backup job"].data["token_id"] == "tok-1"


async def test_legacy_redirect_url_option_becomes_clients(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks, alice: User
) -> None:
    entry = make_entry(
        **{
            CONF_GATE_ENABLED: True,
            "client_redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
        }
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    assert "client_redirect_uris" not in entry.options
    subs = [s for s in entry.subentries.values() if s.subentry_type in CLIENT_TYPES]
    assert [(s.title, s.subentry_type, s.data["redirect_uris"]) for s in subs] == [
        ("claude.ai", "self_registering_app", ["https://claude.ai/api/mcp/auth_callback"])
    ]
    gate = fake_cloudflare.by_name(GATE)
    assert gate["oauth_configuration"]["dynamic_client_registration"]["allowed_uris"] == [
        "https://claude.ai/api/mcp/auth_callback"
    ]


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
    assert access.entry.runtime_data.client_apps == {
        _client_sub(access.entry).subentry_id: client_id
    }

    # the application was deleted in the dashboard: recreated, with new credentials
    del cf.apps[client_id]
    assert await hass.config_entries.async_reload(access.entry.entry_id)
    await hass.async_block_till_done()
    recreated = cf.by_name(f"ha-access: client {HOSTNAME} Alexa")
    assert recreated is not None and recreated["id"] != client_id
    sub = _client_sub(access.entry)
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


async def test_disabling_the_entry_takes_the_gate_down_and_enabling_brings_it_back(
    hass: HomeAssistant, access: Access
) -> None:
    from homeassistant.config_entries import ConfigEntryDisabler

    cf = access.cloudflare
    await _save_options(hass, access.entry, **{"bypass": {CONF_EXTRA_BYPASS_PATHS: ["/api/open"]}})
    await _register_client(hass, access.entry, "Google Home", ["https://example.com/cb"])
    await _settle(hass)
    gate_id = access.entry.data[DATA_GATE_APP_ID]
    assert len(cf.apps) == 3

    # a reload leaves the edge alone
    assert await hass.config_entries.async_reload(access.entry.entry_id)
    await hass.async_block_till_done()
    assert gate_id in cf.apps

    await hass.config_entries.async_set_disabled_by(access.entry.entry_id, ConfigEntryDisabler.USER)
    await hass.async_block_till_done()
    assert access.entry.state is ConfigEntryState.NOT_LOADED
    assert cf.by_name(GATE) is None and cf.by_name(BYPASS) is None, "the hostname is open again"
    assert [a["name"] for a in cf.apps.values()] == [f"ha-access: client {HOSTNAME} Google Home"]
    assert access.entry.data[DATA_GATE_APP_ID] is None
    assert access.entry.data[DATA_POLICY_AUD] is None

    await hass.config_entries.async_set_disabled_by(access.entry.entry_id, None)
    await hass.async_block_till_done()
    assert access.entry.state is ConfigEntryState.LOADED
    gate = cf.by_name(GATE)
    assert gate is not None and gate["id"] != gate_id and cf.by_name(BYPASS) is not None
    assert access.entry.data[DATA_POLICY_AUD] == gate["aud"]
    assert gate["policies"][-1]["include"][0]["linked_app_token"], "the client rule is back"


async def test_disabling_an_entry_in_error_still_takes_the_gate_down(
    hass: HomeAssistant, access: Access
) -> None:
    """An entry that is not loaded is never unloaded; the state change is caught instead."""
    from homeassistant.config_entries import ConfigEntryDisabler

    cf = access.cloudflare
    gate_id = access.entry.data[DATA_GATE_APP_ID]
    cf.fail_status = 400
    assert not await hass.config_entries.async_reload(access.entry.entry_id)
    assert access.entry.state is ConfigEntryState.SETUP_ERROR
    assert gate_id in cf.apps, "a failed setup changes nothing at the edge"

    cf.fail_status = None
    await hass.config_entries.async_set_disabled_by(access.entry.entry_id, ConfigEntryDisabler.USER)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert cf.by_name(GATE) is None
    assert access.entry.data[DATA_GATE_APP_ID] is None


async def test_an_entry_disabled_before_a_restart_is_taken_down_at_start(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks, alice: User
) -> None:
    from homeassistant.config_entries import ConfigEntryDisabler
    from homeassistant.setup import async_setup_component

    cf = fake_cloudflare
    entry = make_entry(**{CONF_GATE_ENABLED: True})
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    gate_id = entry.data[DATA_GATE_APP_ID]
    # disabled while Home Assistant was shutting down: the integration leaves the gate
    # up when `hass.is_stopping`
    hass.set_state(CoreState.stopping)
    await hass.config_entries.async_set_disabled_by(entry.entry_id, ConfigEntryDisabler.USER)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert gate_id in cf.apps and entry.data[DATA_GATE_APP_ID] == gate_id

    # the next start finds the disabled entry and takes the gate down
    hass.set_state(CoreState.running)
    # async_setup_component skips a domain already in hass.config.components; forget
    # the integration so its async_setup runs again as it would after a restart
    hass.data.pop(DOMAIN, None)
    hass.config.components.remove(DOMAIN)
    assert await async_setup_component(hass, DOMAIN, {})
    await hass.async_block_till_done(wait_background_tasks=True)
    assert gate_id not in cf.apps and entry.data[DATA_GATE_APP_ID] is None


async def test_the_gate_sends_people_straight_to_the_only_login_method(
    hass: HomeAssistant, access: Access
) -> None:
    cf = access.cloudflare
    gate = cf.by_name(GATE)
    assert gate["allowed_idps"] == ["otp-1"] and gate["auto_redirect_to_identity"] is True
    assert "People" in gate["custom_deny_message"]
    assert gate["custom_deny_message"].replace(" ", "").isalnum(), "Cloudflare refuses punctuation"
    assert len(gate["custom_deny_message"]) <= 75, "Cloudflare's limit"
    await _register_client(hass, access.entry, "Google Home", ["https://example.com/cb"])
    client = cf.by_name(f"ha-access: client {HOSTNAME} Google Home")
    assert client["allowed_idps"] == ["otp-1"] and client["auto_redirect_to_identity"] is True

    # a second login method brings Cloudflare's picker page back
    cf.identity_providers.append(
        {"id": "google-1", "name": "Google", "type": "google", "config": {}}
    )
    assert await hass.config_entries.async_reload(access.entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    gate = cf.by_name(GATE)
    assert gate["allowed_idps"] == [] and gate["auto_redirect_to_identity"] is False


async def test_a_person_who_loses_access_is_logged_out(
    hass: HomeAssistant, access: Access, bob: User
) -> None:
    """Dropping an address from the allow rule alone leaves the person's session valid."""

    cf = access.cloudflare
    assert cf.revoked == []
    await hass.auth.async_remove_user(bob)
    await _settle(hass)
    assert cf.by_name(GATE)["policies"][0]["include"] == [{"email": {"email": ALICE}}]
    assert cf.revoked == [BOB]

    # an address dropped while Home Assistant was down is found on the gate at the next start
    cf.apps[access.entry.data[DATA_GATE_APP_ID]]["policies"][0]["include"].append(
        {"email": {"email": "Gone@example.com"}}
    )
    assert await hass.config_entries.async_reload(access.entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert cf.revoked == [BOB, "gone@example.com"]

    # a credential that cannot revoke leaves the session and asks for a new sign-in
    carol = await add_user(hass, "carol@example.com", name="Carol")
    await _settle(hass)
    cf.fail_status, cf.fail_predicate = 403, lambda _m, path: path.endswith("/revoke_user")
    await hass.auth.async_remove_user(carol)
    await _settle(hass)
    assert cf.revoked == [BOB, "gone@example.com"]
    reauth = [
        f
        for f in hass.config_entries.flow.async_progress_by_handler(DOMAIN)
        if f["context"].get("source") == "reauth"
    ]
    assert len(reauth) == 1 and reauth[0]["context"]["entry_id"] == access.entry.entry_id


async def test_the_gate_follows_a_changed_external_url(hass: HomeAssistant, access: Access) -> None:
    """The hostname is the External URL's: a change renames everything, a removal freezes it."""
    from homeassistant.helpers import issue_registry as ir

    cf = access.cloudflare
    await _register_script(hass, access.entry, "Probe")
    await _settle(hass)
    gate_id = access.entry.data[DATA_GATE_APP_ID]
    await hass.config.async_update(external_url="https://new.example.com")
    await _settle(hass)
    gate = cf.apps[gate_id]
    assert gate["name"] == "ha-access: gate new.example.com" and gate["domain"] == "new.example.com"
    assert access.entry.title == "new.example.com" and access.entry.unique_id == "new.example.com"
    (token,) = cf.service_tokens.values()
    assert token["name"] == "ha-access: client new.example.com Probe"

    await hass.config.async_update(external_url=None)
    await _settle(hass)
    assert cf.apps[gate_id]["domain"] == "new.example.com", "nothing torn down"
    assert (
        ir.async_get(hass).async_get_issue(DOMAIN, f"no_external_url_{access.entry.entry_id}")
        is not None
    )
    await hass.config.async_update(external_url="https://new.example.com")
    await _settle(hass)
    assert (
        ir.async_get(hass).async_get_issue(DOMAIN, f"no_external_url_{access.entry.entry_id}")
        is None
    )

    # a restart without an External URL refuses to set up, with a clear reason
    await hass.config.async_update(external_url=None)
    assert not await hass.config_entries.async_reload(access.entry.entry_id)
    assert access.entry.state is ConfigEntryState.SETUP_ERROR
    assert "External URL" in str(access.entry.reason)


async def test_a_hostname_outside_the_account_is_refused(
    hass: HomeAssistant, access: Access
) -> None:
    """Cloudflare refuses a foreign hostname: a repair on change, a clear error at setup."""
    cf = access.cloudflare
    gate_id = access.entry.data[DATA_GATE_APP_ID]
    await hass.config.async_update(external_url="https://ha.elsewhere.net")
    await _settle(hass)
    assert cf.apps[gate_id]["domain"] == HOSTNAME, "the gate keeps guarding the last hostname"
    assert access.entry.title == HOSTNAME, "the entry follows the gate, not the External URL"
    issue = ir.async_get(hass).async_get_issue(DOMAIN, issue_id(access.entry, "update_failed"))
    assert issue is not None and issue.translation_placeholders is not None
    assert issue.translation_placeholders["hostname"] == HOSTNAME
    assert "does not belong to zone" in issue.translation_placeholders["error"]

    # back to a hostname of the account: the gate follows and the repair goes
    await hass.config.async_update(external_url="https://again.example.com")
    await _settle(hass)
    assert cf.apps[gate_id]["domain"] == "again.example.com"
    assert access.entry.title == "again.example.com"
    assert (
        ir.async_get(hass).async_get_issue(DOMAIN, issue_id(access.entry, "update_failed")) is None
    )

    # a restart with the foreign hostname refuses to set up, quoting Cloudflare
    await hass.config.async_update(external_url="https://ha.elsewhere.net")
    assert not await hass.config_entries.async_reload(access.entry.entry_id)
    assert access.entry.state is ConfigEntryState.SETUP_ERROR
    assert "ha.elsewhere.net" in str(access.entry.reason)
    assert "does not belong to zone" in str(access.entry.reason)


async def test_a_failed_update_raises_a_repair_and_is_retried(
    hass: HomeAssistant, access: Access
) -> None:
    """Any other refusal of an update becomes a repair; the next change retries."""
    cf = access.cloudflare
    gate_id = access.entry.data[DATA_GATE_APP_ID]
    cf.fail_status = 503
    cf.fail_predicate = lambda method, _path: method == "PUT"
    await hass.config.async_update(external_url="https://new.example.com")
    await _settle(hass)
    assert cf.apps[gate_id]["domain"] == HOSTNAME
    issue = ir.async_get(hass).async_get_issue(DOMAIN, issue_id(access.entry, "update_failed"))
    assert issue is not None and "error" in issue.translation_placeholders

    cf.fail_status = None
    cf.fail_predicate = None
    await hass.config.async_update(external_url="https://newer.example.com")
    await _settle(hass)
    assert cf.apps[gate_id]["domain"] == "newer.example.com"
    assert (
        ir.async_get(hass).async_get_issue(DOMAIN, issue_id(access.entry, "update_failed")) is None
    )


async def test_the_sensors_of_an_earlier_version_are_removed_from_the_registries(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks, alice: User
) -> None:
    from homeassistant.helpers import device_registry as dr, entity_registry as er

    entry = make_entry()
    entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(entry, minor_version=3)
    device = dr.async_get(hass).async_get_or_create(
        config_entry_id=entry.entry_id, identifiers={(DOMAIN, entry.entry_id)}, name=HOSTNAME
    )
    er.async_get(hass).async_get_or_create(
        "sensor", DOMAIN, f"{entry.entry_id}-alice", config_entry=entry, device_id=device.id
    )
    assert await hass.config_entries.async_setup(entry.entry_id)
    assert entry.minor_version == 7
    assert er.async_entries_for_config_entry(er.async_get(hass), entry.entry_id) == []
    assert dr.async_entries_for_config_entry(dr.async_get(hass), entry.entry_id) == []


async def test_remove_entry_deletes_every_application(hass: HomeAssistant, access: Access) -> None:
    cf = access.cloudflare
    await _save_options(
        hass, access.entry, **{"bypass": {CONF_EXTRA_BYPASS_PATHS: ["/api/webhook/x"]}}
    )
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
