"""Provisioning tests against the fake Cloudflare API."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

from aiohttp import web
from homeassistant.components.http.server import StaticPathConfig
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import EVENT_COMPONENT_LOADED
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers.http import HomeAssistantView
from homeassistant.setup import async_setup_component
from homeassistant.util.dt import utcnow
from pytest_homeassistant_custom_component.common import MockConfigEntry, async_fire_time_changed

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
    REDISCOVER_COOLDOWN_SECONDS,
)
from custom_components.cloudflare_access_relay.paths import (
    collapse_prefixes,
    discover_open_paths,
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
# always bypassed: the relay's own surface and the token-authenticated vendor endpoints
OWN = [
    "/cloudflare_access_relay/connect",
    "/cloudflare_access_relay/static",
    "/api/cloudflare_access_relay",
    "/api/google_assistant",
    "/api/alexa",
]
# what core serves to cookie-less clients, as the router exposes it on this Home Assistant version
CORE_OPEN = [
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/auth/authorize",
    "/auth/external/callback",
    "/auth/login_flow",
    "/auth/providers",
    "/auth/revoke",
    "/auth/token",
    "/frontend_es5",
    "/frontend_latest",
    "/onboarding.html",
    "/robots.txt",
    "/service_worker.js",
    "/static",
    "/sw-legacy.js",
    "/sw-legacy.js.map",
    "/sw-modern.js",
    "/sw-modern.js.map",
]


def _uris(app: dict[str, Any]) -> list[str]:
    return [d["uri"] for d in app["destinations"]]


def _expected(*extra: str) -> list[str]:
    return [f"{HOSTNAME}{p}" for p in collapse_prefixes({*CORE_OPEN, *OWN, *extra})]


async def test_discovery_finds_exactly_the_open_surface(hass: HomeAssistant, relay: Relay) -> None:
    found = discover_open_paths(hass)
    # the relay registers its own connect page and script before discovery runs
    assert found == sorted(
        [*CORE_OPEN, "/cloudflare_access_relay/connect", "/cloudflare_access_relay/static"]
    )
    for gated in (
        "/",
        "/api/websocket",
        "/api/onboarding",
        "/api/",
        "/local",
        "/manifest.json",
        "/cloudflare_access_relay/callback",
    ):
        assert gated not in found


def test_collapse_prefixes() -> None:
    assert collapse_prefixes(
        {"/auth/login_flow", "/auth", "/auth/token", "/static", "/statics"}
    ) == [
        "/auth",
        "/static",
        "/statics",
    ]


async def test_fresh_account_creates_two_apps(hass: HomeAssistant, relay: Relay) -> None:
    cf = relay.cloudflare
    posts = cf.writes("POST")
    assert [p[2]["name"] for p in posts] == [BYPASS, GATE], "bypass app is created first"
    assert cf.writes("PUT") == [] and cf.writes("DELETE") == []

    bypass = posts[0][2]
    assert bypass["type"] == "self_hosted"
    assert _uris(bypass) == _expected()
    assert bypass["domain"] == _expected()[0]
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
    assert _uris(puts[0][2]) == _expected("/api/webhook/abc123", "/api/google_assistant")
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


def test_token_caller_paths_are_always_bypassed() -> None:
    """Google's and Amazon's servers never hold a cookie; the paths are declared unconditionally."""
    paths = bypass_paths({CONF_EXTRA_BYPASS_PATHS: []}, CORE_OPEN)
    assert "/api/google_assistant" in paths
    assert "/api/alexa" in paths
    # normalised, de-duplicated and collapsed onto covering prefixes
    paths = bypass_paths({CONF_EXTRA_BYPASS_PATHS: ["/static/", "static/x", "/x/"]}, CORE_OPEN)
    assert paths.count("/static") == 1 and "/static/x" not in paths and paths[-1] == "/x"


async def test_integration_loaded_later_updates_bypass(hass: HomeAssistant, relay: Relay) -> None:
    """An integration set up after this entry gets its open paths bypassed without a reload."""
    cf = relay.cloudflare
    assert cf.writes("PUT") == []

    class InboundView(HomeAssistantView):
        url = "/api/fakevendor/inbound"
        name = "api:fakevendor:inbound"
        requires_auth = False

        async def post(self, request: web.Request) -> web.Response:
            return web.Response(text="ok")

    hass.http.register_view(InboundView())
    hass.bus.async_fire(EVENT_COMPONENT_LOADED, {"component": "fakevendor"})
    await hass.async_block_till_done()
    assert cf.writes("PUT") == [], "discovery is debounced"
    async_fire_time_changed(hass, utcnow() + timedelta(seconds=REDISCOVER_COOLDOWN_SECONDS + 1))
    await hass.async_block_till_done(wait_background_tasks=True)
    puts = cf.writes("PUT")
    assert [p[2]["name"] for p in puts] == [BYPASS]
    assert _uris(puts[0][2]) == _expected("/api/fakevendor/inbound")
    assert "/api/fakevendor/inbound" in relay.entry.runtime_data.open_paths

    # nothing new: no write
    hass.bus.async_fire(EVENT_COMPONENT_LOADED, {"component": "other"})
    async_fire_time_changed(hass, utcnow() + timedelta(seconds=2 * REDISCOVER_COOLDOWN_SECONDS + 2))
    await hass.async_block_till_done(wait_background_tasks=True)
    assert len(cf.writes("PUT")) == 1


async def test_login_integration_paths_are_discovered(
    hass: HomeAssistant, fake_cloudflare: FakeCloudflare, jwks_server: FakeJwks, tmp_path: Path
) -> None:
    """A login integration like hass-openid: unauthenticated /auth/ views and package assets."""
    hass.config.config_dir = str(tmp_path)
    package = Path(hass.config.path("custom_components", "fakelogin"))
    package.mkdir(parents=True)
    (package / "login.js").write_text("// login page script")
    www = Path(hass.config.path("www"))
    www.mkdir(parents=True)
    (www / "snapshot.jpg").write_bytes(b"not code")

    class LoginView(HomeAssistantView):
        url = "/auth/fakelogin/callback"
        name = "auth:fakelogin:callback"
        requires_auth = False

        async def get(self, request: web.Request) -> web.Response:
            return web.Response(text="ok")

    class SettingsView(HomeAssistantView):
        url = "/auth/fakelogin/settings"
        name = "auth:fakelogin:settings"
        requires_auth = True

        async def get(self, request: web.Request) -> web.Response:
            return web.Response(text="ok")

    await async_setup_component(hass, "http", {})
    hass.http.register_view(LoginView())
    hass.http.register_view(SettingsView())
    await hass.http.async_register_static_paths(
        [
            StaticPathConfig("/fakelogin/login.js", str(package / "login.js"), False),
            StaticPathConfig("/local", str(www), False),
        ]
    )
    entry = make_entry()
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    uris = _uris(fake_cloudflare.by_name(BYPASS))
    assert f"{HOSTNAME}/auth/fakelogin/callback" in uris
    assert f"{HOSTNAME}/fakelogin/login.js" in uris
    assert f"{HOSTNAME}/auth/fakelogin/settings" not in uris, "authenticated views stay gated"
    assert f"{HOSTNAME}/local" not in uris, "user content stays gated"


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
    app = desired_bypass_app({"hostname": HOSTNAME, "extra_bypass_paths": []}, CORE_OPEN)
    assert "self_hosted_domains" not in app
    assert all(d["type"] == "public" for d in app["destinations"])


def test_entry_type(config_entry: MockConfigEntry) -> None:
    assert config_entry.domain == "cloudflare_access_relay"
