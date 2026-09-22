"""Edge identity: token-bearing clients admitted by Access are authenticated at the origin."""

from __future__ import annotations

from typing import Any

from aiohttp import web
from homeassistant.auth.models import User
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.http import HomeAssistantView
from homeassistant.setup import async_setup_component
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.cloudflare_access_relay.const import DOMAIN, ISSUE_RESTART_REQUIRED
from custom_components.cloudflare_access_relay.users import allowed_emails

from .conftest import ALICE, BOB, HOSTNAME, Access, FakeCloudflare, FakeJwks, make_entry, token_for

HDR = "Cf-Access-Jwt-Assertion"
# what Access forwards after validating a managed-OAuth or registered-client token
FOREIGN = {"Authorization": "Bearer oauth:CvNooNotAHomeAssistantToken"}


def edge(**extra: str) -> dict[str, str]:
    """Headers of a request that came through Cloudflare for the gated hostname."""
    return {"Host": HOSTNAME, "CF-Ray": "8000abcd-LHR", **extra}


class WhoAmI(HomeAssistantView):
    url = "/api/whoami"
    name = "api:whoami"
    requires_auth = True

    async def get(self, request: web.Request) -> web.Response:
        return web.json_response({"user": request["hass_user"].id})


async def test_access_admitted_bearer_is_authenticated_as_the_mapped_user(
    hass: HomeAssistant, access: Access, alice: User, bob: User, hass_client_no_auth: Any
) -> None:
    hass.http.register_view(WhoAmI())
    client = await hass_client_no_auth()

    resp = await client.get("/api/whoami", headers={**FOREIGN, **edge(**{HDR: access.mint(ALICE)})})
    assert resp.status == 200 and (await resp.json())["user"] == alice.id
    resp = await client.get("/api/whoami", headers={**FOREIGN, **edge(**{HDR: access.mint(BOB)})})
    assert (await resp.json())["user"] == bob.id, "identity claim picks the user"

    resp = await client.get("/api/whoami", headers={**FOREIGN, **edge()})
    assert resp.status == 401, "no assertion: Home Assistant's own verdict on a foreign bearer"
    resp = await client.get("/api/whoami", headers={**FOREIGN, HDR: access.mint(ALICE)})
    assert resp.status == 401, "not through the edge: the assertion is not trusted"
    resp = await client.get(
        "/api/whoami", headers={**FOREIGN, **edge(**{HDR: access.mint("nobody@example.com")})}
    )
    assert resp.status == 401
    assert "no single Home Assistant user" in (await resp.json())["message"]
    bad = access.mint(ALICE)[:-2] + "AA"
    resp = await client.get("/api/whoami", headers={**FOREIGN, **edge(**{HDR: bad})})
    assert resp.status == 401 and "did not verify" in (await resp.json())["message"]


async def test_identity_is_the_login_username_without_configuration(
    hass: HomeAssistant, access: Access, alice: User, hass_client_no_auth: Any
) -> None:
    """A service token has no e-mail: its common name is matched like any login username."""
    from .conftest import add_user

    hass.http.register_view(WhoAmI())
    client = await hass_client_no_auth()
    machine = await add_user(hass, "ci-runner.access", name="CI runner")
    named = await hass.auth.async_create_user(ALICE)  # a display name is not a login
    assert named.id != alice.id
    service = access.mint(extra={"email": None, "sub": "", "common_name": "ci-runner.access"})
    resp = await client.get("/api/whoami", headers={**FOREIGN, **edge(**{HDR: service})})
    assert resp.status == 200 and (await resp.json())["user"] == machine.id

    resp = await client.get(
        "/api/whoami", headers={**FOREIGN, **edge(**{HDR: access.mint(ALICE.upper())})}
    )
    assert (await resp.json())["user"] == alice.id, "matched regardless of case"

    # a credential that carries no username (an OIDC subject) names nobody
    from homeassistant.auth.models import Credentials

    carol = await hass.auth.async_create_user("Carol")
    await hass.auth.async_link_user(
        carol,
        Credentials(
            auth_provider_type="auth_oidc",
            auth_provider_id=None,
            data={"sub": "idp-42"},
            is_new=False,
        ),
    )
    assert "carol" not in " ".join(allowed_emails(hass, {}))

    resp = await client.get(
        "/api/whoami", headers={**FOREIGN, **edge(**{HDR: access.mint(extra={"email": None})})}
    )
    assert resp.status == 401 and "neither email nor common_name" in (await resp.json())["message"]


async def test_a_login_email_names_a_user_whose_username_is_not_an_address(
    hass: HomeAssistant, access: Access, alice: User, hass_client_no_auth: Any
) -> None:
    from custom_components.cloudflare_access_relay.const import CONF_LOGIN_EMAILS

    from .conftest import add_user

    hass.http.register_view(WhoAmI())
    client = await hass_client_no_auth()
    dave = await add_user(hass, "dave", name="Dave")
    resp = await client.get(
        "/api/whoami", headers={**FOREIGN, **edge(**{HDR: access.mint("dave@example.com")})}
    )
    assert resp.status == 401, "no address yet"
    hass.config_entries.async_update_entry(
        access.entry,
        options={**access.entry.options, CONF_LOGIN_EMAILS: {dave.id: "Dave@example.com"}},
    )
    resp = await client.get(
        "/api/whoami", headers={**FOREIGN, **edge(**{HDR: access.mint("dave@example.com")})}
    )
    assert resp.status == 200 and (await resp.json())["user"] == dave.id


async def test_an_identity_shared_by_two_users_is_refused(
    hass: HomeAssistant, access: Access, alice: User, hass_client_no_auth: Any
) -> None:
    """Rather than guess, the origin serves neither user."""
    from .conftest import add_user

    hass.http.register_view(WhoAmI())
    client = await hass_client_no_auth()
    await add_user(hass, ALICE, name="Another Alice")  # a second login with the same username
    resp = await client.get("/api/whoami", headers={**FOREIGN, **edge(**{HDR: access.mint(ALICE)})})
    assert resp.status == 401 and "no single Home Assistant user" in (await resp.json())["message"]


async def test_home_assistant_tokens_and_cookie_sessions_are_untouched(
    hass: HomeAssistant, access: Access, alice: User, bob: User, hass_client_no_auth: Any
) -> None:
    hass.http.register_view(WhoAmI())
    client = await hass_client_no_auth()
    token = await token_for(hass, alice)
    ha = {"Authorization": f"Bearer {token}"}
    resp = await client.get("/api/whoami", headers={**ha, **edge(**{HDR: access.mint(BOB)})})
    assert (await resp.json())["user"] == alice.id, "a Home Assistant token wins over the assertion"
    resp = await client.get("/api/whoami", headers=edge(**{HDR: access.mint(ALICE)}))
    assert resp.status == 401, "no bearer at all: the assertion alone never authenticates"


async def test_disabled_gate_leaves_bearers_to_home_assistant(
    hass: HomeAssistant,
    fake_cloudflare: FakeCloudflare,
    jwks_server: FakeJwks,
    rsa_keys: Any,
    alice: User,
    hass_client_no_auth: Any,
) -> None:
    """Without a gate there is no audience to verify against: nothing is mapped."""
    from .conftest import Minter

    entry: MockConfigEntry = make_entry()
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    hass.http.register_view(WhoAmI())
    client = await hass_client_no_auth()
    assertion = Minter(rsa_keys, "some-aud")(ALICE)
    resp = await client.get("/api/whoami", headers={**FOREIGN, **edge(**{HDR: assertion})})
    assert resp.status == 401


async def test_setup_after_server_start_asks_for_a_restart(
    hass: HomeAssistant,
    fake_cloudflare: FakeCloudflare,
    jwks_server: FakeJwks,
    alice: User,
    hass_client_no_auth: Any,
) -> None:
    assert await async_setup_component(hass, "api", {})
    await hass_client_no_auth()  # starts the server: the app is frozen from here on
    entry: MockConfigEntry = make_entry()
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    assert ir.async_get(hass).async_get_issue(DOMAIN, ISSUE_RESTART_REQUIRED) is not None
