"""Maintain the project's Cloudflare OAuth client (the "Sign in with Cloudflare" client).

Run by the maintainer through the `oauth-client` workflow with the repository's CI
token, or locally with CF_API_TOKEN and CF_ACCOUNT_ID set:

    uv run python -m scripts.oauth_client setup      # grant + create + verify
    uv run python -m scripts.oauth_client publish --yes
    uv run python -m scripts.oauth_client show

`grant` gives the token itself the permissions the other commands need (OAuth
Clients Write on the account, DNS Write on the client URL's zone) and the Access
permissions the live tests exercise; it needs the token to carry "API Tokens Edit". `create` creates the client, or updates it when
one with the same name exists. `verify` adds the domain-verification TXT record
Cloudflare asks for and waits until Cloudflare has seen it. `publish` makes the
client public, which is permanent; it needs --yes.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from custom_components.cloudflare_access_relay.const import OAUTH_SCOPES

API = "https://api.cloudflare.com/client/v4"
CLIENT_NAME = "Cloudflare Access for Home Assistant"
REDIRECT_URI = "https://my.home-assistant.io/redirect/oauth"
REPO_URL = "https://github.com/RReverser/ha-cloudflare-access"
DEFAULT_CLIENT_URI = "https://rreverser.com"
DEFAULT_LOGO_URI = "https://raw.githubusercontent.com/RReverser/ha-cloudflare-access/main/logo.png"
# Protocol scopes are derived by Cloudflare from the grant types, not registered.
CLIENT_SCOPES = [s for s in OAUTH_SCOPES if s not in ("offline_access", "openid")]
VERIFY_TIMEOUT = 20 * 60
VERIFY_INTERVAL = 20


class Api:
    """A thin client over the Cloudflare v4 API."""

    def __init__(self, token: str, account_id: str) -> None:
        self.account_id = account_id
        self._http = httpx.Client(
            base_url=API, headers={"Authorization": f"Bearer {token}"}, timeout=60
        )

    def call(self, method: str, path: str, **kwargs: Any) -> Any:
        """Call the API and return `result`, raising with the error list on failure."""
        resp = self._http.request(method, path, **kwargs)
        body = resp.json()
        if not body.get("success"):
            raise SystemExit(f"{method} {path} failed ({resp.status_code}): {body.get('errors')}")
        return body["result"]

    def list_all(self, path: str, **params: Any) -> list[dict[str, Any]]:
        """Return every item of a paged listing."""
        items: list[dict[str, Any]] = []
        page = 1
        while True:
            batch = self.call("GET", path, params={**params, "page": page, "per_page": 50})
            new = [b for b in batch if b not in items]
            items.extend(new)
            # a listing that ignores paging answers every page alike
            if len(batch) < 50 or not new:
                return items
            page += 1


def zone_for(api: Api, host: str) -> dict[str, Any]:
    """Return the zone that serves `host` (the longest matching suffix)."""
    zones = api.list_all("/zones", **{"account.id": api.account_id})
    matches = [z for z in zones if host == z["name"] or host.endswith("." + z["name"])]
    if not matches:
        raise SystemExit(f"no zone in the account serves {host}")
    return max(matches, key=lambda z: len(z["name"]))


def find_client(api: Api) -> dict[str, Any] | None:
    """Return the project's client, by name, if it exists."""
    clients = api.list_all(f"/accounts/{api.account_id}/oauth_clients")
    return next((c for c in clients if c.get("client_name") == CLIENT_NAME), None)


def permission_group(groups: list[dict[str, Any]], pattern: str, scope: str) -> dict[str, Any]:
    """Return the permission group whose name matches `pattern` for the resource scope."""
    found = [
        g
        for g in groups
        if re.search(pattern, g["name"], re.IGNORECASE) and scope in (g.get("scopes") or [scope])
    ]
    if len(found) != 1:
        names = sorted(g["name"] for g in groups if scope in (g.get("scopes") or [scope]))
        raise SystemExit(f"{len(found)} permission groups match {pattern!r}; available: {names}")
    return found[0]


def cmd_grant(api: Api, args: argparse.Namespace) -> None:
    """Give this token OAuth Clients Write and DNS Write on the client URL's zone."""
    me = api.call("GET", "/user/tokens/verify")
    token = api.call("GET", f"/user/tokens/{me['id']}")
    groups = api.call("GET", "/user/tokens/permission_groups")
    zone = zone_for(api, urlparse(args.client_uri).hostname or "")
    account = {f"com.cloudflare.api.account.{api.account_id}": "*"}
    wanted = [
        # Listing needs Read; Write alone answers "Authentication error" to a GET.
        (permission_group(groups, r"oauth.?clients?.*read", "com.cloudflare.api.account"), account),
        (
            permission_group(
                groups, r"oauth.?clients?.*(write|edit)", "com.cloudflare.api.account"
            ),
            account,
        ),
        (
            permission_group(groups, r"^dns (write|edit)$", "com.cloudflare.api.account.zone"),
            {f"com.cloudflare.api.account.zone.{zone['id']}": "*"},
        ),
        # what the live tests need of the integration's own permissions
        (
            permission_group(
                groups, r"^access: service tokens (write|edit)$", "com.cloudflare.api.account"
            ),
            account,
        ),
        (
            permission_group(
                groups, r"^access: organizations revoke$", "com.cloudflare.api.account"
            ),
            account,
        ),
        (
            permission_group(groups, r"^access: audit logs read$", "com.cloudflare.api.account"),
            account,
        ),
    ]
    policies = list(token["policies"])
    present = {
        (pg["id"], tuple(sorted(p["resources"]))) for p in policies for pg in p["permission_groups"]
    }
    for group, resources in wanted:
        if (group["id"], tuple(sorted(resources))) in present:
            continue
        policies.append(
            {"effect": "allow", "permission_groups": [{"id": group["id"]}], "resources": resources}
        )
    body = {k: token[k] for k in ("name", "status", "condition", "expires_on") if k in token}
    body["policies"] = policies
    api.call("PUT", f"/user/tokens/{me['id']}", json=body)
    token = api.call("GET", f"/user/tokens/{me['id']}")
    print(f"token {token['name']!r} now carries:")
    for policy in token["policies"]:
        names = [pg.get("name") or pg["id"] for pg in policy["permission_groups"]]
        print(f"  {policy['effect']} {names} on {sorted(policy['resources'])}")
    oauth_groups = [g["name"] for g in groups if re.search("oauth", g["name"], re.IGNORECASE)]
    print(f"permission groups mentioning OAuth: {oauth_groups}")


def client_body(args: argparse.Namespace) -> dict[str, Any]:
    """Return the client registration as it must be."""
    return {
        "client_name": CLIENT_NAME,
        "client_uri": args.client_uri,
        "logo_uri": args.logo_uri,
        "policy_uri": f"{REPO_URL}#security-properties",
        "tos_uri": f"{REPO_URL}#readme",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "redirect_uris": [REDIRECT_URI],
        "token_endpoint_auth_method": "none",
        "scopes": CLIENT_SCOPES,
    }


def cmd_create(api: Api, args: argparse.Namespace) -> dict[str, Any]:
    """Create the client, or bring an existing one up to date."""
    body = client_body(args)
    existing = find_client(api)
    if existing is not None:
        changes = {k: v for k, v in body.items() if existing.get(k) != v}
        if existing.get("client_uri_verification", {}).get("status") == "verified":
            changes.pop("client_uri", None)  # the verified domain cannot change
        if changes:
            existing = api.call(
                "PATCH",
                f"/accounts/{api.account_id}/oauth_clients/{existing['client_id']}",
                json=changes,
            )
            print(f"updated {sorted(changes)}")
        print(f"client_id {existing['client_id']} ({existing['visibility']})")
        return existing
    created: dict[str, Any] = api.call(
        "POST", f"/accounts/{api.account_id}/oauth_clients", json=body
    )
    print(f"created client_id {created['client_id']} ({created['visibility']})")
    return created


def cmd_verify(api: Api, args: argparse.Namespace) -> None:
    """Publish the verification TXT record and wait for Cloudflare to see it."""
    client = find_client(api)
    if client is None:
        raise SystemExit("no client; run create first")
    path = f"/accounts/{api.account_id}/oauth_clients/{client['client_id']}"
    verification = client.get("client_uri_verification") or {}
    if verification.get("status") == "verified":
        print("already verified")
        return
    if verification.get("status") == "failed" or not verification.get("text"):
        client = api.call("PATCH", path, json={"client_uri": args.client_uri})
        verification = client.get("client_uri_verification") or {}
    text = verification["text"]
    host = urlparse(args.client_uri).hostname or ""
    zone = zone_for(api, host)
    records = api.list_all(f"/zones/{zone['id']}/dns_records", type="TXT", name=host)
    if not any(r["content"].strip('"') == text for r in records):
        api.call(
            "POST",
            f"/zones/{zone['id']}/dns_records",
            json={"type": "TXT", "name": host, "content": text, "ttl": 60},
        )
        print(f"TXT {host} = {text}")
    deadline = time.monotonic() + VERIFY_TIMEOUT
    while True:
        status = (api.call("GET", path).get("client_uri_verification") or {}).get("status")
        print(f"verification: {status}")
        if status == "verified":
            return
        if status == "failed":
            api.call("PATCH", path, json={"client_uri": args.client_uri})
        if time.monotonic() > deadline:
            raise SystemExit("verification did not complete in time")
        time.sleep(VERIFY_INTERVAL)


def cmd_publish(api: Api, args: argparse.Namespace) -> None:
    """Make the client public. Permanent."""
    if not args.yes:
        raise SystemExit("publishing is permanent; pass --yes")
    client = find_client(api)
    if client is None:
        raise SystemExit("no client; run create first")
    if client["visibility"] == "public":
        print("already public")
        return
    if (client.get("client_uri_verification") or {}).get("status") != "verified":
        raise SystemExit("the client URL is not verified yet; run verify first")
    client = api.call(
        "PATCH",
        f"/accounts/{api.account_id}/oauth_clients/{client['client_id']}",
        json={"visibility": "public"},
    )
    print(f"client_id {client['client_id']} is now {client['visibility']}")


def cmd_scopes(api: Api, args: argparse.Namespace) -> None:
    """Print the OAuth scope catalogue (id, name) for the Access and membership scopes."""
    scopes = api.list_all("/oauth/scopes")
    for scope in scopes:
        if re.search(r"access|membership", f"{scope['id']} {scope['name']}", re.IGNORECASE):
            print(f"{scope['id']}: {scope['name']} [{scope.get('category')}]")
    missing = [s for s in CLIENT_SCOPES if not any(s == x["id"] for x in scopes)]
    print(f"{len(scopes)} scopes; client scopes: {CLIENT_SCOPES}; unknown: {missing}")


def cmd_show(api: Api, args: argparse.Namespace) -> None:
    """Print the client registration."""
    client = find_client(api)
    if client is None:
        print("no client")
        return
    for key in (
        "client_id",
        "client_name",
        "visibility",
        "client_uri",
        "logo_uri",
        "redirect_uris",
        "scopes",
        "grant_types",
        "token_endpoint_auth_method",
        "client_uri_verification",
        "promoted_at",
    ):
        print(f"{key}: {client.get(key)}")


def main(argv: list[str] | None = None) -> None:
    """Run one command."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "command", choices=["setup", "grant", "create", "verify", "publish", "show", "scopes"]
    )
    parser.add_argument("--client-uri", default=DEFAULT_CLIENT_URI)
    parser.add_argument("--logo-uri", default=DEFAULT_LOGO_URI)
    parser.add_argument("--yes", action="store_true", help="confirm a permanent change")
    args = parser.parse_args(argv)
    try:
        api = Api(os.environ["CF_API_TOKEN"], os.environ["CF_ACCOUNT_ID"])
    except KeyError as err:
        raise SystemExit(f"{err.args[0]} is not set") from None
    commands = {
        "grant": cmd_grant,
        "create": cmd_create,
        "verify": cmd_verify,
        "publish": cmd_publish,
        "show": cmd_show,
        "scopes": cmd_scopes,
    }
    steps = ["grant", "create", "verify"] if args.command == "setup" else [args.command]
    for step in steps:
        print(f"== {step}")
        commands[step](api, args)


if __name__ == "__main__":
    main(sys.argv[1:])
