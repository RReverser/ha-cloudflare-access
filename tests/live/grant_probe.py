"""Live probe: what happens to a self-registered client's grant after its callback is removed.

Two phases, because the grant needs one real browser login in the middle:

  start   deploys this run's echo Worker, guards it with a gate (managed OAuth, the
          probe's callback on the allowed list, an allow rule for EMAIL), registers a
          client and prints the authorize URL. Open it, log in, and copy the `code`
          from the URL you land on (example.com ignores it).
  finish  exchanges the code (the PKCE verifier is derived from the API token and the
          start run's id, so no state crosses the runs), proves the token works at the
          origin, then takes the client away the way the integration does when a client
          is deleted (PROBE_MODE=callback: its callback leaves the allowed list) or the
          person away the way it does when a person is removed (PROBE_MODE=person: the
          email leaves the allow rule), then for PROBE_MINUTES checks every minute:
          the original access token at the origin, a refresh, the refreshed token at
          the origin, and a fresh authorization for the client. Afterwards it revokes
          the person's sessions, then every session of the application, checking the
          token after each. Everything of the run is deleted at the end.

No token, code or email is printed; only statuses and where a redirect points.

    CF_API_TOKEN=… CF_ACCOUNT_ID=… EMAIL=… PROBE_RUN=… uv run python -m tests.live.grant_probe start
    CF_API_TOKEN=… CF_ACCOUNT_ID=… EMAIL=… PROBE_RUN=… CLIENT_ID=… CODE=… PROBE_MODE=callback|person uv run python -m tests.live.grant_probe finish
"""

from __future__ import annotations

import asyncio
import base64
from datetime import UTC, datetime
import hashlib
import os
from pathlib import Path
import sys
import time
from typing import Any

import httpx

from custom_components.cloudflare_access_relay.cloudflare_api import CloudflareAccessApi

from .cleanup import delete_run, run_names

CALLBACK = "https://example.com/oauth/callback"
PROBE_MINUTES = int(os.environ.get("PROBE_MINUTES", "25"))
PROBE_MODE = os.environ.get("PROBE_MODE", "callback")
WORKER_SOURCE = Path(__file__).with_name("worker") / "worker.js"


def _verifier() -> str:
    return hashlib.sha256(
        f"{os.environ['CF_API_TOKEN']}:{os.environ['PROBE_RUN']}".encode()
    ).hexdigest()


def _challenge(verifier: str) -> str:
    return (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )


def _now() -> str:
    return datetime.now(UTC).strftime("%H:%M:%S")


def _where(resp: httpx.Response) -> str:
    """Describe a response without its body: status and, for a redirect, the target kind."""
    loc = resp.headers.get("location", "")
    if resp.status_code in (301, 302, 303, 307):
        if loc.startswith(CALLBACK):
            return f"{resp.status_code} -> callback ({loc.split('?', 1)[1] if '?' in loc else ''})"
        return f"{resp.status_code} -> {httpx.URL(loc).host}{httpx.URL(loc).path}"
    return str(resp.status_code)


async def _host(api: CloudflareAccessApi, worker: str) -> str:
    subdomain = (await api.sdk.workers.subdomains.get(account_id=api.account_id)).subdomain
    return f"{worker}.{subdomain}.workers.dev"


async def _gate(api: CloudflareAccessApi, host: str) -> dict[str, Any]:
    for app in await api.list_apps():
        if app.get("domain") == host:
            return app
    raise SystemExit(f"no application guards {host}")


async def _metadata(http: httpx.AsyncClient, host: str) -> dict[str, Any]:
    resp = await http.get(f"https://{host}/.well-known/oauth-authorization-server")
    resp.raise_for_status()
    metadata: dict[str, Any] = resp.json()
    return metadata


async def _origin(http: httpx.AsyncClient, host: str, token: str) -> str:
    """Present a managed-OAuth token as a bearer at the origin; say what came back."""
    resp = await http.get(f"https://{host}/api/echo", headers={"Authorization": f"Bearer {token}"})
    if resp.status_code == 200:
        assertion = resp.json().get("headers", {}).get("cf-access-jwt-assertion")
        return "200 origin, assertion forwarded" if assertion else "200 origin, no assertion"
    return _where(resp)


async def _token(
    http: httpx.AsyncClient, endpoint: str, form: dict[str, str]
) -> tuple[str, dict[str, Any]]:
    resp = await http.post(endpoint, data=form)
    body = (
        resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
    )
    keys = sorted(k for k in body if k not in ("access_token", "refresh_token", "id_token"))
    desc = f"{resp.status_code} {body.get('error', '')} {body.get('error_description', '')}".strip()
    if resp.status_code == 200:
        desc = (
            f"200 ({', '.join(keys)}; refresh_token={'yes' if body.get('refresh_token') else 'no'})"
        )
    return desc, body


async def start(api: CloudflareAccessApi, http: httpx.AsyncClient, run: str) -> None:
    worker, _, _ = run_names(run)
    account = api.account_id
    await api.sdk.workers.scripts.update(
        worker,
        account_id=account,
        metadata={"main_module": "worker.js", "compatibility_date": "2026-09-01"},
        files=[("worker.js", WORKER_SOURCE.read_bytes(), "application/javascript+module")],
    )
    await api.sdk.workers.scripts.subdomain.create(worker, account_id=account, enabled=True)
    host = await _host(api, worker)
    app = await api.create_app(
        {
            "type": "self_hosted",
            "name": f"ha-access probe: gate {host}",
            "domain": host,
            "destinations": [{"type": "public", "uri": host}],
            "session_duration": "2h",
            "app_launcher_visible": False,
            "policies": [
                {
                    "name": "ha-access probe: allow",
                    "decision": "allow",
                    "precedence": 1,
                    "include": [{"email": {"email": os.environ["EMAIL"]}}],
                }
            ],
            "oauth_configuration": {
                "enabled": True,
                "dynamic_client_registration": {
                    "enabled": True,
                    "allow_any_on_localhost": False,
                    "allow_any_on_loopback": False,
                    "allowed_uris": [CALLBACK],
                },
                # access-token lifetime left at Cloudflare's default on purpose; the
                # grant session is set so it cannot end during `finish`
                "grant": {"session_duration": "2h"},
            },
        }
    )
    print(f"host {host}\napp {app['id']}")
    deadline = time.time() + 180
    while True:
        try:
            metadata = await _metadata(http, host)
            break
        except httpx.HTTPError, ValueError:
            if time.time() > deadline:
                raise
            await asyncio.sleep(3)
    registration = await http.post(
        metadata["registration_endpoint"],
        json={
            "client_name": "ha-access probe",
            "redirect_uris": [CALLBACK],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        },
    )
    assert registration.status_code == 201, registration.text
    client_id = registration.json()["client_id"]
    url = httpx.URL(
        metadata["authorization_endpoint"],
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": CALLBACK,
            "state": run,
            "code_challenge": _challenge(_verifier()),
            "code_challenge_method": "S256",
            "resource": f"https://{host}/",
        },
    )
    print(f"client_id {client_id}\nauthorize {url}")


async def finish(api: CloudflareAccessApi, http: httpx.AsyncClient, run: str) -> None:
    worker, _, _ = run_names(run)
    host = await _host(api, worker)
    app = await _gate(api, host)
    metadata = await _metadata(http, host)
    client_id = os.environ["CLIENT_ID"]
    resource = f"https://{host}/"

    desc, grant = await _token(
        http,
        metadata["token_endpoint"],
        {
            "grant_type": "authorization_code",
            "code": os.environ["CODE"],
            "redirect_uri": CALLBACK,
            "client_id": client_id,
            "code_verifier": _verifier(),
            "resource": resource,
        },
    )
    print(f"{_now()} exchange: {desc}; expires_in={grant.get('expires_in')}")
    assert grant.get("access_token"), "no grant, nothing to probe"
    original = grant["access_token"]
    refresh = grant.get("refresh_token")
    print(f"{_now()} original token at origin: {await _origin(http, host, original)}")

    async def do_refresh() -> str:
        nonlocal refresh
        if not refresh:
            return "no refresh token"
        desc, body = await _token(
            http,
            metadata["token_endpoint"],
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh,
                "client_id": client_id,
                "resource": resource,
            },
        )
        if body.get("refresh_token"):
            refresh = body["refresh_token"]
        if body.get("access_token"):
            desc += f"; new token at origin: {await _origin(http, host, body['access_token'])}"
        return desc

    async def do_authorize() -> str:
        resp = await http.get(
            metadata["authorization_endpoint"],
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": CALLBACK,
                "state": "probe",
                "code_challenge": _challenge("x" * 43),
                "code_challenge_method": "S256",
                "resource": resource,
            },
        )
        return _where(resp)

    print(f"{_now()} refresh while still allowed: {await do_refresh()}")
    print(f"{_now()} authorize while still allowed: {await do_authorize()}")

    body = {
        k: v
        for k, v in app.items()
        if k
        in (
            "type",
            "name",
            "domain",
            "destinations",
            "session_duration",
            "app_launcher_visible",
            "policies",
        )
    }
    body["oauth_configuration"] = {
        "enabled": True,
        "dynamic_client_registration": {
            "enabled": True,
            "allow_any_on_localhost": False,
            "allow_any_on_loopback": False,
            "allowed_uris": [CALLBACK],
        },
        "grant": {"session_duration": "2h"},
    }
    if PROBE_MODE == "person":
        # the person leaves the allow rule; the rule keeps a subject so it stays valid
        body["policies"] = [
            {
                "name": "ha-access probe: allow",
                "decision": "allow",
                "precedence": 1,
                "include": [{"email": {"email": "nobody@example.com"}}],
            }
        ]
        print(f"{_now()} person removed from the allow rule")
    else:
        body["oauth_configuration"]["dynamic_client_registration"]["allowed_uris"] = []
        print(f"{_now()} callback removed from the allowed list")
    await api.update_app(app["id"], body)

    end = time.time() + PROBE_MINUTES * 60
    while time.time() < end:
        await asyncio.sleep(60)
        print(
            f"{_now()} original token: {await _origin(http, host, original)} | "
            f"refresh: {await do_refresh()} | authorize: {await do_authorize()}"
        )

    await api.revoke_user(os.environ["EMAIL"])
    print(
        f"{_now()} revoke_user: original token: {await _origin(http, host, original)} | refresh: {await do_refresh()}"
    )
    await api.sdk.zero_trust.access.applications.revoke_tokens(app["id"], account_id=api.account_id)
    print(
        f"{_now()} revoke_tokens: original token: {await _origin(http, host, original)} | refresh: {await do_refresh()}"
    )


async def _main(argv: list[str]) -> int:
    run = os.environ["PROBE_RUN"]
    async with httpx.AsyncClient(follow_redirects=False, timeout=30) as http:
        api = CloudflareAccessApi(
            os.environ["CF_API_TOKEN"], os.environ["CF_ACCOUNT_ID"], http_client=http
        )
        if argv[:1] == ["start"]:
            try:
                await start(api, http, run)
            except BaseException:
                print("deleted: " + ", ".join(await delete_run(api, run)))
                raise
        elif argv[:1] == ["finish"]:
            try:
                await finish(api, http, run)
            finally:
                print("deleted: " + ", ".join(await delete_run(api, run)))
        else:
            print(__doc__)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_main(sys.argv[1:])))
