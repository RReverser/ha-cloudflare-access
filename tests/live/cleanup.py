"""Delete what a live run created in the Cloudflare account.

A run's Worker, service token and Access applications carry the run id in their
names (`ha-access-ci-<run>`). The live test deletes them itself, and CI runs this
module as a step with `if: always()` afterwards, so a cancelled or killed run leaves
nothing behind. `--stale` also removes leftovers of earlier runs older than six hours,
which the test does at its start too.

    CF_API_TOKEN=… CF_ACCOUNT_ID=… uv run python -m tests.live.cleanup [--stale] [--run <id>]
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import os
import sys

import httpx

from custom_components.cloudflare_access_relay.cloudflare_api import (
    CloudflareAccessApi,
    CloudflareApiError,
)

RUN_PREFIX = "ha-access-ci"
STALE_AGE = 6 * 3600


def _older_than(created: datetime | str | None, seconds: float) -> bool:
    if not created:
        return False
    if isinstance(created, str):
        created = datetime.fromisoformat(created.replace("Z", "+00:00"))
    return (datetime.now(UTC) - created).total_seconds() > seconds


def run_names(run: str) -> tuple[str, str, str]:
    """Return the Worker name, service token name and host marker of a run."""
    return f"{RUN_PREFIX}-{run}", f"{RUN_PREFIX} {run}", f"{RUN_PREFIX}-{run}."


async def delete_run(api: CloudflareAccessApi, run: str) -> list[str]:
    """Delete the objects of one run; return what was deleted."""
    worker, token_name, host_marker = run_names(run)
    deleted: list[str] = []
    # applications first: Cloudflare refuses to delete a service token a policy names
    for app in await api.list_apps():
        if host_marker in (app.get("name") or ""):
            await api.delete_app(app["id"])
            deleted.append(f"app {app['name']}")
    for tok in await api.list_service_tokens():
        name = tok.get("name") or ""
        if name == token_name or host_marker in name:
            await api.delete_service_token(tok["id"])
            deleted.append(f"token {name}")
    sdk, account = api.sdk, api.account_id
    async for script in sdk.workers.scripts.list(account_id=account):
        if script.id == worker:
            await sdk.workers.scripts.delete(worker, account_id=account, force=True)
            deleted.append(f"worker {worker}")
    return deleted


async def sweep_stale(api: CloudflareAccessApi) -> list[str]:
    """Delete leftovers of runs older than STALE_AGE; return what was deleted."""
    deleted: list[str] = []
    for app in await api.list_apps():
        name = app.get("name") or ""
        if name.startswith("ha-relay:") or (
            f" {RUN_PREFIX}-" in name and _older_than(app.get("created_at"), STALE_AGE)
        ):
            await api.delete_app(app["id"])
            deleted.append(f"app {name}")
    for tok in await api.list_service_tokens():
        name = tok.get("name") or ""
        if (name.startswith(RUN_PREFIX) or f" {RUN_PREFIX}-" in name) and _older_than(
            tok.get("created_at"), STALE_AGE
        ):
            try:
                await api.delete_service_token(tok["id"])
            except CloudflareApiError:
                continue  # still named by a policy this sweep did not reach; next time
            deleted.append(f"token {name}")
    sdk, account = api.sdk, api.account_id
    async for script in sdk.workers.scripts.list(account_id=account):
        if (script.id or "").startswith(RUN_PREFIX) and _older_than(script.created_on, STALE_AGE):
            await sdk.workers.scripts.delete(script.id, account_id=account, force=True)
            deleted.append(f"worker {script.id}")
    return deleted


async def _main(argv: list[str]) -> int:
    run = os.environ.get("GITHUB_RUN_ID")
    if "--run" in argv:
        run = argv[argv.index("--run") + 1]
    async with httpx.AsyncClient(timeout=30) as http:
        api = CloudflareAccessApi(
            os.environ["CF_API_TOKEN"], os.environ["CF_ACCOUNT_ID"], http_client=http
        )
        deleted = await delete_run(api, run) if run else []
        if "--stale" in argv:
            deleted += await sweep_stale(api)
    print("deleted: " + (", ".join(deleted) or "nothing"))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_main(sys.argv[1:])))
