# Contributing

## Running the checks

```sh
uv sync
uv run pytest -q        # unit tests against a fake Cloudflare API and a fake JWKS
uv run ruff check . && uv run ruff format --check . && uv run mypy
CF_API_TOKEN=… CF_ACCOUNT_ID=… uv run pytest -q tests/live   # the real edge
```

## Test host

The live test needs no hostname of its own: it deploys the echo Worker in `tests/live/worker`
on the account's `workers.dev` subdomain under a run-scoped name, which Access accepts as an
application domain like any hostname, drives the integration through Home Assistant against
it with a run-scoped Access service token, and deletes the Worker, the token and every
application it created; a CI step that always runs afterwards (`tests/live/cleanup.py`)
deletes them by name even when the job was cancelled, and sweeps leftovers of older runs.
CI reads the credentials from the secrets `CF_API_TOKEN` (an API token with the permissions
listed in the README under *Sign-in*, plus **Workers Scripts: Edit**) and `CF_ACCOUNT_ID`;
without them the live job is skipped, as on forks.

## Publishing to HACS

The repository needs a description, topics and a LICENSE file before HACS accepts it; the
`hacs` CI job reports these until they exist.

## Grant probe

`tests/live/grant_probe.py` (the *Grant probe* workflow, two dispatches) checks what happens to
a self-registered client's grant after its callback is removed, which needs one real login in
the middle; its findings are in [docs/verified-cloudflare-behaviour.md](docs/verified-cloudflare-behaviour.md).

## The project's OAuth client

`scripts/oauth_client.py` (run by the *OAuth client* workflow with the repository's Cloudflare
token) creates and maintains the Cloudflare OAuth client the integration signs in with: name,
logo (`logo.png`), redirect URL, grant types, PKCE, scopes, the client URL's DNS verification
record, and the promotion to public visibility, which Cloudflare makes permanent. Its client
ID is `OAUTH_CLIENT_ID` in `const.py`.

The integration's icon in Home Assistant is the same drawing, shipped in the integration's
`brand/` directory (Home Assistant 2026.3 and newer serve it from there; older versions show
no icon). It is deliberately not Cloudflare's logo: this is a third-party project, and the
brand mark belongs to Cloudflare.
