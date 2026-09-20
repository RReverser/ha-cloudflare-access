"""Compute and reconcile the Access applications the relay owns."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
import logging
from typing import Any

from .cloudflare_api import CloudflareAccessApi
from .const import (
    BYPASS_APP_NAME_FMT,
    BYPASS_POLICY_NAME,
    CLIENT_APP_NAME_FMT,
    CONF_ACCESS_GROUP_ID,
    CONF_ALLOWED_EMAILS,
    CONF_CLIENT_REDIRECT_URIS,
    CONF_EXTRA_BYPASS_PATHS,
    CONF_GATE_ENABLED,
    CONF_HOSTNAME,
    CONF_SERVICE_TOKEN_IDS,
    CONF_SESSION_DURATION,
    DEFAULT_GATE_ENABLED,
    DEFAULT_SESSION_DURATION,
    GATE_APP_NAME_FMT,
    GATE_LINKED_POLICY_NAME,
    GATE_POLICY_NAME,
    GATE_SERVICE_POLICY_NAME,
    OWN_BYPASS_PATHS,
    URL_CALLBACK,
)
from .paths import collapse_prefixes

_LOGGER = logging.getLogger(__name__)


def normalise_path(path: str) -> str:
    """Return a hostname-relative path with one leading and no trailing slash."""
    path = path.strip()
    if not path.startswith("/"):
        path = "/" + path
    return path.rstrip("/") or "/"


def bypass_paths(options: dict[str, Any], open_paths: list[str]) -> list[str]:
    """Return the sorted, prefix-collapsed list of bypassed paths.

    `open_paths` is what Home Assistant serves to cookie-less clients, as discovered
    from the router (`paths.discover_open_paths`); the integration's own paths and the
    configured extras are added to it.
    """
    paths: list[str] = [*open_paths, *OWN_BYPASS_PATHS]
    for raw in options.get(CONF_EXTRA_BYPASS_PATHS) or []:
        if raw and raw.strip():
            paths.append(raw)
    return collapse_prefixes({p for p in map(normalise_path, paths) if p != "/"})


def _destinations(hostname: str, paths: list[str]) -> list[dict[str, str]]:
    return [{"type": "public", "uri": f"{hostname}{p}"} for p in paths]


def gate_include_rules(options: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the include rules of the allow policy."""
    if group_id := options.get(CONF_ACCESS_GROUP_ID):
        return [{"group": {"id": group_id}}]
    emails = [e.strip() for e in options.get(CONF_ALLOWED_EMAILS) or [] if e.strip()]
    return [{"email": {"email": e}} for e in emails]


def desired_gate_app(
    options: dict[str, Any],
    gated_paths: Sequence[str] = (),
    linked_app_ids: Sequence[str] = (),
) -> dict[str, Any]:
    """Return the desired gate application body.

    While the gate is disabled the application covers only the relay callback
    path, so the relay can be exercised end to end with no other change in
    behaviour. Enabling the gate widens the same application (same id, same
    audience) to the whole hostname plus `gated_paths`: paths that lie under a
    bypassed prefix but must be gated anyway (the companion-app device webhooks).

    Token-bearing clients are admitted by Access itself. Managed OAuth makes the gate
    an OAuth server for clients that discover and register themselves (MCP clients);
    the redirect URIs such clients may use come from the options. Clients registered
    through the integration (`desired_client_app`) are admitted by a Service Auth
    policy that accepts their applications' tokens (`linked_app_ids`).
    """
    hostname = options[CONF_HOSTNAME]
    gated = bool(options.get(CONF_GATE_ENABLED, DEFAULT_GATE_ENABLED))
    domain = hostname if gated else f"{hostname}{URL_CALLBACK}"
    paths = sorted(map(normalise_path, gated_paths)) if gated else []
    policies: list[dict[str, Any]] = [
        {
            "name": GATE_POLICY_NAME,
            "decision": "allow",
            "precedence": 1,
            "include": gate_include_rules(options),
        }
    ]
    token_ids = [t.strip() for t in options.get(CONF_SERVICE_TOKEN_IDS) or [] if t.strip()]
    if token_ids:
        # Service Auth: machine callers present CF-Access-Client-Id/Secret headers
        # and receive an application token like a user would.
        policies.append(
            {
                "name": GATE_SERVICE_POLICY_NAME,
                "decision": "non_identity",
                "precedence": 2,
                "include": [{"service_token": {"token_id": t}} for t in token_ids],
            }
        )
    if linked_app_ids:
        policies.append(
            {
                "name": GATE_LINKED_POLICY_NAME,
                "decision": "non_identity",
                "precedence": 3,
                "include": [{"linked_app_token": {"app_uid": i}} for i in sorted(linked_app_ids)],
            }
        )
    redirect_uris = [u.strip() for u in options.get(CONF_CLIENT_REDIRECT_URIS) or [] if u.strip()]
    return {
        "type": "self_hosted",
        "name": GATE_APP_NAME_FMT.format(hostname=hostname),
        "domain": domain,
        "destinations": [{"type": "public", "uri": domain}, *_destinations(hostname, paths)],
        "session_duration": options.get(CONF_SESSION_DURATION, DEFAULT_SESSION_DURATION),
        "enable_binding_cookie": False,
        "path_cookie_attribute": False,
        "http_only_cookie_attribute": True,
        "same_site_cookie_attribute": "lax",
        "app_launcher_visible": False,
        "policies": policies,
        "oauth_configuration": {
            "enabled": True,
            "dynamic_client_registration": {
                "enabled": True,
                "allow_any_on_localhost": False,
                "allow_any_on_loopback": False,
                "allowed_uris": sorted(redirect_uris),
            },
        },
    }


def desired_client_app(
    options: dict[str, Any], name: str, redirect_uris: list[str]
) -> dict[str, Any]:
    """Return the desired application body for a client registered by hand.

    An Access for SaaS OIDC application: it is the client's registration with
    Access, with the client id and secret its console wants and Access's own
    authorization and token endpoints. Who may link the client is the gate's own
    allow rule. The tokens it issues are accepted by the gate (`desired_gate_app`).
    """
    hostname = options[CONF_HOSTNAME]
    return {
        "type": "saas",
        "name": CLIENT_APP_NAME_FMT.format(hostname=hostname, name=name),
        "app_launcher_visible": False,
        "saas_app": {
            "auth_type": "oidc",
            "redirect_uris": sorted(u.strip() for u in redirect_uris if u.strip()),
            "grant_types": ["authorization_code", "refresh_tokens"],
            "scopes": ["openid", "email", "profile"],
        },
        "policies": [
            {
                "name": GATE_POLICY_NAME,
                "decision": "allow",
                "precedence": 1,
                "include": gate_include_rules(options),
            }
        ],
    }


def desired_bypass_app(options: dict[str, Any], open_paths: list[str]) -> dict[str, Any]:
    """Return the desired bypass application body."""
    hostname = options[CONF_HOSTNAME]
    paths = bypass_paths(options, open_paths)
    destinations = _destinations(hostname, paths)
    return {
        "type": "self_hosted",
        "name": BYPASS_APP_NAME_FMT.format(hostname=hostname),
        "domain": destinations[0]["uri"],
        "destinations": destinations,
        "app_launcher_visible": False,
        "policies": [
            {
                "name": BYPASS_POLICY_NAME,
                "decision": "bypass",
                "precedence": 1,
                "include": [{"everyone": {}}],
            }
        ],
    }


_COMPARED_FIELDS = (
    "type",
    "name",
    "domain",
    "session_duration",
    "enable_binding_cookie",
    "path_cookie_attribute",
    "http_only_cookie_attribute",
    "same_site_cookie_attribute",
    "app_launcher_visible",
)


# Cloudflare omits some fields from GET responses when they hold the default.
_CF_DEFAULTS: dict[str, Any] = {
    "enable_binding_cookie": False,
    "path_cookie_attribute": False,
    "http_only_cookie_attribute": True,
    "app_launcher_visible": True,
}


def _norm_policy(policy: dict[str, Any]) -> tuple[Any, ...]:
    return (
        policy.get("name"),
        policy.get("decision"),
        _json_key(policy.get("include") or []),
        _json_key(policy.get("exclude") or []),
        _json_key(policy.get("require") or []),
    )


def _json_key(value: Any) -> str:
    import json

    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _oauth_key(config: dict[str, Any] | None) -> str:
    config = config or {}
    dcr = config.get("dynamic_client_registration") or {}
    return _json_key(
        {
            "enabled": bool(config.get("enabled")),
            "dcr": bool(dcr.get("enabled")),
            "localhost": bool(dcr.get("allow_any_on_localhost")),
            "loopback": bool(dcr.get("allow_any_on_loopback")),
            "uris": sorted(dcr.get("allowed_uris") or []),
        }
    )


def _saas_key(config: dict[str, Any] | None) -> str:
    config = config or {}
    return _json_key(
        {
            "auth_type": config.get("auth_type"),
            "redirect_uris": sorted(config.get("redirect_uris") or []),
            "grant_types": sorted(config.get("grant_types") or []),
            "scopes": sorted(config.get("scopes") or []),
        }
    )


def app_matches(existing: dict[str, Any], desired: dict[str, Any]) -> bool:
    """Return True when the existing app already carries the desired config."""
    for key in _COMPARED_FIELDS:
        if key in desired and existing.get(key, _CF_DEFAULTS.get(key)) != desired[key]:
            return False
    if "destinations" in desired:
        have = {(d.get("type"), d.get("uri")) for d in existing.get("destinations") or []}
        want = {(d.get("type"), d.get("uri")) for d in desired["destinations"]}
        if have != want:
            return False
    if "oauth_configuration" in desired and _oauth_key(
        existing.get("oauth_configuration")
    ) != _oauth_key(desired["oauth_configuration"]):
        return False
    if "saas_app" in desired and _saas_key(existing.get("saas_app")) != _saas_key(
        desired["saas_app"]
    ):
        return False
    have_pol = [_norm_policy(p) for p in existing.get("policies") or []]
    want_pol = [_norm_policy(p) for p in desired["policies"]]
    return have_pol == want_pol


@dataclass
class ProvisionResult:
    """Outcome of one reconciliation."""

    team_domain: str
    policy_aud: str
    gate_app_id: str
    bypass_app_id: str
    writes: list[str] = field(default_factory=list)


async def _find_by_name(api: CloudflareAccessApi, name: str) -> dict[str, Any] | None:
    for app in await api.list_apps():
        if app.get("name") == name:
            return app
    return None


async def reconcile_app(
    api: CloudflareAccessApi,
    known_id: str | None,
    desired: dict[str, Any],
    writes: list[str],
) -> dict[str, Any]:
    """Create, update or leave alone one application; return it as Cloudflare has it."""
    existing: dict[str, Any] | None = None
    if known_id:
        existing = await api.get_app(known_id)
    if existing is None:
        existing = await _find_by_name(api, desired["name"])
    if existing is None:
        _LOGGER.info("Creating Access application %s", desired["name"])
        created = await api.create_app(desired)
        writes.append(f"create {desired['name']}")
        return created
    if app_matches(existing, desired):
        _LOGGER.debug("Access application %s is up to date", desired["name"])
        return existing
    _LOGGER.info("Updating Access application %s", desired["name"])
    body = dict(desired)
    # Reusing inline policy ids keeps Cloudflare from creating duplicates.
    existing_policies = {p.get("name"): p.get("id") for p in existing.get("policies") or []}
    body["policies"] = [
        {**p, "id": existing_policies[p["name"]]}
        if p["name"] in existing_policies and existing_policies[p["name"]]
        else p
        for p in desired["policies"]
    ]
    updated = await api.update_app(existing["id"], body)
    writes.append(f"update {desired['name']}")
    _LOGGER.info(
        "Updated Access application %s (updated_at %s, binding cookie %s)",
        desired["name"],
        updated.get("updated_at"),
        updated.get("enable_binding_cookie"),
    )
    return updated


async def async_provision(
    api: CloudflareAccessApi,
    options: dict[str, Any],
    open_paths: list[str],
    *,
    gate_app_id: str | None,
    bypass_app_id: str | None,
    team_domain: str | None,
    gated_paths: Sequence[str] = (),
    linked_app_ids: Sequence[str] = (),
) -> ProvisionResult:
    """Bring the Cloudflare objects in line with the options.

    The bypass application is written before the gate application, so a
    failure part-way never leaves the hostname gated with nothing bypassed.
    """
    writes: list[str] = []
    if not team_domain:
        team_domain = await api.get_team_domain()
    bypass = await reconcile_app(
        api, bypass_app_id, desired_bypass_app(options, open_paths), writes
    )
    gate = await reconcile_app(
        api, gate_app_id, desired_gate_app(options, gated_paths, linked_app_ids), writes
    )
    aud = gate.get("aud")
    if not isinstance(aud, str) or not aud:
        gate_full = await api.get_app(gate["id"])
        aud = (gate_full or {}).get("aud")
    if not isinstance(aud, str) or not aud:
        raise RuntimeError("Cloudflare did not return an audience tag for the gate app")
    return ProvisionResult(
        team_domain=team_domain,
        policy_aud=aud,
        gate_app_id=gate["id"],
        bypass_app_id=bypass["id"],
        writes=writes,
    )


async def async_delete_apps(
    api: CloudflareAccessApi, gate_app_id: str | None, bypass_app_id: str | None
) -> None:
    """Delete both applications (gate first so nothing stays gated)."""
    if gate_app_id:
        await api.delete_app(gate_app_id)
    if bypass_app_id:
        await api.delete_app(bypass_app_id)
