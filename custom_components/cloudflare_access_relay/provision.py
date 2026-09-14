"""Compute and reconcile the Access applications the relay owns."""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
from typing import Any

from .cloudflare_api import CloudflareAccessApi
from .const import (
    BASE_BYPASS_PATHS,
    BYPASS_APP_NAME_FMT,
    BYPASS_POLICY_NAME,
    CONF_ACCESS_GROUP_ID,
    CONF_ALLOWED_EMAILS,
    CONF_EXTRA_BYPASS_PATHS,
    CONF_GATE_ENABLED,
    CONF_HOSTNAME,
    CONF_SERVICE_TOKEN_IDS,
    CONF_SESSION_DURATION,
    DEFAULT_GATE_ENABLED,
    DEFAULT_SESSION_DURATION,
    GATE_APP_NAME_FMT,
    GATE_POLICY_NAME,
    GATE_SERVICE_POLICY_NAME,
    INTEGRATION_BYPASS_PATHS,
    URL_CALLBACK,
)

_LOGGER = logging.getLogger(__name__)


def normalise_path(path: str) -> str:
    """Return a hostname-relative path with one leading and no trailing slash."""
    path = path.strip()
    if not path.startswith("/"):
        path = "/" + path
    return path.rstrip("/") or "/"


def bypass_paths(options: dict[str, Any], loaded_domains: set[str]) -> list[str]:
    """Return the ordered, de-duplicated list of bypassed paths."""
    paths: list[str] = list(BASE_BYPASS_PATHS)
    for domain, extra in INTEGRATION_BYPASS_PATHS.items():
        if domain in loaded_domains:
            paths.extend(extra)
    for raw in options.get(CONF_EXTRA_BYPASS_PATHS) or []:
        if raw and raw.strip():
            paths.append(raw)
    seen: set[str] = set()
    result: list[str] = []
    for path in paths:
        norm = normalise_path(path)
        if norm != "/" and norm not in seen:
            seen.add(norm)
            result.append(norm)
    return result


def _destinations(hostname: str, paths: list[str]) -> list[dict[str, str]]:
    return [{"type": "public", "uri": f"{hostname}{p}"} for p in paths]


def gate_include_rules(options: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the include rules of the allow policy."""
    if group_id := options.get(CONF_ACCESS_GROUP_ID):
        return [{"group": {"id": group_id}}]
    emails = [e.strip() for e in options.get(CONF_ALLOWED_EMAILS) or [] if e.strip()]
    return [{"email": {"email": e}} for e in emails]


def desired_gate_app(options: dict[str, Any]) -> dict[str, Any]:
    """Return the desired gate application body.

    While the gate is disabled the application covers only the relay callback
    path, so the relay can be exercised end to end with no other change in
    behaviour. Enabling the gate widens the same application (same id, same
    audience) to the whole hostname.
    """
    hostname = options[CONF_HOSTNAME]
    gated = bool(options.get(CONF_GATE_ENABLED, DEFAULT_GATE_ENABLED))
    domain = hostname if gated else f"{hostname}{URL_CALLBACK}"
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
    return {
        "type": "self_hosted",
        "name": GATE_APP_NAME_FMT.format(hostname=hostname),
        "domain": domain,
        "destinations": [{"type": "public", "uri": domain}],
        "session_duration": options.get(CONF_SESSION_DURATION, DEFAULT_SESSION_DURATION),
        "enable_binding_cookie": False,
        "path_cookie_attribute": False,
        "http_only_cookie_attribute": True,
        "same_site_cookie_attribute": "lax",
        "app_launcher_visible": False,
        "policies": policies,
    }


def desired_bypass_app(options: dict[str, Any], loaded_domains: set[str]) -> dict[str, Any]:
    """Return the desired bypass application body."""
    hostname = options[CONF_HOSTNAME]
    paths = bypass_paths(options, loaded_domains)
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


def app_matches(existing: dict[str, Any], desired: dict[str, Any]) -> bool:
    """Return True when the existing app already carries the desired config."""
    for key in _COMPARED_FIELDS:
        if key in desired and existing.get(key, _CF_DEFAULTS.get(key)) != desired[key]:
            return False
    have = {(d.get("type"), d.get("uri")) for d in existing.get("destinations") or []}
    want = {(d.get("type"), d.get("uri")) for d in desired["destinations"]}
    if have != want:
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


async def _reconcile(
    api: CloudflareAccessApi,
    known_id: str | None,
    desired: dict[str, Any],
    writes: list[str],
) -> dict[str, Any]:
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
    return updated


async def async_provision(
    api: CloudflareAccessApi,
    options: dict[str, Any],
    loaded_domains: set[str],
    *,
    gate_app_id: str | None,
    bypass_app_id: str | None,
    team_domain: str | None,
) -> ProvisionResult:
    """Bring the Cloudflare objects in line with the options.

    The bypass application is written before the gate application, so a
    failure part-way never leaves the hostname gated with nothing bypassed.
    """
    writes: list[str] = []
    if not team_domain:
        team_domain = await api.get_team_domain()
    bypass = await _reconcile(
        api, bypass_app_id, desired_bypass_app(options, loaded_domains), writes
    )
    gate = await _reconcile(api, gate_app_id, desired_gate_app(options), writes)
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
