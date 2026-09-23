"""Compute and reconcile the Access applications the integration owns."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
import json
import logging
from typing import Any

from .cloudflare_api import CloudflareAccessApi
from .const import (
    BYPASS_APP_NAME_FMT,
    BYPASS_POLICY_NAME,
    CLIENT_APP_NAME_FMT,
    CONF_CLIENT_REDIRECT_URIS,
    CONF_EXTRA_BYPASS_PATHS,
    CONF_GATE_ENABLED,
    CONF_HOSTNAME,
    CONF_SERVICE_TOKEN_IDS,
    CONF_SESSION_DURATION,
    DEFAULT_GATE_ENABLED,
    DEFAULT_SESSION_DURATION,
    DENY_MESSAGE,
    GATE_APP_NAME_FMT,
    GATE_LINKED_POLICY_NAME,
    GATE_POLICY_NAME,
    GATE_SERVICE_POLICY_NAME,
    OPTION_APP_TAG,
    OPTION_IDP_IDS,
)

_LOGGER = logging.getLogger(__name__)


def normalise_path(path: str) -> str:
    """Return a hostname-relative path with one leading and no trailing slash."""
    path = path.strip()
    if not path.startswith("/"):
        path = "/" + path
    return path.rstrip("/") or "/"


def _clean(values: Sequence[str] | None) -> list[str]:
    return [v.strip() for v in values or [] if v and v.strip()]


def _tags(options: dict[str, Any]) -> list[str]:
    return [options[OPTION_APP_TAG]] if options.get(OPTION_APP_TAG) else []


def owned(app: dict[str, Any], tag: str) -> bool:
    """Return whether the application carries this entry's tag."""
    return tag in (app.get("tags") or [])


def _login_settings(options: dict[str, Any]) -> dict[str, Any]:
    """Return the login-method settings shared by the gate and the client applications.

    With exactly one identity provider in the organization there is nothing to pick, so
    people are sent straight to it; otherwise Access shows its picker page.
    """
    idps = list(options.get(OPTION_IDP_IDS) or [])
    return {
        "allowed_idps": idps if len(idps) == 1 else [],
        "auto_redirect_to_identity": len(idps) == 1,
    }


def allowed_emails_of(app: dict[str, Any] | None) -> set[str]:
    """Return the addresses an application's allow policy admits, as Cloudflare has it."""
    found: set[str] = set()
    for policy in (app or {}).get("policies") or []:
        if policy.get("decision") != "allow":
            continue
        for rule in policy.get("include") or []:
            if isinstance(email := (rule.get("email") or {}).get("email"), str):
                found.add(email.strip().lower())
    return found


def include_rules(emails: Sequence[str]) -> list[dict[str, Any]]:
    """Return the include rules of an allow policy: one per e-mail address."""
    return [{"email": {"email": e}} for e in sorted(set(_clean(emails)))]


def desired_gate_app(
    options: dict[str, Any], emails: Sequence[str], linked_app_ids: Sequence[str] = ()
) -> dict[str, Any] | None:
    """Return the desired gate application body, or None while the gate is disabled.

    The gate covers the whole hostname. People pass its allow policy in a browser
    (the companion app included: it shares the cookie with its native requests);
    `emails` are the Home Assistant users' addresses, so whoever has an account
    here may log in and nobody else.
    Token-bearing clients are admitted by Access itself: managed OAuth makes the
    gate an OAuth server for clients that discover and register themselves (MCP
    clients), for the redirect URIs listed in the options; clients registered
    through the integration (`desired_client_app`) are admitted by a Service Auth
    policy that accepts their applications' tokens (`linked_app_ids`).
    """
    if not options.get(CONF_GATE_ENABLED, DEFAULT_GATE_ENABLED):
        return None
    hostname = options[CONF_HOSTNAME]
    policies: list[dict[str, Any]] = [
        {
            "name": GATE_POLICY_NAME,
            "decision": "allow",
            "precedence": 1,
            "include": include_rules(emails),
        }
    ]
    if token_ids := _clean(options.get(CONF_SERVICE_TOKEN_IDS)):
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
    return {
        "type": "self_hosted",
        "name": GATE_APP_NAME_FMT.format(hostname=hostname),
        **_login_settings(options),
        "custom_deny_message": DENY_MESSAGE,
        "tags": _tags(options),
        "domain": hostname,
        "destinations": [{"type": "public", "uri": hostname}],
        "session_duration": options.get(CONF_SESSION_DURATION, DEFAULT_SESSION_DURATION),
        # The companion app's native client reuses the cookie its WebView obtained; a
        # binding cookie would tie the token to the WebView alone.
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
                "allowed_uris": sorted(_clean(options.get(CONF_CLIENT_REDIRECT_URIS))),
            },
        },
    }


def desired_bypass_app(options: dict[str, Any]) -> dict[str, Any] | None:
    """Return the desired bypass application body, or None when nothing is bypassed.

    Only the paths listed in the options are bypassed, each a prefix (Access
    inherits a path rule to everything below it). Nothing is bypassed by default.
    """
    paths = sorted(
        {normalise_path(p) for p in _clean(options.get(CONF_EXTRA_BYPASS_PATHS))} - {"/"}
    )
    if not paths:
        return None
    hostname = options[CONF_HOSTNAME]
    destinations = [{"type": "public", "uri": f"{hostname}{p}"} for p in paths]
    return {
        "type": "self_hosted",
        "name": BYPASS_APP_NAME_FMT.format(hostname=hostname),
        "tags": _tags(options),
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


def desired_client_app(
    options: dict[str, Any], emails: Sequence[str], name: str, redirect_uris: list[str]
) -> dict[str, Any]:
    """Return the desired application body for a client registered by hand.

    An Access for SaaS OIDC application: it is the client's registration with
    Access, with the client id and secret its console wants and Access's own
    authorization and token endpoints. Who may link the client is the gate's own
    allow rule, and the client's refresh token lives as long as an Access session
    of the gate. The tokens it issues are accepted by the gate (`desired_gate_app`).
    """
    hostname = options[CONF_HOSTNAME]
    return {
        "type": "saas",
        "name": CLIENT_APP_NAME_FMT.format(hostname=hostname, name=name),
        "tags": _tags(options),
        **_login_settings(options),
        "app_launcher_visible": False,
        "saas_app": {
            "auth_type": "oidc",
            "redirect_uris": sorted(_clean(redirect_uris)),
            "grant_types": ["authorization_code", "refresh_tokens"],
            "refresh_token_options": {
                "lifetime": options.get(CONF_SESSION_DURATION, DEFAULT_SESSION_DURATION)
            },
            "scopes": ["openid", "email", "profile"],
        },
        "policies": [
            {
                "name": GATE_POLICY_NAME,
                "decision": "allow",
                "precedence": 1,
                "include": include_rules(emails),
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
    "allowed_idps",
    "auto_redirect_to_identity",
    "custom_deny_message",
)


# Cloudflare omits some fields from GET responses when they hold the default.
_CF_DEFAULTS: dict[str, Any] = {
    "enable_binding_cookie": False,
    "path_cookie_attribute": False,
    "http_only_cookie_attribute": True,
    "app_launcher_visible": True,
    "allowed_idps": [],
    "auto_redirect_to_identity": False,
    "custom_deny_message": "",
}


def _json_key(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _norm_policy(policy: dict[str, Any]) -> tuple[Any, ...]:
    return (
        policy.get("name"),
        policy.get("decision"),
        _json_key(policy.get("include") or []),
        _json_key(policy.get("exclude") or []),
        _json_key(policy.get("require") or []),
    )


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
            "refresh": (config.get("refresh_token_options") or {}).get("lifetime"),
            "scopes": sorted(config.get("scopes") or []),
        }
    )


def app_matches(existing: dict[str, Any], desired: dict[str, Any]) -> bool:
    """Return True when the existing app already carries the desired config."""
    for key in _COMPARED_FIELDS:
        if key in desired and existing.get(key, _CF_DEFAULTS.get(key)) != desired[key]:
            return False
    if sorted(existing.get("tags") or []) != sorted(desired.get("tags") or []):
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
    # Set while the gate exists: the audience the origin verifies assertions against.
    policy_aud: str | None
    gate_app_id: str | None
    bypass_app_id: str | None
    writes: list[str] = field(default_factory=list)


def _tag_of(desired: dict[str, Any]) -> str:
    tags = desired.get("tags") or []
    return str(tags[0]) if tags else ""


async def find_owned(api: CloudflareAccessApi, name: str, tag: str) -> dict[str, Any] | None:
    """Return this entry's application with that exact name, if any."""
    for app in await api.list_apps():
        if app.get("name") == name and owned(app, tag):
            return app
    return None


async def _get_owned(api: CloudflareAccessApi, app_id: str, tag: str) -> dict[str, Any] | None:
    """Return the application with that id if it is this entry's; a foreign one is left alone."""
    app = await api.get_app(app_id)
    if app is not None and not owned(app, tag):
        _LOGGER.warning(
            "Access application %s (%s) does not carry this entry's tag; leaving it alone",
            app_id,
            app.get("name"),
        )
        return None
    return app


async def reconcile_app(
    api: CloudflareAccessApi,
    known_id: str | None,
    desired: dict[str, Any],
    writes: list[str],
) -> dict[str, Any]:
    """Create, update or leave alone one application; return it as Cloudflare has it."""
    tag = _tag_of(desired)
    existing: dict[str, Any] | None = None
    if known_id:
        existing = await _get_owned(api, known_id, tag)
    if existing is None:
        existing = await find_owned(api, desired["name"], tag)
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


async def retire_app(
    api: CloudflareAccessApi, known_id: str | None, name: str, tag: str, writes: list[str]
) -> None:
    """Delete an application the options no longer call for, if it exists."""
    app = (await _get_owned(api, known_id, tag)) if known_id else None
    if app is None:
        app = await find_owned(api, name, tag)
    if app is not None:
        _LOGGER.info("Deleting Access application %s", name)
        await api.delete_app(app["id"])
        writes.append(f"delete {name}")


async def async_provision(
    api: CloudflareAccessApi,
    options: dict[str, Any],
    emails: Sequence[str],
    *,
    gate_app_id: str | None,
    bypass_app_id: str | None,
    team_domain: str | None,
    linked_app_ids: Sequence[str] = (),
) -> ProvisionResult:
    """Bring the Cloudflare objects in line with the options.

    The bypass application is written before the gate application, so a
    failure part-way never leaves the hostname gated with nothing bypassed.
    """
    writes: list[str] = []
    if not team_domain:
        team_domain = await api.get_team_domain()
    hostname = options[CONF_HOSTNAME]
    tag = str(options.get(OPTION_APP_TAG) or "")

    bypass_id: str | None = None
    if (bypass := desired_bypass_app(options)) is not None:
        bypass_id = (await reconcile_app(api, bypass_app_id, bypass, writes))["id"]
    else:
        await retire_app(
            api, bypass_app_id, BYPASS_APP_NAME_FMT.format(hostname=hostname), tag, writes
        )

    gate_id: str | None = None
    aud: str | None = None
    if (gate := desired_gate_app(options, emails, linked_app_ids)) is not None:
        app = await reconcile_app(api, gate_app_id, gate, writes)
        gate_id = app["id"]
        aud = app.get("aud")
        if not isinstance(aud, str) or not aud:
            full = await api.get_app(gate_id)
            aud = (full or {}).get("aud")
        if not isinstance(aud, str) or not aud:
            raise RuntimeError("Cloudflare did not return an audience tag for the gate app")
    else:
        await retire_app(api, gate_app_id, GATE_APP_NAME_FMT.format(hostname=hostname), tag, writes)

    return ProvisionResult(
        team_domain=team_domain,
        policy_aud=aud,
        gate_app_id=gate_id,
        bypass_app_id=bypass_id,
        writes=writes,
    )


async def async_delete_apps(api: CloudflareAccessApi, tag: str, *app_ids: str | None) -> None:
    """Delete the given applications of this entry (gate first so nothing stays gated)."""
    for app_id in app_ids:
        if app_id and await _get_owned(api, app_id, tag) is not None:
            await api.delete_app(app_id)
