"""Access applications, service tokens and organization via the official Cloudflare SDK.

A thin layer over `cloudflare.AsyncCloudflare` that works with plain dicts (the
provisioning code diffs request bodies against what the API returns) and maps
the SDK's exceptions onto three outcomes the integration cares about.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
import logging
from typing import Any

from cloudflare import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    AsyncCloudflare,
    AuthenticationError,
    NotFoundError,
    PermissionDeniedError,
)
import httpx
from pydantic import BaseModel

_LOGGER = logging.getLogger(__name__)

API_URL = "https://api.cloudflare.com/client/v4"
MAX_RETRIES = 2


class CloudflareError(Exception):
    """Base error."""


class CloudflareAuthError(CloudflareError):
    """The token was rejected (401/403): wrong token or missing permission."""


class CloudflareUnavailableError(CloudflareError):
    """Cloudflare could not be reached or answered 5xx after retries."""


class CloudflareApiError(CloudflareError):
    """Cloudflare rejected the request (other 4xx)."""

    def __init__(self, status: int, errors: list[dict[str, Any]]) -> None:
        """Initialise with the API error list."""
        self.status = status
        self.errors = errors
        detail = (
            "; ".join(f"{e.get('code')}: {e.get('message')}" for e in errors) or f"HTTP {status}"
        )
        super().__init__(detail)


def _errors_of(err: APIStatusError) -> list[dict[str, Any]]:
    body = err.body
    if isinstance(body, dict) and isinstance(body.get("errors"), list):
        return [e for e in body["errors"] if isinstance(e, dict)]
    return [{"code": err.status_code, "message": err.message}]


def _translate(err: Exception, what: str) -> CloudflareError:
    """Map an SDK exception onto the integration's error classes."""
    if isinstance(err, CloudflareError):
        return err  # raised by the token source (an OAuth refresh that was refused)
    if isinstance(err, AuthenticationError | PermissionDeniedError):
        detail = "; ".join(f"{e.get('code')}: {e.get('message')}" for e in _errors_of(err))
        return CloudflareAuthError(
            f"Cloudflare rejected the API token for {what} (HTTP {err.status_code}: {detail})"
        )
    if isinstance(err, APIStatusError):
        if err.status_code >= 500:
            return CloudflareUnavailableError(
                f"Cloudflare answered HTTP {err.status_code} for {what}"
            )
        return CloudflareApiError(err.status_code, _errors_of(err))
    if isinstance(err, APIConnectionError | APITimeoutError):
        return CloudflareUnavailableError(f"Cloudflare unreachable for {what}: {err}")
    return CloudflareError(f"{what}: {err}")


def _dump(obj: Any) -> Any:
    """Return the SDK's response model as plain JSON-compatible data."""
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json", exclude_none=True)
    if isinstance(obj, list):
        return [_dump(o) for o in obj]
    return obj


class CloudflareAccessApi:
    """Minimal client covering what provisioning and the live tests need."""

    def __init__(
        self,
        api_token: str,
        account_id: str,
        *,
        http_client: httpx.AsyncClient | None = None,
        base_url: str | None = None,
        max_retries: int | None = None,
        token_source: Callable[[], Awaitable[str]] | None = None,
    ) -> None:
        """Initialise the client.

        `token_source`, when given, is awaited before every call and must return the
        bearer to use: an OAuth session that refreshes its access token, for example.
        """
        self._account_id = account_id
        self._token_source = token_source
        self._client = AsyncCloudflare(
            api_token=api_token,
            base_url=base_url or API_URL,
            max_retries=MAX_RETRIES if max_retries is None else max_retries,
            http_client=http_client,
        )

    async def _c(self) -> AsyncCloudflare:
        if self._token_source is not None:
            self._client.api_token = await self._token_source()
        return self._client

    @property
    def sdk(self) -> AsyncCloudflare:
        """The underlying SDK client, for callers that need other Cloudflare APIs."""
        return self._client

    @property
    def account_id(self) -> str:
        """Return the account id."""
        return self._account_id

    async def list_memberships(self) -> list[dict[str, Any]]:
        """Return the accounts the signed-in user is a member of (id and name).

        Listing accounts directly answers with nothing for an OAuth token whose scopes
        are all Zero Trust ones; memberships are a user-level listing.
        """
        try:
            return [
                {"id": m.account.id, "name": m.account.name}
                async for m in (await self._c()).memberships.list(status="accepted", per_page=50)
                if m.account is not None and m.account.id
            ]
        except Exception as err:
            raise _translate(err, "listing memberships") from err

    async def get_organization(self) -> dict[str, Any]:
        """Return the Zero Trust organization (holds auth_domain)."""
        try:
            org = await (await self._c()).zero_trust.organizations.list(account_id=self._account_id)
        except Exception as err:
            raise _translate(err, "reading the Zero Trust organization") from err
        result: dict[str, Any] = _dump(org) or {}
        return result

    async def list_identity_providers(self) -> list[dict[str, Any]]:
        """Return the organization's identity providers (id, name, type)."""
        idps: list[dict[str, Any]] = []
        try:
            async for idp in (await self._c()).zero_trust.identity_providers.list(
                account_id=self._account_id, per_page=100
            ):
                idps.append(_dump(idp))
        except Exception as err:
            raise _translate(err, "listing identity providers") from err
        return idps

    async def revoke_user(self, email: str) -> None:
        """End every Access session and token of the person with this address."""
        try:
            await (await self._c()).zero_trust.organizations.revoke_users(
                account_id=self._account_id, email=email
            )
        except Exception as err:
            raise _translate(err, f"revoking the sessions of {email}") from err

    async def get_team_domain(self) -> str:
        """Return the team domain, e.g. 'team.cloudflareaccess.com'."""
        org = await self.get_organization()
        auth_domain = org.get("auth_domain")
        if not isinstance(auth_domain, str) or not auth_domain:
            raise CloudflareApiError(200, [{"code": 0, "message": "no auth_domain"}])
        return auth_domain

    async def list_apps(self) -> list[dict[str, Any]]:
        """Return every Access application in the account."""
        apps: list[dict[str, Any]] = []
        try:
            async for app in (await self._c()).zero_trust.access.applications.list(
                account_id=self._account_id, per_page=100
            ):
                apps.append(_dump(app))
        except Exception as err:
            raise _translate(err, "listing Access applications") from err
        return apps

    async def get_app(self, app_id: str) -> dict[str, Any] | None:
        """Return one application, or None if it no longer exists."""
        try:
            app = await (await self._c()).zero_trust.access.applications.get(
                app_id, account_id=self._account_id
            )
        except NotFoundError:
            return None
        except Exception as err:
            raise _translate(err, f"reading Access application {app_id}") from err
        result: dict[str, Any] = _dump(app)
        return result

    async def create_app(self, body: dict[str, Any]) -> dict[str, Any]:
        """Create an application and return it."""
        _LOGGER.debug("Creating Access application %s", body.get("name"))
        try:
            app = await (await self._c()).zero_trust.access.applications.create(
                account_id=self._account_id, **body
            )
        except Exception as err:
            raise _translate(err, "creating an Access application") from err
        result: dict[str, Any] = _dump(app)
        return result

    async def update_app(self, app_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """Replace an application's configuration and return it."""
        _LOGGER.debug("Updating Access application %s", body.get("name"))
        try:
            app = await (await self._c()).zero_trust.access.applications.update(
                app_id, account_id=self._account_id, **body
            )
        except Exception as err:
            raise _translate(err, f"updating Access application {app_id}") from err
        result: dict[str, Any] = _dump(app)
        return result

    async def delete_app(self, app_id: str) -> None:
        """Delete an application; a missing one is not an error."""
        try:
            await (await self._c()).zero_trust.access.applications.delete(
                app_id, account_id=self._account_id
            )
        except NotFoundError:
            return
        except Exception as err:
            raise _translate(err, f"deleting Access application {app_id}") from err

    async def ensure_tag(self, name: str) -> None:
        """Create the Access tag if it does not exist yet."""
        try:
            await (await self._c()).zero_trust.access.tags.get(name, account_id=self._account_id)
            return
        except NotFoundError:
            pass
        except Exception as err:
            raise _translate(err, f"reading Access tag {name}") from err
        _LOGGER.debug("Creating Access tag %s", name)
        try:
            await (await self._c()).zero_trust.access.tags.create(
                account_id=self._account_id, name=name
            )
        except Exception as err:
            raise _translate(err, f"creating Access tag {name}") from err

    async def list_service_tokens(self) -> list[dict[str, Any]]:
        """Return the account's Access service tokens (without secrets)."""
        tokens: list[dict[str, Any]] = []
        try:
            async for tok in (await self._c()).zero_trust.access.service_tokens.list(
                account_id=self._account_id, per_page=100
            ):
                tokens.append(_dump(tok))
        except Exception as err:
            raise _translate(err, "listing service tokens") from err
        return tokens

    async def create_service_token(self, name: str, duration: str | None = None) -> dict[str, Any]:
        """Create a service token; the result carries client_id and client_secret once.

        Without a duration Cloudflare applies its default validity.
        """
        try:
            tokens = (await self._c()).zero_trust.access.service_tokens
            tok = await (
                tokens.create(account_id=self._account_id, name=name, duration=duration)
                if duration
                else tokens.create(account_id=self._account_id, name=name)
            )
        except Exception as err:
            raise _translate(err, "creating a service token") from err
        result: dict[str, Any] = _dump(tok)
        return result

    async def get_service_token(self, token_id: str) -> dict[str, Any] | None:
        """Return a service token (without its secret), or None when it is gone."""
        try:
            tok = await (await self._c()).zero_trust.access.service_tokens.get(
                token_id, account_id=self._account_id
            )
        except NotFoundError:
            return None
        except Exception as err:
            raise _translate(err, f"reading service token {token_id}") from err
        result: dict[str, Any] | None = _dump(tok)
        return result

    async def rename_service_token(self, token_id: str, name: str) -> dict[str, Any]:
        """Rename a service token."""
        try:
            tok = await (await self._c()).zero_trust.access.service_tokens.update(
                token_id, account_id=self._account_id, name=name
            )
        except Exception as err:
            raise _translate(err, f"renaming service token {token_id}") from err
        result: dict[str, Any] = _dump(tok)
        return result

    async def refresh_service_token(self, token_id: str) -> dict[str, Any]:
        """Extend a service token's validity by its duration; the secret stays."""
        try:
            tok = await (await self._c()).zero_trust.access.service_tokens.refresh(
                token_id, account_id=self._account_id
            )
        except Exception as err:
            raise _translate(err, f"refreshing service token {token_id}") from err
        result: dict[str, Any] = _dump(tok)
        return result

    async def delete_service_token(self, token_id: str) -> None:
        """Delete a service token; a missing one is not an error."""
        try:
            await (await self._c()).zero_trust.access.service_tokens.delete(
                token_id, account_id=self._account_id
            )
        except NotFoundError:
            return
        except Exception as err:
            raise _translate(err, f"deleting service token {token_id}") from err
