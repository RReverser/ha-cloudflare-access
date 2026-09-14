"""Thin async client for the Cloudflare Access applications API."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import aiohttp

_LOGGER = logging.getLogger(__name__)

API_URL = "https://api.cloudflare.com/client/v4"
_RETRIES = 3
_BACKOFF_BASE = 1.0


class CloudflareError(Exception):
    """Base error."""


class CloudflareAuthError(CloudflareError):
    """The token was rejected (401/403): wrong token or missing scope."""


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


class CloudflareAccessApi:
    """Minimal client covering what provisioning needs."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        api_token: str,
        account_id: str,
        *,
        base_url: str | None = None,
        backoff_base: float | None = None,
    ) -> None:
        """Initialise the client."""
        self._session = session
        self._token = api_token
        self._account_id = account_id
        self._base_url = (base_url or API_URL).rstrip("/")
        self._backoff_base = _BACKOFF_BASE if backoff_base is None else backoff_base

    @property
    def account_id(self) -> str:
        """Return the account id."""
        return self._account_id

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        url = f"{self._base_url}{path}"
        headers = {"Authorization": f"Bearer {self._token}"}
        last_exc: Exception | None = None
        for attempt in range(_RETRIES):
            _LOGGER.debug("Cloudflare %s %s params=%s body=%s", method, path, params, json)
            try:
                async with self._session.request(
                    method,
                    url,
                    json=json,
                    params=params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status in (401, 403):
                        detail = ""
                        try:
                            body = await resp.json(content_type=None)
                            detail = "; ".join(
                                f"{e.get('code')}: {e.get('message')}"
                                for e in body.get("errors") or []
                            )
                        except aiohttp.ClientError, ValueError, AttributeError:
                            pass
                        raise CloudflareAuthError(
                            f"Cloudflare rejected the API token for {method} {path} "
                            f"(HTTP {resp.status}{': ' + detail if detail else ''})"
                        )
                    if resp.status >= 500:
                        last_exc = CloudflareUnavailableError(
                            f"Cloudflare answered HTTP {resp.status} for {method} {path}"
                        )
                        _LOGGER.debug("%s (attempt %d)", last_exc, attempt + 1)
                    else:
                        payload: dict[str, Any] = await resp.json(content_type=None)
                        if resp.status >= 400 or not payload.get("success", False):
                            raise CloudflareApiError(resp.status, payload.get("errors") or [])
                        _LOGGER.debug("Cloudflare %s %s -> %s", method, path, resp.status)
                        return payload
            except (aiohttp.ClientError, TimeoutError) as err:
                last_exc = CloudflareUnavailableError(f"Cloudflare unreachable: {err}")
                _LOGGER.debug("%s (attempt %d)", last_exc, attempt + 1)
            if attempt < _RETRIES - 1:
                await asyncio.sleep(self._backoff_base * (2**attempt))
        assert last_exc is not None
        raise last_exc

    async def get_organization(self) -> dict[str, Any]:
        """Return the Zero Trust organization (holds auth_domain)."""
        payload = await self._request("GET", f"/accounts/{self._account_id}/access/organizations")
        result: dict[str, Any] = payload["result"]
        return result

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
        page = 1
        while True:
            payload = await self._request(
                "GET",
                f"/accounts/{self._account_id}/access/apps",
                params={"page": str(page), "per_page": "100"},
            )
            apps.extend(payload.get("result") or [])
            info = payload.get("result_info") or {}
            total_pages = int(info.get("total_pages") or 1)
            if page >= total_pages:
                return apps
            page += 1

    async def get_app(self, app_id: str) -> dict[str, Any] | None:
        """Return one application, or None if it no longer exists."""
        try:
            payload = await self._request(
                "GET", f"/accounts/{self._account_id}/access/apps/{app_id}"
            )
        except CloudflareApiError as err:
            if err.status == 404:
                return None
            raise
        result: dict[str, Any] = payload["result"]
        return result

    async def create_app(self, body: dict[str, Any]) -> dict[str, Any]:
        """Create an application and return it."""
        payload = await self._request(
            "POST", f"/accounts/{self._account_id}/access/apps", json=body
        )
        result: dict[str, Any] = payload["result"]
        return result

    async def update_app(self, app_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """Replace an application's configuration and return it."""
        payload = await self._request(
            "PUT", f"/accounts/{self._account_id}/access/apps/{app_id}", json=body
        )
        result: dict[str, Any] = payload["result"]
        return result

    async def list_service_tokens(self) -> list[dict[str, Any]]:
        """Return the account's Access service tokens (without secrets)."""
        payload = await self._request("GET", f"/accounts/{self._account_id}/access/service_tokens")
        result: list[dict[str, Any]] = payload.get("result") or []
        return result

    async def create_service_token(self, name: str, duration: str = "24h") -> dict[str, Any]:
        """Create a service token; the result carries client_id and client_secret once."""
        payload = await self._request(
            "POST",
            f"/accounts/{self._account_id}/access/service_tokens",
            json={"name": name, "duration": duration},
        )
        result: dict[str, Any] = payload["result"]
        return result

    async def delete_service_token(self, token_id: str) -> None:
        """Delete a service token; a missing one is not an error."""
        try:
            await self._request(
                "DELETE", f"/accounts/{self._account_id}/access/service_tokens/{token_id}"
            )
        except CloudflareApiError as err:
            if err.status != 404:
                raise

    async def delete_app(self, app_id: str) -> None:
        """Delete an application; a missing one is not an error."""
        try:
            await self._request("DELETE", f"/accounts/{self._account_id}/access/apps/{app_id}")
        except CloudflareApiError as err:
            if err.status != 404:
                raise
