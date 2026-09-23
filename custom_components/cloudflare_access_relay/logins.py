"""Login history: Access's authentication logs, polled and turned into events and issues.

Cloudflare offers no push for these on the Free plan and keeps them for 24 hours, so
they are read on Home Assistant's own polling schedule (a data update coordinator: the
interval below by default, off or on demand through the integration's system options
and the update service) from a stored cursor. Each new entry for one of this entry's
applications becomes a Home Assistant event; an allowed login updates the person's
last-login time (a sensor per person); a denied login raises a repair issue naming the
address, since the usual fix is adding it under People.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .cloudflare_api import CloudflareAccessApi, CloudflareAuthError, CloudflareError
from .const import (
    DOMAIN,
    EVENT_LOGIN,
    ISSUE_DENIED_LOGIN,
    ISSUE_LOGS_UNAVAILABLE,
    LOG_POLL_INTERVAL_SECONDS,
    LOGS_STORE_VERSION,
)
from .users import async_find_user, login_emails

_LOGGER = logging.getLogger(__name__)

# How far back the first poll looks: Cloudflare's shortest retention.
_FIRST_LOOKBACK = timedelta(hours=24)


@dataclass
class LoginHistory:
    """What the logs said so far, persisted between runs."""

    # ISO timestamp of the newest entry seen; the next poll starts after it.
    cursor: str | None = None
    # Latest allowed login per address (lower-cased), as ISO timestamps.
    last_logins: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        """Return the storable form."""
        return {"cursor": self.cursor, "last_logins": dict(self.last_logins)}

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> LoginHistory:
        """Rebuild from storage."""
        data = data or {}
        return cls(cursor=data.get("cursor"), last_logins=dict(data.get("last_logins") or {}))

    def last_login(self, addresses: set[str]) -> datetime | None:
        """Return the latest allowed login of any of the addresses."""
        times = [
            parsed
            for address in addresses
            if (stamp := self.last_logins.get(address))
            and (parsed := dt_util.parse_datetime(stamp)) is not None
        ]
        return max(times) if times else None


class LoginCoordinator(DataUpdateCoordinator[LoginHistory]):
    """Polls the authentication logs of this entry's applications."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry, api: CloudflareAccessApi) -> None:
        """Set up the coordinator; the first refresh loads the stored history."""
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=f"{DOMAIN} logins {entry.title}",
            update_interval=timedelta(seconds=LOG_POLL_INTERVAL_SECONDS),
        )
        self._api = api
        self._store: Store[dict[str, Any]] = Store(
            hass, LOGS_STORE_VERSION, f"{DOMAIN}.{entry.entry_id}.logins"
        )
        self._loaded = False
        # The applications whose entries count: the gate and the clients' applications.
        self.app_ids: set[str] = set()

    async def _async_update_data(self) -> LoginHistory:
        history = self.data if self.data is not None else LoginHistory()
        if not self._loaded:
            history = LoginHistory.from_dict(await self._store.async_load())
            self._loaded = True
        since = dt_util.parse_datetime(history.cursor) if history.cursor else None
        if since is None:
            since = dt_util.utcnow() - _FIRST_LOOKBACK
        try:
            entries = await self._api.list_access_logs(since)
        except CloudflareAuthError as err:
            ir.async_create_issue(
                self.hass,
                DOMAIN,
                ISSUE_LOGS_UNAVAILABLE,
                is_fixable=False,
                severity=ir.IssueSeverity.WARNING,
                translation_key=ISSUE_LOGS_UNAVAILABLE,
            )
            raise UpdateFailed(f"the authentication logs cannot be read: {err}") from err
        except CloudflareError as err:
            raise UpdateFailed(f"the authentication logs were not read: {err}") from err
        ir.async_delete_issue(self.hass, DOMAIN, ISSUE_LOGS_UNAVAILABLE)
        newest = since
        changed = False
        for entry in sorted(entries, key=lambda e: str(e.get("created_at") or "")):
            when = dt_util.parse_datetime(str(entry.get("created_at") or ""))
            if when is None or when <= since or entry.get("app_uid") not in self.app_ids:
                continue
            newest = max(newest, when)
            await self._async_handle(history, entry, when)
            changed = True
        if changed:
            history.cursor = newest.isoformat()
            await self._store.async_save(history.as_dict())
        return history

    async def _async_handle(
        self, history: LoginHistory, entry: dict[str, Any], when: datetime
    ) -> None:
        assert self.config_entry is not None
        email = str(entry.get("user_email") or "").strip().lower()
        allowed = bool(entry.get("allowed"))
        extra = login_emails(self.config_entry)
        user = await async_find_user(self.hass, extra, email) if email else None
        self.hass.bus.async_fire(
            EVENT_LOGIN,
            {
                "entry_id": self.config_entry.entry_id,
                "email": email,
                "allowed": allowed,
                "user_id": user.id if user else None,
                "action": entry.get("action"),
                "app": entry.get("app_domain"),
                "login_method": entry.get("connection"),
                "ip_address": entry.get("ip_address"),
                "when": when.isoformat(),
            },
        )
        if not email:
            return
        if allowed:
            history.last_logins[email] = when.isoformat()
            return
        _LOGGER.warning(
            "Access refused %s at %s: the address is not on the allow list", email, when
        )
        ir.async_create_issue(
            self.hass,
            DOMAIN,
            ISSUE_DENIED_LOGIN,
            is_fixable=False,
            severity=ir.IssueSeverity.WARNING,
            translation_key=ISSUE_DENIED_LOGIN,
            translation_placeholders={
                "email": email,
                "when": when.astimezone(dt_util.get_default_time_zone()).strftime("%Y-%m-%d %H:%M"),
                "app": str(entry.get("app_domain") or ""),
            },
        )
