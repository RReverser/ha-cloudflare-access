"""In-memory store of relay flows (one per connect attempt)."""

from __future__ import annotations

from dataclasses import dataclass, field
import secrets
import time

from .const import FLOW_TTL_SECONDS


@dataclass
class Flow:
    """A relay flow bound to the HA user that created it."""

    user_id: str
    created: float = field(default_factory=time.time)
    jwt: str | None = None
    exp: int | None = None

    def expired(self, now: float, ttl: float = FLOW_TTL_SECONDS) -> bool:
        """Return True when the flow is older than the TTL."""
        return now - self.created > ttl


class FlowStore:
    """Dictionary of flows with TTL sweeping."""

    def __init__(self, ttl: float = FLOW_TTL_SECONDS) -> None:
        """Initialise an empty store."""
        self._flows: dict[str, Flow] = {}
        self._ttl = ttl

    def create(self, user_id: str) -> str:
        """Create a flow for a user and return its id."""
        flow_id = secrets.token_urlsafe(32)
        self._flows[flow_id] = Flow(user_id=user_id)
        return flow_id

    def get(self, flow_id: str, now: float | None = None) -> Flow | None:
        """Return a live flow or None."""
        flow = self._flows.get(flow_id)
        if flow is None:
            return None
        if flow.expired(time.time() if now is None else now, self._ttl):
            del self._flows[flow_id]
            return None
        return flow

    def discard(self, flow_id: str) -> None:
        """Remove a flow (one-shot release)."""
        self._flows.pop(flow_id, None)

    def sweep(self, now: float | None = None) -> int:
        """Drop expired flows; return how many were removed."""
        now = time.time() if now is None else now
        stale = [k for k, v in self._flows.items() if v.expired(now, self._ttl)]
        for key in stale:
            del self._flows[key]
        return len(stale)

    def __len__(self) -> int:
        """Return the number of stored flows."""
        return len(self._flows)

    def __contains__(self, flow_id: object) -> bool:
        """Return whether a flow id is stored (expired or not)."""
        return flow_id in self._flows
