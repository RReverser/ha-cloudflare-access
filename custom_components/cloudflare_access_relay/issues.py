"""Repair issue ids: one per entry, so several entries never overwrite each other's."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry


def issue_id(entry: ConfigEntry, key: str) -> str:
    """Return the issue id of `key` (also its translation key) for this entry."""
    return f"{key}_{entry.entry_id}"
