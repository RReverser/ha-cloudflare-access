"""Home Assistant users as Access identities.

The same values serve both directions: every e-mail address found on a Home Assistant
user goes into the Access allow policy, and a request's Access identity is turned
into the user that carries it. Where the address lives depends on how the user logs
in: the built-in login stores it as the username, a login integration stores it in a
credential field of its own, and the display name is a place too. All of them count,
so there is nothing to configure.
"""

from __future__ import annotations

import logging

from homeassistant.auth.models import User
from homeassistant.core import HomeAssistant, callback

_LOGGER = logging.getLogger(__name__)


def identity_values(user: User) -> set[str]:
    """Return every value that may identify the user, case-folded."""
    values = {user.name} if user.name else set()
    for cred in user.credentials:
        values.update(v for v in cred.data.values() if isinstance(v, str))
    return {v.strip().casefold() for v in values if v and v.strip()}


def _allowed(user: User) -> bool:
    return user.is_active and not user.system_generated


@callback
def allowed_emails(hass: HomeAssistant) -> list[str]:
    """Return the e-mail addresses of the users who may log in, sorted.

    A value that is not an e-mail address (a plain username) cannot be an Access
    policy subject; a user without any address gets no access.
    """
    found = {
        value
        for user in hass.auth._store._users.values()
        if _allowed(user)
        for value in identity_values(user)
        if "@" in value
    }
    return sorted(found)


async def async_find_user(hass: HomeAssistant, identity: str) -> User | None:
    """Return the one user the identity belongs to; none when there is no match or several."""
    wanted = identity.strip().casefold()
    if not wanted:
        return None
    matches = [
        user
        for user in await hass.auth.async_get_users()
        if _allowed(user) and wanted in identity_values(user)
    ]
    if len(matches) > 1:
        _LOGGER.warning(
            "%r identifies several Home Assistant users (%s); refusing to pick one",
            identity,
            ", ".join(u.name or u.id for u in matches),
        )
        return None
    return matches[0] if matches else None
