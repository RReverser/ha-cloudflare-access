"""Home Assistant users as Access identities.

The same mapping serves both directions: the Access allow policy lists the address
of every Home Assistant user, and a request's Access identity is turned into the
user whose address it is. The address lives in the user field the options name:
the built-in login's username by default, the display name, or any credential
field a login integration stores.
"""

from __future__ import annotations

from typing import Any

from homeassistant.auth.models import User
from homeassistant.core import HomeAssistant, callback

from .const import CONF_USER_MATCH, USER_MATCH_NAME


def identity_values(user: User, mode: str) -> list[str]:
    """Return the values of the configured field for one user."""
    if mode == USER_MATCH_NAME:
        return [user.name] if user.name else []
    return [value for cred in user.credentials if isinstance(value := cred.data.get(mode), str)]


def user_matches(user: User, mode: str, value: str) -> bool:
    """Return whether the identity claim value belongs to the user."""
    wanted = value.strip().casefold()
    return bool(wanted) and any(v.strip().casefold() == wanted for v in identity_values(user, mode))


def _allowed(user: User) -> bool:
    return user.is_active and not user.system_generated


@callback
def allowed_emails(hass: HomeAssistant, options: dict[str, Any]) -> list[str]:
    """Return the e-mail addresses of the users who may log in, sorted.

    A value that is not an e-mail address (a plain username) cannot be an Access
    policy subject; such a user gets no access until the field holds an address.
    """
    mode = options[CONF_USER_MATCH]
    found = {
        value.strip().lower()
        for user in hass.auth._store._users.values()
        if _allowed(user)
        for value in identity_values(user, mode)
        if "@" in value
    }
    return sorted(found)


async def async_find_user(hass: HomeAssistant, mode: str, identity: str) -> User | None:
    """Return the user the identity belongs to, if any."""
    for user in await hass.auth.async_get_users():
        if _allowed(user) and user_matches(user, mode, identity):
            return user
    return None
