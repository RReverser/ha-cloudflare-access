"""Home Assistant users as Access identities.

A user is known to Access by an e-mail address, and Home Assistant keeps one in two
places only: the login username (the built-in login has no e-mail field, so the
username is the address when the user was created with it), and the `email` a login
provider that authenticates against an identity provider stores in the credential. The
same two fields serve both directions: every address found feeds the Access allow
policy, and a request's Access identity picks the user that carries it.
"""

from __future__ import annotations

import logging

from homeassistant.auth.models import User
from homeassistant.core import HomeAssistant, callback

_LOGGER = logging.getLogger(__name__)


# The credential fields that hold a login identity: the username of any login
# provider, and the e-mail address a provider fed by an identity provider stores.
IDENTITY_FIELDS = ("username", "email")


def identity_values(user: User) -> set[str]:
    """Return the login identities of the user, case-folded."""
    values = {
        cred.data.get(field)
        for cred in user.credentials
        for field in IDENTITY_FIELDS
        if isinstance(cred.data.get(field), str)
    }
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
