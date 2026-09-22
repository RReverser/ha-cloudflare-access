"""Home Assistant users as Access identities.

A user is known to Access by an e-mail address. Home Assistant has no e-mail field;
the only place it keeps one is the login username, when the user was created with the
address as username (no login provider, core or third-party, stores an e-mail on the
credential). For everyone else the integration keeps its own: a "login e-mail"
subentry per user. The same values serve both directions: every address found feeds
the Access allow policy, and a request's Access identity picks the user that carries it.
"""

from __future__ import annotations

from collections.abc import Mapping
import logging

from homeassistant.auth.models import User
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback

from .const import CONF_EMAIL, CONF_USER_ID, SUBENTRY_TYPE_LOGIN_EMAIL

_LOGGER = logging.getLogger(__name__)

# The credential field that holds a login identity, for every login provider that
# stores one (the built-in login, command line; OIDC providers store only a subject).
IDENTITY_FIELD = "username"


def _norm(value: str) -> str:
    return value.strip().casefold()


@callback
def login_emails(entry: ConfigEntry) -> dict[str, str]:
    """Return the addresses the entry's login e-mail subentries give users, by user id."""
    return {
        sub.data[CONF_USER_ID]: _norm(sub.data[CONF_EMAIL])
        for sub in entry.subentries.values()
        if sub.subentry_type == SUBENTRY_TYPE_LOGIN_EMAIL and sub.data.get(CONF_EMAIL)
    }


def row_title(user: User, address: str | None) -> str:
    """Return the title of a user's row on the integration page."""
    name = user.name or user.id
    return f"{name}: {address}" if address else f"{name}: no address, cannot log in"


def identity_values(user: User, extra: Mapping[str, str]) -> set[str]:
    """Return the login identities of the user, case-folded."""
    values = {
        cred.data.get(IDENTITY_FIELD)
        for cred in user.credentials
        if isinstance(cred.data.get(IDENTITY_FIELD), str)
    }
    if user.id in extra:
        values.add(extra[user.id])
    return {_norm(v) for v in values if v and v.strip()}


def _allowed(user: User) -> bool:
    return user.is_active and not user.system_generated


@callback
def allowed_emails(hass: HomeAssistant, extra: Mapping[str, str]) -> list[str]:
    """Return the e-mail addresses of the users who may log in, sorted.

    A value that is not an e-mail address (a plain username) cannot be an Access
    policy subject; a user without any address gets no access.
    """
    found = {
        value
        for user in hass.auth._store._users.values()
        if _allowed(user)
        for value in identity_values(user, extra)
        if "@" in value
    }
    return sorted(found)


@callback
def person_users(hass: HomeAssistant) -> list[User]:
    """Return the users a person is linked to: the people who log in, by name.

    Users without a person (an add-on's API user, say) are not people and get no row.
    """
    collections = hass.data.get("person") or ()
    ids = {
        item.get("user_id")
        for coll in collections[:2]
        for item in coll.async_items()
        if item.get("user_id")
    }
    users = [u for u in hass.auth._store._users.values() if _allowed(u) and u.id in ids]
    return sorted(users, key=lambda u: (u.name or "").casefold())


def username_address(user: User) -> str | None:
    """Return the user's login username when it is an e-mail address."""
    return next((v for v in sorted(identity_values(user, {})) if "@" in v), None)


@callback
def login_rows(hass: HomeAssistant, extra: Mapping[str, str]) -> list[tuple[User, str | None]]:
    """Return the people whose username is not an address, with their login e-mail if any."""
    return [
        (user, extra.get(user.id)) for user in person_users(hass) if username_address(user) is None
    ]


@callback
def users_without_address(hass: HomeAssistant, extra: Mapping[str, str]) -> list[User]:
    """Return the people who carry no e-mail address at all, by name."""
    return [user for user, address in login_rows(hass, extra) if not address]


async def async_find_user(
    hass: HomeAssistant, extra: Mapping[str, str], identity: str
) -> User | None:
    """Return the one user the identity belongs to; none when there is no match or several."""
    wanted = _norm(identity)
    if not wanted:
        return None
    matches = [
        user
        for user in await hass.auth.async_get_users()
        if _allowed(user) and wanted in identity_values(user, extra)
    ]
    if len(matches) > 1:
        _LOGGER.warning(
            "%r identifies several Home Assistant users (%s); refusing to pick one",
            identity,
            ", ".join(u.name or u.id for u in matches),
        )
        return None
    return matches[0] if matches else None
