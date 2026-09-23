"""A "last login" sensor per person, fed by the login history coordinator."""

from __future__ import annotations

from datetime import datetime

from homeassistant.auth.models import User
from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import AccessConfigEntry
from .const import CONF_HOSTNAME, DOMAIN, SIGNAL_PEOPLE_CHANGED
from .logins import LoginCoordinator
from .users import identity_values, login_emails, person_users


async def async_setup_entry(
    hass: HomeAssistant,
    entry: AccessConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Add a sensor per person; people who arrive later get theirs when the users change."""
    coordinator = entry.runtime_data.logins
    known: set[str] = set()

    @callback
    def _sync(_entry_id: str | None = None) -> None:
        people = person_users(hass)
        new = [LastLoginSensor(coordinator, entry, user) for user in people if user.id not in known]
        known.update(user.id for user in people)
        if new:
            async_add_entities(new)
        present = {user.id for user in people}
        registry = er.async_get(hass)
        for user_id in list(known - present):
            known.discard(user_id)
            if entity_id := registry.async_get_entity_id(
                "sensor", DOMAIN, f"{entry.entry_id}-{user_id}-last-login"
            ):
                registry.async_remove(entity_id)

    _sync()
    entry.async_on_unload(async_dispatcher_connect(hass, SIGNAL_PEOPLE_CHANGED, _sync))


class LastLoginSensor(CoordinatorEntity[LoginCoordinator], SensorEntity):
    """When a person last passed the Access login."""

    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_has_entity_name = True

    def __init__(self, coordinator: LoginCoordinator, entry: AccessConfigEntry, user: User) -> None:
        """Bind the sensor to a person."""
        super().__init__(coordinator)
        self._entry = entry
        self._user_id = user.id
        self._attr_unique_id = f"{entry.entry_id}-{user.id}-last-login"
        self._attr_name = f"{user.name} last login"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=entry.options.get(CONF_HOSTNAME) or entry.title,
            manufacturer="Cloudflare",
            model="Access",
        )

    @property
    def native_value(self) -> datetime | None:
        """Return the latest allowed login of any of the person's addresses."""
        user = next((u for u in person_users(self.hass) if u.id == self._user_id), None)
        if user is None or self.coordinator.data is None:
            return None
        return self.coordinator.data.last_login(identity_values(user, login_emails(self._entry)))
