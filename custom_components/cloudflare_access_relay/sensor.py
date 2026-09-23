"""A "last login" sensor per person, fed by the login history coordinator."""

from __future__ import annotations

from datetime import datetime

from homeassistant.auth.models import User
from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import AccessConfigEntry
from .const import CONF_HOSTNAME, DOMAIN, SIGNAL_PEOPLE_CHANGED
from .logins import LoginCoordinator
from .users import identity_values, login_emails, person_users

# Entities are fed by the coordinator; nothing to poll in parallel.
PARALLEL_UPDATES = 0


def _unique_id(entry: AccessConfigEntry, user_id: str) -> str:
    return f"{entry.entry_id}-{user_id}-last-login"


async def async_setup_entry(
    hass: HomeAssistant,
    entry: AccessConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Add a sensor per person; people who come and go later are followed."""
    coordinator = entry.runtime_data.logins
    sensors: dict[str, LastLoginSensor] = {}
    registry = er.async_get(hass)

    async def _async_sync() -> None:
        people = {user.id: user for user in await person_users(hass)}
        new = [
            LastLoginSensor(coordinator, entry, user)
            for user_id, user in people.items()
            if user_id not in sensors
        ]
        for sensor in new:
            sensors[sensor.user.id] = sensor
        for user_id, user in people.items():
            sensors[user_id].user = user
        if new:
            async_add_entities(new)
        # people who are gone, including those removed while Home Assistant was down
        wanted = {_unique_id(entry, user_id) for user_id in people}
        for reg_entry in er.async_entries_for_config_entry(registry, entry.entry_id):
            if reg_entry.domain == "sensor" and reg_entry.unique_id not in wanted:
                registry.async_remove(reg_entry.entity_id)
        for user_id in list(sensors):
            if user_id not in people:
                del sensors[user_id]

    @callback
    def _people_changed(_entry_id: str) -> None:
        entry.async_create_task(hass, _async_sync())

    await _async_sync()
    entry.async_on_unload(async_dispatcher_connect(hass, SIGNAL_PEOPLE_CHANGED, _people_changed))


class LastLoginSensor(CoordinatorEntity[LoginCoordinator], SensorEntity):
    """When a person last passed the Access login."""

    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_has_entity_name = True
    _attr_translation_key = "last_login"

    def __init__(self, coordinator: LoginCoordinator, entry: AccessConfigEntry, user: User) -> None:
        """Bind the sensor to a person."""
        super().__init__(coordinator)
        self._entry = entry
        self.user = user
        self._attr_unique_id = _unique_id(entry, user.id)
        self._attr_translation_placeholders = {"name": user.name or user.id}
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=entry.options.get(CONF_HOSTNAME) or entry.title,
            manufacturer="Cloudflare",
            model="Access",
            entry_type=DeviceEntryType.SERVICE,
        )

    @property
    def native_value(self) -> datetime | None:
        """Return the latest allowed login of any of the person's addresses."""
        return self.coordinator.data.last_login(
            identity_values(self.user, login_emails(self._entry))
        )
