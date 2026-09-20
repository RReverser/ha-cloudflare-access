"""Application credentials platform: sign in with Cloudflare.

A self-managed Cloudflare OAuth client with PKCE and no secret. The scopes are
exactly what the integration does; the consent page shows them.
"""

from __future__ import annotations

from typing import Any, override

from homeassistant.components.application_credentials import (
    AuthorizationServer,
    ClientCredential,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.config_entry_oauth2_flow import (
    LocalOAuth2ImplementationWithPkce,
)

from .const import OAUTH_AUTHORIZE_URL, OAUTH_SCOPES, OAUTH_TOKEN_URL


class CloudflareOAuth2Implementation(LocalOAuth2ImplementationWithPkce):
    """Cloudflare OAuth with PKCE, asking for the integration's scopes."""

    @property
    @override
    def extra_authorize_data(self) -> dict[str, Any]:
        """Extra data that needs to be appended to the authorize url."""
        return super().extra_authorize_data | {"scope": " ".join(OAUTH_SCOPES)}


async def async_get_authorization_server(hass: HomeAssistant) -> AuthorizationServer:
    """Return Cloudflare's authorization server."""
    return AuthorizationServer(authorize_url=OAUTH_AUTHORIZE_URL, token_url=OAUTH_TOKEN_URL)


async def async_get_auth_implementation(
    hass: HomeAssistant, auth_domain: str, credential: ClientCredential
) -> CloudflareOAuth2Implementation:
    """Return the auth implementation for a credential added by the user."""
    return CloudflareOAuth2Implementation(
        hass, auth_domain, credential.client_id, OAUTH_AUTHORIZE_URL, OAUTH_TOKEN_URL
    )


async def async_get_description_placeholders(hass: HomeAssistant) -> dict[str, str]:
    """Return description placeholders for the credentials dialog."""
    return {
        "redirect_uri": "https://my.home-assistant.io/redirect/oauth",
        "scopes": ", ".join(OAUTH_SCOPES),
        "more_info_url": "https://github.com/RReverser/ha-cloudflare-access#sign-in",
    }
