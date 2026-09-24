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
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.config_entry_oauth2_flow import (
    LocalOAuth2ImplementationWithPkce,
    async_register_implementation,
)

from .const import (
    DOCS_OAUTH_CLIENTS,
    DOMAIN,
    OAUTH_AUTHORIZE_URL,
    OAUTH_CLIENT_ID,
    OAUTH_SCOPES,
    OAUTH_TOKEN_URL,
)


class CloudflareOAuth2Implementation(LocalOAuth2ImplementationWithPkce):
    """Cloudflare OAuth with PKCE, asking for the integration's scopes."""

    @property
    @override
    def extra_authorize_data(self) -> dict[str, Any]:
        """Add the integration's scopes to the authorize URL."""
        # super() supplies code_challenge and code_challenge_method; core's
        # LocalOAuth2ImplementationWithPkce.extra_authorize_data says calling it is mandatory.
        return super().extra_authorize_data | {"scope": " ".join(OAUTH_SCOPES)}


@callback
def async_register_project_client(hass: HomeAssistant) -> None:
    """Offer the project's public client.

    Called at setup and when a config flow starts, since a flow can start before setup.
    A credential added under Application credentials is offered as well: core's
    `config_entry_oauth2_flow.async_get_implementations` adds the providers' implementations
    to the registered ones, and the flow asks which to use when there is more than one.
    """
    if OAUTH_CLIENT_ID:
        async_register_implementation(
            hass,
            DOMAIN,
            CloudflareOAuth2Implementation(
                hass, DOMAIN, OAUTH_CLIENT_ID, OAUTH_AUTHORIZE_URL, OAUTH_TOKEN_URL
            ),
        )


async def async_get_authorization_server(hass: HomeAssistant) -> AuthorizationServer:
    """Return Cloudflare's authorization server."""
    return AuthorizationServer(authorize_url=OAUTH_AUTHORIZE_URL, token_url=OAUTH_TOKEN_URL)


async def async_get_auth_implementation(
    hass: HomeAssistant, auth_domain: str, credential: ClientCredential
) -> CloudflareOAuth2Implementation:
    """Return the auth implementation for a credential added by the user."""
    # Without this hook application_credentials wraps the credential in its own
    # AuthImplementation, a LocalOAuth2Implementation without PKCE.
    return CloudflareOAuth2Implementation(
        hass, auth_domain, credential.client_id, OAUTH_AUTHORIZE_URL, OAUTH_TOKEN_URL
    )


async def async_get_description_placeholders(hass: HomeAssistant) -> dict[str, str]:
    """Return description placeholders for the credentials dialog."""
    return {
        # config_entry_oauth2_flow.MY_AUTH_CALLBACK_PATH: the redirect the flow uses while
        # the `my` integration is loaded (async_get_redirect_uri).
        "redirect_uri": "https://my.home-assistant.io/redirect/oauth",
        "scopes": ", ".join(OAUTH_SCOPES),
        "more_info_url": "https://github.com/RReverser/ha-cloudflare-access#sign-in",
        "docs_oauth_clients": DOCS_OAUTH_CLIENTS,
    }
