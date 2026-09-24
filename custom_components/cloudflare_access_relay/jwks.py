"""Verification of Cloudflare Access application tokens against the team JWKS."""

from __future__ import annotations

import logging
from typing import Any

import httpx
import jwt

_LOGGER = logging.getLogger(__name__)

ALGORITHM = "RS256"
CERTS_URL_FMT = "https://{team_domain}/cdn-cgi/access/certs"


class JwtVerifyError(Exception):
    """The token was rejected; `reason` is safe to show and log."""

    def __init__(self, reason: str, kid: str | None = None) -> None:
        """Initialise with a human-readable reason."""
        super().__init__(reason)
        self.reason = reason
        self.kid = kid


class JwksVerifier:
    """Fetches and caches the team's signing keys, keyed by `kid`."""

    def __init__(self, client: httpx.AsyncClient, team_domain: str) -> None:
        """Initialise for one team domain (host only, no scheme)."""
        self._client = client
        self.issuer = f"https://{team_domain}"
        self.certs_url = CERTS_URL_FMT.format(team_domain=team_domain)
        self._keys: dict[str, Any] = {}

    async def refresh(self) -> None:
        """Replace the key cache from the certs endpoint."""
        try:
            resp = await self._client.get(self.certs_url, timeout=15)
            if resp.status_code != 200:
                raise JwtVerifyError(f"JWKS fetch failed with HTTP {resp.status_code}")
            data = resp.json()
        except (httpx.HTTPError, ValueError) as err:
            raise JwtVerifyError(f"JWKS fetch failed: {err}") from err
        try:
            jwk_set = jwt.PyJWKSet.from_dict(data)
        except jwt.PyJWKSetError as err:
            raise JwtVerifyError(f"JWKS document unusable: {err}") from err
        keys: dict[str, Any] = {
            jwk.key_id: jwk.key for jwk in jwk_set.keys if jwk.key_id and jwk.key_type == "RSA"
        }
        self._keys = keys
        _LOGGER.debug("Loaded %d signing keys from %s", len(keys), self.certs_url)

    async def _key_for(self, kid: str) -> Any:
        # An unknown kid usually means the team rotated its keys: fetch once more
        # before refusing, so a rotation needs no restart.
        if kid not in self._keys:
            await self.refresh()
        if kid not in self._keys:
            raise JwtVerifyError("unknown signing key (kid)", kid)
        return self._keys[kid]

    async def verify(self, token: str, audience: str) -> dict[str, Any]:
        """Verify signature, issuer, audience and expiry; return claims."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as err:
            raise JwtVerifyError(f"malformed token header: {err}") from err
        kid = header.get("kid")
        # Before the key lookup: a token with another alg must not cost a JWKS fetch.
        if header.get("alg") != ALGORITHM:
            raise JwtVerifyError(f"unsupported alg {header.get('alg')!r}", kid)
        if not isinstance(kid, str) or not kid:
            raise JwtVerifyError("token header has no kid")
        key = await self._key_for(kid)
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key,
                algorithms=[ALGORITHM],
                audience=audience,
                issuer=self.issuer,
                # PyJWT checks `exp` only when the token carries one; without `require`
                # a token that omits it would never expire. Five seconds of clock skew.
                options={"require": ["exp", "iat", "aud", "iss"]},
                leeway=5,
            )
        except jwt.ExpiredSignatureError as err:
            raise JwtVerifyError("token expired", kid) from err
        except jwt.InvalidAudienceError as err:
            raise JwtVerifyError("audience mismatch", kid) from err
        except jwt.InvalidIssuerError as err:
            raise JwtVerifyError("issuer mismatch", kid) from err
        except jwt.InvalidSignatureError as err:
            raise JwtVerifyError("bad signature", kid) from err
        except jwt.PyJWTError as err:
            raise JwtVerifyError(f"invalid token: {err}", kid) from err
        return claims


def unverified_claims(token: str) -> dict[str, Any] | None:
    """Decode a token payload without verifying it (for expiry display only)."""
    try:
        claims: dict[str, Any] = jwt.decode(
            token, options={"verify_signature": False, "verify_exp": False}
        )
    except jwt.PyJWTError:
        return None
    return claims
