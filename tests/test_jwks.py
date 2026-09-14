"""JWKS verification tests: signature, claims, key cache and rotation."""

from __future__ import annotations

import time

import httpx
import pytest

from custom_components.cloudflare_access_relay.jwks import (
    JwksVerifier,
    JwtVerifyError,
    unverified_claims,
)

from .conftest import ALICE, ISSUER, TEAM_DOMAIN, FakeJwks, Minter, RsaKey

AUD = "a" * 64


@pytest.fixture
def mint(rsa_keys: dict[str, RsaKey]) -> Minter:
    return Minter(rsa_keys, AUD)


@pytest.fixture
async def verifier(jwks_server: FakeJwks, socket_enabled: None):
    async with httpx.AsyncClient() as client:
        yield JwksVerifier(client, TEAM_DOMAIN)


async def test_valid_token_verifies(
    verifier: JwksVerifier, mint: Minter, jwks_server: FakeJwks
) -> None:
    token = mint(ALICE)
    claims = await verifier.verify(token, AUD)
    assert claims["email"] == ALICE
    assert claims["aud"] == [AUD]
    assert claims["iss"] == ISSUER
    assert jwks_server.fetches == 1
    # second call: cached key, no refetch
    await verifier.verify(mint(ALICE), AUD)
    assert jwks_server.fetches == 1


async def test_string_audience_accepted(verifier: JwksVerifier, mint: Minter) -> None:
    claims = await verifier.verify(mint(aud=AUD), AUD)
    assert claims["aud"] == AUD


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"aud": "b" * 64}, "audience mismatch"),
        ({"iss": "https://other.cloudflareaccess.com"}, "issuer mismatch"),
        ({"exp": int(time.time()) - 60}, "token expired"),
        ({"alg": "none"}, "unsupported alg 'none'"),
        ({"alg": "HS256"}, "unsupported alg 'HS256'"),
    ],
)
async def test_rejected_tokens(
    verifier: JwksVerifier, mint: Minter, kwargs: dict, reason: str
) -> None:
    with pytest.raises(JwtVerifyError) as err:
        await verifier.verify(mint(**kwargs), AUD)
    assert err.value.reason == reason


async def test_tampered_signature(verifier: JwksVerifier, mint: Minter) -> None:
    token = mint()
    head, payload, sig = token.split(".")
    flipped = ("A" if sig[-1] != "A" else "B") + sig[1:]
    with pytest.raises(JwtVerifyError) as err:
        await verifier.verify(f"{head}.{payload}.{flipped}", AUD)
    assert err.value.reason == "bad signature"


async def test_tampered_payload(verifier: JwksVerifier, mint: Minter) -> None:
    token = mint(ALICE)
    other = mint("mallory@example.com")
    head, _, sig = token.split(".")
    _, payload, _ = other.split(".")
    with pytest.raises(JwtVerifyError) as err:
        await verifier.verify(f"{head}.{payload}.{sig}", AUD)
    assert err.value.reason == "bad signature"


async def test_unknown_kid_refetches_once(
    verifier: JwksVerifier, mint: Minter, jwks_server: FakeJwks
) -> None:
    await verifier.verify(mint(kid="current"), AUD)
    assert jwks_server.fetches == 1
    with pytest.raises(JwtVerifyError) as err:
        await verifier.verify(mint(kid="rogue"), AUD)
    assert err.value.reason == "unknown signing key (kid)"
    assert err.value.kid == "rogue"
    assert jwks_server.fetches == 2


async def test_unknown_kid_then_published(
    verifier: JwksVerifier, mint: Minter, jwks_server: FakeJwks
) -> None:
    await verifier.verify(mint(kid="current"), AUD)
    jwks_server.published.append("rogue")
    claims = await verifier.verify(mint(kid="rogue"), AUD)
    assert claims["email"] == ALICE
    assert jwks_server.fetches == 2


async def test_rotation_previous_key_still_verifies(
    verifier: JwksVerifier, mint: Minter, jwks_server: FakeJwks
) -> None:
    await verifier.verify(mint(kid="previous"), AUD)
    jwks_server.published = ["current"]
    # still cached: no refetch, still verifies
    await verifier.verify(mint(kid="previous"), AUD)
    assert jwks_server.fetches == 1
    # a third key fails after exactly one refetch
    with pytest.raises(JwtVerifyError):
        await verifier.verify(mint(kid="rogue"), AUD)
    assert jwks_server.fetches == 2
    # the refetch dropped the previous key
    with pytest.raises(JwtVerifyError) as err:
        await verifier.verify(mint(kid="previous"), AUD)
    assert err.value.reason == "unknown signing key (kid)"


async def test_jwks_unavailable(
    verifier: JwksVerifier, mint: Minter, jwks_server: FakeJwks
) -> None:
    jwks_server.status = 503
    with pytest.raises(JwtVerifyError) as err:
        await verifier.verify(mint(), AUD)
    assert "JWKS fetch failed" in err.value.reason


async def test_malformed(verifier: JwksVerifier) -> None:
    with pytest.raises(JwtVerifyError):
        await verifier.verify("not.a.jwt", AUD)
    with pytest.raises(JwtVerifyError):
        await verifier.verify("", AUD)


def test_unverified_claims(mint: Minter) -> None:
    claims = unverified_claims(mint(exp=123))
    assert claims is not None and claims["exp"] == 123
    assert unverified_claims("garbage") is None
