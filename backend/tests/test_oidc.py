"""Token validation: is this real, and is it for us?

Every token here is **signed for real**, with a keypair generated in this file. A fake
that returns "valid" would prove nothing about code whose entire job is deciding what
counts as valid — this is the one module in the project where the test double would
have to be the thing under test.

The weight is on the forgeries. A round-trip test proves the happy path works; the
tests that matter are the ones asserting that a token which is *almost* right is
refused, because each of those, if missed, is a silent admission rather than a
failure anybody notices.

No network: `JwksCache` takes its fetch as a callable, exactly as `HttpTransport` takes
its HTTP call. The suite still starts nothing.
"""

import time

import pytest

# PyJWT is an optional extra, like psycopg and FastAPI. CI installs it and fails if
# these skip — see .github/workflows/tests.yml.
pytest.importorskip("jwt", reason="install the 'access' extra to run these")

import jwt  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402

from carnet.access import oidc  # noqa: E402
from carnet.access.oidc import (  # noqa: E402
    JwksCache,
    TokenError,
    TokenExpired,
    peek_issuer,
    verify,
)

ISSUER = "https://acme.okta.example"
AUDIENCE = "0oa1client"
JWKS_URI = "https://acme.okta.example/oauth2/v1/keys"

PROVIDER = {"issuer": ISSUER, "audience": AUDIENCE, "jwks_uri": JWKS_URI}


# --- a real signing key, generated once per session -------------------------------


class Signer:
    """One keypair, and the ability to mint tokens with it."""

    def __init__(self, kid: str, key=None, algorithm: str = "RS256"):
        self.kid = kid
        self.algorithm = algorithm
        self.key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def jwk(self) -> dict:
        algorithm = (
            jwt.algorithms.ECAlgorithm
            if self.algorithm.startswith("ES")
            else jwt.algorithms.RSAAlgorithm
        )
        entry = algorithm.to_jwk(self.key.public_key(), as_dict=True)
        entry.update({"kid": self.kid, "use": "sig", "alg": self.algorithm})
        return entry

    def public_pem(self) -> bytes:
        return self.key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def token(self, *, headers=None, **claims) -> str:
        now = int(time.time())
        payload = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "00u1abc",
            "iat": now,
            "exp": now + 300,
            "email": "priya@acme.com",
        }
        payload.update(claims)
        payload = {k: v for k, v in payload.items() if v is not None}
        return jwt.encode(
            payload,
            self.key,
            algorithm=self.algorithm,
            headers={"kid": self.kid, **(headers or {})},
        )


@pytest.fixture(scope="session")
def signer():
    return Signer("key-1")


@pytest.fixture(scope="session")
def other_signer():
    """A second, unrelated keypair. Its tokens must never verify."""
    return Signer("key-1")  # same kid on purpose — only the key differs


@pytest.fixture
def cache(signer):
    """A cache serving this session's key, without a network."""
    return JwksCache(fetch=lambda uri: oidc.keys_from_jwks({"keys": [signer.jwk()]}))


# --- the happy path ---------------------------------------------------------------


def test_a_genuine_token_verifies(signer, cache):
    claims = verify(signer.token(), PROVIDER, cache)

    assert claims["sub"] == "00u1abc"
    assert claims["email"] == "priya@acme.com"


def test_an_es256_token_verifies(cache):
    """Providers differ on curve versus RSA. Both are asymmetric, which is the only
    property that matters here."""
    es = Signer("ec-1", key=ec.generate_private_key(ec.SECP256R1()), algorithm="ES256")
    es_cache = JwksCache(fetch=lambda uri: oidc.keys_from_jwks({"keys": [es.jwk()]}))

    assert verify(es.token(), PROVIDER, es_cache)["sub"] == "00u1abc"


# --- algorithm confusion ----------------------------------------------------------
#
# The two attacks that need no key at all, or need only a key we publish.


def test_alg_none_is_refused(signer, cache):
    """An unsigned token asserting it needs no signature."""
    token = jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "sub": "00u1abc",
                        "exp": int(time.time()) + 300}, key=None, algorithm="none")

    with pytest.raises(TokenError, match="not accepted"):
        verify(token, PROVIDER, cache)


def test_an_hmac_signed_token_is_refused(signer, cache):
    """The classic algorithm-confusion attack, refused before a key is even looked up.

    The provider's public key is *published*. If HS256 were accepted, anyone who can
    fetch it can use it as an HMAC secret and mint tokens that verify perfectly.

    The forgery here is signed with an arbitrary secret rather than the public key,
    because PyJWT now refuses to sign HMAC with anything PEM-shaped — a second defence,
    and not one to depend on. Ours is that the algorithm never reaches key selection.
    """
    forged = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "attacker", "exp": int(time.time()) + 300},
        key="any-secret-at-all-long-enough-to-not-warn",
        algorithm="HS256",
        headers={"kid": signer.kid},
    )

    with pytest.raises(TokenError, match="not accepted"):
        verify(forged, PROVIDER, cache)


def test_pyjwt_also_refuses_to_hmac_sign_with_a_public_key(signer):
    """Belt to our braces, asserted so we notice if it ever stops being true."""
    with pytest.raises(jwt.exceptions.InvalidKeyError):
        jwt.encode({"sub": "x"}, key=signer.public_pem(), algorithm="HS256")


def test_the_allowlist_is_asymmetric_only():
    """Asserted directly, so relaxing it is a deliberate edit to a test rather than a
    quiet addition to a set."""
    assert not any(alg.startswith("HS") for alg in oidc.ALLOWED_ALGORITHMS)
    assert "none" not in oidc.ALLOWED_ALGORITHMS


# --- forgery ----------------------------------------------------------------------


def test_a_token_signed_by_the_wrong_key_is_refused(other_signer, cache):
    """Same issuer, same audience, same `kid`, correct shape — different key."""
    with pytest.raises(TokenError, match="failed verification"):
        verify(other_signer.token(), PROVIDER, cache)


def test_a_tampered_payload_is_refused(signer, cache):
    token = signer.token()
    head, payload, signature = token.split(".")
    # Re-encode a different subject and keep the original signature.
    import base64
    import json

    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    claims["sub"] = "somebody-else"
    swapped = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()

    with pytest.raises(TokenError):
        verify(f"{head}.{swapped}.{signature}", PROVIDER, cache)


def test_a_signature_stripped_token_is_refused(signer, cache):
    head, payload, _ = signer.token().split(".")

    with pytest.raises(TokenError):
        verify(f"{head}.{payload}.", PROVIDER, cache)


def test_garbage_is_refused(cache):
    with pytest.raises(TokenError):
        verify("not-a-token", PROVIDER, cache)


def test_a_token_signed_with_an_unpublished_key_is_refused(cache):
    """A `kid` the provider does not publish. One refetch, then refusal."""
    stranger = Signer("key-nobody-has")

    with pytest.raises(TokenError, match="no signing key"):
        verify(stranger.token(), PROVIDER, cache)


# --- time -------------------------------------------------------------------------


def test_an_expired_token_is_refused(signer, cache):
    with pytest.raises(TokenExpired):
        verify(signer.token(exp=int(time.time()) - 3600), PROVIDER, cache)


def test_expiry_is_its_own_error(signer, cache):
    """The only distinction surfaced, and only because a client can act on it:
    expired means log in again, everything else means something is wrong."""
    with pytest.raises(TokenExpired):
        verify(signer.token(exp=int(time.time()) - 3600), PROVIDER, cache)

    with pytest.raises(TokenError) as caught:
        verify(signer.token(aud="somebody-else"), PROVIDER, cache)
    assert not isinstance(caught.value, TokenExpired)


def test_a_token_from_the_future_is_refused(signer, cache):
    with pytest.raises(TokenError, match="not valid yet"):
        verify(signer.token(nbf=int(time.time()) + 3600), PROVIDER, cache)


def test_a_small_clock_difference_is_tolerated(signer, cache):
    """A server a minute out of sync would otherwise reject every valid token with a
    message about expiry, which reads as the product being broken."""
    just_expired = signer.token(exp=int(time.time()) - 5)

    assert verify(just_expired, PROVIDER, cache, leeway=60)["sub"] == "00u1abc"

    with pytest.raises(TokenExpired):
        verify(just_expired, PROVIDER, cache, leeway=0)


# --- is it for us? ----------------------------------------------------------------


def test_a_token_for_another_application_is_refused(signer, cache):
    """Genuine, unexpired, correctly signed by the right provider — and minted for a
    different app. Accepting it makes any app on a customer's IdP a login here."""
    with pytest.raises(TokenError, match="audience"):
        verify(signer.token(aud="some-other-app"), PROVIDER, cache)


def test_a_token_from_another_issuer_is_refused(signer, cache):
    with pytest.raises(TokenError, match="issuer"):
        verify(signer.token(iss="https://evil.example"), PROVIDER, cache)


@pytest.mark.parametrize("claim", ["exp", "iss", "aud", "sub"])
def test_a_token_missing_a_required_claim_is_refused(signer, cache, claim):
    with pytest.raises(TokenError):
        verify(signer.token(**{claim: None}), PROVIDER, cache)


# --- peek_issuer ------------------------------------------------------------------


def test_peek_issuer_reads_without_verifying(other_signer):
    """It has to work on a token we cannot yet check — that is its whole purpose. Safe
    only because an unrecognised issuer is refused and a recognised one is then
    verified properly."""
    assert peek_issuer(other_signer.token()) == ISSUER


def test_peek_issuer_refuses_a_token_with_no_issuer(signer):
    with pytest.raises(TokenError, match="no issuer"):
        peek_issuer(signer.token(iss=None))


def test_peek_issuer_refuses_garbage():
    with pytest.raises(TokenError):
        peek_issuer("....")


# --- the key cache ----------------------------------------------------------------


def test_keys_are_fetched_once(signer):
    calls = []

    def fetch(uri):
        calls.append(uri)
        return oidc.keys_from_jwks({"keys": [signer.jwk()]})

    cache = JwksCache(fetch=fetch)
    for _ in range(5):
        verify(signer.token(), PROVIDER, cache)

    assert calls == [JWKS_URI]


def test_a_rotated_key_is_picked_up(signer):
    """Rotation looks like a token signed by a key we have not seen. One refetch."""
    rotated = Signer("key-2")
    published = [signer.jwk()]

    cache = JwksCache(fetch=lambda uri: oidc.keys_from_jwks({"keys": list(published)}))
    verify(signer.token(), PROVIDER, cache)

    published.append(rotated.jwk())

    assert verify(rotated.token(), PROVIDER, cache)["sub"] == "00u1abc"


def test_an_unreachable_provider_serves_the_keys_we_have(signer):
    """Every authenticated request needs these keys, so an unreachable JWKS endpoint
    would otherwise be a total outage of ours caused by somebody else's.

    Not failing open: the stale key still has to verify the signature."""
    reachable = [True]

    def fetch(uri):
        if not reachable[0]:
            raise ConnectionError("provider is down")
        return oidc.keys_from_jwks({"keys": [signer.jwk()]})

    cache = JwksCache(fetch=fetch, ttl=0)  # expire immediately, forcing a refetch
    verify(signer.token(), PROVIDER, cache)

    reachable[0] = False

    assert verify(signer.token(), PROVIDER, cache)["sub"] == "00u1abc"


def test_a_stale_key_still_has_to_verify(signer, other_signer):
    """The freshness of the key list is what is relaxed, never whether a token is
    genuine."""
    reachable = [True]

    def fetch(uri):
        if not reachable[0]:
            raise ConnectionError("provider is down")
        return oidc.keys_from_jwks({"keys": [signer.jwk()]})

    cache = JwksCache(fetch=fetch, ttl=0)
    verify(signer.token(), PROVIDER, cache)
    reachable[0] = False

    with pytest.raises(TokenError, match="failed verification"):
        verify(other_signer.token(), PROVIDER, cache)


def test_an_unreachable_provider_we_never_reached_is_an_error(signer):
    """With nothing cached there is nothing to fall back to, and refusing is the only
    honest answer."""
    cache = JwksCache(fetch=lambda uri: (_ for _ in ()).throw(ConnectionError("down")))

    with pytest.raises(TokenError, match="cannot reach"):
        verify(signer.token(), PROVIDER, cache)


def test_an_unknown_kid_does_not_hammer_the_provider(signer):
    """`kid` is attacker-controlled. Without a floor on refetching, a stream of junk
    tokens becomes a stream of requests at a customer's IdP with our name on them."""
    calls = []

    def fetch(uri):
        calls.append(uri)
        return oidc.keys_from_jwks({"keys": [signer.jwk()]})

    cache = JwksCache(fetch=fetch, min_refresh=3600)
    verify(signer.token(), PROVIDER, cache)

    stranger = Signer("key-nobody-has")
    for _ in range(20):
        with pytest.raises(TokenError):
            verify(stranger.token(), PROVIDER, cache)

    # Two, and exactly two: the ordinary fetch, plus **one** refetch to check whether
    # the unknown key is a rotation. The other nineteen are refused from cache. One
    # refetch is the feature; nineteen would be the amplifier.
    assert len(calls) == 2, f"refetched {len(calls) - 1} times for a bogus kid"


def test_rotation_works_on_a_freshly_booted_machine(signer, monkeypatch):
    """A regression test for a bug only CI could find.

    `time.monotonic()` counts from an arbitrary origin — on Linux, from boot. The
    rate limit on forced refetches was seeded with `0.0` meaning "never", which reads
    as "a moment ago" when the clock itself is near zero. On a machine up for days it
    passed; on a fresh CI runner the very first unknown `kid` was rate-limited, so a
    key rotation would have been silently ignored for the first hour of the process's
    life.

    Simulated by moving the clock to just after boot, which is the condition rather
    than an approximation of it.
    """
    rotated = Signer("key-2")
    published = [signer.jwk()]
    monkeypatch.setattr(oidc.time, "monotonic", lambda: 3.0)

    cache = JwksCache(
        fetch=lambda uri: oidc.keys_from_jwks({"keys": list(published)}),
        min_refresh=3600,
    )
    verify(signer.token(), PROVIDER, cache)

    published.append(rotated.jwk())

    assert verify(rotated.token(), PROVIDER, cache)["sub"] == "00u1abc"


def test_a_single_key_needs_no_kid(signer):
    """A key set with one key is unambiguous."""
    cache = JwksCache(fetch=lambda uri: {None: signer.key.public_key()})
    token = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "00u1abc", "exp": int(time.time()) + 300},
        signer.key,
        algorithm="RS256",
    )

    assert verify(token, PROVIDER, cache)["sub"] == "00u1abc"


def test_several_keys_and_no_kid_is_refused(signer):
    """Trying each in turn would mean a token verifying against a key it never named."""
    second = Signer("key-2")
    cache = JwksCache(
        fetch=lambda uri: oidc.keys_from_jwks({"keys": [signer.jwk(), second.jwk()]})
    )
    token = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "00u1abc", "exp": int(time.time()) + 300},
        signer.key,
        algorithm="RS256",
    )

    with pytest.raises(TokenError, match="no signing key"):
        verify(token, PROVIDER, cache)


def test_an_unusable_jwks_entry_does_not_break_the_others(signer):
    """A provider publishing one key type we do not support must not stop us using the
    ones we do."""
    keys = oidc.keys_from_jwks(
        {"keys": [{"kty": "OKP", "crv": "Ed448", "kid": "weird"}, signer.jwk()]}
    )

    assert signer.kid in keys
    assert "weird" not in keys


# --- a redirecting JWKS is named, not misreported (step 064) -------------------------


class _Redirect:
    """A 302 with a Location, the shape a fronted JWKS answers with."""

    status_code = 302
    headers = {"Location": "https://login.acme.com/oauth2/v1/keys"}

    def json(self):  # pragma: no cover - reaching this IS the defect
        raise AssertionError("a redirect body must never be parsed as a key set")

    def raise_for_status(self):
        """`requests`' own behaviour: 3xx is not an error status."""


def test_a_redirecting_jwks_names_the_redirect(monkeypatch):
    """Step 058 stopped following redirects and did not notice that `raise_for_status`
    ignores 3xx, so the redirect fell into `.json()` and died as a decode error —
    reported to the operator as "cannot reach the identity provider's keys" on an IdP
    that was reachable and had answered. An apex-to-www canonicalization was enough.

    Still not followed: a 3xx points somewhere no pin checked. But the refusal now says
    which status, and where to, because the fix is re-registering the provider at the
    URL it actually serves from."""
    import requests

    from carnet.tools.mcp import egress

    # Resolved by a stand-in, not by the network: this suite does not dial, and a test
    # that quietly depends on `acme.com` having an A record is a test that fails on an
    # aeroplane. The address is public so the pin has no reason of its own to refuse.
    monkeypatch.setattr(
        egress.socket,
        "getaddrinfo",
        lambda host, port, **_k: [(0, 0, 0, "", ("93.184.216.34", port))],
    )
    monkeypatch.setattr(requests.Session, "request", lambda *_a, **_k: _Redirect())

    with pytest.raises(RuntimeError) as refusal:
        oidc._fetch_jwks("https://acme.com/keys")

    assert "302" in str(refusal.value)
    assert "login.acme.com/oauth2/v1/keys" in str(refusal.value)
