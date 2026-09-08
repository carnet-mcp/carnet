"""`access/acting.py`: whom a door call says it is for, and what that claim is worth.

Step 033c. Three functions, three failure surfaces:

    parse            the wire shape — nothing looked up, everything refused loudly
    verify           a forwarded IdP token, checked against THIS tenant's providers
    assert_identity  an address believed, with the believing gated elsewhere

The test that matters most is the tenant boundary: a token that verifies perfectly
against *another* tenant's registered provider must be refused without being tried.
`providers.resolve` maps issuer → tenant globally; here the tenant is already known
(it is the door principal's), and a mismatch is one company's chatbot acting as
another company's employee.
"""

import time

import pytest

pytest.importorskip("jwt")
import jwt  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from carnet import storage  # noqa: E402
from carnet.access import acting, oidc, providers  # noqa: E402
from carnet.access.acting import ActingForError  # noqa: E402
from carnet.access.oidc import JwksCache  # noqa: E402
from carnet.core import Principal  # noqa: E402

from conftest import TEST_TENANT  # noqa: E402

OTHER_TENANT = "globex"
ISSUER = "https://acme.okta.example"
OTHER_ISSUER = "https://globex.okta.example"


class Idp:
    """A provider with a real signing key — `test_api.Idp`, trimmed to what this needs."""

    def __init__(self, issuer=ISSUER, audience="api://carnet", kid="k1"):
        self.issuer = issuer
        self.audience = audience
        self.kid = kid
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def jwk(self):
        entry = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        entry.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return entry

    def token(self, **claims):
        now = int(time.time())
        payload = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": "00u-tom",
            "iat": now,
            "exp": now + 300,
            "email": "tom@acme.com",
        }
        payload.update(claims)
        return jwt.encode(payload, self.key, algorithm="RS256", headers={"kid": self.kid})

    def row(self, **overrides):
        return {
            "issuer": self.issuer,
            "jwks_uri": f"{self.issuer}/v1/keys",
            "audience": self.audience,
            "allowed_domains": ("acme.com",),
            **overrides,
        }


@pytest.fixture
def idp():
    return Idp()


@pytest.fixture
def registered(idp, isolated_storage, monkeypatch):
    """`idp` registered for the test tenant, its keys reachable without a network.

    Patches `providers.KEYS` — the one per-process cache both the browser door and
    acting-for verify through since the 033c hoist.
    """
    storage.active().save_tenant_idp(TEST_TENANT, idp.row())
    monkeypatch.setattr(
        providers,
        "KEYS",
        JwksCache(fetch=lambda uri: oidc.keys_from_jwks({"keys": [idp.jwk()]})),
    )
    return idp


@pytest.fixture
def tom(registered):
    """A person who has signed in once — which is what creates the row `verify`
    resolves. Identity is `(issuer, subject)`, exactly as a login writes it."""
    storage.active().create_user(
        TEST_TENANT,
        {
            "id": "u-tom",
            "issuer": ISSUER,
            "subject": "00u-tom",
            "email": "tom@acme.com",
        },
    )
    return "u-tom"


@pytest.fixture
def caller():
    """The door principal an acting-for claim arrives under: a machine token."""
    return Principal.machine("tok-1", TEST_TENANT)


# --- parse: the wire shape --------------------------------------------------------


def test_a_token_parses_as_verified_material():
    assert acting.parse({"token": "eyJ..."}) == (acting.TOKEN_KEY, "eyJ...")


def test_an_email_parses_as_asserted_material():
    assert acting.parse({"email": "tom@acme.com"}) == (acting.EMAIL_KEY, "tom@acme.com")


@pytest.mark.parametrize(
    "raw",
    [
        {},
        {"token": "a", "email": "b@c.d"},
        {"emial": "tom@acme.com"},
        {"email": "tom@acme.com", "extra": True},
        {"token": ""},
        {"email": 7},
        "tom@acme.com",
        ["tom@acme.com"],
    ],
)
def test_every_wrong_shape_refuses_rather_than_degrading(raw):
    """A typo'd key must fail loudly, never quietly become a call with no acting-for —
    an audit row saying `none` about a call somebody meant to attribute is the log
    being wrong at the exact moment it was being used most deliberately."""
    with pytest.raises(ActingForError):
        acting.parse(raw)


def test_an_address_is_bounded_and_email_shaped():
    with pytest.raises(ActingForError, match="254"):
        acting.parse({"email": "a" * 250 + "@acme.com"})
    with pytest.raises(ActingForError, match="one '@'"):
        acting.parse({"email": "not-an-address"})
    with pytest.raises(ActingForError, match="one '@'"):
        acting.parse({"email": "two@at@signs"})
    with pytest.raises(ActingForError, match="whitespace"):
        acting.parse({"email": "tom @acme.com"})


# --- verify: the forwarded token --------------------------------------------------


def test_a_forwarded_token_becomes_the_person_it_names(caller, idp, tom):
    resolved = acting.verify(caller, idp.token())

    assert resolved.user_id == "u-tom"
    assert resolved.source == "verified"
    # Our stored email, never claim text: the token could carry anything in `email`
    # and the audit column still gets the value this system already owns.
    assert resolved.email == "tom@acme.com"


def test_the_tenant_boundary_is_checked_before_the_signature(caller, tom, monkeypatch):
    """**The check that matters most.** A token that verifies perfectly against another
    tenant's registered provider is refused — the door principal's tenant decides which
    providers may vouch, and a mismatch is a cross-tenant act-as."""
    other = Idp(issuer=OTHER_ISSUER, kid="k2")
    storage.active().create_tenant(OTHER_TENANT, "Globex")
    storage.active().save_tenant_idp(OTHER_TENANT, other.row())
    # The keys are *served*, so if the tenant filter were missing the signature would
    # check out and the test would fail for the right reason rather than on a fetch.
    monkeypatch.setattr(
        providers,
        "KEYS",
        JwksCache(fetch=lambda uri: oidc.keys_from_jwks({"keys": [other.jwk()]})),
    )

    with pytest.raises(ActingForError, match="not issued by an identity provider"):
        acting.verify(caller, other.token())


def test_an_expired_token_names_the_fix(caller, idp, tom):
    stale = idp.token(iat=int(time.time()) - 900, exp=int(time.time()) - 600)
    with pytest.raises(ActingForError, match="expired.*fresh"):
        acting.verify(caller, stale)


def test_a_person_who_never_signed_in_is_refused(caller, registered):
    """A tool call creates nobody — `users.resolve`'s first-time path is a login path.
    The sentence says what to do instead."""
    with pytest.raises(ActingForError, match="never signed in"):
        acting.verify(caller, registered.token(sub="00u-stranger"))


def test_a_disabled_person_cannot_be_acted_for(caller, idp, tom):
    storage.active().set_user_status(TEST_TENANT, "u-tom", "disabled", actor="system:test")
    with pytest.raises(ActingForError, match="disabled"):
        acting.verify(caller, idp.token())


def test_garbage_is_refused_as_unreadable(caller, registered):
    with pytest.raises(ActingForError, match="could not be read"):
        acting.verify(caller, "not-a-jwt")


def test_a_wrong_audience_is_refused(caller, idp, tom):
    """Verified for somebody else's API is not verified for this one."""
    with pytest.raises(ActingForError, match="did not verify"):
        acting.verify(caller, idp.token(aud="api://not-carnet"))


# --- assert_identity: the believed address ----------------------------------------


def test_a_known_address_resolves_to_its_person(caller, tom):
    resolved = acting.assert_identity(caller, "tom@acme.com")
    assert resolved.user_id == "u-tom"
    assert resolved.source == "asserted"


def test_an_unknown_address_is_recorded_as_given_with_no_person(caller, isolated_storage):
    """`user_id=None` deliberately, rather than a refusal here: on a `service` tool the
    assertion is only an audit fact, and a `user` tool refuses it at credential time
    with the broker writing both the sentence and the record."""
    resolved = acting.assert_identity(caller, "ghost@acme.com")
    assert resolved.user_id is None
    assert resolved.email == "ghost@acme.com"
    assert resolved.source == "asserted"


def test_a_disabled_person_cannot_be_asserted_either(caller, tom):
    """Different from unknown: "we know nothing about that name" and "we know they
    were turned off" are different answers, and only the second is a decision this
    tenant already made."""
    storage.active().set_user_status(TEST_TENANT, "u-tom", "disabled", actor="system:test")
    with pytest.raises(ActingForError, match="disabled"):
        acting.assert_identity(caller, "tom@acme.com")
