"""Routing a token to a customer, and turning it into somebody.

`test_oidc.py` proves a token is genuine. This proves it belongs to who it says, which
is the different and more dangerous question: a bug in the first is a forged login, a
bug here is one company reading another company's data.

The centre of the file is the shared-issuer set. Okta and Entra give every customer
their own issuer, so routing is a lookup and hard to get wrong. Google Workspace shares
one issuer across every organisation on it, and that is where a design that "works"
against one customer quietly serves the second one the first one's data.
"""

import time

import pytest

pytest.importorskip("jwt", reason="install the 'access' extra to run these")

import jwt  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from carnet import config, storage  # noqa: E402
from carnet.access import oidc, providers, roles, users  # noqa: E402
from carnet.access.oidc import JwksCache, TokenError, TokenExpired  # noqa: E402
from carnet.access.users import AccessDenied  # noqa: E402

ACME = "t-acme"
GLOBEX = "t-globex"

OKTA_ISSUER = "https://acme.okta.example"
GOOGLE_ISSUER = "https://accounts.google.example"

# The one issuer whose `allowed_domains` may be `"*"`. Imported rather than spelled, so a
# test cannot keep passing against a value the guard no longer uses.
LOCAL_ISSUER = storage.LOCAL_ISSUER_WILDCARD_OK


class Provider:
    """A signing identity, standing in for one customer's IdP."""

    def __init__(self, issuer: str, audience: str = "api://default", kid: str = "k1"):
        self.issuer = issuer
        self.audience = audience
        self.kid = kid
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer}/v1/keys"

    def jwk(self) -> dict:
        entry = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        entry.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return entry

    def token(self, **claims) -> str:
        now = int(time.time())
        payload = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": "00u-priya",
            "iat": now,
            "exp": now + 300,
            "email": "priya@acme.com",
        }
        payload.update(claims)
        payload = {k: v for k, v in payload.items() if v is not None}
        return jwt.encode(payload, self.key, algorithm="RS256", headers={"kid": self.kid})

    def row(self, **overrides) -> dict:
        return {
            "issuer": self.issuer,
            "jwks_uri": self.jwks_uri,
            "audience": self.audience,
            "allowed_domains": ("acme.com",),
            **overrides,
        }


@pytest.fixture
def okta():
    return Provider(OKTA_ISSUER)


@pytest.fixture
def local():
    """The local identity provider: the only issuer a wildcard domain is legal on."""
    return Provider(LOCAL_ISSUER, audience=LOCAL_ISSUER)


@pytest.fixture
def google():
    """One signing identity, shared by every customer on it — the real shape."""
    return Provider(GOOGLE_ISSUER, audience="123.apps.googleusercontent.com")


@pytest.fixture
def tenants(isolated_storage):
    store = storage.active()
    store.create_tenant(ACME, "Acme")
    store.create_tenant(GLOBEX, "Globex")
    return store


def cache_for(*provider_objects):
    document = {"keys": [p.jwk() for p in provider_objects]}
    return JwksCache(fetch=lambda uri: oidc.keys_from_jwks(document))


# --- routing ----------------------------------------------------------------------


def test_a_token_routes_to_the_customer_that_registered_its_issuer(tenants, okta):
    tenants.save_tenant_idp(ACME, okta.row())

    provider, claims = providers.resolve(okta.token(), cache_for(okta))

    assert provider["tenant_id"] == ACME
    assert claims["sub"] == "00u-priya"


def test_an_unregistered_issuer_is_refused(tenants, okta):
    with pytest.raises(TokenError, match="no identity provider"):
        providers.resolve(okta.token(), cache_for(okta))


def test_a_disabled_provider_is_refused(tenants, okta):
    tenants.save_tenant_idp(ACME, okta.row(enabled=False))

    with pytest.raises(TokenError, match="no identity provider"):
        providers.resolve(okta.token(), cache_for(okta))


def test_the_tenant_comes_from_our_row_not_from_the_token(tenants, okta):
    """The decision the whole design turns on.

    A provider can be configured to put an organisation id in a claim. If we read it,
    a mis-mapped claim in somebody else's admin console becomes a cross-tenant read
    here — in a setting we cannot see or audit.
    """
    tenants.save_tenant_idp(ACME, okta.row())

    provider, _ = providers.resolve(
        okta.token(tid=GLOBEX, org_id=GLOBEX, tenant=GLOBEX), cache_for(okta)
    )

    assert provider["tenant_id"] == ACME


def test_expiry_survives_routing(tenants, okta):
    """Expired is the one failure a client can act on, so it must not be flattened
    into "invalid" by the candidate loop."""
    tenants.save_tenant_idp(ACME, okta.row())

    with pytest.raises(TokenExpired):
        providers.resolve(okta.token(exp=int(time.time()) - 3600), cache_for(okta))


# --- the shared issuer ------------------------------------------------------------


def test_two_customers_on_one_issuer_are_told_apart(tenants, google):
    """Google Workspace. One issuer, one key, one audience — and two customers.

    Under a design that routes on the issuer alone, the second customer registered
    would read the first one's data."""
    tenants.save_tenant_idp(
        ACME, google.row(discriminator_claim="hd", discriminator_value="acme.com")
    )
    tenants.save_tenant_idp(
        GLOBEX,
        google.row(
            discriminator_claim="hd",
            discriminator_value="globex.com",
            allowed_domains=("globex.com",),
        ),
    )
    cache = cache_for(google)

    acme, _ = providers.resolve(google.token(hd="acme.com"), cache)
    globex, _ = providers.resolve(google.token(hd="globex.com"), cache)

    assert acme["tenant_id"] == ACME
    assert globex["tenant_id"] == GLOBEX


def test_a_shared_issuer_token_with_no_discriminator_is_refused(tenants, google):
    """A real user at a real customer's provider, whose organisation nobody onboarded.
    It must not fall through to whichever row happens to be first."""
    tenants.save_tenant_idp(
        ACME, google.row(discriminator_claim="hd", discriminator_value="acme.com")
    )

    with pytest.raises(TokenError, match="does not identify a registered customer"):
        providers.resolve(google.token(), cache_for(google))


def test_an_unonboarded_organisation_on_a_shared_issuer_is_refused(tenants, google):
    tenants.save_tenant_idp(
        ACME, google.row(discriminator_claim="hd", discriminator_value="acme.com")
    )

    with pytest.raises(TokenError, match="does not identify a registered customer"):
        providers.resolve(google.token(hd="someone-else.com"), cache_for(google))


def test_the_discriminator_is_read_from_verified_claims(tenants, google):
    """A forged token claiming `hd: acme.com` gets nowhere, because it fails the
    signature before the claim is ever consulted."""
    tenants.save_tenant_idp(
        ACME, google.row(discriminator_claim="hd", discriminator_value="acme.com")
    )
    impostor = Provider(GOOGLE_ISSUER, audience=google.audience)

    with pytest.raises(TokenError):
        providers.resolve(impostor.token(hd="acme.com"), cache_for(google))


# --- becoming somebody ------------------------------------------------------------


def test_a_first_login_creates_the_person(tenants, okta):
    tenants.save_tenant_idp(ACME, okta.row())
    provider, claims = providers.resolve(okta.token(), cache_for(okta))

    principal = users.resolve(provider, claims)

    assert principal.kind == "user"
    assert principal.tenant_id == ACME
    assert principal.id.startswith("u_")
    assert len(tenants.list_users(ACME)) == 1
    # Somebody who has logged in exactly once must not read as never seen — that is
    # the row an admin checks when asking whether an account is in use.
    assert tenants.list_users(ACME)[0]["last_seen_at"] is not None


def test_a_second_login_creates_nobody(tenants, okta):
    tenants.save_tenant_idp(ACME, okta.row())
    cache = cache_for(okta)

    first = users.resolve(*providers.resolve(okta.token(), cache))
    second = users.resolve(*providers.resolve(okta.token(), cache))

    assert first.id == second.id
    assert len(tenants.list_users(ACME)) == 1


def test_an_unlisted_domain_creates_nobody(tenants, okta):
    """A registered issuer is not permission to create anyone — only to create people
    who look like they belong to this customer. A contractor or guest in their
    directory is a decision for them to record, not for us to assume."""
    tenants.save_tenant_idp(ACME, okta.row(allowed_domains=("acme.com",)))
    provider, claims = providers.resolve(
        okta.token(email="contractor@elsewhere.example"), cache_for(okta)
    )

    with pytest.raises(AccessDenied, match="not on a domain"):
        users.resolve(provider, claims)

    assert tenants.list_users(ACME) == []


def test_a_provider_with_no_allowed_domains_creates_nobody(tenants, okta):
    """An empty list is not "allow everything"."""
    tenants.save_tenant_idp(ACME, okta.row(allowed_domains=()))
    provider, claims = providers.resolve(okta.token(), cache_for(okta))

    with pytest.raises(AccessDenied, match="no allowed email domains"):
        users.resolve(provider, claims)


def test_a_wildcard_domain_creates_anybody_with_an_address(tenants, local):
    """`"*"` is the explicit opt-in for a provider that is itself the account
    authority — the local identity provider gates who may register, so a domain
    check here would refuse the first teammate on a personal address."""
    tenants.save_tenant_idp(ACME, local.row(allowed_domains=("*",)))
    provider, claims = providers.resolve(
        local.token(email="anyone@somewhere.example"), cache_for(local)
    )

    principal = users.resolve(provider, claims)

    assert principal.tenant_id == ACME
    assert tenants.find_user(LOCAL_ISSUER, "00u-priya")["email"] == "anyone@somewhere.example"


def test_a_wildcard_beside_named_domains_still_admits_any(tenants, local):
    """The wildcard is not order- or neighbour-sensitive; a row that says
    ("acme.com", "*") means any, not acme.com-plus-a-typo."""
    tenants.save_tenant_idp(ACME, local.row(allowed_domains=("acme.com", "*")))
    provider, claims = providers.resolve(
        local.token(email="guest@elsewhere.example"), cache_for(local)
    )

    assert users.resolve(provider, claims).tenant_id == ACME


def test_a_wildcard_still_requires_an_address(tenants, local):
    """The wildcard widens *which* domains may vouch, not *whether* there is an
    address — a row keyed to an empty email is a row no share can ever reach."""
    tenants.save_tenant_idp(ACME, local.row(allowed_domains=("*",)))
    provider, claims = providers.resolve(local.token(email=None), cache_for(local))

    with pytest.raises(AccessDenied, match="no email address"):
        users.resolve(provider, claims)

    assert tenants.list_users(ACME) == []


def test_a_wildcard_is_refused_on_a_customers_provider(tenants, okta):
    """The row 016 made legal for any issuer, and an enterprise premise makes legal for
    exactly one.

    A wildcard on a customer's Okta means *any address that provider will vouch for gets
    an account in this tenant*, which is the domain gate switched off rather than widened
    — the inverse of what 005 built it to say. Refused at the write, so `--add-idp`, the
    local front door and anything registering a provider next all inherit it.
    """
    with pytest.raises(storage.ValueRefused, match="not an allowed email domain"):
        tenants.save_tenant_idp(ACME, okta.row(allowed_domains=("*",)))

    assert tenants.list_tenant_idps(ACME) == []


def test_a_wildcard_beside_named_domains_is_refused_too(tenants, okta):
    """The dangerous half is not lonely. `("acme.com", "*")` reads as a safe list with an
    extra entry and means the same as `("*",)`, which is exactly why it is checked for
    membership rather than for being the only element."""
    with pytest.raises(storage.ValueRefused, match="not an allowed email domain"):
        tenants.save_tenant_idp(ACME, okta.row(allowed_domains=("acme.com", "*")))

    assert tenants.list_tenant_idps(ACME) == []


def test_named_domains_on_a_customers_provider_are_untouched(tenants, okta):
    """The mutation check on the refusal above: it must reject `"*"` and nothing else."""
    tenants.save_tenant_idp(ACME, okta.row(allowed_domains=("acme.com", "acme.co.uk")))

    rows = tenants.list_tenant_idps(ACME)
    assert [r["issuer"] for r in rows] == [OKTA_ISSUER]
    assert set(rows[0]["allowed_domains"]) == {"acme.com", "acme.co.uk"}


def test_a_disabled_account_is_refused(tenants, okta):
    """The only thing that cuts somebody off before their token expires."""
    tenants.save_tenant_idp(ACME, okta.row())
    cache = cache_for(okta)
    principal = users.resolve(*providers.resolve(okta.token(), cache))

    tenants.set_user_status(ACME, principal.id, "disabled", actor="system:test")

    with pytest.raises(AccessDenied, match="disabled"):
        users.resolve(*providers.resolve(okta.token(), cache))


def test_a_suspended_customer_refuses_everybody(tenants, okta):
    """Migration 020. `users.status` cuts off one account; this cuts off the business.

    403 rather than 401, because the token is genuine and signing in again will not
    help — the distinction `deps.py` exists to keep.
    """
    tenants.save_tenant_idp(ACME, okta.row())
    cache = cache_for(okta)
    users.resolve(*providers.resolve(okta.token(), cache))

    tenants.set_tenant_status(ACME, "suspended")

    with pytest.raises(AccessDenied, match="suspended"):
        users.resolve(*providers.resolve(okta.token(), cache))


def test_a_suspended_customer_creates_nobody(tenants, okta):
    """The check is before `find_user` specifically so a first-time login into a
    suspended tenant does not leave a user row behind — the same property
    `test_a_domain_outside_the_allowed_list_creates_nobody` asserts one gate along."""
    tenants.save_tenant_idp(ACME, okta.row())
    tenants.set_tenant_status(ACME, "suspended")

    with pytest.raises(AccessDenied, match="suspended"):
        users.resolve(*providers.resolve(okta.token(), cache_for(okta)))

    assert tenants.list_users(ACME) == []


def test_suspending_one_customer_does_not_touch_another(tenants, okta, google):
    """Two customers, one suspended. The other must not notice."""
    tenants.save_tenant_idp(ACME, okta.row())
    tenants.save_tenant_idp(GLOBEX, google.row())
    tenants.set_tenant_status(ACME, "suspended")

    principal = users.resolve(*providers.resolve(google.token(), cache_for(google)))

    assert principal.tenant_id == GLOBEX


def test_resuming_a_customer_lets_them_back_in(tenants, okta):
    tenants.save_tenant_idp(ACME, okta.row())
    cache = cache_for(okta)
    before = users.resolve(*providers.resolve(okta.token(), cache))

    tenants.set_tenant_status(ACME, "suspended")
    tenants.set_tenant_status(ACME, "active")

    # The same person, not a new row: suspension is a gate, and passing through it
    # again must not mint a second identity for somebody with the same (issuer, subject).
    assert users.resolve(*providers.resolve(okta.token(), cache)).id == before.id


def test_identity_survives_an_email_change(tenants, okta):
    """People marry; companies migrate domains. Keying on email would detach somebody
    from their entire audit history the week it happened."""
    tenants.save_tenant_idp(ACME, okta.row(allowed_domains=("acme.com", "acmegroup.com")))
    cache = cache_for(okta)

    before = users.resolve(*providers.resolve(okta.token(), cache))
    after = users.resolve(
        *providers.resolve(okta.token(email="priya@acmegroup.com"), cache)
    )

    assert before.id == after.id
    assert tenants.find_user(OKTA_ISSUER, "00u-priya")["email"] == "priya@acmegroup.com"


def test_the_email_claim_is_per_provider(tenants, okta):
    """Okta and Google send `email`; Entra frequently sends `preferred_username`."""
    tenants.save_tenant_idp(ACME, okta.row(email_claim="preferred_username"))
    provider, claims = providers.resolve(
        okta.token(email=None, preferred_username="priya@acme.com"), cache_for(okta)
    )

    principal = users.resolve(provider, claims)

    assert tenants.find_user(OKTA_ISSUER, "00u-priya")["email"] == "priya@acme.com"
    assert principal.tenant_id == ACME


def test_the_subject_claim_is_per_provider(tenants, okta):
    """Written from a real Okta access token, not from the spec.

    OIDC says `sub` is the stable identifier, and in an ID token it is. Okta's
    **access** tokens put the user's login in `sub` and the stable id in `uid`:

        sub  priya@example.com
        uid  00u15ycj6pa9ccs2y698

    An API validates access tokens, so trusting `sub` would have keyed identity on an
    email after arguing at length not to — silently, and only noticed the first time
    somebody changed their name.
    """
    tenants.save_tenant_idp(ACME, okta.row(subject_claim="uid"))
    cache = cache_for(okta)

    before = users.resolve(
        *providers.resolve(
            okta.token(sub="priya@acme.com", uid="00u-stable"), cache
        )
    )
    # Their login changes; the stable id does not.
    after = users.resolve(
        *providers.resolve(
            okta.token(sub="priya@acmegroup.com", uid="00u-stable", email="priya@acme.com"),
            cache,
        )
    )

    assert before.id == after.id
    assert len(tenants.list_users(ACME)) == 1


def test_a_token_missing_the_configured_subject_claim_is_refused(tenants, okta):
    tenants.save_tenant_idp(ACME, okta.row(subject_claim="uid"))
    provider, claims = providers.resolve(okta.token(), cache_for(okta))

    with pytest.raises(AccessDenied, match="uid"):
        users.resolve(provider, claims)


def test_subject_defaults_to_sub(tenants, okta):
    """Right for a conformant token, which is what the default should describe."""
    tenants.save_tenant_idp(ACME, okta.row())

    principal = users.resolve(*providers.resolve(okta.token(), cache_for(okta)))

    assert tenants.find_user(OKTA_ISSUER, "00u-priya")["id"] == principal.id


def test_the_principal_id_is_opaque_not_an_email(tenants, okta):
    """It lands in every audit record that person ever produces. An address there
    cannot be removed later — the table is append-only by trigger."""
    tenants.save_tenant_idp(ACME, okta.row())

    principal = users.resolve(*providers.resolve(okta.token(), cache_for(okta)))

    assert "@" not in principal.id
    assert "priya" not in principal.id


def test_two_customers_produce_principals_in_their_own_tenants(tenants, google):
    tenants.save_tenant_idp(
        ACME, google.row(discriminator_claim="hd", discriminator_value="acme.com")
    )
    tenants.save_tenant_idp(
        GLOBEX,
        google.row(
            discriminator_claim="hd",
            discriminator_value="globex.com",
            allowed_domains=("globex.com",),
        ),
    )
    cache = cache_for(google)

    acme = users.resolve(*providers.resolve(google.token(hd="acme.com"), cache))
    globex = users.resolve(
        *providers.resolve(
            google.token(hd="globex.com", sub="00u-bob", email="bob@globex.com"), cache
        )
    )

    assert acme.tenant_id == ACME
    assert globex.tenant_id == GLOBEX
    assert acme.id != globex.id


# --- the first administrator, from configuration (12c) --------------------------------
#
# Decision 1 of plan 012c. 12b made `admin` a row and left granting it on the CLI, which
# left one hole: appointing the *first* administrator needs a shell. These assert the
# window this variable is armed in, and — the half that matters — every case where it is
# not.
#
# Everything here drives `users.resolve` through a real token, because that is where the
# grant happens and a test calling `_bootstrap_admin` directly would prove nothing about
# whether the login path reaches it.


@pytest.fixture
def bootstrap(monkeypatch):
    """Configure `priya@acme.com` as the first administrator, for one test."""

    def configure(email="priya@acme.com"):
        monkeypatch.setattr(config, "BOOTSTRAP_ADMIN_EMAIL", email)

    return configure


def sign_in(provider, **claims):
    return users.resolve(*providers.resolve(provider.token(**claims), cache_for(provider)))


def admins(tenant_id=ACME):
    return [
        (row["principal_kind"], row["principal_id"])
        for row in storage.active().list_platform_roles(tenant_id)
    ]


def test_the_configured_address_becomes_the_first_administrator(
    tenants, okta, bootstrap
):
    """The whole point: no shell after boot, and the log says how it happened."""
    tenants.save_tenant_idp(ACME, okta.row())
    bootstrap()

    priya = sign_in(okta)

    assert admins() == [("user", priya.id)]
    assert roles.is_admin(priya) is True

    (record,) = [r for r in tenants.admin_audit_records(ACME) if r["action"] == "role.grant"]
    assert (record["actor_kind"], record["actor_id"]) == ("system", "bootstrap")
    assert record["target_id"] == priya.id


def test_the_match_is_case_insensitive(tenants, okta, bootstrap):
    """An address is not case-sensitive in its local part in practice, and a variable
    typed by hand is exactly where the difference shows up."""
    tenants.save_tenant_idp(ACME, okta.row())
    bootstrap("PRIYA@Acme.COM")

    priya = sign_in(okta)

    assert admins() == [("user", priya.id)]


def test_nobody_else_is_appointed_by_it(tenants, okta, bootstrap):
    """The second login of the pair the plan's verification names. Sam signs in, the
    table is still empty, and he is not the configured address — so nothing happens."""
    tenants.save_tenant_idp(ACME, okta.row())
    bootstrap()

    sign_in(okta, sub="00u-sam", email="sam@acme.com")

    assert admins() == []


def test_it_is_inert_once_anybody_holds_a_role(tenants, okta, bootstrap):
    """**The empty-table condition, which is the safety property.**

    Somebody else is appointed first — by the CLI, as a real deployment would — and the
    configured address then signs in and is *not* also appointed. The variable answers
    "who is first", and somebody already is.
    """
    tenants.save_tenant_idp(ACME, okta.row())
    tenants.grant_platform_role(ACME, "user", "u_someone_else", "admin", actor="system:cli")
    bootstrap()

    priya = sign_in(okta)

    assert admins() == [("user", "u_someone_else")]
    assert roles.is_admin(priya) is False


def test_a_revoke_is_not_resurrected_while_another_administrator_remains(
    tenants, okta, bootstrap
):
    """Verification 4's middle clause, and it is worth being exact about its edge.

    Revoking one of two administrators leaves the table non-empty, so the next login of
    the configured address changes nothing — which is the case somebody actually hits.

    What this does **not** claim is that the variable remembers a grant ever happened. It
    does not: see `test_revoking_the_only_administrator_re_arms_the_variable` below, which
    pins the other side rather than leaving it to be discovered.
    """
    tenants.save_tenant_idp(ACME, okta.row())
    bootstrap()

    priya = sign_in(okta)
    tenants.grant_platform_role(ACME, "user", "u_colleague", "admin", actor="system:cli")
    tenants.revoke_platform_role(ACME, "user", priya.id, "admin", actor="system:cli")

    assert sign_in(okta).id == priya.id
    assert admins() == [("user", "u_colleague")]


def test_revoking_the_only_administrator_re_arms_the_variable(tenants, okta, bootstrap):
    """**Pinned rather than promised**, because it is the surprising half of decision 1.

    The condition is *the table is empty*, not *no grant has ever happened*, so revoking
    the last administrator arms the variable again and the configured address is
    re-appointed at their next login. On a deployment still being set up that is a
    recovery path; on one where the revocation was meant, it is a surprise — and the
    remedy is to unset the variable, which the multi-tenant note already asks for.

    Asserted so that a future change to this behaviour is a decision somebody makes rather
    than a test they did not know existed.
    """
    tenants.save_tenant_idp(ACME, okta.row())
    bootstrap()

    priya = sign_in(okta)
    tenants.revoke_platform_role(ACME, "user", priya.id, "admin", actor="system:cli")
    assert admins() == []

    sign_in(okta)

    assert admins() == [("user", priya.id)]


def test_an_unset_variable_appoints_nobody(tenants, okta):
    """The default, and the state every deployment ends in."""
    tenants.save_tenant_idp(ACME, okta.row())

    sign_in(okta)

    assert admins() == []


def test_a_second_tenant_is_untouched_unless_its_own_table_is_empty(
    tenants, okta, google, bootstrap
):
    """Per-tenant emptiness, which is what makes this usable on a multi-tenant
    deployment during onboarding — and what makes it something to unset afterwards.

    The same address at two customers is two different people to this system: identity is
    `(issuer, subject)`, so these are two rows, two principals and two independent
    empty-table questions.
    """
    tenants.save_tenant_idp(ACME, okta.row())
    tenants.save_tenant_idp(
        GLOBEX, google.row(allowed_domains=("acme.com",), hd="globex")
    )
    tenants.grant_platform_role(GLOBEX, "user", "u_globex_admin", "admin", actor="system:cli")
    bootstrap()

    acme_priya = sign_in(okta)
    globex_priya = sign_in(google, hd="globex")

    assert admins(ACME) == [("user", acme_priya.id)]
    assert admins(GLOBEX) == [("user", "u_globex_admin")]
    assert roles.is_admin(globex_priya) is False


def test_a_failed_appointment_does_not_fail_the_login(
    tenants, okta, bootstrap, monkeypatch, caplog
):
    """A side effect of signing in must not become a reason not to.

    Somebody who signs in without the role is told by the next screen that they are not an
    administrator, which is a state this product renders properly. Somebody who cannot
    sign in at all because a role grant failed is strictly worse off, and would have no
    way to find out why.
    """
    tenants.save_tenant_idp(ACME, okta.row())
    bootstrap()
    monkeypatch.setattr(
        roles, "grant", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    )

    principal = sign_in(okta)

    assert principal.kind == "user"
    assert admins() == []
    assert "first administrator" in caplog.text
