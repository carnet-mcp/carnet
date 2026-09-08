"""From verified claims to a `Principal`.

The last step: a token has been proved genuine and routed to a customer, and this turns
it into the thing the rest of the runtime already understands. Nothing below here
changes — `Principal` is the same frozen dataclass the CLI has been constructing since
step 001, and the broker, the audit log, the credential lookup and the permission check
all take it as they always have.

That was the bet made when `Principal.user()` was written with nothing able to produce
one. This module is where it pays.

## People are created on first login; customers are not

An earlier draft of the plan refused anyone not already in the database. That is right
about customers and wrong about people — it would mean IT filing a ticket for every new
hire, which is the friction SSO exists to remove.

    a tenant   created by hand, during onboarding      a business event
    a user     created on first successful login       their employer already vouched

Just-in-time creation is only safe because of the two gates around it, and both are
checked here:

  - the **issuer must already be registered**, which `providers.resolve` guarantees
  - the **email domain must be on that customer's allowed list**

A token from a provider nobody registered creates nothing. A token from a registered
provider bearing an unrecognised domain creates nothing either — that is a contractor
or a guest account in the customer's directory, and whether they get access is the
customer's decision to record, not ours to assume.

## Identity is (issuer, subject), and the audit log pays for it

The subject is stable for the life of an account; emails are not. Keying on email means
somebody's history detaches from them the week they marry or their company migrates
domains.

So `Principal.id` is our own opaque identifier, and the audit log reads `user:u_8f2c1a`
rather than `user:priya@acme.com`. That is worse to read and better in two ways: it
stays correct, and it is the version that can survive a request to be forgotten, since
the audit table is append-only by trigger and cannot have an address edited out of it.
"""

import logging
import uuid

from .. import config, storage
from ..core import Principal
from ..storage import StorageError

log = logging.getLogger(__name__)


class AccessDenied(RuntimeError):
    """A genuine token belonging to somebody who may not use this.

    Distinct from `TokenError`, which means the token itself is not good. This one is
    a 403 where that is a 401, and the difference is real: one says "authenticate
    again", the other says "authenticating again will not help".
    """


def profile(principal: Principal) -> dict:
    """What this product knows about a principal by name. `{}` when it knows nothing.

    **Our `users` row, deliberately, and not the token's claims.** Not because the row is
    fresher — `resolve` refreshes it from the claims on every request, so they agree — but
    because **which claim holds the address is per provider**. `email_claim` is a column
    for the reason migration 010 gives: it exists because of a real token rather than a
    spec, and Entra frequently uses `preferred_username` or `upn`. A caller reading
    `claims["email"]` would report nothing for those customers while every other screen
    named the person correctly, and `_email(provider, claims)` has already done that work
    by the time a row exists.

    `{}` rather than a raise for a principal with no row. `system` principals have none by
    construction — they are not people and never logged in — and `GET /me` can describe
    one perfectly well without an email. A function that raised here would make the
    absence of a name an error instead of a fact.
    """
    if principal.kind != "user":
        return {}
    return storage.active().get_user(principal.tenant_id, principal.id) or {}


def new_user_id() -> str:
    """Opaque, never derived from anything that can change. `uuid4` rather than a
    counter so ids are not guessable and never recycled — this becomes `Principal.id`
    and lands in every audit record that person ever produces. One function since 071,
    because a SCIM push creates people too and both must mint the same shape."""
    return f"u_{uuid.uuid4().hex[:16]}"


class UserRefused(RuntimeError):
    """A request about a person that names nobody, or asks the impossible."""


def set_active(
    principal: Principal, user_id: str, active: bool, *, cause: str = ""
) -> dict:
    """Cut somebody off, or let them back in. Step 071, decision 1 — **the seam.**

    `storage.set_user_status` has existed since migration 008 as *"the only thing that
    cuts somebody off immediately"* and until this step nothing called it: not the CLI,
    not the API, not `access/`. This is its first caller, and the three surfaces that
    may offboard somebody — `--disable-user`, and nothing else — come through here so
    they do the same thing and record it the same way.

    **What stops, and what stays.** Everything that acts *as* the person stops; nothing
    the person *made* is deleted. Signing in (008), their API tokens (020) and acting
    for them (041) all stop by re-reading this row, so a door call under a token they
    own is refused at the next call. Agents, grants, memberships and connections are
    left exactly as they are; the plan says why for each.

    Enabling reverses the status and nothing else.
    """
    store = storage.active()
    status = "active" if active else "disabled"
    detail: dict = {"cause": cause} if cause else {}

    row = store.set_user_status(
        principal.tenant_id, user_id, status, actor=str(principal), detail=detail
    )
    if row is None:
        raise UserRefused(
            f"there is no user '{user_id}' in tenant '{principal.tenant_id}'. "
            "--list-users shows who there is."
        )

    log.info(
        "%s %s in tenant %s (%s)",
        "disabled" if not active else "enabled",
        user_id,
        principal.tenant_id,
        principal,
    )
    return row


def resolve(provider: dict, claims: dict) -> Principal:
    """The principal these verified claims describe, creating them if permitted."""
    issuer = provider["issuer"]

    # Not necessarily `sub`. OIDC says the subject is the stable identifier, and it is
    # — in an ID token. Okta's **access** tokens put the user's login there and the
    # stable id in `uid`, so following the spec would have keyed identity on an email
    # after all. See migration 010; this is the same shape as `email_claim`.
    subject = claims.get(provider["subject_claim"])
    if not subject:
        raise AccessDenied(
            f"token carries no '{provider['subject_claim']}' claim, so it identifies "
            "nobody stably"
        )

    store = storage.active()

    # Before `find_user`, and specifically before `_first_time` can create anybody: a
    # suspended customer must not gain a user row from a login it is about to refuse.
    require_active_tenant(store, provider["tenant_id"])

    existing = store.find_user(issuer, subject)

    if existing is not None:
        principal = _returning(store, provider, existing, claims)
    else:
        principal = _first_time(store, provider, subject, claims)

    # After both paths rather than inside either, because the question it asks is about
    # the *tenant* rather than about whether this person is new. A deployment that sets
    # the variable after somebody has already logged in once — which is the ordinary case,
    # since you find out you need it by being unable to administer anything — must still
    # be able to appoint them.
    _bootstrap_admin(store, principal, _email(provider, claims))

    # Step 033e, and after both paths for `_bootstrap_admin`'s reason exactly: what it
    # asks about is the **token**, not whether this person is new. `existing` is the row
    # as it stood before this request — the marker columns are read from it, and None
    # means somebody created a moment ago, who has never been reconciled and therefore
    # lands in their directory's groups before this request returns.
    #
    # Imported here rather than at module scope: `directory` reaches `groups`, which
    # reaches `roles`, and `access/__init__` imports this module first — the same cycle
    # `_claim` documents one function down.
    from . import directory

    directory.reconcile(principal, provider, claims, existing)

    return principal


def require_active_tenant(store, tenant_id: str) -> None:
    """Refuse everybody in a suspended customer. Migration 020.

    **Public, and shared with `access/tokens.py` since step 020.** Migration 020's header
    names the two doors work arrives through — authentication and the claim loop — and a
    machine caller is a third that did not exist when that was written. Called from both
    rather than written twice, so the sentence a suspended customer's machine gets is the
    same one their staff get, which `test_the_suspension_sentence_is_one_sentence`
    asserts by equality rather than by two authors being careful.

    One extra round trip on the authentication path, and it is bought rather than
    saved. The alternative is joining `tenants` into the provider lookup, which would
    make `find_tenant_idps` carry a field only this caller wants and put the tenant's
    status behind a function named for identity providers. This is a primary-key read
    of a table with one row per customer, on a path that already makes three.

    403 rather than 401, via `AccessDenied`: the token is genuine and authenticating
    again will not help, which is exactly the distinction `deps.py` documents.
    """
    tenant = store.get_tenant(tenant_id)

    if tenant is None:
        # Should be impossible — `tenant_idps.tenant_id` is a foreign key — so this is
        # the same shape as the tenant-mismatch check below: loud, because if it ever
        # happens the alternative is serving somebody whose customer does not exist.
        log.error("provider routes to tenant %s, which has no row", tenant_id)
        raise AccessDenied("this account's customer does not exist")

    if tenant["status"] != "active":
        # Says suspended rather than naming the state, because the person reading it
        # takes it to their admin and 'suspended' is the word that admin was given.
        raise AccessDenied(
            f"customer '{tenant_id}' is suspended, so nobody in it may sign in"
        )


# The actor recorded against a bootstrap grant. A `system` principal, because that is
# what performed it — no person clicked anything — and a distinct id from `system:cli`
# because *how* the first administrator was appointed is the one thing somebody auditing
# this row will want to know. It is the deployment's own configuration acting, and the
# log says so in a word.
BOOTSTRAP_ACTOR = "bootstrap"

# The actor on a `user.adopt` record: the directory's own sign-in bound a provisioned
# row to a subject. `access/directory.py`'s `DIRECTORY_ACTOR`, spelled here rather than
# imported, because that module imports this one first.
_ADOPTION_ACTOR = "directory"


def _bootstrap_admin(store, principal: Principal, email: str) -> None:
    """Appoint the first administrator, if this login is the one configured to be it.

    Decision 1 of plan 012c, and the whole of it is three conditions in a deliberate
    order — cheapest first, because this runs on **every authenticated request** and not
    only on a first login:

        1. the variable is set                     a module attribute read
        2. it matches this login's email           a string comparison, case-insensitive
        3. this tenant has no platform roles       one indexed query, and only here

    Every login that is not this address pays 1 and 2 and stops. The address itself pays
    3 as well, until somebody is appointed.

    **The empty-table condition is the whole safety property**, and it is worth being
    exact about what it does and does not promise. It disarms the variable the moment
    anybody holds a role, by any means — a CLI grant, or this. What it does *not* do is
    remember that a grant once happened: revoke the only administrator a tenant has and
    the table is empty again, so the configured address is re-appointed at their next
    login. That is a recovery path on a deployment that still wants one, and a surprise on
    a deployment that meant the revocation. It is the behaviour rather than an oversight;
    unset the variable once a tenant is running, which is what the multi-tenant note in
    `config.BOOTSTRAP_ADMIN_EMAIL` already asks for.

    **Not atomic, deliberately.** Two concurrent first logins both pass the empty-table
    check; `grant_platform_role` is an upsert, so the outcome is one row and possibly two
    identical records in the log. A lock on the login path costs every request in the
    product to deduplicate one line in an audit trail on one day of a deployment's life.

    Failures are logged and swallowed. This is a side effect of signing in, and a person
    who cannot sign in at all because a role grant failed is strictly worse off than one
    who signs in without the role and is told by the next screen that they are not an
    administrator — which is a state the product already renders properly.
    """
    from . import roles

    wanted = config.BOOTSTRAP_ADMIN_EMAIL
    if not wanted:
        return
    if email.strip().lower() != wanted.strip().lower():
        return

    if store.list_platform_roles(principal.tenant_id):
        return

    # Through `roles.grant` rather than around it, so the bootstrap writes the same row,
    # the same `granted_by` and the same administrative record that `--grant-role` does —
    # and so it inherits the tenant check. The actor is a `system` principal, which
    # `roles.is_admin` treats as always an administrator; that is the same root of trust
    # the CLI has, which is exactly what this variable is.
    actor = Principal.system(BOOTSTRAP_ACTOR, principal.tenant_id)
    try:
        roles.grant(actor, principal)
    except Exception:  # noqa: BLE001 - a failed appointment must not fail a login
        log.exception(
            "could not appoint %s as the first administrator of tenant %s",
            principal.id,
            principal.tenant_id,
        )
        return

    log.info(
        "appointed %s as the first administrator of tenant %s, from "
        "CARNET_BOOTSTRAP_ADMIN",
        principal.id,
        principal.tenant_id,
    )


def _claim(principal: Principal, email: str) -> None:
    """Pick up any grants addressed to this person's email before they existed.

    Deliberately not on every request. This is an indexed query against a table that is
    almost always empty for a given address, and the case it catches — a share that
    arrived before its recipient did — can only become true at two moments: the login
    that creates somebody, and a login where their address has changed. Running it on
    every authenticated call would put a write path in front of every read.

    Imported here rather than at module scope: `grants` reads storage and `users` is
    imported by `access/__init__` before it, so a top-level import is a cycle.
    """
    from . import grants

    grants.claim_for(principal, email)


def _returning(store, provider: dict, user: dict, claims: dict) -> Principal:
    if user["status"] != "active":
        # The only thing that cuts somebody off before their token expires. There is
        # no directory sync and no token introspection, so this is it.
        raise AccessDenied(f"account '{user['id']}' is disabled")

    if user["tenant_id"] != provider["tenant_id"]:
        # Should be impossible: `(issuer, subject)` is globally unique and the issuer
        # decided the tenant. Checked because if it ever happens it is a cross-tenant
        # read, and a loud refusal beats serving the wrong customer's data.
        log.error(
            "user %s is in tenant %s but its issuer now routes to %s",
            user["id"],
            user["tenant_id"],
            provider["tenant_id"],
        )
        raise AccessDenied("this account's customer does not match its provider")

    email = _email(provider, claims)
    changed = email.strip().lower() != (user["email"] or "").strip().lower()

    store.record_user_login(user["id"], email, _display_name(claims))
    principal = Principal.user(user["id"], user["tenant_id"])

    if changed:
        # Their address moved — married, a domain migration, a corrected typo — and a
        # share may have been sitting against the new one. `record_user_login` has just
        # overwritten the old value, so this is the last moment the change is knowable.
        #
        # Note what does NOT happen: their identity is `(issuer, subject)` and did not
        # move, so every grant and every audit record they already had stays theirs.
        # This only picks up what was waiting on the new address.
        _claim(principal, email)

    return principal


def _first_time(store, provider: dict, subject: str, claims: dict) -> Principal:
    """Create somebody, if their customer's provider is allowed to vouch for them."""
    email = _email(provider, claims)

    # **Step 071: a row the directory pushed before this person ever signed in.** Same
    # tenant, same issuer, no subject yet, and an address equal to the one this token —
    # signed by that same directory — carries. Adopted by writing the subject, once
    # (compare-and-set on `subject IS NULL`), so from here on they are found by
    # `(issuer, subject)` like everybody else and this branch is never taken again.
    #
    # Before the domain gate, not after. The gate asks whether this provider may
    # *create* somebody; a provisioned row is the customer having already decided that,
    # in their own directory's console, which is a stronger vouching than a domain list.
    # And a *disabled* provisioned row is adopted too, on purpose: somebody deprovisioned
    # before their first sign-in must land on the refusal below, not on a fresh, active,
    # second account.
    if email:
        waiting = store.find_provisioned_user(provider["tenant_id"], provider["issuer"], email)
        if waiting is not None and store.adopt_user_subject(
            provider["tenant_id"],
            waiting["id"],
            subject,
            actor=f"system:{_ADOPTION_ACTOR}",
        ):
            log.info(
                "adopted provisioned user %s for %s at %s", waiting["id"], email, provider["issuer"]
            )
            adopted = store.find_user(provider["issuer"], subject)
            if adopted is not None:
                return _returning(store, provider, adopted, claims)

    allowed = tuple(provider["allowed_domains"] or ())

    if not allowed:
        # An empty list is not "allow everything". A provider registered without one
        # can authenticate people who already exist and create nobody — which is the
        # safe reading, and the CLI says so when registering.
        raise AccessDenied(
            "this identity provider has no allowed email domains, so nobody is "
            "created automatically. Add one, or create the account explicitly."
        )

    domain = email.rpartition("@")[2].lower()
    if "*" in allowed:
        # An explicit wildcard, and only an explicit one — the empty case above keeps
        # its safe reading. This exists for a provider that is itself the account
        # authority (the local identity provider gates who may register; a domain
        # check here would refuse the first teammate on a personal address).
        #
        # **Which rows may carry it is not decided here.** 016 wrote this branch
        # provider-agnostically — *a row is data, and the CLI warns* — and that reading
        # made `--add-idp --domain '*'` legal against a customer's Okta, where a wildcard
        # is the domain gate switched off rather than widened. The refusal now lives at
        # the write, in `storage.check_allowed_domains`, so this branch can trust that a
        # row carrying `"*"` is the one issuer entitled to it. Read time stays permissive
        # on purpose: a rule enforced at both ends is a rule with two opinions the day
        # they disagree.
        #
        # An account still needs an address to be created — a wildcard widens *which*
        # domains may vouch, not *whether* there is one.
        if not domain:
            raise AccessDenied(
                "this token carries no email address, so no account can be created."
            )
    elif not domain or domain not in {d.lower() for d in allowed}:
        log.info("refusing to create a user for domain %r at %s", domain, provider["issuer"])
        raise AccessDenied(
            f"'{email or 'this account'}' is not on a domain this provider may vouch "
            "for. A contractor or guest account needs to be granted access explicitly."
        )

    user_id = new_user_id()

    try:
        store.create_user(
            provider["tenant_id"],
            {
                "id": user_id,
                "issuer": provider["issuer"],
                "subject": subject,
                "email": email,
                "display_name": _display_name(claims),
            },
        )
    except StorageError:
        # Somebody else created them between our lookup and our insert.
        #
        # This is not a rare case: a UI that opens two panels, a refresh, or a retry
        # all send a person's *first* two requests at once, and every one of those
        # threads sees no user and tries to create one. Twelve concurrent first
        # logins against Postgres produced eleven failures before this existed —
        # each surfacing as a 503 on somebody's very first visit.
        #
        # The unique constraint on (issuer, subject) is the arbiter and it has just
        # spoken, so the answer is to re-read rather than to fail. A lock would not
        # help: the racing threads may be in different processes.
        existing = store.find_user(provider["issuer"], subject)
        if existing is None:
            # Not a conflict — a genuinely bad write. Let it through.
            raise
        log.info("lost a first-login race for %s; using the row that won", existing["id"])
        return _returning(store, provider, existing, claims)
    # Stamped on creation too, not only on return visits. Otherwise somebody who has
    # logged in exactly once reads as `last_seen: never`, which is the opposite of
    # true and is the row an admin looks at when asking whether an account is in use.
    store.record_user_login(user_id, email, _display_name(claims))

    log.info(
        "created %s for %s in tenant %s", user_id, email, provider["tenant_id"]
    )
    principal = Principal.user(user_id, provider["tenant_id"])

    # The moment this whole chunk exists for: somebody was shared an agent by address
    # before they had ever logged in, and this is the first instant there is a principal
    # to attach it to.
    _claim(principal, email)
    return principal


def _email(provider: dict, claims: dict) -> str:
    """Whichever claim this provider puts the email in.

    Okta and Google use `email`; Entra frequently uses `preferred_username` or `upn`.
    Hardcoding one would be a provider-specific assumption in the module that exists to
    work with any of them.
    """
    return str(claims.get(provider["email_claim"]) or "")


def _display_name(claims: dict) -> str:
    return str(claims.get("name") or "")
