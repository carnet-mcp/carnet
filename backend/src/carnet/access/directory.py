"""What the customer's directory says a person's groups are.

Step 033e, decision 6 of plan 033. A group is only a bulk-sharing story — *share with
**eng**, not with forty people* — if `eng` is not a list somebody maintains by hand
beside Entra. Until this module, it was one: `--group-add` was the only way in, so every
joiner needed a second manual step that went stale silently, which is the first thing an
enterprise notices and the cheapest 90% of SCIM.

What arrives here is a **verified** claim set (`providers.resolve` has already proved the
token and chosen the customer) and what leaves is membership rows equal to it:

    present in the claim   → a member of the group carrying that `external_id`
    absent from the claim  → not a member of it

...for groups carrying an `external_id`, and **only** those. A group an admin made by
hand is never added to or removed from here, so the two sources of membership cannot
fight. An unmatched claim value creates nothing: a directory that could mint groups would
be a directory that defines this customer's grant targets, which inverts who approves
what.

## What this module refuses to guess

Three of its four decisions are refusals, and each is a silent mass-revocation avoided.

**Absence is not emptiness when the provider says so.** Entra omits the groups claim
entirely when somebody is in more groups than a token may carry, and points at Graph with
`_claim_names` / `_claim_sources` instead. Read naively that token says *this person is in
no groups*, and the obvious implementation removes them from everything — a mass
revocation caused by somebody joining a group. So an absence *with* those markers is
refused and logged; an absence without them is an ordinary empty membership, because Okta
and Entra both omit the claim for somebody in no matched group and treating that as
unknown would make the removal half of this feature unreachable.

**The claim is taken whole or not at all.** Every partial reading of it is a removal, so
there is no truncation anywhere: too many values, one too long, or an entry that is not a
string, and nothing is reconciled at all. The bounds are ours because the values are a
customer's directory's rather than ours — the same reasoning that bounds `_meta` at the
door, one door over.

**A value is matched byte for byte.** Migration 007's rule about the issuer, one column
across: *"that is how the token will arrive and normalising it here would be this layer
guessing."* Entra emits object ids and Okta emits names; case-folding them would let two
distinct directory groups collide into one. Whitespace is stripped where an `external_id`
is *written*, so a value pasted out of a console still matches.

## Why it does not run on every request

`users.resolve` runs on **every authenticated request**, while the claim set it reads is
constant for the life of a token. So `users.directory_digest` records the claim set
already reconciled, and this module does nothing at all — no query, no write, no log line
— until that changes. See migration 043: it is not a cache of an access answer (what a
person may run is still read live, in one statement) but a record of work already done for
one exact input, and every write that changes the *other* input clears it.

## Whose name is on the writes

`system:directory`, on `BOOTSTRAP_ACTOR`'s precedent one function over: a side effect of
signing in, performed by the deployment's own configuration rather than by a person, and
the log should say so in a word. It cannot be the person signing in — the log would read
as though they had added themselves — and it cannot be a machine at all, because
`split_actor` refuses one and the record shares the membership write's transaction, so a
badly chosen actor is not a bad log line but a failed write.
"""

import hashlib
import json
import logging
from datetime import datetime, timezone

from .. import storage
from ..core import Principal
from ..storage.base import EXTERNAL_ID_MAX

log = logging.getLogger(__name__)

# The actor on every row and record this module writes. Distinct from `system:cli` for
# `BOOTSTRAP_ACTOR`'s reason: *how* somebody came to be in a group is the one thing an
# admin reading the row will want to know, and "the directory did it, at 09:12" is the
# answer.
DIRECTORY_ACTOR = "directory"

# Entra's own JWT limit, so a token above it is a misconfiguration this product can name
# rather than a shape it should try to serve. Refused whole — never truncated, because
# truncation is a removal wearing the clothes of a partial success.
DIRECTORY_GROUPS_MAX = 200

# Long enough for a GUID, a distinguished name, or a human group name with room to spare.
# **The storage layer's constant**, imported rather than repeated: the same number has to
# bound what a claim may carry and what an `external_id` may be, or a group is linked to
# a value no token could ever match.
DIRECTORY_GROUP_ID_MAX = EXTERNAL_ID_MAX

# How many unmatched values one log line carries. The line exists so an admin can see
# what their directory is offering that nobody has mapped; it is not a place to dump a
# directory.
UNMATCHED_LOGGED = 20


class ClaimRefused(Exception):
    """This claim cannot be read as a membership, so nothing is reconciled.

    Internal to this module and never raised at a caller: `reconcile` catches it, logs
    what was wrong, and leaves every row exactly as it was. A person's ability to sign in
    does not depend on their directory being configured sensibly.
    """


def reconcile(principal: Principal, provider: dict, claims: dict, user: dict | None) -> None:
    """Make this person's directory-backed memberships equal their groups claim.

    `user` is the stored row — the marker columns are read from it — or None for
    somebody created by this very request, who has never been reconciled.

    Does nothing, cheaply, when the provider has no `groups_claim`, when the claim set
    is the one already reconciled, or when the token is older than the one that
    reconciled it. Never raises: a failure here is logged and swallowed, because
    somebody who cannot sign in at all because a group write failed is strictly worse off
    than somebody who signs in and is reconciled at their next request — which is
    guaranteed, since the marker is written only after a reconciliation fully succeeds.
    """
    claim = provider.get("groups_claim")
    if not claim:
        return

    # **Everything after this point is inside the try**, and the edge-case pass is why:
    # the promise above is *never raises*, and it was being kept by three functions that
    # happened not to. One of them did — a lone surrogate in a claim value (which
    # `json.loads` accepts and UTF-8 cannot encode) came out of `_digest` as a
    # `UnicodeEncodeError`, past `users.resolve`, past `deps.py`'s three expected
    # exception types, and became a **500 on every request that person made** for as
    # long as the value stood in their directory. A promise this shape has to be
    # structural rather than a property of the functions under it.
    try:
        _reconcile(principal, claim, claims, user, provider["issuer"])
    except Exception:  # noqa: BLE001 - a failed reconciliation must not fail a login
        log.exception(
            "could not reconcile directory groups for %s in tenant %s",
            principal.id,
            principal.tenant_id,
        )


def _reconcile(
    principal: Principal, claim: str, claims: dict, user: dict | None, issuer: str
) -> None:
    """The decisions, with the caller holding the safety net."""
    store = storage.active()

    if user is None:
        # Somebody created by this very request — or, rarely, somebody whose creation
        # lost the first-login race, whose row therefore already carries markers that
        # `users.resolve`'s local `existing` cannot see. One primary-key read on the
        # create path only, so both guards below are asked the same question in both
        # cases rather than skipped in one of them.
        user = store.get_user(principal.tenant_id, principal.id)

    previous = (user or {}).get("directory_digest")

    try:
        values = _values(claims, claim)
    except ClaimRefused as refusal:
        # **Marked, not just logged.** Entra's group overage is a *steady state* for a
        # large directory, not a transient, so a refusal that logged on every request
        # would put tens of thousands of ERROR lines a day in front of the one that
        # matters. The marker is the same device the happy path uses — this exact input
        # has been dealt with — so the line arrives once per claim set, and the moment
        # the provider is fixed the input changes and it is read again.
        digest = _refusal_digest(claim, refusal)
        if previous != digest:
            log.error(
                "not reconciling directory groups for %s in tenant %s: %s",
                principal.id,
                principal.tenant_id,
                refusal,
            )
            store.record_directory_sync(
                principal.tenant_id,
                principal.id,
                digest,
                # Nothing was applied, so the ordering stamp stays whatever the last
                # *applied* token left. A refusal must not make a newer token look
                # older than one whose claims were never read.
                (user or {}).get("directory_synced_at"),
                expect=previous,
            )
        return

    digest = _digest(claim, values)
    if previous == digest:
        return

    # **Step 071, decision 5: one writer per issuer, and the push wins.** While the
    # customer holds a live SCIM token for this issuer, membership is the directory's to
    # push and this pull does nothing — two writers with one seam and different
    # opinions would have every sign-in undo what every push added. After the digest
    # check, so it costs one read per *changed* claim set rather than one per request.
    # Nothing is marked: revoke the token and the next sign-in reconciles as before.
    if store.tenant_has_live_scim_token(principal.tenant_id, issuer):
        return

    minted = _issued_at(claims)
    if _is_stale(user, minted):
        # An older token must not rewrite a newer token's answer. Without this a person
        # holding two live tokens — a tab that has not renewed, and a fresh sign-in —
        # watches their access oscillate with nothing to blame.
        return

    _apply(principal, values, digest, minted, previous)


def _apply(
    principal: Principal,
    values: frozenset,
    digest: str,
    minted: datetime | None,
    previous: str | None,
) -> None:
    """The writes, through the seams that already own them. Caller handles failure.

    Through `access/groups.py` rather than around it, on `_bootstrap_admin`'s argument
    for granting through `roles.grant`: the idempotence, the refusals and the
    `group.member.add` / `group.member.remove` records are the ones that already exist,
    which is also why saying the same thing twice writes nothing twice.
    """
    from . import groups

    store = storage.active()
    rows = store.directory_groups(principal.tenant_id, principal.id)
    actor = Principal.system(DIRECTORY_ACTOR, principal.tenant_id)

    # **Removals first, and that ordering is a control rather than a preference.** Each
    # seam write is its own transaction, so a failure part-way leaves the person in
    # whatever has been applied so far. Adding first would leave them holding *more*
    # access than the directory says for as long as it takes to retry; removing first
    # can only ever leave them holding less. Fail-closed, in the one place this
    # module's writes are not atomic.
    changes = [
        (row["group_id"], row["external_id"] in values)
        for row in rows
        if (row["external_id"] in values) != row["member"]
    ]
    for group_id, wanted in sorted(changes, key=lambda change: change[1]):
        if wanted:
            groups.add_member(
                actor, group_id, "user", principal.id, from_directory=True
            )
        else:
            groups.remove_member(
                actor, group_id, "user", principal.id, from_directory=True
            )
    changed = len(changes)

    unmatched = sorted(values - {row["external_id"] for row in rows})
    if unmatched:
        # Once per claim set rather than once per request, which is the digest's doing
        # and the reason this line is readable at all. A person in only unmapped groups
        # produces no membership change, so this is the only thing that says their
        # directory is offering something nobody has created a group for.
        log.info(
            "tenant %s: %d directory group(s) named by %s match no group here: %s",
            principal.tenant_id,
            len(unmatched),
            principal.id,
            ", ".join(unmatched[:UNMATCHED_LOGGED]),
        )

    if changed:
        log.info(
            "reconciled %d directory group membership(s) for %s in tenant %s",
            changed,
            principal.id,
            principal.tenant_id,
        )

    # Last, and only on the way out: a marker written before the writes would remember a
    # partial reconciliation as a finished one.
    #
    # `expect` makes it a compare-and-set, which is what keeps the marker from
    # outliving the input it was computed against. An admin who links a group *while*
    # this reconciliation is in flight clears the markers; without the check this write
    # would immediately put one back — computed against the group set as it stood
    # before the link — and the person would never reconcile again, because the digest
    # covers the claim and the claim may never change. Losing the race here means the
    # work runs once more at the next request, which is the right way to lose it.
    store.record_directory_sync(
        principal.tenant_id, principal.id, digest, minted, expect=previous
    )


def _values(claims: dict, claim: str) -> frozenset:
    """The claim, read as a set of directory ids, or `ClaimRefused`.

    An absent claim is an empty membership **unless** the token says the claim was
    withheld — see the module docstring for the Entra overage this tells apart.

    **A claim present as JSON `null` is read as an absent one**, which is the reading
    that keeps the removal half reachable: some providers (a hand-written Keycloak or
    ADFS mapper, an Auth0 rule) emit `null` where Okta and Entra emit nothing, and both
    mean *this person is in none of them*. It runs the withheld check first, so a
    provider that nulls the claim **and** names it in `_claim_names` is still refused
    rather than read as a mass removal.
    """
    raw = claims.get(claim)

    if claim not in claims or raw is None:
        _refuse_if_withheld(claims, claim)
        return frozenset()

    # A bare string is one value. Deliberately never split on a separator: a group named
    # `Data Science` is one group, and splitting would place somebody in two that do not
    # exist.
    if isinstance(raw, str):
        raw = [raw]

    if not isinstance(raw, (list, tuple)):
        raise ClaimRefused(
            f"claim '{claim}' is a {type(raw).__name__}, and a membership is a list of "
            "strings (or one string)"
        )

    if len(raw) > DIRECTORY_GROUPS_MAX:
        raise ClaimRefused(
            f"claim '{claim}' carries {len(raw)} values, over the {DIRECTORY_GROUPS_MAX} "
            "this reads. Nothing is truncated, because a partial membership is a "
            "removal: filter the claim at the provider so it carries the groups this "
            "application cares about"
        )

    out = set()
    for entry in raw:
        if not isinstance(entry, str):
            raise ClaimRefused(
                f"claim '{claim}' contains a {type(entry).__name__}, and a directory id "
                "is a string"
            )
        if len(entry) > DIRECTORY_GROUP_ID_MAX:
            raise ClaimRefused(
                f"claim '{claim}' contains a value of {len(entry)} characters, over the "
                f"{DIRECTORY_GROUP_ID_MAX} this reads"
            )
        if entry:
            out.add(entry)

    return frozenset(out)


def _refuse_if_withheld(claims: dict, claim: str) -> None:
    """Refuse an absence the provider has told us is not an absence.

    Entra's group overage: over the token's limit it omits `groups` and names it in
    `_claim_names`, with `_claim_sources` pointing at Graph. That is *"ask elsewhere"*,
    not *"in none"*, and the difference is somebody's whole access.
    """
    names = claims.get("_claim_names")
    if isinstance(names, dict) and claim in names:
        raise ClaimRefused(
            f"the provider withheld claim '{claim}' and named it in `_claim_names`, "
            "which means this person is in more groups than the token may carry rather "
            "than in none. Membership is left exactly as it is. Filter the claim at the "
            "provider — Entra can emit only the groups assigned to this application"
        )


def _digest(claim: str, values: frozenset) -> str:
    """A stable name for one claim set, so the work happens once per token rather than
    once per request. The claim's *name* is in it because moving the mapping is as much
    a change of input as moving the values.

    **JSON rather than a joined string**, and the edge-case pass is why: joining on a
    separator makes the encoding ambiguous, so `["a\\nb"]` and `["a", "b"]` — two
    different memberships — produced the same digest, and a person moving between them
    would have been skipped as already reconciled. A directory group's *name* is a
    value here (Okta emits names), and names carry whatever somebody typed. JSON
    escapes the separator, so distinct inputs cannot collide.
    """
    return _hash([claim, sorted(values)])


def _refusal_digest(claim: str, refusal: "ClaimRefused") -> str:
    """A marker for a claim that could not be read, so it is complained about once.

    Shaped so it can never equal a real claim set's digest — a refused claim is not a
    membership, and the two must not be able to collide into *this has been applied*.
    The refusal's own sentence is in it because two different bad shapes (201 values,
    then a value of the wrong type) are different inputs and each deserves its line.
    """
    return _hash(["refused", claim, str(refusal)])


def _hash(canonical: list) -> str:
    """JSON, then sha256. `ensure_ascii` is left **on**, which is not decoration: a lone
    surrogate reaches us intact through `json.loads` and UTF-8 cannot encode one, so the
    escaping is what keeps this function total for any claim a provider can emit."""
    return hashlib.sha256(
        json.dumps(canonical).encode("utf-8")
    ).hexdigest()


def _issued_at(claims: dict) -> datetime | None:
    """When this token was minted, if it says.

    `iat` is not in `oidc.REQUIRED_CLAIMS` — a token without one is still genuine — so
    absence means *no ordering information*, never a moment. Anything unreadable is
    treated the same way rather than refused: this claim orders our own bookkeeping and
    grants nothing.

    **A numeric string counts**, and the edge-case pass is why: PyJWT validates `iat` by
    calling `int()` on it, so `"1699999999"` verifies and reaches here — and a provider
    that quotes its numbers would have silently disabled the staleness guard for every
    one of its customers rather than obviously breaking. A genuinely non-numeric `iat`
    cannot arrive: PyJWT raises `InvalidIssuedAtError` before this module is reached.
    """
    raw = claims.get("iat")
    if isinstance(raw, bool):
        return None
    if isinstance(raw, str):
        try:
            raw = float(raw)
        except ValueError:
            return None
    if not isinstance(raw, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(raw, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _is_stale(user: dict | None, minted: datetime | None) -> bool:
    """Would this token undo what a newer one has already said?"""
    if user is None or minted is None:
        return False
    previous = user.get("directory_synced_at")
    return previous is not None and minted < previous
