"""Groups — the thing you share with when you do not want to name forty people.

A group is a **grantee**: something a grant may point at, and never something that acts.
It cannot own a run, appear in an audit record, or hold a delegated credential. See
`storage/base.py` for the two vocabularies and migration 017 for where that split is
enforced by the database rather than by this sentence.

## What a group is not

Not a wildcard. Step 006 refused wildcards, public flags and share links because absence
must be denial and denial must look like absence, and it is worth being precise about why
a group is a different thing rather than the same thing with a friendlier name.

The test is: *can you answer "who exactly can reach this agent right now?" with a finite
list?* A wildcard cannot — that is what makes it dangerous, because nobody can enumerate
the blast radius after an incident. A group can: membership is rows, and
`grants.who_has_access` expands it into the answer rather than leaving it as an optional
second query. A group is indirection. It is closer to a mailing list than to `*`.

**Step 033e is where that stopped being free, and the debt is paid rather than
forgotten.** Membership resolved from a directory claim means we know who has signed in
and been placed in a group, not who would be — somebody added to `eng` in Entra this
morning is not in `who_has_access` until they next present a token that says so. The
complete answer became a partial one, which is a real regression against 006's rule, and
the answer this module owed is that **the partial answer says it is partial**: a group's
row on the share sheet carries `directory`, and both readers of it — the sheet and
`--agent-access` — print the sentence rather than quietly returning a shorter list. The
enumerable-blast-radius property survives in the form that is actually true: everybody
who can reach an agent right now is still a finite list of rows; who *will* be able to
after their next sign-in is a question for the directory that answers it.

## Who may administer a group

**Mutating a group requires the `admin` platform role**, which as of 12b exists. This
section used to say the opposite — *"a `system` principal, and that is a placeholder
rather than a model"* — and named the thing it was waiting for: platform roles, out of
scope since 003, blocking this since 9a.

The restrictive choice it made has been preserved exactly rather than relaxed. `system`
still passes, because the CLI is always an administrator; what has changed is that a
person can be one too, by a row somebody granted rather than by being authenticated. The
reasoning is unchanged and is worth keeping: if any authenticated person could add
themselves to a group, then any group holding an `editor` grant is a self-service
promotion, and the ladder is decorative.

**There are HTTP routes for this now**, which is what this docstring spent three steps
saying would be the mistake — *before* the role existed. `api/routes_groups.py` carries
them, and the split there is argued rather than assumed: listing groups (id, name,
description) is open to any authenticated person, because it is the menu an `editor`
picks from when sharing; enumerating **membership** is admin, because "who is in every
group" is a directory of the company. `access/grants.py` still governs whether a group's
grant on an agent may be created at all — sharing requires `editor` on that agent, so
filling a group with people grants them nothing until somebody who could already share
does.
"""

import logging
import uuid

from .. import storage
from ..core import Principal
from ..core.credentials import personal_owner
from ..storage import GROUP_ROLES
from ..storage.base import NO_SUCH_GROUP, StorageError
from .roles import require_admin

log = logging.getLogger(__name__)

__all__ = [
    "GroupRefused",
    "add_member",
    "create",
    "delete",
    "get",
    "link",
    "list_groups",
    "members",
    "remove_member",
    "resolve",
    "tenant_reads_groups",
    "unmanaged_members",
]


class GroupRefused(RuntimeError):
    """This group operation may not be done, or cannot be.

    A sibling of `ShareRefused` rather than of `NoAccess`, and for the same reason: a
    group is not a secret. Nothing here leaks the existence of an agent, so the message
    can say what went wrong.

    **Not the refusal for "you are not an administrator"** — that is `RoleRequired`, a
    403, and the two are separate classes on the reasoning that keeps `NoAccess` and
    `ShareRefused` separate: one means *you may not do this at all*, the other means *you
    may do this and this particular request is wrong*. Collapsing that pair cost a real
    bug once already.
    """


def create(
    principal: Principal,
    name: str,
    description: str = "",
    external_id: str | None = None,
) -> dict:
    """Make a group. Returns the row, whose `group_id` is what grants will name."""
    require_admin(principal, "creating a group")

    if not name or not name.strip():
        raise GroupRefused("a group needs a name — it is how a person picks one")

    # Opaque, never derived from the name, in the shape `u_` already uses. A renamed
    # group is the same group, and every grant naming it survives the rename untouched.
    group_id = f"g_{uuid.uuid4().hex[:16]}"

    try:
        row = storage.active().create_group(
            principal.tenant_id,
            group_id,
            name.strip(),
            description=description,
            external_id=external_id,
            created_by=f"{principal.kind}:{principal.id}",
            actor=f"{principal.kind}:{principal.id}",
        )
    except StorageError as exc:
        raise GroupRefused(str(exc)) from exc

    log.info("created group %s ('%s') in tenant %s", group_id, name, principal.tenant_id)
    return row


def link(principal: Principal, group_id: str, external_id: str | None) -> dict:
    """Point a group at a directory group, or let it go. Returns the row. Step 033e.

    **A takeover, and the caller has to say so.** From here on the group's membership is
    whatever the claim says at each person's next sign-in: everybody in it whom the
    directory does not name is removed, one at a time, as they arrive. That is why the
    CLI prints how many people that currently is, in the shape `delete_group` reports
    what a deletion is about to take — the count is the only thing that ever says how
    much is at stake, and it stops being knowable the moment it starts happening.

    `None` unlinks and removes **nobody**: the membership stays exactly as it is and
    becomes the administrator's again, which is the safe direction for a configuration
    change and the reason unlinking needs no warning of its own.

    The value is stripped, and a **blank** one is refused rather than read as an unlink:
    `None` is how *stop following the directory* is spelled, and a client sending a field
    it failed to fill in must not be told it succeeded at the opposite of what it asked.
    Both rules live at the storage seam (`normalize_external_id`) rather than here, so
    `POST /groups` inherits them — the edge-case pass found that it did not, and a group
    created with a trailing newline could be filled by nobody: not by the directory,
    which matches byte for byte, and not by hand, which this step refuses.
    """
    require_admin(principal, "linking a group to a directory")

    try:
        row = storage.active().set_group_external_id(
            principal.tenant_id,
            group_id,
            external_id,
            actor=f"{principal.kind}:{principal.id}",
        )
    except StorageError as exc:
        # `NoSuchGroupError` included, by inheritance: a group that is not there and a
        # directory id somebody else holds are both "this request is wrong", which is
        # exactly what `GroupRefused` means and what `RoleRequired` does not.
        raise GroupRefused(str(exc)) from exc

    log.info(
        "group %s in tenant %s is %s",
        group_id,
        principal.tenant_id,
        (
            f"linked to directory group '{row['external_id']}'"
            if row["external_id"]
            else "no longer linked"
        ),
    )
    return row


def rename(principal: Principal, group_id: str, name: str) -> dict:
    """Give a group a new name. Returns the row. Step 071.

    Grants record the **id**, so this costs nothing they can see; what it changes is
    the word a person types at a share box. A hand rename at the CLI is a flag nobody
    has asked for, and the seam exists so that when they do it is one line.
    """
    require_admin(principal, "renaming a group")
    try:
        row = storage.active().rename_group(
            principal.tenant_id, group_id, name, actor=f"{principal.kind}:{principal.id}"
        )
    except StorageError as exc:
        raise GroupRefused(str(exc)) from exc
    if row is None:
        raise GroupRefused(NO_SUCH_GROUP.format(group=group_id, tenant=principal.tenant_id))
    return row


def unmanaged_members(principal: Principal, group_id: str) -> list[dict]:
    """The people in this group the directory may not name. For `link`'s warning.

    Only `user` rows, because those are the only ones a reconciliation ever writes — a
    `system` or `machine` member survives a link untouched and would be a lie in a
    sentence about what linking costs.

    **Administrators only**, like `members` above and for exactly its reason: this
    returns member rows, and *who is in a group you can name* is a directory of the
    company. Its only caller today runs as `system`, which is precisely how the gate
    came to be missing — the rule was being enforced by which caller happened to exist
    rather than by the seam, and the next caller (a "how many would this take over?"
    preview on the link control) is the obvious one to add.
    """
    require_admin(principal, "listing who is in a group")

    return [
        member
        for member in storage.active().list_group_members(principal.tenant_id, group_id)
        if member["principal_kind"] == "user"
    ]


def delete(principal: Principal, group_id: str) -> bool:
    """Delete a group. Its grants and its membership go with it, in the database.

    Returns whether there was one, so a caller can say something true. Deleting a group
    that does not exist is not an error — the same idempotency `revoke_agent` has.
    """
    require_admin(principal, "deleting a group")
    gone = storage.active().delete_group(
        principal.tenant_id, group_id, actor=f"{principal.kind}:{principal.id}"
    )
    if gone:
        log.info("deleted group %s in tenant %s", group_id, principal.tenant_id)
    return gone


def add_member(
    principal: Principal,
    group_id: str,
    member_kind: str,
    member_id: str,
    *,
    from_directory: bool = False,
) -> None:
    """Put a principal in a group. Idempotent.

    A group may not be a member of a group; storage refuses that with
    `check_principal_kind`, which has permitted exactly `user` and `system` since 009.

    **A person may not be hand-added to a directory-backed group — step 033e.** The
    directory owns that membership: a row added here would be deleted at that person's
    next sign-in, which is a write reporting success and quietly doing nothing — the
    shape `unshare` and 033d's two seams already refuse. `from_directory` is how the
    reconciliation says it is the directory speaking; nothing reachable from a request
    passes it, and nothing needs to, because HTTP cannot produce the `system` principal
    it is called with.

    Only a **`user`** is refused. Reconciliation writes nobody else's rows, so a
    `system` or `machine` member of a linked group is the admin's business and the two
    sources of membership touch disjoint rows — which is the whole reason they cannot
    fight, rather than an exception to it.

    **A personal token is refused as a member — step 033d.** A machine may be a group
    member since migration 031, and for a *service* token that stays the bulk-grant
    path. A personal token's access resolves through its owner, whose own memberships
    already count and whose absence from a group should mean absence; a membership of
    the token's own would be the direct-grant escalation wearing a group — 021's exact
    lesson, a rule enforced at one seam and walked around through membership. The row
    would also be inert (`role_of` queries as the owner, so machine rows never enter
    the statement), and a membership that reports success and confers nothing is the
    unshare-that-does-nothing shape. The sentence quotes only the row's own id and
    owner, never wire text.
    """
    require_admin(principal, "changing who is in a group")

    if not from_directory and member_kind == "user":
        _refuse_if_directory_backed(principal, group_id, member_id, "add")

    if member_kind == "machine":
        owner = personal_owner(Principal.machine(member_id, principal.tenant_id))
        if owner is not None:
            raise GroupRefused(
                f"'{member_id}' is a personal token: its access is its owner's "
                f"({owner}), including the groups the owner is in, so the token "
                "itself is never a member — a membership of its own could hand it "
                "something its owner does not have. Add the owner to the group "
                "instead; every personal token they hold follows."
            )

    try:
        storage.active().add_group_member(
            principal.tenant_id,
            group_id,
            member_kind,
            member_id,
            added_by=f"{principal.kind}:{principal.id}",
            actor=f"{principal.kind}:{principal.id}",
        )
    except StorageError as exc:
        raise GroupRefused(str(exc)) from exc

    log.info(
        "added %s:%s to group %s in tenant %s",
        member_kind,
        member_id,
        group_id,
        principal.tenant_id,
    )


def remove_member(
    principal: Principal,
    group_id: str,
    member_kind: str,
    member_id: str,
    *,
    from_directory: bool = False,
) -> bool:
    """Take a principal out of a group. Returns whether they were in it.

    **This takes away every access they had through it**, on every agent, immediately —
    and nothing tells them. That is the same shape as revoking a grant and it is why
    group membership is a second thing that has to be revoked when somebody leaves.

    Refuses a hand-removal of a **person** from a directory-backed group, for
    `add_member`'s reason in the other direction: the directory would put them back at
    their next sign-in, so the removal is a control that appears to work. Take them out
    of the group in the directory — or unlink the group here, which hands its membership
    back to whoever is reading this.
    """
    require_admin(principal, "changing who is in a group")

    if not from_directory and member_kind == "user":
        _refuse_if_directory_backed(principal, group_id, member_id, "remove")

    removed = storage.active().remove_group_member(
        principal.tenant_id,
        group_id,
        member_kind,
        member_id,
        actor=f"{principal.kind}:{principal.id}",
    )
    if removed:
        log.info(
            "removed %s:%s from group %s in tenant %s",
            member_kind,
            member_id,
            group_id,
            principal.tenant_id,
        )
    return removed


def tenant_reads_groups(tenant_id: str) -> bool:
    """Does any enabled provider for this customer name a groups claim?

    The question *is the directory speaking here* — asked on the hand-edit path only,
    where one extra read of a single-digit-row table buys a group that cannot be frozen
    by configuring things in the wrong order.
    """
    return any(
        row["enabled"] and row["groups_claim"]
        for row in storage.active().list_tenant_idps(tenant_id)
    )


def _refuse_if_directory_backed(
    principal: Principal, group_id: str, member_id: str, verb: str
) -> None:
    """Step 033e's seam, written once so both halves say the same thing.

    Reads the group rather than trusting a caller's word about it, and quotes only the
    row's own `external_id` and the id already checked into the request — the producer of
    a sentence bounds its own input.

    **Refuses only while the directory is actually speaking**, which is a link *and* a
    provider that names a groups claim. Keying on the link alone — as this first did —
    made a group linked before its provider was configured editable by **nobody**:
    `reconcile` returns immediately without a claim, so nothing filled it, and this
    refused every hand edit, so nothing else could either. Recovering needed an unlink
    the admin had no reason to suspect. It is also what makes the promise on the other
    side true: clearing a provider's `groups_claim` hands its groups back rather than
    freezing them where they stand.
    """
    row = storage.active().get_group(principal.tenant_id, group_id)
    if row is None or row.get("external_id") is None:
        return

    if not tenant_reads_groups(principal.tenant_id):
        return

    verb_phrase = (
        f"add '{member_id}' to" if verb == "add" else f"take '{member_id}' out of"
    )
    raise GroupRefused(
        f"'{row['name']}' follows your directory (as '{row['external_id']}'), so this "
        f"cannot {verb_phrase} it: membership is set from the groups claim at every "
        "sign-in, and a change made here would be undone at theirs. Change it in the "
        "directory — or unlink the group, which hands its membership back to you."
    )


def members(principal: Principal, group_id: str) -> list[dict]:
    """Who is in this group. **Administrators only, and this narrowed in 12b.**

    It used to say *"readable by anybody in the tenant"*, open at the bottom for the
    reason `who_has_access` is: somebody deciding whether to run an agent that acts on
    their data should be able to see who else can reach it. That reasoning survives and
    the conclusion does not, because it justifies less than it was being used for — it
    argues for *"who will this share reach"*, which `who_has_access` already answers per
    agent, for an agent the reader holds a grant on. This function answers *"who is in
    any group you can name"*, which is a directory of the company.

    Nothing disclosed it before 12b — there was no route, and the only caller was the CLI
    running as `system`. The narrowing is therefore free, and it is done **here** rather
    than in the route for `tools.catalogue()`'s reason: the CLI and the API must answer
    the same question the same way, and two readers of one table is how they stop
    agreeing.

    `list_groups` below is deliberately **not** narrowed: a name is the menu, membership
    is the directory.
    """
    require_admin(principal, "listing who is in a group")

    if storage.active().get_group(principal.tenant_id, group_id) is None:
        raise GroupRefused(
            NO_SUCH_GROUP.format(group=group_id, tenant=principal.tenant_id)
        )
    return storage.active().list_group_members(principal.tenant_id, group_id)


def get(principal: Principal, group_id: str) -> dict:
    """One group **by id**, or `GroupRefused`. Any authenticated person.

    Deliberately not `resolve` below, which also accepts a name. A name is what somebody
    types at a terminal; an id is what a URL carries and what a grant records, and a route
    that quietly accepted either would mean `GET /groups/support` and
    `GET /groups/g_8f2c…` are the same resource until the day somebody names a group
    after an id.

    Open at the bottom like `list_groups`, and for the same reason: this is the menu entry
    rather than the membership. `GET /groups/{id}` is nonetheless administrator-only,
    because the shape it returns carries `members`.
    """
    row = storage.active().get_group(principal.tenant_id, group_id)
    if row is None:
        raise GroupRefused(
            NO_SUCH_GROUP.format(group=group_id, tenant=principal.tenant_id)
        )
    return row


def list_groups(principal: Principal) -> list[dict]:
    """Every group in this tenant, ordered by name. Any authenticated person.

    Open on `GET /tools`' argument one noun over: **it is the menu.** An `editor` sharing
    an agent with a group has to pick one, and until 12b the share sheet could only take
    an id somebody had been told out of band — a catalogue that cannot be read cannot be
    shared with. What a name discloses is that a team exists, which the org chart already
    does. Membership is the part that is a directory, and that is `members` above.
    """
    return storage.active().list_groups(principal.tenant_id)


def resolve(principal: Principal, who: str) -> dict:
    """Turn what somebody typed into a group row. By id, or by name.

    Names are what a person knows and ids are what grants record, so both work and the
    id wins when a name and an id collide — an id is unambiguous and a name is a label
    somebody may change.
    """
    store = storage.active()

    found = store.get_group(principal.tenant_id, who)
    if found is not None:
        return found

    found = store.find_group_by_name(principal.tenant_id, who)
    if found is not None:
        return found

    known = ", ".join(g["name"] for g in store.list_groups(principal.tenant_id))
    raise GroupRefused(
        f"no group '{who}' in tenant '{principal.tenant_id}'. "
        + (f"Groups: {known}." if known else "There are none yet.")
    )


# Re-exported so a caller deciding what to offer in a UI does not have to reach into
# storage for it. A group may hold `user` or `editor`; ownership is somebody's name.
GROUP_ROLES = GROUP_ROLES
