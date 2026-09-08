"""Group administration over HTTP — 9a's oldest debt, and the wall it hit is gone.

`access/groups.py`'s docstring said for three steps that **adding a route here before a
tenant-admin role existed would be the mistake it guarded against**. The role exists, so
these are the routes.

```
POST   /groups                                   admin    create
GET    /groups                                   user     the menu: id, name, description
GET    /groups/{id}                              admin    detail, INCLUDING members
DELETE /groups/{id}                              admin    and its grants go with it
PUT    /groups/{id}/members/{kind}/{id}          admin    add
DELETE /groups/{id}/members/{kind}/{id}          admin    remove
```

## The list is `user` and the members are `admin`, and that line was audited

An early draft of the plan claimed the share sheet *"already discloses group names and
membership"*. Checked, and it does not: `who_has_access` returns a group's **id** and the
people who reach one agent through it, to grant holders on that one agent. There is no
route today that lists groups or opens an arbitrary group's membership. So the disclosure
being added here is real, and it gets argued rather than waved through.

**Listing is the menu.** `GET /tools`' argument, one noun over: an `editor` sharing an
agent with a group has to pick one, and until now the share sheet could only take an id
somebody had been told out of band. A catalogue that cannot be read cannot be shared with.
What a name discloses is that a team exists, which the org chart already does.

**And the menu had nobody at it until 035h.** The sentence above was written
in the future tense and read ever since as the present: the share sheet had no group
control of any kind and passed `email` as the grantee kind literally, so `GET /groups` was
argued open for a caller nobody wrote, and every reader of this file believed the product
could do something it could not. It is a listing route, so nothing broke and nothing said
so. `DEFERRED.md` carries the general form: a route justified by naming its consumer owes a
test that the consumer exists.

**Membership is the directory.** "Who is in every group" is a map of the company. The one
legitimate non-admin need — *who will this share reach* — is already answered after the
fact, per agent, by `GET /agents/{name}/access`, which shows reach for an agent you hold a
grant on rather than membership of any group you can name. The refusal lives in
`access/groups.members` rather than here, for `tools.catalogue()`'s reason: two readers of
one table is how a CLI and an API stop agreeing about what a customer approved.

## Why these ship without a screen, when 7b's finding says routes-without-a-screen are theatre

7b's routes without a screen left the *problem* untouched, because the person who needed
them had no terminal. That is not the case here: the consumer of these routes today is the
**same engineer who runs `--add-group`**, and what they gain is idempotent HTTP semantics
for automation. The non-technical consumer arrives with 12c's administration surface,
where the vetting screen needs the same chrome — and 12b's screen is the administrative
log, which proves the whole chain end to end without pretending to be a group manager.
"""

from fastapi import APIRouter, Depends

from ..access import groups
from ..core import Principal
from .deps import admin_from_request, principal_from_request
from .schemas import (
    GroupDetail,
    GroupLinkRequest,
    GroupMemberEntry,
    GroupRequest,
    GroupSummary,
    MemberOutcome,
)

router = APIRouter(tags=["groups"])


@router.get("/groups", response_model=list[GroupSummary])
def list_groups(principal: Principal = Depends(principal_from_request)):
    """Every group in this tenant: id, name, description. **No role required.**

    The second route in this API that is not grant-filtered, after `GET /tools`, and for
    the same reason — it is the menu rather than anybody's order. Membership is not here
    and there is no member count, because a count is the first step of the directory this
    shape refuses to become.

    **`directory` since 035h**, and it is the boolean rather than the id: a menu that
    offered two options behaving differently — one an administrator controls, one arriving
    from the customer's directory at each person's next sign-in — and marked neither would
    be lying by omission to the editor picking from it. See `GroupSummary`.
    """
    return [GroupSummary(**_summary(row)) for row in groups.list_groups(principal)]


@router.post("/groups", response_model=GroupDetail, status_code=201)
def create_group(
    request: GroupRequest, principal: Principal = Depends(admin_from_request)
):
    """Make a group. **201**, and the body carries the `group_id` grants will name.

    The id is opaque and is generated here rather than derived from the name, so renaming
    a group leaves every grant naming it untouched — see `access/groups.create`.

    A name already in use is a **400** through `GroupRefused`, not a 409. The distinction
    `AgentNameTaken` draws does not apply: an agent name is a URL and an identity, so
    colliding on one is a conflict about a resource; a group name is a label, and the
    refusal is about the request rather than about a resource that already exists at this
    URL — there is no URL yet, because the id has not been minted.
    """
    row = groups.create(
        principal,
        request.name,
        description=request.description,
        external_id=request.external_id,
    )
    # Freshly created, so the membership is empty and is returned as such rather than
    # being fetched. One shape for a group, whether it was just made or just read.
    return GroupDetail(**_summary(row), members=[])


@router.get("/groups/{group_id}", response_model=GroupDetail)
def get_group(group_id: str, principal: Principal = Depends(admin_from_request)):
    """One group **and who is in it**. Administrators only — see the module docstring.

    A group that does not exist is a **400** through `GroupRefused` rather than a 404, and
    that is deliberate rather than sloppy: the caller has already proved they administer
    this tenant, so nothing about which groups exist is a secret from them, and
    `groups.members` raises one sentence naming the id and the tenant. A 404 here would be
    a second vocabulary for a refusal this layer already words.
    """
    row = groups.get(principal, group_id)
    members = groups.members(principal, row["group_id"])

    return GroupDetail(
        **_summary(row),
        members=[
            GroupMemberEntry(
                kind=member["principal_kind"],
                id=member["principal_id"],
                added_by=member.get("added_by", "") or "",
            )
            for member in members
        ],
    )


@router.patch("/groups/{group_id}", response_model=GroupDetail)
def link_group(
    group_id: str,
    request: GroupLinkRequest,
    principal: Principal = Depends(admin_from_request),
):
    """Point a group at a directory group, or let it go. Step 033e.

    **The one field a group has that can be edited after creation**, and it is here
    rather than in a general `PATCH` for the reason `agent.restore` is its own route: what
    this changes is who may change who is in the group, and a body that could also carry
    a name would make that decision a diff somebody has to notice. `external_id: null`
    unlinks, which removes nobody — the membership becomes the administrator's again.

    A 400 through `GroupRefused` for a group that is not there or a directory id another
    group already holds, matching `GET /groups/{id}`: the caller has already proved they
    administer this tenant, so which groups exist is not a secret from them and a second
    vocabulary for the refusal would be the one thing worth avoiding.

    The membership comes back with the row because the sheet renders both, and because
    *what does this group hold now* is the question somebody asks immediately after
    handing it to their directory.
    """
    row = groups.link(principal, group_id, request.external_id)
    members = groups.members(principal, row["group_id"])

    return GroupDetail(
        **_summary(row),
        members=[
            GroupMemberEntry(
                kind=member["principal_kind"],
                id=member["principal_id"],
                added_by=member.get("added_by", "") or "",
            )
            for member in members
        ],
    )


@router.delete("/groups/{group_id}", status_code=204)
def delete_group(group_id: str, principal: Principal = Depends(admin_from_request)):
    """Delete a group. **204, and every access it carried goes with it.**

    Its membership cascades by foreign key and its grants go by migration 017's trigger —
    on every agent, immediately, and nobody is told. That is the same shape as revoking a
    grant, one level wider, and it is why `--delete-group` prints the counts.

    204 on a group that was not there, unlike `DELETE /agents/{name}`, which answers 404.
    The difference is what the caller may conclude: an agent 404 is also what somebody
    with no grant gets, so the route cannot say which and must not pretend. Here the
    caller is an administrator, deletion is idempotent in storage, and the honest report
    of "there is no such group now" is the same either way.
    """
    groups.delete(principal, group_id)


@router.put(
    "/groups/{group_id}/members/{member_kind}/{member_id}",
    response_model=MemberOutcome,
)
def add_member(
    group_id: str,
    member_kind: str,
    member_id: str,
    principal: Principal = Depends(admin_from_request),
):
    """Put a principal in a group. **Idempotent**, and the body says whether it changed.

    `PUT` on a URL naming the member rather than `POST /groups/{id}/members`, matching
    `PUT /agents/{name}/grants/{kind}/{grantee}`: the write is keyed by who it is for, and
    the URL is that key.

    **A group may not be a member of a group.** Refused by `check_principal_kind`, which
    has permitted exactly `user` and `system` since 009 — so nesting is refused by a rule
    that predates this route rather than by a new one plus cycle detection. It arrives as
    a 400 through `GroupRefused`.

    `changed: false` means they were already in it. Reported rather than swallowed, on
    `GrantOutcome`'s reasoning: "added" and "was already there" are different facts, and
    an administrator who cannot tell them apart cannot tell a working command from a
    no-op.
    """
    before = _is_member(principal, group_id, member_kind, member_id)
    groups.add_member(principal, group_id, member_kind, member_id)

    return MemberOutcome(
        group_id=group_id, kind=member_kind, id=member_id, changed=not before
    )


@router.delete(
    "/groups/{group_id}/members/{member_kind}/{member_id}",
    response_model=MemberOutcome,
)
def remove_member(
    group_id: str,
    member_kind: str,
    member_id: str,
    principal: Principal = Depends(admin_from_request),
):
    """Take a principal out of a group. **Idempotent**, and 200 with a body, not 204.

    The body is the whole reason this is not a 204, and it is `DELETE
    /connectors/{id}/connection`'s precedent: `changed` is the answer to *did this do
    anything*, and a 204 has nowhere to put it. Removing somebody takes away every access
    they had through this group, on every agent, immediately — and nothing tells them. An
    administrator pressing that deserves to know whether it happened.
    """
    changed = groups.remove_member(principal, group_id, member_kind, member_id)

    return MemberOutcome(
        group_id=group_id, kind=member_kind, id=member_id, changed=changed
    )


def _summary(row: dict) -> dict:
    """The fields both group shapes share, off a storage row.

    Written once because `GroupDetail` extends `GroupSummary`, and a second spelling of
    the same projection is how the two stop agreeing about what a group is.
    """
    return {
        "group_id": row["group_id"],
        "name": row["name"],
        "description": row.get("description") or "",
        "external_id": row.get("external_id"),
        "created_by": row.get("created_by") or "",
        # Step 035h. `is not None` and **not** truthiness, because `GROUP_FIELDS` says NULL
        # and `''` are different states. A group linked to a directory group with a blank id
        # is one `check_external_id` describes as removing every person at each sign-in —
        # the state an administrator most needs marked, and the one `bool('')` would report
        # as *managed here*. Unreachable through `PATCH`, which refuses a blank; reachable
        # from below, which is why the rule is here rather than assumed.
        #
        # The boolean lands on `GroupSummary` and the id it is computed from stays on
        # `GroupDetail` — see both models, and `AgentAccessEntry.directory` for the
        # precedent. Computed once, in the projection both shapes share, so the open menu
        # and the administrator's detail cannot disagree about it.
        "directory": row.get("external_id") is not None,
    }


def _is_member(
    principal: Principal, group_id: str, member_kind: str, member_id: str
) -> bool:
    """Whether they are already in it, read **before** the write.

    One extra read for one bit, and it is bought rather than saved: the alternative is
    `add_group_member` returning whether it inserted, which would change a storage
    signature that four callers already use for a fact only this route wants. The read
    also produces the 400 for a group that does not exist, before anything is written.
    """
    return any(
        member["principal_kind"] == member_kind and member["principal_id"] == member_id
        for member in groups.members(principal, group_id)
    )
