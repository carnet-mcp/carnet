"""People and platform roles over HTTP — step 110, decisions 3 and 4.

    GET  /admin/users                 who is in the tenant, their status, whether they
                                      have ever signed in
    POST /admin/users/{id}/disable    cut somebody off now
    POST /admin/users/{id}/enable     let them back in
    GET  /admin/roles                 who holds a platform role, since when, granted by whom

**Disabling is here and granting is not, and the line between them is the design.**
Plan 12b refused `PUT /roles/...` with an argument that has not weakened: admins minting
admins over HTTP is the one thing a compromised admin token cannot cure. Every other
authority a stolen session holds is revocable by an administrator who still has a shell;
the authority to appoint administrators is the one that reproduces. `--disable-user`
*reduces* authority — sign-in refused, every token they own refused at its next call,
nothing they made deleted — and a compromised session that disables people is a
nuisance an administrator with a shell can undo (`--enable-user`), not a foothold that
reproduces. So the people page has two buttons and the roles page has none; the roles
page prints the command instead, and says in a sentence why.

**One refusal, and it is the caller's own row.** An administrator who disables
themselves is locked out with no way back but the shell, and a form is exactly where
that happens by a mis-aimed click. A 400 with the sentence; the CLI never meets the
case because it runs as `system`.

**Everything else is the seam's.** `users.set_active` is the one offboarding path since
071 — the CLI, the SCIM push and now this route all reach it — so what stops and what
stays is decided once, there, and recorded there in the same transaction. This file
adds no rule about what disabling means.

What is deliberately not here: no create (people arrive by signing in, 016's rule),
no delete (there is no hard delete anywhere, 071's rule), no grant or revoke (above),
and no step-up authentication — which is the thing that would change the grant
answer, named in plan 110 decision 3 so it is not re-argued from scratch, and a step
of its own with a trigger of its own.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query

from .. import storage
from ..access import roles, users
from ..core import Principal
from ..storage import ValueRefused
from .deps import admin_from_request
from .schemas import PersonEntry, PersonStatus, RoleEntry

log = logging.getLogger(__name__)

router = APIRouter(tags=["administration"])


def _when(value) -> str:
    if value is None or value == "":
        return ""
    return value.isoformat(timespec="seconds") if hasattr(value, "isoformat") else str(value)


def _person(row: dict) -> PersonEntry:
    return PersonEntry(
        id=row["id"],
        email=row.get("email") or "",
        display_name=row.get("display_name") or "",
        status=row["status"],
        issuer=row["issuer"],
        external_id=row.get("external_id") or "",
        signed_in=row.get("last_seen_at") is not None,
        last_seen_at=_when(row.get("last_seen_at")),
    )


@router.get("/admin/users", response_model=list[PersonEntry])
def list_people(
    email: str | None = Query(default=None),
    principal: Principal = Depends(admin_from_request),
):
    """`--list-users`, for the caller's tenant. Ordered by id, as the store returns them;
    a screen sorts by whatever it is looking for.

    `?email=` answers one principal or none, exactly (plan 107 D10): the groups page
    adds a member by the address a colleague is known by rather than by an id copied
    from a log. The enumeration concern that kept this off the wire was about *anybody
    here*; this is an administrator, who already reads every id in the audit log, and
    prefix search is deliberately not offered.

    **A blank address is refused rather than matched.** It fell through to `"" == ""`
    and answered with every person who has no address — the people a directory pushed
    without one — which is a listing wearing a lookup's clothes and the opposite of
    *one principal or none*. An empty box is not a question, and `--group-add` refuses
    it for the same reason. No parameter at all is still the whole listing, which is a
    different request.

    Every match is returned rather than the first, and normally there is one. Two rows
    can carry one address — the same person in two providers, which 110d made easy to
    set up — and a route that silently picked one would be choosing which of two
    principals a group is about. The screen says so and asks.
    """
    rows = storage.active().list_users(principal.tenant_id)
    if email is not None:
        wanted = email.strip().lower()
        if not wanted:
            raise ValueRefused(
                "an address is needed to look somebody up. Leave the parameter off "
                "altogether for the whole list."
            )
        rows = [row for row in rows if (row.get("email") or "").lower() == wanted]
    return [_person(row) for row in rows]


def _set_active(principal: Principal, user_id: str, active: bool) -> PersonStatus:
    store = storage.active()
    if not active and principal.kind == "user" and principal.id == user_id:
        raise ValueRefused(
            "you cannot disable yourself: your sign-in would be refused from now and "
            "there is no way back from a browser. Another administrator can, or the shell "
            "can (carnet --disable-user)."
        )
    before = store.get_user(principal.tenant_id, user_id)
    if before is None:
        raise ValueRefused(
            f"there is no user '{user_id}' in this tenant. People arrive by signing in; "
            "the list is who has."
        )
    wanted = "active" if active else "disabled"
    if before["status"] == wanted:
        # The seam writes no record for a restatement, and neither does this say it did.
        return PersonStatus(id=user_id, email=before.get("email") or "", status=wanted, changed=False)
    row = users.set_active(
        principal, user_id, active, cause="POST /admin/users/disable" if not active else "POST /admin/users/enable"
    )
    return PersonStatus(id=user_id, email=row.get("email") or "", status=row["status"], changed=True)


@router.post("/admin/users/{user_id}/disable", response_model=PersonStatus)
def disable_person(user_id: str, principal: Principal = Depends(admin_from_request)):
    """Cut somebody off now. Sign-in refused from now, every token they own refused at
    its next call, nothing they made deleted — `users.set_active`'s contract, not this
    route's. Refuses the caller's own row."""
    return _set_active(principal, user_id, False)


@router.post("/admin/users/{user_id}/enable", response_model=PersonStatus)
def enable_person(user_id: str, principal: Principal = Depends(admin_from_request)):
    """Let a disabled person back in. Reverses the status and nothing else."""
    return _set_active(principal, user_id, True)


@router.get("/admin/roles", response_model=list[RoleEntry])
def list_roles(principal: Principal = Depends(admin_from_request)):
    """Who holds a platform role — read only, on purpose, and the module docstring says
    why. Joined to the people rows so the page shows an address; a row whose principal
    is not a person (there are none today: `platform_roles` names people, and `system`
    principals hold no row) is shown by its principal string.

    **This does not list the administrators**, and the page has to say so as the CLI
    does: every `system` principal administers and holds no row here. That is the
    bootstrap and the way back from an empty table.
    """
    store = storage.active()
    people = {row["id"]: row for row in store.list_users(principal.tenant_id)}
    entries = []
    for row in roles.list_roles(principal):
        person = people.get(row["principal_id"]) if row["principal_kind"] == "user" else None
        entries.append(
            RoleEntry(
                principal=f"{row['principal_kind']}:{row['principal_id']}",
                kind=row["principal_kind"],
                id=row["principal_id"],
                email=(person or {}).get("email") or "",
                display_name=(person or {}).get("display_name") or "",
                role=row["role"],
                granted_by=row.get("granted_by") or "",
                granted_at=_when(row.get("granted_at")),
            )
        )
    return entries
