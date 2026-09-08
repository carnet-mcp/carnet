"""Platform roles — who may administer this tenant.

The question four steps deferred with the same sentence, answered once here so that the
four answers cannot disagree:

```
group administration over HTTP     9a    access/groups.py, the docstring
reading the admin log in the app   11    cli.py, "a read route needs a tenant-admin role"
the vetting screen                 12    cli.py, "has now blocked three things"
configuring a consent flow         7b    routes_connections.py, "the same wall"
```

## An admin is not a superuser

**Holding `admin` grants no access to any agent, any run, or any connection.** This
module never consults `agent_grants` and `access/grants.py` never consults
`platform_roles`; the two ladders are orthogonal and there is no interaction to
understand. An admin who wants to run an agent gets a grant like anybody else, recorded
like anybody's.

The argument is 7b's, one level up. 7b exists because *an operator holding everybody's
tokens* is the failure delegated credentials prevent, and an `admin` that implied agent
access would rebuild that operator under a different name, one grant away. What an admin
gets is tenant **configuration**: groups, the administrative log, vetting, consent-flow
setup. None of it is tenant **data**.

## `system` is always an administrator, and that is the bootstrap rather than a shortcut

`api/deps.py` builds every principal through `users.resolve`, which returns
`Principal.user(...)`. **There is no path from an HTTP request to `kind="system"`** —
checked rather than remembered, and pinned by `test_http_can_never_mint_a_system_principal`
so that this rule's precondition fails loudly if some future entry point breaks it.

Two things follow, and both are decisions rather than conveniences:

- Treating `system` as always-admin is safe over HTTP, because no HTTP caller can be one.
  The CLI keeps working unchanged, and *who grants the first admin?* has the answer it has
  always had — whoever has the shell, which is this deployment's actual root of trust.
- **Lockout is impossible by construction**, so revoking the last administrator is
  allowed. A "cannot remove the last admin" rule would guard a failure that cannot occur
  here, and would become wrong the day role administration moves to HTTP — where it must
  be re-decided rather than inherited.

## `CARNET_OPEN_ADMIN` — every signed-in person administers, and nothing is written

Step 097, plan 094 decision 5. With the flag set, `is_admin` answers *yes* for every
`user` principal before storage is touched — `system`'s own shape, one kind over — and
**never for a machine token**: 020's argument stands, a credential that lacks persistence
must not be able to mint itself a successor, and the platform ladder does not admit one.
No `platform_roles` row is written, so unsetting the flag puts the gate back in front of
whoever holds a real row; every act performed under it is in `admin_audit` with the
member as actor, exactly as a real administrator's would be. An admin is still not a
superuser: the flag touches nothing on the agent ladder.

## Granting stays on the CLI

There is no `PUT /roles/...`, deliberately. A role model whose first version includes
admins minting admins over HTTP hands a compromised admin token the one thing it lacks,
quietly, in a step whose purpose is containment. The administrative log would record the
escalation, and recording one is not preventing one. Role administration over HTTP is
real future work with its own questions — may an admin revoke another admin? does the
last-admin rule change when the CLI is not the recovery path? — and gets decided when
somebody needs it, not as a rider on this step.
"""

import logging

from .. import config, storage
from . import denials
from ..core import Principal
from ..storage import ADMIN_ROLE, PLATFORM_ROLES

log = logging.getLogger(__name__)

__all__ = [
    "ADMIN_ROLE",
    "PLATFORM_ROLES",
    "RoleRequired",
    "grant",
    "is_admin",
    "list_roles",
    "require_admin",
    "revoke",
]


class RoleRequired(RuntimeError):
    """This needs a platform role the caller does not hold.

    A **403**, not the 404 `NoAccess` becomes, and the inversion has a reason rather than
    being an inconsistency. Agent routes answer 404 for "no grant" because a 403 confirms
    the agent exists, and an enumeration sweep over plausible names is worth more than the
    access. The resource an administrative route names is *the route itself*:
    `/admin-audit` exists identically for every tenant and is published in the OpenAPI
    document, so its existence is not a secret anybody can be protected from. A 404 here
    would tell an authenticated colleague a lie — *this product has no admin log* — that
    costs support tickets and protects nothing.
    """


# The sentence, written once. It is `deps.py`'s doctrine — a 403 message is returned
# because it is actionable by a person — and it deliberately **names no current
# administrators**: a directory of who to phish is not an error message's job. The cost is
# priced and stated in the plan's known limits: a person has to ask a colleague instead of
# reading a screen.
NOT_AN_ADMINISTRATOR = (
    "this needs an administrator of this workspace, and you are not one. Whoever "
    "runs your workspace can grant it."
)


def require_admin(principal: Principal, what: str = "") -> None:
    """Refuse anybody who is not an administrator of this tenant.

    **The one seam.** It replaces `groups._require_administrator`, whose docstring said
    for three steps that it was *"deliberately not a role check against a table, because
    there is no table"*. There is a table now, and this is the check.

    `what` is appended when a caller has something more specific to say — group
    administration does, because "you may not do this" is more useful when it names the
    thing. It never changes the decision.
    """
    if is_admin(principal):
        return

    # Step 015: the refusal, written down. Best-effort — see `denials.record`. The
    # `what` its callers already pass ("creating a group", '') is recorded for free;
    # a `system` principal never reaches this branch, because always-admin is the
    # bootstrap, so no record ever names one here.
    denials.record(principal, "admin", what, "admin", "")

    detail = f" Refused: {what}." if what else ""
    raise RoleRequired(NOT_AN_ADMINISTRATOR + detail)


def is_admin(principal: Principal) -> bool:
    """Whether this principal may administer this tenant. Renders rather than refuses.

    Separate from `require_admin` for exactly one caller — `GET /me`, which has to say
    *whether* somebody is an administrator without that being a refusal. Everything that
    enforces uses `require_admin`, so there is one place a refusal is produced and one
    sentence it produces.
    """
    # `system` first, and before storage is touched: this is what makes the CLI work
    # against an in-memory store with no tenant row, and what makes `--seed`, workers and
    # every existing unattended path keep passing without a migration having been run.
    if principal.kind == "system":
        return True

    # Step 097: the open door, for people only. Before storage for `system`'s reason —
    # an open deployment pays nothing for the check it switched off — and `config` is
    # read as a module attribute so a test can flip it without a reload.
    if config.OPEN_ADMIN and principal.kind == "user":
        return True

    return storage.active().has_platform_role(
        principal.tenant_id, principal.kind, principal.id, ADMIN_ROLE
    )


def grant(
    principal: Principal, subject: Principal, role: str = ADMIN_ROLE
) -> dict:
    """Give `subject` a platform role. The caller must already be an administrator.

    `subject` is a principal that **exists** — resolving an email address to one is the
    entry point's job, and `--grant-role` refuses an address nobody has logged in with.
    That refusal is `--connect-account`'s, and more so: a pending *admin* grant is a
    landmine that promotes whoever eventually claims an address — a mistyped one, a
    recycled one — silently, at login, with the granting recorded weeks earlier.

    Granting a role somebody already holds is an upsert that records again. See
    `Storage.grant_platform_role`.
    """
    require_admin(principal, f"granting '{role}'")

    if subject.tenant_id != principal.tenant_id:
        # Unreachable through either entry point — both build the subject with the
        # caller's own tenant — and refused anyway, because the alternative is a function
        # that would write a row into somebody else's customer if it ever were reached.
        raise RoleRequired(
            "a platform role is granted within one tenant, and this one names two"
        )

    # A bad role, or a group as the subject, arrives as a `StorageError` carrying the
    # sentence `check_platform_role` wrote. Deliberately not caught and rewrapped: this
    # module has nothing to add to it, and wrapping would replace an explanation with a
    # worse one.
    row = storage.active().grant_platform_role(
        principal.tenant_id,
        subject.kind,
        subject.id,
        role,
        granted_by=f"{principal.kind}:{principal.id}",
        actor=f"{principal.kind}:{principal.id}",
    )

    log.info(
        "granted %s to %s:%s in tenant %s",
        role,
        subject.kind,
        subject.id,
        principal.tenant_id,
    )
    return row


def revoke(
    principal: Principal, subject: Principal, role: str = ADMIN_ROLE
) -> bool:
    """Take a platform role away. Returns whether they held it. Idempotent.

    **Revoking your own role is allowed**, and the record's actor and target are the same
    principal. That is 7b's `connection.create` precedent: self-action is a real case the
    log must be able to represent, not a degenerate one to refuse.

    **Revoking the last administrator is also allowed** — see the module docstring. The
    CLI warns; nothing refuses.
    """
    require_admin(principal, f"revoking '{role}'")

    removed = storage.active().revoke_platform_role(
        principal.tenant_id,
        subject.kind,
        subject.id,
        role,
        actor=f"{principal.kind}:{principal.id}",
    )
    if removed:
        log.info(
            "revoked %s from %s:%s in tenant %s",
            role,
            subject.kind,
            subject.id,
            principal.tenant_id,
        )
    return removed


def list_roles(principal: Principal) -> list[dict]:
    """Every platform role row in this tenant. Administrators only.

    **This is not the same list as "who may administer"**, and the caller has to say so:
    `system` principals administer and hold no row. `--list-roles` prints that note under
    the table rather than this function inventing rows that do not exist — a listing is
    what the table holds, and the rule about `system` is policy that lives in this module.
    """
    require_admin(principal, "listing platform roles")
    return storage.active().list_platform_roles(principal.tenant_id)
