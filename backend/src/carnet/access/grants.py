"""May this **person** use this agent, and at what level?

The other half of a sentence the product has always made and the code has never kept:
*"anyone with access can use an agent, and when they do it acts on their data."* Until
this module, every authenticated person in a tenant could run every agent in it.

## This is not the permission model, and the distinction is load-bearing

Two questions, and collapsing them is how identity gets into the policy engine:

    grants        may this PERSON use this agent?      once, before a run exists
    permissions   may this AGENT do this thing?        on every tool call

`core/permissions.py` has gone six steps without learning what a user is. It takes a
`Principal` and never asks who it belongs to — it asks what the *agent* was granted. If
answering "who may run this?" ever moves in there, the two questions have merged and the
layering argument is over. **If this step changed `core/permissions.py`, the model is
wrong.**

So the check happens where an agent is loaded for a run, and the broker never sees it.

## The ladder

`storage.AGENT_ROLES` is ordered weakest-first and the index *is* the level, so every
question here is one comparison. What the levels mean:

    user     run it; see its tools and what it may reach
    editor   ... and edit its config, and share it on
    owner    ... and delete it, and hand it to somebody else

Named for the verbs an agent has rather than a document's. See migration 011: running is
the reason to share an agent at all, it is the verb that spends money and writes to real
systems, and calling that level `viewer` would be a name that actively misinforms
whoever picks it.

`editor`'s editing half is inert today — `routes_agents.py` is read-only and there is no
write endpoint to permit. Its one live power is re-sharing. That is the same
shape-before-the-thing bet as `Principal.user()` in 001 and the `connections` table in
002: the level goes in now so that a write route is a route rather than a route plus a
permission model.

## Absence is denial, and denial looks like absence

No wildcard, no public flag, no link sharing. An agent nobody has been granted is an
agent nobody can run, including whoever created it.

`NoAccess` becomes a **404** at the API, byte-identical to an agent that does not exist —
and that is true at every level. Asking to edit an agent you may only run gets the same
404 as asking about one that was never there, because distinguishing them confirms that
something exists in a tenant you cannot see.
"""

import logging

from .. import storage
from . import denials
from ..core import Principal
from ..core.credentials import personal_owner
from ..storage import AGENT_ROLES, MACHINE_ROLES, OWNER_ROLE
from ..storage.base import normalize_email

log = logging.getLogger(__name__)


class NoAccess(RuntimeError):
    """This principal may not do this to this agent — or there is no such agent.

    Deliberately one exception for both. The caller cannot tell them apart because the
    person on the other end must not either; see the module docstring.
    """


class ShareRefused(RuntimeError):
    """The sharer may do this; the share itself cannot be made.

    A separate exception from `NoAccess`, and the separation is not tidiness. The two
    say opposite things about the caller:

        NoAccess       you may not touch this agent — and it may not exist
        ShareRefused   you may share this agent, and *this particular share* is bad

    Collapsing them cost a real bug. `--share-agent` reports a `NoAccess` by appending
    "it has not been shared with you at the level this needs", which is true for a
    permission failure and flatly false for a rejected address — the operator owned the
    agent and was told they did not. Found by running it against a real database rather
    than by reading it.

    It is also safe to explain, where `NoAccess` is not: the caller has already proved
    `editor`, so saying *why* leaks nothing about what exists. Behind a share endpoint
    this is a 400, never the 404 that `NoAccess` becomes.
    """


def _level(role: str) -> int:
    return AGENT_ROLES.index(role)


def role_of(principal: Principal, agent_name: str) -> str | None:
    """This principal's **effective** role on this agent, or None if they have none.

    Since step 9a this is the highest of what they hold directly and what they hold
    through any group they belong to. Storage resolves it in one statement — see
    `agent_grant_role` — so the hot path is unchanged in shape even though the answer is
    now computed rather than looked up.

    **A machine is capped at `user` here, and 021's edge hunt is why.** Step 020 states
    the rule twice — `MACHINE_ROLES`, and `agent_grants_no_machine_above_user` — and both
    guard a *direct* grant. Neither can see a group: a machine may be a group member
    (migration 031 widened `group_members` on purpose), a group may be granted `editor`,
    and "highest of direct and inherited" then hands a machine the level both of those
    rules exist to withhold.

    What that produced before this line, found by driving the request rather than by
    reading: `GET /agents/x` reported `your_role: editor` to a machine, so a screen would
    render Edit and Restore for it — and the write itself failed at the **last** guard,
    `ADMIN_ACTOR_KINDS`, as a bare `StorageError`, which `api/errors.py` turns into
    *"storage unavailable: try again later"* about something that will never work. The
    data was safe; the control was somewhere else than where it was documented, and the
    refusal was the wrong family for the ninth time.

    So the cap lives where the effective role is computed, which is the one place every
    path goes through — `check`, `require`, `your_role`, and the share sheet. Editing and
    sharing are human acts; a group cannot make a machine a person.

    **A personal token answers with its owner's effective role — step 033d — and the
    cap does not move.** `personal_owner` redirects the query to run as the owner
    (whose direct grants and group memberships the one statement already resolves),
    and the ceiling is then applied because the *caller* is a machine, whatever the
    owner holds. The redirection runs as (`user`, owner_id), so rows naming the token
    itself — a grant an admin was refused at the seam but somebody smuggled in, a
    group membership likewise — never enter the statement at all: a personal token is
    a cap, never a grant, by construction rather than by filter. `runnable_names`
    redirects through the same helper, which is what keeps the door's `tools/list`
    and this function from ever disagreeing about what the token may do.
    """
    subject = principal
    if principal.kind == "machine":
        subject = personal_owner(principal) or principal

    held = storage.active().agent_grant_role(
        principal.tenant_id, agent_name, subject.kind, subject.id
    )
    if held is not None and principal.kind == "machine":
        return _lowest(held, MACHINE_ROLES[-1])
    return held


def _lowest(*roles: str) -> str:
    """The weakest of these levels. The ladder's order is the meaning — see `AGENT_ROLES`."""
    return min(roles, key=_level)


def check(principal: Principal, agent_name: str, required: str = "user") -> bool:
    """Does this principal hold at least `required` on this agent?

    `required` defaults to the bottom of the ladder because the overwhelmingly common
    question is "may they run it?", and a default that answers the common question is
    one fewer place to write the wrong constant.
    """
    if required not in AGENT_ROLES:
        # A typo'd level is a check that can never pass, which is a denial that looks
        # like a policy. Same reasoning as a malformed scope pattern raising at config
        # load rather than at call time.
        raise ValueError(
            f"required must be one of {list(AGENT_ROLES)}, not '{required}'"
        )

    held = role_of(principal, agent_name)
    return held is not None and _level(held) >= _level(required)


def require(principal: Principal, agent_name: str, required: str = "user") -> str:
    """`check`, raising `NoAccess` instead of returning False. **Returns the role held.**

    The message names the agent and says nothing about why — it is the same string
    whether the agent is ungranted, at too low a level, or absent entirely.

    The return value arrives with 10d and exists for one caller: a screen with an
    owner-only delete and an editor-only edit has to know which of those to offer, and
    the alternative is buttons that answer 404 to the person they were rendered for. It
    is the role this function already had to compute, handed back rather than asked for a
    second time — and it stays the *ladder's* answer rather than a boolean per verb,
    because what a level permits is policy and lives in this module.
    """
    if required not in AGENT_ROLES:
        # The same refusal `check` makes, and it has to be here too: this function no
        # longer routes through it, and a typo'd level would otherwise be a comparison
        # against an index that does not exist.
        raise ValueError(
            f"required must be one of {list(AGENT_ROLES)}, not '{required}'"
        )

    held = role_of(principal, agent_name)
    if held is None or _level(held) < _level(required):
        log.info(
            "refusing %s:%s %s on '%s' in tenant %s",
            principal.kind,
            principal.id,
            required,
            agent_name,
            principal.tenant_id,
        )
        # Step 015: the refusal, written down. Best-effort — see `denials.record` —
        # and after the ValueError above, so a typo'd level stays a programmer error
        # rather than an attempt. Whether the agent *exists* is deliberately not
        # recorded: this function does not know, and must not learn — a second
        # storage read on the refusal path, purely for the log's benefit.
        denials.record(principal, "agent", agent_name, required, held or "")
        raise NoAccess(f"no agent named '{agent_name}'")
    return held


def runnable_names(principal: Principal) -> list[str]:
    """Every agent this principal may run, ordered by name.

    Every level of the ladder may run, so this is the whole grant list rather than a
    filtered one — the filtering would be a no-op that later reads as a rule.

    A personal token lists its owner's agents — the same `personal_owner` redirect
    `role_of` makes, from the same helper, because these two disagreeing is exactly
    the pre-selection-diverges-from-enforcement defect 021 recorded: the door's
    `tools/list` comes from here and the call path's `require` from `role_of`, and a
    tool listed but refused (or refusable but unlisted) would be that defect at the
    door's address.
    """
    subject = principal
    if principal.kind == "machine":
        subject = personal_owner(principal) or principal

    return storage.active().granted_agent_names(
        principal.tenant_id, subject.kind, subject.id
    )


# --- changing who has access ---------------------------------------------------------
#
# Each of these asks `require` first, so the policy is stated here once rather than at
# every call site. Storage refuses what is structurally impossible (a nonexistent agent,
# a second owner); this refuses what is merely not permitted.


def share(
    granter: Principal,
    agent_name: str,
    grantee_kind: str,
    grantee_id: str,
    role: str = "user",
) -> None:
    """Give somebody — or some group — access. Requires `editor`.

    An editor may share, which is the behaviour a Google Doc has and the one that was
    asked for. It also means access fans out without the owner being told — the cost of
    that model, accepted knowingly, and the reason `list_agent_grants` exists.

    **Sharing with a group still requires `editor` on the agent.** That is what keeps
    groups from being a way around the ladder: creating a group and filling it grants
    nobody anything until somebody who may already share this agent shares it.

    **A personal token is refused as a grantee — step 033d.** Its access is resolved
    through its owner, and rows naming it directly are never consulted (`role_of`
    queries as the owner), so a grant here could only do one of two dishonest things:
    report success and change nothing, or — if it were honoured — hand the token
    something its owner does not have, which is the escalation "a cap, never a grant"
    exists to prevent. `ShareRefused` rather than `NoAccess`, on this module's own
    distinction: the sharer has proved `editor`, and the sentence can safely say what
    to do instead. The refusal is the courtesy; the control is `role_of`'s
    construction, which a row smuggled past this seam still cannot reach.
    """
    require(granter, agent_name, "editor")

    if grantee_kind == "machine":
        owner = personal_owner(Principal.machine(grantee_id, granter.tenant_id))
        if owner is not None:
            raise ShareRefused(
                f"'{grantee_id}' is a personal token: it holds whatever its owner "
                f"({owner}) holds, capped at user, and never a grant of its own — a "
                "grant to the token could otherwise hand it something its owner does "
                "not have. Share the agent with the owner instead; every personal "
                "token they hold follows."
            )

    if role == OWNER_ROLE:
        if grantee_kind == "group":
            # Refused here rather than routed to `transfer`, because there is nothing to
            # route to: a group cannot own an agent at all. Storage and migration 017
            # would both refuse it, but neither produces a sentence about accountability.
            raise ShareRefused(
                f"'{grantee_id}' is a group, and a group cannot own an agent. Ownership "
                "is a person's name on the thing — a group-owned agent is one everybody "
                "may delete and nobody answers for. Share it at editor instead."
            )
        # Granting ownership is a transfer, and a transfer needs an owner's say-so.
        # Routing it through `transfer` rather than refusing keeps one path to one
        # outcome; storage would otherwise refuse this anyway, with a message about a
        # unique index rather than about permission.
        transfer(granter, agent_name, grantee_kind, grantee_id)
        return

    storage.active().grant_agent(
        granter.tenant_id,
        agent_name,
        grantee_kind,
        grantee_id,
        role=role,
        granted_by=f"{granter.kind}:{granter.id}",
        actor=f"{granter.kind}:{granter.id}",
    )


def share_by_email(
    granter: Principal, agent_name: str, email: str, role: str = "user"
) -> str:
    """Share with an address, the way a person actually thinks about it.

    Returns `"granted"` or `"pending"` — which one happened is invisible to the sharer
    by design, and is reported only so the CLI can say something true afterwards.

    Two paths, and the fork is not a policy decision but a fact about identity:

        somebody in this tenant already has that address  ->  a grant, immediately
        nobody by that address has ever logged in         ->  pending, until they do

    A `users` row is keyed `(issuer, subject)` and a subject only arrives inside a
    token, so there is no principal to name until a first login has happened. See
    migration 012.
    """
    require(granter, agent_name, "editor")

    address = normalize_email(email)
    if "@" not in address:
        raise ValueError(f"'{email}' is not an email address")

    store = storage.active()
    existing = store.find_user_by_email(granter.tenant_id, address)

    if existing is not None:
        # Already a principal here, so no domain check: whatever their address, this
        # customer's provider has already vouched for them and we created them for it.
        share(granter, agent_name, "user", existing["id"], role=role)
        return "granted"

    if role == OWNER_ROLE:
        # Reachable only through this function: `share` routes owner to `transfer`,
        # which needs a principal. Refused here with a sentence rather than being left
        # to the storage CHECK, because the caller is a person sharing something and the
        # answer is "not yet", not "invalid input".
        raise ShareRefused(
            f"nobody has logged in as '{address}', so ownership cannot be handed to "
            "them. An agent owned by an address that is never claimed is an orphan. "
            "Share it at editor, or wait until they sign in."
        )

    _check_domain(granter.tenant_id, address)
    store.add_pending_grant(
        granter.tenant_id,
        agent_name,
        address,
        role=role,
        granted_by=f"{granter.kind}:{granter.id}",
        actor=f"{granter.kind}:{granter.id}",
    )
    return "pending"


def _check_domain(tenant_id: str, email: str) -> None:
    """Refuse a share to a domain none of this customer's providers may vouch for.

    **The one place we deliberately do not behave like a Google Doc.** Docs lets you
    share with any address on earth. Here that address names somebody who can never
    authenticate into this tenant — every login is gated on the same domain list — so
    the grant is either inert forever or it is the first half of a route across the
    tenant boundary that the whole access layer exists to hold.

    Refusing at share time is also the only moment a person is present to be told why. A
    pending row that silently never lands looks identical to one waiting patiently, and
    the difference surfaces as "I shared that with her weeks ago" much later.

    **The wildcard is honoured here, and it was not for one step.** 016 taught
    `users._first_time` that `"*"` widens which domains may vouch; this function builds the
    same set and asked `domain not in allowed`, so against `{"*"}` every address failed and
    sharing refused everybody on the one deployment shape 016 exists to serve. Fail-closed,
    so nothing leaked — and invisible, because no test shared an agent in local mode. The
    lesson is the `groups.members` one again: two readers of one rule, and only the reader
    that was edited learned it. They now agree because this branch quotes the other's
    meaning rather than re-deriving it.
    """
    allowed = {
        domain.lower()
        for idp in storage.active().list_tenant_idps(tenant_id)
        for domain in (idp.get("allowed_domains") or ())
    }
    domain = email.rpartition("@")[2]

    if not allowed:
        raise ShareRefused(
            f"no identity provider for this customer may vouch for anybody, so "
            f"'{email}' could never log in. Register one with a --domain first."
        )
    if "*" in allowed:
        # A provider that is its own account authority. `_first_time` still requires an
        # address to exist before it creates anybody, and `normalize_email` upstream has
        # already refused anything that is not one, so there is nothing left to check.
        return
    if domain not in allowed:
        raise ShareRefused(
            f"'{email}' is not on a domain this customer's providers may vouch for "
            f"({', '.join(sorted(allowed))}), so they could never log in to use it."
        )


def claim_for(principal: Principal, email: str) -> list[str]:
    """Turn any grants waiting on this address into real ones. Returns what was claimed.

    Called from `access/users.py` at a first login and whenever a recorded address
    changes — not on every request, which would be an indexed query on the hot path to
    catch a case that is rare by construction.
    """
    if not email:
        return []

    claimed = storage.active().claim_pending_grants(
        principal.tenant_id, email, principal.kind, principal.id
    )
    if claimed:
        log.info(
            "claimed %d pending grant(s) for %s: %s",
            len(claimed),
            principal,
            ", ".join(claimed),
        )
    return claimed


def unshare(
    granter: Principal, agent_name: str, grantee_kind: str, grantee_id: str
) -> None:
    """Take access away. Requires `editor`; nobody may unshare the owner.

    The owner exemption is not politeness. Revoking the owner leaves the agent orphaned,
    and an editor who may orphan an agent may take it from the person who made it.

    ## Refusing to do nothing

    Since groups exist, a person can have access to an agent with no grant of their own,
    and there is no grant here to remove. Deleting nothing and reporting success is the
    worst available outcome: whoever ran it believes the access is gone, and stops
    looking. That is the same failure as reporting a cancel on a run that had already
    finished, and it is refused for the same reason.

    `ShareRefused` rather than `NoAccess`, and the distinction is the one this module's
    docstring draws: the caller has already proved `editor`, so the agent's existence is
    not a secret from them and the message can name the group and say what to do.
    """
    store = storage.active()
    require(granter, agent_name, "editor")

    # **Literal**, not resolving. `agent_grant_role` would answer `editor` for somebody
    # holding `user` directly and `editor` through a group, and the owner check below
    # would then be asking about a role nobody wrote down here.
    direct = store.direct_agent_grant_role(
        granter.tenant_id, agent_name, grantee_kind, grantee_id
    )
    if direct == OWNER_ROLE:
        raise NoAccess(
            f"'{grantee_id}' owns '{agent_name}'. Transfer it to somebody else first."
        )

    if direct is None and grantee_kind != "group":
        via = store.groups_granting_agent(
            granter.tenant_id, agent_name, grantee_kind, grantee_id
        )
        if via:
            named = ", ".join(f"group:{g}" for g in via)
            raise ShareRefused(
                f"'{grantee_id}' has no grant of their own on '{agent_name}' — their "
                f"access comes from {named}. Removing a grant that does not exist would "
                "report success and change nothing. Take them out of the group, or "
                "unshare the group itself."
            )

    # Still reached when there is nothing at all: revoking a grant nobody has is
    # idempotent, and always was. What is refused above is the case where the access is
    # real and this call would not have touched it.
    #
    # **`actor` is the parameter step 011 added**, and this is the call site it was added
    # for. Before it, the row carrying `granted_by` was deleted by a statement that
    # recorded nothing, so "who took Sam's access away" had no answer anywhere.
    store.revoke_agent(
        granter.tenant_id,
        agent_name,
        grantee_kind,
        grantee_id,
        actor=f"{granter.kind}:{granter.id}",
    )


def transfer(
    granter: Principal, agent_name: str, principal_kind: str, principal_id: str
) -> None:
    """Hand an agent to somebody else. Requires `owner`.

    The previous owner is demoted to `editor` rather than removed — the person handing an
    agent over almost never means "and lock me out of it", and if they do, that is an
    `unshare` afterwards, which they can no longer perform on themselves. Deliberate: a
    transfer that could also be a self-eviction is two decisions wearing one command.

    **The recipient is a principal.** The group guard is here as well as in `share`, and
    that is not belt-and-braces — it is the only one on this path. `share` routes an
    `owner` role to this function, and the CLI skips `share` entirely for a transfer, so
    a guard that lived only there was one every real caller went around. Found by running
    the command rather than by a test, which is how the last five of these were found.
    """
    if principal_kind == "group":
        raise ShareRefused(
            f"'{principal_id}' is a group, and a group cannot own an agent. Ownership is "
            "a person's name on the thing — a group-owned agent is one everybody may "
            "delete and nobody answers for, and there is nobody to hand it to next. "
            "Share it at editor instead."
        )

    require(granter, agent_name, OWNER_ROLE)

    storage.active().transfer_agent_ownership(
        granter.tenant_id,
        agent_name,
        principal_kind,
        principal_id,
        granted_by=f"{granter.kind}:{granter.id}",
        actor=f"{granter.kind}:{granter.id}",
    )


def who_has_access(reader: Principal, agent_name: str) -> list[dict]:
    """Everyone who can reach this agent, and **how**. Requires `user`.

    Deliberately readable at the bottom of the ladder: somebody about to run an agent
    that acts on their data should be able to see who else can reach it, and the list is
    of people already inside the tenant.

    ## Why the third column is a decision and not a nicety

    Since 9a a person can appear here with no grant of their own. Without saying so, the
    list is unactionable in the exact situation it is read in: an owner sees Sam, removes
    Sam, and Sam still has access. So every row carries where the access comes from:

        kind/id     who
        role        their EFFECTIVE role — the highest of direct and inherited
        direct      the role they hold in their own right, or None
        via         the groups they reach it through, possibly empty

    A group appears as a row of its own (`kind='group'`, `direct` set, `via` empty) as
    well as through its members, because revoking the group's grant is one of the two
    things an owner can do about an inherited access and it has to be visible.

    **This was the complete answer, and 033e is where it stopped being one.** With
    membership in a table we knew everybody. With it coming from a directory claim we
    know who has signed in and been placed in a group, not who *would* be — somebody
    added to `eng` in Entra this morning is not here until they next present a token
    that says so.

    The obligation `DEFERRED.md` recorded against this function was to **say so plainly
    rather than quietly return a shorter list**, and that is the `directory` field on a
    group's own row: true when the group carries an `external_id`. It is the
    `who_is_waiting` device — a different kind of fact, marked rather than merged — and
    both readers (the share sheet, `--agent-access`) turn it into the sentence. One
    `list_groups` call pays for it, in a function that is N+1 by design.

    Not one query, and deliberately: this is an owner reading a screen, not the run path.
    The hot-path constraint is on `agent_grant_role` and `granted_agent_names`, which are
    one statement each.
    """
    require(reader, agent_name, "user")
    return who_has_access_unchecked(reader.tenant_id, agent_name)


def who_has_access_unchecked(tenant_id: str, agent_name: str) -> list[dict]:
    """`who_has_access`'s answer, with **no check of any kind**. Read the name.

    Split out for exactly one caller — `cli.py`'s `--agent-access` — and named to be
    unpleasant to reach for, because the ladder above it is the whole point of this
    module and a function that skips it is a hole in the shape of a convenience.

    The reason it exists is step 072's drill: `system:cli` holds no *grant* on an agent
    somebody has taken over, so the operator holding `CARNET_DATABASE_URL` was told the
    agent did not exist by a check that could not have stopped them reading the table
    directly. The fix belongs at the entry point, not here: it is a *platform* role that
    earns this read, and `access/roles.py` states that these two ladders never consult
    each other — an admin role that implied agent access would rebuild the operator who
    holds everybody's data, which is what 7b exists to prevent. So this function takes a
    tenant and an agent, asks nobody's permission, and leaves the permission to the caller
    who has one to ask about. Nothing in `api/` may call it.
    """
    store = storage.active()

    rows = store.list_agent_grants(tenant_id, agent_name)

    # `dict` keyed by (kind, id) so somebody holding a grant directly *and* through a
    # group is one row saying both, rather than two rows disagreeing about their role.
    out: dict[tuple, dict] = {}

    # Which of this tenant's groups follow a directory. One statement, and only when a
    # group is actually named here — an agent shared with people alone pays nothing.
    from_directory = (
        {
            group["group_id"]
            for group in store.list_groups(tenant_id)
            if group["external_id"] is not None
        }
        if any(row["grantee_kind"] == "group" for row in rows)
        else set()
    )

    for row in rows:
        key = (row["grantee_kind"], row["grantee_id"])
        out[key] = {
            "kind": row["grantee_kind"],
            "id": row["grantee_id"],
            "role": row["role"],
            "direct": row["role"],
            "via": [],
            "granted_by": row["granted_by"],
            # Step 033e, and only ever true on a group's own row: a person's membership
            # is a row either way, and what is incomplete is the group's *list*, which is
            # the group's fact to carry. The kind is checked rather than relied on: ids
            # are prefixed per kind today, so `u_…` could not collide with a group id,
            # and a flag that is correct only because of a naming convention is the kind
            # of thing that stops being correct without a test noticing.
            "directory": (
                row["grantee_kind"] == "group" and row["grantee_id"] in from_directory
            ),
        }

    for row in rows:
        if row["grantee_kind"] != "group":
            continue

        group_id = row["grantee_id"]
        for member in store.list_group_members(tenant_id, group_id):
            key = (member["principal_kind"], member["principal_id"])
            entry = out.get(key)
            if entry is None:
                entry = out[key] = {
                    "kind": member["principal_kind"],
                    "id": member["principal_id"],
                    "role": row["role"],
                    "direct": None,
                    "via": [],
                    "granted_by": "",
                    "directory": False,
                }
            elif _level(row["role"]) > _level(entry["role"]):
                # Highest wins, and this is where decision 2 becomes visible to a person
                # rather than only to the check.
                entry["role"] = row["role"]
            entry["via"].append(group_id)

    for entry in out.values():
        entry["via"].sort()
        # The machine ceiling, applied to the *report* because it is applied to the
        # power. `role_of` caps a machine's effective role at `user` however it is
        # reached; a sheet that said `editor` about the same token would disagree with
        # enforcement on the one screen an auditor reads — the exact drift `via` exists
        # to prevent, arriving through the sheet's own aggregation. `direct` is left as
        # stored: it cannot exceed `user` (the CHECK), and what a *group* holds is the
        # group's fact, reported on the group's own row.
        if entry["kind"] == "machine":
            entry["role"] = _lowest(entry["role"], MACHINE_ROLES[-1])

    return sorted(out.values(), key=lambda r: (r["kind"], r["id"]))


def who_is_waiting(reader: Principal, agent_name: str) -> list[dict]:
    """Addresses shared with that have never logged in.

    Listed separately rather than merged into `who_has_access`, because they are a
    different kind of fact: nobody has this access, somebody *will* if a person ever
    arrives at that address. Merging them would report access that does not exist.

    This is also the only way to find a share that will never land — an address
    somebody's account does not actually carry. Nothing expires these.
    """
    require(reader, agent_name, "user")
    return storage.active().list_pending_grants(reader.tenant_id, agent_name)


def unshare_email(granter: Principal, agent_name: str, email: str) -> str:
    """Take access away by address, whether it landed or is still waiting."""
    require(granter, agent_name, "editor")

    address = normalize_email(email)
    actor = f"{granter.kind}:{granter.id}"
    existing = storage.active().find_user_by_email(granter.tenant_id, address)

    if existing is not None:
        unshare(granter, agent_name, "user", existing["id"])
        # A person can hold both: shared before they logged in, then again after. Clear
        # the pending row too, or a revoke silently leaves one armed. Storage records
        # this only if there *was* one, so the ordinary revoke does not also log a
        # cancellation that never happened.
        storage.active().delete_pending_grant(
            granter.tenant_id, agent_name, address, actor=actor
        )
        return "revoked"

    storage.active().delete_pending_grant(
        granter.tenant_id, agent_name, address, actor=actor
    )
    return "cancelled"
