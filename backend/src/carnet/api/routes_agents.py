"""Agents over HTTP: read, create, and — as of 10d — edit, delete and share.

This file was read-only for four steps, and the docstring said why: creating an agent is
a form, a form is a product surface with its own questions, and guessing at them inside
a concurrency step is how both get done badly. Those questions have now been answered in
`docs/plans/010c-create.md`, and two of the answers are visible here.

**The request body is the config.** No creation-specific shape and no translation — see
`AgentDraft`, where the argument is made. The route's whole job is to establish who is
asking, hand the dict to `agents.create`, and turn its refusals into status codes.

**Creation is not a permission.** Every other write in this system is gated on a grant;
this one is gated on being authenticated in the tenant, and there is no third option.
There is no tenant-admin role and no platform role of any kind — `access/groups.py`
already refuses to be reachable over HTTP for exactly that reason — so the choice was
between "anybody in the tenant" and "nobody, until platform roles exist". 001 settles
it: *agent creation is self-serve; connector onboarding is not.* An agent is dangerous
only through the tools it is granted, every one of those was vetted by a connector admin
who is deliberately a different person, and the catalogue is where that control lives.

It does **not** mean anybody may grant anything. It means anybody may compose the
already-vetted things.

**`editor` is no longer half-inert.** It has had an editing half since migration 011 and
nothing to edit, because this file was read-only for four steps and 10c added two writes
neither of which was an edit. `PATCH` is the first caller of the level — and a *second*
editor is then possible, which is what makes last-write-wins a way for one person to
silently revert another's scope narrowing. Hence `If-Match`, and hence
`storage.update_agent`, which is where the guard has to live: read-then-write here has a
window between the two, and that window is the failure the ETag exists for.

**Delete is `owner`, and it is the one asymmetry worth arguing.** `unshare` already
refuses to revoke the owner on the grounds that *an editor who may orphan an agent may
take it from the person who made it* — and an editor who may **delete** it can do worse
than orphan it. The ladder in `access/grants.py` has said since 011 that `owner` is the
level that may "delete it, and hand it to somebody else"; this is the first code that
makes that sentence true.

**The grant routes are `PUT` and `DELETE` on a URL that names the grantee**, not a
`POST /share`. Granting is idempotent and keyed by who it is for — `grant_agent` has been
an upsert since 009 — and the URL is the key it upserts on.

What is still absent, deliberately: **creating a group**. `access/groups.py` requires a
`system` principal because there is no tenant-admin role, and its docstring says plainly
that an HTTP route before one exists is the mistake it guards against. Sharing *with* an
existing group needs `editor` on the agent, like every share, and is here.
"""

from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Response

from .. import agents, storage
from ..access import grants
from ..agents import InvalidAgentError
from ..core import Principal
from ..storage import AGENT_ROLES, GRANTEE_KINDS
from .deps import principal_from_request
from .schemas import (
    AgentAccess,
    AgentAccessEntry,
    AgentCreated,
    AgentDetail,
    AgentDraft,
    AgentPatch,
    AgentRename,
    AgentSummary,
    AgentVersion,
    AgentVersionSummary,
    DoorActivity,
    DoorRefusal,
    DraftVerdict,
    GrantOutcome,
    GrantRequest,
    PendingGrant,
)

router = APIRouter(tags=["agents"])


def _summary(
    config: dict, error: str | None = None, agent_id: str = ""
) -> AgentSummary:
    """One agent as a list row.

    `agent_id` is passed rather than read out of the config, because it is not in there:
    migration 035 put it on the row, and the config is what a person authored. A default of
    `""` keeps this callable from the one place that has a config and no row — the dry run
    in `POST /agents/validate`, which is validating something that does not exist yet and
    therefore has no identity to report.
    """
    return AgentSummary(
        name=config.get("name", "?"),
        id=agent_id,
        # No default since 081. A config that names no tier reports none; substituting
        # `DEFAULT_RUNTIME` here made a list row assert something the stored config does
        # not say, which is `AgentDraft.runtime`'s defect read back out.
        runtime=config.get("runtime"),
        tools=list(config.get("permissions", {}).get("tools", [])),
        valid=error is None,
        error=error,
    )


def _why_invalid(tenant_id: str, config: dict) -> str | None:
    """The validator's own sentence, or None. Never a paraphrase.

    One function so the list route and the detail route cannot develop two opinions
    about what "broken" looks like — which is the drift decision 4 closes.
    """
    try:
        agents.validate(tenant_id, config)
    except InvalidAgentError as exc:
        return str(exc)
    return None


def _etag(row: dict) -> str:
    """`agents.updated_at` as an entity tag.

    Quoted, because an ETag is a quoted-string by RFC 9110 and a client that copies the
    header verbatim into `If-Match` must produce something this server parses back. Full
    precision, for the reason `AgentDetail.updated_at` is: it is compared to a TIMESTAMPTZ
    by a SQL predicate, and a value rounded to the second matches no row ever written.
    """
    return f'"{row["updated_at"].isoformat()}"'


def _if_match(header: str) -> datetime:
    """`If-Match` as the timestamp the compare-and-set needs. Raises 428 or 400.

    **Required, and its absence is a 428 rather than a permissive write.** A `PATCH` with
    no precondition is last-write-wins, which is the single thing this step exists to
    refuse: it is how one person silently reverts another's scope narrowing, and it
    fails silently by construction. 428 Precondition Required is the status invented for
    exactly this — *"the origin server requires the request to be conditional... to
    prevent the lost update problem"* — and it tells a client author what to send rather
    than that their body was wrong.

    A malformed one is a 400 and not a 412: nothing was compared, so nothing failed a
    precondition. `*` is refused for the same reason — it means "if the thing exists",
    which is a question this route already answered and not the one being asked.
    """
    value = header.strip()
    if not value:
        raise HTTPException(
            status_code=428,
            detail=(
                "this request needs an If-Match header carrying the agent's updated_at, "
                "which GET /agents/{name} returns as `updated_at` and as an ETag. "
                "Without it a save cannot tell 'nothing changed' from 'somebody else "
                "edited this while you had it open', and the second one silently wins."
            ),
        )

    stamp = value.removeprefix("W/").strip('"')
    try:
        parsed = datetime.fromisoformat(stamp)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{header}' is not a usable If-Match. Send back the `updated_at` this "
                "API gave you, unchanged — it is an ISO-8601 timestamp, and truncating "
                "it matches no version of anything."
            ),
        ) from None

    if parsed.tzinfo is None:
        # A naive timestamp is a different instant in every deployment that reads it,
        # which is the same refusal `check_connection` makes about `expires_at`.
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{header}' has no time zone. Send back the `updated_at` this API gave "
                "you, unchanged."
            ),
        )
    return parsed


def _require_agent(principal: Principal, name: str, level: str = "user") -> tuple[dict, str]:
    """The grant check, then the row. **The order is load-bearing.**

    `grants.require` first and always, for the reason api/errors.py gives: an ungranted
    agent and an absent one must be indistinguishable, and an error path is the easiest
    place to reopen that leak. Reading the row first and checking after would answer 404
    for one and something else for the other.

    The 404 below is not reachable through the grant path — `agent_grants` has a foreign
    key to `agents` and cascades, so a grant cannot outlive its agent — and it is here
    because "unreachable" is a claim about today's schema and the failure it would
    otherwise become is a 500.

    Returns the row **and the role the caller holds**, which `require` had to compute
    anyway. See `AgentDetail.your_role` for the one screen that needs it.
    """
    role = grants.require(principal, name, level)

    row = storage.active().get_agent(principal.tenant_id, name)
    if row is None:
        raise HTTPException(status_code=404, detail=f"no agent named '{name}'")
    return row, role


@router.get("/agents", response_model=list[AgentSummary])
def list_agents(principal: Principal = Depends(principal_from_request)):
    """The agents **shared with this caller**, including the broken ones.

    `agents.load()` skips an invalid row and logs it, which is right for a CLI listing
    and wrong here: a form user whose agent stopped working needs to see it in the list
    with the reason attached. An agent that vanishes from the UI when it breaks is one
    somebody re-creates rather than fixes.

    So this reads the rows and validates them itself rather than calling `load()`.

    The grant filter is applied to the **rows**, not to the summaries, so a broken agent
    somebody has no grant on is absent for the access reason before the validation reason
    ever runs. Both would hide it; only one of them is a decision, and if the ordering
    were reversed a fixed config would make somebody else's agent appear.
    """
    visible = set(grants.runnable_names(principal))
    return [
        _summary(
            row["config"],
            error=_why_invalid(principal.tenant_id, row["config"]),
            agent_id=row["agent_id"],
        )
        for row in storage.active().load_agents(principal.tenant_id)
        if row["name"] in visible
    ]


@router.post("/agents", response_model=AgentCreated, status_code=201)
def create_agent(
    draft: AgentDraft,
    response: Response,
    principal: Principal = Depends(principal_from_request),
):
    """Create an agent, owned by whoever asked.

    **Not `agents.save()`**, and the distance between the two is one line of SQL. `save`
    is an upsert, which is right for `--seed` and catastrophic here: it would let this
    request silently replace an agent somebody else owns, and nothing on that path would
    notice — `agents.validate` checks configs rather than grants, and a write to `agents`
    consults no grant table at all. `agents.create` inserts, and a name that exists is
    the 409 below.

    **Ownership is claimed in the same transaction as the row**, inside the store. Four
    handoffs have carried the warning that nothing creates an agent with an owner except
    migration 011 and `--seed`, and absence is denial — so a create that wrote the row
    and then failed to write the grant would ship an agent nobody can run, including the
    person looking at the response. That state is invisible: the row is fine, the list is
    empty, and the agent is indistinguishable from one they were never given.

    Status codes, and the two that are decisions:

        201  with a Location header, because the thing now has a URL
        409  a name this tenant already uses. Never a replacement
        422  a config the validator refuses, in the validator's own sentence
    """
    config = draft.to_config()
    agents.create(principal.tenant_id, config, principal.kind, principal.id)

    # The URL of the agent, not of this API's prefix. A client behind the `/api` proxy
    # (see frontend/src/lib/api.ts) rewrites it or ignores it; what it must not do is
    # guess, and a Location header on a 201 is the one place a caller is entitled to
    # stop guessing.
    response.headers["Location"] = f"/agents/{config['name']}"
    return AgentCreated(name=config["name"], owner=str(principal))


@router.post("/agents/validate", response_model=DraftVerdict)
def validate_draft(
    draft: AgentDraft,
    principal: Principal = Depends(principal_from_request),
):
    """A dry run over the same validator. Writes nothing.

    The UX argument is real and secondary: a wizard whose last step fails with a server
    error is a wizard nobody trusts. **The primary argument is testability.** 010b's
    finding is that a form which derives its scope from the catalogue cannot violate
    `_validate_scope_matches_tools` in either direction — and a claim of the form "cannot
    by construction" is worth exactly the test behind it. Without this route that test
    has to create rows and clean them up, which means it is either slow, or flaky, or
    quietly not written.

    It runs `validate_draft` rather than `validate`, so it answers the question the
    wizard is asking — *would create accept this?* — including the reserved name. The one
    thing it cannot answer is whether the name is free: that is a race whatever asks it,
    and it is a 409 rather than a 422.

    **Authenticated, and no grant**, for the same reason `GET /tools` is: it discloses
    nothing but the shape of what the caller just typed back to them. There is nothing
    here to have a grant on — the agent does not exist, which is the point.
    """
    agents.validate_draft(principal.tenant_id, draft.to_config())
    return DraftVerdict()


def _detail(tenant_id: str, row: dict, role: str) -> AgentDetail:
    config = row["config"]
    permissions = config.get("permissions") or {}
    return AgentDetail(
        **_summary(
            config,
            error=_why_invalid(tenant_id, config),
            agent_id=row["agent_id"],
        ).model_dump(),
        system=config.get("system", ""),
        scope=permissions.get("scope", {}) if isinstance(permissions, dict) else {},
        limits=config.get("limits", {}),
        updated_at=row["updated_at"].isoformat(),
        your_role=role,
        version=row["version"],
        config=config,
    )


@router.get("/agents/{name}", response_model=AgentDetail)
def get_agent(
    name: str,
    response: Response,
    principal: Principal = Depends(principal_from_request),
):
    """One agent, with its grants split into capability and reach.

    **This answered 422 for a broken agent until 10d, and that is a decision revisited
    rather than a bug patched** — `api/errors.py` argues the 422 deliberately. The
    revision: it answers **200 with `valid: false` and the validator's own sentence**,
    which is the shape `GET /agents` has used since 10a on the argument that *an agent
    that vanishes from the UI when it breaks is one somebody re-creates rather than
    fixes*. Listing broken agents with their reason and then refusing to open them is two
    representations of one state, and the second is exactly the agent somebody has come
    here to fix. Editing is the cure, and this is the screen you edit from.

    The 422 **moves rather than disappearing**, which is what keeps it honest:

        GET  /agents/{name}     200  valid: false, error: "<the validator's sentence>"
        POST /runs              422  the same sentence, because running it cannot happen
        PATCH /agents/{name}    200  or 422 if the patch does not fix it

    So this does not call `agents.get()`, which raises. It reads the row and validates it
    itself — the same thing `list_agents` does, for the same reason, and now through the
    same function so the two cannot disagree.

    **The ordering stays load-bearing.** `grants.require` runs first inside
    `_require_agent` and must continue to: an ungranted agent and an absent one must be
    indistinguishable, and an error path is the easiest place to reopen that.
    """
    row, role = _require_agent(principal, name)

    # The precondition a PATCH sends back, in the header a client already knows how to
    # read as well as in the body. Both, because a browser app holds the parsed JSON and
    # a `curl` user holds the headers, and neither should have to construct the other.
    response.headers["ETag"] = _etag(row)
    return _detail(principal.tenant_id, row, role)


@router.get("/agents/{name}/door-activity", response_model=DoorActivity)
def door_activity(
    name: str, principal: Principal = Depends(principal_from_request)
):
    """Has anyone knocked on this agent through the MCP door. Step 044.

    Two scalars for the connect card's waiting state — the ten minutes after somebody
    pastes the endpoint into their assistant. Authorized like every other read on the
    agent (`user`), not admin: whether an agent is being used is a fact its users may
    know, while the *content* of calls stays on `/admin/door-calls`. The grant check
    runs first for `_require_agent`'s reason — an ungranted agent and an absent one
    must be indistinguishable, on this route as on its neighbours.
    """
    row, _ = _require_agent(principal, name)

    # The 404 rule, restated for 070: *the last thing refused here* is a reconnaissance
    # answer at any address but this one, and it sits behind the same grant the count
    # does — `_require_agent` ran first, and an ungranted viewer never reaches this line.
    store = storage.active()
    tools = list((row["config"].get("permissions") or {}).get("tools") or [])
    refusal = store.last_door_refusal(principal.tenant_id, tools)

    return DoorActivity(
        **store.door_call_summary(principal.tenant_id, name),
        last_refusal=(
            DoorRefusal(
                at=refusal["ts"],
                tool=refusal["resource_id"],
                token=refusal["principal_id"],
                reason=refusal["required"],
            )
            if refusal
            else None
        ),
    )


@router.patch(
    "/agents/{name}",
    response_model=AgentDetail,
    responses={
        400: {"description": "a name that differs from the URL, or a bad If-Match"},
        409: {"description": "somebody else edited it; the body says which keys differ"},
        422: {"description": "the merged config is one the validator refuses"},
        428: {"description": "no If-Match, so a lost update could not be detected"},
    },
)
def patch_agent(
    name: str,
    patch: AgentPatch,
    response: Response,
    principal: Principal = Depends(principal_from_request),
    if_match: str = Header(default="", alias="If-Match"),
):
    """Change part of an agent. **`editor`, and conditional on `If-Match`.**

    ```
    PATCH /agents/triage-bot
    If-Match: "2026-08-08T04:12:33.482391+00:00"
    {"system": "...", "permissions": {"tools": [...], "scope": {...}}}

    200  the agent, with its new updated_at
    409  {"detail": "...", "updated_at": "...", "changed": ["permissions"]}
    422  the validator's own sentence
    404  no grant, or no agent — the same 404
    400  a name that differs from the URL
    428  no If-Match
    ```

    **A partial config, merged at the top level**, and a key nobody sends is untouched.
    See `agents.merge`, where the finding this retires is written down: an edit form built
    from the create form deletes `default_task` and `deny_demo_task` on the shipped agent,
    and nothing anywhere reports it. The field survives because the form never sends it,
    rather than because somebody remembered to carry it.

    **`name` is not patchable.** A body carrying one that differs is a 400 rather than a
    silent ignore — renaming touches the URL, the grants, the runs and every audit record,
    and telling somebody it worked when it did not is the worse of the two failures.
    """
    if patch.name is not None and patch.name != name:
        raise HTTPException(
            status_code=400,
            detail=(
                f"this is /agents/{name} and the body names '{patch.name}'. An agent's "
                "name is its URL, its storage key, the identity the broker enforces "
                "against and the string in every record of what it did — renaming one is "
                "a separate operation and this is not it. Remove `name` from the body, "
                "or send this to the other agent's URL."
            ),
        )

    # The grant check before anything else, including before the precondition is parsed:
    # a 428 or a 400 on an agent you have no grant on would say it exists.
    _, role = _require_agent(principal, name, "editor")
    unchanged_since = _if_match(if_match)

    row = agents.update(
        principal.tenant_id,
        name,
        patch.to_patch(),
        actor=str(principal),
        if_unchanged_since=unchanged_since,
    )
    if row is None:
        # Deleted between the grant check and the write. The same 404 as an agent that
        # was never there, which is the same 404 as one you may not see.
        raise HTTPException(status_code=404, detail=f"no agent named '{name}'")

    response.headers["ETag"] = _etag(row)
    return _detail(principal.tenant_id, row, role)


@router.post(
    "/agents/{name}/rename",
    response_model=AgentDetail,
    responses={
        409: {"description": "another agent already has that name"},
        422: {"description": "a name the rules refuse, or the name it already has"},
    },
)
def rename_agent(
    name: str,
    body: AgentRename,
    response: Response,
    principal: Principal = Depends(principal_from_request),
):
    """Give an agent a different name. **`owner`.** Step 025.

    ```
    POST /agents/triage/rename
    {"new_name": "support-triage"}

    200  the agent at its new name, with a new ETag
    409  another agent already has that name
    422  a name the slug rules or the reserved list refuse; or the name it already has
    404  no grant, or no agent — the same 404
    ```

    **Everything survives it**: the grants, the pending grants, the schedules, the
    triggers, the whole version history, the follow-up threads and the run history. That
    is what migration 035 bought — until it, `agents` was keyed by name and the only way to
    change one was to create a second agent and delete the first, which cascades away every
    one of those things. A rename was a delete wearing a rename's clothes, so there was no
    rename.

    **`owner`, not `editor`, and that is the one access decision here.** An editor changes
    what an agent *does*; this changes what it *is called*, which is the URL somebody
    bookmarked, the string in every dashboard, and the name an outside system's runbook
    says to use. `delete` and `transfer` are the other two operations at that altitude and
    both are `owner`.

    **A POST rather than the PATCH that already exists.** `PATCH /agents/{name}` answers a
    body-borne `name` with a 400 whose whole job is to teach that a name is not a field you
    edit — see that route, where the sentence is written — and quietly turning the most
    destabilising thing an agent's address can undergo into a success on that same path
    would repurpose an error into a feature. A separate verb also gives the operation its
    own grant level, which the paragraph above needs.

    **No `If-Match`.** An edit form races another edit form and needs a precondition; a
    rename is one deliberate act from an owner, serialized on the row. The second of two
    concurrent renames finds no agent by the old name and gets the 404 that is true.

    **The old URL is a 404 afterwards, deliberately.** There is no redirect and no memory
    of former names: a name freed by a rename has to be genuinely free, including free of
    ghost routing, or the next agent to take it inherits an address that points somewhere
    else. The cost is real and is a register row — the owner who renames owns the broken
    bookmarks.
    """
    _require_agent(principal, name, "owner")

    row = agents.rename(
        principal.tenant_id, name, body.new_name, actor=str(principal)
    )
    if row is None:
        # Deleted, or renamed by somebody else, between the grant check and the write. The
        # same 404 as an agent that was never there.
        raise HTTPException(status_code=404, detail=f"no agent named '{name}'")

    response.headers["ETag"] = _etag(row)
    # `owner`, because `_require_agent` just insisted on it and a rename cannot change a
    # grant. Re-reading the role would be a second query for an answer already held.
    return _detail(principal.tenant_id, row, "owner")


@router.delete("/agents/{name}", status_code=204)
def delete_agent(name: str, principal: Principal = Depends(principal_from_request)):
    """Delete an agent. **`owner`, and it is a real delete.**

    Soft-delete was considered and refused. A disabled agent still holding grant rows is
    a row that grants nothing and looks like access, which is the artifact this codebase
    has refused three times — `NO_SUCH_GROUP`, the group-delete trigger, and
    `delete_agent`'s own cascade.

    So the row goes, `agent_grants` and `pending_grants` cascade, and `audit` and
    `admin_audit` keep the history because neither has a foreign key that would take it.
    `agent.delete` names who did it, as of step 11.

    **There is no undo.** `admin_audit` records that it happened and the record holds the
    agent's tools and scope — enough to rebuild it by hand, deliberately not enough to
    make an undo button look feasible.

    Its **runs** stay in the table, and since this step they stay readable to whoever
    started them. See `GET /runs`: visibility follows the agent, which is what an owner
    needs, and a deleted agent grants nobody anything — so a run you submitted is visible
    to you regardless. What that does *not* close is the owner's list view of what their
    deleted agent did, which needs run-level visibility that does not follow the agent.

    Idempotent at the storage layer and **not** from here: `_require_agent` answers 404
    for an agent that is already gone, because it is also the answer for one you may not
    see, and this route cannot tell those apart without saying which.
    """
    _require_agent(principal, name, "owner")
    agents.delete(principal.tenant_id, name, actor=str(principal))


# --- version history -----------------------------------------------------------------
#
# Step 021. `update_agent` overwrote, and `admin_audit` records that a config changed and
# deliberately never what it said, so before migration 032 no past version was
# reconstructible from anything this system kept.
#
# **Reading history is `user`**, the same level that reads the agent. A runner can already
# read today's system prompt through `GET /agents/{name}`, so inventing a second
# confidentiality level for the same bytes at a different age would be a rule that reads
# as a control and is not one. Restoring is `editor`, like every other write.


@router.get("/agents/{name}/versions", response_model=list[AgentVersionSummary])
def list_agent_versions(
    name: str, principal: Principal = Depends(principal_from_request)
):
    """Every configuration this agent has had, newest first. **`user`.**

    Capped rather than paginated, on section D's row: every list in this API is, and a
    second convention here would make it two problems. An agent edited more than the cap
    has an older history that is present in the table and not returned.

    **A no-op save is absent from this list and present in the administrative log**, and
    the difference is the design rather than an omission. The history holds distinct
    *states*; the log holds *writes*. Somebody asking "who saved this on Tuesday" is
    asking the log; somebody asking "what did it say on Tuesday" is asking this.
    """
    _require_agent(principal, name)
    return [
        AgentVersionSummary(**{**row, "created_at": row["created_at"].isoformat()})
        for row in agents.versions(principal.tenant_id, name)
    ]


@router.get(
    "/agents/{name}/versions/{version}",
    response_model=AgentVersion,
    responses={404: {"description": "no such agent, no grant, or no such version"}},
)
def get_agent_version(
    name: str, version: int, principal: Principal = Depends(principal_from_request)
):
    """One stored configuration, whole. **`user`.**

    The 404 covers three different facts on purpose — no such agent, no grant on it, and
    no such version — and only the third is new. The first two are `_require_agent`'s
    existing anti-enumeration rule; the third joins them because answering *"that agent
    exists and has no version 9"* to somebody without a grant would be the same leak
    through a number instead of a name.
    """
    _require_agent(principal, name)
    try:
        row = agents.version(principal.tenant_id, name, version)
    except agents.NoSuchVersion as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    return AgentVersion(**{**row, "created_at": row["created_at"].isoformat()})


@router.post(
    "/agents/{name}/versions/{version}/restore",
    response_model=AgentDetail,
    responses={
        400: {"description": "a bad If-Match"},
        404: {"description": "no such agent, no grant, or no such version"},
        409: {"description": "somebody else edited it; the body says which keys differ"},
        422: {"description": "this version would no longer validate"},
        428: {"description": "no If-Match, so a lost update could not be detected"},
    },
)
def restore_agent_version(
    name: str,
    version: int,
    response: Response,
    principal: Principal = Depends(principal_from_request),
    if_match: str = Header(default="", alias="If-Match"),
):
    """Put an old configuration back. **`editor`, and conditional on `If-Match`.**

    ```
    POST /agents/triage-bot/versions/3/restore
    If-Match: "2026-08-13T04:12:33.482391+00:00"

    200  the agent, now at a NEW version whose content is version 3's
    409  {"detail": "...", "updated_at": "...", "changed": [...]}
    422  this version would no longer validate — the sentence says why
    404  no grant, no agent, or no version 3
    428  no If-Match
    ```

    **A restore is a new version, never a pointer moving back.** Restoring 3 while 7 is
    live writes 8, and 3 stays exactly where it is. A moving pointer would make the
    timeline non-monotonic — *what was live on Tuesday* would need a second log recording
    every move, which is a history of the history — and it would leave a bad restore with
    nothing to undo it. This way the restore is itself restorable.

    **This route exists because a client cannot compose it**, which is a finding rather
    than a convenience. `PATCH` merges at the top level, so a key the old config does not
    have survives from the live one: fetching version 3 and PATCHing it back produces
    neither version whenever a field was added since, silently, while the screen says it
    worked. There is no way to remove a field over HTTP at all — see `agents.merge` — so
    no sequence of requests expresses this.

    An empty body: the version in the URL is the whole request.
    """
    # The grant check before the precondition is parsed, for `patch_agent`'s reason: a
    # 428 on an agent you have no grant on would say it exists.
    _, role = _require_agent(principal, name, "editor")
    unchanged_since = _if_match(if_match)

    try:
        row = agents.restore(
            principal.tenant_id,
            name,
            version,
            actor=str(principal),
            if_unchanged_since=unchanged_since,
        )
    except agents.NoSuchVersion as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None

    if row is None:
        # Deleted between the grant check and the write. The same 404 as an agent that
        # was never there, which is the same 404 as one you may not see.
        raise HTTPException(status_code=404, detail=f"no agent named '{name}'")

    response.headers["ETag"] = _etag(row)
    return _detail(principal.tenant_id, row, role)


# --- who has access ------------------------------------------------------------------


@router.get("/agents/{name}/access", response_model=AgentAccess)
def agent_access(name: str, principal: Principal = Depends(principal_from_request)):
    """Everyone who can reach this agent, **and how**, plus who is still waiting.

    `user`, matching `who_has_access`, and deliberately the bottom of the ladder:
    somebody about to run an agent that acts on their data should see who else can reach
    it, and the list is of people already inside the tenant.

    Two lists rather than one. A pending grant is a different kind of fact — nobody has
    that access, somebody *will* if a person ever arrives at that address — and merging
    them would report access that does not exist.

    **`who_has_access` is N+1**, one query per group grant. Deliberate since 9a on the
    grounds that it is an owner reading a screen rather than the run path — and this is
    the step that puts it behind a screen somebody reloads, so it is worth watching for
    the first time.
    """
    # `require` is inside both calls below, at `user`. Called anyway so that an agent
    # that does not exist and one nobody shared with you answer alike, rather than the
    # first producing an empty sheet.
    _require_agent(principal, name)

    return AgentAccess(
        access=[AgentAccessEntry(**row) for row in grants.who_has_access(principal, name)],
        waiting=[
            PendingGrant(
                email=row["email"], role=row["role"], granted_by=row.get("granted_by", "")
            )
            for row in grants.who_is_waiting(principal, name)
        ],
    )


# --- changing who has access ---------------------------------------------------------
#
# `PUT` and `DELETE` on a URL that names the grantee, rather than `POST /share`. Granting
# is idempotent and keyed by who it is for — `grant_agent` has been an upsert since 009 —
# and the URL is the key it upserts on. That also makes the revoke the obvious `DELETE`
# on the same URL, where a `POST /unshare` would be a second vocabulary for one thing.
#
# `kind` is `user`, `system`, `group` or **`email`**, which is not a grantee kind and is
# the point of the fourth: an address is how a person actually thinks about sharing, and
# whether it lands as a grant or as a pending row is a fact about whether that person has
# ever logged in rather than a choice the sharer makes. `access/grants.py` owns that fork.

_EMAIL = "email"


@router.put("/agents/{name}/grants/{kind}/{grantee}", response_model=GrantOutcome)
def put_grant(
    name: str,
    kind: str,
    grantee: str,
    request: GrantRequest,
    principal: Principal = Depends(principal_from_request),
):
    """Share an agent. **`editor`**, which is what `access/grants.share` requires.

    ```
    PUT /agents/triage-bot/grants/user/u_1fbb    {"role": "editor"}
        -> 200 {"outcome": "granted", ...}
    PUT /agents/triage-bot/grants/email/sam@acme.com  {"role": "user"}
        -> 200 {"outcome": "pending", ...}   nobody by that address has logged in
    ```

    **The outcome is reported, and 006 deliberately hid it.** `granted` and `pending` look
    identical on a screen and only one of them means anybody has access; a sharer who
    cannot tell them apart discovers the difference as "I shared that with her weeks ago".

    Idempotent: re-sharing changes the level, which is what an upsert keyed by grantee
    means and is the behaviour a person expects from a share box they type into twice.

    `role: "owner"` is a **transfer**, and `share` routes it to `transfer`, which requires
    `owner` rather than `editor`. Not special-cased here: one path to one outcome, and the
    guard lives in the only function every caller goes through — which is the lesson 9a
    learned by typing the command.

    A refused share is a **400** through `ShareRefused` — a group at `owner`, an address
    on a domain no provider may vouch for — and never the 404 `NoAccess` becomes. The
    caller has already proved `editor`, so the agent's existence is not a secret from
    them and the sentence can say what is wrong. Collapsing those two once told an
    operator who owned an agent that it had not been shared with them.
    """
    _require_agent(principal, name, "editor")

    _check_role(request.role)

    if kind == _EMAIL:
        outcome = grants.share_by_email(principal, name, grantee, role=request.role)
        return GrantOutcome(
            outcome=outcome, kind=_EMAIL, id=grantee, role=request.role
        )

    _check_kind(kind)
    grants.share(principal, name, kind, grantee, role=request.role)
    return GrantOutcome(outcome="granted", kind=kind, id=grantee, role=request.role)


@router.delete("/agents/{name}/grants/{kind}/{grantee}", status_code=204)
def delete_grant(
    name: str,
    kind: str,
    grantee: str,
    principal: Principal = Depends(principal_from_request),
):
    """Take access away. **`editor`**, and nobody may revoke the owner.

    The owner exemption is not politeness: revoking the owner leaves the agent orphaned,
    and an editor who may orphan an agent may take it from the person who made it. That
    is a 404 through `NoAccess`, because the sentence names the owner.

    **Revoking somebody whose access is inherited is refused, loudly.** Since groups
    exist, a person can reach an agent with no grant of their own — deleting nothing and
    reporting success is the worst available outcome, because whoever pressed it believes
    the access is gone and stops looking. `unshare` answers `ShareRefused`, a **400**,
    with a sentence naming the group. The share sheet is meant to say the same thing
    before anybody presses it; this is what happens when it does not.

    Revoking a grant nobody had is idempotent and silent, and always was.
    """
    _require_agent(principal, name, "editor")

    if kind == _EMAIL:
        grants.unshare_email(principal, name, grantee)
        return

    _check_kind(kind)
    grants.unshare(principal, name, kind, grantee)


def _check_role(role: str) -> None:
    """A 400 for a level that is not one, rather than a storage error at 503.

    The same shape as `_check_kind` and found the same way — by asking the route for
    `{"role": "admin"}` and getting *"storage unavailable"*, which tells somebody to try
    again later about a word that will never be a level. `check_agent_role` refuses it in
    the store too and must keep doing so; this is what turns it into an answer.
    """
    if role not in AGENT_ROLES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{role}' is not a level. The ladder is {list(AGENT_ROLES)}: `user` may "
                "run it, `editor` may also change and re-share it, and `owner` may also "
                "delete it and hand it on."
            ),
        )


def _check_kind(kind: str) -> None:
    """A 400 for a kind that is not one, rather than a storage error at 503.

    The store refuses this too — `check_grantee_kind` — and would arrive here as a 503
    saying the database is unavailable, which is the wrong thing to tell somebody who
    typed a URL wrong.
    """
    if kind not in GRANTEE_KINDS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{kind}' is not something a grant can name. Use one of "
                f"{sorted(GRANTEE_KINDS)}, or '{_EMAIL}' to share with an address "
                "whose owner may not have logged in yet."
            ),
        )
