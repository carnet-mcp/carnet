"""The administrative surface: who the caller is, and the log of who changed what.

Two routes, chosen because between them they prove the role seam from both directions —
one that any authenticated person may call and that *tells them* whether they are an
administrator, and one that refuses them if they are not.

## `GET /admin-audit` is the retirement of 011's most-argued deferral

Migration 022 built a log and left it readable only through `psql` and `--admin-log`, on
the grounds that *"a read route needs a tenant-admin role and this platform has none"* —
and its own reasoning against shipping the route anyway was the right one: *a route
retrofitted with authorization later is worse than no route*. So the authorization arrived
first and the route second, which is this file.

The thing it fixes is concrete rather than architectural: **a customer's operations team
cannot answer "who granted this person access" without a database client**, about a
product their staff use all day.

It is deliberately as cheap as `--admin-log`. `limit` and nothing else — no filters, no
pagination, no date range. Those arrive with evidence about what somebody actually needs,
and inventing them now would be guessing at a query shape that then has to be supported.

**Reading the log is not itself recorded.** `ADMIN_ACTIONS` records changes to
who-may-do-what, and a read changes nothing. An access log for reads is a different table
with a different retention question, and it is not smuggled in here as a rider.

## `GET /me` is not a settings surface

It exists because the SPA reads display claims off its own token, and a token knows
nothing about a row in `platform_roles`. Without it the application can only discover it
is not an administrator by rendering a nav item and watching the page behind it answer
403 — which is exactly the class of bug `AgentDetail.your_role` was added to prevent one
level down.
"""

import json
from datetime import date, datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse

from .. import __version__, config, door, metrics, storage
from ..tools import mcp
from ..access import roles, tokens, users
from ..core import Principal
from ..core import credentials
from ..core.usage import metered as usage_metered, price_buckets
from ..storage import (
    DECISIONS,
    DENIAL_RESOURCE_KINDS,
    IDENTITY_SOURCES,
    OUTCOMES,
    PRINCIPAL_KINDS,
    ValueRefused,
)
from ..tools.validation import VALID_EFFECTS
from .deps import admin_from_request, principal_from_request
from .schemas import (
    AdminDay,
    AgentTotals,
    ActingForTotals,
    AdminRecord,
    CallerTotals,
    BytesDay,
    DenialRecord,
    DoorCallRecord,
    DoorDay,
    DoorSpendDay,
    EffectDay,
    Headroom,
    LeaderboardTail,
    HourCell,
    IdentityDay,
    LatencyDay,
    Me,
    MintToken,
    MintedToken,
    Overview,
    OverviewTotals,
    OverviewWindow,
    OwnedToken,
    RefusalDay,
    SpentWindow,
    ToolTotals,
    ToolLatency,
    RefusalReason,
    Simulation,
    SimulationRequest,
    TokenReach,
    TokenRevoked,
    TokenSpend,
)

router = APIRouter(tags=["administration"])

# The four nullable stamps on a token row. Formatted at the boundary, like a run's, and
# named as a set so a field added to `API_TOKEN_PUBLIC_FIELDS` later is a `TypeError`
# here rather than a datetime leaking into a `str` field.
_TOKEN_STAMPS = frozenset(
    {"created_at", "expires_at", "revoked_at", "last_used_at"}
)


def _stamp(value) -> str | None:
    """A timestamp as this API reports it, or None for one that has not happened.

    None rather than an empty string: on a token these three nulls mean
    three different things a picker branches on — never expires, never revoked, never
    used — and an empty string would make "no expiry" and "expired at an unknown time"
    look alike.
    """
    return value.isoformat(timespec="seconds") if value else None

# The default and the ceiling. The default matches `--admin-log`'s `20` in spirit and not
# in number: a screen shows more than a terminal before somebody scrolls, and 200 is a
# page rather than a report. The cap is the honest half — without one, `?limit=10000000`
# is a request that reads a table with no upper bound on its size, and 011's known limit
# is that the table has no retention policy.
DEFAULT_ADMIN_LOG_LIMIT = 200
MAX_ADMIN_LOG_LIMIT = 1000


@router.get("/me", response_model=Me)
def me(principal: Principal = Depends(principal_from_request)):
    """Who you are in this workspace, and whether you may administer it.

    **No role required, and that is the point**: a non-administrator needs this precisely
    in order to be told they are not one, so that the application does not offer them a
    door that will refuse them.

    `email` and `display_name` come from **our** `users` row rather than from the token's
    claims — see `users.profile`. The short version: *which* claim holds the address is
    per provider (migration 010's `email_claim`, which exists because of a real token
    rather than a spec), so a route reaching into the JWT would report nothing for a
    customer on Entra while every other screen named the person correctly.

    Empty strings when there is no row, which is the `system` case: the CLI never calls
    this, and a route that raised for a principal it can describe most of would be worse
    than one that says less.
    """
    row = users.profile(principal)

    return Me(
        principal=f"{principal.kind}:{principal.id}",
        kind=principal.kind,
        email=row.get("email") or "",
        display_name=row.get("display_name") or "",
        admin=roles.is_admin(principal),
        # Step 044. The door's dialable address, from the same config the OAuth
        # callback is built from — the one origin fact a bundle cannot know.
        mcp_url=config.PUBLIC_ORIGIN.rstrip("/") + "/mcp",
    )


@router.get("/me/tokens", response_model=list[OwnedToken])
def my_tokens(principal: Principal = Depends(principal_from_request)):
    """The API tokens **you own**. Step 022b, and it is beside `/me` for `/me`'s reason.

    A schedule fires as a machine, and a person may only schedule the machines they own
    (`schedules.create`'s rule). So a browser that offers to create one has to be able to
    show somebody their own tokens — which nothing over HTTP could do, because token
    minting is CLI-only and no listing existed either.

    **This is deliberately narrower than the register's `GET /admin/tokens`**, which
    stays open with its own trigger. That row serves an operations team who cannot reach
    a shell and needs *everyone's*; this serves a person picking among their own, needs
    no role, and would be useless to them if it were admin-gated. Minting and revoking
    arrive one route down as of step 044 — for the caller's own tokens, sessions only;
    12b decision 5's refusal survives as the machine guard on the mint route. **Listing
    grants nothing**: every field here is one the owner could already read from
    `--list-tokens`, and the hash is not among them by construction, since
    `find_api_token` is the only storage method that returns it and this does not call it.

    **A machine caller gets an empty list**, not a refusal. A token owns nothing — the
    ownership rule requires a person, so `owner_id` never names a machine — and "you own
    no tokens" is a true and complete answer rather than an error about the question.

    Revoked and expired rows are included with the fields that say so. See `OwnedToken`:
    the listing is a record, and it is the picker that greys out what cannot be used.

    **`acts_as_owner` crosses here as of 035c and had not since migration 042** — not
    because this route changed (the comprehension below has always handed it in) but
    because `OwnedToken` had never declared it, and a model drops what it does not name.
    The one property deciding whether a credential carries its owner's whole access or
    only its own grants was readable from `--list-tokens` and from nowhere else.
    """
    # `kind` is checked and not just the id, for `_is_owner`'s reason: ids are minted per
    # population and nothing guarantees a machine's can never equal a person's. Returned
    # early rather than filtered on, because the empty `owner_id` a non-person would need
    # means *everyone* — this must not be the route that reaches that by arithmetic.
    if principal.kind != "user":
        return []

    rows = storage.active().list_api_tokens(
        principal.tenant_id, owner_id=principal.id
    )

    return [
        OwnedToken(
            **{
                key: _stamp(value) if key in _TOKEN_STAMPS else value
                for key, value in row.items()
                if key != "tenant_id"
            }
        )
        for row in rows
    ]


@router.post("/me/tokens", response_model=MintedToken, status_code=201)
def mint_my_token(
    body: MintToken, principal: Principal = Depends(principal_from_request)
):
    """Mint an API token **owned by the caller**, and show its secret once. Step 044.

    This is the route `tokens.mint`'s docstring said would never exist, and the refusal
    it recorded is kept rather than repealed — narrowed to what it always protected.
    12b decision 5's argument was that *a stolen bearer token would mint itself a
    durable successor*; the guard below makes that structurally impossible: **a machine
    principal is refused before anything else**, so no credential that survives its
    presenter can create another. What is newly allowed is a *session* minting — the
    same actor 022b let create a schedule and 023b let hold a trigger secret, with the
    same recorded cost: a stolen session can now mint standing authority without a
    terminal. What bounds it: the token is owned by the session's person (listed on
    their own `GET /me/tokens`, revocable one route down, dead when they are), a
    personal token is capped at its owner's access, and a service token minted here
    holds no grants until someone with share rights gives it some.

    **The owner is the caller, always** — there is no owner field to validate, which is
    most of the CLI's `_mint_token` made unnecessary rather than duplicated: the
    caller's existence and kind are established by authentication, not resolved from an
    address.

    The expiry ceiling is the CLI's exact rule: `>= 1` is the schema's, and further
    ahead than a date can be written is refused rather than clamped.
    """
    if principal.kind != "user":
        raise HTTPException(
            status_code=403,
            detail=(
                "a machine credential may not mint another. What a stolen bearer token "
                "lacks is persistence, and a mint route open to machines would hand it "
                "a durable successor — sign in as a person to mint a token you own."
            ),
        )

    expires_at = None
    if body.expires_days is not None:
        try:
            expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_days)
        except OverflowError:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"expires_days {body.expires_days} is further ahead than a date "
                    "can be written. If the intent is a token that does not expire, "
                    "leave it out — that is what 'no expiry' is spelled as."
                ),
            ) from None

    # An empty name would surface as the storage constraint's 400 either way; refusing
    # it here keeps the sentence about the field rather than about a column.
    if not body.name.strip():
        raise HTTPException(
            status_code=400,
            detail="a token needs a name — it is what `--list-tokens` and the tokens "
            "page show somebody deciding what to revoke.",
        )

    # `ValueRefused` (a duplicate live name) and `StorageError` fall through to their
    # registered handlers — 400 with the CLI's own sentence, and 503, respectively.
    row, presented = tokens.mint(
        principal.tenant_id,
        body.name.strip(),
        principal.id,
        actor=str(principal),
        expires_at=expires_at,
        acts_as_owner=body.acts_as_owner,
    )

    return MintedToken(
        token=presented,
        **{
            key: _stamp(value) if key in _TOKEN_STAMPS else value
            for key, value in row.items()
            if key != "tenant_id"
        },
    )


@router.delete("/me/tokens/{token_id}", response_model=TokenRevoked)
def revoke_my_token(
    token_id: str, principal: Principal = Depends(principal_from_request)
):
    """Revoke a token the caller owns. Step 044, and the mint route's other half.

    A mint surface without a revoke surface means a leaked secret waits for an operator
    with a shell; revocation must never be the hard direction. Authorized by
    `require_owner_or_admin` — deciding when a token's authority *ends* is the same act
    as holding it, the rule schedules and triggers already take — so an administrator
    can also end one here, exactly as `--revoke-token` could.

    Idempotent like the storage call under it: re-revoking answers 200 with
    `changed: false`, because "revoked just now" and "was already dead" are different
    facts (`MemberOutcome`'s device) and a 204 on both would collapse them.
    """
    token = tokens.require_owner_or_admin(principal, token_id)

    already = token.get("revoked_at") is not None
    if not already:
        token = storage.active().revoke_api_token(
            principal.tenant_id, token_id, actor=str(principal)
        )

    return TokenRevoked(
        id=token_id,
        revoked_at=_stamp(token.get("revoked_at")),
        changed=not already,
    )


@router.get("/me/tokens/{token_id}/reach", response_model=TokenReach)
def token_reach(
    token_id: str, principal: Principal = Depends(principal_from_request)
):
    """What this token is **granted** — the door's own answer, without the door.

    Step 035d. A token's reach is computable and was readable nowhere: the only way to
    find it out was to present the credential to `/mcp` and read `tools/list`, which
    needs the secret, at the moment somebody suspects the token is over-broad and
    therefore does not want to be using it. `door.reach` is `list_tools` with
    `require_machine` and the connector binding taken out — the same `_granted_agents`
    and `_granted_tool_names`, so the screen cannot develop a disagreement with the door
    about what a token can do.

    **Not admin-gated, and beside `/me/tokens` for its reason.** The audience is a
    non-administrator looking at their own credential. `require_owner_or_admin` is the
    rule — the *existing* one, written once and shared with the schedule and trigger
    surfaces, because a control written at one surface is a control the next surface does
    not have. It admits an administrator reading somebody else's token, which is fine a
    fortiori: the same function already lets them *aim* that token at an agent on a
    clock, and reading is strictly weaker than aiming. It is **absent from
    `deps.ADMIN_SURFACE` on purpose**, since it authorizes on who owns a row rather than
    on a role, and adding it there would fail
    `test_every_admin_route_carries_the_dependency` in its second direction — correctly.

    `ValueRefused` → 400 for an id this caller may not aim — one that does not exist
    and one that is somebody else's, in one sentence that cannot tell them apart, on
    028's rule since 069. It is `require_owner_or_admin`'s own sentence, unmodified.

    ## Reading a token is not using it, and this route proves it by omission

    `tokens.act_for` stamps `last_used_at`, and an offboarding review that moved the
    stamp by being conducted would corrupt the one question only that column answers.
    Plan 035 called for a non-touching variant of `act_for`; none is needed, because
    `require_owner_or_admin` already touches nothing — it calls `find_api_token` and
    stops — and `_granted_agents` needs only a `Principal.machine`, which is a
    constructor.

    ## Skipping `act_for` also skips its four liveness checks, and that is the decision

    A revoked token, an expired one, one whose owner is disabled, one in a suspended
    tenant: `act_for` refuses all four and **this route answers all four**. Stated here
    because it looks like an oversight and is not.

    *What could this token reach before I killed it* is the offboarding question, asked
    most often about a credential that has just been revoked — and a reach page answering
    *"refused: this token was revoked"* would be useless to precisely the person who came
    to read it, in the reassuring direction: they would read the refusal as *it reaches
    nothing*. So this answers what the grant rows say, which is the thing somebody is
    about to go and revoke, and the *listing* beside it carries the four stamps that say
    whether any of it can happen today. Two facts, two sources, neither pretending to be
    the other.

    The same holds one level down for a personal token: `personal_owner` reads the token
    row without consulting the owner's status, so a disabled owner's token still reports
    her grants here while the door refuses it at authentication.
    """
    row = tokens.require_owner_or_admin(principal, token_id)

    # Constructed rather than resolved. There is no secret in this request and none is
    # wanted: the tenant came from `row`, which `require_owner_or_admin` already proved
    # belongs to this caller's customer.
    machine = Principal.machine(token_id, row["tenant_id"])
    answer = door.reach(machine)

    # **Whose grants actually answered**, and asked of `personal_owner` rather than read
    # off `row["acts_as_owner"]` — which is right here and would be a second construction
    # site for the fact, the exact shape that function's docstring exists to prevent
    # ("which token is personal is decided here, so the door's list, the run path's
    # `require` and the broker's credential read cannot drift apart on it"). It costs one
    # primary-key lookup on a page read and buys that the two fields below cannot
    # disagree with each other. The `or machine` fallback is unreachable — the row exists
    # and its tenant matches, both just proved — and fails closed if that ever changes.
    whose = credentials.personal_owner(machine) or machine

    return TokenReach(
        token_id=token_id,
        acts_as_owner=whose.kind == "user",
        resolved_as=f"{whose.kind}:{whose.id}",
        **answer,
    )


@router.post("/me/tokens/{token_id}/simulate", response_model=Simulation)
def token_simulate(
    token_id: str,
    body: SimulationRequest,
    principal: Principal = Depends(principal_from_request),
):
    """Would this call be admitted, and which rule decided. Step 069.

    `door.simulate` is `call_tool` with everything that acts removed — the door's own
    `_granted_agents`, `_candidates` and `_adjudicate`, invoked without executing the
    tool. The discipline is `core.broker.call`'s: one code path, because a simulator with
    its own copy of the matcher is a second opinion about permission and the first time
    they disagree the simulator is believed.

    **Beside the reach route and authorized identically**, which is the whole of its
    access story. `require_owner_or_admin` is the rule the schedule, trigger, revoke,
    reach and budget surfaces already take, and since 069 it refuses a token that is not
    yours to aim in the sentence a token that does not exist gets — so *"a token they do
    not administer is refused indistinguishably from one that does not exist"* is a
    property of that function rather than a check written again here. It is **absent from
    `deps.ADMIN_SURFACE` on purpose**, for `token_reach`'s reason: it authorizes on who
    owns a row rather than on a role.

    **It writes nothing.** No `audit` row — there was no call, and every door-usage number
    reads that table. No `access_denials` row — that log is *who tried and was refused*,
    and a question is not an attempt. No `admin_audit` row — records there ride the
    transaction of the write they describe (`storage/base.py`, 011 decision 2) and this
    performs none. Plan 069 carries the argument that makes the absence defensible rather
    than merely convenient: every principal who reaches this can already compute its
    answer by hand, so the probe confers nothing there would be a point in recording. The
    register carries the trigger for when that stops being true.

    **`POST` is for the body.** `arguments` is a dict; the route is a read.

    Constructed rather than resolved, exactly as `token_reach` does — and here the
    construction is load-bearing rather than incidental. `grants.runnable_names` redirects
    a *personal* token through `personal_owner`, which makes simulating as the owner look
    right; it is not. `permissions._resolve` substitutes `${principal.id}` from the
    principal it is handed, and the broker is handed the **machine** principal on a real
    door call. Simulating as the owner would resolve that token to a user id the door
    never sees, and the simulator would disagree with the door on precisely the grants
    that use the feature.
    """
    row = tokens.require_owner_or_admin(principal, token_id)

    # **The door's own bound, at the door's own reason one door over.** `routes_mcp`
    # measures `arguments` against `MCP_MAX_CALL_BYTES` because what arrives lands in an
    # append-only table; nothing here lands anywhere, but the refusal *sentence* quotes
    # the value back, so without this a caller could send 200KB and be told 200KB. The
    # edge pass found it by sending 200KB.
    #
    # Measured on the serialized form for that module's reason: that, not the Python
    # object, is what crossed the wire.
    size = len(json.dumps(body.arguments, default=str).encode("utf-8"))
    if size > config.MCP_MAX_CALL_BYTES:
        raise ValueRefused(
            f"the arguments are {size} bytes, and the limit is "
            f"{config.MCP_MAX_CALL_BYTES} — the same one `tools/call` enforces, because "
            "this answers about that call. Only the arguments the tool declares as "
            "resources decide anything."
        )

    machine = Principal.machine(token_id, row["tenant_id"])

    return Simulation(**door.simulate(machine, body.tool, body.arguments))


# How much history the budget route answers with, in windows. Seven UTC days, ending
# today.
#
# **A constant and deliberately not a query parameter**, for two reasons. Plan 035's rule
# for a log route is `limit` and nothing else *"unless an incident asked for a filter"*,
# and none has; and `Failure` in the browser renders every 422 as *"This agent's
# configuration is not valid."* — a live `DEFERRED.md` row, and the reason 035b kept its
# filters out of the URL. A `days=` parameter with a server-side cap would answer an
# over-large value with a sentence about an agent's configuration, on a page that has
# neither an agent nor a configuration.
#
# Seven because the window is a day and the question is *is this the reason it stopped*,
# not *what is the trend*: long enough to see whether today is unusual, short enough to
# stay a figure. The answer is bounded by this rather than by a `limit`, so there is
# nothing here that could be truncated into a lie about completeness.
_BUDGET_WINDOWS = 7


@router.get("/me/tokens/{token_id}/budget", response_model=TokenSpend)
def token_budget(
    token_id: str, principal: Principal = Depends(principal_from_request)
):
    """What this token has **spent** through the MCP door, and against what ceiling.

    Step 035e. `mcp_budget` has been written on every admitted door call since migration
    040 and read by nothing outside the test suite — `mcp_calls_spent`'s own docstring
    said so: *"What reads this today is the suite."* So when a token starts refusing
    calls, the product said nothing about why. The refusal names the ceiling, and only
    the caller holding the credential ever sees it; the person who comes to a browser
    asking why the nightly job stopped at three has the token's id and no answer.

    **Authorized on `tokens.require_owner_or_admin`, beside `/me/tokens/{id}/reach` and
    for its reason** — the audience is a non-administrator looking at their own
    credential, and a role-gated answer would be useless to exactly them. So it is
    **absent from `deps.ADMIN_SURFACE` on purpose**, which
    `test_every_admin_route_carries_the_dependency` asserts in its second direction.

    The admin half is not a rider either, and 035d's build pass found the argument: a
    disabled person's session is refused at `api/deps.py` long before this route, so once
    somebody is offboarded the admin half is the **only** way this answer can be read at
    all — and *what was that credential spending before I killed it* is an offboarding
    question by construction.

    `ValueRefused` → 400 for an id this caller may not aim, not-yours and not-there in
    one sentence (069), `require_owner_or_admin`'s own and unmodified.

    ## Liveness is not this route's, exactly as it is not `reach`'s

    A revoked or expired token still answers. `test_a_revoked_token_keeps_its_counter`
    pins the storage half — revocation closes a door and deletes no evidence — and this
    inherits it by not checking. The listing row's four stamps say whether the credential
    works today; this says what it spent. Two facts, two sources, neither pretending to
    be the other.

    ## The window comes from the door, not from a second clock

    `door.budget_window()` is the same function `TokenBudget` freezes at construction. A
    `datetime.now(timezone.utc).date()` here would be a second definition of *which day
    is today*, and the failure it produces is one nobody would write a test for: a screen
    and a door disagreeing about whether a token is exhausted, for a few milliseconds a
    day, at the boundary.

    ## The list is dense, and the fill is a rule that already exists

    `mcp_call_windows` is sparse — it reports the table. The zero-fill is here because a
    window with no row **is** zero by `mcp_calls_spent`'s own documented contract, so
    this applies a semantic that already has a home rather than inventing a fact; and
    because the alternative is a browser doing the same fill, which would be a second
    implementation of it. A sparse list handed to a page also makes the page guess
    whether a gap is *no calls* or *no answer*, and those are different.
    """
    row = tokens.require_owner_or_admin(principal, token_id)

    window = door.budget_window()
    since = window - timedelta(days=_BUDGET_WINDOWS - 1)

    # Whose allowance this page is about — the door's own rule, not a second reading of
    # the row (step 108, decision 7). For a personal token the subject is the owner and
    # every figure below is theirs across every personal token they hold; the page says
    # so through `keyed_by`, because a count that silently included another machine's
    # morning would look wrong to the person reading it on this one.
    machine = Principal.machine(token_id, row["tenant_id"])
    owner = door.budget_owner(machine)
    spent = {
        entry["window_start"]: entry["calls"]
        for entry in storage.active().mcp_call_windows(
            row["tenant_id"],
            door.budget_subject(machine, owner),
            since=since,
            until=window,
        )
    }

    days = [
        (since + timedelta(days=offset)).isoformat()
        for offset in range(_BUDGET_WINDOWS)
    ]
    history = [SpentWindow(window_start=day, calls=spent.get(day, 0)) for day in days]

    ceiling = config.MCP_CALLS_PER_DAY

    # What this token spent at a model through the door today. Step 045b.
    #
    # **The same subject as `calls` above**, and it is worth saying why rather than
    # leaving it to be inferred: the money ceiling is written against a *principal*, and
    # at this door the principal is the credential — `api/deps.py` resolves a machine
    # token to `Principal.machine(token_id, tenant_id)` and `door.require_machine` refuses
    # every other kind. So the row this page is about and the subject the gate refuses are
    # one thing, and `Principal.machine` here is the door's own resolution repeated rather
    # than a second guess at it.
    #
    # Through `door.door_spend_today` rather than a query written here, because that is
    # the same function `TokenBudget._over_spend_ceiling` refuses from: one arithmetic, so
    # the figure on this page is the figure in the refusal. `spend_today`'s "one function,
    # two readers" rule, at the door.
    #
    # Read for a revoked or expired token too, matching everything above it: revocation
    # closes a door and deletes no evidence, and *what was that credential spending before
    # I killed it* is an offboarding question by construction.
    spend = door.door_spend_today(machine, owner=owner)
    usd_ceiling = config.MCP_USD_PER_DAY
    tokens_ceiling = config.MCP_TOKENS_PER_DAY

    # `days[-1]` rather than a second `window.isoformat()`, so `calls` and the last entry
    # of `history` are the same lookup and cannot disagree about today.
    return TokenSpend(
        token_id=token_id,
        keyed_by="owner" if owner is not None else "token",
        window=days[-1],
        calls=spent.get(days[-1], 0),
        usd=round(spend["usd"], 6),
        usd_ceiling=usd_ceiling,
        # Two flags rather than one, because the two dials are independent: a deployment
        # that bounds tokens without pricing anything has an honest $0 under a live token
        # ceiling, and a single flag would have to lie about one of them. Through
        # `core.usage.metered` for the reason `TokenBudget.metered` exists — the test is
        # `<= 0`, and a reader writing the obvious `== 0` would be wrong for a negative.
        usd_metered=usage_metered(usd_ceiling),
        tokens=spend["tokens"],
        tokens_ceiling=tokens_ceiling,
        tokens_metered=usage_metered(tokens_ceiling),
        unpriced_models=spend["unpriced_models"],
        # Read here rather than captured at import, matching `TokenBudget`: the dial is a
        # knob an operator turns mid-incident, and a page reporting a start-up value
        # would disagree with the door within a minute of somebody turning it.
        ceiling=ceiling,
        # Through the door's own predicate, because the comparison is `<= 0` and not
        # `== 0` — a negative value disables the dial too, and a second reader writing
        # the obvious equality would render a count of nothing as a count of calls.
        metered=door.TokenBudget.metered(ceiling),
        history=history,
    )


# The windows this route will answer for, and the only ones. Step 041.
#
# Fixed rather than free, on 035b's precedent and its recorded reason: an open `days=`
# needs a cap, and a cap needs a refusal, and a refusal on a dashboard is a page that
# will not load because somebody typed a big number into a URL. These three are a week
# (is today unusual), a month (the reporting period nearly every organisation runs on)
# and a quarter (the one a manager presents). Anything else lands on the nearest.
# What a leaderboard that cut nothing reports. A constant rather than a literal at five
# call sites, so "no tail" is one object and cannot be spelled two ways.
_NO_TAIL = {"n": 0, "calls": 0, "denied": 0}

_OVERVIEW_WINDOWS = (1, 7, 30, 90)
_DEFAULT_OVERVIEW_WINDOW = 30

# The window that buckets by the hour, and the only one. Step 066.
#
# A day drawn as one column beside a backdated month is an eleven-pixel sliver — the
# failure a walkthrough on 2026-08-31 found, where eleven real calls against days of
# 76–130 rendered as nothing and made a working demo look broken. Twenty-four columns of
# one day is legible at any volume, and no rescaling of a thirty-day chart is.
#
# One day and not two, because the bucket is what has to change and 48 hourly columns on
# a 720-wide plot is where the axis stops being readable. A reader who wants two days
# wants the week.
_HOURLY_WINDOW = 1


def _clamp_window(days: int) -> tuple[int, bool]:
    """The nearest offered window, and whether the ask was moved.

    Nearest rather than floor: a caller asking for 60 gets a quarter rather than a
    month, which over-answers instead of under-answering, and over-answering a question
    about *how much has been happening* is the safe direction.

    **Step 066 puts a 1 in the offered set**, which points that argument the other way at
    the bottom end: an ask for 3 now lands on 1 rather than 7, and under-answers. That is
    accepted rather than special-cased — 1 and 7 are one button apart, `clamped` still
    says the ask moved, and a tie-breaking rule that read *round up below a week and to
    the nearest above it* would be a second rule to remember for the sake of two days.
    """
    nearest = min(_OVERVIEW_WINDOWS, key=lambda offered: abs(offered - days))
    return nearest, nearest != days


def _previous_window(store, tenant_id: str, since: date, days: int, rates) -> OverviewTotals:
    """The same-length window immediately before this one, as totals. Step 066a.

    Ends the day **before** `since` and is the same number of days long, so the two
    windows are adjacent and equal and a percentage between them means something. An
    overlapping or shorter comparison window would produce a number that looks like a
    trend and is an artefact of the arithmetic.

    Priced with the *same* rate table object the current window was priced with, passed
    in rather than re-read: `door.rates_for` reads an operator's override file and the
    tenant's connector prices, and either edited between two calls inside one request
    would make this window and the last one disagree about what a model costs — a change
    in prices rendered as a change in usage.
    """
    end = since - timedelta(days=1)
    start = end - timedelta(days=days - 1)
    totals = store.overview_totals(tenant_id, since=start, until=end)

    usd, tokens, unpriced = price_buckets(totals["door_spend"], rates)
    return OverviewTotals(
        door_calls=totals["door_calls"],
        door_denied=totals["door_denied"],
        door_writes=totals["door_writes"],
        door_verified=totals["door_verified"],
        callers=totals["callers"],
        refusals=totals["refusals"],
        admin_changes=totals["admin_changes"],
        door_usd=round(usd, 6),
        door_tokens=tokens,
        door_unpriced_models=unpriced,
    )


def _labels(since: date, days: int, bucket: str) -> list[str]:
    """The dense axis a window fills against. Step 066.

    One list, produced here, and handed to every `_fill` below — so the columns of every
    figure on the page land on the same ticks and a reader comparing two charts is
    comparing the same days.

    The hour spelling is `YYYY-MM-DDTHH`, which is what both stores' bucket expressions
    produce and what `OverviewWindow.bucket` tells a client to expect. Twenty-four of
    them for the one-day window, and it is 24 rather than "up to now" deliberately: a
    chart that ended at the current hour would redraw its own width every sixty minutes,
    and the empty hours ahead are the day's remaining shape rather than missing data.
    """
    if bucket == "hour":
        return [f"{since.isoformat()}T{hour:02d}" for hour in range(24)]
    return [(since + timedelta(days=n)).isoformat() for n in range(days)]


def _fill(series: list[dict], days: list[str], model, **zero):
    """A sparse day-keyed series, made dense across `days`, as `model`.

    **The fill lives here rather than in either store**, which is `mcp_call_windows`'
    rule and its reason transfers whole: a store that filled its own gaps would be
    kinder than Postgres, and the contract suite exists to catch exactly that drift. A
    sparse list handed to a page also makes the page guess whether a gap is *nothing
    happened* or *no answer*, and those are different facts.

    `zero` is what a day with no rows means — `0` for every counter, and `None` for a
    percentile, because a day nothing was timed on is not a day of instant calls.
    """
    by_day = {row["day"]: row for row in series}
    return [model(**{**zero, "day": day, **by_day.get(day, {})}) for day in days]


@router.get("/admin/overview", response_model=Overview)
def overview(
    days: int = Query(default=_DEFAULT_OVERVIEW_WINDOW, ge=1, le=3650),
    principal: Principal = Depends(admin_from_request),
):
    """The window's activity, refusals and change — the screen a manager is briefed from.

    Step 041. **The door is the product** (`docs/PREMISE.md`): people connect their own
    assistant to `/mcp` and every tool call goes through the broker, and every series
    here is read from `audit` filtered to the door's own rows.

    **One route, eleven series, one loading state.** The page is the unit. Eleven routes
    would buy nothing but the chance for two of them to straddle a write and disagree
    about what happened, and a composable query API would be a BI tool.

    ## Admin-gated, and the audience tension is real

    On `ADMIN_SURFACE`, because tenant-wide governance data is what it is. The stated
    audience is a manager, and the only role that may read this today is platform
    `admin` — so granting somebody the chart grants them `role.grant` and
    `connector.delete` too. A read-only `viewer` role is the honest answer and is its own
    step: `platform_roles` CHECKs `'admin'` alone, so it is a migration plus a decision
    about which of the eleven admin reads it covers, and building it as a rider here is
    how a permission model grows by accretion. Until then the audience is the admins who
    brief the managers, and the page is built so a screenshot of its top is the briefing.

    ## The clamp is a flag, not a refusal

    `days` outside the three offered windows lands on the nearest and says so in
    `window.clamped`. A 400 would be a dashboard that will not load because of a URL, and
    a silent substitution would let somebody draw a quarter and label it a year.

    ## Two figures that are deliberately not read from the meter

    `headroom` comes from `audit`, never from `mcp_budget`. The meter writes nothing when
    the ceiling is not positive, so a deployment that measures without enforcing — the
    ordinary shape of a rollout — has heavy traffic and an empty table. `metered` is what
    says whether `ceiling` means anything, and when it is false the page prints observed
    volume and *not enforced* rather than a gauge against a limit that is off.
    """
    days, clamped = _clamp_window(days)

    # The same UTC day the door charges against — `budget_window()` is the one definition
    # of it, and a `date.today()` here would be a second one, disagreeing with the ceiling
    # for a few milliseconds a day at the boundary.
    until = door.budget_window()
    since = until - timedelta(days=days - 1)

    # Step 066. The hour is the bucket for exactly one window and the day for the rest,
    # decided here rather than in either store: the stores are told which grouping to
    # apply, and `_labels` below produces the matching dense axis. Two places deciding
    # independently is how a chart's columns and its labels come to be off by one.
    bucket = "hour" if days == _HOURLY_WINDOW else "day"
    store = storage.active()
    series = store.overview(
        principal.tenant_id, since=since, until=until, bucket=bucket
    )

    labels = _labels(since, days, bucket)

    door_calls = _fill(
        series["door_calls"], labels, DoorDay,
        allowed=0, denied=0, errored=0, oversize=0, ok=0, unknown=0,
    )
    identity = _fill(
        series["identity"], labels, IdentityDay, verified=0, asserted=0, none=0
    )
    effects = _fill(series["door_effects"], labels, EffectDay, read=0, write=0)
    refusals = _fill(
        series["refusals"], labels, RefusalDay,
        policy=0, ceiling=0, door_spend=0, run_budget=0, access=0,
    )

    # What the door cost, day by day. Step 045b, and the first money on this page.
    #
    # **Priced here, not in either store**, which is 045's Amendment 3 held for the third
    # time: the stores return token counts grouped by day and model, and the rate table
    # stays in `core/usage.py` where an operator can override it. A dollar figure computed
    # in SQL would be a frozen estimate nobody could reprice.
    #
    # `door.rates_for` rather than `config.model_rates()`, so a malformed override file
    # degrades this page to list prices with a log line instead of 500-ing it — the same
    # call the ceiling makes, so the page and the refusal price identically. **That
    # sentence is why this moved with step 086**: the ceiling now prices against the
    # tenant's connector prices too, and a page still reading `usage.rates()` would show
    # a figure the refusal disagreed with, which is the one thing "one function, two
    # readers" exists to prevent.
    priced_rates = door.rates_for(principal.tenant_id)
    by_day: dict[str, list] = {}
    # `by_model` rather than `bucket`, which now names the window's grouping four lines
    # up. The shadowing was harmless while nothing below the loop read the outer name and
    # would not have been the moment something did.
    for by_model in series.get("door_spend", []):
        by_day.setdefault(by_model["day"], []).append(by_model)

    spend_days = []
    for day in labels:
        usd, tokens, unpriced = price_buckets(by_day.get(day, []), priced_rates)
        spend_days.append(
            DoorSpendDay(
                day=day,
                # Rounded on the wire and never in the arithmetic: the sum below adds the
                # rounded days so the tile equals the chart, which is the disagreement a
                # reader would actually notice.
                usd=round(usd, 6),
                tokens=tokens,
                unpriced_models=unpriced,
            )
        )
    callers = [CallerTotals(**row) for row in series["callers"]]

    ceiling = config.MCP_CALLS_PER_DAY

    # The window before this one, as totals alone. Step 066a.
    #
    # **A second call to the same method rather than a widened one**, because what is
    # wanted is a denominator and not a dataset: `_totals_only` throws away every series
    # it reads. Widening `overview()` to return two windows would double the shape of the
    # one aggregating read in this interface to serve a percentage.
    #
    # It costs one more pass over a bounded window, and it buys every tile on the page the
    # difference between "4,120 calls" — a number nobody can size — and "4,120, up 18%".
    #
    # `None` where the deployment is younger than its own window: a confident `0%` there
    # would be the most misleading possible rendering of *we have not been running long
    # enough to say*, and `oldest_audit_day` is what tells them apart.
    previous = _previous_window(store, principal.tenant_id, since, days, priced_rates)

    return Overview(
        window=OverviewWindow(
            days=days,
            # The window's **dates**, not its first and last label. Identical for a
            # day-bucketed window and correct for an hour-bucketed one, where `labels[0]`
            # is `2026-08-31T00` and a footnote reading "2026-08-31T00 to 2026-08-31T23,
            # in UTC days" would be two kinds of wrong in one sentence.
            since=since.isoformat(),
            until=until.isoformat(),
            clamped=clamped,
            bucket=bucket,
        ),
        previous=previous,
        totals=OverviewTotals(
            door_calls=sum(day.allowed + day.denied for day in door_calls),
            door_denied=sum(day.denied for day in door_calls),
            door_writes=sum(day.write for day in effects),
            door_verified=sum(day.verified for day in identity),
            # The store's own count, never `len(callers)` — that list is the top
            # `LEADERBOARD` rows, and a tile reading its length would report the cap
            # as the answer on any tenant big enough for the tile to matter.
            callers=series["caller_count"],
            refusals=sum(
                day.policy + day.ceiling + day.run_budget + day.access
                for day in refusals
            ),
            admin_changes=sum(row["count"] for row in series["admin_actions"]),
            # Summed from the rounded days above rather than re-priced over the window,
            # so the tile is exactly what the chart adds up to.
            door_usd=round(sum(day.usd for day in spend_days), 6),
            door_tokens=sum(day.tokens for day in spend_days),
            # The union across the window, sorted — a model that could not be priced on
            # one day is a gap in this total whichever day it was.
            door_unpriced_models=sorted(
                {model for day in spend_days for model in day.unpriced_models}
            ),
        ),
        door_calls=door_calls,
        door_spend=spend_days,
        door_effects=effects,
        identity=identity,
        # 066a. Zero-filled like the counters and **null-filled for the percentile**,
        # which is `LatencyDay`'s rule reaching a second series: a bucket nothing was
        # measured in has a byte total of 0 and no 95th percentile at all.
        door_bytes=_fill(
            series.get("door_bytes", []), labels, BytesDay, bytes=0, p95_bytes=None
        ),
        # Percentiles fill with `None`, never 0 — see `LatencyDay`.
        door_latency=_fill(
            series["door_latency"], labels, LatencyDay, median_ms=None, p95_ms=None
        ),
        callers=callers,
        door_tools=[ToolTotals(**row) for row in series["door_tools"]],
        # 066. Every cap, with what it cut. The `.get` defaults keep this route working
        # against a store that predates the key rather than 500-ing the page.
        caller_tail=LeaderboardTail(**series.get("caller_tail", _NO_TAIL)),
        tool_count=series.get("tool_count", 0),
        tool_tail=LeaderboardTail(**series.get("tool_tail", _NO_TAIL)),
        # 066a. The dimensions every audit row carried and no figure grouped by.
        door_agents=[AgentTotals(**row) for row in series.get("door_agents", [])],
        agent_count=series.get("agent_count", 0),
        agent_tail=LeaderboardTail(**series.get("agent_tail", _NO_TAIL)),
        acting_for=[ActingForTotals(**row) for row in series.get("acting_for", [])],
        acting_for_count=series.get("acting_for_count", 0),
        acting_for_tail=LeaderboardTail(**series.get("acting_for_tail", _NO_TAIL)),
        refusal_reasons=[
            RefusalReason(**row) for row in series.get("refusal_reasons", [])
        ],
        refusal_reason_count=series.get("refusal_reason_count", 0),
        refusal_reason_tail=LeaderboardTail(
            **series.get("refusal_reason_tail", _NO_TAIL)
        ),
        tool_latency=[ToolLatency(**row) for row in series.get("tool_latency", [])],
        hourly=[HourCell(**row) for row in series.get("hourly", [])],
        headroom=Headroom(
            metered=door.TokenBudget.metered(ceiling),
            ceiling=ceiling,
            # The busiest single day in the window, allowed and denied together: the
            # question is how close the traffic came to a per-day limit, and a refused
            # call is traffic that arrived.
            busiest_day_calls=max(
                (day.allowed + day.denied for day in door_calls), default=0
            ),
            # Days on which *anything* was refused for hitting the ceiling — not how
            # many callers were, which `audit` cannot answer without a per-caller
            # refusal breakdown this route does not ask for. "On three of the last
            # thirty days somebody ran out of allowance" is the fact in hand, and it is
            # the one that says whether the dial is biting.
            days_at_ceiling=sum(1 for day in refusals if day.ceiling),
        ),
        refusals=refusals,
        # Not a per-day fill: this is one row per (day, family), so a dense version would
        # be every family on every day, mostly zeros, to draw a chart that stacks only
        # what happened. The page groups by day itself.
        admin_actions=[AdminDay(**row) for row in series["admin_actions"]],
    )


@router.get("/admin-audit", response_model=list[AdminRecord])
def admin_audit(
    limit: int = Query(default=DEFAULT_ADMIN_LOG_LIMIT, ge=1, le=MAX_ADMIN_LOG_LIMIT),
    principal: Principal = Depends(admin_from_request),
):
    """The administrative log, **oldest first**, most recent `limit` records.

    Ordered by insertion rather than by `ts`, matching `--admin-log` and `audit_records`:
    two records written in the same millisecond are ambiguous by timestamp and exact by
    insertion order, and a log is read forwards.

    403 for anybody without the `admin` role, with a sentence they can act on and no
    list of who to ask — see `RoleRequired`.

    `limit` is capped by the signature rather than by a branch, so an over-large value is
    FastAPI's 422 naming the field rather than a silent truncation. Silent truncation is
    the one behaviour a log route must not have: it reads as "that is everything".
    """
    return [
        AdminRecord(**{k: v for k, v in row.items() if k != "tenant_id"})
        for row in storage.active().admin_audit_records(
            principal.tenant_id, limit=limit
        )
    ]


@router.get("/admin/denials", response_model=list[DenialRecord])
def denials(
    limit: int = Query(default=DEFAULT_ADMIN_LOG_LIMIT, ge=1, le=MAX_ADMIN_LOG_LIMIT),
    principal_id: str | None = Query(default=None),
    resource_id: str | None = Query(default=None),
    # **Derived from the vocabulary rather than typed out again**, on
    # `AgentAccessEntry.kind`'s precedent and its recorded bug: a hand-written
    # `Literal["user", "system", "group"]` went stale against `GRANTEE_KINDS`, and the
    # first share sheet holding a machine grantee answered 500 with everything below it
    # correct. A fourth kind added to the frozenset and to migration 040's CHECK becomes
    # filterable here without anybody remembering to come and look — and, the direction
    # that matters more, cannot be forgotten here while being accepted there.
    resource_kind: Literal[tuple(sorted(DENIAL_RESOURCE_KINDS))] | None = Query(  # type: ignore[valid-type]
        default=None
    ),
    principal: Principal = Depends(admin_from_request),
):
    """The access-denial log, **oldest first**, most recent `limit` records.

    Step 015's read surface, on `/admin-audit`'s exact pattern: `admin_from_request`
    first — and a non-admin's attempt on this route lands in this very log, one row,
    not recursive, because the record is written where `require_admin` refuses and the
    reader is just another caller of it. The log records its own door.

    The two id filters are the two incident queries the table's indexes exist for:
    `principal_id` answers *"what else did this person probe?"*, `resource_id` answers
    *"who probed payroll-bot?"*. Both optional, and ids rather than kinds, because an
    incident starts from a name somebody already has.

    **`resource_kind` is 035b's one line of backend**, and it is a wire for a filter
    rather than a new one: `denial_records` has accepted it since 015 and this route
    simply never forwarded it. What it buys is *"which of these came from the door"* —
    `tool`, since migration 040 — answered by the server instead of by a client filtering
    a page it was already given, which would be a lie about completeness in a log view.

    **It is validated by the signature and the id filters are not**, and the asymmetry is
    the point. An id is whatever somebody was handed during an incident and this route has
    no opinion about its shape, so an id that matches nothing is honestly an empty answer.
    A kind is a closed vocabulary with a CHECK behind it, so `?resource_kind=tools` is not
    a question with no answers — it is a question the server does not have, and answering
    `[]` with a 200 would read as *"no tool denials"*. That is `limit`'s lie in a
    different costume, and it gets `limit`'s treatment: a 422 naming the field.

    `limit` is capped by the signature rather than by a branch, for the reason
    `/admin-audit`'s is: silent truncation is the one behaviour a log route must not
    have — it reads as "that is everything".
    """
    return [
        DenialRecord(**{k: v for k, v in row.items() if k != "tenant_id"})
        for row in storage.active().denial_records(
            principal.tenant_id,
            principal_id=principal_id,
            resource_id=resource_id,
            resource_kind=resource_kind,
            limit=limit,
        )
    ]


@router.get("/admin/door-calls", response_model=list[DoorCallRecord])
def door_calls(
    limit: int = Query(default=DEFAULT_ADMIN_LOG_LIMIT, ge=1, le=MAX_ADMIN_LOG_LIMIT),
    # The window, inclusive UTC dates — the same day boundary `/admin/overview` groups on
    # and `door.budget_window()` charges against, so a link from a chart column lands on
    # the day that column drew. `date` rather than a string, so FastAPI answers a
    # malformed one with a 422 naming the field instead of the store matching nothing.
    since: date | None = Query(default=None),
    until: date | None = Query(default=None),
    # The open filters. Unvalidated by design — `/admin/denials`' asymmetry, and its
    # argument transfers whole: an id or a name is whatever somebody was handed during an
    # incident, this route has no opinion about its shape, and one that matches nothing is
    # honestly an empty answer.
    tool: str | None = Query(default=None),
    agent: str | None = Query(default=None),
    principal_id: str | None = Query(default=None),
    acting_for: str | None = Query(default=None),
    # Step 108: the person, by email, across every personal token they hold.
    owner: str | None = Query(default=None),
    # The closed ones, and **every Literal below is derived rather than typed out**. The
    # bug that rule exists for is recorded: a hand-written `Literal["user","system",
    # "group"]` went stale against `GRANTEE_KINDS`, and the first share sheet holding a
    # machine grantee answered 500 with everything below it correct. A value added to a
    # CHECK and to its frozenset becomes filterable here without anybody remembering to
    # come and look — and, the direction that matters more, cannot be forgotten here
    # while being accepted there.
    principal_kind: Literal[tuple(sorted(PRINCIPAL_KINDS))] | None = Query(  # type: ignore[valid-type]
        default=None
    ),
    decision: Literal[tuple(sorted(DECISIONS))] | None = Query(  # type: ignore[valid-type]
        default=None
    ),
    outcome: Literal[tuple(sorted(OUTCOMES))] | None = Query(  # type: ignore[valid-type]
        default=None
    ),
    effect: Literal[tuple(sorted(VALID_EFFECTS))] | None = Query(  # type: ignore[valid-type]
        default=None
    ),
    identity_source: Literal[tuple(sorted(IDENTITY_SOURCES))] | None = Query(  # type: ignore[valid-type]
        default=None
    ),
    principal: Principal = Depends(admin_from_request),
):
    """The MCP door's traffic, **oldest first**, most recent `limit` records.

    Step 035a, on `/admin/denials`' exact pattern — and the debt four chunks of plan 033
    each deferred with the same sentence. Door calls have always written a full audit
    record; what they had never had was a reader. The rows with the most to say — whom a
    shared service said it was acting for, and whether that claim was verified — were
    the rows nothing could ask for.

    ## Ten filters, step 066, and why they arrive now

    This route took `limit` and nothing else for six steps, and it wrote down the
    condition for more: *"`/admin/denials` earned its two filters from the indexes
    migration 028 exists for; there is no equivalent index or incident argument here yet,
    and a filter added ahead of the query it serves is a guess with a signature."*

    **Both halves are met.** The incident argument is the Overview, whose every figure is
    a query somebody wants to run and which until 066 could not point at a single row
    behind any of its numbers — the aggregate and the record were two screens with no
    edge between them. The index is migration 050, `audit_door`, which is the partial
    index `door_call_records` has named as *the fix if it bites* since 035a; filtering is
    what makes it bite, because the backward walk that stops as soon as it has a page
    stops early only while every row it meets qualifies.

    **The closed vocabularies are validated by the signature and the open ids are not**,
    which is `/admin/denials`' asymmetry and is deliberate in both directions. An id is
    whatever somebody was handed during an incident, so `?tool=nonesuch` is honestly an
    empty answer. A kind is a closed set with a CHECK behind it, so `?decision=banana` is
    not a question with no answers — it is a question the server does not have, and
    answering `[]` with a 200 would read as *"no refusals"*. That is `limit`'s lie in a
    different costume and it gets `limit`'s treatment: a 422 naming the field.

    `since` and `until` are **inclusive UTC dates**, matching `/admin/overview`'s window
    and `door.budget_window()`'s day, so a link from a chart column covers exactly the
    column. Either may be given alone.

    **These filters are in the caller's URL, and that is new for a log screen here.**
    `DenialsPage` holds its filters in React state on purpose, because `Failure` rendered
    every 422 as *"This agent's configuration is not valid"* and a filter in a URL is one
    keystroke from `?decision=banana` — a screen answering a typo with a confident
    sentence about a different noun. `DEFERRED.md` recorded that with the fix and the
    trigger: *"it is worth doing before the second log screen wants the same thing."*
    This is the second log screen, so the fix ships with it rather than the workaround.

    403 for anybody without the `admin` role — and that refusal lands in the denial log,
    the same way this route's neighbour's does.

    `limit` is capped by the signature rather than by a branch, for the reason
    `/admin-audit`'s is: silent truncation is the one behaviour a log route must not have
    — it reads as "that is everything".
    """
    return [
        DoorCallRecord(**{k: v for k, v in row.items() if k != "tenant_id"})
        for row in storage.active().door_call_records(
            principal.tenant_id,
            limit=limit,
            since=since,
            until=until,
            tool=tool,
            agent=agent,
            principal_id=principal_id,
            principal_kind=principal_kind,
            acting_for=acting_for,
            decision=decision,
            outcome=outcome,
            effect=effect,
            identity_source=identity_source,
            owner=owner,
        )
    ]


@router.get("/metrics", response_class=PlainTextResponse)
def metrics_endpoint(principal: Principal = Depends(admin_from_request)) -> str:
    """Operational numbers, Prometheus text format. Step 057.

    The register's section D by its own name — "numbers somebody can watch": the
    session-pool gauges `MCP_SESSION_POOL_MAX`'s comment says to size the cap from,
    psycopg_pool's own counters for whoever sizes the database pool, and the broker's
    call counters, which count the product's unit of work at the one path every tool
    call takes.

    Admin bearer, in `ADMIN_SURFACE`: it is every caller's operational state and
    nobody's data, the same standing as the logs beside it — and a Prometheus scrape
    config carries a bearer as easily as a header. Counters are per process and reset
    on restart, which is what a Prometheus counter is; the gauges are read live under
    their own locks at scrape time and stored nowhere.

    Hand-rendered text exposition rather than a client library: counters and gauges
    need four lines of formatting, and the escaping below (backslash, quote, newline
    in label values) is the whole of what the format asks for them.
    """

    def esc(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

    lines = [
        "# TYPE carnet_build_info gauge",
        f'carnet_build_info{{version="{esc(__version__)}"}} 1',
    ]

    pool = mcp.POOL.stats()
    lines += [
        "# TYPE carnet_mcp_sessions gauge",
        f"carnet_mcp_sessions {pool['size']}",
        "# TYPE carnet_mcp_sessions_max gauge",
        f"carnet_mcp_sessions_max {pool['max']}",
        "# TYPE carnet_mcp_session_overflow_evictions_total counter",
        f"carnet_mcp_session_overflow_evictions_total {pool['overflow_evictions']}",
    ]

    for key, value in sorted(storage.active().pool_stats().items()):
        if isinstance(value, (int, float)):
            lines += [f"carnet_db_pool_{key} {value}"]

    counters: dict = {}
    for (name, labels), value in metrics.snapshot().items():
        counters.setdefault(name, []).append((labels, value))
    for name in sorted(counters):
        lines += [f"# TYPE {name} counter"]
        for labels, value in sorted(counters[name]):
            rendered = ",".join(f'{k}="{esc(v)}"' for k, v in labels)
            lines += [f"{name}{{{rendered}}} {value}" if rendered else f"{name} {value}"]

    return "\n".join(lines) + "\n"
