"""The MCP door, tool mode: what a machine token may see and call through `/mcp`.

Step 033b — decisions 1 through 4 of `docs/plans/033-mcp-door.md`, built as
`docs/plans/033b-mcp-door-tool-mode.md`. This is the tier `api/routes_mcp.py` speaks to;
that module owns JSON-RPC framing and nothing else, and this one owns what a door call
is.

## What the door buys, and what it deliberately does not

**Distribution, not capability.** Every call admitted here is already possible in the
product's own chat. What it displaces is fifty personal tokens on fifty laptops: without
it each employee installs the GitHub MCP server locally under a credential nobody can
revoke and nothing records. With it, one brokered endpoint with per-caller scope, a
budget, an audit trail, and a token that can be revoked without moving the URL.

So **nothing about enforcement is new here**, and that is the whole reason this step is
cheap. A tool-mode call is one `broker.call` — the same five steps, the same audit
record, the same credential resolution 033a settled. What this module adds is the three
questions the broker has never had to answer for itself because a run always answered
them first:

    which agent is this call attributed to?     `_candidates`, and the union rule below
    what bounds a caller with no run?           `TokenBudget`, and migration 040
    what may this token even see?                `list_tools`, which IS the grant list

## The union rule, and the one place decision 2 was a sentence short

Decision 2: *a token in tool mode sees the union of the tools of the agents it is
granted, each tool keeping its own agent's scope*. Names are the easy half. Scope is not,
because one tool can appear in several granted agents with different scopes — `triage`
may read `acme/*` while `security-triage` reads `acme/secrets`, and both grant
`search_issues`.

**The illustration used to be `acme/secrets-*` and that pattern matches nothing**, which
step 069 found by simulating one. `core/patterns.py` compares whole segments on purpose —
prefix confusion, where `org/*` quietly also matches `org-evil/repo`, is meant to be
inexpressible rather than remembered — so `*` is a whole segment and `secrets-*` is the
literal string `secrets-*`. The same illustration is in plans 035d and 067, which are
records and stay as written; `DEFERRED.md` carries the row.

The rule that makes the sentence true of scope as well as of names: **a call is allowed
if any granted agent carrying the tool would allow it**, and that agent is the one the
call is attributed to. Any other reading makes the union false in one direction or the
other — picking one agent arbitrarily would refuse calls the caller is plainly granted,
and unioning the *scopes* would invent a permission nobody wrote down.

`_candidates` is ordered by agent name so the attribution is deterministic, and
`permissions.check` — the broker's own pure function, not a copy of it — is what decides.
Using the same function is the point: a pre-selection that disagreed with enforcement
would be 021's `role_of` defect at a new address, where the screen and the control
disagree about the same fact.

## A door call is not a run

Decision 4, and it is a vocabulary decision with a storage consequence. A tool-mode call
has no prompt, no config and no version, so a `runs` row would be untrue about all three,
and the run list — which people read to answer "what has this agent been doing" — would
start containing things that are not runs.

It still needs an id, because the audit record correlates on one. `new_call_id` mints a
deliberately distinct shape (`door-<hex>`), so a door call can never be mistaken for a
run, `runs.get`'s prefix lookup can never match one, and the audit log is filterable by
prefix for whoever wants only the door's traffic.

## What is not here, and where it lands

**Agent mode** (an agent as one MCP tool, `tools/call` submitting a run and holding for
the answer) is decision 1's other half and its own chunk.

**Acting-for** landed here in step 033c, and the division of labour is worth stating
because three modules each hold exactly one piece. The wire shape — one `_meta` key,
bounded before anything reads it — is `api/routes_mcp.py`'s. What a claim is *worth* —
verifying a forwarded token against this tenant's own IdP, or believing an address —
is `access/acting.py`'s. What this module owns is the one rule that needs both tools
and identity in scope and therefore can live nowhere else: **asserted identity is
believed only where the tool's connector opted in** (`allow_asserted_identity`). The
resolved value rides the call's context, changes whose account a `user`-identity tool
resolves, lands on every audit record — and changes authorization not at all: the
grants checked below are the token's, before and after.
"""

import logging
import uuid
from datetime import datetime, time, timedelta, timezone

from . import agents, config, storage, tools
from .access import acting, denials, grants, oauth
from .access.users import AccessDenied
from .core import Principal, RunContext, broker, credentials, permissions
from .core.principal import ActingFor
from .core.credentials import DELEGATED
from .core.permissions import ALLOW, Decision
from .core.usage import RATES as usage_RATES
from .core.usage import day_window, metered, price_buckets, rates
from .storage import SPEND_REFUSAL_MARKER
from .tools import mcp

log = logging.getLogger(__name__)

# What a door call's correlation id looks like. `door-` because the one thing it must
# never be is mistakable for a run: `runs.get` matches on a run-id prefix, the run list
# is a place people look to understand what their agents did, and a tool-mode call is
# none of those things. Twelve hex characters, matching `context.new_run_id` — the same
# collision arithmetic applies and the same answer does, which is that a duplicate is a
# correlation somebody has to untangle rather than two customers' records merging.
#
# **Bound to the storage constant rather than spelled here, since 035a.** The prefix is
# now load-bearing in two layers — this module mints ids with it, `door_call_records`
# filters the audit log on it — and storage is the lower one, which imports nothing from
# the app. Two literals would be two values free to disagree, and the disagreement would
# be silent: ids the reader no longer matches, and a door-traffic page that simply looks
# empty. One name, one definition, and this alias is what keeps callers reading
# `door.CALL_ID_PREFIX` where it belongs.
CALL_ID_PREFIX = storage.DOOR_CALL_ID_PREFIX


def new_call_id() -> str:
    return f"{CALL_ID_PREFIX}{uuid.uuid4().hex[:12]}"


class DoorRefused(RuntimeError):
    """This token may not call this tool, and no policy engine had to decide it.

    Raised for a name that is in **no** agent this token is granted — which is a
    different fact from a broker denial and must not be dressed as one. Nothing was
    authorized, nothing was scoped, and there is no agent to attribute an audit record
    to; inventing one would put a row in an append-only table naming an agent that had
    nothing to do with the call.

    The refusal is still written down, as an `access_denials` row — see `call_tool`.
    That is the log built for exactly this: an attempt on a named thing, refused.

    Safe to explain, on `ShareRefused`'s reasoning: `tools/list` has already shown this
    caller its entire union, so naming what is not in it tells them nothing they could
    not have worked out from the list they were handed a moment ago.
    """


class ToolUnavailable(RuntimeError):
    """A granted tool could not be made callable at all, so there was nothing to broker.

    Its own class, and deliberately not a `DoorRefused`: nothing was refused. Two things
    reach here, and the message says which — the customer's own MCP server did not
    answer, or (when nothing has bound it yet) the caller's own connected account for it
    cannot be read. The honest answer names the one that happened rather than implying a
    permission problem, and the second must never be dressed as the first: *your server
    is down* and *your account expired* send two different people to two different fixes.

    **No audit record**, and that is consistent rather than an omission: the audit log is
    the record of brokered *decisions*, and in-product a connector that will not bind
    fails the run at `ensure_available` without writing one either. A door call that
    never reached the broker did not have a decision made about it.

    Note the asymmetry `call_tool` works hard to preserve: whenever the tool *is* bound, a
    credential problem is not this exception at all — the call proceeds and the broker
    produces both the refusal and the record, which is the treatment the same fact gets
    when the caller simply has no connection row.
    """


# --- the budget ---------------------------------------------------------------------

# The phrase that identifies a **ceiling** refusal in the audit log after the fact, for
# step 041's overview. **Bound to the storage constant, exactly as `CALL_ID_PREFIX`
# above is**, and for the identical reason — two layers need it, storage is the lower
# one, and one name is what keeps them from drifting apart in silence. The reasoning is
# with the definition.
CEILING_REFUSAL_MARKER = storage.CEILING_REFUSAL_MARKER


def budget_window():
    """Which UTC day a door call is charged to. **The only definition of it.** Step 035e.

    One line, and it is a function because it acquired a second caller: `TokenBudget`
    below freezes it at construction, and `GET /me/tokens/{id}/budget` has to read the
    same day back or the screen and the door disagree about whether a token is exhausted.

    That disagreement would last a few milliseconds a day, at the boundary, and nothing
    would test for it — which is exactly the kind of second definition this codebase has
    paid for before (`role_of`, the union rule, `personal_owner`). One home instead.

    UTC rather than anybody's local day, and it is migration 040's policy rather than
    storage's: *"this layer stores a counter keyed by a window; it has no opinion about
    how long a window is."* The opinion is here.
    """
    return datetime.now(timezone.utc).date()


def rates_for(tenant_id: str) -> dict:
    """The rate table in force for one tenant. Step 086, 080's E5.

    Three sources of a price, least authoritative first:

        core.usage.RATES        our dated snapshot — "not an authority", and it says so
          overridden by
        binding.pricing         the vetter who registered this vendor's key
          overridden by
        CARNET_MODEL_RATES    the operator who set this deployment's table on purpose

    **The middle one is what this step adds.** Before it, a price could only be written
    into a JSON file on the server, by whoever can reach the filesystem — very often not
    the person who registered the OpenAI key and knows what their contract says. So a
    non-Anthropic model was unpriced unless two different people coordinated, and the
    door reported `unpriced_models` rather than pretending otherwise.

    **An operator's file still *replaces* the built-in rather than layering over it**,
    which is 013's posture and is preserved exactly: somebody who set that variable did
    so because our numbers are wrong for them, and quietly filling their gaps from the
    table they rejected would produce a plausible figure computed from it. So the
    built-in is the base only when there is no override, and connector prices fill in
    from underneath in either case.

    With no override and no connector pricing this returns `core.usage.RATES` and every
    figure in the deployment is what it was.

    Uncached, and one read of this tenant's connectors. `mcp.connectors_for` says why it
    holds no cache — *"the failure mode of getting that wrong is not a stale read, it is
    one tenant serving another tenant's allowlist"* — and a price is not a revocation but
    it is still a row somebody just edited expecting to see it take effect.
    """
    override = rates()
    composed = {} if override is not None else dict(usage_RATES)

    for connector in mcp.connectors_for(tenant_id):
        for vetted in connector.vetted:
            composed.update((vetted.binding or {}).get("pricing") or {})

    if override is not None:
        composed.update(override)
    return composed


def door_spend_today(principal, *, now=None) -> dict:
    """What this principal's door calls have spent since midnight UTC. Step 045b.

    `runs.spend_today`'s sibling on the product's side of the door, and deliberately its
    exact shape — `{window, usd, tokens, unpriced_models, by_model}` — because it is the
    same *"one function, two readers"* argument: the gate below refuses from this and
    `GET /me/tokens/{id}/budget` renders from it, so nobody is shown one number and
    refused by another.

    The premise's own rule: a door call's tokens live on `audit`, because **a door call
    writes no `runs` row** — the table is a leftover of a runtime this tree no longer
    has, and nothing here reads it.

    `usd` excludes any model the price list could not value and `unpriced_models` names
    them, so a caller can say the figure is short rather than presenting it as whole;
    `tokens` counts everything regardless, which is what makes it the usable net beneath
    the money ceiling.

    Rates come from `rates_for` — which is built on `core.usage.rates()`, the
    degrade-on-a-bad-file lookup rather than `config.model_rates()`, because this is on
    the hot path of every door call and a typo in an operator's JSON file must not refuse
    a customer's whole day. Step 086 put the tenant's own connector prices under it, so
    the person who registered a vendor's key can price it without a file on the server.
    """
    since = day_window(now)
    buckets = storage.active().door_spend_since(
        principal.tenant_id,
        since,
        principal_kind=principal.kind,
        principal_id=principal.id,
    )
    usd, tokens, unpriced = price_buckets(buckets, rates_for(principal.tenant_id))
    return {
        # The date, matching `budget_window()` and `TokenSpend.window`, rather than the
        # midnight instant the query was given: the screen and the refusal both talk about
        # a day, and two spellings of it is how they come to disagree.
        "window": since.date(),
        "usd": usd,
        "tokens": tokens,
        "unpriced_models": unpriced,
        "by_model": buckets,
    }


class TokenBudget:
    """What one machine token may still spend through the door today. Decision 4.

    `core.limits.Spending`'s second implementation, and the first one that is not a
    counter on an object. `Budget` is per **run**: the counters die with the run, two
    runs can never interfere, and there is no global mutable state. That works because a
    run is a bounded thing with an owner and an end.

    A tool-mode call is not a run, so nothing in the process outlives a request to hold
    its count — and decision 9 settles what to do about that: **the count goes in
    Postgres**, because the door exists to sit in front of somebody's production agents
    and the API therefore has to be able to run replicated. N replicas each enforcing an
    in-memory copy of "1000 calls a day" is a 1000N ceiling wearing a 1000 label, which
    is worse than having no dial at all — an operator reads the number and is wrong by a
    factor nobody wrote down.

    **Consumed by the broker at step 2, not checked beside it**, and that is the reason
    this is a `Spending` rather than a call to storage in `call_tool`. Sitting in the
    budget's own seat means the ordering comes for free — a call denied at the permission
    check never reaches here, so a refusal cannot push a caller toward exhaustion — and a
    budget denial writes the same audit record an in-product budget denial writes, which
    is one of this step's verification items obtained by construction rather than by
    keeping two code paths in step.
    """

    __slots__ = ("principal", "ceiling", "window")

    def __init__(self, principal: Principal, ceiling: int, window=None):
        self.principal = principal
        self.ceiling = ceiling
        # Frozen at construction, so a call that straddles midnight UTC is charged to
        # one window rather than checked against one and written to another. Injectable
        # for tests, which is the only way to assert a window boundary without waiting
        # for one.
        self.window = window or budget_window()

    @staticmethod
    def metered(ceiling: int) -> bool:
        """Whether this ceiling counts anything at all. Step 035e.

        One expression with two callers, and the second one is a *screen*. `reserve`
        below returns ALLOW before touching storage when this is false, so an unmetered
        deployment has no budget rows however busy its tokens are — which makes
        *"is the dial on"* a question `GET /me/tokens/{id}/budget` has to answer before
        its figure means anything, and a page rendering `0 / 0` about a token hammering
        the door all day would be false in the most reassuring direction.

        **Extracted rather than repeated, because the comparison is `<= 0` and not
        `== 0`.** A negative value disables the dial too (the convention every dial uses),
        so a second reader writing the obvious `== 0` would be wrong for
        `CARNET_MCP_CALLS_PER_DAY=-1` — and wrong by showing a count of nothing as
        though it were a count of calls, which is the direction nobody rechecks.
        """
        return ceiling > 0

    def reserve(self, tool) -> Decision:
        """Consume one call, or refuse. The broker's step 2.

        `tool` is ignored, and the asymmetry with `Budget.reserve` is worth stating: a
        run's budget has per-tool and per-effect dials because a run makes many calls and
        the interesting failure is a loop hammering one write. A door caller makes one
        call per request under its own credential, so the dial that matters is how much
        that credential may spend in total. Per-tool and per-effect ceilings here are a
        column on migration 040's table when somebody wants one, not a shape to invent
        before the first customer.
        """
        # Money first, and the order is load-bearing rather than stylistic. The call
        # count below *consumes* — `spend_mcp_call` is an atomic increment — so checking
        # it first would charge a call to a caller this method is about to refuse for
        # spend, and a token refused all afternoon would burn its call allowance doing it.
        # A refusal must not push a caller toward exhaustion; that is the same reason the
        # broker runs its permission check before this whole method.
        refusal = self._over_spend_ceiling()
        if refusal is not None:
            return refusal

        if not TokenBudget.metered(self.ceiling):
            # The dial is off — `CARNET_MCP_CALLS_PER_DAY=0`, an operator's explicit
            # decision to run unmetered, the convention every dial uses. Nothing
            # is written: rows nobody will read are not a record, and the audit log
            # already says what every call did.
            return ALLOW

        spent = storage.active().spend_mcp_call(
            self.principal.tenant_id,
            self.principal.id,
            self.window,
            ceiling=self.ceiling,
        )
        if spent is None:
            return Decision(
                False,
                f"this token has made {self.ceiling} {CEILING_REFUSAL_MARKER}, "
                "which is its ceiling. Nothing was called. The window is the UTC day, so "
                "it frees at midnight UTC — or raise CARNET_MCP_CALLS_PER_DAY if this "
                "rate is legitimate.",
            )
        return ALLOW

    def _over_spend_ceiling(self, now=None) -> "Decision | None":
        """Refuse when this principal has spent its day at the model. Step 045b.

        `runs._require_under_spend_ceiling` at the other entrance, returning a `Decision`
        instead of raising because it sits in the budget's seat: a money refusal is then
        an ordinary `decision='deny'` audit row through the broker's one path, and 033b's
        *"a budget denial writes the same audit record an in-product budget denial
        writes"* keeps holding by construction rather than by keeping two paths in step.

        **Read-then-decide, not reserve**, and migration 046's header is the argument:
        `spend_mcp_call` can reserve because a door call is one unit known in advance,
        while a call's *token* cost exists only after it returns. So this gates the
        **next** call — the call that crosses the line completes, at whatever it cost —
        and no storage shape fixes that.

        ## Three ways this number is not the whole truth, each stated rather than hidden

        **Two replicas can each admit near the line.** N replicas may each let a call
        through at $299 of a $300 ceiling, so the real bound is the ceiling plus one
        call's cost per replica. It is bounded and it is not exact.

        **Spend is only as true as the reporters.** These counters come from a
        connector's response body, not from a reply this process received.
        `core.usage.parse_report` drops anything malformed, which stops a connector
        lying *upward* — spending somebody's allowance without making an expensive call —
        and does nothing about one that under-reports. The invoice-grade number stays the
        vendor's bill; this bounds and draws.

        **Nothing recorded means nothing spent.** A deployment where no tool reports
        usage has `$0` here forever and this ceiling refuses nothing, however busy the
        door is. That is legible rather than false — the budget screen shows 0 beside the
        limit — and it is why `MCP_TOKENS_PER_DAY` exists as a net beneath it.

        **Off by default**, so this returns before touching storage on every deployment
        that has not opted in — `reserve`'s own shape, and the reason an unmetered door
        pays nothing for the check.

        `now` is a parameter for the reason `TokenBudget`'s window is one: asserting a
        day's arithmetic is otherwise a test that has to wait for midnight. `reserve`
        passes nothing.
        """
        # Read per call, never captured: an operator turning this knob mid-incident
        # expects the next call to honour it. `TokenBudget` reads `MCP_CALLS_PER_DAY` the
        # same way, and `config` is imported as a module so the read is late.
        usd_ceiling = config.MCP_USD_PER_DAY
        token_ceiling = config.MCP_TOKENS_PER_DAY
        if not (metered(usd_ceiling) or metered(token_ceiling)):
            return None

        now = now or datetime.now(timezone.utc)
        spent = door_spend_today(self.principal, now=now)

        over_usd = metered(usd_ceiling) and spent["usd"] >= usd_ceiling
        over_tokens = metered(token_ceiling) and spent["tokens"] >= token_ceiling
        if not (over_usd or over_tokens):
            return None

        # Exact, because a fixed UTC-day window has one answer. Never below one second so
        # a client honouring the sentence cannot busy-loop on a zero.
        tomorrow = datetime.combine(
            spent["window"] + timedelta(days=1), time.min, tzinfo=timezone.utc
        )
        retry_after = max(1, int((tomorrow - now).total_seconds()) + 1)

        if over_usd:
            reached = (
                f"${spent['usd']:,.2f} {SPEND_REFUSAL_MARKER}, and the ceiling is "
                f"${usd_ceiling:,.2f}"
            )
            dial = "CARNET_MCP_USD_PER_DAY"
        else:
            # Named as the backstop it is, so somebody meeting it is not left wondering
            # why the dollar figure looks nowhere near the limit.
            reached = (
                f"{spent['tokens']:,} tokens {SPEND_REFUSAL_MARKER}, and the "
                f"ceiling is {token_ceiling:,}"
            )
            dial = "CARNET_MCP_TOKENS_PER_DAY"

        short = ""
        if over_tokens and spent["unpriced_models"]:
            short = (
                f" The dollar figure excludes {', '.join(spent['unpriced_models'])}, "
                "which the price list cannot value — which is what this ceiling is for."
            )

        return Decision(
            False,
            f"{self.principal.kind}:{self.principal.id} has spent {reached}. Nothing "
            f"was called.{short} The allowance frees at midnight UTC, in {retry_after}s "
            f"— or raise {dial} if this spend is legitimate.",
        )

    def add_bytes(self, count: int | None) -> None:
        """Deliberately nothing, and it is here to say so rather than to be inherited.

        A run's budget accumulates response bytes because a run feeds every response back
        into a model's context and the total is what it pays for on every turn. A door
        call hands its response to somebody else's agent and forgets it; the per-response
        ceiling still applies (`_bound_response` in the broker, unchanged), and a
        per-token byte total is a second dial with no reader — named in the plan as not
        covered rather than left to look like an oversight.
        """


# --- what this token may see --------------------------------------------------------


def require_machine(principal: Principal) -> None:
    """The door is for machine tokens. A person's browser credential is refused here.

    Decision 1, and it is a refusal rather than an accommodation on purpose. A person's
    OIDC token expires within the hour, so pasting one into an editor's MCP configuration
    produces a setup that works for an afternoon and then fails in a way that looks like
    the product being broken. What a person does instead is mint a token, which is one
    command and is what the whole flow in plan 033 is written around.

    `AccessDenied` — a 403 through `api/errors.py`, after authentication, so the sentence
    can be specific. Not a 401: authenticating again with the same kind of credential is
    exactly what will not help.
    """
    if principal.kind == "machine":
        return

    raise AccessDenied(
        "the MCP door is reached with a machine token, and this request carries a "
        f"{principal.kind} credential. Mint one:\n"
        "    carnet --mint-token <name>\n"
        "  then put it in your client's Authorization header. A person's sign-in token "
        "expires within the hour, so a client configured with one would work this "
        "afternoon and fail tomorrow."
    )


def _granted_agents(
    principal: Principal, *, skipped: list[str] | None = None
) -> list[dict]:
    """Every agent this token may run, as configs, ordered by name.

    **Read on every request, and decision 12 is why there is no cache here.** Two of the
    three queries a door call costs are this and the token lookup, and caching them is
    the obvious way to remove them — and it is the stale-permission decision this product
    refuses everywhere else. A revocation that takes effect in "up to 30 seconds" is not
    a revocation. If the query count ever genuinely matters the answer is one query
    instead of several, which is a join.

    An agent whose stored config no longer validates is **skipped and logged**, not
    raised. `agents.get` raises for the run path, where refusing to run something broken
    is right; here it would mean one unusable agent removes every *other* agent's tools
    from a caller's list, which is a much larger failure than the one being reported. The
    agent is broken in the admin surface either way, which is where somebody can fix it.

    **`skipped` is an out-parameter and exists for `reach` alone — 035d decision 7.** The
    two door callers pass nothing and are unchanged: silence is right for them, because a
    client's tool list is not the place to report that somebody's agent config is broken.
    It is wrong for a page whose whole question is *how many agents does this credential
    reach*, where two sections about a token granted three agents is an absence that reads
    as a fact. An out-parameter rather than a second return value so the hot path keeps
    its shape, and rather than a second `runnable_names` call so recovering the names
    costs no extra query — the loop already knows them.
    """
    out = []
    for name in grants.runnable_names(principal):
        try:
            config_ = agents.get(principal.tenant_id, name)
        except agents.InvalidAgentError as exc:
            log.warning(
                "mcp door: skipping agent '%s' for %s — its config is invalid: %s",
                name,
                principal,
                exc,
            )
            if skipped is not None:
                skipped.append(name)
            continue
        if config_ is not None:
            out.append(config_)
    return out


def _granted_tool_names(agent_configs: list[dict]) -> set:
    """The union of decision 2, as names."""
    names: set = set()
    for agent in agent_configs:
        names |= set(agent.get("permissions", {}).get("tools", []) or [])
    return names


def _session_credential(principal: Principal):
    """`credential_for` for `ensure_available`, identical to what a run supplies.

    Deliberately `for_session` and deliberately not `for_connector`: 033a's first review
    defect was treating "what opens a session" and "whose account a call acts as" as one
    question, and the door must not reintroduce it from a second entry point. Binding is
    a tenant fact — which tools exist comes from the tenant's vetting and is identical for
    everybody in it — while whose account a call goes out as is the vetted `identity`,
    resolved per call by the broker.
    """

    def credential_for(connector_id, env_var=None, ref=None):
        credential = credentials.for_session(connector_id, principal, env_var, ref)
        if credential is None:
            return None, False
        return credential.value, credential.source == DELEGATED

    return credential_for


def _bind(principal: Principal, names: set, *, strict: bool) -> None:
    """Connect whatever these tool names need, one connector at a time.

    Per connector rather than in one call, and that is the whole reason this function
    exists instead of a single `ensure_available`. `strict` is the difference between the
    two callers and names exactly what differs:

        strict=False   `tools/list`. A connector that will not bind loses its tools from
                       the list and the rest still serves. Failing the whole list because
                       one of a tenant's five servers is down makes every listed tool
                       hostage to the least reliable one.

        strict=True    `tools/call`. The caller named one tool and is owed the real
                       reason it cannot happen. Silently dropping it here would reach the
                       broker as "not a registered tool", which is a true sentence about
                       a false cause — the customer's server is down, not their grant.

    **A credential failure is not a connector failure, and conflating them was a real
    defect.** They arrive at the same `except` and mean opposite things: one is *your
    server did not answer*, the other is *your own connected account expired*. Reported
    as the first, the second produced `'example' could not be reached` — a sentence that
    is false in every clause, at a JSON-RPC code meaning "the server broke", about
    something the caller fixes by reconnecting an account.

    Worse than the wording: it happened **during binding**, so the call never reached the
    broker and **no audit record was written at all** — while the neighbouring case (no
    connection row at all, where `for_session` returns None rather than raising) reached
    the broker and was audited `allow` / `outcome="error"`. Two callers one row apart, one
    of them invisible in the log. It bites only where `for_session` falls back to the
    caller's own credential — the deployment where everybody connects their own account
    and no shared variable is set, which is exactly the shape 033a's first review defect
    was about, arriving one layer up.

    So `CredentialError` is re-raised unchanged and `call_tool` decides: if the tool is
    bound anyway, the call proceeds and the broker resolves the credential per call,
    producing the right refusal *and* the right record.

    `ensure_available` is handed a synthetic agent carrying only these names, because the
    only thing it reads from one is `permissions.tools`. That is not a shortcut around a
    real agent: a door call is not attributed to an agent until `permissions.check` says
    which, and binding a connector is a tenant fact rather than an agent's, so asking for
    the tools by name is a more honest description of what is wanted than an agent that
    happens to contain them.
    """
    by_connector: dict = {}
    for connector in mcp.connectors_for(principal.tenant_id):
        wanted = connector.declared_names() & names
        if wanted:
            by_connector[connector.id] = (connector, wanted)

    credential_for = _session_credential(principal)

    for connector_id, (connector, wanted) in sorted(by_connector.items()):
        agent = {"name": f"mcp-door:{connector_id}", "permissions": {"tools": sorted(wanted)}}
        try:
            tools.ensure_available(principal.tenant_id, agent, credential_for=credential_for)
        except storage.StorageError:
            # **Not one server's problem.** Everything else caught below is a fact about
            # the connector — it did not answer, its host was revoked — and is reported as
            # such. A storage failure is a fact about *this* deployment, and dressing it
            # as an unreachable connector would send an operator to check somebody else's
            # server about our database. It stays a 503 through `api/errors.py`.
            raise
        except credentials.CredentialError:
            # The caller's own account, not the connector. See the docstring: re-raised
            # rather than wrapped, so `call_tool` can let the broker answer it — which is
            # where the sentence and the audit record both come from.
            if strict:
                raise
            log.warning(
                "mcp door: %s omitted from tools/list for %s — their own connected "
                "account for it could not be read",
                connector_id,
                principal,
            )
        except Exception as exc:  # noqa: BLE001 - see `strict`; every failure is one server's
            refusal = _the_callers_missing_account(principal, connector, exc)
            if refusal is not None:
                # **Step 046: the 401 that is really the caller's missing account.**
                # The sibling branch above fixed this for a credential that *raises*;
                # here the caller has no credential at all — `for_session` returned
                # None, every wanted tool acts as the person calling, and the server
                # demanded auth for the handshake. Dialled with nothing, the vendor's
                # 401 came back dressed as an outage: "'gh-mcp' could not be reached
                # ... (401)" — false in every clause, observed in the wild by the
                # external harness (2026-08-28). The truth is a credential fact, so it
                # follows the credential path: re-raised for `call_tool` to answer
                # with the sentence that names the remedy, or logged honestly here.
                if strict:
                    raise refusal from exc
                log.warning(
                    "mcp door: %s omitted from tools/list for %s — %s",
                    connector_id,
                    principal,
                    refusal,
                )
                continue
            if strict:
                raise ToolUnavailable(
                    f"'{connector_id}' could not be reached, so the tools it provides "
                    f"cannot be called right now: {exc}"
                ) from exc
            log.warning(
                "mcp door: %s did not bind for %s, its tools are omitted from "
                "tools/list: %s",
                connector_id,
                principal,
                exc,
            )


def _the_callers_missing_account(principal: Principal, connector, exc: Exception):
    """The `CredentialError` a bind failure actually is, or None when it is not one.

    Deliberately narrow — the translation applies only when all three hold, and each
    guard keeps a case where the generic "could not be reached" is the honest answer:

        the server refused with an auth status    a down server, a DNS failure or a
        (401/403, off `TransportError.status`)    5xx stays a connector fact

        every vetted tool on the connector        a mixed or service-identity
        acts as the person calling it             connector's session could have been
        (`identity: "user"`)                      opened by a shared credential, so
                                                  its absence is the tenant's
                                                  configuration story, not this
                                                  caller's — and the whole vetted
                                                  set, not the wanted subset, because
                                                  a strict call wants exactly one
                                                  tool and one tool proves nothing
                                                  about whose session this is

        `for_session` finds nothing               a shared credential that was
                                                  *refused* is the server's own
                                                  statement about that credential

    When all three hold, the only session this connector could ever have opened was
    the caller's own account, and there isn't one — so the 401 is not news about the
    server, it is `for_connector`'s refusal arriving over a socket. Asking
    `for_connector` for the user-identity credential produces the canonical sentence
    (owner-has-not-connected for a personal token; the three remedies for a service
    token), which is returned rather than raised so both `strict` arms of `_bind`
    stay the ones deciding what to do with it.

    **Never pre-empts a dial.** A server that accepts an anonymous handshake binds,
    lists its tools, and lets the call reach the broker where the refusal is audited
    — the behaviour the 033b edge family asserts, kept by translating only after a
    failure that already happened.
    """
    statuses = {
        getattr(cause, "status", None)
        for cause in (exc, exc.__cause__)
        if cause is not None
    }
    if not statuses & {401, 403}:
        return None

    if not connector.vetted or any(
        v.identity != credentials.USER_IDENTITY for v in connector.vetted
    ):
        return None

    env_var = getattr(connector.launch, "credential_env", None)
    ref = getattr(connector.launch, "credential_ref", None)
    try:
        if credentials.for_session(connector.id, principal, env_var, ref) is not None:
            return None
        credentials.for_connector(
            connector.id, principal, identity=credentials.USER_IDENTITY
        )
    except credentials.CredentialError as refusal:
        return refusal
    return None


def _descriptor(tool) -> dict:
    """One tool as MCP advertises it.

    `inputSchema` rather than `input_schema`: `Tool.schema` is the Messages API's
    spelling, and this is the other protocol's. Converted here rather than by giving
    `Tool` a second property, because a descriptor is a thing a *door* produces and the
    tool registry has no business knowing that MCP is being spoken outward.

    `annotations.readOnlyHint` is the vetted `effect`, handed to the client because it is
    exactly the fact MCP's annotation was invented to carry and this product happens to
    have somebody's approval behind it rather than a vendor's assertion. **A hint and
    nothing more** — the enforcement is the broker's step 1, which runs whatever the
    client believes.
    """
    return {
        "name": tool.name,
        "description": tool.description,
        "inputSchema": tool.input_schema,
        "annotations": {"readOnlyHint": tool.effect == "read"},
    }


def list_tools(principal: Principal) -> list[dict]:
    """Every tool this token may call, as MCP descriptors. Decision 3.

    **This IS the grant list.** There is deliberately no second filter and no
    MCP-exposure toggle: revoking a grant removes the tool at the next `tools/list`, and
    a separate switch would be a second answer to "what may this caller do" free to drift
    out of step with the first. A token granted nothing gets an empty list, which is the
    empty-denies default this codebase makes everywhere.

    Binding happens here, and it has to: the vetted manifest deliberately stores no input
    schema (migration 018's argument — a copy of a vendor's contract in our database is a
    copy free to drift from the vendor's), so a descriptor cannot be produced without
    asking the server. The first list of the day pays the handshakes; the session pool
    has amortised them by the second.
    """
    require_machine(principal)

    wanted = _granted_tool_names(_granted_agents(principal))
    if not wanted:
        return []

    _bind(principal, wanted, strict=False)

    # `tools.get` is the same lookup the broker will make, so nothing can be advertised
    # here that would be refused there for not existing.
    #
    # **It is not a promise that the call will succeed, and the honest limit is worth
    # stating rather than implying.** A bound tool is a *tenant* fact — this connector
    # was reached and its manifest intersected — while whether *this caller* can use it
    # is a credential question answered per call. So a caller whose own connected account
    # has expired still sees the tool and is told to reconnect when they call it, which is
    # the more actionable of the two failures: a tool that silently vanishes from a
    # client's list gives nobody anything to act on.
    #
    # The consequence, stated because it is a real one: on a process where nothing has
    # bound this connector yet, that same caller sees a *shorter list* instead, because
    # there is no descriptor to show and none can be fetched without a credential. The
    # two answers differ by process warmth. It is not worth engineering around — the
    # deployment it affects is the one with no shared credential at all, the failure is
    # closed in both directions, and the call's own refusal names the connection to make
    # either way — but it is not a difference to discover by surprise.
    bound = [tools.get(name, principal.tenant_id) for name in sorted(wanted)]
    return [_descriptor(tool) for tool in bound if tool is not None]


# --- the union rule, shared by the answer and the call --------------------------------
#
# Below the divider until 069, because `call_tool` was their only caller. `simulate`
# and `_by_tool` are the second and third, and a rule that decides what a token may do
# is exactly the wrong thing to have two of — so they moved up rather than being
# reached down for.


def _candidates(agent_configs: list[dict], tool_name: str) -> list[dict]:
    """The granted agents that carry this tool, ordered by name.

    Ordered so attribution is deterministic: the same call by the same token attributes
    to the same agent every time, which is what makes an audit log answerable rather than
    merely complete.
    """
    return sorted(
        (a for a in agent_configs if tool_name in (a.get("permissions", {}).get("tools", []) or [])),
        key=lambda a: a["name"],
    )


def _adjudicate(
    principal: Principal,
    candidates: list[dict],
    tool_name: str,
    arguments: dict,
    tool,
) -> tuple[dict, list]:
    """**The union rule.** Which granted agent this call attributes to, and what each said.

    Returns `(chosen, decisions)`, `decisions` parallel to `candidates`. 033b's rule is
    *a call is allowed if **any** granted agent carrying the tool would allow it, and
    that agent is the one the call is attributed to*, and this is the whole of it: the
    loop is over *scope*, because `_candidates` already matched the names. First allow
    wins and is what the audit record names.

    The same pure function the broker runs, so a pre-selection here cannot disagree with
    enforcement there.

    Falling back to the first candidate when none allows is deliberate: the call has to
    reach the broker to be *audited* as the denial it is, under a real agent whose scope
    really did refuse it. Deciding here and returning a refusal of our own would be a
    second enforcement point, quietly producing denials the audit log never sees.

    ## Why this is a function — step 069

    It was six lines inside `call_tool`, and it had to be, because it was the only
    caller. `simulate` is the second, and it needs the identical answer without making
    the call. **A second implementation of the union rule is how a screen and the door
    start disagreeing about what a token can do** — 035d's argument for `reach` calling
    `_granted_agents` rather than copying it, arriving one function further in.

    So the two callers share the object in memory rather than the algorithm on paper.
    `call_tool` keeps `chosen` and drops `decisions`; `simulate` keeps both, because the
    thing a person cannot work out on paper is not *did it pass* but *what did each of
    my three grants say about it*.

    **Evaluated eagerly for every candidate, where the loop it replaces short-circuited** —
    a real change, kept because it was measured rather than reasoned about. The edge pass
    built the worst case that exists: fifty granted agents all carrying one tool, the
    first of them allowing. Eager costs **54µs** against the short-circuit's 1µs — a
    ratio that looks alarming and an absolute that is **0.013% of the door call's own
    ~430ms**, at a fan-out fifty times anything real. On a token granted one to three
    agents, which is every token in this repository, the difference is one or two pure
    string comparisons.

    `permissions.check` is pure: it allocates a `Decision`, reads no row and dials
    nothing. The alternative is `simulate` running its own loop to collect what this one
    discarded, which is the copy the whole function exists to prevent — and a `collect=`
    flag that changed which agents are evaluated would be two code paths wearing one
    name, which is worse than either.
    """
    decisions = [
        permissions.check(principal, agent, tool_name, arguments, tool)
        for agent in candidates
    ]
    chosen = candidates[0]
    for agent, decision in zip(candidates, decisions):
        if decision.allowed:
            chosen = agent
            break
    return chosen, decisions


def reach(principal: Principal) -> dict:
    """What a token is *granted*, without presenting it and without touching a socket.

    **Step 035d, and it is `list_tools` with its two obstacles removed rather than a
    second answer to the same question.** The obstacles are both deliberate and neither
    is about grants:

        require_machine   refuses a browser's user principal by design, because a
                          person's sign-in token expires within the hour. The person
                          asking *"what does this credential reach"* is in a browser and
                          usually does not hold the secret — which is the whole gap: the
                          only way to find out today is to present the token to `/mcp`,
                          at the exact moment somebody suspects it is over-broad.

        _bind             opens a live MCP session per connector, so a page would pay
                          handshakes to a customer's servers to answer a question that
                          is settled entirely by rows in this database.

    So this calls `_granted_agents` and `_granted_tool_names` — **the door's own
    functions, not copies of them.** A second implementation of decision 2 is how the
    screen and the door start disagreeing about what a token can do, which is 021's
    `role_of` defect at a new address; and `grants.runnable_names` underneath already
    redirects a *personal* token through `personal_owner`, so both token kinds fall out
    of the same call with nothing written twice.

    ## Why this is a list of reaches and not one of them

    Plan 035 expected one flat `{tools, scope}`, which `Reach.tsx` already renders. That
    shape cannot carry the truth, and the reason is in this module's own header: the
    union rule is *a call is allowed if **any** granted agent carrying the tool would
    allow it, and that agent is the one the call is attributed to*. So:

      - the **names** are statically answerable. They are the union, one set.
      - the **scope** is not. One tool can appear in several granted agents at different
        bounds — `triage` reads `acme/*` while `security-triage` reads `acme/secrets-*`,
        both granting `search_issues` — and which one applies is decided per call by
        `permissions.check`, against the call's own arguments.

    Rendering a token through one flat `Reachable` therefore means either unioning the
    scopes or picking one, and the header names both as making the union false: the first
    invents a permission nobody wrote down, the second refuses calls the caller is plainly
    granted. **One reach per granted agent is the shape that is true**, and the union of
    names rides alongside because it is exactly what `tools/list` answers and is what
    makes the two surfaces comparable.

    ## Two honest differences from `tools/list`, neither of them a defect

    **This is a superset.** `list_tools` filters the union through binding and then
    `tools.get`, so a tool whose connector will not answer — or was un-vetted underneath
    a live agent — drops out of a client's list. Here it does not: this reports the
    *grant*, and the difference between *what somebody granted* and *what is callable on
    this process right now* is a real distinction that binding would erase. Adding a bind
    to close the gap would mean a page opening sessions to every connector a tenant has
    vetted, which is the cost `list_tools` pays because a client needs schemas and this
    caller does not.

    **Nothing here asks whether the credential still works.** There is no `act_for` on
    this path, so a revoked, expired, owner-disabled or suspended-tenant token still
    answers — see the route, where that is decided rather than inherited.
    """
    skipped: list[str] = []
    configs = _granted_agents(principal, skipped=skipped)

    return {
        "tools": sorted(_granted_tool_names(configs)),
        "agents": [
            {
                "name": config_["name"],
                "tools": list(config_.get("permissions", {}).get("tools", []) or []),
                "scope": config_.get("permissions", {}).get("scope", {}) or {},
            }
            for config_ in configs
        ],
        "by_tool": _by_tool(principal, configs),
        "invalid_agents": skipped,
    }


def _by_tool(principal: Principal, configs: list[dict]) -> list[dict]:
    """The same grants, transposed: one row per tool, every agent that carries it.

    **Step 069, and it is the half of reflect that `reach` could not be.** 035d chose one
    reach *per granted agent* and was right to — a flat union of scopes would invent a
    permission nobody wrote down. What that shape cannot do is answer the question people
    actually arrive with, which is about a *tool*: three sections about three agents is a
    cross-reference exercise handed to the reader, and the reader is usually somebody who
    suspects a token is over-broad.

    So this is the transpose, and the three fields that make it an answer rather than a
    regrouping:

      `applies`       not the agent's whole scope map — the patterns that *can decide*.
                      A tool's effect and its declared resource types select them, so a
                      reader sees the three strings that matter rather than a wall.
      `granted_by`    in `_candidates` order, which is the door's own attribution order.

    **There is deliberately no `attributed_to` here, and the first build had one.** It
    named `granted_by[0]`, which is wrong in exactly the case this view exists for: the
    union rule is *first **allow** wins*, not first candidate, so a token granted
    `security-triage` (`#sec-ops`) and `triage` (`#eng`) attributes a call about `#eng`
    to `triage` — while a static field would have claimed `security-triage` for every
    call, confidently, on the page built to explain attribution.

    Attribution is decided per call, against the call's own arguments, and cannot be
    answered without them. What is true statically is the **order**, which is what
    `granted_by` carries: the first of these whose scope admits the arguments is the one
    the audit record will name. `simulate` answers it for a given call, which is the
    other half of this step and the reason the pair is one step rather than two.

    This is 035d's own finding arriving one field over — plan 035 wanted one flat
    `{tools, scope}` and the union rule would not fit in it — and it is worth writing
    down twice, because both times the shape that does not fit is the one that looks
    tidier.

    **Computed here rather than in the browser**, and that is the load-bearing decision.
    The frontend already holds every input — `reach`'s agents and the tool catalogue —
    so the transpose is expressible in TypeScript, and writing it there would be the
    union rule implemented a second time, in a second language, by the surface whose
    whole job is to explain it. `_adjudicate`'s argument, applied to a read.

    `describe` rather than `get`, so this is answerable on a cold process and opens no
    session — see that function. A name nothing describes still gets a row, with a null
    effect and no resource types: an un-vetted tool sitting inside a live grant is a real
    state and 035d's `invalid_agents` is the precedent for showing it rather than
    dropping it. Dropping it would make the token look narrower than it is, which is the
    wrong direction to be wrong in.
    """
    granted = sorted(_granted_tool_names(configs))
    # **One read for the whole catalogue, not one per tool.** `describe` resolves a
    # connector tool by walking this tenant's connectors, which is a storage read, so the
    # obvious loop made this page cost a read per granted tool — 61 for a token granted
    # 30. The edge pass measured it; `describe_all` is the same answer for a set.
    described = tools.describe_all(granted, principal.tenant_id)

    rows = []
    for name in granted:
        tool = described[name]
        carriers = _candidates(configs, name)

        # Which (type, effect) pairs could possibly decide this call. Empty for a tool
        # that touches nothing policy has a name for — a clock, a calculator — and for
        # one nothing describes.
        wanted = (
            [(ref.type, tool.effect) for ref in tool.resources] if tool is not None else []
        )

        rows.append(
            {
                "tool": name,
                "effect": tool.effect if tool is not None else None,
                "resource_types": sorted({type_ for type_, _ in wanted}),
                "granted_by": [
                    {
                        "agent": carrier["name"],
                        "applies": {
                            type_: list(
                                (carrier.get("permissions", {}).get("scope", {}) or {})
                                .get(type_, {})
                                .get(effect, [])
                                or []
                            )
                            for type_, effect in wanted
                        },
                    }
                    for carrier in carriers
                ],
            }
        )
    return rows


def simulate(principal: Principal, tool_name: str, arguments: dict) -> dict:
    """Would this call be admitted, and which rule decided. Step 069.

    **`call_tool` with everything that acts removed**, which is the only shape that can
    honestly claim to give the same verdict. It runs `_granted_agents`, `_candidates` and
    `_adjudicate` — the door's own three, not copies — and stops. It does not bind, does
    not resolve a credential, does not reserve budget, does not touch a socket and does
    not execute.

    ## What it cannot leak, structurally

    Every input is a row in this database: grants, agent configs, vetted descriptors, and
    `patterns.matches`, which is whole-segment string comparison — plus, since 086, the
    family a vetted descriptor derives from the argument, which is comparison against a
    vocabulary that is itself a row. **Nothing here learns anything about the vendor's
    world**: a family is what somebody *approved*, never what a vendor serves, so a
    simulation that admits a model id proves the policy admits it and says nothing about
    whether it exists. So *would this be allowed* cannot drift toward
    *does this exist* — not because the answer is filtered, but because the question is
    never asked of anybody. That is what keeps 026's existence oracle closed at a surface
    that would otherwise be the natural place to reopen it.

    The tool-name half is closed the same way, by reuse: when nothing granted carries the
    name, this returns the door's own `DoorRefused` sentence verbatim. That sentence
    already conflates *not granted* with *no such tool*, deliberately, and rewording it
    here to be more helpful is precisely the improvement that would open the oracle.

    ## What it deliberately does not answer

    Reported in `not_checked` rather than left to be inferred, because a verdict that
    implies more than it checked is worse than no verdict:

      authentication  a revoked, expired, owner-disabled or suspended-tenant token
                      answers here exactly as a live one does — 035d's decision, for
                      035d's reason: *what could this token reach before I killed it* is
                      the offboarding question, and a page answering "refused: revoked"
                      is useless to the person who came to read it, in the reassuring
                      direction. The token's own card carries the four stamps.
      binding         whether the connector answers. `describe` never dials.
      acting-for      whether a claim the call carries can be honoured. See below.
      credential      never resolved, never consulted.
      budget          `GET /me/tokens/{id}/budget` has answered this since 035e and the
                      page already renders it. Two facts, two sources, neither pretending
                      to be the other — folding a counter that moves every call into a
                      verdict would make the verdict expire while it was being read.

    ## No acting-for, and the honest version of why

    This takes no acting-for parameter, and that part is a decision: it would change
    nothing. `broker.call` checks `ctx.principal`, which is the machine token in the
    acting-for case and the plain one alike, so **acting-for decides whose credential the
    call goes out under and whose name is in the record; it does not decide whether the
    call is permitted.** Taking the parameter would imply an effect it does not have, and
    resolving one would put this on the credential path the paragraph above keeps it off.

    **What is not a decision is that `_resolve_acting_for` can refuse a call outright,
    before the union rule runs at all** — an unresolvable address, or an asserted identity
    on a connector that has not opted in — and the edge pass found that `not_checked` did
    not say so. It says so now. The gate is real and this does not test it, which is the
    same sentence the other four keys make; leaving it out would have made an *allowed*
    verdict quietly stronger than the thing it describes for exactly the callers using the
    feature 033c built.

    ## It writes nothing, anywhere, and the argument is in plan 069

    No `audit` row (there was no call), no `access_denials` row (a question is not an
    attempt — see that module's own line between `require` and `check`), no `admin_audit`
    row (records there ride the transaction of the write they describe, and this performs
    none). The bound on that argument is that **every principal who may reach this can
    already compute its answer by hand** — an administrator reads every config and grant,
    and a token's owner is served every granted agent's scope by `reach`. It confers
    nothing, so there is nothing to record. `DEFERRED.md` carries the trigger for when
    that stops being true.
    """
    granted = _granted_agents(principal)
    candidates = _candidates(granted, tool_name)
    not_checked = ["authentication", "binding", "acting-for", "credential", "budget"]

    if not candidates:
        listed = ", ".join(sorted(_granted_tool_names(granted))) or "<none>"

        # **`call_tool`'s two refusals, both of them, and the edge pass is what found the
        # second missing.** A name that cannot match `TOOL_NAME_RE` is not an attempt on a
        # named thing — there is no tool it could ever have been — and the door says so in
        # its own sentence, with the name cut to 64 characters.
        #
        # Answering such a name with *no agent this token is granted provides a tool
        # called '<it>'* would be a **different verdict from the door's**, at the one
        # surface whose entire claim is that it gives the same one. And it would echo an
        # unbounded string from the wire straight back out: the door refuses to write one
        # into `access_denials` for that reason, and a response is not a better place for
        # it than a table is.
        if not mcp.TOOL_NAME_RE.match(tool_name):
            return {
                "tool": tool_name[:64],
                "verdict": "refused",
                "attributed_to": None,
                "rule": permissions.RULE_NOT_GRANTED,
                "reason": (
                    "a tool name must match "
                    f"{mcp.TOOL_NAME_RE.pattern} — letters, digits, underscores and "
                    f"hyphens, up to 64 characters — so '{tool_name[:64]}' could not name "
                    f"one. Available: {listed}."
                ),
                "considered": [],
                "not_checked": not_checked,
            }

        return {
            "tool": tool_name,
            "verdict": "refused",
            "attributed_to": None,
            "rule": permissions.RULE_NOT_GRANTED,
            # `call_tool`'s own sentence, reused rather than rewritten. It says nothing
            # about whether the tool exists, which is the property worth keeping.
            "reason": (
                f"no agent this token is granted provides a tool called '{tool_name}'. "
                f"Available: {listed}."
            ),
            "considered": [],
            "not_checked": not_checked,
        }

    tool = tools.describe(tool_name, principal.tenant_id)
    chosen, decisions = _adjudicate(principal, candidates, tool_name, arguments, tool)

    by_name = {agent["name"]: decision for agent, decision in zip(candidates, decisions)}
    verdict = by_name[chosen["name"]]

    return {
        "tool": tool_name,
        "verdict": "allowed" if verdict.allowed else "refused",
        "attributed_to": chosen["name"],
        "rule": verdict.rule,
        "reason": verdict.reason,
        # **The deliverable, and not `verdict`.** A boolean is what somebody could have
        # got by making the call. What they could not get, and what the union rule makes
        # genuinely hard, is *all three of my agents said no and here is each one's
        # reason* — read the other way when one allows, it is what turns "it works,
        # somehow" into "it works because `triage` grants acme/*".
        "considered": [
            {
                "agent": agent["name"],
                "allowed": decision.allowed,
                "rule": decision.rule,
                "reason": decision.reason,
            }
            for agent, decision in zip(candidates, decisions)
        ],
        "not_checked": not_checked,
    }


# --- making a call ------------------------------------------------------------------


def call_tool(
    principal: Principal,
    tool_name: str,
    arguments: dict,
    acting_for_raw: dict | None = None,
    *,
    call_id: str | None = None,
) -> dict:
    """One brokered call, attributed to a granted agent. Returns what the broker returns.

    The whole of tool mode, and note how little of it is new. Steps 1 and 2 answer the
    two questions a run would have answered before the broker was reached; step 3 is
    `broker.call`, unmodified, which then does everything this product does about
    permission, budget, credentials, execution and audit.

    Never raises for a *policy* outcome — a denial comes back as `{"error": ...}` from
    the broker, exactly as it does for a model, because the calling agent is in the same
    position a model is in and can narrow its request or explain itself. It raises only
    when there is no call to make: `DoorRefused` when nothing granted carries the name,
    `ToolUnavailable` when the tool cannot be made callable at all — the server did not
    answer, or nothing has bound it and the caller's own credential for it will not open.

    **One bound this function does not apply**, named here so a second caller does not
    inherit a gap by not knowing about it: the size of `arguments` is capped in
    `api/routes_mcp.py` (`config.MCP_MAX_CALL_BYTES`) rather than here — and since
    033c the same is true of `acting_for_raw` (`config.MCP_MAX_ACTING_FOR_BYTES`).
    Both are measured against the serialized form, which is a fact about the wire, and
    both exist because what arrives lands in append-only tables — see that module.
    Anything that reaches this function from somewhere other than an untrusted HTTP
    body has to decide the same question for itself.

    `call_id` — step 083 — is the correlation id the audit row will carry, minted by
    the caller when the caller needs to hand it back (the door route returns it in the
    result's `_meta`, so an agent with forty calls and one denial can say which row is
    its) and minted here when nobody asked. Same `new_call_id`, same prefix, and this
    function's return type does not move for it.

    `acting_for_raw` is the caller's acting-for object exactly as it came off the
    wire, or None. It is resolved here — after the tool is bound, because the asserted
    gate needs the tool's connector — and a claim that cannot be honoured refuses the
    call before the broker, with a denial row. A *resolvable* identity whose person
    then has no connected account is deliberately not this path: that is a credential
    problem, the broker answers it, and the refusal is audited (033b's edge-case
    lesson, kept).
    """
    require_machine(principal)

    granted = _granted_agents(principal)
    candidates = _candidates(granted, tool_name)

    if not candidates:
        listed = ", ".join(sorted(_granted_tool_names(granted))) or "<none>"

        # **Only a name that could be a tool name is written down**, and this guard is
        # the door repaying a promise it would otherwise have broken.
        #
        # `make_denial_record` states as a structural fact that *"no user free text can
        # arrive here"* — true while the only producers were `grants.require` and
        # `roles.require_admin`, which see constants, principal ids and agent names. The
        # door is the first caller whose `resource_id` comes straight off the wire from
        # somebody else's agent, and `access_denials.resource_id` is unbounded TEXT in an
        # append-only table.
        #
        # Which made this an unmetered write: the refusal happens *before* the broker, so
        # `MCP_CALLS_PER_DAY` never sees it, and a token granted nothing at all could put
        # a megabyte per request into the one table an operator reads during an incident
        # — degrading the evidence as much as the disk.
        #
        # A name that cannot match `TOOL_NAME_RE` is not an attempt on a named thing;
        # there is no tool it could ever have been. So it is refused without a row, and
        # the shape is the registry's own rule rather than a second one invented here.
        if mcp.TOOL_NAME_RE.match(tool_name):
            # Written down before it is refused, on `grants.require`'s pattern. Best
            # effort — `denials.record` never lets evidence cost enforcement.
            denials.record(principal, "tool", tool_name, "grant")
            raise DoorRefused(
                f"no agent this token is granted provides a tool called '{tool_name}'. "
                f"Available: {listed}."
            )  # `tool_name` matched TOOL_NAME_RE above, so it is at most 64 characters.

        raise DoorRefused(
            "a tool name must match "
            f"{mcp.TOOL_NAME_RE.pattern} — letters, digits, underscores and hyphens, up "
            f"to 64 characters — so '{tool_name[:64]}' could not name one. "
            f"Available: {listed}."
        )

    # Loud, not silent: the caller named one tool and a connector that will not answer is
    # its own fact, not a permission one.
    try:
        _bind(principal, {tool_name}, strict=True)
    except credentials.CredentialError as exc:
        # **The caller's own account is broken, which is a fact about the call rather
        # than about the tool — so wherever possible the broker answers it, not us.**
        #
        # If the tool is bound, binding's failure changes nothing: sessions are created
        # on demand keyed by the credential the broker resolves per call, so the call
        # proceeds and step 3 raises this same error where it is audited (`allow` /
        # `outcome="error"`) and turned into a model-safe sentence. That is the identical
        # treatment the neighbouring case already got — a caller with no connection row
        # at all, where `for_session` returns None instead of raising — and the two
        # disagreeing was the defect.
        #
        # If it is not bound, there is genuinely nothing to call: no session was ever
        # opened, so no descriptor exists. Then the honest answer names the credential
        # rather than the connector, and there is no decision to record because none was
        # made.
        if tools.get(tool_name, principal.tenant_id) is None:
            raise ToolUnavailable(str(exc)) from exc
        log.info(
            "mcp door: %s binding used a broken credential for %s; the call proceeds "
            "and the broker will resolve it per call",
            tool_name,
            principal,
        )

    tool = tools.get(tool_name, principal.tenant_id)

    acting_for = _resolve_acting_for(principal, tool, tool_name, acting_for_raw)
    _refresh_delegated(principal, tool, acting_for)

    # The union rule, and `simulate` runs the identical function — see `_adjudicate`.
    chosen, _ = _adjudicate(principal, candidates, tool_name, arguments, tool)

    ctx = RunContext.for_call(
        principal,
        TokenBudget(principal, config.MCP_CALLS_PER_DAY),
        call_id or new_call_id(),
        acting_for=acting_for,
    )
    return broker.call(ctx, chosen, tool_name, arguments)


def _refresh_delegated(principal: Principal, tool, acting_for: ActingFor | None) -> None:
    """Renew the connection this call is about to act with, if it has gone stale.

    **The door had no equivalent of `runs.execute`'s pre-run refresh, and 033c is what
    made that bite.** `oauth.refresh_for_run` renews a person's OAuth connections
    before every run, and a door call was the only other place a delegated credential
    is read — so a connection made through the consent flow worked here for exactly as
    long as one access token lasts (an hour, typically) and then refused with *reconnect
    that account*, when what it needed was the refresh token sitting in the same row.
    That is 033b's edge-case defect at a new address: a true-sounding sentence sending
    somebody to the wrong fix, about a credential that was never broken.

    It was reachable before this chunk — a machine token with its own connection — and
    unimportant, because a machine token's credential is usually pasted rather than
    consented. Acting-for makes it the mainline: the account a door call now acts as is
    a *person's*, and a person's is the kind that arrives through OAuth.

    **Narrower than the run's sweep, deliberately.** A run refreshes every connector its
    agent can reach because it does not yet know which it will use; a door call is one
    tool, so this renews one connector for the one principal whose account that tool
    will act as. A `service` tool needs nothing — the shared credential is an
    environment variable — and a pasted token is answered for free inside
    `refresh_connection`, which reads the row and returns before any outbound call.

    **Best-effort per connector, exactly as `refresh_for_run` is, and for the same
    reason**: a connection needing re-consent has already been marked on its row, so
    letting the call continue means the broker's credential read raises with that reason
    and *audits* it — a better refusal than one made here, where no decision has been
    recorded yet and the record is the thing this door keeps having to protect.

    The cost, stated because decision 12 quotes a number: for a `user`-identity call
    this adds one lock attempt and one row read, and an outbound token exchange only
    when the credential is genuinely near expiry — which is once an hour per person per
    connector, and is exactly what a run has always paid.
    """
    if tool is None or not tool.connector or tool.identity != credentials.USER_IDENTITY:
        return

    # The same precedence the credential read runs, and the two MUST agree — a refresh
    # aimed at one row while the broker reads another is this function's founding
    # defect (a stale connection refused with a true-sounding sentence about the wrong
    # fix) reintroduced one principal over. Acting-for names the account when present
    # (033c); otherwise a personal token's account is its owner's (033d,
    # `personal_owner` — the same helper `_delegated_credential` redirects through).
    whose = principal
    if acting_for is not None and acting_for.user_id:
        whose = Principal.user(acting_for.user_id, principal.tenant_id)
    else:
        whose = credentials.personal_owner(principal) or principal

    try:
        oauth.refresh_connection(whose, tool.connector)
    except oauth.ReconsentRequired:
        # Recorded on the row already. The call proceeds so the broker produces both the
        # sentence and the audit record — see the docstring.
        log.info(
            "mcp door: the connection to %s for %s needs re-consent",
            tool.connector,
            whose,
        )
    except oauth.OAuthRefused as exc:
        # No consent flow configured, which is not an error: a connector whose
        # credential is a pasted token has nothing to refresh.
        log.debug("mcp door: no refresh for %s: %s", tool.connector, exc)
    except Exception:  # noqa: BLE001 - a provider being down must not lose the call
        log.exception(
            "mcp door: could not refresh the connection to %s for %s",
            tool.connector,
            whose,
        )


def _resolve_acting_for(
    principal: Principal, tool, tool_name: str, raw: dict | None
) -> ActingFor | None:
    """The caller's acting-for claim, resolved — or a refusal with a denial row.

    Three pieces, three owners. The shape (`parse`) and the worth (`verify`,
    `assert_identity`) are `access/acting.py`'s. What belongs to the door is the one
    rule needing both tools and identity in scope: **an asserted identity is believed
    only where this tool's connector opted in** — `allow_asserted_identity`, default
    false, so the resting posture is *verified or nothing*. A hand-written tool has no
    connector to have opted in, so asserted refuses there too; verified needs no
    opt-in anywhere, because nothing about it is taken on trust.

    Every refusal here writes the same `access_denials` row the ungranted-name refusal
    writes — `resource_kind` `tool`, `required` `acting-for` — because it is the same
    kind of fact: an attempt on a named thing, refused before any broker decision
    existed to audit. Bounded by construction: `tool_name` already matched a granted
    agent's tool list to get here, and `"acting-for"` is a constant. The sentence may
    quote the caller's email — `parse` bounded it — never the token.
    """
    if raw is None:
        return None

    try:
        kind, value = acting.parse(raw)

        if kind == acting.EMAIL_KEY:
            connector = (
                tools.mcp.get_connector(principal.tenant_id, tool.connector)
                if tool is not None and tool.connector
                else None
            )
            if connector is None or not connector.allow_asserted_identity:
                raise acting.ActingForError(
                    f"'{tool_name}' does not accept asserted identity: its connector "
                    "has not enabled `allow_asserted_identity`, so only a verified "
                    "acting-for (the person's own IdP token, forwarded) is believed "
                    "here. An administrator enables assertion per connector:\n"
                    "    carnet --set-asserted-identity <connector> on"
                )
            return acting.assert_identity(principal, value)

        return acting.verify(principal, value)

    except acting.ActingForError as exc:
        # Written down before it is refused, exactly as the ungranted-name path —
        # best-effort, so evidence never costs enforcement.
        denials.record(principal, "tool", tool_name, "acting-for")
        raise DoorRefused(str(exc)) from exc


__all__ = [
    "CALL_ID_PREFIX",
    "DoorRefused",
    "TokenBudget",
    "ToolUnavailable",
    "call_tool",
    "list_tools",
    "new_call_id",
    "require_machine",
]
