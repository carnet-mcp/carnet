"""The budget's seat in the broker — `core.limits.Spending`, and what the broker does to it.

## What this file used to be, and why it is not that

Until step 084 this was 200 lines about `core.limits.Budget`: four dials, their
arithmetic, and a closing section checking that the broker actually consulted them.
`Budget` is gone. It was correct code with no caller — `Budget.for_agent` was reached
only from `RunContext.start`, which nothing in this tree has called since 078 removed the
runtime, which is how `max_writes: 0` came to refuse nothing at all (step 081).

**The arithmetic went with it. The broker's contract did not**, and that is what is here
now. `broker.call` reserves before it executes, refuses without executing when the
reservation is refused, never reserves at all when the permission check has already said
no, and hands the response size back afterwards. Those are four properties of
`core/broker.py`, they are true of *any* `Spending`, and until now they were asserted
through one particular implementation of it.

## Why a recording stub rather than the surviving implementation

`door.TokenBudget` is this tree's one `Spending`, and `test_door.py` drives it end to end
over real HTTP: the ceiling refuses, the record is an ordinary broker denial, a denied
call spends nothing. That covers *the door's* ceiling working.

It cannot cover this. `TokenBudget.reserve` **ignores the tool it is handed** and
`TokenBudget.add_bytes` **deliberately does nothing** — both are documented at length in
`door.py`, and both are right for a caller that makes one call per request. So on the
door path, deleting `ctx.budget.add_bytes(response_bytes)` from the broker changes no
observable behaviour anywhere, and `broker.call` could stop passing the tool to `reserve`
without a single test noticing.

A stub that records is the only instrument that can see either. It is also the honest
one: what is under test is the broker's half of the seam, not anybody's counters.
"""

from carnet.core import broker
from carnet.core.context import RunContext
from carnet.core.permissions import ALLOW, Decision
from carnet.core.principal import Principal

from conftest import read_audit

TENANT = "t-test"
SYSTEM = Principal.system("test", TENANT)

AGENT = {
    "name": "test-agent",
    "permissions": {
        "tools": ["post_message"],
        "scope": {"chat.channel": {"write": ["#eng"]}},
    },
}

REFUSAL = "run write budget exhausted: 0 writes already made"


class Recording:
    """A `Spending` that writes down what the broker did to it.

    `refuse` is the reason to give back, or None to allow. Set it and every reservation
    from then on is refused, which is enough for every ordering question here — the
    interesting boundary is *does a refusal execute anything*, not where the boundary
    falls.
    """

    def __init__(self, refuse: str | None = None):
        self.refuse = refuse
        self.reserved: list = []
        self.bytes: list = []

    def reserve(self, tool) -> Decision:
        self.reserved.append(tool)
        return ALLOW if self.refuse is None else Decision(False, self.refuse)

    def add_bytes(self, count) -> None:
        self.bytes.append(count)


def context(budget) -> RunContext:
    """A context around one budget.

    `RunContext(...)` directly rather than a constructor: `start` is gone with `Budget`
    and `for_call` is the door's, which would put a door-shaped call id on a test about
    the broker.
    """
    return RunContext(run_id="aaaabbbbcccc", principal=SYSTEM, budget=budget)


# --- the broker consults whatever it was handed --------------------------------------


def test_the_reservation_is_made_with_the_tool_that_was_called():
    """**The tool reaches `reserve`, and this is the only test that can see it.**

    `Spending.reserve(tool)` takes the tool because a per-run budget has per-tool and
    per-effect dials — *"catches a loop hammering one endpoint"*. The door's
    implementation ignores it and says so, so on every other path in this suite the
    argument could be `None` and nothing would fail. A tree that adds a runtime back
    inherits a broker that already hands the right thing over, or it does not, and this
    is where that is decided.
    """
    budget = Recording()

    broker.call(context(budget), AGENT, "post_message", {"channel": "#eng", "text": "hi"})

    assert [tool.name for tool in budget.reserved] == ["post_message"]
    assert [tool.effect for tool in budget.reserved] == ["write"]


def test_a_refused_reservation_returns_the_reason_verbatim():
    """The refusal is the budget's sentence, not the broker's paraphrase of it. That is
    what lets `overview` file a refusal by matching on `BUDGET_REFUSAL_MARKER` — the
    sentence is the only evidence, because a budget denial is deliberately the same audit
    row a policy denial is."""
    refused = broker.call(
        context(Recording(refuse=REFUSAL)),
        AGENT,
        "post_message",
        {"channel": "#eng", "text": "nope"},
    )

    assert refused["denied_by"] == "broker"
    assert REFUSAL in refused["error"]


def test_a_refused_reservation_never_executes(isolated_var_dir):
    """The ordering that makes a budget a *safety* control rather than a report: the
    refusal lands before `tool.impl`, so nothing reaches an external system. `post_message`
    writes to `outbox.jsonl`, and its absence is the evidence."""
    broker.call(
        context(Recording(refuse=REFUSAL)),
        AGENT,
        "post_message",
        {"channel": "#eng", "text": "should not send"},
    )

    assert not (isolated_var_dir / "outbox.jsonl").exists()


def test_a_refused_reservation_is_audited_as_a_denial_that_ran_nothing():
    """`decision='deny'` and an **empty** outcome, which is the pair a reader needs: a
    denial with an outcome would say something ran and was refused afterwards."""
    ctx = context(Recording(refuse=REFUSAL))

    broker.call(ctx, AGENT, "post_message", {"channel": "#eng", "text": "nope"})

    record = read_audit(TENANT)[-1]
    assert record["decision"] == "deny"
    assert record["outcome"] == ""
    assert REFUSAL in record["reason"]
    assert record["run_id"] == ctx.run_id


def test_a_permission_denial_never_reaches_the_budget():
    """Step 1 before step 2, and the reason is not tidiness: a refusal must not push a
    caller toward exhaustion. Somebody fixing their own scope mistakes must not run out of
    allowance doing it.

    Asserted as *`reserve` was never called* rather than as *the counter did not move* —
    the counter is the implementation's business and the call is the broker's.
    """
    budget = Recording()

    denied = broker.call(
        context(budget), AGENT, "post_message", {"channel": "#random", "text": "denied"}
    )

    assert denied["denied_by"] == "broker"
    assert budget.reserved == []


# --- and hands back what the call cost ------------------------------------------------


def test_the_response_size_is_handed_back_after_execution():
    """`add_bytes` is the half with no live work behind it — the door's implementation
    does nothing on purpose — so this is the only thing standing between the broker and
    somebody deleting the call as dead code. A run feeds every response back into a
    model's context and pays for the total on every turn; a tree with a runtime needs the
    number to arrive."""
    budget = Recording()

    broker.call(context(budget), AGENT, "post_message", {"channel": "#eng", "text": "hi"})

    assert len(budget.bytes) == 1
    assert budget.bytes[0] > 0


def test_a_refused_call_hands_back_no_bytes():
    """Nothing ran, so there is nothing to have cost anything. The same `return` that
    skips execution skips this, and asserting it is how that stays true if the refusal
    ever moves."""
    budget = Recording(refuse=REFUSAL)

    broker.call(context(budget), AGENT, "post_message", {"channel": "#eng", "text": "no"})

    assert budget.bytes == []


# **Every assertion above is on `post_message`, and that is the shipped registry rather
# than a choice**: `tools.REGISTRY` holds exactly one static tool, and everything else a
# tenant can call is a connector it vetted. A read-effect case would need a connector
# fixture and a stub server, which is `test_rest.py`'s and `test_mcp.py`'s world — both
# of which drive `broker.call` with a budget of their own (`conftest.Unmetered`) and
# would fail loudly if the seat moved. What is pinned here is the seat itself.
