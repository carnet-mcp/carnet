"""The seam between the broker and whatever bounds a caller.

One protocol and one constant re-export, and after step 084 nothing else. What used to
be here — `Budget`, a per-run counter with four dials, and `LIMIT_DEFAULTS`, the
vocabulary an agent's `limits` block is checked against — went in that step for two
different reasons, and the difference is worth reading:

    Budget           deleted. Correct code with no caller. Its only caller was
                     `RunContext.start`, whose only caller was nothing — see 081, which
                     found that `max_writes: 0` therefore refused nothing at all.

    LIMIT_DEFAULTS   moved, not deleted, to `agents.KNOWN_LIMITS`. Its *values* were
                     config attribute names read only by `Budget.for_agent` and died
                     with it. Its *keys* are a write-time contract with everybody who
                     writes an agent config, and `agents.validate` still refuses an
                     unknown limit key against them, with the same sentence. It sits in
                     `agents/` now because that is its one reader and because a dict
                     describing the shape of an agent config was a fact `core/` had no
                     business holding — this layer knows no tool and no agent.

Scoping answers "may this agent touch #eng?". A budget answers "has it already posted
there fifteen times?". Both are needed: every call a runaway loop makes is individually
authorized, and the volume is the whole problem. This tree has one implementation of the
second question and it is the door's.
"""

from typing import Protocol

from .. import storage
from .permissions import Decision


class Spending(Protocol):
    """The two methods the broker consumes. **The seam, written down.**

    `RunContext.budget` was a concrete `Budget` for eight steps because there was one
    kind of caller — an agent run — and one kind of ceiling, counted on an object that
    dies with the run. Step 033b added a second: a tool-mode call through the MCP door is
    not a run (see `door.py`), so what bounds it is a machine token over a window, counted
    in Postgres because the API has to be able to run replicated.

    Naming the protocol rather than widening `Budget` kept the distinction the broker
    already relied on: it consumes a *thing that can be spent from*, and has never known
    where the numbers came from. That is the same containment `Cancellation` and
    `Activity` document one file over — whoever builds the context supplies the mutable
    object, and `core/` learns nothing about queues, tokens or tables from any of them.

    **Since step 084 this tree holds one implementation, `door.TokenBudget`**, and the
    paragraph above is written in the past tense on purpose. There is no runtime here to
    carry the other one, and a protocol with a single implementation is a shape nothing
    forces the next one to honour. It is kept anyway, and not collapsed into
    `TokenBudget`, for the reason it was named in the first place: the broker's step 2 is
    the *only* place a ceiling is consumed, and a tree that does execute agents has to be
    able to hand that step a per-run counter without the broker changing. Collapsing it
    would put a door-shaped type in `core/broker.py`, which is the layering this file
    exists to keep straight.

    Two methods, and deliberately not `snapshot()`: nothing calls it on the hot path, and
    a protocol that demands more than its consumer uses is a protocol that makes the next
    implementation carry dead weight.

    `add_bytes` is the half with no live work behind it here — `TokenBudget.add_bytes`
    deliberately does nothing and says why — and it stays on the protocol rather than
    being dropped from it and from the broker. A run feeds every response back into a
    model's context and pays for the total on every turn; that is the measurement, and it
    belongs to whoever has a run.
    """

    def reserve(self, tool) -> Decision:
        """Check every dial and, on success, consume the call."""

    def add_bytes(self, count: int | None) -> None:
        """Record a response's size after execution."""


# The phrase a per-run budget refusal carries, and — with no `kind` column on an audit
# row — the only thing that identifies one after the fact. Step 041.
#
# **Bound to the storage constant rather than spelled here**, on `door.CALL_ID_PREFIX`'s
# exact precedent and for its reason: two layers need this string, `storage` is the lower
# one and imports nothing from the app, so the definition sits at the bottom and whoever
# needs it binds to it. The argument for why a sentence is a constant at all lives with
# the definition.
#
# **Nothing in this tree writes one any more** — `Budget` was the writer and step 084
# deleted it — and the constant stays because the *reader* did not. `storage`'s overview
# files a refusal carrying this phrase under `run_budget`, and an upgraded deployment's
# `audit` table holds rows a pre-078 tree wrote. Dropping the marker would re-file those
# under `policy`, silently, on a screen built to be trusted at a glance, which is exactly
# what the definition's own docstring exists to prevent. Re-exported here so a tree that
# *does* have a runtime finds it where its writer would look.
BUDGET_REFUSAL_MARKER = storage.BUDGET_REFUSAL_MARKER
