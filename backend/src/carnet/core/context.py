"""Everything the broker needs to know about the run a call belongs to.

One object per agent run, created by the runtime before the model is invoked and
threaded through every `broker.call`. It carries:

    run_id        correlates every audit record from one run
    principal     who the run acts for  (see principal.py)
    budget        how much it may still do (see limits.py)
    cancellation  whether somebody has asked it to stop
    usage         what it has spent at the model (see usage.py)

This replaced a bare `principal` parameter rather than sitting beside it. The budget
has to be per-run, and a run is exactly what this object represents — so consolidating
kept the broker signature from growing a parameter per concern.

Nothing here comes from the model. The runtime builds it from the agent config and the
principal handed in by the entry point, both server-side values.
"""

import threading
import uuid
from dataclasses import dataclass, field

from .limits import Spending
from .principal import ActingFor, Principal
from .usage import Meter


def new_run_id() -> str:
    """A fresh run id.

    Exposed as a function because an entry point that records a run before executing it
    needs one *before* there is a context to take it from. One definition, so the id an
    entry point writes into a `runs` row is the same shape as the one every audit record
    carries.

    Twelve hex characters — 48 bits — which is short enough to type a prefix of and,
    honestly, short enough to collide at a billion runs. Migration 015 makes that a
    failed insert rather than two customers' records merging, which is where it should
    arrive; widening it is a change to every id already written down.
    """
    return uuid.uuid4().hex[:12]


def new_file_id() -> str:
    """A fresh id for an uploaded file. Step 028.

    **Longer than a run id — 32 hex characters — and the difference is the point.** A run
    id is short because people type prefixes of it at a terminal and read it in a list;
    nobody ever types a file id, it is copied from one response into the next request.

    So the 48-bit trade `new_run_id` makes deliberately is one this has no reason to
    make, and one it must not: a file id is the *only* thing standing between a caller
    and somebody else's document. `usable_file` refuses a file the caller does not own,
    which is what actually enforces that — but an id short enough to collide is an id
    short enough to guess at scale, and defence that rests on one check is defence with
    no depth. This costs nothing: the id is opaque either way.
    """
    return uuid.uuid4().hex


class Cancellation:
    """Whether this run has been asked to stop. Two methods, and no more.

    A `threading.Event` behind a name, and the name is the point: the broker asks
    `is_set()` before every tool call, and what sets it is somebody else's thread
    entirely — a worker's heartbeat, or a CLI's signal handler. An `Event` is the one
    primitive that is safe across that boundary without a lock at either end.

    **`core/` learns nothing about jobs from this.** It is the same containment as
    `budget`: a mutable thing the broker consumes without knowing where its state came
    from. A budget does not know that a `limits` block in a config exists, and this does
    not know that a `runs` table does. Whoever builds the context supplies both.

    `requested_by` is carried rather than looked up because the thing that sets the flag
    is the only thing that knows who asked — and for a CLI run there is no row to read it
    back from until after the run has already ended. Free text as far as this object is
    concerned; the entry points write `kind:id`.

    Deliberately **not** a `bool` on `RunContext`. A frozen dataclass cannot have one
    reassigned, and unfreezing it to allow that would make the run's identity mutable to
    fix a flag — which is the trade `budget` already refused.
    """

    __slots__ = ("_event", "requested_by")

    def __init__(self):
        self._event = threading.Event()
        self.requested_by = ""

    def request(self, by: str = "") -> None:
        """Ask the run to stop. Idempotent, and the first asker is the one recorded.

        Unlocked, and that is a considered choice rather than an oversight. The `Event`
        is what the broker reads and it is atomic; the only thing that could race is
        `requested_by`, between two callers asking in the same instant. There is exactly
        one setter per run in practice — a worker's heartbeat thread, or a CLI's signal
        handler — and if there were two, the cost is that the wrong one of two
        simultaneous cancellers is named in a log line. **The row is the authority on who
        asked**, and `request_cancel` settles that in the database, atomically.
        """
        if not self._event.is_set():
            self.requested_by = by
            self._event.set()

    def is_set(self) -> bool:
        return self._event.is_set()

    def __repr__(self) -> str:  # pragma: no cover - diagnostics
        state = f"requested by {self.requested_by or '?'}" if self.is_set() else "live"
        return f"<Cancellation {state}>"


class Activity:
    """What this run says about its own progress. One method, and it is best-effort.

    Step 032, and `Cancellation`'s containment pointing the other way: that one is a
    flag set from *outside* that the loop reads, this one is a note written from
    *inside* that somebody outside reads. **`core/` learns nothing about a `runs` table
    from it** — the sink is supplied by whoever builds the context (the runs tier hands
    in a storage write; a bare CLI run hands in nothing), exactly as the budget's
    numbers and the cancellation's setter come from outside.

    `note(turn, doing)` is fire-and-forget by contract: the sink owns its own failure
    handling (the runs tier logs and swallows, the way `_finish` does), because a run
    must never fail over a progress marker. The default sink is nothing, which is a run
    that reports nothing — every run before 032.
    """

    __slots__ = ("_sink",)

    def __init__(self, sink=None):
        self._sink = sink

    def note(self, turn: int, doing: str) -> None:
        """Record what the run is doing now: turn N, `"model"` or `"tools"`."""
        if self._sink is not None:
            self._sink(turn, doing)

    def __repr__(self) -> str:  # pragma: no cover - diagnostics
        return f"<Activity {'wired' if self._sink else 'unreported'}>"


@dataclass(frozen=True)
class RunContext:
    """Frozen so the identity of a run can't be swapped mid-flight.

    `budget` is the deliberate exception: its counters mutate as the run proceeds.
    Freezing the reference is what matters — a call can't be handed a different
    budget, only spend from this one.

    `cancellation` is the second exception and it arrives by the same argument, which is
    why it sits beside the budget rather than anywhere else. The reference is frozen; the
    state behind it is set by another thread while the run is in flight.

    `activity` is the third, and it points the other way: the loop writes, an outside
    reader reads. Same containment, same defaulting rule.

    `usage` is the fourth and takes both halves — the budget's mutability and
    `activity`'s direction. The loop adds each model reply's token counts to it; whoever holds the
    run's row reads it afterwards and writes the numbers down. **`core/` learns nothing
    about a bill from it**, exactly as it learns nothing about a queue from
    `cancellation` or about a table from `activity`: it is handed a thing it can add to.
    Defaulted, so a run built without one counts into an object nobody reads — which is
    every run before 013.
    """

    run_id: str
    principal: Principal
    # Typed as the protocol since 033b: the broker consumes two methods and has never
    # known where the numbers behind them came from. It had two implementations then —
    # a per-run counter and the door's per-token ceiling — and since 084 this tree has
    # only the door's. See `limits.Spending`, which says why the seam stays anyway.
    budget: Spending
    # Defaulted, so every existing construction site keeps working and gets a flag
    # nothing can set — which is exactly today's behaviour for a run nobody can cancel.
    cancellation: Cancellation = field(default_factory=Cancellation)
    # Defaulted the same way: a context built without one reports progress to nobody,
    # which is every run before 032.
    activity: Activity = field(default_factory=Activity)
    # Step 013. Defaulted for the same reason again — a context built without one counts
    # into a meter nothing reads, which is every run before migration 045 and every
    # brokered call through the door, where there is no model call to count.
    usage: Meter = field(default_factory=Meter)
    # Whom this call is made *for*, when a shared service said so through the door —
    # step 033c, and None everywhere else. Defaulted to None rather than threaded
    # through `start`, because on the run path it is the truth: a run's principal IS
    # who it acts for, and `identity_source: none` on every run record is that fact
    # written down. The broker reads it in exactly two places — the credential lookup
    # for a `user`-identity tool, and the audit record — and the permission check
    # deliberately never sees it (see `ActingFor`'s docstring).
    acting_for: ActingFor | None = None

    @property
    def tenant_id(self) -> str:
        """Which customer this run belongs to.

        **Derived, never stored.** The tenant is a property of the principal (see
        principal.py); holding a second copy here would create two values that can
        disagree, and a disagreement between them is a cross-tenant leak rather than
        an inconsistency. Same reasoning as `Connector.read_only`.
        """
        return self.principal.tenant_id

    @classmethod
    def for_call(
        cls,
        principal: Principal,
        budget: Spending,
        call_id: str,
        acting_for: ActingFor | None = None,
    ) -> "RunContext":
        """A context for **one brokered call that is not part of a run**. Step 033b.

        The MCP door in tool mode is the only caller and is likely to stay the only one:
        a `tools/call` there has a principal, a budget and exactly one tool call in it —
        no prompt, no agent config, no turns — so `start` cannot build it (there is no
        `agent` to take limits from) and a `runs` row would be a lie about all three.
        See decision 4 of plan 033.

        **This is not the rule against entry points constructing a context being bent.**
        That rule exists because the *budget* is core's business, and it still is: what
        an entry point may not do is invent its own ceiling inline. The door hands in an
        object whose contract is stated here (`Spending`) and whose numbers come from
        `config.MCP_CALLS_PER_DAY` and a table, which is a decision written down rather
        than a caller improvising.

        `call_id` rather than `run_id`, because it is not one, and the door mints it in a
        deliberately distinct shape (`door-<hex>`) so that nothing downstream can mistake
        a door call for a run — see `door.new_call_id`. It lands in `run_id` on the audit
        record because that column is what correlates records, and correlating a door
        call's records is the same job.

        No cancellation and no activity: there is nothing to cancel between the request
        and its answer, and nobody to report progress to. Both default to the inert
        objects every run before 016 and 032 had.

        `acting_for` is the resolved identity the door was handed for this one call —
        step 033c — and it rides here because the context is the only thing that
        reaches both places that read it, the credential lookup and the audit record.
        The door resolves it (`access/acting.py`) before this is built; nothing raw
        off the wire arrives in core.
        """
        return cls(
            run_id=call_id, principal=principal, budget=budget, acting_for=acting_for
        )

    def __str__(self) -> str:
        return f"run {self.run_id} ({self.principal})"
