"""What a brokered model call spent, counted where the number already exists.

A vendor's reply carries its own usage block, and until this module existed it was
discarded. So one credential got one bill, and nothing in this system could say which
caller produced it. Not approximately: at all. Today the reply is a REST connector's
(step 045b), read through the `--usage-map` its vetter wrote; the arithmetic is the same.

This is plan 013 (`docs/plans/013-token-accounting.md`). It is the *arithmetic* half of
metering — the four-way token split, a per-model rate table, and the rule that a cost is
summed per model bucket rather than computed once at a blended rate — and deliberately
nothing else. There is no ingestion here and there is none anywhere: the counts arrive
on a reply this process already made, so nothing scans, re-tokenizes, or asks a second
API what the first one cost.

## The counters, and why there are four rather than three

Plan 013 specified three — input, output, cache reads — and deliberately refused a
cache-*write* column on the grounds that *"nothing here enables caching yet, so a column
for it would be a column of zeros with a story attached"*. **That was true when 013 was
drafted and stopped being true at step 028**: `_opening_turn` puts
`cache_control: {"type": "ephemeral"}` on a run's attached document precisely so turns
2..N are cache reads, and a cache write is billed at a premium over ordinary input. A
run that attaches a 10 MiB PDF writes the cache once and reads it nine times; folding
the write into `input_tokens` prices those tokens at the wrong rate in the one case the
feature was built for.

So there are four counters, named as the pair they are — `cache_read_tokens` and
`cache_write_tokens`, rather than 013's lone `cached_input_tokens`, which does not say
which direction it means. The four are also exactly what the API reports, so every one
of them is a field read rather than a derivation.

## `Meter` is its own object rather than a field on `Budget`

013's decision 2 said the loop would accumulate through `core/limits.Budget`, which had
an existing per-run counter and an existing reason to grow. **Step 033b closed that
door**, and it is worth naming rather than quietly doing something else: `Budget` is now
one implementation of the `Spending` protocol, and the other is the MCP door's
per-token-per-day ceiling — a caller that makes no model call at all. `Spending`'s own
docstring refuses to widen for this exact reason ("a protocol that demands more than its
consumer uses is a protocol that makes the next implementation carry dead weight"), and
`ctx.budget` is typed as the protocol, so the loop could not call a `record` on it
without either widening the protocol or lying about the type.

What is left is the shape `core/context.py` already documents four times over: a mutable
object handed in from outside, which the loop writes and somebody outside reads.
`Cancellation` is set outside and read inside; `Activity` is written inside and read
outside; this is `Activity`'s direction with `Budget`'s mutability. **`core/` learns
nothing about a `runs` table from it** — the meter is handed in by whoever holds the
row, and a run with no meter counts nothing, which is every run before this.

## The rate table is not in the schema and is not on a customer's screen

013's decision 4 — *"no cost figure anywhere... a wrong number on a screen labelled cost
is worse than no screen"* — holds, and holds where it was aimed. Nothing here is
persisted: `runs` stores tokens and the model, never a dollar figure, because a stored
cost is a frozen guess that reads like an invoice and cannot be corrected when the
number it was computed from changes. `GET /runs/{id}` carries counts only.

What the rate table buys is the operator's own question — *which tenant produced this
month's bill* — asked at a terminal by the person who pays it. `RATES` below is a dated
snapshot, `estimate_cost` returns **None** rather than a number for a model it does not
know, and `CARNET_MODEL_RATES` points at the operator's own file. That is 013's own
sentence — *"the arithmetic is somebody's pricing decision and belongs where prices are
maintained"* — made literal rather than contradicted.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .. import config

log = logging.getLogger(__name__)


def day_window(now: datetime | None = None) -> datetime:
    """Midnight UTC of the day `now` falls in — the window a ceiling is charged against.

    **One definition, three readers**, which is the whole reason it is a function: the
    gate that refuses a submission, the route that renders the meter, and the report that
    buckets by day must agree on when a day starts, or a person reads one number on a
    screen and is refused by a different one.

    UTC rather than the operator's zone, matching both stores' `_day` bucket and the
    door's own window. A local-time day would mean the ceiling frees at a different instant for
    every deployment and could not be reasoned about from a log — and it would move twice
    a year under daylight saving, which is a ceiling that silently doubles one night and
    halves another.

    `now` is a parameter for the reason `TokenBudget`'s window is one: asserting a
    boundary is otherwise a test that waits for midnight.
    """
    moment = now or datetime.now(timezone.utc)
    return moment.astimezone(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )


def metered(ceiling: int) -> bool:
    """Whether a ceiling counts anything at all.

    One expression, and it exists so a second reader cannot write `== 0` — the test is
    `<= 0`, so a deployment set to a negative value is unmetered, and a client or a
    screen writing the equality would be wrong there in the reassuring direction. Exactly
    `door.TokenBudget.metered`'s argument, which is why that one is also one expression
    with a name rather than an inline comparison.

    The second caller is a *screen*: with no ceiling nothing is refused, so a figure
    rendered as `0 of 0` would say a busy deployment had barely been used. Whether the
    dial is on has to be answerable before the number beside it means anything.
    """
    return ceiling > 0


# USD per 1,000,000 tokens, by model family. **A dated snapshot of published list
# prices, not an authority**, and the distinction is the whole reason `estimate_cost`
# hands back `None` for anything it does not recognise instead of guessing.
#
# Rates last checked 2026-08-28. An operator whose contract differs — or who reads this
# a quarter later — sets `CARNET_MODEL_RATES` and this table is never consulted.
RATES_CHECKED = "2026-08-28"

RATES = {
    "opus": {"input": 15.00, "output": 75.00, "cache_read": 1.50, "cache_write": 18.75},
    "sonnet": {"input": 3.00, "output": 15.00, "cache_read": 0.30, "cache_write": 3.75},
    "haiku": {"input": 0.80, "output": 4.00, "cache_read": 0.08, "cache_write": 1.00},
}

def model_family(model: str, rates: dict | None = None) -> str:
    """The key in `rates` that prices this raw model id, or `""` when none of them do.

    Substring matching on the lowercased id, because the same model arrives under
    several spellings depending on how it was reached — `claude-opus-5`,
    `anthropic.claude-opus-5`, a Bedrock ARN — and the rate is a property of the model
    rather than of the path to it.

    **The keys come from the table actually in force, not from three literals here.**
    Step 045c, and it is the one genuine blocker the model connector had. Until it, this
    matched `opus`/`sonnet`/`haiku` and nothing else, which meant an operator who
    registered OpenAI and wrote correct GPT prices into `CARNET_MODEL_RATES` still got
    `$0.00`: their table was keyed `gpt-5`, the lookup asked this function for a family,
    this function had never heard of it, and no key in their file was ever reached. A
    dollar ceiling over that traffic bounded nothing while looking like it did.

    The defect was never the refusal to guess — it is that the table's keys could not be
    extended by the person who knows the prices. So the table is the vocabulary, and
    with no override the vocabulary is the built-in three and the behaviour is
    **identical**.

    **Longest key first**, then alphabetically, rather than dict order. The built-in
    three are disjoint so the result is unchanged, which is what the existing tests
    assert; the ordering is for the table somebody writes next, where `claude-opus-5`
    and `claude-opus-5-mini` can both match one id and the more specific key is the one
    that meant it. Deterministic either way, which is the property that matters: a rate
    must not depend on insertion order.

    **`""` rather than a fallback to the middle tier**, which is the tempting shape and
    the wrong one: it prices an unrecognised model at some other model's rate and reports
    a number, so a model released next quarter is billed at today's Sonnet rate and
    nothing anywhere says so. Here an unknown model is *reported as unpriced* and
    contributes nothing to an estimate. A number that is quietly wrong is the failure 013
    refused a cost column over, and reproducing it inside the estimator would be refusing
    it in the schema and then building it one layer up.
    """
    lowered = (model or "").lower()
    table = RATES if rates is None else rates
    for family in sorted(table, key=lambda key: (-len(key), key)):
        # A table with an empty key would match every id including `''`, which is the
        # one thing `parse_report` is careful to keep meaning *unpriced*.
        if family and family.lower() in lowered:
            return family
    return ""


@dataclass
class TokenUsage:
    """Four counters, and the arithmetic over them. No I/O, no clock, no storage.

    One counter per field the API reports, so every one of them is a field read.
    Nothing here is estimated, inferred or re-tokenized — which is what makes these
    numbers the same numbers an invoice is computed from rather than an approximation of
    them.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    @property
    def total(self) -> int:
        """Every token the reply accounted for, generated and sent alike.

        Useful for ranking and useless for money — the four are priced differently
        enough that a total cannot be multiplied by anything. `estimate_cost` never
        reads this.
        """
        return (
            self.input_tokens
            + self.output_tokens
            + self.cache_read_tokens
            + self.cache_write_tokens
        )

    @property
    def context_tokens(self) -> int:
        """What was *sent* — input plus both cache kinds, output excluded.

        The occupancy question rather than the spend question: this is the number that
        is measured against the model's context window, and generated output is not in
        the prompt that was sent.
        """
        return self.input_tokens + self.cache_read_tokens + self.cache_write_tokens

    def __add__(self, other: "TokenUsage") -> "TokenUsage":
        return TokenUsage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            cache_read_tokens=self.cache_read_tokens + other.cache_read_tokens,
            cache_write_tokens=self.cache_write_tokens + other.cache_write_tokens,
        )

    def to_dict(self) -> dict:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
            "total_tokens": self.total,
        }

    @staticmethod
    def from_row(row) -> "TokenUsage":
        """The four counters off a `runs` row — or off anything shaped like one.

        A row rather than a dataclass is what storage hands back everywhere in this
        codebase (`storage/base.py` states that as a design rather than a gap), so the
        reporting side reads dicts and this is the one place that knows their keys.

        `or 0` rather than a default, because both stores write `0` and neither writes
        `None` — this defends against a row assembled by a test or a caller, not
        against the schema.
        """
        return TokenUsage(
            input_tokens=row.get("input_tokens") or 0,
            output_tokens=row.get("output_tokens") or 0,
            cache_read_tokens=row.get("cache_read_tokens") or 0,
            cache_write_tokens=row.get("cache_write_tokens") or 0,
        )


def usage_of_reply(reply) -> "TokenUsage | None":
    """One model reply's usage, or None when the provider sent none.

    **None is not zero and the difference is load-bearing.** A reply that genuinely used
    no tokens does not exist; a reply carrying no `usage` means the count is *missing*,
    and 013's edge table settles what happens then — zeros and a warning, never a guess
    and never a crash. The caller distinguishes the two; this only reports which it saw.

    Attribute access rather than `dict.get` because this is the SDK's response object.
    The two cache fields arrived with prompt caching and are absent on older shapes and
    `None` when nothing was cached, so both are defended.
    """
    usage = getattr(reply, "usage", None)
    if usage is None:
        return None

    return TokenUsage(
        input_tokens=getattr(usage, "input_tokens", 0) or 0,
        output_tokens=getattr(usage, "output_tokens", 0) or 0,
        cache_read_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
        cache_write_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
    )


@dataclass
class Meter:
    """What one run has spent so far. Mutable, per run, read by whoever holds the row.

    The seventh member of the family a call context carries — call id,
    cancellation, history, attachment, activity, and now this — and it arrives by the
    family's argument: **the loop is the only thing that sees a reply, and `core/` may
    not import the storage that would record one.** So the loop writes here and the
    tier holding the row reads it afterwards, on every path out including the failing
    ones. A run handed no meter counts nothing, which is every run before 013.

    Not thread-safe, and does not need to be: one loop, one meter, one thread. The same
    sentence `Budget` carries, and it becomes false in the same circumstance — a runtime
    that ever issues model calls concurrently is the thing that has to revisit both.
    """

    # What was actually called, which is not what the config said. See `record`.
    model: str = ""
    total: TokenUsage = field(default_factory=TokenUsage)
    # The largest single turn's context. Not derivable from `total`: a run's totals are
    # the *sum* over turns, and a loop that resends its whole message list every turn
    # sums to far more than any one prompt ever was. Occupancy is a per-turn maximum or
    # it is nothing.
    peak_context_tokens: int = 0
    # Replies whose `usage` the provider did not send. Counted rather than only logged,
    # so a total can say *how much of it was measured* — a run reporting zero tokens
    # because nothing was counted and one reporting zero because nothing was spent are
    # different facts, and only this tells them apart.
    unmeasured_replies: int = 0

    def record(self, requested_model: str, reply) -> None:
        """Add one model reply to this run's totals. Never raises.

        `requested_model` is what the loop asked for; **what is kept is what the reply
        says it was served by**, when it says. The two differ routinely — an alias
        resolves to a dated id — and the served id is the one the bill is computed
        against, which makes it the only one worth recording. 013's edge table already
        chose this shape for the other half of the same question ("an agent with no
        `model` in its config records `DEFAULT_MODEL`, not `''` — what the call actually
        used, never what the config omitted"); this is that rule applied one step
        further down.

        A reply with no `usage` costs a warning and a counter, and specifically not an
        exception: this is called immediately after a model call that has already
        succeeded, and a run that produced an answer must never fail over the
        bookkeeping about it. That is the audit writer's rule, one layer down.
        """
        self.model = getattr(reply, "model", "") or requested_model or self.model

        turn = usage_of_reply(reply)
        if turn is None:
            self.unmeasured_replies += 1
            log.warning(
                "model reply carried no usage — this run's token counts are short by "
                "one reply (model %s). Recorded as unmeasured rather than guessed.",
                self.model or "?",
            )
            return

        self.total = self.total + turn
        self.peak_context_tokens = max(self.peak_context_tokens, turn.context_tokens)

    def snapshot(self) -> dict:
        """The columns a `runs` row holds, ready to hand to `finish_run`.

        Keyed exactly as the columns are named, so the write is a `**` rather than six
        assignments that can drift from the schema one at a time.
        """
        return {
            "model": self.model,
            "input_tokens": self.total.input_tokens,
            "output_tokens": self.total.output_tokens,
            "cache_read_tokens": self.total.cache_read_tokens,
            "cache_write_tokens": self.total.cache_write_tokens,
            "peak_context_tokens": self.peak_context_tokens,
        }

    def __repr__(self) -> str:  # pragma: no cover - diagnostics
        short = f", {self.unmeasured_replies} unmeasured" if self.unmeasured_replies else ""
        return f"<Meter {self.model or '?'} {self.total.total} tokens{short}>"


def estimate_cost(model: str, usage: TokenUsage, rates: dict | None = None) -> "float | None":
    """Estimated USD for `usage` at `model`'s rates, or **None if the model is unpriced**.

    None is the whole point of the signature. Every caller has to decide what to do
    about a model nobody has a price for, and the two honest answers are *say so* and
    *leave it out of the total* — both of which need to be able to tell that case from a
    genuine zero. A float fallback would make an unpriced model indistinguishable from a
    free one at every call site at once.

    `rates` defaults to the dated snapshot in this module. Pass the operator's own table
    (`config.model_rates()`) to price against a contract rather than a list price — and
    since 045c that table is also the **vocabulary**: `model_family` matches against its
    keys, so an operator's own model ids are reached by their own prices. The table is
    resolved before the family is asked for, which is the whole of that change here.
    """
    table = RATES if rates is None else rates
    family = model_family(model, table)
    rate = table.get(family) if family else None
    if rate is None:
        return None

    return (
        usage.input_tokens * rate["input"]
        + usage.output_tokens * rate["output"]
        + usage.cache_read_tokens * rate["cache_read"]
        + usage.cache_write_tokens * rate["cache_write"]
    ) / 1_000_000.0


def price_buckets(buckets, rates=None) -> tuple:
    """`(usd, tokens, unpriced_models)` for rows already grouped by model. Step 013c.

    **The one reader of the rate table that survived step 084**, and it arrived here from
    `core/usage_query.py` when the rest of that module went. The module it left was the
    reader half of a writer/reader pair over `runs` rows — *"Reading what `usage.Meter`
    wrote"* — and this function was never that: what it prices is the token columns the
    **broker** writes onto an `audit` row (`broker.py`, step 045b), for a caller that has
    no run. It sits beside `estimate_cost` now because the rate table is what it is about.

    Two rules, and they are the rules money obeys here rather than an implementation
    detail of any one caller:

    **Priced per model bucket, never blended.** A window spans many calls to many models
    and Opus output is five times Sonnet output per token, so one flat rate over a total
    is wrong by whatever the mix happened to be that day, in a direction nobody can
    predict. Migration `046_spend_by_principal.sql` groups by model in SQL for the same
    reason and its header says so — it credits the rule to `cost_of`, which was the run
    report's spelling of it and left with 084. The rule did not: this is where it lives.

    **An unpriced model contributes nothing and is named.** A model with no rate adds
    nothing to `usd`, so a caller printing the figure alone would understate a bill
    silently and by an unknown amount. Every caller is handed the reason instead —
    `door.door_spend` returns `unpriced_models` beside `usd`, and the Overview's tile
    unions them across the window.

    The third return is the one a ceiling needs and a report does not: the token total.
    A spend gate reads both — dollars for the limit a person was told, tokens for the net
    underneath it that catches whatever the price list could not value.
    """
    priced = 0.0
    tokens = 0
    unpriced = set()
    for bucket in buckets:
        usage = TokenUsage.from_row(bucket)
        tokens += usage.total
        amount = estimate_cost(bucket.get("model") or "", usage, rates)
        if amount is None:
            if usage.total:
                unpriced.add(bucket.get("model") or "(unmeasured)")
            continue
        priced += amount
    return priced, tokens, sorted(unpriced)


def rates():
    """The operator's rate table, or None for the built-in snapshot. **Never raises.**

    `config.model_rates()` raises on a missing or malformed file, deliberately: an
    operator who pointed at their own prices should not silently get somebody else's.
    That is right on a report and wrong on a gate — step 013c put a spend ceiling on the
    submit path, and 045b put one at the door, so a typo in a JSON file would otherwise
    refuse every run *and* every brokered call in the deployment.

    So the failure degrades to the built-in table and says so loudly in the log. The
    ceilings still bound; they bound against list prices until somebody fixes the file.

    **Here rather than beside the caller, where 013c first wrote it, and the move is
    the point.** The door needs this behaviour and nothing above `core/` should own it. Two copies would be two answers to *what does a token cost* — the exact
    disagreement `spend_today`'s "one function, two readers" argument exists to prevent,
    one layer further down. `runs._rates` is now this function under its old name.
    """
    try:
        return config.model_rates()
    except Exception:  # noqa: BLE001 - see above
        log.exception(
            "CARNET_MODEL_RATES could not be read; spend ceilings are being enforced "
            "against built-in list prices until it is fixed"
        )
        return None


# The four counters a usage report may carry, and the only names read off one. `model`
# is deliberately not in this tuple: it says *what* answered, not *how much*, and a
# report naming only a model is a report of nothing — see `parse_report`.
COUNTER_FIELDS = (
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
)

# The largest single counter a tool may report, per call. Step 045b.
#
# **A sanity bound, not a ceiling** — the ceiling is `config.MCP_USD_PER_DAY` and it is
# enforced somewhere else entirely. This is the line past which a number stops being a
# plausible report and starts being a bug or a lie, and the distinction matters because
# of who is reporting: not a reply this process just received, but a connector's response
# body, reached through a path a vetter authored. A tool that reports 10**15 output
# tokens would exhaust any dollar ceiling in one call and lock a principal out for the
# day, which is a denial of service written in a JSON field.
#
# A billion is roughly a thousand times the largest context window on the market, so
# nothing real reaches it and nothing real is refused by it.
MAX_REPORTED_TOKENS = 1_000_000_000


def parse_report(report) -> "tuple[str, TokenUsage] | None":
    """A tool's own usage report as `(model, TokenUsage)` — or **None for anything
    untrustworthy**. Step 045b. Never raises.

    Two carriers funnel here, both outside this deployment's control: a REST binding's
    `usage_map` lifting counters out of a vendor's response body, and an MCP server's
    `_meta` on its `CallToolResult`. Both are *the callee's word*, which is what makes
    this a parser with a refusal rather than a constructor.

    **The refusal direction is the whole design.** These counters gate money: they are
    summed by `door_spend_since` and compared against a principal's daily ceiling. A
    connector that could report a large number could spend somebody else's allowance
    without making a single expensive call — so a report that is not four plain
    non-negative integers within `MAX_REPORTED_TOKENS` is **dropped entirely**, with a
    log line, and the call is audited with NULL usage. Dropping under-counts, which is
    the failure that costs a customer nothing; trusting would over-count, which is the
    failure that refuses their traffic.

    Dropped as a whole rather than field by field: a report with one bad counter is a
    report from something that does not know what it is reporting, and keeping the three
    counters that happened to parse would put a confidently wrong number in the meter.

    `bool` is refused explicitly because `isinstance(True, int)` is true in Python and
    `True` would arrive as one token — a silent 1 is worse than a loud drop.

    A report with no `model` is legal and returns `('', usage)`: the tokens are recorded
    and priced by nobody, which is `estimate_cost`'s existing honesty rather than a new
    rule. `unpriced_models` is where that surfaces.
    """
    if report is None:
        return None
    if not isinstance(report, dict):
        log.warning(
            "a tool reported usage as %s rather than a mapping; dropped. Token counts "
            "for this call are not recorded.",
            type(report).__name__,
        )
        return None

    counters = {}
    present = 0
    for field_name in COUNTER_FIELDS:
        if field_name in report:
            present += 1
        value = report.get(field_name, 0)
        # Absent is zero — a vendor that does not use prompt caching sends no cache
        # counters, and demanding all four would drop every honest report from the
        # majority of APIs.
        if value is None:
            value = 0
        if isinstance(value, bool) or not isinstance(value, int):
            log.warning(
                "a tool reported %s as %r; the whole usage report was dropped rather "
                "than partially trusted. This call is audited with no token counts.",
                field_name,
                value,
            )
            return None
        if value < 0 or value > MAX_REPORTED_TOKENS:
            log.warning(
                "a tool reported %s = %d, outside 0..%d; the whole usage report was "
                "dropped. A counter this size is a bug or a claim on somebody's daily "
                "allowance, and neither belongs in the meter.",
                field_name,
                value,
                MAX_REPORTED_TOKENS,
            )
            return None
        counters[field_name] = value

    # **A model name is not a usage report**, and this is the check the live end-to-end
    # found missing. A `usage_map` names `model` beside the counters, so a vendor whose
    # reply carries a model and no `usage` object at all — an error body, a changed
    # response shape, a non-model endpoint sharing the binding — produced a report of
    # `{"model": ...}`, which fell through the absent-is-zero rule above and was recorded
    # as **four zeros**.
    #
    # That is the one distinction migration 048 exists for, inverted: `0` says *a model
    # call that spent nothing*, which does not happen, where the truth was *this call
    # touched no model*. It also enrolled every such row in `door_spend_since`, whose
    # whole predicate is `input_tokens IS NOT NULL`.
    #
    # So: at least one counter has to be **present**, not non-zero. An explicit
    # `{"input_tokens": 0}` is a real report of a real zero and is kept.
    if not present:
        log.warning(
            "a tool reported usage naming no token counter at all (%s); dropped. The "
            "call is recorded as having touched no model, which is what an absent "
            "counter means.",
            ", ".join(sorted(report)) or "empty",
        )
        return None

    model = report.get("model") or ""
    if not isinstance(model, str):
        log.warning(
            "a tool reported model as %r rather than a string; the usage report was "
            "dropped.",
            model,
        )
        return None
    # The same bound `audit.model` carries in the schema is not expressed as a CHECK, so
    # it is expressed here: a model name is an identifier, not a payload, and this table
    # is append-only and kept for the retention window.
    model = model[:200]

    return model, TokenUsage(**counters)


__all__ = [
    "COUNTER_FIELDS",
    "MAX_REPORTED_TOKENS",
    "RATES",
    "RATES_CHECKED",
    "Meter",
    "TokenUsage",
    "day_window",
    "estimate_cost",
    "metered",
    "model_family",
    "parse_report",
    "price_buckets",
    "rates",
    "usage_of_reply",
]
