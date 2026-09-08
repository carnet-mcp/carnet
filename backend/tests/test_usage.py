"""What a run spent at the model: counted, accumulated, recorded, reported. Step 013.

Four layers, and the file is ordered by them because each one can be wrong on its own:

  - **`core/usage.py`** — the arithmetic. Four counters, a rate table, and the rule that
    an unpriced model is reported as unpriced rather than quietly billed at some other
    model's rate.
  - **the loop** — `simple.py` reading `response.usage` off a reply it already made.
    Driven through the *real* Tier 1 loop against a scripted client, because the thing
    under test is the call site: a test that asserted on a `Meter` directly would keep
    passing after somebody deleted the one line in `simple.py` that feeds it.
  - **`runs.execute`** — the numbers reaching the row on **every** path out, including
    the three that raise. A run that hit `MAX_TURNS` spent everything an ordinary run
    spends and produced no answer, so it is the most expensive kind there is and the one
    a naive implementation forgets.
  - **`price_buckets`** — pricing a window's rows, which is the last of `usage_query.py`
    and now lives in `core/usage.py` beside the table it reads. Pure over rows, so every
    assertion is a list of dicts and no database. **The rest of that module — a run
    report of percentiles, seven groupings and a top-N — went in step 084**, along with
    the ~300 lines of this file that were its only caller: nothing outside its own tests
    ever called any of it, and this tree runs no runs to report on.

`tests/test_storage_contract.py` holds what belongs to the table itself — that both
stores round-trip the six columns, that a refused second finish writes nothing, and that
a negative counter is refused — because those run against real Postgres, where a
`GREATEST` or a `COALESCE` written wrong is invisible to the fake's dict.

The model is never called. Every reply in this file is a scripted object, which is what
makes the token counts assertable: they are markers chosen to be wrong in an obvious way
if anything sums, replaces or drops the wrong one.
"""


import pytest

from carnet import storage
from carnet.core import Principal
from carnet.core.usage import (
    MAX_REPORTED_TOKENS,
    RATES,
    Meter,
    TokenUsage,
    estimate_cost,
    model_family,
    parse_report,
    price_buckets,
    rates,
)
from carnet.storage.base import StorageError, normalize_usage

from conftest import TEST_TENANT

CONFIG = {
    "name": "demo",
    "system": "You are a demo agent.",
    "permissions": {"tools": [], "scope": {}},
}


@pytest.fixture
def priya():
    return Principal.user("u_priya", TEST_TENANT)


class Reply:
    """One scripted model reply, carrying exactly what the SDK's response carries.

    Attribute access rather than a dict, because that is what `usage_of_reply` reads and
    a dict-shaped fake would pass while the real object failed. `stop_reason` defaults to
    something that is *not* `tool_use`, so one reply ends a run.
    """

    def __init__(self, *, model="claude-sonnet-4-6", text="done", usage=True, **counts):
        self.model = model
        self.stop_reason = "end_turn"
        self.content = [_Text(text)]
        self.usage = _Usage(**counts) if usage else None


class _Text:
    type = "text"

    def __init__(self, text):
        self.text = text


class _Usage:
    def __init__(
        self,
        input_tokens=0,
        output_tokens=0,
        cache_read_input_tokens=0,
        cache_creation_input_tokens=0,
    ):
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.cache_read_input_tokens = cache_read_input_tokens
        self.cache_creation_input_tokens = cache_creation_input_tokens


# --- the arithmetic ------------------------------------------------------------------


def test_the_four_counters_add_and_never_blend():
    a = TokenUsage(input_tokens=10, output_tokens=1, cache_read_tokens=100, cache_write_tokens=5)
    b = TokenUsage(input_tokens=1, output_tokens=2, cache_read_tokens=3, cache_write_tokens=4)

    total = a + b

    assert (total.input_tokens, total.output_tokens) == (11, 3)
    assert (total.cache_read_tokens, total.cache_write_tokens) == (103, 9)
    assert total.total == 126


def test_context_excludes_output_and_total_includes_it():
    """The two properties answer different questions and must not be confused.

    `total` is what was spent; `context_tokens` is what was *sent*, which is the only one
    that can be measured against a context window. Generated output is not in the prompt.
    """
    usage = TokenUsage(input_tokens=10, output_tokens=7, cache_read_tokens=3, cache_write_tokens=1)

    assert usage.context_tokens == 14
    assert usage.total == 21


def test_a_model_nobody_has_a_rate_for_is_unpriced_rather_than_guessed():
    """**The assertion the whole pricing design exists for.**

    The tempting shape is a fallback to the middle tier, and it is the wrong one: a model
    released next quarter would be billed at today's Sonnet rate and no report anywhere
    would say so. None is what lets every caller tell "we do not know" from "it was free".
    """
    usage = TokenUsage(input_tokens=1_000_000)

    assert model_family("some-other-vendor-model-v9") == ""
    assert estimate_cost("some-other-vendor-model-v9", usage) is None
    # And a known one is a real number, so the None above is a decision rather than a
    # table that does not work.
    assert estimate_cost("claude-sonnet-4-6", usage) == pytest.approx(3.00)


def test_each_kind_of_token_is_priced_at_its_own_rate():
    """Folding cache reads into input would overstate them by ten times; folding cache
    writes in would understate them. Both directions asserted at once."""
    rates = {"sonnet": {"input": 3.0, "output": 15.0, "cache_read": 0.3, "cache_write": 3.75}}

    cost = estimate_cost(
        "claude-sonnet-4-6",
        TokenUsage(
            input_tokens=1_000_000,
            output_tokens=1_000_000,
            cache_read_tokens=1_000_000,
            cache_write_tokens=1_000_000,
        ),
        rates,
    )

    assert cost == pytest.approx(3.0 + 15.0 + 0.3 + 3.75)


def test_the_model_family_is_read_out_of_any_spelling_of_the_id():
    """The same model arrives under several ids depending on how it was reached, and the
    rate is a property of the model rather than of the path to it."""
    for spelling in ("claude-opus-5", "anthropic.claude-opus-5", "CLAUDE-OPUS-5[1m]"):
        assert model_family(spelling) == "opus"


# --- the rate table is the vocabulary, not three literals ---------------------------
#
# Step 045c. `model_family` used to match `opus`/`sonnet`/`haiku` and nothing else, which
# made `CARNET_MODEL_RATES` an override that could correct a *number* and never add a
# *model*: a customer brokering OpenAI wrote correct GPT prices into their file and still
# got `$0.00`, because no key in it was ever reached. The first test below is the
# backward-compatibility assertion and the rest are the hole closing.


def test_the_built_in_families_are_unchanged_by_the_table_lookup():
    """**Decision 3's backward-compatibility claim, asserted rather than assumed.** With
    no override the vocabulary is the built-in three and every id resolves exactly where
    it did — passing the table explicitly must be the same answer as passing nothing."""
    for spelling in ("claude-opus-5", "claude-sonnet-4-6", "claude-haiku-4-5", "gpt-5"):
        assert model_family(spelling) == model_family(spelling, RATES)


def test_an_operators_own_keys_are_reached_by_their_own_models():
    """The whole of 045c's blocker. A table keyed by a customer's model ids prices a
    customer's models — and a model *that table* does not name is still unpriced, so
    extending the vocabulary did not turn the refusal into a guess."""
    table = {
        "gpt-5": {"input": 1.25, "output": 10.0, "cache_read": 0.125, "cache_write": 0.0},
        "claude-opus-5": {
            "input": 15.0,
            "output": 75.0,
            "cache_read": 1.5,
            "cache_write": 18.75,
        },
    }
    million = TokenUsage(input_tokens=1_000_000)

    assert model_family("gpt-5-mini", table) == "gpt-5"
    assert estimate_cost("gpt-5-mini", million, table) == pytest.approx(1.25)
    assert estimate_cost("claude-opus-5", million, table) == pytest.approx(15.0)
    # And the third provider nobody wrote a price for stays honest.
    assert model_family("gemini-2.5-pro", table) == ""
    assert estimate_cost("gemini-2.5-pro", million, table) is None


# Verification 2 — the operator's own table reaching the operator's own figure — moved
# to `test_the_operators_table_is_threaded_all_the_way_to_the_figure` below, when 084
# deleted the report it used to be asserted through. The rollup test that sat here went
# with `by_model_family`: its claim was that a rollup must be keyed by the vocabulary its
# money was computed from, and there is no rollup left in this tree to key. What made the
# rollup right in the first place — the table *is* the vocabulary — is
# `test_an_operators_own_keys_are_reached_by_their_own_models`, above, unchanged.


def test_the_longest_matching_key_wins_so_a_rate_never_depends_on_dict_order():
    """Two keys can match one id once a customer writes the table, and which one applies
    must not be insertion order. Longest first: the more specific key is the one that
    meant this model."""
    table = {
        "gpt-5": {"input": 1.0, "output": 1.0, "cache_read": 1.0, "cache_write": 1.0},
        "gpt-5-mini": {"input": 9.0, "output": 9.0, "cache_read": 9.0, "cache_write": 9.0},
    }
    reversed_table = dict(reversed(list(table.items())))

    assert model_family("gpt-5-mini", table) == "gpt-5-mini"
    assert model_family("gpt-5-mini", reversed_table) == "gpt-5-mini"
    assert model_family("gpt-5-turbo", table) == "gpt-5"


def test_an_empty_key_in_a_table_does_not_swallow_every_model():
    """A rate file with a `""` key is a typo, and `""` is a substring of everything —
    including the empty model id `parse_report` returns for a report that named none.
    Skipped rather than matched, so *unpriced* keeps meaning unpriced."""
    table = {"": {"input": 1.0, "output": 1.0, "cache_read": 1.0, "cache_write": 1.0}}

    assert model_family("gpt-5", table) == ""
    assert estimate_cost("gpt-5", TokenUsage(input_tokens=10), table) is None


# --- a tool's own report, and why it is not believed on sight ------------------------
#
# Step 045b. Everything above this line reads a reply *this process* just received. These
# counters are the opposite: a connector's response body, reached through a path a vetter
# authored, and they gate money. So this is a parser with a refusal rather than a
# constructor, and the refusal direction is the design — dropping under-counts, which
# costs a customer nothing; trusting over-counts, which refuses their traffic.


def test_a_well_formed_report_becomes_a_model_and_four_counters():
    assert parse_report(
        {
            "model": "claude-opus-5",
            "input_tokens": 1,
            "output_tokens": 2,
            "cache_read_tokens": 3,
            "cache_write_tokens": 4,
        }
    ) == ("claude-opus-5", TokenUsage(1, 2, 3, 4))


def test_an_absent_counter_is_zero_because_most_vendors_send_three():
    """A vendor that does not use prompt caching sends no cache counters, and demanding
    all four would drop every honest report from the majority of APIs."""
    assert parse_report({"input_tokens": 5}) == ("", TokenUsage(input_tokens=5))


def test_a_report_with_no_model_is_recorded_and_priced_by_nobody():
    """`''` and `estimate_cost`'s existing honesty, rather than a new rule: the tokens are
    real, the price is unknown, and `unpriced_models` is where that surfaces."""
    model, usage = parse_report({"input_tokens": 5})

    assert model == ""
    assert estimate_cost(model, usage) is None


@pytest.mark.parametrize(
    "report",
    [
        pytest.param({"input_tokens": -1}, id="negative subtracts from a ceiling"),
        pytest.param({"input_tokens": 10**15}, id="past MAX_REPORTED_TOKENS"),
        pytest.param({"input_tokens": "many"}, id="not a number"),
        pytest.param({"input_tokens": 1.5}, id="not a whole number"),
        pytest.param({"input_tokens": True}, id="a bool is an int in Python"),
        pytest.param({"model": 7}, id="a model that is not a name"),
        pytest.param("9000", id="not a mapping"),
        pytest.param([1, 2], id="not a mapping either"),
    ],
)
def test_an_untrustworthy_report_is_dropped_whole(report):
    """**The refusal that costs money.** A connector reporting an absurd number would
    exhaust a principal's allowance in one call without making an expensive one — a denial
    of service written in a JSON field."""
    assert parse_report(report) is None


def test_a_report_naming_only_a_model_is_not_a_usage_report():
    """**Found by the live end-to-end, not by this file**, which is why it is worth a
    named test rather than a parametrize case.

    A `usage_map` names `model` beside the counters, so a vendor reply carrying a model
    and no `usage` object at all — an error body, a changed response shape, an endpoint
    sharing the binding — produced `{"model": ...}`. That fell through the absent-is-zero
    rule and was recorded as **four zeros**: *a model call that spent nothing*, which does
    not happen, in place of *this call touched no model*. It also enrolled the row in
    `door_spend_since`, whose whole predicate is `input_tokens IS NOT NULL`.
    """
    assert parse_report({"model": "claude-opus-5"}) is None
    assert parse_report({}) is None


def test_an_explicit_zero_counter_is_a_real_report_and_is_kept():
    """The other side of the line above: the test is whether a counter is **present**,
    not whether it is non-zero. A vendor that genuinely served a cached turn reports
    `input_tokens: 0` and means it."""
    model, usage = parse_report({"model": "m", "input_tokens": 0})

    assert model == "m"
    assert usage == TokenUsage()


def test_a_report_with_one_counter_and_no_model_is_still_a_report():
    """Counters are what make it a report; the model only prices it."""
    assert parse_report({"cache_read_tokens": 7}) == (
        "",
        TokenUsage(cache_read_tokens=7),
    )


def test_a_report_with_one_bad_counter_is_not_partly_trusted():
    """A report with one bad field is a report from something that does not know what it
    is reporting. Keeping the three that parsed would put a confidently wrong number in
    the meter, which is worse than an honest gap."""
    assert parse_report({"input_tokens": 100, "output_tokens": -1}) is None


def test_nothing_reported_is_nothing_rather_than_zero():
    assert parse_report(None) is None


def test_the_bound_admits_everything_real_and_refuses_the_absurd():
    """A billion is roughly a thousand times the largest context window on the market, so
    nothing real reaches it and nothing real is refused by it."""
    assert parse_report({"input_tokens": MAX_REPORTED_TOKENS}) is not None
    assert parse_report({"input_tokens": MAX_REPORTED_TOKENS + 1}) is None


def test_a_model_name_is_bounded_because_this_table_is_kept_forever():
    """An identifier, not a payload — and `audit` is append-only and held for the
    retention window."""
    model, _ = parse_report({"model": "m" * 5000, "input_tokens": 1})

    assert len(model) == 200


def test_rates_degrade_to_list_prices_rather_than_refusing_every_call(monkeypatch):
    """`config.model_rates()` raises on a malformed override, deliberately — an operator
    who pointed at their own prices should not silently get somebody else's. That is right
    on a report and wrong on a gate: this sits on the submit path *and* the door's hot
    path, so a JSON typo must not refuse a deployment's whole day."""
    from carnet.core import usage as usage_module

    def broken():
        raise ValueError("expecting ',' delimiter")

    monkeypatch.setattr(usage_module.config, "model_rates", broken)

    assert rates() is None  # None means "use the built-in snapshot"


# --- the meter -----------------------------------------------------------------------


def test_the_meter_records_what_the_reply_says_it_was_served_by():
    """An alias resolves to a dated id, and the dated id is what the invoice is computed
    against — so the reply's own `model` wins over the one the config asked for."""
    meter = Meter()

    meter.record("claude-sonnet-4-6", Reply(model="claude-sonnet-4-6-20260215", input_tokens=1))

    assert meter.model == "claude-sonnet-4-6-20260215"


def test_a_reply_that_names_no_model_falls_back_to_what_was_asked_for():
    reply = Reply(input_tokens=1)
    del reply.model
    meter = Meter()

    meter.record("claude-haiku-4-5", reply)

    assert meter.model == "claude-haiku-4-5"


def test_a_reply_with_no_usage_is_counted_as_unmeasured_and_never_raises(caplog):
    """013's edge table: *a provider response with no `usage` — zeros, and a warning log.
    Never a crash, and never a guess.*

    This runs immediately after a model call that already succeeded, so an exception here
    would fail a run that had produced its answer — over bookkeeping about it.
    """
    meter = Meter()

    meter.record("claude-sonnet-4-6", Reply(usage=False, input_tokens=999))

    assert meter.total.total == 0
    assert meter.unmeasured_replies == 1
    assert "no usage" in caplog.text.lower()


def test_the_peak_is_a_maximum_and_the_totals_are_a_sum():
    """The distinction migration 045 adds a column for.

    The loop resends its whole message list every turn, so the totals are many times any
    prompt that was ever actually sent. Occupancy is a per-turn maximum or it is nothing
    — asserted here by making the *larger* prompt the first one, so a `max` written as a
    "last value wins" would produce 20 and fail.
    """
    meter = Meter()

    meter.record("m", Reply(input_tokens=100, output_tokens=5))
    meter.record("m", Reply(input_tokens=20, output_tokens=5))

    assert meter.total.input_tokens == 120
    assert meter.peak_context_tokens == 100


# --- the loop ------------------------------------------------------------------------


# --- every path out of a run ---------------------------------------------------------


# --- what storage refuses ------------------------------------------------------------


def test_usage_with_a_key_that_is_not_a_column_is_refused():
    """One store would keep it forever as a field no read method returns and the other
    would refuse it with a syntax error. That is the drift `RUN_FIELDS` exists to stop,
    caught before either store sees it."""
    with pytest.raises(StorageError, match="not a column"):
        normalize_usage({"input_tokens": 1, "thinking_tokens": 4})


def test_a_negative_counter_is_refused():
    """Migration 045's CHECK, for the store that has none. A negative counter is an
    assignment where an accumulation belongs, arriving from above."""
    with pytest.raises(StorageError, match="count up"):
        normalize_usage({"input_tokens": -1})


def test_a_token_count_that_is_not_a_whole_number_is_refused():
    """A float is a count somebody computed rather than read, which is the one thing this
    feature exists not to do. `True` is refused for the same reason wearing an int."""
    with pytest.raises(StorageError, match="whole number"):
        normalize_usage({"output_tokens": 1.5})
    with pytest.raises(StorageError, match="whole number"):
        normalize_usage({"output_tokens": True})


def test_no_usage_at_all_passes_straight_through():
    assert normalize_usage(None) is None


# --- pricing a window's rows. Step 013c, and what survived 084 -----------------------
#
# `core/usage_query.py` held a 479-line run report — percentiles, a spread, seven
# groupings, a top-N and a `summarize` that assembled them — and roughly 300 lines of
# this file asserted it. Step 084 deleted the module: `grep -rn "usage_query" src/`
# returned two imports, both `price_buckets`, and everything else had no caller outside
# its own tests.
#
# `price_buckets` moved to `core/usage.py` beside the rate table, and what is pinned
# below is what a customer's dollar figure is actually computed from. The two rules are
# the report's rules, kept because they are the rules money obeys here and not an
# implementation detail of the thing that went.


def buckets(*specs):
    """Rows as `spend_since` and `overview` hand them back: a model and four counters."""
    return [
        {
            "model": spec.get("model", "claude-sonnet-4-6"),
            "input_tokens": spec.get("input_tokens", 0),
            "output_tokens": spec.get("output_tokens", 0),
            "cache_read_tokens": spec.get("cache_read_tokens", 0),
            "cache_write_tokens": spec.get("cache_write_tokens", 0),
        }
        for spec in specs
    ]


def test_cost_is_summed_per_model_and_never_at_a_blended_rate():
    """A window spans many callers and therefore many models by construction, and Opus
    output is five times Haiku output per token. A blended rate is wrong by whatever the
    mix happens to be that day, in a direction nobody can predict — which is also why
    migration 046 groups by model in SQL rather than summing there."""
    priced, tokens, unpriced = price_buckets(
        buckets(
            {"model": "claude-opus-5", "output_tokens": 1_000_000},
            {"model": "claude-haiku-4-5", "output_tokens": 1_000_000},
        )
    )

    assert unpriced == []
    assert priced == pytest.approx(75.0 + 4.0)
    assert tokens == 2_000_000


def test_an_unpriced_model_is_named_rather_than_silently_omitted():
    """A total that dropped it would understate the bill by an unknown amount — the one
    wrong answer that looks exactly like a right one. `door.door_spend` returns this list
    beside the figure precisely so the figure reads as short rather than whole."""
    priced, tokens, unpriced = price_buckets(
        buckets(
            {"model": "claude-sonnet-4-6", "output_tokens": 1_000_000},
            {"model": "some-other-vendor-model", "output_tokens": 9_000_000},
        )
    )

    assert priced == pytest.approx(15.0)
    assert unpriced == ["some-other-vendor-model"]
    # **The token total counts what the dollars could not.** That is the third return's
    # whole reason for existing: a ceiling reads dollars for the limit a person was told
    # and tokens for the net underneath it, and an unpriced model must not slip through
    # both.
    assert tokens == 10_000_000


def test_a_model_reported_with_no_tokens_at_all_is_not_called_unpriced():
    """`if usage.total` guards the naming, and it is not a micro-optimisation: a row with
    a model and four zeros contributes nothing to a bill either way, and reporting it as
    *unpriced* would put a scary word on the page about a call that cost nothing."""
    _, tokens, unpriced = price_buckets(buckets({"model": "who-knows"}))

    assert (tokens, unpriced) == (0, [])


def test_a_bucket_with_no_model_is_named_rather_than_dropped():
    """The `''` model — a call whose usage was reported without one. It cannot be priced,
    so it is `(unmeasured)` in the list rather than absent from it: a gap in a total that
    nothing admits to is the failure this whole return shape exists to prevent."""
    _, tokens, unpriced = price_buckets([{"model": "", "input_tokens": 10}])

    assert (tokens, unpriced) == (10, ["(unmeasured)"])


def test_an_empty_window_is_zeros_rather_than_a_special_case():
    """A tenant with no spend is an ordinary tenant, and every caller renders this
    directly — a shape that had to be branched on in three places is a shape one of them
    would get wrong."""
    assert price_buckets([]) == (0.0, 0, [])


def test_the_operators_table_is_threaded_all_the_way_to_the_figure():
    """045c, at the level a page reads it, and the assertion whose failure was the whole
    of that step: `priced` was `0.0` and *both* models were unpriced, because the family
    lookup had never heard of either key.

    **Through `price_buckets` since 084**, where it went through the report's `cost_of`
    before. The claim is unchanged and it is now made against the function the Overview
    and `door.door_spend` really call."""
    table = {
        "gpt-5": {"input": 1.0, "output": 1.0, "cache_read": 1.0, "cache_write": 1.0},
        "claude-opus-5": {"input": 2.0, "output": 2.0, "cache_read": 2.0, "cache_write": 2.0},
    }

    priced, _, unpriced = price_buckets(
        buckets(
            {"model": "gpt-5-mini", "input_tokens": 1_000_000},
            {"model": "claude-opus-5", "input_tokens": 1_000_000},
            {"model": "mistral-large", "input_tokens": 1_000_000},
        ),
        table,
    )

    assert priced == pytest.approx(3.0)
    assert unpriced == ["mistral-large"]


# --- the tier above ------------------------------------------------------------------


def test_an_operators_own_rate_table_replaces_the_snapshot(priya, tmp_path, monkeypatch):
    """`CARNET_MODEL_RATES`, which is 013's *"the arithmetic belongs where prices are
    maintained"* with a filename on it. Asserted through a rate deliberately unlike the
    built-in one, so a report that ignored the file would not coincidentally match."""
    import json

    from carnet import config

    table = tmp_path / "rates.json"
    table.write_text(
        json.dumps({"sonnet": {"input": 1.0, "output": 1.0, "cache_read": 1.0, "cache_write": 1.0}})
    )
    monkeypatch.setattr(config, "MODEL_RATES_PATH", str(table))

    assert config.model_rates()["sonnet"]["output"] == 1.0
    assert config.model_rates_label() == str(table)


def test_a_rate_table_missing_one_kind_of_token_is_refused(tmp_path, monkeypatch):
    """**Refused rather than defaulted.** A missing rate prices that kind of token at
    nothing and reports a total that looks whole — and cache reads are most of a cached
    run's input, so the omission that reads as a typo is the one that halves the bill."""
    import json

    from carnet import config

    table = tmp_path / "rates.json"
    table.write_text(json.dumps({"sonnet": {"input": 3.0, "output": 15.0}}))
    monkeypatch.setattr(config, "MODEL_RATES_PATH", str(table))

    with pytest.raises(ValueError, match="cache_read"):
        config.model_rates()


@pytest.mark.parametrize(
    "table, match",
    [
        pytest.param(["opus"], "not a list", id="top level is a list"),
        pytest.param("opus", "not a str", id="top level is a string"),
        pytest.param({"gpt-5": [1, 2, 3, 4]}, "are a list", id="rate entry is a list"),
        pytest.param({"gpt-5": None}, "are a NoneType", id="rate entry is null"),
        pytest.param(
            {"gpt-5": {"input": True, "output": 1, "cache_read": 1, "cache_write": 1}},
            r"missing \['input'\]",
            id="a bool is not a rate",
        ),
        pytest.param(
            {"gpt-5": {"input": -5, "output": 1, "cache_read": 1, "cache_write": 1}},
            "negative",
            id="a negative rate",
        ),
        pytest.param(
            {"": {"input": 1, "output": 1, "cache_read": 1, "cache_write": 1}},
            "not usable as a key",
            id="an empty key",
        ),
    ],
)
def test_a_malformed_rate_file_is_refused_with_a_sentence_naming_it(
    tmp_path, monkeypatch, table, match
):
    """**Step 045c made this file load-bearing, so its failures had to become sentences.**

    Before 045c the keys here were decorative — `model_family` matched three built-in
    literals — so the file could correct a number and not add a model, and the people
    editing it were operators with a bespoke contract. It is now the only way a customer
    brokering any provider but Anthropic reaches a price at all.

    Five of these shapes escaped as a bare `AttributeError` off `.items()` or `.get()`,
    which reached a report as a traceback naming a Python method about a file the reader
    could have fixed in ten seconds. Two were *accepted*, which is worse:

      - `true` passed as a number, because `isinstance(True, int)` is true in Python —
        the same trap `VetRequest.max_response_bytes` documents at length and
        `check_limit` refuses. It priced a million tokens at one dollar.
      - a **negative** rate, and that one is invisible: spend falls as tokens are used,
        so a dollar ceiling can never be reached and nothing anywhere reports it. An
        unpriced model is at least named in `unpriced_models`.
    """
    import json

    from carnet import config

    path = tmp_path / "rates.json"
    path.write_text(json.dumps(table))
    monkeypatch.setattr(config, "MODEL_RATES_PATH", str(path))

    with pytest.raises(ValueError, match=match):
        config.model_rates()
    # And the ceiling path degrades rather than refusing a customer's whole day — 045b
    # decision 4, which only holds because the raise above is caught there.
    assert rates() is None


def test_a_zero_rate_is_legitimate_and_an_empty_table_is_not_malformed(
    tmp_path, monkeypatch
):
    """The refusals above must not catch the two honest edges: a vendor that does not
    charge for cache writes writes `0.0`, and a table somebody has started but not
    filled is empty rather than wrong."""
    import json

    from carnet import config

    path = tmp_path / "rates.json"
    path.write_text(
        json.dumps({"gpt-5": {"input": 1.0, "output": 1.0, "cache_read": 0, "cache_write": 0.0}})
    )
    monkeypatch.setattr(config, "MODEL_RATES_PATH", str(path))
    assert config.model_rates()["gpt-5"]["cache_write"] == 0.0

    path.write_text(json.dumps({}))
    assert config.model_rates() == {}
    # An empty table prices nothing, which is *unpriced* rather than free.
    assert estimate_cost("gpt-5", TokenUsage(input_tokens=10), {}) is None


# --- the ceiling that refuses. Step 013c ---------------------------------------------


@pytest.fixture
def ceiling(monkeypatch):
    """Set this deployment's per-person dials for one test."""

    def set_to(usd=0.0, tokens=0):
        from carnet import config

        monkeypatch.setattr(config, "USER_USD_PER_DAY", usd)
        monkeypatch.setattr(config, "USER_TOKENS_PER_DAY", tokens)

    return set_to


def spend(who="u_priya", kind="user", tenant=TEST_TENANT, tokens=1000,
          model="claude-sonnet-4-6", when=None):
    """Record a finished run that accounted for `tokens`, without running anything."""
    store = storage.active()
    run_id = f"spent{len(store._runs):07d}"
    store.enqueue_run(
        tenant,
        {"run_id": run_id, "agent": "demo", "principal_kind": kind,
         "principal_id": who, "task": "x"},
    )
    store.start_run(tenant, run_id)
    store.finish_run(
        tenant, run_id, "complete", answer="ok",
        usage={"model": model, "output_tokens": tokens},
    )
    if when is not None:
        store._runs[run_id]["finished_at"] = when
    return run_id


# 1M output tokens on Sonnet is $15.00 — the arithmetic every dollar test below leans on.
USD_PER_MTOK_SONNET_OUT = 15.0


# --- the meter a screen reads --------------------------------------------------------
