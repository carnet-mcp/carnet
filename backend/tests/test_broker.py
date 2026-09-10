"""Broker enforcement tests — the security boundary, so these are the ones that matter.

No API key and no model needed: the broker is called directly, exactly as the loop
calls it. `tmp_path` redirection keeps test runs out of the real audit log.
"""

import json

import pytest

from carnet import config
from carnet.core import audit, broker
from carnet.core.principal import Principal
from carnet import tools as tool_registry
from carnet.tools.base import Resource, Tool

from conftest import read_audit, run_context

# isolated_var_dir is autouse in conftest.py — every test here gets it, and so does
# every test anywhere else that reaches the broker.

AGENT = {
    "name": "test-agent",
    "system": "irrelevant",
    "runtime": "simple",
    "permissions": {
        "tools": ["read_repo", "post_message"],
        "scope": {
            "github.repo": {"read": ["octocat/Hello-World"]},
            "chat.channel": {"write": ["#eng"]},
        },
    },
}

# Every call in these tests is headless, matching how the CLI and scheduler run.
# Tenancy lives on the Principal, so every constructed principal carries one. A named
# constant rather than a literal: the tenant is routing here, not the thing under test.
TENANT = "t-test"

SYSTEM = Principal.system("test", TENANT)

# A read tool with a repo resource, registered for the duration of each test. The
# shipped registry has no hand-written reader any more — the GitHub one was retired
# once the connector replaced it — but the broker's behaviour on a scoped read still
# needs covering, and it should not depend on which tools happen to ship.
READER = Tool(
    name="read_repo",
    description="",
    input_schema={"type": "object", "properties": {"repo": {"type": "string"}}},
    impl=lambda repo: {"repo": repo},
    effect="read",
    resources=[Resource("github.repo", "repo")],
)


@pytest.fixture(autouse=True)
def stub_reader(monkeypatch):
    monkeypatch.setitem(tool_registry.REGISTRY, READER.name, READER)


@pytest.fixture(name="ctx")
def a_run_context():
    """A fresh run context per test.

    Deliberately NOT a module constant: a shared context shares budget counters, so
    tests would spend each other's allowance and the suite would go order-dependent.

    `conftest.run_context` since step 084 — `RunContext.start` built a `Budget` from an
    agent's `limits` block, and both are gone. Nothing here was ever about a ceiling.
    """
    return run_context(SYSTEM)


def is_denied(result):
    return result.get("denied_by") == "broker"


# --- denials -----------------------------------------------------------------


def test_ungranted_tool_is_denied(ctx):
    assert is_denied(broker.call(ctx, AGENT, "delete_everything", {"target": "prod"}))


def test_forbidden_argument_value_is_denied(ctx):
    result = broker.call(ctx, AGENT, "read_repo", {"repo": "torvalds/linux"})
    assert is_denied(result)
    assert "torvalds/linux" in result["error"]


def test_forbidden_channel_is_denied(ctx):
    assert is_denied(broker.call(ctx, AGENT, "post_message", {"channel": "#random", "text": "hi"}))


def test_missing_constrained_argument_is_denied(ctx):
    """Fail closed: an absent constrained arg can't be validated, so it's refused."""
    assert is_denied(broker.call(ctx, AGENT, "post_message", {"text": "no channel"}))


def test_model_supplied_credential_is_denied(ctx):
    """The model must never be able to inject its own webhook URL or token."""
    result = broker.call(
        ctx,
        AGENT,
        "post_message",
        {"channel": "#eng", "text": "hi", "webhook_url": "https://evil.example/hook"},
    )
    assert is_denied(result)


def test_denied_call_never_executes(ctx, isolated_var_dir):
    """A refused post must leave no trace in the outbox."""
    broker.call(ctx, AGENT, "post_message", {"channel": "#random", "text": "should not send"})
    assert not (isolated_var_dir / "outbox.jsonl").exists()


# --- cancellation -------------------------------------------------------------
#
# Step 0, and the reason it is in the broker at all: this is the only path from a runtime
# to a tool, which is what turns "stops before its next tool call" from a hope into a
# guarantee. A check anywhere else would be a check something could route around.


def test_a_cancelled_run_may_not_call_a_tool_it_is_permitted_to_call(ctx):
    """Cancellation is not a policy question, which is why it is checked before the
    policy engine. A run that is fully authorized and fully funded still may not act once
    somebody has stopped it."""
    ctx.cancellation.request("user:u_priya")

    result = broker.call(ctx, AGENT, "post_message", {"channel": "#eng", "text": "hi"})

    assert is_denied(result)
    assert "cancelled" in result["error"]


def test_a_cancelled_call_never_executes(ctx, isolated_var_dir):
    """The property that makes the guarantee worth anything. A refusal that still posted
    the message would be a stop button that lies."""
    ctx.cancellation.request()

    broker.call(ctx, AGENT, "post_message", {"channel": "#eng", "text": "should not send"})

    assert not (isolated_var_dir / "outbox.jsonl").exists()


def test_a_cancelled_call_is_audited_as_a_denial(ctx):
    """So `--runs` shows a cancelled run whose sequence ends in a refusal naming
    cancellation, and a person can see the last thing it did."""
    ctx.cancellation.request()

    broker.call(ctx, AGENT, "post_message", {"channel": "#eng", "text": "hi"})

    record = read_audit()[-1]
    assert record["decision"] == "deny"
    assert "cancelled" in record["reason"]
    assert record["outcome"] == "", "nothing ran"


def test_a_cancelled_call_never_reaches_the_budget():
    """Same rule as a denied call, and it matters more here: a cancelled run's counts are
    what it actually spent, and a refusal is not spending.

    Step 0 runs before step 2, so the assertion is that `reserve` was **never called** —
    which is stricter than the old `ctx.budget.calls == 0` and does not depend on any
    implementation's counters. `Budget` had those; step 084 deleted it, and the ordering
    it was standing in for is the broker's own."""
    ctx = run_context(SYSTEM)
    ctx.cancellation.request()

    broker.call(ctx, AGENT, "post_message", {"channel": "#eng", "text": "hi"})

    assert ctx.budget.reserved == []
    assert ctx.budget.bytes == []


def test_a_live_run_is_unaffected(ctx):
    """The check is a flag read, and the flag is off for every run nobody has stopped —
    which is nearly all of them, on every one of up to thirty calls."""
    assert ctx.cancellation.is_set() is False
    assert not is_denied(
        broker.call(ctx, AGENT, "post_message", {"channel": "#eng", "text": "hi"})
    )


# --- allows ------------------------------------------------------------------


def test_permitted_channel_is_delivered(ctx, isolated_var_dir):
    result = broker.call(ctx, AGENT, "post_message", {"channel": "#eng", "text": "hello"})
    assert result["delivered"] is True
    assert result["transport"] == "local-outbox"  # no webhook env var set in tests

    outbox = (isolated_var_dir / "outbox.jsonl").read_text(encoding="utf-8")
    assert "hello" in outbox


# --- audit -------------------------------------------------------------------


def test_denials_are_audited(ctx):
    broker.call(ctx, AGENT, "post_message", {"channel": "#random", "text": "nope"})
    records = read_audit()
    assert len(records) == 1
    assert records[0]["decision"] == "deny"
    assert records[0]["agent"] == "test-agent"
    assert records[0]["outcome"] == ""  # nothing ran


def test_audit_redacts_message_bodies(ctx):
    broker.call(ctx, AGENT, "post_message", {"channel": "#eng", "text": "secret content"})
    record = read_audit()[-1]
    assert record["args"]["text"].startswith("sha256:")
    assert "secret content" not in json.dumps(record)
    assert record["args"]["channel"] == "#eng"  # policy-relevant args stay readable


def test_redaction_survives_text_no_encoder_can_write(ctx):
    """**A lone surrogate is what a coding agent's prompt holds after reading a file
    with `errors="surrogateescape"`**, which is Python's own default for undecodable
    bytes — and `\\ud800` is legal JSON syntax, so it arrives through any body.

    Found by driving the model surface against real Postgres: the hash was computed
    with a plain `.encode("utf-8")`, which raises on one — *inside the record of a call
    that had already executed*. The tool ran, the vendor was paid, and the process
    answered 500 on its way to writing it down. A hash is a hash whichever encoder
    produced it; what must not happen is the redaction losing the row."""
    result = broker.call(ctx, AGENT, "post_message",
                         {"channel": "#eng", "text": "a file\ud800with bytes"})

    assert "error" not in result
    record = read_audit()[-1]
    assert record["args"]["text"].startswith("sha256:")
    # The length is the string's — six characters, the surrogate, then ten — so the
    # digest still describes what was sent.
    assert "len=17" in record["args"]["text"]


def test_audit_redacts_smuggled_credentials(ctx):
    """A denied call is still logged — the smuggled secret must not land in the log."""
    broker.call(
        ctx,
        AGENT,
        "post_message",
        {"channel": "#eng", "text": "x", "webhook_url": "https://hooks.example/SUPERSECRET"},
    )
    record = read_audit()[-1]
    assert record["args"]["webhook_url"].startswith("sha256:")
    assert "SUPERSECRET" not in json.dumps(record)


def test_agent_identity_comes_from_config_not_the_call(ctx):
    """There is no argument through which a caller can claim a different identity."""
    broker.call(ctx, AGENT, "post_message", {"channel": "#eng", "text": "hi", "agent": "admin"})
    record = read_audit()[-1]
    assert record["agent"] == "test-agent"


# --- principal ---------------------------------------------------------------


def test_principal_is_recorded_on_allowed_calls(ctx):
    broker.call(ctx, AGENT, "post_message", {"channel": "#eng", "text": "hi"})
    record = read_audit()[-1]
    assert record["principal_kind"] == "system"
    assert record["principal_id"] == "test"


def test_principal_is_recorded_on_denials():
    """A denial is the record you most want a principal on."""
    user_ctx = run_context(Principal.user("priya@example.com", TENANT))
    broker.call(user_ctx, AGENT, "post_message", {"channel": "#random"})
    record = read_audit()[-1]
    assert record["decision"] == "deny"
    assert record["principal_kind"] == "user"
    assert record["principal_id"] == "priya@example.com"


# --- run correlation ----------------------------------------------------------


def test_every_record_from_one_run_shares_a_run_id(ctx):
    """Without this there is no way to ask "what did that run do?"."""
    broker.call(ctx, AGENT, "post_message", {"channel": "#eng", "text": "one"})
    broker.call(ctx, AGENT, "post_message", {"channel": "#random", "text": "denied"})

    records = read_audit()
    assert len({r["run_id"] for r in records}) == 1
    assert records[0]["run_id"] == ctx.run_id


def test_separate_runs_get_separate_ids():
    a, b = run_context(SYSTEM), run_context(SYSTEM)
    assert a.run_id != b.run_id


def test_principal_cannot_be_claimed_through_tool_input(ctx):
    """Like agent identity, the principal comes from the caller, not the arguments."""
    broker.call(
        ctx,
        AGENT,
        "post_message",
        {"channel": "#eng", "text": "hi", "principal_id": "admin@example.com"},
    )
    record = read_audit()[-1]
    assert record["principal_id"] == "test"


def test_audit_records_carry_a_schema_version(ctx):
    broker.call(ctx, AGENT, "post_message", {"channel": "#eng", "text": "hi"})
    assert read_audit()[-1]["v"] == audit.SCHEMA_VERSION


def test_audit_records_the_effect(ctx):
    """So "show me every write last quarter" is a filter, not an archaeology project."""
    broker.call(ctx, AGENT, "post_message", {"channel": "#eng", "text": "hi"})
    assert read_audit()[-1]["effect"] == "write"

    # A denied read: the effect is recorded without executing anything, which keeps
    # this suite off the network.
    broker.call(ctx, AGENT, "read_repo", {"repo": "torvalds/linux"})
    record = read_audit()[-1]
    assert record["decision"] == "deny"
    assert record["effect"] == "read"


# --- response size cap -------------------------------------------------------


def _oversized_tool(monkeypatch, limit=None):
    """Register a throwaway tool that returns more than it should."""
    from carnet import tools
    from carnet.tools.base import Tool

    tool = Tool(
        name="firehose",
        description="returns too much",
        input_schema={"type": "object", "properties": {}},
        impl=lambda: {"blob": "x" * 200_000},
        max_response_bytes=limit,
        effect="read",  # reads nothing scopeable, so no resources to declare
    )
    monkeypatch.setitem(tools.REGISTRY, "firehose", tool)
    permissions = {**AGENT["permissions"], "tools": [*AGENT["permissions"]["tools"], "firehose"]}
    return {**AGENT, "permissions": permissions}


def test_oversized_response_is_refused_not_truncated(ctx, isolated_var_dir, monkeypatch):
    agent = _oversized_tool(monkeypatch)
    result = broker.call(ctx, agent, "firehose", {})

    assert "error" in result
    assert result["bytes"] > result["limit"] == config.MAX_RESPONSE_BYTES
    # The payload is discarded entirely — no clipped fragment reaches the model.
    assert "xxx" not in json.dumps(result)


def test_oversized_response_is_audited_with_its_real_size(ctx, isolated_var_dir, monkeypatch):
    agent = _oversized_tool(monkeypatch)
    broker.call(ctx, agent, "firehose", {})

    record = read_audit()[-1]
    assert record["outcome"] == "oversize"
    assert record["response_bytes"] > config.MAX_RESPONSE_BYTES


def test_per_tool_cap_overrides_the_default(ctx, isolated_var_dir, monkeypatch):
    """A tool that legitimately returns a lot can raise its own ceiling."""
    agent = _oversized_tool(monkeypatch, limit=500_000)
    result = broker.call(ctx, agent, "firehose", {})

    assert "error" not in result
    assert read_audit()[-1]["outcome"] == "ok"


def test_response_size_is_recorded_when_under_the_cap(ctx):
    """Sizes are logged even when they pass, so caps can be set from data."""
    broker.call(ctx, AGENT, "post_message", {"channel": "#eng", "text": "hi"})
    assert read_audit()[-1]["response_bytes"] > 0


# --- what the call spent, if the tool said (step 045b) -------------------------------
#
# The broker's one job here is to lift a reserved key off the result, hand it to the one
# validator, and put the answer on the same INSERT the rest of the record rides — `audit`
# forbids UPDATE by trigger, so there is no second write available.


def _reporting_tool(monkeypatch, report):
    """A throwaway tool that reports what it spent, the way a model connector will."""
    from carnet import tools
    from carnet.tools.base import REPORTED_USAGE, Tool

    tool = Tool(
        name="think",
        description="answers, expensively",
        input_schema={"type": "object", "properties": {}},
        impl=lambda: {"answer": "yes", REPORTED_USAGE: report},
        effect="read",
    )
    monkeypatch.setitem(tools.REGISTRY, "think", tool)
    permissions = {**AGENT["permissions"], "tools": [*AGENT["permissions"]["tools"], "think"]}
    return {**AGENT, "permissions": permissions}


def spend_row():
    record = read_audit()[-1]
    return (
        record["model"],
        record["input_tokens"],
        record["output_tokens"],
        record["cache_read_tokens"],
        record["cache_write_tokens"],
    )


def test_reported_usage_rides_the_audit_row(ctx, monkeypatch):
    agent = _reporting_tool(
        monkeypatch,
        {
            "model": "claude-opus-5",
            "input_tokens": 1,
            "output_tokens": 2,
            "cache_read_tokens": 3,
            "cache_write_tokens": 4,
        },
    )

    broker.call(ctx, agent, "think", {})

    assert spend_row() == ("claude-opus-5", 1, 2, 3, 4)


def test_the_reserved_key_never_reaches_the_caller(ctx, monkeypatch):
    """`pop`, not `get`, and the asymmetry with `MAY_HAVE_COMPLETED` is deliberate: that
    one rides back because the *model* decides whether to retry, while this is
    bookkeeping the caller has no use for — and for a REST connector the result is the
    vendor's JSON verbatim, which a key we invented would quietly stop being true of."""
    from carnet.tools.base import REPORTED_USAGE

    agent = _reporting_tool(monkeypatch, {"input_tokens": 1})

    result = broker.call(ctx, agent, "think", {})

    assert REPORTED_USAGE not in result
    assert result == {"answer": "yes"}


def test_the_report_is_lifted_before_the_response_is_measured(ctx, monkeypatch):
    """The size cap measures what enters model context, and the key does not. Removing it
    after the measurement would charge a caller bytes it never received."""
    agent = _reporting_tool(monkeypatch, {"input_tokens": 1})

    broker.call(ctx, agent, "think", {})

    assert read_audit()[-1]["response_bytes"] == len(
        json.dumps({"answer": "yes"}).encode()
    )


def test_a_tool_that_reports_nothing_records_null_and_not_zero(ctx):
    """Every call this product has brokered so far. NULL is *not applicable*; 0 would be
    *a model call that cost nothing*, which does not happen — and the door's spend query
    filters on `IS NOT NULL`, so zeros would enrol the whole audit log in a money
    question."""
    broker.call(ctx, AGENT, "post_message", {"channel": "#eng", "text": "hi"})

    assert spend_row() == ("", None, None, None, None)


def test_a_garbage_report_is_dropped_and_the_call_still_succeeds(ctx, monkeypatch):
    """The counters gate money; the call does not. A connector that reports nonsense has
    its usage dropped with a log line, and the caller gets its answer — a run that
    produced a result must never fail over the bookkeeping about it."""
    agent = _reporting_tool(monkeypatch, {"input_tokens": -5})

    result = broker.call(ctx, agent, "think", {})

    assert result == {"answer": "yes"}
    assert spend_row() == ("", None, None, None, None)


def test_a_denied_call_records_no_usage(ctx, monkeypatch):
    """It cannot: the refusal happens at step 1, before anything is executed. Asserted
    because it is what makes a denied-then-retried call impossible to double-count."""
    _reporting_tool(monkeypatch, {"input_tokens": 1})

    broker.call(ctx, AGENT, "think", {})  # `think` is not in AGENT's tool list

    record = read_audit()[-1]
    assert record["decision"] == "deny"
    assert record["input_tokens"] is None


def test_an_errored_call_records_what_it_spent(ctx, monkeypatch):
    """A vendor that charged and then returned 500 has spent money, and money spent is
    money recorded — the one branch where usage and failure coexist."""
    agent = _reporting_tool(
        monkeypatch, {"model": "claude-opus-5", "input_tokens": 12}
    )
    from carnet import tools
    from carnet.tools.base import REPORTED_USAGE, Tool

    monkeypatch.setitem(
        tools.REGISTRY,
        "think",
        Tool(
            name="think",
            description="fails, expensively",
            input_schema={"type": "object", "properties": {}},
            impl=lambda: {"error": "upstream 500", REPORTED_USAGE: {
                "model": "claude-opus-5", "input_tokens": 12
            }},
            effect="read",
        ),
    )

    broker.call(ctx, agent, "think", {})

    record = read_audit()[-1]
    assert record["outcome"] == "error"
    assert (record["model"], record["input_tokens"]) == ("claude-opus-5", 12)


# --- which credential the call went out with -------------------------------------
#
# The record says who a run acted *for*. Until delegation existed it said nothing about
# whose credential it *used*, because there was one and the two could not disagree.


def test_a_shared_credential_is_recorded_as_shared(ctx):
    """A chat webhook is the organisation's, whoever asked for it."""
    broker.call(ctx, AGENT, "post_message", {"channel": "#eng", "text": "hi"})

    assert read_audit()[-1]["credential"] == "shared"


def test_a_tool_needing_no_credential_records_none(ctx):
    """Distinct from `shared`: the log should not imply an organisational secret was
    used where there is none."""
    broker.call(ctx, AGENT, "read_repo", {"repo": "octocat/Hello-World"})

    assert read_audit()[-1]["credential"] is None


def test_a_denied_call_records_no_credential(ctx):
    """Nothing was executed and no credential was read — step 3 never ran. A value
    here would claim a secret was fetched for a call that did not happen."""
    broker.call(ctx, AGENT, "read_repo", {"repo": "torvalds/linux"})

    record = read_audit()[-1]
    assert record["decision"] == "deny"
    assert record["credential"] is None


def test_a_delegated_credential_is_recorded_as_delegated(ctx, monkeypatch):
    """The half that was missing, and the reason `v` moved to 6.

    Without this a call that reached a vendor as the *operator* and a call that reached
    it as the user are the same record, and only one of them is what the principal
    column implies.
    """
    from carnet.core import credentials

    monkeypatch.setattr(
        credentials,
        "for_tool",
        lambda *a, **kw: credentials.ToolCredentials({}, credentials.DELEGATED),
    )

    broker.call(ctx, AGENT, "read_repo", {"repo": "octocat/Hello-World"})

    assert read_audit()[-1]["credential"] == "delegated"


# --- whose account: the vetted identity, enforced at step 3 (033a) ----------------
#
# The Tom scenario, pre-door shape: a `user`-identity tool called by a principal with
# no connected account must be REFUSED, never quietly served from the connector's
# shared credential — the silent fallback is how somebody reads data their own account
# cannot open, with every check passing and nothing recording that it happened.

GHX_AGENT = {
    "name": "ghx-agent",
    "system": "irrelevant",
    "runtime": "simple",
    "permissions": {"tools": ["ghx_search"], "scope": {}},
}


def _ghx_tool(identity, reached):
    """A connector-shaped tool, as `bind()` would produce one."""
    return Tool(
        name="ghx_search",
        description="",
        input_schema={"type": "object", "properties": {}},
        impl=lambda token=None, **kw: reached.append(token) or {"ok": True},
        effect="read",
        connector="ghx",
        identity=identity,
        credential_env="GHX_TOKEN",
    )


def test_a_user_identity_tool_with_no_connection_is_refused_not_served_shared(
    ctx, monkeypatch
):
    """Every check passes — granted, in scope, budget remains — and the call still
    must not happen, because the vetting says whose account and the caller has none.
    The shared credential is in the environment and provably unused."""
    monkeypatch.setenv("GHX_TOKEN", "the-operators")
    reached = []
    monkeypatch.setitem(tool_registry.REGISTRY, "ghx_search", _ghx_tool("user", reached))

    result = broker.call(ctx, GHX_AGENT, "ghx_search", {})

    assert "unavailable" in result["error"]
    assert reached == []
    record = read_audit()[-1]
    assert record["decision"] == "allow"
    assert record["outcome"] == "error"
    assert "the-operators" not in json.dumps(record)


def test_a_service_identity_tool_uses_the_shared_credential_and_records_shared(
    ctx, monkeypatch
):
    """The wire-through: the manifest's variable reaches step 3 off the Tool, so a
    registered connector's `service` calls authenticate as the service — pre-033a the
    per-call lookup only knew a hardcoded map, and everything not in it went out as
    nobody."""
    monkeypatch.setenv("GHX_TOKEN", "the-operators")
    reached = []
    monkeypatch.setitem(
        tool_registry.REGISTRY, "ghx_search", _ghx_tool("service", reached)
    )

    result = broker.call(ctx, GHX_AGENT, "ghx_search", {})

    assert "error" not in result
    assert reached == ["the-operators"]
    assert read_audit()[-1]["credential"] == "shared"


# --- the failure reason (step 041's live-pass finding) --------------------------------
#
# An errored call's record used to say `outcome="error"` and nothing else — the cause
# existed only in the response the caller received, so "why did that call fail" was
# unanswerable from the one table built to answer it after the fact. The rows below pin
# that the log now keeps the same sentence the caller saw, for every non-ok outcome, and
# nothing more than that sentence.


def _tool(impl, *, effect="read", max_bytes=None):
    return Tool(
        name="read_repo",
        description="",
        input_schema={"type": "object", "properties": {"repo": {"type": "string"}}},
        impl=impl,
        effect=effect,
        resources=[Resource("github.repo", "repo")],
        max_response_bytes=max_bytes,
    )


def test_a_raising_tool_leaves_its_cause_in_the_record(ctx, monkeypatch):
    def boom(repo):
        raise TimeoutError("the vendor took 30s and gave up")

    monkeypatch.setitem(tool_registry.REGISTRY, "read_repo", _tool(boom))

    result = broker.call(ctx, AGENT, "read_repo", {"repo": "octocat/Hello-World"})

    record = read_audit()[-1]
    assert record["outcome"] == "error"
    # The same sentence the caller got — the log discloses nothing the call did not.
    assert record["reason"] == result["error"]
    assert "TimeoutError" in record["reason"]
    assert "gave up" in record["reason"]


def test_a_tool_reporting_its_own_error_leaves_it_in_the_record(ctx, monkeypatch):
    """The other error shape: the tool returned rather than raised, with an `error`
    key — which is how a connector reports a vendor's 4xx."""
    monkeypatch.setitem(
        tool_registry.REGISTRY,
        "read_repo",
        _tool(lambda repo: {"error": "GitHub answered 404: repo not found"}),
    )

    broker.call(ctx, AGENT, "read_repo", {"repo": "octocat/Hello-World"})

    record = read_audit()[-1]
    assert record["outcome"] == "error"
    assert record["reason"] == "GitHub answered 404: repo not found"


def test_an_oversize_response_records_why_it_was_discarded(ctx, monkeypatch):
    monkeypatch.setitem(
        tool_registry.REGISTRY,
        "read_repo",
        _tool(lambda repo: {"rows": "x" * 4096}, max_bytes=64),
    )

    broker.call(ctx, AGENT, "read_repo", {"repo": "octocat/Hello-World"})

    record = read_audit()[-1]
    assert record["outcome"] == "oversize"
    assert "exceeded the size limit" in record["reason"]


def test_a_write_that_may_have_landed_keeps_its_cause_beside_the_unknown(
    ctx, monkeypatch
):
    """`unknown` is the outcome somebody reads during an incident, which makes its
    reason the most valuable of the four."""

    # `**creds` because the credential layer injects the webhook kwarg — and the first
    # version of this test omitted it, raised a TypeError inside the tool, and the new
    # `reason` field named the exact mistake from the audit row alone. The feature
    # debugged its own test.
    def maybe(channel, text, **creds):
        return {
            "error": "the send timed out after the request was written",
            tool_registry.MAY_HAVE_COMPLETED: True,
        }

    monkeypatch.setitem(
        tool_registry.REGISTRY,
        "post_message",
        Tool(
            name="post_message",
            description="",
            input_schema={
                "type": "object",
                "properties": {
                    "channel": {"type": "string"},
                    "text": {"type": "string"},
                },
            },
            impl=maybe,
            effect="write",
            resources=[Resource("chat.channel", "channel")],
        ),
    )

    broker.call(ctx, AGENT, "post_message", {"channel": "#eng", "text": "hi"})

    record = read_audit()[-1]
    assert record["outcome"] == "unknown"
    assert "timed out after the request was written" in record["reason"]


def test_a_clean_call_still_records_no_reason(ctx):
    """The other direction, so `reason` keeps meaning *why it went wrong*: a row whose
    outcome is `ok` carries an empty one, exactly as before."""
    broker.call(ctx, AGENT, "read_repo", {"repo": "octocat/Hello-World"})

    record = read_audit()[-1]
    assert record["outcome"] == "ok"
    assert record["reason"] == ""


def test_a_gigantic_cause_is_bounded_for_the_log(ctx, monkeypatch):
    """An exception repr can carry a vendor's whole response body. The record takes the
    head of the sentence — where every exception puts its type and message — and the
    full text stays where it always was, in the response the caller received."""

    def boom(repo):
        raise RuntimeError("vendor said: " + "x" * 5000)

    monkeypatch.setitem(tool_registry.REGISTRY, "read_repo", _tool(boom))

    result = broker.call(ctx, AGENT, "read_repo", {"repo": "octocat/Hello-World"})

    record = read_audit()[-1]
    assert len(record["reason"]) == 501  # the cap, plus the ellipsis that admits it
    assert record["reason"].endswith("…")
    assert record["reason"].startswith("RuntimeError: vendor said:")
    # The response is NOT bounded — the model needs the whole error to act on it.
    assert len(result["error"]) > 5000


def test_every_call_counts_itself(ctx):
    """057. The broker is the one path every tool call takes —
    so its counters are the product's call meter. A denial and an allowed call land on
    different series, and only the allowed one adds a duration."""
    from carnet import metrics

    metrics.reset()
    broker.call(ctx, AGENT, "delete_everything", {"target": "prod"})
    broker.call(ctx, AGENT, "read_repo", {"repo": "octocat/Hello-World"})

    series = {
        (name, dict(labels).get("decision"), dict(labels).get("outcome")): value
        for (name, labels), value in metrics.snapshot().items()
    }
    assert series[("carnet_broker_calls_total", "deny", "refused")] == 1
    assert series[("carnet_broker_calls_total", "allow", "ok")] == 1
    assert ("carnet_broker_call_duration_ms_total", None, None) in series


def test_an_executed_call_survives_a_dead_audit_table(ctx, isolated_var_dir, monkeypatch):
    """060: the log's one hole, closed. The final audit runs AFTER the side effect,
    so a missing partition used to turn into a 503 about work that already ran — and
    no record anywhere. Now the caller gets their result and the record lands in the
    fallback file, carrying the append failure's own sentence."""
    import json

    from carnet import config, storage
    from carnet.storage.base import StorageError

    real = storage.active().append_audit

    def failing(tenant_id, entry):
        if entry["decision"] == "allow" and entry.get("outcome"):
            raise StorageError("no partition of relation audit found (test)")
        return real(tenant_id, entry)

    monkeypatch.setattr(storage.active(), "append_audit", failing)

    result = broker.call(ctx, AGENT, "read_repo", {"repo": "octocat/Hello-World"})

    assert result == {"repo": "octocat/Hello-World"}
    lines = config.AUDIT_FALLBACK_PATH.read_text().splitlines()
    assert len(lines) == 1
    row = json.loads(lines[0])
    assert row["tool"] == "read_repo"
    assert row["outcome"] == "ok"
    assert "no partition" in row["append_error"]


def test_a_denial_still_fails_loud_when_nothing_can_record_it(
    ctx, isolated_var_dir, monkeypatch
):
    """060's asymmetry, pinned from the other side: a refusal happens BEFORE anything
    executes, so a deny that cannot be recorded is an error the caller should meet —
    and the fallback file stays empty, because nothing happened worth preserving."""
    from carnet import config, storage
    from carnet.storage.base import StorageError

    def dead(tenant_id, entry):
        raise StorageError("no partition of relation audit found (test)")

    monkeypatch.setattr(storage.active(), "append_audit", dead)

    with pytest.raises(StorageError):
        broker.call(ctx, AGENT, "delete_everything", {"target": "prod"})

    assert not config.AUDIT_FALLBACK_PATH.exists()


# --- the answer while it arrives: `stream` -------------------------------------------
#
# Step 108, decision 2. The one invariant the layout protects — nothing outside `core/`
# calls a tool implementation directly — means a streamed model call goes through the
# broker or it is the first bypass. What these pin: `stream` runs every check `call` runs
# before a byte goes out; the bytes come through untouched; the row is written when the
# iteration ends, with `outcome` saying how it ended; and stopping early closes the
# upstream. The upstream here is duck-typed rather than `tools/rest.Upstream`, because
# the broker's contract with it is five attributes and two methods and these tests are
# about the broker.


class FakeUpstream:
    def __init__(self, chunks=(), *, status=200, error=None, relay_body=True,
                 report=None, may_have_completed=False, headers=None):
        self.status = status
        self.headers = headers or {"Content-Type": "text/event-stream"}
        self.error = error
        self.relay_body = relay_body
        self.may_have_completed = may_have_completed
        self._chunks = list(chunks)
        self._report = report
        self.closed = False
        self.yielded = 0

    def chunks(self):
        for chunk in self._chunks:
            self.yielded += 1
            yield chunk

    def report(self):
        return self._report

    def close(self):
        self.closed = True


def _streaming_tool(monkeypatch, upstream, *, limit=None, effect="write", stream_impl=True,
                    redact=frozenset()):
    """Register a throwaway tool whose streamed entry point hands back `upstream`."""
    from carnet import tools
    from carnet.tools.base import Tool

    calls = []

    def impl(**arguments):
        return {"buffered": True}

    def stream(**arguments):
        calls.append(arguments)
        if isinstance(upstream, Exception):
            raise upstream
        return upstream

    tool = Tool(
        name="chat",
        description="a model",
        input_schema={"type": "object", "properties": {
            "model": {"type": "string"}, "messages": {"type": "array"}}},
        impl=impl,
        stream_impl=stream if stream_impl else None,
        max_response_bytes=limit,
        effect=effect,
        resources=[Resource("azure.deployment", "model")],
        redact_args=redact,
    )
    monkeypatch.setitem(tools.REGISTRY, "chat", tool)
    permissions = {
        **AGENT["permissions"],
        "tools": [*AGENT["permissions"]["tools"], "chat"],
        "scope": {**AGENT["permissions"]["scope"], "azure.deployment": {"write": ["gpt-4o"]}},
    }
    return {**AGENT, "permissions": permissions}, calls


PROMPT = {"model": "gpt-4o", "messages": [{"role": "user", "content": "secret prompt"}]}


def test_stream_runs_every_check_call_runs_before_a_byte_goes_out(ctx, isolated_var_dir, monkeypatch):
    """A deployment outside the scope is refused with `call`'s own dict, the upstream is
    never asked for, and the row is the same `deny` row `call` writes."""
    upstream = FakeUpstream([b"x"])
    agent, calls = _streaming_tool(monkeypatch, upstream)

    streamed = broker.stream(ctx, agent, "chat", {**PROMPT, "model": "gpt-3"})

    assert streamed.refused is True
    assert is_denied(streamed.error)
    assert "gpt-3" in streamed.error["error"]
    assert list(streamed) == []
    assert calls == []
    record = read_audit()[-1]
    assert (record["decision"], record["outcome"]) == ("deny", "")


def test_a_cancelled_run_may_not_stream_either(ctx, isolated_var_dir, monkeypatch):
    agent, calls = _streaming_tool(monkeypatch, FakeUpstream([b"x"]))
    ctx.cancellation.request()

    streamed = broker.stream(ctx, agent, "chat", PROMPT)

    assert streamed.refused is True and "cancelled" in streamed.error["error"]
    assert calls == []


def test_a_streamed_answer_comes_through_untouched_and_is_audited_once_at_the_end(
    ctx, isolated_var_dir, monkeypatch
):
    upstream = FakeUpstream([b"data: a\n\n", b"data: b\n\n"],
                            report={"model": "gpt-4o", "input_tokens": 12, "output_tokens": 3})
    agent, calls = _streaming_tool(monkeypatch, upstream)

    streamed = broker.stream(ctx, agent, "chat", PROMPT)
    assert streamed.status == 200 and streamed.error is None
    assert read_audit() == [] or read_audit()[-1]["tool"] != "chat", "no row before the end"

    assert list(streamed) == [b"data: a\n\n", b"data: b\n\n"]

    assert streamed.outcome == "ok"
    assert streamed.response_bytes == 18
    assert upstream.closed is True
    record = read_audit()[-1]
    assert (record["decision"], record["outcome"], record["response_bytes"]) == ("allow", "ok", 18)
    assert (record["model"], record["input_tokens"], record["output_tokens"]) == ("gpt-4o", 12, 3)
    assert calls == [PROMPT]


def test_the_byte_cap_closes_the_upstream_as_the_bytes_pass(ctx, isolated_var_dir, monkeypatch):
    """S7. A stream is the one response a size cap cannot check up front, so it is
    applied on the way past: every byte up to the cap is handed on, the upstream is
    closed there, and the row says `oversize` with the bytes that passed."""
    upstream = FakeUpstream([b"x" * 40, b"y" * 40, b"z" * 40])
    agent, _ = _streaming_tool(monkeypatch, upstream, limit=50)

    streamed = broker.stream(ctx, agent, "chat", PROMPT)
    received = list(streamed)

    assert received == [b"x" * 40]
    assert streamed.outcome == "oversize"
    assert streamed.error["limit"] == 50 and streamed.error["bytes"] == 80
    assert upstream.closed is True
    assert upstream.yielded == 2, "the chunk that crossed the cap was the last one read"
    record = read_audit()[-1]
    assert (record["outcome"], record["response_bytes"]) == ("oversize", 80)
    assert "size limit" in record["reason"]


def test_a_caller_that_stops_early_closes_the_upstream_and_the_row_says_aborted(
    ctx, isolated_var_dir, monkeypatch
):
    """S6. Ctrl-C in the engineer's terminal. The upstream is closed so the vendor stops
    generating for a listener that has gone, and the row records what was counted —
    usually nothing, because the usage object is the final chunk."""
    upstream = FakeUpstream([b"a", b"b", b"c"])
    agent, _ = _streaming_tool(monkeypatch, upstream)

    streamed = broker.stream(ctx, agent, "chat", PROMPT)
    for _chunk in streamed:
        break
    streamed.close()

    assert streamed.outcome == "aborted"
    assert upstream.closed is True
    record = read_audit()[-1]
    assert (record["outcome"], record["response_bytes"], record["input_tokens"]) == ("aborted", 1, None)


def test_a_streamed_never_iterated_is_closed_and_recorded_as_aborted(ctx, isolated_var_dir, monkeypatch):
    upstream = FakeUpstream([b"a"])
    agent, _ = _streaming_tool(monkeypatch, upstream)

    streamed = broker.stream(ctx, agent, "chat", PROMPT)
    streamed.close()
    streamed.close()

    assert streamed.outcome == "aborted" and upstream.closed is True
    assert [r["outcome"] for r in read_audit() if r["tool"] == "chat"] == ["aborted"]


def test_closing_a_stream_that_never_had_an_answer_is_an_error_not_an_abort(
    ctx, isolated_var_dir, monkeypatch
):
    """**Nothing was there to walk away from.** A `Streamed` whose upstream failed
    before the first byte — a connection refused, an argument the tool would not send —
    is closed by the route rather than iterated, and recording that as `aborted` would
    read as *the engineer pressed Ctrl-C* on a call that never reached the vendor.

    The edge pass found the route leaving these unclosed altogether, so the row did not
    exist at all; `close()` had then to decide what it says."""
    upstream = FakeUpstream([], status=None, error="'tracker' could not be reached.")
    agent, _ = _streaming_tool(monkeypatch, upstream)

    streamed = broker.stream(ctx, agent, "chat", PROMPT)
    streamed.close()

    assert streamed.outcome == "error"
    record = read_audit()[-1]
    assert (record["outcome"], record["response_bytes"]) == ("error", 0)
    assert "could not be reached" in record["reason"]


def test_a_break_mid_answer_is_an_error_with_the_upstreams_sentence(ctx, isolated_var_dir, monkeypatch):
    """S11 at the broker: the upstream sets `error` after its last chunk, and the row
    says `error` with that sentence — never `unknown`, because bytes arrived and the
    caller watched them stop."""
    class Stalls(FakeUpstream):
        def chunks(self):
            yield b"a"
            self.error = "'tracker' stopped sending for 60s mid-answer"
    upstream = Stalls(may_have_completed=True)
    agent, _ = _streaming_tool(monkeypatch, upstream)

    streamed = broker.stream(ctx, agent, "chat", PROMPT)

    assert list(streamed) == [b"a"]
    assert streamed.outcome == "error"
    record = read_audit()[-1]
    assert record["outcome"] == "error" and "stopped sending" in record["reason"]


def test_a_failure_before_the_first_byte_keeps_calls_bias_for_a_write(ctx, isolated_var_dir, monkeypatch):
    upstream = FakeUpstream([], status=None, error="'tracker' accepted the request and did not answer in time.",
                            may_have_completed=True)
    agent, _ = _streaming_tool(monkeypatch, upstream)

    streamed = broker.stream(ctx, agent, "chat", PROMPT)
    assert list(streamed) == []

    assert streamed.outcome == "unknown"
    assert read_audit()[-1]["outcome"] == "unknown"


def test_a_vendor_refusal_is_relayed_and_recorded_as_an_error(ctx, isolated_var_dir, monkeypatch):
    """S19, S20. The 429 or the content-filter 400 travels whole to the caller —
    status, `Retry-After`, body — and the row says `error` with the status."""
    upstream = FakeUpstream([b'{"error": "slow down"}'], status=429,
                            error="'tracker' answered HTTP 429.",
                            headers={"Content-Type": "application/json", "Retry-After": "7"})
    agent, _ = _streaming_tool(monkeypatch, upstream)

    streamed = broker.stream(ctx, agent, "chat", PROMPT)

    assert (streamed.status, streamed.headers["Retry-After"]) == (429, "7")
    assert list(streamed) == [b'{"error": "slow down"}']
    assert streamed.outcome == "error"
    assert read_audit()[-1]["reason"] == "'tracker' answered HTTP 429."


def test_a_tool_without_a_stream_impl_is_an_audited_error(ctx, isolated_var_dir, monkeypatch):
    agent, _ = _streaming_tool(monkeypatch, FakeUpstream(), stream_impl=False)

    streamed = broker.stream(ctx, agent, "chat", PROMPT)

    assert streamed.refused is False
    assert "cannot stream" in streamed.error["error"]
    assert list(streamed) == []
    assert read_audit()[-1]["outcome"] == "error"


def test_a_stream_impl_that_raises_is_an_audited_error(ctx, isolated_var_dir, monkeypatch):
    agent, _ = _streaming_tool(monkeypatch, RuntimeError("boom"))

    streamed = broker.stream(ctx, agent, "chat", PROMPT)

    assert streamed.error == {"error": "RuntimeError: boom"}
    assert read_audit()[-1]["outcome"] == "error"


def test_the_caller_can_widen_the_redaction_and_never_narrow_it(ctx, isolated_var_dir, monkeypatch):
    """Decision 10. The OpenAI surface strips `messages` from the row regardless of
    how the tool was vetted; a tool vetted to redact `model` keeps that too."""
    agent, _ = _streaming_tool(monkeypatch, FakeUpstream([b"a"]), redact=frozenset({"model"}))

    list(broker.stream(ctx, agent, "chat", PROMPT, redact={"messages"}))

    args = read_audit()[-1]["args"]
    assert "secret prompt" not in json.dumps(args)
    assert "gpt-4o" not in json.dumps(args)


def test_the_bytes_that_passed_count_against_the_budget(ctx, isolated_var_dir, monkeypatch):
    agent, _ = _streaming_tool(monkeypatch, FakeUpstream([b"abc", b"de"]))

    list(broker.stream(ctx, agent, "chat", PROMPT))

    assert ctx.budget.bytes == [5]
