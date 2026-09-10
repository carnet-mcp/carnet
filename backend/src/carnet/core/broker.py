"""The broker — the only path from an agent to a tool.

The agent loop cannot call a tool implementation. It hands the broker a request and
the broker decides. Every call is five distinct steps, in this order:

    0. CANCELLED    ctx.cancellation         has somebody stopped this run?
    1. PERMISSION   permissions.check()      may this agent do this at all?
    2. BUDGET       ctx.budget.reserve()     has this run already done too much?
    3. CREDENTIAL   credentials.for_tool()   what secret does it need?
    4. EXECUTE      tool.impl + audit        run it, bound it, log it.

Steps 1 and 2 answer different questions. Scoping bounds what a run may *reach*;
the budget bounds how much it may *do* within that reach. A runaway loop makes calls
that are each individually authorized — volume is the whole problem, and no amount of
policy catches it.

Step 0 is numbered from zero because it is not a policy question at all: it asks whether
this run should still be happening, and a cancelled run may not make a call it is fully
authorized and funded to make. It lives here because **this is the only path from a
runtime to a tool**, which is what makes "stops before its next tool call" a guarantee
rather than a hope.

A refusal at 0, 1 or 2 stops there. Nothing is executed, no credential is read, and the
refusal is still audited.

Trusted inputs, all server-side: `ctx` (run identity, principal, budget) is built by
the runtime, and `agent` comes from the registry. The model contributes only
`tool_name` and `tool_input`. There is no parameter through which it can assert who it
is, whose authority it acts under, or how much budget it has left.
"""

import json
import time

from .. import config, metrics, tools as tool_registry
from . import audit, credentials, permissions
from .usage import parse_report


class _Gate:
    """One call's identity for the audit log, held across the steps. Step 108.

    What `call` used to close over — the tool, its redaction policy, its effect, the
    acting-for — so that `stream()` can run the identical steps 0 to 3 without a second
    copy of them. `audit()` and `refuse()` are the two exits every step shares.
    """

    __slots__ = ("ctx", "agent_name", "tool_name", "tool_input", "tool", "redact", "effect", "acting")

    def __init__(self, ctx, agent: dict, tool_name: str, tool_input: dict, extra_redact):
        self.ctx = ctx
        self.agent_name = agent["name"]  # trusted identity, from config — never from the model
        self.tool_name = tool_name
        self.tool_input = tool_input

        # Looked up before the checks so a refusal can still honour the tool's redaction
        # policy when it writes the audit record. None for an unknown tool name.
        #
        # Scoped to the run's tenant: connector tools are a tenant's own vetting decision,
        # so the same name can mean a vetted tool for one customer and nothing at all for
        # another. The tenant comes off `ctx`, which is server-side — the model has no
        # parameter through which to assert one.
        self.tool = tool_registry.get(tool_name, ctx.tenant_id)
        # The tool's own redaction, plus whatever the caller adds: the OpenAI surface
        # strips `messages` and its kin regardless of how the tool was vetted (108,
        # decision 10), because a prompt on an append-only table is not a mis-vetting
        # anybody can undo. A union, never a replacement — a caller can widen what is
        # hidden and cannot narrow it.
        self.redact = (self.tool.redact_args if self.tool else frozenset()) | frozenset(extra_redact)
        self.effect = self.tool.effect if self.tool else ""

        # Whom the call is for, on every record this call writes — allow, deny, and error
        # alike (step 033c). A denial carries the acting-for it was denied *under*, which is
        # what makes `tom@… (verified) … DENIED` a real log line rather than an example.
        self.acting = ctx.acting_for

    def audit(self, **fields):
        acting = self.acting
        return audit.record(
            run_id=self.ctx.run_id,
            principal=self.ctx.principal,
            agent=self.agent_name,
            tool=self.tool_name,
            tool_input=self.tool_input,
            redact_args=self.redact,
            effect=self.effect,
            acting_for=acting.email if acting else None,
            identity_source=acting.source if acting else audit.NO_IDENTITY,
            **fields,
        )

    def refuse(self, reason: str) -> dict:
        self.audit(decision="deny", reason=reason)
        # Step 057: every exit of this function counts itself, and this is the one
        # path all refusals leave through. The reason stays out of the labels — a
        # label per sentence is a cardinality leak, and the audit row has it.
        metrics.bump("carnet_broker_calls_total", decision="deny", outcome="refused")
        # The model sees why it was refused, but nothing about the credential store.
        return {"error": f"Denied by broker: {reason}", "denied_by": "broker"}


def _admit(ctx, agent: dict, tool_name: str, tool_input: dict, extra_redact=frozenset()):
    """Steps 0 to 3, for both `call` and `stream`. Step 108 moved them here unchanged.

    Returns `(gate, creds)` when the call may execute, or the refusal dict — the exact
    dict `call` returns — when it may not. One function, because *"`stream` runs every
    check `call` runs, in the same order, before the first byte is sent upstream"* is
    the sentence the whole streamed surface rests on, and two copies of four steps is
    how one of them stops being true.
    """
    gate = _Gate(ctx, agent, tool_name, tool_input, extra_redact)
    tool = gate.tool

    # --- Step 0: has this run been asked to stop? --------------------------------
    #
    # Before the permission check, because it is a cheaper and more absolute question:
    # a cancelled run may not call a tool it is fully authorized to call. Ordering it
    # first also means a cancelled run's trail ends in `run cancelled` rather than in
    # whatever the policy engine happened to think of the call.
    #
    # A flag, never a query. A run makes many tool calls — thirty was this platform's
    # own default while it ran them — so reading the database here would be thirty round
    # trips to answer "no" thirty times. What
    # sets the flag is a worker's heartbeat, which was going to make that round trip
    # anyway — see `Storage.heartbeat_runs`.
    #
    # Audited as a denial, which is the right shape: nothing executed, no credential was
    # read, and the record shows exactly where the run stopped. The loop then raises
    # `RunCancelled` rather than letting the model recover from this refusal and try
    # something else.
    if ctx.cancellation.is_set():
        return gate.refuse("run cancelled")

    # --- Step 1: permission check ------------------------------------------------
    decision = permissions.check(ctx.principal, agent, tool_name, tool_input, tool)
    if not decision.allowed:
        return gate.refuse(decision.reason)

    # --- Step 2: budget ----------------------------------------------------------
    # Consumes the call on success. Runs after the permission check so a denied call
    # never spends budget — a refusal must not push the run toward exhaustion.
    verdict = ctx.budget.reserve(tool)
    if not verdict.allowed:
        return gate.refuse(verdict.reason)

    # --- Step 3: credential fetch ------------------------------------------------
    # Runs only once the call is authorized and affordable. The returned kwargs go
    # straight into the tool function and are never logged or returned to the model.
    # Keyed by (tool, principal) — and since 033a the tool's vetted `identity` decides
    # which of the two the credential belongs to: `service` is the connector's shared
    # secret with the caller's connections never consulted, `user` is the caller's own
    # connection with no fallback. A `user` tool the caller has not connected lands in
    # the except branch below: audited, and the model told the tool is unavailable.
    # Since 033c an acting-for on the context substitutes *which person* a `user`
    # tool resolves — and only that; the `service` branch never reads it.
    #
    # **Since 070 this line can go to the network**, for one shape: a connector whose
    # shared credential is an `op://` reference rather than an environment variable. It
    # returns the same `ToolCredentials` with the same `source`, so nothing here — and
    # nothing in the audit row below — can tell the two apart. What it costs is one to
    # three round trips inside the door's own budget, and what it buys is that the
    # secret was never in this database. The refusal, when a vault is slow or down,
    # arrives through the `CredentialError` branch already written below and names the
    # vault and the item rather than reading as a generic credential error.
    try:
        creds = credentials.for_tool(
            tool_name,
            tool_input,
            ctx.principal,
            connector=tool.connector,
            identity=tool.identity,
            env_var=tool.credential_env,
            credential_ref=tool.credential_ref,
            acting_for=gate.acting,
        )
    except credentials.CredentialError as exc:
        gate.audit(
            decision="allow",
            outcome="error",
            reason=f"credential fetch failed: {exc}",
        )
        # The sentence itself, not a stub — step 046's edge pass. This used to say
        # "unavailable (credential error)" with the reason kept for the audit row,
        # which left the model no remedy to relay and no way to stop retrying. The
        # sentence is the same class the caller already gets two other ways: a scope
        # denial reaches the model verbatim ("#random is outside this agent's
        # 'write' scope"), and the door's *unbound* path returns this exact error's
        # text as ToolUnavailable. It names connectors, identities and remedies —
        # never a credential value, which `for_tool` returns separately and nothing
        # here interpolates.
        metrics.bump("carnet_broker_calls_total", decision="allow", outcome="error")
        return {"error": f"Tool '{tool_name}' is unavailable: {exc}"}

    return gate, creds


def call(ctx, agent: dict, tool_name: str, tool_input: dict) -> dict:
    """Broker one tool call. Returns data safe to hand back to the model.

    Never raises: failures come back as {"error": ...} so the model can recover or
    explain itself rather than crashing the run.
    """
    admitted = _admit(ctx, agent, tool_name, tool_input)
    if isinstance(admitted, dict):
        return admitted
    gate, creds = admitted
    tool = gate.tool
    _audit = gate.audit

    # --- Step 4: execute, bound the response, audit ------------------------------
    # `tool` is not None here: step 1 refuses unregistered tools, since a tool with no
    # descriptor cannot be scoped.
    started = time.monotonic()

    try:
        result = tool.impl(**tool_input, **creds.kwargs)
        outcome = "error" if isinstance(result, dict) and "error" in result else "ok"
    except Exception as exc:  # noqa: BLE001 - surface failures to the model, not the stack
        result = {"error": f"{type(exc).__name__}: {exc}"}
        outcome = "error"

    duration_ms = int((time.monotonic() - started) * 1000)

    # What the call spent at a model, if the tool said. Step 045b, and it happens
    # **here** — after execution, before the response is bounded and before the single
    # `_audit` below — for a reason the table forces: `audit` is append-only by trigger
    # with no UPDATE, so usage is present at INSERT or it is not recorded at all.
    #
    # `pop`, not `get`. Unlike `MAY_HAVE_COMPLETED`, which rides back to the model
    # because the model is the party that decides whether to retry, this key is
    # bookkeeping: the caller has no use for it, it would count against the size cap
    # measured on the next line, and a REST connector's contract is that the vendor's
    # JSON comes back *verbatim* — a key we invented would quietly end that.
    #
    # Recorded on the error path too, and that is deliberate rather than incidental: a
    # vendor that charges for a call and then returns 500 has spent money, and money
    # spent is money recorded. Only a *refusal* carries no usage, and it carries none by
    # construction — steps 0 to 3 return above without ever reaching here.
    model, usage = "", None
    if isinstance(result, dict) and tool_registry.REPORTED_USAGE in result:
        reported = parse_report(result.pop(tool_registry.REPORTED_USAGE))
        if reported is not None:
            model, usage = reported

    result, outcome, response_bytes = _bound_response(result, outcome, tool)
    ctx.budget.add_bytes(response_bytes)

    # A failed write that may nonetheless have landed is not the same event as one
    # that plainly didn't, and only the audit log will remember which it was. Reads
    # are left as plain errors — an unanswered read changed nothing either way.
    if (
        outcome == "error"
        and tool.effect == "write"
        and isinstance(result, dict)
        and result.get(tool_registry.MAY_HAVE_COMPLETED)
    ):
        outcome = "unknown"

    _audit(
        decision="allow",
        outcome=outcome,
        # Taken from what the lookup returned rather than re-derived, so the record
        # cannot disagree with the credential the call actually went out with.
        credential=creds.source,
        duration_ms=duration_ms,
        response_bytes=response_bytes,
        # `''` and None when nothing was reported, which is every call this product has
        # brokered so far — see `core/audit.record` for why that is four NULLs and not
        # four zeros.
        model=model,
        usage=usage,
        # **Why it went wrong, kept.** Until step 041's live pass noticed, an errored
        # call's record said `outcome="error"` and nothing else: the cause existed only
        # in the response the caller got, so *"why did that call fail"* was unanswerable
        # from the log — the one place built to answer it after the fact. The sentence
        # recorded is the same one the caller was handed (`result["error"]` IS the
        # response), so the log discloses nothing the call did not. Applies to `error`,
        # `oversize` and `unknown` alike; `unknown` most of all, because a write that
        # may have landed is exactly the row somebody reads during an incident.
        reason=_failure_reason(result) if outcome != "ok" else "",
        # Step 060: this is the one record that describes something that already
        # happened, so a failed append lands in the fallback file rather than turning
        # into a 503 about work that ran. Every refusal above stays loud on purpose.
        durable=True,
    )

    # Step 057. The duration series pairs with calls_total{decision="allow"} for a
    # mean; refusals deliberately add no duration, because steps 0-3 execute nothing.
    metrics.bump("carnet_broker_calls_total", decision="allow", outcome=outcome)
    metrics.bump("carnet_broker_call_duration_ms_total", duration_ms)

    return result


def stream(
    ctx, agent: dict, tool_name: str, tool_input: dict, *, redact=frozenset()
) -> "Streamed":
    """Broker one call whose answer is handed on while it is still arriving. Step 108.

    **Every check `call` runs, in the same order, before the first byte is sent
    upstream** — `_admit` is the one implementation of steps 0 to 3 and both entry
    points go through it. What differs is step 4: instead of executing, bounding and
    auditing in one breath, this returns a `Streamed` the caller iterates, and the audit
    row is written when the iteration ends — by exhaustion, by the caller stopping, by
    the byte cap, or by the upstream failing — with `outcome` saying which.

    **The alternative was rejected in the plan and is worth restating here**: buffering
    the upstream inside the broker and handing the route a complete result makes
    streaming a lie. The caller waits for the whole completion and then receives it
    fast; the point of streaming is the first token's latency.

    Never raises for a refusal or a failure: both come back as a `Streamed` whose
    `error` is set and whose iteration is empty, so a caller has one shape to handle.
    `redact` widens the tool's own redaction for this call's audit row (decision 10).

    Only `tools/rest` tools have a `stream_impl`; every other tool answers with an
    error naming that, audited as an error, because the MCP door is JSON-only by
    decision and a hand-written tool has nothing to forward early.
    """
    admitted = _admit(ctx, agent, tool_name, tool_input, extra_redact=redact)
    if isinstance(admitted, dict):
        return Streamed.settled(admitted, refused=True)
    gate, creds = admitted
    tool = gate.tool

    if tool.stream_impl is None:
        reason = (
            f"Tool '{tool_name}' cannot stream: it is not a REST tool, and only a REST "
            "response can be read as it arrives."
        )
        gate.audit(decision="allow", outcome="error", credential=creds.source, reason=reason)
        metrics.bump("carnet_broker_calls_total", decision="allow", outcome="error")
        return Streamed.settled({"error": reason})

    started = time.monotonic()
    try:
        upstream = tool.stream_impl(**tool_input, **creds.kwargs)
    except Exception as exc:  # noqa: BLE001 - surface failures to the caller, not the stack
        reason = f"{type(exc).__name__}: {exc}"
        gate.audit(
            decision="allow",
            outcome="error",
            credential=creds.source,
            duration_ms=int((time.monotonic() - started) * 1000),
            reason=_failure_reason({"error": reason}),
            durable=True,
        )
        metrics.bump("carnet_broker_calls_total", decision="allow", outcome="error")
        return Streamed.settled({"error": reason})

    return Streamed(gate, creds, upstream, started)


class Streamed:
    """A brokered answer, read as it arrives. What `stream()` returns.

    Iterate it for the bytes. Read `status`, `headers` and `error` before iterating to
    decide what to tell the caller; read `outcome` and `response_bytes` after, if the
    caller cares. **Call `close()` if iteration stops early** — a `for` loop that
    `break`s, a client that disconnected — so the upstream request is closed and the
    row is written; a `Streamed` dropped without being exhausted or closed has written
    nothing, which is the one way this object can be wrong, and it is the caller's.

    Five endings, and one row for each:

        ok        the upstream finished and every byte passed
        oversize  the bytes passed the tool's cap; the upstream was closed there. The
                  caller gets every byte up to the cap and nothing after — the wire
                  cannot be un-sent, so the caller says so in its own dialect
        error     the upstream answered a non-2xx, failed before a byte, or broke mid-
                  answer; `error` carries the sentence
        unknown   `call`'s bias, kept: a write whose request may have reached the
                  vendor and answered nothing (a timeout before the first byte)
        aborted   the caller stopped iterating (migration 055)

    `refused` says the call never reached step 4 — steps 0 to 3 refused it, and `error`
    is the dict `call` would have returned. `status` is None in that case and for a
    failure before a byte; otherwise it is the upstream's own, to relay.
    """

    __slots__ = (
        "status", "headers", "error", "refused", "relay_body", "may_have_completed",
        "outcome", "response_bytes", "_gate", "_creds", "_upstream", "_started",
        "_finalized", "_iterator",
    )

    def __init__(self, gate, creds, upstream, started):
        self._gate = gate
        self._creds = creds
        self._upstream = upstream
        self._started = started
        self._finalized = False
        self._iterator = None
        self.status = upstream.status
        self.headers = dict(upstream.headers)
        self.error = {"error": upstream.error} if upstream.error else None
        self.refused = False
        self.relay_body = upstream.relay_body
        self.may_have_completed = upstream.may_have_completed
        self.outcome = ""
        self.response_bytes = 0

    @classmethod
    def settled(cls, error: dict, *, refused: bool = False) -> "Streamed":
        """A `Streamed` with nothing to stream: a refusal, or a failure already audited."""
        self = cls.__new__(cls)
        self._gate = self._creds = self._upstream = None
        self._started = 0.0
        self._finalized = True
        self._iterator = None
        self.status = None
        self.headers = {}
        self.error = error
        self.refused = refused
        self.relay_body = False
        self.may_have_completed = False
        self.outcome = "" if refused else "error"
        self.response_bytes = 0
        return self

    def __iter__(self):
        if self._upstream is None:
            # Settled: refused or already failed. Nothing to relay, nothing to write.
            return iter(())
        if self._iterator is None:
            self._iterator = self._chunks()
        return self._iterator

    def _chunks(self):
        tool = self._gate.tool
        cap = config.MAX_RESPONSE_BYTES
        if tool.max_response_bytes is not None:
            cap = tool.max_response_bytes

        outcome = "ok"
        try:
            for chunk in self._upstream.chunks():
                self.response_bytes += len(chunk)
                if self.response_bytes > cap:
                    # The cap is applied as the bytes pass, which is the one response a
                    # size limit cannot check up front. Closing the upstream is what
                    # stops the vendor generating for a listener that will not relay.
                    outcome = "oversize"
                    self.error = {
                        "error": "Tool response exceeded the size limit and was cut off.",
                        "bytes": self.response_bytes,
                        "limit": cap,
                    }
                    self._upstream.close()
                    break
                yield chunk
            if outcome == "ok" and self._upstream.error:
                # A non-2xx relayed whole, a stall mid-answer, a break in the stream:
                # the upstream says which, and the caller has already had every byte.
                outcome = "error"
                self.error = {"error": self._upstream.error}
        except GeneratorExit:
            # The consumer stopped — a client that disconnected, a loop that broke.
            # The upstream is closed in `finally`; the row says what was counted.
            outcome = "aborted"
            raise
        except Exception as exc:  # noqa: BLE001 - the row is written whatever broke
            outcome = "error"
            self.error = {"error": f"{type(exc).__name__}: {exc}"}
        finally:
            self._upstream.close()
            self._finalize(outcome)

    def close(self) -> None:
        """Stop early. Idempotent. **Writes the row if iteration never finished.**

        The caller owes this call on every path that does not exhaust the iterator, and
        the route's own guard is what pays it — see `api/routes_openai._complete`.

        **What ended it is not always the caller.** A `Streamed` whose upstream had
        already failed — a connection refused, a vendor that never answered, an
        argument the tool would not send — never had anything for the caller to walk
        away from, so closing it records `error` (or `unknown`, by `_finalize`'s bias
        for a write that may have landed) rather than `aborted`. Only a stream that
        could have been read and was not is an abort.
        """
        if self._finalized:
            return
        if self._iterator is not None:
            # Running `finally` inside the generator, which closes the upstream and
            # writes the row as `aborted`.
            self._iterator.close()
            return
        # Never iterated: either nobody read an answer that was there, or there was
        # never an answer to read.
        self._upstream.close()
        self._finalize("error" if self._upstream.error else "aborted")

    def _finalize(self, outcome: str) -> None:
        if self._finalized:
            return
        self._finalized = True
        gate, creds, upstream = self._gate, self._creds, self._upstream
        duration_ms = int((time.monotonic() - self._started) * 1000)

        # `call`'s bias for a write that may have landed, kept for the one case it
        # applies to here — a failure before any byte, where the vendor may have
        # done the work and billed it. A break *after* bytes is an `error`: the
        # caller saw the answer stop, and there is nothing unknown about it.
        if (
            outcome == "error"
            and upstream.may_have_completed
            and self.response_bytes == 0
            and gate.tool.effect == "write"
        ):
            outcome = "unknown"
        self.outcome = outcome

        # What the call spent, from whichever chunk carried it — `parse_report` decides
        # what to believe, exactly as for the buffered path. An aborted stream usually
        # reports nothing, because the usage object is the last chunk; the row then
        # says NULL rather than an estimate.
        model, usage = "", None
        reported = parse_report(upstream.report())
        if reported is not None:
            model, usage = reported

        gate.ctx.budget.add_bytes(self.response_bytes)
        gate.audit(
            decision="allow",
            outcome=outcome,
            credential=creds.source,
            duration_ms=duration_ms,
            response_bytes=self.response_bytes,
            model=model,
            usage=usage,
            reason=_failure_reason(self.error) if outcome != "ok" else "",
            durable=True,
        )
        metrics.bump("carnet_broker_calls_total", decision="allow", outcome=outcome)
        metrics.bump("carnet_broker_call_duration_ms_total", duration_ms)


# A failure sentence is a log field, not a payload. An exception's repr can carry a
# vendor's whole response body inside it, and the audit table keeps every row for the
# retention window — so the record takes the head of the sentence, which is where every
# exception puts its type and message, and the full text stays where it always was: in
# the response the caller received.
_REASON_CAP = 500


def _failure_reason(result) -> str:
    """The caller-visible cause of a failed call, bounded for the log."""
    if not isinstance(result, dict):
        return ""
    reason = str(result.get("error") or "")
    if len(reason) > _REASON_CAP:
        return f"{reason[:_REASON_CAP]}…"
    return reason


def _bound_response(result: dict, outcome: str, tool) -> tuple[dict, str, int | None]:
    """Enforce the per-response size ceiling. Returns (result, outcome, size_in_bytes).

    Measured against the serialized form, because that — not the Python object — is
    what enters model context and what an attacker is trying to fill.

    Oversized responses are REFUSED, not truncated: a clipped JSON payload is
    malformed JSON the model has to guess at, whereas an explicit refusal is
    something it can act on by narrowing its request.
    """
    # config is imported as a module, not by value, so tests can adjust the ceiling.
    cap = config.MAX_RESPONSE_BYTES
    if tool is not None and tool.max_response_bytes is not None:
        cap = tool.max_response_bytes

    try:
        size = len(json.dumps(result).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        # A tool returned something that can't cross the wire. The loop would fail
        # on this later anyway; failing here keeps it inside the broker's contract.
        return (
            {"error": f"Tool response could not be serialized: {type(exc).__name__}."},
            "error",
            None,
        )

    if size <= cap:
        return result, outcome, size

    return (
        {
            "error": "Tool response exceeded the size limit and was discarded.",
            "bytes": size,
            "limit": cap,
            "hint": "Narrow the request — fewer items, a filter, or a smaller range.",
        },
        "oversize",
        size,
    )
