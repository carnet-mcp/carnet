"""Append-only audit log. One row per brokered call.

Every brokered call writes exactly one record, whether it was allowed, denied, or
failed during execution. Records are written *after* the decision is known but are
never conditional on success — a denial is the most important thing to log.

This module depends on nothing but config, credentials and storage. The per-tool
redaction policy is passed in by the broker (it lives on the Tool), so audit has no
knowledge of the tool registry — which is what made swapping the JSONL writer for a
storage call a change to this one file.

**Append-only is a property, not a convention.** A file was append-only because of
what it is; a table is mutable by default, and an audit log somebody can UPDATE is a
weaker artifact than the one it replaced. The interface here offers no way to change
or remove a record, and the Postgres migration revokes UPDATE and DELETE on the table
from the application role.
"""

import hashlib
import json
import logging
from datetime import datetime, timezone

from .. import storage
from .credentials import RESERVED_KWARGS
from .principal import NO_IDENTITY
from .usage import TokenUsage

log = logging.getLogger(__name__)

# Step 096. The logger whose every message is one JSON object — an audit record or a
# refusal — for a log pipeline reading the container's stdout. Nothing here knows about
# stdout: `api.configure_logging` gives this logger a bare `%(message)s` handler and
# stops propagation, so the line never passes through the app log's own wrapper. **The
# name is a promise** the moment a pipeline filters on it; stated so nobody tidies it.
AUDIT_LOGGER = "carnet.audit"
_line = logging.getLogger(AUDIT_LOGGER)


def emit(kind: str, tenant_id: str, entry: dict) -> None:
    """One line: `{"type": kind, "tenant_id": …, **entry}`. Plan 096, decision 3.

    Every field is the row's field, spelled as the row spells it, so the line makes no
    promise the table has not already made — `v` is the table's version. `type` is the
    one word added, because a stream carries two shapes (`audit`, `denial`) and a
    reader has to tell them apart; `tenant_id` rides along because a line, unlike a
    row, has no routing key. `default=str` on `JsonLogFormatter`'s rule: a value that
    will not serialise degrades to its repr rather than losing the line.
    """
    _line.info(json.dumps({"type": kind, "tenant_id": tenant_id, **entry}, default=str))


def _redact(tool_input: dict, redact_args: frozenset) -> dict:
    """Copy tool_input, hashing any argument that must not be stored raw.

    Two sources of redaction:
      - `redact_args`, the tool's own policy (free text, user content)
      - RESERVED_KWARGS, always — a *denied* call still gets logged, and if the
        model smuggled a real credential in as an argument, writing it here in the
        clear would leak the secret into the audit trail we keep forever.
    """
    to_redact = set(redact_args) | RESERVED_KWARGS
    out = {}
    for key, value in tool_input.items():
        if key in to_redact:
            digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]
            out[key] = f"sha256:{digest} (len={len(str(value))})"
        else:
            out[key] = value
    return out


# Bumped whenever the record shape changes. Present from the first record so a
# later migration (JSONL -> Postgres) is a filter on a field rather than a guess
# from which keys happen to be present.
#
# 5: added tenant_id. This is the version the field was written to earn.
# 6: added `credential` — how the call's secret was obtained.
#
#    Added *with* delegated credentials rather than after, and the reason is the whole
#    argument for schema versions. A record carries who a run acted **for**; until this
#    step it said nothing about whose credential it **used**, which was fine while there
#    was one credential and it was the operator's — the two facts could not disagree.
#
#    They disagree the moment delegation ships. Priya has no connection, the read path
#    falls back to the environment variable, and the record says `user:u_8f2c1a` for a
#    call that reached GitHub as the *operator's* account. Somebody auditing a write six
#    months later reads "Priya's agent did this" and is wrong about the account it was
#    done from — and the account is what decides what the write could reach.
#
#    One field now; a backfill against an append-only table later.
#
# 7: added `acting_for` + `identity_source` — whom the call was made for, and how much
#    that claim is worth (step 033c). The same disagreement argument as 6, one person
#    further out: a record already said whose *credential* a call used; through the MCP
#    door the interesting person is the one behind the calling service, and without
#    these fields fifty people through one shared token are indistinguishable in the
#    one log kept to distinguish them. `identity_source` keeps `verified`, `asserted`
#    and `none` apart because collapsing them makes the trail actively untrue — an
#    asserted name is worth exactly what the calling app's honesty is worth, and a row
#    that hides that difference upgrades it.
#
#    Not bumped by 045b, which added `model` and four token counters. The rule this
#    number obeys is *meaning changed*, never *field added*: a reader that has never
#    heard of the counters reads a v7 row correctly and sees NULLs, which is the truth
#    about every row written before there was anything to count. Bumping would make
#    every existing row look like a different kind of record than it is.
SCHEMA_VERSION = 7


def record(
    *,
    run_id: str,
    principal,
    agent: str,
    tool: str,
    tool_input: dict,
    decision: str,
    redact_args: frozenset = frozenset(),
    effect: str = "",
    reason: str = "",
    outcome: str = "",
    credential: str | None = None,
    duration_ms: int | None = None,
    response_bytes: int | None = None,
    acting_for: str | None = None,
    identity_source: str = NO_IDENTITY,
    model: str = "",
    usage: TokenUsage | None = None,
    durable: bool = False,
) -> dict:
    """Append one audit record and return it.

    run_id:    correlates every record from one agent run. Without it there is no way
               to ask "what did that run do?" — only "what did that agent ever do?".
    principal: core.principal.Principal — the authority the call was made under,
               stored flat so the columns survive the move to a database. The
               tenant is taken from here rather than passed separately, because
               the principal is the one place it lives.
    effect:    "read" | "write" | "" (empty when the tool wasn't in the registry)
    decision:  "allow" | "deny"
    outcome:   "ok" | "error" | "oversize" | "unknown" | "" (empty when denied)
               "unknown" is reserved for a WRITE that reached an external system
               and never answered: it may or may not have taken effect, and this
               record is the only place that will ever say so.
    credential: "delegated" | "shared" | None — how the secret this call went out
               with was obtained. `delegated` means the caller's own connected
               account; `shared` means one organisational secret, the same for
               everybody; None means the tool needed no credential at all, or
               nothing was executed.

               Deliberately *which kind*, never *whose*. Storing an identifier for
               the credential's owner would put a second person's name in a table
               that is append-only by trigger and whose retention is undesigned,
               to answer a question `principal_id` mostly answers already. What
               was missing is the one bit that column cannot carry: whether those
               two are the same person.
    response_bytes: serialized size of the tool's response, recorded even when
               under the cap so there's data to set caps from later.
    acting_for: whom the call was made *for*, when a shared service through the MCP
               door said so — an email, bounded at the door's edge before it can
               reach here (migration 041's CHECK is the structural bound behind
               that). None everywhere else, including every run: a run's principal
               is who it acts for, and inventing a copy of that fact here would be
               two values free to disagree.
    identity_source: "verified" | "asserted" | "none" — what the acting_for claim is
               worth. Written on every record, denials included, so the plan-033 log
               line `tom@… (verified) search_issues DENIED` is real. The three are
               never collapsed; see SCHEMA_VERSION 7 above.
    model:     what answered, when the tool reported one. `''` on every other row, and
               `''` is a value this column *means* something by — nobody recorded a
               model — matching `runs.model` and `vetted_tools.server_name`.
    usage:     what the call spent at a model, or None for the overwhelming majority of
               calls that touched no model at all. Step 045b.

               **None becomes four NULLs, never four zeros**, and that is the one
               decision worth stating here rather than only in migration 048: on `runs`
               a zero is honest because every run is a model run, while on `audit` a
               zero would say *spent nothing* about a row where the truth is *not
               applicable*. `response_bytes` already draws exactly this distinction —
               NULL is never-ran, not ran-in-zero-time — and the ceiling that reads
               these columns is predicated on `IS NOT NULL`, so the difference is load
               bearing rather than tidy.

               A denied call carries None by construction: the refusal happens before
               anything is executed, so nothing was spent and nothing is recorded. That
               is also what makes a denied-then-retried call impossible to double-count.
    """
    # The tenant is the routing key and is passed separately, so it deliberately is
    # not a field of the body: two copies of it are two values free to disagree, and
    # a disagreement about which tenant a call belonged to is a cross-tenant leak in
    # the one record that is supposed to settle such questions.
    entry = {
        "v": SCHEMA_VERSION,
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "run_id": run_id,
        "principal_kind": principal.kind,
        "principal_id": principal.id,
        "agent": agent,
        "tool": tool,
        "effect": effect,
        "args": _redact(tool_input, redact_args),
        "decision": decision,
        "reason": reason,
        "outcome": outcome,
        "credential": credential,
        "duration_ms": duration_ms,
        "response_bytes": response_bytes,
        "acting_for": acting_for,
        "identity_source": identity_source,
        "model": model,
        # Spread rather than a nested object, because the columns are flat and this dict
        # is written straight into them — the same reason `principal` is stored flat
        # above. `TokenUsage` is the vocabulary everywhere else — `core.usage`'s
        # `price_buckets` reads these columns back off a door row through it — and it is
        # unpacked here and nowhere else.
        "input_tokens": usage.input_tokens if usage else None,
        "output_tokens": usage.output_tokens if usage else None,
        "cache_read_tokens": usage.cache_read_tokens if usage else None,
        "cache_write_tokens": usage.cache_write_tokens if usage else None,
    }

    # `durable` (step 060) is set only by the broker's final post-execution record —
    # the one row that describes something that already happened. Everywhere else a
    # failed append stays loud: a refusal or a pre-execution record that cannot be
    # written is a call that never ran, and the caller should hear it.
    try:
        if durable:
            try:
                storage.active().append_audit(principal.tenant_id, entry)
            except Exception as exc:  # noqa: BLE001 - the record must outlive the append
                _record_to_fallback(principal.tenant_id, entry, exc)
        else:
            storage.active().append_audit(principal.tenant_id, entry)
    finally:
        # Step 096: after the append is attempted, never instead of it, and regardless
        # of how it went — on the platform artefact this is the second copy 060's
        # fallback file was invented for; on the fileborne door it is the only copy.
        emit("audit", principal.tenant_id, entry)

    # Returned in the shape a read gives back, so a caller cannot tell whether it is
    # holding what it just wrote or what it later queried.
    return {**entry, "tenant_id": principal.tenant_id}


def _record_to_fallback(tenant_id: str, entry: dict, cause: Exception) -> None:
    """The durable sink for a post-execution record the database refused. Step 060.

    The outbox's pattern and placement: one JSON object per line, appended to a file
    on `CARNET_VAR_DIR` — a volume in the shipped compose — carrying the entry, its
    tenant, and the append failure's own sentence, so an operator can re-ingest it
    and see why it landed here. CRITICAL because this file existing at all means the
    audit log has a gap the database does not know about.

    Never raises: if even the file cannot be written, the CRITICAL line is what
    remains, and failing the already-executed call would add nothing but a lie —
    a 503 about work that happened.
    """
    import json

    from ..config import AUDIT_FALLBACK_PATH, ensure_var_dir

    line = json.dumps(
        {
            **entry,
            "tenant_id": tenant_id,
            "append_error": f"{type(cause).__name__}: {cause}",
        },
        default=str,
    )
    try:
        ensure_var_dir()
        with open(AUDIT_FALLBACK_PATH, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception:  # noqa: BLE001 - see the docstring: the log line is what remains
        log.critical(
            "an executed call's audit record could be written NOWHERE — not the "
            "database (%s) and not %s. The record follows, verbatim, as the last "
            "resort: %s",
            cause, AUDIT_FALLBACK_PATH, line,
        )
        return
    log.critical(
        "an executed call's audit record could not reach the database (%s); it is "
        "preserved in %s awaiting re-ingestion. The audit table has a gap until "
        "somebody replays that file.",
        cause, AUDIT_FALLBACK_PATH,
    )
