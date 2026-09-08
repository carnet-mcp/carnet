"""Recording a refusal, without ever changing it.

The hook the two producers of a refusal call on their deny branches — `grants.require`
and `roles.require_admin`, and nothing else. Those two are single seams: every caller
that exists and every caller anyone adds, over HTTP and the CLI alike, goes through one
of them, so the record needs zero call-site changes and no parameter a caller could
forget to pass. **The lesson 022 recorded from 011: a value every caller must supply is
a value the next caller forgets**, and the caller that forgets produces exactly the
silent gap this log exists to close.

## Best-effort, on `runs._finish`'s precedent

The refusal is the security behavior; the record is evidence. A denial that cannot be
recorded is still served, byte-identical to today's — the same `no agent named 'X'`
404, the same `NOT_AN_ADMINISTRATOR` 403 — and the exception is logged. Evidence is
never allowed to cost enforcement, or to fail the request in a new way.

## What is deliberately not recorded

`check()` stays silent. It answers visibility questions — list filtering, `_may_see` on
runs — where a False is the system *withholding*, not the caller *attempting*. The
line: `require` is called when somebody asked to act on a named thing; `check` is
called when the system decides what to show. Only the first is an attempt.
"""

import logging

from .. import storage
from ..core import Principal, audit
from ..storage.base import make_denial_record

log = logging.getLogger(__name__)


def record(
    principal: Principal,
    resource_kind: str,
    resource_id: str,
    required: str,
    held: str = "",
) -> None:
    """Append one denial record, and never let that change the refusal.

    Called from a deny branch that is about to raise, so everything here happens on
    the rare path — the allow branch writes nothing and reads nothing extra.
    """
    record = make_denial_record(
        principal.kind,
        principal.id,
        resource_kind,
        resource_id,
        required,
        held,
    )
    try:
        storage.active().record_denial(principal.tenant_id, record)
    except Exception:  # noqa: BLE001 - the refusal must be served regardless; see above
        log.exception(
            "could not record the denial of %s:%s on %s '%s'",
            principal.kind,
            principal.id,
            resource_kind,
            resource_id,
        )
    # Step 096: the refusal on stdout, after the append was attempted. This is the
    # first refused call plan 094 calls the moment that converts, and a stream that
    # carried `audit` rows only would be silent at exactly that moment.
    audit.emit("denial", principal.tenant_id, record)
