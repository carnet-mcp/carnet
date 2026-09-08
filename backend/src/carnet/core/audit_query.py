"""Reading what audit.py writes.

The audit log was built as an enforcement record — every brokered call, allowed or
refused. It doubles as a measurement instrument, and this module is that half.
`run_id`, `effect`, `outcome`, `duration_ms` and `response_bytes` were on the record
from the first version precisely so questions like "did the connector cost us more
than the hand-written tool?" would be a query rather than an afternoon.

Deliberately separate from audit.py, which stays a writer. The two were built as a
pair for exactly this move, and it cost what it was supposed to: the writer became one
storage call and the reader became one query, with nothing above either changing.

Comparison, not aggregation. This answers "what did that run do?", which is the
question a per-run id makes answerable; fleet-wide reporting belongs to the control
plane, and the aggregation belongs in SQL once there is a fleet to report on.
"""

from dataclasses import dataclass, field

from .. import storage


def load(tenant_id: str, limit: int | None = None) -> list:
    """Every record for this tenant, oldest first.

    Tenant-scoped with no way to ask for all of them. Auditing is exactly where a
    convenience "everything" call would be most tempting and most dangerous.
    """
    return storage.active().audit_records(tenant_id, limit=limit)


@dataclass
class Run:
    """Everything one run did, in order."""

    run_id: str
    agent: str = ""
    principal: str = ""
    started: str = ""
    records: list = field(default_factory=list)

    # --- what it did ------------------------------------------------------------

    @property
    def calls(self) -> int:
        return len(self.records)

    @property
    def allowed(self) -> int:
        return sum(1 for r in self.records if r.get("decision") == "allow")

    @property
    def denied(self) -> int:
        """The most interesting number in a comparison: same task, same grants —
        did one path get refused where the other didn't?"""
        return sum(1 for r in self.records if r.get("decision") == "deny")

    @property
    def writes(self) -> int:
        return sum(
            1
            for r in self.records
            if r.get("effect") == "write" and r.get("decision") == "allow"
        )

    @property
    def errors(self) -> int:
        return sum(1 for r in self.records if r.get("outcome") == "error")

    @property
    def oversize(self) -> int:
        return sum(1 for r in self.records if r.get("outcome") == "oversize")

    @property
    def unknown(self) -> int:
        """Writes that reached an external system and never answered.

        Counted separately from errors because it is the one outcome that needs a
        person: nobody can tell from here whether the thing happened.
        """
        return sum(1 for r in self.records if r.get("outcome") == "unknown")

    @property
    def response_bytes(self) -> int:
        """Cumulative bytes into model context — the volume half of the injected-
        content defense, and the number a verbose connector moves most."""
        return sum(r.get("response_bytes") or 0 for r in self.records)

    @property
    def tool_ms(self) -> int:
        return sum(r.get("duration_ms") or 0 for r in self.records)

    @property
    def sequence(self) -> list:
        """(tool, verdict) in order. Which tool it reached for first, and what
        happened — the shape of the run rather than its totals."""
        out = []
        for r in self.records:
            if r.get("decision") == "deny":
                verdict = "DENIED"
            else:
                verdict = r.get("outcome") or "ok"
            out.append((r.get("tool", "?"), verdict))
        return out

    @property
    def tools_used(self) -> dict:
        counts: dict = {}
        for r in self.records:
            counts[r.get("tool", "?")] = counts.get(r.get("tool", "?"), 0) + 1
        return counts


def runs(tenant_id: str, records=None) -> list:
    """Group this tenant's records into runs, oldest first."""
    records = load(tenant_id) if records is None else records
    by_id: dict = {}

    for record in records:
        run_id = record.get("run_id", "")
        run = by_id.get(run_id)
        if run is None:
            run = Run(
                run_id=run_id,
                agent=record.get("agent", ""),
                principal=f"{record.get('principal_kind')}:{record.get('principal_id')}",
                started=record.get("ts", ""),
            )
            by_id[run_id] = run
        run.records.append(record)

    return list(by_id.values())


def find(tenant_id: str, run_id: str, all_runs=None) -> Run | None:
    """Look up a run by id or unique prefix — twelve hex characters is a lot to type.

    Scoped to a tenant, so a prefix can never resolve to another customer's run.
    """
    all_runs = runs(tenant_id) if all_runs is None else all_runs
    matches = [r for r in all_runs if r.run_id.startswith(run_id)]
    return matches[0] if len(matches) == 1 else None
