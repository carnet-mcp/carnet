"""Partitioning the three log tables, against real Postgres, through the real upgrade.

Migration 030 converts `audit`, `admin_audit` and `access_denials` from ordinary tables
into monthly range partitions on `ts`, so that retention becomes a partition drop rather
than a batched delete. Five things can only fail against a real database, which is why
this is a script and not a test:

  - **the conversion itself.** Rename, build partitioned, copy with `OVERRIDING SYSTEM
    VALUE`, `setval`, recreate indexes and triggers, drop the old shell — in one
    transaction. The in-memory store has no schema to convert, so none of it is
    assertable there.
  - **the upgrade path**, which is the only sequence a deployment actually runs: rows
    written under 028, then 029, then 030, with the same code reading them afterwards.
    Every other test here builds a database from `001` and never sees it.
  - **trigger cloning.** A row trigger on a partitioned parent clones onto every
    partition, including ones created months later. That is a mechanism this step's
    whole safety rests on and it exists nowhere but in Postgres.
  - **the drop.** `prune_log_records` removes partitions rather than rows now, and
    "the partition is gone from `pg_class`" is not a statement the fake can make.
  - **the horizon.** An append whose month has no partition is refused by the database,
    which is the failure mode that pays for not creating partitions on the write path.

**It builds its own world** — two databases, one migrated straight to 030 and one walked
through the upgrade — so it needs nobody at a keyboard.

    cd backend && .venv/bin/python scripts/e2e_partitioning.py

**Costs nothing.** No run is submitted, so no model is called and no connector launched.
"""

import datetime as dt
import os
import pathlib
import sys
from urllib.parse import urlsplit, urlunsplit

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_partitioning"


def dsn_for(database: str) -> str:
    """Where Postgres is. `CARNET_E2E_PG` is a base DSN with no database name."""
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


DSN = dsn_for(DB)
TENANT = "acmeco"
CONTROL = "controlco"

CHECKS = []


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok))
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: {actual!r}"
          + ("" if ok else f"  (expected {expected!r})"))


def say(what):
    print(f"\n=== {what}", flush=True)


def field(row, *path):
    """Read a nested field without ever raising — 12c's `detail()`, for its reason.

    A mutation that stops a record being written makes every read below it a `TypeError`
    on `None`, which kills the run and reports one failure where ten follow.
    """
    for key in path:
        if row is None:
            return None
        try:
            row = row[key]
        except (KeyError, IndexError, TypeError):
            return None
    return row


def report():
    """The summary, callable from anywhere — including a migration that could not run."""
    passed = sum(1 for _label, ok in CHECKS if ok)
    failed = [label for label, ok in CHECKS if not ok]
    print(f"\n=== {passed}/{len(CHECKS)} checks passed")
    for label in failed:
        print(f"  FAILED: {label}")
    return 1 if failed else 0


def _days_ago(days):
    return dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)


def audit_record(ts=None, run_id="r-1"):
    return {
        "v": 6,
        "ts": ts or dt.datetime.now(dt.timezone.utc),
        "run_id": run_id,
        "principal_kind": "user",
        "principal_id": "u-priya",
        "agent": "payroll-bot",
        "tool": "post_message",
        "effect": "write",
        "args": {"channel": "#eng"},
        "decision": "allow",
        "outcome": "ok",
    }


def fresh_database(name):
    import psycopg

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {name}")
        conn.execute(f"CREATE DATABASE {name}")


def partitions_of(store, parent):
    return [
        row[0] for row in store._fetchall(
            """
            SELECT c.relname FROM pg_class c
              JOIN pg_inherits i ON i.inhrelid = c.oid
              JOIN pg_class p ON p.oid = i.inhparent
             WHERE p.relname = %s ORDER BY 1
            """,
            (parent,),
        )
    ]


def the_upgrade(dsn):
    """001..028, a world written by raw SQL, then 029, then 030 — one row at a time.

    This is the sequence a real deployment runs and the only one nothing else exercises.
    The rows below are written as the *old* code left them: raw INSERTs against the
    unpartitioned tables, under the pre-029 trigger definitions.
    """
    import psycopg
    from carnet.storage import migrate

    real_available = migrate.available

    def upto(stop):
        return lambda: [(s, p) for s, p in real_available() if s < stop]

    migrate.available = upto("029")
    try:
        check("the pre-029 world is 28 migrations", len(migrate.apply(dsn)), 28)
    finally:
        migrate.available = real_available

    now = dt.datetime.now(dt.timezone.utc)
    months_back = [0, 40, 75, 200]
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("INSERT INTO tenants (id, name) VALUES (%s, 'Acme')", (TENANT,))
        conn.execute("INSERT INTO tenants (id, name) VALUES (%s, 'Control')", (CONTROL,))
        for n, days in enumerate(months_back):
            for tenant in (TENANT, CONTROL):
                conn.execute(
                    "INSERT INTO audit (tenant_id, v, ts, run_id, principal_kind, "
                    "principal_id, agent, tool, args, decision) VALUES "
                    "(%s, 6, %s, %s, 'user', 'u-1', 'bot', 't', '{}', 'allow')",
                    (tenant, now - dt.timedelta(days=days), f"r{n}"),
                )
            # A gap in the ids, because a real log has them: retention removes rows and
            # the sequence never goes back. Without one these ids are 1..8, and a copy
            # that renumbered every row would produce 1..8 as well — the assertion that
            # ids survived would pass by coincidence. **Found by mutation.**
            conn.execute(
                "SELECT setval(pg_get_serial_sequence('audit', 'id'), %s)",
                (100 * (n + 1),),
            )
        # **A row stamped two years in the future**, which is a skewed clock on one
        # writer or a backup restored from a machine that had one. `append_audit` takes
        # its timestamp from the caller, so nothing in the product prevents it.
        #
        # It is here because the obvious migration seeds partitions from the *oldest*
        # row through `now + 3 months` and then fails on anything past that — and
        # **failing is what it did**: the whole conversion rolled back with Postgres's
        # own "no partition of relation" and no way to tell which row caused it. Rolling
        # back cleanly is the transaction doing its job; being unable to upgrade at all
        # because of one timestamp is still wrong.
        conn.execute(
            "INSERT INTO audit (tenant_id, v, ts, run_id, principal_kind, "
            "principal_id, agent, tool, args, decision) VALUES "
            "(%s, 6, %s, 'from-the-future', 'user', 'u-1', 'bot', 't', '{}', 'allow')",
            (TENANT, now + dt.timedelta(days=730)),
        )
        conn.execute(
            "INSERT INTO admin_audit (tenant_id, v, ts, actor_kind, actor_id, action, "
            "target_kind, target_id) VALUES "
            "(%s, 1, %s, 'user', 'u-1', 'agent.save', 'agent', 'bot')", (TENANT, now))
        conn.execute(
            "INSERT INTO access_denials (tenant_id, v, ts, principal_kind, "
            "principal_id, resource_kind, resource_id, required) VALUES "
            "(%s, 1, %s, 'user', 'u-2', 'agent', 'bot', 'user')", (TENANT, now))

        before = conn.execute(
            "SELECT id, tenant_id, ts, run_id FROM audit ORDER BY id").fetchall()
        check("the pre-030 world has nine audit rows", len(before), 9)
        check("with a gap in their ids, so renumbering would show",
              before[-1][0] - before[0][0] > 8, True)

    say("029 lands first — trigger bodies rebound under six live triggers")
    migrate.available = upto("030")
    try:
        check("029 applies to a populated database", migrate.apply(dsn),
              ["029_retention_and_tombstones"])
    finally:
        migrate.available = real_available

    say("and then 030 partitions those same rows underneath it")
    # Caught rather than allowed to escape, on 12c's `detail()` lesson: a migration that
    # raises here kills the script and reports nothing, so a mutation that breaks the
    # conversion looks like a crash rather than like a failed check. It still stops —
    # nothing below this can mean anything — but it stops having said what went wrong.
    try:
        applied = migrate.apply(dsn)
    except Exception as exc:  # noqa: BLE001 - the whole point is to report it
        check(f"030 applies to a populated, migrated database ({exc})",
              "raised", ["030_partition_log_tables"])
        raise SystemExit(report()) from None
    # Everything from 030 onward, derived rather than written out. This script is about
    # 030, and pinning the literal tail meant every later migration broke it — which 031
    # duly did. What matters is that 030 is in the batch and the batch applies to a
    # database that already holds records.
    check("030 onward applies to a populated, migrated database", applied,
          [stem for stem, _ in migrate.available()][29:])
    check("and 030 is among them", "030_partition_log_tables" in applied, True)
    check("idempotent on a second run", migrate.apply(dsn), [])

    with psycopg.connect(dsn, autocommit=True) as conn:
        after = conn.execute(
            "SELECT id, tenant_id, ts, run_id FROM audit ORDER BY id").fetchall()
    check("every row survived, with its id, in its order", after, before)
    return before


def run(store, before):
    say("the row stamped two years ahead came through, in a partition of its own")
    future = [r for r in store.audit_records(TENANT) if r["run_id"] == "from-the-future"]
    check("it survived the conversion", len(future), 1)
    check("and its month exists as a partition",
          any(name > f"audit_p{dt.datetime.now(dt.timezone.utc):%Y_%m}"
              for name in partitions_of(store, "audit")), True)

    say("the three log tables are partitioned and nothing else is")
    partitioned = sorted(
        row[0] for row in store._fetchall(
            "SELECT relname FROM pg_class WHERE relkind = 'p' AND relname NOT LIKE %s",
            ("pg\\_%",),
        )
    )
    check("exactly the three logs", partitioned,
          ["access_denials", "admin_audit", "audit"])
    check("runs is deliberately not among them", "runs" in partitioned, False)

    say("reads are byte-identical across the conversion, through the product's own path")
    records = store.audit_records(TENANT)
    check("five records for this tenant", len(records), 5)
    check("in insertion order",
          [r["run_id"] for r in records], ["r0", "r1", "r2", "r3", "from-the-future"])
    check("the control tenant is untouched", len(store.audit_records(CONTROL)), 4)
    check("administrative records survived", len(store.admin_audit_records(TENANT)), 1)
    check("denial records survived", len(store.denial_records(TENANT)), 1)

    say("the identity sequence continues past the copied ids rather than colliding")
    store.append_audit(TENANT, audit_record(run_id="post-030"))
    ids = [row[0] for row in store._fetchall("SELECT id FROM audit ORDER BY id")]
    check("no id is repeated", len(ids), len(set(ids)))
    check("and the new one is the highest", ids[-1] > max(r[0] for r in before), True)

    say("every partition carries both append-only triggers, cloned from the parent")
    for parent in ("audit", "admin_audit", "access_denials"):
        parts = partitions_of(store, parent)
        check(f"{parent} has partitions", len(parts) > 0, True)
        missing = [
            name for name in parts
            if {row[0] for row in store._fetchall(
                "SELECT tgname FROM pg_trigger WHERE tgrelid = %s::regclass "
                "AND NOT tgisinternal AND tgparentid <> 0", (name,))}
            != {f"{parent}_no_update", f"{parent}_no_delete"}
        ]
        check(f"{parent}: every partition is protected", missing, [])

    say("a stray DELETE or UPDATE is still refused — through the parent and at a partition")
    from carnet.storage.base import StorageError

    # **A partition that actually holds rows.** The newest one is empty, and a DELETE
    # matching nothing fires no row trigger at all — so aiming there proves the refusal
    # works by never reaching it. Found by aiming there: two checks reported "permitted"
    # against a table where nothing could have been permitted. Counted rather than read
    # from `reltuples`, which is -1 until something has analysed the partition.
    target = next(
        name for name in reversed(partitions_of(store, "audit"))
        if store._fetchone(f"SELECT count(*) FROM {name}")[0] > 0
    )
    check("the partition under attack holds rows, or the refusal is untested",
          store._fetchone(f"SELECT count(*) > 0 FROM {target}")[0], True)
    for label, sql in (
        ("DELETE via the parent", "DELETE FROM audit"),
        ("UPDATE via the parent", "UPDATE audit SET reason = 'rewritten'"),
        ("DELETE aimed at a partition", f"DELETE FROM {target}"),
        ("UPDATE aimed at a partition", f"UPDATE {target} SET reason = 'rewritten'"),
    ):
        try:
            store._execute(sql)
            check(label + " refused", "permitted", "refused")
        except StorageError as exc:
            check(label + " refused", "append-only" in str(exc), True)

    say("the retention exemption still reaches a partition, so deletion is not locked out")
    with store._transaction() as cur:
        cur.execute("SELECT set_config('agent_runtime.retention', 'on', true)")
        cur.execute(f"DELETE FROM {target} WHERE run_id = 'nothing-matches-this'")
    check("the exemption applied without raising", True, True)

    say("a record beyond the horizon is refused, naming the fix rather than the cause")
    try:
        store.append_audit(TENANT, audit_record(ts=_days_ago(-3650)))
        check("refused", "permitted", "refused")
    except StorageError as exc:
        check("refused", "no partition of 'audit' covers" in str(exc), True)
        check("and it names the maintenance call",
              "ensure_log_partitions" in str(exc), True)

    say("maintenance creates what is missing, is idempotent, and reports only new work")
    created = store.ensure_log_partitions(back_to=_days_ago(400))
    check("it created something", len(created) > 0, True)
    check("a second call creates nothing",
          store.ensure_log_partitions(back_to=_days_ago(400)), [])
    store.append_audit(TENANT, audit_record(ts=_days_ago(400), run_id="ancient"))
    check("and the back-dated record now lands",
          any(r["run_id"] == "ancient" for r in store.audit_records(TENANT)), True)

    say("a prune drops whole months rather than deleting rows")
    from carnet.storage.base import prune_floor

    cutoff = _days_ago(150)
    floor = prune_floor(cutoff)
    doomed = [
        name for name in partitions_of(store, "audit")
        if name < f"audit_p{floor:%Y_%m}"
    ]
    check("there are expired months to drop", len(doomed) > 0, True)

    # Older than the window, inside the floor's month: due by the policy, kept by the
    # boundary the policy actually gets. Written before the prune so the prune sees it.
    spared_at = cutoff - dt.timedelta(days=1)
    store.append_audit(TENANT, audit_record(ts=spared_at, run_id="spared"))

    counts = store.prune_log_records(cutoff)

    check("the expired partitions are gone from the catalog",
          [n for n in doomed if n in partitions_of(store, "audit")], [])
    check("the boundary month itself survives",
          f"audit_p{floor:%Y_%m}" in partitions_of(store, "audit"), True)
    check("rows went with them", counts["audit"] > 0, True)

    say("and the boundary is the month floor, which is what the record says")
    records = store.admin_audit_records(TENANT, action="retention.prune")
    check("one record for this customer", len(records), 1)
    check("naming the effective boundary rather than the requested cutoff",
          field(records[0], "detail", "cutoff"), floor.isoformat())
    check("the actor is the sweeper", field(records[0], "actor_id"), "retention")
    check("it names no person", "u-priya" not in str(records[0]), True)

    say("the control customer lost exactly its expired month and nothing else")
    kept = [r["run_id"] for r in store.audit_records(CONTROL)]
    # r3 was 200 days old and its month is wholly behind the floor; r0, r1 and r2 are
    # not. The prune is global by design — one cutoff over every customer — so the
    # control tenant proves the boundary applies per row rather than per tenant.
    check("only the expired month went", sorted(kept), ["r0", "r1", "r2"])

    say("a record older than the window survives if it shares a month with the cutoff")
    # The cost of month granularity, demonstrated rather than described. This record is
    # older than the 150-day window and younger than the floor that window resolves to,
    # so the policy says remove it and the mechanism keeps it — for up to a month.
    check("it is inside the window's own month",
          floor <= spared_at < cutoff, True)
    check("and it is still here",
          "spared" in [r["run_id"] for r in store.audit_records(TENANT)], True)

    say("a prune with nothing due removes nothing and records nothing")
    counts = store.prune_log_records(_days_ago(3650))
    check("nothing removed", sum(counts.values()), 0)
    check("still one prune record",
          len(store.admin_audit_records(TENANT, action="retention.prune")), 1)

    say("the log is still writable after all of that")
    store.append_audit(TENANT, audit_record(run_id="after-everything"))
    check("the newest record is there",
          store.audit_records(TENANT)[-1]["run_id"], "after-everything")


def main():
    root = pathlib.Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root / "src"))

    from carnet.storage.postgres import PostgresStorage

    print(__doc__.strip().splitlines()[0])
    print(f"database: {DSN}\n")

    fresh_database(DB)
    say("the upgrade path — 028, then 029, then 030, on one populated database")
    before = the_upgrade(DSN)

    store = PostgresStorage(DSN)
    try:
        run(store, before)
    finally:
        store.close()

    return report()


if __name__ == "__main__":
    sys.exit(main())
