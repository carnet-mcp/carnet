"""The overview against real Postgres, three timezones deep — step 041's verification.

One seed, written identically into the in-memory store and a migrated Postgres through
the public writers, then `overview()` diffed byte for byte — **under three database
default timezones**: UTC, America/New_York, and Asia/Kolkata (the half-hour zone,
because a half-hour error slips past any whole-hour check). Parity alone is not enough
— two stores can be identically wrong — so a set of absolute assertions rides along:
window edges are inclusive to the millisecond, a `+05:30` stamp lands on its UTC day,
the refusal kinds land one each (five since 045b added `door_spend`), no run-side series
survives in either store, and the second tenant's world leaks into nothing.

**Step 084 took a third of the seed with it.** Eight runs and three schedules were written
here for three series `routes_admin` discarded on every page load and that this tree
cannot fill — 078 removed the runtime and nothing writes `runs` or `schedules`. The
parity diff is stronger for it: what it compares is fourteen series both stores can
actually produce, rather than seventeen of which three could only ever agree about being
empty. What is lost is the one place the run writers were exercised against a real server
under three database timezones, which is registered rather than assumed harmless.

Why this is a script and not a test: the failures it exists to catch are properties of
a real server's **session timezone**, which the fake does not have and CI never varies.
The first run of it found five defects, three of them in migration 030 — partitions
created one UTC day short, and whole months stepped over — the class of bug that was
invisible for fourteen migrations because every environment that ever ran this code
defaulted to UTC. Migration 044 is the fix and its repair path runs here on every pass:
030 creates the broken partitions under the non-UTC session, 044 widens and fills them,
and the seed's July 31 row is the proof.

**It builds its own world** — one database, dropped and re-migrated per timezone:

    cd backend && .venv/bin/python scripts/e2e_overview.py

**Costs nothing.** No run is submitted, so no model is called and no connector launched.
"""

import json
import os
import pathlib
import sys
import uuid
from datetime import date, datetime, timedelta, timezone
from urllib.parse import urlsplit, urlunsplit

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

import psycopg  # noqa: E402

from carnet import storage  # noqa: E402
from carnet.storage import BUDGET_REFUSAL_MARKER  # noqa: E402
from carnet.core.principal import Principal  # noqa: E402
from carnet.door import TokenBudget  # noqa: E402
from carnet.storage import memory, migrate, postgres  # noqa: E402

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_overview"


def dsn_for(database: str) -> str:
    """Where Postgres is. `CARNET_E2E_PG` is a base DSN with no database name."""
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit(
        (parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment)
    )


DSN = dsn_for(DB)
ADMIN_DSN = dsn_for("postgres")

T, OTHER = "acmeco", "controlco"
TODAY = date(2026, 8, 27)  # fixed, so the month-boundary rows are deterministic
WINDOW = {"since": TODAY - timedelta(days=29), "until": TODAY}
WINDOW_90 = {"since": TODAY - timedelta(days=89), "until": TODAY}

CHECKS = []


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok))
    print(
        f"  {'ok  ' if ok else 'FAIL'} {label}: {json.dumps(actual, default=str)[:120]}"
        + ("" if ok else f"  (expected {json.dumps(expected, default=str)[:120]})")
    )


def say(what):
    print(f"\n=== {what}", flush=True)


def iso(day: date, hh=9, mm=0, ss=0, ms=0, offset="+00:00") -> str:
    return f"{day.isoformat()}T{hh:02d}:{mm:02d}:{ss:02d}.{ms:03d}{offset}"


def door_row(ts, **overrides):
    row = {
        "v": 7, "ts": ts, "run_id": f"door-{uuid.uuid4().hex[:12]}",
        "principal_kind": "machine", "principal_id": "tok_alice",
        "agent": "triage", "tool": "search_issues", "effect": "read", "args": {},
        "decision": "allow", "reason": "", "outcome": "ok", "credential": "shared",
        "duration_ms": 100, "response_bytes": 500,
        "acting_for": "alice@acme.example", "identity_source": "verified",
    }
    row.update(overrides)
    return row


def seed(s, dsn=None):
    """The same writes into either store; `dsn` set when poking under Postgres."""
    s.create_tenant(T, "Acme")
    s.create_tenant(OTHER, "Control")
    storage.configure(s)

    # Real refusal sentences from the real enforcers, so a reworded refusal breaks
    # this script the way it breaks the contract suite.
    s.create_api_token(
        T, {"id": "tok_alice", "name": "a", "owner_id": "u1", "secret_hash": "x"},
        actor="system:cli",
    )
    gate = TokenBudget(Principal(kind="machine", id="tok_alice", tenant_id=T), ceiling=1)
    assert gate.reserve(tool=None).allowed
    ceiling_reason = gate.reserve(tool=None).reason

    # **The per-run budget's own sentence, and it is a literal since step 084.** Every
    # other refusal here comes out of the real enforcer, so a rewording breaks this script
    # the way it breaks the contract suite. This one has no enforcer left: `Budget` wrote
    # it, and 084 deleted `Budget` because its only caller had no caller. The band it
    # lands in stays, because an upgraded deployment's `audit` holds rows a pre-078 tree
    # wrote — so what is still worth proving is that both stores *file* such a row the
    # same way, which is exactly what a parity script is for. Built from the constant, so
    # the half of the coupling that survives is still coupled.
    budget_reason = f"run write {BUDGET_REFUSAL_MARKER}: 1 write already made"

    a = s.append_audit
    # Window edges: the first and last instant of the 30d window, and one millisecond
    # past either edge.
    a(T, door_row(iso(WINDOW["since"], 0, 0, 0, 0)))
    a(T, door_row(iso(TODAY, 23, 59, 59, 999)))
    a(T, door_row(iso(WINDOW["since"] - timedelta(days=1), 23, 59, 59, 999),
                  tool="outside_before"))
    a(T, door_row(iso(TODAY + timedelta(days=1), 0, 0, 0, 0), tool="outside_after"))

    # A stamp whose local date is not its UTC day: 02:00+05:30 on the 25th is the
    # 24th, 20:30 UTC.
    a(T, door_row(f"{iso(date(2026, 8, 25), 2, 0)[:23]}+05:30", tool="offset_tool"))

    # Month boundary and a deeper month — the July 31 row is the one that hits
    # migration 030's short-partition hole on a non-UTC server.
    a(T, door_row(iso(date(2026, 7, 31), 12, 0), tool="july_tool"))
    a(T, door_row(iso(date(2026, 6, 15), 12, 0), tool="june_tool"))

    # The four refusal kinds, one each, same day.
    day = date(2026, 8, 24)
    a(T, door_row(iso(day), decision="deny", reason=ceiling_reason,
                  identity_source="asserted", duration_ms=None, outcome=""))
    a(T, door_row(iso(day), decision="deny", reason="tool not granted",
                  identity_source="none", duration_ms=None, outcome=""))
    a(T, {**door_row(iso(day)), "run_id": "abc123abc123", "decision": "deny",
          "reason": budget_reason, "duration_ms": None, "outcome": ""})
    s.record_denial(T, {"v": 1, "ts": iso(day), "principal_kind": "user",
                        "principal_id": "u9", "resource_kind": "admin",
                        "resource_id": "administration", "required": "admin",
                        "held": ""})

    # An allowed row that is not the door's (no `door-` prefix): must appear in no door series.
    a(T, {**door_row(iso(day)), "run_id": "def456def456", "tool": "not_door"})

    # Outcome bands and a second caller.
    b = date(2026, 8, 25)
    a(T, door_row(iso(b), effect="write", tool="create_issue", duration_ms=400))
    a(T, door_row(iso(b), outcome="error", duration_ms=800))
    a(T, door_row(iso(b), outcome="oversize", duration_ms=200))
    a(T, door_row(iso(b), principal_id="tok_bob", tool="list_repos", duration_ms=100,
                  identity_source="none", acting_for=None))

    # Admin actions, through the real writers (stamped now; asserted by family).
    s.create_agent(
        T,
        {"name": "alpha", "description": "d", "model": "m", "tools": ["post_message"],
         "scope": {"chat.channel": {"write": ["#eng"]}}},
        "user", "u1",
    )
    s.grant_agent(T, "alpha", "user", "u2", actor="user:u1")

    # **Runs and schedules were seeded here until step 084**, eight runs across every
    # terminal status and three schedules, with their stamps poked underneath — for three
    # `overview` series (`runs`, `run_latency`, `schedules`) that `routes_admin` discarded
    # on every page load and that nothing in this tree can fill. They went with the
    # queries that read them. `enqueue_run`, `start_run`, `finish_run`, `create_schedule`
    # and `advance_schedule` still exist and still have contract tests; what is gone is
    # the one place they were driven against a real server under three database
    # timezones, and that is registered rather than quietly lost.

    # The control tenant: one of everything that must leak into nothing.
    a(OTHER, door_row(iso(day), principal_id="tok_theirs"))
    s.record_denial(OTHER, {"v": 1, "ts": iso(day), "principal_kind": "user",
                            "principal_id": "them", "resource_kind": "admin",
                            "resource_id": "administration", "required": "admin",
                            "held": ""})


def find(series, day):
    return next((r for r in series if r["day"] == day), None)


def run_pass(tz: str) -> None:
    say(f"database timezone {tz}")
    with psycopg.connect(ADMIN_DSN, autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB} (FORCE)")
        conn.execute(f"CREATE DATABASE {DB}")
        conn.execute(f"ALTER DATABASE {DB} SET timezone TO '{tz}'")
    migrate.apply(DSN)

    pg = postgres.PostgresStorage(DSN)
    # The June row is a back-dated write, which the horizon never covers — the refusal
    # message names this exact call.
    pg.ensure_log_partitions(back_to=datetime(2026, 6, 1, tzinfo=timezone.utc))
    seed(pg, dsn=DSN)
    pg_30 = pg.overview(T, **WINDOW)
    pg_90 = pg.overview(T, **WINDOW_90)
    pg_other = pg.overview(OTHER, **WINDOW)
    # 066a's cheap read, captured before the handle closes. It lost its ninth key with
    # `overview`'s run series — `_previous_window` read it and threw it away.
    pg_totals = pg.overview_totals(T, **WINDOW)
    pg.close()

    mem = memory.InMemoryStorage()
    seed(mem)
    mem_30 = mem.overview(T, **WINDOW)
    mem_90 = mem.overview(T, **WINDOW_90)
    mem_other = mem.overview(OTHER, **WINDOW)
    mem_totals = mem.overview_totals(T, **WINDOW)

    for label, m, p in (("30d", mem_30, pg_30), ("90d", mem_90, pg_90),
                        ("other", mem_other, pg_other)):
        for key in m:
            check(f"[{tz}] parity {label}/{key}", p[key], m[key])

    # Absolute, so parity cannot be identically wrong.
    o = mem_30
    tools = {t["tool"] for t in o["door_tools"]}
    check(f"[{tz}] first instant of the window counts",
          find(o["door_calls"], WINDOW["since"].isoformat())["allowed"], 1)
    check(f"[{tz}] last instant of the window counts",
          find(o["door_calls"], TODAY.isoformat())["allowed"], 1)
    check(f"[{tz}] nothing outside the window",
          sorted(tools & {"outside_before", "outside_after", "june_tool"}), [])
    check(f"[{tz}] audit rows without the door's prefix stay out of door series",
          "not_door" in tools, False)
    check(f"[{tz}] +05:30 lands on its UTC day", "offset_tool" in tools, True)
    # `door_spend` is 045b's fifth band and it is **0 here on purpose**: this seed
    # predates the money ceiling and writes no spend refusal, so the band's presence is
    # what is being asserted, not its count. A band missing from this dict entirely is
    # a band the Overview would render as a gap rather than a zero.
    check(f"[{tz}] the refusal kinds land one each",
          find(o["refusals"], "2026-08-24"),
          {"day": "2026-08-24", "policy": 1, "ceiling": 1, "door_spend": 0,
           "run_budget": 1, "access": 1})
    # The run-side series are **absent**, not empty, and the difference is the claim: a
    # key returning `[]` reads as "no runs in this window" on a deployment that has no
    # runtime at all. Asserted on both stores, so neither can quietly keep one.
    check(f"[{tz}] no run series survives in the fake",
          sorted(k for k in o if k in ("runs", "run_latency", "schedules", "run_tools")),
          [])
    check(f"[{tz}] nor in Postgres",
          sorted(k for k in pg_30
                 if k in ("runs", "run_latency", "schedules", "run_tools")),
          [])
    check(f"[{tz}] and `overview_totals` dropped its run count in both",
          ("runs" in pg_totals, "runs" in mem_totals), (False, False))
    check(f"[{tz}] the cheap read still agrees with the expensive one",
          (pg_totals, mem_totals), (mem_totals, mem_totals))
    check(f"[{tz}] july 31 survives the partition boundary",
          find(mem_90["door_calls"], "2026-07-31")["allowed"],
          find(pg_90["door_calls"], "2026-07-31")["allowed"])
    check(f"[{tz}] the control tenant leaks into nothing",
          [c["principal_id"] for c in o["callers"] if c["principal_id"] == "tok_theirs"],
          [])


for tz in ("UTC", "America/New_York", "Asia/Kolkata"):
    run_pass(tz)

with psycopg.connect(ADMIN_DSN, autocommit=True) as conn:
    conn.execute(f"DROP DATABASE IF EXISTS {DB} (FORCE)")

failed = [label for label, ok in CHECKS if not ok]
say(f"{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
if failed:
    for label in failed:
        print(f"  FAIL {label}")
    sys.exit(1)
