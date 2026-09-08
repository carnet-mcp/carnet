"""Every released migration, forward, over a populated database — and timed.

**This is the job that turns "it applies" into "it preserves".** Four e2e scripts
already do a one-step version of this by hand (021 → 032, 022 → 033, 023 → 034,
025 → 035) and each stops at the migration it was written for. None of them runs in CI.
This is that pattern made systematic and made continuous: the oldest supported schema,
populated in the shapes of its own era, walked all the way to head, then handed to the
contract suite.

**The fixture is cumulative code, not a dump.** `STAGES` is a list of
`(stop_version, populate)` pairs: apply migrations up to `stop`, insert rows the way the
code of that era wrote them, continue. A release that ships migrations appends one
stage. The alternative — a `pg_dump` per release — was declined: a dump is data CI
cannot review, "which release produced this one" becomes archaeology, and the thing
most likely to rot is the fixture rather than the migration.

**Three things it asserts that a fresh-schema test cannot:**

  - *rows survive*. Every sentinel row is snapshotted as a full tuple before the
    upgrade and compared afterwards, ids included. A migration that renumbers or
    silently drops rows passes every functional test ever written.
  - *the preflights refuse*. Scene 0 points the runner at a database holding somebody
    else's table, which is the one guard the contract suite cannot exercise because its
    database always has a ledger.
  - *lock time is a number*. Each migration is applied on its own and timed, over
    tables with real weight in them. `017_groups.sql`, `020_tenant_status.sql` and
    `postgres.py` all carry written claims about locks that nothing measures; 035
    re-keys five tables, and on a large one that is minutes of downtime rather than an
    error. The ceiling here is deliberately generous — this measures, and only fails on
    something pathological.

**It builds its own world**, so it needs nobody at a keyboard:

    cd backend && CARNET_E2E_PG=postgresql://postgres:postgres@localhost:5432 \
        .venv/bin/python scripts/e2e_upgrade.py

**Costs nothing.** No run is submitted, so no model is called and no connector launched.
"""

import datetime as dt
import json
import os
import pathlib
import sys
import time
from urllib.parse import urlsplit, urlunsplit

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"

# The name the CI job's pytest step points `CARNET_TEST_DSN` at. Fixed rather
# than generated: the workflow has to name it too, and two places deriving one string
# is how they stop agreeing.
DB = "e2e_upgrade"
SHARED = "e2e_upgrade_shared_probe"

TENANT = "acme-upgrade"
CONTROL = "control-upgrade"
OWNER = "u-priya"
AGENT = "triage"

# How many rows go in before the migrations that rewrite whole tables. Sized so the
# conversion in 030 and the five-table re-key in 035 do real work inside a CI job's
# patience rather than a token amount — an empty table is exactly the case where a lock
# claim cannot be wrong.
VOLUME = {"audit": 200_000, "runs": 20_000, "grants": 5_000, "versions": 5_000}

# No single migration may take longer than this. Generous on purpose: the number that
# matters is the one printed next to each version, and a tight assertion here would
# make a slow CI runner look like a defect in a migration.
CEILING_SECONDS = 60.0


def dsn_for(database: str) -> str:
    """Where Postgres is. `CARNET_E2E_PG` is a base DSN with no database name."""
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


CHECKS = []


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok))
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: {actual!r}"
          + ("" if ok else f"  (expected {expected!r})"))


def say(what):
    print(f"\n=== {what}", flush=True)


def report():
    """The summary, callable from anywhere — including a migration that could not run."""
    passed = sum(1 for _label, ok in CHECKS if ok)
    failed = [label for label, ok in CHECKS if not ok]
    print(f"\n=== {passed}/{len(CHECKS)} checks passed")
    for label in failed:
        print(f"  FAILED: {label}")
    return 1 if failed else 0


def fresh_database(name):
    import psycopg

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        conn.execute(f"CREATE DATABASE {name}")


# --- the eras --------------------------------------------------------------------
#
# Each `populate` runs against a database migrated to just before its stop version, and
# writes rows the way the code of that era wrote them — old column names, old keys, no
# columns that do not exist yet. That is the whole point: a backfill can only be tested
# against rows that predate it.


def before_029(conn, now):
    """The log tables while they are still ordinary tables, plus the bulk of the data.

    `audit` is loaded here because migration 030 converts it to monthly partitions by
    copying every row, which is the single heaviest thing any migration in this repo
    does. The sentinels carry the two shapes that have caught real defects: a gap in
    the identity sequence, and a row stamped two years ahead.
    """
    conn.execute("INSERT INTO tenants (id, name) VALUES (%s, 'Acme')", (TENANT,))
    conn.execute("INSERT INTO tenants (id, name) VALUES (%s, 'Control')", (CONTROL,))

    for n, days in enumerate([0, 40, 75, 200]):
        for tenant in (TENANT, CONTROL):
            conn.execute(
                "INSERT INTO audit (tenant_id, v, ts, run_id, principal_kind,"
                " principal_id, agent, tool, args, decision) VALUES"
                " (%s, 6, %s, %s, 'user', 'u-1', 'bot', 't', '{}', 'allow')",
                (tenant, now - dt.timedelta(days=days), f"r{n}"),
            )
        # A gap in the ids, because a real log has them — retention removes rows and the
        # sequence never goes back. Without one the ids are 1..8, and a copy that
        # renumbered every row would produce 1..8 too, so "the ids survived" would pass
        # by coincidence. Found by mutation, in 019's script.
        conn.execute(
            "SELECT setval(pg_get_serial_sequence('audit', 'id'), %s)", (100 * (n + 1),)
        )

    # Two years in the future: a skewed clock on one writer, or a backup restored from a
    # machine that had one. `append_audit` takes its timestamp from the caller, so
    # nothing in the product prevents it — and it is what broke the first 030.
    conn.execute(
        "INSERT INTO audit (tenant_id, v, ts, run_id, principal_kind, principal_id,"
        " agent, tool, args, decision) VALUES"
        " (%s, 6, %s, 'from-the-future', 'user', 'u-1', 'bot', 't', '{}', 'allow')",
        (TENANT, now + dt.timedelta(days=730)),
    )
    conn.execute(
        "INSERT INTO admin_audit (tenant_id, v, ts, actor_kind, actor_id, action,"
        " target_kind, target_id) VALUES"
        " (%s, 1, %s, 'user', 'u-1', 'agent.save', 'agent', 'bot')", (TENANT, now))
    conn.execute(
        "INSERT INTO access_denials (tenant_id, v, ts, principal_kind, principal_id,"
        " resource_kind, resource_id, required) VALUES"
        " (%s, 1, %s, 'user', 'u-2', 'agent', 'bot', 'user')", (TENANT, now))

    # The weight. Spread over a year so 030 builds a realistic number of partitions
    # rather than one enormous month.
    conn.execute(
        "INSERT INTO audit (tenant_id, v, ts, run_id, principal_kind, principal_id,"
        " agent, tool, args, decision)"
        " SELECT %s, 6, %s - (n %% 365) * interval '1 day', 'bulk-' || n,"
        " 'user', 'u-1', 'bot', 't', '{}', 'allow'"
        " FROM generate_series(1, %s) AS n",
        (TENANT, now, VOLUME["audit"]),
    )


def before_032(conn, now):
    """Agents with no version history, which is what migration 032 backfills from.

    `created_at` and `updated_at` are set a week apart deliberately: with them equal,
    "the backfill used `updated_at`" and "the backfill used `created_at`" are the same
    assertion and neither is tested. 021's script found that.
    """
    for name in (AGENT, "billing"):
        conn.execute(
            "INSERT INTO agents (tenant_id, name, config, created_at, updated_at)"
            " VALUES (%s, %s, %s, %s, %s)",
            (TENANT, name, json.dumps({"name": name, "system": "s"}),
             now - dt.timedelta(days=7), now),
        )


def before_035(conn, now):
    """The name-keyed world, and the volume the five-table re-key has to carry.

    Everything here is written on `agent_name`, because `agent_id` does not exist yet
    and this is the only order a deployment ever sees.
    """
    for name in (AGENT, "billing"):
        conn.execute(
            "INSERT INTO agent_grants (tenant_id, agent_name, grantee_kind, grantee_id,"
            " role) VALUES (%s, %s, 'system', 'cli', 'owner')", (TENANT, name))
        conn.execute(
            "INSERT INTO pending_grants (tenant_id, agent_name, email, role)"
            " VALUES (%s, %s, 'later@acme.com', 'editor')", (TENANT, name))
        conn.execute(
            "INSERT INTO runs (run_id, tenant_id, agent, principal_kind, principal_id,"
            " task, status, root_run_id) VALUES (%s, %s, %s, 'user', %s, 't',"
            " 'complete', %s)",
            (f"r_{name}"[:12], TENANT, name, OWNER, f"r_{name}"[:12]),
        )

    # A run whose agent is already gone. It must stay `agent_id IS NULL` afterwards —
    # there is nothing to backfill it from, and nothing may invent one. 025's testing
    # pass found an access defect living in exactly these rows.
    conn.execute(
        "INSERT INTO runs (run_id, tenant_id, agent, principal_kind, principal_id, task,"
        " status, root_run_id) VALUES ('r_ghost', %s, 'deleted-agent', 'user', %s, 't',"
        " 'complete', 'r_ghost')", (TENANT, OWNER))

    conn.execute(
        "INSERT INTO api_tokens (id, tenant_id, name, owner_id, secret_hash, created_by)"
        " VALUES ('m_pre035', %s, 'nightly', %s, 'sha256$x', 'system:cli')",
        (TENANT, OWNER))
    conn.execute(
        "INSERT INTO schedules (id, tenant_id, agent_name, token_id, task, cadence,"
        " timezone, next_fire_at, created_by) VALUES ('sch_pre035', %s, %s, 'm_pre035',"
        " 't', '{\"every\":\"day\",\"at\":\"07:30\"}', 'UTC', now(), 'system:cli')",
        (TENANT, AGENT))
    conn.execute(
        "INSERT INTO triggers (id, tenant_id, agent_name, token_id, name, task,"
        " secret_sealed, secret_key_id, created_by) VALUES ('trg_pre035', %s, %s,"
        " 'm_pre035', 'jira', 't', %s, 'k1', 'system:cli')",
        (TENANT, AGENT, b"\x01blob"))

    # Weight on the tables 035 rebuilds. `agent_versions` and `agent_grants` are the two
    # it re-keys with a full copy, and `runs` is the one it adds a column and a partial
    # index to.
    conn.execute(
        "INSERT INTO agent_versions (tenant_id, agent_name, version, config, created_at,"
        " created_by, source)"
        " SELECT %s, %s, n, %s, %s, 'system:cli', 'save'"
        " FROM generate_series(2, %s) AS n",
        (TENANT, AGENT, json.dumps({"name": AGENT, "system": "s"}), now,
         VOLUME["versions"] + 1),
    )
    conn.execute(
        "INSERT INTO agent_grants (tenant_id, agent_name, grantee_kind, grantee_id, role)"
        " SELECT %s, %s, 'user', 'u-bulk-' || n, 'user'"
        " FROM generate_series(1, %s) AS n",
        (TENANT, AGENT, VOLUME["grants"]),
    )
    conn.execute(
        "INSERT INTO runs (run_id, tenant_id, agent, principal_kind, principal_id, task,"
        " status, root_run_id)"
        " SELECT 'rb_' || n, %s, %s, 'user', %s, 't', 'complete', 'rb_' || n"
        " FROM generate_series(1, %s) AS n",
        (TENANT, AGENT, OWNER, VOLUME["runs"]),
    )



def before_036(conn, now):
    """Runs from before files existed. Step 028.

    036 adds a table *and* a column — `files`, plus `runs.file_id` — so there are two
    things to get wrong and this stage exists to catch both. The runs below are the shape
    every deployment has on the morning 036 applies: rows written when no column held a
    file id. Afterwards they must still be exactly themselves, `files` must be empty, and
    every one of them must carry `file_id = ''`.

    The failure this guards against is a back-fill. An `INSERT ... SELECT` inventing a
    file row per historical run, or a DEFAULT that landed as NULL instead of '', would
    look harmless and pass a count — and then hand a model a zero-byte document, or make
    `row["file_id"]` a `None` that every caller here expects to be a string.
    """
    for n in range(3):
        run_id = f"r_pre036_{n}"[:12]
        conn.execute(
            "INSERT INTO runs (run_id, tenant_id, agent, principal_kind, principal_id,"
            " task, status, answer, root_run_id) VALUES (%s, %s, %s, 'user', %s,"
            " 'summarize the attached report', 'complete', 'there was no attachment',"
            " %s)",
            (run_id, TENANT, AGENT, OWNER, run_id),
        )


def before_051(conn, now):
    """A consent flow configured when no column held a sentence. Step 068.

    051 adds `connector_oauth.scope_notes`, and what this stage exists to prove is that
    **nothing is back-filled**. The temptation on a column like this is to invent a
    default description per scope so no screen looks empty — and that would be the
    platform describing somebody else's permission from a guess, on the screen where a
    person decides whether to grant it. `'{}'` is the truth about every row that predates
    the column: nobody wrote a sentence, because there was nowhere to put one.

    The connector row comes first: migration 024's foreign key means an OAuth application
    cannot exist without one.
    """
    conn.execute(
        "INSERT INTO connectors (tenant_id, id, description, launch)"
        " VALUES (%s, 'jira-pre051', 'configured before 051', %s)"
        " ON CONFLICT DO NOTHING",
        (TENANT, '{"kind": "http", "url": "https://mcp.acme.com/mcp"}'),
    )
    conn.execute(
        "INSERT INTO connector_oauth (tenant_id, connector_id, authorize_endpoint,"
        " token_endpoint, client_id, client_secret, key_id, scopes, configured_by)"
        " VALUES (%s, 'jira-pre051', 'https://auth.acme.com/authorize',"
        " 'https://auth.acme.com/token', 'client-pre051', %s, 'k1', %s, %s)",
        (TENANT, b"sealed", '["read:jira-work", "offline_access"]', OWNER),
    )


def before_053(conn, now):
    """A machine minted at the terminal before the door spoke OAuth. Step 083.

    053 adds two tables and touches nothing that exists, and what this stage exists to
    prove is exactly that: a token minted the old way — `--mint-token`, a hash, an owner
    — comes through byte-identical, and both new tables are **empty** afterwards. The
    temptation on a migration like this is to back-fill a client row for every existing
    token so the tokens page can say *connected via*; that would be the platform
    inventing a registration nobody made, for a client that never existed.
    """
    conn.execute(
        "INSERT INTO api_tokens (id, tenant_id, name, owner_id, secret_hash, created_by)"
        " VALUES ('m_pre053', %s, 'pre-053 laptop', %s, %s, 'system:cli')"
        " ON CONFLICT DO NOTHING",
        (TENANT, OWNER, "sha256$" + "a" * 64),
    )


STAGES = [
    ("029", before_029),
    ("032", before_032),
    ("035", before_035),
    ("036", before_036),
    ("051", before_051),
    ("053", before_053),
]

# What must come through the upgrade byte-identical. Each is `(label, query)` and the
# comparison is the full tuple — a count would pass a migration that renumbered every
# row, which is the mutation the id gaps above exist to catch.
SURVIVORS = [
    ("audit sentinels", "SELECT id, tenant_id, ts, run_id FROM audit"
                        " WHERE run_id NOT LIKE 'bulk-%' ORDER BY id"),
    ("admin_audit", "SELECT id, tenant_id, ts, action, target_id FROM admin_audit ORDER BY id"),
    # Step 028. The runs 036 walked past, unchanged — and the new table still empty,
    # because a migration that back-filled an empty attachment onto historical runs
    # would pass every count and hand a model a zero-byte document later.
    ("pre-036 runs", "SELECT run_id, task, answer, status FROM runs"
                     " WHERE run_id LIKE 'r_pre036%' ORDER BY run_id"),
    ("access_denials", "SELECT id, tenant_id, ts, resource_id, required FROM access_denials"
                       " ORDER BY id"),
    ("agents", "SELECT tenant_id, name, config, created_at, updated_at FROM agents"
               " ORDER BY name"),
    # Step 068. The consent flow 051 walked past, unchanged — endpoints, client id and
    # scopes all exactly as they were.
    ("pre-051 consent flows",
     "SELECT tenant_id, connector_id, authorize_endpoint, token_endpoint, client_id,"
     " scopes FROM connector_oauth ORDER BY connector_id"),
    # Step 083. The token 053 walked past, unchanged — id, owner and hash exactly as
    # they were, because the migration adds tables beside `api_tokens` and no column
    # to it.
    ("pre-053 tokens",
     "SELECT id, tenant_id, name, owner_id, acts_as_owner, secret_hash, revoked_at"
     " FROM api_tokens WHERE id = 'm_pre053'"),
]

COUNTS = [
    ("audit", "SELECT count(*) FROM audit"),
    ("runs", "SELECT count(*) FROM runs"),
    ("agent_grants", "SELECT count(*) FROM agent_grants"),
    ("agent_versions", "SELECT count(*) FROM agent_versions"),
    ("pending_grants", "SELECT count(*) FROM pending_grants"),
    ("schedules", "SELECT count(*) FROM schedules"),
    ("triggers", "SELECT count(*) FROM triggers"),
]


def upto(real_available, stop):
    """`available()` filtered to everything below `stop`. 019's idiom.

    Monkeypatching the runner rather than reimplementing it: the four scripts that
    hand-replay migrations each grew their own copy of the apply loop, and a copy of a
    loop is a place for the two to disagree about transactions.
    """
    return lambda: [(s, p) for s, p in real_available() if s < stop]


def the_guards_refuse(psycopg, migrate):
    """Scene 0: the preflights, against the case the contract suite cannot build.

    A database with a ledger is one we have migrated, so the dedicated-database guard is
    unreachable from a suite whose database always has one. Here it is the first thing
    that happens, on its own database, and the refusal must leave that database exactly
    as it found it.
    """
    say("a database holding somebody else's tables is refused, and left alone")
    fresh_database(SHARED)
    with psycopg.connect(dsn_for(SHARED), autocommit=True) as conn:
        conn.execute("CREATE TABLE somebody_elses_table (id int)")

    try:
        migrate.apply(dsn_for(SHARED))
        check("a shared database is refused", "applied", "MigrationError")
    except migrate.MigrationError as exc:
        check("a shared database is refused", "dedicated database" in str(exc), True)

    with psycopg.connect(dsn_for(SHARED), autocommit=True) as conn:
        ledger = conn.execute("SELECT to_regclass('public.schema_migrations')").fetchone()[0]
    check("and the refusal wrote nothing into it", ledger, None)

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {SHARED} WITH (FORCE)")


def apply_one(migrate, version):
    """Apply exactly `version`, and return how long it took.

    One at a time, for the whole walk and not just the tail: the number an operator
    plans a maintenance window around belongs to a single migration. "The upgrade took
    forty seconds" does not say which statement to worry about, and the two migrations
    that rewrite whole tables — 030's partition conversion and 035's five-table re-key
    — are the entire question.
    """
    real_available = migrate.available
    migrate.available = lambda: [(s, p) for s, p in real_available() if s <= version]
    try:
        started = time.monotonic()
        applied = migrate.apply(dsn_for(DB))
        return applied, time.monotonic() - started
    finally:
        migrate.available = real_available


def walk_every_migration(psycopg, migrate):
    """001 to head, one at a time, populating each era before the migration that reads it.

    The stages interleave with the walk rather than preceding it, so the rows are always
    written by the era that owned those columns and every migration is timed against
    whatever was already in the tables when it ran.
    """
    now = dt.datetime.now(dt.timezone.utc)
    stages = dict(STAGES)
    timings = []
    snapshots, counts = {}, {}

    say("001 to head, one migration at a time, over rows that were already there")
    for version, _path in migrate.available():
        stop = version.split("_")[0]
        if stop in stages:
            started = time.monotonic()
            with psycopg.connect(dsn_for(DB), autocommit=True) as conn:
                stages[stop](conn, now)
            print(f"  ... populated the pre-{stop} world in {time.monotonic() - started:.1f}s")

            # Snapshotted at the **last** stage only, and that is deliberate: earlier
            # eras do not have the later tables to read, and by this point every row in
            # every table predates every migration still to run — which is exactly the
            # population the survival assertions are about.
            # **Named, not positional.** This used to read `STAGES[-1][0]`, which was
            # right only while 035 happened to be the last stage — step 028 appended one
            # after it and silently moved this assertion to the far side of the migration
            # it is about. A precondition for 035 belongs at 035.
            if stop == "035":
                with psycopg.connect(dsn_for(DB), autocommit=True) as conn:
                    check("there is no agent_id column yet",
                          column_exists(conn, "agents", "agent_id"), False)

            # Snapshotted at the **last** stage only, and that is deliberate: earlier
            # eras do not have the later tables to read, and by this point every row in
            # every table predates every migration still to run.
            if stop == STAGES[-1][0]:
                with psycopg.connect(dsn_for(DB), autocommit=True) as conn:
                    for label, query in SURVIVORS:
                        snapshots[label] = conn.execute(query).fetchall()
                    for label, query in COUNTS:
                        counts[label] = conn.execute(query).fetchone()[0]

        try:
            applied, elapsed = apply_one(migrate, version)
        except Exception as exc:  # noqa: BLE001 - the whole point is to report it
            check(f"{version} applies to a populated database ({exc})", "raised", "applied")
            raise SystemExit(report()) from None

        check(f"{version} applied, and only it", applied, [version])
        timings.append((version, elapsed))
        print(f"  ... {version}: {elapsed:.2f}s", flush=True)

    # Step 083: 053's two tables exist and hold nothing — no registration was invented
    # for the token that predates them.
    with psycopg.connect(dsn_for(DB), autocommit=True) as conn:
        check("053 left oauth_clients empty (no registration back-filled)",
              conn.execute("SELECT count(*) FROM oauth_clients").fetchone()[0], 0)
        check("and oauth_codes empty",
              conn.execute("SELECT count(*) FROM oauth_codes").fetchone()[0], 0)

    check("the audit sentinels had a gap in their ids, so renumbering would show",
          snapshots["audit sentinels"][-1][0] - snapshots["audit sentinels"][0][0] > 8, True)
    for label, total in counts.items():
        print(f"  ... carried {label}: {total} rows")

    return snapshots, counts, timings


def the_timings(timings):
    """The lock-time half. Nothing in the repo measured this before 027."""
    ranked = sorted(timings, key=lambda pair: pair[1], reverse=True)
    say("the five slowest migrations, over populated tables")
    for version, elapsed in ranked[:5]:
        print(f"  {elapsed:7.2f}s  {version}")

    slowest, worst = ranked[0]
    check(f"no single migration exceeded {CEILING_SECONDS:.0f}s ({slowest} at"
          f" {worst:.2f}s)", worst < CEILING_SECONDS, True)


def column_exists(conn, table, column):
    row = conn.execute(
        "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public'"
        " AND table_name = %s AND column_name = %s", (table, column)).fetchone()
    return row[0] > 0


def table_exists(conn, table):
    row = conn.execute(
        "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'"
        " AND table_name = %s", (table,)).fetchone()
    return row[0] > 0


def everything_survived(psycopg, snapshots, counts):
    """The half a fresh-schema test cannot assert: the rows are the same rows."""
    say("every row that went in came out, with its id and its order")
    with psycopg.connect(dsn_for(DB), autocommit=True) as conn:
        for label, query in SURVIVORS:
            check(f"{label} survived the upgrade unchanged",
                  conn.execute(query).fetchall(), snapshots[label])
        for label, query in COUNTS:
            check(f"{label} kept every row", conn.execute(query).fetchone()[0], counts[label])

        say("and 036 back-filled nothing, which is what a new table owes")
        check("files exists", table_exists(conn, "files"), True)
        check("and is empty",
              conn.execute("SELECT count(*) FROM files").fetchone()[0], 0)
        check("runs grew a file_id column", column_exists(conn, "runs", "file_id"), True)
        # '' and not NULL, on every row that predates the column. A NULL here is a
        # `None` where every caller in `runs.py` expects a string, and it would surface
        # as an AttributeError on the first replay of an old thread rather than here.
        check("and every historical run carries '' rather than NULL",
              conn.execute(
                  "SELECT count(*) FROM runs WHERE file_id IS DISTINCT FROM ''"
              ).fetchone()[0], 0)

        say("and 051 described nobody's scopes on their behalf")
        check("connector_oauth grew scope_notes",
              column_exists(conn, "connector_oauth", "scope_notes"), True)
        # `'{}'` on every row that predates the column, and never NULL: a NULL would be a
        # `None` where every reader expects a mapping, surfacing on the Connections page
        # rather than here. And never a *guessed* sentence — a back-fill here would put
        # words in front of somebody at the moment they consent that nobody wrote.
        check("and every historical consent flow carries an empty object",
              conn.execute(
                  "SELECT count(*) FROM connector_oauth"
                  " WHERE scope_notes IS DISTINCT FROM '{}'::jsonb"
              ).fetchone()[0], 0)

        say("and the backfills the upgrade owed did happen")
        check("agents grew their ids", column_exists(conn, "agents", "agent_id"), True)
        ids = conn.execute("SELECT count(DISTINCT agent_id) FROM agents").fetchone()[0]
        check("one id per agent, and they differ", ids, 2)

        for table in ("agent_grants", "pending_grants", "agent_versions", "schedules",
                      "triggers"):
            check(f"{table} was re-keyed onto the id",
                  column_exists(conn, table, "agent_id"), True)
            check(f"and {table} no longer carries an agent_name column",
                  column_exists(conn, table, "agent_name"), False)
            orphans = conn.execute(
                f"SELECT count(*) FROM {table} WHERE agent_id IS NULL").fetchone()[0]
            check(f"and every {table} row resolved to one", orphans, 0)

        named = conn.execute(
            "SELECT count(*) FROM runs r JOIN agents a ON a.agent_id = r.agent_id"
            " WHERE r.run_id = 'r_triage'").fetchone()[0]
        check("the run whose agent still exists got its id", named, 1)
        ghost = conn.execute(
            "SELECT agent_id FROM runs WHERE run_id = 'r_ghost'").fetchone()[0]
        check("and the run whose agent was gone stayed NULL", ghost, None)


def main():
    try:
        import psycopg
    except ImportError:
        print("psycopg is not installed. pip install -e '.[postgres]'")
        return 1

    from carnet.storage import migrate

    print(__doc__.strip().splitlines()[0])
    print(f"    database: {DB}   volume: {VOLUME}")

    the_guards_refuse(psycopg, migrate)

    fresh_database(DB)
    snapshots, counts, timings = walk_every_migration(psycopg, migrate)
    check("the database is at head", migrate.apply(dsn_for(DB)), [])
    everything_survived(psycopg, snapshots, counts)
    the_timings(timings)

    say("the contract suite runs against this database next, in CI")
    return report()


if __name__ == "__main__":
    sys.exit(main())
