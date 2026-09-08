"""Two migration series, one real Postgres, and a second series that is really installed.

**What this proves that `tests/test_migrations.py` cannot.** The unit tests register a
second series by setting `migrate._series_cache`, which is the one thing an installation
never does. This builds a distribution — a module, a `migrations/` directory and a
`.dist-info` with an `entry_points.txt` — puts it on `PYTHONPATH`, and then runs the real
`carnet --migrate` command as a subprocess against a real database. The public build and
the enterprise build in this script differ by exactly one environment variable, which is
the difference they differ by in a deployment.

Step 082. Run it::

    cd backend && CARNET_E2E_PG=postgresql://postgres:postgres@localhost:5432 \
        .venv/bin/python scripts/e2e_migration_series.py

**Costs nothing.** No model, no connector, no network beyond the database.

The scenes, and the one each exists for:

  0. the covenant — this checkout ships one series and imports nothing to find a second
  1. the public build alone, on a fresh database
  2. the enterprise build arrives, through the CLI, and adds only its own
  3. **the public build against that database** — the case that used to refuse, and did
     so before a single byte of SQL differed between the two trees
  4. a new core migration applied to a database carrying enterprise rows
  5. ahead *within* a series is still ahead
  6. an edited migration in either series is still refused
  7. a database from the future, in the core series, is still refused
  8. what a hand-edited ledger costs, stated rather than discovered
  9. order, on a fresh database: core first, then the second series
 10. four processes migrating at once, with two series to apply
 11. a broken registration refuses, and leaves the database untouched
"""

import os
import pathlib
import shutil
import subprocess
import sys
import textwrap
from urllib.parse import urlsplit, urlunsplit

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from carnet.storage import migrate  # noqa: E402

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"

DB = "e2e_migration_series"
SCRATCH = f"{DB}_scratch"

CHECKS = []


def dsn_for(database: str) -> str:
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok))
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: {actual!r}"
          + ("" if ok else f"  (expected {expected!r})"))
    return ok


def check_that(label, ok):
    return check(label, bool(ok), True)


def say(what):
    print(f"\n=== {what}", flush=True)


def report():
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


def ledger(database=DB):
    """`{version: checksum}`, read with no help from the runner."""
    import psycopg

    with psycopg.connect(dsn_for(database)) as conn:
        rows = conn.execute(
            "SELECT version, checksum FROM schema_migrations ORDER BY applied_at, version"
        ).fetchall()
    return [(row[0], row[1]) for row in rows]


def table_exists(name, database=DB):
    import psycopg

    with psycopg.connect(dsn_for(database)) as conn:
        return conn.execute("SELECT to_regclass(%s) IS NOT NULL", (f"public.{name}",)).fetchone()[0]


# --- the distribution ---------------------------------------------------------------
#
# A real one, in the only sense that matters here: `importlib.metadata` cannot tell it
# from a wheel somebody installed, because what it reads is exactly this. Building it by
# hand rather than by `pip install` keeps the script offline, keeps it fast, and — the
# reason that decides it — lets a scene *break* the distribution on purpose and put it
# back, which an installed package cannot do without a second install.

MODULE = "carnet_series_probe"

EE_001 = b"""-- The enterprise series' first migration.
--
-- It references a core table on purpose: an EE migration may assume every core object
-- that shipped in the same release, and this is the assertion of that rule in SQL. If
-- the runner ever applied the series in the other order, this file would fail here.
CREATE TABLE ee_approvals (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""

EE_002 = b"""ALTER TABLE ee_approvals ADD COLUMN decided_by TEXT;
"""


def build_distribution(
    root: pathlib.Path, *, prefix="ee", name="enterprise", module=MODULE
) -> pathlib.Path:
    """A module, its migrations, and the metadata that makes it discoverable.

    `module` is a parameter because `importlib.metadata` deduplicates distributions by
    normalised *name*: two roots on `sys.path` shipping metadata that calls itself the
    same thing are one distribution, and only the first is seen. A scene that needs two
    vendors registering at once needs two distributions, which is what this says.
    """
    root.mkdir(parents=True, exist_ok=True)
    migrations = root / "probe_migrations"
    migrations.mkdir(exist_ok=True)
    (migrations / f"{prefix}_001_approvals.sql").write_bytes(EE_001)
    (migrations / f"{prefix}_002_decided_by.sql").write_bytes(EE_002)

    (root / f"{module}.py").write_text(textwrap.dedent(f"""
        import pathlib

        from carnet.storage import migrate

        SERIES = migrate.Series(
            name={name!r},
            prefix={prefix!r},
            directory=pathlib.Path(__file__).parent / "probe_migrations",
        )
    """), encoding="utf-8")

    dist = root / f"{module}-0.1.dist-info"
    dist.mkdir(exist_ok=True)
    (dist / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {module.replace('_', '-')}\nVersion: 0.1\n",
        encoding="utf-8",
    )
    (dist / "entry_points.txt").write_text(
        f"[{migrate.ENTRY_POINT_GROUP}]\n{name} = {module}:SERIES\n", encoding="utf-8"
    )
    return migrations


def cli(*args, ee_root=None, database=DB, extra_env=None):
    """`carnet <args>` in a subprocess. `ee_root` is the whole difference between the
    two builds — on the path it is the enterprise build, off it the public one."""
    env = dict(os.environ)
    env["CARNET_DATABASE_URL"] = dsn_for(database)
    src = str(pathlib.Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = f"{ee_root}{os.pathsep}{src}" if ee_root else src
    env.pop("CARNET_TEST_DSN", None)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-m", "carnet.cli", *args],
        env=env, capture_output=True, text=True, timeout=300,
    )


class registered:
    """The enterprise series, in *this* process, discovered the way it would be.

    `sys.path` plus `importlib.invalidate_caches()`, never a hand-set cache: the point
    of this script is that nothing here shortcuts the seam.
    """

    def __init__(self, root):
        self.root = str(root)

    def __enter__(self):
        import importlib

        sys.path.insert(0, self.root)
        importlib.invalidate_caches()
        migrate._reset_series_cache()
        # Deliberately does not resolve the series here. Half the scenes below register
        # a *broken* one, and discovery raising inside `__enter__` would skip the body
        # that was about to assert what it raised.
        return None

    def __exit__(self, *exc):
        import importlib

        while self.root in sys.path:
            sys.path.remove(self.root)
        for loaded in [n for n in sys.modules if n.startswith(MODULE)]:
            sys.modules.pop(loaded, None)
        importlib.invalidate_caches()
        migrate._reset_series_cache()
        return False


def main():
    import psycopg

    scratch_root = pathlib.Path(os.environ.get("TMPDIR", "/tmp")) / "carnet-series-probe"
    shutil.rmtree(scratch_root, ignore_errors=True)
    ee_root = scratch_root / "dist"
    ee_migrations = build_distribution(ee_root)

    core_count = len(migrate.CORE.files())

    # --- 0 ---------------------------------------------------------------------------
    say("the covenant: this checkout ships one series, and names no other")
    migrate._reset_series_cache()
    check("the public checkout registers exactly one series",
          [one.name for one in migrate.series()], ["core"])
    check("and it is the core series, with the empty prefix", migrate.CORE.prefix, "")
    named = subprocess.run(
        [sys.executable, "-c",
         "import sys; from carnet.storage import migrate; migrate.series(); "
         f"print(any(n.startswith('{MODULE}') for n in sys.modules))"],
        capture_output=True, text=True,
        env={**os.environ,
             "PYTHONPATH": str(pathlib.Path(__file__).resolve().parents[1] / "src")},
    )
    check("discovery imports no second series when none is installed",
          named.stdout.strip(), "False")

    # --- 1 ---------------------------------------------------------------------------
    say("the public build alone, on a fresh database")
    fresh_database(DB)
    first = cli("--migrate")
    check("the CLI exits 0", first.returncode, 0)
    check("it applied every core migration and no other",
          [v for v, _ in ledger()], [v for v, _ in migrate.CORE.files()])
    check("...which is all of them", len(ledger()), core_count)
    check("every row carries a checksum",
          all(c and len(c) == 64 for _, c in ledger()), True)
    again = cli("--migrate")
    check("a second run is idempotent and says so", "Already up to date." in again.stdout, True)
    check("...and it says nothing about a series it does not ship",
          "does not ship" in again.stdout, False)

    # --- 2 ---------------------------------------------------------------------------
    say("the enterprise build arrives — one environment variable, through the real CLI")
    ee = cli("--migrate", ee_root=ee_root)
    check("the CLI exits 0", ee.returncode, 0)
    check("it applied exactly the two enterprise migrations",
          "2 migration(s) applied." in ee.stdout, True)
    check("...named in the log", "applied ee_001_approvals" in ee.stdout, True)
    check("the ledger now holds both series", len(ledger()), core_count + 2)
    check("the enterprise rows are the newest two",
          [v for v, _ in ledger()][-2:], ["ee_001_approvals", "ee_002_decided_by"])
    check("the enterprise table exists", table_exists("ee_approvals"), True)
    with psycopg.connect(dsn_for(DB)) as conn:
        column = conn.execute(
            "SELECT count(*) FROM information_schema.columns WHERE table_name = 'ee_approvals'"
            " AND column_name = 'decided_by'"
        ).fetchone()[0]
    check("...and its second migration ran too", column, 1)
    check("no core row moved",
          [v for v, _ in ledger()][:core_count], [v for v, _ in migrate.CORE.files()])
    check("the enterprise build is idempotent too",
          "Already up to date." in cli("--migrate", ee_root=ee_root).stdout, True)

    # --- 3 ---------------------------------------------------------------------------
    say("THE CASE: the public build, against a database the enterprise build migrated")
    public = cli("--migrate")
    check("it does not refuse", public.returncode, 0)
    check("...and finds nothing to do", "Already up to date." in public.stdout, True)
    check("it never says the database is ahead", "ahead of this checkout" in public.stdout
          or "ahead of this checkout" in public.stderr, False)
    check("it names the rows belonging to a series it does not ship",
          "does not ship: ee_001_approvals, ee_002_decided_by" in public.stdout, True)
    check("the enterprise rows are untouched", len(ledger()), core_count + 2)
    check("...and so is the enterprise table", table_exists("ee_approvals"), True)

    # --- 4 ---------------------------------------------------------------------------
    say("a new core migration, applied to a database that carries enterprise rows")
    #
    # The core directory is copied rather than written into: adding a file to the real
    # one would change what every other test in the repository sees. The copies are
    # byte-identical, so the ledger's recorded checksums still verify — which is itself
    # the assertion that `checksum()` follows contents and not paths.
    core_copy = scratch_root / "core"
    core_copy.mkdir(parents=True, exist_ok=True)
    for _version, path in migrate.CORE.files():
        shutil.copyfile(path, core_copy / path.name)
    (core_copy / "053_probe_next.sql").write_bytes(b"CREATE TABLE probe_next (id int);\n")

    real_core = migrate.CORE
    migrate.CORE = migrate.Series(name="core", prefix="", directory=core_copy)
    try:
        migrate._reset_series_cache()
        applied = migrate.apply(dsn_for(DB), verbose=True)
        check("the public build applies its own next migration", applied, ["053_probe_next"])
        check("...and the table is there", table_exists("probe_next"), True)
        check("the enterprise rows are still there", len(ledger()), core_count + 3)
    finally:
        migrate.CORE = real_core
        migrate._reset_series_cache()

    with psycopg.connect(dsn_for(DB), autocommit=True) as conn:
        conn.execute("DROP TABLE probe_next")
        conn.execute("DELETE FROM schema_migrations WHERE version = '053_probe_next'")
    check("...and the scene cleaned up after itself", len(ledger()), core_count + 2)

    # --- 5 ---------------------------------------------------------------------------
    say("ahead within a series this build ships is still ahead")
    held_back = scratch_root / "held-back"
    build_distribution(held_back)
    (held_back / "probe_migrations" / "ee_002_decided_by.sql").unlink()
    with registered(held_back):
        check("the held-back build ships one enterprise migration",
              len(migrate.series()[1].files()), 1)
        try:
            migrate.apply(dsn_for(DB))
            check("it refuses a database holding ee_002", "no refusal", "a refusal")
        except migrate.MigrationError as exc:
            check_that("it refuses a database holding ee_002",
                       "ahead of this checkout" in str(exc))
            check_that("...naming the version it found", "ee_002_decided_by" in str(exc))

    # --- 6 ---------------------------------------------------------------------------
    say("an edited migration is refused in either series")
    edited = scratch_root / "edited"
    build_distribution(edited)
    (edited / "probe_migrations" / "ee_001_approvals.sql").write_bytes(EE_001 + b"-- edited\n")
    with registered(edited):
        try:
            migrate.apply(dsn_for(DB))
            check("an edited enterprise migration is refused", "no refusal", "a refusal")
        except migrate.MigrationError as exc:
            check_that("an edited enterprise migration is refused",
                       "has changed since it was applied" in str(exc))
            check_that("...naming it", "ee_001_approvals" in str(exc))

    with psycopg.connect(dsn_for(DB), autocommit=True) as conn:
        real = conn.execute(
            "SELECT checksum FROM schema_migrations WHERE version = '001_tenants'"
        ).fetchone()[0]
        conn.execute("UPDATE schema_migrations SET checksum = %s WHERE version = '001_tenants'",
                     ("b" * 64,))
    try:
        migrate.apply(dsn_for(DB))
        check("an edited core migration is refused beside enterprise rows",
              "no refusal", "a refusal")
    except migrate.MigrationError as exc:
        check_that("an edited core migration is refused beside enterprise rows",
                   "001_tenants" in str(exc) and "has changed" in str(exc))
    finally:
        with psycopg.connect(dsn_for(DB), autocommit=True) as conn:
            conn.execute("UPDATE schema_migrations SET checksum = %s WHERE version = '001_tenants'",
                         (real,))
    check("the ledger was put back", migrate.apply(dsn_for(DB)), [])

    # --- 7 ---------------------------------------------------------------------------
    say("a database from the future, in a series this build does ship, still refuses")
    with psycopg.connect(dsn_for(DB), autocommit=True) as conn:
        conn.execute("INSERT INTO schema_migrations (version) VALUES ('999_from_a_newer_build')")
    try:
        migrate.apply(dsn_for(DB))
        check("027's refusal survived the scoping", "no refusal", "a refusal")
    except migrate.MigrationError as exc:
        check_that("027's refusal survived the scoping", "999_from_a_newer_build" in str(exc))
    finally:
        with psycopg.connect(dsn_for(DB), autocommit=True) as conn:
            conn.execute("DELETE FROM schema_migrations WHERE version = '999_from_a_newer_build'")

    # --- 8 ---------------------------------------------------------------------------
    say("what a hand-edited ledger costs — the known limit, asserted rather than assumed")
    with psycopg.connect(dsn_for(DB), autocommit=True) as conn:
        conn.execute("INSERT INTO schema_migrations (version) VALUES ('oops_hand_inserted')")
    try:
        check("a row belonging to no series at all is tolerated", migrate.apply(dsn_for(DB)), [])
        noticed = cli("--migrate")
        check("...and named, which is the whole of the signal",
              "oops_hand_inserted" in noticed.stdout, True)
    finally:
        with psycopg.connect(dsn_for(DB), autocommit=True) as conn:
            conn.execute("DELETE FROM schema_migrations WHERE version = 'oops_hand_inserted'")

    # --- 9 ---------------------------------------------------------------------------
    say("order, on a fresh database: core first, then the second series")
    fresh_database(DB)
    both = cli("--migrate", ee_root=ee_root)
    check("one command applies both series", both.returncode, 0)
    check("...all of them", len(ledger()), core_count + 2)
    order = [v for v, _ in ledger()]
    check("core came first, in its own order", order[:core_count],
          [v for v, _ in migrate.CORE.files()])
    check("the enterprise series came after it, in its own order",
          order[core_count:], ["ee_001_approvals", "ee_002_decided_by"])
    check("the foreign key into a core table held", table_exists("ee_approvals"), True)

    # --- 10 --------------------------------------------------------------------------
    say("four processes migrating one fresh database at once, with two series to apply")
    fresh_database(DB)
    running = [
        subprocess.Popen(
            [sys.executable, "-m", "carnet.cli", "--migrate"],
            env={**os.environ,
                 "CARNET_DATABASE_URL": dsn_for(DB),
                 "PYTHONPATH": f"{ee_root}{os.pathsep}"
                               f"{pathlib.Path(__file__).resolve().parents[1] / 'src'}"},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        for _ in range(4)
    ]
    outcomes = [(p.wait(timeout=300), p.communicate()) for p in running]
    check("every process exited 0", sorted(code for code, _ in outcomes), [0, 0, 0, 0])
    check("the database has each migration exactly once", len(ledger()), core_count + 2)
    check("...and no duplicates", len({v for v, _ in ledger()}), core_count + 2)
    winners = sum(1 for _, (out, _err) in outcomes if "migration(s) applied." in out)
    check("exactly one process did the work", winners, 1)

    # --- 11 --------------------------------------------------------------------------
    say("a broken registration refuses, and leaves the database untouched")
    fresh_database(SCRATCH)

    def refuses(label, root, fragment):
        with registered(root):
            try:
                migrate.apply(dsn_for(SCRATCH))
                check(label, "no refusal", "a refusal")
            except migrate.MigrationError as exc:
                check_that(label, fragment in str(exc))
        with psycopg.connect(dsn_for(SCRATCH)) as conn:
            made = conn.execute("SELECT to_regclass('public.schema_migrations')").fetchone()[0]
        check(f"...and {label!r} wrote nothing to the database", made, None)

    broken = scratch_root / "broken-import"
    build_distribution(broken)
    (broken / f"{MODULE}.py").write_text("raise RuntimeError('the wheel is broken')\n")
    refuses("an entry point that will not load is a sentence, not a traceback",
            broken, "could not be loaded")

    misnamed = scratch_root / "misnamed"
    build_distribution(misnamed)
    (misnamed / "probe_migrations" / "ee_7_short.sql").write_bytes(b"SELECT 1;\n")
    refuses("a file named for no series is refused by name", misnamed, "ee_7_short.sql")

    gone = scratch_root / "gone"
    build_distribution(gone)
    shutil.rmtree(gone / "probe_migrations")
    refuses("a directory that is not there is refused", gone, "not a directory")

    collides = scratch_root / "collides"
    build_distribution(collides, prefix="", name="impostor")
    refuses("a series claiming the core prefix is refused", collides, "not a lowercase word")

    stealing = scratch_root / "stealing"
    build_distribution(stealing, prefix="ee", name="core")
    refuses("a series claiming the core name is refused", stealing, "collides")

    say("two distributions claiming one prefix — the collision, arriving through the seam")
    twin = scratch_root / "twin"
    build_distribution(twin, prefix="ee", name="impostor", module=f"{MODULE}_twin")
    sys.path.insert(0, str(twin))
    try:
        refuses("two distributions claiming `ee` cannot both be right",
                ee_root, "collides")
    finally:
        while str(twin) in sys.path:
            sys.path.remove(str(twin))

    say("and the database that refused all five is still migratable")
    check("the scratch database migrates cleanly after every one of them",
          len(migrate.apply(dsn_for(SCRATCH))), core_count)

    say("nothing above left a series registered in this process")
    migrate._reset_series_cache()
    check("the covenant holds at the end as it did at the start",
          [one.name for one in migrate.series()], ["core"])
    check("the real migration directory is untouched",
          len(migrate.CORE.files()), core_count)
    check("...and it is the shipped one", migrate.CORE.directory, migrate.MIGRATIONS_DIR)

    shutil.rmtree(scratch_root, ignore_errors=True)
    assert ee_migrations  # the built distribution is the fixture; named for the reader
    return report()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        import traceback

        traceback.print_exc()
        report()
        sys.exit(1)
