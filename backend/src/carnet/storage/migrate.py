"""Numbered SQL files, applied in order, each in its own transaction.

Not Alembic. Alembic's real value is autogenerating a diff from declarative models,
which requires an ORM we deliberately do not have — without that it is a migration
runner with considerably more machinery than the hundred lines below. Plain SQL files
also mean a reviewer reads the exact DDL that will run, rather than a Python
description of it.

Forward-only. There is no `down`, which is right at this stage and will not stay
right; when it stops being right, the fix is a paired `NNN_name.down.sql`, not a
different tool.

Each file runs inside a transaction, so a migration that fails partway leaves nothing
behind. Postgres does DDL transactionally, which is most of why this is short.

**The promise, as of 027, and it is enforced here rather than written in a document.**
The day somebody else's Postgres holds these tables, the numbering stops being an
internal convenience and becomes a contract:

  - *Forward-only, and never renumbered.* A version is a name, not a position, and the
    ledger is keyed by it. `tests/test_migrations.py` asserts the numbering is
    contiguous, unique and zero-padded — padding is what makes lexicographic order and
    numeric order the same thing, which `available()` depends on.
  - *Never edited once released.* Each applied file's sha256 is recorded, and a changed
    file is refused by name at the next run. An edit to a released migration silently
    produces two different schemas from one version number, and nothing downstream can
    detect it afterwards.
  - *Upgrade from any released version in one command.* `carnet --migrate`, as
    many versions behind as you like; `scripts/e2e_upgrade.py` is CI's proof, over
    populated tables rather than empty ones.
  - *Each migration atomic.* A failure leaves the database cleanly at a known version,
    which is what makes the runbook's answer "fix the row it named and run it again"
    rather than "restore".

Four preflights run before any file does, and each refuses with one sentence naming
what to do about it — see `apply`.

**Series, as of 082.** More than one distribution may add migrations to one database:
this package ships the *core* series, `NNN_name.sql`, and a separately installed one may
ship its own under a prefix of its own, `ee_NNN_name.sql`. They share one ledger,
because the ledger is the operator's answer to *what has been applied to this database*
and two answers to that is worse than one. The series is not a column — it is read out of
the version key, which every row has already recorded, so nothing needs backfilling.

Two rules follow, and they are the whole of it:

  - *The core series has one author.* This package. A distribution that adds migrations
    adds them under its own prefix and never a `NNN_`, because two authors numbering into
    one series is a collision no naming scheme can survive.
  - *Ahead means ahead within a series this build ships.* A ledger row belonging to a
    series nothing here registered is a row this build has no opinion about — not a
    database from the future. `_check_ledger_is_on_disk` is where that is decided.

A further series registers through the `carnet.migration_series` entry point group and
is discovered because it is installed. **Nothing in this package names one**, which is
the same covenant `test_the_server_never_imports_the_local_idp` makes about the local
identity provider, asserted the same way.
"""

import hashlib
import pathlib
import re
import time
from typing import NamedTuple, Optional

MIGRATIONS_DIR = pathlib.Path(__file__).parent / "migrations"

# Where a second series announces itself. A distribution installed into the same
# environment declares one line pointing at a `Series` (or a callable returning one) and
# is found here; this package declares none and names none.
#
# **This grants no privilege that installation did not already grant.** Anything in the
# virtualenv can `import carnet` and rebind `available` outright, so the question an
# entry point raises is not whether foreign SQL can run but whether it is *named* — and
# a series that registers is named, validated and reported, where a monkeypatch is none
# of those. The alternatives were a directory in an environment variable, which turns
# "what DDL runs against my database" into a deployment string an operator can typo, and
# a hard-coded import, which puts the other tree's name in this one.
ENTRY_POINT_GROUP = "carnet.migration_series"

# The oldest server this is willing to migrate. **What CI proves, not the oldest that
# might work**: the feature floor is 15 (migration 007's `UNIQUE NULLS NOT DISTINCT`),
# but 15 is tested nowhere, and a version nothing runs against is a guess with a number
# on it. Raising this is a release decision; see docs/UPGRADING.md.
MIN_SERVER_VERSION_NUM = 160000
MIN_SERVER_VERSION = "16"

# One arbitrary constant, and every process that migrates this database agrees on it.
# Two servers booting together both run `--migrate`, which without this is a race the
# *data* survives — each file is its own transaction — and the operator does not: the
# losers die on `pg_type_typname_nsp_index`, a Postgres catalog index, which says
# nothing about migrations to anybody. Holding the lock across the read *and* the writes
# turns that into the second process waiting and then finding nothing to do.
#
# Session-scoped rather than transaction-scoped, so it spans the per-file commits and is
# released however this exits, including a crash. It waits rather than failing fast on
# purpose: the alternative to waiting out a long migration is booting a server against a
# half-migrated schema.
_ADVISORY_LOCK_KEY = 4_170_027_027_027_027


def _take_the_migration_lock(conn) -> None:
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_lock(%s)", (_ADVISORY_LOCK_KEY,))


class MigrationError(RuntimeError):
    """A refusal to migrate, carrying the remedy in its message.

    Separate from `StorageError` because these are answered by an operator at a shell —
    put the file back, use a fresh database, upgrade the server — rather than by a
    caller handling a failed write.
    """


# Applied migrations, tracked in the database being migrated. Created by hand rather
# than by a migration, because it has to exist before the first one runs.
_SCHEMA_TABLE = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     TEXT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""

# The checksum column arrives the same way and for the same reason. It cannot be a
# migration: the verify pass has to run *before* pending migrations apply, so a
# migration that created the column would leave the first checksummed run with nothing
# to verify against until after it had already applied unverified files.
_CHECKSUM_COLUMN = "ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum TEXT"


class Series(NamedTuple):
    """One numbered, checksummed sequence of migrations, and where its files are.

    `prefix` is what makes a version key say which series it belongs to: empty for the
    core series (`052_scim`), a short lowercase word for any other (`ee_001_approvals`).
    That is the entire series marker — there is no column, and a row written years
    before this type existed still answers correctly, because `052_scim` matched the
    core pattern then and matches it now.
    """

    name: str
    prefix: str
    directory: pathlib.Path

    def pattern(self):
        """`NNN_lower_snake_case`, under this series' prefix.

        Three digits, zero-padded, because that is what makes lexicographic order and
        numeric order the same order — which `files()` depends on and
        `tests/test_migrations.py` states at length.
        """
        head = f"{re.escape(self.prefix)}_" if self.prefix else ""
        return re.compile(rf"^{head}\d{{3}}_[a-z0-9_]+$")

    def owns(self, version: str) -> bool:
        """Does this series' naming account for `version`?

        Asked of a *ledger* row, so it must answer for versions that are not on disk:
        `053_oauth_clients` is owned by core whether or not this build has the file,
        which is exactly what makes it *ahead* rather than *foreign*.
        """
        return bool(self.pattern().match(version))

    def files(self) -> list:
        """This series' migrations, in order. `(version, path)`.

        Refuses a stray rather than applying it. In the core series that duplicates a
        unit test, which is cheap; in a discovered series it is the only thing standing
        between a misnamed file and an apply loop that sorts it somewhere nobody chose.
        """
        found = sorted((path.stem, path) for path in self.directory.glob("*.sql"))
        for version, path in found:
            if not self.owns(version):
                raise MigrationError(
                    f"{path.name} is in the {self.name} migration series but is not "
                    f"named for it: expected "
                    f"{self.prefix + '_' if self.prefix else ''}NNN_lower_snake_case"
                    f".sql. A file the runner cannot place is a file it would apply in "
                    f"an order nobody chose."
                )
        return found


CORE = Series(name="core", prefix="", directory=MIGRATIONS_DIR)

_PREFIX = re.compile(r"^[a-z][a-z0-9]*$")

_series_cache: Optional[list] = None


def _discover() -> list:
    """`CORE`, plus every registered series, validated. Ordering is decision 5's."""
    from importlib.metadata import entry_points

    found = [CORE]
    for entry in sorted(entry_points(group=ENTRY_POINT_GROUP), key=lambda e: e.name):
        try:
            loaded = entry.load()
            registered = loaded() if callable(loaded) else loaded
        except Exception as exc:
            # A broken install of somebody else's package, reached from inside
            # `--migrate`. Every other refusal in this module is one sentence naming
            # the remedy; an unwrapped ImportError here would be the one place an
            # operator gets a traceback from a library they did not install directly.
            raise MigrationError(
                f"the migration series registered as `{entry.name}` "
                f"({entry.value}) could not be loaded: {type(exc).__name__}: {exc}. "
                f"Nothing was applied. Reinstall or remove the distribution that "
                f"registers it."
            ) from exc
        _check_series(entry.name, registered, found)
        found.append(registered)

    # Core first, then the rest by prefix. An EE migration may assume every core object
    # that shipped in the same release and nothing about core migrations that ship
    # later; interleaving by number would mean two series agreeing about numbers, which
    # is the collision the prefix exists to make impossible.
    return found[:1] + sorted(found[1:], key=lambda s: s.prefix)


def _check_series(entry_name: str, registered, already: list) -> None:
    """Refuse a registration that would make the ledger ambiguous.

    Every one of these is a way for two series to disagree about who owns a version key,
    and a version key that two series claim is the exact failure the split exists to
    prevent — arriving through the seam that was built to prevent it.
    """
    if not isinstance(registered, Series):
        raise MigrationError(
            f"the migration series registered as `{entry_name}` is a "
            f"{type(registered).__name__}, not a storage.migrate.Series."
        )
    if not _PREFIX.match(registered.prefix):
        raise MigrationError(
            f"the migration series `{registered.name}` declares the prefix "
            f"{registered.prefix!r}, which is not a lowercase word. The empty prefix "
            f"is the core series and belongs to carnet itself."
        )
    for other in already:
        if registered.prefix == other.prefix or registered.name == other.name:
            raise MigrationError(
                f"the migration series `{registered.name}` collides with `{other.name}`"
                f" (prefix {registered.prefix!r}). Two series claiming one prefix claim "
                f"one version key, which is what the prefix exists to prevent."
            )
    if not isinstance(registered.directory, pathlib.Path):
        # `files()` calls `.glob` on this. A string here is an `AttributeError` three
        # frames into a library the operator did not install directly, which is the
        # shape of refusal this module exists not to produce.
        raise MigrationError(
            f"the migration series `{registered.name}` gives its directory as a "
            f"{type(registered.directory).__name__}, not a pathlib.Path."
        )
    if not registered.directory.is_dir():
        raise MigrationError(
            f"the migration series `{registered.name}` points at "
            f"{registered.directory}, which is not a directory."
        )


def series() -> list:
    """Every migration series this build ships, in apply order. Cached.

    Cached because `available()` is called more than once per run — `apply` walks it
    twice — and an entry-point scan reads installed metadata off disk. The cache is
    process-lifetime: a series arrives by installation, and nothing installs a package
    into a running server.
    """
    global _series_cache
    if _series_cache is None:
        _series_cache = _discover()
    return _series_cache


def _reset_series_cache() -> None:
    """For the tests, which register synthetic series, and for nothing else."""
    global _series_cache
    _series_cache = None


def owner_of(version: str, known: list) -> Optional[Series]:
    """The series whose naming accounts for `version`, or None if nothing here does.

    None is the load-bearing answer. It means *this build has no opinion about that
    row* — not *that row is from the future* — and it is what lets one database carry
    two series while each build reasons only about its own.
    """
    for candidate in known:
        if candidate.owns(version):
            return candidate
    return None


def available() -> list:
    """Every migration on disk, in order. `(version, path)`.

    Spans every series, core first. The signature is deliberately unchanged from the
    single-series form: `scripts/e2e_upgrade.py` replaces this function to replay
    history up to a version, and that script is the only proof the upgrade path has.
    """
    return [entry for one in series() for entry in one.files()]


def checksum(path) -> str:
    """The sha256 of a migration file, over raw bytes.

    Bytes rather than decoded text: a line-ending change rewrites the file, and "never
    edited once released" means the file, not an interpretation of it.
    """
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def applied(conn) -> dict:
    """`{version: checksum}` for everything already applied. Creates the ledger.

    Returns a mapping rather than the set it used to, so a caller can verify as well as
    skip. `checksum` is None for rows written before 027 and for the e2e scripts that
    hand-replay migrations to build an old schema — see `_verify_checksums`.
    """
    with conn.cursor() as cur:
        cur.execute(_SCHEMA_TABLE)
        cur.execute(_CHECKSUM_COLUMN)
        cur.execute("SELECT version, checksum FROM schema_migrations")
        return {row[0]: row[1] for row in cur.fetchall()}


def _check_server_version(server_version_num: int) -> None:
    """Refuse a server older than the floor. Pure, so it is testable without one."""
    if server_version_num < MIN_SERVER_VERSION_NUM:
        pretty = f"{server_version_num // 10000}.{server_version_num % 10000}"
        raise MigrationError(
            f"this runtime requires PostgreSQL {MIN_SERVER_VERSION} or later; this "
            f"server is {pretty}. {MIN_SERVER_VERSION} is the version its migrations "
            f"and contract suite are tested against, not the oldest that might work."
        )


def _check_dedicated_database(conn) -> None:
    """Refuse a database that already holds somebody else's tables.

    Migrations create their tables unqualified, so they land in whatever `search_path`
    resolves to — `public`. Pointed at a database that already holds something, this
    runtime shares a namespace with it, and the failure mode is a name collision
    between two schemas that have never heard of each other.

    A named schema was the alternative and was declined: it is a migration over every
    table plus a `search_path` on every pooled connection, to buy collision *avoidance*
    where `CREATE DATABASE` buys collision *impossibility*. See docs/UPGRADING.md.

    **Runs before the ledger is created**, which is why it asks about
    `schema_migrations` itself rather than taking the applied set: a refusal has to
    leave the database exactly as it found it, and creating a table in somebody's
    database on the way to telling them it is not ours is not that. A database that
    already has a ledger is one we have migrated before, so its `public` is ours.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT to_regclass('public.schema_migrations') IS NOT NULL")
        if cur.fetchone()[0]:
            return

        cur.execute(
            "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')"
        )
        existing = cur.fetchone()[0]

    if existing:
        raise MigrationError(
            f"this database already contains {existing} table(s) in `public` and no "
            f"migration ledger, so it is not ours to migrate. carnet requires a "
            f"dedicated database — create an empty one and point "
            f"CARNET_DATABASE_URL at it."
        )


def foreign(already: dict, known: list) -> list:
    """Ledger rows belonging to no series this build ships. Reported, never refused.

    An operator debugging a feature that vanished should be able to see that their
    database knows about a series their build does not — see `apply`'s verbose line.
    """
    return sorted(v for v in already if owner_of(v, known) is None)


def _check_ledger_is_on_disk(already: dict, on_disk: dict, known: list) -> None:
    """Refuse when the database has been migrated by a newer checkout than this one.

    Forward-only means old code against a new schema is unsupported, and it used to be
    *silent*: `apply` skipped what it did not recognise and reported success. Under
    BYOC this is precisely what "last month's checkout, this month's database" looks
    like, and the honest answer is to stop.

    **Ahead is scoped to the series this build ships — 082.** It used to be
    `set(already) - set(on_disk)`, which reads *unknown to me* and refuses a row it has
    no business having an opinion about. One database may carry two series: a build
    without the enterprise series must migrate its own perfectly happily, and a build
    *with* it must still refuse an `ee_` version it does not have. The difference is
    whether some series here claims the version key, which `owner_of` answers.
    """
    ahead = sorted(
        version
        for version in already
        if version not in on_disk and owner_of(version, known) is not None
    )
    if ahead:
        raise MigrationError(
            f"this database is ahead of this checkout: it records {ahead[0]}, which is "
            f"not in this build's migrations ({len(ahead)} such version(s)). Deploy a "
            f"version at least as new as the database; migrations are forward-only, so "
            f"an older build cannot run against a newer schema."
        )


def _verify_checksums(conn, already: dict, on_disk: dict) -> None:
    """Refuse an edited migration; backfill a checksum nobody recorded.

    **Trust on first verify.** A NULL means the row predates 027 or was written by an
    e2e script replaying migrations by hand — in both cases there is nothing to compare
    against, and inventing a mismatch would refuse every existing deployment on the one
    upgrade that introduces the check. The file on disk becomes the recorded truth, and
    every run after this one is checked against it.

    **A row with no file is skipped rather than indexed — 082.** `_check_ledger_is_on_disk`
    runs first and has already refused everything ahead *within a series this build
    ships*, so what reaches here without a file belongs to a series this build does not
    ship: there is nothing to compare it against and nothing to say about it. This line
    used to be a bare `on_disk[version]`, so such a row was a `KeyError` rather than a
    refusal — unreachable only because the check above it refused first.
    """
    backfill = []
    for version, recorded in sorted(already.items()):
        if version not in on_disk:
            continue
        current = checksum(on_disk[version])
        if recorded is None:
            backfill.append((current, version))
        elif recorded != current:
            raise MigrationError(
                f"migration {version} has changed since it was applied to this "
                f"database (recorded {recorded[:12]}…, on disk {current[:12]}…). "
                f"Released migrations are never edited: restore the released file, or "
                f"make the change a new numbered migration."
            )

    if backfill:
        with conn.cursor() as cur:
            cur.executemany(
                "UPDATE schema_migrations SET checksum = %s WHERE version = %s",
                backfill,
            )
        conn.commit()


def apply(dsn: str, verbose: bool = False) -> list:
    """Bring the database at `dsn` up to date. Returns the versions applied.

    Idempotent: already-applied migrations are skipped, so running this on every
    deploy is the intended usage rather than a thing to be careful about.

    Four preflights run first, in this order, and each raises `MigrationError` with the
    remedy in the sentence: the server is old enough; the database is ours; the ledger
    names nothing this build does not have; no applied migration has been edited. They
    run before the first file so a refusal costs nothing and changes nothing.

    The third of those is scoped to the series this build ships — see
    `_check_ledger_is_on_disk`. Rows from a series it does not ship are reported under
    `verbose` and otherwise left alone.

    **The series are resolved before the connection is opened**, so a distribution that
    registers a broken series — an entry point that will not load, a directory that is
    not there, a file named for no series — costs a refusal and not a socket. It also
    keeps that refusal on the right side of `_check_dedicated_database`'s promise: the
    ledger is created by `applied` a few lines below, and a database refused *after*
    that has been written to on the way to being told it was not ours.
    """
    import psycopg

    known = series()
    on_disk = dict(available())

    done = []
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SHOW server_version_num")
            _check_server_version(int(cur.fetchone()[0]))

        # Before anything reads the ledger, so the whole read-then-apply is serialised
        # against another process doing the same thing.
        _take_the_migration_lock(conn)

        # Before `applied`, which would create the ledger in a database we may be about
        # to refuse.
        _check_dedicated_database(conn)

        already = applied(conn)
        conn.commit()

        _check_ledger_is_on_disk(already, on_disk, known)
        _verify_checksums(conn, already, on_disk)

        if verbose:
            unowned = foreign(already, known)
            if unowned:
                # Not a warning and not a refusal. It is the one place an operator can
                # see that this database knows about a migration series this build does
                # not ship — which is what a lost enterprise package looks like from the
                # inside, and is otherwise entirely silent. Named rather than counted
                # while there are few enough to name: a count plus an ellipsis is a
                # message that tells somebody to go and write the query themselves.
                shown = ", ".join(unowned[:3])
                rest = "" if len(unowned) <= 3 else f", and {len(unowned) - 3} more"
                print(
                    f"  [migrate] {len(unowned)} ledger row(s) belong to a migration "
                    f"series this build does not ship: {shown}{rest}"
                )

        for version, path in available():
            if version in already:
                continue

            sql = path.read_text(encoding="utf-8")
            started = time.monotonic()
            with conn.cursor() as cur:
                cur.execute(sql)
                cur.execute(
                    "INSERT INTO schema_migrations (version, checksum) VALUES (%s, %s)",
                    (version, checksum(path)),
                )
            conn.commit()
            elapsed = time.monotonic() - started

            done.append(version)
            if verbose:
                # The elapsed time is here for the operator mid-upgrade, not for CI:
                # 035 re-keys five tables, and on a large one that is the difference
                # between a pause and an outage somebody needs to have been warned
                # about. CI measures the same thing in scripts/e2e_upgrade.py.
                print(f"  [migrate] applied {version} in {elapsed:.2f}s")

    return done
