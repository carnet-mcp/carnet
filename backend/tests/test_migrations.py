"""The migration numbering, and the server floor — asserted without a database.

These are the half of 027's promise that needs no Postgres to check, which is why they
live here rather than in the contract suite: they run in the `fast` CI job, on every
push, on both interpreters. `available()` only globs a directory, so nothing here
imports psycopg.

What they defend is stated in `storage/migrate.py`'s module docstring. The short
version: a version is a name and not a position, the ledger is keyed by it, and
`available()` orders by the stem — so the zero padding is not cosmetic, it is what
makes lexicographic order and numeric order the same order.

**Since 082 they are scoped to the core series.** `available()` spans every series this
build ships, and contiguity from 001 is a promise about *this package's* files rather
than about everything that may be installed beside them — an enterprise series starting
at its own 001 is correct and would fail a global count. The series machinery itself is
tested at the foot of this file, against a synthetic second series, because the public
tree has no real one and *the public tree runs green with the second series absent* is
the thing that has to be asserted rather than assumed.
"""

import pathlib
import re

import pytest

from carnet.storage import migrate

_NUMBERED = re.compile(r"^(\d+)_[a-z0-9_]+$")


def _core():
    return migrate.CORE.files()


def _numbers():
    return [int(_NUMBERED.match(version).group(1)) for version, _ in _core()]


def test_every_migration_is_numbered_then_named():
    """`NNN_lower_snake_case.sql`, and nothing else in the directory.

    A file that does not match is either a stray — an editor backup, a `.sql` somebody
    left behind — or a migration named in a way that sorts unpredictably against the
    rest. `available()` would apply it either way.
    """
    for version, path in _core():
        assert _NUMBERED.match(version), f"{path.name} is not NNN_name.sql"


def test_migration_numbers_are_zero_padded_to_three_digits():
    """Padding is what makes string order and numeric order the same order.

    Without it `9_x` sorts after `10_x` and the runner applies them in that order, which
    is the one failure this whole file exists to make impossible. Three digits is also
    the width every existing migration uses, so a fourth digit is a decision somebody
    takes deliberately rather than by adding a file.
    """
    for version, _ in _core():
        assert len(version.split("_")[0]) == 3, f"{version} is not zero-padded to three"


def test_migration_numbers_are_unique():
    """Two files with one number is the ambiguity a checksum cannot catch.

    Both apply, both are recorded under their own stems, and which ran first depends on
    the rest of the name. The ledger looks fine afterwards.
    """
    numbers = _numbers()
    duplicates = sorted({n for n in numbers if numbers.count(n) > 1})
    assert not duplicates, f"more than one migration numbered {duplicates}"


def test_migration_numbers_are_contiguous_from_001():
    """A gap means a renumbering or a lost file, and both break the promise.

    Forward-only and never renumbered means the numbers are a history, not an index —
    so a hole in them is either a migration that was deleted after release (a database
    somewhere has it applied and this build cannot verify it) or one that was renamed
    (the same file, applied twice, under two names).
    """
    numbers = _numbers()
    assert numbers == list(range(1, len(numbers) + 1)), (
        f"migrations are not contiguous from 001: {numbers}"
    )


def test_the_server_floor_is_sixteen():
    """Pure, so the floor is testable without standing up an old Postgres.

    `apply` reads `SHOW server_version_num` and hands the integer straight here, so this
    is the whole of the decision — 150002 is a real 15.2 and is refused; 160000 is the
    floor itself and is not.
    """
    with pytest.raises(migrate.MigrationError, match="PostgreSQL 16 or later"):
        migrate._check_server_version(150002)

    migrate._check_server_version(160000)
    migrate._check_server_version(170004)


def test_the_refusal_names_the_version_it_found():
    """An operator reading it should not have to go and look up what they are running."""
    with pytest.raises(migrate.MigrationError, match="15.2"):
        migrate._check_server_version(150002)


def test_a_migrations_checksum_is_over_its_bytes():
    """Stable, and sensitive to a line-ending change.

    "Never edited once released" is a property of the file. A checksum over decoded
    text would let a checkout with different line endings present as unedited, which is
    exactly the case where two deployments disagree about what a version means.
    """
    _, path = _core()[0]

    assert migrate.checksum(path) == migrate.checksum(path)
    assert len(migrate.checksum(path)) == 64


def test_a_checksum_follows_the_contents_and_not_the_path(tmp_path):
    """**The property the whole promise rests on, and it had no test until 027's
    mutation pass.**

    Every other checksum test writes a wrong value into the ledger and watches the
    runner refuse it — which proves the comparison happens, and proves nothing at all
    about *what is being compared*. A `checksum()` that hashed the filename, or any
    other stable-but-wrong thing, passed all of them: the planted value still mismatched,
    so they still went green, while an actually-edited migration would have sailed
    through unnoticed.

    Same path, different bytes, twice — which is exactly the shape of editing a released
    migration, and the one thing a path-derived hash cannot tell apart.
    """
    one = tmp_path / "036_example.sql"

    one.write_bytes(b"CREATE TABLE a (id int);\n")
    before = migrate.checksum(one)

    one.write_bytes(b"CREATE TABLE a (id int); DROP TABLE b;\n")
    after = migrate.checksum(one)

    assert before != after, "the checksum did not follow the file's contents"

    # And a byte the eye slides over — a trailing newline — still moves it.
    one.write_bytes(b"CREATE TABLE a (id int); DROP TABLE b;")
    assert migrate.checksum(one) != after


# --- step 082: two series, one ledger ------------------------------------------------
#
# The public tree ships one series and has to keep working when a second one is
# installed beside it — and has to keep refusing the things it refused before. Neither
# half can be checked against a real enterprise package, because there is not one, so
# both are checked against a synthetic series built in a temporary directory. That is
# stronger than a real one would be: a synthetic series can be wrong on purpose.


@pytest.fixture
def second(tmp_path):
    """A second series with one migration in it, registered for the test's lifetime.

    Registration is by setting the discovery cache, which is fast and says nothing about
    the seam — the entry-point read, the `load()` and the validation on the way through
    are exercised instead by `test_a_series_is_discovered_through_the_entry_point_and_
    not_through_a_name` at the foot of this file, which builds a distribution's metadata
    on `sys.path` and lets `importlib.metadata` find it.
    """
    directory = tmp_path / "ee"
    directory.mkdir()
    (directory / "ee_001_approvals.sql").write_bytes(b"CREATE TABLE ee_approvals (id int);\n")
    made = migrate.Series(name="enterprise", prefix="ee", directory=directory)

    migrate._series_cache = [migrate.CORE, made]
    try:
        yield made
    finally:
        migrate._reset_series_cache()


def test_this_checkout_registers_only_the_core_series():
    """**The tripwire.** The public tree runs with the second series absent.

    `test_the_server_never_imports_the_local_idp`'s covenant, applied to migrations: the
    enterprise package may know this one, and this one must not know it. If anything
    here ever grew an entry point of its own, or a hard-coded import of a second series,
    this is where it shows up — and it shows up on a checkout, not on a deployment.
    """
    migrate._reset_series_cache()
    assert migrate.series() == [migrate.CORE]
    assert migrate.CORE.prefix == ""


def test_nothing_in_this_tree_names_a_second_series():
    """The grep half of the covenant, mirroring the local-idp test's shape.

    `migrate.py` defines the group and the type and names no member of it. A tree that
    said `carnet_ee` anywhere would have put the other tree's name in this one, which
    is the seam's whole point undone.
    """
    src = pathlib.Path(migrate.__file__).resolve().parents[2]
    offenders = [
        path
        for path in src.rglob("*.py")
        if "carnet_ee" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_this_package_declares_no_migration_series_entry_point():
    """The other half of the covenant, and the half a grep over `src/` cannot see.

    `test_nothing_in_this_tree_names_a_second_series` reads Python. A series can also
    arrive without a line of Python — four lines in `pyproject.toml` under
    `[project.entry-points."carnet.migration_series"]` would make this package ship a
    second series, and every Python file in the tree would still be clean.
    """
    root = pathlib.Path(migrate.__file__).resolve().parents[3]
    assert migrate.ENTRY_POINT_GROUP not in (root / "pyproject.toml").read_text(
        encoding="utf-8"
    )


def test_a_row_from_a_series_this_build_does_not_ship_is_not_ahead():
    """**The load-bearing case.** One database, two series, and the public build.

    Before 082 this was `set(already) - set(on_disk)`, which reads *unknown to me* and
    refuses. The enterprise tree migrating a database to `ee_001_approvals` would have
    made every public build refuse it with a sentence about being ahead — and the
    reverse, which is worse, because it is the deployment somebody paid for.
    """
    on_disk = dict(migrate.CORE.files())
    ledger = dict.fromkeys(on_disk, None)
    ledger["ee_001_approvals"] = "a" * 64

    migrate._check_ledger_is_on_disk(ledger, on_disk, [migrate.CORE])


def test_a_row_in_a_series_this_build_does_ship_is_still_ahead(second):
    """And the scoping does not become tolerance. Same row, a build that owns it.

    This is the half that a second ledger table could not express at all: with the
    enterprise series installed at 001, a row saying 004 is a database migrated by a
    newer enterprise build, and it has to stop.
    """
    on_disk = dict(migrate.available())
    ledger = dict.fromkeys(on_disk, None)
    ledger["ee_004_later"] = "a" * 64

    with pytest.raises(migrate.MigrationError, match="ee_004_later"):
        migrate._check_ledger_is_on_disk(ledger, on_disk, migrate.series())


def test_a_core_row_this_build_does_not_have_is_still_refused():
    """The check 027 added, unchanged by the split — asserted here rather than assumed.

    `999_from_a_newer_build` matches the core pattern, so the core series owns it, so it
    is ahead. The scoping in 082 must not have widened into "refuse only what I have a
    file for", which would have made every rollback silent again.
    """
    on_disk = dict(migrate.CORE.files())
    ledger = dict.fromkeys(on_disk, None)
    ledger["999_from_a_newer_build"] = None

    with pytest.raises(migrate.MigrationError, match="999_from_a_newer_build"):
        migrate._check_ledger_is_on_disk(ledger, on_disk, [migrate.CORE])


def test_checksums_are_verified_only_for_series_this_build_ships():
    """A foreign row has no file, and there is nothing to say about it.

    The line used to be `checksum(on_disk[version])` — a `KeyError`, not even a
    `MigrationError`, reachable the moment the check above it stopped refusing. `conn`
    is None on purpose: with no backfill to write, nothing here may touch the database.
    """
    on_disk = dict(migrate.CORE.files())
    ledger = {version: migrate.checksum(path) for version, path in migrate.CORE.files()}
    ledger["ee_001_approvals"] = "a" * 64

    migrate._verify_checksums(None, ledger, on_disk)


def test_an_edited_core_migration_is_still_refused_beside_a_foreign_row():
    """The scoping is per row, not a switch that turns verification off.

    A ledger carrying one unrecognised row must not become a ledger nothing is checked
    against — which is the shape a `continue` in the wrong place produces.
    """
    on_disk = dict(migrate.CORE.files())
    ledger = {version: migrate.checksum(path) for version, path in migrate.CORE.files()}
    ledger["ee_001_approvals"] = "a" * 64
    ledger["001_tenants"] = "b" * 64

    with pytest.raises(migrate.MigrationError, match="001_tenants"):
        migrate._verify_checksums(None, ledger, on_disk)


def test_the_series_is_read_out_of_the_version_key_and_needs_no_backfill():
    """027's precedent was read and does not apply — the plan's decision 4.

    A checksum cannot be derived from a version name, so 027 had to backfill. A series
    can: every row written before this type existed answers correctly, on every deployed
    database, with no column and no migration.
    """
    assert migrate.owner_of("001_tenants", [migrate.CORE]) is migrate.CORE
    assert migrate.owner_of("052_scim", [migrate.CORE]) is migrate.CORE
    assert migrate.owner_of("ee_001_approvals", [migrate.CORE]) is None


def test_a_second_series_applies_after_core_and_orders_within_itself(second):
    """Core first, then each further series; numeric within a series.

    An enterprise migration may assume every core object that shipped in the same
    release. It cannot assume anything about core migrations that ship later, and
    interleaving by number would mean two series agreeing about numbers — the collision
    the prefix exists to make impossible.
    """
    (second.directory / "ee_002_later.sql").write_bytes(b"SELECT 1;\n")

    versions = [version for version, _ in migrate.available()]

    assert versions[: len(migrate.CORE.files())] == [v for v, _ in migrate.CORE.files()]
    assert versions[-2:] == ["ee_001_approvals", "ee_002_later"]


def test_a_file_that_does_not_match_its_series_is_refused_by_name(second):
    """A misnamed file in a discovered directory would sort somewhere nobody chose.

    In the core series this duplicates the numbering tests at the top of this file,
    which is cheap. In a series that arrives by installation it is the only thing
    between somebody else's typo and an apply order this runner invented.
    """
    (second.directory / "ee_1_short.sql").write_bytes(b"SELECT 1;\n")

    with pytest.raises(migrate.MigrationError, match="ee_1_short.sql"):
        migrate.available()


def test_a_series_colliding_with_core_is_refused_at_registration(tmp_path):
    """Two series claiming one prefix claim one version key.

    Every check in `_check_series` is a way for the ledger to become ambiguous, arriving
    through the seam built to prevent ambiguity. The empty prefix is the sharpest of
    them: it is the core series, and a second claimant to it is the original collision.
    """
    directory = tmp_path / "x"
    directory.mkdir()

    with pytest.raises(migrate.MigrationError, match="not a lowercase word"):
        migrate._check_series("x", migrate.Series("x", "", directory), [migrate.CORE])

    with pytest.raises(migrate.MigrationError, match="collides"):
        migrate._check_series(
            "b",
            migrate.Series("enterprise", "ee", directory),
            [migrate.CORE, migrate.Series("enterprise", "ee", directory)],
        )

    with pytest.raises(migrate.MigrationError, match="not a directory"):
        migrate._check_series(
            "c", migrate.Series("ghost", "gh", tmp_path / "nope"), [migrate.CORE]
        )

    with pytest.raises(migrate.MigrationError, match="not a storage.migrate.Series"):
        migrate._check_series("d", {"prefix": "ee"}, [migrate.CORE])


def test_foreign_rows_are_reported_and_never_refused(second):
    """What `apply(verbose=True)` prints, and the reason it prints anything at all.

    A build that lost its enterprise package migrates its own series happily and says
    nothing — which is correct for the check above and is exactly what a misinstall
    looks like from the inside. This is the only signal there is.
    """
    ledger = {"001_tenants": None, "ee_001_approvals": None, "zz_009_other": None}

    assert migrate.foreign(ledger, [migrate.CORE]) == ["ee_001_approvals", "zz_009_other"]
    assert migrate.foreign(ledger, migrate.series()) == ["zz_009_other"]


def test_a_series_is_discovered_through_the_entry_point_and_not_through_a_name(tmp_path):
    """The seam itself, exercised the way an installation exercises it.

    Every test above registers its second series by setting the cache, which is the one
    thing an installation does not do — so the entry-point read, the `load()`, and the
    validation on the way through were asserted nowhere. This builds a distribution's
    metadata on `sys.path` instead: no package is installed, and `importlib.metadata`
    cannot tell the difference, which is the point.

    What it proves is the covenant's active half. `series()` returns two series and this
    module still contains no string naming either the distribution or its prefix — the
    enterprise tree knows this one, and this one finds it without knowing it.
    """
    import importlib
    import sys

    (tmp_path / "series_probe.py").write_text(
        "import pathlib\n"
        "from carnet.storage import migrate\n"
        "SERIES = migrate.Series('probe', 'pb', pathlib.Path(__file__).parent / 'pb')\n",
        encoding="utf-8",
    )
    (tmp_path / "pb").mkdir()
    (tmp_path / "pb" / "pb_001_first.sql").write_bytes(b"SELECT 1;\n")

    dist = tmp_path / "series_probe-0.1.dist-info"
    dist.mkdir()
    (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: series-probe\nVersion: 0.1\n")
    (dist / "entry_points.txt").write_text(
        f"[{migrate.ENTRY_POINT_GROUP}]\nprobe = series_probe:SERIES\n"
    )

    sys.path.insert(0, str(tmp_path))
    importlib.invalidate_caches()
    migrate._reset_series_cache()
    try:
        found = migrate.series()
        assert [one.name for one in found] == ["core", "probe"]
        assert migrate.available()[-1][0] == "pb_001_first"
        assert migrate.owner_of("pb_001_first", found).name == "probe"
    finally:
        sys.path.remove(str(tmp_path))
        sys.modules.pop("series_probe", None)
        importlib.invalidate_caches()
        migrate._reset_series_cache()

    assert migrate.series() == [migrate.CORE]
