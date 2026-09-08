"""One set of assertions, run against every storage implementation.

The whole risk of having an in-memory store is that it quietly permits what Postgres
would refuse — and a suite that only ever exercises the fake is green about behaviour
production does not have. So the rules live here once, and both implementations answer
to them.

The Postgres parameter is **skipped unless `CARNET_TEST_DSN` is set**. That is
what lets the default suite keep starting nothing and calling nothing while CI, or a
developer with a database up, runs the same assertions against the real engine.

    CARNET_TEST_DSN=postgresql://localhost/carnet_test pytest -q

**That database is dropped and rebuilt at the start of every session.** Point it at a
throwaway. It has to be rebuilt rather than cleaned between tests, because the audit
table refuses DELETE by design — which is the correct behaviour making itself felt in
the one place it is inconvenient.

Within a session each test gets its own tenant rather than a truncated database. That
works because every method is tenant-scoped, which is itself worth asserting, and this
is the cheapest possible assertion of it.
"""

import hashlib
import itertools
import json
import os
import re
from datetime import date, datetime, timedelta, timezone

import pytest

from carnet import config
from carnet.storage import (
    AGENT_VERSION_FIELDS,
    AGENT_VERSION_SUMMARY_FIELDS,
    CONNECTION_DETAIL_KEYS,
    DOOR_CALL_ID_PREFIX,
    GROUP_FIELDS,
    GROUP_MEMBER_FIELDS,
    PLATFORM_ROLE_FIELDS,
    RETAINED_LOG_TABLES,
    SCHEDULE_FIELDS,
    TRIGGER_FIELDS,
    AgentNameTaken,
    ConnectorInUseError,
    InMemoryStorage,
    IssuerConflictError,
    NoSuchConnectorError,
    NoSuchGroupError,
    Storage,
    StorageError,
    TENANT_BLOCKING_TABLES,
    TenantDeleted,
    TenantDeletionRefused,
    UnknownConnectorError,
    UnknownTenantError,
    ValueRefused,
    VETTED_TOOL_FIELDS,
)
from carnet.storage.base import (
    LEADERBOARD,
    _add_months,
    new_agent_id,
    log_partition_months,
    prune_floor,
)
from conftest import TEST_ACTOR


@pytest.fixture(scope="session")
def pg_dsn():
    """A migrated, empty Postgres — built once per session, or a skip.

    The drop is deliberate and the docstring above says so. Reusing a dirty database
    is how the first run of this suite passed and the second failed: tenants persisted,
    audit rows accumulated, and per-test tenant names stopped being unique.

    **`CARNET_TEST_KEEP_SCHEMA` skips the drop, and exists for exactly one
    caller**: the `upgrade` CI job, which runs this suite against the database
    `scripts/e2e_upgrade.py` just built out of a decade of migrations and populated —
    where the dirt is the entire point of the exercise. The `migrate.apply` below still
    runs in that mode and is not ceremony: against an already-upgraded database it
    asserts the thing the job is there to prove, that the database is at head and every
    checksum verifies.

    Per-test isolation does not depend on the drop — tenants are named per test, which
    is why this composes with a populated database at all.
    """
    dsn = os.environ.get("CARNET_TEST_DSN")
    if not dsn:
        pytest.skip("CARNET_TEST_DSN not set — Postgres tests skipped")

    try:
        import psycopg

        from carnet.storage import migrate
    except ImportError as exc:  # pragma: no cover - psycopg is an optional extra
        pytest.skip(f"psycopg not installed: {exc}")

    if not os.environ.get("CARNET_TEST_KEEP_SCHEMA"):
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute("DROP SCHEMA public CASCADE")
            conn.execute("CREATE SCHEMA public")

    migrate.apply(dsn)
    return dsn


@pytest.fixture(params=["memory", "postgres"])
def store(request):
    if request.param == "memory":
        yield InMemoryStorage()
        return

    from carnet.storage.postgres import PostgresStorage

    storage = PostgresStorage(request.getfixturevalue("pg_dsn"))
    yield storage
    storage.close()


@pytest.fixture
def tenant(store, request):
    """A tenant unique to this test, so runs never collide in a shared database."""
    tenant_id = f"t-{request.node.name}"[:60]
    store.create_tenant(tenant_id, "Test Tenant")
    return tenant_id


@pytest.fixture
def other(store, request):
    """A second tenant, for the isolation assertions."""
    tenant_id = f"o-{request.node.name}"[:60]
    store.create_tenant(tenant_id, "Other Tenant")
    return tenant_id


AGENT = {
    "name": "issue-reporter",
    "runtime": "simple",
    "system": "You read issues.",
    "permissions": {
        "tools": ["post_message"],
        "scope": {"chat.channel": {"write": ["#eng"]}},
    },
}

# What `create_connector` stores. HTTP, because registration is HTTP-only — see
# `tools.STDIO_REFUSED`. This is the *stored* shape rather than an `HttpLaunch`, since
# storage deals in dicts and never learns what a transport is.
_HTTP_LAUNCH = {
    "kind": "http",
    "url": "https://mcp.example.com/mcp",
    "credential_env": "JIRA_TOKEN",
    "credential_header": "Authorization",
    "credential_prefix": "Bearer ",
    "headers": {},
}

# Step 045a: a REST connector's launch, and the request binding its vetted rows must
# carry. The launch shares `_HTTP_LAUNCH`'s field names on purpose — the kind tag is
# what keeps them distinct.
_REST_LAUNCH = {**_HTTP_LAUNCH, "kind": "rest", "url": "https://api.example.com/v1"}

_BINDING = {
    "method": "GET",
    "path": "/repos/{owner}/{repo}/issues",
    "query": ["state"],
    "body": [],
    "input_schema": {
        "type": "object",
        "properties": {
            "owner": {"type": "string"},
            "repo": {"type": "string"},
            "state": {"type": "string"},
        },
        "required": ["owner", "repo"],
    },
    "usage_map": None,
    # Step 086, beside `usage_map` and for the same reason it is written out here: every
    # binding key is filled by `normalize_vetted_tool`, so a fixture that omits one is
    # asserting that two write paths agree about a key neither of them wrote.
    "pricing": None,
}

MANIFEST = {
    "id": "github-mcp",
    "description": "GitHub, read path.",
    "launch": {
        "command": ["docker", "run", "-i", "--rm", "ghcr.io/github/github-mcp-server"],
        "credential_env": "GITHUB_PERSONAL_ACCESS_TOKEN",
        "env": {"GITHUB_TOOLSETS": "issues"},
        "read_only_env": "GITHUB_READ_ONLY",
    },
    "vetted": [
        {
            "remote_name": "list_issues",
            "effect": "read",
            # 033a: whose account it acts as, stored where `effect` is.
            "identity": "service",
            "resources": [
                {
                    "type": "github.repo",
                    "args": ["owner", "repo"],
                    "template": "{owner}/{repo}",
                }
            ],
            "local_name": None,
            "max_response_bytes": None,
            # Migration 018. Stored at vetting time so a catalogue answers with the
            # connector's server stopped, and so the wording cannot change under a
            # grant somebody already approved.
            "description": "List issues in a GitHub repository.",
            "note": "Scope it to the repositories a team owns.",
            # Migration 047, step 045a: the REST request binding. None on every MCP
            # row — the field and the launch kind imply each other, and this
            # connector speaks stdio.
            "binding": None,
            # Migration 049, step 045c: which arguments the audit log hashes rather
            # than stores. `[]` rather than None — unlike `binding` there is no "not
            # applicable" state, and this connector's approval redacted nothing.
            "redact_args": [],
        }
    ],
    # 033c: whether an asserted acting-for through the MCP door is believed for this
    # server's tools. In the fixture so the equality round-trip covers it in both
    # stores — the same tripwire that caught `audit.credential`.
    "allow_asserted_identity": False,
}


def _days_ago(days: int):
    """A timestamp `days` in the past. See `aged`, which also makes it writable."""
    return datetime.now(timezone.utc) - timedelta(days=days)


def _record(**overrides) -> dict:
    record = {
        "v": 5,
        "ts": "2026-08-02T10:00:00.000+00:00",
        "run_id": "abc123",
        "principal_kind": "system",
        "principal_id": "cli",
        "agent": "issue-reporter",
        "tool": "post_message",
        "effect": "write",
        "args": {"channel": "#eng"},
        "decision": "allow",
        "reason": "",
        "outcome": "ok",
        "duration_ms": 3,
        "response_bytes": 147,
    }
    record.update(overrides)
    return record


# --- the Protocol ---------------------------------------------------------------


def test_implements_the_protocol(store):
    assert isinstance(store, Storage)


def test_ping_answers_on_a_live_store(store):
    """056: the readiness round trip, in both implementations.

    Nothing returned and nothing raised is the whole green contract. The red half —
    `StorageError` when the database is gone — needs a database that can actually go
    away, which is `scripts/e2e_deploy.py`'s job (it stops the `db` container and
    watches `/health/ready` diverge from `/health`)."""
    store.ping()


# --- tenants --------------------------------------------------------------------


def test_tenant_round_trips(store, tenant):
    assert store.get_tenant(tenant)["id"] == tenant


def test_creating_an_existing_tenant_is_not_an_error(store, tenant):
    store.create_tenant(tenant, "Renamed Or Not")
    assert store.get_tenant(tenant) is not None


def test_unknown_tenant_reads_as_none(store):
    assert store.get_tenant("no-such-tenant") is None


def test_list_tenants_includes_created_ones(store, tenant, other):
    listed = {row["id"] for row in store.list_tenants()}
    assert {tenant, other} <= listed


# Migration 020. A customer can be stopped, and the shape of "stopped" is the point:
# it closes the doors work arrives through and ends nothing already inside.


def test_a_new_tenant_is_active(store, tenant):
    """The default matters more than it looks: every tenant created before migration
    020 got this value from the column default, so a suspended-by-accident customer
    would have been a silent, total outage for them."""
    assert store.get_tenant(tenant)["status"] == "active"
    assert all(row["status"] == "active" for row in store.list_tenants())


def test_a_tenant_can_be_suspended_and_resumed(store, tenant):
    store.set_tenant_status(tenant, "suspended")
    assert store.get_tenant(tenant)["status"] == "suspended"

    store.set_tenant_status(tenant, "active")
    assert store.get_tenant(tenant)["status"] == "active"


def test_an_unknown_tenant_status_is_refused(store, tenant):
    """'read_only' is the one somebody will try, because it is the state the migration
    explains is deliberately absent. It must fail loudly rather than be stored as a
    value no code path answers."""
    with pytest.raises(StorageError, match="status must be one of"):
        store.set_tenant_status(tenant, "read_only")

    assert store.get_tenant(tenant)["status"] == "active"


def test_setting_the_status_of_an_unknown_tenant_does_nothing(store):
    """Matches `set_user_status`, which is also a no-op on a row that is not there."""
    store.set_tenant_status("no-such-tenant", "suspended")
    assert store.get_tenant("no-such-tenant") is None


def test_suspension_is_scoped_to_its_tenant(store, tenant, other):
    """The whole control is worthless if it stops the wrong customer."""
    store.set_tenant_status(tenant, "suspended")

    assert store.get_tenant(tenant)["status"] == "suspended"
    assert store.get_tenant(other)["status"] == "active"


# --- agents ---------------------------------------------------------------------


def test_agent_round_trips(store, tenant):
    store.save_agent(tenant, AGENT, actor="system:cli")
    assert store.get_agent(tenant, "issue-reporter")["config"] == AGENT


def test_an_agent_row_carries_every_field_through_both_stores(store, tenant):
    """`AGENT_FIELDS` and nothing else, in both stores — the `RUN_FIELDS` device.

    **This is the assertion 10d could not have shipped without.** Both read methods
    returned `config` alone for eight steps, so `updated_at` — which three handoffs and
    two plans call "the obvious ETag" — was a column nothing above storage could see, and
    the in-memory store had nowhere to keep one at all. A guard built on a field one
    implementation has and the other silently drops is a guard that passes every test and
    protects nothing in production. That is exactly how `audit.credential` shipped.
    """
    from carnet.storage import AGENT_FIELDS

    store.save_agent(tenant, AGENT, actor="system:cli")

    row = store.get_agent(tenant, "issue-reporter")
    assert set(row) == set(AGENT_FIELDS)
    assert (row["tenant_id"], row["name"]) == (tenant, "issue-reporter")
    assert row["created_at"].tzinfo is not None
    assert row["updated_at"] >= row["created_at"]
    # And the list method returns the same shape. Two read methods disagreeing about
    # what a row is would be the drift with extra steps.
    assert set(store.load_agents(tenant)[0]) == set(AGENT_FIELDS)


def test_missing_agent_reads_as_none(store, tenant):
    assert store.get_agent(tenant, "nope") is None


def test_agents_load_ordered_by_name(store, tenant):
    for name in ("zulu", "alpha", "mike"):
        store.save_agent(tenant, {**AGENT, "name": name}, actor="system:cli")

    assert [a["name"] for a in store.load_agents(tenant)] == ["alpha", "mike", "zulu"]


def test_saving_the_same_name_replaces(store, tenant):
    store.save_agent(tenant, AGENT, actor="system:cli")
    store.save_agent(tenant, {**AGENT, "system": "Changed."}, actor="system:cli")

    agents = store.load_agents(tenant)
    assert len(agents) == 1
    assert agents[0]["config"]["system"] == "Changed."


def test_agent_without_a_name_is_refused(store, tenant):
    """The name is the key AND the identity the broker attributes audit records to."""
    with pytest.raises(StorageError):
        store.save_agent(tenant, {"runtime": "simple"}, actor="system:cli")


# --- create, which is not save ---------------------------------------------------
#
# `save_agent` is an upsert and stays one, because `--seed` is documented as safe to
# re-run. Everything below is about the method that is not, and the two properties it
# exists for: a name that is taken is refused, and the owner grant is not a second step.


@pytest.mark.parametrize("name", [
    "Triage Bot",     # the literal thing somebody types into a form
    "TriageBot",      # capitals: two names that sort apart and read the same
    "triage_bot",     # underscore, which is a tool-name convention and not this one
    "-triage",        # leading hyphen
    "triage-",        # trailing
    "triage--bot",    # doubled, which is invisible in a list
    "triage.bot",     # a dot in a path segment reads as an extension
    "a" * 65,         # the length ceiling
])
def test_an_agent_name_must_be_a_slug(store, tenant, name):
    """Migration 019, in both stores.

    Checked on `save_agent` too, and that is the point rather than thoroughness: the
    constraint is on the *column*, so Postgres refuses these on an upsert as well — and a
    fake that accepted one would be more permissive than the real store in the single
    direction memory.py's docstring forbids.
    """
    with pytest.raises(StorageError):
        store.save_agent(tenant, {**AGENT, "name": name}, actor="system:cli")

    with pytest.raises(StorageError):
        store.create_agent(tenant, {**AGENT, "name": name}, "user", "u1")


def test_create_writes_the_agent_and_its_owner(store, tenant):
    store.create_agent(tenant, AGENT, "user", "u-priya")

    assert store.get_agent(tenant, "issue-reporter")["config"] == AGENT
    assert store.agent_grant_role(tenant, "issue-reporter", "user", "u-priya") == "owner"


def test_the_creator_can_run_it_immediately(store, tenant):
    """The property the grant is *for*, asserted through the question a run asks.

    Absence is denial, so an agent created without this is one its author cannot run —
    and the symptom is a 404 that looks exactly like an agent that does not exist.
    """
    store.create_agent(tenant, AGENT, "user", "u-priya")

    assert store.granted_agent_names(tenant, "user", "u-priya") == ["issue-reporter"]


def test_creating_a_name_that_exists_is_refused_and_changes_nothing(store, tenant):
    """The upsert is one line away, and this is the assertion that says which one shipped.

    `save_agent` would return happily here having replaced somebody else's agent, and
    nothing else on that path would notice: `agents.validate` checks configs rather than
    grants, and a write to `agents` consults no grant table at all.
    """
    store.create_agent(tenant, AGENT, "user", "u-priya")

    with pytest.raises(AgentNameTaken):
        store.create_agent(
            tenant,
            {**AGENT, "system": "Mine now.", "permissions": {"tools": [], "scope": {}}},
            "user",
            "u-mallory",
        )

    # Byte-identical, not merely "still there".
    assert store.get_agent(tenant, "issue-reporter")["config"] == AGENT
    # And the second caller took nothing, including a foothold on it.
    assert store.agent_grant_role(tenant, "issue-reporter", "user", "u-mallory") is None
    assert store.agent_grant_role(tenant, "issue-reporter", "user", "u-priya") == "owner"


def test_create_refuses_a_group_as_an_owner(store, tenant):
    """`GROUP_ROLES` says why: an agent owned by a set is an orphan with extra steps.

    Refused before the write rather than by the grant half, so the failure is a sentence
    rather than a rolled-back transaction.
    """
    with pytest.raises(StorageError):
        store.create_agent(tenant, AGENT, "group", "eng")

    assert store.get_agent(tenant, "issue-reporter") is None


def test_create_refuses_an_absent_owner(store, tenant):
    """There is no default owner and there must not be one.

    An owner that can be omitted is an owner that eventually is, and the artifact is an
    agent nobody can run whose row looks perfectly healthy.
    """
    with pytest.raises(StorageError):
        store.create_agent(tenant, AGENT, "user", "")

    assert store.get_agent(tenant, "issue-reporter") is None


def test_create_agent_cannot_be_called_without_an_owner(store, tenant):
    """The signature, asserted rather than assumed.

    Both owner arguments are positional and required in `Storage`, so "create an agent
    and grant it later" is not a thing a caller can express by accident. If this ever
    starts passing, somebody has given them defaults and the four-handoff warning has
    quietly come back.
    """
    with pytest.raises(TypeError):
        store.create_agent(tenant, AGENT)


def test_create_and_save_disagree_about_a_name_that_exists(store, tenant):
    """Both behaviours are correct, for different callers. Asserted together so that
    collapsing them into one method is a test failure rather than a refactor."""
    store.save_agent(tenant, AGENT, actor="system:cli")
    store.save_agent(tenant, {**AGENT, "system": "Replaced."}, actor="system:cli")
    assert store.get_agent(tenant, "issue-reporter")["config"]["system"] == "Replaced."

    with pytest.raises(AgentNameTaken):
        store.create_agent(tenant, AGENT, "user", "u-priya")


# --- update, which is neither create nor save ------------------------------------
#
# The compare-and-set. `save_agent` upserts unconditionally and keeps doing so, because
# `--seed` is documented as safe to re-run and a conditional upsert is a contradiction —
# so "write this" and "write this if nobody else has" are one WHERE clause and one
# catastrophe apart, which is why they are different methods. Same argument that made
# `create_agent` a second one.


def _edit(store, tenant, name="issue-reporter", restored_from=None, **changes):
    """Read the row, then write it back changed. What an edit screen does."""
    row = store.get_agent(tenant, name)
    return store.update_agent(
        tenant,
        {**row["config"], **changes},
        actor="user:u-1",
        if_unchanged_since=row["updated_at"],
        restored_from=restored_from,
    )


def test_update_replaces_the_config_and_advances_the_etag(store, tenant):
    store.save_agent(tenant, AGENT, actor="system:cli")
    before = store.get_agent(tenant, "issue-reporter")

    row = _edit(store, tenant, system="Edited.")

    assert row["config"]["system"] == "Edited."
    assert store.get_agent(tenant, "issue-reporter")["config"]["system"] == "Edited."
    # The ETag moved, which is what makes the *next* stale save detectable. A write that
    # left `updated_at` alone would be a guard that guards exactly once.
    assert row["updated_at"] > before["updated_at"]
    # And `created_at` did not: "when was this agent made" must not mean "when was it
    # last edited".
    assert row["created_at"] == before["created_at"]


def test_a_second_editor_writing_from_a_stale_read_is_refused(store, tenant):
    """**The property this whole step is about, at the layer that can offer it.**

    Two people open the same agent. One narrows its scope and saves. The other saves the
    version they loaded before that — and without the guard it lands, silently reverting
    a permission narrowing with nothing anywhere recording that it happened.

    The interleaving here is sequential, so this asserts the *rule* rather than the
    window. The window is `test_two_editors_and_the_second_is_refused` in
    test_concurrency.py, which is Postgres-only because the in-memory store is too fast
    to expose a race.
    """
    store.save_agent(tenant, AGENT, actor="system:cli")
    stale = store.get_agent(tenant, "issue-reporter")["updated_at"]

    _edit(store, tenant, system="Priya got here first.")

    refused = store.update_agent(
        tenant,
        {**AGENT, "system": "Sam, from a version that is gone."},
        actor="user:u-2",
        if_unchanged_since=stale,
    )

    # None rather than an exception: a lost race is the ordinary shape of concurrency,
    # the same answer `start_run` and `finish_run` give, and the loser needs to report
    # rather than to handle something.
    assert refused is None
    assert store.get_agent(tenant, "issue-reporter")["config"]["system"] == (
        "Priya got here first."
    )


def test_a_refused_update_writes_no_record(store, tenant):
    """The log holds changes, not attempts — the same rule as a revoke of a grant
    nobody had. A record for a save that did not happen makes "who edited this" answer
    with somebody who did not."""
    store.save_agent(tenant, AGENT, actor="system:cli")
    stale = store.get_agent(tenant, "issue-reporter")["updated_at"]
    _edit(store, tenant, system="First.")

    store.update_agent(
        tenant, {**AGENT, "system": "Second."}, actor="user:u-2",
        if_unchanged_since=stale,
    )

    (recorded,) = store.admin_audit_records(tenant, action="agent.update")
    assert recorded["actor_id"] == "u-1"


def test_updating_an_absent_agent_is_none_and_creates_nothing(store, tenant):
    """`update_agent` is not an upsert either. An edit of something that was deleted
    underneath it must not resurrect it — the grants went with the row, so what came back
    would be an agent nobody can run."""
    assert (
        store.update_agent(
            tenant,
            AGENT,
            actor="user:u-1",
            if_unchanged_since=datetime.now(timezone.utc),
        )
        is None
    )
    assert store.get_agent(tenant, "issue-reporter") is None


def test_update_refuses_a_name_that_is_not_a_slug(store, tenant):
    """Migration 019's CHECK is on the column, so every write path is subject to it and
    the fake has to refuse the same names on this one too."""
    store.save_agent(tenant, AGENT, actor="system:cli")
    row = store.get_agent(tenant, "issue-reporter")

    with pytest.raises(StorageError):
        store.update_agent(
            tenant,
            {**AGENT, "name": "Triage Bot"},
            actor="user:u-1",
            if_unchanged_since=row["updated_at"],
        )


# --- config version history ------------------------------------------------------
#
# Migration 032, step 021. The register's only *irrecoverable* row: `agents.config` was
# overwritten in place and `admin_audit` is forbidden from holding a prompt, so every
# edit made before this destroyed the configuration it replaced.
#
# **The first test is the one to read.** Everything below it is a corner of the same
# property: the live config is always the newest version, after every write path, in
# both stores. The counter, the suppression and the `ON CONFLICT` all exist to keep it
# true, and the induction they rest on is asserted rather than trusted.


def _assert_the_live_config_is_the_newest_version(store, tenant, name="issue-reporter"):
    row = store.get_agent(tenant, name)
    newest = store.list_agent_versions(tenant, name)[0]

    assert newest["version"] == row["version"]
    assert store.get_agent_version(tenant, name, row["version"])["config"] == (
        row["config"]
    )
    # The version's timestamp is the agent's, passed in rather than generated a second
    # time — so the ETag a client is holding names a row in the history, and the
    # intervals that answer "what was live on Tuesday" line up with the rows they
    # describe.
    assert newest["created_at"] == row["updated_at"]


# Each path writes to an agent of its own, and that is not decoration. The `tenant`
# fixture truncates its id to 60 characters, so every parametrisation of a test with a
# name this long lands in **one** tenant on Postgres — where the database outlives the
# test — while getting a fresh store in memory. A shared agent would have made the
# `save` case a no-change write over the `create` case's row, which is a Postgres-only
# failure of a test that is green in the fake. Found by running it.
WRITE_PATHS = (
    ("create", lambda s, t, n: s.create_agent(t, {**AGENT, "name": n}, "user", "u-1")),
    ("save", lambda s, t, n: s.save_agent(t, {**AGENT, "name": n}, actor="system:cli")),
    (
        "update",
        lambda s, t, n: (
            s.save_agent(t, {**AGENT, "name": n}, actor="system:cli"),
            _edit(s, t, name=n, system="Edited."),
        ),
    ),
    (
        "restore",
        lambda s, t, n: (
            s.save_agent(t, {**AGENT, "name": n}, actor="system:cli"),
            _edit(s, t, name=n, system="Edited."),
            _edit(s, t, name=n, system=AGENT["system"], restored_from=1),
        ),
    ),
)


@pytest.mark.parametrize("path,write", WRITE_PATHS, ids=[p for p, _ in WRITE_PATHS])
def test_the_live_config_is_always_the_newest_version(store, tenant, path, write):
    """**The invariant the whole step rests on**, after every path that writes a config.

    Parametrised rather than written four times for the reason `IN_SCOPE` is: what this
    guards against is a *fifth* writer added later that stores a config and no version —
    the state in which an edit destroys something again, silently, with every other test
    in this file still green.
    """
    name = f"agent-{path}"
    write(store, tenant, name)
    _assert_the_live_config_is_the_newest_version(store, tenant, name)


def test_a_version_row_carries_every_field_through_both_stores(store, tenant):
    """`AGENT_VERSION_FIELDS`, built from the tuple rather than typed out — the
    `RUN_FIELDS` device, and the drift it catches is a column Postgres keeps and the
    fake drops."""
    store.create_agent(tenant, AGENT, "user", "u-1")

    row = store.get_agent_version(tenant, "issue-reporter", 1)

    assert set(row) == set(AGENT_VERSION_FIELDS)
    assert row["tenant_id"] == tenant
    assert row["agent_name"] == "issue-reporter"
    assert row["version"] == 1
    assert row["config"] == AGENT
    # The owner is the author, for the same reason they are the record's actor.
    assert row["created_by"] == "user:u-1"
    assert row["source"] == "create"
    assert row["restored_from"] is None


def test_a_version_list_carries_the_summary_fields_and_never_a_config(store, tenant):
    """A history card shows dates and authors, and fifty configs down the wire to render
    one is fifty prompts nobody asked for. `API_TOKEN_PUBLIC_FIELDS`' device, here for
    size rather than for secrecy."""
    store.create_agent(tenant, AGENT, "user", "u-1")

    (row,) = store.list_agent_versions(tenant, "issue-reporter")

    assert set(row) == set(AGENT_VERSION_SUMMARY_FIELDS)
    assert "config" not in row


def test_a_write_that_changes_nothing_adds_no_version(store, tenant):
    """`--seed` is documented as safe to re-run, and deployments run it on every boot.
    A version per boot gives the shipped agent a history of nothing — a log that defeats
    the thing it exists for."""
    store.save_agent(tenant, AGENT, actor="system:cli")
    store.save_agent(tenant, AGENT, actor="system:cli")
    store.save_agent(tenant, AGENT, actor="system:cli")

    versions = store.list_agent_versions(tenant, "issue-reporter")
    assert [row["version"] for row in versions] == [1]
    assert store.get_agent(tenant, "issue-reporter")["version"] == 1


def test_a_config_whose_keys_are_merely_reordered_is_not_a_change(store, tenant):
    """**The parity trap in the one line that looks obviously equivalent.**

    Postgres compares `jsonb IS DISTINCT FROM jsonb`, which is a comparison of parsed
    documents: key order and whitespace are not part of what a `jsonb` value is. The
    fake has to compare dicts for the same reason — and comparing `json.dumps(...)`
    there, which reads as the same thing, would make the fake see a change Postgres does
    not and write a version Postgres would not.

    A client reserialising a config it read is not exotic: it is what every JSON round
    trip through a form does.
    """
    store.save_agent(tenant, AGENT, actor="system:cli")
    reordered = dict(reversed(list(AGENT.items())))
    assert list(reordered) != list(AGENT), "the fixture no longer exercises key order"

    store.save_agent(tenant, reordered, actor="system:cli")

    assert [
        row["version"] for row in store.list_agent_versions(tenant, "issue-reporter")
    ] == [1]


def test_a_no_change_edit_adds_no_version_and_still_moves_the_etag(store, tenant):
    """The division of labour, in one test: the history holds **states**, the log holds
    **writes**, and `updated_at` keeps behaving exactly as 10d decided.

    A save that writes back what is already there still advances the ETag — which is
    what invalidates other people's open forms, and is deliberately not re-decided by
    this step."""
    store.save_agent(tenant, AGENT, actor="system:cli")
    before = store.get_agent(tenant, "issue-reporter")

    row = _edit(store, tenant)

    assert row["updated_at"] > before["updated_at"]
    assert row["version"] == before["version"]
    assert len(store.list_agent_versions(tenant, "issue-reporter")) == 1
    # So the two timestamps deliberately come apart here, and this is the one place they
    # do: the version was stamped when the config last *changed*, and the agent when it
    # was last *written*. Any reader treating `updated_at` as "when this version was
    # made" is wrong by exactly the no-op saves in between.
    assert store.list_agent_versions(tenant, "issue-reporter")[0]["created_at"] < (
        row["updated_at"]
    )
    # And the write is in the log, which is where "who saved this, and when" lives.
    assert len(store.admin_audit_records(tenant, action="agent.update")) == 1


def test_a_config_returning_to_an_earlier_one_is_a_new_version(store, tenant):
    """A → B → A is **three** versions.

    Suppression is *"this write changed nothing"*, never *"we have seen this config
    before"*. De-duplicating across a history would destroy the ordering that answers
    what was live at a past instant — and it is the objection `schemas.py` already
    records against a config hash: a hash cannot tell *changed* from *changed and
    changed back*."""
    store.save_agent(tenant, AGENT, actor="system:cli")
    _edit(store, tenant, system="B.")
    _edit(store, tenant, system=AGENT["system"])

    versions = store.list_agent_versions(tenant, "issue-reporter")

    assert [row["version"] for row in versions] == [3, 2, 1]
    assert store.get_agent_version(tenant, "issue-reporter", 3)["config"] == (
        store.get_agent_version(tenant, "issue-reporter", 1)["config"]
    )


def test_a_restore_names_the_version_it_came_from(store, tenant):
    """One parameter decides three things, so they cannot disagree: the source, the
    administrative action, and the pointer back. Migration 032 states the same rule as a
    CHECK."""
    store.save_agent(tenant, AGENT, actor="system:cli")
    _edit(store, tenant, system="Broke it.")

    _edit(store, tenant, system=AGENT["system"], restored_from=1)

    newest = store.get_agent_version(tenant, "issue-reporter", 3)
    assert newest["source"] == "restore"
    assert newest["restored_from"] == 1
    assert store.admin_audit_records(tenant)[-1]["action"] == "agent.restore"


def test_a_restore_of_the_live_version_adds_nothing(store, tenant):
    """It is an ordinary no-change write and takes the ordinary branch. A restore that
    appended a copy of what is already live would make the history a log of clicks."""
    store.save_agent(tenant, AGENT, actor="system:cli")

    row = _edit(store, tenant, restored_from=1)

    assert row["version"] == 1
    assert len(store.list_agent_versions(tenant, "issue-reporter")) == 1


def test_a_lost_race_writes_no_version(store, tenant):
    """The compare-and-set refused, so no configuration was written — and a history row
    for a config that never went live is worse than none, because the next restore would
    offer it."""
    store.save_agent(tenant, AGENT, actor="system:cli")
    stale = store.get_agent(tenant, "issue-reporter")["updated_at"]
    _edit(store, tenant, system="Priya got here first.")

    refused = store.update_agent(
        tenant,
        {**AGENT, "system": "Sam, from a version that is gone."},
        actor="user:u-2",
        if_unchanged_since=stale,
    )

    assert refused is None
    stored = [
        store.get_agent_version(tenant, "issue-reporter", version)["config"]["system"]
        for version in (1, 2)
    ]
    assert stored == ["You read issues.", "Priya got here first."]
    assert store.get_agent_version(tenant, "issue-reporter", 3) is None


def test_versions_come_back_newest_first_and_capped(store, tenant):
    """Newest first, because that is the order a history is read in. Capped, because
    every list in this system is — section D's pagination row owns that for all of them
    at once, and a second convention here would make it two problems."""
    store.save_agent(tenant, AGENT, actor="system:cli")
    for n in range(2, 7):
        _edit(store, tenant, system=f"Edit {n}.")

    versions = store.list_agent_versions(tenant, "issue-reporter")
    assert [row["version"] for row in versions] == [6, 5, 4, 3, 2, 1]
    assert [
        row["version"]
        for row in store.list_agent_versions(tenant, "issue-reporter", limit=2)
    ] == [6, 5]


def test_deleting_an_agent_deletes_its_history(store, tenant):
    """A cascade in Postgres and a hand-written loop in the fake — which is the half
    that can silently not happen, and is why this lives here rather than in a
    Postgres-only file. `delete_agent` learnt the same lesson about `agent_grants`."""
    store.save_agent(tenant, AGENT, actor="system:cli")
    _edit(store, tenant, system="Edited.")

    store.delete_agent(tenant, "issue-reporter", actor="user:u-1")

    assert store.list_agent_versions(tenant, "issue-reporter") == []
    assert store.get_agent_version(tenant, "issue-reporter", 1) is None


# --- rename, step 025 ----------------------------------------------------------------
#
# **The block that says what migration 035 bought.** Every test here would have been
# unwritable before it: `agents` was keyed by name, so the only way to change one was to
# create a second agent and delete the first — which cascades away the grants, the pending
# grants, the schedules, the triggers and the whole version history, and orphans the run
# history from every listing. There was no rename to test.


def test_a_rename_keeps_the_agent_and_moves_its_name(store, tenant):
    """The row is the same row: same `agent_id`, same `created_at`, a new name."""
    store.save_agent(tenant, AGENT, actor="system:cli")
    before = store.get_agent(tenant, "issue-reporter")

    renamed = store.rename_agent(
        tenant, "issue-reporter", "issue-triage", actor="user:u-1"
    )

    assert renamed["name"] == "issue-triage"
    assert renamed["agent_id"] == before["agent_id"]
    assert renamed["created_at"] == before["created_at"]
    # The config's copy moves with the column. Migration 002's
    # `agent_name_matches_config` is still on the table, so a row where these disagree is
    # one Postgres refuses — and the broker reads the config's copy as the agent's
    # identity, so a stale one would misattribute every audit record it went on to write.
    assert renamed["config"]["name"] == "issue-triage"

    assert store.get_agent(tenant, "issue-triage") is not None
    assert store.get_agent(tenant, "issue-reporter") is None


def test_a_rename_advances_the_etag_and_the_version(store, tenant):
    """A rename changes the config, so it is a state the history has to hold."""
    store.save_agent(tenant, AGENT, actor="system:cli")
    before = store.get_agent(tenant, "issue-reporter")

    renamed = store.rename_agent(
        tenant, "issue-reporter", "issue-triage", actor="user:u-1"
    )

    assert renamed["version"] == before["version"] + 1
    assert renamed["updated_at"] > before["updated_at"]


def test_a_renamed_agent_keeps_its_whole_history_under_the_new_name(store, tenant):
    """**The property `agent_versions` was re-keyed for.**

    The history is the agent's, not the name's: every version written before the rename is
    still there, still numbered from 1, and the rename itself is the newest entry with
    `source` `rename`. Under the old key this was impossible — the rows were keyed by the
    name they were written under, so the history either stayed behind or had to be
    rewritten.
    """
    store.save_agent(tenant, AGENT, actor="system:cli")
    _edit(store, tenant, system="Edited before the rename.")

    store.rename_agent(tenant, "issue-reporter", "issue-triage", actor="user:u-1")

    versions = store.list_agent_versions(tenant, "issue-triage")
    assert [row["version"] for row in versions] == [3, 2, 1]
    assert versions[0]["source"] == "rename"
    assert versions[0]["created_by"] == "user:u-1"
    # And the old prompt is still readable at its old number.
    assert store.get_agent_version(tenant, "issue-triage", 1)["config"]["system"] == (
        AGENT["system"]
    )
    # Nothing answers to the old name any more, including its history.
    assert store.list_agent_versions(tenant, "issue-reporter") == []


def test_a_versions_agent_name_is_what_the_agent_is_called_now(store, tenant):
    """`agent_name` on a version row is derived, so it follows the rename.

    The *config* inside the version keeps the historical name — that is a snapshot of what
    was written — and the row's `agent_name` is the join. The two disagreeing is what a
    correct history looks like after a rename, and it is why migration 035 dropped
    `agent_version_name_matches_config` rather than re-keying it.
    """
    store.save_agent(tenant, AGENT, actor="system:cli")
    store.rename_agent(tenant, "issue-reporter", "issue-triage", actor="user:u-1")

    first = store.get_agent_version(tenant, "issue-triage", 1)
    assert first["agent_name"] == "issue-triage"
    assert first["config"]["name"] == "issue-reporter"


def test_a_rename_keeps_every_grant(store, tenant):
    """**What a delete-and-recreate destroyed.** The grants are attached to the id."""
    store.create_agent(tenant, AGENT, "user", "u-1")
    store.grant_agent(tenant, "issue-reporter", "user", "u-2", "editor", actor="user:u-1")

    store.rename_agent(tenant, "issue-reporter", "issue-triage", actor="user:u-1")

    holders = {
        (row["grantee_kind"], row["grantee_id"], row["role"])
        for row in store.list_agent_grants(tenant, "issue-triage")
    }
    assert holders == {("user", "u-1", "owner"), ("user", "u-2", "editor")}
    assert store.agent_grant_role(tenant, "issue-triage", "user", "u-2") == "editor"
    # And the listing a person's screens are built from names the agent as it is now.
    assert store.granted_agent_names(tenant, "user", "u-2") == ["issue-triage"]
    assert store.list_agent_grants(tenant, "issue-reporter") == []


def test_a_rename_keeps_a_pending_grant(store, tenant):
    """A share addressed to somebody who has not logged in yet survives the rename, and
    lands on the agent — under its new name — whenever they arrive."""
    store.create_agent(tenant, AGENT, "user", "u-1")
    store.add_pending_grant(
        tenant, "issue-reporter", "later@acme.com", "editor", actor="user:u-1"
    )

    store.rename_agent(tenant, "issue-reporter", "issue-triage", actor="user:u-1")

    waiting = store.list_pending_grants(tenant, "issue-triage")
    assert [row["email"] for row in waiting] == ["later@acme.com"]
    assert waiting[0]["agent_name"] == "issue-triage"

    claimed = store.claim_pending_grants(tenant, "later@acme.com", "user", "u-3")
    assert claimed == ["issue-triage"]
    assert store.agent_grant_role(tenant, "issue-triage", "user", "u-3") == "editor"


def test_a_rename_keeps_its_schedules_and_triggers(store, tenant):
    """Standing configuration survives, and the listings show the new name.

    Both tables hold the agent as an ordinary column keyed by id, so a rename writes
    neither row — and both listings are joined, so both report the rename without anybody
    having updated them.
    """
    _schedule_for(store, tenant, "m-1", "sch-1")
    _trigger_for(store, tenant, "m-1", "trg-1")

    store.rename_agent(tenant, "issue-reporter", "issue-triage", actor="user:u-1")

    schedules = store.list_schedules(tenant, agent_name="issue-triage")
    assert [row["id"] for row in schedules] == ["sch-1"]
    assert schedules[0]["agent_name"] == "issue-triage"
    assert store.get_schedule(tenant, "sch-1")["agent_name"] == "issue-triage"

    triggers = store.list_triggers(tenant, agent_name="issue-triage")
    assert [row["id"] for row in triggers] == ["trg-1"]
    assert triggers[0]["agent_name"] == "issue-triage"
    # The door's own read, which resolves without a tenant, sees it too.
    assert store.find_trigger("trg-1")["agent_name"] == "issue-triage"

    # And nothing is left answering to the old name.
    assert store.list_schedules(tenant, agent_name="issue-reporter") == []
    assert store.list_triggers(tenant, agent_name="issue-reporter") == []


def test_a_rename_to_a_taken_name_is_refused_and_changes_nothing(store, tenant):
    """`agents_name_unique`, and `create_agent`'s refusal for `create_agent`'s reason:
    two agents cannot answer one URL."""
    store.save_agent(tenant, AGENT, actor="system:cli")
    store.save_agent(tenant, {**AGENT, "name": "billing"}, actor="system:cli")
    before = store.get_agent(tenant, "issue-reporter")

    with pytest.raises(AgentNameTaken, match="already has an agent called 'billing'"):
        store.rename_agent(tenant, "issue-reporter", "billing", actor="user:u-1")

    # Nothing moved: not the row, not its version, not the other agent.
    after = store.get_agent(tenant, "issue-reporter")
    assert after == before
    assert store.get_agent(tenant, "billing")["config"]["name"] == "billing"
    assert [row["version"] for row in store.list_agent_versions(tenant, "issue-reporter")] == [1]


def test_a_rename_to_the_same_name_is_refused_rather_than_a_no_op(store, tenant):
    """Step 025 decision 4. A request that asks for nothing is a mistake, and succeeding
    at it silently would write a version row arguing about whether anything happened."""
    store.save_agent(tenant, AGENT, actor="system:cli")

    with pytest.raises(ValueRefused, match="is already called that"):
        store.rename_agent(
            tenant, "issue-reporter", "issue-reporter", actor="user:u-1"
        )

    assert [row["version"] for row in store.list_agent_versions(tenant, "issue-reporter")] == [1]


def test_renaming_an_agent_that_is_not_there_is_none(store, tenant):
    """`None` is absence and nothing else here — unlike `update_agent`, where it is also
    a lost race. It is also what the second of two concurrent renames gets."""
    assert (
        store.rename_agent(tenant, "ghost", "still-a-ghost", actor="user:u-1") is None
    )


def test_a_rename_to_a_name_the_column_refuses_writes_nothing(store, tenant):
    """`check_agent_name`, reached through the rename rather than through a create.

    Both stores refuse before anything moves, which is the property the fake has to hold
    without a transaction — 021 defect 3's rule.
    """
    store.save_agent(tenant, AGENT, actor="system:cli")

    with pytest.raises(StorageError, match="not a usable agent name"):
        store.rename_agent(tenant, "issue-reporter", "Triage Bot", actor="user:u-1")

    assert store.get_agent(tenant, "issue-reporter") is not None
    assert [row["version"] for row in store.list_agent_versions(tenant, "issue-reporter")] == [1]


def test_a_rename_records_where_the_name_came_from(store, tenant):
    """**The only row that joins an agent's two names.**

    Migration 035 leaves `audit`, `admin_audit` and the denial log holding whatever the
    agent was called at the time, deliberately — so an incident spanning a rename is
    reconstructed through this record's `from`/`to` or not at all. `target_id` is the new
    name, because that is what somebody reading forwards is looking for.
    """
    store.save_agent(tenant, AGENT, actor="system:cli")
    store.rename_agent(tenant, "issue-reporter", "issue-triage", actor="user:u-9")

    record = [
        row
        for row in store.admin_audit_records(tenant)
        if row["action"] == "agent.rename"
    ][-1]
    assert record["target_kind"] == "agent"
    assert record["target_id"] == "issue-triage"
    assert record["actor_id"] == "u-9"
    assert record["detail"]["from"] == "issue-reporter"
    assert record["detail"]["to"] == "issue-triage"


def test_a_recreated_name_starts_a_new_history(store, tenant):
    """The consequence of that cascade, and the argument for it: a kept history would open
    the first author's prompts under a name somebody else merely reused.

    **Migration 035 retired that argument and left the behaviour.** The key is no longer
    the name, so a re-created `issue-reporter` is a different `agent_id` and could not have
    inherited the history even if the cascade forgot to run. What the cascade is for now is
    the plainer thing: erasing an agent erases it.
    """
    store.save_agent(tenant, AGENT, actor="system:cli")
    _edit(store, tenant, system="The first author's.")
    store.delete_agent(tenant, "issue-reporter", actor="user:u-1")

    store.create_agent(tenant, AGENT, "user", "u-2")

    versions = store.list_agent_versions(tenant, "issue-reporter")
    assert [row["version"] for row in versions] == [1]
    assert versions[0]["created_by"] == "user:u-2"
    assert store.get_agent(tenant, "issue-reporter")["version"] == 1


def test_a_create_refused_for_a_taken_name_writes_no_version(store, tenant):
    """`create_agent` refuses a name that exists, and the refusal must not leave a
    version behind claiming the second author's config was live.

    **What this does not catch, recorded rather than left to be discovered.** Writing the
    version *before* the name check was mutated in and the test still passed — and it is
    **equivalent, not uncaught**: the only name that can collide already holds version 1,
    so a premature write conflicts with it and keeps the row that is there. The property
    is held twice over, by the transaction and by the keep-existing rule, and no single
    mutation of either makes it observable. 019 recorded the same shape about
    `prune_floor`.

    It stays because the property is the one that matters — a history entry for a config
    that was never stored is the one artifact `list_agent_versions` must never offer for
    restore — and because the second author's *config* being absent is a real assertion
    even where the row's existence is over-determined.
    """
    store.create_agent(tenant, AGENT, "user", "u-1")

    with pytest.raises(AgentNameTaken):
        store.create_agent(
            tenant, {**AGENT, "system": "the second author's"}, "user", "u-2"
        )

    versions = store.list_agent_versions(tenant, "issue-reporter")
    assert [(row["version"], row["created_by"]) for row in versions] == [(1, "user:u-1")]
    assert store.get_agent_version(tenant, "issue-reporter", 1)["config"] == AGENT


def test_deleting_a_tenant_takes_the_version_history_with_it(store, tenant):
    """**And this needs its own test, which the plan said it would not.**

    `test_deleting_a_tenant_leaves_nothing_behind_anywhere` walks
    `information_schema` for tables with a foreign key **to `tenants(id)`** — and this
    table has none. It references `agents(tenant_id, name)`, so it reaches a tenant only
    transitively and the walk cannot see it, exactly as it cannot see `agent_grants`.
    The plan claimed that walk would prove this cascade; it does not, and the correction
    is this test rather than a wider walk, because widening it is a change to the
    assertion five other steps rely on.

    Two chains have to hold for this to pass: `tenants` → `agents` (migration 002) and
    `agents` → `agent_versions` (032). In the fake there is no chain at all, only the
    loop in `delete_tenant` that has to name this collection.
    """
    store.save_agent(tenant, AGENT, actor="system:cli")
    _edit(store, tenant, system="Edited.")
    store.set_tenant_status(tenant, "suspended")

    store.delete_tenant(tenant, actor=TEST_ACTOR)

    assert store.list_agent_versions(tenant, "issue-reporter") == []
    assert store.get_agent_version(tenant, "issue-reporter", 1) is None


def test_history_of_an_absent_agent_is_empty_rather_than_an_error(store, tenant):
    """`load_agents`' shape. Absence is the caller's question, and the route above has to
    keep an absent agent and an ungranted one indistinguishable."""
    assert store.list_agent_versions(tenant, "nothing-here") == []
    assert store.get_agent_version(tenant, "nothing-here", 1) is None


def test_an_unknown_version_is_none(store, tenant):
    store.save_agent(tenant, AGENT, actor="system:cli")

    assert store.get_agent_version(tenant, "issue-reporter", 2) is None
    assert store.get_agent_version(tenant, "issue-reporter", 0) is None
    assert store.get_agent_version(tenant, "issue-reporter", -1) is None


def test_one_tenants_history_is_not_anothers(store, tenant, other):
    """Every read here filters on `tenant_id`, and a table this new is the one somebody
    forgets."""
    store.save_agent(tenant, AGENT, actor="system:cli")

    assert store.list_agent_versions(other, "issue-reporter") == []
    assert store.get_agent_version(other, "issue-reporter", 1) is None


def test_a_version_source_nothing_writes_is_refused(store, tenant):
    """`VERSION_SOURCES` is a frozenset with no CHECK behind it — migration 022's
    reasoning for `ADMIN_ACTIONS` — so this refusal *is* the constraint, and both stores
    have to make it."""
    from carnet.storage.base import check_version_source

    with pytest.raises(StorageError):
        check_version_source("restored")


def test_a_group_that_does_not_exist_is_its_own_refusal(store, tenant):
    """**A class, not a bare `StorageError`, and the reason is a status code.**

    Every other `StorageError` means the store is broken and answers **503**. This one
    means the store is working and the caller named a group that is not there — and until
    it had a class, `PUT /agents/{name}/grants/group/nope` answered *"storage
    unavailable"*, telling somebody to try again later about an id that will never exist.

    The same mistake `AgentNameTaken` was given a class to fix, arriving through routes
    that did not exist when that reasoning was written. Found by running the grant routes
    at their edges rather than by a test — see `scripts/e2e_edges.py`.

    There is no foreign key for it and cannot be: `grantee_id` means a different table
    depending on the column beside it, so both stores raise this and the contract suite is
    what keeps the two refusals the same one.
    """
    _agent_for(store, tenant)

    with pytest.raises(NoSuchGroupError):
        store.grant_agent(tenant, "issue-reporter", "group", "nope", actor="user:u-1")

    with pytest.raises(NoSuchGroupError):
        store.add_group_member(tenant, "nope", "user", "u-2", actor="user:u-1")

    # Still a StorageError, so nothing that catches the base class stops working.
    assert issubclass(NoSuchGroupError, StorageError)


def test_deleting_an_absent_agent_is_not_an_error(store, tenant):
    store.delete_agent(tenant, "never-existed", actor="system:cli")


def test_delete_removes_the_agent(store, tenant):
    store.save_agent(tenant, AGENT, actor="system:cli")
    store.delete_agent(tenant, "issue-reporter", actor="system:cli")
    assert store.get_agent(tenant, "issue-reporter") is None


def test_writing_to_an_unknown_tenant_is_refused(store):
    """A real foreign key. The fake must not be more permissive than the column."""
    with pytest.raises(UnknownTenantError):
        store.save_agent("no-such-tenant", AGENT, actor="system:cli")


def test_reading_an_unknown_tenant_is_empty_not_an_error(store):
    assert store.load_agents("no-such-tenant") == []


# --- isolation ------------------------------------------------------------------


def test_agents_are_invisible_across_tenants(store, tenant, other):
    store.save_agent(tenant, AGENT, actor="system:cli")

    assert store.get_agent(other, "issue-reporter") is None
    assert store.load_agents(other) == []


def test_same_agent_name_in_two_tenants_are_different_rows(store, tenant, other):
    store.save_agent(tenant, {**AGENT, "system": "A."}, actor="system:cli")
    store.save_agent(other, {**AGENT, "system": "B."}, actor="system:cli")

    assert store.get_agent(tenant, "issue-reporter")["config"]["system"] == "A."
    assert store.get_agent(other, "issue-reporter")["config"]["system"] == "B."


# --- copying: the way an in-memory fake lies ------------------------------------


def test_mutating_a_returned_config_does_not_change_the_store(store, tenant):
    store.save_agent(tenant, AGENT, actor="system:cli")

    loaded = store.get_agent(tenant, "issue-reporter")
    loaded["config"]["permissions"]["tools"].append("smuggled_tool")

    assert store.get_agent(tenant, "issue-reporter")["config"]["permissions"]["tools"] == [
        "post_message"
    ]


def test_mutating_the_input_after_saving_does_not_change_the_store(store, tenant):
    config = {
        "name": "mutable",
        "permissions": {"tools": ["post_message"], "scope": {}},
    }
    store.save_agent(tenant, config, actor="system:cli")
    config["permissions"]["tools"].append("smuggled_tool")

    assert store.get_agent(tenant, "mutable")["config"]["permissions"]["tools"] == [
        "post_message"
    ]


def test_mutating_a_loaded_list_does_not_change_the_store(store, tenant):
    store.save_agent(tenant, AGENT, actor="system:cli")

    agents = store.load_agents(tenant)
    agents[0]["config"]["name"] = "renamed"

    assert store.load_agents(tenant)[0]["config"]["name"] == "issue-reporter"


# --- connectors -----------------------------------------------------------------


def test_connector_round_trips(store, tenant):
    store.save_connector(tenant, MANIFEST, actor=TEST_ACTOR)
    assert store.get_connector(tenant, "github-mcp") == MANIFEST


def test_asserted_identity_toggles_and_round_trips(store, tenant):
    """033c. False at creation — the posture — and each toggle both changes the row
    and writes its own administrative record naming the actor and the new value."""
    store.create_connector(tenant, "jira", launch=_HTTP_LAUNCH, actor="user:u-1")
    assert store.get_connector(tenant, "jira")["allow_asserted_identity"] is False

    store.set_asserted_identity(tenant, "jira", True, actor="user:u-1")
    assert store.get_connector(tenant, "jira")["allow_asserted_identity"] is True

    store.set_asserted_identity(tenant, "jira", False, actor="user:u-2")
    assert store.get_connector(tenant, "jira")["allow_asserted_identity"] is False

    records = store.admin_audit_records(tenant, action="connector.asserted_identity")
    assert [
        (r["actor_id"], r["detail"]["allow_asserted_identity"]) for r in records
    ] == [
        ("u-1", True),
        ("u-2", False),
    ]


def test_asserted_identity_can_be_set_at_creation_and_the_record_says_so(store, tenant):
    store.create_connector(
        tenant, "jira", launch=_HTTP_LAUNCH, allow_asserted_identity=True, actor="user:u-1"
    )

    assert store.get_connector(tenant, "jira")["allow_asserted_identity"] is True
    (created,) = store.admin_audit_records(tenant, action="connector.create")
    assert created["detail"]["allow_asserted_identity"] is True


def test_the_wholesale_save_replaces_the_flag_in_the_closed_direction(store, tenant):
    """`save_connector`'s contract is wholesale, and a manifest that never mentions the
    flag writes False — a re-seed disables trust rather than quietly extending it."""
    store.save_connector(tenant, MANIFEST, actor=TEST_ACTOR)
    store.set_asserted_identity(tenant, "github-mcp", True, actor="user:u-1")

    store.save_connector(tenant, {k: v for k, v in MANIFEST.items() if k != "allow_asserted_identity"}, actor=TEST_ACTOR)

    assert store.get_connector(tenant, "github-mcp")["allow_asserted_identity"] is False


def test_trust_in_a_caller_needs_a_connector_to_exist(store, tenant):
    """Refused with a sentence, and the administrative log records nothing — a log
    line for a change that never happened would be the record lying in the more
    dangerous direction."""
    with pytest.raises(NoSuchConnectorError, match="Register the connector first"):
        store.set_asserted_identity(tenant, "ghost", True, actor="user:u-1")

    assert store.admin_audit_records(tenant, action="connector.asserted_identity") == []


def test_a_vetted_row_carries_every_field_through_both_stores(store, tenant):
    """The expectation is built from `VETTED_TOOL_FIELDS`, not typed out here.

    `audit.credential` shipped written by Postgres and silently dropped by the fake,
    with 818 tests green, because the fake keeps whatever dict it is handed and the
    real table has columns. The equality test above would catch that only if somebody
    remembered to extend `MANIFEST`; this one fails the moment a field is added to one
    implementation and not the other.
    """
    store.save_connector(tenant, MANIFEST, actor=TEST_ACTOR)

    for row in store.get_connector(tenant, "github-mcp")["vetted"]:
        assert set(row) == VETTED_TOOL_FIELDS


def test_the_one_at_a_time_write_path_keeps_a_note_and_a_ceiling(store, tenant):
    """035g, and the check gotcha 2 asks for — a **contract test rather than a grep**.

    The chunk adds no storage method, and 035f's finding 4 is why a grep is not the
    answer for a projection: a grep proves the code says the same thing twice, and only
    this proves the two stores *answer* the same thing. Both fields have been on
    `VETTED_TOOL_DEFAULTS` since 012 and no test had ever written a **non-default** value
    through `vet_tool`, which is the route's own write path — the key-set test above would
    pass with either store storing `None` for both.

    Which matters now because 035g is the first thing to put an input on either: a note
    that silently became `""` would be an administrator's sentence lost, and a ceiling
    that silently became `None` would be a tool quietly reverting to the platform default
    with nobody told.
    """
    store.create_connector(tenant, "jira", launch=_HTTP_LAUNCH, actor=TEST_ACTOR)
    store.vet_tool(
        tenant,
        "jira",
        {
            "remote_name": "search_issues",
            "effect": "read",
            "note": "Finance owns this project.",
            "max_response_bytes": 200_000,
        },
        actor=TEST_ACTOR,
    )

    (row,) = store.get_connector(tenant, "jira")["vetted"]

    assert row["note"] == "Finance owns this project."
    assert row["max_response_bytes"] == 200_000


def test_a_credential_reference_round_trips_through_both_write_paths(store, tenant):
    """070, and it is here because nothing else put it in front of Postgres.

    `credential_ref` lives in `connectors.launch`, which is **JSONB** — which is why the
    step needed no migration and is also why the in-memory store, holding a Python dict,
    cannot tell you the real one agrees. That is this file's whole subject: *the fake
    quietly permits what Postgres would refuse*, and a `None` that round-trips as `null`
    and back is exactly the shape that goes wrong silently.

    The value that matters is the **absent** one: every connector registered before this
    step has no `credential_ref` key at all, and `_launch_from_dict` must read that as
    None rather than as an empty reference — an empty reference would make
    `_shared_credential` take the pointer branch and refuse every call on a connector
    nobody touched.
    """
    reference = "op://Engineering/GitHub Deploy Key/credential"
    launch = {**_HTTP_LAUNCH, "credential_env": None, "credential_ref": reference}

    store.create_connector(tenant, "vaulted", launch=launch, actor=TEST_ACTOR)
    assert store.get_connector(tenant, "vaulted")["launch"] == launch

    # The wholesale writer too — two serializers for one shape is how `--seed` and
    # `--add-connector` stop agreeing, which is 045a's lesson at a new field.
    store.save_connector(
        tenant, {"id": "vaulted-two", "launch": launch, "vetted": []}, actor=TEST_ACTOR
    )
    assert store.get_connector(tenant, "vaulted-two")["launch"] == launch

    # And a row written before the field existed: the key is absent, not null.
    store.create_connector(tenant, "older", launch=_HTTP_LAUNCH, actor=TEST_ACTOR)
    stored = store.get_connector(tenant, "older")["launch"]
    assert "credential_ref" not in stored

    from carnet.tools.mcp.binding import _launch_from_dict

    assert _launch_from_dict(stored).credential_ref is None
    assert _launch_from_dict(launch).credential_ref == reference


def test_a_rest_binding_round_trips_through_both_write_paths(store, tenant):
    """045a. The binding survives `vet_tool` (one at a time) and `save_connector`
    (wholesale) identically — two serializers for one shape is how `--seed` and
    `--vet` stop agreeing about a `usage_map`."""
    store.create_connector(tenant, "tracker", launch=_REST_LAUNCH, actor=TEST_ACTOR)
    store.vet_tool(
        tenant,
        "tracker",
        {"remote_name": "list_issues", "effect": "read", "binding": _BINDING},
        actor=TEST_ACTOR,
    )
    (row,) = store.get_connector(tenant, "tracker")["vetted"]
    assert row["binding"] == _BINDING
    assert set(row) == VETTED_TOOL_FIELDS

    manifest = {
        "id": "tracker-two",
        "launch": _REST_LAUNCH,
        "vetted": [{"remote_name": "list_issues", "effect": "read", "binding": _BINDING}],
    }
    store.save_connector(tenant, manifest, actor=TEST_ACTOR)
    (row,) = store.get_connector(tenant, "tracker-two")["vetted"]
    assert row["binding"] == _BINDING


def test_a_redaction_policy_round_trips_through_both_write_paths(store, tenant):
    """045c, migration 049. What a tool keeps out of the audit log is a stored approval,
    so it has to survive both writers identically — and the failure it prevents is the
    quiet one: a policy dropped on the way to the row reads as approved and logs every
    prompt in the clear, in a table with no UPDATE."""
    store.create_connector(tenant, "jira", launch=_HTTP_LAUNCH, actor=TEST_ACTOR)
    store.vet_tool(
        tenant,
        "jira",
        {"remote_name": "ask", "effect": "read", "redact_args": ["messages", "system"]},
        actor=TEST_ACTOR,
    )
    (row,) = store.get_connector(tenant, "jira")["vetted"]
    assert row["redact_args"] == ["messages", "system"]

    manifest = {
        "id": "jira-two",
        "launch": _HTTP_LAUNCH,
        "vetted": [
            {"remote_name": "ask", "effect": "read", "redact_args": ["messages"]}
        ],
    }
    store.save_connector(tenant, manifest, actor=TEST_ACTOR)
    (row,) = store.get_connector(tenant, "jira-two")["vetted"]
    assert row["redact_args"] == ["messages"]


def test_a_row_written_without_a_redaction_policy_reads_back_as_none_redacted(
    store, tenant
):
    """`[]` rather than NULL, and the difference from `binding` is that there is no *not
    applicable* here: every tool has an answer to what of a call is written down, and for
    a row predating migration 049 that answer is *all of it* — which is what `[]` says."""
    store.create_connector(tenant, "jira", launch=_HTTP_LAUNCH, actor=TEST_ACTOR)
    store.vet_tool(
        tenant, "jira", {"remote_name": "ask", "effect": "read"}, actor=TEST_ACTOR
    )

    (row,) = store.get_connector(tenant, "jira")["vetted"]
    assert row["redact_args"] == []


def test_a_tuple_normalizes_to_a_list_in_both_stores(store, tenant):
    """**Two stores must answer the same *type* for one write**, which is what
    `normalize_vetted_tool` exists for and what it used to miss.

    A tuple came back a tuple from memory and a **list** from Postgres, because the
    Postgres row round-trips through `json.dumps`. Latent on `resources` since the
    function was written and reachable the moment 045c added `redact_args`, because
    `Vetted.redact_args` *is* a tuple — so the obvious call, handing the field straight
    to `vet_tool`, produced the divergence. Found by driving both stores, not by
    reading.
    """
    store.create_connector(tenant, "jira", launch=_HTTP_LAUNCH, actor=TEST_ACTOR)
    store.vet_tool(
        tenant,
        "jira",
        {"remote_name": "ask", "effect": "read", "redact_args": ("messages",),
         "resources": ()},
        actor=TEST_ACTOR,
    )

    (row,) = store.get_connector(tenant, "jira")["vetted"]
    assert row["redact_args"] == ["messages"]
    assert isinstance(row["redact_args"], list)
    assert isinstance(row["resources"], list)


def test_a_resources_families_tuple_normalizes_to_a_list_in_both_stores(store, tenant):
    """The same split, one level down, on a field added by step 086 rather than found in
    one. `vetted_to_dict` already writes a list, so what this catches is the wholesale
    writer — `--seed`, a recipe applied in one call — and a new field is the wrong place
    to add a second instance of a known divergence."""
    store.create_connector(tenant, "jira", launch=_HTTP_LAUNCH, actor=TEST_ACTOR)
    store.vet_tool(
        tenant,
        "jira",
        {
            "remote_name": "ask",
            "effect": "read",
            "resources": [{"type": "vendor.model", "args": ["model"], "families": ("a", "b")}],
        },
        actor=TEST_ACTOR,
    )

    (row,) = store.get_connector(tenant, "jira")["vetted"]
    assert row["resources"][0]["families"] == ["a", "b"]
    assert isinstance(row["resources"][0]["families"], list)


def test_a_blank_family_is_refused_at_the_boundary(store, tenant):
    """The shape only, on the redaction policy's test directly below: a family list that
    is a string or holds a blank would be stored fine and fail at the next bind. A blank
    is refused *here* rather than only one layer up because of what it would do if it
    reached a matcher — an empty token run is inside every identifier, so one scope line
    naming it would admit every model on the connector."""
    store.create_connector(tenant, "jira", launch=_HTTP_LAUNCH, actor=TEST_ACTOR)
    with pytest.raises(StorageError, match="every identifier answers to"):
        store.vet_tool(
            tenant,
            "jira",
            {
                "remote_name": "ask",
                "effect": "read",
                "resources": [{"type": "vendor.model", "args": ["model"], "families": ["  "]}],
            },
            actor=TEST_ACTOR,
        )


def test_a_resource_with_no_families_stores_and_reads_back_unchanged(store, tenant):
    """Almost every resource in the system. The key is absent rather than empty, because
    a row written before 086 has none and the two must not compare differently."""
    store.create_connector(tenant, "jira", launch=_HTTP_LAUNCH, actor=TEST_ACTOR)
    store.vet_tool(
        tenant,
        "jira",
        {
            "remote_name": "ask",
            "effect": "read",
            "resources": [{"type": "jira.project", "args": ["projectKey"]}],
        },
        actor=TEST_ACTOR,
    )

    (row,) = store.get_connector(tenant, "jira")["vetted"]
    assert "families" not in row["resources"][0]

    # And it rebuilds as a resource that derives no family at all, which is the state a
    # pre-086 row is in and the reason a family scope against one refuses.
    from carnet.tools import mcp

    connector = mcp.from_manifest(store.get_connector(tenant, "jira"))
    (ref,) = connector.vetted[0].resources
    assert ref.families == ()
    assert ref.family_of("anything-at-all") == ""


def test_a_malformed_redaction_policy_is_refused_at_the_boundary(store, tenant):
    """The shape only — the names' existence in the schema is a schema-relative rule and
    stays in `tools/validation.py`, where the schema is. This layer refuses what would
    otherwise store fine and fail at the next bind."""
    store.create_connector(tenant, "jira", launch=_HTTP_LAUNCH, actor=TEST_ACTOR)

    for bad in ("messages", ["messages", ""], [None], [{"name": "messages"}]):
        with pytest.raises(StorageError, match="redact_args"):
            store.vet_tool(
                tenant,
                "jira",
                {"remote_name": "ask", "effect": "read", "redact_args": bad},
                actor=TEST_ACTOR,
            )


def test_a_binding_that_omits_its_optional_keys_round_trips_filled(store, tenant):
    """Defaults come from one place, one level down from `VETTED_TOOL_DEFAULTS`'s own
    rule: a binding written without `body` reads back with `[]` in both stores."""
    spare = {k: v for k, v in _BINDING.items() if k in {"method", "path", "query", "input_schema"}}
    store.create_connector(tenant, "tracker", launch=_REST_LAUNCH, actor=TEST_ACTOR)
    store.vet_tool(
        tenant,
        "tracker",
        {"remote_name": "list_issues", "effect": "read", "binding": spare},
        actor=TEST_ACTOR,
    )
    (row,) = store.get_connector(tenant, "tracker")["vetted"]
    assert row["binding"] == _BINDING


def test_the_kind_and_the_binding_imply_each_other(store, tenant):
    """045a's edge case, at the boundary every write funnels through: a binding on a
    non-rest connector is refused, and a rest row without one is refused — on both
    write paths, in both stores."""
    store.create_connector(tenant, "jira", launch=_HTTP_LAUNCH, actor=TEST_ACTOR)
    store.create_connector(tenant, "tracker", launch=_REST_LAUNCH, actor=TEST_ACTOR)

    with pytest.raises(StorageError, match="does not speak 'rest'"):
        store.vet_tool(
            tenant, "jira",
            {"remote_name": "x", "effect": "read", "binding": _BINDING},
            actor=TEST_ACTOR,
        )
    with pytest.raises(StorageError, match="no request binding"):
        store.vet_tool(
            tenant, "tracker", {"remote_name": "x", "effect": "read"}, actor=TEST_ACTOR
        )

    with pytest.raises(StorageError, match="does not speak 'rest'"):
        store.save_connector(
            tenant,
            {"id": "jira", "launch": _HTTP_LAUNCH,
             "vetted": [{"remote_name": "x", "binding": _BINDING}]},
            actor=TEST_ACTOR,
        )
    with pytest.raises(StorageError, match="no request binding"):
        store.save_connector(
            tenant,
            {"id": "tracker", "launch": _REST_LAUNCH, "vetted": [{"remote_name": "x"}]},
            actor=TEST_ACTOR,
        )

    # And a refused wholesale save left the registered rows untouched.
    assert store.get_connector(tenant, "jira")["vetted"] == []
    assert store.get_connector(tenant, "tracker")["vetted"] == []


def test_a_malformed_binding_is_refused_with_a_sentence(store, tenant):
    """The shape half of 045a's storage validation — the way `identity` got it."""
    store.create_connector(tenant, "tracker", launch=_REST_LAUNCH, actor=TEST_ACTOR)

    for broken, complaint in [
        ({**_BINDING, "method": "FETCH"}, "method"),
        ({**_BINDING, "path": "repos/issues"}, "path"),
        ({**_BINDING, "query": "state"}, "query"),
        ({**_BINDING, "surprise": True}, "unknown keys"),
        ({k: v for k, v in _BINDING.items() if k != "input_schema"}, "input_schema"),
        ({**_BINDING, "usage_map": {"input_tokens": 3}}, "usage_map"),
    ]:
        with pytest.raises(StorageError, match=complaint):
            store.vet_tool(
                tenant, "tracker",
                {"remote_name": "x", "effect": "read", "binding": broken},
                actor=TEST_ACTOR,
            )


def test_the_rest_kind_constant_is_pinned_to_the_launch_class(store):
    """`storage.REST_LAUNCH_KIND` is a string rather than an import because the
    layering runs tools -> storage; this is the test that keeps the two spellings
    from drifting, the `_OAUTH_ACCESS` device again."""
    from carnet.storage import REST_LAUNCH_KIND
    from carnet.tools.mcp.binding import RestLaunch

    assert REST_LAUNCH_KIND == RestLaunch.KIND


def test_a_manifest_that_omits_the_new_fields_still_round_trips(store, tenant):
    """Every row written before migration 018 has no description, and must still load.

    Defaults come from one place — `VETTED_TOOL_DEFAULTS` — so the two stores cannot
    disagree about what an absent description is.
    """
    spare = {key: value for key, value in MANIFEST["vetted"][0].items()
             if key not in {"description", "note"}}
    store.save_connector(tenant, {**MANIFEST, "vetted": [spare]}, actor=TEST_ACTOR)

    row = store.get_connector(tenant, "github-mcp")["vetted"][0]
    assert row["description"] == ""
    assert row["note"] == ""


def test_the_review_record_is_not_part_of_the_manifest(store, tenant):
    """Provenance is a column the database owns, never a claim a caller passes in.

    A `vetted_by` arriving in a dict is an assertion that somebody approved this, made
    by code that is not them. So it is read separately and cannot be written by saving
    a connector — there is no key on a manifest it would be read from.

    **Step 012 gave it a writer and this test changed with it.** The assertion used to
    be `vetted_by == ""` with a docstring explaining that nothing vets. What replaced it
    is the same property stated correctly: the name comes from the `actor` parameter,
    which the caller supplies *as themselves* rather than asserts *about somebody else*
    inside the data. `server_name` and `server_version` stay empty on this path, because
    `save_connector` contacts no server — see `test_vetting_records_what_it_was_vetted_against`
    for the path that does.
    """
    store.save_connector(tenant, MANIFEST, actor=TEST_ACTOR)

    assert "vetted_by" not in store.get_connector(tenant, "github-mcp")["vetted"][0]

    record = store.load_vetting_record(tenant)
    assert [(r["connector_id"], r["remote_name"]) for r in record] == [
        ("github-mcp", "list_issues")
    ]
    assert record[0]["vetted_by"] == TEST_ACTOR
    assert record[0]["vetted_at"]
    # Nothing spoke to a server, so there is nothing to record about one. Empty rather
    # than absent, and never invented.
    assert record[0]["server_name"] == ""
    assert record[0]["server_version"] == ""


def test_the_review_record_follows_the_allowlist(store, tenant):
    """Un-vet a tool and its review goes with it; delete the connector and all of it does.

    `save_connector` replaces the allowlist wholesale rather than merging, and the
    review record has to move with it: a review of a tool nobody may call is a row
    that reads as an approval in force.
    """
    two = {
        **MANIFEST,
        "vetted": [
            *MANIFEST["vetted"],
            # A read. It used to be a write with no resources, which storage now refuses
            # outright — see `check_vetted_tool`. That this fixture had to change is the
            # rule having teeth: the row was legal to store and illegal to load, and the
            # gap between those two is what step 012's second verification closes.
            {"remote_name": "add_issue_comment", "effect": "read"},
        ],
    }
    store.save_connector(tenant, two, actor=TEST_ACTOR)
    assert len(store.load_vetting_record(tenant)) == 2

    store.save_connector(tenant, MANIFEST, actor=TEST_ACTOR)
    assert [r["remote_name"] for r in store.load_vetting_record(tenant)] == ["list_issues"]

    store.delete_connector(tenant, "github-mcp", actor=TEST_ACTOR)
    assert store.load_vetting_record(tenant) == []


def test_the_review_record_is_invisible_across_tenants(store, tenant, other):
    store.save_connector(tenant, MANIFEST, actor=TEST_ACTOR)
    assert store.load_vetting_record(other) == []


def test_connectors_load_ordered_by_id(store, tenant):
    for connector_id in ("zulu", "alpha", "mike"):
        store.save_connector(tenant, {**MANIFEST, "id": connector_id}, actor=TEST_ACTOR)

    assert [c["id"] for c in store.load_connectors(tenant)] == ["alpha", "mike", "zulu"]


def test_connector_without_an_id_is_refused(store, tenant):
    with pytest.raises(StorageError):
        store.save_connector(tenant, {"launch": {}, "vetted": []}, actor=TEST_ACTOR)


def test_connector_may_not_store_read_only(store, tenant):
    """read_only is derived from the vetted effects and must never be written down.

    A stored copy is free to disagree with the allowlist it defends: vet a write and
    someone has to remember to clear the flag; remove that write and nobody remembers
    to set it again. Refused rather than dropped — a field silently discarded reads
    as honoured.
    """
    with pytest.raises(StorageError):
        store.save_connector(tenant, {**MANIFEST, "read_only": True}, actor=TEST_ACTOR)


def test_connectors_are_invisible_across_tenants(store, tenant, other):
    store.save_connector(tenant, MANIFEST, actor=TEST_ACTOR)

    assert store.get_connector(other, "github-mcp") is None
    assert store.load_connectors(other) == []


def test_two_tenants_may_vet_the_same_connector_differently(store, tenant, other):
    """The shape of the cross-tenant leak this whole step is guarding against.

    Both tenants run GitHub. One vets a write; the other must not inherit it.
    """
    store.save_connector(tenant, MANIFEST, actor=TEST_ACTOR)
    store.save_connector(
        other,
        {
            **MANIFEST,
            "vetted": [
                *MANIFEST["vetted"],
                {
                    "remote_name": "add_issue_comment",
                    # A read, because a write with no resources is now refused at this
                    # boundary — `check_vetted_tool`. This test is about two tenants
                    # vetting differently, not about effects, so the cheapest legal row
                    # is the right one.
                    "effect": "read",
                    "resources": [],
                    "local_name": None,
                    "max_response_bytes": None,
                },
            ],
        },
    actor=TEST_ACTOR,
    )

    assert len(store.get_connector(tenant, "github-mcp")["vetted"]) == 1
    assert len(store.get_connector(other, "github-mcp")["vetted"]) == 2


def test_deleting_an_absent_connector_is_not_an_error(store, tenant):
    store.delete_connector(tenant, "never-existed", actor=TEST_ACTOR)


def test_delete_removes_the_connector(store, tenant):
    store.save_connector(tenant, MANIFEST, actor=TEST_ACTOR)
    store.delete_connector(tenant, "github-mcp", actor=TEST_ACTOR)
    assert store.get_connector(tenant, "github-mcp") is None


# --- audit ----------------------------------------------------------------------


def test_audit_round_trips_with_the_tenant_merged_in(store, tenant):
    store.append_audit(tenant, _record())

    (row,) = store.audit_records(tenant)
    assert row["tenant_id"] == tenant
    assert row["run_id"] == "abc123"
    assert row["args"] == {"channel": "#eng"}
    assert row["response_bytes"] == 147


def test_audit_is_oldest_first(store, tenant):
    for i in range(5):
        store.append_audit(tenant, _record(tool=f"tool_{i}"))

    assert [r["tool"] for r in store.audit_records(tenant)] == [
        f"tool_{i}" for i in range(5)
    ]


def test_audit_filters_by_run(store, tenant):
    store.append_audit(tenant, _record(run_id="run-a", tool="a1"))
    store.append_audit(tenant, _record(run_id="run-b", tool="b1"))
    store.append_audit(tenant, _record(run_id="run-a", tool="a2"))

    assert [r["tool"] for r in store.audit_records(tenant, run_id="run-a")] == [
        "a1",
        "a2",
    ]


def test_limit_returns_the_most_recent_still_oldest_first(store, tenant):
    for i in range(5):
        store.append_audit(tenant, _record(tool=f"tool_{i}"))

    assert [r["tool"] for r in store.audit_records(tenant, limit=2)] == [
        "tool_3",
        "tool_4",
    ]


def test_audit_is_invisible_across_tenants(store, tenant, other):
    store.append_audit(tenant, _record())
    assert store.audit_records(other) == []


def test_audit_to_an_unknown_tenant_is_refused(store):
    with pytest.raises(UnknownTenantError):
        store.append_audit("no-such-tenant", _record())


def test_the_interface_offers_no_way_to_change_a_record(store):
    """Append-only starts as an absence: there is no method to call.

    Postgres backs this with a trigger (see the tests below); the in-memory store
    backs it by not implementing one. Both answer the same question the same way.
    """
    for forbidden in ("update_audit", "delete_audit", "clear_audit", "purge_audit"):
        assert not hasattr(store, forbidden)


def test_a_denied_record_round_trips(store, tenant):
    """Denials are the most important records, and they carry empty outcome and
    null timings. Nothing in that shape may be lost."""
    store.append_audit(
        tenant,
        _record(
            decision="deny",
            reason="github.repo 'torvalds/linux' is outside this agent's 'read' scope.",
            outcome="",
            duration_ms=None,
            response_bytes=None,
        ),
    )

    (row,) = store.audit_records(tenant)
    assert row["decision"] == "deny"
    assert row["outcome"] == ""
    assert row["duration_ms"] is None
    assert row["response_bytes"] is None
    assert "torvalds/linux" in row["reason"]


# --- the door's traffic ----------------------------------------------------------
#
# Step 035a. Not a fourth log — a reader over `audit`, selected by the one thing that
# separates a door call from a run: a correlation id shaped `door-<hex>`, which
# `runs.get`'s prefix match can never resolve.
#
# Every test below writes both kinds of row, because the *separation* is the behaviour
# under test. A suite that only ever appended door rows would pass against a reader that
# forgot to filter at all.


def _door(**overrides) -> dict:
    """One door call, on `_record`'s shape with a correlation id in place of a run id.

    Built through `_record` rather than beside it so a field added to the audit shape
    lands on both kinds of row at once — the drift `test_every_audit_field_survives_a
    _round_trip` exists to catch, one caller further out.
    """
    return _record(**{"run_id": f"{DOOR_CALL_ID_PREFIX}0123456789ab", **overrides})


def test_a_door_call_is_readable_and_a_run_is_not_in_the_way(store, tenant):
    """The gap 035a closes, in one assertion: the door's row comes back, the run's
    does not, and both are in the same table."""
    store.append_audit(tenant, _record(run_id="abc123", tool="from_a_run"))
    store.append_audit(tenant, _door(tool="from_the_door"))

    assert [r["tool"] for r in store.door_call_records(tenant)] == ["from_the_door"]
    # And the log itself is untouched by the new reader: one table, two questions.
    assert len(store.audit_records(tenant)) == 2


def test_a_door_call_carries_the_fields_only_it_ever_has(store, tenant):
    """`acting_for` and `identity_source` are schema version 7's whole point, and they
    are null/`none` on every run row. This is the read that makes them legible at all —
    and the three identity sources are never collapsed, so `asserted` must survive as
    itself rather than as a boolean."""
    store.append_audit(
        tenant,
        _door(v=7, acting_for="tom@acme.com", identity_source="asserted"),
    )

    (row,) = store.door_call_records(tenant)
    assert row["acting_for"] == "tom@acme.com"
    assert row["identity_source"] == "asserted"
    assert row["run_id"].startswith(DOOR_CALL_ID_PREFIX)
    assert row["tenant_id"] == tenant


def test_door_calls_are_oldest_first(store, tenant):
    for i in range(5):
        store.append_audit(tenant, _door(tool=f"tool_{i}"))

    assert [r["tool"] for r in store.door_call_records(tenant)] == [
        f"tool_{i}" for i in range(5)
    ]


def test_the_door_limit_returns_the_most_recent_still_oldest_first(store, tenant):
    """`audit_records`' rule, on the third reader of the same table. The sort of detail
    a fake gets backwards, which is why it is asserted against both."""
    for i in range(5):
        store.append_audit(tenant, _door(tool=f"tool_{i}"))

    assert [r["tool"] for r in store.door_call_records(tenant, limit=2)] == [
        "tool_3",
        "tool_4",
    ]
    assert store.door_call_records(tenant, limit=0) == []


def test_the_door_limit_counts_door_calls_and_not_rows(store, tenant):
    """The one way a prefix filter goes wrong that ordering tests miss: taking the tail
    of the *table* and then filtering would return fewer rows than asked for — or none
    — whenever runs outnumber door calls, which is every real deployment. Both stores
    must filter first and limit second."""
    for i in range(10):
        store.append_audit(tenant, _record(run_id="abc123", tool=f"run_{i}"))
    for i in range(3):
        store.append_audit(tenant, _door(tool=f"door_{i}"))
    for i in range(10, 20):
        store.append_audit(tenant, _record(run_id="abc123", tool=f"run_{i}"))

    assert [r["tool"] for r in store.door_call_records(tenant, limit=2)] == [
        "door_1",
        "door_2",
    ]


def test_door_calls_are_invisible_across_tenants(store, tenant, other):
    store.append_audit(tenant, _door())
    assert store.door_call_records(other) == []


def test_the_door_summary_counts_one_agents_knocks_and_nothing_else(store, tenant):
    """`door_call_summary` (044): runs are not knocks, other agents' calls are not this
    agent's, and a denial counts — the question is whether anything arrived."""
    store.append_audit(tenant, _record(run_id="abc123", agent="triage-bot"))
    store.append_audit(tenant, _door(agent="other-agent"))
    store.append_audit(tenant, _door(agent="triage-bot"))
    store.append_audit(
        tenant,
        _door(
            agent="triage-bot",
            ts="2026-08-02T11:00:00.000+00:00",
            decision="deny",
            reason="out of scope",
            outcome="",
        ),
    )

    summary = store.door_call_summary(tenant, "triage-bot")
    assert summary["calls"] == 2
    # The denial is the later row, and it is the last knock.
    assert summary["last_call_at"] == "2026-08-02T11:00:00.000+00:00"


def test_the_door_summary_for_the_unknocked_is_zero_and_never_null(store, tenant):
    """The connect card's waiting state is built on exactly this answer — an agent
    nothing has ever dialled, told apart from an error by being a real zero."""
    assert store.door_call_summary(tenant, "never-called") == {
        "calls": 0,
        "last_call_at": None,
    }


def test_the_door_summary_is_invisible_across_tenants(store, tenant, other):
    store.append_audit(tenant, _door(agent="triage-bot"))
    assert store.door_call_summary(other, "triage-bot")["calls"] == 0


def _door_denial(**overrides) -> dict:
    from carnet.storage.base import make_denial_record

    record = make_denial_record("machine", "m_abc", "tool", "post_message", "grant")
    record.update(overrides)
    return record


def test_the_last_door_refusal_is_the_newest_denial_naming_one_of_these_tools(
    store, tenant
):
    """`last_door_refusal` (074): the connect card's *refused, not idle*. Matched by
    tool name against the agent's own list; the newest wins; other tools and other
    resource kinds are not this agent's news."""
    store.record_denial(tenant, _door_denial(resource_id="post_message", principal_id="m_1"))
    store.record_denial(tenant, _door_denial(resource_id="other_tool", principal_id="m_2"))
    store.record_denial(
        tenant, _door_denial(resource_id="read_page", principal_id="m_3", required="acting-for")
    )
    store.record_denial(
        tenant, _door_denial(resource_kind="agent", resource_id="post_message", principal_id="m_4")
    )

    found = store.last_door_refusal(tenant, ["post_message", "read_page"])
    assert found is not None
    assert found["resource_id"] == "read_page"
    assert found["principal_id"] == "m_3"
    assert found["required"] == "acting-for"
    assert found["tenant_id"] == tenant
    assert isinstance(found["ts"], str)

    only = store.last_door_refusal(tenant, ["post_message"])
    assert only is not None and only["principal_id"] == "m_1"


def test_the_last_door_refusal_is_none_for_no_tools_and_no_denials(store, tenant):
    assert store.last_door_refusal(tenant, []) is None
    assert store.last_door_refusal(tenant, ["post_message"]) is None


def test_the_last_door_refusal_is_invisible_across_tenants(store, tenant, other):
    store.record_denial(tenant, _door_denial())
    assert store.last_door_refusal(other, ["post_message"]) is None


# --- the grant, against its evidence (076) ---------------------------------------

_REVIEW_WINDOW = dict(since=__import__("datetime").date(2026, 8, 1), until=__import__("datetime").date(2026, 8, 31))


def test_door_tool_evidence_counts_admitted_and_refused_per_tool_and_never_runs(store, tenant):
    """072: per tool, admitted and broker-refused with their last stamps; a run's rows
    do not count, other agents' rows do not count, and a tool the grant no longer
    carries still appears because a call under it is evidence."""
    store.append_audit(tenant, _door(agent="triage-bot", tool="post_message"))
    store.append_audit(
        tenant, _door(agent="triage-bot", tool="post_message", ts="2026-08-03T10:00:00.000+00:00")
    )
    store.append_audit(
        tenant,
        _door(agent="triage-bot", tool="delete_channel", decision="deny", reason="out of scope",
              outcome="", ts="2026-08-05T10:00:00.000+00:00"),
    )
    store.append_audit(tenant, _door(agent="triage-bot", tool="old_tool", ts="2026-08-06T10:00:00.000+00:00"))
    store.append_audit(tenant, _record(run_id="abc123", agent="triage-bot", tool="from_a_run"))
    store.append_audit(tenant, _door(agent="other-agent", tool="post_message"))
    # Outside the window.
    store.append_audit(tenant, _door(agent="triage-bot", tool="post_message", ts="2026-09-01T00:00:00.000+00:00"))

    evidence = store.door_tool_evidence(tenant, "triage-bot", ["post_message", "delete_channel"], **_REVIEW_WINDOW)
    tools = evidence["tools"]
    assert set(tools) == {"post_message", "delete_channel", "old_tool"}
    assert tools["post_message"]["admitted"] == 2
    assert tools["post_message"]["refused"] == 0
    assert tools["post_message"]["last_admitted_at"] == "2026-08-03T10:00:00.000+00:00"
    assert tools["post_message"]["last_refused_at"] is None
    assert tools["delete_channel"] == {
        "admitted": 0,
        "refused": 1,
        "last_admitted_at": None,
        "last_refused_at": "2026-08-05T10:00:00.000+00:00",
    }
    assert evidence["door_refused"] == {}


def test_door_tool_evidence_is_invisible_across_tenants(store, tenant, other):
    store.append_audit(tenant, _door(agent="triage-bot"))
    assert store.door_tool_evidence(other, "triage-bot", ["post_message"], **_REVIEW_WINDOW)["tools"] == {}


def test_token_door_touch_groups_one_tokens_calls_by_agent_and_tool(store, tenant):
    """072: what one credential did, in the grant's own shape. Other tokens' rows,
    run rows and rows outside the window are not it."""
    # **Partitions before back-dated writes.** `audit` is partitioned by month and
    # coverage is created ahead of time, so a row stamped before the oldest partition is
    # a CheckViolation rather than a row. Every date in this file's 072 tests is
    # absolute — the assertions compare timestamp strings — and the earliest is in July,
    # which default coverage does not reach. In memory there are no partitions, so these
    # passed there and failed the first time they met real Postgres.
    store.ensure_log_partitions(back_to=datetime(2026, 7, 1, tzinfo=timezone.utc))
    store.append_audit(tenant, _door(principal_kind="machine", principal_id="m_1", agent="a", tool="t1"))
    store.append_audit(
        tenant,
        _door(principal_kind="machine", principal_id="m_1", agent="a", tool="t1",
              ts="2026-08-09T10:00:00.000+00:00"),
    )
    store.append_audit(
        tenant,
        _door(principal_kind="machine", principal_id="m_1", agent="b", tool="t2",
              decision="deny", reason="out of scope", outcome="", ts="2026-08-04T10:00:00.000+00:00"),
    )
    store.append_audit(tenant, _door(principal_kind="machine", principal_id="m_2", agent="a", tool="t1"))
    store.append_audit(tenant, _record(run_id="abc123", principal_kind="machine", principal_id="m_1"))
    store.append_audit(
        tenant, _door(principal_kind="machine", principal_id="m_1", agent="a", tool="t1", ts="2026-07-31T23:59:59.000+00:00")
    )

    touch = store.token_door_touch(tenant, "m_1", **_REVIEW_WINDOW)
    assert touch["touched"] == [
        {"agent": "a", "tool": "t1", "admitted": 2, "refused": 0, "last_at": "2026-08-09T10:00:00.000+00:00"},
        {"agent": "b", "tool": "t2", "admitted": 0, "refused": 1, "last_at": "2026-08-04T10:00:00.000+00:00"},
    ]
    assert touch["door_refused"] == []


def test_token_door_touch_is_invisible_across_tenants(store, tenant, other):
    store.append_audit(tenant, _door(principal_kind="machine", principal_id="m_1"))
    assert store.token_door_touch(other, "m_1", **_REVIEW_WINDOW) == {"touched": [], "door_refused": []}


def test_the_oldest_door_record_is_the_evidence_boundary(store, tenant, other):
    """072: the earliest door row for the tenant — runs do not count, and a tenant with
    no door rows has no record at all rather than a stamp."""
    # **Partitions before back-dated writes.** `audit` is partitioned by month and
    # coverage is created ahead of time, so a row stamped before the oldest partition is
    # a CheckViolation rather than a row. Every date in this file's 072 tests is
    # absolute — the assertions compare timestamp strings — and the earliest is in July,
    # which default coverage does not reach. In memory there are no partitions, so these
    # passed there and failed the first time they met real Postgres.
    store.ensure_log_partitions(back_to=datetime(2026, 7, 1, tzinfo=timezone.utc))
    assert store.oldest_door_record_at(tenant) is None
    store.append_audit(tenant, _record(run_id="abc123", ts="2026-07-01T10:00:00.000+00:00"))
    assert store.oldest_door_record_at(tenant) is None
    store.append_audit(tenant, _door(ts="2026-08-02T10:00:00.000+00:00"))
    store.append_audit(tenant, _door(ts="2026-08-01T10:00:00.000+00:00"))
    assert store.oldest_door_record_at(tenant) == "2026-08-01T10:00:00.000+00:00"
    assert store.oldest_door_record_at(other) is None


def test_a_denied_door_call_is_readable(store, tenant):
    """A refusal is the most important row in this log too, and it carries an empty
    outcome and null timings. Nothing in that shape may be lost on the way out."""
    store.append_audit(
        tenant,
        _door(
            decision="deny",
            reason="'search_issues' is outside this agent's 'read' scope.",
            outcome="",
            duration_ms=None,
            response_bytes=None,
            acting_for="tom@acme.com",
            identity_source="verified",
        ),
    )

    (row,) = store.door_call_records(tenant)
    assert (row["decision"], row["outcome"]) == ("deny", "")
    assert (row["duration_ms"], row["response_bytes"]) == (None, None)
    assert row["identity_source"] == "verified"


def test_the_door_reader_returns_the_whole_record(store, tenant):
    """`args` and `credential` come back from storage and are dropped one layer up, by
    `api/schemas.DoorCallRecord`. Asserted here because the layering is the decision:
    projecting in the store would serve the browser at the CLI's expense, and an
    incident query wants both."""
    store.append_audit(tenant, _door(args={"repo": "acme/api"}, credential="shared"))

    (row,) = store.door_call_records(tenant)
    assert row["args"] == {"repo": "acme/api"}
    assert row["credential"] == "shared"


def test_mutating_a_returned_door_call_does_not_change_the_store(store, tenant):
    store.append_audit(tenant, _door())

    store.door_call_records(tenant)[0]["tool"] = "tampered"

    (row,) = store.door_call_records(tenant)
    assert row["tool"] == "post_message"


def test_a_record_written_without_the_optional_fields_reads_alike(store, tenant):
    """**Found by probing 035a's route against both stores, and it was a real split.**

    Postgres fills the optional columns at INSERT because the table demands values; the
    fake used to keep whatever dict it was handed. So a record appended without
    `identity_source` read back as `'none'` from Postgres and with the key **absent**
    from the fake — and `DoorCallRecord`, the first strict model over this table, turns
    that into a 500 on one store and a correct answer on the other.

    Exactly `credential`'s failure one field further on, which is why this asserts the
    whole key set rather than the one field that happened to break: the next optional
    column added to `audit` is covered without anybody remembering this test exists.
    """
    partial = {
        "v": 6,
        "ts": "2026-08-02T10:00:00.000+00:00",
        "run_id": f"{DOOR_CALL_ID_PREFIX}0123456789ab",
        "principal_kind": "machine",
        "principal_id": "tok_1",
        "agent": "triage",
        "tool": "list_issues",
        "decision": "allow",
    }
    store.append_audit(tenant, dict(partial))

    (row,) = store.door_call_records(tenant)

    # The defaults, each the truthful reading of an absent value — and identical to
    # what the columns themselves would have supplied.
    assert row["identity_source"] == "none"
    assert row["acting_for"] is None
    assert row["credential"] is None
    assert row["effect"] == ""
    assert row["reason"] == ""
    assert row["outcome"] == ""
    assert row["args"] == {}
    assert row["duration_ms"] is None and row["response_bytes"] is None

    # The shape, whole: every column, from both stores, for a writer that named eight.
    from carnet.storage.postgres import PostgresStorage

    assert set(row) == {"tenant_id", *PostgresStorage._AUDIT_COLUMNS}


def test_a_partial_record_still_builds_the_response_model(store, tenant):
    """The route's half of the row above. `DoorCallRecord` is deliberately **strict** —
    no default for `identity_source` — because a default would render an unverified
    claim as `none` rather than failing, and quietly downgrading an asserted identity is
    the one thing this log exists to prevent. Strictness is only safe while both stores
    return the field, which is what the test above now guarantees."""
    from carnet.api.schemas import DoorCallRecord

    store.append_audit(
        tenant,
        {
            "v": 6,
            "ts": "2026-08-02T10:00:00.000+00:00",
            "run_id": f"{DOOR_CALL_ID_PREFIX}0123456789ab",
            "principal_kind": "machine",
            "principal_id": "tok_1",
            "agent": "triage",
            "tool": "list_issues",
            "decision": "allow",
        },
    )

    (row,) = store.door_call_records(tenant)
    built = DoorCallRecord(**{k: v for k, v in row.items() if k != "tenant_id"})

    assert built.identity_source == "none"
    assert built.acting_for is None


# --- the overview -----------------------------------------------------------------
#
# Step 041. These are the assertions that keep one aggregating read honest across two
# implementations that count in different languages — `GROUP BY date_trunc` on one side,
# dict arithmetic on the other. Three of them exist because the fake is the one that can
# drift *kinder*: it is easy to write a Python counter that fills a gap, rounds a
# percentile differently, or forgets a tenant filter, and every one of those reads as a
# working dashboard.


_OVERVIEW_WINDOW = {"since": date(2026, 8, 22), "until": date(2026, 8, 27)}


def _door_on(day: int, **overrides) -> dict:
    """One door call on a given August day, allowed and read-effect unless overridden.

    Merged before the call rather than splatted alongside the defaults, so an override
    of any one of them replaces it instead of colliding with it.
    """
    fields = {
        "v": 7,
        "ts": f"2026-08-{day:02d}T09:00:00.000+00:00",
        "run_id": f"{DOOR_CALL_ID_PREFIX}0123456789ab",
        "principal_kind": "machine",
        "principal_id": "tok_1",
        "tool": "search_issues",
        "effect": "read",
        "identity_source": "verified",
    }
    return _record(**{**fields, **overrides})


def test_the_overview_is_sparse_in_both_stores(store, tenant):
    """**A day with nothing in it is absent, not zero**, and that is the contract.

    The zero-fill lives in the route, on `mcp_call_windows`' precedent and for its stated
    reason: a fake that filled its own gaps would be *kinder* than Postgres, and the
    difference would only surface as a chart with two of every day, or none. Whichever
    store is wrong, this is the assertion that says so.
    """
    store.append_audit(tenant, _door_on(24))

    series = store.overview(tenant, **_OVERVIEW_WINDOW)["door_calls"]

    assert [row["day"] for row in series] == ["2026-08-24"]


def test_the_overview_counts_only_this_tenant(store, tenant, other):
    """The failure that matters, and the one the fake's dict lookup would hide.

    A missing `WHERE tenant_id` in any of eleven statements is a cross-tenant leak on the
    one screen built to be read at a glance and trusted.
    """
    store.create_tenant(other, "Other")
    for _ in range(3):
        store.append_audit(other, _door_on(24))
    store.append_audit(tenant, _door_on(24))

    mine = store.overview(tenant, **_OVERVIEW_WINDOW)["door_calls"]

    assert [row["allowed"] for row in mine] == [1]


def test_a_door_call_is_not_counted_as_a_run(store, tenant):
    """Plan 041's first verification, and the one its first draft could not have made.

    A door call writes **no `runs` row** — 033b decision 4, and `docs/PREMISE.md`'s *the
    consequence people get wrong first*. It is disjoint by construction rather than by a
    filter somebody remembered, and a tenant using only the door is a heavy, healthy
    customer with an empty `runs` table.

    **Asserted against the run reader since step 084**, where it read
    `overview["runs"] == []` before. That series is gone — nothing in this tree writes a
    `runs` row, so a chart of them was measuring nothing, which is the premise's own
    sentence — and this claim must not be measured through a thing that was deleted for
    being empty. `list_runs` is the reader that survives (080's C2 keeps the run methods),
    and an empty answer from it is the fact 033b decision 4 is actually about.
    """
    store.append_audit(tenant, _door_on(24))

    assert store.overview(tenant, **_OVERVIEW_WINDOW)["door_calls"][0]["allowed"] == 1
    assert store.list_runs(tenant) == []


def test_the_window_includes_its_last_day(store, tenant):
    """`ts` is a timestamp and `until` is a date, so `<= until` would compare against
    that day's midnight and silently drop everything that happened during it — the day
    somebody reading a dashboard is most likely to be asking about."""
    store.append_audit(tenant, _door_on(27, ts="2026-08-27T23:59:59.000+00:00"))

    series = store.overview(tenant, **_OVERVIEW_WINDOW)["door_calls"]

    assert [row["day"] for row in series] == ["2026-08-27"]


def test_the_identity_split_is_never_collapsed(store, tenant):
    """Three sources, three counts, and no total that adds them.

    `DoorCallRecord`'s own rule one layer up: *"an asserted name is worth exactly what
    the calling app's honesty is worth, and a row that hid the difference would upgrade
    it."* This is the chart that makes the compliance question legible, so collapsing
    two of the three here would be a wrong answer with no way to notice.
    """
    store.append_audit(tenant, _door_on(24, identity_source="verified"))
    store.append_audit(tenant, _door_on(24, identity_source="asserted"))
    store.append_audit(tenant, _door_on(24, identity_source="none"))

    (row,) = store.overview(tenant, **_OVERVIEW_WINDOW)["identity"]

    assert (row["verified"], row["asserted"], row["none"]) == (1, 1, 1)


def test_a_refused_call_still_reports_whose_behalf_it_was_on(store, tenant):
    """Denials carry `identity_source` too (033c), and *what did we refuse, and for
    whom* is the half of the question an incident asks."""
    store.append_audit(
        tenant, _door_on(24, decision="deny", reason="nope", identity_source="asserted")
    )

    (row,) = store.overview(tenant, **_OVERVIEW_WINDOW)["identity"]

    assert row["asserted"] == 1


def test_an_errored_call_is_counted_as_admitted_too(store, tenant):
    """`outcome` bands an **allowed** call by what happened next, so `errored` sits
    beside `allowed` rather than being carved out of it. A call that was permitted and
    then failed is both, and a stack that dropped the first would understate what the
    door let through — which is the number the whole page is about."""
    store.append_audit(tenant, _door_on(24, outcome="error"))

    (row,) = store.overview(tenant, **_OVERVIEW_WINDOW)["door_calls"]

    assert (row["allowed"], row["errored"], row["denied"]) == (1, 1, 0)


def test_a_real_ceiling_refusal_lands_in_its_own_series(store, tenant):
    """**Driven through the real `TokenBudget`, not by writing a sentence by hand.**

    That is the whole point of the test: the refusal text is recovered by matching
    `CEILING_REFUSAL_MARKER`, which couples a query to prose, and a hand-written reason
    string would keep passing after somebody reworded the real one. Rewording it now
    re-files these calls as `policy` and this fails, which is the alarm the coupling was
    given in exchange for 033b's one-audit-path property.
    """
    import carnet.storage as storage_module

    from carnet.core.principal import Principal
    from carnet.door import TokenBudget

    storage_module.configure(store)

    # A real token row, because `mcp_budget` carries a foreign key to `api_tokens` that
    # only Postgres enforces — the fake accepted a spend against an id that never
    # existed, which is the asymmetry running this suite against both stores is for.
    store.create_api_token(
        tenant,
        {
            "id": "tok_1",
            "name": "ci",
            "owner_id": "u-1",
            "secret_hash": "sha256$abc",
        },
        actor="system:cli",
    )
    principal = Principal(kind="machine", id="tok_1", tenant_id=tenant)

    # A ceiling of **one, spent**, rather than a ceiling of zero. Zero is not a tight
    # budget here — it is the *unmetered* branch, which returns ALLOW before touching
    # storage on the grounds that "the audit log already says what every call did". That
    # branch is also why this page's usage series read `audit` and never `mcp_budget`
    # (plan 041, finding 3), and getting it wrong here is how this test first failed.
    budget = TokenBudget(principal, ceiling=1)
    assert budget.reserve(tool=None).allowed
    refusal = budget.reserve(tool=None)

    assert not refusal.allowed
    store.append_audit(tenant, _door_on(24, decision="deny", reason=refusal.reason))

    (row,) = store.overview(tenant, **_OVERVIEW_WINDOW)["refusals"]

    assert (row["ceiling"], row["policy"], row["run_budget"], row["door_spend"]) == (
        1, 0, 0, 0
    )


def test_a_historic_budget_exhaustion_still_lands_in_its_own_series(store, tenant):
    """The in-product twin of the test above — and **the one thing on this page that has
    a reader and no writer.**

    Until step 084 this drove the real `core.limits.Budget`, so a reworded refusal broke
    it. `Budget` is gone: it was the only thing that produced this sentence, its only
    caller was `RunContext.start`, and that had no caller at all since 078 took the
    runtime out.

    **The band stays anyway, and this is why the test does.** `_q_refusals` reads
    `audit`, never `runs`, and an upgraded deployment's `audit` holds refusals a pre-078
    tree wrote — 052 migrations' worth of history that a customer's Overview still draws.
    Deleting the band would re-file every one of them as `policy`, silently, on the screen
    `base.overview` calls *built to be trusted at a glance*.

    So the sentence is built from `storage.BUDGET_REFUSAL_MARKER` rather than produced by
    an enforcer, and what is pinned is exactly what is left to pin: **the read.** What is
    lost, and is worth saying rather than discovering, is the agreement between a writer
    and a reader — a private tree that reworded its own refusals would break its Overview
    and nothing here would notice.

    Note the `run_id`: this is **not** a door call, and that half of the split is
    structural rather than textual — a door call has no run, so `run_budget` is
    unreachable from door traffic by construction whatever any sentence says.
    """
    from carnet.storage import BUDGET_REFUSAL_MARKER

    store.append_audit(
        tenant,
        _record(
            ts="2026-08-24T09:00:00.000+00:00",
            run_id="abc123abc123",
            decision="deny",
            reason=f"run {BUDGET_REFUSAL_MARKER}: 30 tool calls already made",
        ),
    )

    (row,) = store.overview(tenant, **_OVERVIEW_WINDOW)["refusals"]

    assert (row["run_budget"], row["policy"], row["ceiling"], row["door_spend"]) == (
        1, 0, 0, 0
    )


def test_a_wildcard_on_both_sides_is_what_makes_the_qualified_sentences_match(
    store, tenant
):
    """`%budget exhausted%`, not a prefix. Three of the four sentences a per-run budget
    wrote qualify the noun — *write* budget, *response* budget — so a leading anchor would
    have counted one band in four and filed the rest as policy denials.

    Its writer left with 084 and the matching rule did not, so it is asserted directly:
    the phrase mid-sentence, with words on both sides of it, and a near-miss that must
    stay `policy`."""
    from carnet.storage import BUDGET_REFUSAL_MARKER

    for reason in (
        f"run write {BUDGET_REFUSAL_MARKER}: 5 writes already made",
        f"run response {BUDGET_REFUSAL_MARKER}: 1048576 bytes already returned",
    ):
        store.append_audit(
            tenant,
            _record(
                ts="2026-08-24T09:00:00.000+00:00",
                run_id="abc123abc123",
                decision="deny",
                reason=reason,
            ),
        )
    # Neither marker, so `policy` — the third leg, on the in-product side of the split.
    store.append_audit(
        tenant,
        _record(
            ts="2026-08-24T09:00:00.000+00:00",
            run_id="abc123abc123",
            decision="deny",
            reason="agent 'triage' may not call 'delete_repo'",
        ),
    )

    (row,) = store.overview(tenant, **_OVERVIEW_WINDOW)["refusals"]

    assert (row["run_budget"], row["policy"]) == (2, 1)


def test_an_ordinary_denial_is_neither_a_ceiling_nor_a_budget(store, tenant):
    """The third leg, and the one that makes the other two mean something: a refusal
    matching neither marker is `policy`. Without this, a query that matched everything
    would pass both tests above."""
    store.append_audit(
        tenant,
        _door_on(24, decision="deny", reason="agent 'triage' may not call 'delete_repo'"),
    )

    (row,) = store.overview(tenant, **_OVERVIEW_WINDOW)["refusals"]

    assert (row["policy"], row["ceiling"], row["run_budget"], row["door_spend"]) == (
        1, 0, 0, 0
    )


def test_a_money_refusal_lands_in_its_own_band(store, tenant):
    """Step 045b's fourth band, driven through the real refusal rather than a literal.

    **A band rather than rows folded into `ceiling`**, for that constant's own reason:
    *this credential made too many calls* and *this credential spent too much money* are
    answered differently — one is usually a loop or a dial set too tight, the other is a
    real bill arriving — and one line summing them would spike identically for either.

    The sentence is taken from `TokenBudget` itself, so a rewording that accidentally
    contained the call-count marker fails here rather than silently re-filing every money
    refusal under the wrong line.
    """
    from carnet.core.principal import Principal
    from carnet.door import TokenBudget

    store.create_api_token(
        tenant,
        {
            "tenant_id": tenant,
            "id": "tok_spend",
            "name": "ci",
            "owner_id": "u-1",
            "secret_hash": "sha256$abc",
        },
        actor="system:cli",
    )
    principal = Principal(kind="machine", id="tok_spend", tenant_id=tenant)

    # One door call that spent a million Opus input tokens — $15.00 at the built-in rate
    # table — under a $10 ceiling, so the *next* call is refused. Written straight into
    # `audit` because what is under test is the classification, not the broker.
    store.append_audit(
        tenant,
        _door_on(
            24,
            principal_kind="machine",
            principal_id="tok_spend",
            model="claude-opus-5",
            input_tokens=1_000_000,
            output_tokens=0,
            cache_read_tokens=0,
            cache_write_tokens=0,
        ),
    )

    import carnet.storage as storage_module
    from carnet import config as config_module

    # The gate reads the *active* store; conftest points that at its own. Repointed for
    # the length of this test, and `now` is passed rather than waited for — the reason
    # `TokenBudget`'s window is injectable in the first place.
    storage_module.configure(store)
    before = config_module.MCP_USD_PER_DAY
    config_module.MCP_USD_PER_DAY = 10.0
    try:
        refusal = TokenBudget(principal, ceiling=1000)._over_spend_ceiling(
            now=datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)
        )
    finally:
        config_module.MCP_USD_PER_DAY = before

    assert refusal is not None and not refusal.allowed
    store.append_audit(
        tenant,
        _door_on(
            24,
            principal_kind="machine",
            principal_id="tok_spend",
            decision="deny",
            reason=refusal.reason,
        ),
    )

    (row,) = store.overview(tenant, **_OVERVIEW_WINDOW)["refusals"]

    assert (row["door_spend"], row["ceiling"], row["policy"], row["run_budget"]) == (
        1, 0, 0, 0
    )


def test_the_door_spend_series_groups_by_day_and_model(store, tenant):
    """The Overview's money series: rows out, never dollars — the rate table lives one
    layer up so a store cannot disagree with the route about what anything cost."""
    store.append_audit(tenant, _door_on(23, model="claude-opus-5", input_tokens=100,
                                        output_tokens=0, cache_read_tokens=0,
                                        cache_write_tokens=0))
    store.append_audit(tenant, _door_on(24, model="claude-opus-5", input_tokens=1,
                                        output_tokens=0, cache_read_tokens=0,
                                        cache_write_tokens=0))
    store.append_audit(tenant, _door_on(24, model="claude-haiku-4-5", input_tokens=7,
                                        output_tokens=0, cache_read_tokens=0,
                                        cache_write_tokens=0))
    # An ordinary tool call, which reported nothing and must not appear as a `''` bucket.
    store.append_audit(tenant, _door_on(24))

    rows = store.overview(tenant, **_OVERVIEW_WINDOW)["door_spend"]

    assert [(r["day"][-2:], r["model"], r["input_tokens"]) for r in rows] == [
        ("23", "claude-opus-5", 100),
        ("24", "claude-haiku-4-5", 7),
        ("24", "claude-opus-5", 1),
    ]


def test_percentiles_interpolate_the_same_way_in_both_stores(store, tenant):
    """`percentile_cont`, not `percentile_disc` — it blends the two neighbours around a
    fractional position, and the fake reproduces that arithmetic rather than picking a
    row. The two agree on odd-length samples and diverge on even ones, so an even sample
    is what this asserts: the median of 100 and 200 is 150, not either of them."""
    store.append_audit(tenant, _door_on(24, duration_ms=100))
    store.append_audit(tenant, _door_on(24, duration_ms=200))

    (row,) = store.overview(tenant, **_OVERVIEW_WINDOW)["door_latency"]

    assert row["median_ms"] == 150


def test_a_day_with_no_timed_call_reports_no_latency_rather_than_zero(store, tenant):
    """A day of refusals has no duration to report, and `None` says so. Zero would draw
    a latency chart claiming instant calls on a day when nothing ran at all."""
    store.append_audit(tenant, _door_on(24, decision="deny", reason="no"))

    assert store.overview(tenant, **_OVERVIEW_WINDOW)["door_latency"] == []


def test_the_caller_axis_is_the_principal_not_the_token(store, tenant):
    """`audit` has no token id — plan 041 finding 2 — so one person's several personal
    tokens are **one** caller here, and that is stated rather than accidental. *Which
    credential* is the per-token page's question and needs an index migration 040
    declined."""
    store.append_audit(tenant, _door_on(24, principal_id="tok_1", tool="a"))
    store.append_audit(tenant, _door_on(24, principal_id="tok_1", tool="b"))
    store.append_audit(tenant, _door_on(24, principal_id="tok_2"))

    callers = store.overview(tenant, **_OVERVIEW_WINDOW)["callers"]

    assert [(c["principal_id"], c["calls"], c["tools"]) for c in callers] == [
        ("tok_1", 2, 2),
        ("tok_2", 1, 1),
    ]


# The window for the one test whose rows are stamped **now** rather than on one of
# August's fixed days.
#
# `_OVERVIEW_WINDOW` above ends on a hard-coded `date(2026, 8, 27)`, which was "today"
# on the day it was written. `admin_audit` rows carry a real clock, and `until` is a
# **UTC** date — so this test passed all day and began failing at 00:00 UTC, which for
# anybody west of Greenwich is the middle of the working evening. A test that fails on a
# clock rather than on a change is worse than no test: the next person to see it is
# debugging their own diff.
#
# Derived from today in UTC, so it is true on every day and in every timezone, and it is
# the same defect migration 045 fixed one layer down — a calendar boundary computed in
# whatever zone the process happened to be speaking.
def _today_window():
    today = datetime.now(timezone.utc).date()
    return {"since": today - timedelta(days=5), "until": today}


def test_administrative_changes_are_grouped_by_family(store, tenant):
    """The family is the prefix before the first dot, derived rather than maintained:
    the 45-action vocabulary is already dotted, so a new action joins its family for
    free instead of being dropped by a list nobody updated."""
    _agent_for(store, tenant, "alpha")
    store.grant_agent(tenant, "alpha", "user", "u-2", actor="user:u-1")

    families = {
        row["family"] for row in store.overview(tenant, **_today_window())["admin_actions"]
    }

    assert {"agent", "grant"} <= families


def test_the_tool_leaderboard_counts_door_traffic_and_nothing_else(store, tenant):
    """**The predicate, asserted where forgetting it would be invisible.** Step 013c.

    A door call is somebody else's client reaching in; anything else on this table is
    not. The only thing on an `audit` row that tells them apart is the `door-`
    correlation id, so a query that forgot `run_id LIKE 'door-%'` would quietly merge two
    populations into one leaderboard belonging to neither — and it would look right.

    **This asserted both halves until step 084.** `run_tools` was the same leaderboard
    over the product's own runs, and 013c's rule — *two figures, never one sum* — is why
    it existed. `routes_admin` has discarded it since 041 and this tree runs no agents, so
    what it counted was an empty population; the rule survives in
    `base.overview`'s docstring and in `_q_tool_totals`, which now takes no `door` flag to
    get wrong. What is pinned here is the half that can still be false: a non-door row
    reaching this list.
    """
    store.append_audit(tenant, _door_on(24, tool="search_issues"))
    store.append_audit(tenant, _door_on(24, tool="search_issues"))
    store.append_audit(
        tenant, _door_on(24, tool="post_message", run_id="abcdef012345")
    )

    overview = store.overview(tenant, **_OVERVIEW_WINDOW)

    assert [(r["tool"], r["calls"]) for r in overview["door_tools"]] == [
        ("search_issues", 2)
    ]
    assert overview["tool_count"] == 1
    # And the run-side series is gone rather than empty, which is a different claim: a
    # key returning `[]` would read as "no runs today" on a deployment that cannot have
    # any.
    assert "run_tools" not in overview


def test_the_leaderboards_are_capped_and_the_count_is_not(store, tenant):
    """**The bug this pins was found by driving a real world, not by reading the code.**

    The first build returned every caller and let the page slice twelve off the front:
    an unbounded response to draw a bounded picture, and a truncation nothing on the
    wire admitted to. The cap is in SQL now — and the *count* had to become its own
    query at the same moment, because a tile reading `len(callers)` would have started
    reporting the cap as the answer the day the cap arrived.
    """
    from carnet.storage.base import LEADERBOARD

    for n in range(LEADERBOARD + 8):
        store.append_audit(
            tenant, _door_on(24, principal_id=f"tok_{n:02d}", tool=f"tool_{n:02d}")
        )

    overview = store.overview(tenant, **_OVERVIEW_WINDOW)

    assert len(overview["callers"]) == LEADERBOARD
    assert len(overview["door_tools"]) == LEADERBOARD
    # The number that is not the length of the list beside it.
    assert overview["caller_count"] == LEADERBOARD + 8


def test_the_leaderboard_names_the_busiest_not_the_first(store, tenant):
    """A cap is only honest if what survives it is the top. The quiet caller is made
    first, so an implementation that took the head of an unsorted collection would keep
    exactly the wrong rows."""
    from carnet.storage.base import LEADERBOARD

    store.append_audit(tenant, _door_on(24, principal_id="tok_quiet"))
    for n in range(LEADERBOARD + 4):
        for _ in range(3):
            store.append_audit(tenant, _door_on(24, principal_id=f"tok_busy_{n:02d}"))

    callers = store.overview(tenant, **_OVERVIEW_WINDOW)["callers"]

    assert len(callers) == LEADERBOARD
    assert all(caller["principal_id"] != "tok_quiet" for caller in callers)
    assert callers[0]["calls"] == 3


def test_the_overview_survives_a_tenant_with_a_finished_run(store, tenant):
    """**Driven through the real run writers, because the fake's stamps are not strings.**

    `enqueue_run`/`start_run`/`finish_run` store `datetime` objects while the log tables
    store ISO strings, and the first version of the memory overview assumed strings
    everywhere — `fromisoformat` on a `datetime` is a `TypeError`, so one finished run
    crashed the whole answer. No earlier test had seeded one; every run assertion went
    through `append_audit`. This is the regression pin: the run comes in through the same
    door production runs use.

    It is also, since step 084, the pin on the *deletion* — see the assertion.
    """
    row, _ = store.enqueue_run(
        tenant,
        {"run_id": "aaaabbbbcccc", "agent": "demo", "agent_id": None,
         "principal_kind": "user", "principal_id": "u1", "task": "x",
         "idempotency_key": ""},
    )
    store.start_run(tenant, "aaaabbbbcccc", claimed_by="w")
    store.finish_run(tenant, "aaaabbbbcccc", "complete", answer="done")

    today = date.today()
    overview = store.overview(
        tenant, since=today - timedelta(days=6), until=today + timedelta(days=1)
    )

    # **Step 084 inverts the assertion and keeps the pin.** The overview no longer reads
    # `runs` at all, so what this proves now is that it does not: a finished run exists,
    # through the real writers, and no series here mentions it. A store that started
    # reading `self._runs` again would fail on the keys, and — if it also got the stamps
    # wrong the way the fake originally did — on the `TypeError` this test was written
    # for. Both halves are still live.
    assert "runs" not in overview
    assert "run_latency" not in overview
    assert "schedules" not in overview
    assert overview["door_calls"] == []
    assert store.list_runs(tenant)[0]["status"] == "complete"


def test_a_stamp_with_a_foreign_offset_lands_on_its_utc_day(store, tenant):
    """`02:00+05:30` on the 25th is `20:30Z` on the **24th**, and both stores must file
    it there. Postgres gets this from `AT TIME ZONE 'UTC'`; the fake's first version
    sliced ten characters off the string and would have bucketed by the writer's local
    date — the same call on two different days depending on which store answered."""
    store.append_audit(
        tenant, _door_on(25, ts="2026-08-25T02:00:00.000+05:30")
    )

    series = store.overview(tenant, **_OVERVIEW_WINDOW)["door_calls"]

    assert [row["day"] for row in series] == ["2026-08-24"]


# **`test_schedule_health_carries_the_agents_name` was here until step 084.** It drove
# `_schedule_health` in both stores and pinned a real fake-versus-Postgres divergence: the
# fake copied a raw schedule row and reported every failing schedule's agent as null while
# Postgres joined the name, because `agent_name` left the child tables in migration 035
# and is derived on read.
#
# The series went with the rest of the run machinery — `routes_admin` discarded it on
# every page load and nothing in this tree creates a schedule. **The derivation it was
# guarding did not go**: `_agent_name_expr` and `_agent_name_of` have four callers each,
# and `test_a_pending_grant_carries_the_agents_name` and the schedule readers' own
# contract tests still hold them to it. What is lost is one more place that noticed.

# --- step 066: the cap that says what it cut ----------------------------------------
#
# `LEADERBOARD` is 15 and has been since 041. What 066 adds is that both stores now
# report the rows *below* the cap, because a walkthrough found the old arrangement
# showing a tool that had just been called on no chart at all with nothing admitting it.
# Every assertion below is on both stores, which is the only thing that keeps the fake
# from being kinder than Postgres about a truncation.


def _many_tools(store, tenant, count: int) -> None:
    """`count` distinct tools, each called one time fewer than the last.

    Descending so the ranking is unambiguous — with ties the two stores would agree only
    because their tiebreaks agree, which is a different property and has its own test.
    """
    for index in range(count):
        for _ in range(count - index):
            store.append_audit(tenant, _door_on(24, tool=f"tool_{index:02d}"))


def test_a_capped_leaderboard_reports_what_it_cut(store, tenant):
    """Eighteen tools, a cap of fifteen, and the three that fell off are counted.

    This is the walkthrough's finding in one assertion. Before 066 the list came back
    fifteen long and the response said nothing else — so a page could not tell "these are
    all of them" from "these are most of them", and neither could a reader.
    """
    _many_tools(store, tenant, 18)

    view = store.overview(tenant, **_OVERVIEW_WINDOW)

    assert len(view["door_tools"]) == LEADERBOARD
    assert view["tool_count"] == 18
    # The three slowest tools were called 3, 2 and 1 times.
    assert view["tool_tail"] == {"n": 3, "calls": 3 + 2 + 1, "denied": 0}


def test_a_leaderboard_that_cut_nothing_says_so_with_a_zero(store, tenant):
    """`n == 0`, never a null and never an absent key.

    A client rendering "and no more" must not have to test for absence, and a store that
    omitted the key on the happy path would make every reader write that test.
    """
    _many_tools(store, tenant, 3)

    view = store.overview(tenant, **_OVERVIEW_WINDOW)

    assert view["tool_count"] == 3
    assert view["tool_tail"] == {"n": 0, "calls": 0, "denied": 0}


def test_the_caller_count_is_the_count_and_never_the_list(store, tenant):
    """041's rule, now enforced by the same statement that produces the list.

    The tile said "15 callers" on a tenant with twenty before 041 gave it its own query;
    066 moves that guarantee into the ranking window, so the count and the rows come from
    one scan and cannot disagree across a write either.
    """
    for index in range(20):
        store.append_audit(tenant, _door_on(24, principal_id=f"tok_{index:02d}"))

    view = store.overview(tenant, **_OVERVIEW_WINDOW)

    assert len(view["callers"]) == LEADERBOARD
    assert view["caller_count"] == 20
    assert view["caller_tail"]["n"] == 5


def test_a_tail_counts_refusals_apart_from_calls(store, tenant):
    """The tail carries `denied` as well as `calls`, because a page that said "412 more
    calls" while hiding that all 412 were refused would be worse than saying nothing."""
    for index in range(17):
        for _ in range(17 - index):
            store.append_audit(
                store_tenant := tenant,
                _door_on(24, tool=f"t_{index:02d}", decision="deny", reason="no"),
            )
        assert store_tenant

    view = store.overview(tenant, **_OVERVIEW_WINDOW)

    assert view["tool_tail"]["n"] == 2
    assert view["tool_tail"]["calls"] == view["tool_tail"]["denied"] == 2 + 1


# --- step 066: the hour bucket ------------------------------------------------------


def test_the_hour_bucket_groups_by_hour_in_both_stores(store, tenant):
    """`bucket="hour"` groups the same rows into `YYYY-MM-DDTHH`.

    The window that needed this is one day: a day's live traffic drawn as a single column
    beside a backdated month is an eleven-pixel sliver, which is what made a working demo
    look broken on 2026-08-31.

    The spelling matters as much as the grouping — Postgres produces it with `to_char`
    and the fake with `strftime`, and a store that emitted `2026-08-24T09:00:00` would
    fill against an axis of `2026-08-24T09` and draw an empty chart.
    """
    store.append_audit(tenant, _door_on(24, ts="2026-08-24T09:10:00.000+00:00"))
    store.append_audit(tenant, _door_on(24, ts="2026-08-24T09:50:00.000+00:00"))
    store.append_audit(tenant, _door_on(24, ts="2026-08-24T11:05:00.000+00:00"))

    hourly = store.overview(tenant, **_OVERVIEW_WINDOW, bucket="hour")["door_calls"]

    assert [(row["day"], row["allowed"]) for row in hourly] == [
        ("2026-08-24T09", 2),
        ("2026-08-24T11", 1),
    ]


def test_the_default_bucket_is_still_the_day(store, tenant):
    """No caller that omits `bucket` sees a change. The parameter defaults to `"day"` in
    both stores, and the three rows above collapse to one column."""
    store.append_audit(tenant, _door_on(24, ts="2026-08-24T09:10:00.000+00:00"))
    store.append_audit(tenant, _door_on(24, ts="2026-08-24T11:05:00.000+00:00"))

    daily = store.overview(tenant, **_OVERVIEW_WINDOW)["door_calls"]

    assert [(row["day"], row["allowed"]) for row in daily] == [("2026-08-24", 2)]


# --- step 066: the door log's filters -----------------------------------------------


def test_every_door_filter_narrows_in_both_stores(store, tenant):
    """One row per filter, and each filter finds its own.

    Table-driven because the failure this guards is *the eighth one* — a hand-written
    chain of eleven `column = %s` clauses is where `principal_kind` gets compared against
    `principal_id`, and a per-filter test is what makes that a red line rather than a
    surprise during an incident.
    """
    store.append_audit(
        tenant,
        _door_on(
            24,
            tool="create_issue",
            agent="issue-reporter",
            principal_id="tok_hot",
            principal_kind="machine",
            acting_for="sam@example.com",
            effect="write",
            outcome="ok",
            identity_source="asserted",
        ),
    )
    # The decoy differs on **every** filtered column, so each assertion below is a real
    # narrowing rather than one that passes because the two rows happened to share a
    # default. The first version left `agent` at `_record`'s default on both rows and the
    # agent filter "passed" by matching nothing away.
    store.append_audit(
        tenant,
        _door_on(
            25,
            tool="search_issues",
            agent="other-agent",
            principal_id="tok_cold",
            principal_kind="user",
            acting_for="lee@example.com",
            effect="read",
            outcome="error",
            identity_source="none",
        ),
    )

    for keyword, value in (
        ("tool", "create_issue"),
        ("agent", "issue-reporter"),
        ("principal_id", "tok_hot"),
        ("principal_kind", "machine"),
        ("acting_for", "sam@example.com"),
        ("effect", "write"),
        ("outcome", "ok"),
        ("identity_source", "asserted"),
    ):
        found = store.door_call_records(tenant, **{keyword: value})
        assert [row["tool"] for row in found] == ["create_issue"], keyword


def test_the_door_filters_are_anded_not_ored(store, tenant):
    """Two filters that each match a different row match neither together."""
    store.append_audit(tenant, _door_on(24, tool="create_issue", effect="write"))
    store.append_audit(tenant, _door_on(24, tool="search_issues", effect="read"))

    assert store.door_call_records(tenant, tool="create_issue", effect="read") == []


def test_an_empty_outcome_is_a_value_a_filter_can_ask_for(store, tenant):
    """`outcome=""` is a real stored value — the column is `NOT NULL DEFAULT ''` — so
    "the ones nothing was recorded for" has to be a question this filter can put.

    The bug this pins is a falsy check: `if value:` reads an empty string as *do not
    narrow* and silently answers with the whole log, which is the one wrong answer a log
    filter must not give.
    """
    store.append_audit(tenant, _door_on(24, tool="recorded", outcome="ok"))
    store.append_audit(tenant, _door_on(24, tool="not_recorded", outcome=""))

    found = store.door_call_records(tenant, outcome="")

    assert [row["tool"] for row in found] == ["not_recorded"]


def test_the_door_window_is_inclusive_at_both_ends(store, tenant):
    """`since` and `until` are inclusive UTC dates, matching the overview's window.

    The half-open bug this guards is recorded in `_WINDOW`: a `<= until` against a
    TIMESTAMPTZ compares with that day's midnight and drops everything that happened
    *during* the last day — which is the day somebody following a link from a chart
    column is most likely asking about.
    """
    for day in (23, 24, 25, 26):
        store.append_audit(
            tenant, _door_on(day, tool=f"d{day}", ts=f"2026-08-{day}T23:59:00.000+00:00")
        )

    found = store.door_call_records(tenant, since=date(2026, 8, 24), until=date(2026, 8, 25))

    assert [row["tool"] for row in found] == ["d24", "d25"]


def test_a_door_filter_matching_nothing_is_an_empty_answer(store, tenant):
    """No raise, no whole-log fallback. A name that matches nothing is honestly empty —
    the store has no opinion about the shape of an id, which is the route's asymmetry
    seen from below."""
    store.append_audit(tenant, _door_on(24))

    assert store.door_call_records(tenant, tool="nonesuch") == []


def test_a_door_filter_still_excludes_runs(store, tenant):
    """A filter narrows the door's traffic and never widens it past the prefix.

    The prefix is the definition of the split and a filter is applied on top of it, not
    instead of it — a run whose tool matches must not appear because somebody asked for
    that tool.
    """
    store.append_audit(tenant, _record(run_id="abc123", tool="shared_name"))
    store.append_audit(tenant, _door(tool="shared_name"))

    assert len(store.door_call_records(tenant, tool="shared_name")) == 1


# --- step 066a: the dimensions the page threw away ----------------------------------


def test_the_agent_leaderboard_groups_by_the_permission_list(store, tenant):
    """`CLAUDE.md`'s central noun, grouped for the first time.

    An agent in Carnet is a named set of tools with a scope — the permission model
    itself — and every audit row has carried the column since migration 004 while no
    figure grouped by it.
    """
    for _ in range(3):
        store.append_audit(tenant, _door_on(24, agent="issue-reporter", tool="a"))
    store.append_audit(tenant, _door_on(24, agent="issue-reporter", tool="b"))
    store.append_audit(tenant, _door_on(24, agent="quiet-one", tool="a"))

    agents = store.overview(tenant, **_OVERVIEW_WINDOW)["door_agents"]

    assert agents[0] == {
        "agent": "issue-reporter",
        "calls": 4,
        "denied": 0,
        # The *exercised* breadth, not the granted breadth — two distinct tools reached.
        "tools": 2,
    }


def test_acting_for_never_collapses_two_kinds_of_claim(store, tenant):
    """033c's rule, one layer up: the same name reached two ways is two rows.

    An asserted name is worth exactly what the calling application's honesty is worth. A
    leaderboard keyed on the name alone would add a verified count to an asserted one and
    **upgrade the claim**, in the one record kept to tell them apart.
    """
    store.append_audit(
        tenant, _door_on(24, acting_for="sam@example.com", identity_source="verified")
    )
    store.append_audit(
        tenant, _door_on(24, acting_for="sam@example.com", identity_source="asserted")
    )

    rows = store.overview(tenant, **_OVERVIEW_WINDOW)["acting_for"]

    assert sorted((row["identity_source"], row["calls"]) for row in rows) == [
        ("asserted", 1),
        ("verified", 1),
    ]


def test_an_unnamed_call_is_absent_from_acting_for(store, tenant):
    """`identity_source='none'` is already a band on the identity chart. A `(nobody)` row
    would top this list on every deployment and crowd out the names it exists to show."""
    store.append_audit(tenant, _door_on(24, acting_for=None, identity_source="none"))
    store.append_audit(tenant, _door_on(24, acting_for="sam@example.com"))

    rows = store.overview(tenant, **_OVERVIEW_WINDOW)["acting_for"]

    assert [row["acting_for"] for row in rows] == ["sam@example.com"]


def test_refusal_reasons_rank_the_sentences_the_controls_wrote(store, tenant):
    """The refusal chart says *which control*; this says *what it said*.

    Allowed calls contribute nothing however they were worded — the `reason` column is
    written on both, and a leaderboard mixing them would rank an explanation of a
    permitted call among the refusals.
    """
    for _ in range(2):
        store.append_audit(
            tenant, _door_on(24, decision="deny", reason="tool not granted")
        )
    store.append_audit(tenant, _door_on(24, decision="deny", reason="scope mismatch"))
    store.append_audit(tenant, _door_on(24, reason="allowed anyway"))

    rows = store.overview(tenant, **_OVERVIEW_WINDOW)["refusal_reasons"]

    assert rows == [
        {"reason": "tool not granted", "count": 2},
        {"reason": "scope mismatch", "count": 1},
    ]


def test_tool_latency_is_null_where_nothing_was_timed(store, tenant):
    """`LatencyDay`'s rule reaching a leaderboard: a tool that was only ever refused has
    no duration to report, and a zero would claim it was instant.

    It is absent rather than present-with-nulls, because a refused-only tool has no
    measurement at all — the row would be a name and two nulls, which is a gap dressed as
    a fact.
    """
    store.append_audit(tenant, _door_on(24, tool="slow", duration_ms=400))
    store.append_audit(tenant, _door_on(24, tool="quick", duration_ms=10))
    store.append_audit(
        tenant, _door_on(24, tool="refused_only", decision="deny", reason="no")
    )

    rows = store.overview(tenant, **_OVERVIEW_WINDOW)["tool_latency"]

    # Slowest first — the busiest tool is already the top row of the figure beside this.
    assert [row["tool"] for row in rows] == ["slow", "quick"]
    assert rows[0]["median_ms"] == 400


def test_response_bytes_are_summed_and_the_percentile_is_null_when_absent(store, tenant):
    """`oversize` is drawn on this page and the bytes behind it were aggregated nowhere.

    A sum of nothing is 0 and a percentile of nothing is not a number, which is why the
    two fields answer an empty day differently.
    """
    store.append_audit(tenant, _door_on(24, response_bytes=100))
    store.append_audit(tenant, _door_on(24, response_bytes=300))
    store.append_audit(tenant, _door_on(25, response_bytes=None))

    rows = store.overview(tenant, **_OVERVIEW_WINDOW)["door_bytes"]

    assert [(row["day"], row["bytes"]) for row in rows] == [("2026-08-24", 400)]


def test_the_hour_grid_counts_weekdays_from_monday(store, tenant):
    """**0=Monday**, and one of the two stores has to convert to get there.

    Postgres' `dow` is 0=Sunday and Python's `weekday()` is 0=Monday, so the wire has to
    pick and both have to obey it. 2026-08-24 is a Monday; a store answering `1` here is
    off by Postgres' offset and would draw the whole grid one row down.
    """
    store.append_audit(tenant, _door_on(24, ts="2026-08-24T14:30:00.000+00:00"))

    assert store.overview(tenant, **_OVERVIEW_WINDOW)["hourly"] == [
        {"weekday": 0, "hour": 14, "calls": 1}
    ]


def test_all_four_outcome_bands_are_counted(store, tenant):
    """Migration 004's CHECK has held five values since the table existed and this page
    drew two. `unknown` in particular is a value the schema anticipated and no screen
    ever rendered.

    `''` is in **no** band and that is the point of the assertion: an admitted call
    nothing recorded an outcome for is not a success, so `ok` must not absorb it.
    """
    for outcome in ("ok", "error", "oversize", "unknown", ""):
        store.append_audit(tenant, _door_on(24, outcome=outcome))

    (row,) = store.overview(tenant, **_OVERVIEW_WINDOW)["door_calls"]

    assert row["allowed"] == 5
    assert (row["ok"], row["errored"], row["oversize"], row["unknown"]) == (1, 1, 1, 1)


# --- step 066a: the previous window --------------------------------------------------


def test_overview_totals_counts_the_same_window_as_the_overview(store, tenant):
    """The cheap read and the expensive one must agree, or a tile's delta is nonsense.

    This is the assertion that keeps `overview_totals` a projection of `overview` rather
    than a second opinion about what a window contains.
    """
    store.append_audit(tenant, _door_on(24, effect="write", decision="allow"))
    store.append_audit(tenant, _door_on(25, decision="deny", reason="no"))

    view = store.overview(tenant, **_OVERVIEW_WINDOW)
    totals = store.overview_totals(tenant, **_OVERVIEW_WINDOW)

    assert totals["door_calls"] == sum(
        row["allowed"] + row["denied"] for row in view["door_calls"]
    )
    assert totals["door_denied"] == sum(row["denied"] for row in view["door_calls"])
    assert totals["door_writes"] == sum(row["write"] for row in view["door_effects"])
    assert totals["callers"] == view["caller_count"]


def test_an_empty_previous_window_is_zeros_and_not_an_absence(store, tenant):
    """A quiet window and a window before the deployment existed produce the same dict,
    and this method deliberately does not try to tell them apart — that needs the age of
    the log, which nothing here asks for and which it must not invent."""
    totals = store.overview_totals(tenant, since=date(2020, 1, 1), until=date(2020, 1, 7))

    assert totals["door_calls"] == 0
    assert totals["callers"] == 0
    assert totals["door_spend"] == []


def test_the_door_reader_offers_no_way_to_write_one(store):
    """There is no `append_door_call`, and its absence is the design: a door call is an
    ordinary audit row, written by `core/audit.record` like every other. A second
    append would be a second way to produce one, and two producers of one log is how a
    row ends up in it that no call ever made."""
    assert not [
        name
        for name in dir(store)
        if "door" in name.lower()
        # `door_call_summary` (044) is a second *reader* — two scalars for the connect
        # card — and readers are exactly what this guard permits. `door_spend_since`
        # (045b) and each store's overview helper (`_door_spend` / `_q_door_spend`) are
        # three more: all aggregate rows the broker already wrote, and none can produce
        # one.
        #
        # Step 066 adds three, and each is a reader by the same test. `_door_agents` /
        # `_q_agents` group rows the broker wrote by the permission list that admitted
        # them; `_DOOR_FILTERS` is a table of column names. **The guard is doing its job
        # by making each of these a decision** rather than by keeping a short list — a
        # name that needed adding here would be a name worth looking at, which is what
        # happened to all three.
        # `last_door_refusal` (074) reads `access_denials`, not `audit` at all — the
        # door's own refusals, which the broker never sees. A reader by the same test.
        # Step 076 adds three more readers, all of the same kind: `door_tool_evidence`
        # and `token_door_touch` group rows the broker and the door already wrote,
        # `oldest_door_record_at` is one `min(ts)`. None can produce a row.
        and name not in {
            "door_call_records",
            "door_call_summary",
            "last_door_refusal",
            "door_tool_evidence",
            "token_door_touch",
            "oldest_door_record_at",
            "door_spend_since",
            "_door_spend",
            "_q_door_spend",
            "_door_agents",
            "_DOOR_CALL_PATTERN",
            "_DOOR_FILTERS",
        }
    ]


# --- the administrative audit log ------------------------------------------------
#
# Migration 022. Three of these are about the *step* rather than about a method, and
# they are the ones to read first: `test_every_in_scope_method_leaves_a_record`,
# `test_a_revocation_names_who_did_it`, and — Postgres-only, further down —
# `test_a_write_whose_record_is_refused_leaves_nothing_behind`.


def _agent_for(store, tenant, name="issue-reporter"):
    store.save_agent(tenant, {**AGENT, "name": name}, actor="system:cli")
    return name


# A cadence and an instant for the tests that are not about either. Far enough ahead that
# nothing in this file can fire it by accident.
_HOURLY = {"every": "hour", "at": ":15"}
_SOON = datetime(2030, 1, 1, 7, 30, tzinfo=timezone.utc)


def _schedule_for(store, tenant, token_id, schedule_id, agent="issue-reporter"):
    """An agent, a token to fire as, and a schedule joining them. Migration 033's two
    foreign keys mean the first two are prerequisites rather than convenience.

    `token_id` may be one `_schedule_token` already minted, or a fresh id this mints —
    the IN_SCOPE entries want the second, the contract tests below want the first.
    """
    _agent_for(store, tenant, agent)
    if store.find_api_token(token_id) is None:
        store.create_api_token(
            tenant,
            {
                "id": token_id,
                "name": f"ci-{schedule_id}",
                "owner_id": "u-1",
                "secret_hash": "sha256$abc",
            },
            actor="system:cli",
        )
    return store.create_schedule(
        tenant,
        {
            "id": schedule_id,
            "agent_name": agent,
            "token_id": token_id,
            "task": "summarize yesterday",
            "cadence": _HOURLY,
            "timezone": "Europe/Berlin",
            "next_fire_at": _SOON,
        },
        actor="user:u-1",
    )


def _trigger_for(store, tenant, token_id, trigger_id, agent="issue-reporter"):
    """An agent, a token to fire as, and a trigger joining them — `_schedule_for` at
    migration 034. The sealed blob is fake bytes: storage's contract is that it stores
    what `crypto.seal` produced without ever understanding it, so the contract suite
    hands it opaque bytes and asserts they round-trip."""
    _agent_for(store, tenant, agent)
    if store.find_api_token(token_id) is None:
        store.create_api_token(
            tenant,
            {
                "id": token_id,
                "name": f"ci-{trigger_id}",
                "owner_id": "u-1",
                "secret_hash": "sha256$abc",
            },
            actor="system:cli",
        )
    return store.create_trigger(
        tenant,
        {
            "id": trigger_id,
            "agent_name": agent,
            "token_id": token_id,
            "name": f"hook-{trigger_id}",
            "task": "triage the event below",
            "secret_sealed": b"\x01sealed-bytes-not-a-secret",
            "secret_key_id": "k1234567",
        },
        actor="user:u-1",
    )


def _group_for(store, tenant, name="oncall"):
    row = store.create_group(
        tenant, "g-1", name, created_by="system:cli", actor="system:cli"
    )
    return row["group_id"]


def _person_for(store, tenant, **overrides):
    """One person in this tenant, with ids derived from the tenant. `users.id` and
    `(issuer, subject)` are both global, and `IN_SCOPE` runs each entry in its own
    tenant on a shared database — `_token_id`'s lesson, one table over."""
    actor = overrides.pop("actor", None)
    row = {
        "id": f"u-{tenant}",
        "issuer": f"https://{tenant}.idp.example",
        "subject": f"sub-{tenant}",
        "email": "priya@acme.com",
    }
    row.update(overrides)
    store.create_user(tenant, row, actor=actor)
    return row


def _scim_for(store, tenant, suffix=""):
    """A registered provider and a SCIM token bound to it. Returns the token id."""
    issuer = f"https://{tenant}.idp.example"
    store.save_tenant_idp(
        tenant, {"issuer": issuer, "jwks_uri": f"{issuer}/keys", "audience": "aud"}
    )
    token_id = f"s_{tenant}{suffix}".replace("-", "_").replace(".", "_")[:64]
    store.mint_scim_token(
        tenant,
        {
            "id": token_id,
            "issuer": issuer,
            "name": "entra-prod",
            "secret_hash": "sha256$" + "b" * 64,
            "created_by": "user:u-1",
        },
        actor="user:u-1",
    )
    return token_id


# Every method step 011 put in scope, and the action each one must produce. Written as
# data rather than as thirteen test functions for the reason `RUN_FIELDS` is written
# down: the failure this guards against is a method **added later** that quietly writes
# nothing, and a list somebody has to remember to extend is exactly the thing that
# shipped `audit.credential` with 818 tests green.
#
# Each entry is (action, a callable that performs the write). The callable does the
# whole thing, because several of these are only interesting once something exists to
# remove.
IN_SCOPE = (
    (
        "agent.create",
        lambda s, t: s.create_agent(t, AGENT, "user", "u-1"),
    ),
    (
        "agent.save",
        lambda s, t: s.save_agent(t, AGENT, actor="user:u-1"),
    ),
    (
        "agent.update",
        lambda s, t: (_agent_for(s, t), _edit(s, t, system="Edited.")),
    ),
    (
        # Step 021. The same method as `agent.update`, reached with `restored_from`
        # set — which is the point: a restore is an edit whose body is an old config,
        # and one parameter deciding the source, the action and the version row is what
        # stops the three disagreeing.
        "agent.restore",
        lambda s, t: (
            _agent_for(s, t),
            _edit(s, t, system="Edited."),
            _edit(s, t, system=AGENT["system"], restored_from=1),
        ),
    ),
    (
        # Step 025. The record that joins an agent's two names — see `ADMIN_ACTIONS`,
        # where the reason it is not optional is written down.
        "agent.rename",
        lambda s, t: (
            _agent_for(s, t),
            s.rename_agent(t, "issue-reporter", "issue-triage", actor="user:u-1"),
        ),
    ),
    (
        "agent.delete",
        lambda s, t: (
            _agent_for(s, t),
            s.delete_agent(t, "issue-reporter", actor="user:u-1"),
        ),
    ),
    (
        "grant.create",
        lambda s, t: (
            _agent_for(s, t),
            s.grant_agent(t, "issue-reporter", "user", "u-2", actor="user:u-1"),
        ),
    ),
    (
        "grant.revoke",
        lambda s, t: (
            _agent_for(s, t),
            s.grant_agent(t, "issue-reporter", "user", "u-2", actor="user:u-1"),
            s.revoke_agent(t, "issue-reporter", "user", "u-2", actor="user:u-1"),
        ),
    ),
    (
        "grant.transfer",
        lambda s, t: (
            _agent_for(s, t),
            s.transfer_agent_ownership(t, "issue-reporter", "user", "u-2",
                                       actor="user:u-1"),
        ),
    ),
    (
        "grant.pending.add",
        lambda s, t: (
            _agent_for(s, t),
            s.add_pending_grant(t, "issue-reporter", "sam@acme.com",
                                actor="user:u-1"),
        ),
    ),
    (
        "grant.pending.claim",
        lambda s, t: (
            _agent_for(s, t),
            s.add_pending_grant(t, "issue-reporter", "sam@acme.com",
                                actor="user:u-1"),
            s.claim_pending_grants(t, "sam@acme.com", "user", "u-9"),
        ),
    ),
    (
        "grant.pending.delete",
        lambda s, t: (
            _agent_for(s, t),
            s.add_pending_grant(t, "issue-reporter", "sam@acme.com",
                                actor="user:u-1"),
            s.delete_pending_grant(t, "issue-reporter", "sam@acme.com",
                                   actor="user:u-1"),
        ),
    ),
    (
        "group.create",
        lambda s, t: _group_for(s, t),
    ),
    (
        "group.delete",
        lambda s, t: (
            _group_for(s, t),
            s.delete_group(t, "g-1", actor="user:u-1"),
        ),
    ),
    (
        "group.link",
        lambda s, t: (
            _group_for(s, t),
            s.set_group_external_id(t, "g-1", "dir-eng", actor="user:u-1"),
        ),
    ),
    (
        "group.member.add",
        lambda s, t: (
            _group_for(s, t),
            s.add_group_member(t, "g-1", "user", "u-2", actor="user:u-1"),
        ),
    ),
    (
        "group.member.remove",
        lambda s, t: (
            _group_for(s, t),
            s.add_group_member(t, "g-1", "user", "u-2", actor="user:u-1"),
            s.remove_group_member(t, "g-1", "user", "u-2", actor="user:u-1"),
        ),
    ),
    # Step 012's six. `save_connector` and `delete_connector` are the two step 011 named
    # as remaining scope; the other four are methods that did not exist then. This list
    # is why they could not ship silent — adding an action to `ADMIN_ACTIONS` without a
    # row here fails `test_the_vocabulary_and_the_in_scope_list_agree`, which is the
    # guard doing the job it was built for rather than a chore.
    (
        "connector.create",
        lambda s, t: s.create_connector(
            t, "jira", launch=_HTTP_LAUNCH, actor="user:u-1"
        ),
    ),
    (
        "connector.save",
        lambda s, t: s.save_connector(t, MANIFEST, actor="user:u-1"),
    ),
    (
        "connector.vet",
        lambda s, t: (
            s.create_connector(t, "jira", launch=_HTTP_LAUNCH, actor="user:u-1"),
            s.vet_tool(
                t,
                "jira",
                {"remote_name": "search_issues", "effect": "read"},
                actor="user:u-1",
            ),
        ),
    ),
    (
        "connector.delete",
        lambda s, t: (
            s.save_connector(t, MANIFEST, actor="user:u-1"),
            s.delete_connector(t, "github-mcp", actor="user:u-1"),
        ),
    ),
    # Step 033c. Trust in a caller being switched — its own action, so a reader never
    # has to diff manifests to learn who turned asserted identity on.
    (
        "connector.asserted_identity",
        lambda s, t: (
            s.create_connector(t, "jira", launch=_HTTP_LAUNCH, actor="user:u-1"),
            s.set_asserted_identity(t, "jira", True, actor="user:u-1"),
        ),
    ),
    (
        "egress.allow",
        lambda s, t: s.allow_host(t, "mcp.example.com", actor="user:u-1"),
    ),
    (
        "egress.revoke",
        lambda s, t: (
            s.allow_host(t, "mcp.example.com", actor="user:u-1"),
            s.revoke_host(t, "mcp.example.com", actor="user:u-1"),
        ),
    ),
    # Step 7b. `DEFERRED.md` named the connection methods as the administrative log's
    # remaining scope, on the grounds that *"a record that somebody connected an account
    # is wanted and the ciphertext must never be near it"* — and 7b is the step that
    # makes connecting something a person does to themselves rather than something an
    # operator does for them, which is what makes the question worth answering.
    (
        "connector.oauth.configure",
        lambda s, t: (
            s.create_connector(t, "jira", launch=_HTTP_LAUNCH, actor="user:u-1"),
            _configure_oauth(s, t),
        ),
    ),
    (
        "connector.oauth.remove",
        lambda s, t: (
            s.create_connector(t, "jira", launch=_HTTP_LAUNCH, actor="user:u-1"),
            _configure_oauth(s, t),
            s.delete_connector_oauth(t, "jira", actor="user:u-1"),
        ),
    ),
    (
        "connection.create",
        lambda s, t: (
            s.create_connector(t, "jira", launch=_HTTP_LAUNCH, actor="user:u-1"),
            s.save_connection(
                t, "user", "u-1", "jira", ciphertext=SEALED, key_id="k1",
                actor="user:u-1",
            ),
        ),
    ),
    (
        "connection.delete",
        lambda s, t: (
            s.create_connector(t, "jira", launch=_HTTP_LAUNCH, actor="user:u-1"),
            s.save_connection(
                t, "user", "u-1", "jira", ciphertext=SEALED, key_id="k1",
                actor="user:u-1",
            ),
            s.delete_connection(t, "user", "u-1", "jira", actor="user:u-1"),
        ),
    ),
    # Step 12b. The two entries whose subject is a **person** — `user` is the first
    # target kind that is not a thing, which is why `ADMIN_TARGET_KINDS` grew.
    (
        "role.grant",
        lambda s, t: s.grant_platform_role(
            t, "user", "u-1", "admin", granted_by="system:cli", actor="system:cli"
        ),
    ),
    (
        "role.revoke",
        lambda s, t: (
            s.grant_platform_role(t, "user", "u-1", "admin", actor="system:cli"),
            s.revoke_platform_role(t, "user", "u-1", "admin", actor="system:cli"),
        ),
    ),
    (
        # Step 018, and the only entry here whose write is a *deletion*. The record is
        # written after the rows go and it names the tenant rather than anything in it,
        # so an old audit row is what has to exist for a prune to have anything to say.
        "retention.prune",
        lambda s, t: (
            # Recent rather than 2020, which is what it was before migration 030: a
            # back-dated write needs a partition to land in, and six years of monthly
            # partitions is 216 CREATE TABLEs to prove one record gets written.
            s.ensure_log_partitions(back_to=_days_ago(120)),
            s.append_audit(t, _record(ts=_days_ago(120))),
            s.prune_log_records(_days_ago(30)),
        ),
    ),
    (
        # Step 020. Minting a credential that submits runs unattended, recorded against
        # the machine it creates — the first entries whose *target* is a principal that
        # is not a person, and deliberately never whose actor is one.
        "token.mint",
        lambda s, t: s.create_api_token(
            t,
            {
                "id": "m_mint",
                "name": "ci",
                "owner_id": "u-1",
                "secret_hash": "sha256$abc",
            },
            actor="system:cli",
        ),
    ),
    (
        "token.revoke",
        lambda s, t: (
            s.create_api_token(
                t,
                {
                    "id": "m_revoke",
                    "name": "ci",
                    "owner_id": "u-1",
                    "secret_hash": "sha256$abc",
                },
                actor="system:cli",
            ),
            s.revoke_api_token(t, "m_revoke", actor="system:cli"),
        ),
    ),
    # Step 022. Note what is *not* here: there is no `schedule.fire`. A fire writes a
    # `runs` row and, when refused, an `access_denials` row — it is not an administrative
    # act, and an entry here would be one log line per schedule per hour forever. Same
    # argument as the absent `token.use`.
    (
        "schedule.create",
        lambda s, t: _schedule_for(s, t, "m_sched_c", "sch_create"),
    ),
    (
        "schedule.enable",
        lambda s, t: (
            _schedule_for(s, t, "m_sched_e", "sch_enable"),
            # Off first: `set_schedule_enabled` is idempotent, so enabling one that is
            # already enabled writes nothing — which is the behaviour under test one
            # entry down, and would make this entry silently prove nothing.
            s.set_schedule_enabled(
                t, "sch_enable", False, next_fire_at=_SOON, actor="user:u-1"
            ),
            s.set_schedule_enabled(
                t, "sch_enable", True, next_fire_at=_SOON, actor="user:u-1"
            ),
        ),
    ),
    (
        "schedule.disable",
        lambda s, t: (
            _schedule_for(s, t, "m_sched_d", "sch_disable"),
            s.set_schedule_enabled(
                t, "sch_disable", False, next_fire_at=_SOON, actor="user:u-1"
            ),
        ),
    ),
    # Step 035k. The edit the register held for five decisions, now that they are made.
    (
        "schedule.update",
        lambda s, t: (
            _schedule_for(s, t, "m_sched_u", "sch_update"),
            s.update_schedule(
                t,
                "sch_update",
                {"task": "a different question"},
                actor="user:u-1",
                if_unchanged_since=s.get_schedule(t, "sch_update")["updated_at"],
            ),
        ),
    ),
    (
        "schedule.delete",
        lambda s, t: (
            _schedule_for(s, t, "m_sched_x", "sch_delete"),
            s.delete_schedule(t, "sch_delete", actor="user:u-1"),
        ),
    ),
    # Step 023, on 022's terms exactly: there is no `trigger.deliver` here, because a
    # delivery is not an administrative act — its record is the `runs` row and the
    # trigger row's own stamp, and an entry per delivery would be a request log.
    (
        "trigger.create",
        lambda s, t: _trigger_for(s, t, "m_trig_c", "trg_create"),
    ),
    (
        "trigger.enable",
        lambda s, t: (
            _trigger_for(s, t, "m_trig_e", "trg_enable"),
            # Off first — `set_trigger_enabled` is idempotent, `schedule.enable`'s
            # entry says why the round trip is load-bearing.
            s.set_trigger_enabled(t, "trg_enable", False, actor="user:u-1"),
            s.set_trigger_enabled(t, "trg_enable", True, actor="user:u-1"),
        ),
    ),
    # Step 035k. Not idempotent and deliberately so — every rotation is a new secret, so
    # every call is a change and every call is recorded. No round trip needed here.
    (
        "trigger.rotate",
        lambda s, t: (
            _trigger_for(s, t, "m_trig_r", "trg_rotate"),
            s.rotate_trigger_secret(
                t,
                "trg_rotate",
                secret_sealed=b"sealed-again",
                secret_key_id="k2",
                actor="user:u-1",
            ),
        ),
    ),
    (
        "trigger.disable",
        lambda s, t: (
            _trigger_for(s, t, "m_trig_d", "trg_disable"),
            s.set_trigger_enabled(t, "trg_disable", False, actor="user:u-1"),
        ),
    ),
    (
        "trigger.delete",
        lambda s, t: (
            _trigger_for(s, t, "m_trig_x", "trg_delete"),
            s.delete_trigger(t, "trg_delete", actor="user:u-1"),
        ),
    ),
    # Step 071. The first records this log writes *about a person* rather than about
    # what a person did, and the seam a directory push and `--disable-user` share.
    (
        "group.rename",
        lambda s, t: (
            _group_for(s, t),
            s.rename_group(t, "g-1", "on-call", actor="user:u-1"),
        ),
    ),
    (
        # Only with an actor — the JIT sign-in path passes none and writes nothing,
        # which `test_a_sign_in_creates_a_person_without_a_record` holds separately.
        "user.create",
        lambda s, t: _person_for(s, t, subject=None, external_id="obj-1", actor="user:u-1"),
    ),
    (
        "user.update",
        lambda s, t: (
            _person_for(s, t),
            s.update_user(t, f"u-{t}", display_name="Priya P.", actor="user:u-1"),
        ),
    ),
    (
        "user.adopt",
        lambda s, t: (
            _person_for(s, t, subject=None),
            s.adopt_user_subject(t, f"u-{t}", "sub-adopted", actor="system:directory"),
        ),
    ),
    (
        "user.disable",
        lambda s, t: (
            _person_for(s, t),
            s.set_user_status(t, f"u-{t}", "disabled", actor="user:u-1"),
        ),
    ),
    (
        "user.enable",
        lambda s, t: (
            _person_for(s, t),
            # Off first — `set_user_status` writes nothing for a status already held,
            # `schedule.enable`'s entry says why the round trip is load-bearing.
            s.set_user_status(t, f"u-{t}", "disabled", actor="user:u-1"),
            s.set_user_status(t, f"u-{t}", "active", actor="user:u-1"),
        ),
    ),
    (
        "scim.token.mint",
        lambda s, t: _scim_for(s, t),
    ),
    (
        "scim.token.revoke",
        lambda s, t: s.revoke_scim_token(t, _scim_for(s, t), actor="user:u-1"),
    ),
)


def _configure_oauth(store, tenant, connector_id="jira", **overrides):
    """One configured consent flow. The arguments nobody varies, in one place."""
    kwargs = {
        "authorize_endpoint": "https://auth.example.com/authorize",
        "token_endpoint": "https://auth.example.com/token",
        "client_id": "client-abc",
        "client_secret": b"sealed-client-secret",
        "key_id": "k1",
        "scopes": ("read:jira-work", "offline_access"),
        "actor": "user:u-1",
    }
    kwargs.update(overrides)
    return store.set_connector_oauth(tenant, connector_id, **kwargs)


@pytest.mark.parametrize("action,write", IN_SCOPE, ids=[a for a, _ in IN_SCOPE])
def test_every_in_scope_method_leaves_a_record(store, tenant, action, write):
    """The step's first verification: no in-scope write is silent.

    Parametrised over `IN_SCOPE` rather than written thirteen times, so a method that
    joins the list without a hook is a **failing test** rather than a gap nobody
    notices. That is the shape `RUN_FIELDS` has, and it exists because the alternative
    has already failed once here: `audit.credential` shipped written by one store and
    dropped by the other, with the whole suite green.

    A tenant per case, because `tenant` truncates the test id at 60 characters and three
    of these parametrisations collide past that — and because a log holding only this
    case's writes is what makes the assertion readable when it fails.
    """
    scoped = f"{action}-{tenant}"[:60]
    store.create_tenant(scoped, "In Scope")

    write(store, scoped)

    actions = [r["action"] for r in store.admin_audit_records(scoped)]
    assert action in actions, f"{action} left no record; the log has {actions}"


def test_every_principal_kind_is_sorted_into_one_of_the_two_actor_sets():
    """A fourth principal kind must be *placed*, not merely added. Step 020.

    `PRINCIPAL_KINDS` is who may act; `ADMIN_ACTOR_KINDS` is who may perform an
    administrative act, and until 020 they were the same frozenset, which is why
    `split_actor` read the wrong one for free. They are not the same question, and the
    difference is the whole of this step's containment: a machine submits runs and
    administers nothing.

    This is deliberately an equality against a literal rather than a subset check.
    Adding a kind to `PRINCIPAL_KINDS` fails here until somebody writes down which side
    it belongs on — and if the answer is "an administrator", that edit sits in a diff
    beside `admin_audit.actor_kind`'s CHECK, where a reviewer will see it.
    """
    from carnet.storage import ADMIN_ACTOR_KINDS, PRINCIPAL_KINDS

    assert ADMIN_ACTOR_KINDS <= PRINCIPAL_KINDS
    assert PRINCIPAL_KINDS - ADMIN_ACTOR_KINDS == {"machine"}


def test_the_vocabulary_and_the_in_scope_list_agree(store, tenant):
    """`ADMIN_ACTIONS` is not in a CHECK constraint — see migration 022 — so this is
    what stops it drifting from the methods that produce it, in both directions."""
    from carnet.storage import ADMIN_ACTIONS

    assert {action for action, _ in IN_SCOPE} == set(ADMIN_ACTIONS)


def test_a_record_carries_every_field_through_both_stores(store, tenant):
    """`ADMIN_AUDIT_FIELDS` and nothing else, in both stores.

    The `RUN_FIELDS` assertion, applied to a table one step old rather than seven. A
    field written by Postgres and dropped by the fake is the failure this whole file
    exists for, and it is cheapest to close before there is anything to migrate.
    """
    from carnet.storage import ADMIN_AUDIT_FIELDS, ADMIN_AUDIT_V

    store.create_agent(tenant, AGENT, "user", "u-priya")

    (row,) = store.admin_audit_records(tenant)
    assert set(row) == set(ADMIN_AUDIT_FIELDS)
    assert row["v"] == ADMIN_AUDIT_V
    assert (row["actor_kind"], row["actor_id"]) == ("user", "u-priya")
    assert (row["target_kind"], row["target_id"]) == ("agent", "issue-reporter")
    # An ISO string in both stores, for the reason `audit_records` returns one.
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT[\d:.]+\+00:00", row["ts"]), row["ts"]


def test_a_revocation_names_who_did_it(store, tenant):
    """**The question the schema could not answer, and the reason the step exists.**

    `agent_grants.granted_by` records who granted access and is destroyed by the
    revocation it should have recorded. Before this there was nowhere at all that said
    Priya took Sam's editor grant away, or that it had been `editor` rather than `user`.
    """
    _agent_for(store, tenant)
    store.grant_agent(tenant, "issue-reporter", "user", "u-sam", role="editor",
                      granted_by="user:u-priya", actor="user:u-priya")

    store.revoke_agent(tenant, "issue-reporter", "user", "u-sam", actor="user:u-priya")

    (revoked,) = store.admin_audit_records(tenant, action="grant.revoke")
    assert (revoked["actor_kind"], revoked["actor_id"]) == ("user", "u-priya")
    assert revoked["target_id"] == "issue-reporter"
    assert revoked["detail"]["grantee_id"] == "u-sam"
    # The level that was taken away, which existed for the length of one DELETE.
    assert revoked["detail"]["role"] == "editor"


def test_a_revocation_of_a_grant_nobody_had_is_not_a_record(store, tenant):
    """Idempotent, and silent. The log has to read as "what access moved" — a record
    for a revoke that removed nothing makes "who took Sam's access away" ambiguous in
    exactly the situation it is asked in."""
    _agent_for(store, tenant)

    store.revoke_agent(tenant, "issue-reporter", "user", "nobody", actor="user:u-1")

    assert store.admin_audit_records(tenant, action="grant.revoke") == []


def test_deleting_an_agent_that_was_never_there_is_not_a_record(store, tenant):
    store.delete_agent(tenant, "no-such-agent", actor="user:u-1")

    assert store.admin_audit_records(tenant, action="agent.delete") == []


def test_adding_somebody_already_in_a_group_is_not_a_second_record(store, tenant):
    """`ON CONFLICT DO NOTHING`, and nothing means no record: nobody's access changed."""
    _group_for(store, tenant)
    store.add_group_member(tenant, "g-1", "user", "u-2", actor="user:u-1")
    store.add_group_member(tenant, "g-1", "user", "u-2", actor="user:u-1")

    assert len(store.admin_audit_records(tenant, action="group.member.add")) == 1


def test_deleting_a_group_records_how_much_access_went_with_it(store, tenant):
    """The cascade is the whole consequence of the call, and after it there is nothing
    left to count. Removing a group takes away every access it carried, on every
    agent — the numbers are the only thing that ever says how much."""
    _agent_for(store, tenant)
    _group_for(store, tenant)
    store.add_group_member(tenant, "g-1", "user", "u-2", actor="user:u-1")
    store.grant_agent(tenant, "issue-reporter", "group", "g-1", actor="user:u-1")

    store.delete_group(tenant, "g-1", actor="user:u-priya")

    (gone,) = store.admin_audit_records(tenant, action="group.delete")
    assert gone["detail"] == {"name": "oncall", "members": 1, "grants": 1}


def test_a_transfer_names_the_person_who_stepped_down(store, tenant):
    """A transfer changes two people's access at once. A record naming only the
    recipient would leave the demotion unattributed, which is the same half-a-record
    the whole step is about."""
    store.create_agent(tenant, AGENT, "user", "u-priya")

    store.transfer_agent_ownership(tenant, "issue-reporter", "user", "u-sam",
                                   actor="user:u-priya")

    (moved,) = store.admin_audit_records(tenant, action="grant.transfer")
    assert moved["detail"]["to_id"] == "u-sam"
    assert (moved["detail"]["from_kind"], moved["detail"]["from_id"]) == ("user", "u-priya")
    assert moved["detail"]["from_role"] == "editor"


def test_a_claim_names_the_claimant_and_keeps_who_shared_it(store, tenant):
    """Two different people, and the record must not merge them: the actor is whoever
    just logged in, and `granted_by` is whoever shared it, possibly weeks earlier."""
    _agent_for(store, tenant)
    store.add_pending_grant(tenant, "issue-reporter", "sam@acme.com", role="editor",
                            granted_by="user:u-priya", actor="user:u-priya")

    store.claim_pending_grants(tenant, "sam@acme.com", "user", "u-sam")

    (claimed,) = store.admin_audit_records(tenant, action="grant.pending.claim")
    assert (claimed["actor_kind"], claimed["actor_id"]) == ("user", "u-sam")
    assert claimed["detail"]["granted_by"] == "user:u-priya"
    assert claimed["detail"]["applied"] is True


def test_an_actor_that_is_not_a_principal_is_refused(store, tenant):
    """A group may hold a grant and may not take one away. Refused in Python here and
    by `admin_audit_actor_kind_check` in the column — see migration 022, and 017 for
    why a rule in a constant alone does not survive somebody widening the constant."""
    _agent_for(store, tenant)
    store.grant_agent(tenant, "issue-reporter", "user", "u-2", actor="user:u-1")

    with pytest.raises(StorageError, match="principal_kind must be one of"):
        store.revoke_agent(tenant, "issue-reporter", "user", "u-2", actor="group:eng")

    # And the grant is still there: a refused record takes its write with it.
    assert store.direct_agent_grant_role(tenant, "issue-reporter", "user", "u-2")


@pytest.mark.parametrize("actor", ["", "u-1", "user:", ":u-1"])
def test_an_actor_that_is_not_a_pair_is_refused(store, tenant, actor):
    """No default and no half-actor. A record that can say nobody did it is worse than
    no record, because it looks like an answer."""
    _agent_for(store, tenant)

    with pytest.raises(StorageError):
        store.delete_agent(tenant, "issue-reporter", actor=actor)


def test_a_refused_actor_leaves_the_write_undone(store, tenant):
    """The other direction of the same transaction, and the one worth asserting: a
    record the store will not accept takes its write with it."""
    _agent_for(store, tenant)

    with pytest.raises(StorageError):
        store.delete_agent(tenant, "issue-reporter", actor="group:eng")

    assert store.get_agent(tenant, "issue-reporter") is not None


def test_no_record_carries_an_agents_system_prompt(store, tenant):
    """`detail` is what CHANGED, never the contents of every field.

    The system prompt is free text a person typed, which is exactly the class `audit`'s
    redaction exists to keep out of a record kept forever — and it is the field somebody
    will add, because it is the interesting one. Nothing in `make_admin_record` can
    enforce a rule about meaning, so this is the enforcement.
    """
    secret = "MARKER-do-not-store-this-prompt"
    config = {**AGENT, "system": secret, "description": secret}

    store.create_agent(tenant, config, "user", "u-1")
    store.save_agent(tenant, {**config, "name": "second"}, actor="user:u-1")

    assert secret not in json.dumps(store.admin_audit_records(tenant))


def test_a_record_says_what_the_agent_can_reach(store, tenant):
    """What *is* kept, and why: the scope is the thing an incident asks about, and it
    is patterns from the catalogue rather than anything typed free hand."""
    store.create_agent(tenant, AGENT, "user", "u-1")

    (created,) = store.admin_audit_records(tenant, action="agent.create")
    assert created["detail"]["tools"] == ["post_message"]
    assert created["detail"]["scope"] == {"chat.channel": {"write": ["#eng"]}}
    assert "system" not in created["detail"]["fields"]
    assert "permissions" in created["detail"]["fields"]


def test_admin_records_are_oldest_first(store, tenant):
    """Ordered by insertion rather than by `ts`, the same as `audit_records`: two
    records written in the same millisecond are ambiguous by timestamp and exact by
    insertion order, and the sequence is the thing being read."""
    _agent_for(store, tenant, "alpha")
    _agent_for(store, tenant, "beta")
    store.delete_agent(tenant, "alpha", actor="user:u-1")

    assert [r["target_id"] for r in store.admin_audit_records(tenant)] == [
        "alpha", "beta", "alpha",
    ]


def test_a_limit_returns_the_most_recent_still_oldest_first(store, tenant):
    _agent_for(store, tenant, "alpha")
    _agent_for(store, tenant, "beta")
    _agent_for(store, tenant, "gamma")

    recent = store.admin_audit_records(tenant, limit=2)
    assert [r["target_id"] for r in recent] == ["beta", "gamma"]
    assert store.admin_audit_records(tenant, limit=0) == []


def test_records_can_be_read_for_one_target(store, tenant):
    """"Everything that ever happened to this agent" is the incident query, and the
    reason a grant is recorded against its agent rather than against its grantee."""
    _agent_for(store, tenant, "alpha")
    _agent_for(store, tenant, "beta")
    store.grant_agent(tenant, "alpha", "user", "u-2", actor="user:u-1")

    for_alpha = store.admin_audit_records(tenant, target_kind="agent", target_id="alpha")
    assert [r["action"] for r in for_alpha] == ["agent.save", "grant.create"]


def test_admin_records_are_invisible_across_tenants(store, tenant, other):
    store.create_agent(tenant, AGENT, "user", "u-1")

    assert store.admin_audit_records(other) == []


def test_the_interface_offers_no_way_to_write_a_record_directly(store):
    """**There is no `append_admin_audit`, and its absence is the design.**

    Records are written by the storage methods themselves, inside the transaction that
    performs the write. A public append would be a second way to produce one — which
    means a record that can be absent when the write succeeded, and a record that can
    exist when nothing happened. Both failures are silent.
    """
    assert not [
        name
        for name in dir(store)
        if "admin" in name and name not in {"admin_audit_records", "_admin",
                                            "_append_admin", "_write_admin",
                                            "_ADMIN_COLUMNS", "_ADMIN_INSERT"}
    ]


def test_mutating_a_returned_record_does_not_change_the_store(store, tenant):
    store.create_agent(tenant, AGENT, "user", "u-1")

    store.admin_audit_records(tenant)[0]["detail"]["tools"].append("tampered")

    (row,) = store.admin_audit_records(tenant)
    assert row["detail"]["tools"] == ["post_message"]


# --- the access-denial log (migration 028) ----------------------------------------
#
# The third log: who tried, and was refused. `record_denial` is public where
# `append_admin_audit` deliberately does not exist, and the difference is the design
# rather than drift — a denial performs no write and rides no transaction, so there is
# nothing for its record to be atomic with. The shape rules are its two siblings',
# held with the same device: `DENIAL_FIELDS`, applied at birth rather than
# retrofitted.


def _denial(**overrides):
    from carnet.storage.base import make_denial_record

    kwargs = dict(
        principal_kind="user",
        principal_id="u-sam",
        resource_kind="agent",
        resource_id="payroll-bot",
        required="user",
        held="",
    )
    kwargs.update(overrides)
    return make_denial_record(**kwargs)


def test_a_denial_round_trips_with_exactly_its_fields(store, tenant):
    """`DENIAL_FIELDS` and nothing else, in both stores — the `RUN_FIELDS` assertion,
    applied at birth. A field written by Postgres and dropped by the fake is the
    failure this whole file exists for."""
    from carnet.storage import DENIAL_FIELDS, DENIAL_V

    store.record_denial(tenant, _denial(held="user", required="editor"))

    (row,) = store.denial_records(tenant)
    assert set(row) == set(DENIAL_FIELDS)
    assert row["v"] == DENIAL_V
    assert (row["principal_kind"], row["principal_id"]) == ("user", "u-sam")
    assert (row["resource_kind"], row["resource_id"]) == ("agent", "payroll-bot")
    assert (row["required"], row["held"]) == ("editor", "user")
    # An ISO string in both stores, for the reason `audit_records` returns one.
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT[\d:.]+\+00:00", row["ts"]), row["ts"]


def test_a_denial_may_name_the_administrative_surface(store, tenant):
    """The `require_admin` shape: `resource_kind='admin'`, the caller's `what` as the
    resource id — which may be empty, because many callers pass none, and refusing
    that would turn the hook into a parameter every caller must remember."""
    store.record_denial(
        tenant,
        _denial(resource_kind="admin", resource_id="", required="admin"),
    )

    (row,) = store.denial_records(tenant)
    assert (row["resource_kind"], row["resource_id"]) == ("admin", "")
    assert row["held"] == ""


def test_denials_are_oldest_first_and_limit_returns_the_most_recent(store, tenant):
    """Insertion order, `limit` takes the tail still oldest-first — the ordering rules
    every log here shares, because two logs whose read methods disagreed would be two
    things to remember."""
    for name in ("alpha", "beta", "gamma"):
        store.record_denial(tenant, _denial(resource_id=name))

    assert [r["resource_id"] for r in store.denial_records(tenant)] == [
        "alpha", "beta", "gamma",
    ]
    assert [r["resource_id"] for r in store.denial_records(tenant, limit=2)] == [
        "beta", "gamma",
    ]
    assert store.denial_records(tenant, limit=0) == []


def test_denials_can_be_read_for_one_principal_and_one_resource(store, tenant):
    """The two incident queries migration 028's second and third indexes exist for:
    "what else did this person probe?" and "who probed payroll-bot?"."""
    store.record_denial(tenant, _denial(principal_id="u-sam", resource_id="alpha"))
    store.record_denial(tenant, _denial(principal_id="u-sam", resource_id="beta"))
    store.record_denial(tenant, _denial(principal_id="u-priya", resource_id="alpha"))

    sams = store.denial_records(tenant, principal_kind="user", principal_id="u-sam")
    assert [r["resource_id"] for r in sams] == ["alpha", "beta"]

    alphas = store.denial_records(tenant, resource_kind="agent", resource_id="alpha")
    assert [r["principal_id"] for r in alphas] == ["u-sam", "u-priya"]


def test_a_filtered_denial_limit_counts_matches_and_not_rows(store, tenant):
    """The way a filtered log reader goes wrong that ordering tests miss: taking the tail
    of the *table* and then filtering returns fewer rows than asked for — often none —
    whenever the unfiltered kind outnumbers the filtered one, which is every real
    deployment. Both stores must filter first and limit second.

    035a pinned this for `door_call_records` and it was never pinned here, because until
    035b no `resource_kind` reached this method from outside the process. It does now,
    and this is the shape the failure would take: `?resource_kind=tool&limit=200`
    answering `[]` while the log holds tool refusals — which reads as *"the door has
    refused nothing"*, the exact sentence a filtered log view must never say by accident.
    """
    for i in range(10):
        store.record_denial(tenant, _denial(resource_id=f"agent_{i}"))
    for i in range(3):
        store.record_denial(
            tenant, _denial(resource_kind="tool", resource_id=f"tool_{i}")
        )
    for i in range(10, 20):
        store.record_denial(tenant, _denial(resource_id=f"agent_{i}"))

    # The most recent two *tool* refusals, still oldest-first — not the last two rows of
    # the table, which are agents.
    assert [
        r["resource_id"]
        for r in store.denial_records(tenant, resource_kind="tool", limit=2)
    ] == ["tool_1", "tool_2"]

    # And the filters compose without either one being applied after the tail is taken.
    assert [
        r["resource_id"]
        for r in store.denial_records(
            tenant, principal_id="u-sam", resource_kind="tool", limit=1
        )
    ] == ["tool_2"]


def test_denials_are_invisible_across_tenants(store, tenant, other):
    store.record_denial(tenant, _denial())

    assert store.denial_records(other) == []


def test_a_denial_about_nothing_recordable_is_refused(store, tenant):
    """The kind checks at the builder. A group never makes a request, and 'run' is not
    a thing a refusal is about.

    This used to say "both stores build the record there, so a record one accepts is not
    one the other quietly rejects" — true of the one production caller and **not of the
    interface**, which is what 035b found and the three tests below now cover:
    `record_denial` is public, and until then the fake took what the column refuses."""
    with pytest.raises(StorageError, match="principal_kind must be one of"):
        _denial(principal_kind="group")

    with pytest.raises(StorageError, match="not something a denial can be about"):
        _denial(resource_kind="run")


# --- the fake is not more permissive than the column (035b) ------------------------
#
# 035a found `audit`'s split — both stores accepting a partial record and reading it back
# differently — and asked whether this table had the same one. It has a split, and it is
# the other direction. `access_denials` has no optional columns to normalize: all eight
# are NOT NULL and `make_denial_record` sets all eight. What differed was **accept versus
# refuse**, with the fake as the permissive one — the exact shape of fake this whole file
# exists to catch, and it had no test because the one production caller builds through
# the validating builder.
#
# The kind cases assert `StorageError` without matching a message on purpose: the two
# stores raise for the same reason in different words, the fake naming the constant and
# Postgres naming the constraint, and pinning either sentence here would be asserting
# which store ran.


def test_a_denial_of_an_impossible_kind_is_refused_by_both_stores(store, tenant):
    """Reaching past `make_denial_record` to `record_denial`, which is public on the
    protocol. Postgres refuses both of these on a CHECK; until 035b the fake stored them
    and `denial_records(resource_kind='banana')` found them again."""
    good = _denial()

    with pytest.raises(StorageError):
        store.record_denial(tenant, {**good, "resource_kind": "banana"})

    with pytest.raises(StorageError):
        store.record_denial(tenant, {**good, "principal_kind": "group"})

    assert store.denial_records(tenant) == []


def test_a_denial_missing_a_column_is_refused_by_both_stores(store, tenant):
    """`held` is NOT NULL, and Postgres' INSERT reads `record["held"]`, so a record
    without it has always been a `KeyError` there. The fake stored it and read it back
    without the key — which `api.schemas.DenialRecord` would then have defaulted to `''`,
    inventing *"they held nothing"* about somebody in an incident log."""
    partial = {k: v for k, v in _denial().items() if k != "held"}

    with pytest.raises(KeyError):
        store.record_denial(tenant, partial)

    assert store.denial_records(tenant) == []


def test_a_key_the_column_list_does_not_name_is_dropped_by_both_stores(store, tenant):
    """The last row of the same table. Postgres' INSERT names its columns, so an extra
    key was never stored; the fake kept and returned it, which is a record that means one
    thing in the fake and another in production."""
    store.record_denial(tenant, {**_denial(), "note": "not a column"})

    (row,) = store.denial_records(tenant)
    assert "note" not in row


def test_the_interface_offers_no_update_or_delete_for_denials(store):
    """Append and read are the whole surface. An update or delete method on a log
    kept for incidents would be a record of what somebody was willing to leave
    behind — the same rule the triggers enforce in Postgres, held here in the shape
    of the interface."""
    assert not [
        name
        for name in dir(store)
        if "denial" in name.lower()
        and name not in {"record_denial", "denial_records", "_denials",
                         "_DENIAL_COLUMNS", "_DENIAL_INSERT"}
    ]


def test_mutating_a_returned_denial_does_not_change_the_store(store, tenant):
    store.record_denial(tenant, _denial())

    store.denial_records(tenant)[0]["held"] = "owner"

    (row,) = store.denial_records(tenant)
    assert row["held"] == ""


# --- Postgres only: guarantees the database makes and a dict cannot ---------------
#
# These are the rules that exist as schema rather than as Python. They cannot be
# asserted against the in-memory store because there is nothing there to enforce them
# — which is precisely why they are worth testing against the real engine.


@pytest.fixture
def pg(request, pg_dsn):
    from carnet.storage.postgres import PostgresStorage

    storage = PostgresStorage(pg_dsn)
    tenant_id = f"pg-{request.node.name}"[:60]
    storage.create_tenant(tenant_id, "PG Test")
    yield storage, tenant_id
    storage.close()


def test_audit_rows_cannot_be_updated(pg):
    """The audit trail is the enforcement history. If it can be edited, it is a
    record of what someone was willing to leave behind."""
    store, tenant_id = pg
    store.append_audit(tenant_id, _record())

    with pytest.raises(StorageError, match="append-only"):
        store._execute("UPDATE audit SET reason = 'tampered' WHERE tenant_id = %s",
                       (tenant_id,))


def test_audit_rows_cannot_be_deleted(pg):
    store, tenant_id = pg
    store.append_audit(tenant_id, _record())

    with pytest.raises(StorageError, match="append-only"):
        store._execute("DELETE FROM audit WHERE tenant_id = %s", (tenant_id,))


def test_admin_audit_rows_cannot_be_updated(pg):
    """Migration 022, 005's trigger in its own copy. This is the only record of who
    took access away; if it can be edited it is a record of what somebody was willing
    to leave behind."""
    store, tenant_id = pg
    store.save_agent(tenant_id, AGENT, actor="user:u-1")

    with pytest.raises(StorageError, match="append-only"):
        store._execute(
            "UPDATE admin_audit SET actor_id = 'somebody-else' WHERE tenant_id = %s",
            (tenant_id,),
        )


def test_admin_audit_rows_cannot_be_deleted(pg):
    store, tenant_id = pg
    store.save_agent(tenant_id, AGENT, actor="user:u-1")

    with pytest.raises(StorageError, match="append-only"):
        store._execute("DELETE FROM admin_audit WHERE tenant_id = %s", (tenant_id,))


def test_denial_rows_cannot_be_updated(pg):
    """Migration 028, 005's trigger on the third table. The only record of who tried
    and was refused; if it can be edited it is a record of what somebody was willing
    to leave behind."""
    store, tenant_id = pg
    store.record_denial(tenant_id, _denial())

    with pytest.raises(StorageError, match="append-only"):
        store._execute(
            "UPDATE access_denials SET principal_id = 'somebody-else' "
            "WHERE tenant_id = %s",
            (tenant_id,),
        )


def test_denial_rows_cannot_be_deleted(pg):
    store, tenant_id = pg
    store.record_denial(tenant_id, _denial())

    with pytest.raises(StorageError, match="append-only"):
        store._execute("DELETE FROM access_denials WHERE tenant_id = %s", (tenant_id,))


def test_the_denial_kind_checks_are_in_the_columns_not_only_in_python(pg):
    """Migration 017's precedent, applied twice: `PRINCIPAL_KINDS` and
    `DENIAL_RESOURCE_KINDS` are constants the next caller can widen, so the words are
    in CHECKs too — asserted by reaching past `make_denial_record` to write the rows
    the Python guard exists to refuse."""
    store, tenant_id = pg

    with pytest.raises(StorageError, match="access_denials_principal_kind_check"):
        store._execute(
            store._DENIAL_INSERT,
            (tenant_id, 1, datetime.now(timezone.utc), "group", "eng",
             "agent", "payroll-bot", "user", ""),
        )

    with pytest.raises(StorageError, match="access_denials_resource_kind_check"):
        store._execute(
            store._DENIAL_INSERT,
            (tenant_id, 1, datetime.now(timezone.utc), "user", "u-sam",
             "run", "r-1", "user", ""),
        )


def test_the_actor_check_is_in_the_column_not_only_in_python(pg):
    """Migration 017's precedent, applied to `actor_kind`.

    A rule that lives in `PRINCIPAL_KINDS` is one the next caller widens, and a test
    written in the same language as the constant does not survive somebody widening it.
    So the words are in a CHECK, and this is the assertion that they are — reaching past
    `split_actor` to write the row the Python guard exists to refuse.
    """
    store, tenant_id = pg

    with pytest.raises(StorageError, match="admin_audit_actor_kind_check"):
        store._execute(
            store._ADMIN_INSERT,
            (tenant_id, 1, datetime.now(timezone.utc), "group", "eng",
             "grant.revoke", "agent", "issue-reporter", "{}"),
        )


def test_an_empty_actor_is_refused_by_the_column_too(pg):
    """The other half of "there is no default": a blank actor is a record that says
    nobody did it, which is worse than no record because it looks like an answer."""
    store, tenant_id = pg

    with pytest.raises(StorageError, match="admin_audit_actor_id_check"):
        store._execute(
            store._ADMIN_INSERT,
            (tenant_id, 1, datetime.now(timezone.utc), "user", "",
             "grant.revoke", "agent", "issue-reporter", "{}"),
        )


@pytest.mark.parametrize(
    "write,survives",
    [
        (
            lambda s, t: s.delete_agent(t, "issue-reporter", actor="user:u-1"),
            "agent.delete",
        ),
        # **Added by 10d, and it is not a repeat.** `update_agent` is a *third* write
        # method with its own transaction, and it is the one whose two statements are
        # furthest apart in what they mean: a compare-and-set and a log entry. A version
        # of it that opened no transaction would pass every other test in this file —
        # the guard would still guard and the record would still be written — and would
        # leave a config replaced with nobody's name on the replacement.
        (
            lambda s, t: _edit(s, t, system="Edited."),
            "agent.update",
        ),
    ],
    ids=["delete_agent", "update_agent"],
)
def test_a_write_whose_record_is_refused_leaves_nothing_behind(
    pg, monkeypatch, write, survives
):
    """**Decision 2, forced at the database.** The step's second verification.

    The record is written in the same transaction as the write, which buys two
    properties, and only one of them is visible from a successful call: no write can
    succeed without its record. This asserts the *other* one — that a record the
    database refuses takes the write down with it — by making `make_admin_record`
    produce a row `admin_audit_actor_kind_check` will not accept.

    Reaching that means stepping past `split_actor`, exactly as
    `test_the_agent_and_its_owner_grant_are_one_transaction` steps past
    `check_principal_kind`: what is under test is what the transaction does when the
    second statement fails, not which layer catches a bad actor first.

    Without the transaction this leaves an agent deleted and no record of who deleted
    it — which is precisely the artifact the step exists to make impossible.
    """
    from carnet.storage import base as base_module
    from carnet.storage import postgres as postgres_module

    store, tenant_id = pg
    store.save_agent(tenant_id, AGENT, actor="user:u-1")

    real = base_module.make_admin_record

    def forged(action, target_kind, target_id, actor, detail=None):
        record = real(action, target_kind, target_id, "user:u-1", detail)
        # A kind the column refuses and Python has already waved through.
        return {**record, "actor_kind": "group"}

    monkeypatch.setattr(postgres_module, "make_admin_record", forged)

    with pytest.raises(StorageError, match="admin_audit_actor_kind_check"):
        write(store, tenant_id)

    # The row is still there and still says what it said. `AGENT` rather than merely
    # "not None", because the update case fails only on the *contents*: a torn update
    # leaves an agent that exists and is somebody else's version of it.
    assert store.get_agent(tenant_id, "issue-reporter")["config"] == AGENT
    assert store.admin_audit_records(tenant_id, action=survives) == []
    # **And no history for a configuration that was never stored** — step 021's half of
    # the same property. The version row rides this transaction too, so a version of
    # `update_agent` that wrote it outside one would leave `agent_versions` offering a
    # restore of a config the agent never held, with nothing else in this file failing.
    assert [
        row["version"] for row in store.list_agent_versions(tenant_id, "issue-reporter")
    ] == [1]


def test_a_tenant_with_administrative_records_cannot_be_deleted(pg):
    """The same deliberate consequence 005 records for `audit`, and it matters more
    here: you cannot offboard a customer and silently erase who was given access to
    what, and who took it back."""
    store, tenant_id = pg
    store.save_agent(tenant_id, AGENT, actor="user:u-1")

    with pytest.raises(StorageError, match="admin_audit"):
        store._execute("DELETE FROM tenants WHERE id = %s", (tenant_id,))


def test_an_agent_row_cannot_disagree_with_its_config(pg):
    """The broker trusts config['name'] as identity and writes it into every audit
    record. A row keyed 'alpha' holding a config named 'beta' would misattribute
    everything that agent did. This was an import-time check; the CHECK constraint is
    where it went."""
    store, tenant_id = pg

    with pytest.raises(StorageError, match="agent_name_matches_config"):
        store._execute(
            "INSERT INTO agents (tenant_id, agent_id, name, config) "
            "VALUES (%s, %s, %s, %s)",
            (tenant_id, new_agent_id(), "alpha", json.dumps({"name": "beta"})),
        )


def test_an_agent_name_is_a_slug_in_the_column_not_only_in_python(pg):
    """Migration 019, reached past the Python guard.

    The lesson of migration 017 one layer down: a rule that lives only in a constant is
    a rule the next caller widens, and a test written in the same language as the
    constant does not survive somebody widening it. This one goes around `check_agent_name`
    entirely and asks the column.
    """
    store, tenant_id = pg

    with pytest.raises(StorageError, match="agent_name_is_a_slug"):
        store._execute(
            "INSERT INTO agents (tenant_id, agent_id, name, config) "
            "VALUES (%s, %s, %s, %s)",
            (
                tenant_id,
                new_agent_id(),
                "Triage Bot",
                json.dumps({"name": "Triage Bot"}),
            ),
        )


def test_the_agent_and_its_owner_grant_are_one_transaction(pg, monkeypatch):
    """The property that cannot be observed from a successful create.

    Both statements succeed in every ordinary call, so "is this atomic?" is invisible
    unless the second one is made to fail — and the failure has to be a real one, at the
    database, after the first statement has already run. `agent_grants_no_group_owner`
    (migration 017) is exactly that: a group may hold a grant and may not hold *this*
    one, so the row lands and the grant is refused by the column.

    Reaching it means stepping past `check_principal_kind`, which is the Python guard
    that normally refuses this before any write. Bypassing it is the whole method: what
    is under test is what happens when the second statement fails, not which layer
    catches a group.

    **Two guards since step 011, and they are not the same guard.** The owner is checked
    as a principal by `create_agent`, and then again by `make_admin_record`, because the
    owner is also the *actor* on the `agent.create` record and `admin_audit.actor_kind`
    has its own CHECK. Both have to be stood down to reach the database, which is worth
    noticing rather than routing around: a group can no longer own an agent even if
    somebody deletes one of the two checks.

    Without the transaction this leaves an agent with no owner — a row that looks
    perfectly healthy and that nobody, including its author, can run. That is the
    artifact four handoffs have warned about, and it is invisible until somebody tries.
    """
    from carnet.storage import base as base_module
    from carnet.storage import postgres as postgres_module

    store, tenant_id = pg
    monkeypatch.setattr(postgres_module, "check_principal_kind", lambda kind: None)
    monkeypatch.setattr(base_module, "check_principal_kind", lambda kind: None)

    with pytest.raises(StorageError, match="agent_grants_no_group_owner"):
        store.create_agent(tenant_id, AGENT, "group", "eng")

    assert store.get_agent(tenant_id, "issue-reporter") is None


def test_a_tenant_with_audit_records_cannot_be_deleted(pg):
    """No ON DELETE CASCADE from tenants to audit, deliberately: removing a customer
    must not silently erase the record of what their agents did."""
    store, tenant_id = pg
    store.append_audit(tenant_id, _record())

    with pytest.raises(StorageError):
        store._execute("DELETE FROM tenants WHERE id = %s", (tenant_id,))


def test_deleting_a_connector_removes_its_vetted_tools(pg):
    """This cascade IS wanted: a vetting decision has no meaning without the connector
    it was made about."""
    store, tenant_id = pg
    store.save_connector(tenant_id, MANIFEST, actor=TEST_ACTOR)

    count = "SELECT count(*) FROM vetted_tools WHERE tenant_id = %s"
    assert store._fetchone(count, (tenant_id,))[0] == 1

    store.delete_connector(tenant_id, "github-mcp", actor=TEST_ACTOR)

    assert store._fetchone(count, (tenant_id,))[0] == 0


def test_re_vetting_replaces_the_allowlist_rather_than_merging(pg):
    """The manifest IS the allowlist, so a tool absent from it must stop being vetted.
    Merging would make un-vetting require an explicit delete — and the step nobody
    remembers is exactly the one that must not be required."""
    store, tenant_id = pg
    store.save_connector(
        tenant_id,
        {
            **MANIFEST,
            "vetted": [
                *MANIFEST["vetted"],
                {
                    "remote_name": "add_issue_comment",
                    # A read, because a write with no resources is now refused at this
                    # boundary — `check_vetted_tool`. This test is about two tenants
                    # vetting differently, not about effects, so the cheapest legal row
                    # is the right one.
                    "effect": "read",
                    "resources": [],
                    "local_name": None,
                    "max_response_bytes": None,
                },
            ],
        },
    actor=TEST_ACTOR,
    )
    assert len(store.get_connector(tenant_id, "github-mcp")["vetted"]) == 2

    store.save_connector(tenant_id, MANIFEST, actor=TEST_ACTOR)

    remaining = store.get_connector(tenant_id, "github-mcp")["vetted"]
    assert [v["remote_name"] for v in remaining] == ["list_issues"]


def test_migrations_are_idempotent(pg_dsn):
    """Running them on every deploy is the intended usage, not a thing to be careful
    about. The session fixture already applied them, so a second pass does nothing."""
    from carnet.storage import migrate

    assert migrate.apply(pg_dsn) == []


def test_every_migration_on_disk_was_applied(pg_dsn):
    """Guards the packaging: a .sql file that ships but never runs is a schema the
    code expects and the database does not have."""
    import psycopg

    from carnet.storage import migrate

    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        rows = conn.execute("SELECT version FROM schema_migrations").fetchall()

    assert {r[0] for r in rows} == {version for version, _ in migrate.available()}


# --- the promise the runner enforces (027) ------------------------------------------
#
# Each of these mutates the ledger and puts it back, because the session fixture
# migrated this database once and every test after them shares it. They are written as
# try/finally for that reason and not out of neatness.


def test_every_applied_migration_recorded_its_checksum(pg_dsn):
    """The recorded hash is the file's, for every row — not a subset, not a default."""
    import psycopg

    from carnet.storage import migrate

    on_disk = {version: migrate.checksum(path) for version, path in migrate.available()}

    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        rows = conn.execute("SELECT version, checksum FROM schema_migrations").fetchall()

    assert dict(rows) == on_disk


def test_an_edited_released_migration_is_refused(pg_dsn):
    """The whole of "never edited once released", and the only thing that enforces it.

    An edit to a file that has already run somewhere produces two different schemas
    under one version number, and no later run can tell which one it is looking at. The
    refusal has to name the file, because the remedy is to go and put it back.
    """
    import psycopg

    from carnet.storage import migrate

    version = "007_tenant_idps"
    real = migrate.checksum(dict(migrate.available())[version])

    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        conn.execute(
            "UPDATE schema_migrations SET checksum = %s WHERE version = %s",
            ("0" * 64, version),
        )
    try:
        with pytest.raises(migrate.MigrationError, match=version):
            migrate.apply(pg_dsn)
    finally:
        with psycopg.connect(pg_dsn, autocommit=True) as conn:
            conn.execute(
                "UPDATE schema_migrations SET checksum = %s WHERE version = %s",
                (real, version),
            )

    assert migrate.apply(pg_dsn) == []


def test_editing_a_migration_file_on_disk_is_refused(pg_dsn):
    """The promise as an operator would break it: by editing the file, not the ledger.

    **This is the test 027's mutation pass found missing.** Its neighbour above plants a
    wrong checksum in the database, which proves the comparison runs but says nothing
    about what is compared — a `checksum()` hashing the filename passed it while leaving
    an edited migration completely undetected. Here the file itself changes, which is
    the only version of this that a customer could actually do.

    Restores the file in `finally`, because a test that leaves a migration edited would
    fail every run after it in a way that looks like this bug rather than like a test.
    """
    import psycopg

    from carnet.storage import migrate

    version = "007_tenant_idps"
    path = dict(migrate.available())[version]
    original = path.read_bytes()

    try:
        path.write_bytes(original + b"\n-- a comment somebody added in a hurry\n")

        with pytest.raises(migrate.MigrationError, match=version):
            migrate.apply(pg_dsn)
    finally:
        path.write_bytes(original)

    # And the database is untouched by the refusal, so putting the file back is the
    # whole remedy — which is what the error message tells the operator to do.
    assert migrate.apply(pg_dsn) == []
    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        stored = conn.execute(
            "SELECT checksum FROM schema_migrations WHERE version = %s", (version,)
        ).fetchone()[0]
    assert stored == migrate.checksum(path)


def test_a_missing_checksum_is_backfilled_rather_than_fatal(pg_dsn):
    """Trust on first verify, and it is what lets an existing deployment upgrade at all.

    Every ledger written before 027 has NULLs in this column, as does every row the e2e
    scripts insert by hand when they replay migrations to build an old schema. Treating
    NULL as a mismatch would refuse all of them on the one upgrade that introduces the
    check.
    """
    import psycopg

    from carnet.storage import migrate

    version = "007_tenant_idps"

    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        conn.execute(
            "UPDATE schema_migrations SET checksum = NULL WHERE version = %s", (version,)
        )

    assert migrate.apply(pg_dsn) == []

    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        stored = conn.execute(
            "SELECT checksum FROM schema_migrations WHERE version = %s", (version,)
        ).fetchone()[0]

    assert stored == migrate.checksum(dict(migrate.available())[version])


def test_a_ledger_row_with_no_file_stops_the_upgrade(pg_dsn):
    """Old code against a newer database, which forward-only does not support.

    It used to be silent: the runner skipped what it did not recognise and reported
    success, so a deployment rolled back to last month's build came up claiming to be
    migrated. Under BYOC that is a customer's database and a support call nobody can
    reconstruct.
    """
    import psycopg

    from carnet.storage import migrate

    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        conn.execute("INSERT INTO schema_migrations (version) VALUES ('999_from_a_newer_build')")
    try:
        with pytest.raises(migrate.MigrationError, match="999_from_a_newer_build"):
            migrate.apply(pg_dsn)
    finally:
        with psycopg.connect(pg_dsn, autocommit=True) as conn:
            conn.execute("DELETE FROM schema_migrations WHERE version = '999_from_a_newer_build'")

    assert migrate.apply(pg_dsn) == []


def test_a_ledger_row_from_another_series_does_not_stop_the_upgrade(pg_dsn):
    """Step 082, against a real ledger: one database, two series, this build.

    The unit tests exercise the scoping as arithmetic. This is the thing itself — a row
    written by an enterprise build sitting in `schema_migrations` while the public build
    runs `--migrate` — and it is the case that used to fail *before a single byte of SQL
    differed between the two trees*, which is why the split could not wait for a
    divergent file to exist.

    Deliberately paired with the test above it. Scoping "ahead" to the series this build
    ships must not have widened into tolerating everything unknown: `999_from_a_newer_build`
    matches the core pattern and is still refused, and both facts live on one page.
    """
    import psycopg

    from carnet.storage import migrate

    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        conn.execute(
            "INSERT INTO schema_migrations (version, checksum) VALUES "
            "('ee_001_approvals', %s)",
            ("a" * 64,),
        )
    try:
        assert migrate.apply(pg_dsn) == []
        assert migrate.foreign(dict.fromkeys(["ee_001_approvals"]), migrate.series()) == [
            "ee_001_approvals"
        ]
    finally:
        with psycopg.connect(pg_dsn, autocommit=True) as conn:
            conn.execute("DELETE FROM schema_migrations WHERE version = 'ee_001_approvals'")

    assert migrate.apply(pg_dsn) == []


def test_a_database_holding_somebody_elses_tables_is_refused(pg_dsn):
    """The dedicated-database requirement, and the refusal writes nothing.

    Migrations create unqualified tables, so they land in `public` beside whatever is
    already there. The check runs before the ledger is created — asserted here by the
    second half, because a refusal that leaves a `schema_migrations` behind has already
    modified the database it declined to touch.
    """
    import psycopg

    from carnet.storage import migrate

    base, _, name = pg_dsn.rpartition("/")
    scratch = f"{name}_shared_probe"

    with psycopg.connect(f"{base}/postgres", autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {scratch} WITH (FORCE)")
        conn.execute(f"CREATE DATABASE {scratch}")
    try:
        with psycopg.connect(f"{base}/{scratch}", autocommit=True) as conn:
            conn.execute("CREATE TABLE somebody_elses_table (id int)")

        with pytest.raises(migrate.MigrationError, match="dedicated database"):
            migrate.apply(f"{base}/{scratch}")

        with psycopg.connect(f"{base}/{scratch}", autocommit=True) as conn:
            ledger = conn.execute(
                "SELECT to_regclass('public.schema_migrations')"
            ).fetchone()[0]

        assert ledger is None, "the refusal created a ledger in a database it declined"
    finally:
        with psycopg.connect(f"{base}/postgres", autocommit=True) as conn:
            conn.execute(f"DROP DATABASE IF EXISTS {scratch} WITH (FORCE)")


# --- identity providers -----------------------------------------------------------
#
# `tenant_idps` is the access layer's tenant isolation: it decides which customer a
# token belongs to at all. So these are not ordinary round-trip tests — a bug here is
# one company's employees reading another company's data, and every rule below exists
# because some real identity provider behaves that way.
#
# Note the `uniq` fixture. `tenant_idps.issuer` and `users.(issuer, subject)` are
# UNIQUE **globally**, not per tenant — which is the whole point of them — so values
# reused across tests collide in the shared Postgres database exactly as they would in
# production. The in-memory store, being fresh per test, hides that entirely. Finding
# it is the contract suite doing its job on its own fixtures.


@pytest.fixture
def uniq(request):
    """A token unique to this test, safe in a URL and an identifier."""
    return re.sub(r"[^a-z0-9]+", "-", request.node.name.lower())[:50].strip("-")


@pytest.fixture
def okta(uniq):
    """A provider whose issuer is already per-customer, as Okta's and Entra's are."""
    return {
        "issuer": f"https://{uniq}.okta.example",
        "jwks_uri": f"https://{uniq}.okta.example/oauth2/v1/keys",
        "audience": "0oa1client",
        "allowed_domains": ("acme.com",),
    }


@pytest.fixture
def google(uniq):
    """A provider whose issuer is **shared by every customer on it**, as Google
    Workspace's is.

    The real value is `https://accounts.google.com` for everybody; it is made unique
    per test only so the suite does not collide with itself. What matters is preserved:
    within one test, two tenants register the *same* issuer and are told apart by the
    `hd` claim alone.
    """
    return {
        "issuer": f"https://accounts.google.example/{uniq}",
        "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
        "audience": "123.apps.googleusercontent.com",
        "discriminator_claim": "hd",
    }


def test_an_idp_round_trips(store, tenant, okta):
    store.save_tenant_idp(tenant, okta)

    rows = store.find_tenant_idps(okta["issuer"])

    assert len(rows) == 1
    assert rows[0]["tenant_id"] == tenant
    assert rows[0]["jwks_uri"] == okta["jwks_uri"]
    assert rows[0]["allowed_domains"] == ("acme.com",)


def test_idp_defaults_are_filled_in(store, tenant, okta):
    """`email_claim` defaults to `email` — Okta and Google's field. Entra often sends
    `preferred_username`, which is why it is a column at all."""
    store.save_tenant_idp(tenant, okta)

    row = store.find_tenant_idps(okta["issuer"])[0]

    assert row["email_claim"] == "email"
    assert row["enabled"] is True
    assert row["discriminator_claim"] is None
    assert row["discriminator_value"] is None


def test_an_idp_without_an_issuer_is_refused(store, tenant):
    with pytest.raises(StorageError, match="issuer"):
        store.save_tenant_idp(tenant, {"jwks_uri": "x", "audience": "y"})


def test_an_idp_without_an_audience_is_refused(store, tenant):
    """A token minted for a different app at the same provider is a valid token that
    is not for us. Accepting it is how an unrelated app becomes a login here."""
    with pytest.raises(StorageError, match="audience"):
        store.save_tenant_idp(tenant, {"issuer": "https://x", "jwks_uri": "y"})


def test_half_a_discriminator_is_refused(store, tenant, google):
    """A claim with no value routes nothing; a value with no claim names no field to
    read it from. The CHECK constraint, and the same rule in Python."""
    with pytest.raises(StorageError, match="together"):
        store.save_tenant_idp(
            tenant,
            {**google, "discriminator_claim": None, "discriminator_value": "acme.com"},
        )

    with pytest.raises(StorageError, match="together"):
        store.save_tenant_idp(tenant, {**google, "discriminator_value": None})


def test_an_idp_for_an_unknown_tenant_is_refused(store, okta):
    with pytest.raises(UnknownTenantError):
        store.save_tenant_idp("never-created", okta)


def test_two_tenants_may_share_an_issuer_when_they_discriminate(
    store, tenant, other, google
):
    """Google Workspace. Both customers authenticate against the same issuer and are
    told apart by the `hd` claim.

    Under `issuer UNIQUE` this is impossible, and the second customer would have been
    routed into the first one's data."""
    store.save_tenant_idp(tenant, {**google, "discriminator_value": "acme.com"})
    store.save_tenant_idp(other, {**google, "discriminator_value": "globex.com"})

    rows = store.find_tenant_idps(google["issuer"])

    assert len(rows) == 2
    by_domain = {r["discriminator_value"]: r["tenant_id"] for r in rows}
    assert by_domain == {"acme.com": tenant, "globex.com": other}


def test_an_issuer_claimed_outright_cannot_then_be_discriminated(
    store, tenant, other, okta
):
    """A row with no discriminator claims the whole issuer."""
    store.save_tenant_idp(tenant, okta)

    with pytest.raises(IssuerConflictError, match="whole issuer"):
        store.save_tenant_idp(
            other,
            {**okta, "discriminator_claim": "hd", "discriminator_value": "globex.com"},
        )


def test_a_discriminated_issuer_cannot_then_be_claimed_outright(
    store, tenant, other, google
):
    """The same rule from the other direction, which is the one an implementation
    forgets: the first registration looks harmless and the second is the takeover."""
    store.save_tenant_idp(tenant, {**google, "discriminator_value": "acme.com"})

    with pytest.raises(IssuerConflictError, match="cannot coexist"):
        store.save_tenant_idp(
            other, {**google, "discriminator_claim": None, "discriminator_value": None}
        )


def test_another_tenant_cannot_take_over_a_registered_issuer(store, tenant, other, okta):
    """Not a mistake — this one is a takeover. Without it, registering Acme's issuer
    hands you Acme's users."""
    store.save_tenant_idp(tenant, okta)

    with pytest.raises(IssuerConflictError, match="already registered"):
        store.save_tenant_idp(other, okta)


def test_re_registering_your_own_idp_updates_it(store, tenant, okta):
    store.save_tenant_idp(tenant, okta)
    store.save_tenant_idp(tenant, {**okta, "jwks_uri": "https://rotated.example/keys"})

    rows = store.find_tenant_idps(okta["issuer"])

    assert len(rows) == 1
    assert rows[0]["jwks_uri"] == "https://rotated.example/keys"


def test_idps_are_listed_per_tenant(store, tenant, other, okta, google):
    store.save_tenant_idp(tenant, okta)
    store.save_tenant_idp(other, {**google, "discriminator_value": "globex.com"})

    assert [r["issuer"] for r in store.list_tenant_idps(tenant)] == [okta["issuer"]]
    assert [r["issuer"] for r in store.list_tenant_idps(other)] == [google["issuer"]]


def test_deleting_an_idp_is_scoped_to_the_tenant(store, tenant, other, okta):
    """One customer must not be able to unregister another's provider."""
    store.save_tenant_idp(tenant, okta)

    store.delete_tenant_idp(other, okta["issuer"])
    assert len(store.find_tenant_idps(okta["issuer"])) == 1

    store.delete_tenant_idp(tenant, okta["issuer"])
    assert store.find_tenant_idps(okta["issuer"]) == []


def test_deleting_a_discriminated_idp_leaves_its_neighbour(store, tenant, other, google):
    store.save_tenant_idp(tenant, {**google, "discriminator_value": "acme.com"})
    store.save_tenant_idp(other, {**google, "discriminator_value": "globex.com"})

    store.delete_tenant_idp(tenant, google["issuer"], "acme.com")

    remaining = store.find_tenant_idps(google["issuer"])
    assert [r["discriminator_value"] for r in remaining] == ["globex.com"]


def test_an_unknown_issuer_finds_nothing(store, tenant, okta):
    store.save_tenant_idp(tenant, okta)
    assert store.find_tenant_idps("https://evil.example") == []


# --- users --------------------------------------------------------------------------


@pytest.fixture
def person(uniq):
    """One person, unique to this test. `(issuer, subject)` is globally unique."""
    return {
        "id": f"u-{uniq}",
        "issuer": f"https://{uniq}.okta.example",
        "subject": "00u1abc",
        "email": "priya@acme.com",
        "display_name": "Priya",
    }


def test_a_user_round_trips(store, tenant, person):
    store.create_user(tenant, person)

    found = store.find_user(person["issuer"], person["subject"])

    assert found["id"] == person["id"]
    assert found["tenant_id"] == tenant
    assert found["status"] == "active"
    assert found["last_seen_at"] is None


def test_a_user_is_read_back_by_our_own_id(store, tenant, person):
    """`get_user`, added in 12b for `GET /me`. The counterpart to `find_user`: that one is
    keyed `(issuer, subject)` because a token carries those, this one on the opaque id
    every row in this schema names a person by."""
    store.create_user(tenant, person)

    assert store.get_user(tenant, person["id"])["email"] == "priya@acme.com"
    assert store.get_user(tenant, "u-nobody") is None


def test_a_user_is_not_read_across_tenants(store, tenant, person, uniq):
    """`find_user` has no tenant filter, because it is how a tenant is *determined*.
    `get_user` does, because by then the tenant is known — and a read without one is the
    missed-`WHERE` leak this interface documents as a known limit."""
    store.create_tenant(f"{tenant}-other", "Other")
    store.create_user(tenant, person)

    assert store.get_user(f"{tenant}-other", person["id"]) is None


def test_a_user_is_found_by_subject_not_by_email(store, tenant, person):
    """Identity is (issuer, subject). Emails change — people marry, companies migrate
    domains — and keying on one detaches somebody from their audit history the week it
    happens."""
    store.create_user(tenant, person)

    store.record_user_login(person["id"], "priya@acmegroup.com", "Priya Patel")

    still_there = store.find_user(person["issuer"], person["subject"])
    assert still_there["id"] == person["id"]
    assert still_there["email"] == "priya@acmegroup.com"
    assert still_there["last_seen_at"] is not None


def test_the_same_subject_at_two_issuers_is_two_people(store, tenant, person, uniq):
    """A `sub` is unique within an issuer and meaningless across them."""
    elsewhere = f"https://{uniq}.globex.example"
    store.create_user(tenant, person)
    store.create_user(tenant, {**person, "id": f"{person['id']}-2", "issuer": elsewhere})

    assert store.find_user(person["issuer"], person["subject"])["id"] == person["id"]
    assert store.find_user(elsewhere, person["subject"])["id"] == f"{person['id']}-2"


def test_one_person_cannot_belong_to_two_customers(store, tenant, other, person):
    store.create_user(tenant, person)

    with pytest.raises(StorageError):
        store.create_user(other, {**person, "id": f"{person['id']}-2"})


def test_a_recycled_user_id_is_refused(store, tenant, person):
    """`id` becomes Principal.id and lands in every audit record. Reusing one
    reattributes somebody else's history."""
    store.create_user(tenant, person)

    with pytest.raises(StorageError):
        store.create_user(tenant, {**person, "subject": "00u-different"})


def test_a_user_for_an_unknown_tenant_is_refused(store, person):
    with pytest.raises(UnknownTenantError):
        store.create_user("never-created", person)


def test_a_user_with_a_blank_subject_is_refused(store, tenant, uniq):
    """Migration 052 let the subject be *absent* — a provisioned person has not signed
    in yet — and that is exactly why a *blank* one has to be refused: `find_user` never
    matches a blank subject, so a row stored with one could never be signed into."""
    with pytest.raises(StorageError, match="subject"):
        store.create_user(tenant, {"id": f"u-{uniq}", "issuer": "https://x", "subject": ""})
    with pytest.raises(StorageError, match="subject"):
        store.create_user(
            tenant, {"id": f"u-{uniq}", "issuer": "https://x", "subject": "   "}
        )

    assert store.get_user(tenant, f"u-{uniq}") is None


def test_users_are_listed_per_tenant(store, tenant, other, person, uniq):
    store.create_user(tenant, person)
    store.create_user(
        other,
        {**person, "id": f"{person['id']}-2", "issuer": f"https://{uniq}.other.example"},
    )

    assert [u["id"] for u in store.list_users(tenant)] == [person["id"]]
    assert [u["id"] for u in store.list_users(other)] == [f"{person['id']}-2"]


def test_a_user_can_be_disabled(store, tenant, person):
    """The only thing that cuts somebody off immediately. There is no directory sync
    and no token introspection, so otherwise revocation waits for token expiry."""
    store.create_user(tenant, person)

    after = store.set_user_status(tenant, person["id"], "disabled", actor=TEST_ACTOR)

    assert after["status"] == "disabled"
    assert store.find_user(person["issuer"], person["subject"])["status"] == "disabled"


def test_an_invalid_status_is_refused(store, tenant, person):
    store.create_user(tenant, person)

    with pytest.raises(StorageError, match="status"):
        store.set_user_status(tenant, person["id"], "deleted", actor=TEST_ACTOR)


def test_one_tenant_cannot_disable_anothers_user(store, tenant, other, person):
    store.create_user(tenant, person)

    assert store.set_user_status(other, person["id"], "disabled", actor=TEST_ACTOR) is None

    assert store.find_user(person["issuer"], person["subject"])["status"] == "active"
    assert store.admin_audit_records(other) == []


# --- users a directory pushed, step 071 -----------------------------------------------
#
# Migration 052. A row may now exist before its subject is known, and the rules around
# that are the ones worth holding in both stores: `find_user` never matches a null
# subject, adoption happens exactly once, and the log says who did what to whom.


@pytest.fixture
def provisioned(person):
    """`person`, as a SCIM push would create them: an external id and no subject."""
    return {**person, "id": f"{person['id']}-p", "subject": None, "external_id": "obj-1"}


def test_a_user_with_no_subject_is_nobody_to_find_user(store, tenant, provisioned):
    """A token with a missing or blank subject claim must be *nobody*, not *the first
    person the directory mentioned*. Both stores answer before looking."""
    store.create_user(tenant, provisioned)

    assert store.find_user(provisioned["issuer"], None) is None
    assert store.find_user(provisioned["issuer"], "") is None
    assert store.get_user(tenant, provisioned["id"])["subject"] is None


def test_a_provisioned_row_is_found_by_its_address_at_its_issuer(
    store, tenant, other, person, provisioned, uniq
):
    """Case-insensitively, both sides stripped — and bounded four ways: same tenant,
    same issuer, no subject yet. A row that has a subject is never returned, whatever
    its email says; 008's refusal to look people up by address is kept where it was
    made."""
    store.create_user(tenant, person)  # has a subject, same address
    store.create_user(tenant, provisioned)

    found = store.find_provisioned_user(tenant, provisioned["issuer"], "  PRIYA@Acme.com ")
    assert found["id"] == provisioned["id"]

    assert store.find_provisioned_user(other, provisioned["issuer"], "priya@acme.com") is None
    assert store.find_provisioned_user(tenant, f"https://{uniq}.elsewhere", "priya@acme.com") is None
    assert store.find_provisioned_user(tenant, provisioned["issuer"], "sam@acme.com") is None
    assert store.find_provisioned_user(tenant, provisioned["issuer"], "") is None


def test_two_provisioned_rows_with_one_address_resolve_to_the_oldest(
    store, tenant, provisioned
):
    """The directory cannot produce this — `userName` is unique there — and the
    ordering is stated anyway: earliest created, then lowest id."""
    store.create_user(tenant, {**provisioned, "id": "u-zz-first", "external_id": "obj-a"})
    store.create_user(tenant, {**provisioned, "id": "u-aa-second", "external_id": "obj-b"})

    found = store.find_provisioned_user(tenant, provisioned["issuer"], "priya@acme.com")

    assert found["id"] == "u-zz-first"


def test_adoption_happens_exactly_once(store, tenant, provisioned):
    """The compare-and-set on `subject IS NULL`. Two sign-ins racing for one row adopt
    it once; the loser is told so and writes nothing."""
    store.create_user(tenant, provisioned)

    assert store.adopt_user_subject(
        tenant, provisioned["id"], "00u-new", actor="system:directory"
    ) is True
    assert store.adopt_user_subject(
        tenant, provisioned["id"], "00u-other", actor="system:directory"
    ) is False

    row = store.find_user(provisioned["issuer"], "00u-new")
    assert row["id"] == provisioned["id"]
    assert store.find_user(provisioned["issuer"], "00u-other") is None

    (record,) = store.admin_audit_records(tenant, action="user.adopt")
    assert (record["target_kind"], record["target_id"]) == ("user", provisioned["id"])
    assert (record["actor_kind"], record["actor_id"]) == ("system", "directory")
    assert record["detail"] == {"issuer": provisioned["issuer"]}


def test_adoption_refuses_a_blank_subject_and_an_unknown_row(store, tenant, other, provisioned):
    store.create_user(tenant, provisioned)

    with pytest.raises(StorageError, match="blank"):
        store.adopt_user_subject(tenant, provisioned["id"], "  ", actor="system:directory")

    assert store.adopt_user_subject(tenant, "u-nobody", "00u", actor="system:directory") is False
    assert store.adopt_user_subject(other, provisioned["id"], "00u", actor="system:directory") is False
    assert store.get_user(tenant, provisioned["id"])["subject"] is None
    assert store.admin_audit_records(tenant, action="user.adopt") == []


def test_adoption_by_a_subject_somebody_already_holds_is_refused(
    store, tenant, person, provisioned
):
    """`UNIQUE (issuer, subject)` still means what it meant: a provisioned row cannot
    be adopted by a person who is already here."""
    store.create_user(tenant, person)
    store.create_user(tenant, provisioned)

    with pytest.raises(StorageError, match="already exists"):
        store.adopt_user_subject(
            tenant, provisioned["id"], person["subject"], actor="system:directory"
        )

    assert store.get_user(tenant, provisioned["id"])["subject"] is None


def test_a_user_is_found_by_the_directorys_id(store, tenant, other, provisioned, uniq):
    store.create_user(tenant, provisioned)

    found = store.find_user_by_external_id(tenant, provisioned["issuer"], "obj-1")
    assert found["id"] == provisioned["id"]

    assert store.find_user_by_external_id(other, provisioned["issuer"], "obj-1") is None
    assert store.find_user_by_external_id(tenant, f"https://{uniq}.elsewhere", "obj-1") is None
    assert store.find_user_by_external_id(tenant, provisioned["issuer"], "obj-9") is None
    assert store.find_user_by_external_id(tenant, provisioned["issuer"], "") is None


def test_a_directory_id_is_unique_per_issuer_at_creation(store, tenant, person, provisioned):
    store.create_user(tenant, provisioned)

    with pytest.raises(StorageError, match="obj-1"):
        store.create_user(tenant, {**person, "external_id": "obj-1"})

    assert store.get_user(tenant, person["id"]) is None


def test_an_update_records_only_the_fields_that_moved(store, tenant, person):
    store.create_user(tenant, person)

    after = store.update_user(
        tenant,
        person["id"],
        email="priya@acme.com",  # unchanged
        display_name="Priya Patel",
        external_id="obj-7",
        actor="system:scim:s_1",
    )

    assert after["display_name"] == "Priya Patel"
    assert after["external_id"] == "obj-7"
    assert after["email"] == "priya@acme.com"
    (record,) = store.admin_audit_records(tenant, action="user.update")
    assert record["detail"] == {"fields": ["display_name", "external_id"]}
    assert (record["target_kind"], record["target_id"]) == ("user", person["id"])


def test_an_update_that_changes_nothing_writes_nothing(store, tenant, person):
    """A push restating what is already there leaves no record claiming otherwise."""
    store.create_user(tenant, person)

    same = store.update_user(tenant, person["id"], display_name="Priya", actor=TEST_ACTOR)
    untouched = store.update_user(tenant, person["id"], actor=TEST_ACTOR)

    assert same["display_name"] == "Priya"
    assert untouched["display_name"] == "Priya"
    assert store.admin_audit_records(tenant, action="user.update") == []
    assert store.update_user(tenant, "u-nobody", display_name="X", actor=TEST_ACTOR) is None


def test_none_leaves_alone_except_for_the_directory_id_which_it_clears(store, tenant, person):
    """`email` and `display_name` are left alone by None; `external_id` takes a
    sentinel so that None is a real value — *unlinked* — and clears it."""
    store.create_user(tenant, {**person, "external_id": "obj-1"})

    after = store.update_user(tenant, person["id"], external_id=None, actor=TEST_ACTOR)
    assert after["external_id"] is None
    assert after["email"] == "priya@acme.com"
    assert after["display_name"] == "Priya"

    blank = store.update_user(tenant, person["id"], external_id="  obj-2  ", actor=TEST_ACTOR)
    assert blank["external_id"] == "obj-2"
    cleared = store.update_user(tenant, person["id"], external_id="   ", actor=TEST_ACTOR)
    assert cleared["external_id"] is None

    fields = [r["detail"]["fields"] for r in store.admin_audit_records(tenant, action="user.update")]
    assert fields == [["external_id"], ["external_id"], ["external_id"]]


def test_an_update_refuses_a_directory_id_somebody_else_holds(store, tenant, person, provisioned):
    """The directory sent one object id for two people. Refused with a sentence naming
    the id, and the row is untouched."""
    store.create_user(tenant, person)
    store.create_user(tenant, provisioned)

    with pytest.raises(StorageError, match="obj-1"):
        store.update_user(tenant, person["id"], external_id="obj-1", actor=TEST_ACTOR)

    assert store.get_user(tenant, person["id"])["external_id"] is None
    assert store.admin_audit_records(tenant, action="user.update") == []


def test_a_status_change_is_recorded_only_when_it_changes(store, tenant, person):
    """Disabling somebody twice is a push restating what it already said; the log
    must not say the person was cut off twice."""
    store.create_user(tenant, person)

    first = store.set_user_status(
        tenant, person["id"], "disabled", actor="system:scim:s_1", detail={"cause": "scim"}
    )
    again = store.set_user_status(tenant, person["id"], "disabled", actor="system:scim:s_1")
    back = store.set_user_status(tenant, person["id"], "active", actor="user:u-admin")

    assert first["status"] == "disabled"
    assert again["status"] == "disabled"
    assert back["status"] == "active"
    assert store.set_user_status(tenant, "u-nobody", "disabled", actor=TEST_ACTOR) is None

    records = store.admin_audit_records(tenant)
    assert [r["action"] for r in records] == ["user.disable", "user.enable"]
    assert records[0]["detail"] == {"cause": "scim"}
    assert (records[0]["actor_kind"], records[0]["actor_id"]) == ("system", "scim:s_1")
    assert (records[0]["target_kind"], records[0]["target_id"]) == ("user", person["id"])
    assert records[1]["detail"] == {}


def test_a_provisioned_person_is_recorded_and_a_sign_in_is_not(store, tenant, person, provisioned):
    """`create_user(actor=...)` is the directory creating somebody, an administrative
    act; the JIT sign-in path passes no actor and writes nothing, as it always has."""
    store.create_user(tenant, person)
    store.create_user(tenant, provisioned, actor="system:scim:s_1")

    (record,) = store.admin_audit_records(tenant)
    assert record["action"] == "user.create"
    assert (record["target_kind"], record["target_id"]) == ("user", provisioned["id"])
    assert record["detail"] == {"provisioned": True}


def test_a_sign_in_creates_a_person_without_a_record(store, tenant, person):
    store.create_user(tenant, person)

    assert store.admin_audit_records(tenant) == []


def test_a_row_written_before_052_reads_its_directory_id_as_none(store, tenant, person):
    """No backfill: NULL is precisely true of every row a directory has not pushed."""
    store.create_user(tenant, person)

    row = store.get_user(tenant, person["id"])

    assert row["external_id"] is None
    assert row["created_at"] is not None


def test_a_postgres_row_inserted_without_the_column_reads_it_as_none(pg):
    """The same thing, past `create_user`: a row the way 008 wrote it, with no
    `external_id` in the INSERT at all, read back through the 052 column list."""
    store, tenant_id = pg
    store._execute(
        "INSERT INTO users (id, tenant_id, issuer, subject) VALUES (%s, %s, %s, %s)",
        (f"u-{tenant_id}", tenant_id, f"https://{tenant_id}.idp", "00u-old"),
    )

    row = store.get_user(tenant_id, f"u-{tenant_id}")

    assert row["external_id"] is None
    assert row["subject"] == "00u-old"
    assert store.find_user(f"https://{tenant_id}.idp", "00u-old")["id"] == f"u-{tenant_id}"


# --- agent grants -------------------------------------------------------------------


def test_a_grant_round_trips(store, tenant):
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")

    store.grant_agent(tenant, "reporter", "user", "u-1", granted_by="admin", actor="user:admin")

    assert store.direct_agent_grant_role(tenant, "reporter", "user", "u-1") == "user"
    assert store.granted_agent_names(tenant, "user", "u-1") == ["reporter"]
    assert store.list_agent_grants(tenant, "reporter")[0]["granted_by"] == "admin"


def test_absence_is_denial(store, tenant):
    """No wildcard, no public flag. An agent nobody has been granted is one nobody can
    run, including whoever created it."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")

    assert store.direct_agent_grant_role(tenant, "reporter", "user", "u-1") is None
    assert store.granted_agent_names(tenant, "user", "u-1") == []


def test_granting_an_absent_agent_is_refused(store, tenant):
    """A grant on a nonexistent agent is a row that silently reactivates if the name
    is ever reused."""
    with pytest.raises(StorageError, match="no agent"):
        store.grant_agent(tenant, "never-existed", "user", "u-1", actor="system:cli")


def test_grants_do_not_cross_tenants(store, tenant, other):
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.save_agent(other, {"name": "reporter"}, actor="system:cli")
    store.grant_agent(tenant, "reporter", "user", "u-1", actor="system:cli")

    assert store.direct_agent_grant_role(other, "reporter", "user", "u-1") is None
    assert store.granted_agent_names(other, "user", "u-1") == []


def test_a_system_principal_can_be_granted_an_agent(store, tenant):
    """A scheduler running a customer's nightly job needs the same permission a person
    does. A special case for it would be the exception that erodes this."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")

    store.grant_agent(tenant, "reporter", "system", "scheduler", actor="system:cli")

    assert store.direct_agent_grant_role(tenant, "reporter", "system", "scheduler") == "user"
    assert store.direct_agent_grant_role(tenant, "reporter", "user", "scheduler") is None


def test_an_unknown_grantee_kind_is_refused(store, tenant):
    """Named for the column it asserts, and that is the whole point.

    This shared a name with the `save_connection` case below until 027's linter found
    the collision, so for as long as both existed Python kept the second definition and
    this one never ran — a grant-side constraint nobody was checking, in either store.
    """
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")

    with pytest.raises(StorageError, match="grantee_kind"):
        store.grant_agent(tenant, "reporter", "robot", "r2d2", actor="system:cli")


def test_granting_twice_is_idempotent(store, tenant):
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")

    store.grant_agent(tenant, "reporter", "user", "u-1", granted_by="first", actor="user:first")
    store.grant_agent(tenant, "reporter", "user", "u-1", granted_by="second", actor="user:second")

    grants = store.list_agent_grants(tenant, "reporter")
    assert len(grants) == 1
    assert grants[0]["granted_by"] == "second"


def test_revoking_is_idempotent(store, tenant):
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.grant_agent(tenant, "reporter", "user", "u-1", actor="system:cli")

    store.revoke_agent(tenant, "reporter", "user", "u-1", actor="system:cli")
    store.revoke_agent(tenant, "reporter", "user", "u-1", actor="system:cli")

    assert store.direct_agent_grant_role(tenant, "reporter", "user", "u-1") is None


def test_grants_are_ordered(store, tenant):
    store.save_agent(tenant, {"name": "alpha"}, actor="system:cli")
    store.save_agent(tenant, {"name": "zulu"}, actor="system:cli")
    for name in ("zulu", "alpha"):
        store.grant_agent(tenant, name, "user", "u-1", actor="system:cli")

    assert store.granted_agent_names(tenant, "user", "u-1") == ["alpha", "zulu"]


# --- groups (migration 017) ----------------------------------------------------------
#
# The rules a group has to obey in BOTH stores. The permission-model half — what a group
# grant means, who may administer one — is `test_groups.py`; this is the storage
# contract, and it exists because the in-memory store resolves membership with a set
# union while Postgres does it inside one statement. Two implementations of "highest of
# direct and inherited" is exactly the shape that drifts.


@pytest.fixture
def support(store, tenant):
    """A group with two members and no grant."""
    store.create_group(tenant, "g-sup", "support", actor="system:cli")
    store.add_group_member(tenant, "g-sup", "user", "u-sam", actor="system:cli")
    store.add_group_member(tenant, "g-sup", "user", "u-priya", actor="system:cli")
    return "g-sup"


def test_a_group_round_trips(store, tenant):
    row = store.create_group(
        tenant, "g-1", "support", description="the support team", actor="system:cli"
    )

    assert row["group_id"] == "g-1"
    assert row["name"] == "support"
    assert row["description"] == "the support team"
    # NULL, not '' — a group never linked to a directory and one linked to an empty id
    # are different states, and 9b reads this column to tell them apart.
    assert row["external_id"] is None
    assert store.get_group(tenant, "g-1") == row
    assert set(row) == set(GROUP_FIELDS)


def test_a_group_name_is_unique_per_tenant(store, tenant, other):
    store.create_group(tenant, "g-1", "support", actor="system:cli")

    with pytest.raises(StorageError, match="already has a group"):
        store.create_group(tenant, "g-2", "support", actor="system:cli")

    # ...per tenant. Another customer may have a group with the same name.
    store.create_group(other, "g-3", "support", actor="system:cli")


def test_a_group_grant_reaches_a_member(store, tenant, support):
    """The one that matters. Both stores, same answer, and neither person has a row."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.grant_agent(tenant, "reporter", "group", support, role="user", actor="system:cli")

    assert store.agent_grant_role(tenant, "reporter", "user", "u-sam") == "user"
    assert store.granted_agent_names(tenant, "user", "u-sam") == ["reporter"]
    assert store.direct_agent_grant_role(tenant, "reporter", "user", "u-sam") is None


def test_highest_wins_both_ways_round(store, tenant, support):
    """Decision 2, and asserted in both directions because a rule that only holds one
    way round is a coincidence.

    The Postgres half is the one worth having: ordering by `role` itself would be
    alphabetical — editor < owner < user — which is the ladder upside down, and would
    return `user` for somebody who owns the agent.
    """
    store.save_agent(tenant, {"name": "low"}, actor="system:cli")
    store.save_agent(tenant, {"name": "high"}, actor="system:cli")

    store.grant_agent(tenant, "low", "group", support, role="editor", actor="system:cli")
    store.grant_agent(tenant, "low", "user", "u-sam", role="user", actor="system:cli")

    store.grant_agent(tenant, "high", "group", support, role="user", actor="system:cli")
    store.grant_agent(tenant, "high", "user", "u-sam", role="editor", actor="system:cli")

    assert store.agent_grant_role(tenant, "low", "user", "u-sam") == "editor"
    assert store.agent_grant_role(tenant, "high", "user", "u-sam") == "editor"


def test_an_owner_is_not_beaten_by_a_group(store, tenant, support):
    """The alphabetical-ordering trap, stated as its own assertion: `owner` sorts below
    `user` as a string, so a naive ORDER BY would demote the owner of an agent their
    group can also run."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.grant_agent(tenant, "reporter", "user", "u-sam", role="owner", actor="system:cli")
    store.grant_agent(tenant, "reporter", "group", support, role="user", actor="system:cli")

    assert store.agent_grant_role(tenant, "reporter", "user", "u-sam") == "owner"


def test_an_agent_granted_twice_over_appears_once(store, tenant, support):
    """Directly and through a group is not an error, and must not double a list view."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.grant_agent(tenant, "reporter", "group", support, role="user", actor="system:cli")
    store.grant_agent(tenant, "reporter", "user", "u-sam", role="editor", actor="system:cli")

    assert store.granted_agent_names(tenant, "user", "u-sam") == ["reporter"]


def test_membership_is_what_carries_access(store, tenant, support):
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.grant_agent(tenant, "reporter", "group", support, role="user", actor="system:cli")

    assert store.remove_group_member(tenant, support, "user", "u-sam", actor="system:cli") is True

    assert store.agent_grant_role(tenant, "reporter", "user", "u-sam") is None
    assert store.agent_grant_role(tenant, "reporter", "user", "u-priya") == "user"
    # No grant was touched.
    assert len(store.list_agent_grants(tenant, "reporter")) == 1


def test_deleting_a_group_takes_membership_and_grants(store, tenant, support):
    """Cascade in Postgres — a foreign key for the members, migration 017's trigger for
    the grants — and the same outcome in the fake."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.grant_agent(tenant, "reporter", "group", support, role="user", actor="system:cli")

    assert store.delete_group(tenant, support, actor="system:cli") is True

    assert store.get_group(tenant, support) is None
    assert store.list_group_members(tenant, support) == []
    assert store.list_agent_grants(tenant, "reporter") == []
    assert store.agent_grant_role(tenant, "reporter", "user", "u-sam") is None


def test_deleting_a_group_that_is_not_there(store, tenant):
    assert store.delete_group(tenant, "g-nope", actor="system:cli") is False


def test_a_group_may_not_own_an_agent(store, tenant, support):
    """`agent_grants_no_group_owner`. The partial unique index cannot express this — a
    group owner satisfies it perfectly — so without the CHECK the database would accept
    one and only a Python tuple would refuse."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")

    with pytest.raises(StorageError, match="a group may be granted"):
        store.grant_agent(tenant, "reporter", "group", support, role="owner", actor="system:cli")


def test_a_group_may_not_be_a_member_of_a_group(store, tenant, support):
    store.create_group(tenant, "g-leads", "leads", actor="system:cli")

    with pytest.raises(StorageError, match="principal_kind"):
        store.add_group_member(tenant, "g-leads", "group", support, actor="system:cli")


def test_a_group_may_not_act(store, tenant, support):
    """**Decision 1, against the real database.**

    Migration 017 added these three CHECK constraints because until then `agent_grants`
    was the only table with one, and `check_principal_kind` was the entire defense on
    the other three. A test in the same language as that constant would not survive
    somebody widening it; these assertions plus the constraints do.
    """
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")

    with pytest.raises(StorageError, match="never a principal"):
        store.save_connection(
            tenant, "group", support, "github-mcp", ciphertext=b"x", key_id="k1",
            actor=TEST_ACTOR,
        )

    with pytest.raises(StorageError, match="never a principal"):
        store.enqueue_run(
            tenant,
            {
                "run_id": "r-group",
                "agent": "reporter",
                "principal_kind": "group",
                "principal_id": support,
                "task": "t",
            },
        )

    with pytest.raises(StorageError, match="never a principal"):
        store.append_audit(
            tenant,
            {
                "v": 1,
                "ts": datetime.now(timezone.utc),
                "run_id": "r-group",
                "principal_kind": "group",
                "principal_id": support,
                "agent": "reporter",
                "tool": "post_message",
                "effect": "write",
                "args": {},
                "decision": "allow",
            },
        )


def test_a_grant_may_not_name_a_group_that_does_not_exist(store, tenant):
    """No foreign key expresses this, so both stores check it. A grant to a group nobody
    created grants nothing and looks exactly like access."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")

    with pytest.raises(StorageError, match="no group"):
        store.grant_agent(tenant, "reporter", "group", "g-ghost", actor="system:cli")


def test_a_member_may_not_be_added_to_a_group_that_does_not_exist(store, tenant):
    with pytest.raises(StorageError, match="no group"):
        store.add_group_member(tenant, "g-ghost", "user", "u-1", actor="system:cli")


def test_membership_is_idempotent(store, tenant, support):
    store.add_group_member(tenant, support, "user", "u-sam", actor="system:cli")

    assert len(store.list_group_members(tenant, support)) == 2


def test_a_system_principal_may_be_in_a_group(store, tenant, support):
    store.add_group_member(tenant, support, "system", "scheduler", actor="system:cli")

    assert store.groups_for_principal(tenant, "system", "scheduler") == [support]


def test_groups_do_not_cross_tenants(store, tenant, other, support):
    store.save_agent(other, {"name": "reporter"}, actor="system:cli")

    assert store.list_groups(other) == []
    assert store.get_group(other, support) is None
    assert store.groups_for_principal(other, "user", "u-sam") == []
    with pytest.raises(StorageError, match="no group"):
        store.grant_agent(other, "reporter", "group", support, actor="system:cli")


def test_one_directory_id_is_two_groups_in_two_customers(store, tenant, other):
    """Uniqueness is **per tenant**, and 035h is what makes that visible on a screen.

    `test_a_directory_id_round_trips_and_is_unique_per_tenant` above proves the write
    side. This is the read side the menu goes through: each customer's listing marks its
    own group and knows nothing of the other's, so two tenants on one identity provider
    can both link `dir-eng` and neither sees a badge that belongs to the other.
    """
    store.create_group(tenant, "g-1", "eng", external_id="dir-eng", actor="system:cli")
    store.create_group(other, "g-2", "eng", external_id="dir-eng", actor="system:cli")

    assert [(g["group_id"], g["external_id"]) for g in store.list_groups(tenant)] == [
        ("g-1", "dir-eng")
    ]
    assert [(g["group_id"], g["external_id"]) for g in store.list_groups(other)] == [
        ("g-2", "dir-eng")
    ]


def test_groups_and_members_are_ordered(store, tenant):
    store.create_group(tenant, "g-z", "zulu", actor="system:cli")
    store.create_group(tenant, "g-a", "alpha", actor="system:cli")
    store.add_group_member(tenant, "g-a", "user", "u-2", actor="system:cli")
    store.add_group_member(tenant, "g-a", "user", "u-1", actor="system:cli")
    store.add_group_member(tenant, "g-a", "system", "sched", actor="system:cli")

    assert [g["name"] for g in store.list_groups(tenant)] == ["alpha", "zulu"]
    assert [
        (m["principal_kind"], m["principal_id"])
        for m in store.list_group_members(tenant, "g-a")
    ] == [("system", "sched"), ("user", "u-1"), ("user", "u-2")]


def test_a_member_row_round_trips(store, tenant, support):
    row = store.list_group_members(tenant, support)[0]

    assert set(row) == set(GROUP_MEMBER_FIELDS)


def test_groups_granting_an_agent_names_only_this_persons_groups(store, tenant, support):
    """What the refusal in `unshare` puts in its message."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.create_group(tenant, "g-other", "others", actor="system:cli")
    store.add_group_member(tenant, "g-other", "user", "u-outsider", actor="system:cli")
    store.grant_agent(tenant, "reporter", "group", support, role="user", actor="system:cli")
    store.grant_agent(tenant, "reporter", "group", "g-other", role="user", actor="system:cli")

    assert store.groups_granting_agent(tenant, "reporter", "user", "u-sam") == [support]


def test_finding_a_group_by_name(store, tenant, support):
    assert store.find_group_by_name(tenant, "support")["group_id"] == support
    assert store.find_group_by_name(tenant, "finance") is None


def test_the_permission_check_is_one_statement(pg_dsn, monkeypatch):
    """**Decision 7, and the risk this whole step set out to retire.**

    The question 9a exists to answer is whether an indirection survives the permission
    check without turning it into two questions. `agent_grant_role` runs before every run
    and `granted_agent_names` filters every list view, so "one round trip" is a
    requirement rather than a preference — and it is the kind of requirement that is true
    when written and false three refactors later, because fetching a membership list
    first is the obvious way to implement this and nothing else would notice.

    Counted at the store's own round-trip helpers rather than by reading the SQL, so a
    second query added anywhere inside these methods fails this — including one added by
    a helper they call.

    The scale half matters as much as the count: a person in a group holding grants on
    fifty agents must not make the list view fifty queries, so this builds exactly that
    and asserts the number did not move.
    """
    from carnet.storage.postgres import PostgresStorage

    store = PostgresStorage(pg_dsn)
    tenant = "t-one-query"
    store.create_tenant(tenant, "One Query")

    store.create_group(tenant, "g-big", "big", actor="system:cli")
    store.add_group_member(tenant, "g-big", "user", "u-sam", actor="system:cli")
    for n in range(50):
        store.save_agent(tenant, {"name": f"agent-{n:02d}"}, actor="system:cli")
        store.grant_agent(tenant, f"agent-{n:02d}", "group", "g-big", role="user", actor="system:cli")

    # `monkeypatch` rather than setattr-and-restore: a counter left installed on the
    # class would follow every later test in the session, and a suite that measures
    # itself is worse than one that does not.
    calls = []
    for name in ("_execute", "_fetchone", "_fetchall"):
        original = getattr(PostgresStorage, name)

        def counted(self, sql, params=(), _original=original, _name=name):
            calls.append(_name)
            return _original(self, sql, params)

        monkeypatch.setattr(PostgresStorage, name, counted)

    calls.clear()
    role = store.agent_grant_role(tenant, "agent-00", "user", "u-sam")
    role_calls = len(calls)

    calls.clear()
    names = store.granted_agent_names(tenant, "user", "u-sam")
    list_calls = len(calls)

    assert role == "user"
    assert len(names) == 50
    assert role_calls == 1, f"the permission check took {role_calls} round trips"
    assert list_calls == 1, f"the list view took {list_calls} round trips"


# --- directory-backed membership (migration 043, step 033e) -------------------------


def test_a_directory_id_round_trips_and_is_unique_per_tenant(store, tenant, other):
    """`external_id` has been writable since 017 and nothing has ever read one back.

    The uniqueness is asserted here in both stores because it is what 033e's
    reconciliation stands on — one directory group is one group here — and because the
    two stores said *different sentences* about it until this step: Postgres translated
    every unique violation on `groups` as a name collision, safely, since a second
    `external_id` was unreachable while linking did not exist.
    """
    linked = store.create_group(tenant, "g-1", "eng", external_id="dir-eng", actor="system:cli")

    assert linked["external_id"] == "dir-eng"
    assert store.get_group(tenant, "g-1")["external_id"] == "dir-eng"

    with pytest.raises(StorageError, match="already has a group linked to directory"):
        store.create_group(tenant, "g-2", "other", external_id="dir-eng", actor="system:cli")

    # A *name* collision still says so — the two sentences are told apart by the
    # constraint that fired, not by which write it was.
    with pytest.raises(StorageError, match="already has a group called"):
        store.create_group(tenant, "g-3", "eng", external_id="dir-ops", actor="system:cli")

    # ...per tenant. Another customer's directory has its own ids.
    store.create_group(other, "g-4", "eng", external_id="dir-eng", actor="system:cli")


def test_a_group_is_linked_and_unlinked_after_it_exists(store, tenant):
    """The write 017 left out, and the reason `eng` could not adopt a directory: the
    only way to set an `external_id` was to create a group, and re-creating one takes
    its grants with it."""
    store.create_group(tenant, "g-1", "eng", actor="system:cli")

    linked = store.set_group_external_id(tenant, "g-1", "dir-eng", actor="user:u-priya")
    assert linked["external_id"] == "dir-eng"

    (record,) = store.admin_audit_records(tenant, action="group.link")
    assert (record["actor_kind"], record["actor_id"]) == ("user", "u-priya")
    assert record["detail"] == {"external_id": "dir-eng"}

    # Unlinking is the same action with a null id, and removes nobody.
    store.add_group_member(tenant, "g-1", "user", "u-sam", actor="system:cli")
    unlinked = store.set_group_external_id(tenant, "g-1", None, actor="user:u-priya")

    assert unlinked["external_id"] is None
    assert [m["principal_id"] for m in store.list_group_members(tenant, "g-1")] == ["u-sam"]


def test_the_listing_says_which_groups_are_linked_and_says_it_as_null(store, tenant):
    """Step 035h reads `external_id` off **`list_groups`**, which nothing has asserted.

    `get_group` is covered above and it is not the method the menu goes through. The
    projection behind `GET /groups` is `external_id is not None`, so the whole badge rests
    on the two stores agreeing that an unlinked group's `external_id` is `None` **in a
    listing** — a fake returning `''` and a Postgres returning `NULL` would both look
    correct in a grep of `routes_groups.py` and mark the same group two different ways.
    That is 035f's finding restated: a grep proves the code says one thing twice, and only
    a contract test proves the stores answer the same thing.
    """
    store.create_group(tenant, "g-1", "eng", external_id="dir-eng", actor="system:cli")
    store.create_group(tenant, "g-2", "by-hand", actor="system:cli")

    listed = {row["group_id"]: row["external_id"] for row in store.list_groups(tenant)}
    assert listed == {"g-1": "dir-eng", "g-2": None}

    # And unlinking is visible in the listing rather than only in the detail, because the
    # menu is the reader that has to stop marking it.
    store.set_group_external_id(tenant, "g-1", None, actor="system:cli")
    listed = {row["group_id"]: row["external_id"] for row in store.list_groups(tenant)}
    assert listed == {"g-1": None, "g-2": None}


def test_a_blank_directory_id_is_refused_by_both_stores(store, tenant):
    """`''` is not `None`, and neither store may quietly turn one into the other.

    A group linked to `''` is `IS NOT NULL` to the reconciliation and matches no claim
    value, so it removes every person at each sign-in — which is why `check_external_id`
    refuses it, and why 035h's projection reads `is not None` rather than truthiness. The
    refusal is asserted in both stores so that the unreachable state stays unreachable
    from a direction the routes cannot see.
    """
    with pytest.raises(StorageError):
        store.create_group(tenant, "g-1", "eng", external_id="", actor="system:cli")

    store.create_group(tenant, "g-2", "ops", actor="system:cli")
    with pytest.raises(StorageError):
        store.set_group_external_id(tenant, "g-2", "   ", actor="system:cli")

    assert store.get_group(tenant, "g-2")["external_id"] is None


def test_linking_a_group_to_a_directory_id_somebody_else_holds_is_refused(store, tenant):
    store.create_group(tenant, "g-1", "eng", external_id="dir-eng", actor="system:cli")
    store.create_group(tenant, "g-2", "ops", actor="system:cli")

    with pytest.raises(StorageError, match="already has a group linked to directory"):
        store.set_group_external_id(tenant, "g-2", "dir-eng", actor="system:cli")

    assert store.get_group(tenant, "g-2")["external_id"] is None


def test_linking_a_group_that_is_not_there(store, tenant):
    with pytest.raises(NoSuchGroupError):
        store.set_group_external_id(tenant, "g-nope", "dir-eng", actor="system:cli")


def test_a_group_can_be_renamed_and_keeps_everything_keyed_on_its_id(store, tenant):
    """Step 071. A directory renames a group with a PUT on `displayName`; the id is
    what every grant and membership row names, so nothing else moves — and the record
    carries both names, on `agent.rename`'s argument."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.create_group(tenant, "g-1", "eng", external_id="dir-eng", actor="system:cli")
    store.add_group_member(tenant, "g-1", "user", "u-sam", actor="system:cli")
    store.grant_agent(tenant, "reporter", "group", "g-1", actor="system:cli")

    after = store.rename_group(tenant, "g-1", "  engineering ", actor="user:u-1")

    assert after["name"] == "engineering"
    assert after["group_id"] == "g-1"
    assert after["external_id"] == "dir-eng"
    assert store.get_group(tenant, "g-1") == after
    assert store.find_group_by_name(tenant, "engineering")["group_id"] == "g-1"
    assert store.find_group_by_name(tenant, "eng") is None
    assert store.list_group_members(tenant, "g-1")[0]["principal_id"] == "u-sam"
    assert store.agent_grant_role(tenant, "reporter", "user", "u-sam") == "user"

    (record,) = store.admin_audit_records(tenant, action="group.rename")
    assert (record["target_kind"], record["target_id"]) == ("group", "g-1")
    assert record["detail"] == {"from": "eng", "to": "engineering"}


def test_a_rename_to_the_same_name_writes_nothing(store, tenant):
    store.create_group(tenant, "g-1", "eng", actor="system:cli")

    same = store.rename_group(tenant, "g-1", "eng", actor="user:u-1")

    assert same["name"] == "eng"
    assert store.admin_audit_records(tenant, action="group.rename") == []


def test_a_rename_to_a_name_another_group_holds_names_the_other_group(store, tenant):
    store.create_group(tenant, "g-1", "eng", actor="system:cli")
    store.create_group(tenant, "g-2", "ops", actor="system:cli")

    with pytest.raises(StorageError, match="'eng' \\(group 'g-1'\\)"):
        store.rename_group(tenant, "g-2", "eng", actor="user:u-1")

    assert store.get_group(tenant, "g-2")["name"] == "ops"
    assert store.admin_audit_records(tenant, action="group.rename") == []


def test_a_rename_to_nothing_is_refused_and_an_unknown_group_is_none(store, tenant):
    store.create_group(tenant, "g-1", "eng", actor="system:cli")

    with pytest.raises(StorageError, match="name"):
        store.rename_group(tenant, "g-1", "   ", actor="user:u-1")

    assert store.rename_group(tenant, "g-nope", "eng", actor="user:u-1") is None
    assert store.get_group(tenant, "g-1")["name"] == "eng"


def test_directory_groups_answers_only_for_linked_groups(store, tenant):
    """What the reconciliation reads: this tenant's directory-backed groups, and
    whether this person is in each. A hand-made group is not the directory's to change
    and must not appear at all."""
    store.create_group(tenant, "g-1", "eng", external_id="dir-eng", actor="system:cli")
    store.create_group(tenant, "g-2", "ops", external_id="dir-ops", actor="system:cli")
    store.create_group(tenant, "g-3", "by-hand", actor="system:cli")

    store.add_group_member(tenant, "g-1", "user", "u-sam", actor="system:cli")
    store.add_group_member(tenant, "g-3", "user", "u-sam", actor="system:cli")

    assert store.directory_groups(tenant, "u-sam") == [
        {"group_id": "g-1", "external_id": "dir-eng", "member": True},
        {"group_id": "g-2", "external_id": "dir-ops", "member": False},
    ]

    # Somebody else's membership of the same groups is nobody's business here.
    assert store.directory_groups(tenant, "u-priya") == [
        {"group_id": "g-1", "external_id": "dir-eng", "member": False},
        {"group_id": "g-2", "external_id": "dir-ops", "member": False},
    ]


def test_directory_groups_asks_only_about_people(store, tenant):
    """A `system` or `machine` member of a linked group is the admin's business: the
    reconciliation writes nobody but the person signing in, so the two sources of
    membership touch disjoint rows and cannot fight."""
    store.create_group(tenant, "g-1", "eng", external_id="dir-eng", actor="system:cli")
    store.add_group_member(tenant, "g-1", "system", "nightly", actor="system:cli")

    assert store.directory_groups(tenant, "nightly") == [
        {"group_id": "g-1", "external_id": "dir-eng", "member": False},
    ]


def test_directory_groups_does_not_cross_tenants(store, tenant, other):
    store.create_group(other, "g-1", "eng", external_id="dir-eng", actor="system:cli")
    assert store.directory_groups(tenant, "u-sam") == []


def test_a_directory_id_is_normalised_by_every_writer(store, tenant):
    """Both writers, one rule — the edge-case pass found `set_group_external_id`
    stripping and `create_group` not, so `POST /groups` could store `"dir-eng\n"`: a
    group the directory could never fill (matching is byte for byte) and hand edits
    were refused on, leaving it editable by nobody."""
    made = store.create_group(
        tenant, "g-1", "eng", external_id="  dir-eng\t ", actor="system:cli"
    )
    assert made["external_id"] == "dir-eng"

    linked = store.set_group_external_id(tenant, "g-1", " dir-ops ", actor="system:cli")
    assert linked["external_id"] == "dir-ops"


@pytest.mark.parametrize(
    "case,value,because",
    [
        ("blank", "", "blank"),
        ("spaces", "   ", "blank"),
        ("newline", "dir\neng", "control characters"),
        ("nul", "dir\x00eng", "control characters"),
        ("long", "d" * 300, "characters"),
    ],
    ids=lambda case: case if isinstance(case, str) and len(case) < 12 else "",
)
def test_a_bad_directory_id_is_refused(store, tenant, case, value, because):
    """Each of these makes a group that is filled by nothing and editable by nobody.
    The NUL is the sharpest: Postgres cannot store one in TEXT at all, so it would
    arrive as *"storage unavailable: try again later"* about a value that will never be
    accepted.

    Ids of its own per case, because `tenant` truncates a long test id at 60 characters
    and every parametrisation of this name collides past that — the same thing
    `test_every_in_scope_method_leaves_a_record` says one screen up.
    """
    kept, other = f"g-{case}-1", f"g-{case}-2"
    store.create_group(tenant, kept, f"eng-{case}", actor="system:cli")

    with pytest.raises(StorageError, match=because):
        store.create_group(
            tenant, other, f"ops-{case}", external_id=value, actor="system:cli"
        )

    with pytest.raises(StorageError, match=because):
        store.set_group_external_id(tenant, kept, value, actor="system:cli")

    assert store.get_group(tenant, kept)["external_id"] is None
    assert store.get_group(tenant, other) is None


def test_relinking_a_group_to_the_id_it_holds_changes_nothing(store, tenant):
    """`add_group_member`'s rule, one method over: a write that changed nothing writes
    no record — and here it must also not clear the tenant's markers, or a provisioning
    script that re-runs makes every person in the tenant reconcile again for a no-op."""
    store.create_user(tenant, {"id": "u-relink", "issuer": "https://i", "subject": "s-relink"})
    store.create_group(tenant, "g-1", "eng", external_id="dir-eng", actor="system:cli")
    store.record_directory_sync(tenant, "u-relink", "abc123", None)

    same = store.set_group_external_id(tenant, "g-1", "dir-eng", actor="system:cli")

    assert same["external_id"] == "dir-eng"
    assert len(store.admin_audit_records(tenant, action="group.link")) == 0
    assert store.get_user(tenant, "u-relink")["directory_digest"] == "abc123"


def test_invalidation_clears_the_digest_and_keeps_the_ordering(store, tenant):
    """The two marker columns are not one fact. `directory_digest` is *what has been
    done* and is invalidated; `directory_synced_at` is *how new the token was that did
    it*, which nothing about a group changes — and clearing it disarmed the guard that
    keeps an older token from rewriting a newer one's answer."""
    from datetime import datetime, timezone

    store.create_user(tenant, {"id": "u-order", "issuer": "https://i", "subject": "s-order"})
    minted = datetime(2026, 8, 22, 9, 0, tzinfo=timezone.utc)
    store.record_directory_sync(tenant, "u-order", "abc123", minted)

    store.create_group(tenant, "g-1", "eng", external_id="dir-eng", actor="system:cli")

    row = store.get_user(tenant, "u-order")
    assert row["directory_digest"] is None
    assert row["directory_synced_at"] == minted


def test_a_marker_is_only_written_over_the_one_it_was_read_from(store, tenant):
    """The compare-and-set that keeps a marker from outliving the input it was computed
    against: an admin linking a group mid-reconciliation clears it, and the in-flight
    request must not put one straight back."""
    store.create_user(tenant, {"id": "u-cas", "issuer": "https://i", "subject": "s-cas"})

    store.record_directory_sync(tenant, "u-cas", "first", None, expect=None)
    assert store.get_user(tenant, "u-cas")["directory_digest"] == "first"

    store.record_directory_sync(tenant, "u-cas", "stale", None, expect="something-else")
    assert store.get_user(tenant, "u-cas")["directory_digest"] == "first"

    store.record_directory_sync(tenant, "u-cas", "second", None, expect="first")
    assert store.get_user(tenant, "u-cas")["directory_digest"] == "second"


def test_re_registering_a_provider_only_invalidates_when_the_claim_moves(store, tenant):
    """`--add-idp` is an upsert, so a provisioning script re-runs it. Clearing every
    marker in the tenant to rotate a `jwks_uri` is the stampede the digest exists to
    prevent."""
    issuer = f"https://idp/{tenant}"
    store.create_user(tenant, {"id": "u-idp", "issuer": "https://i", "subject": "s-idp"})
    row = {"issuer": issuer, "jwks_uri": "https://idp/keys", "audience": "api",
           "groups_claim": "groups"}
    store.save_tenant_idp(tenant, row)
    store.record_directory_sync(tenant, "u-idp", "abc123", None)

    store.save_tenant_idp(tenant, {**row, "jwks_uri": "https://idp/keys2"})
    assert store.get_user(tenant, "u-idp")["directory_digest"] == "abc123"

    store.save_tenant_idp(tenant, {**row, "groups_claim": "roles"})
    assert store.get_user(tenant, "u-idp")["directory_digest"] is None


def test_the_reconciliation_marker_round_trips(store, tenant):
    from datetime import datetime, timezone

    store.create_user(
        tenant, {"id": "u-synced", "issuer": "https://idp", "subject": "s-synced"}
    )
    assert store.find_user("https://idp", "s-synced")["directory_digest"] is None

    minted = datetime(2026, 8, 22, 9, 0, tzinfo=timezone.utc)
    store.record_directory_sync(tenant, "u-synced", "abc123", minted)

    row = store.find_user("https://idp", "s-synced")
    assert row["directory_digest"] == "abc123"
    assert row["directory_synced_at"] == minted


def test_a_marker_never_outlives_the_thing_it_was_computed_against(store, tenant):
    """The invariant that makes the digest exact rather than a guess with a staleness
    window: every write that changes what a reconciliation would produce clears it.

    Linking does. Unlinking deliberately does **not** — nobody is removed, the group
    simply stops being the directory's — and neither does creating a group nobody has
    linked.
    """
    store.create_user(
        tenant, {"id": "u-marker", "issuer": "https://idp", "subject": "s-marker"}
    )
    store.create_group(tenant, "g-1", "eng", actor="system:cli")

    def mark():
        store.record_directory_sync(tenant, "u-marker", "abc123", None)

    def digest():
        return store.find_user("https://idp", "s-marker")["directory_digest"]

    mark()
    store.create_group(tenant, "g-2", "hand", actor="system:cli")
    assert digest() == "abc123", "an unlinked group changes nothing"

    store.set_group_external_id(tenant, "g-1", "dir-eng", actor="system:cli")
    assert digest() is None, "linking a group must be believed at the next request"

    mark()
    store.set_group_external_id(tenant, "g-1", None, actor="system:cli")
    assert digest() == "abc123", "unlinking removes nobody, so nothing is recomputed"

    mark()
    store.create_group(tenant, "g-3", "linked", external_id="dir-ops", actor="system:cli")
    assert digest() is None, "a group born linked is the same change"

    mark()
    store.save_tenant_idp(
        tenant,
        {
            "issuer": f"https://idp/{tenant}",
            "jwks_uri": "https://idp/keys",
            "audience": "api",
            "groups_claim": "groups",
        },
    )
    assert digest() is None, "the claim mapping is the other half of what it read"

    # ...and a registration that leaves the claim where it was does **not** — see
    # `test_re_registering_a_provider_only_invalidates_when_the_claim_moves`.


def test_the_claim_mapping_defaults_to_saying_nothing_about_groups(store, tenant):
    """`subject_claim` and `email_claim` default to what a conformant token uses; this
    one defaults to None, because a provider that emits no groups claim is ordinary and
    a default would be a promise the token cannot keep."""
    issuer = f"https://idp/{tenant}"
    store.save_tenant_idp(
        tenant,
        {"issuer": issuer, "jwks_uri": "https://idp/keys", "audience": "api"},
    )
    (row,) = store.find_tenant_idps(issuer)
    assert row["groups_claim"] is None

    store.save_tenant_idp(
        tenant,
        {
            "issuer": issuer,
            "jwks_uri": "https://idp/keys",
            "audience": "api",
            "groups_claim": "groups",
        },
    )
    (row,) = store.find_tenant_idps(issuer)
    assert row["groups_claim"] == "groups"
    assert store.list_tenant_idps(tenant)[0]["groups_claim"] == "groups"


# --- roles and ownership (migration 011) --------------------------------------------


def test_a_grant_defaults_to_the_bottom_of_the_ladder(store, tenant):
    """Sharing without saying a level shares the least of it."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")

    store.grant_agent(tenant, "reporter", "user", "u-1", actor="system:cli")

    assert store.agent_grant_role(tenant, "reporter", "user", "u-1") == "user"


def test_a_role_round_trips(store, tenant):
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")

    store.grant_agent(tenant, "reporter", "user", "u-1", role="editor", actor="system:cli")

    assert store.agent_grant_role(tenant, "reporter", "user", "u-1") == "editor"
    assert store.list_agent_grants(tenant, "reporter")[0]["role"] == "editor"


def test_no_grant_has_no_role(store, tenant):
    """None rather than a default, because "they hold nothing" and "they hold the
    weakest level" are different answers and only one of them permits a run."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")

    assert store.agent_grant_role(tenant, "reporter", "user", "nobody") is None


def test_an_unknown_role_is_refused(store, tenant):
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")

    with pytest.raises(StorageError, match="role must be one of"):
        store.grant_agent(tenant, "reporter", "user", "u-1", role="admin", actor="system:cli")


def test_re_granting_changes_the_role(store, tenant):
    """Promotion and demotion are the same operation, so there is one path to a level
    rather than two that can disagree about what happens to `granted_by`."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")

    store.grant_agent(tenant, "reporter", "user", "u-1", role="user", actor="system:cli")
    store.grant_agent(tenant, "reporter", "user", "u-1", role="editor", actor="system:cli")

    grants = store.list_agent_grants(tenant, "reporter")
    assert len(grants) == 1
    assert grants[0]["role"] == "editor"


def test_an_agent_has_exactly_one_owner(store, tenant):
    """The partial unique index. A second owner is refused, in both stores, with the
    same sentence — a person reads this while trying to share something."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.grant_agent(tenant, "reporter", "user", "u-1", role="owner", actor="system:cli")

    with pytest.raises(StorageError, match="already has an owner"):
        store.grant_agent(tenant, "reporter", "user", "u-2", role="owner", actor="system:cli")

    assert store.agent_grant_role(tenant, "reporter", "user", "u-1") == "owner"
    assert store.agent_grant_role(tenant, "reporter", "user", "u-2") is None


def test_re_granting_ownership_to_the_incumbent_is_not_a_conflict(store, tenant):
    """Idempotence has to survive the index: re-asserting what is already true is not a
    second owner."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")

    store.grant_agent(tenant, "reporter", "user", "u-1", role="owner", granted_by="a", actor="user:a")
    store.grant_agent(tenant, "reporter", "user", "u-1", role="owner", granted_by="b", actor="user:b")

    grants = store.list_agent_grants(tenant, "reporter")
    assert len(grants) == 1
    assert (grants[0]["role"], grants[0]["granted_by"]) == ("owner", "b")


def test_two_tenants_may_each_own_an_agent_of_the_same_name(store, tenant, other):
    """The index is per (tenant, agent). Two customers both calling an agent `reporter`
    is the ordinary case, not a collision."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.save_agent(other, {"name": "reporter"}, actor="system:cli")

    store.grant_agent(tenant, "reporter", "user", "u-1", role="owner", actor="system:cli")
    store.grant_agent(other, "reporter", "user", "u-2", role="owner", actor="system:cli")

    assert store.agent_grant_role(tenant, "reporter", "user", "u-1") == "owner"
    assert store.agent_grant_role(other, "reporter", "user", "u-2") == "owner"


def test_transfer_demotes_the_previous_owner(store, tenant):
    """Demotion rather than removal: handing an agent over almost never means "and lock
    me out of it"."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.grant_agent(tenant, "reporter", "user", "u-1", role="owner", actor="system:cli")

    store.transfer_agent_ownership(tenant, "reporter", "user", "u-2", granted_by="u-1", actor="user:u-1")

    assert store.agent_grant_role(tenant, "reporter", "user", "u-1") == "editor"
    assert store.agent_grant_role(tenant, "reporter", "user", "u-2") == "owner"


def test_transfer_promotes_somebody_who_already_had_a_grant(store, tenant):
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.grant_agent(tenant, "reporter", "user", "u-1", role="owner", actor="system:cli")
    store.grant_agent(tenant, "reporter", "user", "u-2", role="user", actor="system:cli")

    store.transfer_agent_ownership(tenant, "reporter", "user", "u-2", actor="system:cli")

    assert store.agent_grant_role(tenant, "reporter", "user", "u-2") == "owner"
    assert len(store.list_agent_grants(tenant, "reporter")) == 2


def test_transfer_to_the_incumbent_leaves_them_owning_it(store, tenant):
    """The demote-then-promote ordering must not demote the person it is promoting."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.grant_agent(tenant, "reporter", "user", "u-1", role="owner", actor="system:cli")

    store.transfer_agent_ownership(tenant, "reporter", "user", "u-1", actor="system:cli")

    assert store.agent_grant_role(tenant, "reporter", "user", "u-1") == "owner"


def test_transfer_of_an_ownerless_agent_just_sets_one(store, tenant):
    """The state migration 011 exists to prevent, reachable again by revoking an owner.
    Transfer is how it gets fixed, so it must not require an incumbent."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")

    store.transfer_agent_ownership(tenant, "reporter", "user", "u-1", actor="system:cli")

    assert store.agent_grant_role(tenant, "reporter", "user", "u-1") == "owner"


def test_transferring_an_absent_agent_is_refused(store, tenant):
    with pytest.raises(StorageError, match="no agent"):
        store.transfer_agent_ownership(tenant, "never-existed", "user", "u-1", actor="system:cli")


# --- platform roles (migration 026) --------------------------------------------------
#
# Who may administer a **tenant**, as opposed to `agent_grants`, which answers who may use
# one agent. The assertions worth reading first are the two that are about the schema
# rather than about a method: `test_a_group_cannot_hold_a_platform_role`, which is the
# constraint that stops group membership becoming self-service promotion, and
# `test_a_platform_role_row_carries_exactly_the_fields_both_stores_agree_on`, which is the
# `RUN_FIELDS` device catching a column added to one implementation and not the other.


def test_a_platform_role_row_carries_exactly_the_fields_both_stores_agree_on(
    store, tenant
):
    """Built from `PLATFORM_ROLE_FIELDS` rather than typed out, so a column added to one
    store and not the other fails without anybody remembering to extend a list. That is
    the exact drift that shipped `audit.credential` with 818 tests green."""
    row = store.grant_platform_role(
        tenant, "user", "u-1", "admin", granted_by="system:cli", actor="system:cli"
    )

    assert set(row) == set(PLATFORM_ROLE_FIELDS)
    assert row["tenant_id"] == tenant
    assert (row["principal_kind"], row["principal_id"], row["role"]) == (
        "user",
        "u-1",
        "admin",
    )
    assert row["granted_by"] == "system:cli"
    assert row["granted_at"] is not None


def test_a_role_is_read_back_and_is_scoped_to_its_tenant(store, tenant):
    """The tenant filter is in the WHERE clause of the one method on the request path.
    An admin of tenant A holds nothing in tenant B."""
    other = f"{tenant}-other"
    store.create_tenant(other, "Other")
    store.grant_platform_role(tenant, "user", "u-1", "admin", actor="system:cli")

    assert store.has_platform_role(tenant, "user", "u-1", "admin") is True
    assert store.has_platform_role(other, "user", "u-1", "admin") is False
    assert store.has_platform_role(tenant, "user", "u-2", "admin") is False
    assert store.list_platform_roles(other) == []


def test_a_group_cannot_hold_a_platform_role(store, tenant):
    """Migration 026's CHECK and `check_platform_role`, and the reason for both: anybody
    who may add a member to a group would otherwise be able to make an administrator."""
    with pytest.raises(StorageError, match="group cannot hold"):
        store.grant_platform_role(tenant, "group", "g-1", "admin", actor="system:cli")

    assert store.list_platform_roles(tenant) == []


def test_a_role_outside_the_vocabulary_is_refused(store, tenant):
    with pytest.raises(StorageError, match="PLATFORM_ROLES"):
        store.grant_platform_role(tenant, "user", "u-1", "auditor", actor="system:cli")


def test_a_role_row_needs_a_principal_id(store, tenant):
    with pytest.raises(StorageError, match="principal id"):
        store.grant_platform_role(tenant, "user", "", "admin", actor="system:cli")


def test_granting_a_role_somebody_already_holds_refreshes_it(store, tenant):
    """An upsert, and re-granting records **again** — `allow_host`'s argument verbatim: a
    second approval is a second decision, and the most recent yes is who an incident wants
    to talk to."""
    store.grant_platform_role(
        tenant, "user", "u-1", "admin", granted_by="system:cli", actor="system:cli"
    )
    store.grant_platform_role(
        tenant, "user", "u-1", "admin", granted_by="user:u-priya", actor="user:u-priya"
    )

    rows = store.list_platform_roles(tenant)
    assert len(rows) == 1
    assert rows[0]["granted_by"] == "user:u-priya"

    granted = store.admin_audit_records(tenant, action="role.grant")
    assert [record["actor_id"] for record in granted] == ["cli", "u-priya"]


def test_revoking_a_role_nobody_holds_changes_nothing_and_records_nothing(store, tenant):
    """`delete_pending_grant`'s rule and `revoke_host`'s: the log records changes, not
    attempts."""
    assert (
        store.revoke_platform_role(tenant, "user", "u-1", "admin", actor="system:cli")
        is False
    )

    assert store.admin_audit_records(tenant, action="role.revoke") == []


def test_a_revoked_role_is_gone_and_leaves_a_record_naming_the_person(store, tenant):
    """`user` is the first `ADMIN_TARGET_KINDS` value that is a person, and it has to be:
    "who made Sam an administrator" has no other noun to be recorded against."""
    store.grant_platform_role(tenant, "user", "u-sam", "admin", actor="system:cli")

    assert (
        store.revoke_platform_role(tenant, "user", "u-sam", "admin", actor="user:u-priya")
        is True
    )
    assert store.has_platform_role(tenant, "user", "u-sam", "admin") is False

    record = store.admin_audit_records(tenant, action="role.revoke")[0]
    assert (record["target_kind"], record["target_id"]) == ("user", "u-sam")
    assert (record["actor_kind"], record["actor_id"]) == ("user", "u-priya")
    assert record["detail"]["role"] == "admin"


def test_a_system_principal_may_hold_a_row_even_though_it_needs_none(store, tenant):
    """The row is meaningless — `require_admin` short-circuits on `system` — and it is
    **accepted** rather than refused, because `principal_kind` is the vocabulary of who
    may act and a store that second-guessed policy would be the wrong layer for it.

    **The record calls it `system`, not `user`.** That is why `ADMIN_TARGET_KINDS` grew
    two values rather than one: recording every role grant against `user` would have
    logged a scheduler as a person, and it was found by running the end-to-end script
    rather than by reading the plan, which asked for `user` alone.
    """
    store.grant_platform_role(tenant, "system", "nightly", "admin", actor="system:cli")

    assert store.has_platform_role(tenant, "system", "nightly", "admin") is True

    record = store.admin_audit_records(tenant, action="role.grant")[0]
    assert (record["target_kind"], record["target_id"]) == ("system", "nightly")


def test_roles_are_listed_in_a_stable_order(store, tenant):
    store.grant_platform_role(tenant, "user", "u-2", "admin", actor="system:cli")
    store.grant_platform_role(tenant, "system", "nightly", "admin", actor="system:cli")
    store.grant_platform_role(tenant, "user", "u-1", "admin", actor="system:cli")

    assert [
        (row["principal_kind"], row["principal_id"])
        for row in store.list_platform_roles(tenant)
    ] == [("system", "nightly"), ("user", "u-1"), ("user", "u-2")]


def test_a_role_row_needs_a_tenant_that_exists(store, uniq):
    """The foreign key, in both stores. A role granted into a tenant nobody created is a
    row that grants access inside a customer that does not exist."""
    with pytest.raises(StorageError):
        store.grant_platform_role(
            f"no-such-{uniq}", "user", "u-1", "admin", actor="system:cli"
        )


# --- pending grants (migration 012) --------------------------------------------------


def _a_user(store, tenant, user_id, email):
    """A user in `tenant`, with an identity scoped to it.

    `users` is unique on `(issuer, subject)` **globally** — deliberately, because a
    subject cannot belong to two customers — so a fixed pair here would collide across
    tests against Postgres while passing in memory. Which it did.
    """
    store.create_user(
        tenant,
        {
            "id": f"{tenant}-{user_id}",
            "issuer": f"https://{tenant}.idp.example",
            "subject": user_id,
            "email": email,
        },
    )
    return f"{tenant}-{user_id}"


def test_a_user_is_found_by_email(store, tenant):
    """For sharing, never for authentication — see migration 012. Nobody is identified
    by this; it answers "is there already a principal to grant to?\""""
    uid = _a_user(store, tenant, "u-1", "priya@acme.com")

    assert store.find_user_by_email(tenant, "priya@acme.com")["id"] == uid


def test_finding_by_email_ignores_case(store, tenant):
    """Somebody typing a colleague's address into a share box will not match its stored
    casing, and being right about RFC 5321 would only make the feature not work."""
    uid = _a_user(store, tenant, "u-1", "Priya@Acme.com")

    assert store.find_user_by_email(tenant, "  priya@acme.com ")["id"] == uid


def test_finding_by_email_does_not_cross_tenants(store, tenant, other):
    _a_user(store, tenant, "u-1", "priya@acme.com")

    assert store.find_user_by_email(other, "priya@acme.com") is None


def test_an_empty_email_matches_nobody(store, tenant):
    """A provider that supplies no email claim leaves this blank on every user, and a
    blank lookup must not resolve to the first of them."""
    _a_user(store, tenant, "u-1", "")

    assert store.find_user_by_email(tenant, "") is None


def test_a_pending_grant_round_trips(store, tenant):
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")

    store.add_pending_grant(tenant, "reporter", "Priya@Acme.com", role="editor",
                            granted_by="user:u-1", actor="user:u-1")

    waiting = store.list_pending_grants(tenant, "reporter")
    assert [(w["email"], w["role"], w["granted_by"]) for w in waiting] == [
        ("priya@acme.com", "editor", "user:u-1")
    ]


def test_a_pending_grant_cannot_be_owner(store, tenant):
    """Ownership is transferred to a real principal. An agent owned by an address that
    is never claimed is an orphan created on purpose."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")

    with pytest.raises(StorageError, match="Ownership is transferred"):
        store.add_pending_grant(tenant, "reporter", "priya@acme.com", role="owner", actor="system:cli")


def test_pending_grants_on_an_absent_agent_are_refused(store, tenant):
    with pytest.raises(StorageError, match="no agent"):
        store.add_pending_grant(tenant, "never-existed", "priya@acme.com", actor="system:cli")


def test_claiming_turns_a_pending_grant_into_a_real_one(store, tenant):
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.add_pending_grant(tenant, "reporter", "priya@acme.com", role="editor", actor="system:cli")

    claimed = store.claim_pending_grants(tenant, "Priya@acme.com", "user", "u-1")

    assert claimed == ["reporter"]
    assert store.agent_grant_role(tenant, "reporter", "user", "u-1") == "editor"
    assert store.list_pending_grants(tenant, "reporter") == []


def test_claiming_twice_claims_nothing_the_second_time(store, tenant):
    """Two of somebody's very first requests arrive at once and both try to claim. The
    second must find nothing rather than fail."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.add_pending_grant(tenant, "reporter", "priya@acme.com", actor="system:cli")

    assert store.claim_pending_grants(tenant, "priya@acme.com", "user", "u-1") == ["reporter"]
    assert store.claim_pending_grants(tenant, "priya@acme.com", "user", "u-1") == []


def test_claiming_never_demotes(store, tenant):
    """Shared at `user` while already an editor, a plain upsert would take access away
    at the moment of a login — the worst possible time to find out."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.grant_agent(tenant, "reporter", "user", "u-1", role="editor", actor="system:cli")
    store.add_pending_grant(tenant, "reporter", "priya@acme.com", role="user", actor="system:cli")

    store.claim_pending_grants(tenant, "priya@acme.com", "user", "u-1")

    assert store.agent_grant_role(tenant, "reporter", "user", "u-1") == "editor"


def test_claiming_does_promote(store, tenant):
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.grant_agent(tenant, "reporter", "user", "u-1", role="user", actor="system:cli")
    store.add_pending_grant(tenant, "reporter", "priya@acme.com", role="editor", actor="system:cli")

    store.claim_pending_grants(tenant, "priya@acme.com", "user", "u-1")

    assert store.agent_grant_role(tenant, "reporter", "user", "u-1") == "editor"


def test_claiming_never_touches_an_owner(store, tenant):
    """The partial unique index would refuse it anyway; this is the check that the
    claim path cannot be the thing that trips it."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.grant_agent(tenant, "reporter", "user", "u-1", role="owner", actor="system:cli")
    store.add_pending_grant(tenant, "reporter", "priya@acme.com", role="editor", actor="system:cli")

    store.claim_pending_grants(tenant, "priya@acme.com", "user", "u-1")

    assert store.agent_grant_role(tenant, "reporter", "user", "u-1") == "owner"


def test_claiming_collects_every_agent_at_once(store, tenant):
    for name in ("alpha", "zulu"):
        store.save_agent(tenant, {"name": name}, actor="system:cli")
        store.add_pending_grant(tenant, name, "priya@acme.com", actor="system:cli")

    assert store.claim_pending_grants(tenant, "priya@acme.com", "user", "u-1") == [
        "alpha", "zulu"
    ]


def test_claiming_does_not_cross_tenants(store, tenant, other):
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.save_agent(other, {"name": "reporter"}, actor="system:cli")
    store.add_pending_grant(tenant, "reporter", "priya@acme.com", actor="system:cli")

    assert store.claim_pending_grants(other, "priya@acme.com", "user", "u-1") == []
    assert len(store.list_pending_grants(tenant, "reporter")) == 1


def test_claiming_an_empty_address_claims_nothing(store, tenant):
    """A provider with no email claim gives every user a blank address, and blank must
    not be a key that collects other people's invitations."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.add_pending_grant(tenant, "reporter", "priya@acme.com", actor="system:cli")

    assert store.claim_pending_grants(tenant, "", "user", "u-1") == []


def test_a_pending_grant_can_be_cancelled(store, tenant):
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.add_pending_grant(tenant, "reporter", "priya@acme.com", actor="system:cli")

    store.delete_pending_grant(tenant, "reporter", "PRIYA@acme.com", actor="system:cli")
    store.delete_pending_grant(tenant, "reporter", "priya@acme.com", actor="system:cli")

    assert store.list_pending_grants(tenant, "reporter") == []


def test_deleting_an_agent_takes_its_pending_grants_with_it(store, tenant):
    """Worse than a stale grant: a stale pending row does not reactivate on the next
    read, it reactivates at somebody's first login, weeks later, on an agent that merely
    reuses the name."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.add_pending_grant(tenant, "reporter", "priya@acme.com", actor="system:cli")

    store.delete_agent(tenant, "reporter", actor="system:cli")
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")

    assert store.list_pending_grants(tenant, "reporter") == []
    assert store.claim_pending_grants(tenant, "priya@acme.com", "user", "u-1") == []


def test_deleting_an_agent_takes_its_grants_with_it(store, tenant):
    """Migration 009 says why: "a grant on a deleted agent is not a grant, it is a row
    that will quietly reactivate if the name is ever reused."

    Postgres enforces it with ON DELETE CASCADE. The in-memory store has to be told, and
    until it was, it kept the rows — so deleting `reporter` and creating a new one by the
    same name handed the new agent the old one's audience, silently, in the store every
    test in this repository runs against by default.
    """
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.grant_agent(tenant, "reporter", "user", "u-1", role="owner", actor="system:cli")

    store.delete_agent(tenant, "reporter", actor="system:cli")

    assert store.list_agent_grants(tenant, "reporter") == []
    assert store.granted_agent_names(tenant, "user", "u-1") == []

    # The state the cascade exists for: a new agent reusing the name starts ungranted.
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    assert store.agent_grant_role(tenant, "reporter", "user", "u-1") is None


def test_the_owner_index_is_not_inert(pg_dsn):
    """Postgres only, and written in the shape of the bug it is guarding against.

    `agent_grants_one_owner` is a **partial** index. Two things have to be true and only
    one of them is obvious: a second owner must be refused, and two non-owners must
    still be permitted. An index accidentally written without its `WHERE` would pass a
    test that only checked the first, while silently allowing an agent exactly one
    grant of any kind — which is sharing that cannot share.

    Asserted against the raw table, because both application-level paths route around
    this and this is about the database.
    """
    import psycopg

    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        conn.execute(
            "INSERT INTO tenants (id, name) VALUES (%s, %s) ON CONFLICT (id) DO NOTHING",
            ("t-owner", "Owner"),
        )
        reporter = new_agent_id()
        conn.execute(
            "INSERT INTO agents (tenant_id, agent_id, name, config) "
            "VALUES (%s, %s, %s, %s)",
            ("t-owner", reporter, "reporter", '{"name": "reporter"}'),
        )

        def grant(principal_id, role):
            conn.execute(
                "INSERT INTO agent_grants "
                "(tenant_id, agent_id, grantee_kind, grantee_id, role) "
                "VALUES (%s, %s, 'user', %s, %s)",
                ("t-owner", reporter, principal_id, role),
            )

        grant("u-1", "owner")
        with pytest.raises(psycopg.errors.UniqueViolation):
            grant("u-2", "owner")

        # The half a total index would break.
        grant("u-3", "editor")
        grant("u-4", "editor")


def test_migration_011_adopts_agents_that_predate_it(pg_dsn):
    """The backfill, run against an agent that has no grant — which is the only state
    it exists for, and the one it never sees in a suite that builds the schema before
    writing any rows.

    Without this the statement is untested by construction: every migration runs against
    an empty `agents` table here, so an `INSERT ... SELECT` that adopted nothing would
    pass every other test in this file. That is the same shape as the inert unique
    constraint below — a statement that looks enforced and does nothing.

    The SQL is read from the migration rather than restated, so editing one edits both.

    ## Why the column names are rewritten before replaying it

    Migration 017 renamed `principal_kind`/`principal_id` on this table to
    `grantee_kind`/`grantee_id`, so 011's statement no longer parses against the current
    schema. In production that is fine and invisible — migrations run in order, each
    exactly once, and 011 ran while the old names were current. It only bites here,
    because this test deliberately replays a historical statement against a
    fully-migrated database.

    Rewriting is the right fix rather than restating the statement: what is under test is
    011's *logic* — the `WHERE NOT EXISTS` guard, the `ON CONFLICT ... DO UPDATE` that
    promotes rather than skips — and none of that is affected by what the columns are
    called. Restating it would decouple the test from the file and lose the property the
    docstring above claims.

    **Editing the migration file's column names is not what this substitution is for.**
    It applies exactly the renames later migrations perform, so if a new one arrives this
    fails loudly rather than silently testing the wrong thing.

    ## Migration 035 arrived, and it is a re-key rather than a rename

    The paragraph above promised a loud failure, and got one: 035 replaced
    `agent_grants.agent_name` with `agent_id` and made `agents` keyed by the id. That is
    not a third rename — the new column holds a *different value*, so the substitution
    below has to translate `a.name` into `a.agent_id` on the SELECT side as well as the
    column name on the INSERT side.

    Both edges are still 011's own logic under test: the `WHERE NOT EXISTS` guard and the
    `ON CONFLICT ... DO UPDATE` promote are what this replays, and neither depends on which
    column identifies the agent. What the substitution must not become is a rewrite that
    quietly makes a *different* statement pass, which is why each rule below is one
    migration's one change, spelled out.
    """
    import psycopg

    from carnet.storage import migrate

    sql = (migrate.MIGRATIONS_DIR / "011_agent_grant_roles.sql").read_text(
        encoding="utf-8"
    )
    backfill = next(
        statement
        for statement in sql.split(";")
        if "INSERT INTO agent_grants" in statement
    )
    # 017's two renames.
    backfill = backfill.replace("principal_kind", "grantee_kind").replace(
        "principal_id", "grantee_id"
    )
    # 035's re-key. `a.name` first: it is what the SELECT projects into the column, and
    # rewriting the column name alone would insert a name into an id column — which the
    # `agent_id_is_opaque` CHECK would refuse, loudly, but for the wrong reason.
    backfill = backfill.replace("a.name", "a.agent_id").replace(
        "g.agent_name = a.agent_id", "g.agent_id = a.agent_id"
    )
    backfill = backfill.replace("agent_name", "agent_id")

    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        conn.execute(
            "INSERT INTO tenants (id, name) VALUES (%s, %s) ON CONFLICT (id) DO NOTHING",
            ("t-adopt", "Adopt"),
        )
        ids = {
            name: new_agent_id()
            for name in ("orphan", "already-owned", "cli-had-a-grant")
        }
        for name, agent_id in ids.items():
            conn.execute(
                "INSERT INTO agents (tenant_id, agent_id, name, config) "
                "VALUES (%s, %s, %s, %s)",
                ("t-adopt", agent_id, name, '{"name": "%s"}' % name),
            )

        # The two branches the guards exist for: one agent already owned, one holding a
        # lower `system:cli` grant that the ON CONFLICT has to promote.
        conn.execute(
            "INSERT INTO agent_grants "
            "(tenant_id, agent_id, grantee_kind, grantee_id, role) "
            "VALUES (%s, %s, 'user', 'u-9', 'owner')",
            ("t-adopt", ids["already-owned"]),
        )
        conn.execute(
            "INSERT INTO agent_grants "
            "(tenant_id, agent_id, grantee_kind, grantee_id, role) "
            "VALUES (%s, %s, 'system', 'cli', 'user')",
            ("t-adopt", ids["cli-had-a-grant"]),
        )

        conn.execute(backfill)

        def grants(agent_name):
            return conn.execute(
                "SELECT grantee_kind, grantee_id, role, granted_by "
                "FROM agent_grants WHERE tenant_id = %s AND agent_id = %s",
                ("t-adopt", ids[agent_name]),
            ).fetchall()

        orphan = grants("orphan")
        already_owned = grants("already-owned")
        cli_had_a_grant = grants("cli-had-a-grant")

    assert orphan == [("system", "cli", "owner", "migration:011")]

    # An agent that already has an owner is left entirely alone.
    assert already_owned == [("user", "u-9", "owner", "")]

    # And one where `system:cli` already held something lower is promoted rather than
    # skipped — DO NOTHING here would leave the agent with no owner at all, which is the
    # single outcome this migration exists to prevent.
    assert cli_had_a_grant == [("system", "cli", "owner", "migration:011")]


def test_the_issuer_constraint_is_not_inert(pg_dsn):
    """Postgres only, and it exists because this constraint WAS inert.

    A plain `UNIQUE (issuer, discriminator_claim, discriminator_value)` permits any
    number of rows for one issuer while the discriminator columns are NULL, because
    Postgres treats NULL as distinct from NULL — and NULL is exactly the Okta and Entra
    shape, the common case. `NULLS NOT DISTINCT` is what makes it mean anything.

    Asserted against the raw table rather than through `save_tenant_idp`, because the
    application-level check passes either way. This is about the database.
    """
    import psycopg

    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        conn.execute(
            "INSERT INTO tenants (id, name) VALUES (%s, %s) ON CONFLICT (id) DO NOTHING",
            ("t-inert", "Inert"),
        )
        conn.execute(
            "INSERT INTO tenant_idps (tenant_id, issuer, jwks_uri, audience) "
            "VALUES (%s, %s, %s, %s)",
            ("t-inert", "https://inert.example", "https://inert.example/keys", "aud"),
        )

        with pytest.raises(psycopg.errors.UniqueViolation):
            conn.execute(
                "INSERT INTO tenant_idps (tenant_id, issuer, jwks_uri, audience) "
                "VALUES (%s, %s, %s, %s)",
                ("t-inert", "https://inert.example", "https://x.example/keys", "aud"),
            )


def test_only_a_person_may_claim_a_pending_grant(store, tenant):
    """A pending grant is addressed to somebody's email. A system principal has none
    and never arrives through a login, so claiming one as `system` is meaningless — and
    was permitted until this asked. Not an exploit (the caller already holds the
    database) but a door left open for the second caller of this method."""
    store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    store.add_pending_grant(tenant, "reporter", "priya@acme.com", actor="system:cli")

    with pytest.raises(StorageError, match="only a 'user' may claim"):
        store.claim_pending_grants(tenant, "priya@acme.com", "system", "scheduler")

    assert len(store.list_pending_grants(tenant, "reporter")) == 1


def test_every_audit_field_survives_a_round_trip(store, tenant):
    """A record read back must carry every field it was written with.

    This exists because it did not, and the failure was invisible in exactly the way
    this suite exists to prevent. `audit` has fixed columns in Postgres and the
    in-memory store keeps whatever dict it is given, so a field added to
    `core/audit.py` without being added to `_AUDIT_COLUMNS` is written by one
    implementation and **silently dropped** by the other. `credential` shipped that way
    and was caught by running a real query against a real database, not by the suite.

    Built from `audit.record`'s own output rather than a literal, so a field added
    later is covered without anybody remembering to extend this list. That is the whole
    point: a test naming today's fields would have passed on the day `credential` was
    added, for the same reason everything else did.
    """
    import carnet.storage as storage_module
    from carnet.core import audit
    from carnet.core.principal import Principal

    # `audit.record` writes through the *active* store, and conftest points that at its
    # own in-memory one. Repointed for the length of this test; the autouse fixture
    # resets it afterwards.
    storage_module.configure(store)

    written = audit.record(
        run_id="r-roundtrip",
        principal=Principal.user("u_priya", tenant),
        agent="reporter",
        tool="github_mcp_list_issues",
        tool_input={"owner": "anthropics", "repo": "sdk"},
        effect="read",
        decision="allow",
        outcome="ok",
        credential="delegated",
        duration_ms=42,
        response_bytes=1234,
    )

    (read_back,) = store.audit_records(tenant, run_id="r-roundtrip")

    missing = {k for k in written if k not in read_back}
    assert not missing, (
        f"{sorted(missing)} was written and did not come back. A field added to "
        "core/audit.py needs a column and a place in PostgresStorage._AUDIT_COLUMNS."
    )
    assert read_back == written


def test_the_credential_kind_is_stored_and_returned(store, tenant):
    """The v6 field specifically, since it is the one that was dropped.

    `None` is in the list deliberately: it is what a record written before v6 carries,
    and what a tool needing no secret carries now. It has to survive as NULL rather
    than becoming an empty string, because "no credential" and "we did not record one"
    are the two things a reader has to tell apart.
    """
    for kind in ("delegated", "shared", None):
        store.append_audit(
            tenant,
            {
                "v": 6,
                "ts": "2026-08-04T10:00:00.000+00:00",
                "run_id": f"r-{kind}",
                "principal_kind": "user",
                "principal_id": "u_priya",
                "agent": "reporter",
                "tool": "t",
                "decision": "allow",
                "credential": kind,
            },
        )
        (record,) = store.audit_records(tenant, run_id=f"r-{kind}")
        assert record["credential"] == kind


# --- connections ------------------------------------------------------------------
#
# Delegated credentials. Storage holds opaque bytes and never decrypts anything, so
# every assertion here is about the *row* — that it round-trips byte-identically, that
# it is scoped, and that the metadata view cannot hand anybody the sealed value.

SEALED = b"\x00\x01nonce-and-ciphertext-and-tag\xff"


@pytest.fixture
def connectors(store, tenant):
    """The connector rows a connection may point at. Migration 021.

    Named on each test rather than autouse, unlike the equivalent in
    `test_connections.py`: this file's other sections assert things about an *empty*
    tenant — `test_connectors_are_invisible_across_tenants` reads `load_connectors` and
    expects `[]` — and a fixture that quietly put two rows in every tenant would make
    those pass or fail for reasons unrelated to what they are about.

    Minimal manifests. The foreign key wants a row, not a launchable server.
    """
    for connector_id in ("github-mcp", "jira"):
        store.save_connector(tenant, {"id": connector_id, "launch": {}, "vetted": []}, actor=TEST_ACTOR)


def test_a_connection_round_trips(store, tenant, connectors):
    store.save_connection(
        tenant,
        "user",
        "u_priya",
        "github-mcp",
        ciphertext=SEALED,
        key_id="4b1f9c02",
        account_label="@priya-acme",
        actor=TEST_ACTOR,
    )

    row = store.find_connection(tenant, "user", "u_priya", "github-mcp")

    assert row["ciphertext"] == SEALED
    assert isinstance(row["ciphertext"], bytes)
    assert row["key_id"] == "4b1f9c02"
    assert row["account_label"] == "@priya-acme"
    assert row["expires_at"] is None
    assert row["created_at"] is not None and row["updated_at"] is not None


def test_an_absent_connection_is_none_not_an_error(store, tenant):
    """No row and an unreadable row are different answers. This is the no-row half."""
    assert store.find_connection(tenant, "user", "u_nobody", "github-mcp") is None
    assert store.has_connection(tenant, "user", "u_nobody", "github-mcp") is False


def test_each_principal_has_their_own_connection(store, tenant, connectors):
    """The whole point of the table: two people, one connector, two credentials."""
    store.save_connection(
        tenant, "user", "u_priya", "github-mcp", ciphertext=b"priya", key_id="k1",
        actor=TEST_ACTOR,
    )
    store.save_connection(
        tenant, "user", "u_sam", "github-mcp", ciphertext=b"sam", key_id="k1",
        actor=TEST_ACTOR,
    )

    priya = store.find_connection(tenant, "user", "u_priya", "github-mcp")
    sam = store.find_connection(tenant, "user", "u_sam", "github-mcp")

    assert priya["ciphertext"] == b"priya"
    assert sam["ciphertext"] == b"sam"


def test_one_principal_has_a_connection_per_connector(store, tenant, connectors):
    store.save_connection(
        tenant, "user", "u_priya", "github-mcp", ciphertext=b"gh", key_id="k1",
        actor=TEST_ACTOR,
    )
    store.save_connection(
        tenant, "user", "u_priya", "jira", ciphertext=b"jira", key_id="k1",
        actor=TEST_ACTOR,
    )

    row = store.find_connection(tenant, "user", "u_priya", "jira")
    assert row["ciphertext"] == b"jira"


def test_a_connection_is_scoped_to_its_tenant(store, tenant, other, connectors):
    """The same principal id in two tenants must not reach one credential.

    Application-enforced, like every other tenant boundary here, and asserted for the
    same reason: a missed WHERE is the leak this suite exists to catch.
    """
    store.save_connection(
        tenant, "user", "u_shared", "github-mcp", ciphertext=b"ours", key_id="k1",
        actor=TEST_ACTOR,
    )

    assert store.find_connection(other, "user", "u_shared", "github-mcp") is None
    assert store.list_connections(other) == []


def test_reconnecting_replaces_the_credential_in_place(store, tenant, connectors):
    """Rotating a token must not require disconnecting first, which would leave a
    window in which the person has no credential at all."""
    store.save_connection(
        tenant, "user", "u_priya", "github-mcp", ciphertext=b"old", key_id="k1",
        actor=TEST_ACTOR,
    )
    first = store.find_connection(tenant, "user", "u_priya", "github-mcp")

    store.save_connection(
        tenant,
        "user",
        "u_priya",
        "github-mcp",
        ciphertext=b"new",
        key_id="k2",
        account_label="@priya-acme",
        actor=TEST_ACTOR,
    )
    second = store.find_connection(tenant, "user", "u_priya", "github-mcp")

    assert second["ciphertext"] == b"new"
    assert second["key_id"] == "k2"
    assert second["account_label"] == "@priya-acme"
    assert len(store.list_connections(tenant)) == 1
    # created_at survives, updated_at moves. Two different questions.
    assert second["created_at"] == first["created_at"]
    assert second["updated_at"] >= first["updated_at"]


def test_an_expiry_round_trips_as_an_aware_instant(store, tenant, connectors):
    expires = datetime.now(timezone.utc) + timedelta(days=30)
    store.save_connection(
        tenant,
        "user",
        "u_priya",
        "github-mcp",
        ciphertext=SEALED,
        key_id="k1",
        expires_at=expires,
        actor=TEST_ACTOR,
    )

    row = store.find_connection(tenant, "user", "u_priya", "github-mcp")
    assert row["expires_at"].tzinfo is not None
    assert abs((row["expires_at"] - expires).total_seconds()) < 1


def test_a_naive_expiry_is_refused(store, tenant):
    """Postgres would attach the server's zone, so one row would mean a different
    instant in every deployment that read it."""
    with pytest.raises(StorageError, match="timezone-aware"):
        store.save_connection(
            tenant,
            "user",
            "u_priya",
            "github-mcp",
            ciphertext=SEALED,
            key_id="k1",
            expires_at=datetime(2027, 1, 1),
            actor=TEST_ACTOR,
        )


def test_ciphertext_must_be_bytes(store, tenant):
    """A string would be encoded by psycopg and kept as text in memory, and the two
    stores would then disagree about what came back out."""
    with pytest.raises(StorageError, match="must be bytes"):
        store.save_connection(
            tenant, "user", "u_priya", "github-mcp", ciphertext="not bytes", key_id="k1",
            actor=TEST_ACTOR,
        )


def test_a_row_must_say_which_key_it_needs(store, tenant):
    with pytest.raises(StorageError, match="key_id is required"):
        store.save_connection(
            tenant, "user", "u_priya", "github-mcp", ciphertext=SEALED, key_id="",
            actor=TEST_ACTOR,
        )


def test_an_empty_ciphertext_is_refused(store, tenant):
    with pytest.raises(StorageError, match="nothing sealed"):
        store.save_connection(
            tenant, "user", "u_priya", "github-mcp", ciphertext=b"", key_id="k1",
            actor=TEST_ACTOR,
        )


def test_a_connection_needs_a_real_tenant(store):
    with pytest.raises(UnknownTenantError):
        store.save_connection(
            "t-does-not-exist",
            "user",
            "u_priya",
            "github-mcp",
            ciphertext=SEALED,
            key_id="k1",
            actor=TEST_ACTOR,
        )


def test_an_unknown_principal_kind_is_refused(store, tenant):
    with pytest.raises(StorageError, match="principal_kind"):
        store.save_connection(
            tenant, "robot", "r_1", "github-mcp", ciphertext=SEALED, key_id="k1",
            actor=TEST_ACTOR,
        )


def test_listing_connections_never_returns_ciphertext(store, tenant, connectors):
    """The administrator's view is read by people who must not be handed credentials.

    Enforced by the method rather than by remembering: `find_connection` is the only
    way to obtain sealed bytes, and it has exactly one caller.
    """
    store.save_connection(
        tenant, "user", "u_priya", "github-mcp", ciphertext=SEALED, key_id="k1",
        actor=TEST_ACTOR,
    )

    rows = store.list_connections(tenant)

    assert len(rows) == 1
    assert "ciphertext" not in rows[0]
    assert rows[0]["key_id"] == "k1"  # kept: "what still needs re-encrypting?"
    assert rows[0]["principal_id"] == "u_priya"


def test_the_connection_listing_projects_every_metadata_column(store, tenant, connectors):
    """**The projection is the contract — step 035f**, and it had no test.

    `test_listing_connections_never_returns_ciphertext` asserts one key is absent and two
    are present, which is the containment half. This is the other half: a reader is
    entitled to every metadata column, and `GET /connections` started depending on that in
    035f when `refresh_expires_at` and `updated_at` reached the wire.

    Without this, a store that stopped projecting one of them would raise a `KeyError` in
    a memory-store route test and nothing at all against Postgres — the wrong tier for a
    disagreement between two stores, which is the thing this file exists to catch. It is
    035c's `API_TOKEN_PUBLIC_FIELDS` device and 023b's `TRIGGER_FIELDS` device, one table
    over.

    Set equality in both directions on purpose. A store returning *more* than this is the
    direction that leaks: `ciphertext` is the column immediately beside these.
    """
    store.save_connection(
        tenant, "user", "u_priya", "github-mcp", ciphertext=SEALED, key_id="k1",
        actor=TEST_ACTOR,
    )

    keys = set(store.list_connections(tenant)[0])

    assert keys == {
        "tenant_id",
        "principal_kind",
        "principal_id",
        "connector_id",
        "key_id",
        "expires_at",
        "account_label",
        "created_at",
        "updated_at",
        "credential_kind",
        "refresh_expires_at",
        "reconsent_reason",
    }


def test_connections_are_listed_in_a_stable_order(store, tenant, connectors):
    """Postgres without an ORDER BY is unordered, and a caller that depended on
    insertion order would pass against the fake and fail in production."""
    for kind, pid, connector in [
        ("user", "u_sam", "jira"),
        ("user", "u_priya", "jira"),
        ("user", "u_priya", "github-mcp"),
        ("system", "cli", "github-mcp"),
    ]:
        store.save_connection(
            tenant, kind, pid, connector, ciphertext=SEALED, key_id="k1",
            actor=TEST_ACTOR,
        )

    listed = [
        (r["principal_kind"], r["principal_id"], r["connector_id"])
        for r in store.list_connections(tenant)
    ]
    assert listed == sorted(listed)


def test_listing_can_be_narrowed_to_one_principal(store, tenant, connectors):
    store.save_connection(
        tenant, "user", "u_priya", "github-mcp", ciphertext=SEALED, key_id="k1",
        actor=TEST_ACTOR,
    )
    store.save_connection(
        tenant, "user", "u_sam", "github-mcp", ciphertext=SEALED, key_id="k1",
        actor=TEST_ACTOR,
    )

    mine = store.list_connections(tenant, principal_kind="user", principal_id="u_priya")

    assert [r["principal_id"] for r in mine] == ["u_priya"]


def test_deleting_a_connection_is_idempotent(store, tenant, connectors):
    """Disconnecting an account that was never connected is not an error."""
    store.delete_connection(tenant, "user", "u_priya", "github-mcp", actor=TEST_ACTOR)

    store.save_connection(
        tenant, "user", "u_priya", "github-mcp", ciphertext=SEALED, key_id="k1",
        actor=TEST_ACTOR,
    )
    store.delete_connection(tenant, "user", "u_priya", "github-mcp", actor=TEST_ACTOR)
    store.delete_connection(tenant, "user", "u_priya", "github-mcp", actor=TEST_ACTOR)

    assert store.find_connection(tenant, "user", "u_priya", "github-mcp") is None


def test_deleting_removes_the_ciphertext_rather_than_flagging_it(store, tenant, connectors):
    """Deletion rather than a status column: a revoked row still holding live
    ciphertext is a worse artifact than no row. See migration 013."""
    store.save_connection(
        tenant, "user", "u_priya", "github-mcp", ciphertext=SEALED, key_id="k1",
        actor=TEST_ACTOR,
    )
    store.delete_connection(tenant, "user", "u_priya", "github-mcp", actor=TEST_ACTOR)

    assert store.list_connections(tenant) == []
    assert store.has_connection(tenant, "user", "u_priya", "github-mcp") is False


def test_a_returned_connection_cannot_be_edited_through(store, tenant, connectors):
    """The in-memory store deep-copies on read. Mutating what you read must not mutate
    the store — behaviour no database has, and the commonest way a fake lies."""
    store.save_connection(
        tenant, "user", "u_priya", "github-mcp", ciphertext=SEALED, key_id="k1",
        actor=TEST_ACTOR,
    )

    row = store.find_connection(tenant, "user", "u_priya", "github-mcp")
    row["key_id"] = "tampered"

    again = store.find_connection(tenant, "user", "u_priya", "github-mcp")
    assert again["key_id"] == "k1"


# Migration 021, both directions. A foreign key is not directional and neither is this
# section: the delete half is the bug the register named, and the insert half is the
# behaviour that came with it and had to be decided rather than absorbed.


def test_a_connection_must_name_a_connector_that_exists(store, tenant, connectors):
    """The insert half. Sealed against a name nothing vetted, the row could never be
    used and could never be read back to find out whose it was."""
    with pytest.raises(UnknownConnectorError, match="no connector 'github-mpc'"):
        store.save_connection(
            tenant, "user", "u_priya", "github-mpc", ciphertext=SEALED, key_id="k1",
            actor=TEST_ACTOR,
        )

    assert store.find_connection(tenant, "user", "u_priya", "github-mpc") is None


def test_a_connector_in_another_tenant_does_not_satisfy_the_key(store, tenant, other):
    """The key is `(tenant_id, connector_id)`, not `connector_id`. Two customers vet
    independently, so Acme having `github-mcp` must not let Globex connect to it."""
    store.save_connector(tenant, {"id": "github-mcp", "launch": {}, "vetted": []}, actor=TEST_ACTOR)

    with pytest.raises(UnknownConnectorError):
        store.save_connection(
            other, "user", "u_priya", "github-mcp", ciphertext=SEALED, key_id="k1",
            actor=TEST_ACTOR,
        )


def test_a_connector_with_connected_accounts_cannot_be_deleted(store, tenant, connectors):
    """The delete half, and the bug the register called live.

    RESTRICT rather than CASCADE: cascading would destroy sealed credentials as a side
    effect of an unrelated administrative action, silently, and they are exactly the
    rows nobody can reconstruct — the platform cannot read its own ciphertext.
    """
    store.save_connection(
        tenant, "user", "u_priya", "github-mcp", ciphertext=SEALED, key_id="k1",
        actor=TEST_ACTOR,
    )

    with pytest.raises(ConnectorInUseError, match="still holds connected accounts"):
        store.delete_connector(tenant, "github-mcp", actor=TEST_ACTOR)

    # The refusal leaves everything as it was, rather than half-deleting.
    assert store.get_connector(tenant, "github-mcp") is not None
    assert store.find_connection(tenant, "user", "u_priya", "github-mcp") is not None


def test_a_connector_can_be_deleted_once_its_accounts_are_disconnected(
    store, tenant, connectors
):
    """The refusal is a sequencing requirement, not a permanent one."""
    store.save_connection(
        tenant, "user", "u_priya", "github-mcp", ciphertext=SEALED, key_id="k1",
        actor=TEST_ACTOR,
    )
    store.delete_connection(tenant, "user", "u_priya", "github-mcp", actor=TEST_ACTOR)

    store.delete_connector(tenant, "github-mcp", actor=TEST_ACTOR)

    assert store.get_connector(tenant, "github-mcp") is None


def test_another_tenants_connection_does_not_block_a_delete(store, tenant, other, connectors):
    """The `RESTRICT` scan is tenant-scoped, like everything else here. Globex having
    connected to their `github-mcp` must not stop Acme retiring theirs."""
    store.save_connector(other, {"id": "github-mcp", "launch": {}, "vetted": []}, actor=TEST_ACTOR)
    store.save_connection(
        other, "user", "u_priya", "github-mcp", ciphertext=SEALED, key_id="k1",
        actor=TEST_ACTOR,
    )

    store.delete_connector(tenant, "github-mcp", actor=TEST_ACTOR)

    assert store.get_connector(tenant, "github-mcp") is None
    assert store.find_connection(other, "user", "u_priya", "github-mcp") is not None


def test_a_system_principal_may_hold_a_connection(store, tenant, connectors):
    """Nothing about the table is user-only. A scheduler acting for a customer is that
    customer's scheduler, and may have its own service credential."""
    store.save_connection(
        tenant, "system", "scheduler", "github-mcp", ciphertext=SEALED, key_id="k1",
        actor=TEST_ACTOR,
    )

    assert store.has_connection(tenant, "system", "scheduler", "github-mcp") is True
    assert store.has_connection(tenant, "user", "scheduler", "github-mcp") is False


# --- runs (migration 015) -----------------------------------------------------------
#
# A run as a row rather than as a grouping of audit records. Every assertion here is
# about the *row*: that it round-trips with every column, that a status transition is
# atomic, that an idempotency key is scoped to one customer, and that a run id names one
# run in the whole table.
#
# The race-shaped ones are asserted through the return value rather than with threads.
# `start_run` and `finish_run` express their race in the WHERE clause, so "the second
# caller gets None" is the observable form of "exactly one UPDATE matched". Threads
# would prove nothing here anyway — the in-memory store is too fast to expose a race,
# which is the lesson three sessions each learned independently.


@pytest.fixture
def rid(request):
    """Run ids unique to this test.

    Every other fixture in this file isolates a test with its own **tenant**, and that
    is not enough here: a run id is unique across the whole table rather than per
    customer — see migration 015, where the reason is that a worker claims a run by id
    alone. So a literal `"r-1"` passes against the in-memory store and collides with the
    previous test on a shared Postgres.

    Exactly the trap `users` already sets with its global `(issuer, subject)`, found the
    same way: by running it.
    """
    stem = re.sub(r"[^a-z0-9]", "", request.node.name.lower())[-28:]
    return lambda suffix="1": f"{stem}-{suffix}"


def a_run(run_id, **overrides):
    return {
        "run_id": run_id,
        "agent": "reporter",
        "principal_kind": "user",
        "principal_id": "u_priya",
        "task": "summarize the open issues",
        **overrides,
    }


def test_a_run_round_trips_with_every_field(store, tenant, rid):
    """The `credential` lesson, applied before it can happen again.

    `runs` has fixed columns in Postgres and the in-memory store keeps whatever dict it
    is handed, so a column added to one and forgotten in the other is written by one
    implementation and silently dropped by the other. Asserted against `RUN_FIELDS`
    rather than a literal list, so the two stores cannot drift from each other — and a
    column added to the table without a place in that tuple never reaches a caller.
    """
    from carnet.storage import RUN_FIELDS

    row, created = store.enqueue_run(tenant, a_run(rid()))

    assert created is True
    assert set(row) == set(RUN_FIELDS), (
        "a run row must carry exactly the fields both stores agree on. A new column "
        "needs a place in storage/base.py RUN_FIELDS."
    )
    assert row["run_id"] == rid()
    assert row["tenant_id"] == tenant
    assert row["status"] == "queued"
    assert row["task"] == "summarize the open issues"
    assert row["answer"] is None
    assert row["attempt"] == 0
    assert row["started_at"] is None
    assert row["finished_at"] is None
    assert row["created_at"] is not None
    # Migration 016. NULL and '' respectively, which is "nobody has asked" — one
    # representation of absent per column, matching `claimed_by` beside them.
    assert row["cancel_requested_at"] is None
    assert row["cancelled_by"] == ""


def test_a_run_is_read_back_by_its_exact_id(store, tenant, rid):
    store.enqueue_run(tenant, a_run(rid()))
    assert store.get_run(tenant, rid())["agent"] == "reporter"
    assert store.get_run(tenant, rid("2")) is None


def test_a_run_belonging_to_another_tenant_is_simply_absent(store, tenant, other, rid):
    """The id is unique across the whole table, so this row genuinely exists — and it
    still has to be indistinguishable from one that does not."""
    store.enqueue_run(other, a_run(rid()))

    assert store.get_run(tenant, rid()) is None
    assert store.find_run(tenant, rid()[:6]) is None
    assert store.list_runs(tenant) == []


def test_a_run_id_is_unique_across_every_tenant(store, tenant, other, rid):
    """The primary key, and it is global — see migration 015. A worker claims a run by
    id alone, so an id naming two rows would be a claim naming two customers."""
    store.enqueue_run(tenant, a_run(rid()))

    with pytest.raises(StorageError, match="already exists"):
        store.enqueue_run(other, a_run(rid()))


def test_a_run_is_found_by_unique_prefix(store, tenant, rid):
    store.enqueue_run(tenant, a_run(rid("abc123")))

    assert store.find_run(tenant, rid("abc123"))["run_id"] == rid("abc123")
    assert store.find_run(tenant, rid("abc"))["run_id"] == rid("abc123")
    assert store.find_run(tenant, rid("zzz")) is None
    assert store.find_run(tenant, "") is None


def test_an_ambiguous_prefix_finds_nothing(store, tenant, rid):
    """Nothing rather than the first match. Handing back one of two runs somebody might
    have meant is how a person reads the wrong trail and believes it."""
    store.enqueue_run(tenant, a_run(rid("abc111")))
    store.enqueue_run(tenant, a_run(rid("abc222")))

    assert store.find_run(tenant, rid("abc")) is None
    assert store.find_run(tenant, rid("abc1"))["run_id"] == rid("abc111")


def test_a_prefix_containing_a_wildcard_matches_nothing(store, tenant, rid):
    """`%` and `_` are LIKE wildcards and this takes a caller-supplied string.

    Unescaped, a lookup for `%` matches every run in the tenant — and in a tenant with
    one run that resolves to it, so the "unique prefix" convenience becomes a way to be
    handed a run you did not name.
    """
    store.enqueue_run(tenant, a_run(rid("abc111")))

    assert store.find_run(tenant, "%") is None
    # Same id with its first character replaced by `_`, which matches any single
    # character unescaped and nothing at all escaped.
    assert store.find_run(tenant, "_" + rid("abc111")[1:]) is None


def test_runs_are_listed_newest_first(store, tenant, rid):
    """The opposite order from `audit_records`, deliberately: that is a sequence and
    this is a list of recent things."""
    for suffix in ("1", "2", "3"):
        store.enqueue_run(tenant, a_run(rid(suffix)))

    assert [r["run_id"] for r in store.list_runs(tenant)] == [
        rid("3"), rid("2"), rid("1")
    ]
    assert [r["run_id"] for r in store.list_runs(tenant, limit=2)] == [
        rid("3"), rid("2")
    ]
    assert store.list_runs(tenant, limit=0) == []


def test_runs_can_be_listed_by_status(store, tenant, rid):
    store.enqueue_run(tenant, a_run(rid("1")))
    store.enqueue_run(tenant, a_run(rid("2")))
    store.start_run(tenant, rid("1"))

    assert [r["run_id"] for r in store.list_runs(tenant, status="queued")] == [rid("2")]
    assert [r["run_id"] for r in store.list_runs(tenant, status="running")] == [rid("1")]


def test_starting_a_run_stamps_it_and_counts_the_attempt(store, tenant, rid):
    store.enqueue_run(tenant, a_run(rid()))

    row = store.start_run(tenant, rid(), claimed_by="worker-a")

    assert row["status"] == "running"
    assert row["started_at"] is not None
    assert row["claimed_at"] is not None
    assert row["claimed_by"] == "worker-a"
    assert row["attempt"] == 1
    assert row["finished_at"] is None


def test_only_one_caller_can_start_a_run(store, tenant, rid):
    """None rather than an exception, because two things racing for one run is the
    ordinary shape of a queue and the loser has to carry on. This is the property
    `claim_run` will need, on the one transition that exists today."""
    store.enqueue_run(tenant, a_run(rid()))

    assert store.start_run(tenant, rid()) is not None
    assert store.start_run(tenant, rid()) is None
    assert store.get_run(tenant, rid())["attempt"] == 1, "the loser did not count"


def test_starting_a_run_that_is_not_yours_is_none(store, tenant, other, rid):
    store.enqueue_run(other, a_run(rid()))

    assert store.start_run(tenant, rid("nope")) is None
    assert store.start_run(tenant, rid()) is None, "not this tenant's to start"
    assert store.get_run(other, rid())["status"] == "queued"


def test_a_run_finishes_with_an_answer(store, tenant, rid):
    store.enqueue_run(tenant, a_run(rid()))
    store.start_run(tenant, rid())

    row = store.finish_run(tenant, rid(), "complete", answer="there are four")

    assert row["status"] == "complete"
    assert row["answer"] == "there are four"
    assert row["error"] == ""
    assert row["finished_at"] is not None


def test_a_run_finishes_with_an_error(store, tenant, rid):
    store.enqueue_run(tenant, a_run(rid()))
    store.start_run(tenant, rid())

    row = store.finish_run(tenant, rid(), "failed", error="the provider is down")

    assert row["status"] == "failed"
    assert row["answer"] is None
    assert "provider" in row["error"]


def test_a_failed_run_can_keep_both_the_answer_and_the_error(store, tenant, rid):
    """Step 024's evidence shape. A failed-validation run keeps the raw model text in
    `answer` beside the refusal sentence in `error` — money was spent producing the
    text and it is the only evidence for debugging a schema mismatch. A row shape
    neither store had been asked to hold before, asserted here so they cannot
    disagree about it."""
    store.enqueue_run(tenant, a_run(rid()))
    store.start_run(tenant, rid())

    row = store.finish_run(
        tenant, rid(), "failed", answer="prose, not JSON", error="the answer is not JSON"
    )

    assert row["status"] == "failed"
    assert row["answer"] == "prose, not JSON"
    assert row["error"] == "the answer is not JSON"


def test_an_empty_answer_is_not_a_missing_one(store, tenant, rid):
    """NULL and '' are different states and a UI renders them differently — one is a
    blank reply and the other is no reply yet."""
    store.enqueue_run(tenant, a_run(rid()))
    store.start_run(tenant, rid())

    assert store.finish_run(tenant, rid(), "complete", answer="")["answer"] == ""
    assert store.get_run(tenant, rid())["answer"] == ""


def test_the_first_outcome_recorded_is_the_one_kept(store, tenant, rid):
    """A retry after a partial failure must not overwrite what actually happened."""
    store.enqueue_run(tenant, a_run(rid()))
    store.start_run(tenant, rid())
    store.finish_run(tenant, rid(), "complete", answer="done")

    assert store.finish_run(tenant, rid(), "failed", error="no") is None
    assert store.get_run(tenant, rid())["answer"] == "done"


# --- what a run spent at the model. Step 013, migration 045 -------------------------
#
# The columns themselves, against both stores and therefore against real Postgres. What
# belongs to the layers above — the loop reading `response.usage`, the meter, the report
# — is `tests/test_usage.py`, which needs no database at all.

USAGE = {
    "model": "claude-sonnet-4-6",
    "input_tokens": 1101,
    "output_tokens": 222,
    "cache_read_tokens": 33_000,
    "cache_write_tokens": 44,
    "peak_context_tokens": 34_101,
}


def finished_with_usage(store, tenant, run_id, **overrides):
    store.enqueue_run(tenant, a_run(run_id))
    store.start_run(tenant, run_id)
    return store.finish_run(
        tenant, run_id, "complete", answer="done", usage={**USAGE, **overrides}
    )


def test_a_run_carries_no_usage_until_something_records_some(store, tenant, rid):
    """Migration 045's defaults, and they are a claim: `0` and `''` mean *nobody counted
    this*, which every run written before the columns existed genuinely is. Deliberately
    not NULL — that says the same thing while making every SUM in every report carry a
    COALESCE."""
    row, _created = store.enqueue_run(tenant, a_run(rid()))

    assert row["model"] == ""
    assert row["input_tokens"] == 0
    assert row["output_tokens"] == 0
    assert row["cache_read_tokens"] == 0
    assert row["cache_write_tokens"] == 0
    assert row["peak_context_tokens"] == 0


def test_the_four_counters_and_the_model_round_trip(store, tenant, rid):
    """The `credential` lesson on six new columns. Markers rather than round numbers, so
    two fields swapped in one store's write fails rather than coincidentally matching."""
    row = finished_with_usage(store, tenant, rid())

    for field, expected in USAGE.items():
        assert row[field] == expected, field
    # And a re-read agrees with what the write returned, which is what catches a column
    # written by the UPDATE and missing from the SELECT.
    assert store.get_run(tenant, rid())["input_tokens"] == 1101


def test_finishing_without_usage_leaves_the_counters_alone(store, tenant, rid):
    """`usage=None` is an ordinary call — the CLI's bare `finish_run`, and every caller
    written before 013. It must not zero anything or write a model."""
    store.enqueue_run(tenant, a_run(rid()))
    store.start_run(tenant, rid())

    row = store.finish_run(tenant, rid(), "complete", answer="done")

    assert row["model"] == ""
    assert row["input_tokens"] == 0


def test_usage_is_recorded_on_a_run_that_produced_no_answer(store, tenant, rid):
    """The expensive case. A run that hit the turn limit spent everything an ordinary run
    spends and has no answer to show for it — so `incomplete` is the status most worth
    counting, and the one an implementation that only writes usage on the happy path
    silently drops."""
    store.enqueue_run(tenant, a_run(rid()))
    store.start_run(tenant, rid())

    row = store.finish_run(tenant, rid(), "incomplete", error="hit the turn limit", usage=USAGE)

    assert row["status"] == "incomplete"
    assert row["input_tokens"] == 1101


def test_a_second_finish_writes_nothing_at_all(store, tenant, rid):
    """**The invariant that makes `+=` and `=` equivalent today, pinned so that changing
    it is deliberate.**

    `finish_run` keeps the first outcome, and nothing in this platform returns a run to
    `queued` — `recover_expired_runs` moves an expired run to `interrupted` and never
    back. So exactly one usage write can ever land on a row. The counters are written
    with `+=` anyway, because a retry built on `=` would lose the first attempt's spend
    silently; this asserts the reason that has not mattered yet.
    """
    finished_with_usage(store, tenant, rid())

    assert store.finish_run(tenant, rid(), "failed", usage=USAGE) is None
    assert store.get_run(tenant, rid())["input_tokens"] == 1101, (
        "a refused finish must not double the counters either"
    )


def test_a_negative_counter_is_refused_by_both_stores(store, tenant, rid):
    """Migration 045's CHECK, and the in-memory store's own version of it. A negative
    counter is an assignment where an accumulation belongs, arriving from above — the one
    implementation mistake here that would otherwise produce a plausible number."""
    store.enqueue_run(tenant, a_run(rid()))
    store.start_run(tenant, rid())

    with pytest.raises(StorageError):
        store.finish_run(tenant, rid(), "complete", usage={**USAGE, "output_tokens": -1})


def test_tokens_spent_since_sums_the_day(store, tenant, rid):
    """The token ceiling's whole read. All four counters, summed unweighted — the
    ceiling is denominated in tokens rather than money precisely so an unpriced model
    cannot be free of it."""
    finished_with_usage(store, tenant, rid("1"))

    since = datetime.now(timezone.utc) - timedelta(hours=1)

    assert store.tokens_spent_since(tenant, since) == (
        USAGE["input_tokens"] + USAGE["output_tokens"]
        + USAGE["cache_read_tokens"] + USAGE["cache_write_tokens"]
    )


def test_spend_since_groups_by_model(store, tenant, rid):
    """**Grouped rather than summed flat, and that is what makes money possible without
    money in the schema.** A cost is tokens x the rate for the model that produced them,
    so one flat SUM could only ever be priced at a blended rate."""
    finished_with_usage(store, tenant, rid("1"), model="claude-opus-5", input_tokens=100)
    finished_with_usage(store, tenant, rid("2"), model="claude-haiku-4-5", input_tokens=7)
    finished_with_usage(store, tenant, rid("3"), model="claude-opus-5", input_tokens=1)

    since = datetime.now(timezone.utc) - timedelta(hours=1)
    rows = store.spend_since(tenant, since)

    by_model = {row["model"]: row for row in rows}
    assert set(by_model) == {"claude-opus-5", "claude-haiku-4-5"}
    assert by_model["claude-opus-5"]["input_tokens"] == 101
    assert by_model["claude-haiku-4-5"]["input_tokens"] == 7
    # Richest first, so a caller rendering the top row gets the same answer from either
    # store — the ordering the two implementations have to agree on.
    assert rows[0]["model"] == "claude-opus-5"


def test_spend_since_scopes_to_one_principal(store, tenant, rid):
    """**The clause the whole per-person ceiling rests on.** A missing scope here is one
    person's allowance being consumed by another's spend — and against the fake's dict
    that failure is invisible, which is why this runs against Postgres too."""
    finished_with_usage(store, tenant, rid("1"), input_tokens=100)
    store.enqueue_run(
        tenant,
        {**a_run(rid("2")), "principal_kind": "user", "principal_id": "u_sam"},
    )
    store.start_run(tenant, rid("2"))
    store.finish_run(
        tenant, rid("2"), "complete",
        usage={**USAGE, "input_tokens": 999_999},
    )

    since = datetime.now(timezone.utc) - timedelta(hours=1)

    mine = store.spend_since(
        tenant, since, principal_kind="user", principal_id="u_priya"
    )
    theirs = store.spend_since(
        tenant, since, principal_kind="user", principal_id="u_sam"
    )

    assert sum(row["input_tokens"] for row in mine) == 100
    assert sum(row["input_tokens"] for row in theirs) == 999_999
    # Unscoped is still the tenant's whole day.
    assert sum(row["input_tokens"] for row in store.spend_since(tenant, since)) == 1_000_099


def test_spend_since_belongs_to_exactly_one_customer(store, tenant, other, rid):
    finished_with_usage(store, tenant, rid("1"), input_tokens=100)
    store.enqueue_run(other, a_run(rid("2")))
    store.start_run(other, rid("2"))
    store.finish_run(other, rid("2"), "complete", usage={**USAGE, "input_tokens": 5})

    since = datetime.now(timezone.utc) - timedelta(hours=1)

    assert sum(r["input_tokens"] for r in store.spend_since(tenant, since)) == 100
    assert sum(r["input_tokens"] for r in store.spend_since(other, since)) == 5


def test_spend_since_skips_a_run_still_in_flight(store, tenant, rid):
    store.enqueue_run(tenant, a_run(rid()))
    store.start_run(tenant, rid())

    assert store.spend_since(tenant, datetime.now(timezone.utc) - timedelta(hours=1)) == []


# --- what a door call spent -------------------------------------------------------
#
# Step 045b. `spend_since` above reads `runs`; this family reads `audit`, and the two are
# separate methods because they are separate tables — a door call writes no `runs` row,
# which is the premise's own rule. Every test here writes a **run's** audit row beside the
# door's for `door_call_records`' reason: a suite that only appended door rows would pass
# against a reader that forgot to filter at all.

_DOOR_PRINCIPAL = {"principal_kind": "machine", "principal_id": "m_nightly"}


def _spent(ts="2026-08-02T10:00:00.000+00:00", **overrides) -> dict:
    """One door call that reported usage, on `_door`'s shape."""
    return _door(**{
        "ts": ts,
        **_DOOR_PRINCIPAL,
        "model": "claude-opus-5",
        "input_tokens": 100,
        "output_tokens": 10,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
        **overrides,
    })


_BEFORE_THE_ROWS = datetime(2026, 8, 2, 0, 0, tzinfo=timezone.utc)


def _door_spend(store, tenant, since=_BEFORE_THE_ROWS):
    return store.door_spend_since(tenant, since, **_DOOR_PRINCIPAL)


def test_door_spend_groups_by_model(store, tenant):
    """Grouped rather than summed flat, for `spend_since`'s reason: a cost is tokens x the
    rate for the model that produced them, so one flat SUM could only be priced blended."""
    store.append_audit(tenant, _spent(input_tokens=100))
    store.append_audit(tenant, _spent(input_tokens=1))
    store.append_audit(tenant, _spent(model="claude-haiku-4-5", input_tokens=7))

    rows = _door_spend(store, tenant)

    by_model = {row["model"]: row for row in rows}
    assert set(by_model) == {"claude-opus-5", "claude-haiku-4-5"}
    assert by_model["claude-opus-5"]["input_tokens"] == 101
    assert by_model["claude-haiku-4-5"]["input_tokens"] == 7
    # Richest first, so a caller rendering the top row gets the same answer from either
    # store — the ordering the two implementations have to agree on.
    assert rows[0]["model"] == "claude-opus-5"


def test_door_spend_ignores_a_call_that_touched_no_model(store, tenant):
    """**The predicate that keeps the meter honest, and it is nearly every row.**

    An ordinary tool call carries NULL counters, which means *not applicable* rather than
    *spent nothing* — migration 048's whole argument. A store reading them as zeros would
    return one enormous `''` bucket contributing nothing but a spurious unpriced-model
    warning to every screen that renders this.
    """
    store.append_audit(tenant, _spent(input_tokens=100))
    store.append_audit(tenant, _door(**_DOOR_PRINCIPAL, tool="list_issues"))

    rows = _door_spend(store, tenant)

    assert [row["model"] for row in rows] == ["claude-opus-5"]
    assert sum(row["input_tokens"] for row in rows) == 100


def test_door_spend_leaves_a_runs_tokens_alone(store, tenant, rid):
    """The premise's rule, as an assertion. A run's tokens live on `runs`; a door call's
    live on `audit`. Anything that summed them would be counting two things as one."""
    finished_with_usage(store, tenant, rid("1"), input_tokens=999_999)
    store.append_audit(tenant, _spent(input_tokens=100))
    # A run's *audit* row, which never carries usage — the counters went on the run.
    store.append_audit(
        tenant, _record(run_id=rid("1"), **_DOOR_PRINCIPAL, tool="list_issues")
    )

    assert sum(row["input_tokens"] for row in _door_spend(store, tenant)) == 100


def test_door_spend_scopes_to_one_principal(store, tenant):
    """**The clause the whole ceiling rests on.** A missing scope here is one credential's
    allowance being consumed by another's spend — and against the fake's dict that failure
    is invisible, which is why this runs against Postgres too."""
    store.append_audit(tenant, _spent(input_tokens=100))
    store.append_audit(
        tenant,
        _spent(principal_id="m_other", input_tokens=999_999),
    )

    mine = _door_spend(store, tenant)
    theirs = store.door_spend_since(
        tenant, _BEFORE_THE_ROWS, principal_kind="machine", principal_id="m_other"
    )

    assert sum(row["input_tokens"] for row in mine) == 100
    assert sum(row["input_tokens"] for row in theirs) == 999_999


def test_door_spend_belongs_to_exactly_one_customer(store, tenant, other):
    store.append_audit(tenant, _spent(input_tokens=100))
    store.append_audit(other, _spent(input_tokens=5))

    assert sum(r["input_tokens"] for r in _door_spend(store, tenant)) == 100
    assert sum(r["input_tokens"] for r in _door_spend(store, other)) == 5


def test_door_spend_starts_at_the_window(store, tenant):
    """`>=` and inclusive, matching `spend_since`. The window is a UTC day and a call made
    a minute before midnight belongs to yesterday's allowance, not today's."""
    store.append_audit(tenant, _spent(ts="2026-08-01T23:59:00.000+00:00", input_tokens=7))
    store.append_audit(tenant, _spent(ts="2026-08-02T00:00:00.000+00:00", input_tokens=100))

    rows = _door_spend(store, tenant, since=_BEFORE_THE_ROWS)

    assert sum(row["input_tokens"] for row in rows) == 100


def test_door_spend_is_empty_rather_than_an_error_before_anything_is_recorded(
    store, tenant
):
    """The ordinary state of every deployment: the dial may be on and nothing reports
    usage. Empty is legible — the budget screen shows 0 beside the ceiling — where a
    raise would take the door down on a query nobody had rows for."""
    assert _door_spend(store, tenant) == []


def test_a_denied_door_call_carries_no_usage(store, tenant):
    """A refusal spends nothing, and it cannot report otherwise: the broker refuses before
    anything executes. Asserted at this layer because it is what makes a denied-then-
    retried call impossible to double-count."""
    store.append_audit(
        tenant, _door(**_DOOR_PRINCIPAL, decision="deny", reason="not granted")
    )

    assert _door_spend(store, tenant) == []


def test_the_five_usage_columns_survive_a_round_trip(store, tenant):
    """`test_every_audit_field_survives_a_round_trip`'s point aimed at 048's columns.

    The generic test builds from `audit.record`'s output, which writes None for a call
    that touched no model — so it would pass against a store that dropped the counters
    entirely. This writes real numbers, which is what a brokered model call produces.
    """
    store.append_audit(
        tenant,
        _spent(
            run_id=f"{DOOR_CALL_ID_PREFIX}beefbeefbeef",
            input_tokens=11,
            output_tokens=22,
            cache_read_tokens=33,
            cache_write_tokens=44,
        ),
    )

    (row,) = store.door_call_records(tenant)

    assert row["model"] == "claude-opus-5"
    assert (
        row["input_tokens"],
        row["output_tokens"],
        row["cache_read_tokens"],
        row["cache_write_tokens"],
    ) == (11, 22, 33, 44)


def test_an_unrecorded_counter_comes_back_as_none_and_not_zero(store, tenant):
    """**The distinction the whole design rests on**, held at the storage boundary.

    NULL is *this call touched no model*; 0 would be *it made a model call that cost
    nothing*, which does not happen. `door_spend_since` filters on `IS NOT NULL`, so a
    store that normalized the absence to 0 would enrol every ordinary tool call in a money
    query — and `response_bytes` one column over draws exactly this distinction already.
    """
    store.append_audit(tenant, _door(**_DOOR_PRINCIPAL))

    (row,) = store.door_call_records(tenant)

    assert row["input_tokens"] is None
    assert row["output_tokens"] is None
    assert row["cache_read_tokens"] is None
    assert row["cache_write_tokens"] is None
    # `model` is the exception, and deliberately: the column is NOT NULL, and `''` is what
    # "nobody recorded one" already looks like in this schema.
    assert row["model"] == ""


def test_a_negative_token_count_is_refused_by_both_stores(store, tenant):
    """Migration 048's CHECK, and the in-memory store's version of it.

    It bites harder than 045's did on `runs`: these counters arrive from a *connector's*
    response body, and a negative one would subtract from somebody's daily allowance — a
    connector able to spend a principal's ceiling downward. `core.usage.parse_report`
    refuses it one layer up; this is what makes that a property of the table.
    """
    with pytest.raises(StorageError):
        store.append_audit(tenant, _spent(input_tokens=-1))


def test_tokens_spent_since_is_zero_rather_than_none(store, tenant, rid):
    """SUM over no rows is NULL in SQL. A tenant that has run nothing today has spent
    nothing, not an unknown amount — and a caller must never have to spell those
    differently."""
    assert store.tokens_spent_since(tenant, datetime.now(timezone.utc)) == 0


def test_tokens_spent_since_ignores_runs_that_have_not_finished(store, tenant, rid):
    """A run in flight has spent nothing that has been accounted, matching
    `finished_since` everywhere else and the fact that the counters are written by
    `finish_run`."""
    store.enqueue_run(tenant, a_run(rid()))
    store.start_run(tenant, rid())

    assert store.tokens_spent_since(tenant, datetime.now(timezone.utc) - timedelta(hours=1)) == 0


def test_tokens_spent_since_is_one_tenants_only(store, tenant, other, rid):
    """**The failure the fake's dict hides and Postgres would not.** A missing
    `WHERE tenant_id` here is one customer's spending refusing another customer's runs."""
    finished_with_usage(store, tenant, rid("1"))
    store.enqueue_run(other, a_run(rid("2")))
    store.start_run(other, rid("2"))
    store.finish_run(other, rid("2"), "complete", usage={**USAGE, "input_tokens": 999_999})

    since = datetime.now(timezone.utc) - timedelta(hours=1)

    assert store.tokens_spent_since(tenant, since) == 34_367
    assert store.tokens_spent_since(other, since) == 999_999 + 222 + 33_000 + 44


def test_the_report_window_is_what_finished_inside_it(store, tenant, rid):
    """`finished_since`, which is the usage report's whole query. **`finished_at` rather
    than `created_at`**, and the difference is visible here: a run that is still going has
    spent nothing that has been accounted, so it is out of every window."""
    finished_with_usage(store, tenant, rid("1"))
    store.enqueue_run(tenant, a_run(rid("2")))
    store.start_run(tenant, rid("2"))  # running, never finished

    recent = store.list_runs(tenant, finished_since=datetime.now(timezone.utc) - timedelta(hours=1))
    ancient = store.list_runs(tenant, finished_since=datetime.now(timezone.utc) + timedelta(hours=1))

    assert [row["run_id"] for row in recent] == [rid("1")]
    assert ancient == [], "a window in the future contains nothing, not everything"


def test_a_queued_run_can_finish_without_ever_starting(store, tenant, rid):
    """Cancelling a run that never started.

    Written one chunk before it was reachable, because the `finished_at` CHECK that looks
    obviously right — a finished run has started — would have forbidden it and would have
    had to be dropped again. It is reachable now: `request_cancel` on a queued run takes
    exactly this transition, and the tests below assert it through that door.
    """
    store.enqueue_run(tenant, a_run(rid()))

    row = store.finish_run(tenant, rid(), "cancelled")

    assert row["status"] == "cancelled"
    assert row["started_at"] is None
    assert row["finished_at"] is not None


def test_finishing_needs_a_terminal_status(store, tenant, rid):
    store.enqueue_run(tenant, a_run(rid()))

    with pytest.raises(StorageError, match="not a terminal status"):
        store.finish_run(tenant, rid(), "running")


def test_an_unknown_run_status_is_refused(store, tenant, rid):
    with pytest.raises(StorageError, match="status must be one of"):
        store.enqueue_run(tenant, a_run(rid(), status="pending"))


# --- activity, and the fingerprint the wait probes (step 032) --------------------


def test_a_new_run_carries_no_activity(store, tenant, rid):
    """NULL means "nothing to say" — a run that has not started has no phase."""
    row, _ = store.enqueue_run(tenant, a_run(rid()))
    assert row["activity"] is None


def test_activity_is_noted_on_a_running_run(store, tenant, rid):
    from carnet.storage import normalize_activity

    store.enqueue_run(tenant, a_run(rid()))
    store.start_run(tenant, rid())

    marker = normalize_activity(3, "model", datetime.now(timezone.utc))
    store.note_activity(tenant, rid(), marker)

    row = store.get_run(tenant, rid())
    assert row["activity"] == marker
    assert row["activity"]["v"] == 1
    assert row["activity"]["doing"] == "model"
    assert isinstance(row["activity"]["since"], str)


def test_activity_on_a_run_that_is_not_running_changes_nothing(store, tenant, rid):
    """The guard is in the statement: a note racing a finish must not resurrect a
    terminal row's marker, and a queued run has no phase to report. Silent in both
    cases, because the writer is a best-effort progress note with no remedy to name."""
    from carnet.storage import normalize_activity

    marker = normalize_activity(1, "model", datetime.now(timezone.utc))

    store.enqueue_run(tenant, a_run(rid()))
    store.note_activity(tenant, rid(), marker)
    assert store.get_run(tenant, rid())["activity"] is None

    store.start_run(tenant, rid())
    store.finish_run(tenant, rid(), "complete", answer="done")
    store.note_activity(tenant, rid(), marker)
    assert store.get_run(tenant, rid())["activity"] is None


def test_activity_is_tenant_scoped(store, tenant, other, rid):
    """Another customer's run id must be as unwritable as it is invisible."""
    from carnet.storage import normalize_activity

    store.enqueue_run(other, a_run(rid()))
    store.start_run(other, rid())

    store.note_activity(
        tenant, rid(), normalize_activity(1, "model", datetime.now(timezone.utc))
    )
    assert store.get_run(other, rid())["activity"] is None


def test_finishing_clears_activity(store, tenant, rid):
    """A terminal run has nothing it is doing. A stale "waiting on the model" beside a
    `complete` badge would be the two-sources disagreement the row exists to prevent."""
    from carnet.storage import normalize_activity

    store.enqueue_run(tenant, a_run(rid()))
    store.start_run(tenant, rid())
    store.note_activity(
        tenant, rid(), normalize_activity(2, "tools", datetime.now(timezone.utc))
    )

    store.finish_run(tenant, rid(), "complete", answer="done")

    assert store.get_run(tenant, rid())["activity"] is None


def test_recovery_clears_activity(store, tenant, rid):
    """The other path to a terminal status. An `interrupted` run claiming to be
    "waiting on the model" would be the recovery sweep contradicted by its own row."""
    from carnet.storage import normalize_activity

    store.enqueue_run(tenant, a_run(rid()))
    store.claim_run("w1", lease_seconds=-1, limit_to_tenant=tenant)
    store.note_activity(
        tenant, rid(), normalize_activity(1, "model", datetime.now(timezone.utc))
    )

    store.recover_expired_runs(deadline_seconds=3600)

    assert store.get_run(tenant, rid())["activity"] is None


def test_activity_must_be_a_marker_both_stores_agree_on(store, tenant, rid):
    """`normalize_activity` is the one shape — a phase outside the vocabulary or a
    0-based turn is refused before either store can write it."""
    from carnet.storage import normalize_activity

    with pytest.raises(StorageError, match="doing must be one of"):
        normalize_activity(1, "thinking", datetime.now(timezone.utc))
    with pytest.raises(StorageError, match="1-based"):
        normalize_activity(0, "model", datetime.now(timezone.utc))


def test_the_fingerprint_moves_on_every_leg_and_holds_still_otherwise(
    store, tenant, rid
):
    """The wait's whole contract. `GET /runs/{id}?wait=…` holds while the fingerprint
    matches the caller's cursor, so it must move exactly when the page would render
    differently — status, cancellation, activity, a new audit record — and hold still
    when nothing has happened, or the wait returns for nothing forever."""
    from carnet.storage import normalize_activity

    store.enqueue_run(tenant, a_run(rid()))
    seen = [store.run_fingerprint(tenant, rid())]
    assert store.run_fingerprint(tenant, rid()) == seen[0], (
        "two probes over an unchanged run must agree, or every wait returns instantly"
    )

    store.start_run(tenant, rid())
    seen.append(store.run_fingerprint(tenant, rid()))

    store.note_activity(
        tenant, rid(), normalize_activity(1, "model", datetime.now(timezone.utc))
    )
    seen.append(store.run_fingerprint(tenant, rid()))

    store.append_audit(tenant, _record(run_id=rid()))
    seen.append(store.run_fingerprint(tenant, rid()))

    store.request_cancel(tenant, rid(), cancelled_by="user:u_priya")
    seen.append(store.run_fingerprint(tenant, rid()))

    store.finish_run(tenant, rid(), "cancelled", error="stopped")
    seen.append(store.run_fingerprint(tenant, rid()))

    assert len(set(seen)) == len(seen), (
        "every transition must move the fingerprint — a leg two states share is a "
        "change the wait sleeps through"
    )


def test_the_fingerprint_of_an_absent_run_is_none(store, tenant, other, rid):
    """None, not a value — and another customer's run is the same None, so a held wait
    can never be used to observe a run the caller cannot read."""
    assert store.run_fingerprint(tenant, rid()) is None

    store.enqueue_run(other, a_run(rid()))
    assert store.run_fingerprint(tenant, rid()) is None


def test_the_fingerprint_agrees_with_its_composer(store, tenant, rid):
    """The route composes the cursor it hands back from the row and the records it just
    rendered, with the same function the stores use for the probe. If the two
    compositions drift, every wait returns immediately forever — busy-polling wearing
    a streaming hat — so the agreement is pinned here, in both stores."""
    from carnet.storage import compose_run_fingerprint, normalize_activity

    store.enqueue_run(tenant, a_run(rid()))
    store.start_run(tenant, rid())
    store.note_activity(
        tenant, rid(), normalize_activity(1, "tools", datetime.now(timezone.utc))
    )
    store.append_audit(tenant, _record(run_id=rid()))

    row = store.get_run(tenant, rid())
    records = store.audit_records(tenant, run_id=rid())

    assert store.run_fingerprint(tenant, rid()) == compose_run_fingerprint(
        row["status"], row["cancel_requested_at"], row["activity"], len(records)
    )


def test_a_run_needs_a_real_tenant(store, rid):
    with pytest.raises(UnknownTenantError):
        store.enqueue_run("t-nope", a_run(rid()))


def test_a_run_needs_an_id_and_a_principal(store, tenant, rid):
    with pytest.raises(StorageError, match="run is missing"):
        store.enqueue_run(tenant, a_run(""))

    with pytest.raises(StorageError, match="run is missing"):
        store.enqueue_run(tenant, a_run(rid(), principal_id=""))


def test_an_empty_task_is_allowed(store, tenant, rid):
    """Refusing one is a policy decision and belongs above storage, next to the agent
    that would have to answer it."""
    assert store.enqueue_run(tenant, a_run(rid(), task=""))[0]["task"] == ""


def test_an_idempotency_key_returns_the_first_run(store, tenant, rid):
    """The whole mechanism: an enterprise client's retry must not spend the money
    twice."""
    first, created = store.enqueue_run(tenant, a_run(rid("1"), idempotency_key="k1"))
    assert created is True

    second, again = store.enqueue_run(tenant, a_run(rid("2"), idempotency_key="k1"))

    assert again is False
    assert second["run_id"] == first["run_id"] == rid("1")
    assert store.get_run(tenant, rid("2")) is None, "the retry created nothing"
    assert len(store.list_runs(tenant)) == 1


def test_the_key_returns_whatever_state_the_first_run_reached(store, tenant, rid):
    store.enqueue_run(tenant, a_run(rid("1"), idempotency_key="k1"))
    store.start_run(tenant, rid("1"))
    store.finish_run(tenant, rid("1"), "complete", answer="there are four")

    row, created = store.enqueue_run(tenant, a_run(rid("2"), idempotency_key="k1"))

    assert created is False
    assert row["status"] == "complete"
    assert row["answer"] == "there are four"


def test_idempotency_keys_are_scoped_to_a_tenant(store, tenant, other, rid):
    """Never global: keys are chosen by customers and two of them will pick '1'."""
    store.enqueue_run(tenant, a_run(rid("1"), idempotency_key="1"))
    row, created = store.enqueue_run(other, a_run(rid("2"), idempotency_key="1"))

    assert created is True
    assert row["run_id"] == rid("2")


def test_an_absent_key_never_collides_with_another_absent_key(store, tenant, rid):
    """'' means "the caller supplied none", and is not a key. The unique index is
    partial for exactly this reason — otherwise the second run of the day comes back as
    a retry of the first."""
    for suffix in ("1", "2", "3"):
        _row, created = store.enqueue_run(tenant, a_run(rid(suffix)))
        assert created is True

    assert len(store.list_runs(tenant)) == 3


def test_a_returned_run_cannot_be_edited_through(store, tenant, rid):
    """No database hands a caller a live row. An in-memory store that did would let a
    test mutate the store by reading from it."""
    store.enqueue_run(tenant, a_run(rid()))

    row = store.get_run(tenant, rid())
    row["status"] = "complete"

    assert store.get_run(tenant, rid())["status"] == "queued"


def test_a_system_principal_may_own_a_run(store, tenant, rid):
    """The CLI is `system:cli`, and its runs appear in `--runs` beside the API's."""
    row, _created = store.enqueue_run(
        tenant, a_run(rid(), principal_kind="system", principal_id="cli")
    )

    assert row["principal_kind"] == "system"
    assert store.list_runs(tenant)[0]["principal_id"] == "cli"


def test_an_unknown_principal_kind_is_refused_on_a_run(store, tenant, rid):
    with pytest.raises(StorageError):
        store.enqueue_run(tenant, a_run(rid(), principal_kind="robot"))


def test_deleting_an_agent_leaves_its_runs_alone(store, tenant, rid):
    """The opposite of every other reference to an agent in this schema, and
    deliberately. A grant on a deleted agent reactivates when the name is reused; a run
    is history. An owner who could erase their agent's trail by deleting it has an audit
    log that answers to the person it audits."""
    store.save_agent(tenant, AGENT, actor="system:cli")
    store.enqueue_run(tenant, a_run(rid(), agent=AGENT["name"]))

    store.delete_agent(tenant, AGENT["name"], actor="system:cli")

    assert store.get_run(tenant, rid())["agent"] == AGENT["name"]


def test_a_run_needs_no_agent_row_at_all(store, tenant, rid):
    """There is no foreign key, so a run can name an agent deleted a second ago — or one
    that was already gone before this table existed."""
    row, created = store.enqueue_run(tenant, a_run(rid(), agent="deleted-last-march"))

    assert created is True
    assert row["agent"] == "deleted-last-march"


# --- the queue (step 008b) ----------------------------------------------------------
#
# `runs` is the queue as well as the record. These are the three methods a worker needs,
# and the properties that make a claim safe to lose: exactly one worker gets a run, a
# lease can only be renewed by whoever holds it, and an abandoned run becomes
# `interrupted` rather than being quietly re-run.
#
# `limit_to_tenant` is passed everywhere a claim is made, because these tests share one
# Postgres and a claim has no tenant filter in production — a worker in one test would
# otherwise take a run from another. That parameter exists for exactly this.


def test_a_claim_takes_the_oldest_queued_run(store, tenant, rid):
    for suffix in ("1", "2", "3"):
        store.enqueue_run(tenant, a_run(rid(suffix)))

    first = store.claim_run("w1", lease_seconds=60, limit_to_tenant=tenant)
    second = store.claim_run("w2", lease_seconds=60, limit_to_tenant=tenant)

    # Arrival order, not `seq` — they agree today and the claim is the one place that
    # changes when fairness between tenants needs a different key.
    assert [first["run_id"], second["run_id"]] == [rid("1"), rid("2")]


def test_a_claim_stamps_the_lease_and_the_worker(store, tenant, rid):
    store.enqueue_run(tenant, a_run(rid()))

    row = store.claim_run("worker-a", lease_seconds=60, limit_to_tenant=tenant)

    assert row["status"] == "running"
    assert row["claimed_by"] == "worker-a"
    assert row["claimed_at"] is not None
    assert row["lease_expires_at"] is not None
    assert row["lease_expires_at"] > row["claimed_at"]
    assert row["started_at"] is not None
    assert row["attempt"] == 1


def test_an_empty_queue_claims_nothing(store, tenant):
    assert store.claim_run("w1", lease_seconds=60, limit_to_tenant=tenant) is None


def test_a_claim_never_takes_a_run_that_is_not_queued(store, tenant, rid):
    store.enqueue_run(tenant, a_run(rid()))
    store.claim_run("w1", lease_seconds=60, limit_to_tenant=tenant)

    assert store.claim_run("w2", lease_seconds=60, limit_to_tenant=tenant) is None
    assert store.get_run(tenant, rid())["claimed_by"] == "w1"


def test_a_claim_crosses_tenants(store, tenant, other, rid):
    """**The one query in the system with no tenant filter**, asserted rather than left
    to a comment. A worker serves every customer; filtering here would mean a worker per
    tenant. What stays tenant-scoped is everything the run then does, because the
    principal on the row carries the tenant.

    Drained in a loop rather than claimed once, because a shared database holds runs
    other tests queued and never claimed — which is this property demonstrating itself
    before the assertion gets to.
    """
    store.enqueue_run(other, a_run(rid()))

    for _ in range(500):
        claimed = store.claim_run("w1", lease_seconds=60)
        assert claimed is not None, "the queue emptied without ever reaching our run"
        if claimed["run_id"] == rid():
            break

    assert claimed["tenant_id"] == other, "a worker was handed a tenant nobody told it about"


# Migration 020. The claim loop is the second of the two doors suspension closes; the
# first is authentication, and that one is asserted in `test_access.py`.


def test_a_suspended_tenants_run_is_not_claimed(store, tenant, rid):
    store.enqueue_run(tenant, a_run(rid()))
    store.set_tenant_status(tenant, "suspended")

    assert store.claim_run("w1", lease_seconds=60, limit_to_tenant=tenant) is None

    # Skipped, not failed, and the difference is the whole design: a run moved to
    # `interrupted` here would have burned an attempt and could not be released by
    # resuming. Suspension closes doors; cancellation ends work.
    row = store.get_run(tenant, rid())
    assert row["status"] == "queued"
    assert row["attempt"] == 0


def test_resuming_a_tenant_releases_its_queued_runs(store, tenant, rid):
    """The maintenance-window case, which is why suspension does not cancel."""
    store.enqueue_run(tenant, a_run(rid()))
    store.set_tenant_status(tenant, "suspended")
    assert store.claim_run("w1", lease_seconds=60, limit_to_tenant=tenant) is None

    store.set_tenant_status(tenant, "active")

    claimed = store.claim_run("w1", lease_seconds=60, limit_to_tenant=tenant)
    assert claimed is not None and claimed["run_id"] == rid()


def test_a_suspended_tenant_does_not_block_another_tenants_queue(store, tenant, other, rid):
    """Head-of-line blocking, asserted rather than assumed.

    An implementation that took the oldest queued run and *then* checked whether its
    customer was active would return nothing here — one suspended tenant holding an old
    run would stall every other customer's queue. That is a far larger outage than the
    one suspension was reaching for, and it is invisible until a tenant is suspended in
    production. The filter belongs inside the row selection, and this is what says so.

    Drained in a loop for the reason `test_a_claim_crosses_tenants` gives.
    """
    store.enqueue_run(tenant, a_run(rid("blocked")))
    store.enqueue_run(other, a_run(rid("runnable")))
    store.set_tenant_status(tenant, "suspended")

    for _ in range(500):
        claimed = store.claim_run("w1", lease_seconds=60)
        assert claimed is not None, "the queue emptied without ever reaching our run"
        if claimed["run_id"] == rid("runnable"):
            break

    assert claimed["tenant_id"] == other
    assert store.get_run(tenant, rid("blocked"))["status"] == "queued"


def test_a_heartbeat_extends_a_lease(store, tenant, rid):
    store.enqueue_run(tenant, a_run(rid()))
    claimed = store.claim_run("w1", lease_seconds=1, limit_to_tenant=tenant)

    kept = store.heartbeat_runs("w1", [rid()], lease_seconds=3600)

    # `{id: cancel_requested}`, not a list. The beat is also how a worker learns that a
    # run it is executing has been cancelled — see the cancellation section below.
    assert kept == {rid(): False}
    assert store.get_run(tenant, rid())["lease_expires_at"] > claimed["lease_expires_at"]


def test_a_worker_cannot_renew_another_workers_lease(store, tenant, rid):
    """Otherwise a worker whose lease already expired could re-take a run something else
    has declared interrupted, and two processes would be running it."""
    store.enqueue_run(tenant, a_run(rid()))
    store.claim_run("w1", lease_seconds=60, limit_to_tenant=tenant)

    assert store.heartbeat_runs("w2", [rid()], lease_seconds=3600) == {}


def test_a_heartbeat_reports_what_it_could_not_keep(store, tenant, rid):
    """The id coming back missing is how a worker learns it has lost a run it is still
    executing — which it cannot stop, and must therefore say loudly."""
    store.enqueue_run(tenant, a_run(rid("1")))
    store.enqueue_run(tenant, a_run(rid("2")))
    store.claim_run("w1", lease_seconds=60, limit_to_tenant=tenant)
    store.claim_run("w1", lease_seconds=60, limit_to_tenant=tenant)
    store.finish_run(tenant, rid("1"), "complete", answer="done")

    kept = store.heartbeat_runs("w1", [rid("1"), rid("2")], lease_seconds=60)

    assert kept == {rid("2"): False}


def test_heartbeating_nothing_is_not_an_error(store):
    assert store.heartbeat_runs("w1", [], lease_seconds=60) == {}


def test_an_expired_lease_becomes_interrupted(store, tenant, rid):
    """A worker died. The run started, nobody knows how far it got, and a person has to
    look — which is what `interrupted` is for and why it is not `failed`."""
    store.enqueue_run(tenant, a_run(rid()))
    store.claim_run("w1", lease_seconds=-1, limit_to_tenant=tenant)

    moved = store.recover_expired_runs(deadline_seconds=3600)

    # Our row, not the whole result. Recovery has no tenant filter — that is the point of
    # it — so in a shared database it also collects rows other tests abandoned.
    assert rid() in {row["run_id"] for row in moved}
    row = store.get_run(tenant, rid())
    assert row["status"] == "interrupted"
    assert row["finished_at"] is not None
    assert "stopped responding" in row["error"]


def test_an_expired_lease_is_never_requeued(store, tenant, rid):
    """The decision this whole design turns on. A run that may have half-happened must
    not happen twice: it calls tools that write to a customer's systems, and one comment
    becomes two. Resubmission is a new run with a new id, deliberately."""
    store.enqueue_run(tenant, a_run(rid()))
    store.claim_run("w1", lease_seconds=-1, limit_to_tenant=tenant)
    store.recover_expired_runs(deadline_seconds=3600)

    assert store.claim_run("w2", lease_seconds=60, limit_to_tenant=tenant) is None
    assert store.get_run(tenant, rid())["attempt"] == 1


def test_a_run_past_its_deadline_becomes_interrupted(store, tenant, rid):
    """The other half, and a different failure: the worker is alive and the run is not.

    This exists because 202 removed the only thing that ever bounded a run. `RUN_TIMEOUT`
    bounded a caller's patience, and with nobody waiting a run wedged in a model call
    hangs forever — heartbeating the whole time, so the lease never saves it.
    """
    store.enqueue_run(tenant, a_run(rid()))
    store.claim_run("w1", lease_seconds=3600, limit_to_tenant=tenant)

    # -1, not 0. A deadline of zero means "started at or before this instant", and
    # `started_at` was stamped microseconds ago — on Windows the clock advances about
    # every 15ms, so the two are frequently the *same* instant and a strict `<` is false.
    # The same clock resolution that made `created_at` unusable as a sort key in 8a.
    moved = store.recover_expired_runs(deadline_seconds=-1)

    assert rid() in {row["run_id"] for row in moved}
    row = store.get_run(tenant, rid())
    assert row["status"] == "interrupted"
    assert "stopped making progress" in row["error"], "the live-lease wording, not the dead one"


def test_recovery_leaves_healthy_runs_alone(store, tenant, rid):
    store.enqueue_run(tenant, a_run(rid("1")))
    store.enqueue_run(tenant, a_run(rid("2")))
    store.claim_run("w1", lease_seconds=3600, limit_to_tenant=tenant)

    moved = {row["run_id"] for row in store.recover_expired_runs(deadline_seconds=3600)}

    assert rid("1") not in moved and rid("2") not in moved
    assert store.get_run(tenant, rid("1"))["status"] == "running"
    assert store.get_run(tenant, rid("2"))["status"] == "queued", "queued is not abandoned"


def test_recovery_takes_each_run_once(store, tenant, rid):
    """Several workers sweep, and whichever gets there first takes the rows. The others
    must find nothing rather than reporting the same run again — an `interrupted` row
    exists to make a person look, and reporting it twice is how they stop looking."""
    store.enqueue_run(tenant, a_run(rid()))
    store.claim_run("w1", lease_seconds=-1, limit_to_tenant=tenant)

    first = [row["run_id"] for row in store.recover_expired_runs(deadline_seconds=3600)]
    second = [row["run_id"] for row in store.recover_expired_runs(deadline_seconds=3600)]

    assert first.count(rid()) == 1
    assert rid() not in second


def test_a_finished_run_is_not_recovered(store, tenant, rid):
    store.enqueue_run(tenant, a_run(rid()))
    store.claim_run("w1", lease_seconds=-1, limit_to_tenant=tenant)
    store.finish_run(tenant, rid(), "complete", answer="done")

    moved = {row["run_id"] for row in store.recover_expired_runs(deadline_seconds=-1)}

    assert rid() not in moved
    assert store.get_run(tenant, rid())["answer"] == "done"


def test_two_workers_never_claim_the_same_run(store, tenant, rid):
    """**Real threads against a real database**, and the reason this is Postgres-gated
    in spirit even though it also runs in memory: the in-memory store is too fast to
    expose a race, so passing there proves nothing. Three sessions of this project each
    learned that independently.

    What it asserts is the property `FOR UPDATE SKIP LOCKED` exists for: two workers
    asking at the same instant get two different runs, and never the same one. A
    `SELECT` followed by an `UPDATE` passes every sequential test in this file and fails
    this one.
    """
    import threading

    count = 24
    for n in range(count):
        store.enqueue_run(tenant, a_run(rid(str(n))))

    claimed: list = []
    lock = threading.Lock()
    start = threading.Event()

    def worker(name):
        start.wait()
        while True:
            row = store.claim_run(name, lease_seconds=60, limit_to_tenant=tenant)
            if row is None:
                return
            with lock:
                claimed.append((row["run_id"], name))

    threads = [threading.Thread(target=worker, args=(f"w{n}",)) for n in range(4)]
    for thread in threads:
        thread.start()
    start.set()
    for thread in threads:
        thread.join(timeout=30)

    ids = [run_id for run_id, _name in claimed]
    assert len(ids) == count, "every run was claimed"
    assert len(set(ids)) == count, f"a run was claimed twice: {sorted(ids)}"


# --- cancellation (migration 016) ----------------------------------------------------
#
# The whole subject of this section is one distinction: **when somebody asked** and
# **whether the run has actually stopped** are two facts, and the row carries both
# separately. Python cannot interrupt a thread, so a row saying `cancelled` while the
# audit log shows writes after it would be the same disagreement `interrupted` exists to
# avoid — and worse, because a person reading `cancelled` concludes nothing further
# happened and stops looking.
#
# Everything here is about the row. That a *run* then stops is `tests/test_runs.py` and
# `tests/test_worker.py`; that it stops when a **different process** asks is in
# `tests/test_concurrency.py`, Postgres-gated, because an in-memory store cannot
# demonstrate a flag crossing a process boundary.


def test_cancelling_a_queued_run_cancels_it_outright(store, tenant, rid):
    """Nothing has run and nothing is going to, so there is nothing to wait for. This is
    the one case where the request and the outcome are the same event."""
    store.enqueue_run(tenant, a_run(rid()))

    row = store.request_cancel(tenant, rid(), cancelled_by="user:u_priya")

    assert row["status"] == "cancelled"
    assert row["cancel_requested_at"] is not None
    assert row["cancelled_by"] == "user:u_priya"
    assert row["finished_at"] is not None
    assert row["started_at"] is None, "it never started"


def test_a_cancelled_queued_run_is_never_claimed(store, tenant, rid):
    """The point of cancelling before a claim: no worker ever picks it up, so no model
    call is made and nothing reaches a customer's systems."""
    store.enqueue_run(tenant, a_run(rid()))
    store.request_cancel(tenant, rid())

    assert store.claim_run("w1", lease_seconds=60, limit_to_tenant=tenant) is None


def test_cancelling_a_running_run_leaves_the_status_alone(store, tenant, rid):
    """**The assertion this whole design exists for.** The run is still executing — it is
    inside a tool call in another process and cannot be interrupted — so the row records
    that somebody asked and says nothing about it having stopped."""
    store.enqueue_run(tenant, a_run(rid()))
    store.claim_run("w1", lease_seconds=60, limit_to_tenant=tenant)

    row = store.request_cancel(tenant, rid(), cancelled_by="user:u_priya")

    assert row["status"] == "running", "the row must not claim it stopped before it did"
    assert row["cancel_requested_at"] is not None
    assert row["cancelled_by"] == "user:u_priya"
    assert row["finished_at"] is None


def test_a_cancelled_run_reaches_cancelled_through_finish_run(store, tenant, rid):
    """Through the same door as every other outcome. There is no second write path that
    could disagree with the first about how a run ended."""
    store.enqueue_run(tenant, a_run(rid()))
    store.claim_run("w1", lease_seconds=60, limit_to_tenant=tenant)
    store.request_cancel(tenant, rid(), cancelled_by="user:u_priya")

    row = store.finish_run(tenant, rid(), "cancelled", error="stopped")

    assert row["status"] == "cancelled"
    assert row["finished_at"] is not None
    assert row["cancel_requested_at"] is not None, "the request survives the outcome"
    assert row["cancelled_by"] == "user:u_priya"


def test_cancelling_twice_is_a_retry_and_keeps_the_first_asker(store, tenant, rid):
    """A repeat of one intent is fine; what must not change is who asked and when. The
    same distinction the idempotency key draws — a repeat is a repeat, a different intent
    under the same handle is not."""
    store.enqueue_run(tenant, a_run(rid()))
    store.claim_run("w1", lease_seconds=60, limit_to_tenant=tenant)
    first = store.request_cancel(tenant, rid(), cancelled_by="user:u_priya")

    again = store.request_cancel(tenant, rid(), cancelled_by="user:u_someone_else")

    assert again is not None, "asking twice is not an error"
    assert again["cancelled_by"] == "user:u_priya"
    assert again["cancel_requested_at"] == first["cancel_requested_at"]


def test_cancelling_an_already_cancelled_queued_run_is_still_a_retry(store, tenant, rid):
    """**The bug this section was missing**, found by running the command twice rather
    than by a test — every test above cancels a queued run exactly once.

    A queued run *is* `cancelled` a microsecond after the first request, and `cancelled`
    is terminal. So the ordinary retry every enterprise HTTP stack makes hit an
    already-terminal row and was refused, reporting a failure where nothing had failed.
    `cancelled` is therefore in `CANCELLABLE_RUN_STATUSES` and not in the complement of
    `TERMINAL_RUN_STATUSES`, which looks like a contradiction and is the whole fix.
    """
    store.enqueue_run(tenant, a_run(rid()))
    first = store.request_cancel(tenant, rid(), cancelled_by="user:u_priya")

    again = store.request_cancel(tenant, rid(), cancelled_by="user:u_someone_else")

    assert again is not None, "a retry of an ordinary cancel must not be an error"
    assert again["status"] == "cancelled"
    assert again["cancelled_by"] == "user:u_priya"
    assert again["cancel_requested_at"] == first["cancel_requested_at"]
    assert again["finished_at"] == first["finished_at"]


def test_a_run_finished_as_cancelled_by_something_else_is_not_re_stamped(
    store, tenant, rid
):
    """The edge the retry fix opens, closed. `finish_run(..., 'cancelled')` can land
    without a request ever having been recorded — and then `cancel_requested_at` must stay
    empty rather than being stamped with a time *after* the run ended."""
    store.enqueue_run(tenant, a_run(rid()))
    store.start_run(tenant, rid())
    store.finish_run(tenant, rid(), "cancelled")

    row = store.request_cancel(tenant, rid(), cancelled_by="user:u_priya")

    assert row is not None, "still a retry, not an error"
    assert row["cancel_requested_at"] is None, "asked-at after it ended would be a lie"
    assert row["cancelled_by"] == ""


def test_cancelling_a_finished_run_changes_nothing(store, tenant, rid):
    """None, so the layer above can answer 409 rather than a green tick on a run that has
    already written to somebody's systems."""
    store.enqueue_run(tenant, a_run(rid()))
    store.start_run(tenant, rid())
    store.finish_run(tenant, rid(), "complete", answer="done")

    assert store.request_cancel(tenant, rid()) is None

    row = store.get_run(tenant, rid())
    assert row["status"] == "complete"
    assert row["answer"] == "done"
    assert row["cancel_requested_at"] is None


def test_cancelling_an_absent_or_other_tenants_run_is_none(store, tenant, other, rid):
    """Indistinguishable from each other, which is what keeps a run id from being a way
    to learn that another customer has one."""
    store.enqueue_run(other, a_run(rid()))

    assert store.request_cancel(tenant, rid()) is None
    assert store.request_cancel(tenant, rid("nope")) is None
    assert store.get_run(other, rid())["status"] == "queued", "untouched"


def test_a_heartbeat_reports_a_cancelled_run(store, tenant, rid):
    """**How the flag crosses a process boundary**, and the reason it costs no query per
    tool call: this round trip already happens every `RUN_HEARTBEAT` seconds and already
    writes exactly these rows."""
    store.enqueue_run(tenant, a_run(rid("1")))
    store.enqueue_run(tenant, a_run(rid("2")))
    store.claim_run("w1", lease_seconds=60, limit_to_tenant=tenant)
    store.claim_run("w1", lease_seconds=60, limit_to_tenant=tenant)
    store.request_cancel(tenant, rid("1"), cancelled_by="user:u_priya")

    kept = store.heartbeat_runs("w1", [rid("1"), rid("2")], lease_seconds=60)

    assert kept == {rid("1"): True, rid("2"): False}


def test_a_cancelled_run_keeps_its_lease_renewed(store, tenant, rid):
    """It is still executing. A cancel that stopped the lease from being renewed would
    have the run declared `interrupted` by the sweep a minute later — reporting "we do not
    know how far it got" about a run that is stopping on purpose, in a place the audit
    trail names."""
    store.enqueue_run(tenant, a_run(rid()))
    claimed = store.claim_run("w1", lease_seconds=1, limit_to_tenant=tenant)
    store.request_cancel(tenant, rid())

    store.heartbeat_runs("w1", [rid()], lease_seconds=3600)

    row = store.get_run(tenant, rid())
    assert row["lease_expires_at"] > claimed["lease_expires_at"]
    assert row["status"] == "running"


# --- 7b: the consent flow's three tables ----------------------------------------------
#
# Against **both** stores, which is the point: the in-memory one is what `test_oauth.py`
# and `test_api.py` run on, so a property asserted only there is a property of the fake.
# Mutation C in step 7b's checks found exactly that hole — breaking the atomic
# `DELETE ... RETURNING` in Postgres failed nothing, because the replay test never
# reached Postgres.

_OAUTH_APP = {
    "authorize_endpoint": "https://auth.example.com/authorize",
    "token_endpoint": "https://auth.example.com/token",
    "client_id": "client-abc",
    "client_secret": b"sealed-client-secret",
    "key_id": "k1",
}

_PENDING = {
    "principal_kind": "user",
    "principal_id": "u_priya",
    "connector_id": "jira",
    "code_verifier": b"sealed-verifier",
    "key_id": "k1",
    "redirect_uri": "https://runtime.acme.com/connect/callback",
}


def _state(suffix="a"):
    """A state long enough for the CHECK. 43 characters is what `token_urlsafe(32)` gives."""
    return (suffix * 43)[:43]


def test_an_oauth_application_round_trips(store, tenant, connectors):
    store.set_connector_oauth(
        tenant, "jira", **_OAUTH_APP, scopes=("read:jira-work", "offline_access"),
        actor=TEST_ACTOR,
    )

    row = store.get_connector_oauth(tenant, "jira")

    assert row["client_id"] == "client-abc"
    assert row["client_secret"] == b"sealed-client-secret"
    assert isinstance(row["client_secret"], bytes)
    assert row["scopes"] == ["read:jira-work", "offline_access"]
    assert row["revoke_endpoint"] == ""
    assert row["configured_by"] == TEST_ACTOR


def test_scope_notes_round_trip_through_both_stores(store, tenant, connectors):
    """Migration 051, and `authorize_params`' check one column over.

    Both stores go through `normalize_scope_notes`, which is what stops them disagreeing
    about what is valid. This asserts they *answer* the same — which a shared validator
    does not guarantee once one store writes JSONB and the other keeps a dict.
    """
    store.set_connector_oauth(
        tenant,
        "jira",
        **_OAUTH_APP,
        scopes=("read:jira-work", "offline_access"),
        scope_notes={
            "read:jira-work": {
                "name": "Read issues",
                "description": "See issues you already have access to.",
                "access": "read",
            }
        },
        actor=TEST_ACTOR,
    )

    row = store.get_connector_oauth(tenant, "jira")
    assert row["scope_notes"] == {
        "read:jira-work": {
            "name": "Read issues",
            "description": "See issues you already have access to.",
            "access": "read",
        }
    }
    # A scope with no note stays absent rather than becoming an empty one — the two say
    # different things, and the consent screen renders them differently.
    assert "offline_access" not in row["scope_notes"]

    # Public projection carries it: this is the one field on the row whose entire purpose
    # is to be shown to a non-administrator.
    listed = [r for r in store.list_connector_oauth(tenant) if r["connector_id"] == "jira"]
    assert listed[0]["scope_notes"] == row["scope_notes"]


def test_scope_notes_are_replaced_rather_than_merged(store, tenant, connectors):
    """A note surviving the scope it described would be a consent screen explaining a
    permission the flow no longer asks for."""
    store.set_connector_oauth(
        tenant,
        "jira",
        **_OAUTH_APP,
        scopes=("read:jira-work", "write:jira-work"),
        scope_notes={
            "write:jira-work": {"name": "Write", "description": "d", "access": "write"}
        },
        actor=TEST_ACTOR,
    )
    store.set_connector_oauth(
        tenant, "jira", **_OAUTH_APP, scopes=("read:jira-work",), actor=TEST_ACTOR
    )
    assert store.get_connector_oauth(tenant, "jira")["scope_notes"] == {}


def test_a_scope_note_for_an_unrequested_scope_is_refused_by_both_stores(
    store, tenant, connectors
):
    """`redact_args`' rule in a different column: a policy that reads as applied and is
    not, refused where it is written rather than never."""
    with pytest.raises(ValueRefused, match="does not request"):
        store.set_connector_oauth(
            tenant,
            "jira",
            **_OAUTH_APP,
            scopes=("read:jira-work",),
            scope_notes={
                "write:jira-work": {
                    "name": "Write",
                    "description": "d",
                    "access": "write",
                }
            },
            actor=TEST_ACTOR,
        )
    assert store.get_connector_oauth(tenant, "jira") is None


def test_authorize_params_round_trip_through_both_stores(store, tenant, connectors):
    """Migration 025's JSONB column, and 035g's other half of the same check.

    `authorize_params` reached this column from one caller — `--set-oauth` — until 035g
    gave it a form. Both stores go through `normalize_authorize_params`, which is the
    device that stops them disagreeing; this asserts they *answer* the same, which the
    shared helper does not by itself guarantee once one store writes JSONB and the other
    keeps a dict.
    """
    store.set_connector_oauth(
        tenant,
        "jira",
        **_OAUTH_APP,
        authorize_params={"audience": "api.atlassian.com", "prompt": "consent"},
        actor=TEST_ACTOR,
    )

    row = store.get_connector_oauth(tenant, "jira")

    assert row["authorize_params"] == {
        "audience": "api.atlassian.com",
        "prompt": "consent",
    }
    # And the projection a listing gets carries them too — the page reads the connector
    # listing, not this row.
    (listed,) = store.list_connector_oauth(tenant)
    assert listed["authorize_params"] == {"audience": "api.atlassian.com", "prompt": "consent"}


def test_both_stores_refuse_what_a_jsonb_column_cannot_hold(store, tenant, connectors):
    """035g's third pass: a NUL byte and a lone surrogate, at the column that gets them.

    Postgres answers *"unsupported Unicode escape sequence"*, which arrives as a
    `StorageError` and a **503 — try again later** about a request no amount of later will
    accept. `check_config_is_storable` was written for exactly that on the config columns
    and had never been pointed at this one.

    **Asserted here rather than only through the route**, because a lone surrogate cannot
    cross HTTP at all — a JSON body must be valid UTF-8 — so the CLI and a direct storage
    call are the only ways to reach that half of the rule.
    """
    for params in (
        {"audience": "a\x00b"},
        {"a\x00b": "x"},
        {"audience": "a\ud800b"},
    ):
        with pytest.raises(ValueRefused):
            store.set_connector_oauth(
                tenant, "jira", **_OAUTH_APP, authorize_params=params, actor=TEST_ACTOR
            )

    assert store.get_connector_oauth(tenant, "jira") is None


def test_both_stores_refuse_a_name_given_twice(store, tenant, connectors):
    """Names are stripped before storage, so two that differ only in spacing are one — and
    the `dict` build silently kept the last, throwing away a value somebody typed. A form
    with a row per parameter is what makes that a reachable typo."""
    with pytest.raises(ValueRefused, match="given twice"):
        store.set_connector_oauth(
            tenant, "jira", **_OAUTH_APP,
            authorize_params={"audience": "first", " audience": "second"},
            actor=TEST_ACTOR,
        )


def test_both_stores_refuse_a_reserved_name_in_the_endpoint_s_query_string(
    store, tenant, connectors
):
    """The other place one of the seven can arrive. `oauth.begin` appends its parameters
    after the endpoint's own query string, so a reserved name there puts it on the sign-in
    link **twice** — and no specification says which one a provider reads.

    A non-reserved query string stays legal, because it predates the column and is why
    `?audience=x` on this endpoint works at all.
    """
    with pytest.raises(ValueRefused, match="twice"):
        store.set_connector_oauth(
            tenant, "jira",
            **{**_OAUTH_APP,
               "authorize_endpoint": "https://auth.example.com/authorize?state=fixed"},
            actor=TEST_ACTOR,
        )

    store.set_connector_oauth(
        tenant, "jira",
        **{**_OAUTH_APP,
           "authorize_endpoint": "https://auth.example.com/authorize?audience=x"},
        actor=TEST_ACTOR,
    )

    assert store.get_connector_oauth(tenant, "jira")["authorize_endpoint"].endswith(
        "?audience=x"
    )


def test_both_stores_refuse_a_reserved_authorize_param_identically(
    store, tenant, connectors
):
    """The seven names, refused below the route so no interface can forget.

    Two of the sentences are the security design rather than bookkeeping, and 035g is the
    step that puts them in front of a person: the form types the name, the platform
    refuses, and the paragraph is what explains why. A store that refused with a different
    sentence — or did not refuse — would make that paragraph a lie on one deployment.
    """
    with pytest.raises(ValueRefused) as forgeable:
        store.set_connector_oauth(
            tenant,
            "jira",
            **_OAUTH_APP,
            authorize_params={"state": "guessable"},
            actor=TEST_ACTOR,
        )

    assert "forgeable" in str(forgeable.value)

    with pytest.raises(ValueRefused) as redirected:
        store.set_connector_oauth(
            tenant,
            "jira",
            **_OAUTH_APP,
            authorize_params={"redirect_uri": "https://evil"},
            actor=TEST_ACTOR,
        )

    assert "stolen grant" in str(redirected.value)
    assert store.get_connector_oauth(tenant, "jira") is None


def test_listing_oauth_applications_never_returns_the_secret(store, tenant, connectors):
    """The `list_connections` rule, one table over: the projection is the containment."""
    store.set_connector_oauth(tenant, "jira", **_OAUTH_APP, actor=TEST_ACTOR)

    rows = store.list_connector_oauth(tenant)

    assert [r["connector_id"] for r in rows] == ["jira"]
    assert "client_secret" not in rows[0]
    assert "key_id" not in rows[0]


def test_reconfiguring_replaces_rather_than_refusing(store, tenant, connectors):
    """An upsert, unlike `create_connector` — see `set_connector_oauth` for why.

    There is no allowlist here to lose, and re-running the command is how a rotated
    client secret is installed. Refusing would make rotation a delete-then-create with a
    window in which nobody can connect.
    """
    store.set_connector_oauth(tenant, "jira", **_OAUTH_APP, actor=TEST_ACTOR)
    store.set_connector_oauth(
        tenant, "jira", **{**_OAUTH_APP, "client_secret": b"rotated"}, actor=TEST_ACTOR
    )

    assert store.get_connector_oauth(tenant, "jira")["client_secret"] == b"rotated"


def test_an_oauth_application_needs_a_connector_that_exists(store, tenant):
    with pytest.raises(NoSuchConnectorError):
        store.set_connector_oauth(tenant, "ghost", **_OAUTH_APP, actor=TEST_ACTOR)


def test_an_oauth_application_is_scoped_to_its_tenant(store, tenant, connectors):
    store.set_connector_oauth(tenant, "jira", **_OAUTH_APP, actor=TEST_ACTOR)
    store.create_tenant("t-oauth-other", "Other")

    assert store.get_connector_oauth("t-oauth-other", "jira") is None
    assert store.list_connector_oauth("t-oauth-other") == []


def test_removing_an_oauth_application_is_idempotent(store, tenant, connectors):
    store.set_connector_oauth(tenant, "jira", **_OAUTH_APP, actor=TEST_ACTOR)

    assert store.delete_connector_oauth(tenant, "jira", actor=TEST_ACTOR) is True
    assert store.delete_connector_oauth(tenant, "jira", actor=TEST_ACTOR) is False
    assert store.get_connector_oauth(tenant, "jira") is None


def test_deleting_a_connector_takes_its_oauth_application_with_it(store, tenant, connectors):
    """CASCADE, and note the asymmetry with `connections` — migration 024.

    A client app we registered is configuration; a credential somebody consented to give
    is evidence, and migration 021 makes that one RESTRICT.
    """
    store.set_connector_oauth(tenant, "jira", **_OAUTH_APP, actor=TEST_ACTOR)

    store.delete_connector(tenant, "jira", actor=TEST_ACTOR)

    assert store.get_connector_oauth(tenant, "jira") is None


# --- pending authorizations ------------------------------------------------------------


def test_a_pending_authorization_round_trips(store, tenant):
    store.create_pending_authorization(_state(), tenant, **_PENDING, return_to="/x")

    row = store.consume_pending_authorization(_state())

    assert row["tenant_id"] == tenant
    assert row["principal_id"] == "u_priya"
    assert row["code_verifier"] == b"sealed-verifier"
    assert isinstance(row["code_verifier"], bytes)
    assert row["redirect_uri"] == _PENDING["redirect_uri"]
    assert row["return_to"] == "/x"


def test_consuming_a_pending_authorization_deletes_it(store, tenant):
    """**Single-use, and it is one statement.** Decision 2.

    A read-then-delete has a window in which two callbacks carrying the same `state` both
    find it and both exchange the same authorization code. This is the assertion that a
    replayed `state` finds nothing — asserted here rather than only in `test_oauth.py`,
    because that file runs against the in-memory store and the atomic
    `DELETE ... RETURNING` is a property of the Postgres one.
    """
    store.create_pending_authorization(_state(), tenant, **_PENDING)

    assert store.consume_pending_authorization(_state()) is not None
    assert store.consume_pending_authorization(_state()) is None


def test_an_unknown_state_consumes_nothing(store, tenant):
    assert store.consume_pending_authorization(_state("z")) is None
    assert store.consume_pending_authorization("") is None


def test_a_duplicate_state_is_refused_rather_than_replacing(store, tenant):
    """A collision on 256 bits does not happen, so one means the generator is wrong —
    and replacing would hand one person's flow to another's callback."""
    store.create_pending_authorization(_state(), tenant, **_PENDING)

    with pytest.raises(StorageError):
        store.create_pending_authorization(
            _state(), tenant, **{**_PENDING, "principal_id": "u_mallory"}
        )

    assert store.consume_pending_authorization(_state())["principal_id"] == "u_priya"


def test_a_short_state_is_refused(store, tenant):
    """It is the only thing binding a callback to the person who started it."""
    with pytest.raises(StorageError, match="32"):
        store.create_pending_authorization("short", tenant, **_PENDING)


@pytest.mark.parametrize(
    "hostile", ["https://evil.example.com", "//evil.example.com", "/\\evil.example.com"]
)
def test_a_return_to_that_leaves_the_application_is_refused(store, tenant, hostile):
    """The open redirect, refused at the last point before a row exists."""
    with pytest.raises(StorageError, match="return_to"):
        store.create_pending_authorization(
            _state(), tenant, **_PENDING, return_to=hostile
        )


def test_sweeping_removes_only_abandoned_flows(store, tenant):
    store.create_pending_authorization(_state(), tenant, **_PENDING)

    assert store.sweep_pending_authorizations(older_than_seconds=3600) == 0
    assert store.consume_pending_authorization(_state()) is not None

    store.create_pending_authorization(_state("b"), tenant, **_PENDING)
    assert store.sweep_pending_authorizations(older_than_seconds=-1) == 1
    assert store.consume_pending_authorization(_state("b")) is None


# --- the connection's new columns ------------------------------------------------------


def test_an_oauth_connection_records_its_kind_and_both_expiries(store, tenant, connectors):
    later = datetime(2030, 1, 1, tzinfo=timezone.utc)
    store.save_connection(
        tenant, "user", "u_priya", "jira",
        ciphertext=SEALED, key_id="k1",
        credential_kind="oauth",
        expires_at=datetime(2029, 1, 1, tzinfo=timezone.utc),
        refresh_expires_at=later,
        actor=TEST_ACTOR,
    )

    row = store.find_connection(tenant, "user", "u_priya", "jira")

    assert row["credential_kind"] == "oauth"
    assert row["refresh_expires_at"] == later
    assert row["reconsent_reason"] == ""


def test_both_expiries_reach_the_LISTING_and_not_only_find(store, tenant, connectors):
    """**035f depends on the listing, and every existing test here reads `find`.**

    `GET /connections` is built from `list_connections`, which is a different projection
    written twice — a SQL column list in one store and a dict comprehension in the other.
    The test above proves `find_connection` carries these columns and says nothing about
    the method the route actually calls.
    """
    access = datetime(2029, 1, 1, tzinfo=timezone.utc)
    lapse = datetime(2030, 6, 30, 12, 30, 45, tzinfo=timezone.utc)
    store.save_connection(
        tenant, "user", "u_priya", "jira",
        ciphertext=SEALED, key_id="k1", credential_kind="oauth",
        expires_at=access, refresh_expires_at=lapse, actor=TEST_ACTOR,
    )

    listed = store.list_connections(tenant)[0]
    found = store.find_connection(tenant, "user", "u_priya", "jira")

    assert listed["expires_at"] == access
    assert listed["refresh_expires_at"] == lapse
    # The two projections describe one row, which is the property the route leans on.
    assert {k: v for k, v in found.items() if k != "ciphertext"} == listed


def test_an_instant_keeps_its_microseconds_through_either_store(store, tenant, connectors):
    """A `TIMESTAMPTZ` holds microseconds and a Python `datetime` holds microseconds, so
    a value that lost them in one store and kept them in the other would make two
    deployments disagree about an instant they were both told exactly."""
    exact = datetime(2031, 2, 3, 4, 5, 6, 789012, tzinfo=timezone.utc)
    store.save_connection(
        tenant, "user", "u_priya", "jira",
        ciphertext=SEALED, key_id="k1", credential_kind="oauth",
        expires_at=exact, refresh_expires_at=exact, actor=TEST_ACTOR,
    )

    row = store.list_connections(tenant)[0]

    assert row["expires_at"] == exact
    assert row["refresh_expires_at"] == exact
    assert row["expires_at"].microsecond == 789012


def test_an_instant_in_another_offset_is_the_same_instant_in_either_store(
    store, tenant, connectors
):
    """Postgres normalises a `TIMESTAMPTZ` to UTC on the way in; the fake keeps whatever
    object it was handed. Both must **compare** equal to the instant that was stored —
    which is what a reader gets — even where the two objects carry different `tzinfo`."""
    kolkata = timezone(timedelta(hours=5, minutes=30))
    written = datetime(2032, 1, 1, 5, 30, tzinfo=kolkata)
    store.save_connection(
        tenant, "user", "u_priya", "jira",
        ciphertext=SEALED, key_id="k1", credential_kind="oauth",
        refresh_expires_at=written, actor=TEST_ACTOR,
    )

    got = store.list_connections(tenant)[0]["refresh_expires_at"]

    assert got == written
    assert got == datetime(2032, 1, 1, 0, 0, tzinfo=timezone.utc)


def test_a_naive_refresh_expiry_is_refused_by_both_stores(store, tenant, connectors):
    """`expires_at` has had this check since 7a; `refresh_expires_at` goes through the
    same one and nothing asserted it did. A naive value into a `TIMESTAMPTZ` means the
    *server's* zone, so the same row would name a different instant depending on which
    machine wrote it — and the fake would keep it naive and disagree with all of them."""
    with pytest.raises(StorageError) as caught:
        store.save_connection(
            tenant, "user", "u_priya", "jira",
            ciphertext=SEALED, key_id="k1", credential_kind="oauth",
            refresh_expires_at=datetime(2030, 1, 1),  # noqa: DTZ001 - the point
            actor=TEST_ACTOR,
        )

    assert "timezone-aware" in str(caught.value)


def test_reconnecting_keeps_created_at_and_moves_updated_at_in_both_stores(
    store, tenant, connectors
):
    """Migration 013's two questions, asserted against both projections.

    *"When did this person first connect"* and *"when did this credential last change"*
    are different facts, and 035f puts the second on a screen under the word **changed**
    — a word that is only true if reconnecting really does move it and really does not
    move the other. The in-memory store carries this as a comment (*"reconnecting keeps
    the original created_at"*) and Postgres carries it as an `ON CONFLICT DO UPDATE` that
    omits the column; nothing compared the two.
    """
    store.save_connection(
        tenant, "user", "u_priya", "jira", ciphertext=SEALED, key_id="k1",
        actor=TEST_ACTOR,
    )
    first = store.list_connections(tenant)[0]

    store.save_connection(
        tenant, "user", "u_priya", "jira", ciphertext=b"a-second-credential",
        key_id="k2", actor=TEST_ACTOR,
    )
    second = store.list_connections(tenant)[0]

    assert second["created_at"] == first["created_at"]
    assert second["updated_at"] > first["updated_at"]


def test_a_reconnection_replaces_the_refresh_expiry_rather_than_merging(
    store, tenant, connectors
):
    """`save_connection` is an outright replacement and must stay one.

    The *caller* decides whether a kept refresh token keeps its lifetime — see
    `oauth.refresh_connection`, where that rule lives and is scoped to the one branch
    where the credential did not change. A store that merged here would apply an old
    grant's lifetime to a new grant, silently, everywhere, with no branch to argue about.
    """
    store.save_connection(
        tenant, "user", "u_priya", "jira",
        ciphertext=SEALED, key_id="k1", credential_kind="oauth",
        refresh_expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc), actor=TEST_ACTOR,
    )

    store.save_connection(
        tenant, "user", "u_priya", "jira",
        ciphertext=SEALED, key_id="k1", credential_kind="oauth", actor=TEST_ACTOR,
    )

    assert store.list_connections(tenant)[0]["refresh_expires_at"] is None


def test_a_credential_update_returns_both_expiries_it_wrote(store, tenant, connectors):
    """The `RETURNING` projection, which is `_CONNECTION_META_COLUMNS` in one store and a
    dict comprehension in the other. `refresh_connection` only checks it for `None`, so
    a store that returned a short row would go unnoticed until something read it."""
    store.save_connection(
        tenant, "user", "u_priya", "jira",
        ciphertext=SEALED, key_id="k1", credential_kind="oauth", actor=TEST_ACTOR,
    )
    row = store.find_connection(tenant, "user", "u_priya", "jira")
    lapse = datetime(2033, 3, 3, tzinfo=timezone.utc)

    updated = store.update_connection_credential(
        tenant, "user", "u_priya", "jira",
        ciphertext=b"renewed", key_id="k1",
        expires_at=datetime(2033, 1, 1, tzinfo=timezone.utc),
        refresh_expires_at=lapse,
        if_updated_at=row["updated_at"],
    )

    assert updated["refresh_expires_at"] == lapse
    assert updated["updated_at"] > row["updated_at"]
    assert updated["created_at"] == row["created_at"]
    assert "ciphertext" not in updated
    # And the returned row is the row, not a partial view of it.
    assert set(updated) == set(store.list_connections(tenant)[0])


def test_a_credential_update_can_clear_the_refresh_expiry(store, tenant, connectors):
    """Both stores write this column unconditionally, and that is the behaviour
    `oauth.refresh_connection` depends on for a **rotating** provider: a new refresh
    token whose lifetime nobody stated must not inherit the spent one's."""
    store.save_connection(
        tenant, "user", "u_priya", "jira",
        ciphertext=SEALED, key_id="k1", credential_kind="oauth",
        refresh_expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc), actor=TEST_ACTOR,
    )
    row = store.find_connection(tenant, "user", "u_priya", "jira")

    updated = store.update_connection_credential(
        tenant, "user", "u_priya", "jira",
        ciphertext=b"renewed", key_id="k1",
        expires_at=None, refresh_expires_at=None,
        if_updated_at=row["updated_at"],
    )

    assert updated["refresh_expires_at"] is None
    assert store.list_connections(tenant)[0]["refresh_expires_at"] is None


def test_a_connection_defaults_to_static(store, tenant, connectors):
    """Every row written before migration 024 was pasted in, and the default says so."""
    store.save_connection(
        tenant, "user", "u_priya", "jira", ciphertext=SEALED, key_id="k1",
        actor=TEST_ACTOR,
    )

    assert store.find_connection(tenant, "user", "u_priya", "jira")[
        "credential_kind"
    ] == "static"


def test_a_credential_kind_nobody_defined_is_refused(store, tenant, connectors):
    with pytest.raises(StorageError, match="credential kind"):
        store.save_connection(
            tenant, "user", "u_priya", "jira", ciphertext=SEALED, key_id="k1",
            credential_kind="magic", actor=TEST_ACTOR,
        )


def test_a_refresh_replaces_the_credential_and_advances_the_version(store, tenant, connectors):
    store.save_connection(
        tenant, "user", "u_priya", "jira", ciphertext=b"first", key_id="k1",
        credential_kind="oauth", actor=TEST_ACTOR,
    )
    before = store.find_connection(tenant, "user", "u_priya", "jira")

    after = store.update_connection_credential(
        tenant, "user", "u_priya", "jira",
        ciphertext=b"second", key_id="k2",
        expires_at=None, refresh_expires_at=None,
        if_updated_at=before["updated_at"],
    )

    assert after is not None
    assert after["updated_at"] > before["updated_at"]
    assert "ciphertext" not in after, "a metadata row must not carry the sealed bytes"
    assert store.find_connection(tenant, "user", "u_priya", "jira")["ciphertext"] == b"second"


def test_a_refresh_from_the_wrong_version_lands_nothing(store, tenant, connectors):
    """The compare-and-set's semantics, identical in both stores.

    The *window* it protects is only observable against Postgres — see
    `test_concurrency.py` — but a caller written against one store has to behave the same
    against the other, and that is what this asserts.
    """
    store.save_connection(
        tenant, "user", "u_priya", "jira", ciphertext=b"first", key_id="k1",
        credential_kind="oauth", actor=TEST_ACTOR,
    )
    stale = datetime(2020, 1, 1, tzinfo=timezone.utc)

    assert store.update_connection_credential(
        tenant, "user", "u_priya", "jira",
        ciphertext=b"second", key_id="k1",
        expires_at=None, refresh_expires_at=None, if_updated_at=stale,
    ) is None
    assert store.find_connection(tenant, "user", "u_priya", "jira")["ciphertext"] == b"first"


def test_a_refresh_keeps_the_account_label_it_was_not_given(store, tenant, connectors):
    """A refresh response rarely repeats the account's identity. None means leave it."""
    store.save_connection(
        tenant, "user", "u_priya", "jira", ciphertext=b"first", key_id="k1",
        credential_kind="oauth", account_label="priya@acme.com", actor=TEST_ACTOR,
    )
    row = store.find_connection(tenant, "user", "u_priya", "jira")

    store.update_connection_credential(
        tenant, "user", "u_priya", "jira",
        ciphertext=b"second", key_id="k1",
        expires_at=None, refresh_expires_at=None, if_updated_at=row["updated_at"],
    )

    assert store.find_connection(tenant, "user", "u_priya", "jira")[
        "account_label"
    ] == "priya@acme.com"


def test_marking_re_consent_keeps_the_row(store, tenant, connectors):
    """Deleting it is what would send `for_connector` to the shared credential."""
    store.save_connection(
        tenant, "user", "u_priya", "jira", ciphertext=SEALED, key_id="k1",
        credential_kind="oauth", actor=TEST_ACTOR,
    )

    assert store.mark_connection_reconsent(
        tenant, "user", "u_priya", "jira", reason="Consent was withdrawn."
    ) is True

    row = store.find_connection(tenant, "user", "u_priya", "jira")
    assert row["reconsent_reason"] == "Consent was withdrawn."
    assert row["ciphertext"] == SEALED


def test_reconnecting_clears_the_re_consent_mark(store, tenant, connectors):
    """Reconnecting is the fix, so it has to actually clear the refusal."""
    store.save_connection(
        tenant, "user", "u_priya", "jira", ciphertext=SEALED, key_id="k1",
        credential_kind="oauth", actor=TEST_ACTOR,
    )
    store.mark_connection_reconsent(tenant, "user", "u_priya", "jira", reason="gone")

    store.save_connection(
        tenant, "user", "u_priya", "jira", ciphertext=b"fresh", key_id="k1",
        credential_kind="oauth", actor=TEST_ACTOR,
    )

    assert store.find_connection(tenant, "user", "u_priya", "jira")["reconsent_reason"] == ""


def test_a_refresh_clears_the_re_consent_mark_too(store, tenant, connectors):
    store.save_connection(
        tenant, "user", "u_priya", "jira", ciphertext=SEALED, key_id="k1",
        credential_kind="oauth", actor=TEST_ACTOR,
    )
    store.mark_connection_reconsent(tenant, "user", "u_priya", "jira", reason="gone")
    row = store.find_connection(tenant, "user", "u_priya", "jira")

    store.update_connection_credential(
        tenant, "user", "u_priya", "jira",
        ciphertext=b"fresh", key_id="k1",
        expires_at=None, refresh_expires_at=None, if_updated_at=row["updated_at"],
    )

    assert store.find_connection(tenant, "user", "u_priya", "jira")["reconsent_reason"] == ""


def test_marking_an_absent_connection_says_so(store, tenant):
    assert store.mark_connection_reconsent(
        tenant, "user", "u_nobody", "jira", reason="x"
    ) is False


def test_the_refresh_lock_is_tried_rather_than_waited_on(store, tenant, connectors):
    """The contract both stores have to keep, and it is a **bug fix** rather than taste.

    The Postgres version took the blocking `pg_advisory_xact_lock` first, and a waiter
    holds its pooled connection for the whole wait — the length of somebody else's token
    endpoint round trip. Eight concurrent refreshes held eight of a ten-connection pool,
    and that pool is shared with every other request the server is serving.

    So the contract is *"tell me immediately whether I hold it"*. A fake that blocked
    would let a caller written against it stall against the real store, which is exactly
    the drift this suite exists to catch.
    """
    key = (tenant, "user", "u_priya", "jira")

    with store.refresh_lock(*key) as outer:
        assert outer is True
        with store.refresh_lock(*key) as inner:
            assert inner is False, "the second holder must be told, not made to wait"

    # And it is released, so the next run is not locked out by the last one.
    with store.refresh_lock(*key) as again:
        assert again is True


def test_a_connection_record_carries_only_the_keys_it_is_allowed(store, tenant, connectors):
    """`CONNECTION_DETAIL_KEYS`, made load-bearing rather than decorative.

    The set was written as documentation for what a connection record may say, and a
    frozenset nothing reads is a rule that stops being true the first time somebody adds
    a helpful field. `test_no_secret_reaches_the_administrative_log` catches the *values*
    that must never appear — every secret in the flow is a marker string — and this
    catches the shape, which is the half that goes wrong quietly: a new key holding
    something nobody classified as a secret, that turns out to be one.
    """
    store.save_connection(
        tenant, "user", "u_priya", "jira",
        ciphertext=SEALED, key_id="k1", credential_kind="oauth",
        account_label="priya@acme.com", actor="user:u_priya",
    )
    store.delete_connection(
        tenant, "user", "u_priya", "jira",
        actor="user:u_priya", detail={"kind": "oauth", "revoked_upstream": True},
    )

    records = [
        r for r in store.admin_audit_records(tenant)
        if r["action"] in ("connection.create", "connection.delete")
    ]

    assert len(records) == 2
    for record in records:
        extra = set(record["detail"]) - CONNECTION_DETAIL_KEYS
        assert not extra, (
            f"{record['action']} carries {sorted(extra)}, which nobody classified. "
            "Add it to CONNECTION_DETAIL_KEYS deliberately, having decided it is not a "
            "secret — or stop putting it in the record."
        )


# --- the first administrator, against a real database (12c) ---------------------------


def test_the_bootstrap_appointment_works_against_both_stores(
    store, tenant, other, okta, monkeypatch
):
    """Verification 4's "both stores", and it is not a formality.

    `test_access.py` covers what the bootstrap *decides* — the match, the window, the
    tenant boundary — and covers it against the in-memory store only, like everything in
    that file. What can only differ between the two stores is the pair of queries the
    decision rests on: **the empty-table check and the grant**, one of which runs on every
    authenticated request while the variable is set.

    So this drives `users.resolve` — the real entry point, not `_bootstrap_admin` — with
    the active store repointed at the parametrised one. Under `[postgres]` the emptiness
    check is a real `SELECT ... WHERE tenant_id = %s` and the appointment is a real
    `INSERT` against migration 026's CHECKs and its foreign key, none of which the fake
    can refuse on anybody's behalf.

    **What this does not add is the tenant boundary**, and saying so is the point of
    stating what a test covers: `test_a_second_tenant_is_untouched_unless_its_own_table_is_empty`
    already fails if the emptiness check loses its filter, in memory, because that test
    gives the two tenants different states. Checked by mutation rather than assumed. The
    second tenant is here so the *SQL* is exercised with more than one customer's rows in
    the table, which is a different thing from being the only test that could catch it.

    The claims are handed in directly rather than signed into a JWT: `providers.resolve`
    is what turns a token into this pair and it has its own tests. What is under test here
    is everything after that point.
    """
    import carnet.storage as storage_module
    from carnet.access import users

    storage_module.configure(store)
    monkeypatch.setattr(config, "BOOTSTRAP_ADMIN_EMAIL", "priya@acme.com")

    # A second customer, already administered, so an unfiltered emptiness check reads
    # "somebody is an admin" and appoints nobody.
    store.grant_platform_role(other, "user", "u_other_admin", "admin", actor="system:cli")

    store.save_tenant_idp(tenant, okta)
    (provider,) = store.find_tenant_idps(okta["issuer"])

    priya = users.resolve(provider, {"sub": "00u-priya", "email": "priya@acme.com"})

    assert [
        (row["principal_kind"], row["principal_id"]) for row in store.list_platform_roles(tenant)
    ] == [("user", priya.id)]
    # And the other customer gained nothing from a login that was never theirs.
    assert [
        row["principal_id"] for row in store.list_platform_roles(other)
    ] == ["u_other_admin"]

    # Signing in again appoints nobody a second time — the table is no longer empty, and
    # against Postgres that is the round trip rather than a dict lookup.
    users.resolve(provider, {"sub": "00u-priya", "email": "priya@acme.com"})
    assert len(store.list_platform_roles(tenant)) == 1


# --- follow-up turns (migration 027) --------------------------------------------------
#
# A run that continues a run. Two columns written once at insert (`parent_run_id`,
# `root_run_id`), one that mutates (`thread_shared`), and one partial unique index —
# `runs_one_live_child` — that is the linearity rule itself. Everything here is about
# the rows; that a follow-up then *replays* its chain is `tests/test_threads.py`.


def _complete(store, tenant, run_id, answer="an answer"):
    """Drive one enqueued run to `complete`, the only status a follow-up may continue."""
    store.start_run(tenant, run_id)
    store.finish_run(tenant, run_id, "complete", answer=answer)


def test_a_follow_up_stores_the_parent_and_derives_the_root(store, tenant, rid):
    """`root_run_id` is the **parent's root, never the parent** — the denormalisation
    that makes "fetch the whole thread" one indexed query, kept honest here so a walk
    can never be needed. Derived by the store from the parent row, so a caller cannot
    supply a second opinion about which thread a run belongs to."""
    store.enqueue_run(tenant, a_run(rid("a")))
    _complete(store, tenant, rid("a"))
    store.enqueue_run(tenant, a_run(rid("b"), parent_run_id=rid("a")))
    _complete(store, tenant, rid("b"))

    row, created = store.enqueue_run(tenant, a_run(rid("c"), parent_run_id=rid("b")))

    assert created is True
    assert row["parent_run_id"] == rid("b")
    assert row["root_run_id"] == rid("a"), "the grandparent's thread, not the parent"
    assert row["thread_shared"] is False


def test_a_run_without_a_parent_is_its_own_root(store, tenant, rid):
    row, _created = store.enqueue_run(tenant, a_run(rid()))

    assert row["parent_run_id"] is None
    assert row["root_run_id"] == rid()


def test_a_parent_with_a_live_child_refuses_a_second(store, tenant, rid):
    """The `runs_one_live_child` rule: a run has at most one child that is live or
    succeeded. The second follow-up is a 409-shaped refusal, not a 503 — the store is
    working perfectly and the request is wrong."""
    from carnet.storage.base import FollowUpConflict

    store.enqueue_run(tenant, a_run(rid("parent")))
    _complete(store, tenant, rid("parent"))
    store.enqueue_run(tenant, a_run(rid("child1"), parent_run_id=rid("parent")))

    with pytest.raises(FollowUpConflict, match="already has a continuation"):
        store.enqueue_run(tenant, a_run(rid("child2"), parent_run_id=rid("parent")))


def test_a_complete_child_still_occupies_the_slot(store, tenant, rid):
    """`complete` is in the predicate on purpose: a succeeded follow-up IS the thread's
    next turn, and the thing to continue is it — not its parent a second time, which
    would be a branch."""
    from carnet.storage.base import FollowUpConflict

    store.enqueue_run(tenant, a_run(rid("parent")))
    _complete(store, tenant, rid("parent"))
    store.enqueue_run(tenant, a_run(rid("child"), parent_run_id=rid("parent")))
    _complete(store, tenant, rid("child"))

    with pytest.raises(FollowUpConflict):
        store.enqueue_run(tenant, a_run(rid("again"), parent_run_id=rid("parent")))


def test_a_dead_child_frees_the_parents_slot(store, tenant, rid):
    """The freed-slot rule, and it is what prevents dead-end threads: a child that
    fails or is cancelled *leaves* the index, so cancelling your own follow-up never
    bricks the conversation. A mutation check the verification names: widen the index
    predicate to all statuses and this fails."""
    store.enqueue_run(tenant, a_run(rid("parent")))
    _complete(store, tenant, rid("parent"))
    store.enqueue_run(tenant, a_run(rid("dead"), parent_run_id=rid("parent")))
    # Still queued, so cancelling kills it outright — the ordinary way a person
    # abandons a follow-up they regret.
    store.request_cancel(tenant, rid("dead"))

    row, created = store.enqueue_run(
        tenant, a_run(rid("retry"), parent_run_id=rid("parent"))
    )

    assert created is True
    assert row["parent_run_id"] == rid("parent")


def test_a_cross_tenant_parent_is_invisible(store, tenant, other, rid):
    """The parent lookup is tenant-scoped, so another customer's run — which genuinely
    exists, under a globally unique id — is byte-identically the refusal an absent one
    gets. A mutation check: drop the tenant scope from the chain fetch and this fails."""
    from carnet.storage.base import ValueRefused

    store.enqueue_run(other, a_run(rid("theirs")))
    _complete(store, other, rid("theirs"))

    with pytest.raises(ValueRefused, match="nothing to .*continue|nothing to continue"):
        store.enqueue_run(tenant, a_run(rid("mine"), parent_run_id=rid("theirs")))

    with pytest.raises(ValueRefused, match="nothing to continue"):
        store.enqueue_run(tenant, a_run(rid("mine2"), parent_run_id=rid("absent")))


def test_the_thread_filters_answer_one_indexed_question_each(store, tenant, rid):
    """`root` is the thread view, `roots_only` is the Conversations list, and the
    principal pair is the "mine" filter — a clause in the store rather than a Python
    `if` above it, because a missing scope clause against real Postgres is the failure
    that matters and a dict-lookup fake would hide it."""
    store.enqueue_run(tenant, a_run(rid("a")))
    _complete(store, tenant, rid("a"))
    store.enqueue_run(tenant, a_run(rid("b"), parent_run_id=rid("a")))
    store.enqueue_run(
        tenant, a_run(rid("solo"), principal_id="u_sam")
    )

    thread = store.list_runs(tenant, root=rid("a"))
    assert [r["run_id"] for r in thread] == [rid("b"), rid("a")], "newest first"

    roots = store.list_runs(tenant, roots_only=True)
    assert [r["run_id"] for r in roots] == [rid("solo"), rid("a")], "no follow-ups"

    mine = store.list_runs(tenant, principal_kind="user", principal_id="u_priya")
    assert [r["run_id"] for r in mine] == [rid("b"), rid("a")]

    sams = store.list_runs(tenant, principal_kind="user", principal_id="u_sam")
    assert [r["run_id"] for r in sams] == [rid("solo")]


def test_thread_shared_round_trips_and_is_root_only(store, tenant, rid):
    """The flag lives on the root and nowhere else. A follow-up's id answers None —
    the same None as absent and another customer's, told apart by the caller having
    read the row first, exactly as `request_cancel` is."""
    store.enqueue_run(tenant, a_run(rid("root")))
    _complete(store, tenant, rid("root"))
    store.enqueue_run(tenant, a_run(rid("child"), parent_run_id=rid("root")))

    opened = store.set_thread_shared(tenant, rid("root"), True)
    assert opened["thread_shared"] is True
    assert store.get_run(tenant, rid("root"))["thread_shared"] is True

    closed = store.set_thread_shared(tenant, rid("root"), False)
    assert closed["thread_shared"] is False

    assert store.set_thread_shared(tenant, rid("child"), True) is None
    assert store.get_run(tenant, rid("child"))["thread_shared"] is False
    assert store.set_thread_shared(tenant, rid("absent"), True) is None


def test_thread_shared_is_scoped_to_its_tenant(store, tenant, other, rid):
    store.enqueue_run(tenant, a_run(rid()))

    assert store.set_thread_shared(other, rid(), True) is None
    assert store.get_run(tenant, rid())["thread_shared"] is False


def test_two_simultaneous_follow_ups_and_exactly_one_wins(store, tenant, rid):
    """**The race is real, and only Postgres can prove it** — the in-memory store
    serialises under one lock and is too fast to expose a window, so passing there
    proves nothing; it runs anyway because the *observable* behaviour must match.
    Against the real store this is the `runs_one_live_child` index deciding between
    two INSERTs with no advisory lock and no read-then-write window."""
    import threading

    from carnet.storage.base import FollowUpConflict

    store.enqueue_run(tenant, a_run(rid("parent")))
    _complete(store, tenant, rid("parent"))

    outcomes: list = []
    lock = threading.Lock()
    start = threading.Event()

    def follow_up(n):
        start.wait()
        try:
            store.enqueue_run(
                tenant, a_run(rid(f"child{n}"), parent_run_id=rid("parent"))
            )
            with lock:
                outcomes.append("won")
        except FollowUpConflict:
            with lock:
                outcomes.append("refused")

    threads = [threading.Thread(target=follow_up, args=(n,)) for n in range(2)]
    for thread in threads:
        thread.start()
    start.set()
    for thread in threads:
        thread.join(timeout=30)

    assert sorted(outcomes) == ["refused", "won"], outcomes


# --- tenant deletion, migration 029 --------------------------------------------------
#
# The row the register carried from 002 whose answer was *impossible* rather than *not
# yet*. These run against both stores, which is the whole point: Postgres refuses a
# tenant delete with five foreign keys, and the in-memory store had to be told about
# every one of them plus the twenty collections a cascade would have handled.


def _populate(store, tenant_id, rid_for):
    """One row in as many of a tenant's tables as a test can cheaply reach.

    Deliberately not exhaustive — `test_deleting_a_tenant_leaves_nothing_behind` walks
    `information_schema` for that, which is the assertion that survives somebody adding
    a table. This is what makes the *counts* in the tombstone non-zero.
    """
    store.save_agent(tenant_id, AGENT, actor=TEST_ACTOR)
    store.append_audit(tenant_id, _record())
    store.record_denial(tenant_id, _denial())
    store.create_group(
        tenant_id, "eng", "Engineering", created_by=TEST_ACTOR, actor=TEST_ACTOR
    )
    store.enqueue_run(tenant_id, a_run(rid_for()))
    return tenant_id


def test_a_suspended_tenant_is_deleted_with_everything_in_it(store, tenant, rid):
    """The whole arc, and the five tables that block it are the point.

    `audit` is the one every previous statement of this problem names. `runs` and
    `groups` are the two nobody had counted — they reference `tenants(id)` with no
    cascade and no trigger, so they block a delete just as hard and were found by
    reading the catalog rather than the prose.
    """
    _populate(store, tenant, rid)
    store.set_tenant_status(tenant, "suspended")

    tombstone = store.delete_tenant(tenant, actor=TEST_ACTOR)

    assert store.get_tenant(tenant) is None
    assert store.load_agents(tenant) == []
    assert store.audit_records(tenant) == []
    assert store.admin_audit_records(tenant) == []
    assert store.denial_records(tenant) == []
    assert store.list_runs(tenant) == []
    assert store.list_groups(tenant) == []

    assert tombstone["tenant_id"] == tenant
    assert tombstone["detail"]["rows"]["audit"] == 1
    assert tombstone["detail"]["rows"]["access_denials"] == 1
    assert tombstone["detail"]["rows"]["groups"] == 1
    assert tombstone["detail"]["rows"]["runs"] == 1
    # `save_agent` and `create_group` each leave one; the count is what they wrote.
    assert tombstone["detail"]["rows"]["admin_audit"] >= 2


def test_deleting_an_active_tenant_is_refused(store, tenant):
    """Suspension is the brake and deletion is the demolition.

    Not a permission check — a race one: a customer who can still authenticate can
    create rows while the delete runs, and suspension is what already closes both doors
    work arrives through.
    """
    with pytest.raises(TenantDeletionRefused, match="Suspend it first"):
        store.delete_tenant(tenant, actor=TEST_ACTOR)

    assert store.get_tenant(tenant) is not None


def test_deleting_a_tenant_with_a_run_in_flight_is_refused(store, tenant, rid):
    """Migration 020's documented gap, met head-on: suspension deliberately does not
    stop a run already executing, so without this the delete races a worker that is
    still writing audit rows for a tenant being erased underneath it."""
    run_id = rid()
    store.enqueue_run(tenant, a_run(run_id))
    store.start_run(tenant, run_id)
    store.set_tenant_status(tenant, "suspended")

    with pytest.raises(TenantDeletionRefused, match="still executing"):
        store.delete_tenant(tenant, actor=TEST_ACTOR)

    assert store.get_tenant(tenant) is not None

    # A queued run is not a live one — suspension already stopped the claim loop, so it
    # is inert and goes with the tenant.
    store.finish_run(tenant, run_id, status="complete")
    store.enqueue_run(tenant, a_run(rid("2")))
    store.delete_tenant(tenant, actor=TEST_ACTOR)
    assert store.get_tenant(tenant) is None


def test_deleting_an_unknown_tenant_is_refused(store):
    with pytest.raises(UnknownTenantError):
        store.delete_tenant("no-such-tenant", actor=TEST_ACTOR)


def test_deleting_a_tenant_twice_is_an_error_rather_than_a_no_op(store, tenant):
    """Deletion is a ceremony, not a convergence. The second call is the same
    `UnknownTenantError` every other method gives, and the tombstone is where an
    operator finds out why — which is more useful than "does not exist", a sentence
    indistinguishable from a typo."""
    store.set_tenant_status(tenant, "suspended")
    store.delete_tenant(tenant, actor=TEST_ACTOR)

    with pytest.raises(UnknownTenantError):
        store.delete_tenant(tenant, actor=TEST_ACTOR)

    assert store.get_tenant_tombstone(tenant) is not None


def test_a_deleted_tenants_id_is_never_reused(store, tenant):
    """No foreign key does this in either store — `tenant_tombstones` deliberately has
    none to `tenants`, because the row it describes is gone. So both stores check it,
    which is also what keeps the two refusals identical.

    The reason it is refused at all: every record surviving a deletion that names this
    id would otherwise be ambiguous between two customers, in tables nobody can edit to
    disambiguate.
    """
    store.set_tenant_status(tenant, "suspended")
    store.delete_tenant(tenant, actor=TEST_ACTOR)

    with pytest.raises(TenantDeleted, match="never reused"):
        store.create_tenant(tenant, "Somebody Else")

    assert store.get_tenant(tenant) is None


def test_creating_an_existing_tenant_is_still_idempotent(store, tenant):
    """The refusal above is the one place `create_tenant`'s idempotency stops, and this
    is what says it stopped only there."""
    store.create_tenant(tenant, "Test Tenant")
    assert store.get_tenant(tenant)["name"] == "Test Tenant"


def test_the_tombstone_round_trips_every_field(store, tenant):
    """`TOMBSTONE_FIELDS`, the `RUN_FIELDS` device: a column added to the table and
    forgotten in a store is a failure here rather than a silent difference."""
    from carnet.storage import TOMBSTONE_FIELDS

    store.set_tenant_status(tenant, "suspended")
    written = store.delete_tenant(tenant, actor=TEST_ACTOR)
    read = store.get_tenant_tombstone(tenant)

    assert set(read) == set(TOMBSTONE_FIELDS)
    assert read == written
    assert read["actor"] == TEST_ACTOR
    assert read["name"] == "Test Tenant"


def test_the_tombstone_names_no_person(store, tenant, rid, person):
    """The property that lets this table be kept forever without reopening the question
    the deletion was performed to answer.

    A tenant id, an organisation's name, an actor and arithmetic. No principal ids of
    the people who worked there, no addresses, no agent names — `detail` is counts, and
    this is what stops the next person putting a list of deleted users in it.
    """
    store.create_user(tenant, person)
    _populate(store, tenant, rid)
    store.set_tenant_status(tenant, "suspended")

    tombstone = store.delete_tenant(tenant, actor=TEST_ACTOR)

    rendered = json.dumps(tombstone, default=str)
    assert person["email"] not in rendered
    assert person["id"] not in rendered
    assert person["subject"] not in rendered
    assert AGENT["name"] not in rendered
    assert set(tombstone["detail"]) == {"v", "rows"}


def test_an_unusable_actor_deletes_nothing(store, tenant, rid):
    """`make_tombstone` runs before anything is touched, so the refusal arrives with the
    store intact rather than with five tables already empty. Postgres gets that from the
    transaction; the in-memory store gets it from the order, which is the property
    `_append_admin` already documents."""
    _populate(store, tenant, rid)
    store.set_tenant_status(tenant, "suspended")

    with pytest.raises(StorageError):
        store.delete_tenant(tenant, actor="nonsense-with-no-kind")

    assert store.get_tenant(tenant) is not None
    assert len(store.audit_records(tenant)) == 1
    assert store.get_tenant_tombstone(tenant) is None


def test_deleting_a_tenant_leaves_every_other_tenant_alone(store, tenant, other, rid):
    """The assertion a cross-tenant bug fails, and the one a `WHERE tenant_id` typo
    fails loudest."""
    _populate(store, tenant, rid)
    _populate(store, other, lambda suffix="9": rid("9"))

    store.set_tenant_status(tenant, "suspended")
    store.delete_tenant(tenant, actor=TEST_ACTOR)

    assert store.get_tenant(other) is not None
    assert len(store.load_agents(other)) == 1
    assert len(store.audit_records(other)) == 1
    assert len(store.denial_records(other)) == 1
    assert len(store.list_runs(other)) == 1
    assert len(store.list_groups(other)) == 1
    assert store.get_tenant_tombstone(other) is None


def test_tombstones_are_listed_most_recent_first(store, request):
    """`list_tenants`' operator view, for the customers who are gone."""
    ids = []
    for n in range(3):
        tenant_id = f"tomb{n}-{request.node.name}"[:60]
        store.create_tenant(tenant_id, f"Tenant {n}")
        store.set_tenant_status(tenant_id, "suspended")
        store.delete_tenant(tenant_id, actor=TEST_ACTOR)
        ids.append(tenant_id)

    listed = [row["tenant_id"] for row in store.list_tenant_tombstones()]
    assert set(ids) <= set(listed)
    stamps = [row["deleted_at"] for row in store.list_tenant_tombstones()]
    assert stamps == sorted(stamps, reverse=True)


def test_a_denial_for_an_unknown_tenant_is_refused(store):
    """Drift found while planning 018 rather than by a failure: `append_audit` calls
    `_require_tenant` in both stores and `record_denial` called it in neither. Postgres
    still refused via the foreign key; the in-memory store accepted the row silently,
    which is exactly the shape of fake this suite exists to catch.

    It matters more now than it did: "the tenant is gone" is a state both stores have to
    refuse identically, and a store that keeps writing denials for a deleted customer is
    a store that re-populates a table the deletion just emptied.
    """
    with pytest.raises(UnknownTenantError):
        store.record_denial("no-such-tenant", _denial())


# --- migration 029 against the real engine -------------------------------------------
#
# Guarantees the database makes and a dict cannot. The in-memory store has no triggers,
# no transaction-scoped settings and no catalog, so everything below is asserted where
# it actually lives.


def test_the_retention_setting_lets_a_delete_past_the_trigger(pg):
    """The whole of the exemption, and the reason it is not `DROP TRIGGER`.

    Dropping a trigger takes an ACCESS EXCLUSIVE lock on a table the product writes to
    on every tool call, and a crash between the drop and the recreate leaves the log
    silently mutable with nothing recording that it ever was.
    """
    store, tenant_id = pg
    store.append_audit(tenant_id, _record())

    with store._transaction() as cur:
        cur.execute("SELECT set_config('agent_runtime.retention', 'on', true)")
        cur.execute("DELETE FROM audit WHERE tenant_id = %s", (tenant_id,))

    assert store.audit_records(tenant_id) == []


def test_update_is_refused_even_with_the_retention_setting(pg):
    """The asymmetry worth not collapsing later: retention SHORTENS the record and
    nothing ever rewrites one.

    A trigger that allowed UPDATE under a setting would make "correcting" a record
    expressible, and the whole value of these tables is that they say what happened
    rather than what somebody would prefer had happened.
    """
    store, tenant_id = pg
    store.append_audit(tenant_id, _record())
    store.record_denial(tenant_id, _denial())
    store.save_agent(tenant_id, AGENT, actor=TEST_ACTOR)

    for table, column in (
        ("audit", "reason"),
        ("admin_audit", "action"),
        ("access_denials", "required"),
    ):
        with pytest.raises(StorageError, match="append-only"):
            with store._transaction() as cur:
                cur.execute("SELECT set_config('agent_runtime.retention', 'on', true)")
                cur.execute(
                    f"UPDATE {table} SET {column} = 'tampered' WHERE tenant_id = %s",
                    (tenant_id,),
                )


def test_the_retention_setting_does_not_outlive_its_transaction(pg):
    """`set_config(..., true)` is transaction-local, and that is the property that makes
    this safe: there is no window in which the protection is off for anybody else, and a
    process dying mid-block cannot leave one open."""
    store, tenant_id = pg
    store.append_audit(tenant_id, _record())

    with store._transaction() as cur:
        cur.execute("SELECT set_config('agent_runtime.retention', 'on', true)")

    store.append_audit(tenant_id, _record())
    with pytest.raises(StorageError, match="append-only"):
        store._execute("DELETE FROM audit WHERE tenant_id = %s", (tenant_id,))


def test_a_stray_delete_is_still_refused_on_every_log_table(pg):
    """The friction the three migrations asked for, preserved. A DELETE from psql fails
    exactly as it did before this migration."""
    store, tenant_id = pg
    store.append_audit(tenant_id, _record())
    store.record_denial(tenant_id, _denial())
    store.save_agent(tenant_id, AGENT, actor=TEST_ACTOR)

    for table in ("audit", "admin_audit", "access_denials"):
        with pytest.raises(StorageError, match="append-only"):
            store._execute(f"DELETE FROM {table} WHERE tenant_id = %s", (tenant_id,))


def test_the_tombstone_table_has_no_retention_exception(pg):
    """The only table in the schema whose append-only trigger has no way past it.

    Retention prunes the logs; the record that a customer was erased is precisely the
    record erasure must never be able to reach.
    """
    store, tenant_id = pg
    store.set_tenant_status(tenant_id, "suspended")
    store.delete_tenant(tenant_id, actor=TEST_ACTOR)

    for sql in (
        "UPDATE tenant_tombstones SET name = 'somebody else' WHERE tenant_id = %s",
        "DELETE FROM tenant_tombstones WHERE tenant_id = %s",
    ):
        with pytest.raises(StorageError, match="append-only"):
            store._execute(sql, (tenant_id,))

        with pytest.raises(StorageError, match="append-only"):
            with store._transaction() as cur:
                cur.execute("SELECT set_config('agent_runtime.retention', 'on', true)")
                cur.execute(sql, (tenant_id,))


# --- partitioning, step 019 ----------------------------------------------------------
#
# Postgres-only by nature: the in-memory store holds lists and has no months. What the
# two stores are held to *together* is the boundary a prune applies, which is
# `prune_floor` in the retention section above.


def _partitions_of(store, parent: str) -> list[str]:
    """Every partition of `parent`, oldest first. Read from the catalog rather than
    generated from `log_partition_months`, so a test cannot agree with the code by
    computing the same wrong answer twice."""
    return [
        row[0]
        for row in store._fetchall(
            """
            SELECT c.relname
              FROM pg_class c
              JOIN pg_inherits i ON i.inhrelid = c.oid
              JOIN pg_class p ON p.oid = i.inhparent
             WHERE p.relname = %s
             ORDER BY 1
            """,
            (parent,),
        )
    ]


def test_partition_bounds_do_not_depend_on_the_session_timezone(pg_dsn):
    """**Migration 045's whole reason, held at the function.**

    Migration 030's `upper := lower + INTERVAL '1 month'` added the month through the
    session's timezone: under America/New_York, May's UTC midnight is April 30 local,
    so "one month later" landed on May 30 local — a partition one UTC day short, and
    the missing day a **hole**, because the next month's lower bound was computed
    correctly and did not move. An audit INSERT in the hole raises, `audit.record`
    sits on the broker's path, and every tool call in the deployment fails for the
    last UTC day of the month. Invisible until step 041's verification pass ran the
    suite against a database defaulting to New York — every environment before that
    was UTC.

    Asserted by calling the real function from a session pinned to the timezone that
    broke it, on a far-future month no horizon call will ever create. The far half of
    the year matters too: Kolkata is +05:30, so a half-hour error would slip past any
    test that only checked whole hours.
    """
    import psycopg

    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        try:
            for tz, month in (("America/New_York", "2031-05-01"),
                              ("Asia/Kolkata", "2031-07-01")):
                conn.execute(f"SET TIME ZONE '{tz}'")
                conn.execute("SELECT ensure_log_partition('audit', %s::timestamptz)",
                             (f"{month}T00:00:00+00:00",))
                conn.execute("SET TIME ZONE 'UTC'")
                bound = conn.execute(
                    "SELECT pg_get_expr(relpartbound, oid) FROM pg_class "
                    " WHERE relname = %s",
                    (f"audit_p{month[:4]}_{month[5:7]}",),
                ).fetchone()[0]
                lower, upper = re.findall(r"'([^']+)'", bound)
                assert lower.startswith(f"{month} 00:00:00"), (tz, bound)
                next_month = {"05": "06", "07": "08"}[month[5:7]]
                assert upper.startswith(f"2031-{next_month}-01 00:00:00"), (tz, bound)
        finally:
            # Both empty, both far outside any horizon — dropped so this test leaves
            # the shared schema exactly as it found it. The horizon-repair test below
            # picks "the newest audit partition" to drop, and a 2031 stray would make
            # that a partition no horizon repair will ever recreate.
            for stray in ("audit_p2031_05", "audit_p2031_07"):
                conn.execute(f"DROP TABLE IF EXISTS {stray}")


def test_the_three_log_tables_are_partitioned_and_nothing_else_is(pg):
    """Migration 030 converted exactly the three append-only logs.

    `runs` is the one worth naming: it is the largest table with a `ts`-shaped column and
    it is deliberately *not* partitioned, because it is live product data with rows
    referencing each other (threads, migration 027) and no retention window at all.
    """
    store, _tenant_id = pg
    partitioned = {
        row[0]
        for row in store._fetchall(
            "SELECT relname FROM pg_class WHERE relkind = 'p' AND relname NOT LIKE %s",
            ("pg\\_%",),
        )
    }
    assert partitioned == set(RETAINED_LOG_TABLES)
    assert "runs" not in partitioned


def test_every_log_partition_carries_the_append_only_triggers(pg):
    """The property the whole step had to get right, asserted against `pg_trigger`.

    Creating a row trigger on a partitioned parent clones it onto every partition — the
    existing ones and the ones created months from now. That is a mechanism rather than
    a promise, so this walks the catalog instead of trusting it: every partition of every
    log table carries both clones (`tgparentid <> 0` is what makes it a clone rather than
    a lookalike somebody created by hand).

    Without it, the failure mode is silent and total: a partition with no trigger is a
    month of audit records anybody can UPDATE or DELETE, and every test that checks the
    refusal would still pass, because they all hit whichever partition today lands in.
    """
    store, _tenant_id = pg
    for parent in RETAINED_LOG_TABLES:
        partitions = _partitions_of(store, parent)
        assert partitions, f"{parent} has no partitions at all"

        for partition in partitions:
            names = {
                row[0]
                for row in store._fetchall(
                    """
                    SELECT t.tgname
                      FROM pg_trigger t
                     WHERE t.tgrelid = %s::regclass
                       AND NOT t.tgisinternal
                       AND t.tgparentid <> 0
                    """,
                    (partition,),
                )
            }
            assert names == {f"{parent}_no_update", f"{parent}_no_delete"}, (
                f"{partition} is missing an append-only trigger: it has {names}"
            )


def _make_fresh_partition(store, days_ago: int) -> str:
    """An `audit` partition that certainly did not exist a moment ago.

    Dropped first rather than assumed absent: partitions are schema, so they are shared
    by every test in the session and whichever of these ran first would otherwise leave
    the others asserting that nothing was created. **This is the shared-database lesson
    for the fourth time** — twice for global row counts in 018, and now for the catalog.
    """
    when = _days_ago(days_ago)
    store._execute(f"DROP TABLE IF EXISTS audit_p{when:%Y_%m}")  # noqa: S608
    created = store.ensure_log_partitions(back_to=when)
    assert f"audit_p{when:%Y_%m}" in created, f"expected a fresh partition, got {created}"
    return f"audit_p{when:%Y_%m}"


def test_a_partition_created_after_the_migration_is_protected_too(pg):
    """The half a walk of today's partitions cannot reach: next year's.

    A trigger that clones onto existing partitions and not onto future ones would pass
    every other assertion in this file for months and then quietly stop protecting the
    log. So this creates a partition the migration never saw and attacks it **directly**
    — not through the parent, which would prove only that the parent's own trigger fired.
    """
    store, tenant_id = pg
    fresh = _make_fresh_partition(store, 400)
    assert fresh in _partitions_of(store, "audit")

    store.append_audit(tenant_id, _record(ts=_days_ago(400)))

    for sql in (
        f"DELETE FROM {fresh}",  # noqa: S608 - a partition name from the catalog
        f"UPDATE {fresh} SET reason = 'rewritten'",  # noqa: S608
    ):
        with pytest.raises(StorageError, match="append-only"):
            store._execute(sql)

    # And the retention exemption still reaches it, so `delete_tenant` is not locked out
    # of a partition it did not create.
    with store._transaction() as cur:
        cur.execute("SELECT set_config('agent_runtime.retention', 'on', true)")
        cur.execute(f"DELETE FROM {fresh}")  # noqa: S608


def test_ensuring_partitions_twice_creates_nothing_the_second_time(pg):
    """Idempotent, and it reports what it *did* rather than what exists.

    Three callers run this — the migration, opening a store, and the worker's sweep — so
    the common case is a no-op and an implementation that recreated or reported
    everything each time would be indistinguishable from one that worked, right up until
    somebody read the log.
    """
    store, _tenant_id = pg
    # A partition dropped and recreated rather than a window nobody has reached yet:
    # see `_make_fresh_partition` for why assuming absence does not survive a full run.
    fresh = _make_fresh_partition(store, 500)

    assert store.ensure_log_partitions(back_to=_days_ago(500)) == []
    assert store.ensure_log_partitions() == []
    assert fresh in _partitions_of(store, "audit"), "and it is still there"


def test_an_append_beyond_the_horizon_says_what_to_do(pg):
    """The loud failure that pays for not creating partitions on the write path.

    A record stamped past the last partition has nowhere to go, and Postgres says so with
    *"no partition of relation ... found for row"* — accurate and useless. The sentence
    names the maintenance call instead, because the person reading it is holding a
    traceback rather than this migration.
    """
    store, tenant_id = pg
    far = datetime.now(timezone.utc) + timedelta(days=365 * 5)

    with pytest.raises(StorageError, match="ensure_log_partitions") as caught:
        store.append_audit(tenant_id, _record(ts=far))

    assert "no partition of 'audit' covers" in str(caught.value)

    store.ensure_log_partitions()
    assert store.audit_records(tenant_id) == [], "and nothing was written"


def test_opening_a_store_repairs_the_horizon(pg, pg_dsn):
    """The second of the three callers, and the one a long-lived deployment relies on.

    A process that has been up for a quarter has a worker keeping this true; a CLI
    invocation and a server boot have only this. Best-effort by design — see
    `_repair_partition_horizon` — so what is asserted is the repair, not a refusal.
    """
    from carnet.storage.postgres import PostgresStorage

    store, _tenant_id = pg
    newest = _partitions_of(store, "audit")[-1]
    store._execute(f"DROP TABLE {newest}")  # noqa: S608 - from the catalog
    assert newest not in _partitions_of(store, "audit")

    reopened = PostgresStorage(pg_dsn)
    try:
        assert newest in _partitions_of(reopened, "audit")
    finally:
        reopened.close()


def test_the_identity_sequence_survived_the_conversion(pg):
    """Ids continue the line rather than restarting it.

    Migration 030 copies rows with `OVERRIDING SYSTEM VALUE` and then `setval`s the
    sequence. Without the setval the next append reuses an id — and because the primary
    key is now `(id, ts)` rather than `id`, nothing would refuse the duplicate: it would
    sit in the log breaking the ordering guarantee every read of these tables depends on.
    """
    store, tenant_id = pg
    for _ in range(3):
        store.append_audit(tenant_id, _record())

    ids = [
        row[0]
        for row in store._fetchall(
            "SELECT id FROM audit WHERE tenant_id = %s ORDER BY id", (tenant_id,)
        )
    ]
    assert len(ids) == len(set(ids)) == 3
    assert ids == sorted(ids)


def test_reads_stay_in_insertion_order_across_partitions(pg):
    """`ORDER BY id` is what every log read means by "in the order it happened", and
    partitioning is the first thing that could have made it a lie: the rows now live in
    different physical tables, merged by the planner.

    Three months, appended out of order, read back in id order.
    """
    store, tenant_id = pg
    store.ensure_log_partitions(back_to=_days_ago(70))

    for days in (5, 70, 40):
        store.append_audit(tenant_id, _record(ts=_days_ago(days), run_id=f"r-{days}"))

    assert [r["run_id"] for r in store.audit_records(tenant_id)] == ["r-5", "r-70", "r-40"]
    assert [r["run_id"] for r in store.audit_records(tenant_id, limit=2)] == [
        "r-70",
        "r-40",
    ]


def test_deleting_a_tenant_leaves_nothing_behind_anywhere(pg, rid):
    """Walked from `information_schema` rather than from a list somebody maintains.

    This is the test that survives the next migration: a table added with a foreign key
    to `tenants(id)` and forgotten in `TENANT_BLOCKING_TABLES` fails here, by name,
    rather than failing a customer's deletion months later. It is also why those keys
    deliberately did not gain `ON DELETE CASCADE` — a cascade would have silently
    handled the forgotten table, and "handled" is doing dangerous work in that sentence.
    """
    store, tenant_id = pg
    _populate(store, tenant_id, rid)
    store.create_user(
        tenant_id,
        {
            "id": f"u-{tenant_id}",
            "issuer": f"https://{tenant_id}.okta.example",
            "subject": "00u1abc",
            "email": "priya@acme.example",
        },
    )
    store.allow_host(tenant_id, "mcp.acme.com", actor=TEST_ACTOR)
    store.grant_platform_role(
        tenant_id, "user", f"u-{tenant_id}", "admin", TEST_ACTOR, actor=TEST_ACTOR
    )
    # Step 071: a provider and the directory's credential bound to it.
    _scim_for(store, tenant_id)

    referencing = store._fetchall(
        """
        SELECT DISTINCT tc.table_name
          FROM information_schema.table_constraints tc
          JOIN information_schema.constraint_column_usage ccu
            ON tc.constraint_name = ccu.constraint_name
          JOIN pg_class c
            ON c.relname = tc.table_name AND c.relkind IN ('r', 'p')
         WHERE tc.constraint_type = 'FOREIGN KEY'
           AND ccu.table_name = 'tenants'
           AND ccu.column_name = 'id'
           AND NOT c.relispartition
         ORDER BY 1
        """
    )
    tables = [row[0] for row in referencing]
    # A meta-guard on the walk itself, on `test_the_route_table_assertions_can_see_the
    # _route_table`'s precedent: a query that silently returned nothing would make this
    # test pass by checking nothing at all.
    assert len(tables) >= 13
    assert {"audit", "admin_audit", "access_denials", "runs", "groups"} <= set(tables)
    # And a meta-guard on the *exclusion*, which is the half that can rot silently.
    # Migration 030 clones each log table's foreign key onto every monthly partition, so
    # without `NOT relispartition` this walk returns `audit_p2026_08` and a hundred
    # siblings — and a clause that excluded everything would look exactly as green as one
    # that excluded the right thing. This asserts there was something to exclude.
    partitions = store._fetchall(
        "SELECT count(*) FROM pg_class WHERE relispartition AND relname LIKE %s",
        ("audit\\_p%",),
    )
    assert partitions[0][0] > 0, "no partitions exist, so the exclusion proves nothing"
    assert not any(name.startswith("audit_p") for name in tables)

    store.set_tenant_status(tenant_id, "suspended")
    store.delete_tenant(tenant_id, actor=TEST_ACTOR)

    left = {
        table: store._fetchone(
            f"SELECT count(*) FROM {table} WHERE tenant_id = %s", (tenant_id,)
        )[0]
        for table in tables
    }
    assert left == dict.fromkeys(tables, 0)


def test_the_blocking_table_list_is_the_one_the_catalog_says(pg):
    """`TENANT_BLOCKING_TABLES` written down against the database rather than against a
    memory of it. Every previous statement of this problem named `audit` alone; it is
    one of five, and `runs` and `groups` are the two nobody had counted."""
    from carnet.storage import TENANT_BLOCKING_TABLES

    store, _tenant_id = pg
    rows = store._fetchall(
        """
        SELECT tc.table_name
          FROM information_schema.table_constraints tc
          JOIN information_schema.constraint_column_usage ccu
            ON tc.constraint_name = ccu.constraint_name
          JOIN information_schema.referential_constraints rc
            ON tc.constraint_name = rc.constraint_name
          JOIN pg_class c
            ON c.relname = tc.table_name AND c.relkind IN ('r', 'p')
         WHERE tc.constraint_type = 'FOREIGN KEY'
           AND ccu.table_name = 'tenants'
           AND ccu.column_name = 'id'
           AND rc.delete_rule = 'NO ACTION'
           AND NOT c.relispartition
         ORDER BY 1
        """
    )
    # `NOT relispartition`, and the constant is unchanged by migration 030 — which is the
    # point of the clause rather than an exception to the assertion. A partition is not a
    # table `delete_tenant` empties: emptying the parent routes to all of them, so the
    # five blocking tables are still five. Without the clause this equality fails against
    # a hundred-odd `audit_p2026_08`-shaped names, every one of them a partition of a
    # table that is already in the list.
    assert sorted({row[0] for row in rows}) == sorted(TENANT_BLOCKING_TABLES)


def test_the_tombstone_survives_in_the_table_after_the_tenant_is_gone(pg):
    """No foreign key to `tenants`, deliberately — the row it describes is gone, and a
    key would make the tombstone deletable by the very operation it witnesses."""
    store, tenant_id = pg
    store.append_audit(tenant_id, _record())
    store.set_tenant_status(tenant_id, "suspended")
    store.delete_tenant(tenant_id, actor=TEST_ACTOR)

    row = store._fetchone(
        "SELECT name, actor, detail FROM tenant_tombstones WHERE tenant_id = %s",
        (tenant_id,),
    )
    assert row[0] == "PG Test"
    assert row[1] == TEST_ACTOR
    assert row[2]["rows"]["audit"] == 1


# --- retention, step 018 chunk 2 -----------------------------------------------------


@pytest.fixture
def aged(store):
    """A timestamp `days_ago` in the past, **with a partition able to hold it**.

    Migration 030 partitions the three logs by month and creates coverage ahead of time,
    which makes back-dating a record a two-step operation: the partition has to exist
    before the append, or Postgres refuses the row with `missing_partition`'s sentence.
    Production writers stamp `now` and never meet this; every caller that meets it is a
    test or an e2e writing a world older than the deployment, which is why
    `ensure_log_partitions` takes `back_to` at all.

    A day either side is covered as well as the instant itself: these tests append at
    `cutoff ± 1s`, and a cutoff that lands within a second of a month boundary would
    otherwise put one of those rows in a month nobody asked for.
    """
    def _aged(days_ago: int):
        when = _days_ago(days_ago)
        store.ensure_log_partitions(back_to=when - timedelta(days=1))
        return when

    return _aged


def test_the_boundary_a_prune_applies_is_the_month_floor(store, tenant, aged):
    """Strictly `<`, and the boundary is `prune_floor(cutoff)` rather than `cutoff`.

    Migration 030 made a prune a partition drop and a partition is a whole month, so a
    month goes only once the cutoff has passed all of it. The boundary is asserted from
    both sides plus the exact instant, as it always was — at the floor, which is where it
    now lives. **Both stores are held to it through the same function**, which is the
    whole reason `prune_floor` exists rather than each store rounding for itself: the
    fake could delete at the exact instant and would then be more precise than the real
    store, which is drift in the direction nobody notices until production keeps a record
    a test said was gone.
    """
    cutoff = aged(45)
    floor = prune_floor(cutoff)
    store.ensure_log_partitions(back_to=floor - timedelta(days=1))

    store.append_audit(tenant, _record(ts=floor - timedelta(seconds=1), run_id="before"))
    store.append_audit(tenant, _record(ts=floor, run_id="exactly"))
    store.append_audit(tenant, _record(ts=floor + timedelta(seconds=1), run_id="after"))

    counts = store.prune_log_records(cutoff)

    # **Which rows, not how many.** Pruning is global by design — one cutoff over every
    # customer — and the Postgres parameter shares one database across the session, so
    # `counts["audit"]` legitimately includes aged rows other tests left behind. This is
    # the **third** assertion in this file to learn that; the first two were 018's, and
    # this one was written as `== 1`, passed alone, and failed in a full run the moment
    # step 019's partition tests started leaving year-old rows around.
    assert counts["audit"] >= 1
    assert [r["run_id"] for r in store.audit_records(tenant)] == ["exactly", "after"]


def test_a_record_inside_the_cutoffs_own_month_outlives_the_window(store, tenant, aged):
    """The cost of month granularity, pinned rather than left as prose.

    A record older than the configured window survives if it shares a month with the
    cutoff — by up to a month, plus a sweep interval. The window was always a floor
    rather than a ceiling, and this is the test that stops somebody "fixing" it into a
    row-level delete without reading why it is a drop.
    """
    cutoff = aged(45)
    floor = prune_floor(cutoff)
    assert floor < cutoff, "the cutoff must be mid-month for this to mean anything"

    # Older than the window and inside the cutoff's own month: due by the configured
    # policy, kept by the boundary that policy actually gets.
    store.append_audit(tenant, _record(ts=cutoff - timedelta(hours=1), run_id="spared"))

    store.prune_log_records(cutoff)

    assert [r["run_id"] for r in store.audit_records(tenant)] == ["spared"]


def test_pruning_covers_all_three_append_only_tables(store, tenant, aged):
    """One window over the three tables that share the append-only pattern — and not
    over `runs`, which is live product data with references between rows."""
    store.append_audit(tenant, _record(ts=aged(90)))
    store.record_denial(tenant, _denial())
    store.save_agent(tenant, AGENT, actor=TEST_ACTOR)
    store.enqueue_run(tenant, a_run(f"keep-{tenant}"[:60]))

    # `admin_audit` and `access_denials` stamp their own `ts` — neither has a public
    # writer that takes one, and aging them afterwards is an UPDATE the trigger refuses
    # — so the only way to put this tenant's rows behind a boundary is to prune against
    # the future.
    #
    # **45 days into the future, not one.** Since migration 030 the boundary applied is
    # the start of the cutoff's month, so a cutoff of tomorrow floors to the start of
    # *this* month and takes nothing stamped today. Landing the cutoff in a later month
    # is what puts the current month wholly behind the floor. That is not a trick to get
    # the test to pass: it is the same arithmetic that makes the current month
    # structurally undroppable in production no matter how short the window is set.
    #
    # **The counts are therefore the whole database's, not this tenant's**, because the
    # Postgres parameter shares one database across the session. That is harmless — the
    # rows it also removes belong to tests that have already finished — but it means the
    # assertion has to be about this tenant's tables being empty rather than about a
    # number. Asserting `== 1` on a global count passed alone and failed in a full run,
    # which is the whole reason this comment exists.
    counts = store.prune_log_records(datetime.now(timezone.utc) + timedelta(days=45))

    assert counts["audit"] >= 1
    assert counts["admin_audit"] >= 1
    assert counts["access_denials"] >= 1
    assert store.audit_records(tenant) == []
    assert store.denial_records(tenant) == []
    # Everything this tenant had is gone EXCEPT the record saying so. That is the
    # ordering the implementation is built for — the prune records are written after the
    # deletes rather than inside them, so a sweep never eats its own account of why the
    # log is short.
    remaining = [r["action"] for r in store.admin_audit_records(tenant)]
    assert remaining == ["retention.prune"]

    assert len(store.list_runs(tenant)) == 1, "runs are not on a retention window"

    # This test is the only one that drops the *current* month, so it is the only one
    # that has to put the coverage back: every later test in the session appends a record
    # stamped now, and a dropped partition is not a slow write, it is a refused one.
    # Production never reaches this — the floor cannot pass the current month — and the
    # worker ensures coverage before each sweep regardless.
    store.ensure_log_partitions()


def test_a_prune_that_removes_nothing_leaves_no_record(store, tenant, aged):
    """`delete_agent`'s rule: a log recording attempts as well as changes cannot answer
    "what happened" with one row."""
    store.append_audit(tenant, _record(ts=aged(1)))
    before = len(store.admin_audit_records(tenant))

    counts = store.prune_log_records(aged(30))

    assert counts == {"audit": 0, "admin_audit": 0, "access_denials": 0}
    assert len(store.admin_audit_records(tenant)) == before


def test_a_prune_that_removes_something_says_so_per_tenant(store, tenant, other, aged):
    """One record per affected customer, naming the tenant and the boundary — so
    "why is our log short" is answerable by the customer whose log it is."""
    store.append_audit(tenant, _record(ts=aged(90)))
    store.append_audit(other, _record(ts=aged(90)))
    cutoff = aged(30)

    store.prune_log_records(cutoff)

    for tenant_id in (tenant, other):
        records = store.admin_audit_records(tenant_id, action="retention.prune")
        assert len(records) == 1
        assert records[0]["target_kind"] == "tenant"
        assert records[0]["target_id"] == tenant_id
        assert records[0]["actor_id"] == "retention"
        assert records[0]["detail"]["rows"]["audit"] == 1
        # The **effective** boundary, not the requested cutoff. A record claiming
        # "everything before the 14th is gone" when a month-grained drop removed
        # everything before the 1st asserts a precision the operation does not have.
        assert records[0]["detail"]["cutoff"] == prune_floor(cutoff).isoformat()


def test_the_prune_record_names_no_person(store, tenant, aged):
    """Counts and a boundary. The same property the tombstone has, and for the same
    reason: this record outlives the records it is about."""
    store.append_audit(
        tenant, _record(ts=aged(90), principal_id="u-priya", agent="payroll-bot")
    )

    store.prune_log_records(aged(30))

    rendered = json.dumps(
        store.admin_audit_records(tenant, action="retention.prune")[0], default=str
    )
    assert "u-priya" not in rendered
    assert "payroll-bot" not in rendered


def test_a_prune_drops_whole_partitions_rather_than_rows(store, tenant, aged, request):
    """What replaced the batch loop, and the reason the loop's guard went with it.

    018 batched because one statement deleting ten million rows holds locks for minutes
    on the table every tool call writes to. A drop writes no per-row WAL and takes no
    per-row lock, so there is nothing left for a batch size to bound — and
    `check_prune_batch`, which existed because `batch=0` spun forever in Postgres and
    returned the right answer in memory, went with the loop that made it dangerous.
    Deleting the hazard rather than defending it is 029's own rule about the BRIN
    indexes, applied to a guard.

    Postgres-only for the second half: the in-memory store has no partitions to count,
    which is exactly why the *boundary* rather than the mechanism is what the two stores
    are held to together.
    """
    old = aged(400)
    for n in range(25):
        store.append_audit(tenant, _record(ts=old, run_id=f"old-{n}"))

    if request.node.callspec.params.get("store") == "postgres":
        month = f"audit_p{old:%Y_%m}"
        assert month in _partitions_of(store, "audit")

    counts = store.prune_log_records(_days_ago(200))

    assert counts["audit"] >= 25
    assert store.audit_records(tenant) == []

    if request.node.callspec.params.get("store") == "postgres":
        assert month not in _partitions_of(store, "audit"), (
            "the month was emptied rather than dropped"
        )


# --- the edge hunt, step 019 -------------------------------------------------------
#
# The plan's edge table had fifteen rows and all fifteen were covered, so the question
# became which edges the plan did not think of. These are what that found, and three of
# them were defects.


@pytest.mark.parametrize(
    "boundary",
    [
        datetime(2026, 8, 12, 15, 0),                      # naive
        datetime(2026, 1, 1, 0, 0),                        # naive, on a boundary
    ],
)
def test_a_naive_retention_boundary_is_refused(store, tenant, boundary):
    """A wrong answer with no symptom, in the operation that destroys records.

    `astimezone` on a naive datetime silently reads it as the *server's local* time. On a
    machine east of UTC that shifts the floor by up to a day — and within a day of a
    month boundary, by a whole month, which is a month of audit records dropped that
    nobody asked to drop. Nothing would look wrong afterwards; the partition is simply
    gone.

    Refused in `month_start`, so `prune_floor` and every caller of it inherit the
    refusal. This is `check_prune_batch`'s argument arriving at a different door: a
    public method on the storage protocol, and the next caller will not know.
    """
    # A run_id unique to this case, because the `tenant` fixture truncates the test id at
    # 60 characters and the two parametrisations collide past that — the same trap
    # `test_every_in_scope_method_leaves_a_record` names.
    marker = f"kept-{boundary:%Y%m%d%H%M}"
    store.append_audit(tenant, _record(run_id=marker))

    with pytest.raises(StorageError, match="aware datetime"):
        store.prune_log_records(boundary)

    assert marker in [r["run_id"] for r in store.audit_records(tenant)], (
        "it destroyed something on the way to refusing"
    )


def test_a_boundary_in_another_timezone_floors_to_its_utc_month(store, tenant):
    """Aware but not UTC is converted, not refused — and the month is the UTC one.

    Half an hour into September in Tokyo is still August in UTC, and August is the month
    the partition is named for. Getting this backwards would drop a month early for every
    deployment whose operator passes a local timestamp.
    """
    tokyo = timezone(timedelta(hours=9))
    assert prune_floor(datetime(2026, 9, 1, 0, 30, tzinfo=tokyo)) == datetime(
        2026, 8, 1, tzinfo=timezone.utc
    )
    # And the other side of the same boundary.
    assert prune_floor(datetime(2026, 9, 1, 9, 30, tzinfo=tokyo)) == datetime(
        2026, 9, 1, tzinfo=timezone.utc
    )


@pytest.mark.parametrize(
    "now,expected",
    [
        # December into January, which is the one an off-by-one in month arithmetic gets
        # wrong — and it would only be found in December.
        (datetime(2026, 12, 15, tzinfo=timezone.utc),
         ["2026-11", "2026-12", "2027-01", "2027-02", "2027-03"]),
        (datetime(2027, 1, 5, tzinfo=timezone.utc),
         ["2026-12", "2027-01", "2027-02", "2027-03", "2027-04"]),
        # A leap February, reached from a 31-day January: naive date arithmetic that
        # added days rather than months would land on the 31st of a month that has 29.
        (datetime(2028, 1, 31, tzinfo=timezone.utc),
         ["2027-12", "2028-01", "2028-02", "2028-03", "2028-04"]),
    ],
)
def test_partition_months_cross_years_and_leap_februaries(now, expected):
    assert [f"{m:%Y-%m}" for m in log_partition_months(now=now)] == expected


def test_a_back_to_in_the_future_still_covers_today(store):
    """`back_to` widens the window backwards and must never narrow it forwards.

    A caller passing a future date — a typo, or a test computing one — would otherwise
    get coverage starting after today, which is a horizon failure created by the very
    call that exists to prevent one.
    """
    months = log_partition_months(
        datetime(2027, 6, 1, tzinfo=timezone.utc),
        now=datetime(2026, 8, 12, tzinfo=timezone.utc),
    )
    assert f"{months[0]:%Y-%m}" == "2026-07", "coverage must still start before today"
    assert "2026-08" in [f"{m:%Y-%m}" for m in months]


def test_the_horizon_edge_is_exact(pg):
    """The last covered instant lands and the first uncovered one is refused.

    An off-by-one here is a partition boundary that either overlaps — which Postgres
    refuses at creation — or leaves a gap of one microsecond that an append falls into
    once a month. Asserted at the instant rather than the day.
    """
    store, tenant_id = pg
    store.ensure_log_partitions()
    last = log_partition_months()[-1]
    following = _add_months(last, 1)

    store.append_audit(tenant_id, _record(ts=following - timedelta(microseconds=1)))
    assert len(store.audit_records(tenant_id)) == 1

    with pytest.raises(StorageError, match="no partition"):
        store.append_audit(tenant_id, _record(ts=following))


def test_only_one_sweep_prunes_and_it_drains_everything(pg, pg_dsn):
    """Four sweeps at once: one does all of it, three do nothing, nothing is left.

    **Two defects came out of racing this**, and neither was in the plan's edge table.
    Dropping a partition takes ACCESS EXCLUSIVE on the partition *and* on its parent, so
    two sweeps dropping different months of one table each hold what the other wants —
    **eighteen deadlocks in a single race**, all caught and retried, which is the
    database saying the design has an ordering problem rather than saying it is fine.
    The first fix took a lock per partition, which removed the deadlocks and introduced a
    worse thing: every sweep dropped a few months, skipped the ones the others held, and
    went home. **93 of 200 aged rows went.** A retention policy that under-deletes under
    exactly the deployment shape it exists for — more than one worker — is the failure
    this asserts against.

    So the lock is taken once for the whole sweep and the losers stand down entirely.
    """
    import threading

    from carnet.storage.postgres import PostgresStorage

    store, tenant_id = pg
    old = _days_ago(400)
    store.ensure_log_partitions(back_to=old)
    for n in range(30):
        store.append_audit(
            tenant_id, _record(ts=old + timedelta(days=n % 3 * 31), run_id=f"old-{n}")
        )
    aged = len(store.audit_records(tenant_id))
    assert aged == 30

    sweepers = [PostgresStorage(pg_dsn) for _ in range(4)]
    results, errors = [], []

    def sweep(which):
        try:
            results.append(which.prune_log_records(_days_ago(200)))
        except Exception as exc:  # noqa: BLE001 - the assertion is that there are none
            errors.append(repr(exc))

    try:
        threads = [threading.Thread(target=sweep, args=(s,)) for s in sweepers]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    finally:
        for s in sweepers:
            s.close()

    assert errors == []
    assert store.audit_records(tenant_id) == [], "the sweep did not drain the table"
    # Exactly one sweep did the work; the other three removed nothing at all.
    did_work = [r for r in results if r["audit"]]
    assert len(did_work) == 1, [r["audit"] for r in results]
    assert did_work[0]["audit"] >= aged

    # And the records agree with what was actually removed, rather than with what was
    # attempted — three sweeps that removed nothing must have written nothing.
    records = store.admin_audit_records(tenant_id, action="retention.prune")
    assert len(records) == 1
    assert records[0]["detail"]["rows"]["audit"] >= aged


def test_eight_processes_ensuring_partitions_collide_harmlessly(pg, pg_dsn):
    """The advisory lock on maintenance, raced rather than reasoned about.

    Every process that opens a store repairs the horizon, so a deployment restarting its
    workers together runs this eight times at once. `CREATE TABLE ... PARTITION OF` twice
    for the same month is an error, not a no-op, and `IF NOT EXISTS` alone does not close
    the window between the existence check and the create.
    """
    import threading

    from carnet.storage.postgres import PostgresStorage

    store, _tenant_id = pg
    fresh = _make_fresh_partition(store, 700)
    store._execute(f"DROP TABLE {fresh}")  # noqa: S608 - from the catalog

    stores = [PostgresStorage(pg_dsn) for _ in range(8)]
    created, errors = [], []

    def ensure(which):
        try:
            created.append(which.ensure_log_partitions(back_to=_days_ago(700)))
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))

    try:
        threads = [threading.Thread(target=ensure, args=(s,)) for s in stores]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    finally:
        for s in stores:
            s.close()

    assert errors == []
    # Exactly one of them created the missing month, and it says so; the rest report the
    # empty list that means "there was nothing to do".
    makers = [c for c in created if fresh in c]
    assert len(makers) == 1, created
    assert fresh in _partitions_of(store, "audit")


def test_a_partition_held_by_a_reader_is_skipped_rather_than_waited_on(pg, pg_dsn):
    """The `lock_timeout` path, which nothing exercised until it was raced.

    `DROP TABLE` queues for ACCESS EXCLUSIVE *ahead* of every writer behind it, so a drop
    that waited on somebody's long report would stall every log append in the product for
    the length of it. It gives up after five seconds, says so, and leaves the month —
    and the next sweep, an hour later against a window measured in days, takes it.
    """
    import psycopg

    store, tenant_id = pg
    old = _days_ago(500)
    store.ensure_log_partitions(back_to=old)
    store.append_audit(tenant_id, _record(ts=old, run_id="held"))
    target = f"audit_p{old:%Y_%m}"
    assert target in _partitions_of(store, "audit")

    holder = psycopg.connect(pg_dsn, autocommit=False)
    try:
        holder.execute(f"SELECT count(*) FROM {target}")  # noqa: S608 - ACCESS SHARE
        store.prune_log_records(_days_ago(300))
        assert target in _partitions_of(store, "audit"), "it dropped through a held lock"
    finally:
        holder.rollback()
        holder.close()

    # The lock is gone; the next sweep takes the month it left.
    store.prune_log_records(_days_ago(300))
    assert target not in _partitions_of(store, "audit")


def test_a_tenant_is_deleted_across_every_month_it_wrote_in(pg, rid):
    """`delete_tenant` deletes through the parent, which routes to every partition.

    Nothing in the deletion path names a partition, so this is the assertion that says
    the routing is real rather than that today's rows happen to share a month. The
    tombstone's count has to sum across all of them, because it is the number an operator
    reports to a customer.
    """
    store, tenant_id = pg
    store.ensure_log_partitions(back_to=_days_ago(200))
    for days in (5, 40, 70, 100, 160):
        store.append_audit(tenant_id, _record(ts=_days_ago(days), run_id=f"d{days}"))

    months = {f"{_days_ago(d):%Y_%m}" for d in (5, 40, 70, 100, 160)}
    assert len(months) >= 4, "the rows must span months for this to prove anything"

    store.set_tenant_status(tenant_id, "suspended")
    tombstone = store.delete_tenant(tenant_id, actor=TEST_ACTOR)

    assert tombstone["detail"]["rows"]["audit"] == 5
    assert store.audit_records(tenant_id) == []


def test_reads_and_writes_survive_every_partition_being_dropped(pg):
    """The empty-log case, which is what a first enablement on an old deployment reaches.

    A read has to answer `[]` rather than fail, and the next write has to land — which it
    only does because the sweep puts coverage back after dropping.
    """
    store, tenant_id = pg
    store.append_audit(tenant_id, _record())

    store.prune_log_records(datetime.now(timezone.utc) + timedelta(days=400))

    assert store.audit_records(tenant_id) == []
    assert _partitions_of(store, "audit"), "coverage was not restored"

    store.append_audit(tenant_id, _record(run_id="after-everything"))
    assert [r["run_id"] for r in store.audit_records(tenant_id)] == ["after-everything"]


def test_a_partition_the_bound_cannot_be_read_from_is_never_dropped(pg):
    """A partition is selected for dropping by its **declared bound**, and anything whose
    bound does not parse as a month is left alone rather than guessed at.

    The reachable case is a DEFAULT partition, which is a real thing somebody may add —
    it is the obvious alternative to `missing_partition`'s loud refusal, catching every
    row whose month is absent instead of rejecting it. Whatever one thinks of that
    trade, a default partition holds rows of *every* age, so dropping it on a cutoff
    would destroy live records. Its bound renders as `DEFAULT` with no upper value, the
    selection reads no timestamp out of it, and it is skipped.

    The same property covers the shapes nobody has built: `TO (MAXVALUE)`, and any future
    rendering of a bound this code does not recognise. Unrecognised means untouched.
    """
    store, tenant_id = pg
    store._execute("DROP TABLE IF EXISTS audit_default")
    store._execute("CREATE TABLE audit_default PARTITION OF audit DEFAULT")
    try:
        # It routes rows whose month has no partition — which is exactly the horizon case
        # `missing_partition` otherwise refuses, so this row could not exist without it.
        far = datetime.now(timezone.utc) + timedelta(days=365 * 5)
        store.append_audit(tenant_id, _record(ts=far, run_id="defaulted"))

        store.prune_log_records(datetime.now(timezone.utc))

        assert "audit_default" in _partitions_of(store, "audit"), "it was dropped"
        assert [r["run_id"] for r in store.audit_records(tenant_id)] == ["defaulted"]
    finally:
        store._execute("ALTER TABLE audit DETACH PARTITION audit_default")
        store._execute("DROP TABLE audit_default")


def test_only_wholly_expired_months_are_selected_for_dropping(pg):
    """The selection rule itself, against the bounds rather than against the names.

    The month the floor falls *inside* is the one somebody gets wrong, and getting it
    wrong deletes records inside the retention window — the single worst thing this step
    can do. So the boundary month is asserted present in the catalog and absent from the
    selection, which is a stronger statement than any count of deleted rows.
    """
    store, _tenant_id = pg
    floor = prune_floor(_days_ago(120))
    store.ensure_log_partitions(back_to=floor - timedelta(days=90))

    selected = set(store._expired_partitions("audit", floor))
    existing = set(_partitions_of(store, "audit"))

    boundary = f"audit_p{floor:%Y_%m}"
    assert boundary in existing, "the boundary month must exist for this to mean anything"
    assert boundary not in selected, "the floor's own month is kept, not dropped"

    earlier = f"audit_p{prune_floor(floor - timedelta(days=1)):%Y_%m}"
    assert earlier in existing
    assert earlier in selected, "the month before the floor is wholly expired"

    # And nothing at or after the boundary is ever in the list.
    assert all(name < boundary for name in selected), sorted(selected)


def test_pruning_leaves_another_tenants_records_alone(store, tenant, other, aged):
    """The cutoff is the only predicate, so this is what says it is applied per row
    rather than per table."""
    store.append_audit(tenant, _record(ts=aged(90)))
    store.append_audit(other, _record(ts=aged(1)))

    store.prune_log_records(aged(30))

    assert store.audit_records(tenant) == []
    assert len(store.denial_records(other)) == 0
    assert len(store.audit_records(other)) == 1


def test_a_prune_survives_a_tenant_that_vanished_mid_sweep(store, tenant, other, aged):
    """The race the plan's edge table called "both safe" and had not measured.

    A retention sweep deletes a tenant's aged rows, and the customer is deleted before
    the sweep writes the record attributing them. Postgres refuses that record with a
    foreign-key violation; the in-memory store never had a key to refuse it with, so it
    skipped the tenant from the first version — **store drift, found by racing them
    against a real database rather than by reading either one.**

    What was at stake was not corruption. It was a whole retention sweep abandoning
    every tenant after the deleted one, once an hour, logged as an exception.

    Simulated rather than raced here, because a test that depends on winning a race is a
    test that fails on somebody else's laptop: the observable property is that pruning
    survives records whose tenant is gone, and that is what this asserts.
    """
    store.append_audit(tenant, _record(ts=aged(90)))
    store.append_audit(other, _record(ts=aged(90)))
    store.set_tenant_status(tenant, "suspended")
    store.delete_tenant(tenant, actor=TEST_ACTOR)

    # `other` still exists and still has an aged row, so the sweep has real work to do.
    counts = store.prune_log_records(aged(30))

    assert counts["audit"] == 1, "the surviving tenant's row still went"
    records = store.admin_audit_records(other, action="retention.prune")
    assert len(records) == 1, "and the surviving tenant still got its record"


def test_deleting_a_tenant_takes_a_thread_of_runs_with_it(store, tenant, rid):
    """`runs.parent_run_id` and `runs.root_run_id` reference `runs(run_id)` with no
    `ON DELETE` clause (migration 027), so a thread is rows referencing each other inside
    the table being emptied. One statement per table is what makes that legal — Postgres
    checks a self-reference at statement end rather than per row."""
    root, child = rid("root"), rid("child")
    store.enqueue_run(tenant, a_run(root))
    store.finish_run(tenant, root, status="complete", answer="done")
    store.enqueue_run(
        tenant, a_run(child, parent_run_id=root, root_run_id=root)
    )
    store.set_tenant_status(tenant, "suspended")

    tombstone = store.delete_tenant(tenant, actor=TEST_ACTOR)

    assert tombstone["detail"]["rows"]["runs"] == 2
    assert store.get_tenant(tenant) is None


def test_deleting_a_tenant_whose_group_holds_a_grant(store, tenant):
    """Deleting a `groups` row fires `groups_cascade_grants` (migration 017), which
    deletes `agent_grants` — a trigger running inside the deletion transaction, on a
    table the tenant cascade is about to remove anyway. Both orders have to be legal."""
    store.create_agent(tenant, AGENT, "user", "u-1")
    store.create_group(tenant, "eng", "Engineering",
                       created_by=TEST_ACTOR, actor=TEST_ACTOR)
    store.grant_agent(tenant, AGENT["name"], "group", "eng", actor=TEST_ACTOR)
    store.set_tenant_status(tenant, "suspended")

    store.delete_tenant(tenant, actor=TEST_ACTOR)

    assert store.get_tenant(tenant) is None
    assert store.list_groups(tenant) == []


def test_an_empty_tenant_deletes_and_still_leaves_a_tombstone(store, tenant):
    """Nothing to erase is not nothing to record: a customer who never used the product
    still left, and the id is still burned."""
    store.set_tenant_status(tenant, "suspended")

    tombstone = store.delete_tenant(tenant, actor=TEST_ACTOR)

    assert tombstone["detail"]["rows"] == dict.fromkeys(TENANT_BLOCKING_TABLES, 0)
    assert store.get_tenant_tombstone(tenant) is not None
    with pytest.raises(TenantDeleted):
        store.create_tenant(tenant, "Reborn")


def test_a_tenant_id_is_never_interpolated_into_sql(store, request):
    """`delete_tenant` interpolates TABLE names into its statements — from a module
    constant — and takes the tenant id as a parameter. This is what says the second half
    stayed true."""
    hostile = f"x'; DROP TABLE tenants;--{request.node.name}"[:60]
    store.create_tenant(hostile, "Hostile Co")
    store.append_audit(hostile, _record())
    store.set_tenant_status(hostile, "suspended")

    store.delete_tenant(hostile, actor=TEST_ACTOR)

    assert store.get_tenant(hostile) is None
    # The table is still there to be asked, which is the whole assertion.
    assert store.list_tenants() is not None


# --- api tokens, step 020 ---------------------------------------------------------
#
# The machine caller's credential. What these hold is not mainly the round trip — that
# is four methods and a dict — but the two containments the design rests on: the hash
# leaves through exactly one door, and a machine is refused the two things that would
# make it an administrator by the long way round.


def _token_id(tenant, suffix=""):
    """A token id unique to this test. **`api_tokens.id` is a GLOBAL primary key** — the
    one table here whose key is not tenant-scoped, because `find_api_token` produces a
    tenant rather than taking one — and the Postgres parameter shares one database for
    the whole session. A fixed id in a helper is therefore a collision between tests
    rather than a fixture, which is 018's shared-database lesson arriving for the third
    time and the reason it is a function rather than a constant."""
    return f"m_{tenant}{suffix}".replace("-", "_")[:64]


def _token(tenant, **overrides):
    """One `api_tokens` row's worth of arguments. The fields nobody varies, in one place."""
    row = {
        "id": _token_id(tenant),
        "name": "nightly-ci",
        "owner_id": "u-priya",
        "secret_hash": "sha256$" + "a" * 64,
    }
    row.update(overrides)
    return row


def test_a_token_round_trips_through_both_stores(store, tenant):
    minted = store.create_api_token(tenant, _token(tenant), actor=TEST_ACTOR)

    assert minted["id"] == _token_id(tenant)
    assert minted["name"] == "nightly-ci"
    assert minted["owner_id"] == "u-priya"
    assert minted["tenant_id"] == tenant
    assert minted["created_by"] == TEST_ACTOR
    assert minted["created_at"] is not None
    # The default kind is 020's service token — false is precisely true of every
    # token minted before 033d existed, which is why migration 042 backfills nothing.
    assert minted["acts_as_owner"] is False
    # Three nulls that mean three different things, and all three are load-bearing:
    # never expires, never revoked, never used.
    assert minted["expires_at"] is None
    assert minted["revoked_at"] is None
    assert minted["last_used_at"] is None


def test_a_personal_token_round_trips_and_the_mint_record_says_so(store, tenant):
    """Step 033d. The flag survives every read (`find` is the request path's read, so
    a store that dropped it there would quietly turn every personal token back into a
    service token) — and the mint's administrative record carries it, because minting
    a personal token IS the trust decision and "who approved that" should be a row."""
    minted = store.create_api_token(
        tenant,
        _token(tenant, id=_token_id(tenant, "p"), name="priya-cursor", acts_as_owner=True),
        actor=TEST_ACTOR,
    )

    assert minted["acts_as_owner"] is True
    assert store.find_api_token(_token_id(tenant, "p"))["acts_as_owner"] is True
    listed = {row["name"]: row for row in store.list_api_tokens(tenant)}
    assert listed["priya-cursor"]["acts_as_owner"] is True

    (record,) = store.admin_audit_records(tenant, action="token.mint")
    assert record["detail"]["acts_as_owner"] is True


def test_a_token_kind_must_be_a_bool(store, tenant):
    """Refused rather than coerced: three readers redirect on this column (grants,
    credentials, the door's refresh), and a truthy string would make "personal" a
    fact about how a caller spelled it."""
    with pytest.raises(StorageError, match="acts_as_owner"):
        store.create_api_token(
            tenant, _token(tenant, acts_as_owner="yes"), actor=TEST_ACTOR
        )


def test_only_find_api_token_returns_the_hash(store, tenant):
    """The containment `find_connection` has against `ciphertext`, one table over.

    `create` and `list` are the surfaces a person or a screen reads; both project
    through `API_TOKEN_PUBLIC_FIELDS`, so neither can carry the hash past a caller who
    was not thinking about it. `find_api_token` is the single exception because
    comparing against the hash is the one thing that needs it.
    """
    from carnet.storage import API_TOKEN_FIELDS, API_TOKEN_PUBLIC_FIELDS

    minted = store.create_api_token(tenant, _token(tenant), actor=TEST_ACTOR)
    listed = store.list_api_tokens(tenant)
    found = store.find_api_token(_token_id(tenant))

    assert set(minted) == set(API_TOKEN_PUBLIC_FIELDS)
    assert set(listed[0]) == set(API_TOKEN_PUBLIC_FIELDS)
    assert set(found) == set(API_TOKEN_FIELDS)

    assert "secret_hash" not in minted
    assert "secret_hash" not in listed[0]
    assert found["secret_hash"] == "sha256$" + "a" * 64


def test_listing_tokens_narrows_to_one_owner_and_empty_means_everyone(store, tenant):
    """022b's `GET /me/tokens` is the caller: a person picking among the tokens they may
    schedule, which is exactly the tokens they own.

    The empty string means *everyone* rather than *nobody*, and that is asked on purpose
    — it is the value a route reaches by forgetting to pass one, and the CLI's own call
    relies on it. A store that read it as a filter would show `--list-tokens` nothing.
    """
    store.create_api_token(tenant, _token(tenant), actor=TEST_ACTOR)
    store.create_api_token(
        tenant,
        _token(tenant, id=_token_id(tenant, "b"), name="weekly-ci", owner_id="u-sam"),
        actor=TEST_ACTOR,
    )

    assert [row["name"] for row in store.list_api_tokens(tenant)] == [
        "nightly-ci",
        "weekly-ci",
    ]
    assert [
        row["name"] for row in store.list_api_tokens(tenant, owner_id="u-priya")
    ] == ["nightly-ci"]
    assert [row["name"] for row in store.list_api_tokens(tenant, owner_id="")] == [
        "nightly-ci",
        "weekly-ci",
    ]
    # A person who owns none is an empty list, not an error: "you have no tokens" is a
    # true and complete answer to the question the screen asks.
    assert store.list_api_tokens(tenant, owner_id="u-nobody") == []


def test_a_revoked_token_is_still_listed_for_its_owner(store, tenant):
    """The listing is a record, and the *picker* is what excludes the unusable.

    Filtering revoked rows out here would make the one person entitled to the whole
    answer the one person who cannot see it — and `--list-tokens` prints their state for
    exactly that reason.
    """
    store.create_api_token(tenant, _token(tenant), actor=TEST_ACTOR)
    store.revoke_api_token(tenant, _token_id(tenant), actor=TEST_ACTOR)

    listed = store.list_api_tokens(tenant, owner_id="u-priya")

    assert [row["name"] for row in listed] == ["nightly-ci"]
    assert listed[0]["revoked_at"] is not None


def test_find_api_token_takes_no_tenant_and_produces_one(store, tenant):
    """The third method in this interface that determines a tenant rather than taking
    one, after `find_user` and `claim_run`. A caller holding a token string has no
    tenant to pass — the tenant is the answer, not the question."""
    store.create_api_token(tenant, _token(tenant), actor=TEST_ACTOR)

    found = store.find_api_token(_token_id(tenant))

    assert found["tenant_id"] == tenant
    assert store.find_api_token("m_nosuchtoken") is None


def test_two_LIVE_tokens_cannot_share_a_name_in_one_tenant(store, tenant, other):
    """`ValueRefused`, not a bare `StorageError`: the store is working perfectly and
    somebody reused a name, which is a 400 over HTTP and a `parser.error` on the CLI
    rather than "storage unavailable"."""
    from carnet.storage.base import ValueRefused

    store.create_api_token(tenant, _token(tenant), actor=TEST_ACTOR)

    with pytest.raises(ValueRefused, match="already has a live API token called"):
        store.create_api_token(
            tenant, _token(tenant, id=_token_id(tenant, "b")), actor=TEST_ACTOR
        )

    # The name is per tenant, not global. Two customers both calling theirs `nightly-ci`
    # is the expected case, not a collision.
    store.create_api_token(other, _token(other, id=_token_id(other)), actor=TEST_ACTOR)
    assert [row["name"] for row in store.list_api_tokens(other)] == ["nightly-ci"]


def test_revoking_a_token_frees_its_name_for_a_replacement(store, tenant):
    """**Found by an edge hunt, and it is the moment the feature matters most.**

    `UNIQUE (tenant_id, name)` burned a name permanently: a token leaks, the operator
    revokes `nightly-ci`, and then cannot mint its replacement under the name the
    pipeline's configuration already refers to. The workaround is `nightly-ci-2`, which
    is how a deployment ends up with names nobody can map to systems.

    Deliberately **not** migration 029's tombstone argument. A tenant id *is* an
    identity, so recycling one could make one customer's records look like another's; a
    token's name is a label on a row whose identity is `id`, every record it writes names
    `machine:m_...`, and `--list-tokens` shows the revoked row beside the live one with
    its revocation date. So: `api_tokens_one_live_name`, a partial unique index on the
    pattern `runs_idempotency` and `agent_grants_one_owner` already use.
    """
    from carnet.storage.base import ValueRefused

    first = store.create_api_token(tenant, _token(tenant), actor=TEST_ACTOR)
    store.revoke_api_token(tenant, first["id"], actor=TEST_ACTOR)

    second = store.create_api_token(
        tenant, _token(tenant, id=_token_id(tenant, "b")), actor=TEST_ACTOR
    )

    assert second["id"] != first["id"]
    # Both rows survive, and the list is still legible because state is a column.
    listed = {row["id"]: row["revoked_at"] is None for row in store.list_api_tokens(tenant)}
    assert listed == {first["id"]: False, second["id"]: True}

    # And the freed name is only free once: the replacement now holds it.
    with pytest.raises(ValueRefused, match="already has a live API token called"):
        store.create_api_token(
            tenant, _token(tenant, id=_token_id(tenant, "c")), actor=TEST_ACTOR
        )


def test_revocation_stamps_the_row_and_never_deletes_it(store, tenant):
    """The opposite of `platform_roles`, deliberately: a role is proved by the log that
    granted it, and a token id is a *subject* in records that outlive it. Delete the row
    and `machine:m_...` in three years of audit records resolves to nothing."""
    store.create_api_token(tenant, _token(tenant), actor=TEST_ACTOR)

    revoked = store.revoke_api_token(tenant, _token_id(tenant), actor="user:u-sam")

    assert revoked["revoked_at"] is not None
    assert revoked["revoked_by"] == "user:u-sam"
    assert store.find_api_token(_token_id(tenant)) is not None
    assert [row["id"] for row in store.list_api_tokens(tenant)] == [_token_id(tenant)]


def test_revoking_twice_is_idempotent_and_records_once(store, tenant):
    """`revoke_platform_role`'s treatment of a row that was not there, with the row
    surviving instead of going. Anything a client retries needs a test that does it
    twice — section H, learned the expensive way in 008c."""
    store.create_api_token(tenant, _token(tenant), actor=TEST_ACTOR)

    first = store.revoke_api_token(tenant, _token_id(tenant), actor=TEST_ACTOR)
    second = store.revoke_api_token(tenant, _token_id(tenant), actor=TEST_ACTOR)

    assert second is not None
    # The stamp does not move on the second call: the moment it was revoked is a fact
    # about the first revocation, and a retry must not rewrite it.
    assert second["revoked_at"] == first["revoked_at"]

    actions = [r["action"] for r in store.admin_audit_records(tenant)]
    assert actions.count("token.revoke") == 1


def test_revoking_an_unknown_or_other_tenants_token_answers_none(store, tenant, other):
    store.create_api_token(other, _token(other), actor=TEST_ACTOR)

    assert store.revoke_api_token(tenant, "m_nosuchtoken", actor=TEST_ACTOR) is None

    # Scoped by tenant, so one customer cannot revoke another's. Asserted with the
    # **other tenant's real id** rather than an absent one, because an id that exists
    # nowhere would answer None for the wrong reason and the test would pass with the
    # tenant filter deleted. `find_api_token` is deliberately tenantless, which is
    # exactly what makes it easy to write this method that way by accident.
    assert store.revoke_api_token(tenant, _token_id(other), actor=TEST_ACTOR) is None
    assert store.find_api_token(_token_id(other))["revoked_at"] is None


def test_touch_stamps_last_used(store, tenant):
    """The per-request write `record_user_login` has always paid for people. It answers
    the one question an offboarding review asks that nothing else can."""
    store.create_api_token(tenant, _token(tenant), actor=TEST_ACTOR)
    assert store.find_api_token(_token_id(tenant))["last_used_at"] is None

    store.touch_api_token(_token_id(tenant))

    assert store.find_api_token(_token_id(tenant))["last_used_at"] is not None
    # Unknown ids are a no-op rather than an error: this runs on the request path and a
    # token deleted underneath a live request must not turn a refusal into a 503.
    store.touch_api_token("m_nosuchtoken")


def test_a_naive_token_expiry_is_refused(store, tenant):
    """019's lesson, one column over: a naive datetime is read as server-local time, so
    the moment a credential stops working moves by however far the deployment is from
    UTC — silently, and in the direction nobody checks.

    Named for the *token* rather than sharing `test_a_naive_expiry_is_refused` with the
    connections case: two module-level functions of one name means Python keeps the
    second and the first silently stops running, which is coverage lost with nothing
    reporting it.
    """
    with pytest.raises(StorageError, match="timezone-aware"):
        store.create_api_token(
            tenant,
            _token(tenant, expires_at=datetime(2027, 1, 1)),
            actor=TEST_ACTOR,
        )


def test_a_token_needs_an_owner_and_a_hash(store, tenant):
    for missing in ("owner_id", "secret_hash", "name", "id"):
        with pytest.raises(StorageError, match="api token is missing"):
            store.create_api_token(
                tenant, _token(tenant, **{missing: ""}), actor=TEST_ACTOR
            )


def test_a_machine_can_never_hold_a_platform_role(store, tenant):
    """**The other half of not inheriting the always-admin `system` rule.**

    Refusing a machine the `system` shortcut is worth nothing if the long way round is
    open. Both stores refuse with the same class, and `platform_roles_principal_kind_check`
    — which migration 031 pointedly did not widen — refuses it in the column.
    """
    with pytest.raises(StorageError, match="machine cannot hold a platform role"):
        store.grant_platform_role(
            tenant, "machine", _token_id(tenant), "admin", actor=TEST_ACTOR
        )


def test_a_machine_can_never_be_an_administrative_actor(store, tenant):
    """`admin_audit.actor_kind` keeps the two kinds it had. A machine is something a
    record can be *about* — `machine` is in `ADMIN_TARGET_KINDS` — and never something
    that writes one."""
    with pytest.raises(StorageError, match="machine cannot be the actor"):
        store.create_group(tenant, "g_bots", "Bots", actor="machine:m_ci")


def test_a_machine_is_granted_user_and_nothing_higher(store, tenant):
    """`agent_grants_no_group_owner`'s argument at a different address. A machine runs
    an agent; editing and re-sharing carry somebody's judgment, and a credential living
    in a CI variable is the wrong place for that judgment to sit."""
    store.create_agent(tenant, AGENT, "user", "u-priya")

    store.grant_agent(
        tenant, "issue-reporter", "machine", "m_ci", "user", actor=TEST_ACTOR
    )
    assert (
        store.agent_grant_role(tenant, "issue-reporter", "machine", "m_ci") == "user"
    )

    for role in ("editor", "owner"):
        with pytest.raises(StorageError, match="a machine may be granted"):
            store.grant_agent(
                tenant, "issue-reporter", "machine", "m_ci2", role, actor=TEST_ACTOR
            )


def test_a_machine_may_belong_to_a_group_and_reach_an_agent_through_it(store, tenant):
    """A group of service accounts is legitimate — `group_members.principal_kind` is
    widened for exactly this — and the resolving lookup is kind-agnostic, so it works
    with no machine-specific branch anywhere in `grants.py`."""
    store.create_agent(tenant, AGENT, "user", "u-priya")
    store.create_group(tenant, "g_bots", "Bots", actor=TEST_ACTOR)
    store.add_group_member(tenant, "g_bots", "machine", "m_ci", actor=TEST_ACTOR)
    store.grant_agent(
        tenant, "issue-reporter", "group", "g_bots", "user", actor=TEST_ACTOR
    )

    assert (
        store.agent_grant_role(tenant, "issue-reporter", "machine", "m_ci") == "user"
    )


def test_deleting_a_tenant_takes_its_tokens(store, tenant):
    """`ON DELETE CASCADE`, and by hand in the fake. A token outliving its customer is a
    credential nobody can see and nobody can revoke."""
    store.create_api_token(tenant, _token(tenant), actor=TEST_ACTOR)
    store.set_tenant_status(tenant, "suspended")

    store.delete_tenant(tenant, actor=TEST_ACTOR)

    assert store.find_api_token(_token_id(tenant)) is None


# --- scim tokens, step 071 ----------------------------------------------------------
#
# The directory's credential, on `api_tokens`' terms: the hash leaves through exactly
# one door, revocation is a stamp, and — the one thing that is new — the token is bound
# to an issuer the tenant has registered.


def _scim_id(tenant, suffix=""):
    """Global primary key, like `api_tokens.id` — see `_token_id`."""
    return f"s_{tenant}{suffix}".replace("-", "_").replace(".", "_")[:64]


def _scim_row(tenant, issuer, **overrides):
    row = {
        "id": _scim_id(tenant),
        "issuer": issuer,
        "name": "entra-prod",
        "secret_hash": "sha256$" + "b" * 64,
        "created_by": "user:u-priya",
    }
    row.update(overrides)
    return row


def test_a_scim_token_round_trips_and_the_mint_record_names_no_secret(store, tenant, okta):
    store.save_tenant_idp(tenant, okta)

    minted = store.mint_scim_token(tenant, _scim_row(tenant, okta["issuer"]), actor=TEST_ACTOR)

    assert minted["id"] == _scim_id(tenant)
    assert minted["tenant_id"] == tenant
    assert minted["issuer"] == okta["issuer"]
    assert minted["name"] == "entra-prod"
    assert minted["created_by"] == "user:u-priya"
    assert minted["created_at"] is not None
    assert minted["revoked_at"] is None
    assert minted["revoked_by"] is None
    assert minted["last_used_at"] is None

    (record,) = store.admin_audit_records(tenant, action="scim.token.mint")
    assert (record["target_kind"], record["target_id"]) == ("scim_token", _scim_id(tenant))
    assert record["detail"] == {"issuer": okta["issuer"], "name": "entra-prod"}
    assert "b" * 64 not in json.dumps(record)


def test_only_find_scim_token_returns_the_hash(store, tenant, okta):
    from carnet.storage import SCIM_TOKEN_FIELDS, SCIM_TOKEN_PUBLIC_FIELDS

    store.save_tenant_idp(tenant, okta)
    minted = store.mint_scim_token(tenant, _scim_row(tenant, okta["issuer"]), actor=TEST_ACTOR)
    listed = store.list_scim_tokens(tenant)
    found = store.find_scim_token(_scim_id(tenant))
    revoked = store.revoke_scim_token(tenant, _scim_id(tenant), actor=TEST_ACTOR)

    assert set(minted) == set(SCIM_TOKEN_PUBLIC_FIELDS)
    assert set(listed[0]) == set(SCIM_TOKEN_PUBLIC_FIELDS)
    assert set(revoked) == set(SCIM_TOKEN_PUBLIC_FIELDS)
    assert set(found) == set(SCIM_TOKEN_FIELDS)
    assert found["secret_hash"] == "sha256$" + "b" * 64
    assert SCIM_TOKEN_FIELDS[-1] == "secret_hash"


def test_find_scim_token_takes_no_tenant_and_produces_one(store, tenant, okta):
    store.save_tenant_idp(tenant, okta)
    store.mint_scim_token(tenant, _scim_row(tenant, okta["issuer"]), actor=TEST_ACTOR)

    assert store.find_scim_token(_scim_id(tenant))["tenant_id"] == tenant
    assert store.find_scim_token("s_nobody") is None


def test_scim_tokens_are_listed_oldest_first_with_revoked_ones_kept(store, tenant, other, okta):
    store.save_tenant_idp(tenant, okta)
    store.mint_scim_token(
        tenant, _scim_row(tenant, okta["issuer"], id=_scim_id(tenant, "_1")), actor=TEST_ACTOR
    )
    store.mint_scim_token(
        tenant,
        _scim_row(tenant, okta["issuer"], id=_scim_id(tenant, "_2"), name="okta-prod"),
        actor=TEST_ACTOR,
    )
    store.revoke_scim_token(tenant, _scim_id(tenant, "_1"), actor=TEST_ACTOR)

    listed = store.list_scim_tokens(tenant)

    assert [row["id"] for row in listed] == [_scim_id(tenant, "_1"), _scim_id(tenant, "_2")]
    assert listed[0]["revoked_at"] is not None
    assert listed[1]["revoked_at"] is None
    assert store.list_scim_tokens(other) == []


def test_revoking_a_scim_token_is_idempotent_and_turns_the_pull_back_on(store, tenant, okta):
    """One record however many times it is revoked, and `tenant_has_live_scim_token` —
    the read `directory.reconcile` makes — answers False the moment it lands."""
    store.save_tenant_idp(tenant, okta)
    store.mint_scim_token(tenant, _scim_row(tenant, okta["issuer"]), actor=TEST_ACTOR)
    assert store.tenant_has_live_scim_token(tenant, okta["issuer"]) is True

    first = store.revoke_scim_token(tenant, _scim_id(tenant), actor="user:u-admin")
    again = store.revoke_scim_token(tenant, _scim_id(tenant), actor="user:u-other")

    assert first["revoked_at"] is not None
    assert first["revoked_by"] == "user:u-admin"
    assert again["revoked_by"] == "user:u-admin"
    assert store.tenant_has_live_scim_token(tenant, okta["issuer"]) is False
    (record,) = store.admin_audit_records(tenant, action="scim.token.revoke")
    assert (record["target_kind"], record["target_id"]) == ("scim_token", _scim_id(tenant))
    # Still there, so the actor string in every row the directory wrote resolves.
    assert store.find_scim_token(_scim_id(tenant))["name"] == "entra-prod"


def test_a_live_scim_token_is_per_issuer_and_per_tenant(store, tenant, other, okta, uniq):
    store.save_tenant_idp(tenant, okta)
    store.mint_scim_token(tenant, _scim_row(tenant, okta["issuer"]), actor=TEST_ACTOR)

    assert store.tenant_has_live_scim_token(tenant, okta["issuer"]) is True
    assert store.tenant_has_live_scim_token(other, okta["issuer"]) is False
    assert store.tenant_has_live_scim_token(tenant, f"https://{uniq}.elsewhere") is False


def test_revoking_an_unknown_or_other_tenants_scim_token_answers_none(store, tenant, other, okta):
    store.save_tenant_idp(tenant, okta)
    store.mint_scim_token(tenant, _scim_row(tenant, okta["issuer"]), actor=TEST_ACTOR)

    assert store.revoke_scim_token(other, _scim_id(tenant), actor=TEST_ACTOR) is None
    assert store.revoke_scim_token(tenant, "s_nobody", actor=TEST_ACTOR) is None
    assert store.find_scim_token(_scim_id(tenant))["revoked_at"] is None
    assert store.admin_audit_records(other) == []


def test_touching_a_scim_token_stamps_last_used_and_writes_nothing(store, tenant, okta):
    store.save_tenant_idp(tenant, okta)
    store.mint_scim_token(tenant, _scim_row(tenant, okta["issuer"]), actor=TEST_ACTOR)

    store.touch_scim_token(_scim_id(tenant))
    store.touch_scim_token("s_nobody")

    assert store.find_scim_token(_scim_id(tenant))["last_used_at"] is not None
    assert [r["action"] for r in store.admin_audit_records(tenant)] == ["scim.token.mint"]


def test_minting_a_scim_token_for_an_unregistered_issuer_is_refused(store, tenant, okta, uniq):
    """Bound to a provider the tenant has, or the rows it provisions could never be
    adopted. The caller's mistake, so `ValueRefused`; and nothing is written."""
    store.save_tenant_idp(tenant, okta)

    with pytest.raises(ValueRefused, match="no identity provider registered"):
        store.mint_scim_token(
            tenant, _scim_row(tenant, f"https://{uniq}.elsewhere"), actor=TEST_ACTOR
        )

    assert store.find_scim_token(_scim_id(tenant)) is None
    assert store.admin_audit_records(tenant) == []


def test_a_scim_token_id_is_not_recycled_and_every_field_is_required(store, tenant, okta):
    store.save_tenant_idp(tenant, okta)
    store.mint_scim_token(tenant, _scim_row(tenant, okta["issuer"]), actor=TEST_ACTOR)

    with pytest.raises(StorageError, match="already exists"):
        store.mint_scim_token(
            tenant, _scim_row(tenant, okta["issuer"], name="second"), actor=TEST_ACTOR
        )
    with pytest.raises(StorageError, match="created_by"):
        store.mint_scim_token(
            tenant, _scim_row(tenant, okta["issuer"], id="s_x", created_by=""), actor=TEST_ACTOR
        )
    with pytest.raises(StorageError, match="name"):
        store.mint_scim_token(
            tenant, _scim_row(tenant, okta["issuer"], id="s_x", name="  "), actor=TEST_ACTOR
        )
    with pytest.raises(StorageError, match="'\\.'"):
        store.mint_scim_token(
            tenant, _scim_row(tenant, okta["issuer"], id="s.x"), actor=TEST_ACTOR
        )

    assert len(store.list_scim_tokens(tenant)) == 1


def test_a_scim_token_for_an_unknown_tenant_is_refused(store, okta):
    with pytest.raises(UnknownTenantError):
        store.mint_scim_token("never-created", _scim_row("never", okta["issuer"]), actor=TEST_ACTOR)


def test_deleting_a_tenant_takes_its_scim_tokens(store, tenant, okta):
    """`ON DELETE CASCADE`, and by hand in the fake — a directory credential outliving
    its customer is one nobody can list and nobody can revoke."""
    store.save_tenant_idp(tenant, okta)
    store.mint_scim_token(tenant, _scim_row(tenant, okta["issuer"]), actor=TEST_ACTOR)
    store.set_tenant_status(tenant, "suspended")

    store.delete_tenant(tenant, actor=TEST_ACTOR)

    assert store.find_scim_token(_scim_id(tenant)) is None


def test_the_machine_kind_checks_are_in_the_columns_not_only_in_python(pg):
    """Migration 017's precedent, applied to step 020's two narrow columns.

    A rule that lives only in a Python frozenset is one the next caller widens, and a
    test written in the same language as the constant does not survive somebody widening
    it. So this reaches **past** `check_platform_role` and `split_actor` to write the
    rows they exist to refuse, and requires the database to be the thing that says no.

    These are the two constraints migration 031 deliberately left alone while widening
    six others, so they are the ones worth proving are still narrow.
    """
    store, tenant_id = pg

    with pytest.raises(StorageError, match="platform_roles_principal_kind_check"):
        store._execute(
            "INSERT INTO platform_roles (tenant_id, principal_kind, principal_id, "
            "role, granted_by) VALUES (%s, %s, %s, %s, %s)",
            (tenant_id, "machine", "m_ci", "admin", "system:cli"),
        )

    with pytest.raises(StorageError, match="admin_audit_actor_kind_check"):
        store._execute(
            store._ADMIN_INSERT,
            (tenant_id, 1, datetime.now(timezone.utc), "machine", "m_ci",
             "grant.revoke", "agent", "issue-reporter", "{}"),
        )


def test_the_widened_kind_checks_accept_machine_in_the_column(pg):
    """The other direction, and it is worth asserting for the reason the migration
    carries an assertion of its own: the live constraint names were **not** the ones
    migration 030's source text implies — every CHECK it declared inline landed with a
    `1` suffix, because the rename that preceded it took the old names along. A `DROP
    CONSTRAINT IF EXISTS` against the wrong spelling is silent, and the first machine
    denial would then fail against a control 031 believed it had widened.
    """
    store, tenant_id = pg

    store._execute(
        store._DENIAL_INSERT,
        (tenant_id, 1, datetime.now(timezone.utc), "machine", "m_ci",
         "agent", "payroll-bot", "user", ""),
    )

    assert store.denial_records(tenant_id)[0]["principal_kind"] == "machine"


# --- what the edge hunt found -----------------------------------------------------
#
# Step 021's hunt, and every one of these is a question asked of **both** stores at once.
# That is not a style: each was a place where one store answered and the other refused,
# or where both answered and they disagreed — and none of them was reachable from the
# routes, which is why reading the code found them and the suite did not.


def test_a_negative_limit_is_refused_rather_than_silently_truncating(store, tenant):
    """**The fake was returning a truncated history and calling it a whole one.**

    `rows[:-1]` drops the oldest version and reports success; Postgres refuses a negative
    LIMIT outright. So the same call returned plausible-but-wrong data from one store and
    an error from the other, which is the drift direction that survives review.
    """
    store.save_agent(tenant, AGENT, actor="system:cli")
    _edit(store, tenant, system="Second.")

    with pytest.raises(StorageError, match="non-negative"):
        store.list_agent_versions(tenant, "issue-reporter", limit=-1)

    # Zero is legal in both and means what it says.
    assert store.list_agent_versions(tenant, "issue-reporter", limit=0) == []


@pytest.mark.parametrize("limit", [None, 2.5, True, 2**63], ids=["none", "float", "bool", "huge"])
def test_a_limit_that_is_not_a_count_is_refused(store, tenant, limit):
    """`None` is the interesting one: a Python slice and `LIMIT NULL` both read it as
    *everything*, so the two stores agreed — by accident, and on defeating the cap."""
    store.save_agent(tenant, AGENT, actor="system:cli")

    with pytest.raises(StorageError):
        store.list_agent_versions(tenant, "issue-reporter", limit=limit)


@pytest.mark.parametrize("version", ["1", 1.0, True], ids=["string", "float", "bool"])
def test_a_version_number_that_is_not_an_integer_is_refused(store, tenant, version):
    """**Postgres answered and the fake did not.** A text literal is cast to compare it
    against an `integer` column, so `get_agent_version(t, n, "1")` returned the row from
    Postgres and `None` from a dict keyed by `int` — an answer from one store and an
    absence from the other, for a caller that is simply confused."""
    store.save_agent(tenant, AGENT, actor="system:cli")

    with pytest.raises(StorageError, match="must be an integer"):
        store.get_agent_version(tenant, "issue-reporter", version)


def test_a_restore_naming_a_version_that_never_existed_is_refused(store, tenant):
    """Unreachable through `agents.restore`, which reads the version first — and refused
    anyway, on `check_prune_batch`'s reason: this is a public storage method and the next
    caller will not know that. Postgres says it with a self-referential foreign key; the
    fake says it by hand, and both produce `ValueRefused` rather than a 503."""
    store.save_agent(tenant, AGENT, actor="system:cli")
    row = store.get_agent(tenant, "issue-reporter")

    for absent in (99, -5, 0):
        with pytest.raises(ValueRefused, match="cannot have come from it"):
            store.update_agent(
                tenant,
                {**AGENT, "system": f"restored from {absent}"},
                actor="user:u-1",
                if_unchanged_since=row["updated_at"],
                restored_from=absent,
            )

    # And nothing was written by any of them.
    assert [r["version"] for r in store.list_agent_versions(tenant, "issue-reporter")] == [1]


def test_a_version_number_reused_with_a_different_config_is_refused_loudly(store, tenant):
    """**The one that would have been a silent lie.**

    The suppression rests on the counter and the history agreeing: a conflict on the
    primary key is supposed to mean *this write changed nothing*, so the row already
    there holds this exact config. Forced out of step, the conflict fires on a different
    config instead — and `ON CONFLICT DO NOTHING` kept the old row, leaving the live
    configuration recorded nowhere while the history claimed to hold it. That is the one
    state this entire step exists to prevent, produced by the mechanism meant to prevent
    it.

    Reached past the protocol on purpose, the way this file already reaches past Python
    to assert CHECK constraints by name.
    """
    store.save_agent(tenant, AGENT, actor="system:cli")
    if hasattr(store, "_agents"):
        # Keyed by `agent_id` since migration 035, so the row is reached through the
        # store's own name lookup rather than by subscripting with a name.
        store._agent_by_name(tenant, "issue-reporter")["version"] = 0
    else:
        store._execute(
            "UPDATE agents SET version = 0 WHERE tenant_id = %s AND name = %s",
            (tenant, "issue-reporter"),
        )
    row = store.get_agent(tenant, "issue-reporter")

    with pytest.raises(ValueRefused, match="already exists and holds a different"):
        store.update_agent(
            tenant,
            {**AGENT, "system": "this config would have been unrecorded"},
            actor="user:u-1",
            if_unchanged_since=row["updated_at"],
        )


def test_a_boolean_is_not_a_number_to_either_store(store, tenant):
    """**The one line where `!=` and `IS DISTINCT FROM` disagree.**

    Python says `True == 1`; jsonb says a boolean and a number are different types. So a
    config changing a field from `1` to `true` was a new version in Postgres and no
    version at all in the fake — a divergence in the version *number*, which is the value
    this step hands to a screen. Everything else about `!=` matched jsonb, which is why
    the fake compares through `configs_differ` rather than being rewritten.
    """
    store.save_agent(tenant, {**AGENT, "private_runs": 1}, actor="system:cli")
    store.save_agent(tenant, {**AGENT, "private_runs": True}, actor="system:cli")

    versions = store.list_agent_versions(tenant, "issue-reporter")
    assert [row["version"] for row in versions] == [2, 1]
    # And the other direction still agrees with jsonb: 1 and 1.0 are one number.
    store.save_agent(tenant, {**AGENT, "private_runs": True}, actor="system:cli")
    assert len(store.list_agent_versions(tenant, "issue-reporter")) == 2


UNSTORABLE = [
    ({"system": "before\x00after"}, "NUL byte"),
    ({"system": "\ud800"}, "surrogate"),
    ({"limits": {"max_calls": float("nan")}}, "not a JSON number"),
    ({"limits": {"max_calls": float("inf")}}, "not a JSON number"),
    ({"model": datetime.now(timezone.utc)}, "not a JSON value"),
    # **In a KEY, not a value**, and the two below are 035i's edge pass. The walk in
    # `check_config_is_storable` visited dict values and never dict keys, for as long as
    # it has existed — so `{"a\x00b": ...}` passed a function whose own sentence is *a
    # NUL, or a lone surrogate, in any string*, and arrived at Postgres as a 503 about a
    # request that will never work.
    #
    # It survived because until 035i **no config key had ever come from a person**: every
    # key in every config was written by the code. A JSON Schema's `properties` are dict
    # keys, the schema editor is a textarea, and `"\u0000"` is four characters somebody
    # can paste — so the hole became reachable and the fix is one line.
    ({"output": {"schema": {"type": "object", "additionalProperties": False,
                            "properties": {"a\x00b": {"type": "string"}}}}}, "NUL byte"),
    ({"output": {"schema": {"type": "object", "additionalProperties": False,
                            "properties": {"a\ud800b": {"type": "string"}}}}}, "surrogate"),
]


@pytest.mark.parametrize(
    "extra,why",
    UNSTORABLE,
    ids=["nul", "surrogate", "nan", "inf", "datetime", "nul-in-a-key", "surrogate-in-a-key"],
)
def test_a_config_postgres_could_not_hold_is_refused_by_both(store, tenant, extra, why):
    """**The fake catching up to the real store**, which is the direction parity gets
    fixed in this project.

    Every one of these was stored happily by a dict and refused by a `jsonb` column — so
    the in-memory suite was green on configs that fail in a deployment, and the deployment
    answered *"storage unavailable: try again later"* about a request that will never
    work. The `datetime` was worse: `json.dumps` raised `TypeError`, which is not a
    `StorageError` and not anything a caller can catch.

    `NaN` also broke the version counter specifically and silently: `nan != nan`, so the
    fake saw every re-seed of such a config as a change and grew a version per boot —
    the exact failure the suppression exists to prevent, invisible to the test that pins
    it.
    """
    with pytest.raises(StorageError, match=why):
        store.save_agent(tenant, {**AGENT, **extra}, actor="system:cli")

    assert store.get_agent(tenant, "issue-reporter") is None


def test_the_storable_check_lets_an_ordinary_config_through(store, tenant):
    """The guard above refuses a great deal; this is the assertion that it refuses
    nothing else. Every JSON-native shape, nested."""
    config = {
        **AGENT,
        "limits": {"max_calls": 3},
        "model": None,
        "private_runs": False,
        "default_task": "Ünïcödé — 日本語 — 🙂",
        "deny_demo_task": {"nested": [1, 1.5, "x", None, True, {"deeper": []}]},
    }

    store.save_agent(tenant, config, actor="system:cli")

    assert store.get_agent_version(tenant, "issue-reporter", 1)["config"] == config


def test_a_refused_version_write_leaves_the_config_alone_in_both_stores(store, tenant):
    """**The fake's transaction story, asserted for the first time.**

    `test_a_write_whose_record_is_refused_leaves_nothing_behind` proves this for Postgres
    by forcing a constraint violation, and it is Postgres-only for that reason — so the
    property has never been checked in the store every test runs against by default.

    Step 021 broke it and this is how it was found: `update_agent` wrote the agent dict
    and then called a version write that could refuse, leaving the config changed with no
    version recorded. Postgres rolls back and the fake had nothing to roll back with, so
    the refusals moved ahead of the first mutation instead.
    """
    store.save_agent(tenant, AGENT, actor="system:cli")
    row = store.get_agent(tenant, "issue-reporter")

    with pytest.raises(ValueRefused):
        store.update_agent(
            tenant,
            {**AGENT, "system": "this must not land"},
            actor="user:u-1",
            if_unchanged_since=row["updated_at"],
            restored_from=99,
        )

    after = store.get_agent(tenant, "issue-reporter")
    assert after["config"] == AGENT
    assert after["version"] == 1
    # And the ETag did not move either, so the caller's next write is not mysteriously
    # stale — which is what makes the refusal retryable rather than a dead end.
    assert after["updated_at"] == row["updated_at"]
    assert [r["version"] for r in store.list_agent_versions(tenant, "issue-reporter")] == [1]
    assert len(store.admin_audit_records(tenant, action="agent.restore")) == 0


def test_updating_an_unknown_tenant_diverges_and_that_is_a_known_gap(store, tenant):
    """**Probed and recorded rather than fixed**, on 020's precedent for edges whose fix
    re-decides an earlier step.

    The fake calls `_require_tenant` and raises; Postgres never does, so its UPDATE
    matches nothing and returns `None`. Both are defensible — `update_agent`'s own
    docstring says absent and stale are deliberately indistinguishable, which argues for
    `None`, while every other write in the fake refuses an unknown tenant loudly.

    Pinned so the divergence is visible rather than discovered, and left alone because
    either direction changes a 10d method that has shipped: making Postgres raise adds a
    read to the compare-and-set's one statement, and making the fake return `None`
    weakens a guard nothing else has asked to weaken.
    """
    from carnet.storage.memory import InMemoryStorage

    write = lambda: store.update_agent(  # noqa: E731
        "no-such-tenant", AGENT, actor="user:u-1",
        if_unchanged_since=datetime.now(timezone.utc),
    )

    if isinstance(store, InMemoryStorage):
        with pytest.raises(UnknownTenantError):
            write()
    else:
        assert write() is None


def test_what_was_live_at_a_past_instant(store, tenant):
    """**The question the whole design turns on, asked directly.**

    Decision 3 chose "a restore writes a new version" over "a pointer moves back" on
    exactly one argument: a moving pointer makes the timeline non-monotonic, so *what was
    live on Tuesday* stops being an interval lookup and needs a second log recording every
    move. Everything else in this file tests the mechanism; this tests the property the
    mechanism exists for, and it is the plan's verification 5.

    The lookup is the whole claim: version N was live from its `created_at` until N+1's,
    so the version live at an instant is the newest one created at or before it. That
    holds only while version numbers and timestamps agree about order — which is what a
    pointer moving backwards would end.

    **Asserted across a restore**, because that is the only moment the two designs differ:
    v4 holds v1's *content* and is a later state than v3, and an instant during v2 must
    still answer v2 rather than "the version whose config is live now".
    """
    def live_at(instant):
        history = store.list_agent_versions(tenant, "issue-reporter", limit=100)
        older = [row for row in history if row["created_at"] <= instant]
        if not older:
            return None
        newest = max(older, key=lambda row: row["created_at"])
        return store.get_agent_version(tenant, "issue-reporter", newest["version"])

    store.save_agent(tenant, AGENT, actor="system:cli")
    was_v1 = store.get_agent(tenant, "issue-reporter")["updated_at"]

    _edit(store, tenant, system="The second thing it said.")
    was_v2 = store.get_agent(tenant, "issue-reporter")["updated_at"]

    _edit(store, tenant, system="The third thing it said.")
    was_v3 = store.get_agent(tenant, "issue-reporter")["updated_at"]

    # The restore: v4 carries v1's content, and v1, v2 and v3 do not move.
    _edit(store, tenant, system=AGENT["system"], restored_from=1)
    was_v4 = store.get_agent(tenant, "issue-reporter")["updated_at"]

    assert live_at(was_v1)["config"]["system"] == "You read issues."
    assert live_at(was_v2)["config"]["system"] == "The second thing it said."
    assert live_at(was_v3)["config"]["system"] == "The third thing it said."
    assert live_at(was_v4)["config"]["system"] == "You read issues."

    # And the two that carry identical content are still distinguishable, which is what
    # a pointer moving back would have destroyed: same config, different instants,
    # different version numbers, in order.
    assert live_at(was_v1)["version"] == 1
    assert live_at(was_v4)["version"] == 4
    assert live_at(was_v4)["restored_from"] == 1

    # Before the agent existed there is nothing to answer with — not "the oldest one".
    before_everything = was_v1 - timedelta(days=1)
    assert live_at(before_everything) is None

    # The ordering the lookup rests on: version numbers and timestamps agree.
    history = store.list_agent_versions(tenant, "issue-reporter", limit=100)
    by_number = [row["version"] for row in history]
    by_time = [
        row["version"] for row in sorted(history, key=lambda r: r["created_at"], reverse=True)
    ]
    assert by_number == by_time == [4, 3, 2, 1]

# A fresh token id per call. **Not `_token_id(tenant, suffix)`** — that builds
# `m_<tenant><suffix>` and truncates to 64, so a long parametrised test name eats the
# suffix and two params collide on one id. Found by three Postgres failures that named
# an id ending in the middle of a pytest node name.
_SCHEDULE_SEQUENCE = itertools.count()


def _schedule_token(store, tenant):
    """Mint a token this tenant can schedule, with an id nothing else will claim."""
    token_id = f"m_sch{next(_SCHEDULE_SEQUENCE)}_{abs(hash(tenant)) % 100000}"
    store.create_api_token(
        tenant,
        {"id": token_id, "name": f"ci-{token_id}", "owner_id": "u-1",
         "secret_hash": "sha256$abc"},
        actor="system:cli",
    )
    return token_id


def _fresh_schedule_id(tenant):
    return f"sch{next(_SCHEDULE_SEQUENCE)}_{abs(hash(tenant)) % 100000}"


# --- the MCP door's per-token budget, migration 040 ----------------------------------
#
# Both stores, and this family is the reason that rule exists. The ceiling is one
# `INSERT ... ON CONFLICT DO UPDATE ... WHERE` in Postgres and a compare under a lock in
# memory — the same shape as the schedule CAS below, which is to say the shape that
# agrees right up until it does not.
#
# It is also 033a's lesson taken early. That step's plan claimed no migration was needed
# because the in-memory store keeps manifests whole and masked a missing column until an
# e2e ran against Postgres. Here the table is new, so the contract tests come with it.

_WINDOW = date(2026, 8, 21)
_NEXT_WINDOW = date(2026, 8, 22)


def _budget_token(store, tenant):
    token_id = _token_id(tenant, "_budget")
    store.create_api_token(tenant, _token(tenant, id=token_id), actor=TEST_ACTOR)
    return token_id


def test_spending_a_door_call_counts_up_from_nothing(store, tenant):
    token_id = _budget_token(store, tenant)

    assert store.mcp_calls_spent(tenant, token_id, _WINDOW) == 0
    assert store.spend_mcp_call(tenant, token_id, _WINDOW, ceiling=3) == 1
    assert store.spend_mcp_call(tenant, token_id, _WINDOW, ceiling=3) == 2
    assert store.mcp_calls_spent(tenant, token_id, _WINDOW) == 2


def test_the_ceiling_refuses_and_writes_nothing(store, tenant):
    """**The refusal must not also be a spend.**

    A refused call that still incremented would make the ceiling a moving target: a
    client retrying against a wall would push its own window further out, and the count
    an operator reads would be of attempts rather than of calls admitted. The broker
    makes the same promise one layer up — `Budget.reserve` consumes nothing on a denial —
    and this is that promise where it is actually written down.
    """
    token_id = _budget_token(store, tenant)

    assert store.spend_mcp_call(tenant, token_id, _WINDOW, ceiling=2) == 1
    assert store.spend_mcp_call(tenant, token_id, _WINDOW, ceiling=2) == 2
    assert store.spend_mcp_call(tenant, token_id, _WINDOW, ceiling=2) is None
    assert store.spend_mcp_call(tenant, token_id, _WINDOW, ceiling=2) is None

    assert store.mcp_calls_spent(tenant, token_id, _WINDOW) == 2


def test_a_lowered_ceiling_bites_immediately_and_a_raised_one_frees(store, tenant):
    """The dial is read per call, never captured — so `CARNET_MCP_CALLS_PER_DAY` is a
    knob an operator turns mid-incident rather than one that takes a restart and a new
    window to mean anything."""
    token_id = _budget_token(store, tenant)

    for _ in range(3):
        store.spend_mcp_call(tenant, token_id, _WINDOW, ceiling=10)

    assert store.spend_mcp_call(tenant, token_id, _WINDOW, ceiling=3) is None
    assert store.spend_mcp_call(tenant, token_id, _WINDOW, ceiling=4) == 4


def test_each_window_counts_alone(store, tenant):
    token_id = _budget_token(store, tenant)

    store.spend_mcp_call(tenant, token_id, _WINDOW, ceiling=1)
    assert store.spend_mcp_call(tenant, token_id, _WINDOW, ceiling=1) is None

    # Tomorrow is a fresh row, and yesterday's is left where it is: it is the only
    # record of what this credential did, which is what an offboarding review asks for.
    assert store.spend_mcp_call(tenant, token_id, _NEXT_WINDOW, ceiling=1) == 1
    assert store.mcp_calls_spent(tenant, token_id, _WINDOW) == 1


def test_two_tokens_do_not_share_a_budget(store, tenant):
    first = _budget_token(store, tenant)
    second = _token_id(tenant, "_budget2")
    store.create_api_token(
        tenant, _token(tenant, id=second, name="other-ci"), actor=TEST_ACTOR
    )

    store.spend_mcp_call(tenant, first, _WINDOW, ceiling=1)

    assert store.spend_mcp_call(tenant, first, _WINDOW, ceiling=1) is None
    assert store.spend_mcp_call(tenant, second, _WINDOW, ceiling=1) == 1


def test_two_customers_do_not_share_a_budget(store, tenant, other):
    """The isolation assertion every method here carries, at a table whose primary key
    is (tenant, token, window) — so a store that dropped the tenant from the key would
    still pass every test above."""
    mine = _budget_token(store, tenant)
    theirs = _token_id(other, "_budget")
    store.create_api_token(other, _token(other, id=theirs), actor=TEST_ACTOR)

    store.spend_mcp_call(tenant, mine, _WINDOW, ceiling=1)

    assert store.mcp_calls_spent(other, theirs, _WINDOW) == 0
    assert store.spend_mcp_call(other, theirs, _WINDOW, ceiling=1) == 1


def test_a_revoked_token_keeps_its_counter(store, tenant):
    """Revocation closes a door and deletes no evidence — migration 031's rule, which
    this table inherits by not doing anything. What a revoked credential spent today is
    exactly the question somebody asks *after* revoking it."""
    token_id = _budget_token(store, tenant)
    store.spend_mcp_call(tenant, token_id, _WINDOW, ceiling=5)

    store.revoke_api_token(tenant, token_id, actor=TEST_ACTOR)

    assert store.mcp_calls_spent(tenant, token_id, _WINDOW) == 1


def test_deleting_a_customer_takes_their_budget_rows(store, tenant):
    """Postgres gets this from the cascade on `mcp_budget.tenant_id`; the in-memory store
    gets it from a loop somebody has to remember to add. That asymmetry is the exact
    shape of drift this suite exists to catch — a fake that KEEPS what Postgres removes —
    and the "nothing left behind" walk is what would have caught it a second way."""
    token_id = _budget_token(store, tenant)
    store.spend_mcp_call(tenant, token_id, _WINDOW, ceiling=5)

    store.set_tenant_status(tenant, "suspended")
    store.delete_tenant(tenant, actor=TEST_ACTOR)

    # Read back against the id that is now gone. A tenant id is never reused (see
    # `tenant_tombstones`), so this is the only way to ask the question — and it is the
    # right way round: a store that kept the row answers 1 here.
    assert store.mcp_calls_spent(tenant, token_id, _WINDOW) == 0


# --- the range read the browser uses, step 035e --------------------------------------
#
# `mcp_call_windows` is `mcp_calls_spent`'s range sibling and the first read of this
# table with a caller outside this suite. Pinned here rather than in `test_api.py`
# because `tests/test_api.py` is **memory-store only** — `isolated_storage` is an
# `InMemoryStorage` and nothing parametrises it — so a route test proves nothing about
# Postgres, a real DATE column, or RLS. Four chunks running (035a's `audit` value drift,
# 035b's `access_denials`, 035c's `list_api_tokens` ordering, 035d's collation) each
# found a real store disagreement by looking exactly here.
#
# The property that has to hold in both stores and would be easy to get wrong in one:
# **sparse**. A window nothing was spent in has no row, and neither store invents one —
# the zero-fill is the route's, on `mcp_calls_spent`'s documented "0 when there is no
# row". A fake that filled gaps would be kinder than Postgres, which is the drift this
# file exists to catch rather than a convenience.

_WEEK_AGO = date(2026, 8, 15)


def test_the_window_range_is_sparse_and_oldest_first(store, tenant):
    """The two properties a page depends on, and the one it must not get from here."""
    token_id = _budget_token(store, tenant)

    # Deliberately written out of order, so a store answering in insertion order rather
    # than by window passes only by accident.
    store.spend_mcp_call(tenant, token_id, date(2026, 8, 20), ceiling=10)
    store.spend_mcp_call(tenant, token_id, date(2026, 8, 17), ceiling=10)
    store.spend_mcp_call(tenant, token_id, date(2026, 8, 17), ceiling=10)

    assert store.mcp_call_windows(
        tenant, token_id, since=_WEEK_AGO, until=_WINDOW
    ) == [
        {"window_start": "2026-08-17", "calls": 2},
        {"window_start": "2026-08-20", "calls": 1},
    ]


def test_the_bounds_are_inclusive_at_both_ends(store, tenant):
    """A half-open range would silently drop **today** — the one window the page's whole
    question is about — and would do it only on the day somebody looked."""
    token_id = _budget_token(store, tenant)

    for window in (_WEEK_AGO, date(2026, 8, 18), _WINDOW):
        store.spend_mcp_call(tenant, token_id, window, ceiling=10)

    inside = store.mcp_call_windows(tenant, token_id, since=_WEEK_AGO, until=_WINDOW)
    assert [row["window_start"] for row in inside] == [
        "2026-08-15",
        "2026-08-18",
        "2026-08-21",
    ]

    # And a window outside the range is excluded rather than clamped in.
    store.spend_mcp_call(tenant, token_id, date(2026, 8, 14), ceiling=10)
    store.spend_mcp_call(tenant, token_id, _NEXT_WINDOW, ceiling=10)

    assert store.mcp_call_windows(
        tenant, token_id, since=_WEEK_AGO, until=_WINDOW
    ) == inside


def test_a_token_that_has_spent_nothing_has_no_windows(store, tenant):
    """An empty list, not a row of zeros. Absence is the table's answer and the route is
    where it becomes a dense series — see `SpentWindow`."""
    token_id = _budget_token(store, tenant)

    assert store.mcp_call_windows(tenant, token_id, since=_WEEK_AGO, until=_WINDOW) == []


def test_a_single_day_range_answers_that_day_alone(store, tenant):
    """`since == until`, which is what a one-window read looks like and what an
    off-by-one in either bound would break."""
    token_id = _budget_token(store, tenant)

    store.spend_mcp_call(tenant, token_id, _WINDOW, ceiling=10)
    store.spend_mcp_call(tenant, token_id, _NEXT_WINDOW, ceiling=10)

    assert store.mcp_call_windows(
        tenant, token_id, since=_WINDOW, until=_WINDOW
    ) == [{"window_start": "2026-08-21", "calls": 1}]


def test_one_tokens_windows_are_not_anothers(store, tenant):
    """The primary key is three columns and the range only bounds one of them, so a
    store that dropped `token_id` from the predicate would still pass every test above
    — every one of them has a single token in the tenant."""
    mine = _budget_token(store, tenant)
    theirs = _token_id(tenant, "_budget2")
    store.create_api_token(
        tenant, _token(tenant, id=theirs, name="other-ci"), actor=TEST_ACTOR
    )

    store.spend_mcp_call(tenant, mine, _WINDOW, ceiling=10)
    for _ in range(4):
        store.spend_mcp_call(tenant, theirs, _WINDOW, ceiling=10)

    assert store.mcp_call_windows(tenant, mine, since=_WEEK_AGO, until=_WINDOW) == [
        {"window_start": "2026-08-21", "calls": 1}
    ]
    assert store.mcp_call_windows(tenant, theirs, since=_WEEK_AGO, until=_WINDOW) == [
        {"window_start": "2026-08-21", "calls": 4}
    ]


def test_another_customers_windows_are_invisible(store, tenant, other):
    """The isolation assertion every method here carries. Postgres gets it from RLS and
    the tenant in the predicate; the fake gets it from a comparison somebody has to
    remember to write."""
    mine = _budget_token(store, tenant)
    theirs = _token_id(other, "_budget")
    store.create_api_token(other, _token(other, id=theirs), actor=TEST_ACTOR)

    store.spend_mcp_call(other, theirs, _WINDOW, ceiling=10)

    assert store.mcp_call_windows(tenant, mine, since=_WEEK_AGO, until=_WINDOW) == []
    # And the token id alone does not reach across, which is the shape a range read
    # makes newly easy to get wrong: the tenant is the first key column and the one a
    # `WHERE` clause written from the question ("this token's windows") would omit.
    assert store.mcp_call_windows(tenant, theirs, since=_WEEK_AGO, until=_WINDOW) == []


def test_a_revoked_token_keeps_its_windows(store, tenant):
    """`test_a_revoked_token_keeps_its_counter`'s property through the method a page
    actually calls. *What was that credential spending before I killed it* is asked
    after a revocation, not before one — so a range read that filtered revoked tokens
    would be empty for exactly the reader who came for it."""
    token_id = _budget_token(store, tenant)
    store.spend_mcp_call(tenant, token_id, _WINDOW, ceiling=10)

    store.revoke_api_token(tenant, token_id, actor=TEST_ACTOR)

    assert store.mcp_call_windows(tenant, token_id, since=_WEEK_AGO, until=_WINDOW) == [
        {"window_start": "2026-08-21", "calls": 1}
    ]


def test_a_window_start_is_an_iso_string_in_both_stores(store, tenant):
    """The coercion, asserted as a type rather than inferred from the equalities above.

    psycopg hands back a `datetime.date` and the fake holds one as a dict key, so
    without the `.isoformat()` on both sides this method would return a `date` object
    that pydantic would happily coerce — and the two stores would agree in this suite
    while a JSON body and a browser saw something else. 033a's lesson: the fake keeping
    a shape whole is what hid a missing column until an e2e ran."""
    token_id = _budget_token(store, tenant)
    store.spend_mcp_call(tenant, token_id, _WINDOW, ceiling=10)

    (row,) = store.mcp_call_windows(tenant, token_id, since=_WEEK_AGO, until=_WINDOW)

    assert isinstance(row["window_start"], str)
    assert isinstance(row["calls"], int)
    assert sorted(row) == ["calls", "window_start"]


def test_deleting_a_customer_takes_their_windows(store, tenant):
    """The cascade, through the second reader. Postgres gets it from
    `mcp_budget.tenant_id`; the fake gets it from a loop somebody has to remember."""
    token_id = _budget_token(store, tenant)
    store.spend_mcp_call(tenant, token_id, _WINDOW, ceiling=5)

    store.set_tenant_status(tenant, "suspended")
    store.delete_tenant(tenant, actor=TEST_ACTOR)

    assert store.mcp_call_windows(tenant, token_id, since=_WEEK_AGO, until=_WINDOW) == []


# --- schedules, migration 033 --------------------------------------------------------
#
# Both stores, because the fake is the one every other test in this repository runs
# against — and because the compare-and-set below is a *statement* in Postgres and a
# comparison under a lock in memory, which is exactly the shape that agrees until it
# does not. A mutation that made the Postgres CAS blind survived the whole suite before
# these existed.


def test_a_schedule_round_trips(store, tenant):
    row = _schedule_for(store, tenant, _schedule_token(store, tenant), _fresh_schedule_id(tenant))

    assert set(row) == set(SCHEDULE_FIELDS)
    assert row["cadence"] == _HOURLY
    assert row["timezone"] == "Europe/Berlin"
    assert row["enabled"] is True
    assert row["next_fire_at"] == _SOON
    assert row["last_fired_at"] is None
    assert row["last_run_id"] == ""
    assert row["last_outcome"] == ""

    assert store.get_schedule(tenant, row["id"]) == row
    assert store.list_schedules(tenant) == [row]
    assert store.list_schedules(tenant, agent_name="issue-reporter") == [row]
    assert store.list_schedules(tenant, agent_name="somebody-else") == []


def test_a_schedule_edit_moves_only_what_it_names(store, tenant):
    """Step 035k. The four fields that move, and everything else standing still — because
    a patch that quietly reset `last_outcome` or `enabled` would be a delete-and-recreate
    wearing an edit's clothes, which is the thing this verb exists not to be."""
    row = _schedule_for(store, tenant, _schedule_token(store, tenant), _fresh_schedule_id(tenant))

    edited = store.update_schedule(
        tenant,
        row["id"],
        {"task": "a different question"},
        actor="user:u-1",
        if_unchanged_since=row["updated_at"],
    )

    assert set(edited) == set(SCHEDULE_FIELDS)
    assert edited["task"] == "a different question"
    assert edited["id"] == row["id"], "an edit keeps the id — that is the whole verb"
    assert edited["cadence"] == row["cadence"]
    assert edited["timezone"] == row["timezone"]
    assert edited["token_id"] == row["token_id"]
    assert edited["enabled"] == row["enabled"]
    assert edited["next_fire_at"] == row["next_fire_at"], "a task change does not move the clock"
    assert edited["created_at"] == row["created_at"]
    assert edited["created_by"] == row["created_by"]
    # The validator advanced, which is what makes the next edit conditional on this one.
    assert edited["updated_at"] > row["updated_at"]
    assert store.get_schedule(tenant, row["id"]) == edited


def test_a_schedule_edit_is_a_compare_and_set_in_both_stores(store, tenant):
    """**The shape that agrees until it does not.** In Postgres this is `AND updated_at =
    %s` inside one statement; in memory it is a comparison under a lock. A mutation that
    made either one blind is a lost update — one editor silently reverting another — and
    it would survive every other test in this file."""
    row = _schedule_for(store, tenant, _schedule_token(store, tenant), _fresh_schedule_id(tenant))
    stale = row["updated_at"]

    first = store.update_schedule(
        tenant, row["id"], {"task": "first"}, actor="user:u-1", if_unchanged_since=stale
    )
    assert first is not None

    # The second write, built on the version the first one replaced.
    assert (
        store.update_schedule(
            tenant, row["id"], {"task": "second"}, actor="user:u-1", if_unchanged_since=stale
        )
        is None
    )
    # And it wrote nothing — the log holds changes rather than attempts.
    assert store.get_schedule(tenant, row["id"])["task"] == "first"
    assert len(store.admin_audit_records(tenant, action="schedule.update")) == 1


def test_a_schedule_update_record_names_the_keys_and_never_the_task(store, tenant):
    """`schedule.create`'s redaction rule at the same table, and migration 022's one
    column over: a record is forever, and a schedule's task is `default_task`'s content
    wearing a different key."""
    row = _schedule_for(store, tenant, _schedule_token(store, tenant), _fresh_schedule_id(tenant))

    store.update_schedule(
        tenant,
        row["id"],
        {"task": "a secret question about payroll", "timezone": "Asia/Tokyo"},
        actor="user:u-1",
        if_unchanged_since=row["updated_at"],
    )

    (record,) = store.admin_audit_records(tenant, action="schedule.update")
    assert record["detail"]["changed"] == ["task", "timezone"]
    assert record["detail"]["timezone"] == "Asia/Tokyo"
    assert "payroll" not in str(record), "the task must never reach an administrative record"


def test_an_edit_naming_a_token_that_does_not_exist_is_refused_by_both_stores(
    store, tenant
):
    """A caller error, so `ValueRefused` and never a bare `StorageError` — the composite
    foreign key in Postgres and the same check by hand in the fake. This is the
    wrong-refusal-family shape at its seventh possible address, closed on arrival."""
    row = _schedule_for(store, tenant, _schedule_token(store, tenant), _fresh_schedule_id(tenant))

    with pytest.raises(ValueRefused):
        store.update_schedule(
            tenant,
            row["id"],
            {"token_id": "m_not_a_token"},
            actor="user:u-1",
            if_unchanged_since=row["updated_at"],
        )


@pytest.mark.parametrize(
    "changes",
    [
        {},
        {"task": ""},
        {"task": "a\x00b"},
        {"cadence": {"every": "fortnight", "at": "07:30"}},
        {"cadence": {"every": "day", "at": "not a time"}},
        {"cadence": {"every": "day", "at": "07:30", "note": "a\x00b"}},
        {"timezone": "Mars/Olympus"},
        {"timezone": ""},
        {"token_id": ""},
    ],
    ids=[
        "empty", "blank-task", "nul-task", "unknown-arm", "bad-time",
        "nul-in-cadence", "unknown-zone", "blank-zone", "blank-token",
    ],
)
def test_both_stores_refuse_the_same_bad_edit(store, tenant, changes):
    """`test_both_stores_refuse_the_same_bad_schedule`'s twin at the second door into the
    same four columns. **`ValueRefused` specifically, not `StorageError`**, because that
    class subclasses this one — so a `pytest.raises(StorageError)` here would assert only
    that *something* refused, which is exactly the reason the contract suite could not
    see the last two wrong-family defects."""
    row = _schedule_for(store, tenant, _schedule_token(store, tenant), _fresh_schedule_id(tenant))

    with pytest.raises(ValueRefused):
        store.update_schedule(
            tenant, row["id"], changes, actor="user:u-1", if_unchanged_since=row["updated_at"]
        )
    # And nothing moved.
    assert store.get_schedule(tenant, row["id"])["updated_at"] == row["updated_at"]


@pytest.mark.parametrize("blob", [b"plain", bytearray(b"array"), memoryview(b"view")],
                         ids=["bytes", "bytearray", "memoryview"])
def test_a_rotation_stores_bytes_whatever_bytes_like_it_is_given(store, tenant, blob):
    """**A defect this chunk shipped and its own contract test missed**, because that test
    passed a `bytes` literal and the divergence only appears for the other two.

    `normalize_trigger` does `bytes(...)` at create and `reseal_trigger_secret` does it at
    the key sweep. `rotate_trigger_secret` did not — so the fake kept a `bytearray` as one
    and Postgres stored `bytes`, which is precisely the class this file exists to catch.

    The `memoryview` case was worse than a divergence: `_trigger_out` deep-copies every
    field and `copy.deepcopy` raises `TypeError: cannot pickle memoryview objects`, an
    exception escaping the storage boundary as neither `StorageError` nor anything a
    caller can catch. That door was opened by widening `check_sealed_secret` to accept
    `memoryview` for parity with `check_reseal` — **widening what a guard admits without
    widening what the write normalises is how a consistency fix becomes a crash.**
    """
    row = _trigger_for(store, tenant, _schedule_token(store, tenant), _fresh_trigger_id(tenant))

    rotated = store.rotate_trigger_secret(
        tenant, row["id"], secret_sealed=blob, secret_key_id="k9999999", actor="user:u-1"
    )

    assert type(rotated["secret_sealed"]) is bytes, "both stores hold this column as bytes"
    assert rotated["secret_sealed"] == bytes(blob)
    # And it survives a read, which is where the memoryview crash actually landed.
    assert store.get_trigger(tenant, row["id"])["secret_sealed"] == bytes(blob)


def test_an_update_record_names_only_the_fields_that_actually_moved(store, tenant):
    """**The log must not claim a change that did not happen.**

    A `PATCH` that sets fields to the values they already hold is legal — it is how a
    client re-sending a whole form behaves — and the first version of this recorded all
    four as changed. In an append-only record read years later that is a false hit for the
    one question this row exists to answer: *who changed the machine this fires as*.

    `ScheduleChanged` already computed a real diff for its 409 body, so the log was the
    only half of the chunk that lied.
    """
    row = _schedule_for(store, tenant, _schedule_token(store, tenant), _fresh_schedule_id(tenant))
    everything_unchanged = {
        "task": row["task"],
        "cadence": row["cadence"],
        "timezone": row["timezone"],
        "token_id": row["token_id"],
    }

    store.update_schedule(tenant, row["id"], everything_unchanged,
                          actor="user:u-1", if_unchanged_since=row["updated_at"])

    (record,) = store.admin_audit_records(tenant, action="schedule.update")
    assert record["detail"]["changed"] == []
    # And the three value-bearing keys stay out too, or the same claim returns one key over.
    assert "cadence" not in record["detail"]
    assert "timezone" not in record["detail"]
    assert "fires_as" not in record["detail"]
    # The act is still recorded and the stamp still moves — `update_agent`'s precedent,
    # which writes a record for a save that changed nothing and no version row.
    assert store.get_schedule(tenant, row["id"])["updated_at"] > row["updated_at"]


def test_a_partly_unchanged_update_records_only_the_moving_half(store, tenant):
    """The mixed case, which is the one a re-sent form actually produces."""
    row = _schedule_for(store, tenant, _schedule_token(store, tenant), _fresh_schedule_id(tenant))

    store.update_schedule(
        tenant, row["id"],
        {"task": "something genuinely different", "timezone": row["timezone"]},
        actor="user:u-1", if_unchanged_since=row["updated_at"],
    )

    (record,) = store.admin_audit_records(tenant, action="schedule.update")
    assert record["detail"]["changed"] == ["task"]
    assert "timezone" not in record["detail"], "a re-sent zone is not a zone change"
    assert "something genuinely different" not in str(record), "and the task never appears"


def test_only_whitelisted_columns_can_reach_the_update_statement(store, tenant):
    """**The one thing standing between `update_schedule` and a SQL injection.**

    Postgres builds its `SET` clause by interpolating the keys of `changes` — SQL does not
    allow an identifier to be parameterised, so there is no alternative — which means the
    whitelist in `normalize_schedule_changes` is load-bearing rather than tidy. Pinned
    here because the only other thing holding it is a comment.
    """
    from carnet.storage import SCHEDULE_PATCH_FIELDS

    row = _schedule_for(store, tenant, _schedule_token(store, tenant), _fresh_schedule_id(tenant))
    stamp = row["updated_at"]

    for hostile in (
        "task; DROP TABLE schedules --",
        "task = 'x', enabled",
        "enabled",
        "id",
        "tenant_id",
        "updated_at",
        "TASK",
        " task",
        "task ",
    ):
        with pytest.raises(StorageError):
            store.update_schedule(tenant, row["id"], {hostile: "x"},
                                  actor="user:u-1", if_unchanged_since=stamp)

    # The table is still there and the row is untouched — the point of the whole test.
    assert store.get_schedule(tenant, row["id"]) == row
    assert set(SCHEDULE_PATCH_FIELDS) == {"task", "cadence", "timezone", "token_id"}


def test_editing_a_schedule_that_is_not_there_is_none(store, tenant):
    from datetime import datetime, timezone as _tz

    assert (
        store.update_schedule(
            tenant,
            "sch_nothing",
            {"task": "x"},
            actor="user:u-1",
            if_unchanged_since=datetime.now(_tz.utc),
        )
        is None
    )


def test_the_runs_of_a_schedule_are_matched_by_key_prefix_in_both_stores(
    store, tenant, rid
):
    """**035k's first decision, asserted rather than argued.** There is no fire log and no
    `runs.schedule_id`; the linkage is the idempotency key every fire already writes. What
    this pins is that the prefix match is exact — a *different* schedule's runs and a
    caller-supplied key that merely looks similar must not be swept in."""
    from carnet.storage import schedule_key_prefix

    mine, theirs = "sch_mine12345678", "sch_theirs123456"

    store.enqueue_run(
        tenant, a_run(rid("1"), idempotency_key=schedule_key_prefix(mine) + "2026-01-01T07:30:00+00:00")
    )
    store.enqueue_run(
        tenant, a_run(rid("2"), idempotency_key=schedule_key_prefix(mine) + "2026-01-02T07:30:00+00:00")
    )
    store.enqueue_run(
        tenant, a_run(rid("3"), idempotency_key=schedule_key_prefix(theirs) + "2026-01-01T07:30:00+00:00")
    )
    # A run with no key at all, and one whose key is a *prefix of the prefix* — the
    # schedule id without its trailing colon, which would match under a sloppier LIKE.
    store.enqueue_run(tenant, a_run(rid("4")))
    store.enqueue_run(tenant, a_run(rid("5"), idempotency_key=f"sched:{mine}x:2026-01-01"))

    produced = store.runs_of_schedule(tenant, mine)

    # Newest first, `list_runs`' order and for its reason.
    assert [r["run_id"] for r in produced] == [rid("2"), rid("1")]
    assert store.runs_of_schedule(tenant, mine, limit=1) == [produced[0]]
    assert store.runs_of_schedule(tenant, "sch_nothing000000") == []


def test_the_runs_of_a_schedule_stop_at_the_tenant(store, tenant, rid):
    """The prefix is not the scope — `tenant_id` is, in the WHERE clause of both. A
    derivation that leaked across customers would be the cost of not having a column,
    and it is not one this pays."""
    from carnet.storage import schedule_key_prefix

    other = f"{tenant}-other"
    store.create_tenant(other, name="Other")
    key = schedule_key_prefix("sch_shared12345") + "2026-01-01T07:30:00+00:00"

    store.enqueue_run(tenant, a_run(rid("1"), idempotency_key=key))
    store.enqueue_run(other, a_run(rid("2"), idempotency_key=key))

    assert [r["run_id"] for r in store.runs_of_schedule(tenant, "sch_shared12345")] == [rid("1")]
    assert [r["run_id"] for r in store.runs_of_schedule(other, "sch_shared12345")] == [rid("2")]


def test_an_absent_schedule_is_none_rather_than_an_error(store, tenant):
    assert store.get_schedule(tenant, "sch_nothing") is None
    assert store.delete_schedule(tenant, "sch_nothing", actor="user:u-1") is False


def test_only_a_due_and_enabled_schedule_is_listed(store, tenant):
    row = _schedule_for(store, tenant, _schedule_token(store, tenant), _fresh_schedule_id(tenant))
    ids = lambda rows: [r["id"] for r in rows]

    # Not yet due.
    assert row["id"] not in ids(store.due_schedules(now=_SOON - timedelta(minutes=1)))
    # Due exactly on the instant: `<=`, because a boundary must have one answer and the
    # one that never fires is the wrong one to guess.
    assert row["id"] in ids(store.due_schedules(now=_SOON))
    assert row["id"] in ids(store.due_schedules(now=_SOON + timedelta(days=1)))

    # Disabled is never due, whatever the clock says.
    store.set_schedule_enabled(tenant, row["id"], False, next_fire_at=_SOON, actor="user:u-1")
    assert row["id"] not in ids(store.due_schedules(now=_SOON + timedelta(days=1)))


def test_due_schedules_defaults_to_the_stores_own_clock(store, tenant):
    """**The branch no test took.** Every other assertion in this file passes `now=`
    explicitly, and `fire_due` passes it too — so the default arm was dead in the suite
    and raised `NameError` against Postgres the first time a script called it, because
    `datetime` is not imported in that module.

    It now compares against `now()` on the same connection as the read, so a worker with
    a drifted host clock cannot decide what is due.
    """
    row = _schedule_for(store, tenant, _schedule_token(store, tenant), _fresh_schedule_id(tenant))

    # `_SOON` is 2030, so nothing is due by either clock.
    assert row["id"] not in [r["id"] for r in store.due_schedules()]

    store.advance_schedule(
        tenant, row["id"], if_next_fire_at=_SOON,
        next_fire_at=datetime.now(timezone.utc) - timedelta(minutes=1),
    )
    assert row["id"] in [r["id"] for r in store.due_schedules()]


def test_the_advance_is_a_compare_and_set(store, tenant):
    """**The mechanism that makes a due schedule advance once however many workers saw
    it.** Postgres gets it from `AND next_fire_at = %s`; the fake gets it from a
    comparison under the same lock as the write. A store where this is blind fires a
    schedule on every tick forever."""
    row = _schedule_for(store, tenant, _schedule_token(store, tenant), _fresh_schedule_id(tenant))
    later = _SOON + timedelta(hours=1)
    later_still = _SOON + timedelta(hours=2)

    won = store.advance_schedule(
        tenant, row["id"], if_next_fire_at=_SOON, next_fire_at=later,
        last_run_id="r-1", last_outcome="fired r-1",
    )
    assert won is not None
    assert won["next_fire_at"] == later
    assert won["last_run_id"] == "r-1"
    assert won["last_fired_at"] is not None

    # The second worker read the same instant this one just replaced.
    lost = store.advance_schedule(
        tenant, row["id"], if_next_fire_at=_SOON, next_fire_at=later_still,
    )
    assert lost is None
    assert store.get_schedule(tenant, row["id"])["next_fire_at"] == later


def test_a_fire_that_submitted_nothing_leaves_last_fired_at_alone(store, tenant):
    """`fired=False` is a refusal or a skip. The clock still moves — otherwise a revoked
    token is retried at tick rate — but "when did this last actually run" must stay
    answerable beside "what happened last time"."""
    row = _schedule_for(store, tenant, _schedule_token(store, tenant), _fresh_schedule_id(tenant))

    store.advance_schedule(
        tenant, row["id"], if_next_fire_at=_SOON, next_fire_at=_SOON + timedelta(hours=1),
        last_outcome="skipped: still running", fired=False,
    )
    after = store.get_schedule(tenant, row["id"])
    assert after["last_fired_at"] is None
    assert after["last_outcome"] == "skipped: still running"
    assert after["next_fire_at"] == _SOON + timedelta(hours=1)


def test_advancing_a_schedule_that_is_not_there_is_none(store, tenant):
    assert store.advance_schedule(
        tenant, "sch_nothing", if_next_fire_at=_SOON, next_fire_at=_SOON,
    ) is None


def test_enabling_is_idempotent_and_only_a_change_is_recorded(store, tenant):
    row = _schedule_for(store, tenant, _schedule_token(store, tenant), _fresh_schedule_id(tenant))
    before = len(store.admin_audit_records(tenant))

    # Already enabled: the row comes back, nothing is written.
    assert store.set_schedule_enabled(
        tenant, row["id"], True, next_fire_at=_SOON, actor="user:u-1"
    )["enabled"] is True
    assert len(store.admin_audit_records(tenant)) == before

    off = store.set_schedule_enabled(
        tenant, row["id"], False, next_fire_at=_SOON, actor="user:u-1"
    )
    assert off["enabled"] is False
    assert len(store.admin_audit_records(tenant)) == before + 1


def test_a_schedule_naming_an_agent_that_does_not_exist_is_refused(store, tenant):
    token_id = _schedule_token(store, tenant)
    with pytest.raises(ValueRefused, match="no agent called"):
        store.create_schedule(
            tenant,
            {"id": _fresh_schedule_id(tenant), "agent_name": "ghost",
             "token_id": token_id, "task": "t",
             "cadence": _HOURLY, "timezone": "UTC", "next_fire_at": _SOON},
            actor="user:u-1",
        )


def test_a_schedule_naming_a_token_that_does_not_exist_is_refused(store, tenant):
    _agent_for(store, tenant)
    with pytest.raises(ValueRefused, match="no API token"):
        store.create_schedule(
            tenant,
            {"id": _fresh_schedule_id(tenant), "agent_name": "issue-reporter",
             "token_id": "m_never_minted", "task": "t",
             "cadence": _HOURLY, "timezone": "UTC", "next_fire_at": _SOON},
            actor="user:u-1",
        )


@pytest.mark.parametrize(
    "field,value",
    [
        pytest.param("cadence", {"every": "minute", "at": ":05"}, id="cadence-too-fine"),
        pytest.param("cadence", {"every": "day", "at": "7:5"}, id="cadence-not-two-digits"),
        pytest.param("cadence", "day@07:30", id="cadence-not-an-object"),
        pytest.param("timezone", "Mars/Olympus", id="unknown-zone"),
        pytest.param("timezone", "", id="no-zone"),
        pytest.param("task", "", id="empty-task"),
        pytest.param("next_fire_at", datetime(2030, 1, 1, 7, 30), id="naive-instant"),
        pytest.param("next_fire_at", "2030-01-01T07:30:00Z", id="instant-is-a-string"),
    ],
)
def test_both_stores_refuse_the_same_bad_schedule(store, tenant, field, value):
    """**Asking both stores the same odd question**, which is how 021's edge hunt found
    four divergences. Every one of these is refused in Python rather than by a
    constraint, so a fake that skipped the check would accept rows Postgres cannot hold
    — or worse, accept them in both and diverge on what they mean."""
    _agent_for(store, tenant)
    token_id = _schedule_token(store, tenant)
    row = {
        "id": _fresh_schedule_id(tenant), "agent_name": "issue-reporter",
        "token_id": token_id, "task": "t", "cadence": _HOURLY,
        "timezone": "UTC", "next_fire_at": _SOON,
    }
    row[field] = value

    with pytest.raises(StorageError):
        store.create_schedule(tenant, row, actor="user:u-1")

    assert store.get_schedule(tenant, row["id"]) is None


@pytest.mark.parametrize(
    "task",
    [
        pytest.param("has a \x00 nul byte", id="nul"),
        pytest.param("a lone surrogate \ud800", id="surrogate"),
    ],
)
def test_a_task_postgres_could_not_hold_is_refused_by_both(store, tenant, task):
    """021 defect 8, at a TEXT column instead of a jsonb one. A dict holds these happily
    and Postgres refuses them outright, so without the check the suite goes green on
    schedules that 503 the first time somebody creates one for real."""
    _agent_for(store, tenant)
    token_id = _schedule_token(store, tenant)
    with pytest.raises(StorageError):
        store.create_schedule(
            tenant,
            {"id": _fresh_schedule_id(tenant), "agent_name": "issue-reporter",
             "token_id": token_id, "task": task, "cadence": _HOURLY,
             "timezone": "UTC", "next_fire_at": _SOON},
            actor="user:u-1",
        )


def test_deleting_the_agent_takes_its_schedules_in_both_stores(store, tenant):
    """Migration 033's cascade in Postgres, and by hand in the fake — the shape of fake
    the contract suite exists to catch is not one that refuses what Postgres accepts, it
    is one that KEEPS what Postgres removes."""
    row = _schedule_for(store, tenant, _schedule_token(store, tenant), _fresh_schedule_id(tenant))
    store.delete_agent(tenant, "issue-reporter", actor="user:u-1")

    assert store.get_schedule(tenant, row["id"]) is None
    assert store.list_schedules(tenant) == []


def test_a_schedule_is_gone_with_its_tenant(store, tenant):
    """`schedules` is absent from `TENANT_BLOCKING_TABLES` because it cascades — from the
    tenant directly and from the agent as well. Two cascade paths onto one row, which is
    why the token key is written CASCADE rather than left to default."""
    row = _schedule_for(store, tenant, _schedule_token(store, tenant), _fresh_schedule_id(tenant))
    store.set_tenant_status(tenant, "suspended")
    store.delete_tenant(tenant, actor="system:cli")

    store.create_tenant(f"{tenant}-successor", name="Successor")
    assert store.list_schedules(f"{tenant}-successor") == []
    assert row["id"] not in [
        r["id"] for r in store.due_schedules(now=_SOON + timedelta(days=1))
    ]


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(None, id="none"),
        pytest.param(datetime(2030, 1, 1, 7, 30), id="naive"),
        pytest.param("2030-01-01T07:30:00Z", id="string"),
    ],
)
def test_neither_store_lets_a_bad_instant_reach_the_scheduler_clock(store, tenant, value):
    """**The defect whose blast radius was the whole deployment.**

    `normalize_schedule` refused these on create from the first version; `advance_schedule`
    and `set_schedule_enabled` did not. The fake then held a naive instant or a `None`, and
    `due_schedules` — one scan across every tenant, before any schedule is considered —
    raised `TypeError`. Every customer's scheduling stopped, permanently, and the symptom
    was one log line per tick.

    Postgres coerced the naive value and refused the `None`, so the two stores disagreed
    as well: exactly the shape the contract suite exists to catch.
    """
    row = _schedule_for(store, tenant, _schedule_token(store, tenant), _fresh_schedule_id(tenant))

    with pytest.raises(StorageError):
        store.advance_schedule(
            tenant, row["id"], if_next_fire_at=_SOON, next_fire_at=value,
        )
    with pytest.raises(StorageError):
        store.set_schedule_enabled(
            tenant, row["id"], False, next_fire_at=value, actor="user:u-1"
        )

    # Nothing was written, so the scan across every tenant still answers.
    assert store.get_schedule(tenant, row["id"])["next_fire_at"] == _SOON
    assert isinstance(store.due_schedules(now=_SOON), list)


def test_neither_store_takes_a_nul_byte_in_what_a_fire_reports(store, tenant):
    """021 defect 8 at two more TEXT columns. `last_outcome` is `str(exc)` of whatever
    refused the fire, so it is only as constrained as the messages upstream of it."""
    row = _schedule_for(store, tenant, _schedule_token(store, tenant), _fresh_schedule_id(tenant))

    for field in ("last_outcome", "last_run_id"):
        with pytest.raises(StorageError):
            store.advance_schedule(
                tenant, row["id"], if_next_fire_at=_SOON,
                next_fire_at=_SOON + timedelta(hours=1),
                **{field: "bad\x00value"},
            )
    assert store.get_schedule(tenant, row["id"])["next_fire_at"] == _SOON


# --- event triggers, migration 034 ---------------------------------------------------
#
# Both stores, on the schedules section's argument verbatim. The extra thing under test
# here is the sealed blob: storage's contract is that it holds what `crypto.seal`
# produced without understanding it, so these tests hand it opaque bytes and the
# assertion that matters is that they come back as the same *bytes* from both stores —
# psycopg answers BYTEA with a memoryview, and a fake returning bytes while Postgres
# returned memoryview would make signature verification a type error in production only.

_TRIGGER_SEQUENCE = itertools.count()


def _fresh_trigger_id(tenant):
    return f"trg{next(_TRIGGER_SEQUENCE)}_{abs(hash(tenant)) % 100000}"


def test_a_trigger_round_trips(store, tenant):
    row = _trigger_for(store, tenant, _schedule_token(store, tenant), _fresh_trigger_id(tenant))

    assert set(row) == set(TRIGGER_FIELDS)
    assert row["name"] == f"hook-{row['id']}"
    assert row["task"] == "triage the event below"
    assert isinstance(row["secret_sealed"], bytes)
    assert row["secret_sealed"] == b"\x01sealed-bytes-not-a-secret"
    assert row["secret_key_id"] == "k1234567"
    assert row["enabled"] is True
    assert row["last_delivery_at"] is None
    assert row["last_run_id"] == ""
    assert row["last_outcome"] == ""

    assert store.get_trigger(tenant, row["id"]) == row
    assert store.find_trigger(row["id"]) == row
    assert store.list_triggers(tenant) == [row]
    assert store.list_triggers(tenant, agent_name="issue-reporter") == [row]
    assert store.list_triggers(tenant, agent_name="somebody-else") == []


def test_rotating_a_trigger_replaces_the_seal_and_moves_nothing_else(store, tenant):
    """Step 035k. **The URL not moving is the verb**, and at this layer that means the id,
    the name, the task, the machine and `enabled` all stand still while two columns
    change. `updated_at` moving is the only reader that tells a rotated trigger from an
    untouched one, which is why `TriggerDetail` declares it."""
    row = _trigger_for(store, tenant, _schedule_token(store, tenant), _fresh_trigger_id(tenant))

    rotated = store.rotate_trigger_secret(
        tenant,
        row["id"],
        secret_sealed=b"\x02a-different-sealed-blob",
        secret_key_id="k9999999",
        actor="user:u-1",
    )

    assert set(rotated) == set(TRIGGER_FIELDS)
    assert rotated["secret_sealed"] == b"\x02a-different-sealed-blob"
    assert rotated["secret_key_id"] == "k9999999"
    assert isinstance(rotated["secret_sealed"], bytes), "bytes in, bytes out, in both stores"

    for unchanged in ("id", "name", "task", "token_id", "agent_name", "enabled", "created_at", "created_by"):
        assert rotated[unchanged] == row[unchanged], unchanged
    assert rotated["updated_at"] > row["updated_at"]
    assert store.get_trigger(tenant, row["id"]) == rotated


def test_a_rotation_record_names_the_trigger_and_neither_secret(store, tenant):
    """`core/crypto.py`'s division at the log: a layer that cannot see a secret cannot log
    one, and a record is forever. So not the plaintext (which never reaches here), not the
    ciphertext, and not the key id."""
    row = _trigger_for(store, tenant, _schedule_token(store, tenant), _fresh_trigger_id(tenant))

    store.rotate_trigger_secret(
        tenant,
        row["id"],
        secret_sealed=b"\x02rotated-sealed-blob",
        secret_key_id="k9999999",
        actor="user:u-1",
    )

    (record,) = store.admin_audit_records(tenant, action="trigger.rotate")
    assert record["target_id"] == row["id"]
    assert record["detail"]["name"] == row["name"]
    assert record["detail"]["agent"] == "issue-reporter"
    assert "k9999999" not in str(record)
    assert "sealed" not in str(record["detail"]).lower()


def test_every_rotation_is_recorded_because_none_of_them_is_a_no_op(store, tenant):
    """Enable and disable carry `AND enabled <> %s` because setting a state a row already
    holds is not a change. A rotation always produces a new secret, so there is no
    idempotent case to suppress and two calls are two records."""
    row = _trigger_for(store, tenant, _schedule_token(store, tenant), _fresh_trigger_id(tenant))

    for blob in (b"\x02first", b"\x02second"):
        store.rotate_trigger_secret(
            tenant, row["id"], secret_sealed=blob, secret_key_id="k2", actor="user:u-1"
        )

    assert len(store.admin_audit_records(tenant, action="trigger.rotate")) == 2
    assert store.get_trigger(tenant, row["id"])["secret_sealed"] == b"\x02second"


def test_both_stores_refuse_a_rotation_that_is_not_sealed(store, tenant):
    """**The guard that became a function because this write is its second caller.** A
    rotation does not go through `normalize_trigger`, so before 035k extracted
    `check_sealed_secret` the rule would have been one function away from the write it
    guards — which is the exact shape 035i found `check_config_is_storable` in.

    `StorageError` rather than `ValueRefused`, and that is the one place on this boundary
    where a 503 is honest: no caller can put a value here, so a `str` in this column means
    a module above sealed nothing.
    """
    row = _trigger_for(store, tenant, _schedule_token(store, tenant), _fresh_trigger_id(tenant))

    for plaintext in ("a-plaintext-secret", None, 12):
        with pytest.raises(StorageError):
            store.rotate_trigger_secret(
                tenant, row["id"], secret_sealed=plaintext, secret_key_id="k2", actor="user:u-1"
            )
    # And it is refused *before* anything is written.
    assert store.get_trigger(tenant, row["id"]) == row


def test_rotating_a_trigger_that_is_not_there_is_none(store, tenant):
    assert (
        store.rotate_trigger_secret(
            tenant, "trg_nothing", secret_sealed=b"x", secret_key_id="k2", actor="user:u-1"
        )
        is None
    )


def test_an_absent_trigger_is_none_rather_than_an_error(store, tenant):
    assert store.get_trigger(tenant, "trg_nothing") is None
    assert store.find_trigger("trg_nothing") is None
    assert store.delete_trigger(tenant, "trg_nothing", actor="user:u-1") is False


def test_find_trigger_is_tenantless_and_get_trigger_is_not(store, tenant):
    """`find_trigger` is the door's read and the door has no tenant until the row
    supplies one — `find_api_token`'s shape. `get_trigger` is every *administrative*
    read, and it must not let one tenant's id resolve through another's surface."""
    row = _trigger_for(store, tenant, _schedule_token(store, tenant), _fresh_trigger_id(tenant))

    other = f"{tenant[:50]}-other"
    store.create_tenant(other, "Other")
    assert store.find_trigger(row["id"]) is not None
    assert store.get_trigger(other, row["id"]) is None
    assert store.delete_trigger(other, row["id"], actor="user:u-1") is False


def test_a_trigger_naming_an_agent_that_does_not_exist_is_refused(store, tenant):
    token_id = _schedule_token(store, tenant)
    with pytest.raises(ValueRefused, match="no agent called"):
        store.create_trigger(
            tenant,
            {"id": _fresh_trigger_id(tenant), "agent_name": "ghost",
             "token_id": token_id, "name": "n", "task": "t",
             "secret_sealed": b"\x01blob", "secret_key_id": "k1"},
            actor="user:u-1",
        )


def test_a_trigger_naming_a_token_that_does_not_exist_is_refused(store, tenant):
    _agent_for(store, tenant)
    with pytest.raises(ValueRefused, match="no API token"):
        store.create_trigger(
            tenant,
            {"id": _fresh_trigger_id(tenant), "agent_name": "issue-reporter",
             "token_id": "m_never_minted", "name": "n", "task": "t",
             "secret_sealed": b"\x01blob", "secret_key_id": "k1"},
            actor="user:u-1",
        )


def test_a_trigger_may_not_borrow_another_tenants_token(store, tenant):
    """The composite key's more important half, `create_schedule`'s test at the next
    table: a token that exists in another customer is exactly as absent as one that
    does not exist at all."""
    other = f"{tenant[:50]}-lender"
    store.create_tenant(other, "Lender")
    foreign_token = _schedule_token(store, other)
    _agent_for(store, tenant)

    with pytest.raises(ValueRefused, match="no API token"):
        store.create_trigger(
            tenant,
            {"id": _fresh_trigger_id(tenant), "agent_name": "issue-reporter",
             "token_id": foreign_token, "name": "n", "task": "t",
             "secret_sealed": b"\x01blob", "secret_key_id": "k1"},
            actor="user:u-1",
        )


@pytest.mark.parametrize(
    "field,value,family",
    [
        # Typed by a person, so a 400 with a sentence they can act on.
        pytest.param("name", "", ValueRefused, id="empty-name"),
        pytest.param("task", "", ValueRefused, id="empty-task"),
        pytest.param("token_id", "", ValueRefused, id="empty-token-id"),
        pytest.param("task", "bad\x00task", ValueRefused, id="nul-in-task"),
        pytest.param("name", "bad\x00name", ValueRefused, id="nul-in-name"),
        # Minted by the module above, so an empty one is a bug and 503 is the truth.
        pytest.param("secret_sealed", b"", StorageError, id="empty-blob"),
        pytest.param("secret_sealed", "plaintext-string", StorageError, id="blob-is-a-string"),
        pytest.param("secret_key_id", "", StorageError, id="no-key-id"),
        pytest.param("id", "", StorageError, id="no-id"),
    ],
)
def test_both_stores_refuse_the_same_bad_trigger(store, tenant, field, value, family):
    """The same odd question to both stores — the schedules table's discipline. The
    `blob-is-a-string` case is the one with teeth: a plaintext secret handed to storage
    by mistake must be refused loudly, not stored quietly in a column named sealed.

    **The family is asserted, not just the refusal, and that is the point of this
    version.** `ValueRefused` subclasses `StorageError`, so the earlier
    `pytest.raises(StorageError)` passed for both — which is exactly how an empty name
    came to answer *"storage unavailable: try again later"* to somebody who left a form
    field blank, and passed every test in this file while doing it. The register's
    wrong-refusal-family row says what is missing is a test that walks the *checks*
    rather than the handler table; asserting the family here is the narrow version of
    that, at the one function where the two populations meet.
    """
    _agent_for(store, tenant)
    token_id = _schedule_token(store, tenant)
    trigger = {
        "id": _fresh_trigger_id(tenant), "agent_name": "issue-reporter",
        "token_id": token_id, "name": "n", "task": "t",
        "secret_sealed": b"\x01blob", "secret_key_id": "k1",
    }
    trigger[field] = value
    with pytest.raises(family):
        store.create_trigger(tenant, trigger, actor="user:u-1")
    if family is StorageError:
        # The narrower class must NOT be what came out, or the assertion above is
        # satisfied by the subclass and proves nothing about the family.
        try:
            store.create_trigger(tenant, trigger, actor="user:u-1")
        except ValueRefused:  # pragma: no cover - the failure this guards against
            pytest.fail(f"{field} is minted by the module above, so it is not a 400")
        except StorageError:
            pass
    assert store.list_triggers(tenant) == []


def test_enabling_a_trigger_is_idempotent_and_the_log_holds_changes(store, tenant):
    row = _trigger_for(store, tenant, _schedule_token(store, tenant), _fresh_trigger_id(tenant))
    before = len(store.admin_audit_records(tenant))

    # Already on: the row comes back, nothing is recorded.
    same = store.set_trigger_enabled(tenant, row["id"], True, actor="user:u-1")
    assert same["enabled"] is True
    assert len(store.admin_audit_records(tenant)) == before

    off = store.set_trigger_enabled(tenant, row["id"], False, actor="user:u-1")
    assert off["enabled"] is False
    assert len(store.admin_audit_records(tenant)) == before + 1

    assert store.set_trigger_enabled(tenant, "trg_nothing", False, actor="user:u-1") is None


def test_a_delivery_stamp_round_trips_and_stamps_nothing_administrative(store, tenant):
    row = _trigger_for(store, tenant, _schedule_token(store, tenant), _fresh_trigger_id(tenant))
    before = len(store.admin_audit_records(tenant))

    store.record_trigger_delivery(
        tenant, row["id"], last_run_id="r_abc", last_outcome="fired r_abc"
    )

    after = store.get_trigger(tenant, row["id"])
    assert after["last_run_id"] == "r_abc"
    assert after["last_outcome"] == "fired r_abc"
    assert after["last_delivery_at"] is not None
    assert len(store.admin_audit_records(tenant)) == before

    # A stamp on a row that is not there is a no-op, not an error: the trigger can
    # cascade away mid-delivery and the stamp is best-effort by design.
    store.record_trigger_delivery(
        tenant, "trg_nothing", last_run_id="", last_outcome="x"
    )


def test_neither_store_stamps_an_unstorable_outcome(store, tenant):
    row = _trigger_for(store, tenant, _schedule_token(store, tenant), _fresh_trigger_id(tenant))
    with pytest.raises(StorageError):
        store.record_trigger_delivery(
            tenant, row["id"], last_run_id="", last_outcome="bad\x00outcome"
        )
    assert store.get_trigger(tenant, row["id"])["last_outcome"] == ""


def test_deleting_the_agent_takes_its_triggers_in_both_stores(store, tenant):
    """Migration 034's cascade — and the sharper consequence this table adds: a
    surviving row would be a URL an outside system still holds, springing to life at
    somebody's reused agent name."""
    row = _trigger_for(store, tenant, _schedule_token(store, tenant), _fresh_trigger_id(tenant))
    store.delete_agent(tenant, "issue-reporter", actor="user:u-1")

    assert store.get_trigger(tenant, row["id"]) is None
    assert store.find_trigger(row["id"]) is None
    assert store.list_triggers(tenant) == []


def test_a_trigger_is_gone_with_its_tenant(store, tenant):
    """`triggers` is absent from `TENANT_BLOCKING_TABLES` because it cascades — from
    the tenant directly and from the agent as well, `schedules`' twin."""
    row = _trigger_for(store, tenant, _schedule_token(store, tenant), _fresh_trigger_id(tenant))
    store.set_tenant_status(tenant, "suspended")
    store.delete_tenant(tenant, actor="system:cli")

    assert store.find_trigger(row["id"]) is None


# --- counting a principal's recent runs, migration 034's index -----------------------


def test_count_recent_runs_counts_one_principal_in_one_tenant(store, tenant):
    for i in range(3):
        store.enqueue_run(tenant, {
            "run_id": f"r_count_{i}", "agent": "a", "principal_kind": "machine",
            "principal_id": "m_counted", "task": "t",
        })
    store.enqueue_run(tenant, {
        "run_id": "r_other_principal", "agent": "a", "principal_kind": "machine",
        "principal_id": "m_somebody_else", "task": "t",
    })
    other = f"{tenant[:50]}-other"
    store.create_tenant(other, "Other")
    store.enqueue_run(other, {
        "run_id": "r_other_tenant", "agent": "a", "principal_kind": "machine",
        "principal_id": "m_counted", "task": "t",
    })

    since = datetime.now(timezone.utc) - timedelta(hours=1)
    count, oldest = store.count_recent_runs(tenant, "machine", "m_counted", since=since)
    assert count == 3
    assert oldest is not None

    # `kind` scopes as well as `id`: a user whose id happens to equal a machine's is a
    # different principal, which is `_is_owner`'s argument made in a query.
    count, _ = store.count_recent_runs(tenant, "user", "m_counted", since=since)
    assert count == 0


def test_count_recent_runs_is_strictly_after_since(store, tenant):
    """A run at exactly `since` has aged out — one answer at the boundary, and it is
    the one the Retry-After arithmetic promises: the window frees at oldest + window,
    not one instant later."""
    row, _ = store.enqueue_run(tenant, {
        "run_id": "r_boundary", "agent": "a", "principal_kind": "machine",
        "principal_id": "m_edge", "task": "t",
    })
    stamped = store.get_run(tenant, "r_boundary")["created_at"]

    count, oldest = store.count_recent_runs(
        tenant, "machine", "m_edge", since=stamped - timedelta(microseconds=1)
    )
    assert (count, oldest) == (1, stamped)

    count, oldest = store.count_recent_runs(tenant, "machine", "m_edge", since=stamped)
    assert (count, oldest) == (0, None)


# --- key rotation (step 026) -----------------------------------------------------------
#
# The sweep's two shapes per table: a tenantless fetch that returns the sealed blob,
# and a reseal whose compare-and-set token is the blob itself. `base.py`'s section
# comment is the contract; these assert it against both stores.


def test_rotation_fetch_spans_tenants_and_returns_the_blob(store, tenant, other, connectors):
    """A rotation serves every customer or it is not a rotation."""
    store.save_connector(other, {"id": "jira", "launch": {}, "vetted": []}, actor=TEST_ACTOR)
    store.save_connection(
        tenant, "user", "u_priya", "jira", ciphertext=b"old-1", key_id="k-old",
        actor=TEST_ACTOR,
    )
    store.save_connection(
        other, "user", "u_sam", "jira", ciphertext=b"old-2", key_id="k-old",
        actor=TEST_ACTOR,
    )
    store.save_connection(
        tenant, "user", "u_fresh", "jira", ciphertext=b"new", key_id="k-cur",
        actor=TEST_ACTOR,
    )

    rows = [
        r for r in store.connections_not_sealed_under("k-cur")
        if r["tenant_id"] in (tenant, other)
    ]

    assert [(r["tenant_id"], r["principal_id"]) for r in rows] == [
        (other, "u_sam"),
        (tenant, "u_priya"),
    ]
    assert all(isinstance(r["ciphertext"], bytes) for r in rows)
    assert rows[0]["key_id"] == "k-old"


def test_rotation_fetches_cover_the_other_three_tables(store, tenant, connectors):
    _configure_oauth(store, tenant, "jira", client_secret=b"old-secret", key_id="k-old")
    _trigger_for(store, tenant, "m_rot", "trg_rot1")  # sealed under 'k1234567'
    store.create_pending_authorization(_state("r"), tenant, **{**_PENDING, "key_id": "k-old"})

    apps = [r for r in store.connector_oauth_not_sealed_under("k-cur") if r["tenant_id"] == tenant]
    trgs = [r for r in store.triggers_not_sealed_under("k-cur") if r["tenant_id"] == tenant]
    pend = [r for r in store.pending_authorizations_not_sealed_under("k-cur") if r["tenant_id"] == tenant]

    assert [(r["connector_id"], r["key_id"]) for r in apps] == [("jira", "k-old")]
    assert apps[0]["client_secret"] == b"old-secret"
    assert [(r["id"], r["secret_key_id"]) for r in trgs] == [("trg_rot1", "k1234567")]
    assert isinstance(trgs[0]["secret_sealed"], bytes)
    assert [(r["state"], r["key_id"]) for r in pend] == [(_state("r"), "k-old")]
    assert pend[0]["code_verifier"] == b"sealed-verifier"
    assert pend[0]["created_at"] is not None

    # A row sealed under the asked-about key is not in any population.
    assert [r for r in store.connector_oauth_not_sealed_under("k-old") if r["tenant_id"] == tenant] == []


def test_a_reseal_is_conditional_on_the_bytes_read(store, tenant, connectors):
    """The blob is the version token: stale bytes write nothing and say so."""
    store.save_connection(
        tenant, "user", "u_priya", "jira", ciphertext=b"old", key_id="k-old",
        actor=TEST_ACTOR,
    )

    assert store.reseal_connection(
        tenant, "user", "u_priya", "jira",
        ciphertext=b"resealed", key_id="k-cur", if_ciphertext=b"old",
    ) is True
    row = store.find_connection(tenant, "user", "u_priya", "jira")
    assert (row["ciphertext"], row["key_id"]) == (b"resealed", "k-cur")

    # The same expectation again is now stale — the row moved on.
    assert store.reseal_connection(
        tenant, "user", "u_priya", "jira",
        ciphertext=b"other", key_id="k-cur", if_ciphertext=b"old",
    ) is False
    row = store.find_connection(tenant, "user", "u_priya", "jira")
    assert (row["ciphertext"], row["key_id"]) == (b"resealed", "k-cur")

    # A row that is not there at all is the same False, not an error.
    assert store.reseal_connection(
        tenant, "user", "u_gone", "jira",
        ciphertext=b"x", key_id="k-cur", if_ciphertext=b"old",
    ) is False


def test_a_reseal_touches_nothing_but_the_blob_and_the_key(store, tenant, connectors):
    """Rotation must be invisible to the refresh machinery and to the reconsent flag.

    `updated_at` is `update_connection_credential`'s compare-and-set token, and
    `reconsent_reason` is a true sentence about the provider — a reseal that bumped
    the one or cleared the other would break a concurrent refresh or forge a
    "the grant is back" signal.
    """
    store.save_connection(
        tenant, "user", "u_priya", "jira", ciphertext=b"old", key_id="k-old",
        actor=TEST_ACTOR,
    )
    store.mark_connection_reconsent(
        tenant, "user", "u_priya", "jira", reason="consent was revoked at the provider."
    )
    before = store.find_connection(tenant, "user", "u_priya", "jira")

    assert store.reseal_connection(
        tenant, "user", "u_priya", "jira",
        ciphertext=b"resealed", key_id="k-cur", if_ciphertext=b"old",
    )

    after = store.find_connection(tenant, "user", "u_priya", "jira")
    assert after["updated_at"] == before["updated_at"]
    assert after["reconsent_reason"] == "consent was revoked at the provider."
    assert after["created_at"] == before["created_at"]


def test_the_other_three_reseals_are_the_same_contract(store, tenant, connectors):
    _configure_oauth(store, tenant, "jira", client_secret=b"old-secret", key_id="k-old")
    _trigger_for(store, tenant, "m_rot2", "trg_rot2")
    store.create_pending_authorization(_state("s"), tenant, **{**_PENDING, "key_id": "k-old"})

    assert store.reseal_connector_oauth(
        tenant, "jira", client_secret=b"new-secret", key_id="k-cur",
        if_client_secret=b"old-secret",
    ) is True
    assert store.get_connector_oauth(tenant, "jira")["client_secret"] == b"new-secret"
    assert store.reseal_connector_oauth(
        tenant, "jira", client_secret=b"x", key_id="k-cur", if_client_secret=b"old-secret",
    ) is False

    sealed = store.get_trigger(tenant, "trg_rot2")["secret_sealed"]
    assert store.reseal_trigger_secret(
        tenant, "trg_rot2", secret_sealed=b"new-sealed", secret_key_id="k-cur",
        if_secret_sealed=sealed,
    ) is True
    row = store.get_trigger(tenant, "trg_rot2")
    assert (row["secret_sealed"], row["secret_key_id"]) == (b"new-sealed", "k-cur")
    assert store.reseal_trigger_secret(
        tenant, "trg_rot2", secret_sealed=b"y", secret_key_id="k-cur",
        if_secret_sealed=sealed,
    ) is False

    assert store.reseal_pending_authorization(
        _state("s"), code_verifier=b"new-verifier", key_id="k-cur",
        if_code_verifier=b"sealed-verifier",
    ) is True
    assert store.consume_pending_authorization(_state("s"))["code_verifier"] == b"new-verifier"
    # Consumed above — the row is gone, and gone is False, not an error. This is the
    # callback-races-the-sweep case in one line.
    assert store.reseal_pending_authorization(
        _state("s"), code_verifier=b"z", key_id="k-cur", if_code_verifier=b"new-verifier",
    ) is False


def test_a_trigger_reseal_is_scoped_to_its_tenant(store, tenant, other):
    """The one reseal whose row key is not globally unique by construction gets the
    cross-tenant assertion: another tenant's id must not reach the blob."""
    _trigger_for(store, tenant, "m_rot3", "trg_rot3")
    sealed = store.get_trigger(tenant, "trg_rot3")["secret_sealed"]

    assert store.reseal_trigger_secret(
        other, "trg_rot3", secret_sealed=b"stolen", secret_key_id="k-evil",
        if_secret_sealed=sealed,
    ) is False
    assert store.get_trigger(tenant, "trg_rot3")["secret_sealed"] == sealed


def test_the_key_id_census_counts_every_sealed_row_without_a_blob(
    store, tenant, connectors, uniq
):
    """The done-when question — *does any row still name a retired key* — asked as one
    query rather than as a second walk over every credential in the deployment.

    **Key ids unique to this test**, because the census is deployment-wide on purpose:
    a rotation serves every tenant, so this is one of the few methods here with no
    tenant parameter, and asserting a global count of a shared id would be asserting
    what the rest of the suite happens to have left lying around.
    """
    old_key, current = f"old-{uniq}"[:16], f"cur-{uniq}"[:16]
    _configure_oauth(store, tenant, "jira", client_secret=b"old-secret", key_id=old_key)
    store.create_pending_authorization(
        _state("c"), tenant, **{**_PENDING, "key_id": old_key}
    )
    for who, key_id in (("u_one", old_key), ("u_two", old_key), ("u_three", current)):
        store.save_connection(
            tenant, "user", who, "jira", ciphertext=b"blob", key_id=key_id,
            actor=TEST_ACTOR,
        )

    census = store.sealed_key_id_census()

    assert set(census) == {
        "connections", "connector_oauth", "triggers", "pending_authorizations",
    }
    assert census["connections"][old_key] == 2
    assert census["connections"][current] == 1
    assert census["connector_oauth"][old_key] == 1
    assert census["pending_authorizations"][old_key] == 1
    # Counts and key ids only — a census that carried blobs would be the thing it
    # exists to avoid.
    for counts in census.values():
        assert all(isinstance(n, int) for n in counts.values())
        assert all(isinstance(k, str) for k in counts)


def test_the_census_sees_every_tenants_rows(store, tenant, other, connectors, uniq):
    """Tenantless, like `find_trigger` and `claim_run`: a rotation that could not see
    one customer's rows would report a finished rotation that was not one."""
    store.save_connector(other, {"id": "jira", "launch": {}, "vetted": []}, actor=TEST_ACTOR)
    shared = f"both-{uniq}"[:16]
    store.save_connection(
        tenant, "user", "u_here", "jira", ciphertext=b"a", key_id=shared, actor=TEST_ACTOR
    )
    store.save_connection(
        other, "user", "u_there", "jira", ciphertext=b"b", key_id=shared, actor=TEST_ACTOR
    )

    assert store.sealed_key_id_census()["connections"][shared] == 2


def test_a_reseal_refuses_an_empty_or_unsealed_value(store, tenant, connectors):
    """`check_connection`'s rules, on the write that rotation performs — including the
    expectation the compare-and-set is made of. A `str` there would match nothing and
    be reported as "the row changed underneath us", which is the one wrong answer this
    method must never give."""
    store.save_connection(
        tenant, "user", "u_priya", "jira", ciphertext=b"old", key_id="k-old",
        actor=TEST_ACTOR,
    )

    with pytest.raises(StorageError, match="must be bytes"):
        store.reseal_connection(
            tenant, "user", "u_priya", "jira",
            ciphertext="not-bytes", key_id="k-cur", if_ciphertext=b"old",
        )
    with pytest.raises(StorageError, match="must be bytes"):
        store.reseal_connection(
            tenant, "user", "u_priya", "jira",
            ciphertext=b"new", key_id="k-cur", if_ciphertext="old",
        )
    with pytest.raises(StorageError, match="empty"):
        store.reseal_connection(
            tenant, "user", "u_priya", "jira",
            ciphertext=b"", key_id="k-cur", if_ciphertext=b"old",
        )
    with pytest.raises(StorageError, match="key_id is required"):
        store.reseal_connection(
            tenant, "user", "u_priya", "jira",
            ciphertext=b"new", key_id="", if_ciphertext=b"old",
        )
    assert store.find_connection(tenant, "user", "u_priya", "jira")["ciphertext"] == b"old"


# --- step 028: a file with a task ----------------------------------------------------
#
# Two requests: a file is uploaded and gets an id, a run names the id. What the schema no
# longer enforces — that a file reaches only one run — is enforced by `runs.usable_file`
# above this tier, so what these assert is the half storage still owns: the row, the
# tenant filter, the ownership fields the check reads, and the sweep.


@pytest.fixture
def fid(request):
    """File ids unique to this test — `rid`'s trap, one table over.

    A file id is unique across the whole table rather than per customer, because a caller
    quotes it back on a later request and the lookup that resolves it must name one row.
    So a literal id passes against the in-memory store, which is rebuilt per test, and
    collides with the previous test on a shared Postgres. Found the same way `rid` was:
    by running it.

    Padded to the 32 characters `new_file_id` produces, so nothing here depends on the
    column being lax about length.
    """
    stem = re.sub(r"[^a-f0-9]", "", request.node.name.lower())[-24:]
    return lambda suffix="1": f"{stem}{suffix}".ljust(32, "0")


def a_file(file_id, **overrides):
    """A valid file row, any field overridable.

    The digest and size derive from the content, so changing the bytes gives a
    *consistent* row rather than one that trips the agreement checks by accident — those
    have their own tests and must fail for their own reasons. `content` is hashed only
    when it is bytes: one test passes a `str` to prove the store refuses it, and a helper
    that raised on the way in would make that test pass without the store being consulted.
    """
    content = overrides.pop("content", b"hello world")
    derived = (
        {"sha256": hashlib.sha256(content).hexdigest(), "byte_size": len(content)}
        if isinstance(content, (bytes, bytearray))
        else {"sha256": "0" * 64, "byte_size": 1}
    )
    return {
        "id": file_id,
        "owner_kind": "user",
        "owner_id": "u_priya",
        "filename": "notes.txt",
        "media_type": "text/plain",
        "content": content,
        **derived,
        **overrides,
    }


def test_a_file_round_trips_as_metadata_and_content(store, tenant, fid):
    """Two reads, and the split is the whole design. `get_file` answers the ownership
    check and the run detail; `file_content` is the one method that touches bytes and is
    called once per run by the worker."""
    stored = store.create_file(tenant, a_file(fid()))

    assert stored["id"] == fid()
    assert stored["owner_kind"] == "user"
    assert stored["owner_id"] == "u_priya"
    assert stored["byte_size"] == 11
    assert stored["sha256"] == hashlib.sha256(b"hello world").hexdigest()
    # Neither the create nor the read may carry content. Asserted rather than assumed,
    # because the cheap implementation of both is `SELECT *` and it would pass every
    # other test in this section.
    assert "content" not in stored
    assert "content" not in store.get_file(tenant, fid())

    assert store.file_content(tenant, fid()) == b"hello world"


def test_bytes_survive_exactly_including_ones_that_are_not_text(store, tenant, fid):
    """A PDF is binary and the column is BYTEA. The failure this catches is a store that
    decodes on the way in or out — which round-trips every ASCII fixture in this file
    perfectly and corrupts every real PDF. It also pins that both stores return `bytes`,
    where psycopg hands back `memoryview`."""
    blob = bytes(range(256)) * 4
    store.create_file(tenant, a_file(fid(), content=blob))

    read = store.file_content(tenant, fid())
    assert read == blob
    assert isinstance(read, bytes)


def test_a_file_is_invisible_to_another_tenant(store, tenant, other, fid):
    """`get_run`'s rule applied to the file: an id from another customer must be
    indistinguishable from one that does not exist. The id is global — a caller quotes it
    back on a later request — so a store that resolved it without the tenant filter would
    serve one customer's document to another."""
    store.create_file(tenant, a_file(fid()))

    assert store.get_file(other, fid()) is None
    assert store.file_content(other, fid()) is None


def test_the_owner_is_recorded_because_the_check_above_reads_it(store, tenant, fid):
    """Storage records who uploaded it and decides nothing about it. The ownership rule
    is `runs.usable_file`'s, above this tier, because it needs a principal — but it can
    only be right if these two fields come back exactly as written."""
    store.create_file(tenant, a_file(fid(), owner_kind="machine", owner_id="m_nightly"))

    meta = store.get_file(tenant, fid())
    assert (meta["owner_kind"], meta["owner_id"]) == ("machine", "m_nightly")


def test_a_reused_id_is_refused_rather_than_overwriting(store, tenant, fid):
    """At 128 bits a collision does not happen, so a duplicate is a caller reusing an id.
    Overwriting would hand these bytes to a run somebody else already started."""
    store.create_file(tenant, a_file(fid(), content=b"first"))

    with pytest.raises(StorageError, match="already exists"):
        store.create_file(tenant, a_file(fid(), content=b"second"))

    assert store.file_content(tenant, fid()) == b"first"


def test_a_lying_byte_size_is_refused(store, tenant, fid):
    """The stored size exists so a metadata read never touches the content column, and
    that only works while the two agree."""
    with pytest.raises(StorageError, match="byte_size"):
        store.create_file(tenant, a_file(fid(), byte_size=999))


def test_a_malformed_digest_is_refused(store, tenant, fid):
    with pytest.raises(StorageError, match="sha256"):
        store.create_file(tenant, a_file(fid(), sha256="nope"))


def test_text_content_is_refused_because_the_column_is_bytes(store, tenant, fid):
    """`str` here is the mistake that corrupts every PDF, and the one a caller reading
    `filename` and `media_type` beside it is most likely to make."""
    with pytest.raises(StorageError, match="not bytes"):
        store.create_file(tenant, a_file(fid(), content="hello"))


def test_a_run_records_the_file_it_was_given(store, tenant, rid, fid):
    """`file_id` is a column on `runs` now — the id made it one — so it belongs to
    `RUN_FIELDS` and the row-shape contract covers it."""
    from carnet.storage import RUN_FIELDS

    store.create_file(tenant, a_file(fid()))
    row, created = store.enqueue_run(tenant, a_run(rid(), file_id=fid()))

    assert created is True
    assert set(row) == set(RUN_FIELDS)
    assert row["file_id"] == fid()


def test_a_run_without_a_file_says_so_with_an_empty_string(store, tenant, rid):
    """'' rather than NULL, matching `idempotency_key` beside it: the NULL spelling
    belongs to columns carrying a foreign key, and this one deliberately has none."""
    row, _ = store.enqueue_run(tenant, a_run(rid()))
    assert row["file_id"] == ""


def test_storage_does_not_decide_who_may_use_a_file(store, tenant, rid, fid):
    """**The boundary, asserted.** As far as storage is concerned a run may name a file
    belonging to somebody else — the refusal is `runs.usable_file`'s, one tier up, where
    there is a principal to compare against. Pinning it here stops somebody adding a
    second opinion in the store, which would then disagree with the first."""
    store.create_file(tenant, a_file(fid(), owner_id="u_someone_else"))

    row, created = store.enqueue_run(tenant, a_run(rid(), file_id=fid()))
    assert created is True
    assert row["file_id"] == fid()


def test_a_run_outlives_the_file_it_read(pg, fid):
    """015's rule, applied to a second column: **a run is history.** `runs.file_id`
    carries no foreign key, so deleting a file must not delete — or silently blank — the
    record of the run that read it. `ON DELETE SET NULL` would rewrite history, and
    `CASCADE` would let deleting a document erase the evidence of what was done with it.
    """
    store, tenant_id = pg
    run_id = "outlives-" + fid()[:8]
    store.create_file(tenant_id, a_file(fid()))
    store.enqueue_run(tenant_id, a_run(run_id, file_id=fid()))

    store._execute("DELETE FROM files WHERE id = %s", (fid(),))

    row = store.get_run(tenant_id, run_id)
    assert row is not None
    assert row["file_id"] == fid()
    assert store.get_file(tenant_id, fid()) is None


def test_a_file_is_gone_with_its_tenant(store, tenant, fid):
    """The register's retention answer, and the half that had to be checked in both
    stores. In Postgres this is the cascade on `files.tenant_id`; in the fake it is an
    explicit sweep, and the drift this suite exists to catch is not a fake that refuses
    what Postgres accepts — it is one that KEEPS what Postgres removes."""
    store.create_file(tenant, a_file(fid()))
    assert store.file_content(tenant, fid()) is not None

    store.set_tenant_status(tenant, "suspended")
    store.delete_tenant(tenant, actor=TEST_ACTOR)

    assert store.get_file(tenant, fid()) is None
    assert store.file_content(tenant, fid()) is None


def test_one_file_can_be_read_by_two_runs(store, tenant, rid, fid):
    """**What the id bought, pinned as a property rather than left implied.** The
    rejected one-request design made this unrepresentable; this one allows it, so a large
    file is uploaded once rather than on every retry of a run. That the *same* person is
    doing it is `runs.usable_file`'s business, not storage's."""
    first, second = rid("a"), rid("b")
    store.create_file(tenant, a_file(fid()))
    store.enqueue_run(tenant, a_run(first, file_id=fid()))
    store.enqueue_run(tenant, a_run(second, file_id=fid()))

    assert store.get_run(tenant, first)["file_id"] == fid()
    assert store.get_run(tenant, second)["file_id"] == fid()
    assert store.file_content(tenant, fid()) == b"hello world"


# --- step 029: row-level security -----------------------------------------------
#
# The database's own opinion about tenancy. Two kinds of assertion, deliberately kept
# apart: what the *catalog* says (the policies exist, the role is shaped right, and a
# future migration cannot add a table without joining in — the TENANT_BLOCKING_TABLES
# device applied to a second rule), and what a *scoped connection* actually sees, which
# is the only test that can tell "the policy filters" apart from "the application
# filtered first". Postgres-only where the subject is the policy machinery; both stores
# where the subject is the contract's observable behaviour.


def test_every_tenant_table_carries_the_policy_and_the_catalog_says_so(pg):
    """The anti-compounding device. The register graded this row compounding because
    every step adds query paths; this walk is what stops the growth: a migration that
    adds a table with a `tenant_id` and forgets its policy fails here by name, so from
    029 on tenancy costs a new table exactly one CREATE POLICY line."""
    from carnet.storage import TENANT_ROLE

    store, _tenant_id = pg
    tables = store._fetchall(
        """
        SELECT c.relname,
               c.relrowsecurity,
               c.relforcerowsecurity,
               EXISTS (SELECT 1 FROM pg_attribute a
                        WHERE a.attrelid = c.oid AND a.attname = 'tenant_id'
                          AND a.attnum > 0 AND NOT a.attisdropped)
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
           AND NOT c.relispartition
         ORDER BY 1
        """
    )
    policies = {
        row[0]: row[1:]
        for row in store._fetchall(
            """
            SELECT c.relname, p.polname, pg_get_expr(p.polqual, p.polrelid),
                   ARRAY(SELECT rolname FROM pg_roles WHERE oid = ANY(p.polroles))
              FROM pg_policy p
              JOIN pg_class c ON c.oid = p.polrelid
            """
        )
    }

    # The guard on the guard, in the style of the deletion walk's floor: if the catalog
    # query collapses, this fails before the loop proves anything about nothing.
    with_tenant = [name for name, _rls, _force, has in tables if has]
    assert len(with_tenant) >= 20
    assert {"agents", "runs", "audit", "files", "schedules"} <= set(with_tenant)

    for name, rls, force, has_tenant_id in tables:
        assert rls, f"{name} has row-level security disabled"
        # FORCE is deliberately off everywhere: the owner's exemption is what lets the
        # worker's tenantless claim, rotation's sweeps and the migration runner keep
        # working. A hardening pass that flips this must first answer decision 4 of
        # step 029.
        assert not force, f"{name} has FORCE ROW LEVEL SECURITY, which breaks the queue"

        if has_tenant_id:
            polname, qual, roles = policies[name]
            assert polname == "tenant_isolation", name
            assert roles == [TENANT_ROLE], (name, roles)
            assert qual == "(tenant_id = agent_runtime_tenant_id())", (name, qual)
        elif name == "tenants":
            polname, qual, roles = policies[name]
            assert qual == "(id = agent_runtime_tenant_id())", qual
            assert roles == [TENANT_ROLE]
        elif name == "schema_migrations":
            # RLS enabled with no policy is default deny for the tenant role: no scoped
            # session has any business in the ledger.
            assert name not in policies
        elif name == "oauth_clients":
            # Migration 053. No tenant: a client registers before anybody signs in, and
            # the consent route — scoped to the person's tenant — must read it and stamp
            # it. Visible whole, decided in the migration.
            polname, qual, roles = policies[name]
            assert qual == "true", qual
            assert roles == [TENANT_ROLE]
        else:
            raise AssertionError(
                f"{name} has no tenant_id and no decided policy — decide one in its "
                "migration and teach this test the answer"
            )


def test_the_tenant_role_cannot_log_in_and_cannot_bypass(pg):
    """The role is taken with SET ROLE by an already-authenticated connection, never
    presented as a credential; and a role that could BYPASSRLS would make every policy
    decorative. Also asserts the serving role can actually take it, which is the
    membership half of `verify_tenant_isolation`."""
    from carnet.storage import TENANT_ROLE

    store, _tenant_id = pg
    row = store._fetchone(
        "SELECT rolcanlogin, rolbypassrls, rolsuper FROM pg_roles WHERE rolname = %s",
        (TENANT_ROLE,),
    )
    assert row == (False, False, False)
    # 'SET' rather than 'MEMBER', because it is the stronger claim and the one
    # `_connection()` actually exercises: a creator's implicit ADMIN-only membership
    # satisfies 'MEMBER' while SET ROLE still fails (step 030 found exactly that).
    member = store._fetchone(
        "SELECT pg_has_role(current_user, %s, 'SET')", (TENANT_ROLE,)
    )
    assert member[0] is True


def test_verify_tenant_isolation_passes_on_a_migrated_store(store, tenant):
    """Both stores: the startup check is callable and quiet where the wiring is right.
    On Postgres it proves role, membership, ownership and one scoped borrow; on the
    fake it is a documented no-op — the guard it stands in for runs on every call."""
    store.verify_tenant_isolation()


def test_a_scoped_connection_sees_one_tenant_with_no_where_clause(pg):
    """The one test that can tell the policy apart from the application. Every other
    read in this suite goes through methods that filter on tenant_id, so a vacuous
    policy would be invisible; this SELECT carries no filter at all, and what comes
    back is what the database itself decided to show."""
    from carnet.storage import tenancy

    store, tenant_id = pg
    neighbour = f"{tenant_id[:56]}-nb"
    store.create_tenant(neighbour, "Neighbour")
    store.save_agent(tenant_id, AGENT, actor=TEST_ACTOR)
    store.save_agent(neighbour, AGENT, actor=TEST_ACTOR)

    with tenancy.scoped(tenant_id):
        tenants_seen = store._fetchall("SELECT id FROM tenants")
        agents_seen = store._fetchall("SELECT DISTINCT tenant_id FROM agents")

    assert tenants_seen == [(tenant_id,)]
    assert agents_seen == [(tenant_id,)]

    # And unscoped, the same statement sees both — the owner's exemption, which is what
    # keeps the worker, rotation and the CLI whole.
    everyone = {row[0] for row in store._fetchall("SELECT DISTINCT tenant_id FROM agents")}
    assert {tenant_id, neighbour} <= everyone


def test_a_scoped_write_for_another_tenant_is_refused(store, tenant, other):
    """Both stores refuse, each with its own mechanism: Postgres's policy WITH CHECK
    ("new row violates row-level security policy"), the fake's scope-mismatch guard.
    The wide class is asserted on purpose — *that* it refuses is the contract, and how
    is each store's own."""
    from carnet.storage import tenancy

    with tenancy.scoped(tenant):
        with pytest.raises(StorageError):
            store.create_group(other, "g-foreign", "Foreign", actor=TEST_ACTOR)

    # The refusal left nothing behind, and the unscoped path still works.
    assert store.list_groups(other) == []
    store.create_group(other, "g-foreign", "Foreign", actor=TEST_ACTOR)
    assert [g["group_id"] for g in store.list_groups(other)] == ["g-foreign"]


def test_a_scoped_read_for_another_tenant_diverges_and_that_is_a_known_gap(
    store, tenant, other
):
    """Pinned divergence, the `update_agent`-on-an-unknown-tenant precedent. The same
    bug — asking a scoped store about somebody else's tenant — reads as not-found on
    Postgres (the row is invisible, which is the product's own oracle rule) and raises
    on the fake (stricter on purpose: a red test beats a silently wrong answer). Fixing
    either direction means re-deciding the other, so the gap is named instead."""
    from carnet.storage import tenancy

    store.save_agent(other, AGENT, actor=TEST_ACTOR)

    with tenancy.scoped(tenant):
        if isinstance(store, InMemoryStorage):
            with pytest.raises(StorageError, match="tenant scope violation"):
                store.get_agent(other, AGENT["name"])
        else:
            assert store.get_agent(other, AGENT["name"]) is None


def test_scoped_reads_equal_unscoped_reads_for_the_same_tenant(store, tenant):
    """The scope must be invisible to a well-behaved caller: same tenant in, same rows
    out, whether or not the borrow wore the role. This is the assertion that lets every
    existing test in this file stand as evidence about the scoped path too."""
    from carnet.storage import tenancy

    store.save_agent(tenant, AGENT, actor=TEST_ACTOR)
    unscoped = store.get_agent(tenant, AGENT["name"])
    with tenancy.scoped(tenant):
        scoped = store.get_agent(tenant, AGENT["name"])
        listed = store.load_agents(tenant)

    assert scoped == unscoped
    assert AGENT["name"] in [config["name"] for config in listed]


def test_a_returned_connection_is_unscoped(pg):
    """The pool-hygiene property, cycled enough times to visit every pooled connection:
    after a scoped borrow returns, the next unscoped borrow — very likely the same
    connection — must answer as the owner with no tenant bound. A leak here is the
    silent cross-tenant read the handoff called the part most likely to be wrong."""
    from carnet.storage import TENANT_GUC, TENANT_ROLE, tenancy

    store, tenant_id = pg
    for _ in range(25):
        with tenancy.scoped(tenant_id):
            assert store._fetchone("SELECT current_user")[0] == TENANT_ROLE
        user, bound = store._fetchone(
            "SELECT current_user, current_setting(%s, true)", (TENANT_GUC,)
        )
        assert user != TENANT_ROLE
        assert bound in ("", None)


def test_the_tenant_role_with_no_tenant_bound_raises_the_sentence(pg):
    """The loud half of decision 6. `tenant_id = NULLIF(current_setting(...), '')`
    would have silently filtered everything — zero rows that read as an empty table —
    so the policy function raises instead, naming the seam that should have bound a
    tenant. This is the tripwire for the first hand-written path that takes the role
    without going through `_connection()`."""
    import psycopg

    from carnet.storage import TENANT_ROLE

    store, _tenant_id = pg
    with psycopg.connect(store._dsn, autocommit=True) as conn:
        conn.execute(f"SET ROLE {TENANT_ROLE}")
        with pytest.raises(psycopg.Error, match="no tenant is bound"):
            conn.execute("SELECT count(*) FROM agents")


def test_claim_run_under_a_scope_is_filtered_which_is_why_the_worker_never_scopes(
    pg, rid
):
    """Decision 4, asserted from the sharp side: if a scoped connection *did* run the
    claim, another tenant's queued run would be invisible to it. That is exactly what
    would break the queue — so the worker's loops never set a scope, and the policies
    are targeted at a role the worker never takes."""
    from carnet.storage import tenancy

    store, tenant_id = pg
    neighbour = f"{tenant_id[:56]}-nb"
    store.create_tenant(neighbour, "Neighbour")
    store.enqueue_run(neighbour, a_run(rid("n")))

    with tenancy.scoped(tenant_id):
        assert (
            store.claim_run("w-scoped", lease_seconds=5, limit_to_tenant=neighbour)
            is None
        )

    claimed = store.claim_run("w-open", lease_seconds=5, limit_to_tenant=neighbour)
    assert claimed is not None and claimed["run_id"] == rid("n")


# --- step 029's testing pass: the edges, and the guard on the guard ----------------


def test_the_policy_guard_actually_catches_a_table_without_one(pg):
    """**The guard on the guard**, and the reason the one above is worth anything.

    A catalog walk that asserts a property every table happens to have would pass just
    as green if it were walking nothing, or asserting nothing. So: create a table with a
    `tenant_id` and no policy — precisely what a future migration that forgets one
    leaves behind — and assert the guard's own query reports it. The `>= 20` floor in
    that test is the other half of this; both exist because a silent list is the failure
    mode a guard test cannot see about itself."""
    store, _tenant_id = pg
    store._execute("CREATE TABLE forgotten_policy (tenant_id TEXT NOT NULL, x INT)")
    try:
        unguarded = store._fetchall(
            """
            SELECT c.relname
              FROM pg_class c
              JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
               AND NOT c.relispartition
               AND EXISTS (SELECT 1 FROM pg_attribute a
                            WHERE a.attrelid = c.oid AND a.attname = 'tenant_id'
                              AND a.attnum > 0 AND NOT a.attisdropped)
               AND NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid)
            """
        )
        assert [row[0] for row in unguarded] == ["forgotten_policy"]

        # And it is not merely unpolicied — it is unprotected: RLS is off, so a scoped
        # session would read every tenant's rows out of it.
        rls = store._fetchone(
            "SELECT relrowsecurity FROM pg_class WHERE relname = 'forgotten_policy'"
        )
        assert rls[0] is False
    finally:
        store._execute("DROP TABLE forgotten_policy")


def test_scoped_writes_reach_the_partitioned_log_tables(pg):
    """The three partitioned tables under a scope: partition routing, the identity
    sequence, and the append-only triggers all have to work for a *restricted* role, and
    a policy on the parent has to govern rows that live in a child. Nothing in this
    suite scoped a write before 029, so none of that was exercised — and the failure
    would have been every audit row a request writes."""
    from carnet.storage.base import make_denial_record
    from carnet.storage import tenancy

    store, tenant_id = pg
    # A neighbour with audit rows of its own, written first and unscoped — without one,
    # the no-WHERE assertion below passes whether or not the policy did anything,
    # because this test's tenant would be the only one in the table.
    neighbour = f"{tenant_id[:52]}-nb"
    store.create_tenant(neighbour, "Neighbour")
    store.append_audit(neighbour, _record())

    with tenancy.scoped(tenant_id):
        store.append_audit(tenant_id, _record())
        store.record_denial(
            tenant_id,
            make_denial_record(
                principal_kind="user", principal_id="u-sam", resource_kind="agent",
                resource_id="bot", required="user", held="",
            ),
        )
        store.create_group(tenant_id, "g-scoped", "Scoped", actor=TEST_ACTOR)

        assert len(store.audit_records(tenant_id, limit=10)) == 1
        assert len(store.denial_records(tenant_id, limit=10)) == 1
        assert len(store.admin_audit_records(tenant_id, limit=10)) >= 1

        # The parent's policy governs rows that live in a child partition: no WHERE
        # clause, and the neighbour's rows are not there.
        assert store._fetchall("SELECT DISTINCT tenant_id FROM audit") == [(tenant_id,)]


def test_a_tenantless_token_lookup_under_a_scope_still_finds_its_own_row(pg):
    """`find_api_token` and `touch_api_token` take no tenant — and are called from
    `act_for` and `require_owner_or_admin` **inside** a scope, which is every schedule
    fire, every trigger delivery and every schedule/trigger route. If the policy hid
    the row from its own tenant, all of those would fail with "no such token" and the
    cause would be three layers away. Driven by e2e_triggers and e2e_schedules
    incidentally; pinned here so a policy change fails by name instead."""
    from carnet.storage import tenancy

    store, tenant_id = pg
    store.create_api_token(
        tenant_id,
        {"id": "tok_scope", "name": "n", "secret_hash": "h", "owner_kind": "user",
         "owner_id": "u1", "created_by": TEST_ACTOR, "expires_at": None},
        actor=TEST_ACTOR,
    )

    with tenancy.scoped(tenant_id):
        found = store.find_api_token("tok_scope")
        assert found is not None and found["tenant_id"] == tenant_id
        store.touch_api_token("tok_scope")
        assert store.find_api_token("tok_scope")["last_used_at"] is not None

    # And from another tenant's scope the same global id is simply not there — the
    # invisibility rule, which is also the check `act_for` makes explicitly.
    other_tenant = f"{tenant_id[:52]}-other"
    store.create_tenant(other_tenant, "Other")
    with tenancy.scoped(other_tenant):
        assert store.find_api_token("tok_scope") is None


def test_a_failed_scoped_statement_leaves_the_connection_clean(pg):
    """Both failure shapes — a statement that violates a constraint, and a transaction
    that rolls back — must still unscope on the way out. A connection returned to the
    pool still wearing a tenant is the leak this design's `finally` exists for, and an
    error path is where a `finally` is most likely to be wrong."""
    from carnet.storage import TENANT_GUC, TENANT_ROLE, tenancy

    store, tenant_id = pg

    with pytest.raises(StorageError):
        with tenancy.scoped(tenant_id):
            store._execute(
                "INSERT INTO tenants (id, name) VALUES (%s, 'dup')", (tenant_id,)
            )
    user, bound = store._fetchone(
        "SELECT current_user, current_setting(%s, true)", (TENANT_GUC,)
    )
    assert user != TENANT_ROLE and bound in ("", None)

    with pytest.raises(StorageError):
        with tenancy.scoped(tenant_id):
            with store._transaction() as cur:
                cur.execute(
                    "INSERT INTO tenants (id, name) VALUES (%s, 'dup')", (tenant_id,)
                )
    user, bound = store._fetchone(
        "SELECT current_user, current_setting(%s, true)", (TENANT_GUC,)
    )
    assert user != TENANT_ROLE and bound in ("", None)


def test_a_connection_whose_reset_fails_is_closed_rather_than_pooled(pg, monkeypatch):
    """The third leg of the pool discipline, and the one a first attempt tested badly.

    Killing the backend mid-scope proves little: psycopg_pool discards an already-dead
    connection by itself, so that test passed with the `close()` removed. The case the
    `close()` is actually for is a reset that fails on a connection that is still
    **alive** — a timeout, a permission error, a failed-transaction state — where the
    pool would happily take back a connection that may still be wearing a tenant. That
    is a cross-tenant read waiting for the next borrower, so the connection is closed
    instead. Driven by making the reset itself fail."""
    import psycopg

    from carnet.storage import TENANT_GUC, TENANT_ROLE, tenancy

    store, tenant_id = pg
    captured = []
    real_execute = psycopg.Connection.execute

    def refuse_the_reset(self, query, params=None, **kwargs):
        if "set_config" in str(query) and "'role', 'none'" in str(query):
            captured.append(self)
            raise psycopg.OperationalError("simulated: the reset could not be sent")
        return real_execute(self, query, params, **kwargs)

    monkeypatch.setattr(psycopg.Connection, "execute", refuse_the_reset)
    with tenancy.scoped(tenant_id):
        assert store._fetchall("SELECT id FROM tenants") == [(tenant_id,)]
    monkeypatch.undo()

    assert captured, "the reset never ran — this test is not exercising what it claims"
    assert captured[0].closed, (
        "a connection whose reset failed went back to the pool; its tenant is unknown "
        "and the next borrower inherits it"
    )

    # And the pool carries on: a discarded connection is replaced, not lost.
    assert store._fetchone("SELECT 1")[0] == 1
    user, bound = store._fetchone(
        "SELECT current_user, current_setting(%s, true)", (TENANT_GUC,)
    )
    assert user != TENANT_ROLE and bound in ("", None)


def test_a_connection_that_dies_mid_scope_lets_the_pool_recover(pg):
    """The neighbouring case, and deliberately a weaker claim than the test above: when
    the backend is killed under a live scope, psycopg_pool's own health check is what
    discards it. What is asserted here is only that the store survives it and hands out
    something clean afterwards — because a dead connection cannot leak a tenant, and
    claiming this proves the `close()` would be claiming too much."""
    import psycopg

    from carnet.storage import TENANT_GUC, TENANT_ROLE, tenancy

    store, tenant_id = pg
    with pytest.raises(psycopg.Error):
        with tenancy.scoped(tenant_id):
            with store._connection() as conn:
                pid = conn.execute("SELECT pg_backend_pid()").fetchone()[0]
                with psycopg.connect(store._dsn, autocommit=True) as killer:
                    killer.execute("SELECT pg_terminate_backend(%s)", (pid,))
                conn.execute("SELECT 1")

    assert store._fetchone("SELECT 1")[0] == 1
    user, bound = store._fetchone(
        "SELECT current_user, current_setting(%s, true)", (TENANT_GUC,)
    )
    assert user != TENANT_ROLE and bound in ("", None)
    with tenancy.scoped(tenant_id):
        assert store._fetchall("SELECT id FROM tenants") == [(tenant_id,)]


def test_an_empty_tenant_scope_raises_rather_than_matching_nothing(pg):
    """`scope_to("")` is a bug in whatever computed it, and it must not read as "this
    tenant owns no rows". The policy function's own refusal covers it, which is the
    same sentence that covers a hand-written path forgetting to bind — one refusal for
    the whole family of "the role is in force and the tenant is not"."""
    from carnet.storage import tenancy

    store, _tenant_id = pg
    with tenancy.scoped(""):
        with pytest.raises(StorageError, match="no tenant is bound"):
            store._fetchall("SELECT id FROM tenants")


def test_the_migration_ledger_is_invisible_to_a_scoped_session(pg):
    """`schema_migrations` has RLS on and no policy — default deny — because no scoped
    session has business in the ledger. Asserted from both sides so "invisible" is
    distinguished from "empty"."""
    from carnet.storage import tenancy

    store, _tenant_id = pg
    assert store._fetchone("SELECT count(*) FROM schema_migrations")[0] > 0
    with tenancy.scoped("anything"):
        assert store._fetchone("SELECT count(*) FROM schema_migrations")[0] == 0


def test_a_cross_tenant_write_through_require_tenant_says_the_tenant_is_missing(
    store, tenant, other
):
    """A pinned surprise rather than a defect. `_require_tenant` reads `tenants`, and
    under a scope another customer's row is invisible — so a scoped-to-A write naming B
    is refused as *"tenant 'B' does not exist"* even though it does. That is the
    invisibility rule applied consistently (and the same answer the API gives for a
    file or an agent), but the sentence would mislead an operator debugging one, so it
    is written down here rather than discovered there. Both stores refuse; only the
    wording differs, which is why the assertion is on the class."""
    from carnet.storage import tenancy

    with tenancy.scoped(tenant):
        with pytest.raises(StorageError):
            store.save_agent(other, AGENT, actor=TEST_ACTOR)

    assert store.get_agent(other, AGENT["name"]) is None


def test_an_unreachable_database_is_not_the_isolation_checks_verdict(pg):
    """A regression this testing pass caused and then fixed, pinned so it cannot come
    back quietly.

    `verify_tenant_isolation` runs at every entry point now, and a first version of it
    answered *"no database connection available"* for a database that was merely down —
    pre-empting the words each command already has for an outage. `--finish-rotation`'s
    are the sharpest (*"nothing is half-written"*, step 026): a runbook reading the
    generic message loses the one fact that tells an operator the rotation did not half
    happen. So an unreachable database returns without a verdict, and the caller fails
    where it always did."""
    from carnet.storage.postgres import PostgresStorage

    unreachable = PostgresStorage.__new__(PostgresStorage)

    def refuse(*_args, **_kwargs):
        raise StorageError("no database connection available: simulated")

    unreachable._fetchone = refuse
    unreachable.verify_tenant_isolation()  # returns quietly, says nothing it cannot know

    # And a database that *is* reachable still gets a real verdict — this test must not
    # pass by making the check unable to refuse anything.
    store, _tenant_id = pg
    store.verify_tenant_isolation()
    broken = PostgresStorage.__new__(PostgresStorage)
    answers = iter([(1,), (None,)])  # reachable, then: 037 has not been applied
    broken._fetchone = lambda *a, **k: next(answers)
    with pytest.raises(StorageError, match="has not had migration 037 applied"):
        broken.verify_tenant_isolation()


# --- the door as an OAuth resource server -------------------------------------------
#
# Step 083, migration 053. Two tables that exist before a token does. Both stores,
# because the compare-and-set on a code and the tenantless reads are exactly the shapes
# the fake and the real store have disagreed about before.


def _client_id(tenant, suffix=""):
    """Global primary key, like `api_tokens.id` — see `_token_id`."""
    return f"oc_{tenant}{suffix}".replace("-", "_")[:64]


def _client(tenant, **overrides):
    row = {
        "id": _client_id(tenant),
        "client_name": "Claude Desktop",
        "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
        "metadata": {"client_uri": "https://claude.ai"},
    }
    row.update(overrides)
    return row


def _code(tenant, **overrides):
    row = {
        "code_hash": f"sha256${hashlib.sha256(tenant.encode()).hexdigest()}",
        "client_id": _client_id(tenant),
        "owner_id": "u-priya",
        "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
        "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "resource": "https://carnet.acme.com/api/mcp",
        "token_name": "Claude Desktop",
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    row.update(overrides)
    return row


def test_an_oauth_client_round_trips_without_a_tenant(store, tenant):
    """The first table keyed on nothing tenant-shaped: a client registers before anybody
    signs in, so `find` takes an id and nothing else, and the row carries no tenant."""
    from carnet.storage import OAUTH_CLIENT_FIELDS

    created = store.create_oauth_client(_client(tenant))
    found = store.find_oauth_client(_client_id(tenant))

    assert set(created) == set(OAUTH_CLIENT_FIELDS)
    assert found == created
    assert "tenant_id" not in found
    assert found["client_name"] == "Claude Desktop"
    assert found["redirect_uris"] == ["https://claude.ai/api/mcp/auth_callback"]
    assert found["metadata"] == {"client_uri": "https://claude.ai"}
    assert found["last_consented_at"] is None
    assert store.find_oauth_client("oc_nobody") is None
    assert store.find_oauth_client("") is None


def test_registering_a_client_is_bounded_at_the_store(store, tenant):
    """The registration endpoint carries no credential, so every field was written by
    somebody nobody authenticated. The access layer refuses first; the store refuses
    again, because a bound enforced in one layer is one the next caller lacks."""
    with pytest.raises(StorageError, match="1 to 10 redirect"):
        store.create_oauth_client(_client(tenant, redirect_uris=["https://a/"] * 11))
    with pytest.raises(StorageError, match="1 to 10 redirect"):
        store.create_oauth_client(_client(tenant, redirect_uris=[]))
    with pytest.raises(StorageError, match="2048"):
        store.create_oauth_client(_client(tenant, redirect_uris=["https://" + "a" * 2048]))
    with pytest.raises(StorageError, match="1 to 200"):
        store.create_oauth_client(_client(tenant, client_name=""))
    with pytest.raises(StorageError, match="1 to 200"):
        store.create_oauth_client(_client(tenant, client_name="x" * 201))
    with pytest.raises(StorageError, match="4096"):
        store.create_oauth_client(_client(tenant, metadata={"blob": "x" * 5000}))
    assert store.find_oauth_client(_client_id(tenant)) is None


def test_a_duplicate_client_id_is_a_collision_not_a_caller_error(store, tenant):
    store.create_oauth_client(_client(tenant))
    with pytest.raises(StorageError, match="already exists"):
        store.create_oauth_client(_client(tenant, client_name="another"))


def test_a_consented_client_survives_the_sweep_and_an_unused_one_does_not(store, tenant):
    """`last_consented_at` is the sweep's key. A client anybody ever approved is kept:
    its tokens name it and the person may re-consent."""
    store.create_oauth_client(_client(tenant, id=_client_id(tenant, "used")))
    store.create_oauth_client(_client(tenant, id=_client_id(tenant, "idle")))
    store.touch_oauth_client(_client_id(tenant, "used"))
    assert store.find_oauth_client(_client_id(tenant, "used"))["last_consented_at"] is not None

    assert store.sweep_oauth_clients(unused_for_seconds=3600) == 0
    gone = store.sweep_oauth_clients(unused_for_seconds=0)
    assert gone >= 1
    assert store.find_oauth_client(_client_id(tenant, "used")) is not None
    assert store.find_oauth_client(_client_id(tenant, "idle")) is None


def test_a_code_round_trips_and_is_found_without_a_tenant(store, tenant):
    """The token request carries no bearer, so the row is what supplies the tenant —
    `find_api_token`'s pattern, one table over."""
    from carnet.storage import OAUTH_CODE_FIELDS

    store.create_oauth_client(_client(tenant))
    store.create_oauth_code(tenant, _code(tenant))
    found = store.find_oauth_code(_code(tenant)["code_hash"])

    assert set(found) == set(OAUTH_CODE_FIELDS)
    assert found["tenant_id"] == tenant
    assert found["client_id"] == _client_id(tenant)
    assert found["owner_id"] == "u-priya"
    assert found["resource"] == "https://carnet.acme.com/api/mcp"
    assert found["used_at"] is None and found["token_id"] is None
    assert found["expires_at"].tzinfo is not None
    assert store.find_oauth_code("sha256$nothing") is None


def test_a_code_needs_a_registered_client_and_a_live_expiry(store, tenant):
    with pytest.raises(ValueRefused, match="no OAuth client"):
        store.create_oauth_code(tenant, _code(tenant))
    store.create_oauth_client(_client(tenant))
    with pytest.raises(StorageError, match="timezone-aware"):
        store.create_oauth_code(tenant, _code(tenant, expires_at=datetime(2030, 1, 1)))
    with pytest.raises(StorageError, match="missing"):
        store.create_oauth_code(tenant, _code(tenant, code_challenge=""))
    store.create_oauth_code(tenant, _code(tenant))
    with pytest.raises(StorageError, match="already exists"):
        store.create_oauth_code(tenant, _code(tenant))


def test_a_code_is_consumed_exactly_once_and_remembers_its_token(store, tenant):
    """The compare-and-set is the single-use guarantee: two exchanges racing on one code
    cannot both mint. The row survives its use, because a replay has to find it to know
    which token to revoke."""
    store.create_oauth_client(_client(tenant))
    store.create_oauth_code(tenant, _code(tenant))
    code_hash = _code(tenant)["code_hash"]

    assert store.consume_oauth_code(code_hash) is True
    assert store.consume_oauth_code(code_hash) is False
    assert store.consume_oauth_code("sha256$nothing") is False
    assert store.consume_oauth_code("") is False

    store.record_oauth_code_token(code_hash, "m_minted")
    found = store.find_oauth_code(code_hash)
    assert found["used_at"] is not None
    assert found["token_id"] == "m_minted"


def test_sweeping_codes_keeps_a_used_row_inside_the_window(store, tenant):
    """Expired-and-swept is later than expired: the window is what lets a replayed code
    be recognised as one rather than as an unknown string."""
    store.create_oauth_client(_client(tenant))
    live = _code(tenant)
    stale = _code(
        tenant,
        code_hash="sha256$" + "b" * 64,
        expires_at=datetime.now(timezone.utc) - timedelta(hours=2),
    )
    store.create_oauth_code(tenant, live)
    store.create_oauth_code(tenant, stale)
    store.consume_oauth_code(live["code_hash"])

    assert store.sweep_oauth_codes(older_than_seconds=3600) >= 1
    assert store.find_oauth_code(live["code_hash"]) is not None
    assert store.find_oauth_code(stale["code_hash"]) is None


def test_deleting_a_tenant_takes_its_codes_and_leaves_the_client(store, tenant):
    """`oauth_codes` cascades from `tenants`; `oauth_clients` has no tenant to cascade
    from and outlives every customer that ever consented to it."""
    store.create_oauth_client(_client(tenant))
    store.create_oauth_code(tenant, _code(tenant))
    store.set_tenant_status(tenant, "suspended")
    store.delete_tenant(tenant, actor=TEST_ACTOR)

    assert store.find_oauth_code(_code(tenant)["code_hash"]) is None
    assert store.find_oauth_client(_client_id(tenant)) is not None


# --- a price is arithmetic, so the boundary checks the whole table (step 086) --------
#
# These were found by driving a **wholesale** write — `save_connector`, which is `--seed`
# and any manifest writer — against real Postgres. The rules lived one layer up in
# `tools/rest.check_binding`, so the vet path ran them and this path did not. Three of
# the four below broke money and one of them broke the door outright.

_PRICED = {"input": 1.0, "output": 1.0, "cache_read": 0.0, "cache_write": 0.0}


def _rest_manifest(pricing):
    schema = {"type": "object", "properties": {"model": {"type": "string"}},
              "required": ["model"]}
    return {
        "id": "vendor",
        "description": "",
        "launch": {"kind": "rest", "url": "https://api.v.example/v1",
                   "credential_env": "OPENAI_BROKERED_KEY"},
        "vetted": [{
            "remote_name": "chat", "effect": "write", "identity": "service",
            "resources": [{"type": "vendor.model", "args": ["model"]}],
            "binding": {"method": "POST", "path": "/chat", "body": ["model"],
                        "input_schema": schema, "usage_map": {"model": "model"},
                        "pricing": pricing},
        }],
    }


@pytest.mark.parametrize(
    "label,pricing,fragment",
    [
        # `{"gpt-5": {}}` stored, and then `estimate_cost` did `rate["input"]` on it.
        # `door_spend_today` is on every metered door call, so one seeded typo was a 500
        # on every brokered call in that tenant until somebody edited the database.
        ("a rate object with no counters", {"gpt-5": {}}, "missing"),
        ("a counter that is a string",
         {"gpt-5": dict(_PRICED, input="abc")}, "missing"),
        # The quiet one, which this rule has always refused in a *file*: spend falls as
        # tokens are used, so a dollar ceiling is never reached.
        ("a negative rate", {"gpt-5": dict(_PRICED, input=-5.0)}, "negative"),
        # `isinstance(True, int)` is true, so this priced a million tokens at a dollar.
        ("a bool where a number goes", {"gpt-5": dict(_PRICED, input=True)}, "missing"),
        # `nan > ceiling` is False, so a NaN spend never trips a ceiling — and the figure
        # serializes to `{"usd": NaN}`, which no parser outside Python reads. Postgres
        # refused this at its JSON parser and the fake took it: a two-store split, closed.
        ("NaN", {"gpt-5": dict(_PRICED, input=float("nan"))}, "not finite"),
        ("an infinite rate", {"gpt-5": dict(_PRICED, input=float("inf"))}, "not finite"),
        ("a rate that is not an object", {"gpt-5": [1, 2, 3, 4]}, "not an object"),
        ("an empty key", {"": dict(_PRICED)}, "not usable as a key"),
    ],
)
def test_a_price_a_figure_cannot_use_is_refused_at_the_boundary(
    store, tenant, label, pricing, fragment
):
    store.create_tenant_if_missing(tenant) if hasattr(store, "create_tenant_if_missing") else None
    store.allow_host(tenant, "api.v.example", actor=TEST_ACTOR)
    with pytest.raises(StorageError, match=fragment):
        store.save_connector(tenant, _rest_manifest(pricing), actor=TEST_ACTOR)


def test_a_well_formed_price_still_stores(store, tenant):
    """The contrast, so the rules above are not simply refusing everything."""
    store.allow_host(tenant, "api.v.example", actor=TEST_ACTOR)
    store.save_connector(tenant, _rest_manifest({"gpt-5": _PRICED}), actor=TEST_ACTOR)

    (row,) = store.get_connector(tenant, "vendor")["vetted"]
    assert row["binding"]["pricing"] == {"gpt-5": _PRICED}


def test_a_price_key_a_column_cannot_hold_is_refused_in_both_stores(store, tenant):
    """The `families` rule at the other new position. Postgres answered *"unsupported
    Unicode escape sequence"* — a 503 about a value somebody typed — and the fake stored
    it happily."""
    store.allow_host(tenant, "api.v.example", actor=TEST_ACTOR)
    with pytest.raises(ValueRefused, match="cannot be stored"):
        store.save_connector(
            tenant, _rest_manifest({"gpt\x005": _PRICED}), actor=TEST_ACTOR
        )
