"""Deleting a customer, against real Postgres, with the real CLI in its own process.

The register carried "retention and tenant deletion" from 002 as the one row whose
answer was *impossible* rather than *not yet*: five tables reference `tenants(id)` with
no `ON DELETE CASCADE`, so removing a customer raised a foreign-key violation. Migration
029 builds the release valve the three append-only triggers describe in their own hints.

Four things can only fail against a real database, which is why this is a script and not
a test:

  - **the triggers.** `audit`, `admin_audit` and `access_denials` refuse DELETE by
    trigger, and the exemption is a transaction-scoped setting. The in-memory store has
    neither, so "a stray DELETE is still refused" is unassertable there.
  - **the transaction boundary.** `set_config(..., true)` lasting exactly one
    transaction is the whole reason this is not `DROP TRIGGER`, and only a database can
    say whether it does.
  - **the cascade.** Deleting a tenant takes twelve tables with it by DDL; the fake
    reimplements every one of them in Python. The catalog walk below is what says the
    two agree.
  - **the CLI's confirmation.** A typed tenant id read from stdin, in a real process,
    with a real database behind it — including the run where the operator types the
    wrong thing and nothing happens.

**It builds its own world** — a database, a populated customer, and a control customer
who must come through untouched — so it needs nobody at a keyboard.

    cd backend && .venv/bin/python scripts/e2e_tenant_deletion.py

**Costs nothing.** No run is submitted, so no model is called and no connector launched.
"""

import datetime as dt
import os
import pathlib
import subprocess
import sys
from urllib.parse import urlsplit, urlunsplit

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_tenant_deletion"


def dsn_for(database: str) -> str:
    """Where Postgres is. The socket this project has used, unless told otherwise.

    `CARNET_E2E_PG` is a base DSN with **no database name**. Not a concatenation:
    a socket DSN carries its host in the query string and a TCP one does not.
    """
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


DSN = dsn_for(DB)
DOOMED = "doomedco"
KEEPER = "keeperco"

CHECKS = []


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok))
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: {actual!r}"
          + ("" if ok else f"  (expected {expected!r})"))


def say(what):
    print(f"\n=== {what}", flush=True)


def field(row, *path):
    """Read a nested field without ever raising. 12c's `detail()`, for the same reason.

    A mutation that stops the tombstone being written makes every read below it a
    `TypeError` on `None`, which kills the run and reports one failure where six follow.
    `check()`'s whole doctrine is that a broken thing tells you everything that is
    broken — found here by running exactly that mutation.
    """
    for key in path:
        if row is None:
            return None
        try:
            row = row[key]
        except (KeyError, IndexError, TypeError):
            return None
    return row


def cli(*args, stdin=None, tenant=DOOMED, retention_days=None, rehearsing=True):
    """The real command, in its own process, against the same database.

    `retention_days` goes in the environment rather than on the command line because
    that is where it lives: `config.py` reads it at import, so a subprocess is the only
    honest way to exercise a different window.

    **The rehearsal variable is the reason this script still runs.** `--delete-tenant`
    checks `sys.stdin.isatty()` since 072's drill — a pipe is not a person, and the sentence
    it prints has always claimed one — and a subprocess with `input=` is exactly the pipe
    it refuses. `CARNET_TENANT_DELETION_REHEARSAL_I_AM_NOT_A_PERSON` is the one door,
    named to be unreachable by accident and read here rather than in a shell so that a
    person who runs this script is not the one holding it open. Everything after it is
    unchanged: the confirmation is still typed, still checked, and still wrong once on
    purpose.
    """
    env = {**os.environ, "CARNET_TENANT": tenant}
    if rehearsing:
        env["CARNET_TENANT_DELETION_REHEARSAL_I_AM_NOT_A_PERSON"] = "yes"
    else:
        # `rehearsing=False` is the scene that drives the drill's own finding: a piped
        # id, against a real database, with nothing holding the door open.
        env.pop("CARNET_TENANT_DELETION_REHEARSAL_I_AM_NOT_A_PERSON", None)
    if retention_days is not None:
        env["CARNET_RETENTION_DAYS"] = retention_days
    return subprocess.run(
        [sys.executable, "-m", "carnet.cli", *args],
        env=env,
        input=stdin,
        capture_output=True,
        text=True,
    )


def _days_ago(days):
    return dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)


AGENT = {
    "name": "payroll-bot",
    "runtime": "simple",
    "system": "You read payroll.",
    "model": "claude-haiku-4-5",
    "permissions": {"tools": ["post_message"],
                    "scope": {"chat.channel": {"write": ["#eng"]}}},
    "limits": {"max_calls": 3},
}


def audit_record(agent="payroll-bot"):
    return {
        "v": 6,
        "ts": dt.datetime.now(dt.timezone.utc),
        "run_id": "r-1",
        "principal_kind": "user",
        "principal_id": "u-priya",
        "agent": agent,
        "tool": "post_message",
        "effect": "write",
        "args": {"channel": "#eng"},
        "decision": "allow",
        "outcome": "ok",
    }


# Every table holding a tenant's data, whether it references `tenants(id)` directly or
# hangs off something that does. `populate` fills **all** of them and the run asserts so
# before deleting anything — because the first version of this script left `connections`,
# `connector_oauth` and `pending_authorizations` empty, so "nothing left behind" was
# partly a test passing by checking nothing. `connections` is the one that matters most:
# it holds sealed credentials, and its `connector_id` key is ON DELETE RESTRICT.
TENANT_TABLES = (
    "access_denials", "admin_audit", "agents", "agent_grants", "audit",
    "connections", "connector_oauth", "connectors", "group_members", "groups",
    "pending_authorizations", "pending_grants", "platform_roles", "runs",
    "tenant_egress_hosts", "tenant_idps", "users", "vetted_tools",
)

ACTOR = "system:cli"
LAUNCH = {"kind": "http", "url": "https://mcp.acme.com/mcp"}


def populate(store, tenant_id, label):
    """One customer with a row in every table a deletion has to reach. All eighteen."""
    from carnet.storage.base import make_denial_record

    store.create_tenant(tenant_id, label)
    store.save_tenant_idp(tenant_id, {
        "issuer": f"https://{tenant_id}.okta.example",
        "jwks_uri": f"https://{tenant_id}.okta.example/v1/keys",
        "audience": "api://default",
        "allowed_domains": ("acme.com",),
    })
    store.create_user(tenant_id, {
        "id": f"u-{tenant_id}",
        "issuer": f"https://{tenant_id}.okta.example",
        "subject": "00u1abc",
        "email": "priya@acme.com",
    })
    # `create_agent` rather than `save_agent`, because it writes the owner grant too —
    # `agent_grants` was one of the tables the first version of this left empty.
    store.create_agent(tenant_id, AGENT, "user", f"u-{tenant_id}")
    store.grant_agent(tenant_id, "payroll-bot", "user", "u-sam", actor=ACTOR)
    store.add_pending_grant(tenant_id, "payroll-bot", "later@acme.com", "user",
                            granted_by=ACTOR, actor=ACTOR)
    store.create_group(tenant_id, "eng", "Engineering",
                       created_by=ACTOR, actor=ACTOR)
    store.add_group_member(tenant_id, "eng", "user", f"u-{tenant_id}",
                           added_by=ACTOR, actor=ACTOR)
    store.grant_platform_role(tenant_id, "user", f"u-{tenant_id}", "admin",
                              ACTOR, actor=ACTOR)
    store.allow_host(tenant_id, "mcp.acme.com", actor=ACTOR)
    store.create_connector(tenant_id, "jira", launch=LAUNCH, actor=ACTOR)
    store.vet_tool(tenant_id, "jira",
                   {"remote_name": "search_issues", "effect": "read"}, actor=ACTOR)
    store.set_connector_oauth(
        tenant_id, "jira",
        authorize_endpoint="https://auth.example.com/authorize",
        token_endpoint="https://auth.example.com/token",
        client_id="cid", client_secret=b"SEALED-CLIENT-SECRET", key_id="k1",
        scopes=("read",), actor=ACTOR)
    # A sealed credential. The register recorded that `connections.connector_id`'s
    # RESTRICT does not block a tenant delete — verified against real Postgres, but
    # **before migrations 022 and 028 existed**. This is what re-verifies it.
    store.save_connection(tenant_id, "user", f"u-{tenant_id}", "jira",
                          ciphertext=b"SEALED-CREDENTIAL", key_id="k1",
                          account_label="priya@acme.com", actor=ACTOR)
    store.create_pending_authorization(
        f"state-{tenant_id}-" + "x" * 40, tenant_id,
        principal_kind="user", principal_id=f"u-{tenant_id}",
        connector_id="jira", code_verifier=b"verifier", key_id="k1",
        redirect_uri="https://app.example/callback")
    store.enqueue_run(tenant_id, {
        "run_id": f"run-{tenant_id}",
        "agent": "payroll-bot",
        "principal_kind": "user",
        "principal_id": f"u-{tenant_id}",
        "task": "summarise payroll",
    })
    store.append_audit(tenant_id, audit_record())
    store.record_denial(tenant_id, make_denial_record(
        "user", "u-sam", "agent", "payroll-bot", "user", ""))


def rows_per_table(store, tenant_id):
    return {
        table: count_for(store, table, tenant_id) for table in TENANT_TABLES
    }


def main():
    import psycopg

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")

    os.environ["CARNET_DATABASE_URL"] = DSN
    os.environ.setdefault("CARNET_SECRET_KEY", _key())
    os.environ["CARNET_WORKERS"] = "0"

    from carnet import storage
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    applied = migrate.apply(DSN)
    store = storage.configure(PostgresStorage(DSN))

    try:
        run(store, applied)
    finally:
        store.close()

    failed = [label for label, ok in CHECKS if not ok]
    say(f"{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    for label in failed:
        print("  FAILED:", label)
    raise SystemExit(1 if failed else 0)


def upgrade_path():
    """029 and then 030, applied to a database that already holds records — which is what
    a real deployment does and nothing else here exercises.

    Everything else here builds a database from `001` and never exercises the only
    sequence that actually happens in production: rows written under the old trigger
    definitions, then the migration, then the new code. `CREATE OR REPLACE FUNCTION`
    rebinding a body under six existing triggers is the load-bearing mechanic, and it
    is unasserted anywhere else.
    """
    import psycopg
    from carnet.storage import migrate
    from carnet.storage.base import StorageError
    from carnet.storage.postgres import PostgresStorage

    upgrade_db = f"{DB}_upgrade"
    dsn = dsn_for(upgrade_db)
    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {upgrade_db}")
        conn.execute(f"CREATE DATABASE {upgrade_db}")

    # 001..028 only, so the world below is written exactly as the old code left it.
    real_available = migrate.available

    def upto(stop: str):
        return lambda: [
            (stem, path) for stem, path in real_available() if stem < stop
        ]

    migrate.available = upto("029")
    try:
        before = migrate.apply(dsn)
    finally:
        migrate.available = real_available
    check("the pre-029 world is 28 migrations", len(before), 28)

    now = dt.datetime.now(dt.timezone.utc)
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("INSERT INTO tenants (id, name) VALUES ('legacy', 'Legacy Co')")
        for n in range(3):
            conn.execute(
                "INSERT INTO audit (tenant_id, v, ts, run_id, principal_kind, "
                "principal_id, agent, tool, args, decision) VALUES "
                "('legacy', 6, %s, %s, 'user', 'u-1', 'bot', 't', '{}', 'allow')",
                (now, f"legacy-r{n}"),
            )
            # **A gap in the ids, and it is load-bearing.** A real log has them —
            # retention deletes rows and the sequence never goes back. Without one these
            # ids are 1, 2, 3, and a copy that renumbered every row would produce 1, 2, 3
            # as well: the assertion that ids survived would pass by coincidence.
            # **Found by mutation** — dropping `OVERRIDING SYSTEM VALUE` from migration
            # 030 left this script at 100/100 until this line existed.
            conn.execute(
                "SELECT setval(pg_get_serial_sequence('audit', 'id'), %s)", (100 * (n + 1),)
            )
        conn.execute(
            "INSERT INTO admin_audit (tenant_id, v, ts, actor_kind, actor_id, action, "
            "target_kind, target_id) VALUES "
            "('legacy', 1, %s, 'user', 'u-1', 'agent.save', 'agent', 'bot')", (now,))
        conn.execute(
            "INSERT INTO access_denials (tenant_id, v, ts, principal_kind, principal_id, "
            "resource_kind, resource_id, required) VALUES "
            "('legacy', 1, %s, 'user', 'u-2', 'agent', 'bot', 'user')", (now,))

    # **029 first and 030 second, rather than both at once**, because that is the
    # sequence a deployment actually runs and each one has a different load-bearing
    # mechanic: 029 rebinds trigger bodies under six live triggers, and 030 copies every
    # row of three tables into partitions. Applying them together would prove neither
    # separately, and 030's copy would be reading rows 029 had only just made deletable.
    migrate.available = upto("030")
    try:
        check("029 applies to a populated database", migrate.apply(dsn),
              ["029_retention_and_tombstones"])
    finally:
        migrate.available = real_available

    # Raw SQL rather than a `PostgresStorage` for this stretch, because the database is
    # deliberately mid-upgrade: at 029 it has no `ensure_log_partition`, and opening a
    # store here would fire `_repair_partition_horizon` against a schema that does not
    # have it yet. That is caught and warned about by design — and a passing script that
    # prints a traceback teaches the next reader to ignore tracebacks.
    with psycopg.connect(dsn, autocommit=True) as conn:
        check("audit rows survived the migration",
              conn.execute("SELECT count(*) FROM audit").fetchone()[0], 3)
        check("administrative rows survived",
              conn.execute("SELECT count(*) FROM admin_audit").fetchone()[0], 1)
        check("denial rows survived",
              conn.execute("SELECT count(*) FROM access_denials").fetchone()[0], 1)

        # The triggers were replaced, not dropped — so they must still refuse.
        for sql in ("DELETE FROM audit", "UPDATE audit SET reason = 'x'"):
            try:
                with psycopg.connect(dsn, autocommit=True) as attacker:
                    attacker.execute(sql)
                check(f"{sql.split()[0]} on pre-029 rows refused", "permitted", "refused")
            except psycopg.errors.RaiseException as exc:
                check(f"{sql.split()[0]} on pre-029 rows refused",
                      "append-only" in str(exc), True)

        ids_before = [
            row[0] for row in
            conn.execute("SELECT id FROM audit ORDER BY id").fetchall()
        ]
        check("the legacy ids have a gap, so renumbering would be visible",
              ids_before[-1] - ids_before[0] > 2, True)

    say("and then 030 partitions those same rows underneath the same code")
    # Everything from 030 onward, derived rather than written out: this script is about
    # 029 and 030, and pinning the literal tail meant every later migration broke it —
    # which 031 duly did. What matters here is that 030 is in the batch and the batch
    # applies to a populated database.
    remaining = [stem for stem, _ in migrate.available()][29:]
    check("030 onward applies to the populated, migrated database",
          migrate.apply(dsn), remaining)
    check("and 030 is among them", "030_partition_log_tables" in remaining, True)

    aged = PostgresStorage(dsn)
    try:

        check("audit rows survived partitioning too",
              len(aged.audit_records("legacy")), 3)
        check("administrative rows survived", len(aged.admin_audit_records("legacy")), 1)
        check("denial rows survived", len(aged.denial_records("legacy")), 1)
        check("and their ids are the ones they had", [
            row[0] for row in aged._fetchall(
                "SELECT id FROM audit WHERE tenant_id = 'legacy' ORDER BY id")
        ], ids_before)

        # The triggers are new objects on new tables now, bound to the same 029 function
        # bodies. Re-asserted rather than assumed: this is the one place where a
        # migration replaced the table a trigger was attached to.
        for sql in ("DELETE FROM audit", "UPDATE audit SET reason = 'x'"):
            try:
                aged._execute(sql)
                check(f"{sql.split()[0]} on partitioned rows refused",
                      "permitted", "refused")
            except StorageError as exc:
                check(f"{sql.split()[0]} on partitioned rows refused",
                      "append-only" in str(exc), True)

        # The sequence continues past the copied ids rather than colliding with them.
        aged.append_audit("legacy", audit_record() | {"run_id": "post-030"})
        check("a new record gets an id past the copied ones", [
            row[0] for row in aged._fetchall(
                "SELECT id FROM audit WHERE tenant_id = 'legacy' ORDER BY id")
        ][-1] > max(ids_before), True)

        aged.set_tenant_status("legacy", "suspended")
        tombstone = aged.delete_tenant("legacy", actor="user:u-1")
        check("records written before 029 existed can now be deleted",
              field(tombstone, "detail", "rows", "audit"), 4)
        check("the legacy tenant is gone", aged.get_tenant("legacy"), None)
    finally:
        aged.close()


def run(store, applied):
    from carnet.storage import migrate

    say("migration 030 applies as one of the full set on an empty database")
    # Counted against `migrate.available()` rather than a literal, for the reason above.
    check("every migration applied", len(applied), len(migrate.available()))
    check("030 is among them", "030_partition_log_tables" in applied, True)
    check("idempotent on a second run", migrate_again(), [])

    say("and it applies to a database that already holds records — the upgrade path")
    upgrade_path()

    populate(store, DOOMED, "Doomed Co")
    populate(store, KEEPER, "Keeper Co")

    say("the world exists — every table, or the deletion check proves nothing")
    before = rows_per_table(store, DOOMED)
    # The meta-guard. "Nothing left behind" over a table that was empty to begin with is
    # a green check measuring nothing, which is how the first version of this script
    # passed while never touching a sealed credential.
    check("every tenant-scoped table has a row", [t for t, n in before.items() if not n], [])
    check("18 tables populated", len(before), 18)
    check("a sealed credential is among them", before["connections"], 1)
    check("so is a sealed client secret", before["connector_oauth"], 1)

    # --- the friction the three migrations asked for, still there --------------------
    say("a stray DELETE is refused on every append-only table, as before 029")
    for table in ("audit", "admin_audit", "access_denials"):
        check(f"DELETE FROM {table} refused", refused(store, f"DELETE FROM {table}"), True)
    for table, column in (("audit", "reason"), ("admin_audit", "action"),
                          ("access_denials", "required")):
        check(f"UPDATE {table} refused",
              refused(store, f"UPDATE {table} SET {column} = 'x'"), True)

    say("a raw DELETE FROM tenants still fails — no key gained a cascade")
    check("raw tenant delete refused",
          refused(store, f"DELETE FROM tenants WHERE id = '{DOOMED}'"), True)

    say("UPDATE is refused even with the retention setting on — retention shortens, "
        "it never rewrites")
    check("UPDATE under the setting refused", refused_in_retention_txn(
        store, "UPDATE audit SET reason = 'tampered'"), True)

    say("the setting does not outlive its transaction")
    with store._transaction() as cur:
        cur.execute("SELECT set_config('agent_runtime.retention', 'on', true)")
    check("DELETE refused again afterwards",
          refused(store, "DELETE FROM audit"), True)

    # --- the CLI, in its own process ------------------------------------------------
    say("the CLI refuses to delete an active customer, even correctly confirmed")
    result = cli("--delete-tenant", DOOMED, stdin=f"{DOOMED}\n")
    check("exit code", result.returncode, 2)
    check("says to suspend first", "Suspend it first" in result.stderr, True)
    check("tenant survives", store.get_tenant(DOOMED) is not None, True)

    say("suspended, then confirmed WRONGLY: nothing happens")
    store.set_tenant_status(DOOMED, "suspended")
    result = cli("--delete-tenant", DOOMED, stdin="yes\n")
    check("exit code", result.returncode, 1)
    check("says nothing deleted", "nothing deleted" in result.stderr, True)
    check("printed the counts first", "1  audit records" in result.stdout, True)
    check("warned the id is burned",
          "can never be created again" in result.stdout, True)
    check("tenant still there", store.get_tenant(DOOMED) is not None, True)
    check("audit still there", len(store.audit_records(DOOMED)), 1)

    # The drill's own finding, against a real database: the customer is suspended, the id
    # is correct, and the only thing between the pipe and an empty tenant is the check.
    # Until 072's third finding was fixed there was nothing there — `echo <id> |` deleted them, past a
    # sentence saying this is the one command that will not run unattended.
    say("piped rather than typed, with nothing holding the door open: refused")
    result = cli("--delete-tenant", DOOMED, stdin=f"{DOOMED}\n", rehearsing=False)
    check("exit code", result.returncode, 1)
    check("says it needs a terminal",
          "needs a terminal to confirm in" in result.stderr, True)
    check("names the one way past it",
          "CARNET_TENANT_DELETION_REHEARSAL_I_AM_NOT_A_PERSON" in result.stderr, True)
    check("tenant survives a correct id it should not have read",
          store.get_tenant(DOOMED) is not None, True)
    check("no tombstone was written", store.get_tenant_tombstone(DOOMED), None)
    check("audit still there", len(store.audit_records(DOOMED)), 1)

    say("confirmed with the tenant id: gone")
    result = cli("--delete-tenant", DOOMED, stdin=f"{DOOMED}\n")
    check("exit code", result.returncode, 0)
    check("says it is deleted", f"Tenant '{DOOMED}' is deleted." in result.stdout, True)
    check("tenant gone", store.get_tenant(DOOMED), None)

    say("nothing of theirs is left in any table referencing tenants")
    tables = referencing_tables(store)
    check("the catalog walk sees the tables", len(tables) >= 13, True)
    check("audit/admin_audit/access_denials/runs/groups among them",
          {"audit", "admin_audit", "access_denials", "runs", "groups"} <= set(tables),
          True)
    left = {t: count_for(store, t, DOOMED) for t in tables}
    check("rows left in any FK table", {t: n for t, n in left.items() if n}, {})
    # And the second-order tables, which hang off a connector or an agent rather than off
    # `tenants` — `vetted_tools`, `agent_grants`, `group_members`, `pending_grants`,
    # `connector_oauth`. The catalog walk above cannot see them.
    wider = rows_per_table(store, DOOMED)
    check("rows left anywhere at all", {t: n for t, n in wider.items() if n}, {})

    say("the tombstone is the surviving record")
    tombstone = store.get_tenant_tombstone(DOOMED)
    check("name", field(tombstone, "name"), "Doomed Co")
    check("actor", field(tombstone, "actor"), "system:cli")
    check("counted the audit row", field(tombstone, "detail", "rows", "audit"), 1)
    check("counted the denial",
          field(tombstone, "detail", "rows", "access_denials"), 1)
    check("counted the run", field(tombstone, "detail", "rows", "runs"), 1)
    check("counted the group", field(tombstone, "detail", "rows", "groups"), 1)
    check("detail is only v and rows",
          sorted(field(tombstone, "detail") or {}), ["rows", "v"])
    rendered = str(tombstone)
    check("names no person", "priya@acme.com" not in rendered, True)
    check("names no agent", "payroll-bot" not in rendered, True)

    say("the tombstone itself cannot be edited or removed, under any setting")
    check("UPDATE refused",
          refused(store, "UPDATE tenant_tombstones SET name = 'x'"), True)
    check("DELETE refused", refused(store, "DELETE FROM tenant_tombstones"), True)
    check("DELETE refused even in a retention transaction", refused_in_retention_txn(
        store, "DELETE FROM tenant_tombstones"), True)

    say("the id is never reused, and the CLI says so rather than crashing")
    result = cli("--add-tenant", DOOMED, "Doomed Reborn")
    check("exit code", result.returncode, 2)
    check("says never reused", "never reused" in result.stderr, True)
    # The property is that the refusal arrives as a sentence rather than as an
    # unhandled exception — checked by class name, because every CLI process on this
    # machine also prints a `PythonFinalizationError` traceback from psycopg_pool at
    # interpreter shutdown. That is pre-existing (`--list-idps` does it too), unrelated
    # to this step, and a bare "Traceback" check would be measuring it instead.
    check("the refusal is not an unhandled exception",
          "TenantDeleted" not in result.stderr, True)

    say("deleting it again answers with the tombstone rather than 'no such tenant'")
    result = cli("--delete-tenant", DOOMED, stdin=f"{DOOMED}\n")
    check("exit code", result.returncode, 0)
    check("says already deleted", "was already deleted" in result.stdout, True)
    check("names who did it", "system:cli" in result.stdout, True)

    # --- the control customer -------------------------------------------------------
    say("the other customer came through untouched")
    check("still exists", store.get_tenant(KEEPER) is not None, True)
    check("agent", len(store.load_agents(KEEPER)), 1)
    check("audit", len(store.audit_records(KEEPER)), 1)
    check("denials", len(store.denial_records(KEEPER)), 1)
    check("runs", len(store.list_runs(KEEPER)), 1)
    check("groups", len(store.list_groups(KEEPER)), 1)
    check("users", len(store.list_users(KEEPER)), 1)
    check("roles", len(store.list_platform_roles(KEEPER)), 1)
    check("no tombstone", store.get_tenant_tombstone(KEEPER), None)
    check("every one of its eighteen tables still has its rows",
          [t for t, n in rows_per_table(store, KEEPER).items() if not n], [])

    # --- retention, over the same real database --------------------------------------
    say("--prune-logs refuses without a configured window")
    result = cli("--prune-logs", tenant=KEEPER)
    check("exit code", result.returncode, 2)
    check("says no policy is configured",
          "no retention policy is configured" in result.stderr, True)
    check("records untouched", len(store.audit_records(KEEPER)), 1)

    say("a record older than the window goes; one inside it stays")
    # Migration 030 partitions these tables by month and creates coverage ahead of time,
    # so a world older than the deployment has to say how far back it reaches. Production
    # writers stamp `now` and never need this; a script back-dating a record does.
    store.ensure_log_partitions(back_to=_days_ago(120))
    store.append_audit(KEEPER, audit_record() | {"ts": _days_ago(90), "run_id": "old"})
    store.append_audit(KEEPER, audit_record() | {"ts": _days_ago(2), "run_id": "recent"})
    check("three audit records now", len(store.audit_records(KEEPER)), 3)

    result = cli("--prune-logs", tenant=KEEPER, retention_days="30")
    check("exit code", result.returncode, 0)
    check("said what it removed", "Removed 1 record(s)" in result.stdout, True)
    kept = [r["run_id"] for r in store.audit_records(KEEPER)]
    check("the old one went", "old" in kept, False)
    check("the recent one stayed", "recent" in kept, True)
    check("and so did the original", "r-1" in kept, True)

    say("the prune left a record naming the customer and the boundary")
    records = store.admin_audit_records(KEEPER, action="retention.prune")
    check("one record", len(records), 1)
    check("target is the tenant", field(records[0], "target_id"), KEEPER)
    check("actor is the sweeper", field(records[0], "actor_id"), "retention")
    check("counted one audit row", field(records[0], "detail", "rows", "audit"), 1)
    check("names no person",
          "priya@acme.com" not in str(records[0]), True)

    say("a second sweep with nothing due removes nothing and records nothing")
    result = cli("--prune-logs", tenant=KEEPER, retention_days="30")
    check("exit code", result.returncode, 0)
    check("says nothing removed", "Nothing removed" in result.stdout, True)
    check("still one prune record",
          len(store.admin_audit_records(KEEPER, action="retention.prune")), 1)

    say("zero days is refused rather than read as 'off'")
    result = cli("--prune-logs", tenant=KEEPER, retention_days="0")
    check("exit code", result.returncode, 1)
    check("says at least 1", "at least 1" in result.stderr, True)
    check("nothing removed", len(store.audit_records(KEEPER)), 2)

    say("and it can still be deleted afterwards — one deletion did not break the next")
    store.set_tenant_status(KEEPER, "suspended")
    result = cli("--delete-tenant", KEEPER, stdin=f"{KEEPER}\n", tenant=KEEPER)
    check("exit code", result.returncode, 0)
    check("gone", store.get_tenant(KEEPER), None)
    check("two tombstones", len(store.list_tenant_tombstones()), 2)


def refused(store, sql) -> bool:
    """Whether the database refuses a statement. The trigger's own sentence, not ours."""
    from carnet.storage import StorageError

    try:
        store._execute(sql)
    except StorageError as exc:
        return "append-only" in str(exc) or "violates foreign key" in str(exc)
    return False


def refused_in_retention_txn(store, sql) -> bool:
    """The same, inside a transaction that has turned the retention setting on."""
    from carnet.storage import StorageError

    try:
        with store._transaction() as cur:
            cur.execute("SELECT set_config('agent_runtime.retention', 'on', true)")
            cur.execute(sql)
    except StorageError as exc:
        return "append-only" in str(exc)
    return False


def referencing_tables(store):
    rows = store._fetchall(
        """
        SELECT DISTINCT tc.table_name
          FROM information_schema.table_constraints tc
          JOIN information_schema.constraint_column_usage ccu
            ON tc.constraint_name = ccu.constraint_name
         WHERE tc.constraint_type = 'FOREIGN KEY'
           AND ccu.table_name = 'tenants'
           AND ccu.column_name = 'id'
         ORDER BY 1
        """
    )
    return [row[0] for row in rows]


def count_for(store, table, tenant_id):
    return store._fetchone(
        f"SELECT count(*) FROM {table} WHERE tenant_id = %s", (tenant_id,)
    )[0]


def migrate_again():
    from carnet.storage import migrate

    return migrate.apply(DSN)


def _key():
    import base64

    return base64.b64encode(os.urandom(32)).decode()


if __name__ == "__main__":
    main()
