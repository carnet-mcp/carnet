"""Postgres storage. Raw SQL over psycopg3.

No ORM, deliberately. The `Storage` protocol is already the seam an ORM is usually
reached for, so SQLAlchemy would be a second abstraction over the same joint â€” and its
declarative models would become a second place the agent config shape is defined,
which is exactly what keeping the config a plain dict avoids. These are flat rows read
by a loader; there is no object graph to map.

Every query filters on `tenant_id`, and there is no method that does not take one.
Isolation is enforced here, in the application, which makes a missed WHERE a leak.
Row-level security is the belt to these braces, and since migration 037 (step 029) it
is on: when a request's tenant is known — `tenancy.current_tenant()` — `_connection()`
hands out connections wearing the `agent_runtime_tenant` role with the tenant bound in
`agent_runtime.tenant_id`, and the database itself refuses to show anybody else's rows.
A missed WHERE on a scoped path is now a not-found instead of a leak. Unscoped borrows
(the worker, the scheduler, rotation, the CLI) are byte-identical to what every borrow
was before: the login role owns these tables, and no policy applies to the owner.

Driver exceptions are translated at this boundary so nothing above storage learns
which database is underneath.

## Why a pool, and why the helper looks like this

This held a single connection for the life of the process, which was right for a CLI
and wrong the moment an HTTP server put two requests in flight at once: psycopg
connections are not safe for concurrent use, and interleaved cursors on one connection
corrupt results rather than raising something you can catch.

The pool is not the interesting part of that change. The **helper shape** is. The old
`_execute` returned a live cursor and its callers read from it, which cannot work here:
the connection has to go back to the pool, and it cannot go back while somebody still
holds a cursor onto it. So the helper splits into three â€” `_execute` (returns nothing),
`_fetchone`, `_fetchall` â€” each of which borrows a connection, does all of its reading
inside the borrow, and returns plain Python values. That is the rule the whole file now
follows: **nothing driver-shaped escapes a `with` block.**
"""

import json
import logging
import re
from contextlib import contextmanager
from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # types only, never a runtime import — see `due_schedules`
    from datetime import date, datetime

from .base import (
    check_sealed_secret,
    normalize_schedule_changes,
    schedule_key_prefix,
    schedule_update_detail,
    ADMIN_AUDIT_FIELDS,
    AGENT_FIELDS,
    FILE_META_FIELDS,
    normalize_external_id,
    normalize_file,
    AGENT_NAME_TAKEN,
    AGENT_NAME_UNIQUE,
    AGENT_RENAME_TO_SELF,
    AGENT_ROLES,
    AGENT_VERSION_FIELDS,
    AGENT_VERSION_SUMMARY_FIELDS,
    API_TOKEN_FIELDS,
    API_TOKEN_PUBLIC_FIELDS,
    SCIM_TOKEN_FIELDS,
    SCIM_TOKEN_PUBLIC_FIELDS,
    CANCELLABLE_RUN_STATUSES,
    CONNECTOR_EXISTS,
    CONNECTOR_IN_USE,
    DEADLINE_PASSED,
    DENIAL_FIELDS,
    BUDGET_REFUSAL_MARKER,
    LEADERBOARD,
    CEILING_REFUSAL_MARKER,
    SPEND_REFUSAL_MARKER,
    check_audit_tokens,
    DOOR_CALL_ID_PREFIX,
    normalize_audit_record,
    DERIVED_CONNECTOR_FIELDS,
    GRANT_FIELDS,
    PENDING_GRANT_FIELDS,
    GROUP_FIELDS,
    GROUP_MEMBER_FIELDS,
    GROUP_LINK_TAKEN,
    GROUP_NAME_TAKEN,
    GROUP_RENAME_TAKEN,
    SCIM_ISSUER_NOT_REGISTERED,
    LEASE_LOST,
    NO_OWNER,
    NO_SUCH_AGENT_TO_SCHEDULE,
    NO_SUCH_CONNECTOR,
    NO_SUCH_CONNECTOR_TO_TRUST,
    NO_SUCH_CONNECTOR_TO_VET,
    NO_SUCH_GROUP,
    NO_SUCH_AGENT_TO_TRIGGER,
    NO_SUCH_TOKEN_TO_FIRE_AS,
    NO_SUCH_TOKEN_TO_TRIGGER,
    OAUTH_APP_FIELDS,
    OAUTH_APP_PUBLIC_FIELDS,
    OWNER_ROLE,
    OWNER_TAKEN,
    PENDING_AUTHORIZATION_FIELDS,
    PLATFORM_ROLE_FIELDS,
    RETAINED_LOG_TABLES,
    RETENTION_ACTOR,
    RETENTION_GUC,
    RETENTION_GUC_ON,
    TENANT_GUC,
    TENANT_ROLE,
    RUN_FIELDS,
    RESTORED_FROM_FK,
    SCHEDULE_AGENT_FK,
    SCHEDULE_FIELDS,
    SCHEDULE_TOKEN_FK,
    TRIGGER_AGENT_FK,
    TRIGGER_FIELDS,
    TRIGGER_TOKEN_FK,
    RESTORED_FROM_UNKNOWN,
    VERSION_COLLISION,
    STATIC_CREDENTIAL,
    TENANT_BLOCKING_TABLES,
    TENANT_STATUSES,
    TOMBSTONE_FIELDS,
    USER_STATUSES,
    AgentNameTaken,
    ConnectorExistsError,
    ConnectorInUseError,
    FollowUpConflict,
    IssuerConflictError,
    NO_SUCH_PARENT,
    NoSuchConnectorError,
    NoSuchGroupError,
    ONE_LIVE_CHILD,
    StorageError,
    TenantDeleted,
    TenantDeletionRefused,
    UnknownConnectorError,
    UnknownTenantError,
    ValueRefused,
    agent_detail,
    check_agent_name,
    check_claimant,
    check_connection,
    check_reseal,
    check_credential_kind,
    check_grant,
    check_oauth_app,
    check_pending_authorization,
    check_platform_role,
    check_pending_role,
    check_principal_kind,
    check_terminal_status,
    compose_run_fingerprint,
    check_config_is_storable,
    check_next_fire_at,
    check_outcome,
    check_version_limit,
    check_version_number,
    check_version_source,
    log_partition_months,
    make_admin_record,
    make_tombstone,
    missing_partition,
    prune_floor,
    normalize_email,
    normalize_host,
    normalize_idp,
    normalize_authorize_params,
    describe_cadence,
    normalize_run,
    normalize_schedule,
    normalize_trigger,
    normalize_scope_notes,
    normalize_scopes,
    normalize_api_token,
    normalize_usage,
    normalize_user,
    normalize_user_external_id,
    normalize_scim_token,
    normalize_vetted_tool,
    check_binding_kind,
    new_agent_id,
    split_actor,
    _UNSET,
    OAUTH_CLIENT_FIELDS,
    OAUTH_CODE_FIELDS,
    normalize_oauth_client,
    normalize_oauth_code,
)
from . import tenancy

log = logging.getLogger(__name__)

# Sized for a threadpool-backed HTTP server rather than a CLI. `max_size` should stay
# comfortably under the database's own connection limit; `min_size` keeps a couple warm
# so the first request of the day does not pay for a handshake.
DEFAULT_POOL_MIN_SIZE = 2
DEFAULT_POOL_MAX_SIZE = 10

# How long a caller waits for a connection before giving up. A request that blocks
# forever on an exhausted pool is a server that has stopped answering while appearing
# healthy; a timeout is at least a 503 somebody can see.
DEFAULT_POOL_TIMEOUT = 10.0

# The first 32 bits of `pg_advisory_xact_lock(int4, int4)`, reserving a namespace for
# this schema's locks. Advisory locks are a **single global keyspace per database** with
# no ownership and no registry: any extension, any other application sharing the
# database, and any future lock of our own can collide with a bare hash of a string, and
# the symptom is not an error — it is two unrelated things silently serialising, or worse,
# one of them getting a lock it does not deserve. The two-argument form gives a free
# namespace, so the collision surface is our own keys only.
_LOCK_NAMESPACE = 0x7B0A

# The second half of the advisory key for partition maintenance. A fixed number rather
# than a digest, because unlike a refresh lock there is exactly one of these: every
# process ensuring partitions is contending for the same thing, and they should all
# queue behind one another. Migration 030.
_PARTITION_LOCK_KEY = 30

# And the lock that makes exactly one retention sweep run at a time. **A different key
# from the one above, and that is load-bearing**: `prune_log_records` holds this one while
# calling `ensure_log_partitions`, which takes `_PARTITION_LOCK_KEY` on a *different*
# pooled connection — so a shared key would have a sweep waiting on itself.
_SWEEP_LOCK_KEY = 31


def _advisory_key(*parts: str) -> int:
    """A stable 32-bit signed key for one `(tenant, principal, connector)`.

    `hash()` is deliberately not used: Python salts string hashing per process, so two
    workers would compute different keys for the same connection and the lock would
    protect nothing while appearing to work. This has to be stable across processes and
    across restarts, so it is a real digest.
    """
    import hashlib

    digest = hashlib.sha256(
        b"carnet/refresh-lock/v1|"
        + b"|".join(f"{len(p)}:{p}".encode("utf-8") for p in parts)
    ).digest()
    # int4, so signed 32-bit. Postgres rejects anything wider.
    return int.from_bytes(digest[:4], "big", signed=True)


def _open_pool(dsn: str, min_size: int, max_size: int, timeout: float):
    from psycopg_pool import ConnectionPool

    # autocommit, so a single statement is a single statement â€” the same semantics the
    # one-connection version had. Multi-statement writes ask for a transaction
    # explicitly via `_transaction()`, which is legal on an autocommit connection and
    # is the only place this file wants one.
    return ConnectionPool(
        dsn,
        min_size=min_size,
        max_size=max_size,
        timeout=timeout,
        kwargs={"autocommit": True},
        open=True,
    )


# The ranking window every capped leaderboard on the overview shares. Step 066.
#
# `ROW_NUMBER()` rather than a `LIMIT` on the inner query, because the tail has to be the
# rows the cap excluded and a `LIMIT` throws them away before anything can count them.
# `COUNT(*) OVER ()` is the true total on every row, which is what makes "15 of 5,214" a
# fact from the same scan that produced the fifteen.
#
# `{tiebreak}` is the ranking's second key, and it is `.format`-substituted from a
# literal at each call site — never from anything a caller supplies. It is a column name,
# which cannot be a parameter, so the only safe spelling is one that never touches input.
_RANKED_SQL = (
    " SELECT *, ROW_NUMBER() OVER (ORDER BY calls DESC, {tiebreak}) AS rank,"
    "        COUNT(*) OVER () AS total"
    "   FROM ranked"
)


def _round_ms(value) -> int | None:
    """A percentile as a whole millisecond, or `None` where there was nothing to measure.

    Step 041. `percentile_cont` returns a `numeric` — psycopg hands back a `Decimal` —
    and interpolation makes it fractional on most samples. The wire carries integers,
    matching the fake, which computes the same blend in Python and rounds it.

    **`None` survives rather than becoming `0`.** A day with no timed call is not a day
    of instant calls, and the two would be indistinguishable on a chart drawn from a
    zero. It is the same distinction `audit`'s own `duration_ms` keeps by being nullable:
    *never ran* rather than *ran in no time*.
    """
    return None if value is None else round(float(value))


def _agent_name_expr(table: str) -> str:
    """`agent_name`, as a scalar subquery against `table`'s `agent_id`. Migration 035.

    The four child tables lost their `agent_name` column and kept the *field*: the FIELDS
    tuples still carry it, every caller above `storage/` still reads it, and this is where
    it now comes from.

    A subquery rather than a join, for one reason that decides it — **`RETURNING` cannot
    join.** `create_schedule`, the enable and disable paths on both schedules and triggers,
    and `update_trigger` all build their result out of a `RETURNING` clause. Rewriting each
    of them as a write followed by a second read would add a round trip and a window to
    five methods, to avoid a subquery Postgres answers from the primary key.

    What the derivation buys is that the name cannot drift. A denormalised copy in five
    tables makes a rename a five-table write, which is the disease migration 035 cures,
    with an id column added.
    """
    return (
        f"(SELECT __a.name FROM agents __a "
        f"WHERE __a.tenant_id = {table}.tenant_id "
        f"AND __a.agent_id = {table}.agent_id) AS agent_name"
    )


def _child_columns(fields: tuple, table: str) -> str:
    """A child table's SELECT list, with `agent_name` derived. See `_agent_name_expr`.

    Built from the FIELDS tuple exactly as `_AGENT_COLUMNS` is, so that device survives
    migration 035: a field added to the tuple and forgotten here is still impossible.

    Module-level rather than a method because it runs in the class body, where a
    `classmethod` is still a descriptor and not yet callable — and because it is a string
    built from constants, with no store to consult.
    """
    return ", ".join(
        _agent_name_expr(table) if field == "agent_name" else f"{table}.{field}"
        for field in fields
    )


class PostgresStorage:
    """A `Storage` implementation over a connection pool.

    Safe for concurrent use: every method borrows a connection for the length of one
    statement (or one `_transaction()` block) and returns it. Nothing is held between
    calls, so two threads never touch the same connection.
    """

    def __init__(
        self,
        dsn: str,
        *,
        min_size: int = DEFAULT_POOL_MIN_SIZE,
        max_size: int = DEFAULT_POOL_MAX_SIZE,
        timeout: float = DEFAULT_POOL_TIMEOUT,
    ):
        self._dsn = dsn
        self._pool = _open_pool(dsn, min_size, max_size, timeout)
        self._repair_partition_horizon()

    def close(self) -> None:
        self._pool.close()

    def ping(self) -> None:
        """One `SELECT 1` through `_connection`, the one borrow site — step 056.

        Through `_connection` on purpose: it is the single place tenant scope is set
        and reset, and a readiness probe does not get to be the second door. It also
        inherits the pool-timeout-to-`StorageError` translation, so the worst case
        while the database is unreachable is the pool timeout, arriving as a sentence
        rather than as a hung request. Driver errors mid-statement (a connection the
        pool held while the database went away) are translated here for the same
        reason every other method translates them.
        """
        import psycopg

        try:
            with self._connection() as conn:
                conn.execute("SELECT 1")
        except psycopg.Error as exc:
            raise StorageError(f"the database did not answer: {exc}") from exc

    def pool_stats(self) -> dict:
        """psycopg_pool's own counters, verbatim — see `Storage.pool_stats`."""
        return dict(self._pool.get_stats())

    def verify_tenant_isolation(self) -> None:
        """Refuse to start when row-level security cannot work on this database.

        Called wherever a store is configured (`bootstrap.configure`), on
        `configure_crypto`'s argument — *at startup, not at first use*. Without it a
        misconfigured deployment answers its first scoped request with a 503, and a
        worker claims **nothing at all, silently**, which is the exact failure this
        step exists to make loud.

        The checks run from the most **database-local** fact to the most global,
        because testing showed the other order lies. The role is cluster-global, so in
        a cluster where another deployment already created it, "the role exists" says
        nothing about whether *this* database has been migrated — and the startup then
        died three checks later with *"permission denied for table tenants"*, which
        names neither the cause nor the remedy.

        **An unreachable database is not this function's verdict to give**, and that
        distinction was also found by testing rather than reasoned out. Constructing a
        store has never required the database to be up — `_repair_partition_horizon`
        says so in its own docstring — and every command already has its own words for
        an outage. `--finish-rotation`'s are load-bearing (*"nothing is half-written"*,
        step 026), and answering first with a generic pool timeout took them away. So
        connectivity is probed separately and, when it fails, this returns without a
        verdict and the caller fails exactly where it did before this check existed.
        """
        try:
            self._fetchone("SELECT 1")
        except StorageError:
            log.warning(
                "could not reach the database to verify that tenant scoping works; "
                "whatever is wrong with it will surface at the first query, which is "
                "where it surfaced before this check existed",
            )
            return

        if self._fetchone("SELECT to_regprocedure('agent_runtime_tenant_id()')")[0] is None:
            raise StorageError(
                "this database has not had migration 037 applied, so row-level "
                "security is not in place and tenant requests cannot be scoped. Run "
                "--migrate before serving. (The role is cluster-global: another "
                "database in this cluster may already have created it, which says "
                "nothing about this one.)"
            )

        if self._fetchone(
            "SELECT 1 FROM pg_roles WHERE rolname = %s", (TENANT_ROLE,)
        ) is None:
            raise StorageError(
                f"this database's policies name the '{TENANT_ROLE}' role and no such "
                "role exists, so every scoped request would fail. Recreate it: "
                f"CREATE ROLE {TENANT_ROLE} NOLOGIN; then grant it to the serving role."
            )

        # 'SET', not 'MEMBER': a role that *created* the tenant role holds an implicit
        # membership row with only ADMIN OPTION, so 'MEMBER' answers true while
        # SET ROLE is still denied (migration 037's comment has the full story). What
        # scoping needs is the right to take the role, and 'SET' asks exactly that.
        member = self._fetchone(
            "SELECT pg_has_role(current_user, %s, 'SET'), current_user",
            (TENANT_ROLE,),
        )
        if not member[0]:
            raise StorageError(
                f"role '{member[1]}' cannot SET ROLE into '{TENANT_ROLE}' (not a "
                "member, or a membership without the SET option) and cannot scope "
                "tenant requests. Have an administrator run: GRANT "
                f"{TENANT_ROLE} TO {member[1]}; then restart."
            )

        # Ownership is the bypass: the worker's cross-tenant queries work because the
        # login role owns the tables and no policy applies to an owner. A non-owner
        # serving role is default-denied everything the moment migration 037 lands —
        # fail closed, and say so here rather than as empty lists at runtime.
        owner = self._fetchone(
            "SELECT r.rolname, r.rolname = current_user"
            "  FROM pg_class c"
            "  JOIN pg_namespace n ON n.oid = c.relnamespace"
            "  JOIN pg_roles r ON r.oid = c.relowner"
            " WHERE n.nspname = 'public' AND c.relname = 'tenants'"
        )
        if owner is None or not owner[1]:
            named = owner[0] if owner else "<nobody — the tables are missing>"
            raise StorageError(
                f"the tables are owned by '{named}', not by the serving role. "
                "Row-level security exempts only the owner, so the worker's "
                "cross-tenant queries would see nothing. Serve with the role that "
                "runs migrations, or reassign ownership."
            )

        # And the wiring end to end: one scoped borrow, which takes the role, binds a
        # tenant that cannot exist, and reads a policied table. Anything wrong with
        # the grants, the policy function or the reset discipline surfaces here as a
        # sentence instead of at somebody's first request.
        with tenancy.scoped("startup-probe"):
            self._fetchone("SELECT count(*) FROM tenants")

    def _repair_partition_horizon(self) -> None:
        """Top up log partition coverage when a process opens the store. Migration 030.

        One of the three callers that keep partitions ahead of the writes (see
        `ensure_log_partitions`), and the one that covers a long-lived deployment being
        restarted or a CLI being run — neither of which has a worker sweep.

        **Best-effort, deliberately.** Opening a store has never done more than build a
        pool, and making construction fail against a database that is un-migrated, at an
        older migration, or opened by a role that may not create tables would be a change
        with blast radius far beyond this step — every CLI command and every server boot
        goes through here. A missed repair is not silent: the append that outruns the
        horizon raises `missing_partition`, which names this method.

        The check is one catalog query on the common path, and the DDL only runs when
        coverage is actually short.
        """
        try:
            if self._partition_horizon_is_complete():
                return
            created = self.ensure_log_partitions()
            if created:
                log.info(
                    "created %d log partition(s) on startup: %s",
                    len(created), ", ".join(created),
                )
        except Exception:  # noqa: BLE001 - see the docstring; this must not stop a boot
            log.warning(
                "could not check or extend log partition coverage; appends will say so "
                "if it is actually short", exc_info=True,
            )

    def _partition_horizon_is_complete(self) -> bool:
        """Does every log table already have the last month `log_partition_months` wants?

        The cheap half of the startup repair: one catalog query rather than the three
        times fourteen `to_regclass` calls the full ensure would make. Only the newest
        month is checked, because coverage is created as a contiguous run and the newest
        is the one that expires.
        """
        newest = log_partition_months()[-1]
        rows = self._fetchall(
            "SELECT count(*) FROM pg_class "
            " WHERE relname = ANY(%s) AND relkind = 'r'",
            ([f"{table}_p{newest:%Y_%m}" for table in RETAINED_LOG_TABLES],),
        )
        return rows[0][0] == len(RETAINED_LOG_TABLES)

    def ensure_log_partitions(self, *, back_to=None) -> list:
        created: list[str] = []
        with self._transaction() as cur:
            # Blocking rather than `try`, unlike `refresh_lock`: the loser here wants the
            # work done, not to be told somebody else is doing it, and the wait is the
            # length of a few CREATE TABLEs rather than a third party's HTTP round trip.
            # Transaction-scoped, so a dying process releases it.
            cur.execute(
                "SELECT pg_advisory_xact_lock(%s, %s)",
                (_LOCK_NAMESPACE, _PARTITION_LOCK_KEY),
            )
            for month in log_partition_months(back_to):
                for table in RETAINED_LOG_TABLES:
                    name = cur.execute(
                        "SELECT ensure_log_partition(%s, %s)", (table, month)
                    ).fetchone()[0]
                    # NULL when it was already there, so this is the list of what this
                    # call actually created rather than of what now exists.
                    if name is not None:
                        created.append(name)
        return created

    # --- helpers ----------------------------------------------------------------

    @contextmanager
    def _connection(self):
        """Borrow a connection; take the tenant role when a scope is present.

        The pool is shared across tenants, so a pooled connection carrying the previous
        borrower's tenant would be a cross-tenant read that returns data rather than an
        error. This is the one place any code borrows from the pool, and the hazard is
        answered here structurally, three ways:

          - **Overwrite at borrow.** With a scope present, one round trip sets both
            halves in a single statement — the tenant in `agent_runtime.tenant_id` and
            the `agent_runtime_tenant` role (`set_config('role', …)` is SET ROLE by
            another door) — so there is no instant where the role is active and the
            tenant unbound, whatever the connection last held.
          - **Reset at return.** The `finally` clears both before the connection
            re-enters the pool.
          - **Discard on a failed reset.** A connection that cannot prove it is
            unscoped is closed rather than pooled; psycopg_pool drops closed
            connections instead of reusing them.

        Unscoped borrows — the worker, the scheduler, rotation, the CLI, and every
        request until its principal resolves — pay nothing and behave exactly as every
        borrow did before step 029: the login role owns the tables and no policy
        applies to it. `SET LOCAL` was rejected because the pool is autocommit, so most
        statements run outside any transaction and a transaction-local setting would
        evaporate before the query it exists to scope.

        An exhausted pool is a storage failure and must arrive as one. Letting
        `PoolTimeout` through would be the first time something above this layer had to
        know psycopg_pool exists.
        """
        import psycopg
        import psycopg_pool

        try:
            with self._pool.connection() as conn:
                tenant = tenancy.current_tenant()
                if tenant is None:
                    yield conn
                    return

                try:
                    conn.execute(
                        "SELECT set_config(%s, %s, false),"
                        "       set_config('role', %s, false)",
                        (TENANT_GUC, tenant, TENANT_ROLE),
                    )
                except (
                    psycopg.errors.InsufficientPrivilege,
                    psycopg.errors.UndefinedObject,
                ) as exc:
                    # The two deployment mistakes, told apart from a network failure so
                    # the sentence can carry the remedy: the role does not exist
                    # (migration 037 has not run) or the login role is not a member of
                    # it (somebody migrated as one role and serves as another).
                    raise StorageError(
                        f"this connection cannot take the '{TENANT_ROLE}' role: "
                        f"{exc}. Run --migrate (migration 037 creates the role and "
                        "grants it to the migrating role), or have an administrator "
                        f"run: GRANT {TENANT_ROLE} TO <the serving role>."
                    ) from exc

                try:
                    yield conn
                finally:
                    try:
                        conn.execute(
                            "SELECT set_config(%s, '', false),"
                            "       set_config('role', 'none', false)",
                            (TENANT_GUC,),
                        )
                    except Exception:  # noqa: BLE001 - see the docstring: discard
                        log.warning(
                            "could not unscope a pooled connection; closing it so the "
                            "pool cannot reuse it",
                            exc_info=True,
                        )
                        conn.close()
        except psycopg_pool.PoolTimeout as exc:  # pragma: no cover - timing dependent
            raise StorageError(f"no database connection available: {exc}") from exc

    @staticmethod
    def _translate(exc):
        """Driver exception -> our exception. The whole of what this boundary hides."""
        import psycopg

        if isinstance(exc, psycopg.errors.ForeignKeyViolation):
            return UnknownTenantError(str(exc))
        if isinstance(exc, psycopg.errors.CheckViolation):
            # An insert with no partition to route to arrives as a CheckViolation, whose
            # own message — *"no partition of relation "audit" found for row"* — says
            # what happened and nothing about what to do. Migration 030's answer is a
            # maintenance call, so the sentence names it. Matched on Postgres's wording
            # rather than on SQLSTATE because the state is shared with every other CHECK.
            text = str(exc)
            if "no partition of relation" in text:
                match = re.search(r'no partition of relation "([^"]+)"', text)
                table = match.group(1) if match else "a log table"
                return StorageError(missing_partition(table, text.splitlines()[0]))
            return StorageError(text)
        if isinstance(exc, psycopg.Error):
            return StorageError(str(exc))
        return None

    def _execute(self, sql: str, params=()) -> None:
        """Run one statement for its effect. Returns nothing, deliberately.

        The old version returned the cursor. It cannot now â€” see the module docstring.
        """
        import psycopg

        try:
            with self._connection() as conn:
                conn.cursor().execute(sql, params)
        except psycopg.Error as exc:
            raise self._translate(exc) from exc

    def _fetchone(self, sql: str, params=()):
        import psycopg

        try:
            with self._connection() as conn:
                return conn.cursor().execute(sql, params).fetchone()
        except psycopg.Error as exc:
            raise self._translate(exc) from exc

    def _fetchall(self, sql: str, params=()) -> list:
        import psycopg

        try:
            with self._connection() as conn:
                return conn.cursor().execute(sql, params).fetchall()
        except psycopg.Error as exc:
            raise self._translate(exc) from exc

    @contextmanager
    def _transaction(self):
        """A borrowed connection with an explicit transaction around it.

        Two callers, and they want it for different reasons. `create_agent` needs a row
        and its owner grant to be one write, because the torn state is an agent nobody
        can run. `save_connector` replaces a connector's vetted tools by deleting them
        and re-inserting. Under one connection those were two autocommitted
        statements and the gap between them was invisible, because nothing else was
        running. Behind a server two admins saving the same connector can interleave, and
        the artifact they would tear is **the allowlist** â€” the thing the whole vetting
        model rests on. A torn allowlist is not a stale read; it is a tenant briefly
        exposing tools nobody vetted, or none at all.

        `conn.transaction()` is legal on an autocommit connection â€” it issues an explicit
        BEGIN/COMMIT and rolls back if the block raises.
        """
        import psycopg

        try:
            with self._connection() as conn, conn.transaction():
                yield conn.cursor()
        except psycopg.Error as exc:
            raise self._translate(exc) from exc

    def _require_tenant(self, tenant_id: str) -> None:
        """Checked explicitly as well as by the foreign key.

        The FK catches it on tables that have one; this gives the same error for every
        write, so the in-memory implementation and this one refuse identically rather
        than one raising UnknownTenantError and the other a driver error.
        """
        if self._fetchone("SELECT 1 FROM tenants WHERE id = %s", (tenant_id,)) is None:
            raise UnknownTenantError(
                f"tenant '{tenant_id}' does not exist. Create it before writing to it."
            )

    # --- tenants ----------------------------------------------------------------

    def create_tenant(self, tenant_id: str, name: str) -> None:
        if not tenant_id:
            raise StorageError("tenant_id must be a non-empty string")

        # Checked rather than left to a foreign key, because there is deliberately no
        # key to leave it to: `tenant_tombstones` has no FK to `tenants` (the row it
        # describes is gone). Migration 029, and the reason is that every record
        # surviving a deletion which names this id would otherwise be ambiguous between
        # two customers — in tables nobody can edit to disambiguate.
        gone = self._fetchone(
            "SELECT deleted_at, actor FROM tenant_tombstones WHERE tenant_id = %s",
            (tenant_id,),
        )
        if gone is not None:
            raise TenantDeleted(
                f"tenant '{tenant_id}' was deleted on {gone[0]:%Y-%m-%d} by {gone[1]} "
                "and its id is never reused. Choose another id."
            )

        self._execute(
            "INSERT INTO tenants (id, name) VALUES (%s, %s) ON CONFLICT (id) DO NOTHING",
            (tenant_id, name),
        )

    def get_tenant(self, tenant_id: str) -> dict | None:
        row = self._fetchone(
            "SELECT id, name, status, created_at FROM tenants WHERE id = %s",
            (tenant_id,),
        )
        if row is None:
            return None
        return {"id": row[0], "name": row[1], "status": row[2], "created_at": row[3]}

    def list_tenants(self) -> list[dict]:
        rows = self._fetchall(
            "SELECT id, name, status, created_at FROM tenants ORDER BY id"
        )
        return [
            {"id": r[0], "name": r[1], "status": r[2], "created_at": r[3]} for r in rows
        ]

    def set_tenant_status(self, tenant_id: str, status: str) -> None:
        # Checked here as well as by the CHECK constraint, for the reason `check_grant`
        # gives: the constraint is what survives somebody editing the frozenset, and
        # this is what produces a sentence rather than a constraint name.
        if status not in TENANT_STATUSES:
            raise StorageError(
                f"status must be one of {sorted(TENANT_STATUSES)}, not '{status}'"
            )
        self._execute(
            "UPDATE tenants SET status = %s WHERE id = %s", (status, tenant_id)
        )

    def delete_tenant(self, tenant_id: str, *, actor: str) -> dict:
        row = self._fetchone(
            "SELECT name, status FROM tenants WHERE id = %s", (tenant_id,)
        )
        if row is None:
            raise UnknownTenantError(
                f"tenant '{tenant_id}' does not exist. Create it before writing to it."
            )

        name, status = row

        if status != "suspended":
            raise TenantDeletionRefused(
                f"tenant '{tenant_id}' is {status}. Suspend it first — deletion is not "
                "the brake, and a customer who can still authenticate can create rows "
                "while this runs."
            )

        # `running` rather than `queued`: suspension already stops the claim loop, so
        # queued runs are inert and go with the tenant. What suspension deliberately
        # does not stop is a run already executing (migration 020 says so), and that is
        # a worker which will write audit rows for a tenant being erased underneath it.
        live = self._fetchall(
            "SELECT run_id FROM runs WHERE tenant_id = %s AND status = 'running' "
            "ORDER BY run_id",
            (tenant_id,),
        )
        if live:
            names = ", ".join(r[0] for r in live)
            raise TenantDeletionRefused(
                f"tenant '{tenant_id}' has {len(live)} run(s) still executing: {names}. "
                "Cancel them or wait — suspension does not stop a run in flight."
            )

        # Built before anything is touched, so an unusable actor refuses the deletion
        # rather than being discovered with five tables already empty.
        counts: dict = {}
        tombstone = make_tombstone(tenant_id, name, actor, counts)

        with self._transaction() as cur:
            # The whole of the exemption, and it lasts exactly as long as this
            # transaction — including if this process dies mid-block. See migration 029
            # for why this rather than DROP TRIGGER.
            cur.execute(
                "SELECT set_config(%s, %s, true)", (RETENTION_GUC, RETENTION_GUC_ON)
            )

            for table in TENANT_BLOCKING_TABLES:
                # The table name is interpolated, and it is a module constant rather
                # than anything a caller supplies — the same shape `_AGENT_COLUMNS`
                # already uses. A placeholder cannot name a table.
                deleted = cur.execute(
                    f"DELETE FROM {table} WHERE tenant_id = %s",  # noqa: S608
                    (tenant_id,),
                ).rowcount
                counts[table] = deleted

            # After the counts are known and before the tenant row goes, so the
            # tombstone is written in the same transaction as the thing it witnesses.
            tombstone["detail"]["rows"] = dict(counts)
            cur.execute(
                "INSERT INTO tenant_tombstones (tenant_id, name, actor, detail) "
                "VALUES (%s, %s, %s, %s) RETURNING deleted_at",
                (
                    tombstone["tenant_id"],
                    tombstone["name"],
                    tombstone["actor"],
                    json.dumps(tombstone["detail"]),
                ),
            )
            tombstone["deleted_at"] = cur.fetchone()[0]

            # Everything else cascades. If a table has been added since this method was
            # written and nobody updated `TENANT_BLOCKING_TABLES`, this is the statement
            # that fails — loudly, inside a transaction that rolls back, which is the
            # entire argument for not adding `ON DELETE CASCADE` to those keys.
            cur.execute("DELETE FROM tenants WHERE id = %s", (tenant_id,))

        return tombstone

    def _expired_partitions(self, table: str, floor) -> list[str]:
        """Partitions of `table` whose whole range is below `floor`, oldest first.

        Selected from the **declared partition bound** rather than from the name, which
        is the difference between reading what Postgres will actually route where and
        trusting a string this code wrote. `pg_get_expr` renders the bound in a canonical
        form — `FOR VALUES FROM ('...') TO ('...')` — and the upper bound is what decides
        whether a month is wholly expired.

        The caller re-checks the data before dropping anything; this is the cheap
        catalog-only pass that says which partitions are worth looking at.
        """
        rows = self._fetchall(
            """
            SELECT c.relname,
                   (regexp_match(
                        pg_get_expr(c.relpartbound, c.oid),
                        'TO \\(''([^'']+)''\\)'
                    ))[1]::timestamptz AS upper_bound
              FROM pg_class c
              JOIN pg_inherits i ON i.inhrelid = c.oid
              JOIN pg_class p ON p.oid = i.inhparent
             WHERE p.relname = %s
             ORDER BY 2
            """,
            (table,),
        )
        return [name for name, upper in rows if upper is not None and upper <= floor]

    @contextmanager
    def _sweep_lock(self):
        """Try to become the one retention sweep that runs. Yields True, or False.

        **Session-scoped rather than transaction-scoped, which is the one place this file
        does that**, because a sweep spans many transactions — one per partition — and a
        lock that ended with the first of them would protect only the first month. It is
        held on a single borrowed connection and released in a `finally`, so the
        connection never returns to the pool still holding it, which is the hazard
        `refresh_lock`'s docstring names. If the process dies the session ends and
        Postgres releases it; there is no state to clean up.

        `try` rather than the blocking form, and the loser does **nothing at all** rather
        than joining in. That is the correction: an earlier version took a lock per
        partition instead, which removed the deadlocks but left every sweep dropping a
        few months and skipping the rest. **Raced four sweeps against 200 aged rows and
        93 went**, because each one gave up on the months the others happened to be
        holding and no one came back for them. Two sweeps doing the same work is waste;
        two sweeps doing *half* the work each is a retention policy that under-deletes.

        Holding a pooled connection for the length of a sweep is the cost, and it is
        bounded: a drop is milliseconds, and the only slow path is `lock_timeout`, which
        is five seconds by construction.
        """
        import psycopg

        try:
            with self._connection() as conn:
                held = (
                    conn.cursor()
                    .execute(
                        "SELECT pg_try_advisory_lock(%s, %s)",
                        (_LOCK_NAMESPACE, _SWEEP_LOCK_KEY),
                    )
                    .fetchone()[0]
                )
                if not held:
                    yield False
                    return
                try:
                    yield True
                finally:
                    conn.cursor().execute(
                        "SELECT pg_advisory_unlock(%s, %s)",
                        (_LOCK_NAMESPACE, _SWEEP_LOCK_KEY),
                    )
        except psycopg.Error as exc:
            raise self._translate(exc) from exc

    def prune_log_records(self, cutoff) -> dict:
        # The boundary both stores share, so the fake cannot disagree with this one
        # about which records a sweep removes.
        floor = prune_floor(cutoff)

        with self._sweep_lock() as mine:
            if not mine:
                # Another sweep is already doing exactly this. Zero counts and no
                # records, which is honest: this call removed nothing.
                log.debug("retention: another sweep is running; standing down")
                return {table: 0 for table in RETAINED_LOG_TABLES}
            return self._prune_under_lock(floor)

    def _prune_under_lock(self, floor) -> dict:
        counts = {table: 0 for table in RETAINED_LOG_TABLES}
        # Per tenant, so the records written at the end say whose history moved. A
        # dict rather than a running total because one sweep spans every customer and
        # "4,000 rows went" is not a fact anybody can act on.
        per_tenant: dict[str, dict] = {}

        for table in RETAINED_LOG_TABLES:
            for partition in self._expired_partitions(table, floor):
                try:
                    with self._transaction() as cur:
                        # Re-read inside the transaction. The catalog was read outside it,
                        # and although the sweep lock means no *other* sweep is dropping,
                        # a partition can still have gone — a `--prune-logs` run that
                        # finished a moment ago, or an operator with psql. Skipping
                        # silently is right: the month is gone, which is the goal.
                        if not cur.execute(
                            "SELECT to_regclass(%s) IS NOT NULL", (partition,)
                        ).fetchone()[0]:
                            continue

                        # Seconds, not minutes. `DROP TABLE` needs ACCESS EXCLUSIVE on
                        # the partition and on its parent, and a lock request queues
                        # *ahead* of every writer behind it — so a drop waiting on
                        # somebody's long report would stall every log append in the
                        # product for the length of it. Timing out and trying again in an
                        # hour costs nothing against an obligation measured in days.
                        cur.execute("SET LOCAL lock_timeout = '5s'")

                        # Counted inside the same transaction as the drop, so the numbers
                        # in the record are the rows that actually went. Nothing can be
                        # written into a past month's partition meanwhile — current
                        # writes carry current timestamps — but the transaction is what
                        # makes that a guarantee rather than an argument.
                        rows = cur.execute(
                            f"""
                            SELECT tenant_id,
                                   count(*),
                                   count(*) FILTER (WHERE ts >= %s)
                              FROM {partition}
                             GROUP BY tenant_id
                            """,  # noqa: S608 - a partition name from the catalog
                            (floor,),
                        ).fetchall()

                        # The bound said this month was wholly expired; the data has the
                        # final say. A partition holding a row at or past the floor is a
                        # catalog and a table disagreeing, which must never happen — and
                        # if it ever does, nothing here is going to be the thing that
                        # deletes an unexpired record.
                        live = sum(recent for _tenant, _total, recent in rows)
                        if live:
                            log.error(
                                "retention: %s holds %d record(s) at or past the "
                                "boundary despite its bound; not dropping it",
                                partition, live,
                            )
                            continue

                        cur.execute(f"DROP TABLE {partition}")  # noqa: S608
                except StorageError as exc:
                    # A lock timeout, overwhelmingly. Retention is a days-scale
                    # obligation swept hourly, so the honest answer is to say so and
                    # leave the month for the next sweep rather than to wait.
                    log.warning(
                        "retention: could not drop %s this sweep (%s); it stays until "
                        "the next one", partition, exc,
                    )
                    continue

                for tenant_id, total, _recent in rows:
                    bucket = per_tenant.setdefault(tenant_id, {})
                    bucket[table] = bucket.get(table, 0) + total
                    counts[table] += total

        # **A method that removes partitions leaves coverage intact.** Ordinarily this
        # creates nothing: the floor is the start of the cutoff's month, so the current
        # month's partition — whose upper bound is in the future — can never be selected,
        # no matter how short the retention window is set. What made this worth writing is
        # that the very next thing this method does is write its own `retention.prune`
        # records, stamped now, into `admin_audit`; a sweep that had somehow dropped the
        # month it needed would fail while reporting what it had already destroyed.
        # **Found by a test pruning against a future cutoff**, which is the one caller
        # that can reach the state at all.
        self.ensure_log_partitions()

        for tenant_id, rows in sorted(per_tenant.items()):
            record = make_admin_record(
                "retention.prune",
                "tenant",
                tenant_id,
                RETENTION_ACTOR,
                # The **effective** boundary rather than the requested cutoff. A record
                # saying "everything before the 14th is gone" when a month-grained drop
                # removed everything before the 1st is a claim of precision the operation
                # does not have, which is the control that looks present and is absent.
                {"cutoff": floor.isoformat(), "rows": rows},
            )
            # Its own transaction, after the drops rather than inside one of them. A
            # record written during the sweep would be dropped by a later partition of
            # the same sweep if the cutoff had moved past it, which is a log that eats
            # its own account of why it is short.
            try:
                with self._transaction() as cur:
                    self._write_admin(cur, tenant_id, record)
            except UnknownTenantError:
                # The customer was deleted while this sweep ran. Their records went with
                # them, so there is nothing left to attribute and no record to write —
                # the tombstone already says what happened to that tenant's history.
                #
                # Caught rather than pre-checked, because a `SELECT` first would be the
                # same race with a smaller window. **Found by racing them**: the
                # in-memory store skipped a vanished tenant from the first version and
                # this one raised, which is store drift of exactly the kind the contract
                # suite exists to catch — and the failure was not corruption but a whole
                # retention sweep abandoning its remaining tenants for an hour.
                log.warning(
                    "retention: tenant %s was deleted mid-sweep; %d record(s) of theirs "
                    "had already aged out and are unattributed",
                    tenant_id, sum(rows.values()),
                )

        return counts

    _TOMBSTONE_COLUMNS = ", ".join(TOMBSTONE_FIELDS)

    def get_tenant_tombstone(self, tenant_id: str) -> dict | None:
        row = self._fetchone(
            f"SELECT {self._TOMBSTONE_COLUMNS} FROM tenant_tombstones "  # noqa: S608
            "WHERE tenant_id = %s",
            (tenant_id,),
        )
        return None if row is None else dict(zip(TOMBSTONE_FIELDS, row))

    def list_tenant_tombstones(self) -> list[dict]:
        rows = self._fetchall(
            f"SELECT {self._TOMBSTONE_COLUMNS} FROM tenant_tombstones "  # noqa: S608
            "ORDER BY deleted_at DESC, tenant_id"
        )
        return [dict(zip(TOMBSTONE_FIELDS, row)) for row in rows]

    # --- agents -----------------------------------------------------------------

    # `AGENT_FIELDS`, as a SELECT list. Written from the tuple rather than typed out, so
    # a column added to one and forgotten in the other cannot happen here at all.
    _AGENT_COLUMNS = ", ".join(AGENT_FIELDS)

    def _agent_id_for(self, tenant_id: str, name: str, cur=None) -> str | None:
        """This tenant's agent by name, as an id. None when there is none.

        The name→id translation the whole layer above this one is spared. Every public
        method here still takes a name, because step 025 decided the name stays the address
        at every boundary — so this is the only place the two vocabularies meet, and it is
        one indexed read on `agents_name_unique`.

        `cur` is passed when the caller is already inside a transaction, so the resolution
        and the write it feeds cannot straddle a commit.
        """
        sql = "SELECT agent_id FROM agents WHERE tenant_id = %s AND name = %s"
        if cur is not None:
            row = cur.execute(sql, (tenant_id, name)).fetchone()
        else:
            row = self._fetchone(sql, (tenant_id, name))
        return None if row is None else row[0]

    def load_agents(self, tenant_id: str) -> list[dict]:
        rows = self._fetchall(
            f"SELECT {self._AGENT_COLUMNS} FROM agents WHERE tenant_id = %s ORDER BY name",
            (tenant_id,),
        )
        return [dict(zip(AGENT_FIELDS, row)) for row in rows]

    def get_agent(self, tenant_id: str, name: str) -> dict | None:
        row = self._fetchone(
            f"SELECT {self._AGENT_COLUMNS} FROM agents "
            "WHERE tenant_id = %s AND name = %s",
            (tenant_id, name),
        )
        return dict(zip(AGENT_FIELDS, row)) if row is not None else None

    def get_agent_by_id(self, tenant_id: str, agent_id: str) -> dict | None:
        if not agent_id:
            return None
        row = self._fetchone(
            f"SELECT {self._AGENT_COLUMNS} FROM agents "
            "WHERE tenant_id = %s AND agent_id = %s",
            (tenant_id, agent_id),
        )
        return dict(zip(AGENT_FIELDS, row)) if row is not None else None

    # `agent_name` is a subquery in both — see `_agent_name_column`. The summary list is
    # still derived from its tuple, so the "no configs in a listing" rule cannot be lost by
    # somebody editing one of these two strings.
    _VERSION_COLUMNS = _child_columns(AGENT_VERSION_FIELDS, "agent_versions")
    _VERSION_SUMMARY_COLUMNS = _child_columns(
        AGENT_VERSION_SUMMARY_FIELDS, "agent_versions"
    )

    @staticmethod
    def _write_version(
        cur,
        tenant_id: str,
        agent_id: str,
        name: str,
        version: int,
        config: dict,
        created_at,
        created_by: str,
        source: str,
        restored_from: int | None = None,
    ) -> None:
        """One `agent_versions` row, **on the caller's cursor**. Step 021.

        `_write_admin`'s shape and its reasoning verbatim: the history has to land in the
        same transaction as the config write it copies, or a crash between the two leaves
        an agent whose live configuration is recorded nowhere — which is the state this
        whole step exists to make impossible.

        **`ON CONFLICT DO NOTHING` is the suppression, not a defence.** Every caller has
        just written `version` with `+ (config IS DISTINCT FROM new)::int`, so the number
        advanced exactly when the configuration changed. A conflict therefore means one
        thing only: this write changed nothing, and the row it would insert is already
        there holding the same config. Re-running `--seed` takes that branch; so does a
        restore of the version that is already live.

        That equivalence rests on the invariant — `agents.version` names the newest
        version row, and that row holds what `agents.config` holds — which this method
        and its callers maintain inductively from `create_agent`'s version 1. The
        contract suite asserts it after every write path in both stores rather than
        trusting the induction.

        `created_at` is passed in rather than defaulted, so it is the same instant the
        agent row was stamped with. See the column comment in migration 032.

        **`agent_id` keys the row and `name` only appears in refusals**, since migration
        035. Both are parameters because the two are needed for different things and the
        method must not go looking up one from the other: the id is the key, and the name is
        what a person reads in `RESTORED_FROM_UNKNOWN` or `VERSION_COLLISION`.
        """
        import psycopg

        check_version_source(source)
        if restored_from is not None:
            check_version_number(restored_from, what="restored_from")
        try:
            written = cur.execute(
                """
                INSERT INTO agent_versions (
                    tenant_id, agent_id, version, config, created_at, created_by,
                    source, restored_from
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, agent_id, version) DO NOTHING
                RETURNING version
                """,
                (
                    tenant_id,
                    agent_id,
                    version,
                    json.dumps(config),
                    created_at,
                    created_by,
                    source,
                    restored_from,
                ),
            ).fetchone()
        except psycopg.errors.ForeignKeyViolation as exc:
            # **Caught by constraint name, and the class matters more than the message.**
            # `_translate` maps every foreign-key violation to `UnknownTenantError`, which
            # is right for the keys that existed when it was written and wrong here: a
            # restore naming a version nobody wrote would have answered *"unknown
            # tenant"* about a perfectly good tenant. `save_vetted_tool` and `grant_agent`
            # already do exactly this for their own keys.
            if getattr(exc.diag, "constraint_name", "") == RESTORED_FROM_FK:
                raise ValueRefused(
                    RESTORED_FROM_UNKNOWN.format(version=restored_from, agent=name)
                ) from exc
            raise

        # **The conflict is verified rather than assumed**, and the edge hunt is why.
        # `DO NOTHING` is meant to fire only when the config did not change, so the row
        # already there holds exactly this config. Forced out of step — a counter behind
        # its history — it fires on a *different* config instead and keeps the old row
        # silently: the live configuration is then recorded nowhere while the history
        # claims to hold it, which is the one state this whole step exists to prevent.
        # One indexed read on the suppression path buys a refusal instead.
        if written is None:
            existing = cur.execute(
                "SELECT config FROM agent_versions "
                "WHERE tenant_id = %s AND agent_id = %s AND version = %s",
                (tenant_id, agent_id, version),
            ).fetchone()
            if existing is None or existing[0] != config:
                raise ValueRefused(
                    VERSION_COLLISION.format(version=version, agent=name)
                )

    def save_agent(self, tenant_id: str, config: dict, *, actor: str) -> None:
        self._require_tenant(tenant_id)

        name = config.get("name")
        # `agent_name_is_a_slug` as well as the non-empty rule, because migration 019
        # put the constraint on the column rather than on one statement — so this path
        # is subject to it too, and the fake has to refuse the same names.
        check_agent_name(name)
        check_config_is_storable(config)

        record = make_admin_record(
            "agent.save", "agent", name, actor, agent_detail(config)
        )

        # A transaction, where this used to be one autocommitted statement. That is the
        # cost decision 2 names out loud: a write that was one statement is now two, and
        # the alternative is a record that can be missing when the write succeeded.
        with self._transaction() as cur:
            # The version expression is the whole of 021's suppression on this path.
            # `--seed` is documented as safe to re-run and deployments run it on every
            # boot, so an unconditional increment would give the shipped agent a version
            # per boot and a history of nothing. `IS DISTINCT FROM` on jsonb compares the
            # parsed documents, which is what the in-memory store's dict comparison does
            # — the two agree on key order and on `1` versus `1.0`, and a comparison of
            # serialized text would not.
            # **`ON CONFLICT (tenant_id, name)` still, and it is no longer the primary
            # key.** Since migration 035 that is `agents_name_unique`, which is exactly
            # what this upsert wants: `--seed` re-runs mean *"the agent called this"*, and
            # an agent id is minted here rather than supplied, so a conflict on the id is
            # not a thing this statement can produce. The freshly minted id is discarded by
            # the DO UPDATE branch, which is what makes re-seeding leave identity alone.
            agent_id, version, updated_at = cur.execute(
                """
                INSERT INTO agents (tenant_id, agent_id, name, config)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (tenant_id, name)
                DO UPDATE SET config = EXCLUDED.config,
                              updated_at = now(),
                              version = agents.version
                                  + (agents.config IS DISTINCT FROM EXCLUDED.config)::int
                RETURNING agent_id, version, updated_at
                """,
                (tenant_id, new_agent_id(), name, json.dumps(config)),
            ).fetchone()
            self._write_admin(cur, tenant_id, record)
            self._write_version(
                cur, tenant_id, agent_id, name, version, config, updated_at, actor, "save"
            )

    def create_agent(
        self,
        tenant_id: str,
        config: dict,
        owner_kind: str,
        owner_id: str,
    ) -> None:
        import psycopg

        self._require_tenant(tenant_id)

        name = config.get("name")
        check_agent_name(name)
        check_config_is_storable(config)
        # A group cannot own an agent, and this is the one write to `agent_grants` other
        # than `transfer_agent_ownership` that is narrower than `GRANTEE_KINDS`.
        check_principal_kind(owner_kind)
        if not owner_id:
            raise StorageError(NO_OWNER)

        # The owner is the actor: creating a thing is what makes you its owner.
        record = make_admin_record(
            "agent.create",
            "agent",
            name,
            f"{owner_kind}:{owner_id}",
            {**agent_detail(config), "owner": f"{owner_kind}:{owner_id}"},
        )

        try:
            # **One transaction, three statements** since 011, and the ordering of the
            # first two is forced: the grant has a foreign key to the agent. What the
            # transaction buys is the other direction — a failure on any later statement
            # takes the earlier ones with it, so there is no window in which this tenant
            # holds an agent nobody can run, and none in which one exists unrecorded.
            #
            # No ON CONFLICT on either. On `agents` its absence is the whole method; on
            # `agent_grants` there is nothing to conflict with, because the agent came
            # into existence four lines ago inside this same transaction.
            with self._transaction() as cur:
                agent_id, version, updated_at = cur.execute(
                    "INSERT INTO agents (tenant_id, agent_id, name, config) "
                    "VALUES (%s, %s, %s, %s) RETURNING agent_id, version, updated_at",
                    (tenant_id, new_agent_id(), name, json.dumps(config)),
                ).fetchone()
                cur.execute(
                    """
                    INSERT INTO agent_grants (
                        tenant_id, agent_id, grantee_kind, grantee_id, role, granted_by
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        tenant_id,
                        agent_id,
                        owner_kind,
                        owner_id,
                        OWNER_ROLE,
                        f"{owner_kind}:{owner_id}",
                    ),
                )
                self._write_admin(cur, tenant_id, record)
                # Four statements now: the row, its grant, the record, and version 1 —
                # authored by the owner, for the same reason the record is. An agent's
                # history starts at the instant it exists, so there is no window in
                # which a live config is recorded nowhere.
                self._write_version(
                    cur,
                    tenant_id,
                    agent_id,
                    name,
                    version,
                    config,
                    updated_at,
                    f"{owner_kind}:{owner_id}",
                    "create",
                )
        except StorageError as exc:
            cause = exc.__cause__
            # The name uniqueness on `agents`. Reported as its own class because it is the
            # only 409 this method can produce and every other StorageError is a 503.
            #
            # **By constraint name, not by table name, since migration 035** — and the
            # comment this replaces already contained the argument for the change: *"a
            # method that reports somebody else's constraint as 'that name is taken' is one
            # that lies the first time the schema changes."* The schema changed. `agents`
            # now carries two unique keys, and the other one is on `agent_id`, so a
            # table-level test would answer "that name is taken" to a uuid4 collision — a
            # lie about the one input the caller did not choose.
            if (
                isinstance(cause, psycopg.errors.UniqueViolation)
                and getattr(cause.diag, "constraint_name", "") == AGENT_NAME_UNIQUE
            ):
                raise AgentNameTaken(AGENT_NAME_TAKEN.format(agent=name)) from exc
            raise

    def update_agent(
        self,
        tenant_id: str,
        config: dict,
        *,
        actor: str,
        if_unchanged_since,
        restored_from: int | None = None,
    ) -> dict | None:
        name = config.get("name")
        check_agent_name(name)
        check_config_is_storable(config)

        # One parameter decides all three, so they cannot disagree: a restore is an edit
        # whose body is an old config, and the version it came from *is* its provenance.
        # Migration 032's `agent_version_restore_names_one` says the same thing in the
        # schema.
        source = "update" if restored_from is None else "restore"
        record = make_admin_record(
            f"agent.{source}", "agent", name, actor, agent_detail(config)
        )

        with self._transaction() as cur:
            # **One statement, and the `AND updated_at = %s` is the whole method.** A
            # read in the route followed by a write here has a window between the two in
            # which the other editor commits — which is precisely the lost update the
            # timestamp exists to catch, arriving through the code that was supposed to
            # prevent it. There is no window inside a single UPDATE.
            #
            # `RETURNING` rather than a second SELECT for the reason `delete_agent` uses
            # one: it is the same statement, so nothing can move the row between them,
            # and it is what says whether anything actually happened.
            # The version expression rides inside the same statement rather than beside
            # it, which is what keeps the guard above intact: it reads the row's own
            # pre-image (the right-hand side of a SET sees the old values), so the
            # counter advances exactly when the configuration changed and there is still
            # nothing between the read and the write.
            row = cur.execute(
                f"""
                UPDATE agents
                   SET config = %s,
                       updated_at = now(),
                       version = version + (config IS DISTINCT FROM %s::jsonb)::int
                 WHERE tenant_id = %s AND name = %s AND updated_at = %s
                RETURNING {self._AGENT_COLUMNS}
                """,
                (
                    json.dumps(config),
                    json.dumps(config),
                    tenant_id,
                    name,
                    if_unchanged_since,
                ),
            ).fetchone()

            # Nothing moved: the agent is gone, or somebody else got here first. No
            # record, for the reason a revoke of a grant nobody had writes none — the log
            # holds changes rather than attempts. No version either: a lost race wrote no
            # configuration, so there is no state for the history to hold.
            if row is None:
                return None

            self._write_admin(cur, tenant_id, record)
            updated = dict(zip(AGENT_FIELDS, row))
            self._write_version(
                cur,
                tenant_id,
                updated["agent_id"],
                name,
                updated["version"],
                config,
                updated["updated_at"],
                actor,
                source,
                restored_from,
            )
            return updated

    def rename_agent(
        self,
        tenant_id: str,
        name: str,
        new_name: str,
        *,
        actor: str,
    ) -> dict | None:
        import psycopg

        check_agent_name(new_name)
        if new_name == name:
            raise ValueRefused(AGENT_RENAME_TO_SELF.format(agent=name))

        try:
            with self._transaction() as cur:
                # **One statement for the column and the config**, because migration 002's
                # `agent_name_matches_config` refuses a row where they disagree — so there
                # is no ordering of two statements that is ever legal, and the constraint is
                # what makes that a fact rather than a convention. `jsonb_set` edits the one
                # key rather than rewriting the document, so nothing else in the config can
                # be lost by a rename.
                #
                # The version expression is `update_agent`'s, verbatim: the right-hand side
                # of a SET reads the row's pre-image, so this advances exactly when the
                # config changed — which, for a rename that reaches this line, is always.
                row = cur.execute(
                    f"""
                    UPDATE agents
                       SET name = %s,
                           config = jsonb_set(config, '{{name}}', to_jsonb(%s::text)),
                           updated_at = now(),
                           version = version + 1
                     WHERE tenant_id = %s AND name = %s
                    RETURNING {self._AGENT_COLUMNS}
                    """,
                    (new_name, new_name, tenant_id, name),
                ).fetchone()

                # No agent by that name. No record and no version, on `update_agent`'s
                # rule: the log holds changes rather than attempts.
                if row is None:
                    return None

                renamed = dict(zip(AGENT_FIELDS, row))
                # `from` and `to` in the detail, and this is the only place they meet.
                # Migration 035 leaves the log tables holding whatever the agent was called
                # at the time, so an incident spanning a rename is reconstructed through
                # this record or not at all. `target_id` is the **new** name, because that
                # is what somebody reading the log forwards from here will be looking for.
                self._write_admin(
                    cur,
                    tenant_id,
                    make_admin_record(
                        "agent.rename",
                        "agent",
                        new_name,
                        actor,
                        {"from": name, "to": new_name},
                    ),
                )
                self._write_version(
                    cur,
                    tenant_id,
                    renamed["agent_id"],
                    new_name,
                    renamed["version"],
                    renamed["config"],
                    renamed["updated_at"],
                    actor,
                    "rename",
                )
                return renamed
        except StorageError as exc:
            cause = exc.__cause__
            # `create_agent`'s refusal, for `create_agent`'s reason and by the same
            # constraint: two agents cannot answer one URL. The name in the message is the
            # one the caller asked for, not the one they already have.
            if (
                isinstance(cause, psycopg.errors.UniqueViolation)
                and getattr(cause.diag, "constraint_name", "") == AGENT_NAME_UNIQUE
            ):
                raise AgentNameTaken(AGENT_NAME_TAKEN.format(agent=new_name)) from exc
            raise

    def delete_agent(self, tenant_id: str, name: str, *, actor: str) -> None:
        record = make_admin_record("agent.delete", "agent", name, actor)

        with self._transaction() as cur:
            # `RETURNING` rather than a SELECT first: it is the same statement, so
            # nothing can delete the row between the two, and it is what tells this
            # whether anything actually happened.
            gone = cur.execute(
                "DELETE FROM agents WHERE tenant_id = %s AND name = %s RETURNING name",
                (tenant_id, name),
            ).fetchone()

            # Idempotent, and no record. Deleting an agent that was never there changed
            # nothing, and a log that records attempts as well as changes cannot answer
            # "who deleted triage-bot" with one row.
            #
            # One record for the deletion, not one per cascaded grant — the grants went
            # because the agent did, and attributing each of them separately would say
            # five revocations happened when one deletion did.
            # The version history goes with it, by the cascade in migration 032 — one
            # more reason there is one record rather than one per removed row.
            if gone is not None:
                self._write_admin(cur, tenant_id, record)

    def list_agent_versions(
        self,
        tenant_id: str,
        name: str,
        *,
        limit: int = 50,
    ) -> list[dict]:
        check_version_limit(limit)
        # Filtered on the id, so the history returned is the *agent's* — including the
        # versions written when it was called something else, which is the point.
        agent_id = self._agent_id_for(tenant_id, name)
        if agent_id is None:
            return []
        rows = self._fetchall(
            f"SELECT {self._VERSION_SUMMARY_COLUMNS} FROM agent_versions "
            "WHERE tenant_id = %s AND agent_id = %s "
            "ORDER BY version DESC LIMIT %s",
            (tenant_id, agent_id, limit),
        )
        return [dict(zip(AGENT_VERSION_SUMMARY_FIELDS, row)) for row in rows]

    def get_agent_version(self, tenant_id: str, name: str, version: int) -> dict | None:
        check_version_number(version)
        agent_id = self._agent_id_for(tenant_id, name)
        if agent_id is None:
            return None
        row = self._fetchone(
            f"SELECT {self._VERSION_COLUMNS} FROM agent_versions "
            "WHERE tenant_id = %s AND agent_id = %s AND version = %s",
            (tenant_id, agent_id, version),
        )
        return dict(zip(AGENT_VERSION_FIELDS, row)) if row is not None else None

    # --- connectors -------------------------------------------------------------

    def load_connectors(self, tenant_id: str) -> list[dict]:
        rows = self._fetchall(
            "SELECT id FROM connectors WHERE tenant_id = %s ORDER BY id", (tenant_id,)
        )
        # Each id is re-read in its own statement, so a connector deleted between the
        # list and its read answers None. Dropped rather than passed on: the return type
        # says `list[dict]`, and every caller indexes into the rows it gets.
        loaded = (self.get_connector(tenant_id, row[0]) for row in rows)
        return [row for row in loaded if row is not None]

    def get_connector(self, tenant_id: str, connector_id: str) -> dict | None:
        row = self._fetchone(
            "SELECT id, description, launch, allow_asserted_identity FROM connectors "
            "WHERE tenant_id = %s AND id = %s",
            (tenant_id, connector_id),
        )
        if row is None:
            return None

        # Ordered by remote_name so a manifest round-trips to the same list every
        # time; binding does not care, but an equality assertion does.
        vetted = [
            normalize_vetted_tool(
                {
                    "remote_name": v[0],
                    "effect": v[1],
                    "identity": v[2],
                    "resources": v[3],
                    "local_name": v[4],
                    "max_response_bytes": v[5],
                    "description": v[6],
                    "note": v[7],
                    "binding": v[8],
                    "redact_args": v[9],
                }
            )
            for v in self._fetchall(
                "SELECT remote_name, effect, identity, resources, local_name, "
                "max_response_bytes, description, note, binding, redact_args "
                "FROM vetted_tools WHERE tenant_id = %s AND connector_id = %s "
                "ORDER BY remote_name",
                (tenant_id, connector_id),
            )
        ]

        # No read_only key, because there is no read_only column. It is recomputed
        # from these effects when the manifest becomes a Connector.
        return {
            "id": row[0],
            "description": row[1],
            "launch": row[2],
            "vetted": vetted,
            "allow_asserted_identity": bool(row[3]),
        }

    def create_connector(
        self,
        tenant_id: str,
        connector_id: str,
        *,
        launch: dict,
        description: str = "",
        allow_asserted_identity: bool = False,
        from_recipe: str = "",
        actor: str,
    ) -> None:
        import psycopg

        self._require_tenant(tenant_id)

        if not connector_id or not isinstance(connector_id, str):
            raise StorageError("a connector needs a non-empty string id")

        record = make_admin_record(
            "connector.create",
            "connector",
            connector_id,
            actor,
            {
                "kind": (launch or {}).get("kind", ""),
                "url": (launch or {}).get("url", ""),
                # Recorded on create as well as on toggle, so a connector born trusting
                # asserted identity is not invisible to the question "who approved that".
                "allow_asserted_identity": bool(allow_asserted_identity),
                # Step 068: which checked-in preset supplied these values, or `""`. A log
                # line and not a link — nothing indexes or joins it, so deleting the
                # recipe breaks nothing and this stays readable.
                "from_recipe": from_recipe or "",
            },
        )

        try:
            with self._transaction() as cur:
                # **No ON CONFLICT**, and its absence is the whole method — the same one
                # line of SQL that separates `create_agent` from `save_agent`. See
                # `ConnectorExistsError` for what the upsert would cost here.
                cur.execute(
                    "INSERT INTO connectors "
                    "(tenant_id, id, description, launch, allow_asserted_identity) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (
                        tenant_id,
                        connector_id,
                        description or "",
                        json.dumps(launch or {}),
                        bool(allow_asserted_identity),
                    ),
                )
                self._write_admin(cur, tenant_id, record)
        except StorageError as exc:
            if isinstance(exc.__cause__, psycopg.errors.UniqueViolation):
                raise ConnectorExistsError(
                    CONNECTOR_EXISTS.format(connector=connector_id, tenant=tenant_id)
                ) from exc
            raise

        # No `vetted_tools` rows, deliberately: registration vets nothing, and a
        # connector with an empty allowlist contributes no tools to the catalogue. That
        # is the correct intermediate state rather than a hole — `bind()` over an empty
        # manifest yields no tools and excludes everything the server advertises.

    def set_asserted_identity(
        self, tenant_id: str, connector_id: str, allowed: bool, *, actor: str
    ) -> None:
        self._require_tenant(tenant_id)

        record = make_admin_record(
            "connector.asserted_identity",
            "connector",
            connector_id or "",
            actor,
            {"allow_asserted_identity": bool(allowed)},
        )

        with self._transaction() as cur:
            cur.execute(
                "UPDATE connectors SET allow_asserted_identity = %s "
                "WHERE tenant_id = %s AND id = %s",
                (bool(allowed), tenant_id, connector_id),
            )
            if cur.rowcount == 0:
                # Raising inside the transaction rolls the admin record back with the
                # change that never happened — a log line for a no-op would be the
                # record lying in the more dangerous direction.
                raise NoSuchConnectorError(
                    NO_SUCH_CONNECTOR_TO_TRUST.format(
                        connector=connector_id, tenant=tenant_id
                    )
                )
            self._write_admin(cur, tenant_id, record)

    def vet_tool(
        self,
        tenant_id: str,
        connector_id: str,
        vetted: dict,
        *,
        actor: str,
        server_name: str = "",
        server_version: str = "",
        vetted_arguments: tuple = (),
    ) -> None:
        import psycopg

        self._require_tenant(tenant_id)
        row = normalize_vetted_tool(vetted)

        record = make_admin_record(
            "connector.vet",
            "connector",
            connector_id or "",
            actor,
            {
                "remote_name": row["remote_name"],
                "effect": row["effect"],
                # Whose account it will act as — part of what was approved, so part
                # of the administrative record of the approval (033a).
                "identity": row["identity"],
                "resources": sorted({ref["type"] for ref in row["resources"]}),
                "server_name": server_name,
                "server_version": server_version,
            },
        )

        try:
            with self._transaction() as cur:
                # The launch, read before the write: the kind/binding implication
                # (step 045a) needs the connector's kind, and reading it here also
                # answers "is it registered" with a sentence instead of leaving that
                # to the foreign-key violation below — which stays, as the backstop
                # for a connector deleted between this read and the insert.
                cur.execute(
                    "SELECT launch FROM connectors WHERE tenant_id = %s AND id = %s",
                    (tenant_id, connector_id),
                )
                found = cur.fetchone()
                if found is None:
                    raise NoSuchConnectorError(
                        NO_SUCH_CONNECTOR_TO_VET.format(
                            connector=connector_id, tenant=tenant_id
                        )
                    )
                check_binding_kind(found[0], row, connector_id)

                # An upsert on the table's primary key past the tenant, so exactly one
                # row moves. Every other tool this connector has vetted is untouched —
                # the difference between this and `save_connector`, in one statement.
                #
                # `vetted_at` is refreshed on conflict rather than kept, because a
                # re-vet is a new review: keeping the old timestamp would attribute
                # today's decision to whenever the first one happened.
                cur.execute(
                    """
                    INSERT INTO vetted_tools (
                        tenant_id, connector_id, remote_name, effect, identity,
                        resources, local_name, max_response_bytes,
                        description, note, binding, redact_args, vetted_by, vetted_at,
                        server_name, server_version, vetted_arguments
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now(), %s, %s, %s)
                    ON CONFLICT (tenant_id, connector_id, remote_name)
                    DO UPDATE SET
                        effect = EXCLUDED.effect,
                        identity = EXCLUDED.identity,
                        resources = EXCLUDED.resources,
                        local_name = EXCLUDED.local_name,
                        max_response_bytes = EXCLUDED.max_response_bytes,
                        description = EXCLUDED.description,
                        note = EXCLUDED.note,
                        binding = EXCLUDED.binding,
                        redact_args = EXCLUDED.redact_args,
                        vetted_by = EXCLUDED.vetted_by,
                        vetted_at = now(),
                        server_name = EXCLUDED.server_name,
                        server_version = EXCLUDED.server_version,
                        vetted_arguments = EXCLUDED.vetted_arguments
                    """,
                    (
                        tenant_id,
                        connector_id,
                        row["remote_name"],
                        row["effect"],
                        row["identity"],
                        json.dumps(row["resources"]),
                        row["local_name"],
                        row["max_response_bytes"],
                        row["description"],
                        row["note"],
                        json.dumps(row["binding"]) if row["binding"] is not None else None,
                        json.dumps(row["redact_args"]),
                        actor,
                        server_name,
                        server_version,
                        json.dumps(sorted(vetted_arguments)),
                    ),
                )
                self._write_admin(cur, tenant_id, record)
        except StorageError as exc:
            cause = exc.__cause__
            if isinstance(cause, psycopg.errors.ForeignKeyViolation):
                raise NoSuchConnectorError(
                    NO_SUCH_CONNECTOR_TO_VET.format(
                        connector=connector_id, tenant=tenant_id
                    )
                ) from exc
            raise

    def save_connector(self, tenant_id: str, manifest: dict, *, actor: str) -> None:
        self._require_tenant(tenant_id)

        connector_id = manifest.get("id")
        if not connector_id or not isinstance(connector_id, str):
            raise StorageError("connector manifest must have a non-empty string 'id'")

        stored = set(manifest) & DERIVED_CONNECTOR_FIELDS
        if stored:
            raise StorageError(
                f"connector manifest may not set {sorted(stored)} â€” derived from the "
                "vetted effects, never stored. A stored copy is free to disagree with "
                "the allowlist it defends."
            )

        record = make_admin_record(
            "connector.save",
            "connector",
            connector_id,
            actor,
            {
                "tools": sorted(
                    row.get("remote_name", "") for row in manifest.get("vetted") or ()
                ),
                "kind": (manifest.get("launch") or {}).get("kind", ""),
                "url": (manifest.get("launch") or {}).get("url", ""),
            },
        )

        # One transaction, because the delete-then-insert below is a replacement and a
        # reader must never see the halfway point. See `_transaction`.
        #
        # `allow_asserted_identity` is replaced with the rest — this method's contract
        # is wholesale, exactly as it is for the vetted list — and a manifest without
        # the key writes False, which fails in the closed direction: a re-seed that
        # never mentions the flag disables trust rather than quietly extending it.
        with self._transaction() as cur:
            cur.execute(
                """
                INSERT INTO connectors
                    (tenant_id, id, description, launch, allow_asserted_identity)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, id)
                DO UPDATE SET description = EXCLUDED.description,
                              launch = EXCLUDED.launch,
                              allow_asserted_identity = EXCLUDED.allow_asserted_identity
                """,
                (
                    tenant_id,
                    connector_id,
                    manifest.get("description", ""),
                    json.dumps(manifest.get("launch") or {}),
                    bool(manifest.get("allow_asserted_identity", False)),
                ),
            )

            # Replaced wholesale rather than merged: the manifest IS the allowlist, so a
            # tool absent from it must stop being vetted. Merging would mean un-vetting
            # required an explicit delete, and the thing nobody remembers to do is exactly
            # the thing that must not be required.
            cur.execute(
                "DELETE FROM vetted_tools WHERE tenant_id = %s AND connector_id = %s",
                (tenant_id, connector_id),
            )
            for row in manifest.get("vetted") or ():
                vetted = normalize_vetted_tool(row)
                # The kind/binding implication (045a), against the launch this same
                # manifest carries — the wholesale writer is exactly the path the
                # vet-time guard cannot cover.
                check_binding_kind(
                    manifest.get("launch") or {}, vetted, connector_id
                )
                cur.execute(
                    """
                    INSERT INTO vetted_tools (
                        tenant_id, connector_id, remote_name, effect, identity,
                        resources, local_name, max_response_bytes,
                        description, note, binding, redact_args, vetted_by
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        tenant_id,
                        connector_id,
                        vetted["remote_name"],
                        vetted["effect"],
                        vetted["identity"],
                        json.dumps(vetted["resources"]),
                        vetted["local_name"],
                        vetted["max_response_bytes"],
                        vetted["description"],
                        vetted["note"],
                        json.dumps(vetted["binding"])
                        if vetted["binding"] is not None
                        else None,
                        json.dumps(vetted["redact_args"]),
                        # New in 012, where this column took the `''` default. No
                        # `server_name`/`server_version`: this method contacts no server.
                        actor,
                    ),
                )

            self._write_admin(cur, tenant_id, record)

    def delete_connector(self, tenant_id: str, connector_id: str, *, actor: str) -> None:
        record = make_admin_record(
            "connector.delete", "connector", connector_id or "", actor
        )

        # vetted_tools cascades. `connections` deliberately does NOT — migration 021
        # makes this RESTRICT, so a connector somebody has connected to cannot be
        # removed out from under their sealed credential.
        try:
            with self._transaction() as cur:
                cur.execute(
                    "DELETE FROM connectors WHERE tenant_id = %s AND id = %s",
                    (tenant_id, connector_id),
                )
                # Only when a row went, on `delete_agent`'s precedent. `rowcount` is
                # what makes that checkable inside the transaction — the record and the
                # deletion commit together or neither does.
                if cur.rowcount:
                    self._write_admin(cur, tenant_id, record)
        except StorageError as exc:
            cause = exc.__cause__
            if (
                cause is not None
                # `diag` via getattr too: it exists on psycopg's errors and not on
                # BaseException, so reaching through it directly turned a chained
                # non-psycopg cause into an AttributeError from the handler itself.
                and getattr(getattr(cause, "diag", None), "constraint_name", "")
                == "connections_connector_fk"
            ):
                raise ConnectorInUseError(
                    CONNECTOR_IN_USE.format(connector=connector_id, tenant=tenant_id)
                ) from exc
            raise

    def load_vetting_record(self, tenant_id: str) -> list[dict]:
        # One statement for the whole tenant rather than one per connector: the caller
        # is building a catalogue and wants all of it, and `get_connector` is already
        # N+1 across connectors without this adding a second N to it.
        return [
            {
                "connector_id": row[0],
                "remote_name": row[1],
                "vetted_by": row[2],
                "vetted_at": row[3].isoformat(),
                "server_name": row[4],
                "server_version": row[5],
                "vetted_arguments": row[6],
            }
            for row in self._fetchall(
                "SELECT connector_id, remote_name, vetted_by, vetted_at, "
                "server_name, server_version, vetted_arguments "
                "FROM vetted_tools WHERE tenant_id = %s "
                "ORDER BY connector_id, remote_name",
                (tenant_id,),
            )
        ]

    # --- egress -----------------------------------------------------------------

    def allowed_hosts(self, tenant_id: str) -> list[dict]:
        return [
            {
                "host": row[0],
                "allowed_by": row[1],
                "allowed_at": row[2].isoformat(),
                "note": row[3],
            }
            for row in self._fetchall(
                "SELECT host, allowed_by, allowed_at, note FROM tenant_egress_hosts "
                "WHERE tenant_id = %s ORDER BY host",
                (tenant_id,),
            )
        ]

    def allow_host(
        self, tenant_id: str, host: str, *, actor: str, note: str = ""
    ) -> None:
        self._require_tenant(tenant_id)
        normalized = normalize_host(host)
        record = make_admin_record(
            "egress.allow", "host", normalized, actor, {"note": note or ""}
        )

        with self._transaction() as cur:
            # Idempotent. Re-approving refreshes who approved it and when, because a
            # second approval is a second decision — the last person to say yes is the
            # one an incident wants to talk to.
            cur.execute(
                """
                INSERT INTO tenant_egress_hosts (tenant_id, host, allowed_by, note)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (tenant_id, host)
                DO UPDATE SET allowed_by = EXCLUDED.allowed_by,
                              allowed_at = now(),
                              note = EXCLUDED.note
                """,
                (tenant_id, normalized, actor, note or ""),
            )
            self._write_admin(cur, tenant_id, record)

    def revoke_host(self, tenant_id: str, host: str, *, actor: str) -> bool:
        normalized = normalize_host(host)
        record = make_admin_record("egress.revoke", "host", normalized, actor)

        with self._transaction() as cur:
            cur.execute(
                "DELETE FROM tenant_egress_hosts WHERE tenant_id = %s AND host = %s",
                (tenant_id, normalized),
            )
            if not cur.rowcount:
                return False
            self._write_admin(cur, tenant_id, record)
            return True

    # --- audit ------------------------------------------------------------------

    # Every field of an audit record, and the reason this tuple is worth reading twice:
    # the `audit` table has fixed columns while the in-memory store keeps whatever dict
    # it is handed. A field added to `core/audit.py` and not added here is written by
    # one implementation, **silently dropped** by the other, and invisible to a suite
    # that only ever runs against the fake. That is exactly how `credential` shipped
    # into this list late â€” see `test_every_audit_field_survives_a_round_trip`, which
    # is the assertion that now fails when somebody forgets.
    _AUDIT_COLUMNS = (
        "v",
        "ts",
        "run_id",
        "principal_kind",
        "principal_id",
        "agent",
        "tool",
        "effect",
        "args",
        "decision",
        "reason",
        "outcome",
        "credential",
        "duration_ms",
        "response_bytes",
        "acting_for",
        "identity_source",
        # Step 045b. Five more, and the reason they are appended to *this* tuple rather
        # than spelled into the INSERT is the failure its own comment below records: the
        # `credential` column shipped written by this store and dropped by the fake
        # because three lists had to be edited by hand and one was not.
        "model",
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "cache_write_tokens",
    )

    # Generated from `_AUDIT_COLUMNS` rather than typed out, so the statement, the
    # placeholder count and the parameter order have one source. Hand-syncing three
    # lists is how `credential` came to be written by this store and dropped by the
    # fake; two of the three are now derived and the third is the tuple itself.
    _AUDIT_INSERT = (
        f"INSERT INTO audit (tenant_id, {', '.join(_AUDIT_COLUMNS)}) "
        f"VALUES ({', '.join(['%s'] * (len(_AUDIT_COLUMNS) + 1))})"
    )

    @staticmethod
    def _audit_params(tenant_id: str, row: dict) -> tuple:
        """The INSERT's values, in `_AUDIT_COLUMNS` order.

        Built by walking that tuple rather than hand-listing eighteen values, so a
        column added to it cannot be silently left out of the write — which is the
        failure `_AUDIT_COLUMNS`' own comment records `credential` shipping with.
        `args` is the one column whose Python value is not its SQL value.
        """
        values = [tenant_id]
        for column in PostgresStorage._AUDIT_COLUMNS:
            value = row[column]
            values.append(json.dumps(value) if column == "args" else value)
        return tuple(values)

    def append_audit(self, tenant_id: str, record: dict) -> None:
        # `audit_principal_kind_check` from migration 017, in Python, so the refusal is
        # the sentence the in-memory store raises rather than a constraint name. The
        # constraint stays the thing that actually guarantees it.
        check_principal_kind(record["principal_kind"])
        # Migration 048's CHECK, in Python for the same reason as the line above it: the
        # refusal is a sentence rather than a constraint name, and both stores make it.
        check_audit_tokens(record)

        self._require_tenant(tenant_id)
        self._execute(
            self._AUDIT_INSERT,
            # Through the shared normalizer rather than eight `.get`s spelled here, so
            # this store and the fake cannot disagree about what an absent field means.
            # They did: see `normalize_audit_record`.
            self._audit_params(tenant_id, normalize_audit_record(record)),
        )

    def audit_records(
        self,
        tenant_id: str,
        *,
        run_id: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        columns = ", ".join(self._AUDIT_COLUMNS)
        params: list = [tenant_id]

        where = "tenant_id = %s"
        if run_id is not None:
            where += " AND run_id = %s"
            params.append(run_id)

        if limit is None:
            sql = f"SELECT {columns} FROM audit WHERE {where} ORDER BY id"
        else:
            # The most recent N, then re-sorted oldest-first. Taking the tail requires
            # ordering by id DESC to use the index; the caller still wants the
            # sequence in the order it happened.
            sql = (
                f"SELECT {columns} FROM ("
                f"  SELECT {columns}, id FROM audit WHERE {where} ORDER BY id DESC "
                f"  LIMIT %s"
                f") recent ORDER BY id"
            )
            params.append(max(limit, 0))

        rows = []
        for row in self._fetchall(sql, tuple(params)):
            record = dict(zip(self._AUDIT_COLUMNS, row))
            # Written as an ISO string, and read back as one: audit records are
            # compared and diffed as data, and a driver-native datetime here would
            # make the two implementations disagree about what a record is.
            record["ts"] = record["ts"].isoformat(timespec="milliseconds")
            record["tenant_id"] = tenant_id
            rows.append(record)

        return rows

    # --- the administrative audit log -------------------------------------------

    _ADMIN_COLUMNS = ADMIN_AUDIT_FIELDS[1:]  # everything but tenant_id, merged on read

    _ADMIN_INSERT = """
        INSERT INTO admin_audit (
            tenant_id, v, ts, actor_kind, actor_id, action, target_kind, target_id,
            detail
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    @staticmethod
    def _write_admin(cur, tenant_id: str, record: dict) -> None:
        """One administrative record, **on the caller's cursor**.

        A cursor rather than `self._execute`, and that is the whole of decision 2: the
        record has to land in the same transaction as the write it describes. Borrowing
        a second connection here would produce exactly the artifact the decision refuses
        — a record that can be absent when the write succeeded, silently.

        The other direction matters as much and is easier to miss: because this shares
        the transaction, a record the database refuses (a `group` actor, an empty
        `actor_id`) takes the write down with it. That is intended and it is asserted —
        see `test_a_write_whose_record_is_refused_leaves_nothing_behind`.
        """
        cur.execute(
            PostgresStorage._ADMIN_INSERT,
            (
                tenant_id,
                record["v"],
                record["ts"],
                record["actor_kind"],
                record["actor_id"],
                record["action"],
                record["target_kind"],
                record["target_id"],
                json.dumps(record["detail"]),
            ),
        )

    def admin_audit_records(
        self,
        tenant_id: str,
        *,
        action: str | None = None,
        target_kind: str | None = None,
        target_id: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        columns = ", ".join(self._ADMIN_COLUMNS)

        where = "tenant_id = %s"
        params: list = [tenant_id]
        for column, value in (
            ("action", action),
            ("target_kind", target_kind),
            ("target_id", target_id),
        ):
            if value is not None:
                where += f" AND {column} = %s"
                params.append(value)

        if limit is None:
            sql = f"SELECT {columns} FROM admin_audit WHERE {where} ORDER BY id"
        else:
            # The most recent N, then re-sorted oldest-first — the same shape
            # `audit_records` uses, and for the same two reasons: taking the tail wants
            # `id DESC` to use the index, and the caller still wants the sequence in the
            # order it happened.
            sql = (
                f"SELECT {columns} FROM ("
                f"  SELECT {columns}, id FROM admin_audit WHERE {where} ORDER BY id DESC "
                f"  LIMIT %s"
                f") recent ORDER BY id"
            )
            params.append(max(limit, 0))

        rows = []
        for row in self._fetchall(sql, tuple(params)):
            record = dict(zip(self._ADMIN_COLUMNS, row))
            record["ts"] = record["ts"].isoformat(timespec="milliseconds")
            record["tenant_id"] = tenant_id
            rows.append(record)

        return rows

    # --- the access-denial log --------------------------------------------------

    _DENIAL_COLUMNS = DENIAL_FIELDS[1:]  # everything but tenant_id, merged on read

    _DENIAL_INSERT = """
        INSERT INTO access_denials (
            tenant_id, v, ts, principal_kind, principal_id, resource_kind,
            resource_id, required, held
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    def record_denial(self, tenant_id: str, record: dict) -> None:
        # Its own statement on its own connection, unlike `_write_admin` — and that is
        # the design rather than a shortcut. A denial performs no write and rides no
        # transaction; there is nothing for this record to be atomic *with*. The caller
        # treats the append as best-effort, because the refusal it describes must be
        # served whether or not this lands. See `access/denials.py`.
        self._execute(
            self._DENIAL_INSERT,
            (
                tenant_id,
                record["v"],
                record["ts"],
                record["principal_kind"],
                record["principal_id"],
                record["resource_kind"],
                record["resource_id"],
                record["required"],
                record["held"],
            ),
        )

    def denial_records(
        self,
        tenant_id: str,
        *,
        principal_kind: str | None = None,
        principal_id: str | None = None,
        resource_kind: str | None = None,
        resource_id: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        columns = ", ".join(self._DENIAL_COLUMNS)

        where = "tenant_id = %s"
        params: list = [tenant_id]
        for column, value in (
            ("principal_kind", principal_kind),
            ("principal_id", principal_id),
            ("resource_kind", resource_kind),
            ("resource_id", resource_id),
        ):
            if value is not None:
                where += f" AND {column} = %s"
                params.append(value)

        if limit is None:
            sql = f"SELECT {columns} FROM access_denials WHERE {where} ORDER BY id"
        else:
            # The most recent N, then re-sorted oldest-first — the same shape the other
            # two logs use, and for the same two reasons: taking the tail wants
            # `id DESC` to use the index, and the caller still wants the sequence in
            # the order it happened.
            sql = (
                f"SELECT {columns} FROM ("
                f"  SELECT {columns}, id FROM access_denials WHERE {where} "
                f"  ORDER BY id DESC LIMIT %s"
                f") recent ORDER BY id"
            )
            params.append(max(limit, 0))

        rows = []
        for row in self._fetchall(sql, tuple(params)):
            record = dict(zip(self._DENIAL_COLUMNS, row))
            record["ts"] = record["ts"].isoformat(timespec="milliseconds")
            record["tenant_id"] = tenant_id
            rows.append(record)

        return rows

    def last_door_refusal(self, tenant_id: str, tool_names: Sequence[str]) -> dict | None:
        names = sorted(set(tool_names))
        if not names:
            return None
        columns = ", ".join(self._DENIAL_COLUMNS)
        # `access_denials_resource` (migration 028) is (tenant_id, resource_kind,
        # resource_id, id): one index range per name, newest `id` wins.
        row = self._fetchone(
            f"SELECT {columns} FROM access_denials"
            " WHERE tenant_id = %s AND resource_kind = 'tool' AND resource_id = ANY(%s)"
            " ORDER BY id DESC LIMIT 1",
            (tenant_id, names),
        )
        if row is None:
            return None
        record = dict(zip(self._DENIAL_COLUMNS, row))
        record["ts"] = record["ts"].isoformat(timespec="milliseconds")
        record["tenant_id"] = tenant_id
        return record

    # --- the door's traffic -----------------------------------------------------

    # `LIKE 'door-%'`, built from the shared constant rather than typed here: the one
    # place that mints these ids and the one place that reads them back must not be able
    # to drift apart. The `%` is appended in Python rather than written into the SQL so
    # the pattern is a parameter — the prefix contains no wildcard today, and a literal
    # in the statement would be one edit away from mattering.
    _DOOR_CALL_PATTERN = f"{DOOR_CALL_ID_PREFIX}%"

    # The filters `door_call_records` accepts, as `(keyword, column)`. Step 066.
    #
    # A table rather than eleven `if` statements, and the reason is the failure it makes
    # impossible: every one of these builds the same `column = %s` clause, and a hand
    # written chain is where the eighth one gets `principal_kind` compared against
    # `principal_id`. The column names are literals in this tuple and never come from a
    # caller — they cannot be parameters, so the only safe spelling is one where input
    # never reaches the string.
    _DOOR_FILTERS = (
        ("tool", "tool"),
        ("agent", "agent"),
        ("principal_id", "principal_id"),
        ("principal_kind", "principal_kind"),
        ("acting_for", "acting_for"),
        ("decision", "decision"),
        ("outcome", "outcome"),
        ("effect", "effect"),
        ("identity_source", "identity_source"),
    )

    def door_call_records(
        self,
        tenant_id: str,
        *,
        limit: int | None = None,
        since: "date | None" = None,
        until: "date | None" = None,
        **filters,
    ) -> list[dict]:
        columns = ", ".join(self._AUDIT_COLUMNS)
        params: list = [tenant_id, self._DOOR_CALL_PATTERN]
        where = "tenant_id = %s AND run_id LIKE %s"

        # The date bounds first, because they are the ones the index is for. Half-open at
        # the top — `< until + 1 day` — which is `_WINDOW`'s decision and its recorded
        # bug: a `<= until` compares against that day's midnight and silently drops
        # everything that happened *during* the last day of the window, which is the day
        # a person following a link from a chart is most likely asking about.
        #
        # `(date)::timestamp AT TIME ZONE 'UTC'` rather than a bare comparison, for
        # `_WINDOW`'s other reason: a bare `ts >= %s` with a date parameter casts through
        # the **session's** `TimeZone`, and under BYOC that is somebody else's Postgres
        # with somebody else's default. The chart that linked here grouped in UTC.
        if since is not None:
            where += " AND ts >= (%s::date)::timestamp AT TIME ZONE 'UTC'"
            params.append(since)
        if until is not None:
            where += " AND ts < ((%s::date + 1))::timestamp AT TIME ZONE 'UTC'"
            params.append(until)

        for keyword, column in self._DOOR_FILTERS:
            value = filters.get(keyword)
            # `is not None`, never truthiness: `outcome=""` is a real stored value — the
            # column is `NOT NULL DEFAULT ''` — so "the ones nothing was recorded for" is
            # a question this filter has to be able to ask, and a falsy check would
            # silently turn it into "do not narrow".
            if value is not None:
                where += f" AND {column} = %s"
                params.append(value)

        if limit is None:
            sql = f"SELECT {columns} FROM audit WHERE {where} ORDER BY id"
        else:
            # The most recent N, then re-sorted oldest-first — `audit_records`' shape,
            # and for its two reasons: taking the tail wants `id DESC`, and the caller
            # still wants the sequence in the order it happened.
            sql = (
                f"SELECT {columns} FROM ("
                f"  SELECT {columns}, id FROM audit WHERE {where} ORDER BY id DESC "
                f"  LIMIT %s"
                f") recent ORDER BY id"
            )
            params.append(max(limit, 0))

        rows = []
        for row in self._fetchall(sql, tuple(params)):
            record = dict(zip(self._AUDIT_COLUMNS, row))
            # An ISO string in both stores, the coercion every log reader here applies.
            record["ts"] = record["ts"].isoformat(timespec="milliseconds")
            record["tenant_id"] = tenant_id
            rows.append(record)

        return rows

    def door_call_summary(self, tenant_id: str, agent_name: str) -> dict:
        # `MAX(ts)` rather than the `id`-ordered tail: the caller wants "when was the
        # last knock", a fact about time, and one aggregate row costs one scan of the
        # same filter either way.
        row = self._fetchone(
            "SELECT COUNT(*), MAX(ts) FROM audit"
            " WHERE tenant_id = %s AND agent = %s AND run_id LIKE %s",
            (tenant_id, agent_name, self._DOOR_CALL_PATTERN),
        )
        calls, last = row if row else (0, None)
        return {
            "calls": int(calls or 0),
            # The ISO coercion every log reader here applies.
            "last_call_at": last.isoformat(timespec="milliseconds") if last else None,
        }

    # --- the grant, against its evidence ------------------------------------------

    def door_tool_evidence(
        self,
        tenant_id: str,
        agent_name: str,
        tool_names: Sequence[str],
        *,
        since,
        until,
    ) -> dict:
        iso = lambda when: when.isoformat(timespec="milliseconds") if when else None  # noqa: E731

        # `_TRAFFIC_WHERE` plus the agent: the same window predicate the overview uses,
        # so the planner prunes the same partitions, and migration 050's partial index
        # carries the `LIKE`.
        tools = {}
        for row in self._fetchall(
            "SELECT tool,"
            "       count(*) FILTER (WHERE decision = 'allow'),"
            "       count(*) FILTER (WHERE decision = 'deny'),"
            "       max(ts) FILTER (WHERE decision = 'allow'),"
            "       max(ts) FILTER (WHERE decision = 'deny')"
            f"  FROM audit WHERE {self._TRAFFIC_WHERE} AND agent = %s"
            "  GROUP BY tool",
            (tenant_id, since, until, self._DOOR_CALL_PATTERN, agent_name),
        ):
            tools[row[0] or ""] = {
                "admitted": int(row[1] or 0),
                "refused": int(row[2] or 0),
                "last_admitted_at": iso(row[3]),
                "last_refused_at": iso(row[4]),
            }

        door_refused = {}
        names = sorted(set(tool_names))
        if names:
            for row in self._fetchall(
                "SELECT resource_id, count(*), max(ts) FROM access_denials"
                f" WHERE tenant_id = %s AND {self._WINDOW}"
                "   AND resource_kind = 'tool' AND resource_id = ANY(%s)"
                " GROUP BY resource_id",
                (tenant_id, since, until, names),
            ):
                door_refused[row[0]] = {"count": int(row[1]), "last_at": iso(row[2])}

        return {"tools": tools, "door_refused": door_refused}

    def token_door_touch(self, tenant_id: str, token_id: str, *, since, until) -> dict:
        touched = [
            {
                "agent": row[0] or "",
                "tool": row[1] or "",
                "admitted": int(row[2] or 0),
                "refused": int(row[3] or 0),
                "last_at": row[4].isoformat(timespec="milliseconds"),
            }
            for row in self._fetchall(
                "SELECT agent, tool,"
                "       count(*) FILTER (WHERE decision = 'allow'),"
                "       count(*) FILTER (WHERE decision = 'deny'),"
                "       max(ts)"
                f"  FROM audit WHERE {self._TRAFFIC_WHERE}"
                "   AND principal_kind = 'machine' AND principal_id = %s"
                "  GROUP BY agent, tool ORDER BY agent, tool",
                (tenant_id, since, until, self._DOOR_CALL_PATTERN, token_id),
            )
        ]
        door_refused = [
            {
                "tool": row[0],
                "count": int(row[1]),
                "last_at": row[2].isoformat(timespec="milliseconds"),
            }
            for row in self._fetchall(
                "SELECT resource_id, count(*), max(ts) FROM access_denials"
                f" WHERE tenant_id = %s AND {self._WINDOW}"
                "   AND principal_kind = 'machine' AND principal_id = %s"
                "   AND resource_kind = 'tool'"
                " GROUP BY resource_id ORDER BY resource_id",
                (tenant_id, since, until, token_id),
            )
        ]
        return {"touched": touched, "door_refused": door_refused}

    def oldest_door_record_at(self, tenant_id: str) -> "str | None":
        row = self._fetchone(
            "SELECT min(ts) FROM audit WHERE tenant_id = %s AND run_id LIKE %s",
            (tenant_id, self._DOOR_CALL_PATTERN),
        )
        when = row[0] if row else None
        return when.isoformat(timespec="milliseconds") if when else None

    # --- the overview -----------------------------------------------------------
    #
    # Step 041, and the first aggregating read in this class. Every statement below
    # shares one shape, and it is the shape that makes them cheap:
    #
    #     WHERE tenant_id = %s AND ts >= %s AND ts < %s
    #     GROUP BY date_trunc('day', ts)
    #
    # The `ts` range is doing two jobs. It is the window the caller asked for, and it is
    # what lets the planner prune migration 030's monthly partitions — without it, every
    # one of these becomes a scan of the whole log's history rather than of the month or
    # three the question is about.
    #
    # **`< until + 1 day`, never `<= until`.** `ts` is a TIMESTAMPTZ and `until` is a
    # date, so `<= until` compares against that day's midnight and silently drops
    # everything that happened during the last day of the window — the one day somebody
    # reading a dashboard is most likely to be checking. The half-open bound is computed
    # once, in `overview`, so no statement here can get it wrong on its own.
    #
    # **`date_trunc(...)::date::text`, so the wire carries `YYYY-MM-DD`.** The fake slices
    # an ISO string to ten characters and this must agree with it exactly; a `datetime`
    # returned here and a `str` there is precisely the drift the contract suite exists to
    # catch, and it would show up as a chart with two of every day.

    # Days are UTC, matching `door.budget_window()` — the page and the ceiling it draws
    # must not disagree about which day is today. `ts` is TIMESTAMPTZ so it is stored in
    # UTC already; `AT TIME ZONE 'UTC'` makes the grouping explicit rather than dependent
    # on the session's `TimeZone`, which a pooled connection does not guarantee.
    _DAY = "(date_trunc('day', ts AT TIME ZONE 'UTC'))::date::text"

    # The hour's spelling, step 066. `YYYY-MM-DDTHH` — `to_char` rather than a cast,
    # because a truncated timestamp casts to a full ISO string with `:00:00` on the end
    # and the fake would have to reproduce those four characters exactly to match. A
    # format string states the shape once, in the place a reader looks for it.
    #
    # Still `AT TIME ZONE 'UTC'` and still `date_trunc`, for `_DAY`'s reasons unchanged:
    # the grouping is explicit rather than dependent on a pooled connection's `TimeZone`,
    # and the day this rolls up to is the day the ceiling charges against.
    _HOUR = "to_char(date_trunc('hour', ts AT TIME ZONE 'UTC'), 'YYYY-MM-DD\"T\"HH24')"

    @classmethod
    def _bucket(cls, bucket: str) -> str:
        """The grouping expression for a window's bucket. Never a caller's string.

        Interpolated into every statement below, which is why it is a lookup and not a
        parameter: `bucket` reaches this from a route that validated it, and the one
        spelling that could turn a widened vocabulary into an injection is
        `f"date_trunc('{bucket}', ...)"`. An unknown value falls to the day rather than
        raising — this is a dashboard, and the route has already refused anything the
        page could not draw.
        """
        return cls._HOUR if bucket == "hour" else cls._DAY

    def overview_totals(self, tenant_id: str, *, since: "date", until: "date") -> dict:
        """The window's scalars. Step 066a — see `base.overview_totals`.

        Five statements over three tables, where `overview` runs fifteen over the same
        three. The window predicate and the door pattern are the same ones, so the planner
        prunes the same partitions and this is a strictly cheaper read of the same rows.

        **It was six until step 084**, the sixth a `count(*) FROM runs` whose answer
        `_previous_window` read and dropped — the same defect as `overview`'s run series,
        on the read that exists to be the cheap one.
        """
        door = (tenant_id, since, until, self._DOOR_CALL_PATTERN)

        # One row, one scan of the door's traffic — every counter the tiles carry that
        # can be read off an `audit` row, gathered in a single pass rather than in five.
        row = self._fetchone(
            "SELECT count(*)                                          AS calls,"
            "       count(*) FILTER (WHERE decision = 'deny')          AS denied,"
            "       count(*) FILTER (WHERE decision <> 'deny'"
            "                          AND effect = 'write')           AS writes,"
            "       count(*) FILTER (WHERE identity_source='verified') AS verified,"
            "       count(DISTINCT (principal_kind, principal_id))     AS callers"
            f"  FROM audit WHERE {self._TRAFFIC_WHERE}",
            door,
        ) or (0, 0, 0, 0, 0)

        # Refusals as one number, not five bands — `base.overview_totals` says why. Both
        # halves of the window's refusals: brokered denials over `audit` (matching what
        # `overview`'s five bands sum to) and `access_denials`,
        # which is the genuinely different table.
        brokered = self._fetchone(
            "SELECT count(*) FROM audit"
            f" WHERE tenant_id = %s AND {self._WINDOW} AND decision = 'deny'",
            (tenant_id, since, until),
        ) or (0,)
        access = self._fetchone(
            "SELECT count(*) FROM access_denials"
            f" WHERE tenant_id = %s AND {self._WINDOW}",
            (tenant_id, since, until),
        ) or (0,)
        changes = self._fetchone(
            "SELECT count(*) FROM admin_audit"
            f" WHERE tenant_id = %s AND {self._WINDOW}",
            (tenant_id, since, until),
        ) or (0,)
        # By model and **not by day** — nothing draws a previous window's shape, only its
        # total, and a day breakdown would be rows built to be summed and discarded.
        spend = self._fetchall(
            "SELECT model, COALESCE(SUM(input_tokens), 0),"
            "       COALESCE(SUM(output_tokens), 0),"
            "       COALESCE(SUM(cache_read_tokens), 0),"
            "       COALESCE(SUM(cache_write_tokens), 0)"
            f"  FROM audit WHERE {self._TRAFFIC_WHERE}"
            "   AND input_tokens IS NOT NULL"
            "  GROUP BY 1 ORDER BY 1",
            door,
        )

        return {
            "door_calls": int(row[0]),
            "door_denied": int(row[1]),
            "door_writes": int(row[2]),
            "door_verified": int(row[3]),
            "callers": int(row[4]),
            "refusals": int(brokered[0]) + int(access[0]),
            "admin_changes": int(changes[0]),
            "door_spend": [
                {
                    "model": bucket[0],
                    "input_tokens": int(bucket[1]),
                    "output_tokens": int(bucket[2]),
                    "cache_read_tokens": int(bucket[3]),
                    "cache_write_tokens": int(bucket[4]),
                }
                for bucket in spend
            ],
        }

    def overview(
        self,
        tenant_id: str,
        *,
        since: "date",
        until: "date",
        bucket: str = "day",
    ) -> dict:
        # `until` is passed through as the caller's inclusive date and widened to the
        # half-open bound **in SQL** (`%s::date + 1`), not here. This module holds no
        # runtime handle on a date type — `datetime` is imported under `TYPE_CHECKING`
        # alone, deliberately, which is why `due_schedules` does its arithmetic the same
        # way. Postgres adding a day to a date is also the same clock the column is
        # stored against, rather than this process's idea of one.
        door = (tenant_id, since, until, self._DOOR_CALL_PATTERN)
        window = (tenant_id, since, until)
        day = self._bucket(bucket)

        tools, tool_count, tool_tail = self._q_tool_totals(door)
        callers, caller_count, caller_tail = self._q_callers(door)
        agents, agent_count, agent_tail = self._q_agents(door)
        acting, acting_count, acting_tail = self._q_acting_for(door)
        reasons, reason_count, reason_tail = self._q_refusal_reasons(door)

        return {
            "door_calls": self._q_calls_by_day(door, day),
            "door_spend": self._q_door_spend(door, day),
            "door_effects": self._q_effects_by_day(door, day),
            "identity": self._q_identity(door, day),
            "door_latency": self._q_latency(door, day),
            "door_bytes": self._q_bytes(door, day),
            "callers": callers,
            # The store's own count and the store's own remainder, both from the
            # statement that produced the list. See `base.overview` for why a tail
            # computed by subtracting one query from another can go negative.
            "caller_count": caller_count,
            "caller_tail": caller_tail,
            "door_tools": tools,
            "tool_count": tool_count,
            "tool_tail": tool_tail,
            # 066a. The three dimensions this page held on every row and grouped by on
            # none: which permission list admitted the call, whose name it went out
            # under, and what the refusal actually said.
            "door_agents": agents,
            "agent_count": agent_count,
            "agent_tail": agent_tail,
            "acting_for": acting,
            "acting_for_count": acting_count,
            "acting_for_tail": acting_tail,
            "refusal_reasons": reasons,
            "refusal_reason_count": reason_count,
            "refusal_reason_tail": reason_tail,
            "tool_latency": self._q_tool_latency(door),
            "hourly": self._q_hourly(door),
            "refusals": self._q_refusals(tenant_id, since, until, day),
            "admin_actions": self._q_changes_by_family(window, day),
        }

    # The window, spelled once. Two decisions live in this string, and the second was a
    # bug in its first version:
    #
    # `>= floor` and `< until + 1 day`: `ts` is a TIMESTAMPTZ and `until` is a date, so
    # a `<= until` would compare against that day's midnight and silently drop
    # everything that happened *during* the last day of the window — the day a person
    # reading a dashboard is most likely to be asking about.
    #
    # `::timestamp AT TIME ZONE 'UTC'`, explicitly: a bare `ts >= %s` with a date
    # parameter casts through the **session's** `TimeZone`, and under BYOC that is
    # somebody else's Postgres with somebody else's default. The `_DAY` grouping is
    # pinned to UTC, so the first version had bounds and buckets on two different
    # clocks — a server on `America/New_York` shifted the window edges five hours off
    # the day labels, and rows near midnight either vanished or landed on days the
    # zero-fill then dropped. `(date)::timestamp` is naive midnight; `AT TIME ZONE
    # 'UTC'` declares that instant to be UTC. Constant per statement, so partition
    # pruning is unaffected.
    _WINDOW = (
        "ts >= (%s::date)::timestamp AT TIME ZONE 'UTC'"
        " AND ts < ((%s::date + 1))::timestamp AT TIME ZONE 'UTC'"
    )
    _TRAFFIC_WHERE = f"tenant_id = %s AND {_WINDOW} AND run_id LIKE %s"

    def _q_calls_by_day(self, params, day) -> list[dict]:
        # `FILTER (WHERE ...)` rather than `SUM(CASE ...)`: one pass, and each band reads
        # as the sentence it is. `errored` and `oversize` are counted **beside**
        # `allowed`, not carved out of it — a call that was permitted and then failed is
        # both, and subtracting the first would understate what the door admitted.
        #
        # **All four outcome bands, step 066a**, where two were drawn before. Migration
        # 004's CHECK has held five values since the table existed and this page has only
        # ever shown two of them; `unknown` in particular is a value the schema
        # anticipated and no screen has ever rendered. The stacked chart is unchanged —
        # it stays two disjoint segments for its own recorded reasons — and these land in
        # the numbers under it, which is where a band that is a *slice of* `allowed`
        # rather than a sibling of it can be read without lying about the total.
        #
        # `ok` is `outcome = 'ok'` and not "allowed minus the rest": a refused call
        # carries `''` and so does an admitted one nothing recorded for, so the residue
        # is not a synonym for success.
        rows = self._fetchall(
            f"SELECT {day} AS day,"
            "       count(*) FILTER (WHERE decision <> 'deny')            AS allowed,"
            "       count(*) FILTER (WHERE decision = 'deny')             AS denied,"
            "       count(*) FILTER (WHERE decision <> 'deny'"
            "                          AND outcome = 'error')             AS errored,"
            "       count(*) FILTER (WHERE decision <> 'deny'"
            "                          AND outcome = 'oversize')          AS oversize,"
            "       count(*) FILTER (WHERE decision <> 'deny'"
            "                          AND outcome = 'ok')                AS ok,"
            "       count(*) FILTER (WHERE decision <> 'deny'"
            "                          AND outcome = 'unknown')           AS unknown"
            f"  FROM audit WHERE {self._TRAFFIC_WHERE}"
            "  GROUP BY 1 ORDER BY 1",
            params,
        )
        return [
            {
                "day": row[0],
                "allowed": row[1],
                "denied": row[2],
                "errored": row[3],
                "oversize": row[4],
                "ok": row[5],
                "unknown": row[6],
            }
            for row in rows
        ]

    def _q_door_spend(self, params, day) -> list[dict]:
        """Per day and per model, what the door's calls reported spending. Step 045b.

        **Rows out, not dollars out.** The rate table lives in `core/usage.py` and the
        arithmetic happens in the route, because 045's Amendment 3 keeps money off every
        stored row and out of every statement — an operator who fixes their prices next
        week can reprice this history, which they could not if a dollar figure had been
        computed here.

        Grouped by model for the reason `spend_since` is: a cost is tokens x the rate for
        the model that produced them, and one flat `SUM` could only ever be priced at a
        blended rate.

        `input_tokens IS NOT NULL` is the door's *usage* filter, and it does most of the
        work: nearly every row this table holds is an ordinary tool call that touched no
        model, and reading those as zeros would return one enormous `''` bucket that
        contributes nothing but a spurious unpriced-model warning on every page.
        """
        rows = self._fetchall(
            f"SELECT {day} AS day, model,"
            "       COALESCE(SUM(input_tokens), 0),"
            "       COALESCE(SUM(output_tokens), 0),"
            "       COALESCE(SUM(cache_read_tokens), 0),"
            "       COALESCE(SUM(cache_write_tokens), 0)"
            f"  FROM audit WHERE {self._TRAFFIC_WHERE}"
            "   AND input_tokens IS NOT NULL"
            "  GROUP BY 1, 2 ORDER BY 1, 2",
            params,
        )
        return [
            {
                "day": row[0],
                "model": row[1],
                "input_tokens": int(row[2]),
                "output_tokens": int(row[3]),
                "cache_read_tokens": int(row[4]),
                "cache_write_tokens": int(row[5]),
            }
            for row in rows
        ]

    def _q_effects_by_day(self, params, day) -> list[dict]:
        rows = self._fetchall(
            f"SELECT {day} AS day,"
            "       count(*) FILTER (WHERE effect = 'read')  AS reads,"
            "       count(*) FILTER (WHERE effect = 'write') AS writes"
            f"  FROM audit WHERE {self._TRAFFIC_WHERE} AND decision <> 'deny'"
            "  GROUP BY 1 ORDER BY 1",
            params,
        )
        return [{"day": row[0], "read": row[1], "write": row[2]} for row in rows]

    def _q_identity(self, params, day) -> list[dict]:
        # Allow *and* deny, deliberately — 033c writes `identity_source` on refusals too,
        # and *what did we refuse, and on whose behalf* is the half an incident asks.
        # An unrecognised value falls into `none` rather than vanishing: a call missing
        # from this series is worse than one filed under the weakest claim.
        rows = self._fetchall(
            f"SELECT {day} AS day,"
            "       count(*) FILTER (WHERE identity_source = 'verified') AS verified,"
            "       count(*) FILTER (WHERE identity_source = 'asserted') AS asserted,"
            "       count(*) FILTER (WHERE identity_source NOT IN"
            "                              ('verified', 'asserted'))     AS anonymous"
            f"  FROM audit WHERE {self._TRAFFIC_WHERE}"
            "  GROUP BY 1 ORDER BY 1",
            params,
        )
        return [
            {"day": row[0], "verified": row[1], "asserted": row[2], "none": row[3]}
            for row in rows
        ]

    def _q_latency(self, params, day) -> list[dict]:
        # `percentile_cont`, not `percentile_disc` — it interpolates between neighbours,
        # which is what the fake's `_percentiles` reproduces. The two differ on every
        # even-length sample, and a store that was only *nearly* right here would drift
        # from the contract in a way no single assertion would name.
        rows = self._fetchall(
            f"SELECT {day} AS day,"
            "       percentile_cont(0.5)  WITHIN GROUP (ORDER BY duration_ms) AS med,"
            "       percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) AS p95"
            f"  FROM audit WHERE {self._TRAFFIC_WHERE}"
            "   AND decision <> 'deny' AND duration_ms IS NOT NULL"
            "  GROUP BY 1 ORDER BY 1",
            params,
        )
        return [
            {"day": row[0], "median_ms": _round_ms(row[1]), "p95_ms": _round_ms(row[2])}
            for row in rows
        ]

    # How a capped leaderboard reports what it cut. Step 066.
    #
    # **One statement, two answers.** The ranked rows and the totals they were ranked out
    # of come from the same CTE, so the cap, the count and the remainder are all computed
    # against one scan of one window. The alternative — the list from here, the count
    # from a second statement — is two scans that can straddle a write, and a remainder
    # derived by subtracting one from the other can then come out **negative**, which is
    # the one arithmetic on this page a reader would definitely notice.
    #
    # `ROW_NUMBER()` rather than a `LIMIT` on the CTE, because the tail has to be the
    # rows the cap excluded and a `LIMIT` throws them away before anything can count them.
    #
    # Returns `(rows, count, tail)`. `tail` is always a dict — `{"n": 0, ...}` when
    # nothing was cut — so a caller never has to test for None to render "and no more".
    @staticmethod
    def _split_tail(rows: list, project) -> tuple[list[dict], int, dict]:
        """The rows above the cap, the true count, and the sum of what fell below it.

        `rows` are `(..., rank, total)`-suffixed; `project` turns one into the dict the
        wire carries. The tail's `calls` and `denied` are summed **here** from the rows
        the statement returned rather than in SQL, because the statement already had to
        return them to rank them — a second aggregate over the same CTE would be a second
        pass to recompute numbers already in hand.
        """
        kept, tail_calls, tail_denied, tail_n = [], 0, 0, 0
        total = 0
        for row in rows:
            total = int(row[-1])
            if int(row[-2]) <= LEADERBOARD:
                kept.append(project(row))
            else:
                tail_n += 1
                tail_calls += int(row[-4])
                tail_denied += int(row[-3])
        return (
            kept,
            total,
            {"n": tail_n, "calls": tail_calls, "denied": tail_denied},
        )

    def _q_callers(self, params) -> tuple[list[dict], int, dict]:
        # Window totals, not a series: the question is *who is using this*, and a caller
        # who appears on three days is one row. Grouped on the principal rather than on
        # a token because `audit` has no token id — plan 041 finding 2, and the reason
        # one person's several personal tokens are one caller here.
        rows = self._fetchall(
            "WITH ranked AS ("
            "SELECT principal_kind, principal_id,"
            "       count(DISTINCT tool)                      AS tools,"
            # `AT TIME ZONE 'UTC'` strips to a naive UTC timestamp before psycopg sees
            # it, because a timestamptz comes back in the **session's** timezone and
            # `.isoformat()` faithfully renders that offset — same instant, a string
            # the fake (which renders `+00:00`) never produces. Found by running the
            # suite against a database defaulting to America/New_York.
            "       max(ts) AT TIME ZONE 'UTC'                AS last_seen,"
            "       count(*) FILTER (WHERE decision <> 'deny'"
            "                          AND effect = 'write')  AS writes,"
            # The last two ordinary columns are `calls` and `denied` in that order, and
            # `_split_tail` reads them positionally from the right (`row[-4]`, `row[-3]`)
            # so that every leaderboard here can share one splitter. Moving either is a
            # silent change to what the tail reports.
            "       count(*)                                  AS calls,"
            "       count(*) FILTER (WHERE decision = 'deny')  AS denied"
            f"  FROM audit WHERE {self._TRAFFIC_WHERE}"
            "  GROUP BY 1, 2"
            ")"
            # **Capped in SQL, not in the browser.** The first build shipped every
            # caller and let the page slice twelve off the front — which is unbounded
            # response size on a tenant with thousands of machines, and a truncation
            # nothing on the wire admits to.
            #
            # 066 keeps the cap and stops it being silent: the rows below it are counted
            # and summed rather than discarded, so the page can say *15 of 5,214* and
            # what the other 5,199 came to. Busiest first; the id breaks ties so the
            # order is stable across both stores rather than being whatever the group
            # order happened to produce.
            + _RANKED_SQL.format(tiebreak="principal_id")
            + "  ORDER BY rank",
            params,
        )
        return self._split_tail(
            rows,
            lambda row: {
                "principal_kind": row[0],
                "principal_id": row[1],
                "tools": row[2],
                # Naive UTC from the SELECT above; the suffix restores what the strip
                # removed, and matches the fake's `+00:00` byte for byte.
                "last_seen": f"{row[3].isoformat(timespec='milliseconds')}+00:00",
                "writes": row[4],
                "calls": row[5],
                "denied": row[6],
            },
        )

    def _q_tool_totals(self, params) -> tuple[list[dict], int, dict]:
        """One tool's totals across the window, **door traffic only**.

        `run_id LIKE 'door-%'` — the predicate is the whole of what separates a door call
        from anything else on this table, and it is applied here rather than left to the
        caller so that a leaderboard cannot quietly become a union.

        **This took a `door=False` and returned a second leaderboard until step 084.**
        013c added it so a run's tool calls and a door caller's could be read as two
        figures and never one sum — the right shape, for a tree that ran agents. This one
        does not, `routes_admin` discarded the second figure on every page load, and a
        statement over an empty population is a bar chart of nothing. What survives is the
        rule: two different things, and if a run's tool calls ever come back they come
        back as their own series, not folded into this one.
        """
        # `max(effect)` picks the non-empty one, because '' sorts below both 'read' and
        # 'write'. A refusal can carry '' — nothing was bound — and a tool reported as
        # having no effect would be indistinguishable from a read on the screen.
        #
        # Capped, counted and tailed together since 066: a deployment with eighteen tools
        # and a cap of fifteen showed a tool that had just been called on no chart at all
        # and said nothing about it. See `base.overview`.
        rows = self._fetchall(
            "WITH ranked AS ("
            "SELECT tool, max(effect) AS effect, count(*) AS calls,"
            "       count(*) FILTER (WHERE decision = 'deny') AS denied"
            f"  FROM audit WHERE {self._TRAFFIC_WHERE}"
            "  GROUP BY 1)"
            + _RANKED_SQL.format(tiebreak="tool")
            + "  ORDER BY rank",
            params,
        )
        return self._split_tail(
            rows,
            lambda row: {
                "tool": row[0],
                "effect": row[1],
                "calls": row[2],
                "denied": row[3],
            },
        )

    # `_q_caller_count` is gone, and its argument survived it. Since 041 the tile's
    # number was its own statement *"precisely because the leaderboard is capped — a tile
    # reading `len(callers)` would say 15 callers on a tenant with five thousand"*. That
    # is still true and is now enforced one layer earlier: `COUNT(*) OVER ()` gives the
    # true total from the same scan that produced the fifteen, so the tile cannot be
    # derived from the list's length and cannot disagree with it across a write either.

    def _q_agents(self, params) -> tuple[list[dict], int, dict]:
        """Which **permission list** admitted the traffic. Step 066a.

        `CLAUDE.md`'s first thing-not-to-get-wrong is that an agent is a named set of
        tools with a scope — the permission model itself, read by `door._granted_agents`
        on every single call — and until now the product's own dashboard grouped by it
        nowhere. Every `audit` row has carried the column since 004.

        The name is **as it was spelled when the row was written**, which is
        `door_call_summary`'s rule and its reason: the audit log keeps old names on
        purpose (035i), so a renamed agent's history stays under the name that was in
        force. Joining to the current name would rewrite what the log says happened.
        """
        rows = self._fetchall(
            "WITH ranked AS ("
            "SELECT agent, count(DISTINCT tool) AS tools, count(*) AS calls,"
            "       count(*) FILTER (WHERE decision = 'deny') AS denied"
            f"  FROM audit WHERE {self._TRAFFIC_WHERE}"
            "  GROUP BY 1)"
            + _RANKED_SQL.format(tiebreak="agent")
            + "  ORDER BY rank",
            params,
        )
        return self._split_tail(
            rows,
            lambda row: {
                "agent": row[0],
                "tools": row[1],
                "calls": row[2],
                "denied": row[3],
            },
        )

    def _q_acting_for(self, params) -> tuple[list[dict], int, dict]:
        """**Whose name** calls went out under, and what the claim was worth. Step 066a.

        Grouped by `(acting_for, identity_source)` and **never by name alone**, which is
        033c's rule at one more layer up: *"an asserted name is worth exactly what the
        calling app's honesty is worth, and a row that hid the difference would upgrade
        it."* One person reached both ways is two rows here, and that is the fact rather
        than a duplication to be tidied away.

        Rows with no name are excluded — `identity_source='none'` is already a band on
        the identity chart, and a leaderboard row reading `(nobody)` at the top of every
        deployment would crowd out the names this figure exists to show.
        """
        rows = self._fetchall(
            "WITH ranked AS ("
            "SELECT acting_for, identity_source, count(*) AS calls,"
            "       count(*) FILTER (WHERE decision = 'deny') AS denied"
            f"  FROM audit WHERE {self._TRAFFIC_WHERE}"
            "   AND acting_for IS NOT NULL AND acting_for <> ''"
            "  GROUP BY 1, 2)"
            + _RANKED_SQL.format(tiebreak="acting_for, identity_source")
            + "  ORDER BY rank",
            params,
        )
        return self._split_tail(
            rows,
            lambda row: {
                "acting_for": row[0],
                "identity_source": row[1],
                "calls": row[2],
                "denied": row[3],
            },
        )

    def _q_refusal_reasons(self, params) -> tuple[list[dict], int, dict]:
        """**What the control actually said.** Step 066a.

        The refusal chart says which control refused — policy, a ceiling, a budget,
        access — and it recovers three of those five bands by matching sentences, because
        033b kept one write path and a budget denial is not a distinct kind of row. This
        is the sentences themselves, ranked.

        `reason` is written by this codebase, never by a caller, and `core/audit._redact`
        has already been over the record. That is the condition under which it is safe to
        render on an admin screen, and it is a condition rather than a property — see the
        plan's known limits.

        `denied` is carried and is always equal to `calls` here, because the filter is
        `decision = 'deny'`. It is returned anyway so this list can share `_split_tail`
        with the other four rather than needing a second splitter for one column.
        """
        rows = self._fetchall(
            "WITH ranked AS ("
            "SELECT reason, count(*) AS calls, count(*) AS denied"
            f"  FROM audit WHERE {self._TRAFFIC_WHERE}"
            "   AND decision = 'deny' AND reason <> ''"
            "  GROUP BY 1)"
            + _RANKED_SQL.format(tiebreak="reason")
            + "  ORDER BY rank",
            params,
        )
        return self._split_tail(
            rows,
            lambda row: {"reason": row[0], "count": row[1]},
        )

    def _q_tool_latency(self, params) -> list[dict]:
        """How long each **tool** took. Step 066a.

        Latency existed only per day, so *which tool is slow* — the first question anybody
        asks after seeing a p95 move — was unanswerable from this page.

        Capped without a tail, and it is the one leaderboard here that has none: a
        remainder row summing the durations of every tool below the cap would be a
        percentile of a percentile, which is not a number. The cap is stated instead.

        Percentiles are `null` where nothing was timed, never 0 — `LatencyDay`'s rule,
        which exists because a day of refusals is not a day of instant calls, and a tool
        that was only ever refused is its exact analogue.
        """
        rows = self._fetchall(
            "SELECT tool, count(*) AS calls,"
            "       percentile_cont(0.5)  WITHIN GROUP (ORDER BY duration_ms) AS med,"
            "       percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) AS p95"
            f"  FROM audit WHERE {self._TRAFFIC_WHERE}"
            "   AND decision <> 'deny' AND duration_ms IS NOT NULL"
            # Ranked by how slow it is, not by how busy: the busiest tool is already the
            # top row of the figure beside this one, and repeating that order would draw
            # the same chart twice.
            f"  GROUP BY 1 ORDER BY med DESC NULLS LAST, tool LIMIT {LEADERBOARD}",
            params,
        )
        return [
            {
                "tool": row[0],
                "calls": row[1],
                "median_ms": _round_ms(row[2]),
                "p95_ms": _round_ms(row[3]),
            }
            for row in rows
        ]

    def _q_bytes(self, params, day) -> list[dict]:
        """What the door carried back, in bytes. Step 066a.

        `response_bytes` is on every admitted row and was aggregated nowhere, while
        `oversize` — which the page *does* draw — is the symptom of it. A day whose
        oversize count rises is a day to look at this.

        Allowed calls with a non-null size only, and `null` rather than 0 for a bucket
        with none, on `_q_latency`'s rule: nothing measured is not a measurement of
        nothing.
        """
        rows = self._fetchall(
            f"SELECT {day} AS day, COALESCE(SUM(response_bytes), 0) AS total,"
            "       percentile_cont(0.95) WITHIN GROUP (ORDER BY response_bytes) AS p95"
            f"  FROM audit WHERE {self._TRAFFIC_WHERE}"
            "   AND decision <> 'deny' AND response_bytes IS NOT NULL"
            "  GROUP BY 1 ORDER BY 1",
            params,
        )
        return [
            {"day": row[0], "bytes": int(row[1]), "p95_bytes": _round_ms(row[2])}
            for row in rows
        ]

    def _q_hourly(self, params) -> list[dict]:
        """Calls by weekday and hour of day, across the whole window. Step 066b.

        Not a series and deliberately not one: it answers *when is the door busy*, which
        is a question about the shape of a week rather than about any particular Tuesday,
        and it is the one figure on this page that survives the failure that prompted
        066 — eleven live calls in one hour is a lit cell whether or not the month behind
        it was heavy.

        **`weekday` is 0=Monday.** Postgres' `dow` is 0=Sunday and Python's `weekday()` is
        0=Monday, so one of the two stores has to convert and the choice decides what the
        wire means. Monday, because the page draws a working week and a grid whose first
        row is Sunday reads as off-by-one to everybody looking for it.

        Sparse: an hour nothing happened in is absent, which the page renders as an empty
        cell rather than as the bottom of the colour ramp — *nothing happened* and *the
        least that happened* are different facts.
        """
        rows = self._fetchall(
            "SELECT (extract(dow FROM ts AT TIME ZONE 'UTC')::int + 6) %% 7 AS weekday,"
            "       extract(hour FROM ts AT TIME ZONE 'UTC')::int AS hour,"
            "       count(*) AS calls"
            f"  FROM audit WHERE {self._TRAFFIC_WHERE}"
            "  GROUP BY 1, 2 ORDER BY 1, 2",
            params,
        )
        return [
            {"weekday": int(row[0]), "hour": int(row[1]), "calls": int(row[2])}
            for row in rows
        ]

    def _q_refusals(self, tenant_id, floor, until, day) -> list[dict]:
        """The five refusal kinds, merged into one dense-by-day shape.

        Two tables and one `FULL OUTER JOIN`, because `access_denials` is a genuinely
        different fact — a refusal that never reached a broker — and a day can have one
        kind without the other. An inner join would drop exactly the days where only one
        thing went wrong, which are the interesting ones.

        The `ceiling` / `run_budget` split is the string coupling plan 041 decision 7
        pins; the `run_id` half of it is structural. See `BUDGET_REFUSAL_MARKER`.

        **`door_spend` is the fourth band, added by 045b**, and it is a band rather than
        rows folded into `ceiling` for that constant's own reason one level on: *this
        credential made too many calls* and *this credential spent too much money* are
        different facts a manager acts on differently, and a single line that summed them
        would spike identically for either. The three door predicates are mutually
        exclusive because the two markers do not overlap as substrings — stated in
        `SPEND_REFUSAL_MARKER` and pinned by a test, because if they ever did, money
        refusals would silently file themselves under the call-count line and that line
        would be the only one anybody saw.

        Spend is tested **before** ceiling in the `policy` residue below for the same
        reason it is ordered first in the memory twin: the residue is *everything that is
        neither*, and writing it as a negation of both is what keeps the four bands
        summing to the day's denials however the sentences are worded.
        """
        rows = self._fetchall(
            "WITH brokered AS ("
            f"  SELECT {day} AS day,"
            "         count(*) FILTER (WHERE run_id LIKE %(door)s"
            "                            AND reason LIKE %(ceiling)s) AS ceiling,"
            "         count(*) FILTER (WHERE run_id LIKE %(door)s"
            "                            AND reason LIKE %(spend)s)   AS door_spend,"
            "         count(*) FILTER (WHERE run_id NOT LIKE %(door)s"
            "                            AND reason LIKE %(budget)s)  AS run_budget,"
            "         count(*) FILTER (WHERE NOT ("
            "                    (run_id LIKE %(door)s AND reason LIKE %(ceiling)s) OR"
            "                    (run_id LIKE %(door)s AND reason LIKE %(spend)s) OR"
            "                    (run_id NOT LIKE %(door)s AND reason LIKE %(budget)s)"
            "                  ))                                     AS policy"
            "    FROM audit"
            "   WHERE tenant_id = %(tenant)s"
            "     AND ts >= (%(floor)s::date)::timestamp AT TIME ZONE 'UTC'"
            "     AND ts < ((%(until)s::date + 1))::timestamp AT TIME ZONE 'UTC'"
            "     AND decision = 'deny'"
            "   GROUP BY 1"
            "), refused AS ("
            f"  SELECT {day} AS day, count(*) AS access"
            "    FROM access_denials"
            "   WHERE tenant_id = %(tenant)s"
            "     AND ts >= (%(floor)s::date)::timestamp AT TIME ZONE 'UTC'"
            "     AND ts < ((%(until)s::date + 1))::timestamp AT TIME ZONE 'UTC'"
            "   GROUP BY 1"
            ")"
            " SELECT coalesce(b.day, r.day) AS day,"
            "        coalesce(b.policy, 0), coalesce(b.ceiling, 0),"
            "        coalesce(b.door_spend, 0),"
            "        coalesce(b.run_budget, 0), coalesce(r.access, 0)"
            "   FROM brokered b FULL OUTER JOIN refused r ON b.day = r.day"
            "  ORDER BY 1",
            {
                "tenant": tenant_id,
                "floor": floor,
                "until": until,
                "door": self._DOOR_CALL_PATTERN,
                # Wildcards on both sides: the phrases sit mid-sentence, after an
                # interpolated number in the door's case and after a qualifier
                # ("write", "response") in the budget's.
                "ceiling": f"%{CEILING_REFUSAL_MARKER}%",
                "spend": f"%{SPEND_REFUSAL_MARKER}%",
                "budget": f"%{BUDGET_REFUSAL_MARKER}%",
            },
        )
        return [
            {
                "day": row[0],
                "policy": row[1],
                "ceiling": row[2],
                "door_spend": row[3],
                "run_budget": row[4],
                "access": row[5],
            }
            for row in rows
        ]

    def _q_changes_by_family(self, params, day) -> list[dict]:
        # `split_part(action, '.', 1)` is the family — `grant.create` is `grant`. Derived
        # rather than maintained: the 45-action vocabulary is already dotted, so a new
        # action joins its family for free and a new family appears without anyone
        # updating a list that would otherwise drop it silently.
        rows = self._fetchall(
            f"SELECT {day} AS day, split_part(action, '.', 1) AS family,"
            "       count(*) AS calls"
            "  FROM admin_audit"
            f" WHERE tenant_id = %s AND {self._WINDOW}"
            " GROUP BY 1, 2 ORDER BY 1, 2",
            params,
        )
        return [{"day": row[0], "family": row[1], "count": row[2]} for row in rows]

    # **`_q_runs`, `_q_run_latency`, `_q_schedule_health` and `_run_bucket` were here
    # until step 084.** Three statements over `runs` and `schedules` on every load of
    # `GET /admin/overview`, producing three series the route has discarded since 041 and
    # that this tree cannot fill: 078 took the runtime out, nothing writes either table,
    # and `docs/PREMISE.md` says plainly that anything measuring `runs` is measuring
    # nothing. The tables stay — released migrations are immutable and an empty table is
    # free — and the *methods* that read them for a screen do not, because a query on a
    # live read is not free.
    #
    # `_agent_name_expr` stays: `_q_schedule_health` was one of its callers and the
    # derivation has four more.

    # --- identity providers -----------------------------------------------------

    _IDP_COLUMNS = (
        "tenant_id",
        "issuer",
        "discriminator_claim",
        "discriminator_value",
        "jwks_uri",
        "audience",
        "subject_claim",
        "email_claim",
        "groups_claim",
        "allowed_domains",
        "enabled",
    )

    @staticmethod
    def _idp_row(row) -> dict:
        out = dict(zip(PostgresStorage._IDP_COLUMNS, row))
        # A Postgres TEXT[] arrives as a list; the in-memory store holds a tuple.
        # The contract suite compares round-tripped rows, so they have to agree.
        out["allowed_domains"] = tuple(out["allowed_domains"] or ())
        return out

    def save_tenant_idp(self, tenant_id: str, idp: dict) -> None:
        row = normalize_idp(idp)
        self._require_tenant(tenant_id)

        # Conflict check and write in one transaction. Two admins registering the same
        # issuer at the same moment would otherwise both pass the check and the second
        # would win the upsert â€” which is the exact ambiguity being guarded against,
        # arrived at by a different route.
        with self._transaction() as cur:
            cur.execute(
                "SELECT tenant_id, discriminator_claim, discriminator_value, "
                "groups_claim FROM tenant_idps WHERE issuer = %s FOR UPDATE",
                (row["issuer"],),
            )
            existing = cur.fetchall()
            self._check_issuer_conflict(row, tenant_id, existing)

            # What this row said about groups *before* this write, if it existed. Read
            # inside the same transaction as the upsert, so the comparison below cannot
            # be raced.
            was = next(
                (
                    other[3]
                    for other in existing
                    if (other[1], other[2])
                    == (row["discriminator_claim"], row["discriminator_value"])
                ),
                None,
            )

            cur.execute(
                """
                INSERT INTO tenant_idps (
                    tenant_id, issuer, discriminator_claim, discriminator_value,
                    jwks_uri, audience, subject_claim, email_claim, groups_claim,
                    allowed_domains, enabled
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (issuer, discriminator_claim, discriminator_value)
                DO UPDATE SET
                    tenant_id = EXCLUDED.tenant_id,
                    jwks_uri = EXCLUDED.jwks_uri,
                    audience = EXCLUDED.audience,
                    subject_claim = EXCLUDED.subject_claim,
                    email_claim = EXCLUDED.email_claim,
                    groups_claim = EXCLUDED.groups_claim,
                    allowed_domains = EXCLUDED.allowed_domains,
                    enabled = EXCLUDED.enabled
                """,
                (
                    tenant_id,
                    row["issuer"],
                    row["discriminator_claim"],
                    row["discriminator_value"],
                    row["jwks_uri"],
                    row["audience"],
                    row["subject_claim"],
                    row["email_claim"],
                    row["groups_claim"],
                    list(row["allowed_domains"]),
                    row["enabled"],
                ),
            )

            # Step 033e. A registration that **moves the groups claim** clears what
            # this tenant's reconciliations have already done, because the claim mapping
            # is half of what they read — believed at the next request rather than
            # whenever somebody's token next happens to change. Only when it moves:
            # `--add-idp` is an upsert, so a provisioning script re-runs it, and
            # clearing every marker in the tenant to rotate a `jwks_uri` is the
            # stampede the marker exists to prevent. In this transaction, so a
            # registration that fails leaves the markers alone.
            if was != row["groups_claim"]:
                self._forget_directory_digests(cur, tenant_id)

    @staticmethod
    def _check_issuer_conflict(row: dict, tenant_id: str, existing: list) -> None:
        """The rule no UNIQUE can express. See `base.save_tenant_idp`.

        Note this is NOT the `ON CONFLICT` clause's job: that handles the exact key
        colliding, which is a legitimate update. This handles two *different* keys for
        one issuer being mutually exclusive, which no constraint can state.
        """
        issuer = row["issuer"]
        claim = row["discriminator_claim"]
        value = row["discriminator_value"]

        for other_tenant, other_claim, other_value, *_ in existing:
            same_key = (other_claim, other_value) == (claim, value)

            if same_key:
                if other_tenant != tenant_id:
                    raise IssuerConflictError(
                        f"issuer '{issuer}' is already registered to tenant "
                        f"'{other_tenant}'. An identity provider speaks for one "
                        "customer; registering it twice is how one reads the other's "
                        "data."
                    )
                continue

            if claim is None:
                raise IssuerConflictError(
                    f"issuer '{issuer}' already has a provider registered with a "
                    f"discriminator ({other_claim}={other_value}). A registration "
                    "without one claims the whole issuer and cannot coexist with it."
                )
            if other_claim is None:
                raise IssuerConflictError(
                    f"issuer '{issuer}' is already registered without a "
                    f"discriminator, by tenant '{other_tenant}', which claims the "
                    "whole issuer. Both registrations must discriminate, or neither "
                    "can."
                )

    def find_tenant_idps(self, issuer: str) -> list[dict]:
        columns = ", ".join(self._IDP_COLUMNS)
        return [
            self._idp_row(row)
            for row in self._fetchall(
                f"SELECT {columns} FROM tenant_idps WHERE issuer = %s "
                "ORDER BY coalesce(discriminator_value, '')",
                (issuer,),
            )
        ]

    def list_tenant_idps(self, tenant_id: str) -> list[dict]:
        columns = ", ".join(self._IDP_COLUMNS)
        return [
            self._idp_row(row)
            for row in self._fetchall(
                f"SELECT {columns} FROM tenant_idps WHERE tenant_id = %s "
                "ORDER BY issuer, coalesce(discriminator_value, '')",
                (tenant_id,),
            )
        ]

    def delete_tenant_idp(
        self, tenant_id: str, issuer: str, discriminator_value: str | None = None
    ) -> None:
        # `IS NOT DISTINCT FROM` rather than `=`, so a NULL discriminator matches a
        # NULL discriminator. With `=` this would silently delete nothing for exactly
        # the Okta and Entra rows that are the common case.
        self._execute(
            "DELETE FROM tenant_idps WHERE tenant_id = %s AND issuer = %s "
            "AND discriminator_value IS NOT DISTINCT FROM %s",
            (tenant_id, issuer, discriminator_value),
        )

    # --- users ------------------------------------------------------------------

    _USER_COLUMNS = (
        "id",
        "tenant_id",
        "issuer",
        "subject",
        "email",
        "display_name",
        "status",
        "last_seen_at",
        # Migration 043. What the directory reconciliation has already done for this
        # person, and the `iat` of the token it did it from. Read on the authentication
        # path, which already has this row in hand — see `access/directory.py`.
        "directory_digest",
        "directory_synced_at",
        # Migration 052. The directory's own id for the person, NULL for everybody it
        # has not pushed; and `created_at`, which has been in the table since 008 and
        # is read now because `find_provisioned_user` orders by it.
        "external_id",
        "created_at",
    )

    def create_user(
        self, tenant_id: str, user: dict, *, actor: str | None = None
    ) -> None:
        import psycopg

        row = normalize_user(user)
        self._require_tenant(tenant_id)

        # Built before the transaction opens, matching every other write here. None
        # for the JIT sign-in path, which writes no record.
        record = (
            None
            if actor is None
            else make_admin_record(
                "user.create", "user", row["id"], actor, {"provisioned": True}
            )
        )

        try:
            with self._transaction() as cur:
                cur.execute(
                    """
                    INSERT INTO users (
                        id, tenant_id, issuer, subject, external_id, email,
                        display_name, status
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        row["id"],
                        tenant_id,
                        row["issuer"],
                        row["subject"],
                        row["external_id"],
                        row["email"],
                        row["display_name"],
                        row["status"],
                    ),
                )
                if record is not None:
                    self._write_admin(cur, tenant_id, record)
        except StorageError as exc:
            # A unique violation here is a recycled id, the same person twice, or —
            # since 052 — a directory id another row already holds. All are refusals
            # rather than upserts: `create_user` means create.
            cause = exc.__cause__
            if isinstance(cause, psycopg.errors.UniqueViolation):
                constraint = getattr(getattr(cause, "diag", None), "constraint_name", "")
                if constraint == "users_by_external_id":
                    raise StorageError(
                        self._external_id_taken(tenant_id, row["issuer"], row["external_id"])
                    ) from exc
                raise StorageError(
                    f"a user already exists for id '{row['id']}' or for subject "
                    f"'{row['subject']}' at issuer '{row['issuer']}'. Identity is the "
                    "pair; a person cannot belong to two customers."
                ) from exc
            raise

    def _external_id_taken(self, tenant_id: str, issuer: str, external_id) -> str:
        """The sentence for `users_by_external_id`, naming the row that holds it.

        A second read after the violation rather than a guess, on
        `_group_collision`'s precedent: the push reading this has to say which person
        collided, and the memory store has known from the first version.
        """
        other = self._fetchone(
            "SELECT id FROM users WHERE tenant_id = %s AND issuer = %s "
            "AND external_id = %s",
            (tenant_id, issuer, external_id),
        )
        holder = f" (user '{other[0]}')" if other else ""
        return (
            f"another person in this tenant at issuer '{issuer}' already holds the "
            f"directory id '{external_id}'{holder}. The directory sent one object id "
            "for two people; that is its record to read, not ours to resolve by "
            "picking one."
        )

    def find_user(self, issuer: str, subject: str | None) -> dict | None:
        # A provisioned row has no subject, and a token with none must be nobody.
        # `subject = NULL` is never true in SQL, so this would be None anyway — but
        # returned before looking, so the contract does not rest on how a driver
        # renders a parameter.
        if not subject:
            return None
        columns = ", ".join(self._USER_COLUMNS)
        row = self._fetchone(
            f"SELECT {columns} FROM users WHERE issuer = %s AND subject = %s",
            (issuer, subject),
        )
        return dict(zip(self._USER_COLUMNS, row)) if row is not None else None

    def find_provisioned_user(
        self, tenant_id: str, issuer: str, email: str
    ) -> dict | None:
        wanted = normalize_email(email)
        if not wanted:
            return None
        columns = ", ".join(self._USER_COLUMNS)
        # `lower(btrim(email))` rather than an index, on `find_user_by_email`'s
        # reasoning: this runs once per first sign-in, against one tenant's rows.
        row = self._fetchone(
            f"""
            SELECT {columns} FROM users
             WHERE tenant_id = %s AND issuer = %s AND subject IS NULL
               AND email <> '' AND lower(btrim(email)) = %s
             ORDER BY created_at, id LIMIT 1
            """,
            (tenant_id, issuer, wanted),
        )
        return dict(zip(self._USER_COLUMNS, row)) if row is not None else None

    def adopt_user_subject(
        self, tenant_id: str, user_id: str, subject: str, *, actor: str
    ) -> bool:
        import psycopg

        if not subject or not subject.strip():
            raise StorageError(
                "a provisioned row cannot be adopted by a blank subject: `find_user` "
                "never matches one, so the person could never sign in again."
            )
        subject = subject.strip()
        split_actor(actor)

        try:
            with self._transaction() as cur:
                # The compare-and-set: `subject IS NULL` in the WHERE, so a second
                # sign-in racing for the row updates nothing and writes no record.
                row = cur.execute(
                    """
                    UPDATE users SET subject = %s
                     WHERE tenant_id = %s AND id = %s AND subject IS NULL
                    RETURNING issuer
                    """,
                    (subject, tenant_id, user_id),
                ).fetchone()
                if row is None:
                    return False
                record = make_admin_record(
                    "user.adopt", "user", user_id, actor, {"issuer": row[0]}
                )
                self._write_admin(cur, tenant_id, record)
                return True
        except StorageError as exc:
            if isinstance(exc.__cause__, psycopg.errors.UniqueViolation):
                raise StorageError(
                    f"a user for subject '{subject}' already exists at this issuer. "
                    "Identity is the pair; a provisioned row cannot be adopted by "
                    "somebody who is already here."
                ) from exc
            raise

    def find_user_by_external_id(
        self, tenant_id: str, issuer: str, external_id: str
    ) -> dict | None:
        if not external_id:
            return None
        columns = ", ".join(self._USER_COLUMNS)
        row = self._fetchone(
            f"SELECT {columns} FROM users "
            "WHERE tenant_id = %s AND issuer = %s AND external_id = %s",
            (tenant_id, issuer, external_id),
        )
        return dict(zip(self._USER_COLUMNS, row)) if row is not None else None

    def update_user(
        self,
        tenant_id: str,
        user_id: str,
        *,
        actor: str,
        email: str | None = None,
        display_name: str | None = None,
        external_id=_UNSET,
    ) -> dict | None:
        import psycopg

        split_actor(actor)
        wanted: dict = {}
        if email is not None:
            wanted["email"] = email
        if display_name is not None:
            wanted["display_name"] = display_name
        if external_id is not _UNSET:
            wanted["external_id"] = normalize_user_external_id(external_id)

        columns = ", ".join(self._USER_COLUMNS)
        try:
            with self._transaction() as cur:
                # Read under a row lock, so "what changed" is decided against the row
                # this transaction will write and not against one another push moved.
                existing = cur.execute(
                    f"SELECT {columns} FROM users WHERE tenant_id = %s AND id = %s "
                    "FOR UPDATE",
                    (tenant_id, user_id),
                ).fetchone()
                if existing is None:
                    return None
                current = dict(zip(self._USER_COLUMNS, existing))

                changed = sorted(k for k, v in wanted.items() if current[k] != v)
                if not changed:
                    return current

                record = make_admin_record(
                    "user.update", "user", user_id, actor, {"fields": changed}
                )
                # Column names come from `wanted`'s three fixed keys, never from a
                # caller; the values are parameters.
                assignments = ", ".join(f"{key} = %s" for key in changed)
                row = cur.execute(
                    f"UPDATE users SET {assignments} "  # noqa: S608
                    f"WHERE tenant_id = %s AND id = %s RETURNING {columns}",
                    (*[wanted[key] for key in changed], tenant_id, user_id),
                ).fetchone()
                self._write_admin(cur, tenant_id, record)
                return dict(zip(self._USER_COLUMNS, row))
        except StorageError as exc:
            if isinstance(exc.__cause__, psycopg.errors.UniqueViolation):
                # The subject is not being written here, so there is exactly one
                # uniqueness this statement can violate.
                issuer = self._fetchone(
                    "SELECT issuer FROM users WHERE tenant_id = %s AND id = %s",
                    (tenant_id, user_id),
                )
                raise StorageError(
                    self._external_id_taken(
                        tenant_id, issuer[0] if issuer else "", wanted.get("external_id")
                    )
                ) from exc
            raise

    def list_users(self, tenant_id: str) -> list[dict]:
        columns = ", ".join(self._USER_COLUMNS)
        return [
            dict(zip(self._USER_COLUMNS, row))
            for row in self._fetchall(
                f"SELECT {columns} FROM users WHERE tenant_id = %s ORDER BY id",
                (tenant_id,),
            )
        ]

    def get_user(self, tenant_id: str, user_id: str) -> dict | None:
        columns = ", ".join(self._USER_COLUMNS)
        row = self._fetchone(
            f"SELECT {columns} FROM users WHERE tenant_id = %s AND id = %s",
            (tenant_id, user_id),
        )
        return dict(zip(self._USER_COLUMNS, row)) if row is not None else None

    def set_user_status(
        self,
        tenant_id: str,
        user_id: str,
        status: str,
        *,
        actor: str,
        detail: dict | None = None,
    ) -> dict | None:
        if status not in USER_STATUSES:
            raise StorageError(
                f"status must be one of {sorted(USER_STATUSES)}, not '{status}'"
            )
        action = "user.disable" if status == "disabled" else "user.enable"
        record = make_admin_record(action, "user", user_id, actor, detail)

        columns = ", ".join(self._USER_COLUMNS)
        with self._transaction() as cur:
            # `status <> %s` in the WHERE, so restating the current status updates
            # nothing and writes no record — `revoke_api_token`'s idempotence.
            row = cur.execute(
                f"""
                UPDATE users SET status = %s
                 WHERE tenant_id = %s AND id = %s AND status <> %s
                RETURNING {columns}
                """,
                (status, tenant_id, user_id, status),
            ).fetchone()

            if row is None:
                # Either there is no such person, or they are already so. Tell those
                # apart for the caller, but write no record either way.
                existing = cur.execute(
                    f"SELECT {columns} FROM users WHERE tenant_id = %s AND id = %s",
                    (tenant_id, user_id),
                ).fetchone()
                if existing is None:
                    return None
                return dict(zip(self._USER_COLUMNS, existing))

            self._write_admin(cur, tenant_id, record)
            return dict(zip(self._USER_COLUMNS, row))

    def record_user_login(self, user_id: str, email: str, display_name: str) -> None:
        self._execute(
            "UPDATE users SET email = %s, display_name = %s, last_seen_at = now() "
            "WHERE id = %s",
            (email, display_name, user_id),
        )

    def record_directory_sync(
        self,
        tenant_id: str,
        user_id: str,
        digest: str,
        synced_at: "datetime | None",
        *,
        expect: str | None = None,
    ) -> None:
        self._execute(
            "UPDATE users SET directory_digest = %s, directory_synced_at = %s "
            "WHERE tenant_id = %s AND id = %s "
            # The compare-and-set. `IS NOT DISTINCT FROM` rather than `=` because the
            # expected value is NULL for a first reconciliation and for one that follows
            # an invalidation, which is exactly when this matters.
            "AND directory_digest IS NOT DISTINCT FROM %s",
            (digest, synced_at, tenant_id, user_id, expect),
        )

    @staticmethod
    def _forget_directory_digests(cur, tenant_id: str) -> None:
        """Clear this tenant's reconciliation markers, inside a caller's transaction.

        Every write that could change what a reconciliation would produce calls this, in
        the same transaction as the write itself: a group gaining an `external_id`, and a
        provider's claim mapping moving. That is what makes `directory_digest` exact
        rather than a TTL guess — the marker cannot outlive the input it was computed
        against, so *"I linked the group, why is nobody in it"* has the answer **at their
        next request** rather than at some unstated later time.

        **Only the digest.** `directory_synced_at` is not an input to what a
        reconciliation would produce — it is the ordering fact, *how new the token was
        that last applied* — and clearing it disarmed the guard that keeps an older
        token from rewriting a newer one's answer. The edge-case pass found the
        consequence: link any unrelated group, and one stale tab per person could put
        back a membership their newer token had already removed.

        Deliberately **not** called when a group is unlinked or deleted: a group that
        stops being directory-backed keeps the membership it has and the admin owns it
        from then on, and a deleted group's rows went with it. Nothing needs recomputing
        to make either true.

        One UPDATE over `users` behind `users_by_tenant` (migration 008), on an action
        nobody runs in a loop — the same trade `delete_group` makes when it counts what
        it is about to destroy.
        """
        cur.execute(
            "UPDATE users SET directory_digest = NULL "
            "WHERE tenant_id = %s AND directory_digest IS NOT NULL",
            (tenant_id,),
        )

    def directory_groups(self, tenant_id: str, user_id: str) -> list[dict]:
        return [
            {"group_id": row[0], "external_id": row[1], "member": row[2]}
            for row in self._fetchall(
                """
                SELECT g.group_id, g.external_id, (m.principal_id IS NOT NULL)
                  FROM groups g
                  LEFT JOIN group_members m
                    ON m.tenant_id = g.tenant_id
                   AND m.group_id = g.group_id
                   AND m.principal_kind = 'user'
                   AND m.principal_id = %s
                 WHERE g.tenant_id = %s AND g.external_id IS NOT NULL
                 ORDER BY g.group_id
                """,
                (user_id, tenant_id),
            )
        ]

    # --- api tokens -------------------------------------------------------------

    _API_TOKEN_COLUMNS = API_TOKEN_FIELDS
    _API_TOKEN_PUBLIC_COLUMNS = API_TOKEN_PUBLIC_FIELDS

    def create_api_token(self, tenant_id: str, token: dict, *, actor: str) -> dict:
        import psycopg

        row = normalize_api_token(token)
        self._require_tenant(tenant_id)

        # Built before the transaction opens, matching every other write here: a bad
        # actor must leave the table untouched rather than half-written.
        record = make_admin_record(
            "token.mint",
            "machine",
            row["id"],
            actor,
            {
                "name": row["name"],
                "owner": row["owner_id"],
                # Minting a personal token IS the trust decision of step 033d, so the
                # record carries it — "who approved that" should be a row, the same
                # argument `connector.asserted_identity` made one chunk earlier.
                "acts_as_owner": row["acts_as_owner"],
                "expires_at": row["expires_at"].isoformat()
                if row["expires_at"]
                else "",
                # Step 083. Only when there is one, so a record written before this
                # key existed and one written by the CLI today read identically.
                **({"via": row["via"]} if row.get("via") else {}),
            },
        )

        columns = ", ".join(self._API_TOKEN_PUBLIC_COLUMNS)
        try:
            with self._transaction() as cur:
                created = cur.execute(
                    f"""
                    INSERT INTO api_tokens (
                        id, tenant_id, name, owner_id, acts_as_owner, secret_hash,
                        created_by, expires_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING {columns}
                    """,
                    (
                        row["id"],
                        tenant_id,
                        row["name"],
                        row["owner_id"],
                        row["acts_as_owner"],
                        row["secret_hash"],
                        actor,
                        row["expires_at"],
                    ),
                ).fetchone()
                self._write_admin(cur, tenant_id, record)
                return dict(zip(self._API_TOKEN_PUBLIC_COLUMNS, created))
        except StorageError as exc:
            # **Two unique constraints, and they are different failures.** Discriminated
            # by constraint name on `save_connection`'s precedent, because catching
            # `UniqueViolation` alone and blaming the name reports a collision on the
            # opaque id — which nobody chose and nobody can act on — as though somebody
            # had typed a duplicate name. The contract suite caught exactly that, and
            # the in-memory store had told them apart from the first version.
            cause = exc.__cause__
            if isinstance(cause, psycopg.errors.UniqueViolation):
                constraint = getattr(getattr(cause, "diag", None), "constraint_name", "")
                if constraint == "api_tokens_one_live_name":
                    # The store working perfectly and somebody reusing a name: a 400 over
                    # HTTP and a `parser.error` on the CLI, not "storage unavailable".
                    raise ValueRefused(
                        f"this customer already has a live API token called "
                        f"'{row['name']}'. The name is what somebody reads when "
                        "deciding which token to revoke, so two live rows sharing one "
                        "makes that decision a guess. Revoking the old one frees the "
                        "name for its replacement."
                    ) from exc
                raise StorageError(
                    f"an api token with id '{row['id']}' already exists. The id is "
                    "minted rather than chosen, so this is a collision in whatever "
                    "generated it rather than anything a caller did."
                ) from exc
            raise

    def find_api_token(self, token_id: str) -> dict | None:
        # No tenant filter, and it is not an omission: a caller holding a token string
        # has no tenant to pass, because the tenant is what this lookup produces. The
        # third such method, after `find_user` and `claim_run`.
        columns = ", ".join(self._API_TOKEN_COLUMNS)
        row = self._fetchone(
            f"SELECT {columns} FROM api_tokens WHERE id = %s", (token_id,)
        )
        return dict(zip(self._API_TOKEN_COLUMNS, row)) if row is not None else None

    def list_api_tokens(self, tenant_id: str, *, owner_id: str = "") -> list[dict]:
        columns = ", ".join(self._API_TOKEN_PUBLIC_COLUMNS)
        # `%s = ''` rather than a built-up WHERE clause: one statement, one plan, and no
        # branch where a caller's empty string could become a missing predicate.
        return [
            dict(zip(self._API_TOKEN_PUBLIC_COLUMNS, row))
            for row in self._fetchall(
                f"""
                SELECT {columns} FROM api_tokens
                 WHERE tenant_id = %s AND (%s = '' OR owner_id = %s)
                 ORDER BY name
                """,
                (tenant_id, owner_id, owner_id),
            )
        ]

    def revoke_api_token(
        self, tenant_id: str, token_id: str, *, actor: str
    ) -> dict | None:
        record = make_admin_record("token.revoke", "machine", token_id, actor)

        columns = ", ".join(self._API_TOKEN_PUBLIC_COLUMNS)
        with self._transaction() as cur:
            # `revoked_at IS NULL` in the WHERE, so re-revoking updates nothing and the
            # second call writes no record — `revoke_platform_role`'s idempotence, with
            # the row surviving instead of going.
            row = cur.execute(
                f"""
                UPDATE api_tokens SET revoked_at = now(), revoked_by = %s
                 WHERE tenant_id = %s AND id = %s AND revoked_at IS NULL
                RETURNING {columns}
                """,
                (actor, tenant_id, token_id),
            ).fetchone()

            if row is None:
                # Either there is no such token, or it was already revoked. Tell those
                # apart for the caller's sentence, but write no record either way.
                existing = cur.execute(
                    f"SELECT {columns} FROM api_tokens WHERE tenant_id = %s AND id = %s",
                    (tenant_id, token_id),
                ).fetchone()
                if existing is None:
                    return None
                return dict(zip(self._API_TOKEN_PUBLIC_COLUMNS, existing))

            self._write_admin(cur, tenant_id, record)
            return dict(zip(self._API_TOKEN_PUBLIC_COLUMNS, row))

    def touch_api_token(self, token_id: str) -> None:
        self._execute(
            "UPDATE api_tokens SET last_used_at = now() WHERE id = %s", (token_id,)
        )

    # --- scim tokens -------------------------------------------------------------

    _SCIM_TOKEN_COLUMNS = SCIM_TOKEN_FIELDS
    _SCIM_TOKEN_PUBLIC_COLUMNS = SCIM_TOKEN_PUBLIC_FIELDS

    def mint_scim_token(self, tenant_id: str, row: dict, *, actor: str) -> dict:
        import psycopg

        row = normalize_scim_token(row)
        self._require_tenant(tenant_id)

        record = make_admin_record(
            "scim.token.mint",
            "scim_token",
            row["id"],
            actor,
            {"issuer": row["issuer"], "name": row["name"]},
        )

        columns = ", ".join(self._SCIM_TOKEN_PUBLIC_COLUMNS)
        try:
            with self._transaction() as cur:
                # Bound to an issuer this tenant has registered, checked in the same
                # transaction as the insert. Not a foreign key — `tenant_idps` has no
                # single-column key to reference — so this is the check.
                registered = cur.execute(
                    "SELECT 1 FROM tenant_idps WHERE tenant_id = %s AND issuer = %s "
                    "LIMIT 1",
                    (tenant_id, row["issuer"]),
                ).fetchone()
                if registered is None:
                    raise ValueRefused(
                        SCIM_ISSUER_NOT_REGISTERED.format(issuer=row["issuer"])
                    )

                created = cur.execute(
                    f"""
                    INSERT INTO scim_tokens (
                        id, tenant_id, issuer, name, secret_hash, created_by
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING {columns}
                    """,
                    (
                        row["id"],
                        tenant_id,
                        row["issuer"],
                        row["name"],
                        row["secret_hash"],
                        row["created_by"],
                    ),
                ).fetchone()
                self._write_admin(cur, tenant_id, record)
                return dict(zip(self._SCIM_TOKEN_PUBLIC_COLUMNS, created))
        except StorageError as exc:
            if isinstance(exc.__cause__, psycopg.errors.UniqueViolation):
                raise StorageError(
                    f"a scim token with id '{row['id']}' already exists. The id is "
                    "minted rather than chosen, so this is a collision in whatever "
                    "generated it rather than anything a caller did."
                ) from exc
            raise

    def find_scim_token(self, token_id: str) -> dict | None:
        # No tenant filter, and it is not an omission — see `find_api_token`.
        columns = ", ".join(self._SCIM_TOKEN_COLUMNS)
        row = self._fetchone(
            f"SELECT {columns} FROM scim_tokens WHERE id = %s", (token_id,)
        )
        return dict(zip(self._SCIM_TOKEN_COLUMNS, row)) if row is not None else None

    def list_scim_tokens(self, tenant_id: str) -> list[dict]:
        columns = ", ".join(self._SCIM_TOKEN_PUBLIC_COLUMNS)
        return [
            dict(zip(self._SCIM_TOKEN_PUBLIC_COLUMNS, row))
            for row in self._fetchall(
                f"SELECT {columns} FROM scim_tokens WHERE tenant_id = %s "
                "ORDER BY created_at, id",
                (tenant_id,),
            )
        ]

    def revoke_scim_token(
        self, tenant_id: str, token_id: str, *, actor: str
    ) -> dict | None:
        record = make_admin_record("scim.token.revoke", "scim_token", token_id, actor)

        columns = ", ".join(self._SCIM_TOKEN_PUBLIC_COLUMNS)
        with self._transaction() as cur:
            # `revoked_at IS NULL` in the WHERE — `revoke_api_token`'s idempotence.
            row = cur.execute(
                f"""
                UPDATE scim_tokens SET revoked_at = now(), revoked_by = %s
                 WHERE tenant_id = %s AND id = %s AND revoked_at IS NULL
                RETURNING {columns}
                """,
                (actor, tenant_id, token_id),
            ).fetchone()

            if row is None:
                existing = cur.execute(
                    f"SELECT {columns} FROM scim_tokens WHERE tenant_id = %s AND id = %s",
                    (tenant_id, token_id),
                ).fetchone()
                if existing is None:
                    return None
                return dict(zip(self._SCIM_TOKEN_PUBLIC_COLUMNS, existing))

            self._write_admin(cur, tenant_id, record)
            return dict(zip(self._SCIM_TOKEN_PUBLIC_COLUMNS, row))

    def touch_scim_token(self, token_id: str) -> None:
        self._execute(
            "UPDATE scim_tokens SET last_used_at = now() WHERE id = %s", (token_id,)
        )

    def tenant_has_live_scim_token(self, tenant_id: str, issuer: str) -> bool:
        return (
            self._fetchone(
                "SELECT 1 FROM scim_tokens WHERE tenant_id = %s AND issuer = %s "
                "AND revoked_at IS NULL LIMIT 1",
                (tenant_id, issuer),
            )
            is not None
        )

    # --- the MCP door's per-token budget ------------------------------------------

    def spend_mcp_call(
        self, tenant_id: str, token_id: str, window_start, *, ceiling: int
    ) -> int | None:
        # **One statement, and that is the whole point of this table.** The ceiling is
        # in the UPDATE's WHERE, so two replicas arriving at `ceiling - 1` in the same
        # instant produce one admission and one refusal — the row is locked for the
        # duration of the conflicting update, and the loser re-evaluates the predicate
        # against the winner's value. A SELECT followed by an UPDATE would admit both,
        # which is `start_run`'s lesson at a second address.
        #
        # The INSERT arm needs no ceiling test: it can only fire when there is no row,
        # which means nothing has been spent, and `ceiling` is positive by contract (see
        # `Storage.spend_mcp_call` — the caller skips this entirely when the dial is
        # off, so there is no sentinel to interpret here).
        row = self._fetchone(
            """
            INSERT INTO mcp_budget (tenant_id, token_id, window_start, calls)
                 VALUES (%s, %s, %s, 1)
            ON CONFLICT (tenant_id, token_id, window_start) DO UPDATE
                    SET calls = mcp_budget.calls + 1
                  WHERE mcp_budget.calls < %s
              RETURNING calls
            """,
            (tenant_id, token_id, window_start, ceiling),
        )
        # No row means the DO UPDATE's WHERE was false: the ceiling is met, and nothing
        # was written. `ON CONFLICT ... WHERE` that matches nothing is not an error.
        return row[0] if row is not None else None

    def mcp_calls_spent(self, tenant_id: str, token_id: str, window_start) -> int:
        row = self._fetchone(
            "SELECT calls FROM mcp_budget "
            " WHERE tenant_id = %s AND token_id = %s AND window_start = %s",
            (tenant_id, token_id, window_start),
        )
        return row[0] if row is not None else 0

    def mcp_call_windows(
        self,
        tenant_id: str,
        token_id: str,
        *,
        # Quoted, and `date` is imported under `TYPE_CHECKING` above: this file
        # deliberately holds no runtime handle on a clock type.
        since: "date",
        until: "date",
    ) -> list[dict]:
        # Every predicate is a primary-key column, so this is an index range scan and
        # not a table read: `(tenant_id, token_id)` equal, `window_start` bounded. The
        # `ORDER BY` is free for the same reason — it is the key's own order. Measured
        # at 2M rows: five buffers, 0.023 ms. See migration 040 and the base docstring.
        rows = self._fetchall(
            "SELECT window_start, calls FROM mcp_budget "
            " WHERE tenant_id = %s AND token_id = %s "
            "   AND window_start >= %s AND window_start <= %s "
            " ORDER BY window_start",
            (tenant_id, token_id, since, until),
        )
        # An ISO string in both stores, the coercion every reader of a stamped column
        # here applies — psycopg hands back a `date` and the fake holds one as a key.
        return [{"window_start": row[0].isoformat(), "calls": row[1]} for row in rows]

    # --- schedules ----------------------------------------------------------------

    _SCHEDULE_COLUMNS = _child_columns(SCHEDULE_FIELDS, "schedules")

    def create_schedule(self, tenant_id: str, schedule: dict, *, actor: str) -> dict:
        import psycopg

        row = normalize_schedule(schedule)
        self._require_tenant(tenant_id)

        # Built before the transaction opens, matching every other write here. The detail
        # is the cadence and the machine — **never `task`**; see `ADMIN_ACTIONS`.
        record = make_admin_record(
            "schedule.create",
            "schedule",
            row["id"],
            actor,
            {
                "agent": row["agent_name"],
                "cadence": describe_cadence(row["cadence"]),
                "timezone": row["timezone"],
                "fires_as": f"machine:{row['token_id']}",
            },
        )

        try:
            with self._transaction() as cur:
                # Resolved inside the transaction, so the lookup and the insert cannot
                # straddle a commit. The foreign key is still the second layer — an agent
                # deleted between these two statements is refused by the database — and
                # this is the first, because with the id resolved here an absent agent
                # produces no FK violation to discriminate on.
                agent_id = self._agent_id_for(tenant_id, row["agent_name"], cur)
                if agent_id is None:
                    raise ValueRefused(
                        NO_SUCH_AGENT_TO_SCHEDULE.format(
                            tenant=tenant_id, agent=row["agent_name"]
                        )
                    )
                created = cur.execute(
                    f"""
                    INSERT INTO schedules (
                        id, tenant_id, agent_id, token_id, task, cadence, timezone,
                        enabled, next_fire_at, created_by
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING {self._SCHEDULE_COLUMNS}
                    """,
                    (
                        row["id"],
                        tenant_id,
                        agent_id,
                        row["token_id"],
                        row["task"],
                        json.dumps(row["cadence"]),
                        row["timezone"],
                        row["enabled"],
                        row["next_fire_at"],
                        actor,
                    ),
                ).fetchone()
                self._write_admin(cur, tenant_id, record)
                return dict(zip(SCHEDULE_FIELDS, created))
        except StorageError as exc:
            # **Three foreign keys, and two of them are caller errors rather than broken
            # stores.** `_translate` turns every `ForeignKeyViolation` into
            # `UnknownTenantError`, which becomes "storage unavailable" over HTTP — the
            # exact wrong-family refusal 021's edge hunt found for a machine editor, so
            # it is discriminated here on `create_api_token`'s precedent.
            cause = exc.__cause__
            if isinstance(cause, psycopg.errors.ForeignKeyViolation):
                constraint = getattr(getattr(cause, "diag", None), "constraint_name", "")
                if constraint == SCHEDULE_AGENT_FK:
                    raise ValueRefused(
                        NO_SUCH_AGENT_TO_SCHEDULE.format(
                            tenant=tenant_id, agent=row["agent_name"]
                        )
                    ) from exc
                if constraint == SCHEDULE_TOKEN_FK:
                    raise ValueRefused(
                        NO_SUCH_TOKEN_TO_FIRE_AS.format(
                            tenant=tenant_id, token=row["token_id"]
                        )
                    ) from exc
            if isinstance(cause, psycopg.errors.UniqueViolation):
                raise StorageError(
                    f"a schedule with id '{row['id']}' already exists. The id is minted "
                    "rather than chosen, so this is a collision in whatever generated it "
                    "rather than anything a caller did."
                ) from exc
            raise

    def update_schedule(
        self,
        tenant_id: str,
        schedule_id: str,
        changes: dict,
        *,
        actor: str,
        if_unchanged_since,
    ) -> dict | None:
        import psycopg

        moved = normalize_schedule_changes(changes)

        # The record needs the row as it stands to name the agent, and it must be built
        # from a read that cannot straddle the write — so unlike `create_schedule` this
        # one opens the transaction first. The read is not the race: the guard is
        # `AND updated_at = %s` in the single UPDATE below.
        try:
            with self._transaction() as cur:
                before = cur.execute(
                    f"SELECT {self._SCHEDULE_COLUMNS} FROM schedules "
                    "WHERE tenant_id = %s AND id = %s",
                    (tenant_id, schedule_id),
                ).fetchone()
                if before is None:
                    return None

                # **One pass, so the clause and the parameters cannot disagree.** Built
                # separately they aligned only because dicts preserve insertion order and
                # `moved` was iterated twice — true today and a trap for whoever adds a
                # filter to one of the two comprehensions.
                #
                # The column names are interpolated rather than parameterised, which SQL
                # does not allow for identifiers — so the safety is entirely
                # `normalize_schedule_changes` refusing every key outside
                # `SCHEDULE_PATCH_FIELDS` before this line is reached. That is asserted
                # by a test rather than trusted, because this comment is the only other
                # thing holding it.
                assignments, values = [], []
                for key, value in moved.items():
                    assignments.append(f"{key} = %s")
                    values.append(json.dumps(value) if key == "cadence" else value)
                assignments = ", ".join(assignments)
                row = cur.execute(
                    f"""
                    UPDATE schedules
                       SET {assignments}, updated_at = now()
                     WHERE tenant_id = %s AND id = %s AND updated_at = %s
                    RETURNING {self._SCHEDULE_COLUMNS}
                    """,
                    (*values, tenant_id, schedule_id, if_unchanged_since),
                ).fetchone()

                # Somebody else got here first. No record, on `update_agent`'s rule and
                # `revoke_api_token`'s before it: the log holds changes rather than
                # attempts. Told apart from a deleted row above this layer, where a second
                # read is a report rather than a window.
                if row is None:
                    return None

                self._write_admin(
                    cur,
                    tenant_id,
                    make_admin_record(
                        "schedule.update",
                        "schedule",
                        schedule_id,
                        actor,
                        schedule_update_detail(
                            dict(zip(SCHEDULE_FIELDS, before)), moved
                        ),
                    ),
                )
                return dict(zip(SCHEDULE_FIELDS, row))
        except StorageError as exc:
            # `create_schedule`'s discrimination at the one foreign key a patch can
            # violate. Without it `_translate` turns the violation into
            # `UnknownTenantError` and a retarget at a token that does not exist answers
            # "storage unavailable" about a request that will never work — the exact
            # wrong-family refusal that has now been found and fixed six times.
            cause = exc.__cause__
            if isinstance(cause, psycopg.errors.ForeignKeyViolation):
                constraint = getattr(getattr(cause, "diag", None), "constraint_name", "")
                if constraint == SCHEDULE_TOKEN_FK:
                    raise ValueRefused(
                        NO_SUCH_TOKEN_TO_FIRE_AS.format(
                            tenant=tenant_id, token=moved.get("token_id", "")
                        )
                    ) from exc
            raise

    def runs_of_schedule(
        self, tenant_id: str, schedule_id: str, *, limit: int = 50
    ) -> list[dict]:
        check_version_limit(limit)

        # `LIKE` with the prefix escaped, because a schedule id is ours and opaque but
        # the escape is what makes that a fact about today's minting rather than a
        # promise this query depends on. `ORDER BY seq DESC` is `list_runs`' order and
        # for its reason: runs inside one clock tick share a `created_at`.
        rows = self._fetchall(
            f"""
            SELECT {self._RUN_COLUMNS} FROM runs
             WHERE tenant_id = %s AND idempotency_key LIKE %s ESCAPE '\\'
             ORDER BY seq DESC
             LIMIT %s
            """,
            (
                tenant_id,
                schedule_key_prefix(schedule_id)
                .replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_")
                + "%",
                limit,
            ),
        )
        return [dict(zip(RUN_FIELDS, row)) for row in rows]

    def get_schedule(self, tenant_id: str, schedule_id: str) -> dict | None:
        row = self._fetchone(
            f"SELECT {self._SCHEDULE_COLUMNS} FROM schedules "
            "WHERE tenant_id = %s AND id = %s",
            (tenant_id, schedule_id),
        )
        return dict(zip(SCHEDULE_FIELDS, row)) if row is not None else None

    def list_schedules(self, tenant_id: str, *, agent_name: str = "") -> list[dict]:
        # The filter is on the id, resolved from the name the caller passed. An absent
        # agent has no schedules, which is the same answer the old `agent_name = %s`
        # predicate gave and reached without a second read.
        clause = ""
        params = (tenant_id,)
        if agent_name:
            agent_id = self._agent_id_for(tenant_id, agent_name)
            if agent_id is None:
                return []
            clause = " AND agent_id = %s"
            params = (tenant_id, agent_id)
        # `ORDER BY agent_name` sorts on the output column — the derived name, not a
        # column — which Postgres allows and which keeps the listing ordered the way a
        # person reads it rather than by an opaque id.
        rows = self._fetchall(
            f"SELECT {self._SCHEDULE_COLUMNS} FROM schedules WHERE tenant_id = %s"
            f"{clause} ORDER BY agent_name, id",
            params,
        )
        return [dict(zip(SCHEDULE_FIELDS, row)) for row in rows]

    def due_schedules(self, *, now=None, limit: int = 100, limit_to_tenant=None):
        check_version_limit(limit)
        clause = " AND tenant_id = %s" if limit_to_tenant else ""
        # `now()` rather than Python's clock when the caller does not supply one, which
        # is better than the import this originally wanted: the comparison then happens
        # against the database's own clock, on the same connection as the read, so a
        # worker whose host clock has drifted cannot decide what is due. Every caller in
        # the product passes `now` explicitly — `fire_due` does — so this is the default
        # for a direct caller, and it used to be a `NameError` because `datetime` is not
        # imported in this module and no test ever took the branch.
        params = [now] if now is not None else []
        moment = "%s" if now is not None else "now()"
        if limit_to_tenant:
            params.append(limit_to_tenant)
        params.append(limit)
        rows = self._fetchall(
            f"SELECT {self._SCHEDULE_COLUMNS} FROM schedules "
            f"WHERE enabled AND next_fire_at <= {moment}{clause} "
            "ORDER BY next_fire_at LIMIT %s",
            tuple(params),
        )
        return [dict(zip(SCHEDULE_FIELDS, row)) for row in rows]

    def advance_schedule(
        self,
        tenant_id: str,
        schedule_id: str,
        *,
        if_next_fire_at,
        next_fire_at,
        last_run_id: str = "",
        last_outcome: str = "",
        fired: bool = True,
    ) -> dict | None:
        # Checked here as well as in the fake, so the two agree about a naive instant
        # rather than one coercing it and the other storing it. See `check_next_fire_at`.
        check_next_fire_at(next_fire_at)
        check_next_fire_at(if_next_fire_at, what="if_next_fire_at")
        check_outcome(last_run_id, last_outcome)

        # **One statement, and `AND next_fire_at = %s` is the whole method** —
        # `update_agent`'s compare-and-set at a different address, and here it is what
        # makes a due schedule advance exactly once however many workers saw it due.
        # There is no window inside a single UPDATE.
        row = self._fetchone(
            f"""
            UPDATE schedules
               SET next_fire_at = %s,
                   last_fired_at = CASE WHEN %s THEN now() ELSE last_fired_at END,
                   last_run_id = %s,
                   last_outcome = %s,
                   updated_at = now()
             WHERE tenant_id = %s AND id = %s AND next_fire_at = %s
            RETURNING {self._SCHEDULE_COLUMNS}
            """,
            (
                next_fire_at,
                fired,
                last_run_id,
                last_outcome,
                tenant_id,
                schedule_id,
                if_next_fire_at,
            ),
        )
        return dict(zip(SCHEDULE_FIELDS, row)) if row is not None else None

    def set_schedule_enabled(
        self, tenant_id: str, schedule_id: str, enabled: bool, *, next_fire_at, actor: str
    ) -> dict | None:
        check_next_fire_at(next_fire_at)
        record = make_admin_record(
            "schedule.enable" if enabled else "schedule.disable",
            "schedule",
            schedule_id,
            actor,
        )

        with self._transaction() as cur:
            # `AND enabled <> %s` gives the idempotence: setting the state it already
            # holds matches nothing, so no record is written — `revoke_api_token`'s rule
            # that the log holds changes rather than attempts.
            row = cur.execute(
                f"""
                UPDATE schedules
                   SET enabled = %s, next_fire_at = %s, updated_at = now()
                 WHERE tenant_id = %s AND id = %s AND enabled <> %s
                RETURNING {self._SCHEDULE_COLUMNS}
                """,
                (enabled, next_fire_at, tenant_id, schedule_id, enabled),
            ).fetchone()

            if row is None:
                existing = cur.execute(
                    f"SELECT {self._SCHEDULE_COLUMNS} FROM schedules "
                    "WHERE tenant_id = %s AND id = %s",
                    (tenant_id, schedule_id),
                ).fetchone()
                return dict(zip(SCHEDULE_FIELDS, existing)) if existing else None

            self._write_admin(cur, tenant_id, record)
            return dict(zip(SCHEDULE_FIELDS, row))

    def delete_schedule(self, tenant_id: str, schedule_id: str, *, actor: str) -> bool:
        record = make_admin_record("schedule.delete", "schedule", schedule_id, actor)

        with self._transaction() as cur:
            gone = cur.execute(
                "DELETE FROM schedules WHERE tenant_id = %s AND id = %s RETURNING id",
                (tenant_id, schedule_id),
            ).fetchone()
            if gone is None:
                return False
            self._write_admin(cur, tenant_id, record)
            return True

    # --- event triggers ---------------------------------------------------------

    _TRIGGER_COLUMNS = _child_columns(TRIGGER_FIELDS, "triggers")

    def create_trigger(self, tenant_id: str, trigger: dict, *, actor: str) -> dict:
        import psycopg

        row = normalize_trigger(trigger)
        self._require_tenant(tenant_id)

        # The detail is the agent, the trigger's name and the machine — **never `task`,
        # never any form of the secret**; see `ADMIN_ACTIONS`. The name is safe where
        # the task is not: it is a label a person chose for a list, not content.
        record = make_admin_record(
            "trigger.create",
            "trigger",
            row["id"],
            actor,
            {
                "agent": row["agent_name"],
                "name": row["name"],
                "fires_as": f"machine:{row['token_id']}",
            },
        )

        try:
            with self._transaction() as cur:
                # `create_schedule`'s resolution, for its reason — see the comment there.
                agent_id = self._agent_id_for(tenant_id, row["agent_name"], cur)
                if agent_id is None:
                    raise ValueRefused(
                        NO_SUCH_AGENT_TO_TRIGGER.format(
                            tenant=tenant_id, agent=row["agent_name"]
                        )
                    )
                created = cur.execute(
                    f"""
                    INSERT INTO triggers (
                        id, tenant_id, agent_id, token_id, name, task,
                        secret_sealed, secret_key_id, enabled, created_by
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING {self._TRIGGER_COLUMNS}
                    """,
                    (
                        row["id"],
                        tenant_id,
                        agent_id,
                        row["token_id"],
                        row["name"],
                        row["task"],
                        row["secret_sealed"],
                        row["secret_key_id"],
                        row["enabled"],
                        actor,
                    ),
                ).fetchone()
                self._write_admin(cur, tenant_id, record)
                return self._trigger_row(created)
        except StorageError as exc:
            # `create_schedule`'s discrimination at the next table, same reasoning: two
            # of the three foreign keys are caller errors, and `_translate`'s blanket
            # `UnknownTenantError` would answer them "storage unavailable".
            cause = exc.__cause__
            if isinstance(cause, psycopg.errors.ForeignKeyViolation):
                constraint = getattr(getattr(cause, "diag", None), "constraint_name", "")
                if constraint == TRIGGER_AGENT_FK:
                    raise ValueRefused(
                        NO_SUCH_AGENT_TO_TRIGGER.format(
                            tenant=tenant_id, agent=row["agent_name"]
                        )
                    ) from exc
                if constraint == TRIGGER_TOKEN_FK:
                    raise ValueRefused(
                        NO_SUCH_TOKEN_TO_TRIGGER.format(
                            tenant=tenant_id, token=row["token_id"]
                        )
                    ) from exc
            if isinstance(cause, psycopg.errors.UniqueViolation):
                raise StorageError(
                    f"a trigger with id '{row['id']}' already exists. The id is minted "
                    "rather than chosen, so this is a collision in whatever generated "
                    "it rather than anything a caller did."
                ) from exc
            raise

    def _trigger_row(self, row) -> dict:
        """A tuple into a `TRIGGER_FIELDS` dict, with the sealed blob as `bytes`.

        psycopg returns BYTEA as `memoryview`, which compares unequal to the `bytes`
        the in-memory store returns and cannot be handed back to `crypto.open_`'s
        slicing without a copy anyway. One conversion here rather than at every reader.
        """
        record = dict(zip(TRIGGER_FIELDS, row))
        record["secret_sealed"] = bytes(record["secret_sealed"])
        return record

    def get_trigger(self, tenant_id: str, trigger_id: str) -> dict | None:
        row = self._fetchone(
            f"SELECT {self._TRIGGER_COLUMNS} FROM triggers "
            "WHERE tenant_id = %s AND id = %s",
            (tenant_id, trigger_id),
        )
        return self._trigger_row(row) if row is not None else None

    def find_trigger(self, trigger_id: str) -> dict | None:
        row = self._fetchone(
            f"SELECT {self._TRIGGER_COLUMNS} FROM triggers WHERE id = %s",
            (trigger_id,),
        )
        return self._trigger_row(row) if row is not None else None

    def list_triggers(self, tenant_id: str, *, agent_name: str = "") -> list[dict]:
        # `list_schedules`' shape, for its reasons.
        clause = ""
        params = (tenant_id,)
        if agent_name:
            agent_id = self._agent_id_for(tenant_id, agent_name)
            if agent_id is None:
                return []
            clause = " AND agent_id = %s"
            params = (tenant_id, agent_id)
        rows = self._fetchall(
            f"SELECT {self._TRIGGER_COLUMNS} FROM triggers WHERE tenant_id = %s"
            f"{clause} ORDER BY agent_name, id",
            params,
        )
        return [self._trigger_row(row) for row in rows]

    def record_trigger_delivery(
        self, tenant_id: str, trigger_id: str, *, last_run_id: str, last_outcome: str
    ) -> None:
        # `check_outcome` for 021 defect 8's reason: the outcome is `str(exc)` of
        # whatever refused, and a NUL byte a dict holds happily is a 503 from TEXT.
        check_outcome(last_run_id, last_outcome)
        self._execute(
            """
            UPDATE triggers
               SET last_delivery_at = now(), last_run_id = %s, last_outcome = %s,
                   updated_at = now()
             WHERE tenant_id = %s AND id = %s
            """,
            (last_run_id, last_outcome, tenant_id, trigger_id),
        )

    def rotate_trigger_secret(
        self,
        tenant_id: str,
        trigger_id: str,
        *,
        secret_sealed,
        secret_key_id: str,
        actor: str,
    ) -> dict | None:
        # The second writer of this column, and the reason the guard became a function:
        # a rotation does not go through `normalize_trigger`, so without this the rule
        # would be one function away from the write it guards.
        check_sealed_secret(secret_sealed)

        with self._transaction() as cur:
            row = cur.execute(
                f"""
                UPDATE triggers
                   SET secret_sealed = %s, secret_key_id = %s, updated_at = now()
                 WHERE tenant_id = %s AND id = %s
                RETURNING {self._TRIGGER_COLUMNS}
                """,
                (bytes(secret_sealed), secret_key_id, tenant_id, trigger_id),
            ).fetchone()

            if row is None:
                return None

            # **Not idempotent, and there is no `AND` to make it so.** Enable and disable
            # carry one because setting the state a row already holds is not a change; a
            # rotation always produces a new secret, so every call is a change and every
            # call is recorded. Built from the returned row so the record's agent name
            # comes from the same statement that wrote.
            out = self._trigger_row(row)
            self._write_admin(
                cur,
                tenant_id,
                make_admin_record(
                    "trigger.rotate",
                    "trigger",
                    trigger_id,
                    actor,
                    {"agent": out["agent_name"], "name": out["name"]},
                ),
            )
            return out

    def set_trigger_enabled(
        self, tenant_id: str, trigger_id: str, enabled: bool, *, actor: str
    ) -> dict | None:
        record = make_admin_record(
            "trigger.enable" if enabled else "trigger.disable",
            "trigger",
            trigger_id,
            actor,
        )

        with self._transaction() as cur:
            # `AND enabled <> %s` gives the idempotence — `set_schedule_enabled`'s
            # device, and the log's changes-not-attempts rule with it.
            row = cur.execute(
                f"""
                UPDATE triggers
                   SET enabled = %s, updated_at = now()
                 WHERE tenant_id = %s AND id = %s AND enabled <> %s
                RETURNING {self._TRIGGER_COLUMNS}
                """,
                (enabled, tenant_id, trigger_id, enabled),
            ).fetchone()

            if row is None:
                existing = cur.execute(
                    f"SELECT {self._TRIGGER_COLUMNS} FROM triggers "
                    "WHERE tenant_id = %s AND id = %s",
                    (tenant_id, trigger_id),
                ).fetchone()
                return self._trigger_row(existing) if existing else None

            self._write_admin(cur, tenant_id, record)
            return self._trigger_row(row)

    def delete_trigger(self, tenant_id: str, trigger_id: str, *, actor: str) -> bool:
        record = make_admin_record("trigger.delete", "trigger", trigger_id, actor)

        with self._transaction() as cur:
            gone = cur.execute(
                "DELETE FROM triggers WHERE tenant_id = %s AND id = %s RETURNING id",
                (tenant_id, trigger_id),
            ).fetchone()
            if gone is None:
                return False
            self._write_admin(cur, tenant_id, record)
            return True

    # --- agent grants -----------------------------------------------------------

    _GRANT_COLUMNS = GRANT_FIELDS

    # The membership half of every resolving lookup, written once. Inlined into a
    # statement rather than run as its own query: decision 7 of step 9a is that the
    # permission check stays ONE round trip, and this is the half that would otherwise
    # be the second.
    _VIA_GROUP = """
        grantee_kind = 'group' AND grantee_id IN (
            SELECT group_id FROM group_members
             WHERE tenant_id = %s AND principal_kind = %s AND principal_id = %s
        )
    """

    # Migration 035's name→id translation, **inlined for the same reason `_VIA_GROUP` is
    # inlined**. `agent_grant_role` runs before every run and `granted_agent_names` behind
    # every list view; resolving the name with `_agent_id_for` first would make each of them
    # two round trips where step 9a decision 7 says one. Postgres answers this from
    # `agents_name_unique`, inside the same plan.
    #
    # Takes two parameters — the tenant and the name — wherever it appears.
    _AGENT_BY_NAME = "(SELECT agent_id FROM agents WHERE tenant_id = %s AND name = %s)"

    def grant_agent(
        self,
        tenant_id: str,
        agent_name: str,
        grantee_kind: str,
        grantee_id: str,
        role: str = "user",
        granted_by: str = "",
        *,
        actor: str,
    ) -> None:
        import psycopg

        # `agent_grants_grantee_kind_check` and `agent_grants_no_group_owner`, in Python,
        # so the person sharing something reads a sentence instead of a constraint name.
        check_grant(grantee_kind, role)

        if grantee_kind == "group" and self.get_group(tenant_id, grantee_id) is None:
            # Not a foreign key, because `grantee_id` names a different table depending
            # on the column beside it. See migration 017.
            raise NoSuchGroupError(
                NO_SUCH_GROUP.format(group=grantee_id, tenant=tenant_id)
            )

        # `actor`, not `granted_by`. They carry the same string at every caller today
        # and they are not the same field: `granted_by` is a column, free text, and
        # migration 011 filled it with 'migration:011' for every agent it adopted.
        # `admin_audit.actor_kind` has a CHECK. See `grant_agent` in base.py.
        record = make_admin_record(
            "grant.create",
            "agent",
            agent_name,
            actor,
            {"grantee_kind": grantee_kind, "grantee_id": grantee_id, "role": role},
        )

        try:
            with self._transaction() as cur:
                # Resolved rather than left to the foreign key, since migration 035 — the
                # same shape `create_schedule` uses, and the same reason: with the id
                # resolved here an absent agent produces no FK violation to discriminate
                # on. The key still guards a concurrent delete.
                agent_id = self._agent_id_for(tenant_id, agent_name, cur)
                if agent_id is None:
                    raise StorageError(
                        f"no agent named '{agent_name}' in tenant '{tenant_id}'"
                    )
                cur.execute(
                    """
                    INSERT INTO agent_grants (
                        tenant_id, agent_id, grantee_kind, grantee_id, role, granted_by
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_id, agent_id, grantee_kind, grantee_id)
                    DO UPDATE SET role = EXCLUDED.role,
                                  granted_by = EXCLUDED.granted_by,
                                  granted_at = now()
                    """,
                    (tenant_id, agent_id, grantee_kind, grantee_id, role, granted_by),
                )
                self._write_admin(cur, tenant_id, record)
        except StorageError as exc:
            cause = exc.__cause__
            # The FK to agents. Reported as "no such agent" rather than as a
            # constraint name, because the person reading this is granting access. Reachable
            # only through a concurrent delete now that the resolution above runs first.
            if isinstance(cause, psycopg.errors.ForeignKeyViolation):
                raise StorageError(
                    f"no agent named '{agent_name}' in tenant '{tenant_id}'"
                ) from exc
            # The partial unique index from migration 011. Same sentence the in-memory
            # store raises, because the contract suite compares them.
            if isinstance(cause, psycopg.errors.UniqueViolation):
                raise StorageError(OWNER_TAKEN.format(agent=agent_name)) from exc
            raise

    def revoke_agent(
        self,
        tenant_id: str,
        agent_name: str,
        grantee_kind: str,
        grantee_id: str,
        *,
        actor: str,
    ) -> None:
        with self._transaction() as cur:
            # **`RETURNING role` is the step.** `agent_grants.granted_by` records who
            # granted access and is destroyed by the revocation it should have recorded,
            # so the level Sam actually lost exists for exactly the length of this
            # statement — and this is the only place it is ever written down.
            removed = cur.execute(
                f"DELETE FROM agent_grants WHERE tenant_id = %s "
                f"AND agent_id = {self._AGENT_BY_NAME} "
                "AND grantee_kind = %s AND grantee_id = %s "
                "RETURNING role, granted_by",
                (tenant_id, tenant_id, agent_name, grantee_kind, grantee_id),
            ).fetchone()

            if removed is None:
                # Idempotent, and no record: revoking a grant nobody had changed nothing.
                return

            self._write_admin(
                cur,
                tenant_id,
                make_admin_record(
                    "grant.revoke",
                    "agent",
                    agent_name,
                    actor,
                    {
                        "grantee_kind": grantee_kind,
                        "grantee_id": grantee_id,
                        "role": removed[0],
                        "granted_by": removed[1],
                    },
                ),
            )

    def transfer_agent_ownership(
        self,
        tenant_id: str,
        agent_name: str,
        principal_kind: str,
        principal_id: str,
        granted_by: str = "",
        *,
        actor: str,
    ) -> None:
        import psycopg

        check_principal_kind(principal_kind)

        try:
            # One transaction, and the order inside it is forced: the partial unique
            # index permits a single owner, so the incumbent has to step down before the
            # successor steps up. Between those two statements the agent has no owner,
            # which is exactly why nobody may observe the gap.
            with self._transaction() as cur:
                # `RETURNING` on the demote, which costs nothing and is the only place
                # the outgoing owner is named. A transfer changes two people's access at
                # once, and a record naming only the recipient would leave the demotion
                # unattributed — the same half-a-record this whole step is about.
                agent_id = self._agent_id_for(tenant_id, agent_name, cur)
                if agent_id is None:
                    raise StorageError(
                        f"no agent named '{agent_name}' in tenant '{tenant_id}'"
                    )
                demoted = cur.execute(
                    "UPDATE agent_grants SET role = 'editor' "
                    "WHERE tenant_id = %s AND agent_id = %s AND role = 'owner' "
                    "AND NOT (grantee_kind = %s AND grantee_id = %s) "
                    "RETURNING grantee_kind, grantee_id",
                    (tenant_id, agent_id, principal_kind, principal_id),
                ).fetchone()
                cur.execute(
                    """
                    INSERT INTO agent_grants (
                        tenant_id, agent_id, grantee_kind, grantee_id,
                        role, granted_by
                    ) VALUES (%s, %s, %s, %s, 'owner', %s)
                    ON CONFLICT (tenant_id, agent_id, grantee_kind, grantee_id)
                    DO UPDATE SET role = 'owner',
                                  granted_by = EXCLUDED.granted_by,
                                  granted_at = now()
                    """,
                    (tenant_id, agent_id, principal_kind, principal_id, granted_by),
                )
                self._write_admin(
                    cur,
                    tenant_id,
                    make_admin_record(
                        "grant.transfer",
                        "agent",
                        agent_name,
                        actor,
                        {
                            "to_kind": principal_kind,
                            "to_id": principal_id,
                            "from_kind": demoted[0] if demoted else None,
                            "from_id": demoted[1] if demoted else None,
                            "from_role": "editor" if demoted else None,
                        },
                    ),
                )
        except StorageError as exc:
            cause = exc.__cause__
            if isinstance(cause, psycopg.errors.ForeignKeyViolation):
                raise StorageError(
                    f"no agent named '{agent_name}' in tenant '{tenant_id}'"
                ) from exc
            if isinstance(cause, psycopg.errors.UniqueViolation):
                # Two transfers of one agent at once. The demote in this transaction
                # cannot see an owner another transaction installed after this statement
                # began, so the promote lands on a taken index â€” measured at eight
                # concurrent transfers: three commit, five arrive here, and there is
                # exactly one owner afterwards.
                #
                # Translated because the raw text names a constraint, which reads as the
                # server breaking rather than as somebody else having got there first.
                # The invariant held; only the message was wrong.
                raise StorageError(
                    f"ownership of '{agent_name}' changed while this transfer was in "
                    "flight. Nothing was applied â€” look at who owns it now and retry."
                ) from exc
            raise

    def agent_grant_role(
        self, tenant_id: str, agent_name: str, principal_kind: str, principal_id: str
    ) -> str | None:
        """The highest role this principal reaches, directly or through a group.

        **One statement**, which is decision 7 of step 9a and a requirement rather than a
        preference: this runs before every run and behind every list view.

        `array_position` supplies the ladder, and the ladder is passed in rather than
        written into the SQL. Ordering by `role` itself would be alphabetical â€”
        `editor` < `owner` < `user` â€” which is the ladder upside down and would silently
        return `user` for somebody who owns the agent. `AGENT_ROLES` stays the one place
        the order is stated.
        """
        row = self._fetchone(
            f"""
            SELECT role FROM agent_grants
             WHERE tenant_id = %s AND agent_id = {self._AGENT_BY_NAME}
               AND ( (grantee_kind = %s AND grantee_id = %s) OR ({self._VIA_GROUP}) )
             ORDER BY array_position(%s::text[], role) DESC
             LIMIT 1
            """,
            (
                tenant_id,
                tenant_id,
                agent_name,
                principal_kind,
                principal_id,
                tenant_id,
                principal_kind,
                principal_id,
                list(AGENT_ROLES),
            ),
        )
        return None if row is None else row[0]

    def direct_agent_grant_role(
        self, tenant_id: str, agent_name: str, grantee_kind: str, grantee_id: str
    ) -> str | None:
        row = self._fetchone(
            f"SELECT role FROM agent_grants WHERE tenant_id = %s "
            f"AND agent_id = {self._AGENT_BY_NAME} "
            "AND grantee_kind = %s AND grantee_id = %s",
            (tenant_id, tenant_id, agent_name, grantee_kind, grantee_id),
        )
        return None if row is None else row[0]

    def granted_agent_names(
        self, tenant_id: str, principal_kind: str, principal_id: str
    ) -> list[str]:
        """One statement, for the reason `agent_grant_role` is one.

        `DISTINCT` because a person may hold a grant on an agent directly *and* through a
        group, which is not an error and must not produce the agent twice in a list view.

        **A join since migration 035**, because the names live one table over now. Still one
        round trip, and the join is on `agents_pkey` — and it buys something the old column
        could not: what comes back is what each agent is called *now*, so a rename shows up
        in every caller's list view with nothing to invalidate.
        """
        return [
            row[0]
            for row in self._fetchall(
                f"""
                SELECT DISTINCT a.name FROM agent_grants
                  JOIN agents a
                    ON a.tenant_id = agent_grants.tenant_id
                   AND a.agent_id = agent_grants.agent_id
                 WHERE agent_grants.tenant_id = %s
                   AND ( (grantee_kind = %s AND grantee_id = %s)
                         OR ({self._VIA_GROUP}) )
                 ORDER BY a.name
                """,
                (
                    tenant_id,
                    principal_kind,
                    principal_id,
                    tenant_id,
                    principal_kind,
                    principal_id,
                ),
            )
        ]

    def groups_granting_agent(
        self, tenant_id: str, agent_name: str, principal_kind: str, principal_id: str
    ) -> list[str]:
        return [
            row[0]
            for row in self._fetchall(
                f"""
                SELECT grantee_id FROM agent_grants
                 WHERE tenant_id = %s AND agent_id = {self._AGENT_BY_NAME}
                   AND ({self._VIA_GROUP})
                 ORDER BY grantee_id
                """,
                (
                    tenant_id,
                    tenant_id,
                    agent_name,
                    tenant_id,
                    principal_kind,
                    principal_id,
                ),
            )
        ]

    def list_agent_grants(self, tenant_id: str, agent_name: str) -> list[dict]:
        columns = _child_columns(self._GRANT_COLUMNS, "agent_grants")
        return [
            dict(zip(self._GRANT_COLUMNS, row))
            for row in self._fetchall(
                f"SELECT {columns} FROM agent_grants WHERE tenant_id = %s "
                f"AND agent_id = {self._AGENT_BY_NAME} "
                "ORDER BY grantee_kind, grantee_id",
                (tenant_id, tenant_id, agent_name),
            )
        ]

    # --- groups -------------------------------------------------------------------

    _GROUP_COLUMNS = GROUP_FIELDS
    _MEMBER_COLUMNS = GROUP_MEMBER_FIELDS

    def create_group(
        self,
        tenant_id: str,
        group_id: str,
        name: str,
        description: str = "",
        external_id: str | None = None,
        created_by: str = "",
        *,
        actor: str,
    ) -> dict:
        import psycopg

        if not group_id or not name:
            raise StorageError("a group needs an id and a name")

        external_id = normalize_external_id(external_id)

        record = make_admin_record(
            "group.create",
            "group",
            group_id,
            actor,
            {"name": name, "external_id": external_id},
        )

        columns = ", ".join(self._GROUP_COLUMNS)
        try:
            with self._transaction() as cur:
                row = cur.execute(
                    f"""
                    INSERT INTO groups (
                        tenant_id, group_id, name, description, external_id, created_by
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING {columns}
                    """,
                    (tenant_id, group_id, name, description, external_id, created_by),
                ).fetchone()
                self._write_admin(cur, tenant_id, record)

                # Step 033e. A group that arrives already linked changes what a
                # reconciliation would produce for everybody in this tenant, so the
                # markers go in the same transaction as the row.
                if external_id is not None:
                    self._forget_directory_digests(cur, tenant_id)
        except StorageError as exc:
            cause = exc.__cause__
            if isinstance(cause, psycopg.errors.UniqueViolation):
                # Translated because the raw text names a constraint, and the person
                # reading it typed a group name — **or a directory id**, which is why
                # this asks which one collided instead of assuming. It used to assume,
                # safely, because a second `external_id` was unreachable until
                # `set_group_external_id` existed; 033e is what made the wrong sentence
                # possible.
                raise StorageError(
                    self._group_collision(tenant_id, name, external_id, cause, group_id)
                ) from exc
            if isinstance(cause, psycopg.errors.ForeignKeyViolation):
                raise StorageError(f"no tenant '{tenant_id}'") from exc
            raise

        return dict(zip(self._GROUP_COLUMNS, row))

    @staticmethod
    def _group_collision(
        tenant_id: str, name: str, external_id: str | None, cause, group_id: str = ""
    ) -> str:
        """Which uniqueness on `groups` was violated, in the sentence for that column.

        Postgres names the constraint in `diag.constraint_name` and both are
        auto-named by column, so the tell is the constraint rather than a second query
        — and the fallback is the name sentence, which is what every collision meant
        before 033e.
        """
        constraint = getattr(getattr(cause, "diag", None), "constraint_name", "") or ""
        if external_id is not None and "external_id" in constraint:
            return GROUP_LINK_TAKEN.format(tenant=tenant_id, external_id=external_id)
        if "pkey" in constraint:
            # A recycled `g_<hex>`, or an id somebody supplied by hand through the
            # storage API. Rare to the point of never, and it used to be reported as a
            # name collision about a name that is very likely free — the memory store
            # has always said the true thing here.
            return f"group '{group_id}' already exists in tenant '{tenant_id}'"
        return GROUP_NAME_TAKEN.format(tenant=tenant_id, name=name)

    def set_group_external_id(
        self, tenant_id: str, group_id: str, external_id: str | None, *, actor: str
    ) -> dict:
        import psycopg

        external_id = normalize_external_id(external_id)

        record = make_admin_record(
            "group.link", "group", group_id, actor, {"external_id": external_id}
        )

        columns = ", ".join(self._GROUP_COLUMNS)
        try:
            with self._transaction() as cur:
                # `IS DISTINCT FROM` rather than an unconditional UPDATE: re-linking a
                # group to the id it already holds changed nothing, and a write that
                # changed nothing writes no record — `add_group_member`'s rule, which
                # matters more here than there, because clearing the tenant's markers
                # would make every person in it reconcile again for a no-op. A
                # provisioning script that re-runs is the ordinary way this happens.
                row = cur.execute(
                    f"""
                    UPDATE groups SET external_id = %s
                     WHERE tenant_id = %s AND group_id = %s
                       AND external_id IS DISTINCT FROM %s
                     RETURNING {columns}
                    """,
                    (external_id, tenant_id, group_id, external_id),
                ).fetchone()

                if row is None:
                    # Either there is no such group, or it already says this. The read
                    # tells them apart, inside the same transaction.
                    unchanged = cur.execute(
                        f"SELECT {columns} FROM groups "
                        "WHERE tenant_id = %s AND group_id = %s",
                        (tenant_id, group_id),
                    ).fetchone()
                    if unchanged is None:
                        raise NoSuchGroupError(
                            NO_SUCH_GROUP.format(group=group_id, tenant=tenant_id)
                        )
                    return dict(zip(self._GROUP_COLUMNS, unchanged))

                self._write_admin(cur, tenant_id, record)

                # Linking changes what a reconciliation would produce; unlinking does
                # not, because nobody is removed and the membership simply stops being
                # the directory's. See `_forget_directory_digests`.
                if external_id is not None:
                    self._forget_directory_digests(cur, tenant_id)
        except StorageError as exc:
            if isinstance(exc.__cause__, psycopg.errors.UniqueViolation):
                # The name is not being written here, so there is exactly one
                # uniqueness this statement can violate and no need to ask which.
                raise StorageError(
                    GROUP_LINK_TAKEN.format(tenant=tenant_id, external_id=external_id)
                ) from exc
            raise

        return dict(zip(self._GROUP_COLUMNS, row))

    def rename_group(
        self, tenant_id: str, group_id: str, name: str, *, actor: str
    ) -> dict | None:
        import psycopg

        if not name or not name.strip():
            raise StorageError("a group needs a name; a rename to nothing is refused")
        name = name.strip()
        split_actor(actor)

        columns = ", ".join(self._GROUP_COLUMNS)
        try:
            with self._transaction() as cur:
                # Read under a row lock so `from` in the record is the name this
                # transaction replaces, and `name <> %s` below is decided against it.
                existing = cur.execute(
                    f"SELECT {columns} FROM groups "
                    "WHERE tenant_id = %s AND group_id = %s FOR UPDATE",
                    (tenant_id, group_id),
                ).fetchone()
                if existing is None:
                    return None
                current = dict(zip(self._GROUP_COLUMNS, existing))
                if current["name"] == name:
                    return current

                record = make_admin_record(
                    "group.rename",
                    "group",
                    group_id,
                    actor,
                    {"from": current["name"], "to": name},
                )
                row = cur.execute(
                    f"""
                    UPDATE groups SET name = %s
                     WHERE tenant_id = %s AND group_id = %s
                    RETURNING {columns}
                    """,
                    (name, tenant_id, group_id),
                ).fetchone()
                self._write_admin(cur, tenant_id, record)
                return dict(zip(self._GROUP_COLUMNS, row))
        except StorageError as exc:
            if isinstance(exc.__cause__, psycopg.errors.UniqueViolation):
                # Only the name is written here, so the one uniqueness this can
                # violate is `(tenant_id, name)`; read the holder back for the
                # sentence, as the memory store has it in hand.
                other = self._fetchone(
                    "SELECT group_id FROM groups WHERE tenant_id = %s AND name = %s",
                    (tenant_id, name),
                )
                raise StorageError(
                    GROUP_RENAME_TAKEN.format(
                        tenant=tenant_id, name=name, other=other[0] if other else "?"
                    )
                ) from exc
            raise

    def get_group(self, tenant_id: str, group_id: str) -> dict | None:
        columns = ", ".join(self._GROUP_COLUMNS)
        row = self._fetchone(
            f"SELECT {columns} FROM groups WHERE tenant_id = %s AND group_id = %s",
            (tenant_id, group_id),
        )
        return None if row is None else dict(zip(self._GROUP_COLUMNS, row))

    def find_group_by_name(self, tenant_id: str, name: str) -> dict | None:
        columns = ", ".join(self._GROUP_COLUMNS)
        row = self._fetchone(
            f"SELECT {columns} FROM groups WHERE tenant_id = %s AND name = %s",
            (tenant_id, name),
        )
        return None if row is None else dict(zip(self._GROUP_COLUMNS, row))

    def list_groups(self, tenant_id: str) -> list[dict]:
        columns = ", ".join(self._GROUP_COLUMNS)
        return [
            dict(zip(self._GROUP_COLUMNS, row))
            for row in self._fetchall(
                f"SELECT {columns} FROM groups WHERE tenant_id = %s ORDER BY name",
                (tenant_id,),
            )
        ]

    def delete_group(self, tenant_id: str, group_id: str, *, actor: str) -> bool:
        """Membership cascades by foreign key; the grants go by migration 017's trigger.

        Neither is done here, and that is the point â€” see `delete_group` in base.py.
        What *is* done here is counting them first. The cascade is the whole consequence
        of this call: every access the group carried, on every agent, gone. After the
        DELETE there is nothing left to count, and the numbers are the only thing that
        ever says how much went. Three statements, for an operation nobody runs in a
        loop.
        """
        with self._transaction() as cur:
            counts = cur.execute(
                """
                SELECT g.name,
                       (SELECT count(*) FROM group_members m
                         WHERE m.tenant_id = %s AND m.group_id = %s),
                       (SELECT count(*) FROM agent_grants a
                         WHERE a.tenant_id = %s AND a.grantee_kind = 'group'
                           AND a.grantee_id = %s)
                  FROM groups g
                 WHERE g.tenant_id = %s AND g.group_id = %s
                """,
                (tenant_id, group_id) * 3,
            ).fetchone()

            if counts is None:
                return False

            cur.execute(
                "DELETE FROM groups WHERE tenant_id = %s AND group_id = %s",
                (tenant_id, group_id),
            )
            self._write_admin(
                cur,
                tenant_id,
                make_admin_record(
                    "group.delete",
                    "group",
                    group_id,
                    actor,
                    {"name": counts[0], "members": counts[1], "grants": counts[2]},
                ),
            )
            return True

    def add_group_member(
        self,
        tenant_id: str,
        group_id: str,
        principal_kind: str,
        principal_id: str,
        added_by: str = "",
        *,
        actor: str,
    ) -> None:
        import psycopg

        check_principal_kind(principal_kind)

        if not principal_id:
            raise StorageError("a member needs a principal id")

        record = make_admin_record(
            "group.member.add",
            "group",
            group_id,
            actor,
            {"member_kind": principal_kind, "member_id": principal_id},
        )

        try:
            with self._transaction() as cur:
                added = cur.execute(
                    """
                    INSERT INTO group_members (
                        tenant_id, group_id, principal_kind, principal_id, added_by
                    ) VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_id, group_id, principal_kind, principal_id)
                    DO NOTHING
                    RETURNING group_id
                    """,
                    (tenant_id, group_id, principal_kind, principal_id, added_by),
                ).fetchone()

                # `DO NOTHING` returns no row, and nothing means no record either:
                # adding somebody who is already in the group changed nobody's access.
                if added is not None:
                    self._write_admin(cur, tenant_id, record)
        except StorageError as exc:
            if isinstance(exc.__cause__, psycopg.errors.ForeignKeyViolation):
                raise NoSuchGroupError(
                    NO_SUCH_GROUP.format(group=group_id, tenant=tenant_id)
                ) from exc
            raise

    def remove_group_member(
        self,
        tenant_id: str,
        group_id: str,
        principal_kind: str,
        principal_id: str,
        *,
        actor: str,
    ) -> bool:
        with self._transaction() as cur:
            row = cur.execute(
                "DELETE FROM group_members WHERE tenant_id = %s AND group_id = %s "
                "AND principal_kind = %s AND principal_id = %s RETURNING added_by",
                (tenant_id, group_id, principal_kind, principal_id),
            ).fetchone()

            if row is None:
                return False

            self._write_admin(
                cur,
                tenant_id,
                make_admin_record(
                    "group.member.remove",
                    "group",
                    group_id,
                    actor,
                    {
                        "member_kind": principal_kind,
                        "member_id": principal_id,
                        "added_by": row[0],
                    },
                ),
            )
            return True

    def list_group_members(self, tenant_id: str, group_id: str) -> list[dict]:
        columns = ", ".join(self._MEMBER_COLUMNS)
        return [
            dict(zip(self._MEMBER_COLUMNS, row))
            for row in self._fetchall(
                f"SELECT {columns} FROM group_members WHERE tenant_id = %s "
                "AND group_id = %s ORDER BY principal_kind, principal_id",
                (tenant_id, group_id),
            )
        ]

    def groups_for_principal(
        self, tenant_id: str, principal_kind: str, principal_id: str
    ) -> list[str]:
        return [
            row[0]
            for row in self._fetchall(
                "SELECT group_id FROM group_members WHERE tenant_id = %s "
                "AND principal_kind = %s AND principal_id = %s ORDER BY group_id",
                (tenant_id, principal_kind, principal_id),
            )
        ]

    # --- platform roles -----------------------------------------------------------

    _PLATFORM_ROLE_COLUMNS = PLATFORM_ROLE_FIELDS

    def grant_platform_role(
        self,
        tenant_id: str,
        principal_kind: str,
        principal_id: str,
        role: str,
        granted_by: str = "",
        *,
        actor: str,
    ) -> dict:
        check_platform_role(principal_kind, role)

        if not principal_id:
            raise StorageError("a platform role needs a principal id")

        # Built before the transaction opens, matching every other write here: the only
        # thing on this path that can raise is `make_admin_record`, and a bad actor must
        # leave the table untouched rather than half-written.
        record = make_admin_record(
            "role.grant",
            # The principal's own kind, not the literal 'user' — a role may be granted to
            # a `system` principal, and a log that called `nightly` a person would be
            # wrong in the one place this table is read.
            principal_kind,
            principal_id,
            actor,
            {"role": role},
        )

        columns = ", ".join(self._PLATFORM_ROLE_COLUMNS)
        with self._transaction() as cur:
            row = cur.execute(
                f"""
                INSERT INTO platform_roles (
                    tenant_id, principal_kind, principal_id, role, granted_by
                ) VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, principal_kind, principal_id, role)
                DO UPDATE SET granted_by = EXCLUDED.granted_by, granted_at = now()
                RETURNING {columns}
                """,
                (tenant_id, principal_kind, principal_id, role, granted_by or actor),
            ).fetchone()

            # Unlike `add_group_member`, the conflict branch **does** record. `DO UPDATE`
            # always returns a row, and that is the intended shape rather than an
            # accident of SQL: re-granting is a second decision about the same person,
            # and the most recent one is the one an incident asks about.
            self._write_admin(cur, tenant_id, record)
            return dict(zip(self._PLATFORM_ROLE_COLUMNS, row))

    def revoke_platform_role(
        self,
        tenant_id: str,
        principal_kind: str,
        principal_id: str,
        role: str,
        *,
        actor: str,
    ) -> bool:
        record = make_admin_record(
            "role.revoke",
            # The principal's own kind, not the literal 'user' — a role may be granted to
            # a `system` principal, and a log that called `nightly` a person would be
            # wrong in the one place this table is read.
            principal_kind,
            principal_id,
            actor,
            {"role": role},
        )

        with self._transaction() as cur:
            cur.execute(
                "DELETE FROM platform_roles WHERE tenant_id = %s "
                "AND principal_kind = %s AND principal_id = %s AND role = %s",
                (tenant_id, principal_kind, principal_id, role),
            )
            if not cur.rowcount:
                return False
            self._write_admin(cur, tenant_id, record)
            return True

    def list_platform_roles(self, tenant_id: str) -> list[dict]:
        columns = ", ".join(self._PLATFORM_ROLE_COLUMNS)
        return [
            dict(zip(self._PLATFORM_ROLE_COLUMNS, row))
            for row in self._fetchall(
                f"SELECT {columns} FROM platform_roles WHERE tenant_id = %s "
                "ORDER BY principal_kind, principal_id, role",
                (tenant_id,),
            )
        ]

    def has_platform_role(
        self, tenant_id: str, principal_kind: str, principal_id: str, role: str
    ) -> bool:
        # `SELECT 1` rather than a row: this runs on every request to an administrative
        # route and the answer is one bit. The WHERE clause is the primary key, so it is
        # an index lookup — and `tenant_id` leads it, which is the assertion in
        # verification 3 of the plan rather than an incidental ordering.
        return (
            self._fetchone(
                "SELECT 1 FROM platform_roles WHERE tenant_id = %s "
                "AND principal_kind = %s AND principal_id = %s AND role = %s",
                (tenant_id, principal_kind, principal_id, role),
            )
            is not None
        )

    # --- pending grants ---------------------------------------------------------

    # Was a private tuple here; step 025 moved it to `base.py` so the fake reads the same
    # one. See `PENDING_GRANT_FIELDS` for what that omission cost.
    _PENDING_COLUMNS = PENDING_GRANT_FIELDS

    def find_user_by_email(self, tenant_id: str, email: str) -> dict | None:
        # `lower(email)` rather than a citext column or a functional index: this runs
        # once per share and once per login-with-a-new-address, against a table with one
        # row per employee. An index here would be tuning ahead of a measurement.
        row = self._fetchone(
            f"SELECT {', '.join(self._USER_COLUMNS)} FROM users "
            "WHERE tenant_id = %s AND email <> '' AND lower(email) = %s "
            "ORDER BY id LIMIT 1",
            (tenant_id, normalize_email(email)),
        )
        return dict(zip(self._USER_COLUMNS, row)) if row else None

    def add_pending_grant(
        self,
        tenant_id: str,
        agent_name: str,
        email: str,
        role: str = "user",
        granted_by: str = "",
        *,
        actor: str,
    ) -> None:
        import psycopg

        check_pending_role(role)
        address = normalize_email(email)

        record = make_admin_record(
            "grant.pending.add",
            "agent",
            agent_name,
            actor,
            # The address is the identifying fact of the action. There is no principal
            # yet, so it is the only thing that says who this was for.
            {"email": address, "role": role},
        )

        try:
            with self._transaction() as cur:
                agent_id = self._agent_id_for(tenant_id, agent_name, cur)
                if agent_id is None:
                    raise StorageError(
                        f"no agent named '{agent_name}' in tenant '{tenant_id}'"
                    )
                cur.execute(
                    """
                    INSERT INTO pending_grants (
                        tenant_id, agent_id, email, role, granted_by
                    ) VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_id, agent_id, email)
                    DO UPDATE SET role = EXCLUDED.role,
                                  granted_by = EXCLUDED.granted_by,
                                  granted_at = now()
                    """,
                    (tenant_id, agent_id, address, role, granted_by),
                )
                self._write_admin(cur, tenant_id, record)
        except StorageError as exc:
            if isinstance(exc.__cause__, psycopg.errors.ForeignKeyViolation):
                raise StorageError(
                    f"no agent named '{agent_name}' in tenant '{tenant_id}'"
                ) from exc
            raise

    def claim_pending_grants(
        self, tenant_id: str, email: str, principal_kind: str, principal_id: str
    ) -> list[str]:
        check_claimant(principal_kind)
        address = normalize_email(email)
        if not address:
            return []

        # One transaction. Two of somebody's very first requests can arrive at once â€”
        # a UI opening two panels, a refresh, a retry â€” and both will try to claim. The
        # DELETE ... RETURNING is what makes losing safe: whichever transaction commits
        # first takes the rows, and the other finds none and claims nothing. A SELECT
        # then DELETE would let both see the same rows and both insert.
        with self._transaction() as cur:
            # `agent_id` and the name, both — the id to write the grant with, the name for
            # the record and the return value. The name comes out of a subquery on the
            # deleted row rather than a second statement, so `RETURNING` stays the thing
            # that makes losing this race safe.
            taken = cur.execute(
                f"""
                DELETE FROM pending_grants WHERE tenant_id = %s AND email = %s
                RETURNING agent_id, {_agent_name_expr("pending_grants")},
                          role, granted_by
                """,
                (tenant_id, address),
            ).fetchall()

            for agent_id, agent_name, role, granted_by in taken:
                # A pending grant never demotes somebody: shared at `user` while already
                # an editor, a plain upsert would take access away at the moment of a
                # login, which is the worst time to find out. The array position of the
                # role is the ladder, same as `AGENT_ROLES`.
                applied = cur.execute(
                    """
                    INSERT INTO agent_grants (
                        tenant_id, agent_id, grantee_kind, grantee_id,
                        role, granted_by
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_id, agent_id, grantee_kind, grantee_id)
                    DO UPDATE SET role = EXCLUDED.role,
                                  granted_by = EXCLUDED.granted_by,
                                  granted_at = now()
                    WHERE array_position(ARRAY['user','editor','owner'],
                                         agent_grants.role)
                        < array_position(ARRAY['user','editor','owner'],
                                         EXCLUDED.role)
                    RETURNING role
                    """,
                    (tenant_id, agent_id, principal_kind, principal_id, role, granted_by),
                ).fetchone()

                # One record per agent claimed, all inside the one transaction. The
                # claim is atomic across agents and the *access* is per agent, so this
                # is the granularity `admin_audit_records(target_id=...)` has to answer
                # at.
                #
                # The claimant is the actor: a claim is somebody's own first login
                # collecting what was addressed to them. Who shared it, weeks ago, is
                # carried in the detail rather than in the actor — they are different
                # people and the record must not merge them.
                self._write_admin(
                    cur,
                    tenant_id,
                    make_admin_record(
                        "grant.pending.claim",
                        "agent",
                        agent_name,
                        f"{principal_kind}:{principal_id}",
                        {
                            "email": address,
                            "role": role,
                            "granted_by": granted_by,
                            # Whether it actually raised their level. A pending grant
                            # never demotes, so a claim can legitimately change nothing.
                            "applied": applied is not None,
                        },
                    ),
                )

        return sorted(name for _id, name, _role, _by in taken)

    def list_pending_grants(self, tenant_id: str, agent_name: str) -> list[dict]:
        columns = _child_columns(self._PENDING_COLUMNS, "pending_grants")
        return [
            dict(zip(self._PENDING_COLUMNS, row))
            for row in self._fetchall(
                f"SELECT {columns} FROM pending_grants WHERE tenant_id = %s "
                f"AND agent_id = {self._AGENT_BY_NAME} ORDER BY email",
                (tenant_id, tenant_id, agent_name),
            )
        ]

    def delete_pending_grant(
        self, tenant_id: str, agent_name: str, email: str, *, actor: str
    ) -> None:
        address = normalize_email(email)

        with self._transaction() as cur:
            waiting = cur.execute(
                f"DELETE FROM pending_grants WHERE tenant_id = %s "
                f"AND agent_id = {self._AGENT_BY_NAME} "
                "AND email = %s RETURNING role, granted_by",
                (tenant_id, tenant_id, agent_name, address),
            ).fetchone()

            # No row, no record. `unshare_email` calls this on *both* of its branches —
            # a real revoke also clears any pending row left armed — so recording
            # unconditionally would log a cancellation every time somebody revoked an
            # ordinary grant.
            if waiting is None:
                return

            self._write_admin(
                cur,
                tenant_id,
                make_admin_record(
                    "grant.pending.delete",
                    "agent",
                    agent_name,
                    actor,
                    {
                        "email": address,
                        "role": waiting[0],
                        "granted_by": waiting[1],
                    },
                ),
            )

    # --- connections ------------------------------------------------------------

    # Ordered to match what both stores return. `ciphertext` is deliberately absent
    # from the metadata list and appears only in `find_connection`.
    _CONNECTION_KEY_COLUMNS = (
        "tenant_id",
        "principal_kind",
        "principal_id",
        "connector_id",
    )
    _CONNECTION_META_COLUMNS = (
        *_CONNECTION_KEY_COLUMNS,
        "key_id",
        "expires_at",
        "account_label",
        "created_at",
        "updated_at",
        # Step 7b. Added to the shared list rather than to `find_connection` alone,
        # because every one of them is something a *reader* has to branch on: the kind
        # decides how the ciphertext is decoded, the reason decides whether the row can
        # be used at all, and the refresh expiry is what lets a screen warn before a
        # connection dies rather than after. A metadata view that could not say "this
        # one needs reconnecting" would be a Connections page that renders every row the
        # same and is wrong about a third of them.
        "credential_kind",
        "refresh_expires_at",
        "reconsent_reason",
    )

    def save_connection(
        self,
        tenant_id: str,
        principal_kind: str,
        principal_id: str,
        connector_id: str,
        *,
        ciphertext: bytes,
        key_id: str,
        expires_at=None,
        account_label: str = "",
        credential_kind: str = STATIC_CREDENTIAL,
        refresh_expires_at=None,
        actor: str,
    ) -> None:
        check_principal_kind(principal_kind)
        check_connection(ciphertext, key_id, expires_at)
        check_connection(ciphertext, key_id, refresh_expires_at)
        check_credential_kind(credential_kind)
        if not connector_id:
            raise StorageError("connector_id must be a non-empty string")
        if not principal_id:
            raise StorageError("principal_id must be a non-empty string")

        record = make_admin_record(
            "connection.create",
            "connector",
            connector_id,
            actor,
            {
                "principal": f"{principal_kind}:{principal_id}",
                "kind": credential_kind,
                "label": account_label or "",
            },
        )

        # created_at is left alone by the UPDATE branch on purpose: reconnecting
        # changes the credential, not the fact that this person connected in March.
        #
        # `reconsent_reason` is reset to '' on both branches, and that is the one thing
        # in this statement that is not merely mechanical: reconnecting is the fix for a
        # revoked grant, so leaving the old refusal standing would tell somebody who just
        # did exactly the right thing that it had not worked.
        try:
            with self._transaction() as cur:
                cur.execute(
                    """
                    INSERT INTO connections (
                        tenant_id, principal_kind, principal_id, connector_id,
                        ciphertext, key_id, expires_at, account_label,
                        credential_kind, refresh_expires_at, reconsent_reason
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, '')
                    ON CONFLICT (tenant_id, principal_kind, principal_id, connector_id)
                    DO UPDATE SET ciphertext = EXCLUDED.ciphertext,
                                  key_id = EXCLUDED.key_id,
                                  expires_at = EXCLUDED.expires_at,
                                  account_label = EXCLUDED.account_label,
                                  credential_kind = EXCLUDED.credential_kind,
                                  refresh_expires_at = EXCLUDED.refresh_expires_at,
                                  reconsent_reason = '',
                                  updated_at = now()
                    """,
                    (
                        tenant_id,
                        principal_kind,
                        principal_id,
                        connector_id,
                        bytes(ciphertext),
                        key_id,
                        expires_at,
                        account_label or "",
                        credential_kind,
                        refresh_expires_at,
                    ),
                )
                # Inside the transaction, on migration 022's rule: a credential stored
                # with nobody's name on the storing is the gap the administrative log
                # exists to close.
                self._write_admin(cur, tenant_id, record)
        except StorageError as exc:
            # Migration 021. Two foreign keys can fire here and they mean different
            # things — an unregistered customer and an unvetted connector — so the
            # constraint name is what tells them apart rather than "it was a
            # ForeignKeyViolation". `_translate` turns every FK violation into
            # `UnknownTenantError`, which is right for the other one and would be a
            # lie here.
            cause = exc.__cause__
            if (
                cause is not None
                # `diag` via getattr too: it exists on psycopg's errors and not on
                # BaseException, so reaching through it directly turned a chained
                # non-psycopg cause into an AttributeError from the handler itself.
                and getattr(getattr(cause, "diag", None), "constraint_name", "")
                == "connections_connector_fk"
            ):
                raise UnknownConnectorError(
                    NO_SUCH_CONNECTOR.format(
                        connector=connector_id, tenant=tenant_id
                    )
                ) from exc
            raise

    def find_connection(
        self, tenant_id: str, principal_kind: str, principal_id: str, connector_id: str
    ) -> dict | None:
        check_principal_kind(principal_kind)
        columns = ("ciphertext", *self._CONNECTION_META_COLUMNS)
        row = self._fetchone(
            f"SELECT {', '.join(columns)} FROM connections "
            "WHERE tenant_id = %s AND principal_kind = %s AND principal_id = %s "
            "AND connector_id = %s",
            (tenant_id, principal_kind, principal_id, connector_id),
        )
        if row is None:
            return None

        found = dict(zip(columns, row))
        # psycopg hands back a `memoryview` for BYTEA. Callers get `bytes`, because the
        # in-memory store has no way to produce a memoryview and the contract suite
        # compares what comes out of both.
        found["ciphertext"] = bytes(found["ciphertext"])
        return found

    def has_connection(
        self, tenant_id: str, principal_kind: str, principal_id: str, connector_id: str
    ) -> bool:
        check_principal_kind(principal_kind)
        row = self._fetchone(
            "SELECT 1 FROM connections WHERE tenant_id = %s AND principal_kind = %s "
            "AND principal_id = %s AND connector_id = %s",
            (tenant_id, principal_kind, principal_id, connector_id),
        )
        return row is not None

    def list_connections(
        self,
        tenant_id: str,
        *,
        principal_kind: str | None = None,
        principal_id: str | None = None,
    ) -> list[dict]:
        if principal_kind is not None:
            check_principal_kind(principal_kind)

        clauses = ["tenant_id = %s"]
        params = [tenant_id]
        if principal_kind is not None:
            clauses.append("principal_kind = %s")
            params.append(principal_kind)
        if principal_id is not None:
            clauses.append("principal_id = %s")
            params.append(principal_id)

        columns = ", ".join(self._CONNECTION_META_COLUMNS)
        return [
            dict(zip(self._CONNECTION_META_COLUMNS, row))
            for row in self._fetchall(
                f"SELECT {columns} FROM connections WHERE {' AND '.join(clauses)} "
                "ORDER BY principal_kind, principal_id, connector_id",
                tuple(params),
            )
        ]

    def delete_connection(
        self,
        tenant_id: str,
        principal_kind: str,
        principal_id: str,
        connector_id: str,
        *,
        actor: str,
        detail: dict | None = None,
    ) -> bool:
        check_principal_kind(principal_kind)
        record = make_admin_record(
            "connection.delete",
            "connector",
            connector_id,
            actor,
            {
                "principal": f"{principal_kind}:{principal_id}",
                **(detail or {}),
            },
        )

        with self._transaction() as cur:
            cur.execute(
                "DELETE FROM connections WHERE tenant_id = %s AND principal_kind = %s "
                "AND principal_id = %s AND connector_id = %s",
                (tenant_id, principal_kind, principal_id, connector_id),
            )
            if not cur.rowcount:
                return False
            self._write_admin(cur, tenant_id, record)
            return True

    # --- OAuth ---------------------------------------------------------------------

    _OAUTH_PUBLIC_COLUMNS = ", ".join(OAUTH_APP_PUBLIC_FIELDS)
    _OAUTH_ALL_COLUMNS = ", ".join(OAUTH_APP_FIELDS)

    def set_connector_oauth(
        self,
        tenant_id: str,
        connector_id: str,
        *,
        authorize_endpoint: str,
        token_endpoint: str,
        revoke_endpoint: str = "",
        client_id: str,
        client_secret: bytes,
        key_id: str,
        scopes=(),
        authorize_params=None,
        scope_notes=None,
        actor: str,
    ) -> None:
        check_oauth_app(
            authorize_endpoint=authorize_endpoint,
            token_endpoint=token_endpoint,
            client_id=client_id,
            client_secret=client_secret,
            key_id=key_id,
        )
        wanted = normalize_scopes(scopes)
        extra = normalize_authorize_params(authorize_params)
        # Checked against `wanted` rather than the raw argument, so a scope written with
        # surrounding spaces still matches the note that describes it.
        notes = normalize_scope_notes(scope_notes, scopes=wanted)

        # The connector is checked explicitly as well as by the foreign key, for
        # `_require_tenant`'s reason: the FK would raise `UnknownTenantError` through
        # `_translate`, and "tenant does not exist" is the wrong sentence to show
        # somebody who mistyped a connector name.
        if self._fetchone(
            "SELECT 1 FROM connectors WHERE tenant_id = %s AND id = %s",
            (tenant_id, connector_id),
        ) is None:
            raise NoSuchConnectorError(
                NO_SUCH_CONNECTOR_TO_VET.format(
                    connector=connector_id, tenant=tenant_id
                )
            )

        record = make_admin_record(
            "connector.oauth.configure",
            "connector",
            connector_id,
            actor,
            # The client id is public by construction — it is in a browser address bar
            # every time somebody consents. The scopes are the interesting half: *what
            # did we ask this person to agree to*. The secret is not here and must never
            # be; see `CONNECTION_DETAIL_KEYS`.
            {
                "client_id": client_id,
                "scopes": list(wanted),
                "token_endpoint": token_endpoint,
                # Not a secret — these end up in a browser's address bar — and this is
                # where "what exactly did we ask this provider for" is answerable.
                "authorize_params": extra,
                # Which scopes were annotated, never the prose. *Was the consent screen
                # explained when this was configured* is a real question after an
                # incident; three paragraphs per scope in an append-only table is how the
                # administrative log stops being readable.
                "described_scopes": sorted(notes),
            },
        )

        with self._transaction() as cur:
            cur.execute(
                """
                INSERT INTO connector_oauth (
                    tenant_id, connector_id, authorize_endpoint, token_endpoint,
                    revoke_endpoint, client_id, client_secret, key_id, scopes,
                    authorize_params, scope_notes, configured_by
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, connector_id)
                DO UPDATE SET authorize_endpoint = EXCLUDED.authorize_endpoint,
                              token_endpoint     = EXCLUDED.token_endpoint,
                              revoke_endpoint    = EXCLUDED.revoke_endpoint,
                              client_id          = EXCLUDED.client_id,
                              client_secret      = EXCLUDED.client_secret,
                              key_id             = EXCLUDED.key_id,
                              scopes             = EXCLUDED.scopes,
                              authorize_params   = EXCLUDED.authorize_params,
                              -- Replaced wholesale, never merged. A note surviving the
                              -- scope it described would be a consent screen explaining
                              -- a permission this flow no longer asks for.
                              scope_notes        = EXCLUDED.scope_notes,
                              configured_by      = EXCLUDED.configured_by,
                              configured_at      = now()
                """,
                (
                    tenant_id,
                    connector_id,
                    authorize_endpoint,
                    token_endpoint,
                    revoke_endpoint or "",
                    client_id,
                    bytes(client_secret),
                    key_id,
                    json.dumps(list(wanted)),
                    json.dumps(extra),
                    json.dumps(notes),
                    actor,
                ),
            )
            self._write_admin(cur, tenant_id, record)

    def get_connector_oauth(self, tenant_id: str, connector_id: str) -> dict | None:
        row = self._fetchone(
            f"SELECT {self._OAUTH_ALL_COLUMNS} FROM connector_oauth "
            "WHERE tenant_id = %s AND connector_id = %s",
            (tenant_id, connector_id),
        )
        if row is None:
            return None
        found = dict(zip(OAUTH_APP_FIELDS, row))
        # psycopg hands back a `memoryview` for BYTEA; the in-memory store cannot
        # produce one and the contract suite compares what comes out of both.
        found["client_secret"] = bytes(found["client_secret"])
        found["configured_at"] = found["configured_at"].isoformat()
        return found

    def list_connector_oauth(self, tenant_id: str) -> list[dict]:
        # `row[-1]` until step 068, which is a silent trap one position wide: it works
        # only while `configured_at` is the last name in `OAUTH_APP_PUBLIC_FIELDS`, and
        # 051 added `scope_notes` to that tuple. Placed after `configured_at` instead of
        # before it, the timestamp would have been a dict and this an `AttributeError` on
        # every read of the Connections page — from a field addition nowhere near this
        # line. Named now, so where a field goes in that tuple stops mattering here.
        return [
            {
                **(found := dict(zip(OAUTH_APP_PUBLIC_FIELDS, row))),
                "configured_at": found["configured_at"].isoformat(),
            }
            for row in self._fetchall(
                f"SELECT {self._OAUTH_PUBLIC_COLUMNS} FROM connector_oauth "
                "WHERE tenant_id = %s ORDER BY connector_id",
                (tenant_id,),
            )
        ]

    def delete_connector_oauth(
        self, tenant_id: str, connector_id: str, *, actor: str
    ) -> bool:
        record = make_admin_record(
            "connector.oauth.remove", "connector", connector_id or "", actor
        )
        with self._transaction() as cur:
            cur.execute(
                "DELETE FROM connector_oauth WHERE tenant_id = %s AND connector_id = %s",
                (tenant_id, connector_id),
            )
            if not cur.rowcount:
                return False
            self._write_admin(cur, tenant_id, record)
            return True

    def update_connection_credential(
        self,
        tenant_id: str,
        principal_kind: str,
        principal_id: str,
        connector_id: str,
        *,
        ciphertext: bytes,
        key_id: str,
        expires_at,
        refresh_expires_at,
        account_label: str | None = None,
        if_updated_at,
    ) -> dict | None:
        check_principal_kind(principal_kind)
        check_connection(ciphertext, key_id, expires_at)
        check_connection(ciphertext, key_id, refresh_expires_at)
        if if_updated_at is None:
            raise StorageError(
                "update_connection_credential needs the version it is replacing. A "
                "refresh with no precondition is last-write-wins, which is how a run "
                "stores a refresh token the provider has already invalidated."
            )

        # **One statement, and `AND updated_at = %s` is the whole method.** See
        # `update_agent`, which took this shape for the identical reason: a read in one
        # statement and a write in another has a window between them, and that window is
        # precisely the lost update this exists to catch.
        #
        # `COALESCE` on the label rather than a second UPDATE branch: a refresh response
        # rarely repeats the account's identity, and overwriting a verified label with ''
        # because the provider stayed quiet would lose the only thing on this row a
        # person recognises.
        columns = ", ".join(self._CONNECTION_META_COLUMNS)
        row = self._fetchone(
            f"""
            UPDATE connections
               SET ciphertext         = %s,
                   key_id             = %s,
                   expires_at         = %s,
                   refresh_expires_at = %s,
                   account_label      = COALESCE(%s, account_label),
                   reconsent_reason   = '',
                   updated_at         = now()
             WHERE tenant_id = %s AND principal_kind = %s AND principal_id = %s
               AND connector_id = %s AND updated_at = %s
         RETURNING {columns}
            """,
            (
                bytes(ciphertext),
                key_id,
                expires_at,
                refresh_expires_at,
                account_label,
                tenant_id,
                principal_kind,
                principal_id,
                connector_id,
                if_updated_at,
            ),
        )
        return dict(zip(self._CONNECTION_META_COLUMNS, row)) if row else None

    def mark_connection_reconsent(
        self,
        tenant_id: str,
        principal_kind: str,
        principal_id: str,
        connector_id: str,
        *,
        reason: str,
    ) -> bool:
        check_principal_kind(principal_kind)
        if not reason:
            raise StorageError(
                "a connection is marked as needing re-consent with a reason, because "
                "the reason is what the person reads. Clearing the mark is what "
                "reconnecting does."
            )
        row = self._fetchone(
            "UPDATE connections SET reconsent_reason = %s, updated_at = now() "
            "WHERE tenant_id = %s AND principal_kind = %s AND principal_id = %s "
            "AND connector_id = %s RETURNING 1",
            (reason, tenant_id, principal_kind, principal_id, connector_id),
        )
        return row is not None

    def create_pending_authorization(
        self,
        state: str,
        tenant_id: str,
        *,
        principal_kind: str,
        principal_id: str,
        connector_id: str,
        code_verifier: bytes,
        key_id: str,
        redirect_uri: str,
        return_to: str = "",
    ) -> None:
        check_principal_kind(principal_kind)
        check_pending_authorization(
            state=state,
            connector_id=connector_id,
            code_verifier=code_verifier,
            key_id=key_id,
            redirect_uri=redirect_uri,
            return_to=return_to,
        )
        self._require_tenant(tenant_id)
        self._execute(
            """
            INSERT INTO pending_authorizations (
                state, tenant_id, principal_kind, principal_id, connector_id,
                code_verifier, key_id, redirect_uri, return_to
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                state,
                tenant_id,
                principal_kind,
                principal_id,
                connector_id,
                bytes(code_verifier),
                key_id,
                redirect_uri,
                return_to or "",
            ),
        )

    def consume_pending_authorization(self, state: str) -> dict | None:
        if not state:
            return None
        # One statement, and the atomicity is the single-use guarantee: a read-then-
        # delete has a window in which two callbacks carrying the same `state` both find
        # it and both exchange the same authorization code.
        row = self._fetchone(
            f"DELETE FROM pending_authorizations WHERE state = %s "
            f"RETURNING {', '.join(PENDING_AUTHORIZATION_FIELDS)}",
            (state,),
        )
        if row is None:
            return None
        found = dict(zip(PENDING_AUTHORIZATION_FIELDS, row))
        found["code_verifier"] = bytes(found["code_verifier"])
        return found

    def sweep_pending_authorizations(self, *, older_than_seconds: int) -> int:
        row = self._fetchone(
            "WITH gone AS ("
            "  DELETE FROM pending_authorizations"
            "   WHERE created_at < now() - make_interval(secs => %s)"
            "  RETURNING 1"
            ") SELECT count(*) FROM gone",
            (int(older_than_seconds),),
        )
        return int(row[0]) if row else 0

    # --- the door as an OAuth resource server ---------------------------------------
    #
    # Step 083, migration 053. `oauth_clients` has no tenant and no policy; every read
    # of it here is unscoped by construction. `oauth_codes` is tenant-keyed, but its
    # reads are tenantless too — the token request carries no bearer, so the row is
    # what produces the tenant, on `find_api_token`'s pattern.

    _OAUTH_CLIENT_COLUMNS = OAUTH_CLIENT_FIELDS
    _OAUTH_CODE_COLUMNS = OAUTH_CODE_FIELDS

    def create_oauth_client(self, client: dict) -> dict:
        import psycopg

        row = normalize_oauth_client(client)
        columns = ", ".join(self._OAUTH_CLIENT_COLUMNS)
        try:
            created = self._fetchone(
                f"""
                INSERT INTO oauth_clients (id, client_name, redirect_uris, metadata)
                VALUES (%s, %s, %s, %s)
                RETURNING {columns}
                """,
                (
                    row["id"],
                    row["client_name"],
                    json.dumps(row["redirect_uris"]),
                    json.dumps(row["metadata"]),
                ),
            )
        except StorageError as exc:
            if isinstance(exc.__cause__, psycopg.errors.UniqueViolation):
                raise StorageError(
                    f"an OAuth client with id '{row['id']}' already exists. The id is "
                    "minted rather than chosen, so this is a collision in whatever "
                    "generated it rather than anything a caller did."
                ) from exc
            raise
        return self._oauth_client_row(created)

    def _oauth_client_row(self, row) -> dict:
        found = dict(zip(self._OAUTH_CLIENT_COLUMNS, row))
        # psycopg hands JSONB back decoded; a `list`/`dict` is what callers read.
        found["redirect_uris"] = list(found["redirect_uris"] or [])
        found["metadata"] = dict(found["metadata"] or {})
        return found

    def find_oauth_client(self, client_id: str) -> dict | None:
        if not client_id:
            return None
        columns = ", ".join(self._OAUTH_CLIENT_COLUMNS)
        row = self._fetchone(
            f"SELECT {columns} FROM oauth_clients WHERE id = %s", (client_id,)
        )
        return self._oauth_client_row(row) if row is not None else None

    def touch_oauth_client(self, client_id: str) -> None:
        self._execute(
            "UPDATE oauth_clients SET last_consented_at = now() WHERE id = %s",
            (client_id,),
        )

    def sweep_oauth_clients(self, *, unused_for_seconds: int) -> int:
        row = self._fetchone(
            "WITH gone AS ("
            "  DELETE FROM oauth_clients"
            "   WHERE last_consented_at IS NULL"
            "     AND created_at < now() - make_interval(secs => %s)"
            "  RETURNING 1"
            ") SELECT count(*) FROM gone",
            (int(unused_for_seconds),),
        )
        return int(row[0]) if row else 0

    def create_oauth_code(self, tenant_id: str, code: dict) -> None:
        import psycopg

        row = normalize_oauth_code(code)
        self._require_tenant(tenant_id)
        try:
            self._execute(
                """
                INSERT INTO oauth_codes (
                    code_hash, tenant_id, client_id, owner_id, redirect_uri,
                    code_challenge, resource, token_name, expires_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    row["code_hash"],
                    tenant_id,
                    row["client_id"],
                    row["owner_id"],
                    row["redirect_uri"],
                    row["code_challenge"],
                    row["resource"],
                    row["token_name"],
                    row["expires_at"],
                ),
            )
        except StorageError as exc:
            cause = exc.__cause__
            if isinstance(cause, psycopg.errors.UniqueViolation):
                raise StorageError(
                    "an OAuth code with this hash already exists. Codes are random and "
                    "single-use; a duplicate means they are not being generated the "
                    "way this table assumes."
                ) from exc
            if isinstance(cause, psycopg.errors.ForeignKeyViolation):
                raise ValueRefused(
                    f"there is no OAuth client '{row['client_id']}' to issue a code to."
                ) from exc
            raise

    def find_oauth_code(self, code_hash: str) -> dict | None:
        if not code_hash:
            return None
        columns = ", ".join(self._OAUTH_CODE_COLUMNS)
        row = self._fetchone(
            f"SELECT {columns} FROM oauth_codes WHERE code_hash = %s", (code_hash,)
        )
        return dict(zip(self._OAUTH_CODE_COLUMNS, row)) if row is not None else None

    def consume_oauth_code(self, code_hash: str) -> bool:
        if not code_hash:
            return False
        row = self._fetchone(
            "UPDATE oauth_codes SET used_at = now()"
            " WHERE code_hash = %s AND used_at IS NULL RETURNING 1",
            (code_hash,),
        )
        return row is not None

    def record_oauth_code_token(self, code_hash: str, token_id: str) -> None:
        self._execute(
            "UPDATE oauth_codes SET token_id = %s WHERE code_hash = %s",
            (token_id, code_hash),
        )

    def sweep_oauth_codes(self, *, older_than_seconds: int) -> int:
        row = self._fetchone(
            "WITH gone AS ("
            "  DELETE FROM oauth_codes"
            "   WHERE expires_at < now() - make_interval(secs => %s)"
            "  RETURNING 1"
            ") SELECT count(*) FROM gone",
            (int(older_than_seconds),),
        )
        return int(row[0]) if row else 0

    # --- key rotation ---------------------------------------------------------------
    #
    # Step 026. Tenantless fetches and blob-conditional single-statement updates; the
    # whole contract, including why the compare-and-set token is the blob itself, is in
    # `base.py`'s section comment. `RETURNING 1` through `_fetchone` is how a
    # cursor-less `_execute` answers "did that land".

    _ROTATION_CONNECTION_COLUMNS = ("ciphertext", *_CONNECTION_KEY_COLUMNS, "key_id")

    # The four sealed columns and the column naming the key each was sealed under.
    # Written once because the census and the four fetches would otherwise be five
    # places that have to agree about which column `triggers` calls its key.
    _SEALED_KEY_COLUMNS = (
        ("connections", "key_id"),
        ("connector_oauth", "key_id"),
        ("triggers", "secret_key_id"),
        ("pending_authorizations", "key_id"),
    )

    def sealed_key_id_census(self) -> dict:
        census = {table: {} for table, _ in self._SEALED_KEY_COLUMNS}
        union = " UNION ALL ".join(
            f"SELECT '{table}' AS sealed_table, {column} AS key_id, count(*) AS rows"
            f"   FROM {table} GROUP BY {column}"
            for table, column in self._SEALED_KEY_COLUMNS
        )
        for table, key_id, rows in self._fetchall(union):
            census[table][key_id] = int(rows)
        return census

    def connections_not_sealed_under(self, key_id: str) -> list[dict]:
        columns = self._ROTATION_CONNECTION_COLUMNS
        out = []
        for row in self._fetchall(
            f"SELECT {', '.join(columns)} FROM connections WHERE key_id <> %s "
            "ORDER BY tenant_id, principal_kind, principal_id, connector_id",
            (key_id,),
        ):
            found = dict(zip(columns, row))
            found["ciphertext"] = bytes(found["ciphertext"])
            out.append(found)
        return out

    def connector_oauth_not_sealed_under(self, key_id: str) -> list[dict]:
        columns = ("tenant_id", "connector_id", "client_secret", "key_id")
        out = []
        for row in self._fetchall(
            f"SELECT {', '.join(columns)} FROM connector_oauth WHERE key_id <> %s "
            "ORDER BY tenant_id, connector_id",
            (key_id,),
        ):
            found = dict(zip(columns, row))
            found["client_secret"] = bytes(found["client_secret"])
            out.append(found)
        return out

    def triggers_not_sealed_under(self, key_id: str) -> list[dict]:
        columns = ("tenant_id", "id", "secret_sealed", "secret_key_id")
        out = []
        for row in self._fetchall(
            f"SELECT {', '.join(columns)} FROM triggers WHERE secret_key_id <> %s "
            "ORDER BY tenant_id, id",
            (key_id,),
        ):
            found = dict(zip(columns, row))
            found["secret_sealed"] = bytes(found["secret_sealed"])
            out.append(found)
        return out

    def pending_authorizations_not_sealed_under(self, key_id: str) -> list[dict]:
        columns = ("state", "tenant_id", "code_verifier", "key_id", "created_at")
        out = []
        for row in self._fetchall(
            f"SELECT {', '.join(columns)} FROM pending_authorizations "
            "WHERE key_id <> %s ORDER BY tenant_id, state",
            (key_id,),
        ):
            found = dict(zip(columns, row))
            found["code_verifier"] = bytes(found["code_verifier"])
            out.append(found)
        return out

    def reseal_connection(
        self,
        tenant_id: str,
        principal_kind: str,
        principal_id: str,
        connector_id: str,
        *,
        ciphertext: bytes,
        key_id: str,
        if_ciphertext: bytes,
    ) -> bool:
        check_reseal(ciphertext, key_id, if_ciphertext)
        check_principal_kind(principal_kind)
        # No `updated_at = now()` and no touch of `reconsent_reason`, and both absences
        # are the contract: `updated_at` is the refresh machinery's compare-and-set
        # token, and a reseal must be invisible to it.
        row = self._fetchone(
            """
            UPDATE connections SET ciphertext = %s, key_id = %s
             WHERE tenant_id = %s AND principal_kind = %s AND principal_id = %s
               AND connector_id = %s AND ciphertext = %s
            RETURNING 1
            """,
            (
                bytes(ciphertext),
                key_id,
                tenant_id,
                principal_kind,
                principal_id,
                connector_id,
                bytes(if_ciphertext),
            ),
        )
        return row is not None

    def reseal_connector_oauth(
        self,
        tenant_id: str,
        connector_id: str,
        *,
        client_secret: bytes,
        key_id: str,
        if_client_secret: bytes,
    ) -> bool:
        check_reseal(client_secret, key_id, if_client_secret)
        row = self._fetchone(
            """
            UPDATE connector_oauth SET client_secret = %s, key_id = %s
             WHERE tenant_id = %s AND connector_id = %s AND client_secret = %s
            RETURNING 1
            """,
            (
                bytes(client_secret),
                key_id,
                tenant_id,
                connector_id,
                bytes(if_client_secret),
            ),
        )
        return row is not None

    def reseal_trigger_secret(
        self,
        tenant_id: str,
        trigger_id: str,
        *,
        secret_sealed: bytes,
        secret_key_id: str,
        if_secret_sealed: bytes,
    ) -> bool:
        check_reseal(secret_sealed, secret_key_id, if_secret_sealed)
        row = self._fetchone(
            """
            UPDATE triggers SET secret_sealed = %s, secret_key_id = %s
             WHERE tenant_id = %s AND id = %s AND secret_sealed = %s
            RETURNING 1
            """,
            (
                bytes(secret_sealed),
                secret_key_id,
                tenant_id,
                trigger_id,
                bytes(if_secret_sealed),
            ),
        )
        return row is not None

    def reseal_pending_authorization(
        self,
        state: str,
        *,
        code_verifier: bytes,
        key_id: str,
        if_code_verifier: bytes,
    ) -> bool:
        check_reseal(code_verifier, key_id, if_code_verifier)
        row = self._fetchone(
            """
            UPDATE pending_authorizations SET code_verifier = %s, key_id = %s
             WHERE state = %s AND code_verifier = %s
            RETURNING 1
            """,
            (bytes(code_verifier), key_id, state, bytes(if_code_verifier)),
        )
        return row is not None

    @contextmanager
    def refresh_lock(
        self, tenant_id: str, principal_kind: str, principal_id: str, connector_id: str
    ):
        """`pg_try_advisory_xact_lock`. Yields True if we hold it, False if somebody does.

        **`try`, not the blocking form, and that is a bug fix rather than a refinement.**
        The first version of this took `pg_advisory_xact_lock`, which waits — and a waiter
        holds its pooled connection for the whole wait. The wait is the length of somebody
        else's *token-endpoint round trip*, so eight concurrent refreshes of one connection
        held eight of a ten-connection pool for as long as a third party took to answer.

        The test found it immediately, with a pool of five: four threads failed with
        `couldn't get a connection after 10.00 sec`. In production the failure is worse
        than four errors, because the pool is shared with **every other request the server
        is serving** — a slow identity provider would have stalled agent listings, run
        submissions and health checks alike. Holding a database connection across a
        third-party HTTP call is the classic way to turn somebody else's bad afternoon
        into your own outage, and the blocking lock made it structural.

        So the loser now learns it lost *immediately*, returns its connection, and waits
        outside the pool entirely. At most one connection is held across the exchange, and
        it is held by the thread actually doing the work.

        A **transaction-scoped** lock rather than a session-scoped one, which is the other
        half of being safe on a pool: a session lock outlives the statement that took it
        and is released by name, so a connection handed back still holding one poisons
        every later borrower. The transaction variant is released by COMMIT or ROLLBACK —
        including the rollback a dying process gets for free, so a lost worker cannot wedge
        somebody's connection.

        Two 32-bit keys rather than one 64-bit hash, because the two-argument form gives a
        free namespace: `_LOCK_NAMESPACE` means a refresh can never collide with any other
        advisory lock this schema grows later, which a single hash of a string cannot
        promise.
        """
        import psycopg

        key = _advisory_key(tenant_id, principal_kind, principal_id, connector_id)
        try:
            with self._connection() as conn, conn.transaction():
                held = (
                    conn.cursor()
                    .execute(
                        "SELECT pg_try_advisory_xact_lock(%s, %s)",
                        (_LOCK_NAMESPACE, key),
                    )
                    .fetchone()[0]
                )
                if held:
                    yield True
                    return
                # Fall out of the `with` **before** yielding False, so the connection is
                # back in the pool before the caller does anything slow with the answer.
        except psycopg.Error as exc:
            raise self._translate(exc) from exc

        yield False

    # --- runs -------------------------------------------------------------------

    _RUN_COLUMNS = ", ".join(RUN_FIELDS)

    @staticmethod
    def _run_row(row) -> dict:
        return dict(zip(RUN_FIELDS, row))

    def enqueue_run(self, tenant_id: str, run: dict) -> tuple[dict, bool]:
        import psycopg

        row = normalize_run(run)
        self._require_tenant(tenant_id)

        # The root is the parent's root, read here and never accepted from a caller.
        # A read-then-insert with no lock, and deliberately so: nothing deletes a run
        # and `root_run_id` is immutable by construction, so there is no race for a
        # window to matter. The lookup is tenant-scoped, which is what makes a parent
        # from another customer the same refusal as one that does not exist.
        root_run_id = row["run_id"]
        if row["parent_run_id"] is not None:
            parent = self._fetchone(
                "SELECT root_run_id FROM runs WHERE tenant_id = %s AND run_id = %s",
                (tenant_id, row["parent_run_id"]),
            )
            if parent is None:
                raise ValueRefused(
                    NO_SUCH_PARENT.format(parent=row["parent_run_id"], tenant=tenant_id)
                )
            root_run_id = parent[0]

        # `ON CONFLICT ... DO NOTHING RETURNING` is the whole of the idempotency
        # mechanism, and the reason it is one statement rather than find-then-insert:
        # two retries of the same request arriving together would both find nothing and
        # both insert, which is the exact double-spend this column exists to prevent.
        #
        # The conflict target is the partial index, so it has to be spelled with the
        # same predicate â€” `ON CONFLICT (tenant_id, idempotency_key)` alone does not
        # match a partial index and Postgres refuses it.
        # One statement again, step 028. The file was stored by its own request and the
        # run merely names it, so there is no second write to keep atomic — which is the
        # quiet simplification the id bought back.
        try:
            inserted = self._fetchone(
                f"""
                INSERT INTO runs (
                    run_id, tenant_id, agent, agent_id, principal_kind, principal_id,
                    task, status, idempotency_key, parent_run_id, root_run_id, file_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, idempotency_key) WHERE idempotency_key <> ''
                DO NOTHING
                RETURNING {self._RUN_COLUMNS}
                """,
                (
                    row["run_id"],
                    tenant_id,
                    row["agent"],
                    row["agent_id"],
                    row["principal_kind"],
                    row["principal_id"],
                    row["task"],
                    row["status"],
                    row["idempotency_key"],
                    row["parent_run_id"],
                    root_run_id,
                    row["file_id"],
                ),
            )
        except StorageError as exc:
            cause = exc.__cause__
            if isinstance(cause, psycopg.errors.UniqueViolation):
                # Two unique indexes can refuse this insert, and they are different
                # sentences to different people. `runs_one_live_child` is the
                # linearity rule — the parent's continuation slot is taken, decided by
                # the database so two simultaneous follow-ups have no read-then-write
                # window. Anything else is the global primary key — see migration 015:
                # at 48 bits a collision is a thing that happens rather than a thing
                # somebody did wrong.
                if getattr(cause.diag, "constraint_name", "") == "runs_one_live_child":
                    raise FollowUpConflict(
                        ONE_LIVE_CHILD.format(parent=row["parent_run_id"])
                    ) from exc
                raise StorageError(
                    f"run '{row['run_id']}' already exists. Run ids are unique across "
                    "every tenant, because a worker claims a run by id alone."
                ) from exc
            raise

        if inserted is not None:
            return self._run_row(inserted), True

        # The key was taken. Read back the run it belongs to â€” that row, not the one
        # asked for, is what the caller gets.
        existing = self._fetchone(
            f"SELECT {self._RUN_COLUMNS} FROM runs "
            "WHERE tenant_id = %s AND idempotency_key = %s",
            (tenant_id, row["idempotency_key"]),
        )
        if existing is None:  # pragma: no cover - only if the row vanished between the two
            raise StorageError(
                f"idempotency key '{row['idempotency_key']}' conflicted and then "
                "resolved to no run. Retry."
            )
        return self._run_row(existing), False

    _FILE_COLUMNS = ", ".join(FILE_META_FIELDS)

    def create_file(self, tenant_id: str, row: dict) -> dict:
        import psycopg

        record = normalize_file(row)
        self._require_tenant(tenant_id)

        try:
            stored = self._fetchone(
                f"""
                INSERT INTO files (
                    id, tenant_id, owner_kind, owner_id, filename, media_type,
                    content, sha256, byte_size
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING {self._FILE_COLUMNS}
                """,
                (
                    record["id"],
                    tenant_id,
                    record["owner_kind"],
                    record["owner_id"],
                    record["filename"],
                    record["media_type"],
                    record["content"],
                    record["sha256"],
                    record["byte_size"],
                ),
            )
        except StorageError as exc:
            if isinstance(exc.__cause__, psycopg.errors.UniqueViolation):
                raise StorageError(
                    f"file '{record['id']}' already exists. Ids are 128 bits, so this "
                    "is a caller reusing one rather than a collision — and overwriting "
                    "would hand these bytes to a run somebody else already started."
                ) from exc
            raise

        return dict(zip(FILE_META_FIELDS, stored))

    def get_file(self, tenant_id: str, file_id: str) -> dict | None:
        # `content` is deliberately absent from the column list. Naming it here would
        # make every ownership check and every run detail page pull the file off TOAST
        # to report a size the row already carries.
        row = self._fetchone(
            f"SELECT {self._FILE_COLUMNS} FROM files WHERE tenant_id = %s AND id = %s",
            (tenant_id, file_id),
        )
        return dict(zip(FILE_META_FIELDS, row)) if row is not None else None

    def file_content(self, tenant_id: str, file_id: str) -> bytes | None:
        row = self._fetchone(
            "SELECT content FROM files WHERE tenant_id = %s AND id = %s",
            (tenant_id, file_id),
        )
        # psycopg hands BYTEA back as `memoryview`. Converted here rather than at the
        # call site, so both stores return the same type and a caller can base64 it
        # without knowing which one answered.
        return bytes(row[0]) if row is not None else None

    def get_run(self, tenant_id: str, run_id: str) -> dict | None:
        row = self._fetchone(
            f"SELECT {self._RUN_COLUMNS} FROM runs WHERE tenant_id = %s AND run_id = %s",
            (tenant_id, run_id),
        )
        return self._run_row(row) if row is not None else None

    def find_run(self, tenant_id: str, prefix: str) -> dict | None:
        if not prefix:
            return None

        # LIMIT 2, so "ambiguous" costs the same as "found". The caller only needs to
        # know whether there is exactly one.
        #
        # The prefix is escaped rather than interpolated: a run id is hex today, but
        # this takes a caller-supplied string and `%` in a LIKE pattern is a wildcard
        # that would turn a lookup into a scan matching everything.
        escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        rows = self._fetchall(
            f"SELECT {self._RUN_COLUMNS} FROM runs "
            "WHERE tenant_id = %s AND run_id LIKE %s LIMIT 2",
            (tenant_id, escaped + "%"),
        )
        return self._run_row(rows[0]) if len(rows) == 1 else None

    def list_runs(
        self,
        tenant_id: str,
        *,
        limit: int | None = None,
        status: str | None = None,
        root: str | None = None,
        roots_only: bool = False,
        principal_kind: str | None = None,
        principal_id: str | None = None,
        finished_since=None,
    ) -> list[dict]:
        clauses = ["tenant_id = %s"]
        params: list = [tenant_id]
        if status is not None:
            clauses.append("status = %s")
            params.append(status)
        if root is not None:
            # The `runs_thread` index — one thread, one indexed query.
            clauses.append("root_run_id = %s")
            params.append(root)
        if roots_only:
            clauses.append("parent_run_id IS NULL")
        if principal_kind is not None:
            # The "mine" filter, as a clause rather than a Python `if` above this
            # layer, because a missing scope clause against the real store is exactly
            # the failure the contract suite runs this against Postgres to catch.
            clauses.append("(principal_kind, principal_id) = (%s, %s)")
            params.extend([principal_kind, principal_id])
        if finished_since is not None:
            # Step 013's window, over `runs_finished` (migration 045). `IS NOT NULL` is
            # implied by the comparison and stated anyway, because it is what makes the
            # partial index eligible — without it Postgres cannot prove the predicate
            # holds and falls back to walking `runs_recent` over the tenant's whole
            # history, which is the exact scan the index was added to end.
            clauses.append("finished_at IS NOT NULL AND finished_at >= %s")
            params.append(finished_since)

        # By `seq`, not by `created_at`. Runs submitted inside one clock tick share a
        # timestamp, and ordering them by anything else â€” an id, nothing at all â€” is not
        # an order. See the column comment in migration 015; this was found by running
        # it rather than by reasoning about it.
        sql = (
            f"SELECT {self._RUN_COLUMNS} FROM runs WHERE {' AND '.join(clauses)} "
            "ORDER BY seq DESC"
        )
        if limit is not None:
            sql += " LIMIT %s"
            params.append(max(limit, 0))

        return [self._run_row(row) for row in self._fetchall(sql, tuple(params))]

    def spend_since(
        self,
        tenant_id: str,
        since,
        *,
        principal_kind: str | None = None,
        principal_id: str | None = None,
    ) -> list[dict]:
        # `finished_at IS NOT NULL` spelled out rather than left implied by the
        # comparison: both candidate indexes are partial on it, and without the predicate
        # Postgres cannot prove either applies and falls back to a heap scan of the
        # tenant's history. Same reason `list_runs` spells it.
        clauses = ["tenant_id = %s", "finished_at IS NOT NULL", "finished_at >= %s"]
        params: list = [tenant_id, since]
        if principal_kind is not None:
            # Over `runs_principal_finished` (046). The pair together, never one — a
            # half-applied scope is one person's ceiling counting another's spend.
            clauses.append("(principal_kind, principal_id) = (%s, %s)")
            params.extend([principal_kind, principal_id])

        rows = self._fetchall(
            "SELECT model,"
            "       COALESCE(SUM(input_tokens), 0)      AS input_tokens,"
            "       COALESCE(SUM(output_tokens), 0)     AS output_tokens,"
            "       COALESCE(SUM(cache_read_tokens), 0) AS cache_read_tokens,"
            "       COALESCE(SUM(cache_write_tokens), 0) AS cache_write_tokens"
            f"  FROM runs WHERE {' AND '.join(clauses)}"
            "  GROUP BY model"
            # Written out rather than `ORDER BY 2+3+4+5`: a bare integer in ORDER BY is a
            # column reference, but an *expression* of integers is the constant 14 — which
            # sorts nothing at all, silently, and would have shipped a leaderboard in
            # arbitrary order.
            "  ORDER BY SUM(input_tokens) + SUM(output_tokens)"
            "         + SUM(cache_read_tokens) + SUM(cache_write_tokens) DESC, model",
            tuple(params),
        )
        return [
            {
                "model": row[0],
                "input_tokens": int(row[1]),
                "output_tokens": int(row[2]),
                "cache_read_tokens": int(row[3]),
                "cache_write_tokens": int(row[4]),
            }
            for row in rows
        ]

    def door_spend_since(
        self,
        tenant_id: str,
        since,
        *,
        principal_kind: str,
        principal_id: str,
    ) -> list[dict]:
        # Over `audit_principal_usage` (048). The predicates are in the order the index
        # keys them so the planner can prove it applies; `input_tokens IS NOT NULL` is
        # spelled out for the same reason `spend_since` spells `finished_at IS NOT NULL`
        # — without it Postgres cannot use a partial index and falls back to scanning
        # this tenant's whole audit history, which on an append-only table grows forever.
        #
        # `run_id LIKE %s` with the pattern passed as a parameter, never interpolated:
        # `_DOOR_CALL_PATTERN`'s discipline everywhere else in this file. It selects door
        # calls from runs, and it is a filter rather than an access path — see 048's own
        # note on why `run_id` is not in the index key.
        rows = self._fetchall(
            "SELECT model,"
            "       COALESCE(SUM(input_tokens), 0)       AS input_tokens,"
            "       COALESCE(SUM(output_tokens), 0)      AS output_tokens,"
            "       COALESCE(SUM(cache_read_tokens), 0)  AS cache_read_tokens,"
            "       COALESCE(SUM(cache_write_tokens), 0) AS cache_write_tokens"
            "  FROM audit"
            " WHERE tenant_id = %s"
            "   AND (principal_kind, principal_id) = (%s, %s)"
            "   AND ts >= %s"
            "   AND input_tokens IS NOT NULL"
            "   AND run_id LIKE %s"
            " GROUP BY model"
            # Written out rather than `ORDER BY 2+3+4+5`, which is the constant 14 and
            # sorts nothing — `spend_since`'s recorded mistake, not repeated.
            " ORDER BY SUM(input_tokens) + SUM(output_tokens)"
            "        + SUM(cache_read_tokens) + SUM(cache_write_tokens) DESC, model",
            (
                tenant_id,
                principal_kind,
                principal_id,
                since,
                self._DOOR_CALL_PATTERN,
            ),
        )
        return [
            {
                "model": row[0],
                "input_tokens": int(row[1]),
                "output_tokens": int(row[2]),
                "cache_read_tokens": int(row[3]),
                "cache_write_tokens": int(row[4]),
            }
            for row in rows
        ]

    def tokens_spent_since(self, tenant_id: str, since) -> int:
        # One indexed aggregate over `runs_finished` (migration 045), which is partial on
        # `finished_at IS NOT NULL` — so the predicate is spelled out rather than left
        # implied by the comparison, exactly as in `list_runs`, because without it
        # Postgres cannot prove the index applies and falls back to the tenant's whole
        # history.
        #
        # `COALESCE` because SUM over no rows is NULL, and a tenant that has run nothing
        # today has spent nothing rather than an unknown amount.
        row = self._fetchone(
            "SELECT COALESCE(SUM(input_tokens + output_tokens "
            "                   + cache_read_tokens + cache_write_tokens), 0) "
            "FROM runs "
            "WHERE tenant_id = %s AND finished_at IS NOT NULL AND finished_at >= %s",
            (tenant_id, since),
        )
        return int(row[0])

    def count_recent_runs(
        self, tenant_id: str, principal_kind: str, principal_id: str, *, since
    ) -> tuple:
        # One query for both values, over `runs_by_principal` (migration 034). Strictly
        # `>`: a run at exactly `since` has aged out, matching the Retry-After
        # arithmetic in `runs.submit`, which promises the window frees at oldest+window.
        row = self._fetchone(
            "SELECT count(*), min(created_at) FROM runs "
            "WHERE tenant_id = %s AND principal_kind = %s AND principal_id = %s "
            "AND created_at > %s",
            (tenant_id, principal_kind, principal_id, since),
        )
        return (row[0], row[1])

    def start_run(
        self, tenant_id: str, run_id: str, *, claimed_by: str = ""
    ) -> dict | None:
        # `AND status = 'queued'` in the WHERE rather than checked first. Read-then-write
        # would let two callers both see `queued`; this way exactly one UPDATE matches
        # and the other returns no row. Same property `claim_run` will need â€” this is
        # the one transition that exists today, built the way the next one has to be.
        row = self._fetchone(
            f"""
            UPDATE runs SET status = 'running',
                            started_at = now(),
                            claimed_by = %s,
                            claimed_at = now(),
                            attempt = attempt + 1
            WHERE tenant_id = %s AND run_id = %s AND status = 'queued'
            RETURNING {self._RUN_COLUMNS}
            """,
            (claimed_by, tenant_id, run_id),
        )
        return self._run_row(row) if row is not None else None

    def finish_run(
        self,
        tenant_id: str,
        run_id: str,
        status: str,
        *,
        answer: str | None = None,
        error: str = "",
        usage: dict | None = None,
    ) -> dict | None:
        check_terminal_status(status)
        spent = normalize_usage(usage)

        # 045's six columns, folded into the statement that was happening anyway — 013's
        # decision 2, and the reason a ten-turn run costs one usage write rather than
        # ten. Three different rules, which is why this is built rather than looped:
        #
        #   counters             `col = col + %s`. Indistinguishable from `=` today —
        #                        nothing re-executes a run, see `finish_run`'s contract —
        #                        and written this way because a retry built on `=` would
        #                        lose the first attempt's spend silently.
        #   peak_context_tokens  `GREATEST`. A high-water mark across everything this
        #                        row accounts for, which is a maximum and not a sum.
        #   model                `COALESCE(NULLIF(%s, ''), model)`. Replaced when there
        #                        is something to replace it with, so a second attempt
        #                        that never reached a model call cannot blank what the
        #                        first recorded.
        usage_sql = ""
        usage_params: tuple = ()
        if spent is not None:
            usage_sql = (
                ", model = COALESCE(NULLIF(%s, ''), model)"
                ", input_tokens = input_tokens + %s"
                ", output_tokens = output_tokens + %s"
                ", cache_read_tokens = cache_read_tokens + %s"
                ", cache_write_tokens = cache_write_tokens + %s"
                ", peak_context_tokens = GREATEST(peak_context_tokens, %s)"
            )
            usage_params = (
                spent["model"],
                spent["input_tokens"],
                spent["output_tokens"],
                spent["cache_read_tokens"],
                spent["cache_write_tokens"],
                spent["peak_context_tokens"],
            )

        # `NOT IN (terminal)` for the same reason as above, and with the same
        # consequence: the first outcome recorded is the one kept.
        #
        # `activity = NULL` (038): a terminal run has nothing it is doing, and a stale
        # "waiting on the model" beside a `complete` badge is the two-sources
        # disagreement this table exists to prevent.
        row = self._fetchone(
            f"""
            UPDATE runs SET status = %s, answer = %s, error = %s, finished_at = now(),
                            activity = NULL{usage_sql}
            WHERE tenant_id = %s AND run_id = %s
              AND status IN ('queued', 'running')
            RETURNING {self._RUN_COLUMNS}
            """,
            (status, answer, error or "", *usage_params, tenant_id, run_id),
        )
        return self._run_row(row) if row is not None else None

    def note_activity(self, tenant_id: str, run_id: str, activity: dict) -> None:
        # `AND status = 'running'` is the whole guard, in the statement rather than
        # read-then-write: a note racing a cancellation or a finish matches no row and
        # changes nothing, which is exactly what a progress marker owes a terminal run.
        # Matching nothing is not reported — the writer is the runtime making a
        # best-effort note, and there is no remedy a raise would name.
        self._execute(
            "UPDATE runs SET activity = %s "
            "WHERE tenant_id = %s AND run_id = %s AND status = 'running'",
            (json.dumps(activity), tenant_id, run_id),
        )

    def run_fingerprint(self, tenant_id: str, run_id: str) -> str | None:
        # One statement, because this is the recurring cost of a held wait: the row by
        # primary key, plus an index-only count over `audit_run (tenant_id, run_id, id)`.
        # The count is a cursor because the audit table is append-only by grant
        # revocation (migration 005) — rows are only ever added.
        row = self._fetchone(
            """
            SELECT r.status, r.cancel_requested_at, r.activity,
                   (SELECT count(*) FROM audit a
                     WHERE a.tenant_id = r.tenant_id AND a.run_id = r.run_id)
              FROM runs r
             WHERE r.tenant_id = %s AND r.run_id = %s
            """,
            (tenant_id, run_id),
        )
        if row is None:
            return None
        return compose_run_fingerprint(row[0], row[1], row[2], row[3])

    def request_cancel(
        self, tenant_id: str, run_id: str, *, cancelled_by: str = ""
    ) -> dict | None:
        # One statement for both outcomes, which is what makes them atomic with respect
        # to a claim landing at the same instant. Every SET expression sees the row as it
        # was *before* this update, so `WHEN status = 'queued'` is the same guard the
        # plan's separate `WHERE status = 'queued'` statement would have applied â€” with
        # no window between the two for a worker to claim into.
        #
        # `coalesce` on the timestamp is what makes asking twice a retry rather than an
        # error: the second request keeps the first instant and the first asker.
        #
        # `cancelled` is in the WHERE and it is the whole of the fix for a bug found by
        # running this: a queued run goes straight to `cancelled`, so a *retry* of a
        # perfectly ordinary cancel hit an already-terminal row and was refused. The row
        # is untouched â€” every CASE evaluates to what is already there â€” and returning it
        # is what makes the retry a retry. See CANCELLABLE_RUN_STATUSES.
        row = self._fetchone(
            f"""
            UPDATE runs
               SET cancel_requested_at = CASE WHEN status IN ('queued', 'running')
                                              THEN coalesce(cancel_requested_at, now())
                                              ELSE cancel_requested_at END,
                   cancelled_by = CASE WHEN status IN ('queued', 'running')
                                        AND cancel_requested_at IS NULL
                                       THEN %s ELSE cancelled_by END,
                   status = CASE WHEN status = 'queued'
                                 THEN 'cancelled' ELSE status END,
                   finished_at = CASE WHEN status = 'queued'
                                      THEN now() ELSE finished_at END
             WHERE tenant_id = %s AND run_id = %s
               AND status = ANY(%s)
            RETURNING {self._RUN_COLUMNS}
            """,
            (cancelled_by or "", tenant_id, run_id, sorted(CANCELLABLE_RUN_STATUSES)),
        )
        return self._run_row(row) if row is not None else None

    def set_thread_shared(
        self, tenant_id: str, run_id: str, shared: bool
    ) -> dict | None:
        # `parent_run_id IS NULL` in the WHERE, not checked first: the flag is
        # meaningful on root runs only, and a follow-up's id answers None exactly as
        # an absent or another tenant's id does. The caller has read the row already
        # and tells those apart the way `request_cancel`'s callers do.
        row = self._fetchone(
            f"""
            UPDATE runs SET thread_shared = %s
             WHERE tenant_id = %s AND run_id = %s AND parent_run_id IS NULL
            RETURNING {self._RUN_COLUMNS}
            """,
            (bool(shared), tenant_id, run_id),
        )
        return self._run_row(row) if row is not None else None

    # --- the queue --------------------------------------------------------------

    def claim_run(
        self, worker: str, *, lease_seconds: int, limit_to_tenant: str | None = None
    ) -> dict | None:
        # `FOR UPDATE SKIP LOCKED` is the whole mechanism, and the reason the subselect
        # exists rather than a plain `UPDATE ... LIMIT 1`: the lock has to be taken while
        # choosing, so a second worker choosing at the same instant steps over the locked
        # row instead of blocking on it and then losing.
        #
        # **No tenant filter, and it is the one query in this file without one.** A
        # worker serves every customer; filtering here would mean a worker per tenant.
        # Everything the run then does stays tenant-scoped, because the principal on the
        # row carries the tenant and every layer below takes it from there. This is the
        # shape a reviewer is trained to flag, so: it is deliberate, and the isolation it
        # looks like it is breaking lives one layer up.
        #
        # Migration 037's row-level security cannot reach this query by construction:
        # its policies apply only to `agent_runtime_tenant`, the worker never sets a
        # scope, and an unscoped borrow runs as the login role, which owns the table.
        # That arrangement — role-targeted policies, owner-exempt loops — exists in
        # large part so this query keeps working; see step 029, decision 4.
        #
        # That is still true of *which customer*, and migration 020 adds a filter on
        # **whether** a customer is running. A suspended tenant's queued runs are
        # skipped, not failed — they stay `queued` and are released on resume, because
        # suspension closes doors and cancellation is what ends work. The subquery is
        # aliased so `status` cannot bind to `runs.status` by accident: unqualified, it
        # would resolve to the inner table today and silently correlate to the outer one
        # if `tenants.status` were ever dropped.
        #
        # `limit_to_tenant` is for tests sharing one database. Production passes None.
        where = (
            "status = 'queued' "
            "AND tenant_id IN (SELECT t.id FROM tenants t WHERE t.status = 'active')"
        )
        params: list = [worker, lease_seconds]
        if limit_to_tenant is not None:
            where += " AND tenant_id = %s"
            params.append(limit_to_tenant)

        row = self._fetchone(
            f"""
            UPDATE runs SET status = 'running',
                            claimed_by = %s,
                            claimed_at = now(),
                            lease_expires_at = now() + make_interval(secs => %s),
                            attempt = attempt + 1,
                            started_at = coalesce(started_at, now())
            WHERE run_id = (
                SELECT run_id FROM runs
                WHERE {where}
                -- Arrival order, not `seq`. They agree today. They stop agreeing when
                -- fairness between tenants needs a key that is not arrival order, and
                -- this is the single place that changes.
                ORDER BY created_at
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            RETURNING {self._RUN_COLUMNS}
            """,
            tuple(params),
        )
        return self._run_row(row) if row is not None else None

    def heartbeat_runs(self, worker: str, run_ids: list, *, lease_seconds: int) -> dict:
        if not run_ids:
            return {}

        # `claimed_by = %s` is the scope that matters: one worker cannot renew another's
        # claim, so a worker whose lease already expired and was recovered gets its id
        # back as missing rather than quietly re-taking a run somebody has declared
        # interrupted.
        #
        # The second returned column is cancellation, and it rides along for free â€” these
        # are exactly the rows a worker holds, already being written. It is the reason
        # the broker checks a flag rather than the database: no query per tool call.
        rows = self._fetchall(
            """
            UPDATE runs SET lease_expires_at = now() + make_interval(secs => %s)
            WHERE run_id = ANY(%s) AND status = 'running' AND claimed_by = %s
            RETURNING run_id, cancel_requested_at IS NOT NULL
            """,
            (lease_seconds, list(run_ids), worker),
        )
        return {row[0]: bool(row[1]) for row in rows}

    def recover_expired_runs(self, *, deadline_seconds: int) -> list:
        # One statement for both conditions, and the CASE is what lets a person reading
        # the row learn which fired. Set-based rather than a loop: several workers may
        # run this at once and whichever gets there first takes the rows, so the others
        # find nothing rather than double-reporting.
        rows = self._fetchall(
            f"""
            UPDATE runs SET status = 'interrupted',
                            finished_at = now(),
                            activity = NULL,
                            error = CASE
                                WHEN lease_expires_at < now() THEN %s
                                ELSE %s
                            END
            WHERE status = 'running'
              AND (lease_expires_at < now()
                   OR started_at < now() - make_interval(secs => %s))
            RETURNING {self._RUN_COLUMNS}
            """,
            (LEASE_LOST, DEADLINE_PASSED, deadline_seconds),
        )
        return [self._run_row(row) for row in rows]
