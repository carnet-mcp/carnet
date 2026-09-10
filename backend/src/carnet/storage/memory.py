"""In-memory storage. The implementation the test suite runs against.

This exists so the suite keeps the property it has always had: it starts nothing and
calls nothing, and a full run costs half a second. Introducing a real database into
`pytest` would trade that away for fidelity we can get more cheaply — see
`tests/test_storage_contract.py`, which runs the same assertions here and against
Postgres.

The risk of a fake is that it is more permissive than the real thing, so every rule
Postgres enforces with a constraint is enforced here in Python:

  - a write naming an unknown tenant is refused          (foreign key)
  - a connection names a connector that exists           (foreign key, migration 021)
  - a connector with connected accounts cannot be deleted (the same key, RESTRICT)
  - an agent is keyed by `config["name"]`                (CHECK constraint)
  - a connector manifest may not carry `read_only`       (no such column)
  - reads are ordered                                    (ORDER BY)
  - audit is append-only                                 (revoked UPDATE/DELETE)
  - an administrative record names a principal           (CHECK, migration 022)
  - every in-scope write leaves one                      (the same statement, here the
                                                          same lock)
  - a deleted tenant's id is never reused                (checked, not a key — migration
                                                          029 gives the tombstone no FK)
  - deleting a tenant leaves nothing behind              (ON DELETE CASCADE, here twenty
                                                          collections by hand)

Two rules are deliberately **not** reproduced. The log tables are partitioned by month
in Postgres (migration 030) and are lists here, so an append whose month has no
partition fails there and succeeds here. It cannot be enforced in a list without
inventing partitions to enforce it with — so instead the *boundary* is shared:
`prune_floor` decides what a retention sweep removes and both stores call it, which is
the observable half. `ensure_log_partitions` is a no-op here and the difference is
named on it.

The second is row-level security (migration 037), and the argument is the same shape:
the bug class the policy catches in SQL — a query that forgets its tenant filter —
cannot be written against a dict a tenant key unlocks, and simulating row filtering
would mean re-implementing every method's not-found behaviour, which is a fake that can
lie in a brand-new way. What *is* shared is the invariant behind the policy: under an
ambient tenant scope (`tenancy.current_tenant()`), storage is only ever asked about
that tenant — enforced here by the scope-mismatch guard at the bottom of this module,
which raises where Postgres would filter. Stricter on purpose: it turns a silently
wrong API test into a failing one, and the divergence is pinned by name in the
contract suite.

**Everything is deep-copied on the way in and on the way out.** Handing a caller the
stored dict would let it mutate the store by editing what it read — behaviour no
database has, and the single most common way an in-memory fake lies.
"""

import copy
from collections.abc import Sequence
import functools
import inspect
import threading
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone

from . import tenancy

from .base import (
    AGENT_FIELDS,
    check_sealed_secret,
    normalize_schedule_changes,
    schedule_key_prefix,
    schedule_update_detail,
    BUDGET_REFUSAL_MARKER,
    LEADERBOARD,
    CEILING_REFUSAL_MARKER,
    SPEND_REFUSAL_MARKER,
    check_audit_tokens,
    DOOR_CALL_ID_PREFIX,
    normalize_audit_record,
    FILE_META_FIELDS,
    normalize_external_id,
    normalize_file,
    AGENT_NAME_TAKEN,
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
    DERIVED_CONNECTOR_FIELDS,
    FIRST_VERSION,
    GROUP_LINK_TAKEN,
    GROUP_NAME_TAKEN,
    GROUP_RENAME_TAKEN,
    SCIM_ISSUER_NOT_REGISTERED,
    LEASE_LOST,
    NO_OWNER,
    NO_SUCH_AGENT_TO_SCHEDULE,
    NO_SUCH_AGENT_TO_TRIGGER,
    NO_SUCH_TOKEN_TO_FIRE_AS,
    NO_SUCH_TOKEN_TO_TRIGGER,
    NO_SUCH_CONNECTOR,
    NO_SUCH_CONNECTOR_TO_TRUST,
    NO_SUCH_CONNECTOR_TO_VET,
    NO_SUCH_GROUP,
    OAUTH_APP_FIELDS,
    OAUTH_APP_PUBLIC_FIELDS,
    PENDING_GRANT_FIELDS,
    GRANT_FIELDS,
    OWNER_ROLE,
    OWNER_TAKEN,
    RESTORED_FROM_UNKNOWN,
    VERSION_COLLISION,
    SCHEDULE_FIELDS,
    STATIC_CREDENTIAL,
    TRIGGER_FIELDS,
    RETAINED_LOG_TABLES,
    RETENTION_ACTOR,
    TENANT_STATUSES,
    TOMBSTONE_FIELDS,
    TERMINAL_RUN_STATUSES,
    USAGE_COUNTERS,
    USER_STATUSES,
    AgentNameTaken,
    ConnectorExistsError,
    ConnectorInUseError,
    IssuerConflictError,
    FollowUpConflict,
    LIVE_CHILD_STATUSES,
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
    check_denial_resource_kind,
    check_grant,
    check_oauth_app,
    check_pending_authorization,
    check_pending_role,
    check_platform_role,
    prune_floor,
    check_principal_kind,
    check_terminal_status,
    compose_run_fingerprint,
    check_config_is_storable,
    check_next_fire_at,
    check_outcome,
    check_version_limit,
    check_version_number,
    configs_differ,
    check_version_source,
    make_admin_record,
    make_tombstone,
    normalize_email,
    normalize_host,
    normalize_idp,
    normalize_authorize_params,
    normalize_run,
    normalize_scope_notes,
    normalize_scopes,
    normalize_usage,
    describe_cadence,
    normalize_api_token,
    personal_name_taken,
    service_name_taken,
    normalize_schedule,
    normalize_trigger,
    normalize_user,
    normalize_user_external_id,
    normalize_scim_token,
    normalize_vetted_tool,
    check_binding_kind,
    new_agent_id,
    split_actor,
    _UNSET,
    normalize_oauth_client,
    normalize_oauth_code,
)


def _level(role: str) -> int:
    return AGENT_ROLES.index(role)


def _as_datetime(ts):
    """A record's `ts` as something comparable, whatever it was stored as.

    Postgres hands back a `datetime` because the column is TIMESTAMPTZ; this store keeps
    whatever the caller passed, and callers pass both — `core/audit.py` builds a
    `datetime` and several tests pass an ISO string. Comparing those raises rather than
    answering wrongly, so the fake normalises where the column would have.
    """
    if isinstance(ts, str):
        parsed = datetime.fromisoformat(ts)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts


class InMemoryStorage:
    """A `Storage` implementation backed by dicts, safe for concurrent use.

    This said "not thread-safe, deliberately: the runtime is a single-threaded loop,
    and a lock here would imply otherwise." That was true and stopped being true when
    an HTTP server put two requests in flight at once — and a fake that is unsafe where
    the real implementation is safe is a fake that lies in the direction that matters,
    since the whole point of the contract suite is that behaviour does not depend on
    which store is underneath.

    One coarse lock rather than a fine-grained scheme. Contention is irrelevant here:
    this is a dict, the operations are microseconds, and the only process that runs
    against it in anger is the test suite.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._tenants: dict[str, dict] = {}
        # Migration 029. Keyed by tenant id, which is the table's primary key — and the
        # reason it is: an id here is one that may never be issued again, so a dict that
        # allowed two rows for one id would be a fake permitting the exact ambiguity the
        # table exists to prevent. Outlives every other collection here by design.
        self._tombstones: dict[str, dict] = {}
        # tenant -> **agent_id** -> a **row**, not a config. See `AGENT_FIELDS`: this store
        # used to keep `copy.deepcopy(config)` here and nothing else, which is why the
        # `updated_at` three handoffs called "the obvious ETag" could not be read.
        #
        # **Keyed by id since migration 035, and that is the whole of this store's half of
        # step 025.** It was keyed by name, which made a fake whose agents could not be
        # renamed — faithful to the old schema and to nothing else. Name lookups go through
        # `_agent_by_name`, which is a scan: `agents_name_unique` is what Postgres uses and
        # a dict of this size makes an index a fiction with a maintenance cost.
        self._agents: dict[str, dict[str, dict]] = {}
        self._connectors: dict[str, dict[str, dict]] = {}
        # (tenant, connector) -> the review record for its vetted tools. Separate from
        # the manifest because it is separate in the database, and for the reason it is
        # separate there: provenance is not something a caller asserts by passing a dict.
        self._vetting: dict[tuple, list[dict]] = {}
        # Keyed by (tenant, host) — migration 023's primary key. Hosts this tenant will
        # let us dial, and **an absent tenant here denies everything**: that reading lives
        # in `tools/mcp/egress.py` rather than in this dict, so a store cannot be the
        # thing that decides a policy question by what it happens to have in it.
        self._egress: dict[tuple, dict] = {}
        # One flat list, filtered on read. Insertion order IS the ordering guarantee,
        # which is what `audit_records` documents and what BIGINT IDENTITY gives us
        # in Postgres.
        self._audit: list[tuple] = []
        # Migration 022, and a second flat list for the same reason the first is one:
        # insertion order IS the ordering guarantee, which is what BIGINT IDENTITY gives
        # in Postgres. Separate from `_audit` because the two tables are separate, and
        # for the reason they are — see the migration.
        self._admin: list[tuple] = []
        # Migration 028, and a third flat list for the same reason as the other two:
        # insertion order IS the ordering guarantee, which is what BIGINT IDENTITY
        # gives in Postgres. Records vanish at exit, which is true of every table here;
        # the contract suite still holds the shape.
        self._denials: list[tuple] = []
        # Keyed by (issuer, discriminator_claim, discriminator_value) — the same
        # UNIQUE the table declares, so a conflict here is the conflict there.
        self._idps: dict[tuple, dict] = {}
        # Keyed by our opaque user id. `(issuer, subject)` uniqueness is enforced in
        # `create_user`, matching the table's second UNIQUE.
        self._users: dict[str, dict] = {}
        # Migration 031. Keyed by the token's own opaque id, which is the table's primary
        # key — and unlike every other collection here the key is global rather than
        # tenant-prefixed, because `find_api_token` produces a tenant rather than taking
        # one. `UNIQUE (tenant_id, name)` is enforced in `create_api_token`, matching
        # `create_user`'s treatment of the second UNIQUE on `users`.
        self._api_tokens: dict[str, dict] = {}
        # Migration 052. `_api_tokens`' shape exactly, for `_api_tokens`' reason:
        # `find_scim_token` produces a tenant rather than taking one, so the key is the
        # global id and the collection goes in the *second* loop of `delete_tenant`.
        self._scim_tokens: dict[str, dict] = {}
        # Migration 040. Keyed by (tenant, token_id, window_start) — the table's primary
        # key — so unlike `_api_tokens` beside it this one *is* tenant-prefixed and goes
        # in the first loop of `delete_tenant`. The value is a bare int rather than a
        # row dict: the table has exactly one non-key column, and a dict wrapping one
        # integer is a shape somebody later reads as though it had provenance in it.
        self._mcp_budget: dict[tuple, int] = {}
        # Migration 033. Keyed by the schedule's own opaque id, which is the table's
        # primary key — so like `_api_tokens` and unlike most of this class, the key is
        # global rather than tenant-prefixed. **That is what puts it in the second loop of
        # `delete_tenant` rather than the first**, and the first loop is the one somebody
        # adding a collection copies.
        self._schedules: dict[str, dict] = {}
        # Migration 034. `_schedules`' shape exactly, including the delete_tenant caveat.
        self._triggers: dict[str, dict] = {}
        # Keyed by (tenant, **agent_id**, grantee_kind, grantee_id) — renamed by migration
        # 017, re-keyed by 035, and the shape is still the table's primary key. A grantee
        # may be a group; nothing keyed anywhere else in this class may be.
        self._grants: dict[tuple, dict] = {}
        # Migration 032, re-keyed by 035. Keyed by (tenant, **agent_id**, version) — the
        # table's primary key, flat rather than a list per agent so the delete cascade below
        # is the same loop `_grants` uses and cannot forget an agent it did not think of.
        self._versions: dict[tuple, dict] = {}
        # Keyed by (tenant, group_id).
        self._groups: dict[tuple, dict] = {}
        # Keyed by (tenant, group_id, principal_kind, principal_id) — the table's primary
        # key. `principal_kind`, so a group cannot be a member of a group.
        self._members: dict[tuple, dict] = {}
        # Migration 026. Keyed by (tenant, principal_kind, principal_id, role) — the
        # table's primary key, role included, so holding two roles is two rows rather
        # than an overwrite. `principal_kind` rather than `grantee_kind`: a group cannot
        # hold one, which is the whole point of the CHECK this dict stands in for.
        self._platform_roles: dict[tuple, dict] = {}
        # Keyed by (tenant, **agent_id**, email) — a grant waiting on a first login.
        self._pending: dict[tuple, dict] = {}
        # Keyed by (tenant, principal_kind, principal_id, connector) — the table's
        # primary key, and the same tuple the ciphertext is bound to.
        self._connections: dict[tuple, dict] = {}
        # Migration 024. Keyed by (tenant, connector) — the table's primary key. Holds a
        # sealed client secret, which is why `list_connector_oauth` projects it away
        # rather than the callers remembering not to look.
        self._oauth_apps: dict[tuple, dict] = {}
        # Keyed by `state` alone, because that IS the table's primary key: the callback
        # arrives with no tenant and no principal, so nothing else is available to key on.
        self._pending_authorizations: dict[str, dict] = {}
        # Migration 053. Keyed by id and by code hash; the code carries its tenant.
        self._oauth_clients: dict[str, dict] = {}
        self._oauth_codes: dict[str, dict] = {}
        # One `threading.Lock` per connection, minted on demand. Not a table and not
        # durable — see `refresh_lock` for why that is a genuinely weaker guarantee than
        # the Postgres store's and what follows from it.
        self._refresh_locks: dict[tuple, threading.Lock] = {}
        # Keyed by run_id alone, because migration 015 makes it the primary key of the
        # whole table rather than of a tenant's slice. A fake that keyed this by
        # (tenant, run) would accept a collision Postgres refuses.
        self._runs: dict[str, dict] = {}
        # `runs.seq`, the ordering column — kept beside the rows rather than in them so
        # a row handed to a caller carries exactly the fields the table exposes. Python
        # dicts preserve insertion order and this could read it off them, but that is
        # O(n) per lookup and, more to the point, it would be relying on a language
        # guarantee to stand in for a column Postgres actually has.
        self._run_seq: dict[str, int] = {}
        # Step 028. Keyed by the file id alone, mirroring the table, where the id is the
        # primary key and is global rather than per tenant — a caller quotes it back on a
        # later request, so the lookup that resolves it must name one row. The tenant
        # lives inside the row, which puts this in the group `delete_tenant` sweeps by
        # value rather than by key.
        self._files: dict[str, dict] = {}

    # --- lifecycle ---------------------------------------------------------------

    def ping(self) -> None:
        """Ready whenever the process is — an in-memory store has no ground to lose.

        See `Storage.ping`: the readiness probe's round trip. Nothing to do here, and
        that is the honest answer rather than a stub — this store's availability IS
        the process's.
        """

    def pool_stats(self) -> dict:
        """No pool, no numbers — `{}` is the honest answer, not zeros pretending."""
        return {}

    def close(self) -> None:
        """Nothing to release. See `Storage.close` for why this exists anyway.

        Deliberately does **not** clear the collections: `close` means *give back what
        you borrowed*, and a fake that emptied itself would make "close the store" a
        destructive operation on one implementation and not the other — the exact
        asymmetry the contract suite exists to prevent. `storage.reset()` is how a
        caller discards state.
        """

    def verify_tenant_isolation(self) -> None:
        """Nothing to verify. See `Storage.verify_tenant_isolation` for why it exists.

        There are no roles and no policies here. The half of step 029 this store *can*
        hold — under an ambient scope, storage is only ever asked about that tenant —
        is enforced on every call by the scope-mismatch guard at the bottom of this
        module, which needs no startup check because it cannot be misconfigured.
        """

    # --- tenants ----------------------------------------------------------------

    def create_tenant(self, tenant_id: str, name: str) -> None:
        if not tenant_id:
            raise StorageError("tenant_id must be a non-empty string")
        with self._lock:
            # Migration 029. There is no foreign key doing this in Postgres either —
            # `tenant_tombstones` deliberately has none to `tenants` — so both stores
            # check it, which is also what keeps the two refusals identical.
            gone = self._tombstones.get(tenant_id)
            if gone is not None:
                raise TenantDeleted(
                    f"tenant '{tenant_id}' was deleted on "
                    f"{gone['deleted_at']:%Y-%m-%d} by {gone['actor']} and its id is "
                    "never reused. Choose another id."
                )

            if tenant_id in self._tenants:
                return
            self._tenants[tenant_id] = {
                "id": tenant_id,
                "name": name,
                "status": "active",
                "created_at": datetime.now(timezone.utc),
            }
            self._agents[tenant_id] = {}
            self._connectors[tenant_id] = {}

    def get_tenant(self, tenant_id: str) -> dict | None:
        with self._lock:
            row = self._tenants.get(tenant_id)
            return copy.deepcopy(row) if row is not None else None

    def list_tenants(self) -> list[dict]:
        with self._lock:
            return [copy.deepcopy(self._tenants[k]) for k in sorted(self._tenants)]

    def set_tenant_status(self, tenant_id: str, status: str) -> None:
        if status not in TENANT_STATUSES:
            raise StorageError(
                f"status must be one of {sorted(TENANT_STATUSES)}, not '{status}'"
            )
        with self._lock:
            row = self._tenants.get(tenant_id)
            if row is None:
                return
            row["status"] = status

    def delete_tenant(self, tenant_id: str, *, actor: str) -> dict:
        with self._lock:
            row = self._tenants.get(tenant_id)
            if row is None:
                raise UnknownTenantError(
                    f"tenant '{tenant_id}' does not exist. Create it before writing "
                    "to it."
                )

            if row["status"] != "suspended":
                raise TenantDeletionRefused(
                    f"tenant '{tenant_id}' is {row['status']}. Suspend it first — "
                    "deletion is not the brake, and a customer who can still "
                    "authenticate can create rows while this runs."
                )

            live = sorted(
                run_id
                for run_id, run in self._runs.items()
                if run["tenant_id"] == tenant_id and run["status"] == "running"
            )
            if live:
                raise TenantDeletionRefused(
                    f"tenant '{tenant_id}' has {len(live)} run(s) still executing: "
                    f"{', '.join(live)}. Cancel them or wait — suspension does not "
                    "stop a run in flight."
                )

            # Built before anything is touched — `make_tombstone` is the only thing on
            # this path that can raise, so building it first is what makes a bad actor
            # leave the store untouched rather than half-erased. The same ordering
            # `_append_admin` documents, for the same reason: Postgres gets this from a
            # transaction and this store gets it from the order.
            counts = {
                "runs": sum(
                    1 for r in self._runs.values() if r["tenant_id"] == tenant_id
                ),
                "groups": sum(1 for key in self._groups if key[0] == tenant_id),
                "access_denials": sum(1 for t, _ in self._denials if t == tenant_id),
                "admin_audit": sum(1 for t, _ in self._admin if t == tenant_id),
                "audit": sum(1 for t, _ in self._audit if t == tenant_id),
            }
            tombstone = make_tombstone(tenant_id, row["name"], actor, counts)
            tombstone["deleted_at"] = datetime.now(timezone.utc)

            # Everything Postgres does by cascade, by hand — the shape of fake the
            # contract suite exists to catch is not one that refuses what Postgres
            # accepts, it is one that KEEPS what Postgres removes. `delete_agent` learnt
            # that about `agent_grants`; this is the same lesson over twenty
            # collections, and the "nothing left behind" contract test is what holds it.
            self._tenants.pop(tenant_id, None)
            self._agents.pop(tenant_id, None)
            self._connectors.pop(tenant_id, None)

            self._audit = [rec for rec in self._audit if rec[0] != tenant_id]
            self._admin = [rec for rec in self._admin if rec[0] != tenant_id]
            self._denials = [rec for rec in self._denials if rec[0] != tenant_id]

            # Keyed by a tuple whose first element is the tenant.
            for collection in (
                self._vetting,
                self._egress,
                self._grants,
                self._versions,
                self._groups,
                self._members,
                self._platform_roles,
                self._pending,
                self._connections,
                self._oauth_apps,
                self._refresh_locks,
                self._mcp_budget,
            ):
                for key in [k for k in collection if k[0] == tenant_id]:
                    del collection[key]

            # Keyed by something else, with the tenant *inside* the row. These are the
            # ones a loop over keys would silently miss.
            for key in [
                k for k, v in self._idps.items() if v["tenant_id"] == tenant_id
            ]:
                del self._idps[key]
            for key in [
                k for k, v in self._users.items() if v["tenant_id"] == tenant_id
            ]:
                del self._users[key]
            for key in [
                k for k, v in self._api_tokens.items() if v["tenant_id"] == tenant_id
            ]:
                del self._api_tokens[key]
            # Migration 052. Postgres gets this from `ON DELETE CASCADE`; a fake that
            # kept the directory's credential past its customer is the drift the
            # "nothing left behind" test exists to catch.
            for key in [
                k for k, v in self._scim_tokens.items() if v["tenant_id"] == tenant_id
            ]:
                del self._scim_tokens[key]
            # Migration 053: `oauth_codes` cascades from `tenants`; `oauth_clients`
            # has no tenant and survives, exactly as Postgres leaves it.
            for key in [
                k for k, v in self._oauth_codes.items() if v["tenant_id"] == tenant_id
            ]:
                del self._oauth_codes[key]
            for key in [
                k for k, v in self._schedules.items() if v["tenant_id"] == tenant_id
            ]:
                del self._schedules[key]
            for key in [
                k for k, v in self._triggers.items() if v["tenant_id"] == tenant_id
            ]:
                del self._triggers[key]
            for key in [
                k
                for k, v in self._pending_authorizations.items()
                if v["tenant_id"] == tenant_id
            ]:
                del self._pending_authorizations[key]
            # Step 028. Postgres gets this from the cascade on `files.tenant_id`; this
            # store has none, which is the exact shape of drift the contract suite's
            # "nothing left behind" test exists to catch — a fake that KEEPS what
            # Postgres removes.
            for key in [
                k for k, v in self._files.items() if v["tenant_id"] == tenant_id
            ]:
                del self._files[key]
            for key in [
                k for k, v in self._runs.items() if v["tenant_id"] == tenant_id
            ]:
                del self._runs[key]
                self._run_seq.pop(key, None)

            # Projected through `TOMBSTONE_FIELDS` rather than stored as built, so this
            # store hands back exactly the columns the table has, in the order the
            # Postgres SELECT lists them. A field added to one and forgotten in the
            # other is then a contract-suite failure rather than a silent difference.
            row = {key: tombstone[key] for key in TOMBSTONE_FIELDS}
            self._tombstones[tenant_id] = copy.deepcopy(row)
            return copy.deepcopy(row)

    def prune_log_records(self, cutoff) -> dict:
        # **The same boundary Postgres applies, from the same function.** There the floor
        # is forced by the physics — a partition is a whole month and a drop takes all of
        # it — and here nothing would stop this store deleting at the exact instant. That
        # is precisely why it must not: a fake that is *more* precise than the real store
        # makes every caller written against it wrong about which records survive, which
        # is the drift the contract suite exists to catch, in the direction that is
        # hardest to notice.
        floor = prune_floor(cutoff)

        with self._lock:
            counts = {table: 0 for table in RETAINED_LOG_TABLES}
            per_tenant: dict[str, dict] = {}

            for table, collection in (
                ("audit", "_audit"),
                ("admin_audit", "_admin"),
                ("access_denials", "_denials"),
            ):
                kept = []
                for tenant_id, record in getattr(self, collection):
                    # Strictly `<`, matching Postgres: a record stamped exactly at the
                    # boundary survives, and a boundary has to have one answer.
                    if _as_datetime(record["ts"]) < floor:
                        counts[table] += 1
                        bucket = per_tenant.setdefault(tenant_id, {})
                        bucket[table] = bucket.get(table, 0) + 1
                    else:
                        kept.append((tenant_id, record))
                setattr(self, collection, kept)

            # After the deletes, and appended rather than folded into the loop above, so
            # a record written by this sweep is never removed by it — the same ordering
            # the Postgres store gets from writing them in a later transaction.
            for tenant_id, rows in sorted(per_tenant.items()):
                if tenant_id not in self._tenants:
                    # The tenant went while its records aged out. Postgres cannot write
                    # this record either — the foreign key refuses it — so neither does
                    # this, rather than the fake keeping a row the real store rejects.
                    continue
                self._append_admin(
                    tenant_id,
                    make_admin_record(
                        "retention.prune",
                        "tenant",
                        tenant_id,
                        RETENTION_ACTOR,
                        # The effective boundary, matching Postgres — see `prune_floor`.
                        {"cutoff": floor.isoformat(), "rows": rows},
                    ),
                )

            return counts

    def ensure_log_partitions(self, *, back_to=None) -> list:
        """Nothing to create: this store holds lists, and a list has no months.

        Present rather than absent because the worker calls it against whichever store
        is configured, and a method that exists on one side of that seam is exactly the
        drift the contract suite exists to catch. It returns `[]` for the same reason
        Postgres does when coverage is already complete, so a caller cannot tell the two
        situations apart by the shape of the answer — only by the store it is holding.

        `back_to` is accepted and ignored, deliberately: an append here can never fail
        for want of a partition, so a back-dated write needs no preparation. A caller
        written against this store and then pointed at Postgres is the case
        `missing_partition`'s sentence exists for.
        """
        return []

    def get_tenant_tombstone(self, tenant_id: str) -> dict | None:
        with self._lock:
            row = self._tombstones.get(tenant_id)
            return copy.deepcopy(row) if row is not None else None

    def list_tenant_tombstones(self) -> list[dict]:
        with self._lock:
            return [
                copy.deepcopy(row)
                for row in sorted(
                    self._tombstones.values(),
                    key=lambda r: (r["deleted_at"], r["tenant_id"]),
                    reverse=True,
                )
            ]

    def _tenant_is_active(self, tenant_id: str) -> bool:
        """Caller holds the lock. Unknown tenants are not active — the claim loop's
        one use of this would otherwise treat a run whose customer vanished as
        claimable, and Postgres cannot produce that row at all."""
        row = self._tenants.get(tenant_id)
        return row is not None and row["status"] == "active"

    def _require_tenant(self, tenant_id: str) -> None:
        """The foreign key. Enforced on writes only, matching Postgres: reading an
        unknown tenant is an empty result, writing to one is an error."""
        if tenant_id not in self._tenants:
            raise UnknownTenantError(
                f"tenant '{tenant_id}' does not exist. Create it before writing to it."
            )

    # --- agents -----------------------------------------------------------------

    def _agent_by_name(self, tenant_id: str, name: str) -> dict | None:
        """This tenant's agent row by name, or None. `agents_name_unique`, as a scan.

        Migration 035 made the id the key, so every caller that arrives with a name — which
        is all of them above `storage/`, by step 025's decision that the name stays the
        address — comes through here. A scan rather than a second dict: an index would have
        to be maintained by every write and by the rename, and a stale index is a fake that
        answers a question Postgres would answer differently. Over the handful of agents a
        test holds, the scan is the cheaper correctness.
        """
        for row in self._agents.get(tenant_id, {}).values():
            if row["name"] == name:
                return row
        return None

    def _agent_id_of(self, tenant_id: str, name: str) -> str | None:
        """`_agent_by_name`, as an id. What the child collections are keyed by."""
        row = self._agent_by_name(tenant_id, name)
        return None if row is None else row["agent_id"]

    def _agent_name_of(self, tenant_id: str, agent_id: str) -> str | None:
        """The join. What Postgres does with `_agent_name_expr` and for the same reason.

        The child tables hold no name since migration 035, and every row they hand back
        still carries one — so this is where it comes from, on the way out, always current.
        """
        row = self._agents.get(tenant_id, {}).get(agent_id)
        return None if row is None else row["name"]

    def _with_agent_name(self, row: dict, fields: tuple) -> dict:
        """A stored child row, projected through `fields` with `agent_name` filled in.

        The counterpart of `_child_columns` in the Postgres store: the FIELDS tuples still
        carry `agent_name`, the collections do not store one, and both stores derive it. A
        deep copy, because everything this store hands out is a copy.
        """
        out = {}
        for field in fields:
            if field == "agent_name":
                out[field] = self._agent_name_of(row["tenant_id"], row["agent_id"])
            else:
                out[field] = copy.deepcopy(row[field])
        return out

    def _next_version(self, tenant_id: str, agent_id: str, config: dict) -> int:
        """What this write makes the agent's version. Step 021.

        The Postgres half is an expression inside the writing statement —
        `version + (config IS DISTINCT FROM %s)::int` — and this is the same rule where
        this store keeps its equivalent of a transaction, under `_lock`.

        **The comparison is between parsed structures in both stores**, which is what
        makes them agree: `jsonb IS DISTINCT FROM jsonb` ignores key order and whitespace
        exactly as a Python dict comparison does. Comparing serialized text here would
        have made the fake see a change Postgres does not on a config whose keys were
        merely reordered — parity drift produced by the one line that looks obviously
        equivalent.
        """
        previous = self._agents.get(tenant_id, {}).get(agent_id)
        if previous is None:
            return FIRST_VERSION
        return previous["version"] + configs_differ(previous["config"], config)

    def _check_version_write(
        self,
        tenant_id: str,
        agent_id: str,
        name: str,
        version: int,
        config: dict,
        source: str,
        restored_from: int | None,
    ) -> bool:
        """Everything about a version write that can refuse. True = write nothing.

        **Split out of `_write_version` because this store has no transaction**, and the
        edge hunt found what that costs. `update_agent` wrote the agent dict and *then*
        called the version write, so a refusal there left the config changed and no
        version recorded — precisely the artifact `test_a_write_whose_record_is_refused_
        leaves_nothing_behind` exists to prevent, in the store that test cannot run
        against (it is Postgres-only, because it forces a constraint violation).

        The fake's whole transaction story is *one lock, and nothing that can raise
        between the mutations* — `create_agent`'s comment has said so since 10c. Adding a
        raising call after the first mutation broke that quietly. So the refusals happen
        here, before anything moves, and `_write_version` is left with no way to fail.
        """
        check_version_source(source)
        if restored_from is not None:
            # A `bool` reaches Postgres as a boolean and the column is an integer, so
            # `restored_from=True` was a driver error there and version 1 here — `True`
            # hashes as `1` in this dict's key. `check_version_number` refuses both.
            check_version_number(restored_from, what="restored_from")
            # Migration 032's self-referential foreign key, by hand. Without it the fake
            # accepts `restored_from=99` on an agent with two versions and Postgres does
            # not, which is the drift the contract suite exists to catch.
            if (tenant_id, agent_id, restored_from) not in self._versions:
                raise ValueRefused(
                    RESTORED_FROM_UNKNOWN.format(version=restored_from, agent=name)
                )

        existing = self._versions.get((tenant_id, agent_id, version))
        if existing is None:
            return False
        # Verified rather than assumed — Postgres' `ON CONFLICT` half, and the same
        # reasoning: keeping a row that holds a *different* config would leave the live
        # configuration recorded nowhere while the history claimed to hold it.
        if configs_differ(existing["config"], config):
            raise ValueRefused(VERSION_COLLISION.format(version=version, agent=name))
        return True

    def _write_version(
        self,
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
        """One `agent_versions` row, under the caller's lock. `_write_admin`'s shape.

        Keeping a row that is already there is Postgres' `ON CONFLICT DO NOTHING`, and it
        means the same thing here: the caller's `_next_version` did not advance, so this
        write changed no configuration and the version it names already holds this exact
        config. That is how a re-run `--seed` adds nothing to a history.

        **No `agent_name` is stored**, since migration 035 dropped the column. `name` is
        here for the refusals in `_check_version_write` and for nothing else; readers derive
        the name through `_with_agent_name`.
        """
        if self._check_version_write(
            tenant_id, agent_id, name, version, config, source, restored_from
        ):
            return
        key = (tenant_id, agent_id, version)
        row = {
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "version": version,
            "config": copy.deepcopy(config),
            "created_at": created_at,
            "created_by": created_by,
            "source": source,
            "restored_from": restored_from,
        }
        # Projected through the tuple for the reason `_agent_row` is: this store's idea
        # of a row is the object Postgres builds its SELECT list from. `agent_name` is
        # skipped here and filled in on read — it is not a column any more.
        self._versions[key] = {
            field: row[field] for field in AGENT_VERSION_FIELDS if field != "agent_name"
        }

    def _agent_row(
        self,
        tenant_id: str,
        agent_id: str,
        name: str,
        config: dict,
        created_at,
        version: int,
    ) -> dict:
        """One `agents` row, with `AGENT_FIELDS` and nothing else.

        `updated_at` is **strictly after** whatever the row carried, rather than simply
        `now()`. Postgres gets that free: `now()` is the transaction's start and two
        transactions cannot begin in the same microsecond across a round trip. This store
        has no round trip, so two writes inside one test can land on one clock reading —
        and a compare-and-set whose new ETag equals the old one is a guard that silently
        does not guard. Stricter than the real store in a direction that cannot hide a
        bug, which is the one direction `memory.py`'s docstring permits.
        """
        now = datetime.now(timezone.utc)
        previous = self._agents.get(tenant_id, {}).get(agent_id)
        if previous is not None and now <= previous["updated_at"]:
            now = previous["updated_at"] + timedelta(microseconds=1)

        row = {
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "name": name,
            "config": copy.deepcopy(config),
            "created_at": created_at if created_at is not None else now,
            "updated_at": now,
            "version": version,
        }
        # Projected through the tuple rather than returned as written, so this store's
        # idea of a row is the same object Postgres builds its SELECT list from.
        return {key: row[key] for key in AGENT_FIELDS}

    def load_agents(self, tenant_id: str) -> list[dict]:
        with self._lock:
            # Still `ORDER BY name`, which is what the Postgres statement says and what a
            # person reading a list expects — the dict is keyed by id now, so the sort is
            # explicit rather than a property of the key.
            rows = self._agents.get(tenant_id, {}).values()
            return [
                copy.deepcopy(row) for row in sorted(rows, key=lambda r: r["name"])
            ]

    def get_agent(self, tenant_id: str, name: str) -> dict | None:
        with self._lock:
            row = self._agent_by_name(tenant_id, name)
            return copy.deepcopy(row) if row is not None else None

    def get_agent_by_id(self, tenant_id: str, agent_id: str) -> dict | None:
        if not agent_id:
            return None
        with self._lock:
            # The dict's own key since migration 035, so this is the cheap lookup and
            # `get_agent` is the scan — the inverse of what this store used to be.
            row = self._agents.get(tenant_id, {}).get(agent_id)
            return copy.deepcopy(row) if row is not None else None

    def save_agent(self, tenant_id: str, config: dict, *, actor: str) -> None:
        with self._lock:
            self._require_tenant(tenant_id)

            # Postgres cannot key the row without a name, and the broker cannot
            # attribute an audit record without one; migration 019 additionally fixes
            # its shape. Structural, not policy — whether the *grants* are sane is
            # agents/ business.
            check_agent_name(config.get("name"))
            check_config_is_storable(config)

            name = config["name"]
            record = make_admin_record(
                "agent.save",
                "agent",
                name,
                actor,
                agent_detail(config),
            )
            # `ON CONFLICT (tenant_id, name) ... DO UPDATE` keeps the original `created_at`,
            # so this does too. An upsert that reset it would make "when was this agent
            # made" mean "when was it last seeded".
            #
            # **And it keeps the original `agent_id`**, which is the same rule one column
            # over and matters more: `--seed` runs on every boot, and an upsert that minted
            # a new identity each time would detach every grant, schedule and trigger from
            # the shipped agents on restart. The id is minted only when there is no row.
            existing = self._agents[tenant_id].get(
                self._agent_id_of(tenant_id, name) or ""
            )
            agent_id = existing["agent_id"] if existing else new_agent_id()
            version = self._next_version(tenant_id, agent_id, config)
            row = self._agent_row(
                tenant_id,
                agent_id,
                name,
                config,
                existing["created_at"] if existing else None,
                version,
            )
            # **Every refusal before the first mutation**, which is this store's whole
            # version of Postgres' transaction. See `_check_version_write`.
            suppressed = self._check_version_write(
                tenant_id, agent_id, name, version, config, "save", None
            )

            self._agents[tenant_id][agent_id] = row
            self._append_admin(tenant_id, record)
            if not suppressed:
                self._write_version(
                    tenant_id,
                    agent_id,
                    name,
                    version,
                    config,
                    row["updated_at"],
                    actor,
                    "save",
                )

    def update_agent(
        self,
        tenant_id: str,
        config: dict,
        *,
        actor: str,
        if_unchanged_since,
        restored_from: int | None = None,
    ) -> dict | None:
        check_agent_name(config.get("name"))
        check_config_is_storable(config)
        name = config["name"]

        # One parameter decides all three — see `update_agent` in base.py, and migration
        # 032's `agent_version_restore_names_one` for the same rule in the schema.
        source = "update" if restored_from is None else "restore"
        record = make_admin_record(
            f"agent.{source}", "agent", name, actor, agent_detail(config)
        )

        with self._lock:
            self._require_tenant(tenant_id)

            existing = self._agent_by_name(tenant_id, name)
            # The `WHERE ... AND updated_at = %s` half, and the one line this method
            # exists for. Absent and stale are both None here, deliberately — see
            # `update_agent` in base.py.
            if existing is None or existing["updated_at"] != if_unchanged_since:
                return None

            agent_id = existing["agent_id"]
            version = self._next_version(tenant_id, agent_id, config)
            row = self._agent_row(
                tenant_id, agent_id, name, config, existing["created_at"], version
            )
            suppressed = self._check_version_write(
                tenant_id, agent_id, name, version, config, source, restored_from
            )

            self._agents[tenant_id][agent_id] = row
            self._append_admin(tenant_id, record)
            if not suppressed:
                self._write_version(
                    tenant_id,
                    agent_id,
                    name,
                    version,
                    config,
                    row["updated_at"],
                    actor,
                    source,
                    restored_from,
                )
            return copy.deepcopy(row)

    def create_agent(
        self,
        tenant_id: str,
        config: dict,
        owner_kind: str,
        owner_id: str,
    ) -> None:
        check_agent_name(config.get("name"))
        check_config_is_storable(config)
        check_principal_kind(owner_kind)
        if not owner_id:
            raise StorageError(NO_OWNER)

        name = config["name"]

        # **One lock for both writes**, which is this store's whole version of the
        # transaction Postgres opens. It is a weaker guarantee than the real one — a
        # process that dies mid-block leaves nothing behind either way, because the
        # store dies with it — and it is the same *observable* behaviour, which is what
        # the contract suite compares. Nothing here can raise between the two dict
        # writes; the checks that can raise all happen above.
        # The owner is the actor: creating a thing is what makes you its owner.
        record = make_admin_record(
            "agent.create",
            "agent",
            name,
            f"{owner_kind}:{owner_id}",
            {**agent_detail(config), "owner": f"{owner_kind}:{owner_id}"},
        )

        with self._lock:
            self._require_tenant(tenant_id)

            if self._agent_by_name(tenant_id, name) is not None:
                # `agents_name_unique`, migration 035's — the primary key until then.
                # Refused rather than replaced: see `create_agent` in base.py, where the
                # reason is the point of the method.
                raise AgentNameTaken(AGENT_NAME_TAKEN.format(agent=name))

            agent_id = new_agent_id()
            row = self._agent_row(
                tenant_id, agent_id, name, config, None, FIRST_VERSION
            )
            self._check_version_write(
                tenant_id, agent_id, name, FIRST_VERSION, config, "create", None
            )

            self._append_admin(tenant_id, record)
            self._agents[tenant_id][agent_id] = row
            self._write_version(
                tenant_id,
                agent_id,
                name,
                FIRST_VERSION,
                config,
                row["updated_at"],
                f"{owner_kind}:{owner_id}",
                "create",
            )
            self._grants[(tenant_id, agent_id, owner_kind, owner_id)] = {
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "grantee_kind": owner_kind,
                "grantee_id": owner_id,
                "role": OWNER_ROLE,
                "granted_by": f"{owner_kind}:{owner_id}",
                "granted_at": datetime.now(timezone.utc),
            }

    def rename_agent(
        self,
        tenant_id: str,
        name: str,
        new_name: str,
        *,
        actor: str,
    ) -> dict | None:
        check_agent_name(new_name)
        if new_name == name:
            raise ValueRefused(AGENT_RENAME_TO_SELF.format(agent=name))

        # Built before the lock, on `_append_admin`'s stated ordering. `target_id` is the
        # new name — see `rename_agent` in postgres.py for why, and for what the detail is
        # load-bearing for.
        record = make_admin_record(
            "agent.rename", "agent", new_name, actor, {"from": name, "to": new_name}
        )

        with self._lock:
            self._require_tenant(tenant_id)

            existing = self._agent_by_name(tenant_id, name)
            if existing is None:
                return None

            # `agents_name_unique`. Checked before anything moves, which is this store's
            # whole version of the transaction Postgres opens.
            if self._agent_by_name(tenant_id, new_name) is not None:
                raise AgentNameTaken(AGENT_NAME_TAKEN.format(agent=new_name))

            agent_id = existing["agent_id"]
            # The config's name moves with the column, because `agent_name_matches_config`
            # from migration 002 refuses a row where they disagree — and because the broker
            # reads the config's copy as the agent's identity. One dict, both halves.
            config = copy.deepcopy(existing["config"])
            config["name"] = new_name

            version = existing["version"] + 1
            row = self._agent_row(
                tenant_id,
                agent_id,
                new_name,
                config,
                existing["created_at"],
                version,
            )
            self._check_version_write(
                tenant_id, agent_id, new_name, version, config, "rename", None
            )

            # **The dict key does not move**, which is the whole point of migration 035
            # restated in eleven characters: the agent is the same agent, so every
            # collection keyed on `agent_id` — grants, pending grants, versions, and the
            # schedules and triggers that hold it as a field — needs no touching at all.
            # Under the old name key this line was a `pop` and an insert, and the five
            # cascades below `delete_agent` would each have had a twin here.
            self._agents[tenant_id][agent_id] = row
            self._append_admin(tenant_id, record)
            self._write_version(
                tenant_id,
                agent_id,
                new_name,
                version,
                config,
                row["updated_at"],
                actor,
                "rename",
            )
            return copy.deepcopy(row)

    def delete_agent(self, tenant_id: str, name: str, *, actor: str) -> None:
        with self._lock:
            existing = self._agent_by_name(tenant_id, name)
            if existing is None:
                # Idempotent, and no record. Deleting an agent that was never there
                # changed nothing, and a log that records attempts as well as changes
                # cannot answer "who deleted triage-bot" with one row.
                return

            agent_id = existing["agent_id"]
            record = make_admin_record("agent.delete", "agent", name, actor)

            self._agents[tenant_id].pop(agent_id, None)

            # `ON DELETE CASCADE` from migration 009, by hand. Postgres does this
            # because a grant on a deleted agent is not a grant — it is a row that
            # reactivates the moment the name is reused, handing a brand-new agent the
            # audience of the one it replaced.
            #
            # This store had to be told, and was not. It is the exact shape of fake that
            # the contract suite exists to catch: not permitting what Postgres refuses,
            # but *keeping* what Postgres removes, in the implementation every test in
            # this repository runs against by default.
            #
            # **All five loops filter on `agent_id` since migration 035.** Under the name
            # key a re-created name inherited whatever the cascade missed; now an id is
            # never reissued, so a missed row is orphaned rather than adopted — a leak
            # instead of a privilege escalation. The cascades still run, because a leak in
            # a store that answers "who has access" is its own problem.
            for key in [
                key
                for key in self._grants
                if key[0] == tenant_id and key[1] == agent_id
            ]:
                del self._grants[key]

            # And the pending ones, which migration 012 cascades for a worse version of
            # the same reason: a stale pending row does not reactivate on the next read,
            # it reactivates at somebody's first login, weeks later.
            for key in [
                key
                for key in self._pending
                if key[0] == tenant_id and key[1] == agent_id
            ]:
                del self._pending[key]

            # And the version history, which migration 032 cascades. Its original argument
            # was the key — a name re-created next week would open the first author's
            # prompts — and migration 035 retired that argument by retiring the key. What
            # is left is the plainer one: erasing an agent erases it.
            for key in [
                key
                for key in self._versions
                if key[0] == tenant_id and key[1] == agent_id
            ]:
                del self._versions[key]

            # And the schedules, which migration 033 cascades for the stale-grant reason
            # rather than the version-history one: a schedule naming a deleted agent is
            # standing configuration, and standing configuration pointing at nothing is a
            # row that fires into an error every time its clock comes round.
            #
            # **Keyed by schedule id, so this loop reads the row rather than the key.**
            # The three loops above filter on `key[1] == agent_id` and copying one of them
            # here would have silently matched nothing.
            for key in [
                key
                for key, row in self._schedules.items()
                if row["tenant_id"] == tenant_id and row["agent_id"] == agent_id
            ]:
                del self._schedules[key]

            # Migration 034's agent key, the same cascade for the same reason — a
            # trigger for a deleted agent is a URL an outside system still holds.
            for key in [
                key
                for key, row in self._triggers.items()
                if row["tenant_id"] == tenant_id and row["agent_id"] == agent_id
            ]:
                del self._triggers[key]

            # One record for the deletion, not one per cascaded grant. The grants went
            # because the agent did — attributing each of them separately would say five
            # revocations happened when one deletion did, and an incident reading this
            # log would go looking for a revoker who does not exist.
            self._append_admin(tenant_id, record)

    def list_agent_versions(
        self,
        tenant_id: str,
        name: str,
        *,
        limit: int = 50,
    ) -> list[dict]:
        check_version_limit(limit)
        with self._lock:
            # An absent agent has no history and answers `[]` — `load_agents`' shape, and
            # what the Postgres half does when the name resolves to no id.
            agent_id = self._agent_id_of(tenant_id, name)
            if agent_id is None:
                return []
            rows = sorted(
                (
                    row
                    for key, row in self._versions.items()
                    if key[0] == tenant_id and key[1] == agent_id
                ),
                key=lambda row: row["version"],
                reverse=True,
            )
            return [
                self._with_agent_name(row, AGENT_VERSION_SUMMARY_FIELDS)
                for row in rows[:limit]
            ]

    def get_agent_version(self, tenant_id: str, name: str, version: int) -> dict | None:
        check_version_number(version)
        with self._lock:
            agent_id = self._agent_id_of(tenant_id, name)
            if agent_id is None:
                return None
            row = self._versions.get((tenant_id, agent_id, version))
            if row is None:
                return None
            return self._with_agent_name(row, AGENT_VERSION_FIELDS)

    # --- connectors -------------------------------------------------------------

    def load_connectors(self, tenant_id: str) -> list[dict]:
        with self._lock:
            by_id = self._connectors.get(tenant_id, {})
            return [copy.deepcopy(by_id[cid]) for cid in sorted(by_id)]

    def get_connector(self, tenant_id: str, connector_id: str) -> dict | None:
        with self._lock:
            row = self._connectors.get(tenant_id, {}).get(connector_id)
            return copy.deepcopy(row) if row is not None else None

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
        # Built before the lock is taken, on `_append_admin`'s stated ordering: a bad
        # actor must leave the store untouched rather than half-written, and
        # `make_admin_record` is the only thing here that can raise for that reason.
        record = make_admin_record(
            "connector.create",
            "connector",
            connector_id or "",
            actor,
            # The transport kind and the host, because "what did somebody point this
            # tenant at" is the question an incident asks — and the URL is not a secret
            # (`credential_env` is a variable *name*, never a value, since migration 003).
            {
                "kind": (launch or {}).get("kind", ""),
                "url": (launch or {}).get("url", ""),
                # Recorded on create as well as on toggle — see the Postgres twin.
                "allow_asserted_identity": bool(allow_asserted_identity),
                # Step 068: which checked-in preset supplied these values, or `""`. A log
                # line and not a link — nothing indexes or joins it, so deleting the
                # recipe breaks nothing and this stays readable.
                "from_recipe": from_recipe or "",
            },
        )

        with self._lock:
            self._require_tenant(tenant_id)

            if not connector_id or not isinstance(connector_id, str):
                raise StorageError("a connector needs a non-empty string id")

            if connector_id in self._connectors.get(tenant_id, {}):
                raise ConnectorExistsError(
                    CONNECTOR_EXISTS.format(connector=connector_id, tenant=tenant_id)
                )

            self._connectors[tenant_id][connector_id] = {
                "id": connector_id,
                "description": description or "",
                "launch": copy.deepcopy(launch or {}),
                # Empty, and that is the method. Registration vets nothing.
                "vetted": [],
                "allow_asserted_identity": bool(allow_asserted_identity),
            }
            self._vetting[(tenant_id, connector_id)] = []
            self._append_admin(tenant_id, record)

    def set_asserted_identity(
        self, tenant_id: str, connector_id: str, allowed: bool, *, actor: str
    ) -> None:
        record = make_admin_record(
            "connector.asserted_identity",
            "connector",
            connector_id or "",
            actor,
            {"allow_asserted_identity": bool(allowed)},
        )

        with self._lock:
            self._require_tenant(tenant_id)
            row = self._connectors.get(tenant_id, {}).get(connector_id)
            if row is None:
                # Nothing written, including the admin record — the log records
                # changes, and this one never happened. The Postgres twin gets the
                # same property from its transaction rolling back.
                raise NoSuchConnectorError(
                    NO_SUCH_CONNECTOR_TO_TRUST.format(
                        connector=connector_id, tenant=tenant_id
                    )
                )
            row["allow_asserted_identity"] = bool(allowed)
            self._append_admin(tenant_id, record)

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
        row = normalize_vetted_tool(vetted)

        record = make_admin_record(
            "connector.vet",
            "connector",
            connector_id or "",
            actor,
            {
                "remote_name": row["remote_name"],
                # The annotations that decide what this tool may reach and whose
                # account it reaches it as. Not the description — that is the vendor's
                # free text, which is the class of thing this log does not keep.
                "effect": row["effect"],
                "identity": row["identity"],
                "resources": sorted({ref["type"] for ref in row["resources"]}),
                "server_name": server_name,
                "server_version": server_version,
            },
        )

        with self._lock:
            self._require_tenant(tenant_id)

            connector = self._connectors.get(tenant_id, {}).get(connector_id)
            if connector is None:
                raise NoSuchConnectorError(
                    NO_SUCH_CONNECTOR_TO_VET.format(
                        connector=connector_id, tenant=tenant_id
                    )
                )

            # The kind/binding implication (045a), before anything moves — the same
            # ordering the Postgres twin gets from raising inside its transaction.
            check_binding_kind(connector.get("launch") or {}, row, connector_id)

            # Upserted on `remote_name`, which is `vetted_tools`' primary key past the
            # tenant and connector. Everything already vetted stays exactly where it is —
            # the whole difference between this and `save_connector`.
            connector["vetted"] = [
                existing
                for existing in connector["vetted"]
                if existing["remote_name"] != row["remote_name"]
            ] + [row]
            connector["vetted"].sort(key=lambda entry: entry["remote_name"])

            entries = [
                existing
                for existing in self._vetting.setdefault((tenant_id, connector_id), [])
                if existing["remote_name"] != row["remote_name"]
            ]
            entries.append(
                {
                    "connector_id": connector_id,
                    "remote_name": row["remote_name"],
                    # The first writer this column has had. See migration 018 for the
                    # two steps it spent defaulting to `''` because nothing vetted.
                    "vetted_by": actor,
                    "vetted_at": datetime.now(timezone.utc).isoformat(),
                    "server_name": server_name,
                    "server_version": server_version,
                    "vetted_arguments": sorted(vetted_arguments),
                }
            )
            entries.sort(key=lambda entry: entry["remote_name"])
            self._vetting[(tenant_id, connector_id)] = entries

            self._append_admin(tenant_id, record)

    def save_connector(self, tenant_id: str, manifest: dict, *, actor: str) -> None:
        record = make_admin_record(
            "connector.save",
            "connector",
            manifest.get("id") or "",
            actor,
            {
                "tools": sorted(
                    row.get("remote_name", "") for row in manifest.get("vetted") or ()
                ),
                "kind": (manifest.get("launch") or {}).get("kind", ""),
                "url": (manifest.get("launch") or {}).get("url", ""),
            },
        )

        with self._lock:
            self._save_connector_locked(tenant_id, manifest, actor=actor)
            self._append_admin(tenant_id, record)

    def _save_connector_locked(self, tenant_id: str, manifest: dict, *, actor: str) -> None:
        self._require_tenant(tenant_id)

        connector_id = manifest.get("id")
        if not connector_id or not isinstance(connector_id, str):
            raise StorageError("connector manifest must have a non-empty string 'id'")

        # `read_only` is derived from the vetted effects and there is no column for it.
        # Refused rather than dropped: a field silently discarded reads as honoured,
        # and this is the exact flag the design goes out of its way not to write down.
        stored = set(manifest) & DERIVED_CONNECTOR_FIELDS
        if stored:
            raise StorageError(
                f"connector manifest may not set {sorted(stored)} — derived from the "
                "vetted effects, never stored. A stored copy is free to disagree with "
                "the allowlist it defends."
            )

        stored = copy.deepcopy(manifest)
        # Normalized on the way in rather than on the way out, because this store's
        # `get` is a deep copy of whatever it was handed. Postgres normalizes on read
        # because it reconstructs from columns; either way the manifest a caller reads
        # back has exactly `VETTED_TOOL_FIELDS`, which is the property being kept.
        stored["vetted"] = [
            normalize_vetted_tool(row) for row in stored.get("vetted") or ()
        ]
        # The kind/binding implication (045a), against the launch this same manifest
        # carries — the wholesale writer is exactly the path the vet-time guard
        # cannot cover. Before anything is stored, so a refusal leaves the old row.
        for row in stored["vetted"]:
            check_binding_kind(stored.get("launch") or {}, row, connector_id)
        # Normalized like the vetted rows and for the same reason: a manifest read back
        # from either store has the key, as a bool, absent meaning False — the closed
        # direction. The Postgres twin gets this from its column's default.
        stored["allow_asserted_identity"] = bool(
            stored.get("allow_asserted_identity", False)
        )
        self._connectors[tenant_id][connector_id] = stored

        # The review record, which is a column in Postgres and deliberately not part of
        # the manifest — see `Storage.load_vetting_record`. Replaced wholesale with the
        # allowlist for the same reason the table's rows are: a tool that stopped being
        # vetted has no review to report.
        #
        # `vetted_at` is stamped here the way `DEFAULT now()` stamps it there. That
        # makes it the moment the connector was last *saved*, which is what it means in
        # both stores — honest, and not the same thing as when this tool was approved.
        #
        # `vetted_by` is the actor from step 012, where it used to be `''`. For `--seed`
        # that is `system:cli`, which is true and not very informative; a row that says
        # a person's name got there through `vet_tool`.
        #
        # `server_name`/`server_version` stay `''` here and there is no way to pass them:
        # `save_connector` contacts no server, so it has nothing to record and inventing
        # a version would be the one lie this record exists not to tell.
        now = datetime.now(timezone.utc)
        self._vetting[(tenant_id, connector_id)] = [
            {
                "connector_id": connector_id,
                "remote_name": row["remote_name"],
                "vetted_by": actor,
                "vetted_at": now.isoformat(),
                "server_name": "",
                "server_version": "",
                # No baseline, because nothing was observed. `review()` reads an empty
                # list as "no baseline" and reports nothing rather than guessing.
                "vetted_arguments": [],
            }
            for row in stored["vetted"]
        ]

    def delete_connector(self, tenant_id: str, connector_id: str, *, actor: str) -> None:
        record = make_admin_record(
            "connector.delete", "connector", connector_id or "", actor
        )

        with self._lock:
            # Migration 021's delete half: RESTRICT, checked before anything is
            # removed so a refusal leaves the connector and its vetting intact.
            if any(
                key[0] == tenant_id and key[3] == connector_id
                for key in self._connections
            ):
                raise ConnectorInUseError(
                    CONNECTOR_IN_USE.format(connector=connector_id, tenant=tenant_id)
                )

            removed = self._connectors.get(tenant_id, {}).pop(connector_id, None)
            # The cascade, by hand. `vetted_tools` has ON DELETE CASCADE; a vetting
            # decision has no meaning without the connector it was made about.
            self._vetting.pop((tenant_id, connector_id), None)
            # Migration 024's cascade, and it was **missing** — the fake kept a
            # `connector_oauth` row, holding a sealed client secret, for a connector that
            # no longer existed. Found by `test_deleting_a_connector_takes_its_oauth_
            # application_with_it`, which is the whole reason every rule Postgres enforces
            # with a constraint is enforced here in Python too: the fake being the looser
            # of the two is the drift this suite exists to catch, and it had drifted
            # within one step of the column being added.
            self._oauth_apps.pop((tenant_id, connector_id), None)

            # Only when something went, on `delete_agent`'s precedent: the log records
            # changes rather than attempts, so a re-run of an idempotent delete does not
            # accumulate records of deletions that did not happen.
            if removed is not None:
                self._append_admin(tenant_id, record)

    def load_vetting_record(self, tenant_id: str) -> list[dict]:
        with self._lock:
            rows = [
                copy.deepcopy(row)
                for (tid, _), entries in self._vetting.items()
                if tid == tenant_id
                for row in entries
            ]
        return sorted(rows, key=lambda r: (r["connector_id"], r["remote_name"]))

    # --- egress -----------------------------------------------------------------

    def allowed_hosts(self, tenant_id: str) -> list[dict]:
        with self._lock:
            rows = [
                copy.deepcopy(row)
                for (tid, _), row in self._egress.items()
                if tid == tenant_id
            ]
        return sorted(rows, key=lambda row: row["host"])

    def allow_host(
        self, tenant_id: str, host: str, *, actor: str, note: str = ""
    ) -> None:
        # Normalized before the record is built, so the log holds what the allowlist
        # holds. A record naming `MCP.Example.COM:443` for a row keyed `mcp.example.com`
        # would be an audit trail that does not match the thing it is auditing.
        normalized = normalize_host(host)
        record = make_admin_record(
            "egress.allow", "host", normalized, actor, {"note": note or ""}
        )

        with self._lock:
            self._require_tenant(tenant_id)
            self._egress[(tenant_id, normalized)] = {
                "host": normalized,
                "allowed_by": actor,
                "allowed_at": datetime.now(timezone.utc).isoformat(),
                "note": note or "",
            }
            self._append_admin(tenant_id, record)

    def revoke_host(self, tenant_id: str, host: str, *, actor: str) -> bool:
        normalized = normalize_host(host)
        record = make_admin_record("egress.revoke", "host", normalized, actor)

        with self._lock:
            removed = self._egress.pop((tenant_id, normalized), None)
            if removed is None:
                return False
            self._append_admin(tenant_id, record)
            return True

    # --- audit ------------------------------------------------------------------

    def append_audit(self, tenant_id: str, record: dict) -> None:
        # `audit_principal_kind_check`, added by migration 017. Enforced here because a
        # fake that is more permissive than the real store is a fake that lies in the
        # direction that matters — and until 017 there was no constraint on this column
        # in either place, so nothing was being compared.
        check_principal_kind(record["principal_kind"])
        # Migration 048's CHECK, here for the same reason as the line above it.
        check_audit_tokens(record)

        # Normalized rather than kept verbatim, and that is the fix for a real
        # divergence: Postgres fills the optional columns at INSERT because the table
        # demands values, so a record written without `identity_source` came back as
        # `'none'` from one store and with the key missing from the other. Storing what
        # the real store would store is what makes the two answer alike — the same
        # reason `check_principal_kind` is called above rather than left to the database.
        row = normalize_audit_record(record)

        with self._lock:
            self._require_tenant(tenant_id)
            self._audit.append((tenant_id, copy.deepcopy(row)))

    def audit_records(
        self,
        tenant_id: str,
        *,
        run_id: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        with self._lock:
            # Snapshotted under the lock. Iterating the live list while another thread
            # appends is the one operation here that can raise rather than merely
            # return something stale.
            rows = [
                {**copy.deepcopy(record), "tenant_id": tid}
                for tid, record in self._audit
                if tid == tenant_id
                and (run_id is None or record.get("run_id") == run_id)
            ]

        if limit is not None:
            # The most recent N, still oldest-first. Slicing from the end rather than
            # the front — a log view wants the tail, and getting this backwards is the
            # sort of thing only a shared contract test catches.
            rows = rows[-limit:] if limit > 0 else []

        return rows

    # --- the administrative audit log -------------------------------------------

    def _append_admin(self, tenant_id: str, record: dict) -> None:
        """Append one administrative record. **Caller holds the lock.**

        That is this store's whole version of the transaction Postgres opens, and it is
        the same device `create_agent` already uses: the write and its record happen
        with nobody else able to look in between. A weaker guarantee than the real one —
        a process that dies mid-block loses the store with it — and the same
        *observable* behaviour, which is what the contract suite compares.

        The ordering at every call site is the load-bearing part and it is the same one
        everywhere: **build the record first, mutate second, append third.**
        `make_admin_record` is the only thing on this path that can raise, so building it
        before touching anything is what makes a bad actor leave the store untouched
        rather than half-written. Postgres gets the same property from the transaction;
        this gets it from the order.
        """
        self._admin.append((tenant_id, copy.deepcopy(record)))

    def admin_audit_records(
        self,
        tenant_id: str,
        *,
        action: str | None = None,
        target_kind: str | None = None,
        target_id: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        with self._lock:
            # Snapshotted under the lock, for the reason `audit_records` is: iterating
            # the live list while another thread appends is the one operation here that
            # raises rather than merely returning something stale.
            rows = [
                {**copy.deepcopy(record), "tenant_id": tid}
                for tid, record in self._admin
                if tid == tenant_id
                and (action is None or record["action"] == action)
                and (target_kind is None or record["target_kind"] == target_kind)
                and (target_id is None or record["target_id"] == target_id)
            ]

        for row in rows:
            # An ISO string in both stores, the same coercion `audit_records` applies
            # and for the same reason: records are compared and diffed as data, and a
            # driver-native datetime here would make the two disagree about what a
            # record is.
            row["ts"] = row["ts"].isoformat(timespec="milliseconds")

        if limit is not None:
            rows = rows[-limit:] if limit > 0 else []
        return rows

    # --- the access-denial log --------------------------------------------------

    def record_denial(self, tenant_id: str, record: dict) -> None:
        # The kind checks and the projection below are `append_audit`'s device on the
        # third log, added by 035b — and they close a split that was real rather than
        # theoretical. It is not `audit`'s split: `access_denials` has no optional
        # columns to normalize, all eight are NOT NULL and `make_denial_record` sets all
        # eight. It is the other direction, **accept versus refuse**, with the fake as
        # the permissive one:
        #
        #   resource_kind='banana'  Postgres refuses on the CHECK; the fake stored it,
        #                           and `denial_records(resource_kind='banana')` found it
        #   principal_kind='group'  the same, on migration 031's widened CHECK
        #   no `held` key           Postgres raises KeyError here; the fake stored the
        #                           record and read it back without the key
        #   an extra key            Postgres drops it — the INSERT names its columns —
        #                           and the fake returned it
        #
        # Invisible because the one production caller (`access/denials.py`) builds
        # through `make_denial_record`, which validates. That is true of the caller and
        # not of the interface: this method is public on the protocol, and a fake more
        # permissive than the real store is a fake that lies in the direction that
        # matters.
        check_principal_kind(record["principal_kind"])
        check_denial_resource_kind(record["resource_kind"])

        # Built from `DENIAL_FIELDS` rather than kept verbatim, which **is** what the
        # real store's INSERT does: it names its columns, so it raises on a missing one
        # and ignores an extra. Storing what Postgres would store is what makes the two
        # answer alike.
        row = {field: record[field] for field in DENIAL_FIELDS[1:]}

        with self._lock:
            # `append_audit` has always called this and `record_denial` never did, so
            # Postgres refused an unknown tenant via the foreign key while this store
            # accepted the row — the exact shape of fake the contract suite exists to
            # catch, and it had no test because no caller had ever tried.
            #
            # It matters more since migration 029: "this tenant is gone" is now a state
            # both stores must refuse identically, and a store that keeps taking denials
            # for a deleted customer is one that re-populates a table the deletion just
            # emptied.
            self._require_tenant(tenant_id)
            self._denials.append((tenant_id, copy.deepcopy(row)))

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
        with self._lock:
            # Snapshotted under the lock, for the reason `audit_records` is.
            rows = [
                {**copy.deepcopy(record), "tenant_id": tid}
                for tid, record in self._denials
                if tid == tenant_id
                and (principal_kind is None or record["principal_kind"] == principal_kind)
                and (principal_id is None or record["principal_id"] == principal_id)
                and (resource_kind is None or record["resource_kind"] == resource_kind)
                and (resource_id is None or record["resource_id"] == resource_id)
            ]

        for row in rows:
            # An ISO string in both stores, the coercion every log reader here applies:
            # records are compared and diffed as data, and a driver-native datetime
            # would make the two stores disagree about what a record is.
            row["ts"] = row["ts"].isoformat(timespec="milliseconds")

        if limit is not None:
            rows = rows[-limit:] if limit > 0 else []
        return rows

    def last_door_refusal(self, tenant_id: str, tool_names: Sequence[str]) -> dict | None:
        wanted = set(tool_names)
        if not wanted:
            return None
        with self._lock:
            # Newest last: `_denials` is append-ordered, so the last match is the answer.
            found = None
            for tid, record in self._denials:
                if (
                    tid == tenant_id
                    and record["resource_kind"] == "tool"
                    and record["resource_id"] in wanted
                ):
                    found = record
            if found is None:
                return None
            row = {**copy.deepcopy(found), "tenant_id": tenant_id}
        row["ts"] = row["ts"].isoformat(timespec="milliseconds")
        return row

    # --- the door's traffic -----------------------------------------------------

    # The filters, mirroring `PostgresStorage._DOOR_FILTERS` field for field. Two lists
    # that had to be edited by hand is how `credential` came to be written by one store
    # and dropped by the other, so this one is compared against that one by the contract
    # suite rather than by anybody remembering.
    _DOOR_FILTERS = (
        "tool",
        "agent",
        "principal_id",
        "principal_kind",
        "acting_for",
        "decision",
        "outcome",
        "effect",
        "identity_source",
    )

    def door_call_records(
        self,
        tenant_id: str,
        *,
        limit: int | None = None,
        since: date | None = None,
        until: date | None = None,
        **filters,
    ) -> list[dict]:
        floor = since.isoformat() if since is not None else None
        ceiling = until.isoformat() if until is not None else None

        def in_window(record: dict) -> bool:
            # The stored day compared as an ISO string, which is exact for these and is
            # the same inclusive-both-ends bound the SQL applies. `overview` compares the
            # same way for the same reason.
            day = self._day(record.get("ts"))
            if not day:
                return False
            if floor is not None and day < floor:
                return False
            return not (ceiling is not None and day > ceiling)

        def matches(record: dict) -> bool:
            for keyword in self._DOOR_FILTERS:
                wanted = filters.get(keyword)
                # `is not None`, never truthiness — `outcome=""` is a real stored value
                # and asking for it must not read as "do not narrow". The Postgres twin
                # says the same at greater length.
                if wanted is not None and (record.get(keyword) or "") != wanted:
                    return False
            return True

        with self._lock:
            # Snapshotted under the lock, for the reason `audit_records` is.
            #
            # `startswith` against the shared constant is this store's version of
            # Postgres' `LIKE 'door-%'`. Reading `self._audit` rather than a list of its
            # own is the point: there is one log, and a door call is a row in it that a
            # run could not have written.
            wanted_owner = filters.get("owner")
            rows = []
            for tid, record in self._audit:
                if (
                    tid != tenant_id
                    or not str(record.get("run_id") or "").startswith(DOOR_CALL_ID_PREFIX)
                    or not in_window(record)
                    or not matches(record)
                ):
                    continue
                # The read-time join, step 108: the person behind a personal token,
                # never stored on the row. `''` for everything that is not one.
                owner = self._owner_email(tenant_id, record)
                # `''` narrows to nothing rather than to the service tokens — the SQL's
                # `NULLIF(u.email, '') = ''` is never true, and neither is this.
                if wanted_owner is not None and (not wanted_owner or owner != wanted_owner):
                    continue
                rows.append({**copy.deepcopy(record), "tenant_id": tid, "owner": owner})

        if limit is not None:
            # The most recent N, still oldest-first — `audit_records`' rule.
            rows = rows[-limit:] if limit > 0 else []

        return rows

    def _owner_email(self, tenant_id: str, record: dict) -> str:
        """`api_tokens.owner_id` → `users.email` for a personal token's call. Called
        under the lock. The SQL's two LEFT JOINs, as two dict reads."""
        return self._subject(tenant_id, record)[2]

    def _subject(self, tenant_id: str, record: dict) -> tuple:
        """Who a door call counts as on the overview, step 108: the owner for a
        personal token's call, the principal for everything else — `door.budget_subject`'s
        rule applied to attribution. `(kind, id, owner_email)`; the email is `''` unless
        the call was a personal token's. Called under the lock."""
        if record.get("principal_kind") == "machine":
            token = self._api_tokens.get(record.get("principal_id") or "")
            if token is not None and token["tenant_id"] == tenant_id and token["acts_as_owner"]:
                user = self._users.get(token["owner_id"])
                email = ""
                if user is not None and user["tenant_id"] == tenant_id:
                    email = user.get("email") or ""
                return ("user", token["owner_id"], email)
        return (record.get("principal_kind"), record.get("principal_id"), "")

    def door_call_summary(self, tenant_id: str, agent_name: str) -> dict:
        with self._lock:
            # One pass, counting rather than collecting — the base docstring's point.
            # The last match's `ts` is the latest because `_audit` is append-ordered,
            # which is the same fact `door_call_records`' tail-slice leans on.
            calls = 0
            last = None
            for tid, record in self._audit:
                if (
                    tid == tenant_id
                    and record.get("agent") == agent_name
                    and str(record.get("run_id") or "").startswith(DOOR_CALL_ID_PREFIX)
                ):
                    calls += 1
                    last = record.get("ts")

        return {"calls": calls, "last_call_at": last}

    # --- the grant, against its evidence ------------------------------------------

    def _window_bounds(self, since, until) -> tuple:
        from datetime import datetime as _dt, time as _time, timedelta as _td, timezone as _tz

        start = _dt.combine(since, _time.min, tzinfo=_tz.utc)
        stop = _dt.combine(until + _td(days=1), _time.min, tzinfo=_tz.utc)
        return start, stop

    def door_tool_evidence(
        self,
        tenant_id: str,
        agent_name: str,
        tool_names: Sequence[str],
        *,
        since,
        until,
    ) -> dict:
        start, stop = self._window_bounds(since, until)
        wanted = set(tool_names)
        tools: dict[str, dict] = {}
        door_refused: dict[str, dict] = {}

        with self._lock:
            for tid, record in self._audit:
                if tid != tenant_id or record.get("agent") != agent_name:
                    continue
                if not str(record.get("run_id") or "").startswith(DOOR_CALL_ID_PREFIX):
                    continue
                when = self._as_utc(record.get("ts"))
                if when is None or not (start <= when < stop):
                    continue
                tool = tools.setdefault(
                    record.get("tool") or "",
                    {"admitted": 0, "refused": 0, "last_admitted_at": None, "last_refused_at": None},
                )
                if record.get("decision") == "deny":
                    tool["refused"] += 1
                    if tool["last_refused_at"] is None or when > tool["last_refused_at"]:
                        tool["last_refused_at"] = when
                else:
                    tool["admitted"] += 1
                    if tool["last_admitted_at"] is None or when > tool["last_admitted_at"]:
                        tool["last_admitted_at"] = when

            for tid, record in self._denials:
                if tid != tenant_id or record["resource_kind"] != "tool":
                    continue
                if record["resource_id"] not in wanted:
                    continue
                when = self._as_utc(record["ts"])
                if when is None or not (start <= when < stop):
                    continue
                entry = door_refused.setdefault(record["resource_id"], {"count": 0, "last_at": None})
                entry["count"] += 1
                if entry["last_at"] is None or when > entry["last_at"]:
                    entry["last_at"] = when

        iso = lambda when: when.isoformat(timespec="milliseconds") if when else None  # noqa: E731
        return {
            "tools": {
                name: {
                    "admitted": row["admitted"],
                    "refused": row["refused"],
                    "last_admitted_at": iso(row["last_admitted_at"]),
                    "last_refused_at": iso(row["last_refused_at"]),
                }
                for name, row in tools.items()
            },
            "door_refused": {
                name: {"count": row["count"], "last_at": iso(row["last_at"])}
                for name, row in door_refused.items()
            },
        }

    def token_door_touch(self, tenant_id: str, token_id: str, *, since, until) -> dict:
        start, stop = self._window_bounds(since, until)
        touched: dict[tuple, dict] = {}
        door_refused: dict[str, dict] = {}

        with self._lock:
            for tid, record in self._audit:
                if tid != tenant_id:
                    continue
                if record.get("principal_kind") != "machine" or record.get("principal_id") != token_id:
                    continue
                if not str(record.get("run_id") or "").startswith(DOOR_CALL_ID_PREFIX):
                    continue
                when = self._as_utc(record.get("ts"))
                if when is None or not (start <= when < stop):
                    continue
                key = (record.get("agent") or "", record.get("tool") or "")
                row = touched.setdefault(
                    key, {"agent": key[0], "tool": key[1], "admitted": 0, "refused": 0, "last_at": None}
                )
                if record.get("decision") == "deny":
                    row["refused"] += 1
                else:
                    row["admitted"] += 1
                if row["last_at"] is None or when > row["last_at"]:
                    row["last_at"] = when

            for tid, record in self._denials:
                if tid != tenant_id or record["resource_kind"] != "tool":
                    continue
                if record["principal_kind"] != "machine" or record["principal_id"] != token_id:
                    continue
                when = self._as_utc(record["ts"])
                if when is None or not (start <= when < stop):
                    continue
                entry = door_refused.setdefault(record["resource_id"], {"count": 0, "last_at": None})
                entry["count"] += 1
                if entry["last_at"] is None or when > entry["last_at"]:
                    entry["last_at"] = when

        return {
            "touched": [
                {**row, "last_at": row["last_at"].isoformat(timespec="milliseconds")}
                for _, row in sorted(touched.items())
            ],
            "door_refused": [
                {"tool": name, "count": row["count"], "last_at": row["last_at"].isoformat(timespec="milliseconds")}
                for name, row in sorted(door_refused.items())
            ],
        }

    def oldest_door_record_at(self, tenant_id: str) -> "str | None":
        oldest = None
        with self._lock:
            for tid, record in self._audit:
                if tid != tenant_id:
                    continue
                if not str(record.get("run_id") or "").startswith(DOOR_CALL_ID_PREFIX):
                    continue
                when = self._as_utc(record.get("ts"))
                if when is not None and (oldest is None or when < oldest):
                    oldest = when
        return oldest.isoformat(timespec="milliseconds") if oldest else None

    # --- the overview -----------------------------------------------------------------

    @staticmethod
    def _as_utc(stamp) -> "datetime | None":
        """A stored stamp as an aware UTC datetime, whatever shape this store holds.

        Two shapes are real, not hypothetical: the log tables hold **ISO strings**
        (`audit.record` writes `isoformat(timespec="milliseconds")`), and the `runs` and
        `schedules` rows hold **`datetime` objects** (`enqueue_run`/`start_run`/
        `finish_run` store `datetime.now(timezone.utc)` directly). The first version of
        `overview` assumed strings everywhere and crashed on the first tenant with a
        finished run — `fromisoformat` on a `datetime` is a `TypeError` — which no test
        caught because none had seeded one.

        The `astimezone` matters too, not just the parse: a stamp written with a
        non-UTC offset would otherwise be bucketed by its **local** date, while Postgres
        groups by `AT TIME ZONE 'UTC'` — the same call, `02:00+05:30` on the 25th,
        landing on two different days in the two stores. Every writer in this codebase
        stamps UTC, but the reader matching the real store's arithmetic is what the
        contract suite is for.

        A naive datetime is treated as UTC, which is what Postgres does with a naive
        literal in a UTC session and the only reading that cannot shift a row silently.
        """
        if stamp is None or stamp == "":
            return None
        if isinstance(stamp, str):
            stamp = datetime.fromisoformat(stamp)
        if stamp.tzinfo is None:
            return stamp.replace(tzinfo=timezone.utc)
        return stamp.astimezone(timezone.utc)

    @classmethod
    def _day(cls, stamp) -> str:
        """The UTC day of a stored stamp, as `YYYY-MM-DD` — `date_trunc`'s twin."""
        moment = cls._as_utc(stamp)
        return "" if moment is None else moment.date().isoformat()

    @classmethod
    def _hour(cls, stamp) -> str:
        """The UTC hour, as `YYYY-MM-DDTHH`. Step 066, and `_HOUR`'s twin.

        Formatted rather than sliced off an ISO string, because a stored stamp's ISO
        spelling varies with its offset and this has to be the same fifteen characters
        Postgres' `to_char` produces however the row arrived.
        """
        moment = cls._as_utc(stamp)
        return "" if moment is None else moment.strftime("%Y-%m-%dT%H")

    @staticmethod
    def _percentiles(values: list) -> tuple[int | None, int | None]:
        """Median and p95 of an unsorted list, matching Postgres' `percentile_cont`.

        **Linear interpolation between neighbours**, which is what `percentile_cont` does
        and what `percentile_disc` does not — the difference shows up on every even-length
        sample and would read as a fake being *nearly* right. Empty is `(None, None)`
        rather than zeros: no observation is not an observation of zero, and the wire
        carries the distinction.
        """
        if not values:
            return None, None

        ordered = sorted(values)

        def at(fraction: float) -> int:
            # Postgres' definition: the position is `fraction * (n - 1)`, and a
            # fractional position is the weighted blend of the two rows around it.
            position = fraction * (len(ordered) - 1)
            low = int(position)
            high = min(low + 1, len(ordered) - 1)
            weight = position - low
            return round(ordered[low] * (1 - weight) + ordered[high] * weight)

        return at(0.5), at(0.95)

    def overview_totals(self, tenant_id: str, *, since: date, until: date) -> dict:
        """`_q`-free twin of `PostgresStorage.overview_totals`. Step 066a.

        Counted rather than queried, because this store's whole dataset is already in
        Python and there is nothing to avoid loading — `base.overview`'s standing note
        about why the counting lives in the store either way.
        """
        floor, ceiling = since.isoformat(), until.isoformat()

        def within(day: str) -> bool:
            return bool(day) and floor <= day <= ceiling

        with self._lock:
            # One snapshot, for `overview`'s reason: counting across live lists while
            # another thread appends lets two of these numbers disagree about whether a
            # call happened.
            audit = [
                copy.deepcopy(record)
                for tid, record in self._audit
                if tid == tenant_id and within(self._day(record.get("ts")))
            ]
            access = sum(
                1
                for tid, record in self._denials
                if tid == tenant_id and within(self._day(record.get("ts")))
            )
            changes = sum(
                1
                for tid, record in self._admin
                if tid == tenant_id and within(self._day(record.get("ts")))
            )

        door = [
            record
            for record in audit
            if str(record.get("run_id") or "").startswith(DOOR_CALL_ID_PREFIX)
        ]

        models: dict[str, dict] = {}
        for record in door:
            # NULL means the call touched no model, which is nearly every row — read as
            # zero it would produce one enormous `''` bucket. `_door_spend`'s filter.
            if record.get("input_tokens") is None:
                continue
            name = record.get("model") or ""
            bucket = models.setdefault(
                name,
                {
                    "model": name,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cache_read_tokens": 0,
                    "cache_write_tokens": 0,
                },
            )
            for field in (
                "input_tokens",
                "output_tokens",
                "cache_read_tokens",
                "cache_write_tokens",
            ):
                bucket[field] += record.get(field) or 0

        return {
            "door_calls": len(door),
            "door_denied": sum(1 for r in door if r.get("decision") == "deny"),
            "door_writes": sum(
                1
                for r in door
                if r.get("decision") != "deny" and r.get("effect") == "write"
            ),
            "door_verified": sum(
                1 for r in door if r.get("identity_source") == "verified"
            ),
            "callers": len({self._subject(tenant_id, r)[:2] for r in door}),
            # Every brokered denial — what `overview`'s five bands
            # sum to — plus the access log, which is the genuinely different table.
            "refusals": sum(1 for r in audit if r.get("decision") == "deny") + access,
            "admin_changes": changes,
            "door_spend": [models[name] for name in sorted(models)],
        }

    def overview(
        self,
        tenant_id: str,
        *,
        since: date,
        until: date,
        bucket: str = "day",
    ) -> dict:
        floor, ceiling = since.isoformat(), until.isoformat()
        # The bucket is a **function**, passed down, rather than a flag each helper
        # branches on: there are eight of them and eight `if bucket == "hour"` branches
        # is eight chances for one to be missed, which the contract suite would catch as
        # a store being *nearly* right — the drift it exists for.
        stamp = self._hour if bucket == "hour" else self._day

        def within(day: str) -> bool:
            # String comparison, which is exact for ISO dates and is the same bound the
            # SQL applies — inclusive at both ends.
            return bool(day) and floor <= day <= ceiling

        with self._lock:
            # One snapshot for the whole method. Counting across the live lists while
            # another thread appends would let two series disagree about whether a call
            # happened, which is the one inconsistency a dashboard cannot explain away.
            # Three lists since step 084 took the run and schedule series; the property
            # is unchanged and so is the reason for it.
            audit = [
                copy.deepcopy(record)
                for tid, record in self._audit
                if tid == tenant_id and within(self._day(record.get("ts")))
            ]
            denials = [
                copy.deepcopy(record)
                for tid, record in self._denials
                if tid == tenant_id and within(self._day(record.get("ts")))
            ]
            admin = [
                copy.deepcopy(record)
                for tid, record in self._admin
                if tid == tenant_id and within(self._day(record.get("ts")))
            ]

        def through_the_door(record: dict) -> bool:
            return str(record.get("run_id") or "").startswith(DOOR_CALL_ID_PREFIX)

        # Partitioned by the same predicate rather than by set difference: two audit
        # rows can be equal in every field a dict comparison sees — same tool, same
        # tenant, same millisecond — so `record not in door` would drop a real call and
        # do it in quadratic time. The prefix is the definition of the split; asking it
        # twice is the cheap, correct spelling.
        #
        # `in_product` had two readers until step 084 took the run leaderboard; it keeps
        # one, and it is the one that reads history rather than this tree's own traffic
        # — see `_refusals`.
        door = [record for record in audit if through_the_door(record)]
        in_product = [record for record in audit if not through_the_door(record)]

        tools, tool_count, tool_tail = self._tool_totals(door)
        callers, caller_count, caller_tail = self._callers(tenant_id, door)
        agents, agent_count, agent_tail = self._door_agents(door)
        acting, acting_count, acting_tail = self._acting_for(door)
        reasons, reason_count, reason_tail = self._refusal_reasons(door)

        return {
            "door_calls": self._calls_by_day(door, stamp),
            "door_spend": self._door_spend(door, stamp),
            "door_effects": self._effects_by_day(door, stamp),
            "identity": self._identity(door, stamp),
            "door_latency": self._latency(door, stamp),
            "door_bytes": self._bytes(door, stamp),
            "callers": callers,
            "caller_count": caller_count,
            "caller_tail": caller_tail,
            "door_tools": tools,
            "tool_count": tool_count,
            "tool_tail": tool_tail,
            "door_agents": agents,
            "agent_count": agent_count,
            "agent_tail": agent_tail,
            "acting_for": acting,
            "acting_for_count": acting_count,
            "acting_for_tail": acting_tail,
            "refusal_reasons": reasons,
            "refusal_reason_count": reason_count,
            "refusal_reason_tail": reason_tail,
            "tool_latency": self._tool_latency(door),
            "hourly": self._hourly(door),
            # `in_product` survives step 084's cut of the run series precisely here:
            # a *refusal* on a non-door row is history an upgraded deployment still
            # holds, and the `run_budget` band is the only thing that can read it.
            "refusals": self._refusals(door, in_product, denials, stamp),
            "admin_actions": self._changes_by_family(admin, stamp),
        }

    # Each series below is its own function for one reason: they are the assertions of
    # `test_storage_contract`, one at a time, and a single 200-line `overview` would make
    # a failure say "the overview is wrong" rather than "the identity split is wrong".

    # The stored `outcome` value, and the band it is counted in. `error` is spelled
    # `errored` on the wire and always has been — the only member whose name changes —
    # and `''` is absent on purpose: an admitted call nothing recorded an outcome for is
    # in no band.
    _OUTCOME_BANDS = {
        "error": "errored",
        "oversize": "oversize",
        "ok": "ok",
        "unknown": "unknown",
    }

    def _calls_by_day(self, door: list[dict], stamp) -> list[dict]:
        days: dict[str, dict] = {}
        for record in door:
            day = days.setdefault(
                stamp(record["ts"]),
                {
                    "allowed": 0,
                    "denied": 0,
                    "errored": 0,
                    "oversize": 0,
                    "ok": 0,
                    "unknown": 0,
                },
            )
            if record.get("decision") == "deny":
                day["denied"] += 1
                continue
            day["allowed"] += 1
            # `outcome` bands an **allowed** call by what happened next, so they are
            # counted beside `allowed` rather than instead of it: a call that was
            # permitted and then failed is both, and a stack that dropped the first
            # would understate how much the door admitted.
            #
            # All four bands since 066a, where two were counted. Exhaustive over
            # migration 004's CHECK **except** `''`, which is an admitted call nothing
            # recorded an outcome for and is deliberately in no band: it is not a
            # success, and `ok` must not absorb it.
            #
            # Through `_OUTCOME_BANDS` rather than `if outcome in day`, which was the
            # first spelling and was wrong: the stored value is `error` and the band is
            # `errored`, so a membership test silently counted nothing for the one band
            # this series had before today. The map states the rename in the one place it
            # happens; Postgres states it in its `FILTER` clauses.
            band = self._OUTCOME_BANDS.get(record.get("outcome"))
            if band:
                day[band] += 1
        return [{"day": day, **counts} for day, counts in sorted(days.items())]

    def _door_spend(self, door: list[dict], stamp) -> list[dict]:
        """`_q_door_spend`'s twin: per day and per model, what door calls reported.

        Rows out, never dollars — the rate table is one layer up, so a store cannot
        disagree with the route about what anything cost.
        """
        buckets: dict[tuple, dict] = {}
        for record in door:
            # NULL means *this call touched no model*, which is nearly every row. Read as
            # zero it would produce one enormous `''` bucket contributing a spurious
            # unpriced-model warning to every day of the window.
            if record.get("input_tokens") is None:
                continue
            key = (stamp(record["ts"]), record.get("model") or "")
            bucket = buckets.setdefault(
                key,
                {
                    "day": key[0],
                    "model": key[1],
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cache_read_tokens": 0,
                    "cache_write_tokens": 0,
                },
            )
            for field in (
                "input_tokens",
                "output_tokens",
                "cache_read_tokens",
                "cache_write_tokens",
            ):
                # `or 0` for what the SQL's `COALESCE(SUM(...))` reads as zero.
                bucket[field] += record.get(field) or 0
        # Day then model — the SQL's `ORDER BY 1, 2`.
        return [buckets[key] for key in sorted(buckets)]

    def _effects_by_day(self, door: list[dict], stamp) -> list[dict]:
        days: dict[str, dict] = {}
        for record in door:
            if record.get("decision") == "deny":
                continue
            day = days.setdefault(stamp(record["ts"]), {"read": 0, "write": 0})
            effect = record.get("effect") or ""
            if effect in day:
                day[effect] += 1
        return [{"day": day, **counts} for day, counts in sorted(days.items())]

    def _identity(self, door: list[dict], stamp) -> list[dict]:
        days: dict[str, dict] = {}
        for record in door:
            day = days.setdefault(
                stamp(record["ts"]), {"verified": 0, "asserted": 0, "none": 0}
            )
            # Allow *and* deny, deliberately: 033c writes `identity_source` on refusals
            # too, and "what did we refuse, and on whose behalf" is the half of this
            # question an incident asks. An unknown value is counted as `none` rather
            # than dropped, because a call that vanishes from this series is worse than
            # one filed under the weakest claim.
            source = record.get("identity_source") or "none"
            day[source if source in day else "none"] += 1
        return [{"day": day, **counts} for day, counts in sorted(days.items())]

    def _latency(self, door: list[dict], stamp) -> list[dict]:
        days: dict[str, list] = {}
        for record in door:
            if record.get("decision") == "deny":
                continue
            duration = record.get("duration_ms")
            if duration is None:
                continue
            days.setdefault(stamp(record["ts"]), []).append(duration)

        out = []
        for day, values in sorted(days.items()):
            median, p95 = self._percentiles(values)
            out.append({"day": day, "median_ms": median, "p95_ms": p95})
        return out

    @staticmethod
    def _ranked(rows: list[dict], tiebreak) -> tuple[list[dict], int, dict]:
        """Cap a leaderboard and say what the cap left out. `_split_tail`'s twin.

        Busiest first, then the caller's tiebreak, so the order is identical in both
        stores rather than being whatever a dict or a group happened to produce — and
        then sliced at `LEADERBOARD`, which is where the fake being *kinder* by returning
        everything would be exactly the drift the contract suite exists to catch.

        Returns `(rows, count, tail)`. `count` is every row before the cap and `tail`
        sums the ones below it; both come from this one ordering, which is what the SQL
        gets from one scan and one window function.
        """
        ordered = sorted(rows, key=lambda row: (-row["calls"], tiebreak(row)))
        kept, cut = ordered[:LEADERBOARD], ordered[LEADERBOARD:]
        return (
            kept,
            len(ordered),
            {
                "n": len(cut),
                "calls": sum(row["calls"] for row in cut),
                "denied": sum(row["denied"] for row in cut),
            },
        )

    def _callers(self, tenant_id: str, door: list[dict]) -> tuple[list[dict], int, dict]:
        callers: dict[tuple, dict] = {}
        for record in door:
            kind, ident, owner = self._subject(tenant_id, record)
            key = (kind, ident)
            caller = callers.setdefault(
                key,
                {
                    "principal_kind": kind,
                    "principal_id": ident,
                    "owner": owner,
                    "calls": 0,
                    "denied": 0,
                    "writes": 0,
                    "tools": set(),
                    "last_seen": None,
                },
            )
            caller["calls"] += 1
            if record.get("decision") == "deny":
                caller["denied"] += 1
            elif record.get("effect") == "write":
                caller["writes"] += 1
            caller["tools"].add(record.get("tool"))
            # Compared as instants, not as strings: a string max is only chronological
            # while every offset matches, and Postgres' `max(ts)` has no such caveat.
            seen = self._as_utc(record.get("ts"))
            if caller["last_seen"] is None or seen > caller["last_seen"]:
                caller["last_seen"] = seen

        rows = [
            {
                **caller,
                "tools": len(caller["tools"]),
                # UTC ISO with milliseconds — the exact string the real store's
                # `.isoformat(timespec="milliseconds")` renders its `max(ts)` as.
                "last_seen": caller["last_seen"].isoformat(timespec="milliseconds"),
            }
            for caller in callers.values()
        ]
        return self._ranked(rows, lambda row: row["principal_id"] or "")

    def _tool_totals(self, door: list[dict]) -> tuple[list[dict], int, dict]:
        tools: dict[str, dict] = {}
        for record in door:
            tool = tools.setdefault(
                record.get("tool") or "",
                {"tool": record.get("tool") or "", "effect": "", "calls": 0, "denied": 0},
            )
            tool["calls"] += 1
            if record.get("decision") == "deny":
                tool["denied"] += 1
            # `max`, matching the SQL's `max(effect)` exactly rather than rhyming with
            # it: `'write' > 'read' > ''` in both orderings, so a refusal's empty
            # effect never wins over a bound one — and "last non-empty seen", the first
            # version here, would have drifted from Postgres the day a tool ever
            # carried two different effects, in whichever order the rows arrived.
            tool["effect"] = max(tool["effect"], record.get("effect") or "")
        return self._ranked(list(tools.values()), lambda row: row["tool"])

    # `_door_agents`, not `_agents`: this store keeps the tenant's agent rows in
    # `self._agents`, and a series helper by that name shadows the table it reads nothing
    # from. Found by the contract suite in the first minute, which is the argument for
    # running it.
    def _door_agents(self, door: list[dict]) -> tuple[list[dict], int, dict]:
        """`_q_agents`' twin — which permission list admitted the traffic."""
        agents: dict[str, dict] = {}
        for record in door:
            name = record.get("agent") or ""
            agent = agents.setdefault(
                name,
                {"agent": name, "tools": set(), "calls": 0, "denied": 0},
            )
            agent["calls"] += 1
            if record.get("decision") == "deny":
                agent["denied"] += 1
            agent["tools"].add(record.get("tool"))
        rows = [{**agent, "tools": len(agent["tools"])} for agent in agents.values()]
        return self._ranked(rows, lambda row: row["agent"])

    def _acting_for(self, door: list[dict]) -> tuple[list[dict], int, dict]:
        """`_q_acting_for`' twin — whose name, and what the claim was worth.

        Keyed on the **pair**, never on the name: one person reached once on their own
        verified token and once on an application's word is two rows, because collapsing
        them would upgrade the second. 033c's rule.
        """
        names: dict[tuple, dict] = {}
        for record in door:
            name = record.get("acting_for") or ""
            # Excluded rather than bucketed as "(nobody)": `identity_source='none'` is
            # already a band on the identity chart, and an unnamed row would top this
            # list on every deployment and crowd out what it exists to show.
            if not name:
                continue
            key = (name, record.get("identity_source") or "none")
            row = names.setdefault(
                key,
                {
                    "acting_for": key[0],
                    "identity_source": key[1],
                    "calls": 0,
                    "denied": 0,
                },
            )
            row["calls"] += 1
            if record.get("decision") == "deny":
                row["denied"] += 1
        return self._ranked(
            list(names.values()),
            lambda row: (row["acting_for"], row["identity_source"]),
        )

    def _refusal_reasons(self, door: list[dict]) -> tuple[list[dict], int, dict]:
        """`_q_refusal_reasons`' twin — the sentences the controls actually wrote."""
        reasons: dict[str, dict] = {}
        for record in door:
            if record.get("decision") != "deny":
                continue
            reason = record.get("reason") or ""
            if not reason:
                continue
            row = reasons.setdefault(reason, {"reason": reason, "calls": 0, "denied": 0})
            row["calls"] += 1
            row["denied"] += 1
        rows, count, tail = self._ranked(
            list(reasons.values()), lambda row: row["reason"]
        )
        # `calls`/`denied` are what `_ranked` sorts and sums on; the wire calls this one
        # `count`, because a refusal reason has one number and naming it twice on the row
        # would invite somebody to wonder how they could differ.
        return (
            [{"reason": row["reason"], "count": row["calls"]} for row in rows],
            count,
            tail,
        )

    def _tool_latency(self, door: list[dict]) -> list[dict]:
        """`_q_tool_latency`' twin. Capped without a tail — see the SQL for why."""
        tools: dict[str, list] = {}
        for record in door:
            if record.get("decision") == "deny":
                continue
            duration = record.get("duration_ms")
            if duration is None:
                continue
            tools.setdefault(record.get("tool") or "", []).append(duration)

        rows: list[dict] = []
        for tool, values in tools.items():
            median, p95 = self._percentiles(values)
            rows.append(
                {
                    "tool": tool,
                    "calls": len(values),
                    "median_ms": median,
                    "p95_ms": p95,
                }
            )
        # Slowest first — the SQL's `ORDER BY med DESC NULLS LAST, tool`. A median is
        # never None here (every row in `values` is a real measurement, so the list is
        # non-empty), and `or 0` is the belt for a `_percentiles` that ever changed.
        return sorted(rows, key=lambda row: (-(row["median_ms"] or 0), row["tool"]))[
            :LEADERBOARD
        ]

    def _bytes(self, door: list[dict], stamp) -> list[dict]:
        """`_q_bytes`' twin — what the door carried back."""
        days: dict[str, list] = {}
        for record in door:
            if record.get("decision") == "deny":
                continue
            size = record.get("response_bytes")
            if size is None:
                continue
            days.setdefault(stamp(record["ts"]), []).append(size)

        out = []
        for day, values in sorted(days.items()):
            _, p95 = self._percentiles(values)
            out.append({"day": day, "bytes": sum(values), "p95_bytes": p95})
        return out

    def _hourly(self, door: list[dict]) -> list[dict]:
        """`_q_hourly`' twin — weekday x hour of day, across the window.

        `datetime.weekday()` is already 0=Monday, which is the numbering the wire
        carries; it is Postgres that converts, because its `dow` is 0=Sunday. Stated in
        both places rather than in neither.
        """
        cells: dict[tuple, int] = {}
        for record in door:
            moment = self._as_utc(record.get("ts"))
            if moment is None:
                continue
            key = (moment.weekday(), moment.hour)
            cells[key] = cells.get(key, 0) + 1
        return [
            {"weekday": weekday, "hour": hour, "calls": calls}
            for (weekday, hour), calls in sorted(cells.items())
        ]

    def _refusals(
        self,
        door: list[dict],
        in_product: list[dict],
        denials: list[dict],
        stamp,
    ) -> list[dict]:
        days: dict[str, dict] = {}

        def slot(ts) -> dict:
            return days.setdefault(
                stamp(ts),
                {
                    "policy": 0,
                    "ceiling": 0,
                    "door_spend": 0,
                    "run_budget": 0,
                    "access": 0,
                },
            )

        for record in door:
            if record.get("decision") != "deny":
                continue
            reason = record.get("reason") or ""
            # The door's two ceilings first, then everything else. A door call has no
            # `core.limits.Budget`, so `run_budget` is unreachable from here by
            # construction rather than by an `elif`.
            #
            # Money before calls, matching the SQL's band order, and it is a chain rather
            # than two independent tests so a single denial lands in exactly one band —
            # the four have to sum to the day's denials or the chart double-counts. The
            # two markers do not overlap as substrings (`SPEND_REFUSAL_MARKER` says why
            # that is load-bearing), so the order is defensive rather than necessary.
            if SPEND_REFUSAL_MARKER in reason:
                kind = "door_spend"
            elif CEILING_REFUSAL_MARKER in reason:
                kind = "ceiling"
            else:
                kind = "policy"
            slot(record["ts"])[kind] += 1

        for record in in_product:
            if record.get("decision") != "deny":
                continue
            reason = record.get("reason") or ""
            kind = "run_budget" if BUDGET_REFUSAL_MARKER in reason else "policy"
            slot(record["ts"])[kind] += 1

        for record in denials:
            slot(record["ts"])["access"] += 1

        return [{"day": day, **counts} for day, counts in sorted(days.items())]

    def _changes_by_family(self, admin: list[dict], stamp) -> list[dict]:
        counts: dict[tuple, int] = {}
        for record in admin:
            # The family is the prefix before the first dot — `grant.create` is
            # `grant`. Derived rather than maintained: the 45-action vocabulary in
            # `base.ADMIN_ACTIONS` is already dotted, so a new action joins an existing
            # family for free and a genuinely new family appears without anyone
            # updating a list that would otherwise silently drop it.
            family = str(record.get("action") or "").split(".", 1)[0]
            key = (stamp(record.get("ts")), family)
            counts[key] = counts.get(key, 0) + 1
        return [
            {"day": day, "family": family, "count": count}
            for (day, family), count in sorted(counts.items())
        ]

    # **`_runs_by_day`, `_run_latency` and `_schedule_health` were here until step 084**,
    # with `_elapsed_ms` beside them. They were `_q_runs`, `_q_run_latency` and
    # `_q_schedule_health`'s twins over `self._runs` and `self._schedules` — two dicts
    # nothing in this tree writes, for three series `routes_admin` discarded on every page
    # load. The fake goes when the real one does, or the contract suite stops meaning
    # anything.
    #
    # `_elapsed_ms` went with them because it had no other caller. `_as_utc`,
    # `_percentiles` and the `_day` / `_hour` stampers stay: every surviving series uses
    # at least one of them.

    # --- identity providers -----------------------------------------------------

    def save_tenant_idp(self, tenant_id: str, idp: dict) -> None:
        row = normalize_idp(idp)

        with self._lock:
            self._require_tenant(tenant_id)

            key = (row["issuer"], row["discriminator_claim"], row["discriminator_value"])
            self._check_issuer_conflict(key, tenant_id)

            was = (self._idps.get(key) or {}).get("groups_claim")
            self._idps[key] = {**row, "tenant_id": tenant_id}
            # Step 033e: the claim mapping is half of what a reconciliation reads, so a
            # registration that **moves** it must be believed at the next request — and
            # one that does not must not stampede the tenant. See the Postgres sibling.
            if was != row["groups_claim"]:
                self._forget_directory_digests(tenant_id)

    def _check_issuer_conflict(self, key: tuple, tenant_id: str) -> None:
        """The rule no UNIQUE can express. Caller holds the lock.

        A row with no discriminator claims the whole issuer, so it cannot coexist with
        any other row for that issuer — in either direction. And an exact key already
        held by another tenant is a takeover, not a mistake.
        """
        issuer, claim, _value = key

        existing = self._idps.get(key)
        if existing is not None and existing["tenant_id"] != tenant_id:
            raise IssuerConflictError(
                f"issuer '{issuer}' is already registered to tenant "
                f"'{existing['tenant_id']}'. An identity provider speaks for one "
                "customer; registering it twice is how one reads the other's data."
            )

        for other_key, other in self._idps.items():
            if other_key[0] != issuer or other_key == key:
                continue
            if claim is None:
                raise IssuerConflictError(
                    f"issuer '{issuer}' already has a provider registered with a "
                    f"discriminator ({other_key[1]}={other_key[2]}). A registration "
                    "without one claims the whole issuer and cannot coexist with it."
                )
            if other_key[1] is None:
                raise IssuerConflictError(
                    f"issuer '{issuer}' is already registered without a "
                    f"discriminator, by tenant '{other['tenant_id']}', which claims "
                    "the whole issuer. Both registrations must discriminate, or "
                    "neither can."
                )

    def find_tenant_idps(self, issuer: str) -> list[dict]:
        with self._lock:
            rows = [
                copy.deepcopy(row)
                for key, row in self._idps.items()
                if key[0] == issuer
            ]
        return sorted(rows, key=lambda r: (r["discriminator_value"] or "",))

    def list_tenant_idps(self, tenant_id: str) -> list[dict]:
        with self._lock:
            rows = [
                copy.deepcopy(row)
                for row in self._idps.values()
                if row["tenant_id"] == tenant_id
            ]
        return sorted(rows, key=lambda r: (r["issuer"], r["discriminator_value"] or ""))

    def delete_tenant_idp(
        self, tenant_id: str, issuer: str, discriminator_value: str | None = None
    ) -> None:
        with self._lock:
            doomed = [
                key
                for key, row in self._idps.items()
                if key[0] == issuer
                and key[2] == discriminator_value
                and row["tenant_id"] == tenant_id
            ]
            for key in doomed:
                del self._idps[key]

    # --- users ------------------------------------------------------------------

    def create_user(
        self, tenant_id: str, user: dict, *, actor: str | None = None
    ) -> None:
        row = normalize_user(user)

        # Built before the lock, on `_append_admin`'s ordering: a bad actor leaves the
        # store untouched. None for the JIT sign-in path, which writes no record.
        record = (
            None
            if actor is None
            else make_admin_record(
                "user.create", "user", row["id"], actor, {"provisioned": True}
            )
        )

        with self._lock:
            self._require_tenant(tenant_id)

            if row["id"] in self._users:
                raise StorageError(f"user id '{row['id']}' already exists")

            # `UNIQUE (issuer, subject)`, and NULLs are distinct to it: two provisioned
            # rows at one issuer coexist, so the pair is only checked when there is one.
            if row["subject"] is not None:
                pair = (row["issuer"], row["subject"])
                for existing in self._users.values():
                    if (existing["issuer"], existing["subject"]) == pair:
                        raise StorageError(
                            f"a user for subject '{row['subject']}' at issuer "
                            f"'{row['issuer']}' already exists. Identity is the pair; "
                            "a person cannot belong to two customers."
                        )

            if row["external_id"] is not None:
                self._check_user_external_id_free(
                    tenant_id, row["issuer"], row["external_id"], row["id"]
                )

            self._users[row["id"]] = {
                **row,
                "tenant_id": tenant_id,
                "created_at": datetime.now(timezone.utc),
                "last_seen_at": None,
                # Migration 043, and here rather than in `normalize_user` for the reason
                # `last_seen_at` is: they are columns this store owns the lifecycle of,
                # never fields a caller supplies. NULL until a reconciliation runs.
                "directory_digest": None,
                "directory_synced_at": None,
            }
            if record is not None:
                self._append_admin(tenant_id, record)

    def _check_user_external_id_free(
        self, tenant_id: str, issuer: str, external_id: str, user_id: str
    ) -> None:
        """`users_by_external_id`, migration 052's partial unique index. Caller holds
        the lock. A fake that permitted what Postgres refuses is the drift the contract
        suite exists to catch."""
        for other in self._users.values():
            if (
                other["tenant_id"] == tenant_id
                and other["issuer"] == issuer
                and other["external_id"] == external_id
                and other["id"] != user_id
            ):
                raise StorageError(
                    f"another person in this tenant at issuer '{issuer}' already "
                    f"holds the directory id '{external_id}' (user '{other['id']}'). "
                    "The directory sent one object id for two people; that is its "
                    "record to read, not ours to resolve by picking one."
                )

    def find_user(self, issuer: str, subject: str | None) -> dict | None:
        # A provisioned row has no subject, and a token with none must be nobody —
        # returned before looking, so the answer does not depend on how `None == None`
        # happens to fall in this store versus `= NULL` in the other.
        if not subject:
            return None
        with self._lock:
            for row in self._users.values():
                if row["issuer"] == issuer and row["subject"] == subject:
                    return copy.deepcopy(row)
        return None

    def find_provisioned_user(
        self, tenant_id: str, issuer: str, email: str
    ) -> dict | None:
        wanted = normalize_email(email)
        if not wanted:
            return None
        with self._lock:
            matches = [
                copy.deepcopy(row)
                for row in self._users.values()
                if row["tenant_id"] == tenant_id
                and row["issuer"] == issuer
                and row["subject"] is None
                and row["email"]
                and normalize_email(row["email"]) == wanted
            ]
        # Earliest created, then lowest id — the ordering the Protocol states, so two
        # provisioned rows with one address resolve the same way in both stores.
        matches.sort(key=lambda r: (r["created_at"], r["id"]))
        return matches[0] if matches else None

    def adopt_user_subject(
        self, tenant_id: str, user_id: str, subject: str, *, actor: str
    ) -> bool:
        if not subject or not subject.strip():
            raise StorageError(
                "a provisioned row cannot be adopted by a blank subject: `find_user` "
                "never matches one, so the person could never sign in again."
            )
        subject = subject.strip()
        split_actor(actor)

        with self._lock:
            row = self._users.get(user_id)
            if row is None or row["tenant_id"] != tenant_id:
                return False
            # The compare-and-set. Postgres gets this from `subject IS NULL` in the
            # UPDATE's WHERE clause; a second sign-in racing for the row loses here.
            if row["subject"] is not None:
                return False

            for other in self._users.values():
                if other["issuer"] == row["issuer"] and other["subject"] == subject:
                    raise StorageError(
                        f"a user for subject '{subject}' at issuer '{row['issuer']}' "
                        "already exists. Identity is the pair; a provisioned row "
                        "cannot be adopted by somebody who is already here."
                    )

            record = make_admin_record(
                "user.adopt", "user", user_id, actor, {"issuer": row["issuer"]}
            )
            row["subject"] = subject
            self._append_admin(tenant_id, record)
            return True

    def find_user_by_external_id(
        self, tenant_id: str, issuer: str, external_id: str
    ) -> dict | None:
        if not external_id:
            return None
        with self._lock:
            for row in self._users.values():
                if (
                    row["tenant_id"] == tenant_id
                    and row["issuer"] == issuer
                    and row["external_id"] == external_id
                ):
                    return copy.deepcopy(row)
        return None

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
        split_actor(actor)
        wanted: dict = {}
        if email is not None:
            wanted["email"] = email
        if display_name is not None:
            wanted["display_name"] = display_name
        if external_id is not _UNSET:
            wanted["external_id"] = normalize_user_external_id(external_id)

        with self._lock:
            row = self._users.get(user_id)
            if row is None or row["tenant_id"] != tenant_id:
                return None

            changed = sorted(k for k, v in wanted.items() if row[k] != v)
            if not changed:
                return copy.deepcopy(row)

            if "external_id" in changed and wanted["external_id"] is not None:
                self._check_user_external_id_free(
                    tenant_id, row["issuer"], wanted["external_id"], user_id
                )

            record = make_admin_record(
                "user.update", "user", user_id, actor, {"fields": changed}
            )
            for key in changed:
                row[key] = wanted[key]
            self._append_admin(tenant_id, record)
            return copy.deepcopy(row)

    def list_users(self, tenant_id: str) -> list[dict]:
        with self._lock:
            rows = [
                copy.deepcopy(row)
                for row in self._users.values()
                if row["tenant_id"] == tenant_id
            ]
        return sorted(rows, key=lambda r: r["id"])

    def get_user(self, tenant_id: str, user_id: str) -> dict | None:
        with self._lock:
            row = self._users.get(user_id)
            # Keyed by id alone in this dict, so the tenant is checked rather than being
            # part of the lookup — the filter Postgres puts in the WHERE clause, and it
            # has to be here too or the fake would read across tenants where the real
            # store does not.
            if row is None or row["tenant_id"] != tenant_id:
                return None
            return copy.deepcopy(row)

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

        with self._lock:
            row = self._users.get(user_id)
            if row is None or row["tenant_id"] != tenant_id:
                return None
            # Already so: return the row, write nothing. Postgres gets this from
            # `status <> %s` in the UPDATE's WHERE clause.
            if row["status"] == status:
                return copy.deepcopy(row)
            row["status"] = status
            self._append_admin(tenant_id, record)
            return copy.deepcopy(row)

    def record_user_login(self, user_id: str, email: str, display_name: str) -> None:
        with self._lock:
            row = self._users.get(user_id)
            if row is None:
                return
            row["email"] = email
            row["display_name"] = display_name
            row["last_seen_at"] = datetime.now(timezone.utc)

    def record_directory_sync(
        self,
        tenant_id: str,
        user_id: str,
        digest: str,
        synced_at: datetime | None,
        *,
        expect: str | None = None,
    ) -> None:
        with self._lock:
            row = self._users.get(user_id)
            if row is None or row["tenant_id"] != tenant_id:
                return
            if row["directory_digest"] != expect:
                # Somebody invalidated the marker while this reconciliation was in
                # flight — see the Postgres sibling's `IS NOT DISTINCT FROM`.
                return
            row["directory_digest"] = digest
            row["directory_synced_at"] = synced_at

    def _forget_directory_digests(self, tenant_id: str) -> None:
        """Caller holds the lock. See `PostgresStorage._forget_directory_digests`."""
        for row in self._users.values():
            # The same `directory_digest IS NOT NULL` predicate the SQL carries, so the
            # two stores stay identical for a caller that ever stamps one column
            # without the other.
            if row["tenant_id"] == tenant_id and row["directory_digest"] is not None:
                # The digest only — `directory_synced_at` is the ordering fact and
                # survives, or an older token flaps a membership back after every link.
                row["directory_digest"] = None

    def directory_groups(self, tenant_id: str, user_id: str) -> list[dict]:
        with self._lock:
            rows = [
                {
                    "group_id": row["group_id"],
                    "external_id": row["external_id"],
                    "member": (tenant_id, row["group_id"], "user", user_id)
                    in self._members,
                }
                for row in self._groups.values()
                if row["tenant_id"] == tenant_id and row["external_id"] is not None
            ]
        return sorted(rows, key=lambda r: r["group_id"])

    # --- api tokens -------------------------------------------------------------

    def create_api_token(self, tenant_id: str, token: dict, *, actor: str) -> dict:
        row = normalize_api_token(token)
        record = make_admin_record(
            "token.mint",
            "machine",
            row["id"],
            actor,
            {
                "name": row["name"],
                "owner": row["owner_id"],
                # Minting a personal token IS the trust decision of step 033d, so the
                # record carries it — the Postgres store writes the same detail.
                "acts_as_owner": row["acts_as_owner"],
                "expires_at": row["expires_at"].isoformat()
                if row["expires_at"]
                else "",
                # Step 083. Only when there is one, so a record written before this
                # key existed and one written by the CLI today read identically.
                **({"via": row["via"]} if row.get("via") else {}),
            },
        )

        with self._lock:
            self._require_tenant(tenant_id)

            if row["id"] in self._api_tokens:
                raise StorageError(f"api token id '{row['id']}' already exists")

            # Migration 054's two **partial** unique indexes, one per kind of token.
            # The `revoked_at is None` half is the load-bearing part: without it here
            # the fake would burn a name on revocation while Postgres frees it — a fake
            # STRICTER than the real store, which is migration 007's direction of drift
            # and the harder one to notice, because the refusal looks deliberate. The
            # `acts_as_owner` half is 054's: a personal token's name is unique among its
            # owner's live personal tokens, a service token's among the customer's live
            # service tokens, and the two kinds never collide with each other.
            for existing in self._api_tokens.values():
                if (
                    existing["tenant_id"] != tenant_id
                    or existing["name"] != row["name"]
                    or existing["revoked_at"] is not None
                    or existing["acts_as_owner"] != row["acts_as_owner"]
                ):
                    continue
                if row["acts_as_owner"]:
                    if existing["owner_id"] == row["owner_id"]:
                        raise ValueRefused(personal_name_taken(row["name"]))
                    continue
                raise ValueRefused(service_name_taken(row["name"]))

            self._api_tokens[row["id"]] = {
                "id": row["id"],
                "tenant_id": tenant_id,
                "name": row["name"],
                "owner_id": row["owner_id"],
                "acts_as_owner": row["acts_as_owner"],
                "created_by": actor,
                "created_at": datetime.now(timezone.utc),
                "expires_at": row["expires_at"],
                "revoked_at": None,
                "revoked_by": "",
                "last_used_at": None,
                "secret_hash": row["secret_hash"],
            }
            self._append_admin(tenant_id, record)
            return self._public_api_token(self._api_tokens[row["id"]])

    @staticmethod
    def _public_api_token(row: dict) -> dict:
        # Projected through the tuple rather than by deleting a key, so a field added to
        # the table and forgotten here is a contract-suite failure rather than a silent
        # difference — and so the hash cannot escape by somebody copying the dict.
        return {key: copy.deepcopy(row[key]) for key in API_TOKEN_PUBLIC_FIELDS}

    def find_api_token(self, token_id: str) -> dict | None:
        with self._lock:
            row = self._api_tokens.get(token_id)
            if row is None:
                return None
            return {key: copy.deepcopy(row[key]) for key in API_TOKEN_FIELDS}

    def list_api_tokens(self, tenant_id: str, *, owner_id: str = "") -> list[dict]:
        with self._lock:
            rows = [
                self._public_api_token(row)
                for row in self._api_tokens.values()
                if row["tenant_id"] == tenant_id
                and (not owner_id or row["owner_id"] == owner_id)
            ]
        return sorted(rows, key=lambda r: r["name"])

    def revoke_api_token(
        self, tenant_id: str, token_id: str, *, actor: str
    ) -> dict | None:
        record = make_admin_record("token.revoke", "machine", token_id, actor)

        with self._lock:
            row = self._api_tokens.get(token_id)
            if row is None or row["tenant_id"] != tenant_id:
                return None

            # Already revoked: return the row, write nothing. The Postgres store gets
            # this from `revoked_at IS NULL` in the UPDATE's WHERE clause.
            if row["revoked_at"] is not None:
                return self._public_api_token(row)

            row["revoked_at"] = datetime.now(timezone.utc)
            row["revoked_by"] = actor
            self._append_admin(tenant_id, record)
            return self._public_api_token(row)

    def touch_api_token(self, token_id: str) -> None:
        with self._lock:
            row = self._api_tokens.get(token_id)
            if row is None:
                return
            row["last_used_at"] = datetime.now(timezone.utc)

    # --- scim tokens -------------------------------------------------------------

    def mint_scim_token(self, tenant_id: str, row: dict, *, actor: str) -> dict:
        row = normalize_scim_token(row)
        record = make_admin_record(
            "scim.token.mint",
            "scim_token",
            row["id"],
            actor,
            {"issuer": row["issuer"], "name": row["name"]},
        )

        with self._lock:
            self._require_tenant(tenant_id)

            if row["id"] in self._scim_tokens:
                raise StorageError(f"scim token id '{row['id']}' already exists")

            # Bound to an issuer this tenant has registered — the Postgres sibling
            # reads `tenant_idps` inside the same transaction.
            if not any(
                idp["tenant_id"] == tenant_id and idp["issuer"] == row["issuer"]
                for idp in self._idps.values()
            ):
                raise ValueRefused(SCIM_ISSUER_NOT_REGISTERED.format(issuer=row["issuer"]))

            self._scim_tokens[row["id"]] = {
                "id": row["id"],
                "tenant_id": tenant_id,
                "issuer": row["issuer"],
                "name": row["name"],
                "created_by": row["created_by"],
                "created_at": datetime.now(timezone.utc),
                "revoked_at": None,
                "revoked_by": None,
                "last_used_at": None,
                "secret_hash": row["secret_hash"],
            }
            self._append_admin(tenant_id, record)
            return self._public_scim_token(self._scim_tokens[row["id"]])

    @staticmethod
    def _public_scim_token(row: dict) -> dict:
        # `_public_api_token`'s device: projected through the tuple so the hash cannot
        # escape by somebody copying the dict.
        return {key: copy.deepcopy(row[key]) for key in SCIM_TOKEN_PUBLIC_FIELDS}

    def find_scim_token(self, token_id: str) -> dict | None:
        with self._lock:
            row = self._scim_tokens.get(token_id)
            if row is None:
                return None
            return {key: copy.deepcopy(row[key]) for key in SCIM_TOKEN_FIELDS}

    def list_scim_tokens(self, tenant_id: str) -> list[dict]:
        with self._lock:
            rows = [
                self._public_scim_token(row)
                for row in self._scim_tokens.values()
                if row["tenant_id"] == tenant_id
            ]
        return sorted(rows, key=lambda r: (r["created_at"], r["id"]))

    def revoke_scim_token(
        self, tenant_id: str, token_id: str, *, actor: str
    ) -> dict | None:
        record = make_admin_record("scim.token.revoke", "scim_token", token_id, actor)

        with self._lock:
            row = self._scim_tokens.get(token_id)
            if row is None or row["tenant_id"] != tenant_id:
                return None
            if row["revoked_at"] is not None:
                return self._public_scim_token(row)
            row["revoked_at"] = datetime.now(timezone.utc)
            row["revoked_by"] = actor
            self._append_admin(tenant_id, record)
            return self._public_scim_token(row)

    def touch_scim_token(self, token_id: str) -> None:
        with self._lock:
            row = self._scim_tokens.get(token_id)
            if row is None:
                return
            row["last_used_at"] = datetime.now(timezone.utc)

    def tenant_has_live_scim_token(self, tenant_id: str, issuer: str) -> bool:
        with self._lock:
            return any(
                row["tenant_id"] == tenant_id
                and row["issuer"] == issuer
                and row["revoked_at"] is None
                for row in self._scim_tokens.values()
            )

    # --- the MCP door's per-token budget ------------------------------------------

    def spend_mcp_call(
        self, tenant_id: str, subject: str, window_start, *, ceiling: int
    ) -> int | None:
        # Under the lock for the whole read-modify-write, which is this store's version
        # of the Postgres statement's atomicity: the API runs endpoints in a threadpool,
        # so two threads reaching `ceiling - 1` together is an ordinary shape here and
        # not a hypothetical.
        key = (tenant_id, subject, window_start)
        with self._lock:
            spent = self._mcp_budget.get(key, 0)
            if spent >= ceiling:
                return None
            self._mcp_budget[key] = spent + 1
            return spent + 1

    def mcp_calls_spent(self, tenant_id: str, subject: str, window_start) -> int:
        with self._lock:
            return self._mcp_budget.get((tenant_id, subject, window_start), 0)

    def mcp_call_windows(
        self,
        tenant_id: str,
        subject: str,
        *,
        since: date,
        until: date,
    ) -> list[dict]:
        with self._lock:
            # Sparse, exactly as the SELECT is: a window with no row is absent here and
            # absent there, and the zero-fill happens above both. A fake that filled the
            # gaps would be kinder than Postgres, which is the drift the contract suite
            # exists to catch rather than a convenience.
            windows = [
                (window, calls)
                for (tid, kid, window), calls in self._mcp_budget.items()
                if tid == tenant_id and kid == subject and since <= window <= until
            ]

        # Sorted here rather than relying on insertion order: the Postgres side gets
        # oldest-first from the key's own ordering, and a dict that happened to agree
        # would be an accident that a single out-of-order spend breaks.
        return [
            {"window_start": window.isoformat(), "calls": calls}
            for window, calls in sorted(windows)
        ]

    # --- schedules ----------------------------------------------------------------

    def create_schedule(self, tenant_id: str, schedule: dict, *, actor: str) -> dict:
        row = normalize_schedule(schedule)
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

        with self._lock:
            self._require_tenant(tenant_id)

            if row["id"] in self._schedules:
                raise StorageError(f"schedule id '{row['id']}' already exists")

            # Migration 033's two foreign keys, by hand. **Both are checked before
            # anything is written**, which is 021 defect 3's lesson in the store that has
            # no transaction to roll back: the fake wrote the agent dict and then called
            # something that could raise, leaving a state Postgres could not produce.
            agent_id = self._agent_id_of(tenant_id, row["agent_name"])
            if agent_id is None:
                raise ValueRefused(
                    NO_SUCH_AGENT_TO_SCHEDULE.format(
                        tenant=tenant_id, agent=row["agent_name"]
                    )
                )

            # The **composite** key, and the `tenant_id` half is the one that matters: a
            # token that exists in another customer is exactly as absent as one that does
            # not exist at all, and a fake that checked only existence would accept the
            # cross-tenant row Postgres refuses.
            token = self._api_tokens.get(row["token_id"])
            if token is None or token["tenant_id"] != tenant_id:
                raise ValueRefused(
                    NO_SUCH_TOKEN_TO_FIRE_AS.format(
                        tenant=tenant_id, token=row["token_id"]
                    )
                )

            now = datetime.now(timezone.utc)
            # `agent_id`, and no `agent_name` — migration 035 dropped the column, and
            # `_schedule_out` is where every reader gets the name from instead.
            self._schedules[row["id"]] = {
                "id": row["id"],
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "token_id": row["token_id"],
                "task": row["task"],
                "cadence": copy.deepcopy(row["cadence"]),
                "timezone": row["timezone"],
                "enabled": row["enabled"],
                "next_fire_at": row["next_fire_at"],
                "last_fired_at": None,
                "last_run_id": "",
                "last_outcome": "",
                "created_by": actor,
                "created_at": now,
                "updated_at": now,
            }
            self._append_admin(tenant_id, record)
            return self._schedule_out(self._schedules[row["id"]])

    def _schedule_out(self, row: dict) -> dict:
        """A stored schedule, as callers see it: `SCHEDULE_FIELDS`, `agent_name` derived."""
        return self._with_agent_name(row, SCHEDULE_FIELDS)

    def _trigger_out(self, row: dict) -> dict:
        """`_schedule_out` one table over. `TRIGGER_FIELDS`, `agent_name` derived."""
        return self._with_agent_name(row, TRIGGER_FIELDS)

    def update_schedule(
        self,
        tenant_id: str,
        schedule_id: str,
        changes: dict,
        *,
        actor: str,
        if_unchanged_since,
    ) -> dict | None:
        moved = normalize_schedule_changes(changes)

        with self._lock:
            row = self._schedules.get(schedule_id)
            if row is None or row["tenant_id"] != tenant_id:
                return None

            # The compare-and-set, and it is the whole method — Postgres gets this from
            # `AND updated_at = %s` inside one statement. Here the lock is what makes it
            # atomic, and returning None rather than raising keeps the two stores'
            # contract identical: gone and lost-the-race are one answer, told apart above.
            if row["updated_at"] != if_unchanged_since:
                return None

            # The composite foreign key by hand, `create_schedule`'s check verbatim,
            # because a retarget is the same write create makes and the `tenant_id` half
            # is the one that matters: a token in another customer is exactly as absent
            # as one that does not exist.
            if "token_id" in moved:
                token = self._api_tokens.get(moved["token_id"])
                if token is None or token["tenant_id"] != tenant_id:
                    raise ValueRefused(
                        NO_SUCH_TOKEN_TO_FIRE_AS.format(
                            tenant=tenant_id, token=moved["token_id"]
                        )
                    )

            record = make_admin_record(
                "schedule.update",
                "schedule",
                schedule_id,
                actor,
                schedule_update_detail(self._schedule_out(row), moved),
            )

            for key, value in moved.items():
                row[key] = copy.deepcopy(value) if key == "cadence" else value
            row["updated_at"] = datetime.now(timezone.utc)
            self._append_admin(tenant_id, record)
            return self._schedule_out(row)

    def runs_of_schedule(
        self, tenant_id: str, schedule_id: str, *, limit: int = 50
    ) -> list[dict]:
        check_version_limit(limit)
        prefix = schedule_key_prefix(schedule_id)

        # `list_runs`' own ordering by `seq` rather than by `created_at`, for its reason:
        # runs submitted inside one clock tick share a timestamp. The filter is in the
        # comprehension here and in the WHERE clause in Postgres, which is the point of
        # the method — `limit` means `limit` in both.
        with self._lock:
            matching = sorted(
                (
                    row
                    for row in self._runs.values()
                    if row["tenant_id"] == tenant_id
                    and (row.get("idempotency_key") or "").startswith(prefix)
                ),
                key=lambda r: self._run_seq[r["run_id"]],
                reverse=True,
            )
            return [copy.deepcopy(row) for row in matching[:limit]]

    def get_schedule(self, tenant_id: str, schedule_id: str) -> dict | None:
        with self._lock:
            row = self._schedules.get(schedule_id)
            if row is None or row["tenant_id"] != tenant_id:
                return None
            return self._schedule_out(row)

    def list_schedules(self, tenant_id: str, *, agent_name: str = "") -> list[dict]:
        with self._lock:
            # Filtered on the id the name resolves to, so an absent agent has no schedules
            # — which is what the Postgres predicate answers too.
            wanted = self._agent_id_of(tenant_id, agent_name) if agent_name else None
            if agent_name and wanted is None:
                return []
            rows = [
                self._schedule_out(row)
                for row in self._schedules.values()
                if row["tenant_id"] == tenant_id
                and (wanted is None or row["agent_id"] == wanted)
            ]
        return sorted(rows, key=lambda r: (r["agent_name"], r["id"]))

    def due_schedules(self, *, now=None, limit: int = 100, limit_to_tenant=None):
        check_version_limit(limit)
        moment = now or datetime.now(timezone.utc)
        with self._lock:
            rows = [
                self._schedule_out(row)
                for row in self._schedules.values()
                if row["enabled"]
                and row["next_fire_at"] <= moment
                and (not limit_to_tenant or row["tenant_id"] == limit_to_tenant)
            ]
        return sorted(rows, key=lambda r: r["next_fire_at"])[:limit]

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
        # **Before the lock and before any mutation**, which is 021 defect 3's rule in the
        # store that has no transaction to roll back — and here it is also what stops a
        # single bad row poisoning `due_schedules` for every tenant at once.
        check_next_fire_at(next_fire_at)
        check_next_fire_at(if_next_fire_at, what="if_next_fire_at")
        check_outcome(last_run_id, last_outcome)

        with self._lock:
            row = self._schedules.get(schedule_id)
            if row is None or row["tenant_id"] != tenant_id:
                return None

            # The compare-and-set, which Postgres gets from `AND next_fire_at = %s` in
            # the UPDATE's WHERE clause. Under the same lock as the write, so there is no
            # window here either.
            if row["next_fire_at"] != if_next_fire_at:
                return None

            row["next_fire_at"] = next_fire_at
            if fired:
                row["last_fired_at"] = datetime.now(timezone.utc)
            row["last_run_id"] = last_run_id
            row["last_outcome"] = last_outcome
            row["updated_at"] = datetime.now(timezone.utc)
            return self._schedule_out(row)

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

        with self._lock:
            row = self._schedules.get(schedule_id)
            if row is None or row["tenant_id"] != tenant_id:
                return None

            # Already in that state: return it, write nothing. Postgres gets this from
            # `AND enabled <> %s` in the UPDATE's WHERE clause.
            if row["enabled"] == enabled:
                return self._schedule_out(row)

            row["enabled"] = enabled
            row["next_fire_at"] = next_fire_at
            row["updated_at"] = datetime.now(timezone.utc)
            self._append_admin(tenant_id, record)
            return self._schedule_out(row)

    def delete_schedule(self, tenant_id: str, schedule_id: str, *, actor: str) -> bool:
        record = make_admin_record("schedule.delete", "schedule", schedule_id, actor)

        with self._lock:
            row = self._schedules.get(schedule_id)
            if row is None or row["tenant_id"] != tenant_id:
                return False
            del self._schedules[schedule_id]
            self._append_admin(tenant_id, record)
            return True

    # --- event triggers ---------------------------------------------------------

    def create_trigger(self, tenant_id: str, trigger: dict, *, actor: str) -> dict:
        row = normalize_trigger(trigger)
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

        with self._lock:
            self._require_tenant(tenant_id)

            if row["id"] in self._triggers:
                raise StorageError(f"trigger id '{row['id']}' already exists")

            # Migration 034's two foreign keys by hand, before anything is written —
            # `create_schedule`'s checks at the next table, including the composite
            # half: a token in another customer is exactly as absent as none.
            agent_id = self._agent_id_of(tenant_id, row["agent_name"])
            if agent_id is None:
                raise ValueRefused(
                    NO_SUCH_AGENT_TO_TRIGGER.format(
                        tenant=tenant_id, agent=row["agent_name"]
                    )
                )

            token = self._api_tokens.get(row["token_id"])
            if token is None or token["tenant_id"] != tenant_id:
                raise ValueRefused(
                    NO_SUCH_TOKEN_TO_TRIGGER.format(
                        tenant=tenant_id, token=row["token_id"]
                    )
                )

            now = datetime.now(timezone.utc)
            self._triggers[row["id"]] = {
                "id": row["id"],
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "token_id": row["token_id"],
                "name": row["name"],
                "task": row["task"],
                "secret_sealed": row["secret_sealed"],
                "secret_key_id": row["secret_key_id"],
                "enabled": row["enabled"],
                "last_delivery_at": None,
                "last_run_id": "",
                "last_outcome": "",
                "created_by": actor,
                "created_at": now,
                "updated_at": now,
            }
            self._append_admin(tenant_id, record)
            return self._trigger_out(self._triggers[row["id"]])

    def get_trigger(self, tenant_id: str, trigger_id: str) -> dict | None:
        with self._lock:
            row = self._triggers.get(trigger_id)
            if row is None or row["tenant_id"] != tenant_id:
                return None
            return self._trigger_out(row)

    def find_trigger(self, trigger_id: str) -> dict | None:
        with self._lock:
            row = self._triggers.get(trigger_id)
            return self._trigger_out(row) if row is not None else None

    def list_triggers(self, tenant_id: str, *, agent_name: str = "") -> list[dict]:
        with self._lock:
            # `list_schedules`' filter, for its reasons.
            wanted = self._agent_id_of(tenant_id, agent_name) if agent_name else None
            if agent_name and wanted is None:
                return []
            rows = [
                self._trigger_out(row)
                for row in self._triggers.values()
                if row["tenant_id"] == tenant_id
                and (wanted is None or row["agent_id"] == wanted)
            ]
        return sorted(rows, key=lambda r: (r["agent_name"], r["id"]))

    def record_trigger_delivery(
        self, tenant_id: str, trigger_id: str, *, last_run_id: str, last_outcome: str
    ) -> None:
        # Before the lock and before any mutation — 021 defect 3's rule, and parity
        # with the TEXT columns Postgres would refuse.
        check_outcome(last_run_id, last_outcome)

        with self._lock:
            row = self._triggers.get(trigger_id)
            if row is None or row["tenant_id"] != tenant_id:
                return
            row["last_delivery_at"] = datetime.now(timezone.utc)
            row["last_run_id"] = last_run_id
            row["last_outcome"] = last_outcome
            row["updated_at"] = datetime.now(timezone.utc)

    def rotate_trigger_secret(
        self,
        tenant_id: str,
        trigger_id: str,
        *,
        secret_sealed,
        secret_key_id: str,
        actor: str,
    ) -> dict | None:
        # The same refusal `check_trigger` makes at create, at the second door into the
        # column: a plaintext secret must never reach storage, and a `str` here is what
        # that mistake looks like.
        check_sealed_secret(secret_sealed)

        with self._lock:
            row = self._triggers.get(trigger_id)
            if row is None or row["tenant_id"] != tenant_id:
                return None

            record = make_admin_record(
                "trigger.rotate",
                "trigger",
                trigger_id,
                actor,
                # The agent and the name, and nothing about either secret — see
                # `ADMIN_ACTIONS`. `_trigger_out` is how the name is resolved, because
                # migration 035 keeps `agent_id` and derives `agent_name` on read.
                {
                    "agent": self._trigger_out(row)["agent_name"],
                    "name": row["name"],
                },
            )

            # **`bytes()`, and this is the third writer of this column agreeing with the
            # other two rather than a conversion for its own sake.** `normalize_trigger`
            # does it at create and `reseal_trigger_secret` does it at the key sweep;
            # without it here a `bytearray` is kept as one by the fake and stored as
            # `bytes` by Postgres — the exact store divergence the contract suite exists
            # to catch, and one it missed because its probe passed a `bytes` literal.
            #
            # A `memoryview` was worse: `_trigger_out` deep-copies every field, and
            # `copy.deepcopy` raises `TypeError: cannot pickle memoryview objects` — an
            # exception escaping the storage boundary as neither `StorageError` nor
            # anything a caller can catch. That door was opened by widening
            # `check_sealed_secret` to accept `memoryview` for parity with
            # `check_reseal`; widening what a guard admits without widening what the
            # write normalises is how a consistency fix becomes a crash.
            row["secret_sealed"] = bytes(secret_sealed)
            row["secret_key_id"] = secret_key_id
            row["updated_at"] = datetime.now(timezone.utc)
            self._append_admin(tenant_id, record)
            return self._trigger_out(row)

    def set_trigger_enabled(
        self, tenant_id: str, trigger_id: str, enabled: bool, *, actor: str
    ) -> dict | None:
        record = make_admin_record(
            "trigger.enable" if enabled else "trigger.disable",
            "trigger",
            trigger_id,
            actor,
        )

        with self._lock:
            row = self._triggers.get(trigger_id)
            if row is None or row["tenant_id"] != tenant_id:
                return None

            # Already in that state: return it, write nothing — `set_schedule_enabled`'s
            # idempotence, which Postgres gets from `AND enabled <> %s`.
            if row["enabled"] == enabled:
                return self._trigger_out(row)

            row["enabled"] = enabled
            row["updated_at"] = datetime.now(timezone.utc)
            self._append_admin(tenant_id, record)
            return self._trigger_out(row)

    def delete_trigger(self, tenant_id: str, trigger_id: str, *, actor: str) -> bool:
        record = make_admin_record("trigger.delete", "trigger", trigger_id, actor)

        with self._lock:
            row = self._triggers.get(trigger_id)
            if row is None or row["tenant_id"] != tenant_id:
                return False
            del self._triggers[trigger_id]
            self._append_admin(tenant_id, record)
            return True

    # --- agent grants -----------------------------------------------------------

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
        # The widened CHECK and `agent_grants_no_group_owner`, both from migration 017.
        check_grant(grantee_kind, role)

        with self._lock:
            self._require_tenant(tenant_id)
            # Migration 035's key. Resolved under the lock, so the id the grant is written
            # against is the one the agent had when it was checked.
            agent_id = self._agent_id_of(tenant_id, agent_name)
            if agent_id is None:
                # The foreign key. A grant on a nonexistent agent is a row pointing at
                # nothing, and before migration 035 it was worse than that: a row that
                # reactivated the moment the name was reused.
                raise StorageError(
                    f"no agent named '{agent_name}' in tenant '{tenant_id}'"
                )
            key = (tenant_id, agent_id, grantee_kind, grantee_id)

            if grantee_kind == "group" and (tenant_id, grantee_id) not in self._groups:
                # No foreign key expresses this — see `grant_agent` in base.py — so it
                # is checked in both stores rather than in neither.
                raise NoSuchGroupError(
                    NO_SUCH_GROUP.format(group=grantee_id, tenant=tenant_id)
                )

            if role == OWNER_ROLE:
                # The partial unique index, in Python. Postgres refuses this with a
                # constraint name; both stores have to refuse it with the same sentence,
                # because the contract suite compares them and a person reads it.
                owner = self._owner_key(tenant_id, agent_id)
                if owner is not None and owner != key:
                    raise StorageError(OWNER_TAKEN.format(agent=agent_name))

            # `actor`, not `granted_by`. They carry the same string at every caller
            # today and they are not the same field: `granted_by` is a column, free
            # text, and migration 011 filled it with 'migration:011' for every agent it
            # adopted. `admin_audit.actor_kind` has a CHECK. See `grant_agent` in
            # base.py, where the plan's decision to merge them is argued out of.
            record = make_admin_record(
                "grant.create",
                "agent",
                agent_name,
                actor,
                # Deliberately **not** the previous role. It would cost a read on the one
                # method here that is anywhere near a hot path, and it is already in this
                # log: replaying `grant.create` and `grant.revoke` for one agent gives
                # every level a grantee has ever held. A record says what changed.
                {"grantee_kind": grantee_kind, "grantee_id": grantee_id, "role": role},
            )

            self._grants[key] = {
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "grantee_kind": grantee_kind,
                "grantee_id": grantee_id,
                "role": role,
                "granted_by": granted_by,
                "granted_at": datetime.now(timezone.utc),
            }
            self._append_admin(tenant_id, record)

    def revoke_agent(
        self,
        tenant_id: str,
        agent_name: str,
        grantee_kind: str,
        grantee_id: str,
        *,
        actor: str,
    ) -> None:
        with self._lock:
            agent_id = self._agent_id_of(tenant_id, agent_name)
            key = (tenant_id, agent_id, grantee_kind, grantee_id)
            removed = self._grants.get(key)
            if removed is None:
                # Idempotent, and no record. Revoking a grant nobody had changed
                # nothing, and this log has to be readable as "what access moved".
                return

            # **The role is read before the row goes**, and that is the whole point of
            # the step. `agent_grants.granted_by` records who granted access and is
            # destroyed by the revocation it should have recorded; this is the only
            # place the level Sam actually lost is ever written down.
            record = make_admin_record(
                "grant.revoke",
                "agent",
                agent_name,
                actor,
                {
                    "grantee_kind": grantee_kind,
                    "grantee_id": grantee_id,
                    "role": removed["role"],
                    "granted_by": removed["granted_by"],
                },
            )

            del self._grants[key]
            self._append_admin(tenant_id, record)

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
        check_principal_kind(principal_kind)

        # Under one lock for the whole of it. Postgres does this in a transaction for
        # the same reason: between demoting the old owner and promoting the new one the
        # agent has no owner, and nobody may observe that.
        with self._lock:
            self._require_tenant(tenant_id)
            agent_id = self._agent_id_of(tenant_id, agent_name)
            if agent_id is None:
                raise StorageError(
                    f"no agent named '{agent_name}' in tenant '{tenant_id}'"
                )

            key = (tenant_id, agent_id, principal_kind, principal_id)
            owner = self._owner_key(tenant_id, agent_id)

            record = make_admin_record(
                "grant.transfer",
                "agent",
                agent_name,
                actor,
                {
                    "to_kind": principal_kind,
                    "to_id": principal_id,
                    # Who stepped down, and to what. A transfer is the one write here
                    # that changes two people's access at once, and a record naming only
                    # the recipient would leave the demotion unattributed — the same
                    # half-a-record the whole step is about.
                    "from_kind": owner[2] if owner is not None else None,
                    "from_id": owner[3] if owner is not None else None,
                    "from_role": "editor" if owner is not None and owner != key else None,
                },
            )

            if owner is not None and owner != key:
                self._grants[owner]["role"] = "editor"

            now = datetime.now(timezone.utc)
            self._grants[key] = {
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                # A principal, checked as one above: a group cannot own an agent, so
                # this is the one write here that is narrower than `GRANTEE_KINDS`.
                "grantee_kind": principal_kind,
                "grantee_id": principal_id,
                "role": OWNER_ROLE,
                "granted_by": granted_by,
                "granted_at": now,
            }
            self._append_admin(tenant_id, record)

    def _owner_key(self, tenant_id: str, agent_id: str):
        """The key of this agent's owner row, if it has one. Caller holds the lock.

        Takes an **id** since migration 035, matching the collection it searches. The
        parameter was renamed rather than left reading `agent_name`: this store has two
        vocabularies now, and a name in a signature that wants an id is how a lookup that
        silently matches nothing gets written and reviewed.
        """
        for key, row in self._grants.items():
            if key[0] == tenant_id and key[1] == agent_id and row["role"] == OWNER_ROLE:
                return key
        return None

    def agent_grant_role(
        self, tenant_id: str, agent_name: str, principal_kind: str, principal_id: str
    ) -> str | None:
        """Highest of direct and inherited. Postgres does this in one statement; this
        does it with a set union, and the contract suite compares the answers."""
        with self._lock:
            agent_id = self._agent_id_of(tenant_id, agent_name)
            held = [
                row["role"]
                for row in self._grants_reaching(
                    tenant_id, principal_kind, principal_id
                )
                if agent_id is not None and row["agent_id"] == agent_id
            ]
        # `max` by ladder index, never by string order — alphabetically `editor` sorts
        # below `owner` sorts below `user`, which is the ladder upside down.
        return max(held, key=_level) if held else None

    def direct_agent_grant_role(
        self, tenant_id: str, agent_name: str, grantee_kind: str, grantee_id: str
    ) -> str | None:
        with self._lock:
            agent_id = self._agent_id_of(tenant_id, agent_name)
            row = self._grants.get((tenant_id, agent_id, grantee_kind, grantee_id))
            return None if row is None else row["role"]

    def granted_agent_names(
        self, tenant_id: str, principal_kind: str, principal_id: str
    ) -> list[str]:
        with self._lock:
            # The join, and the `is not None` is the cascade's shadow rather than
            # defensiveness: a grant whose agent is gone should not exist, and a name of
            # `None` in a list of names would be a crash somewhere else entirely.
            names = {
                self._agent_name_of(tenant_id, row["agent_id"])
                for row in self._grants_reaching(
                    tenant_id, principal_kind, principal_id
                )
            }
            return sorted(name for name in names if name is not None)

    def groups_granting_agent(
        self, tenant_id: str, agent_name: str, principal_kind: str, principal_id: str
    ) -> list[str]:
        with self._lock:
            mine = self._group_ids(tenant_id, principal_kind, principal_id)
            agent_id = self._agent_id_of(tenant_id, agent_name)
            return sorted(
                key[3]
                for key in self._grants
                if key[0] == tenant_id
                and agent_id is not None
                and key[1] == agent_id
                and key[2] == "group"
                and key[3] in mine
            )

    def _grants_reaching(
        self, tenant_id: str, principal_kind: str, principal_id: str
    ) -> list[dict]:
        """Every grant row this principal reaches, directly or through a group.

        Caller holds the lock. The union Postgres does inside one statement — kept in
        one place here for the same reason it is one statement there: two callers
        computing "reaches" separately is two chances to disagree about what access is.
        """
        mine = self._group_ids(tenant_id, principal_kind, principal_id)
        return [
            row
            for key, row in self._grants.items()
            if key[0] == tenant_id
            and (
                (key[2] == principal_kind and key[3] == principal_id)
                or (key[2] == "group" and key[3] in mine)
            )
        ]

    def _group_ids(self, tenant_id: str, principal_kind: str, principal_id: str) -> set:
        """Caller holds the lock."""
        return {
            key[1]
            for key in self._members
            if key[0] == tenant_id and key[2] == principal_kind and key[3] == principal_id
        }

    def list_agent_grants(self, tenant_id: str, agent_name: str) -> list[dict]:
        with self._lock:
            agent_id = self._agent_id_of(tenant_id, agent_name)
            if agent_id is None:
                return []
            rows = [
                self._with_agent_name(row, GRANT_FIELDS)
                for key, row in self._grants.items()
                if key[0] == tenant_id and key[1] == agent_id
            ]
        return sorted(rows, key=lambda r: (r["grantee_kind"], r["grantee_id"]))

    # --- groups -------------------------------------------------------------------

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
        if not group_id or not name:
            raise StorageError("a group needs an id and a name")

        external_id = normalize_external_id(external_id)

        with self._lock:
            self._require_tenant(tenant_id)

            # UNIQUE (tenant_id, name), and UNIQUE (tenant_id, external_id) — **name
            # first, across every row**, because Postgres checks its unique indexes in
            # declaration order (017 declares the name first) and a create colliding on
            # both must not report a different one of the two depending on which row was
            # inserted first. Two passes rather than one, for that reason alone.
            mine = [
                (key, row) for key, row in self._groups.items()
                if key[0] == tenant_id and key[1] != group_id
            ]
            for _key, row in mine:
                if row["name"] == name:
                    raise StorageError(
                        GROUP_NAME_TAKEN.format(tenant=tenant_id, name=name)
                    )
            for _key, row in mine:
                if external_id is not None and row["external_id"] == external_id:
                    raise StorageError(
                        GROUP_LINK_TAKEN.format(
                            tenant=tenant_id, external_id=external_id
                        )
                    )

            if (tenant_id, group_id) in self._groups:
                raise StorageError(f"group '{group_id}' already exists")

            record = make_admin_record(
                "group.create",
                "group",
                group_id,
                actor,
                {"name": name, "external_id": external_id},
            )

            row = {
                "tenant_id": tenant_id,
                "group_id": group_id,
                "name": name,
                "description": description,
                "external_id": external_id,
                "created_by": created_by,
                "created_at": datetime.now(timezone.utc),
            }
            self._groups[(tenant_id, group_id)] = row
            self._append_admin(tenant_id, record)
            if external_id is not None:
                self._forget_directory_digests(tenant_id)
            return copy.deepcopy(row)

    def set_group_external_id(
        self, tenant_id: str, group_id: str, external_id: str | None, *, actor: str
    ) -> dict:
        external_id = normalize_external_id(external_id)

        record = make_admin_record(
            "group.link", "group", group_id, actor, {"external_id": external_id}
        )

        with self._lock:
            row = self._groups.get((tenant_id, group_id))
            if row is None:
                raise NoSuchGroupError(
                    NO_SUCH_GROUP.format(group=group_id, tenant=tenant_id)
                )

            if row["external_id"] == external_id:
                # Changed nothing, so no record and no invalidation — see the Postgres
                # sibling, where the same rule is an `IS DISTINCT FROM` on the UPDATE.
                return copy.deepcopy(row)

            # UNIQUE (tenant_id, external_id), which Postgres enforces and this has to
            # too — a fake that permitted what the real store refuses is the drift the
            # contract suite exists to catch.
            if external_id is not None:
                for key, other in self._groups.items():
                    if (
                        key[0] == tenant_id
                        and key[1] != group_id
                        and other["external_id"] == external_id
                    ):
                        raise StorageError(
                            GROUP_LINK_TAKEN.format(
                                tenant=tenant_id, external_id=external_id
                            )
                        )

            row["external_id"] = external_id
            self._append_admin(tenant_id, record)
            if external_id is not None:
                self._forget_directory_digests(tenant_id)
            return copy.deepcopy(row)

    def rename_group(
        self, tenant_id: str, group_id: str, name: str, *, actor: str
    ) -> dict | None:
        if not name or not name.strip():
            raise StorageError("a group needs a name; a rename to nothing is refused")
        name = name.strip()
        split_actor(actor)

        with self._lock:
            row = self._groups.get((tenant_id, group_id))
            if row is None:
                return None
            if row["name"] == name:
                return copy.deepcopy(row)

            # UNIQUE (tenant_id, name), naming the other group — the Postgres sibling
            # reads it back after the violation.
            for key, other in self._groups.items():
                if key[0] == tenant_id and key[1] != group_id and other["name"] == name:
                    raise StorageError(
                        GROUP_RENAME_TAKEN.format(
                            tenant=tenant_id, name=name, other=other["group_id"]
                        )
                    )

            record = make_admin_record(
                "group.rename",
                "group",
                group_id,
                actor,
                {"from": row["name"], "to": name},
            )
            row["name"] = name
            self._append_admin(tenant_id, record)
            return copy.deepcopy(row)

    def get_group(self, tenant_id: str, group_id: str) -> dict | None:
        with self._lock:
            row = self._groups.get((tenant_id, group_id))
            return None if row is None else copy.deepcopy(row)

    def find_group_by_name(self, tenant_id: str, name: str) -> dict | None:
        with self._lock:
            for key, row in self._groups.items():
                if key[0] == tenant_id and row["name"] == name:
                    return copy.deepcopy(row)
            return None

    def list_groups(self, tenant_id: str) -> list[dict]:
        with self._lock:
            rows = [
                copy.deepcopy(row)
                for key, row in self._groups.items()
                if key[0] == tenant_id
            ]
        return sorted(rows, key=lambda r: r["name"])

    def delete_group(self, tenant_id: str, group_id: str, *, actor: str) -> bool:
        with self._lock:
            gone = self._groups.get((tenant_id, group_id))
            if gone is None:
                return False

            # Counted before the cascade runs, because afterwards there is nothing left
            # to count. Deleting a group takes away every access it carried, on every
            # agent, and the numbers are the only thing that says how much.
            record = make_admin_record(
                "group.delete",
                "group",
                group_id,
                actor,
                {
                    "name": gone["name"],
                    "members": sum(
                        1
                        for k in self._members
                        if k[0] == tenant_id and k[1] == group_id
                    ),
                    "grants": sum(
                        1
                        for k in self._grants
                        if k[0] == tenant_id and k[2] == "group" and k[3] == group_id
                    ),
                },
            )

            del self._groups[(tenant_id, group_id)]
            self._append_admin(tenant_id, record)

            # The foreign key cascade and migration 017's trigger, in Python. Both, and
            # in this order, because the point of the trigger is that a group's grants do
            # not outlive it as rows that grant nothing and look like access.
            for key in [
                k for k in self._members if k[0] == tenant_id and k[1] == group_id
            ]:
                del self._members[key]

            for key in [
                k
                for k in self._grants
                if k[0] == tenant_id and k[2] == "group" and k[3] == group_id
            ]:
                del self._grants[key]

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
        # Nesting refused by a rule that predates this step.
        check_principal_kind(principal_kind)

        if not principal_id:
            raise StorageError("a member needs a principal id")

        with self._lock:
            if (tenant_id, group_id) not in self._groups:
                raise NoSuchGroupError(
                    NO_SUCH_GROUP.format(group=group_id, tenant=tenant_id)
                )

            key = (tenant_id, group_id, principal_kind, principal_id)
            if key in self._members:
                # `ON CONFLICT DO NOTHING`, and nothing means no record either: adding
                # somebody who is already in the group changed nobody's access.
                return

            record = make_admin_record(
                "group.member.add",
                "group",
                group_id,
                actor,
                {"member_kind": principal_kind, "member_id": principal_id},
            )

            self._members[key] = {
                "tenant_id": tenant_id,
                "group_id": group_id,
                "principal_kind": principal_kind,
                "principal_id": principal_id,
                "added_by": added_by,
                "added_at": datetime.now(timezone.utc),
            }
            self._append_admin(tenant_id, record)

    def remove_group_member(
        self,
        tenant_id: str,
        group_id: str,
        principal_kind: str,
        principal_id: str,
        *,
        actor: str,
    ) -> bool:
        with self._lock:
            key = (tenant_id, group_id, principal_kind, principal_id)
            if key not in self._members:
                return False

            record = make_admin_record(
                "group.member.remove",
                "group",
                group_id,
                actor,
                {
                    "member_kind": principal_kind,
                    "member_id": principal_id,
                    "added_by": self._members[key]["added_by"],
                },
            )

            del self._members[key]
            self._append_admin(tenant_id, record)
            return True

    def list_group_members(self, tenant_id: str, group_id: str) -> list[dict]:
        with self._lock:
            rows = [
                copy.deepcopy(row)
                for key, row in self._members.items()
                if key[0] == tenant_id and key[1] == group_id
            ]
        return sorted(rows, key=lambda r: (r["principal_kind"], r["principal_id"]))

    def groups_for_principal(
        self, tenant_id: str, principal_kind: str, principal_id: str
    ) -> list[str]:
        with self._lock:
            return sorted(self._group_ids(tenant_id, principal_kind, principal_id))

    # --- platform roles -----------------------------------------------------------

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

        # Built first, mutated second, appended third — `_append_admin`'s rule, and the
        # only thing here that can raise is this call.
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

        with self._lock:
            self._require_tenant(tenant_id)
            row = {
                "tenant_id": tenant_id,
                "principal_kind": principal_kind,
                "principal_id": principal_id,
                "role": role,
                "granted_by": granted_by or actor,
                "granted_at": datetime.now(timezone.utc),
            }
            # An upsert, and re-granting records again — see `grant_platform_role` in
            # base.py. `allow_host` above does the same thing for the same reason.
            self._platform_roles[(tenant_id, principal_kind, principal_id, role)] = row
            self._append_admin(tenant_id, record)
            return copy.deepcopy(row)

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

        with self._lock:
            removed = self._platform_roles.pop(
                (tenant_id, principal_kind, principal_id, role), None
            )
            if removed is None:
                # No row, no record. The log records changes, not attempts.
                return False
            self._append_admin(tenant_id, record)
            return True

    def list_platform_roles(self, tenant_id: str) -> list[dict]:
        with self._lock:
            rows = [
                copy.deepcopy(row)
                for key, row in self._platform_roles.items()
                if key[0] == tenant_id
            ]
        return sorted(
            rows, key=lambda r: (r["principal_kind"], r["principal_id"], r["role"])
        )

    def has_platform_role(
        self, tenant_id: str, principal_kind: str, principal_id: str, role: str
    ) -> bool:
        with self._lock:
            return (
                tenant_id,
                principal_kind,
                principal_id,
                role,
            ) in self._platform_roles

    # --- pending grants ---------------------------------------------------------

    def find_user_by_email(self, tenant_id: str, email: str) -> dict | None:
        wanted = normalize_email(email)
        with self._lock:
            matches = [
                copy.deepcopy(row)
                for row in self._users.values()
                if row["tenant_id"] == tenant_id
                and normalize_email(row["email"]) == wanted
                and row["email"]
            ]
        # Ordered so two rows sharing an address resolve the same way every time. Two
        # can exist: `users` is unique on (issuer, subject), and one tenant may have two
        # providers. Rare, deterministic, and worth not being arbitrary about.
        return sorted(matches, key=lambda r: r["id"])[0] if matches else None

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
        check_pending_role(role)
        address = normalize_email(email)

        with self._lock:
            self._require_tenant(tenant_id)
            agent_id = self._agent_id_of(tenant_id, agent_name)
            if agent_id is None:
                raise StorageError(
                    f"no agent named '{agent_name}' in tenant '{tenant_id}'"
                )

            record = make_admin_record(
                "grant.pending.add",
                "agent",
                agent_name,
                actor,
                # The address is the identifying fact of the action — there is no
                # principal yet, so it is the only thing that says who this was for.
                {"email": address, "role": role},
            )

            self._pending[(tenant_id, agent_id, address)] = {
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "email": address,
                "role": role,
                "granted_by": granted_by,
                "granted_at": datetime.now(timezone.utc),
            }
            self._append_admin(tenant_id, record)

    def claim_pending_grants(
        self, tenant_id: str, email: str, principal_kind: str, principal_id: str
    ) -> list[str]:
        check_claimant(principal_kind)
        address = normalize_email(email)
        if not address:
            return []

        claimed = []
        with self._lock:
            waiting = [
                (key, row)
                for key, row in self._pending.items()
                if key[0] == tenant_id and key[2] == address
            ]
            for key, row in waiting:
                agent_id = row["agent_id"]
                agent_name = self._agent_name_of(tenant_id, agent_id)
                grant_key = (tenant_id, agent_id, principal_kind, principal_id)
                existing = self._grants.get(grant_key)

                # One record per agent claimed, all inside the one lock. The claim is
                # atomic across agents and the *access* is per agent, so this is the
                # granularity `admin_audit_records(target_id=...)` has to answer at.
                #
                # The claimant is the actor: a claim is somebody's own first login
                # collecting what was addressed to them, and `granted_by` — who shared
                # it, weeks ago — is carried in the detail rather than in the actor,
                # because they are different people and the record must not merge them.
                self._append_admin(
                    tenant_id,
                    make_admin_record(
                        "grant.pending.claim",
                        "agent",
                        agent_name,
                        f"{principal_kind}:{principal_id}",
                        {
                            "email": address,
                            "role": row["role"],
                            "granted_by": row["granted_by"],
                            # Whether it actually raised their level. A pending grant
                            # never demotes, so a claim can legitimately change nothing.
                            "applied": existing is None
                            or _level(existing["role"]) < _level(row["role"]),
                        },
                    ),
                )
                # A pending grant never demotes somebody. Shared at `user` while already
                # an editor, the claim would otherwise take access away at the moment of
                # a login, which is the worst possible time to discover it.
                if existing is None or _level(existing["role"]) < _level(row["role"]):
                    # **`grantee_kind` and `grantee_id`, which migration 017 renamed these
                    # to and this method never learned.** It wrote `principal_kind` and
                    # `principal_id` until step 025 found it: a grant row carrying the
                    # pre-017 field names, produced only by a claim, in the store every test
                    # runs against. `who_has_access` reads `row["grantee_kind"]`, so "who
                    # has access to this agent?" raised `KeyError` for any agent whose grant
                    # arrived through somebody's first login — and nothing noticed, because
                    # no test ever looked at a claimed agent's access list.
                    #
                    # Found by projecting these rows through `GRANT_FIELDS` on the way out,
                    # which is the device meant to catch exactly this and could not while
                    # the reader was a `deepcopy`.
                    self._grants[grant_key] = {
                        "tenant_id": tenant_id,
                        "agent_id": agent_id,
                        "grantee_kind": principal_kind,
                        "grantee_id": principal_id,
                        "role": row["role"],
                        "granted_by": row["granted_by"],
                        "granted_at": datetime.now(timezone.utc),
                    }
                del self._pending[key]
                claimed.append(agent_name)

        return sorted(claimed)

    def list_pending_grants(self, tenant_id: str, agent_name: str) -> list[dict]:
        with self._lock:
            agent_id = self._agent_id_of(tenant_id, agent_name)
            if agent_id is None:
                return []
            rows = [
                self._with_agent_name(row, PENDING_GRANT_FIELDS)
                for key, row in self._pending.items()
                if key[0] == tenant_id and key[1] == agent_id
            ]
        return sorted(rows, key=lambda r: r["email"])

    def delete_pending_grant(
        self, tenant_id: str, agent_name: str, email: str, *, actor: str
    ) -> None:
        address = normalize_email(email)
        with self._lock:
            key = (tenant_id, self._agent_id_of(tenant_id, agent_name), address)
            waiting = self._pending.get(key)
            if waiting is None:
                # No row, no record. `unshare_email` calls this on *both* of its
                # branches — a real revoke also clears any pending row left armed — so
                # recording unconditionally would log a cancellation every time somebody
                # revoked an ordinary grant.
                return

            record = make_admin_record(
                "grant.pending.delete",
                "agent",
                agent_name,
                actor,
                {
                    "email": address,
                    "role": waiting["role"],
                    "granted_by": waiting["granted_by"],
                },
            )

            del self._pending[key]
            self._append_admin(tenant_id, record)

    # --- connections ------------------------------------------------------------

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

        key = (tenant_id, principal_kind, principal_id, connector_id)
        now = datetime.now(timezone.utc)

        with self._lock:
            self._require_tenant(tenant_id)
            # Migration 021's insert half. Postgres gets this from
            # `connections_connector_fk`; without it here the fake would be the looser
            # of the two, which is the exact drift the contract suite exists to catch.
            if connector_id not in self._connectors.get(tenant_id, {}):
                raise UnknownConnectorError(
                    NO_SUCH_CONNECTOR.format(
                        connector=connector_id, tenant=tenant_id
                    )
                )
            # Reconnecting keeps the original created_at: "when did this person first
            # connect" and "when did this credential last change" are two questions,
            # and collapsing them loses the one the audit conversation wants.
            existing = self._connections.get(key)
            self._connections[key] = {
                "tenant_id": tenant_id,
                "principal_kind": principal_kind,
                "principal_id": principal_id,
                "connector_id": connector_id,
                "ciphertext": bytes(ciphertext),
                "key_id": key_id,
                "expires_at": expires_at,
                "account_label": account_label or "",
                "created_at": existing["created_at"] if existing else now,
                "updated_at": now,
                "credential_kind": credential_kind,
                "refresh_expires_at": refresh_expires_at,
                # Cleared on both branches, as in Postgres: reconnecting is the fix for
                # a revoked grant, so keeping the old refusal would tell somebody who did
                # exactly the right thing that it had not worked.
                "reconsent_reason": "",
            }
            self._append_admin(tenant_id, record)

    def find_connection(
        self, tenant_id: str, principal_kind: str, principal_id: str, connector_id: str
    ) -> dict | None:
        check_principal_kind(principal_kind)
        key = (tenant_id, principal_kind, principal_id, connector_id)
        with self._lock:
            row = self._connections.get(key)
            return copy.deepcopy(row) if row is not None else None

    def has_connection(
        self, tenant_id: str, principal_kind: str, principal_id: str, connector_id: str
    ) -> bool:
        check_principal_kind(principal_kind)
        with self._lock:
            return (tenant_id, principal_kind, principal_id, connector_id) in (
                self._connections
            )

    def list_connections(
        self,
        tenant_id: str,
        *,
        principal_kind: str | None = None,
        principal_id: str | None = None,
    ) -> list[dict]:
        if principal_kind is not None:
            check_principal_kind(principal_kind)

        with self._lock:
            rows = [
                {k: v for k, v in row.items() if k != "ciphertext"}
                for key, row in self._connections.items()
                if key[0] == tenant_id
                and (principal_kind is None or key[1] == principal_kind)
                and (principal_id is None or key[2] == principal_id)
            ]

        return sorted(
            copy.deepcopy(rows),
            key=lambda r: (r["principal_kind"], r["principal_id"], r["connector_id"]),
        )

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
            {"principal": f"{principal_kind}:{principal_id}", **(detail or {})},
        )
        with self._lock:
            gone = self._connections.pop(
                (tenant_id, principal_kind, principal_id, connector_id), None
            )
            if gone is None:
                return False
            self._append_admin(tenant_id, record)
            return True

    # --- OAuth ---------------------------------------------------------------------

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
        record = make_admin_record(
            "connector.oauth.configure",
            "connector",
            connector_id,
            actor,
            {
                "client_id": client_id,
                "scopes": list(wanted),
                "token_endpoint": token_endpoint,
                "authorize_params": extra,
                # Which scopes were annotated, never the prose. *Was the consent screen
                # explained when this was configured* is a real question after an
                # incident; three paragraphs per scope in an append-only table is how the
                # administrative log stops being readable.
                "described_scopes": sorted(notes),
            },
        )

        with self._lock:
            self._require_tenant(tenant_id)
            # Migration 024's foreign key, in the fake. Same reason as `save_connection`'s
            # above: without it here the in-memory store is the looser of the two.
            if connector_id not in self._connectors.get(tenant_id, {}):
                raise NoSuchConnectorError(
                    NO_SUCH_CONNECTOR_TO_VET.format(
                        connector=connector_id, tenant=tenant_id
                    )
                )
            self._oauth_apps[(tenant_id, connector_id)] = {
                "connector_id": connector_id,
                "authorize_endpoint": authorize_endpoint,
                "token_endpoint": token_endpoint,
                "revoke_endpoint": revoke_endpoint or "",
                "client_id": client_id,
                "scopes": list(wanted),
                "authorize_params": dict(extra),
                "scope_notes": copy.deepcopy(notes),
                "configured_by": actor,
                "configured_at": datetime.now(timezone.utc).isoformat(),
                "client_secret": bytes(client_secret),
                "key_id": key_id,
            }
            self._append_admin(tenant_id, record)

    def get_connector_oauth(self, tenant_id: str, connector_id: str) -> dict | None:
        with self._lock:
            row = self._oauth_apps.get((tenant_id, connector_id))
            if row is None:
                return None
            return {key: copy.deepcopy(row[key]) for key in OAUTH_APP_FIELDS}

    def list_connector_oauth(self, tenant_id: str) -> list[dict]:
        with self._lock:
            rows = [
                {key: copy.deepcopy(row[key]) for key in OAUTH_APP_PUBLIC_FIELDS}
                for (tenant, _), row in self._oauth_apps.items()
                if tenant == tenant_id
            ]
        return sorted(rows, key=lambda r: r["connector_id"])

    def delete_connector_oauth(
        self, tenant_id: str, connector_id: str, *, actor: str
    ) -> bool:
        record = make_admin_record(
            "connector.oauth.remove", "connector", connector_id or "", actor
        )
        with self._lock:
            if self._oauth_apps.pop((tenant_id, connector_id), None) is None:
                return False
            self._append_admin(tenant_id, record)
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

        key = (tenant_id, principal_kind, principal_id, connector_id)
        with self._lock:
            row = self._connections.get(key)
            # The compare-and-set. **The fake is too fast to expose the window this
            # protects** — which is exactly what 10d found writing the same shape of test
            # for `update_agent`, and why the eight-concurrent-refresh test is
            # Postgres-only. What this half buys is that the *semantics* are identical, so
            # a caller written against one store behaves the same against the other.
            if row is None or row["updated_at"] != if_updated_at:
                return None

            row["ciphertext"] = bytes(ciphertext)
            row["key_id"] = key_id
            row["expires_at"] = expires_at
            row["refresh_expires_at"] = refresh_expires_at
            if account_label is not None:
                row["account_label"] = account_label
            row["reconsent_reason"] = ""
            row["updated_at"] = datetime.now(timezone.utc)
            return {k: copy.deepcopy(v) for k, v in row.items() if k != "ciphertext"}

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
        with self._lock:
            row = self._connections.get(
                (tenant_id, principal_kind, principal_id, connector_id)
            )
            if row is None:
                return False
            row["reconsent_reason"] = reason
            row["updated_at"] = datetime.now(timezone.utc)
            return True

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
        with self._lock:
            self._require_tenant(tenant_id)
            if state in self._pending_authorizations:
                # The primary key, in the fake. A collision on 256 bits of randomness
                # does not happen, so one means something is generating them badly — and
                # replacing the row would hand one person's flow to another's callback.
                raise StorageError(
                    "a pending authorization with this state already exists. States are "
                    "random and single-use; a duplicate means they are not being "
                    "generated the way this table assumes."
                )
            self._pending_authorizations[state] = {
                "state": state,
                "tenant_id": tenant_id,
                "principal_kind": principal_kind,
                "principal_id": principal_id,
                "connector_id": connector_id,
                "code_verifier": bytes(code_verifier),
                "key_id": key_id,
                "redirect_uri": redirect_uri,
                "return_to": return_to or "",
                "created_at": datetime.now(timezone.utc),
            }

    def consume_pending_authorization(self, state: str) -> dict | None:
        if not state:
            return None
        with self._lock:
            row = self._pending_authorizations.pop(state, None)
        return copy.deepcopy(row) if row is not None else None

    def sweep_pending_authorizations(self, *, older_than_seconds: int) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=int(older_than_seconds))
        with self._lock:
            stale = [
                state
                for state, row in self._pending_authorizations.items()
                if row["created_at"] < cutoff
            ]
            for state in stale:
                del self._pending_authorizations[state]
        return len(stale)

    # --- the door as an OAuth resource server ---------------------------------------
    #
    # Step 083, migration 053. See `base.py`'s section comment.

    def create_oauth_client(self, client: dict) -> dict:
        row = normalize_oauth_client(client)
        with self._lock:
            if row["id"] in self._oauth_clients:
                raise StorageError(
                    f"an OAuth client with id '{row['id']}' already exists. The id is "
                    "minted rather than chosen, so this is a collision in whatever "
                    "generated it rather than anything a caller did."
                )
            self._oauth_clients[row["id"]] = {
                "id": row["id"],
                "client_name": row["client_name"],
                "redirect_uris": list(row["redirect_uris"]),
                "metadata": dict(row["metadata"]),
                "created_at": datetime.now(timezone.utc),
                "last_consented_at": None,
            }
            return copy.deepcopy(self._oauth_clients[row["id"]])

    def find_oauth_client(self, client_id: str) -> dict | None:
        if not client_id:
            return None
        with self._lock:
            row = self._oauth_clients.get(client_id)
        return copy.deepcopy(row) if row is not None else None

    def touch_oauth_client(self, client_id: str) -> None:
        with self._lock:
            row = self._oauth_clients.get(client_id)
            if row is not None:
                row["last_consented_at"] = datetime.now(timezone.utc)

    def sweep_oauth_clients(self, *, unused_for_seconds: int) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=int(unused_for_seconds))
        with self._lock:
            stale = [
                client_id
                for client_id, row in self._oauth_clients.items()
                if row["last_consented_at"] is None and row["created_at"] < cutoff
            ]
            for client_id in stale:
                del self._oauth_clients[client_id]
                # `ON DELETE CASCADE` on the code's foreign key.
                for code_hash in [
                    h for h, c in self._oauth_codes.items() if c["client_id"] == client_id
                ]:
                    del self._oauth_codes[code_hash]
        return len(stale)

    def create_oauth_code(self, tenant_id: str, code: dict) -> None:
        row = normalize_oauth_code(code)
        with self._lock:
            self._require_tenant(tenant_id)
            if row["client_id"] not in self._oauth_clients:
                raise ValueRefused(
                    f"there is no OAuth client '{row['client_id']}' to issue a code to."
                )
            if row["code_hash"] in self._oauth_codes:
                raise StorageError(
                    "an OAuth code with this hash already exists. Codes are random and "
                    "single-use; a duplicate means they are not being generated the "
                    "way this table assumes."
                )
            self._oauth_codes[row["code_hash"]] = {
                "code_hash": row["code_hash"],
                "tenant_id": tenant_id,
                "client_id": row["client_id"],
                "owner_id": row["owner_id"],
                "redirect_uri": row["redirect_uri"],
                "code_challenge": row["code_challenge"],
                "resource": row["resource"],
                "token_name": row["token_name"],
                "created_at": datetime.now(timezone.utc),
                "expires_at": row["expires_at"],
                "used_at": None,
                "token_id": None,
            }

    def find_oauth_code(self, code_hash: str) -> dict | None:
        if not code_hash:
            return None
        with self._lock:
            row = self._oauth_codes.get(code_hash)
        return copy.deepcopy(row) if row is not None else None

    def consume_oauth_code(self, code_hash: str) -> bool:
        if not code_hash:
            return False
        with self._lock:
            row = self._oauth_codes.get(code_hash)
            if row is None or row["used_at"] is not None:
                return False
            row["used_at"] = datetime.now(timezone.utc)
            return True

    def record_oauth_code_token(self, code_hash: str, token_id: str) -> None:
        with self._lock:
            row = self._oauth_codes.get(code_hash)
            if row is not None:
                row["token_id"] = token_id

    def sweep_oauth_codes(self, *, older_than_seconds: int) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=int(older_than_seconds))
        with self._lock:
            stale = [h for h, row in self._oauth_codes.items() if row["expires_at"] < cutoff]
            for code_hash in stale:
                del self._oauth_codes[code_hash]
        return len(stale)

    # --- key rotation ---------------------------------------------------------------
    #
    # Step 026 — `base.py`'s section comment is the contract. The fakes' one wrinkle:
    # an OAuth application row does not carry its tenant (the dict key does), so the
    # fetch synthesizes it, exactly as Postgres's column list produces it.

    def sealed_key_id_census(self) -> dict:
        with self._lock:
            populations = (
                ("connections", self._connections.values(), "key_id"),
                ("connector_oauth", self._oauth_apps.values(), "key_id"),
                ("triggers", self._triggers.values(), "secret_key_id"),
                (
                    "pending_authorizations",
                    self._pending_authorizations.values(),
                    "key_id",
                ),
            )
            census = {}
            for table, rows, column in populations:
                counts: dict = {}
                for row in rows:
                    counts[row[column]] = counts.get(row[column], 0) + 1
                census[table] = counts
        return census

    def connections_not_sealed_under(self, key_id: str) -> list[dict]:
        wanted = (
            "ciphertext",
            "tenant_id",
            "principal_kind",
            "principal_id",
            "connector_id",
            "key_id",
        )
        with self._lock:
            rows = [
                {column: row[column] for column in wanted}
                for row in self._connections.values()
                if row["key_id"] != key_id
            ]
        return sorted(
            copy.deepcopy(rows),
            key=lambda r: (
                r["tenant_id"],
                r["principal_kind"],
                r["principal_id"],
                r["connector_id"],
            ),
        )

    def connector_oauth_not_sealed_under(self, key_id: str) -> list[dict]:
        with self._lock:
            rows = [
                {
                    "tenant_id": tenant,
                    "connector_id": row["connector_id"],
                    "client_secret": row["client_secret"],
                    "key_id": row["key_id"],
                }
                for (tenant, _), row in self._oauth_apps.items()
                if row["key_id"] != key_id
            ]
        return sorted(
            copy.deepcopy(rows), key=lambda r: (r["tenant_id"], r["connector_id"])
        )

    def triggers_not_sealed_under(self, key_id: str) -> list[dict]:
        wanted = ("tenant_id", "id", "secret_sealed", "secret_key_id")
        with self._lock:
            rows = [
                {column: row[column] for column in wanted}
                for row in self._triggers.values()
                if row["secret_key_id"] != key_id
            ]
        return sorted(copy.deepcopy(rows), key=lambda r: (r["tenant_id"], r["id"]))

    def pending_authorizations_not_sealed_under(self, key_id: str) -> list[dict]:
        wanted = ("state", "tenant_id", "code_verifier", "key_id", "created_at")
        with self._lock:
            rows = [
                {column: row[column] for column in wanted}
                for row in self._pending_authorizations.values()
                if row["key_id"] != key_id
            ]
        return sorted(copy.deepcopy(rows), key=lambda r: (r["tenant_id"], r["state"]))

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
        with self._lock:
            row = self._connections.get(
                (tenant_id, principal_kind, principal_id, connector_id)
            )
            if row is None or row["ciphertext"] != bytes(if_ciphertext):
                return False
            # Only the blob and the key id — no `updated_at`, no `reconsent_reason`.
            # Both absences are the contract; see `base.py`.
            row["ciphertext"] = bytes(ciphertext)
            row["key_id"] = key_id
            return True

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
        with self._lock:
            row = self._oauth_apps.get((tenant_id, connector_id))
            if row is None or row["client_secret"] != bytes(if_client_secret):
                return False
            row["client_secret"] = bytes(client_secret)
            row["key_id"] = key_id
            return True

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
        with self._lock:
            row = self._triggers.get(trigger_id)
            if (
                row is None
                or row["tenant_id"] != tenant_id
                or row["secret_sealed"] != bytes(if_secret_sealed)
            ):
                return False
            row["secret_sealed"] = bytes(secret_sealed)
            row["secret_key_id"] = secret_key_id
            return True

    def reseal_pending_authorization(
        self,
        state: str,
        *,
        code_verifier: bytes,
        key_id: str,
        if_code_verifier: bytes,
    ) -> bool:
        check_reseal(code_verifier, key_id, if_code_verifier)
        with self._lock:
            row = self._pending_authorizations.get(state)
            if row is None or row["code_verifier"] != bytes(if_code_verifier):
                return False
            row["code_verifier"] = bytes(code_verifier)
            row["key_id"] = key_id
            return True

    @contextmanager
    def refresh_lock(
        self, tenant_id: str, principal_kind: str, principal_id: str, connector_id: str
    ):
        """A per-connection `threading.Lock`, tried rather than waited on.

        **Non-blocking, matching the Postgres store**, and that shape is not a detail: the
        blocking version there held a pooled database connection for the length of somebody
        else's token-endpoint round trip, so the contract is *"tell me immediately whether
        I hold it"*. A fake that blocked would let a caller written against it deadlock or
        stall against the real store, which is precisely the drift the contract suite
        exists to catch.

        **This is a genuinely weaker guarantee than Postgres's, and the difference is not
        a detail of the fake either.** An advisory lock serialises every process pointed at
        the database; this serialises threads in one interpreter. That is the right shape
        for the in-memory store — it is not durable and has never been shared between
        processes — but it means a test of the *single-flight property* against this store
        proves nothing about a deployment with two workers. See decision 11: the eight
        concurrent refreshes are asserted against real Postgres for exactly this reason.

        The lock registry is itself locked while a lock is fetched, which is the ordinary
        double-checked shape: without it, two threads arriving at once for an unseen
        connection each mint their own `Lock` and neither excludes the other.
        """
        key = (tenant_id, principal_kind, principal_id, connector_id)
        with self._lock:
            gate = self._refresh_locks.setdefault(key, threading.Lock())

        if not gate.acquire(blocking=False):
            yield False
            return
        try:
            yield True
        finally:
            gate.release()

    # --- runs -------------------------------------------------------------------

    def enqueue_run(self, tenant_id: str, run: dict) -> tuple[dict, bool]:
        row = normalize_run(run)
        now = datetime.now(timezone.utc)

        with self._lock:
            self._require_tenant(tenant_id)

            # The partial unique index, in Python. An empty key matches nothing,
            # including another empty key — which is why this is guarded rather than
            # keyed on the value.
            key = row["idempotency_key"]
            if key:
                for existing in self._runs.values():
                    if (
                        existing["tenant_id"] == tenant_id
                        and existing["idempotency_key"] == key
                    ):
                        # Nothing is written. The caller is getting the run the key
                        # already named, file and all.
                        return copy.deepcopy(existing), False

            if row["run_id"] in self._runs:
                # The primary key, and it is global. See migration 015: a 48-bit id
                # collides eventually, and this is where it must arrive as a refusal
                # rather than as two customers' records merging under one id.
                raise StorageError(
                    f"run '{row['run_id']}' already exists. Run ids are unique across "
                    "every tenant, because a worker claims a run by id alone."
                )

            # The root is the parent's root, derived here and never accepted from a
            # caller. The parent lookup is tenant-scoped, so a parent from another
            # customer is the same refusal as one that does not exist.
            root_run_id = row["run_id"]
            if row["parent_run_id"] is not None:
                parent = self._runs.get(row["parent_run_id"])
                if parent is None or parent["tenant_id"] != tenant_id:
                    raise ValueRefused(
                        NO_SUCH_PARENT.format(
                            parent=row["parent_run_id"], tenant=tenant_id
                        )
                    )
                # The `runs_one_live_child` predicate, under the same lock as the
                # insert — the fake's version of "no read-then-write window".
                for sibling in self._runs.values():
                    if (
                        sibling["parent_run_id"] == row["parent_run_id"]
                        and sibling["status"] in LIVE_CHILD_STATUSES
                    ):
                        raise FollowUpConflict(
                            ONE_LIVE_CHILD.format(parent=row["parent_run_id"])
                        )
                root_run_id = parent["root_run_id"]

            self._run_seq[row["run_id"]] = len(self._run_seq)
            self._runs[row["run_id"]] = {
                **row,
                "tenant_id": tenant_id,
                "answer": None,
                "error": "",
                "claimed_by": "",
                "claimed_at": None,
                "lease_expires_at": None,
                "attempt": 0,
                "created_at": now,
                "started_at": None,
                "finished_at": None,
                "cancel_requested_at": None,
                "cancelled_by": "",
                "root_run_id": root_run_id,
                "thread_shared": False,
                "activity": None,
                # Migration 045's defaults, and they are the migration's argument in
                # Python: a run that has not finished has spent nothing that has been
                # accounted, and every run written before 013 spent tokens nobody
                # counted. `0` and `''` say both, and keep every `SUM` over these
                # columns from needing to know which it is looking at.
                "model": "",
                "input_tokens": 0,
                "output_tokens": 0,
                "cache_read_tokens": 0,
                "cache_write_tokens": 0,
                "peak_context_tokens": 0,
            }
            return copy.deepcopy(self._runs[row["run_id"]]), True

    def create_file(self, tenant_id: str, row: dict) -> dict:
        record = normalize_file(row)
        now = datetime.now(timezone.utc)

        with self._lock:
            self._require_tenant(tenant_id)
            if record["id"] in self._files:
                raise StorageError(
                    f"file '{record['id']}' already exists. Ids are 128 bits, so this "
                    "is a caller reusing one rather than a collision — and overwriting "
                    "would hand these bytes to a run somebody else already started."
                )
            self._files[record["id"]] = {
                **record,
                "tenant_id": tenant_id,
                "created_at": now,
            }
            return {f: self._files[record["id"]][f] for f in FILE_META_FIELDS}

    def get_file(self, tenant_id: str, file_id: str) -> dict | None:
        with self._lock:
            row = self._files.get(file_id)
            # The tenant is a filter, not a key — another customer's id must be
            # indistinguishable from one that does not exist.
            if row is None or row["tenant_id"] != tenant_id:
                return None
            # The narrow shape, built by naming the fields rather than by deleting
            # `content` from a copy. A delete-what-we-do-not-want version leaks the
            # column the day somebody adds another one.
            return {field: row[field] for field in FILE_META_FIELDS}

    def file_content(self, tenant_id: str, file_id: str) -> bytes | None:
        with self._lock:
            row = self._files.get(file_id)
            if row is None or row["tenant_id"] != tenant_id:
                return None
            return row["content"]

    def get_run(self, tenant_id: str, run_id: str) -> dict | None:
        with self._lock:
            row = self._runs.get(run_id)
            # The tenant filter is a filter, not a lookup key. A run id belonging to
            # another customer has to be indistinguishable from one that does not exist.
            if row is None or row["tenant_id"] != tenant_id:
                return None
            return copy.deepcopy(row)

    def find_run(self, tenant_id: str, prefix: str) -> dict | None:
        if not prefix:
            return None
        with self._lock:
            matches = [
                copy.deepcopy(row)
                for row in self._runs.values()
                if row["tenant_id"] == tenant_id and row["run_id"].startswith(prefix)
            ]
        return matches[0] if len(matches) == 1 else None

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
        with self._lock:
            # Newest first, by insertion rather than by timestamp. `created_at` is not
            # a usable sort key on its own — runs submitted inside one clock tick share
            # one, and on Windows that tick is about 15ms. `seq` is the column Postgres
            # orders by and this is the same order. See migration 015.
            matching = sorted(
                (
                    row
                    for row in self._runs.values()
                    if row["tenant_id"] == tenant_id
                    and (status is None or row["status"] == status)
                    and (root is None or row["root_run_id"] == root)
                    and (not roots_only or row["parent_run_id"] is None)
                    and (
                        principal_kind is None
                        or (row["principal_kind"], row["principal_id"])
                        == (principal_kind, principal_id)
                    )
                    # 045's window. `>=` and inclusive, matching the SQL — a report for
                    # "the last seven days" that silently dropped the run at the
                    # boundary would disagree with itself between two stores.
                    # A run with no `finished_at` has finished nothing and is out.
                    and (
                        finished_since is None
                        or (
                            row["finished_at"] is not None
                            and row["finished_at"] >= finished_since
                        )
                    )
                ),
                key=lambda r: self._run_seq[r["run_id"]],
                reverse=True,
            )
            rows = [copy.deepcopy(row) for row in matching]

        if limit is not None:
            rows = rows[:limit] if limit > 0 else []
        return rows

    def set_thread_shared(
        self, tenant_id: str, run_id: str, shared: bool
    ) -> dict | None:
        with self._lock:
            row = self._runs.get(run_id)
            if row is None or row["tenant_id"] != tenant_id:
                return None
            # Meaningful on root runs only, and enforced rather than assumed: a
            # follow-up's id gets None, exactly as the Postgres WHERE clause answers.
            if row["parent_run_id"] is not None:
                return None
            row["thread_shared"] = bool(shared)
            return copy.deepcopy(row)

    def door_spend_since(
        self,
        tenant_id: str,
        since,
        *,
        principal_kind: str,
        principal_id: str,
    ) -> list[dict]:
        return self._door_spend_buckets(
            tenant_id,
            since,
            lambda record: (record["principal_kind"], record["principal_id"])
            == (principal_kind, principal_id),
        )

    def owner_door_spend_since(self, tenant_id: str, since, *, owner_id: str) -> list[dict]:
        # The subquery, as a set: every token this person owns that acts as them,
        # revoked or not — the SQL's `IN (SELECT id ...)` has no liveness predicate
        # either, and the base docstring says why a revoked token's morning still
        # counts. Resolved under the lock in the same breath as the scan, which is this
        # store's version of one statement under one snapshot.
        with self._lock:
            theirs = {
                row["id"]
                for row in self._api_tokens.values()
                if row["tenant_id"] == tenant_id
                and row["owner_id"] == owner_id
                and row["acts_as_owner"]
            }
        return self._door_spend_buckets(
            tenant_id,
            since,
            lambda record: record["principal_kind"] == "machine"
            and record["principal_id"] in theirs,
        )

    def _door_spend_buckets(self, tenant_id: str, since, whose) -> list[dict]:
        # `spend_since` below over `audit` instead of `runs`, and the three differences
        # are the three predicates in the SQL: the `door-` prefix, the required principal
        # scope (`whose`, which is the one thing the two callers differ on), and
        # `input_tokens is not None` — a NULL counter is *this call touched no model*,
        # which is nearly every row in this list.
        # `since` normalised once rather than per row: it does not change, and `_as_utc`
        # answers `None` only for an absent stamp, which a required parameter is not.
        floor = self._as_utc(since) or since

        totals: dict = {}
        with self._lock:
            for tid, record in self._audit:
                if tid != tenant_id:
                    continue
                if not str(record.get("run_id") or "").startswith(DOOR_CALL_ID_PREFIX):
                    continue
                if record.get("input_tokens") is None:
                    continue
                if not whose(record):
                    continue
                # `>=` and inclusive, matching the SQL. `ts` is an ISO string here and
                # `since` is an aware datetime, so both go through `_as_utc` — the
                # device `_day` uses one line up, and the reason it exists: comparing a
                # naive stamp against an aware one raises rather than answering wrongly,
                # and a store that raised here would take the door down.
                moment = self._as_utc(record.get("ts"))
                if moment is None or moment < floor:
                    continue

                model = record.get("model") or ""
                bucket = totals.setdefault(
                    model,
                    {
                        "model": model,
                        "input_tokens": 0,
                        "output_tokens": 0,
                        "cache_read_tokens": 0,
                        "cache_write_tokens": 0,
                    },
                )
                for field in (
                    "input_tokens",
                    "output_tokens",
                    "cache_read_tokens",
                    "cache_write_tokens",
                ):
                    # `or 0` for the three that may be NULL beside a non-NULL
                    # `input_tokens`: `parse_report` never produces a partial report, but
                    # `append_audit` is a public method and the SQL's `COALESCE(SUM(...))`
                    # would read a NULL as zero, so this store must too.
                    bucket[field] += record.get(field) or 0

        # Richest first, then by model — the SQL's ORDER BY, so a caller rendering the
        # first row gets the same answer from either store.
        return sorted(
            totals.values(),
            key=lambda b: (
                -(
                    b["input_tokens"]
                    + b["output_tokens"]
                    + b["cache_read_tokens"]
                    + b["cache_write_tokens"]
                ),
                b["model"],
            ),
        )

    def spend_since(
        self,
        tenant_id: str,
        since,
        *,
        principal_kind: str | None = None,
        principal_id: str | None = None,
    ) -> list[dict]:
        # `>=` and inclusive, matching the SQL and `tokens_spent_since` beside it.
        totals: dict = {}
        with self._lock:
            for row in self._runs.values():
                if row["tenant_id"] != tenant_id:
                    continue
                if row["finished_at"] is None or row["finished_at"] < since:
                    continue
                if principal_kind is not None and (
                    row["principal_kind"],
                    row["principal_id"],
                ) != (principal_kind, principal_id):
                    continue
                bucket = totals.setdefault(
                    row["model"],
                    {
                        "model": row["model"],
                        "input_tokens": 0,
                        "output_tokens": 0,
                        "cache_read_tokens": 0,
                        "cache_write_tokens": 0,
                    },
                )
                for field in (
                    "input_tokens",
                    "output_tokens",
                    "cache_read_tokens",
                    "cache_write_tokens",
                ):
                    bucket[field] += row[field]

        # Richest first, then by model — the SQL's ORDER BY, so a caller rendering the
        # first row gets the same answer from either store.
        return sorted(
            totals.values(),
            key=lambda b: (
                -(
                    b["input_tokens"]
                    + b["output_tokens"]
                    + b["cache_read_tokens"]
                    + b["cache_write_tokens"]
                ),
                b["model"],
            ),
        )

    def tokens_spent_since(self, tenant_id: str, since) -> int:
        # `>=` and inclusive, matching the SQL and `list_runs(finished_since=...)` beside
        # it — deliberately *not* `count_recent_runs`' strict `>`. That one ages a run out
        # of a rolling window; this one asks what a fixed day holds, and a run finishing
        # exactly at midnight belongs to the day that starts there.
        with self._lock:
            return sum(
                row["input_tokens"]
                + row["output_tokens"]
                + row["cache_read_tokens"]
                + row["cache_write_tokens"]
                for row in self._runs.values()
                if row["tenant_id"] == tenant_id
                and row["finished_at"] is not None
                and row["finished_at"] >= since
            )

    def count_recent_runs(
        self, tenant_id: str, principal_kind: str, principal_id: str, *, since
    ) -> tuple:
        # Strictly `>`, matching the Postgres store to the character of the comparison:
        # a run at exactly `since` has aged out of the window.
        with self._lock:
            stamps = [
                row["created_at"]
                for row in self._runs.values()
                if row["tenant_id"] == tenant_id
                and row["principal_kind"] == principal_kind
                and row["principal_id"] == principal_id
                and row["created_at"] > since
            ]
        return (len(stamps), min(stamps) if stamps else None)

    def start_run(
        self, tenant_id: str, run_id: str, *, claimed_by: str = ""
    ) -> dict | None:
        now = datetime.now(timezone.utc)
        with self._lock:
            row = self._runs.get(run_id)
            if row is None or row["tenant_id"] != tenant_id:
                return None
            # Not queued: somebody else already started it. None rather than an
            # exception — two things racing for one run is the ordinary shape of a
            # queue, and the loser carries on.
            if row["status"] != "queued":
                return None

            row["status"] = "running"
            row["started_at"] = now
            row["claimed_by"] = claimed_by
            row["claimed_at"] = now
            row["attempt"] += 1
            return copy.deepcopy(row)

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
        # Before the lock and before the status guard, so a malformed usage dict is
        # refused identically whether or not the run turns out to be finishable — the
        # Postgres store's CHECK does not care what state the row was in either.
        spent = normalize_usage(usage)
        now = datetime.now(timezone.utc)

        with self._lock:
            row = self._runs.get(run_id)
            if row is None or row["tenant_id"] != tenant_id:
                return None
            # Already over. The first outcome recorded is the one kept: a retry after a
            # partial failure must not overwrite what actually happened.
            if row["status"] in TERMINAL_RUN_STATUSES:
                return None

            row["status"] = status
            row["answer"] = answer
            row["error"] = error or ""
            row["finished_at"] = now
            if spent is not None:
                # 045, and the three rules the columns take — the fake's version of the
                # Postgres UPDATE's `col = col + %s`, `GREATEST(...)` and
                # `COALESCE(NULLIF(...))`. Written out rather than looped over all six,
                # because the whole point is that they are *not* the same rule.
                for counter in USAGE_COUNTERS:
                    row[counter] += spent[counter]
                row["peak_context_tokens"] = max(
                    row["peak_context_tokens"], spent["peak_context_tokens"]
                )
                # Replaced only when there is one, so a caller recording no model call
                # cannot blank what an earlier one wrote.
                row["model"] = spent["model"] or row["model"]
            # 038: a terminal run has nothing it is doing, and a stale "waiting on the
            # model" beside a `complete` badge is the disagreement the runs row exists
            # to prevent. Matches the Postgres UPDATE's `activity = NULL`.
            row["activity"] = None
            return copy.deepcopy(row)

    def note_activity(self, tenant_id: str, run_id: str, activity: dict) -> None:
        with self._lock:
            row = self._runs.get(run_id)
            # The Postgres guard (`AND status = 'running'`), under the lock: a note
            # racing a cancellation or a finish changes nothing, silently — the writer
            # is the runtime making a best-effort progress note.
            if row is None or row["tenant_id"] != tenant_id:
                return
            if row["status"] != "running":
                return
            row["activity"] = copy.deepcopy(activity)

    def run_fingerprint(self, tenant_id: str, run_id: str) -> str | None:
        with self._lock:
            row = self._runs.get(run_id)
            if row is None or row["tenant_id"] != tenant_id:
                return None
            # The audit count, under the same lock as the row read — this store's
            # version of Postgres's single statement.
            count = sum(
                1
                for tid, record in self._audit
                if tid == tenant_id and record.get("run_id") == run_id
            )
            return compose_run_fingerprint(
                row["status"], row["cancel_requested_at"], row["activity"], count
            )

    def request_cancel(
        self, tenant_id: str, run_id: str, *, cancelled_by: str = ""
    ) -> dict | None:
        now = datetime.now(timezone.utc)

        with self._lock:
            row = self._runs.get(run_id)
            if row is None or row["tenant_id"] != tenant_id:
                return None
            # Over, and not by being cancelled. None, and the caller — which has the row
            # — reports 409 with whatever it actually ended as. `cancelled` is in the
            # permitted set precisely because a queued run reaches it in one step, so a
            # retry of an ordinary cancel would otherwise be reported as a failure.
            if row["status"] not in CANCELLABLE_RUN_STATUSES:
                return None

            # First asker wins both fields. A second request is a retry of one intent,
            # and the interesting fact is who asked first. Not stamped at all on a run
            # that is already over: "asked at" after it finished would be a lie.
            if row["cancel_requested_at"] is None and row["status"] != "cancelled":
                row["cancel_requested_at"] = now
                row["cancelled_by"] = cancelled_by or ""

            if row["status"] == "queued":
                # Nothing has run and nothing is going to. Straight to the terminal
                # status, in the same breath, because there is nothing to wait for.
                row["status"] = "cancelled"
                row["finished_at"] = now

            return copy.deepcopy(row)

    # --- the queue --------------------------------------------------------------

    def claim_run(
        self, worker: str, *, lease_seconds: int, limit_to_tenant: str | None = None
    ) -> dict | None:
        now = datetime.now(timezone.utc)

        # One lock for select-and-update, which is this store's `FOR UPDATE SKIP
        # LOCKED`. It is a coarser guarantee than Postgres gives — a real claim blocks
        # nothing, this blocks everything — and it is the same *observable* behaviour,
        # which is what the contract suite compares. The suite asserts the real property
        # against real Postgres, because a lock this broad cannot be wrong in the
        # direction that matters and cannot prove anything either.
        with self._lock:
            queued = [
                row
                for row in self._runs.values()
                if row["status"] == "queued"
                and (limit_to_tenant is None or row["tenant_id"] == limit_to_tenant)
                # Migration 020. A suspended customer's queued runs are skipped rather
                # than failed: suspension closes the doors and cancellation is what
                # stops work, so these stay `queued` and are released on resume.
                and self._tenant_is_active(row["tenant_id"])
            ]
            if not queued:
                return None

            # Oldest first, by arrival. `created_at` rather than `seq` — they agree
            # today and stop agreeing the moment fairness between tenants needs a key
            # that is not arrival order, and this is the one query that changes then.
            queued.sort(key=lambda r: (r["created_at"], self._run_seq[r["run_id"]]))
            row = queued[0]

            row["status"] = "running"
            row["claimed_by"] = worker
            row["claimed_at"] = now
            row["lease_expires_at"] = now + timedelta(seconds=lease_seconds)
            row["attempt"] += 1
            row["started_at"] = row["started_at"] or now
            return copy.deepcopy(row)

    def heartbeat_runs(self, worker: str, run_ids: list, *, lease_seconds: int) -> dict:
        now = datetime.now(timezone.utc)
        kept = {}

        with self._lock:
            for run_id in run_ids:
                row = self._runs.get(run_id)
                # Scoped to this worker's own claims. A worker renewing a lease it no
                # longer holds is a worker arguing with the recovery it exists to
                # enable, so the id simply does not come back.
                if row is None or row["status"] != "running" or row["claimed_by"] != worker:
                    continue
                row["lease_expires_at"] = now + timedelta(seconds=lease_seconds)
                # The other half of this round trip: whether somebody has asked this run
                # to stop. Free — the row is already in hand.
                kept[run_id] = row["cancel_requested_at"] is not None

        return kept

    def recover_expired_runs(self, *, deadline_seconds: int) -> list:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=deadline_seconds)
        moved = []

        with self._lock:
            for row in self._runs.values():
                if row["status"] != "running":
                    continue

                expired = row["lease_expires_at"] is not None and row["lease_expires_at"] < now
                overdue = row["started_at"] is not None and row["started_at"] < cutoff
                if not expired and not overdue:
                    continue

                # `interrupted`, never back to `queued`. A run that may have
                # half-happened must not happen twice.
                row["status"] = "interrupted"
                row["error"] = LEASE_LOST if expired else DEADLINE_PASSED
                row["finished_at"] = now
                row["activity"] = None
                moved.append(copy.deepcopy(row))

        return moved


# --- the scope-mismatch guard — this store's half of step 029 --------------------
#
# Postgres enforces tenancy with row-level security: a scoped connection cannot see or
# write another tenant's rows, whatever the query says. That cannot be reproduced over
# dicts (see the module docstring — it is the second rule deliberately not shared), but
# the invariant behind it can: **under an ambient tenant scope, storage is only ever
# asked about that tenant.** Every public method taking a `tenant_id` is wrapped once,
# here, rather than each method remembering to check — the same reasoning that keyed
# the collections by tenant instead of trusting each method's filter.
#
# Deliberately *stricter* than Postgres, and the divergence is pinned in the contract
# suite: Postgres filters a mismatched read (the row is invisible, which reads as
# not-found) and refuses a mismatched write; this raises for both. A fake that is
# stricter than the real thing fails a test that production would let limp along with
# wrong answers, which is the useful direction — the reverse is how fakes lie.


def _scope_guarded(method, tenant_position: int):
    @functools.wraps(method)
    def guarded(self, *args, **kwargs):
        scope = tenancy.current_tenant()
        if scope is not None:
            if "tenant_id" in kwargs:
                asked = kwargs["tenant_id"]
            elif len(args) >= tenant_position:
                asked = args[tenant_position - 1]
            else:
                asked = None
            if asked is not None and asked != scope:
                raise StorageError(
                    f"tenant scope violation: this context is scoped to '{scope}' and "
                    f"{method.__name__} was asked about '{asked}'. On Postgres this "
                    "row would be invisible or the write refused (migration 037); "
                    "here it is an error so the bug is a red test instead of a wrong "
                    "answer."
                )
        return method(self, *args, **kwargs)

    return guarded


def _install_scope_guard() -> None:
    for name, member in list(vars(InMemoryStorage).items()):
        if name.startswith("_") or not inspect.isfunction(member):
            continue
        parameters = list(inspect.signature(member).parameters)
        if "tenant_id" not in parameters:
            continue
        setattr(
            InMemoryStorage,
            name,
            _scope_guarded(member, parameters.index("tenant_id")),
        )


_install_scope_guard()
