-- Partition the three append-only logs by `ts`, so retention is a drop rather than a
-- sweep.
--
-- ## Why now, and what 018 promised
--
-- The register's top compounding row. These tables grow on every tool call, every
-- administrative write and every refusal, and converting a large delete-protected table
-- later is a maintenance window with a full data copy. Today the copy is free.
--
-- Step 018 shaped `prune_log_records` so it could collapse into this: pruning is by `ts`
-- cutoff only — no per-row predicate, no per-tenant window, nothing a partition drop
-- cannot express (plan 018, decision 8). This migration is that collection. Retention
-- becomes `DROP TABLE` of a wholly-expired month, which writes no WAL per row, fires no
-- row trigger, and needs no exception to the append-only rule at all.
--
-- ## Monthly, and the granularity is a READ decision
--
-- No read of these tables carries a `ts` predicate: `audit_records`,
-- `admin_audit_records` and `denial_records` all order by `id` and filter by tenant.
-- So partition pruning never helps a read and **every read visits every live
-- partition** — one index descent each, multiplied by the partition count. Daily
-- partitions would put thirty times that cost on every read of the log for a precision
-- the product does not promise: retention is configured in whole days and swept hourly.
--
-- The cost is retention precision, and it is stated rather than hidden: a month is
-- dropped only once the cutoff has passed all of it, so a record can outlive its window
-- by up to a month. See `prune_floor` in `storage/base.py`, which both stores share so
-- the fake cannot drift from this.
--
-- ## The primary key gains `ts`, and that is invisible above this layer
--
-- Postgres requires the partition key in every unique constraint, so
-- `PRIMARY KEY (id)` becomes `PRIMARY KEY (id, ts)`. Nothing above `storage/` can
-- observe it: `id` appears in none of `_AUDIT_COLUMNS`, `ADMIN_AUDIT_FIELDS` or
-- `DENIAL_FIELDS`, so no caller has ever held, joined on or compared one. `ORDER BY id`
-- still means insertion order — the parent keeps one identity sequence, and the
-- per-partition `(id, ts)` indexes let the planner Merge Append them in order.
--
-- What it costs: `id` uniqueness now rests on the sequence rather than on a constraint.
-- The only writers that can supply an explicit `id` are this migration's copy and
-- raw-SQL tests; every product writer goes through `GENERATED ALWAYS AS IDENTITY`,
-- which still refuses an accidental explicit value.
--
-- ## Why not DETACH, which is the usual advice
--
-- `DETACH PARTITION ... CONCURRENTLY` takes weaker locks and is the recommended way to
-- retire a partition. **It also strips the cloned append-only trigger from the detached
-- table** — measured, not assumed. A crash between the detach and the drop would leave a
-- table full of audit records that anybody can UPDATE, with nothing recording that it
-- ever happened, and it cannot run inside a transaction so the window is real. That is
-- precisely the artifact migration 029 refused when it rejected DROP TRIGGER, arrived at
-- through a different door. The drop is therefore a plain transactional `DROP TABLE`
-- behind a `lock_timeout`; see `prune_log_records`.
--
-- ## The conversion: rename, build, copy, swap — all in one transaction
--
-- Postgres cannot convert a regular table into a partitioned one, so the choice was
-- swap-by-rename or build-under-a-temporary-name-and-rename. Rename-first wins because
-- the partitions are born with their final names. `migrate.py` runs each file in one
-- transaction and Postgres does DDL transactionally, so a failure at any statement below
-- leaves the original three tables untouched under their original names.


-- ## The naming and creation of a partition, in the database rather than in Python
--
-- Two callers create partitions: this migration, and `ensure_log_partitions` at runtime.
-- Naming them in both places is two homes for one rule, so the rule lives here and the
-- Python calls it. `IF NOT EXISTS` plus the advisory lock the Python caller takes is what
-- makes two processes booting together safe.

CREATE FUNCTION log_partition_name(parent TEXT, month_start TIMESTAMPTZ)
RETURNS TEXT AS $$
    SELECT format('%s_p%s', parent, to_char($2 AT TIME ZONE 'UTC', 'YYYY_MM'));
$$ LANGUAGE sql IMMUTABLE;

CREATE FUNCTION ensure_log_partition(parent TEXT, month_start TIMESTAMPTZ)
RETURNS TEXT AS $$
DECLARE
    part    TEXT;
    lower   TIMESTAMPTZ;
    upper   TIMESTAMPTZ;
    existed BOOLEAN;
BEGIN
    -- A whitelist rather than trust, although both callers pass a module constant. This
    -- is a function anybody who can reach the database can call, and it builds DDL by
    -- string interpolation; the argument that the caller is careful is not one this
    -- function can check.
    IF parent NOT IN ('audit', 'admin_audit', 'access_denials') THEN
        RAISE EXCEPTION 'not a partitioned log table: %', parent;
    END IF;

    -- Truncated here rather than trusted from the caller, so a mid-month timestamp
    -- cannot create a partition whose bounds are not a whole month.
    lower := date_trunc('month', month_start AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
    upper := lower + INTERVAL '1 month';
    part  := log_partition_name(parent, lower);

    -- Reported rather than inferred, so a caller can say what it actually created and a
    -- routine call on a healthy database is visibly a no-op. `IF NOT EXISTS` stays on
    -- the DDL regardless: this check and the create are not atomic together, and the
    -- advisory lock the Python caller takes is what makes them so.
    existed := to_regclass(part) IS NOT NULL;

    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
        part, parent, lower, upper
    );

    IF existed THEN
        RETURN NULL;
    END IF;
    RETURN part;
END;
$$ LANGUAGE plpgsql;


-- ## audit
--
-- The one every statement of the retention problem names, and the largest of the three.

-- **Renaming a table does not rename its indexes**, and indexes share one namespace with
-- tables. So `audit_old` still owns the names `audit_pkey`, `audit_run`, `audit_recent`,
-- `audit_writes` and `audit_denials`, and recreating them below would collide — worse for
-- the primary key, which is created implicitly with the table and would silently take
-- `audit_pkey1` instead of failing. Moved aside rather than dropped, so `audit_old` stays
-- fully inspectable right up to the moment it goes.
ALTER TABLE audit RENAME TO audit_old;
ALTER INDEX audit_pkey    RENAME TO audit_old_pkey;
ALTER INDEX audit_run     RENAME TO audit_old_run;
ALTER INDEX audit_recent  RENAME TO audit_old_recent;
ALTER INDEX audit_writes  RENAME TO audit_old_writes;
ALTER INDEX audit_denials RENAME TO audit_old_denials;

-- Columns in the order 004 and 014 left them. `credential` is last because it was added
-- by an ALTER, and keeping the order means the copy below can be read against the
-- original table definition.
--
-- **`audit_principal_kind_check` is deliberately absent here and added after the copy.**
-- Migration 017 created it `NOT VALID`, which means rows written before it existed were
-- never verified — but a NOT VALID constraint still checks every *inserted* row, and the
-- copy below is an insert. Creating it now would make the conversion fail on exactly the
-- historical rows 017 chose to leave alone. Added afterwards, NOT VALID, it reproduces
-- the pre-030 semantics exactly: old rows unchecked, new rows refused.
CREATE TABLE audit (
    id              BIGINT      GENERATED ALWAYS AS IDENTITY,
    tenant_id       TEXT        NOT NULL REFERENCES tenants(id),
    v               SMALLINT    NOT NULL,
    ts              TIMESTAMPTZ NOT NULL,
    run_id          TEXT        NOT NULL,
    principal_kind  TEXT        NOT NULL,
    principal_id    TEXT        NOT NULL,
    agent           TEXT        NOT NULL,
    tool            TEXT        NOT NULL,
    effect          TEXT        NOT NULL DEFAULT '',
    args            JSONB       NOT NULL,
    decision        TEXT        NOT NULL CHECK (decision IN ('allow', 'deny')),
    reason          TEXT        NOT NULL DEFAULT '',
    outcome         TEXT        NOT NULL DEFAULT ''
                    CHECK (outcome IN ('', 'ok', 'error', 'oversize', 'unknown')),
    duration_ms     INTEGER,
    response_bytes  BIGINT,
    credential      TEXT,
    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);


-- ## admin_audit

ALTER TABLE admin_audit RENAME TO admin_audit_old;
ALTER INDEX admin_audit_pkey   RENAME TO admin_audit_old_pkey;
ALTER INDEX admin_audit_recent RENAME TO admin_audit_old_recent;
ALTER INDEX admin_audit_target RENAME TO admin_audit_old_target;
ALTER INDEX admin_audit_actor  RENAME TO admin_audit_old_actor;

CREATE TABLE admin_audit (
    id          BIGINT      GENERATED ALWAYS AS IDENTITY,
    tenant_id   TEXT        NOT NULL REFERENCES tenants(id),
    v           SMALLINT    NOT NULL,
    ts          TIMESTAMPTZ NOT NULL,
    actor_kind  TEXT        NOT NULL CHECK (actor_kind IN ('user', 'system')),
    actor_id    TEXT        NOT NULL CHECK (actor_id <> ''),
    action      TEXT        NOT NULL CHECK (action <> ''),
    target_kind TEXT        NOT NULL CHECK (target_kind <> ''),
    target_id   TEXT        NOT NULL CHECK (target_id <> ''),
    detail      JSONB       NOT NULL DEFAULT '{}',
    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);


-- ## access_denials

ALTER TABLE access_denials RENAME TO access_denials_old;
ALTER INDEX access_denials_pkey      RENAME TO access_denials_old_pkey;
ALTER INDEX access_denials_recent    RENAME TO access_denials_old_recent;
ALTER INDEX access_denials_principal RENAME TO access_denials_old_principal;
ALTER INDEX access_denials_resource  RENAME TO access_denials_old_resource;

CREATE TABLE access_denials (
    id              BIGINT      GENERATED ALWAYS AS IDENTITY,
    tenant_id       TEXT        NOT NULL REFERENCES tenants(id),
    v               SMALLINT    NOT NULL,
    ts              TIMESTAMPTZ NOT NULL,
    principal_kind  TEXT        NOT NULL CHECK (principal_kind IN ('user', 'system')),
    principal_id    TEXT        NOT NULL,
    resource_kind   TEXT        NOT NULL CHECK (resource_kind IN ('agent', 'admin')),
    resource_id     TEXT        NOT NULL,
    required        TEXT        NOT NULL,
    held            TEXT        NOT NULL DEFAULT '',
    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);


-- ## Partitions, seeded from the data that exists
--
-- Every month from the oldest surviving record through three months ahead, so a
-- deployment that upgrades and is never restarted again still has somewhere to write
-- for a quarter. `PARTITION_HORIZON_MONTHS` in `storage/base.py` is the same number and
-- `ensure_log_partitions` is what keeps it true afterwards.
--
-- One month *before* the current month is always created even on an empty database. It
-- costs nothing and it closes the boundary case where a record stamped at 23:59:59 on
-- the last day of a month is inserted a second after midnight — with the migration
-- having run in between.
-- **Seeded from `max(ts)` as well as `min(ts)`, and that is not symmetry for its own
-- sake.** The obvious version reads the oldest row and runs to `now + 3 months`, which
-- fails outright on a row stamped further ahead than that — and such a row is entirely
-- possible: `append_audit` takes its timestamp from the caller, so one machine with a
-- skewed clock, or a restored backup written by one, is enough. The copy below would
-- then find no partition for it and the whole migration would roll back, blocking the
-- upgrade on data nobody can see without reading the table.
--
-- **Found by trying it**: a single row two years ahead left the migration failing with
-- Postgres's own *"no partition of relation "audit" found for row"*, which says nothing
-- about which row or what to do about it. Rolling back cleanly is the transaction doing
-- its job; being unable to upgrade at all is still the wrong outcome for one bad
-- timestamp.
DO $$
DECLARE
    parent  TEXT;
    oldest  TIMESTAMPTZ;
    newest  TIMESTAMPTZ;
    month   TIMESTAMPTZ;
    horizon TIMESTAMPTZ;
BEGIN
    FOREACH parent IN ARRAY ARRAY['audit', 'admin_audit', 'access_denials'] LOOP
        EXECUTE format('SELECT min(ts), max(ts) FROM %I', parent || '_old')
            INTO oldest, newest;

        month := date_trunc(
            'month',
            LEAST(
                coalesce(oldest, now()),
                now() - INTERVAL '1 month'
            ) AT TIME ZONE 'UTC'
        ) AT TIME ZONE 'UTC';

        horizon := date_trunc(
            'month',
            GREATEST(
                coalesce(newest, now()),
                now()
            ) AT TIME ZONE 'UTC'
        ) AT TIME ZONE 'UTC' + INTERVAL '3 months';

        WHILE month <= horizon LOOP
            PERFORM ensure_log_partition(parent, month);
            month := month + INTERVAL '1 month';
        END LOOP;
    END LOOP;
END;
$$;


-- ## The copy
--
-- `OVERRIDING SYSTEM VALUE` because the columns are `GENERATED ALWAYS`: without it the
-- copy is refused, and with a plain `GENERATED BY DEFAULT` column it would silently
-- renumber every row instead. Ids are preserved exactly, which is what makes reads
-- across this migration byte-identical — including their order.
--
-- Inserted through the parent so each row is routed to its month by the partition key.

INSERT INTO audit (
    id, tenant_id, v, ts, run_id, principal_kind, principal_id, agent, tool, effect,
    args, decision, reason, outcome, duration_ms, response_bytes, credential
) OVERRIDING SYSTEM VALUE
SELECT
    id, tenant_id, v, ts, run_id, principal_kind, principal_id, agent, tool, effect,
    args, decision, reason, outcome, duration_ms, response_bytes, credential
FROM audit_old;

INSERT INTO admin_audit (
    id, tenant_id, v, ts, actor_kind, actor_id, action, target_kind, target_id, detail
) OVERRIDING SYSTEM VALUE
SELECT
    id, tenant_id, v, ts, actor_kind, actor_id, action, target_kind, target_id, detail
FROM admin_audit_old;

INSERT INTO access_denials (
    id, tenant_id, v, ts, principal_kind, principal_id, resource_kind, resource_id,
    required, held
) OVERRIDING SYSTEM VALUE
SELECT
    id, tenant_id, v, ts, principal_kind, principal_id, resource_kind, resource_id,
    required, held
FROM access_denials_old;


-- ## The sequences continue the line
--
-- Each new identity column starts at 1, and the copy above wrote ids around it without
-- advancing it. Without this the next append collides with a row that already exists —
-- and now that `id` alone is not unique (the primary key is `(id, ts)`), the collision
-- would not be refused: it would be a duplicate id sitting in the log, breaking the
-- ordering guarantee every read depends on. `setval` with `is_called = true` means the
-- next value is `max(id) + 1`; `coalesce` handles the empty table.

SELECT setval(
    pg_get_serial_sequence('audit', 'id'),
    coalesce((SELECT max(id) FROM audit), 0) + 1,
    false
);
SELECT setval(
    pg_get_serial_sequence('admin_audit', 'id'),
    coalesce((SELECT max(id) FROM admin_audit), 0) + 1,
    false
);
SELECT setval(
    pg_get_serial_sequence('access_denials', 'id'),
    coalesce((SELECT max(id) FROM access_denials), 0) + 1,
    false
);


-- ## The constraint 017 left NOT VALID, restored NOT VALID
--
-- See the note on the `audit` table above: added after the copy so the historical rows
-- 017 declined to verify are not verified now either. New rows are checked, which is
-- what the constraint was for.

ALTER TABLE audit
    ADD CONSTRAINT audit_principal_kind_check
    CHECK (principal_kind IN ('user', 'system')) NOT VALID;


-- ## Indexes, recreated on the parents
--
-- Created on the partitioned parent, where Postgres clones each one onto every existing
-- and future partition. Identical to what 004, 022 and 028 created, including the two
-- partial indexes — a partial index on a partitioned parent is legal and clones like any
-- other.

CREATE INDEX audit_run ON audit (tenant_id, run_id, id);
CREATE INDEX audit_recent ON audit (tenant_id, ts DESC);
CREATE INDEX audit_writes ON audit (tenant_id, ts DESC) WHERE effect = 'write';
CREATE INDEX audit_denials ON audit (tenant_id, ts DESC) WHERE decision = 'deny';

CREATE INDEX admin_audit_recent ON admin_audit (tenant_id, ts DESC, id DESC);
CREATE INDEX admin_audit_target ON admin_audit (tenant_id, target_kind, target_id, id);
CREATE INDEX admin_audit_actor ON admin_audit (tenant_id, actor_kind, actor_id, id);

CREATE INDEX access_denials_recent ON access_denials (tenant_id, ts DESC, id DESC);
CREATE INDEX access_denials_principal
    ON access_denials (tenant_id, principal_kind, principal_id, id);
CREATE INDEX access_denials_resource
    ON access_denials (tenant_id, resource_kind, resource_id, id);


-- ## The append-only triggers, on the parents
--
-- **The trigger functions are not touched.** These are 029's bodies, with its
-- DELETE-under-`agent_runtime.retention` exception, bound to new triggers on the new
-- parents. Creating a row trigger on a partitioned parent clones it onto every existing
-- partition and onto every partition created afterwards, which is what makes the
-- protection hold for months that do not exist yet — the property this step had to get
-- right, and the one `test_every_log_partition_carries_the_append_only_triggers` asserts
-- against `pg_trigger` rather than against this comment.
--
-- The retention exception is now used by `delete_tenant` alone: a partition drop is DDL
-- and fires no row trigger, so the pruner never sets the setting.

CREATE TRIGGER audit_no_update
    BEFORE UPDATE ON audit
    FOR EACH ROW EXECUTE FUNCTION audit_is_append_only();

CREATE TRIGGER audit_no_delete
    BEFORE DELETE ON audit
    FOR EACH ROW EXECUTE FUNCTION audit_is_append_only();

CREATE TRIGGER admin_audit_no_update
    BEFORE UPDATE ON admin_audit
    FOR EACH ROW EXECUTE FUNCTION admin_audit_is_append_only();

CREATE TRIGGER admin_audit_no_delete
    BEFORE DELETE ON admin_audit
    FOR EACH ROW EXECUTE FUNCTION admin_audit_is_append_only();

CREATE TRIGGER access_denials_no_update
    BEFORE UPDATE ON access_denials
    FOR EACH ROW EXECUTE FUNCTION access_denials_is_append_only();

CREATE TRIGGER access_denials_no_delete
    BEFORE DELETE ON access_denials
    FOR EACH ROW EXECUTE FUNCTION access_denials_is_append_only();


-- ## The old tables go
--
-- `DROP TABLE` is DDL and fires no row trigger, so the append-only triggers still
-- attached to these three do not stand in the way — the same boundary migration 014
-- named when it added a column to a table nobody may UPDATE: the trigger protects the
-- contents of the log from being rewritten, not its shape from being changed.
--
-- The rows are not lost, they were copied above; this drops the empty shell they were
-- copied out of. If the copy had failed, this file's transaction would have rolled back
-- before reaching here and the tables would still be called `audit`, `admin_audit` and
-- `access_denials`.

DROP TABLE audit_old;
DROP TABLE admin_audit_old;
DROP TABLE access_denials_old;
