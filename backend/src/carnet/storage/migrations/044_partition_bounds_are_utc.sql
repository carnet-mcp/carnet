-- A month is a month in UTC, whatever timezone the session happens to speak.
--
-- Step 041's verification pass, which ran the suite against a database whose default
-- timezone was America/New_York — the BYOC posture taken seriously: somebody else's
-- Postgres, somebody else's defaults — and found that `ensure_log_partition` creates
-- partitions **one UTC day short** under any non-UTC session.
--
-- ## The defect, in one line of migration 030
--
--     lower := date_trunc('month', month_start AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
--     upper := lower + INTERVAL '1 month';
--
-- `lower` is careful: it does its calendar work on a naive timestamp and declares the
-- result UTC, so it lands on the month's UTC midnight in every session. `upper` is not:
-- adding a month to a TIMESTAMPTZ converts to the **session's** local time, adds one
-- calendar month there, and converts back. Under America/New_York, May's UTC midnight
-- is April 30 20:00 local — so "one month later" is May 30 20:00 local, which is
-- May 31 00:00 UTC. The partition covers thirty days of a thirty-one-day month.
--
-- The missing day is a **hole**, not an overlap: the next month's partition computes
-- its own `lower` correctly, so nothing covers the last UTC day of the month. And the
-- consequence is not a reporting blemish — `audit` is written by the broker on every
-- brokered call, an INSERT with no partition raises, and `core/audit.record` sits on
-- the call path. **Every tool call in the deployment fails for one day a month.** The
-- same hole opens in `admin_audit` (inside the same transaction as the write it
-- records, so the write itself is rolled back) and `access_denials`.
--
-- It was invisible until now because every environment that ever ran this — CI, the
-- compose file's own Postgres, the docker image — defaults to UTC. Migration 019
-- measured its reads against "the deployment's own Postgres 16"; nothing ever ran the
-- writes against somebody else's.
--
-- ## The fix: do the month arithmetic where there is no timezone to consult
--
-- The naive timestamp is the right place for calendar arithmetic — `naive + INTERVAL
-- '1 month'` has no session to be relative to — and `AT TIME ZONE 'UTC'` then declares
-- the result to be an instant. One expression, session-independent by construction:
--
--     upper := (date_trunc('month', month_start AT TIME ZONE 'UTC')
--               + INTERVAL '1 month') AT TIME ZONE 'UTC';
--
-- `CREATE OR REPLACE` rather than a new name, because both callers — migration 030's
-- initial creation (already run) and `ensure_log_partitions` at runtime (runs forever)
-- — reach it by this name, and a second name would leave the old arithmetic reachable.
--
-- ## The same arithmetic skipped whole months, not just days
--
-- Migration 030's initial-creation loop steps with the same instrument:
--
--     WHILE month <= horizon LOOP
--         PERFORM ensure_log_partition(parent, month);
--         month := month + INTERVAL '1 month';
--     END LOOP;
--
-- Under America/New_York the walk from July 1 UTC goes Jul 31, Aug 31, **Oct 1** —
-- each step lands a day short, and the truncation inside the function folds the first
-- two onto months that already exist while stepping clean over September. A deployment
-- that migrated under a non-UTC session is missing **entire months**, and the runtime
-- horizon repair never notices: `_partition_horizon_is_complete` checks only that the
-- newest month exists, on 030's stated assumption that *"coverage is created as a
-- contiguous run"* — an assumption the skipping loop itself broke. So the gap sits
-- silent until the first write stamped inside it, which fails.
--
-- ## The repair: widen what the old arithmetic created, and fill what it skipped
--
-- A deployment that migrated under a non-UTC session already holds short partitions.
-- Postgres cannot alter a partition's bounds in place, so each one is detached and
-- re-attached with the correct upper bound — plain transactional DETACH, not
-- CONCURRENTLY, for migration 019's reason: CONCURRENTLY cannot run in a transaction
-- and strips the cloned append-only triggers on a crash. ATTACH re-clones the parent's
-- triggers; `test_every_log_partition_carries_the_append_only_triggers` is what holds
-- that, against the catalog rather than against this comment.
--
-- The re-attach scans each repaired partition to validate its rows against the new
-- bounds. That is a real cost on a large log table and it is paid on purpose: it runs
-- once, inside the migration window, on exactly the deployments that were broken — a
-- UTC deployment finds nothing to repair and pays nothing.
--
-- The migration pins its own session to UTC first, so the repair's comparisons cannot
-- themselves depend on the very default they are correcting. The replaced function
-- stays session-independent without this — a runtime caller gets no such courtesy.

SET LOCAL TIME ZONE 'UTC';

CREATE OR REPLACE FUNCTION ensure_log_partition(parent TEXT, month_start TIMESTAMPTZ)
RETURNS TEXT AS $$
DECLARE
    part    TEXT;
    lower   TIMESTAMPTZ;
    upper   TIMESTAMPTZ;
    existed BOOLEAN;
BEGIN
    -- A whitelist rather than trust, exactly as migration 030 had it: this function
    -- builds DDL by interpolation and anybody who can reach the database can call it.
    IF parent NOT IN ('audit', 'admin_audit', 'access_denials') THEN
        RAISE EXCEPTION 'not a partitioned log table: %', parent;
    END IF;

    -- Both bounds from the same naive calendar arithmetic, declared UTC at the end.
    -- The one change from migration 030 is that `upper` now takes the same route
    -- `lower` always took, instead of adding a month to an instant through whatever
    -- timezone the session carries. See this file's header for the day that lost.
    lower := date_trunc('month', month_start AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
    upper := (date_trunc('month', month_start AT TIME ZONE 'UTC')
              + INTERVAL '1 month') AT TIME ZONE 'UTC';
    part  := log_partition_name(parent, lower);

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

DO $$
DECLARE
    child   RECORD;
    lower   TIMESTAMPTZ;
    upper   TIMESTAMPTZ;
    correct TIMESTAMPTZ;
BEGIN
    FOR child IN
        SELECT c.oid,
               c.relname,
               i.inhparent::regclass::text AS parent,
               pg_get_expr(c.relpartbound, c.oid) AS bound
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
         WHERE i.inhparent::regclass::text IN ('audit', 'admin_audit', 'access_denials')
         ORDER BY c.relname
    LOOP
        -- The bounds, read back from the catalog. The rendered literals parse exactly
        -- whatever session rendered them, and this session is pinned to UTC above.
        lower := (regexp_match(child.bound, 'FROM \(''([^'']+)''\)'))[1]::timestamptz;
        upper := (regexp_match(child.bound, 'TO \(''([^'']+)''\)'))[1]::timestamptz;

        -- What the upper bound should have been: one calendar month after the lower,
        -- in UTC. `lower` was always computed correctly, which is what makes it a
        -- trustworthy anchor for repairing the bound that was not.
        correct := (date_trunc('month', lower AT TIME ZONE 'UTC')
                    + INTERVAL '1 month') AT TIME ZONE 'UTC';

        IF upper IS DISTINCT FROM correct THEN
            RAISE NOTICE 'repairing % (% -> %)', child.relname, upper, correct;
            EXECUTE format('ALTER TABLE %I DETACH PARTITION %I',
                           child.parent, child.relname);
            EXECUTE format(
                'ALTER TABLE %I ATTACH PARTITION %I FOR VALUES FROM (%L) TO (%L)',
                child.parent, child.relname, lower, correct
            );
        END IF;
    END LOOP;

    -- The months the skipping loop stepped over. For each parent, walk from its oldest
    -- attached month to its newest — with the replaced function, whose arithmetic is
    -- the fix — and ensure every month between exists. On a UTC deployment the walk
    -- finds every month already present and creates nothing; on a skipped one it fills
    -- the gap with a correctly-bounded, trigger-carrying partition, because it is the
    -- same CREATE every partition comes from. Interior months only: the horizon ahead
    -- belongs to the runtime repair, which enumerates its months in Python and was
    -- never subject to this loop's stepping.
    DECLARE
        parent TEXT;
        span   RECORD;
        naive  TIMESTAMP;
    BEGIN
        FOREACH parent IN ARRAY ARRAY['audit', 'admin_audit', 'access_denials'] LOOP
            EXECUTE format(
                $q$SELECT min((regexp_match(pg_get_expr(c.relpartbound, c.oid),
                                'FROM \(''([^'']+)''\)'))[1]::timestamptz) AS oldest,
                          max((regexp_match(pg_get_expr(c.relpartbound, c.oid),
                                'FROM \(''([^'']+)''\)'))[1]::timestamptz) AS newest
                     FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
                    WHERE i.inhparent = %L::regclass$q$, parent)
                INTO span;

            IF span.oldest IS NULL THEN
                CONTINUE;
            END IF;

            -- Naive for the walk, `AT TIME ZONE 'UTC'` at the call: the loop being
            -- repaired stepped an instant through the session's calendar, and a repair
            -- that did the same would skip the same months.
            naive := span.oldest AT TIME ZONE 'UTC';
            WHILE naive <= span.newest AT TIME ZONE 'UTC' LOOP
                PERFORM ensure_log_partition(parent, naive AT TIME ZONE 'UTC');
                naive := naive + INTERVAL '1 month';
            END LOOP;
        END LOOP;
    END;
END;
$$;
