-- Retention and tenant deletion: a customer who leaves is actually gone.
--
-- ## What was impossible, and why it was impossible on purpose
--
-- Migrations 005, 022 and 028 each end with the same deliberate consequence: their
-- table references tenants(id) WITHOUT ON DELETE CASCADE, so a tenant with records
-- cannot be removed. *"You cannot offboard a customer and silently erase the record of
-- what their agents did."* That was right, and it is still right — the word carrying
-- the weight is **silently**, not **erase**.
--
-- What it left is a product where deleting a customer raises a foreign-key violation.
-- A contract with a deletion clause turns that from a strong default into an
-- unmeetable obligation, so this migration builds the release valve the three trigger
-- functions describe in prose — each of them says, in its own HINT, "drop the trigger
-- deliberately if you are implementing retention."
--
-- ## Five tables block a tenant delete, not one
--
-- Every previous statement of this problem names `audit`. Reading the catalog says
-- otherwise. Referencing tenants(id) with no ON DELETE clause:
--
--     audit            004     append-only by trigger
--     runs             015     no trigger — blocks on the foreign key alone
--     groups           017     no trigger — blocks on the foreign key alone
--     admin_audit      022     append-only by trigger
--     access_denials   028     append-only by trigger
--
-- `runs` and `groups` are the two nobody had counted, and they are the reason the
-- deletion path deletes explicitly rather than trusting a cascade to find everything.
--
-- ## Why not DROP TRIGGER, which is what the hints say
--
-- The hints predate having to do it. Dropping a trigger takes an ACCESS EXCLUSIVE lock
-- on a table the product writes to on every tool call, and — worse — a crash between
-- the drop and the recreate leaves the log silently mutable with nothing recording
-- that it ever was. The friction those comments wanted is *"erasing audit records
-- should be a deliberate, visible operation and never something a stray DELETE can
-- do"*, and a transaction-scoped setting delivers exactly that friction without DDL at
-- runtime:
--
--     SELECT set_config('agent_runtime.retention', 'on', true);   -- true = transaction-local
--
-- A stray DELETE still fails. A DELETE from psql still fails. What passes is a
-- transaction whose own text says it is doing retention, which is visible in
-- pg_stat_activity while it runs and greppable in the code forever. The permission
-- ends when the transaction does, in every case including a crash — there is no window
-- in which the protection is off for anybody else.
--
-- ## UPDATE keeps no escape hatch, under any setting
--
-- This is the asymmetry worth not collapsing later. Retention **shortens** the record;
-- nothing ever rewrites one. A trigger that allowed UPDATE under a setting would make
-- "correcting" a record expressible, and the whole value of these tables is that they
-- say what happened rather than what somebody would prefer had happened. So the
-- exception below is keyed on TG_OP = 'DELETE' and there is deliberately no sibling
-- for UPDATE.

CREATE OR REPLACE FUNCTION audit_is_append_only() RETURNS TRIGGER AS $$
BEGIN
    -- The second argument is missing_ok: unset reads as NULL rather than raising, so
    -- an ordinary DELETE on an ordinary connection takes the refusal below.
    IF TG_OP = 'DELETE'
       AND current_setting('agent_runtime.retention', true) = 'on' THEN
        RETURN OLD;
    END IF;

    RAISE EXCEPTION 'audit is append-only: % is not permitted', TG_OP
        USING HINT = 'Records are the enforcement history. Retention and tenant '
                     'deletion go through storage.delete_tenant / prune_log_records, '
                     'which set agent_runtime.retention for one transaction.';
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION admin_audit_is_append_only() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE'
       AND current_setting('agent_runtime.retention', true) = 'on' THEN
        RETURN OLD;
    END IF;

    RAISE EXCEPTION 'admin_audit is append-only: % is not permitted', TG_OP
        USING HINT = 'It is the only record of who took access away. Retention and '
                     'tenant deletion go through storage.delete_tenant / '
                     'prune_log_records, which set agent_runtime.retention for one '
                     'transaction.';
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION access_denials_is_append_only() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE'
       AND current_setting('agent_runtime.retention', true) = 'on' THEN
        RETURN OLD;
    END IF;

    RAISE EXCEPTION 'access_denials is append-only: % is not permitted', TG_OP
        USING HINT = 'It is the only record of who tried and was refused. Retention '
                     'and tenant deletion go through storage.delete_tenant / '
                     'prune_log_records, which set agent_runtime.retention for one '
                     'transaction.';
END;
$$ LANGUAGE plpgsql;

-- The triggers themselves are untouched: CREATE OR REPLACE FUNCTION rebinds the body
-- under the names the six existing triggers already point at. Nothing is dropped, so
-- there is no instant at which any of these tables is unprotected.


-- ## The record that erasure cannot reach
--
-- "You cannot silently erase a customer" survives this migration by MOVING, not by
-- being abandoned. Deleting a tenant writes one row here, and this is the only table
-- in the schema whose append-only trigger has no exception at all: retention prunes
-- the logs, and the record that a customer was erased is precisely the record that
-- erasure must never be able to remove.
--
-- No foreign key to tenants, deliberately — the row this describes is gone, and that
-- is the point. A FK would make the tombstone deletable by the very operation it
-- exists to witness.
CREATE TABLE tenant_tombstones (
    -- The primary key rather than a surrogate id, and it does a second job: it is what
    -- makes `create_tenant` able to refuse a tombstoned id. An id is never reused,
    -- because a reused id makes every surviving record naming it ambiguous between two
    -- customers — and those records are in tables nobody can edit to disambiguate.
    tenant_id   TEXT        PRIMARY KEY,

    -- The organisation's name as it was. A counterparty to a contract, not a person:
    -- this table holds no personal data, which is what lets it be kept forever without
    -- reopening the question this migration exists to close.
    name        TEXT        NOT NULL,

    deleted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- 'kind:id', on `admin_audit.actor_id`'s argument: a record that does not say who
    -- did it looks like an answer and is not one. Never empty.
    actor       TEXT        NOT NULL CHECK (actor <> ''),

    -- The per-table row counts the deletion removed, and the version of the deleting
    -- code. JSONB for `admin_audit.detail`'s reason: the shape will grow, and the flat
    -- columns above are the ones anybody filters on.
    detail      JSONB       NOT NULL DEFAULT '{}'
);

CREATE FUNCTION tenant_tombstones_is_append_only() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'tenant_tombstones is append-only: % is not permitted', TG_OP
        USING HINT = 'It is the only surviving record that a customer was deleted. '
                     'There is no retention exception here, deliberately — retention '
                     'prunes the logs, and this is what says the logs once existed.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tenant_tombstones_no_update
    BEFORE UPDATE ON tenant_tombstones
    FOR EACH ROW EXECUTE FUNCTION tenant_tombstones_is_append_only();

CREATE TRIGGER tenant_tombstones_no_delete
    BEFORE DELETE ON tenant_tombstones
    FOR EACH ROW EXECUTE FUNCTION tenant_tombstones_is_append_only();


-- ## No new index, and the reason is worth more than an index
--
-- This migration carried three BRIN indexes on `ts` through most of its life, on the
-- argument that every existing `ts` index leads with `tenant_id` (`audit_recent` and its
-- two siblings) while a retention sweep is the first query that is not — so the sweep
-- would seq-scan the largest tables in the schema.
--
-- **That argument ignored the primary key, and measuring it settled the matter.** The
-- sweep's statement is `SELECT id ... WHERE ts < cutoff ORDER BY id LIMIT n`, and on an
-- append-only table `id` order *is* `ts` order — rows are inserted in time order and
-- never moved. So the planner walks `audit_pkey` from the oldest row, filters on `ts`,
-- and stops at the limit. Against 200,000 rows: 154 buffers, ~1 ms, and **the same plan
-- and the same time with the BRIN index present or absent**. Forcing the planner to use
-- BRIN instead made it five times slower, because it then has to sort what the primary
-- key was already handing over in order.
--
-- An index nothing chooses, justified by reasoning that turned out to be wrong, is the
-- kind of thing this schema deletes rather than leaves behind — the same call migration
-- 020 makes about a CHECK value no code path honours: a control that looks present and
-- is absent is worse than one that was never added. The correlation the primary key
-- relies on is a property of these tables being append-only, which is the one property
-- they are never going to lose.


-- ## What this migration deliberately does not do
--
-- **No foreign key gains ON DELETE CASCADE.** `DELETE FROM tenants` from psql fails
-- after this migration exactly as it did before, and the two contract tests asserting
-- that are unchanged and still green. Deletion is `storage.delete_tenant`, which does
-- the work explicitly. The property that buys: when a later migration adds a table
-- referencing tenants(id) and nobody updates the deletion path, a no-cascade key makes
-- `delete_tenant` fail loudly on its next run. A cascade would have handled it
-- silently — and "handled" is doing dangerous work in that sentence, because the
-- silent version is also how a table gets forgotten by the contract test that checks
-- nothing is left behind.
--
-- **`runs` is not given a retention window.** `runs.task` and `runs.answer` hold free
-- text a person typed — the sharpest personal data in the schema, which 008 said out
-- loud — but they are also live product data with foreign keys between them (threads,
-- migration 027) and a screen that reads them. Pruning a thread's root is a decision
-- about conversations vanishing, not a compliance sweep. Tenant deletion removes runs
-- wholesale, which is what a deletion clause requires; day-two retention for `runs`
-- belongs with the encrypt-at-rest row it shares a register line with.
