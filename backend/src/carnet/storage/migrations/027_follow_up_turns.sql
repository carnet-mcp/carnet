-- Follow-up turns: a run that continues a run. Step 014.
--
-- A follow-up re-enters the same broker with the same grants and budgets, so the
-- mechanism is a runs-table shape rather than a new enforcement path. Two columns are
-- written once at insert and never updated; the third mutates, which `runs` already
-- does throughout a row's life.
--
-- `parent_run_id` is the feature. `root_run_id` is denormalised on purpose: it makes
-- "fetch the whole thread" one indexed query instead of a walk, in both stores, and it
-- is immutable by construction — a run's root is its parent's root, or itself. A
-- recursive CTE would keep the schema purer and would have no in-memory equivalent;
-- the contract suite exists precisely to refuse that trade.
--
-- The foreign keys are sound where the missing FK to `agents` (015) was not: history
-- must survive the thing it records, and nothing deletes a run. Tenancy is not the
-- FK's job either — `get_run` is tenant-scoped, so a cross-tenant `parent_run_id` is
-- simply not found, and answers with the same 404 as a typo.
ALTER TABLE runs
    ADD COLUMN parent_run_id TEXT REFERENCES runs(run_id),
    ADD COLUMN root_run_id   TEXT REFERENCES runs(run_id),
    -- Meaningful on root runs only: whether the starter has opened this thread to
    -- collaborators (anyone with a run grant). FALSE is the default on purpose — a
    -- conversation reads as personal in a way a run never did, so the default follows
    -- the person, not the grant.
    ADD COLUMN thread_shared BOOLEAN NOT NULL DEFAULT FALSE;

-- Every existing row is its own root; nothing about old rows changes meaning, and
-- "which thread" has one answer for every run ever recorded.
UPDATE runs SET root_run_id = run_id WHERE root_run_id IS NULL;

ALTER TABLE runs ALTER COLUMN root_run_id SET NOT NULL;

-- The whole thread, one indexed query, in insertion order.
CREATE INDEX runs_thread ON runs (tenant_id, root_run_id, seq);

-- Linearity is this index, not an application promise. The rule it enforces: **a run
-- has at most one child that is live or succeeded.** Two simultaneous follow-ups to
-- the same parent race to the index and exactly one wins — decided by the database,
-- with no advisory lock and no read-then-write window.
--
-- The status list is the subtle part, and it is what prevents dead-end threads: a
-- child that reaches `failed`, `cancelled`, `incomplete` or `interrupted` *leaves*
-- the index, freeing the parent to be asked again. Without that, cancelling your own
-- follow-up would brick the conversation permanently. A terminal status never becomes
-- `complete` later, so two complete children cannot arise from the freed slot.
CREATE UNIQUE INDEX runs_one_live_child ON runs (parent_run_id)
    WHERE parent_run_id IS NOT NULL
      AND status IN ('queued', 'running', 'complete');
