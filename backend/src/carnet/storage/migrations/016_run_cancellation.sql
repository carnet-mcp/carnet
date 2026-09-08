-- Cancellation: two fields, because they are two facts.
--
-- The obvious implementation sets `status = 'cancelled'` the moment somebody asks. It
-- is wrong, and the reason is the one this whole design keeps returning to: **Python
-- cannot interrupt a thread.** Between "somebody asked" and "the run stopped" the run
-- is still making tool calls — so a row saying `cancelled` while the audit log shows
-- writes after it is exactly the disagreement `interrupted` exists to avoid. Worse
-- here, in fact: a person reading `cancelled` concludes that nothing further happened,
-- and acts on it.
--
--   cancel_requested_at   somebody asked. The run is still `running`.
--   status = 'cancelled'  the run actually stopped, through the same `finish_run`
--                         that records every other outcome.
--
-- A `queued` run cancelled before any worker claims it goes straight to `cancelled`,
-- because there is nothing to wait for. Migration 015 already permits that: its
-- `finished_at` CHECK deliberately does not assert that a finished run has started, and
-- the note there says why — the constraint that looks obviously right would have had to
-- be dropped again the moment this landed.
--
-- Both columns are nullable / defaulted, so this is two cheap `ADD COLUMN`s on a small
-- table today rather than a rewrite of a populated one later. Same reasoning that put
-- the claim columns in 015 one chunk before anything wrote them.

ALTER TABLE runs
    -- When it was asked for. NULL means nobody has asked.
    --
    -- Note what this means on a row that ended some other way. On an `interrupted` run
    -- it means **the cancel never landed** — the worker died before its next heartbeat,
    -- so nobody knows whether it stopped for that reason or any other. On a `complete`
    -- run it means the cancel arrived while the model was producing the final answer
    -- and the run finished first. Both are honest states, and both are states a UI has
    -- to have wording for.
    ADD COLUMN cancel_requested_at TIMESTAMPTZ,

    -- Who asked, as `kind:id`. The first question about a stopped run is who stopped
    -- it, and `agent_grants.granted_by` is the precedent for recording that on the row
    -- rather than reconstructing it from a log afterwards.
    --
    -- '' rather than NULL for "nobody has asked", matching `claimed_by` on the same
    -- table: one representation of absent, so no caller has to handle two.
    ADD COLUMN cancelled_by TEXT NOT NULL DEFAULT '';

-- No index. The only query that reads these is the heartbeat, which already selects the
-- rows a worker holds by primary key and now returns one more column from them — zero
-- new queries and nothing new to scan. An index here would be a cost with no reader.
