-- What a running run is doing right now. Step 032.
--
-- The gap this fills is a silence, not a slowness: the audit log records brokered tool
-- calls and a model call is not one, so a run spending forty seconds inside
-- `client.messages.create(...)` emits nothing at all — and no transport can deliver
-- events that were never written. This column is the runtime saying what it is doing,
-- updated at the two transitions its turn loop already owns.
--
--   {"v": 1, "turn": 3, "doing": "model", "since": "<iso8601>"}
--
-- **Current state, deliberately not a history.** A `run_events` child table would be
-- the transcript-storage row in DEFERRED.md arriving sideways, with its retention and
-- injection questions unanswered; the history of tool calls already exists in the
-- audit trail. And deliberately not audit rows: that log is the administrative record
-- of brokered actions — decision, credential, effect — and a model turn is none of
-- those.
--
-- NULL means "nothing to say": a run that has not started, or one that is over.
-- `note_activity` writes it guarded on `status = 'running'`, so a late write cannot
-- resurrect a terminal row's marker, and `finish_run` / `recover_expired_runs` null it
-- so a finished run never carries a stale "doing".
--
-- One nullable ADD COLUMN on a table whose rows are short-lived-hot: ~2 small writes
-- per turn, on a row the worker already owns.

ALTER TABLE runs
    ADD COLUMN activity JSONB;

-- No index. The only readers fetch the row by primary key — the run detail and the
-- wait probe — and nothing ever searches by what runs are doing.
