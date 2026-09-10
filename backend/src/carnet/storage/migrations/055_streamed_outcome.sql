-- A sixth outcome, for a call whose answer was still arriving when the caller left.
--
-- Step 108, sequencing item 2. The broker gains `stream()`: a model call whose response
-- is forwarded chunk by chunk while it arrives, rather than assembled and handed back
-- whole. A streamed call ends one of four ways, and three of them already have a word —
-- `ok` (the upstream finished), `error` (the upstream failed or stalled), `oversize`
-- (the bytes passed the per-tool cap and the upstream was closed). The fourth is new: the
-- **caller** went away. An engineer pressed Ctrl-C in the middle of a completion; the
-- broker closed the upstream request so Azure stops billing, and wrote a row for what
-- had been counted up to that point.
--
-- That row is not an `error` — nothing failed — and not `ok` — the answer was cut short
-- by the party that asked for it. Recording it as either would be a true-sounding word
-- for a different event, on the one table built to answer *what happened* afterwards.
-- So: `aborted`. Usage on the row is what the stream had reported when it was closed,
-- which for a provider that sends its usage object in the final chunk is usually
-- nothing; the row says so honestly (NULL counters) rather than estimating.
--
-- Widened exactly as 031 widened `principal_kind` on the same two tables, and for the
-- same reason: `audit` is partitioned, append-only and unbounded, so the check is added
-- `NOT VALID` — cloned onto every partition, present and future, enforced on every new
-- row, and never a scan of history that no code path could have written. Both spellings
-- of the constraint name are dropped, because 030's rename-aside left the inline check
-- as `audit_outcome_check1` (read out of `pg_constraint`, as 031's header explains).
--
-- `access_denials` has no outcome column and is untouched. To finish the job where the
-- scan is affordable, out of migration and outside a transaction:
--
--     ALTER TABLE audit VALIDATE CONSTRAINT audit_outcome_check;

ALTER TABLE audit DROP CONSTRAINT IF EXISTS audit_outcome_check;
ALTER TABLE audit DROP CONSTRAINT IF EXISTS audit_outcome_check1;
ALTER TABLE audit
    ADD CONSTRAINT audit_outcome_check
        CHECK (outcome IN ('', 'ok', 'error', 'oversize', 'unknown', 'aborted')) NOT VALID;
