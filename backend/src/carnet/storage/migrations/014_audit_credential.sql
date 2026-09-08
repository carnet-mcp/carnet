-- Which kind of credential a call went out with. Audit schema v6.
--
-- A record says who a run acted *for*. Until delegated credentials existed it said
-- nothing about whose credential it *used*, and the two could not disagree — there was
-- one credential and it was the operator's. They disagree the moment delegation ships:
-- somebody with no connection falls back to the environment variable, the call reaches
-- the vendor as the operator, and the record reads as though it went out as them.
--
-- Whoever audits that write six months later is wrong about the account it was made
-- from, and the account is what decides what the write could reach.
--
-- NULL for every row written before this, which is the honest value: not "shared", but
-- "this predates the question". `v` is what tells the two apart — records at v5 and
-- below cannot have had a credential kind, records at v6 always do.
--
-- Nullable rather than defaulted for the same reason. A DEFAULT 'shared' would backfill
-- an assertion onto history instead of admitting the gap, and it happens to be the
-- assertion that is *usually* right, which is what would make it hard to spot later.
--
-- Added as its own column rather than folded into the JSONB `args`: this is a fact
-- about the call, not an argument to it, and "every write last quarter that used a
-- shared credential" should be a WHERE clause rather than a JSON traversal.
--
-- ALTER TABLE is DDL, so the append-only trigger — which refuses UPDATE and DELETE —
-- does not stand in the way. That is the correct boundary: the trigger protects the
-- *contents* of the log from being rewritten, not its shape from being extended.

ALTER TABLE audit
    ADD COLUMN credential TEXT;
