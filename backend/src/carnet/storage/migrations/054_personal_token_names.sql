-- A personal token's name is the owner's to reuse, and its daily allowance is the owner's
-- to share.
--
-- Step 108, sequencing item 1. Two corrections to what a *personal* token is, both found
-- by walking one journey end to end: a company's own coding agent mints a personal token
-- on every engineer's machine, silently, on first run, and calls through it. Under the
-- rows as 031 and 040 left them, the second engineer is refused and the second machine
-- gets a second budget. Neither is a bug in the code that wrote those migrations — 031
-- had no personal tokens (033d added `acts_as_owner`) and 040 had one token per caller
-- in mind — but both are wrong now, and both are corrected here rather than in a branch
-- somebody has to remember to take.
--
-- ## 1. Names are per owner for personal tokens, per customer for the rest
--
-- 031's `api_tokens_one_live_name` is `UNIQUE (tenant_id, name) WHERE revoked_at IS
-- NULL`, and 031's argument for it stands: the name is what somebody reads when deciding
-- which token to revoke, and two live rows sharing one make that decision a guess. What
-- 031 did not have was a second *kind* of token. A personal token is read on **its
-- owner's** tokens page, by its owner, beside its owner's other tokens — never on a
-- customer-wide list where another person's `coding-agent` could be mistaken for it. So
-- the collision the index guards against is between one owner's tokens, and a
-- customer-wide index refuses the second engineer for a confusion nobody could have.
-- Step 099's team journey found exactly that: the second colleague to call theirs
-- `claude-code` was refused with a sentence about *this customer*.
--
-- A service token stays customer-wide. It is listed on `--list-tokens` and the admin
-- tokens page beside every other service token, whoever minted it, and that list is the
-- one where two `nightly-ci` rows would be a guess. Two partial unique indexes, then,
-- split on the bit that decides which list a token is read on:
--
--     (tenant_id, owner_id, name)   WHERE revoked_at IS NULL AND acts_as_owner
--     (tenant_id, name)             WHERE revoked_at IS NULL AND NOT acts_as_owner
--
-- Both are strictly weaker than the index they replace, so no existing row can violate
-- either and the build cannot fail on data. Revocation still frees a name (031's
-- reason, unchanged). And a personal token and a service token *may* share a name — they
-- are never on the same list, and refusing it would be the old confusion by another
-- route.
--
-- `postgres.py` tells the two apart by constraint name, as it told `api_tokens_pkey`
-- and the old index apart, and the fake mirrors both predicates.
--
-- ## 2. A personal token's daily call allowance is its owner's
--
-- 040's `mcp_budget` is keyed on the token, and for a service token that is right: a CI
-- bot with three tokens for three pipelines was given three allowances on purpose, and
-- `TokenSpend`'s docstring says so. For a personal token it is wrong in the direction
-- that matters. *A daily ceiling per engineer* is the sentence the dial is sold with, and
-- an engineer with a laptop and a desktop holds two personal tokens — so the ceiling was
-- per device, and the reason it exists evaporated. Money was already keyed on the
-- principal in the schema's own words (`TokenSpend`: *"minting another one does not buy
-- another budget"*) and was in fact keyed on the token in `door_spend_today`; this
-- migration and step 108's door change make the words true.
--
-- So the key column becomes a **subject**: the token's id for a service token, the
-- owner's user id for a personal token. Two things follow, and both are done here rather
-- than left for the first request to discover:
--
--   - the composite foreign key to `api_tokens` goes, because a user id is not a token
--     id. Nothing is lost with it: the key existed so one customer's row could not name
--     another customer's token, and `tenant_id` is still in the primary key and still
--     under the same row-level policy. A subject that names nothing is a row that counts
--     nothing, which is what an orphan here always was;
--   - every window a personal token has already spent is **re-keyed under its owner,
--     summed**, so an engineer whose two machines had each spent 400 calls today wakes
--     up at 800 rather than 0. A migration that reset the day's count would let the
--     ceiling be passed once, silently, by exactly the people it was meant to bound.
--     Service rows are not touched.
--
-- The column is renamed rather than kept as `token_id` holding user ids: a column named
-- for a thing it no longer holds is the drift `runs_one_live_child` and the `migration:011`
-- actor were both lessons about, and the rename costs a catalogue update.
--
-- ## Lock time
--
-- Four `CREATE INDEX` / `DROP INDEX` on `api_tokens`, a table with one row per token —
-- built in the time it takes to read them. The `mcp_budget` rewrite touches one row per
-- token per day of history, which 035e sized as "a few dozen bytes each"; the INSERT and
-- DELETE run in this migration's own transaction, so a failure leaves the old rows and
-- the old key and the runner retries the whole file.
--
-- `scripts/e2e_upgrade.py`'s `before_054` stage populates tokens of both kinds under the
-- old index with windows of both kinds under the old key, and asserts the sums.


-- --- 1. the name --------------------------------------------------------------------

DROP INDEX IF EXISTS api_tokens_one_live_name;

CREATE UNIQUE INDEX api_tokens_one_live_personal_name
    ON api_tokens (tenant_id, owner_id, name)
    WHERE revoked_at IS NULL AND acts_as_owner;

CREATE UNIQUE INDEX api_tokens_one_live_service_name
    ON api_tokens (tenant_id, name)
    WHERE revoked_at IS NULL AND NOT acts_as_owner;


-- --- 2. the allowance ---------------------------------------------------------------

ALTER TABLE mcp_budget DROP CONSTRAINT mcp_budget_tenant_id_token_id_fkey;
ALTER TABLE mcp_budget RENAME COLUMN token_id TO subject;

-- The pooled rows first, then the rows they replace. The join is on the old key, which
-- every existing row still carries; a personal token's owner cannot collide with a
-- token id (user ids and token ids are minted with different prefixes, and the primary
-- key would refuse the insert if one somehow did), so this is a plain INSERT.
INSERT INTO mcp_budget (tenant_id, subject, window_start, calls)
SELECT b.tenant_id, t.owner_id, b.window_start, SUM(b.calls)
  FROM mcp_budget b
  JOIN api_tokens t ON t.tenant_id = b.tenant_id AND t.id = b.subject
 WHERE t.acts_as_owner
 GROUP BY b.tenant_id, t.owner_id, b.window_start;

DELETE FROM mcp_budget b
 USING api_tokens t
 WHERE t.tenant_id = b.tenant_id
   AND t.id = b.subject
   AND t.acts_as_owner;
