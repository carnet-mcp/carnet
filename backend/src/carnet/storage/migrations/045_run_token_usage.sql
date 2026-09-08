-- What a run spent at the model. Step 013, finally built.
--
-- **Numbered 045 rather than 044, and the renumber is the record of a collision.**
-- This landed as 044 on a branch while `044_partition_bounds_are_utc` landed as 044
-- on another, and the ledger keys on the filename stem — so both would have applied,
-- in an order decided by a string sort, with the numbering that makes this schema
-- readable quietly broken. The branch merging *in* is the one that moves, which is
-- why this is the file that changed and not the other.
--
-- `response.usage` comes back on every reply the Messages API returns and was discarded
-- in `core/runtimes/simple.py` for thirteen steps: the loop took `response.content` and
-- dropped the rest. `runs` had twenty-six columns and not one of them was a token, a
-- model name, or anything a bill could be attributed with.
--
-- **One deployment holds one `ANTHROPIC_API_KEY` and gets one invoice, and nothing in
-- this schema could say which customer produced it.** A tenant that runs one agent a
-- week and a tenant that runs ten thousand were indistinguishable in every table. That
-- was tolerable while agents were run from a terminal by the people who built them;
-- 12c ended it, and 033b's machine door ended it again at a larger volume.
--
-- Plan 013 has been a document since it was written. This is that document, with three
-- of its decisions amended where the code moved underneath them — each amendment is
-- argued below rather than performed quietly, because a plan silently departed from is
-- a plan nobody can trust to describe the system afterwards.
--
-- ## Amendment 1: four counters, not three
--
-- 013 specified `input_tokens`, `output_tokens` and `cached_input_tokens`, and refused
-- a cache-*write* column: *"nothing here enables caching yet, so a column for it would
-- be a column of zeros with a story attached."* True then. **Step 028 made it false** —
-- `_opening_turn` sets `cache_control: {"type": "ephemeral"}` on an attached document
-- precisely so a 10 MiB PDF is written to the cache once and read on turns 2..N, and a
-- cache write is billed above ordinary input while a cache read is billed an order of
-- magnitude below it. Folding writes into `input_tokens` would misprice the tokens in
-- exactly the feature the cache breakpoint was built for.
--
-- So four, named as the pair they are: `cache_read_tokens` and `cache_write_tokens`,
-- rather than 013's lone `cached_input_tokens`, which does not say which direction it
-- means. This is the shape `core/usage.TokenUsage` carries and the shape the API
-- reports, so each column is a field read.
--
-- ## Amendment 2: `peak_context_tokens`, which 013 did not ask for
--
-- The one column here that is not about money, and it answers a question nothing else
-- in this system can: **a run whose prompt approached the context window produced its
-- answer under conditions nobody could see.** There is no error and no status for it —
-- the model answers from what fit — so a run that lost the top of its history is
-- indistinguishable from one that did not.
--
-- It is a per-turn **maximum**, not a total, and that is the whole reason it is a column
-- rather than a derivation: this loop resends its entire message list every turn, so the
-- sum of a run's inputs is many times any prompt that was ever actually sent. Occupancy
-- is a high-water mark or it is nothing.
--
-- ## Amendment 3: the model is recorded, and cost is not
--
-- 013 found this and it stands unchanged: `config.get("model", DEFAULT_MODEL)` means the
-- model lives in the agent's config, the config is versioned and editable, and a token
-- count with no model beside it can never become a cost. Worse, a run priced later
-- against its agent's *current* model is priced against a model it never called. So the
-- model goes on the run.
--
-- And **no cost column**, which is 013's decision 4 kept where it was aimed. A stored
-- dollar figure is a frozen estimate that reads like an invoice: it is computed from a
-- rate list that changes without warning, and once written it cannot be corrected by
-- fixing the list. The rates live in `core/usage.py`, off the run path, overridable with
-- `SHIPYARD_MODEL_RATES`, and the arithmetic happens at read time in the one place a
-- person asked for it. `GET /runs/{id}` carries counts and never a currency.
--
-- ## Defaults rather than NULL, and `+=` rather than `=`
--
-- `0` and `''` on every existing row, and they are honest: those runs genuinely spent
-- tokens nobody counted. NULL would say the same thing while making every `SUM()` in
-- every report carry a `COALESCE`, and `''` for the model is what "nobody recorded this"
-- already looks like in this schema (`vetted_tools.server_name`'s precedent).
--
-- **`finish_run` adds to these columns; it never assigns — and today that is
-- future-proofing rather than a behaviour, which is worth saying plainly.** Plan 013's
-- finding 6 argued `+=` from a run reclaimed after a lease expiry re-executing and
-- spending again. **This platform does not do that**: `recover_expired_runs` moves an
-- expired run to `interrupted` and never back to `queued` ("a run that may have
-- half-happened must not happen twice"), `start_run` and `claim_run` both require
-- `queued`, and `finish_run` keeps the first outcome. Exactly one write lands per row,
-- so `+=` and `=` are indistinguishable here.
--
-- It is `+=` anyway, because of the direction the two fail in if that ever changes: a
-- retry built on `=` loses the first attempt's spend silently, in the column an invoice
-- is reconciled against. The contract suite pins the invariant that makes them equal
-- today (`test_a_second_finish_writes_nothing_at_all`), so relaxing it is a decision
-- somebody makes with this comment in front of them.
--
-- ## What this deliberately does not add
--
-- **No per-turn table.** The richer answer to *where inside a run did the tokens go* is
-- a child table keyed by `run_id`, and it is refused here on 013's own grounds: a new
-- table, a new retention question and a new write in the hot loop, for a question nobody
-- has asked. Nothing about these columns forecloses it — turn rows would sit beside
-- them, not replace them.
--
-- **No rollup and no materialized view.** A tenant total is a `GROUP BY` over that
-- tenant's runs. The first deployment where that is too slow is a deployment holding the
-- row count needed to size the fix, which is exactly the evidence nobody has today.

ALTER TABLE runs
    -- What the reply said it was served by, which is not always what the config asked
    -- for: an alias resolves to a dated id, and the dated id is what the invoice is
    -- computed against. '' on a run that never reached a model call — one refused at the
    -- credential read, or cancelled while queued.
    ADD COLUMN model               TEXT   NOT NULL DEFAULT '',
    ADD COLUMN input_tokens        BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN output_tokens       BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN cache_read_tokens   BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN cache_write_tokens  BIGINT NOT NULL DEFAULT 0,
    -- The largest single prompt this run sent. See amendment 2.
    ADD COLUMN peak_context_tokens BIGINT NOT NULL DEFAULT 0;

-- Counters count up. Cheap, and it is what catches a `=` written where a `+=` belongs —
-- the one implementation mistake in this migration that would produce a plausible number
-- rather than an obviously broken one, and therefore the only one worth a constraint.
ALTER TABLE runs
    ADD CONSTRAINT runs_tokens_are_not_negative CHECK (
        input_tokens >= 0
        AND output_tokens >= 0
        AND cache_read_tokens >= 0
        AND cache_write_tokens >= 0
        AND peak_context_tokens >= 0
    );

-- The usage report's window: this tenant's runs that finished after some instant.
--
-- 013 said a tenant total is *"a query, not a table"* and pointed at `runs_recent`
-- (`tenant_id, seq DESC`) as the index that serves it. That index serves the *list* —
-- which is bounded by a LIMIT and stops walking — and does not serve this one: a window
-- has no limit, so ordering by `seq` and filtering on `finished_at` walks every run the
-- tenant has ever had, forever, and gets slower every week the deployment stays up.
--
-- Partial on `finished_at IS NOT NULL` because queued and running rows have spent
-- nothing that has been accounted yet, and they are the rows a busy deployment has most
-- of at any instant.
CREATE INDEX runs_finished ON runs (tenant_id, finished_at DESC)
    WHERE finished_at IS NOT NULL;
