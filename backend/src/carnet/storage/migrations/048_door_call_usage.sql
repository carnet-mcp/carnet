-- What a door call spent at a model. Step 045b.
--
-- Migrations 045 and 046 made the product able to say what a **run** cost. Every one of
-- those numbers reads `runs` — and a door call writes no `runs` row, by the premise's
-- own rule (`CLAUDE.md`: *"a door call is not a run"*). So the paying shape of the
-- product, ten thousand door calls a week, had a call-count ceiling (`mcp_budget`, 040)
-- and **no dollar anywhere**: not recorded, not bounded, not drawn.
--
-- That was tolerable while every brokered call was a vetted tool whose token cost is a
-- vendor's problem. 045c ends it — a brokered model call spends real money per call,
-- under a key this platform holds — so these columns land *before* the first one exists,
-- and the ceiling built on them is never fiction.
--
-- ## The columns are filled at INSERT because there is no other moment
--
-- `audit` is append-only by trigger, and migration 029 loosened DELETE for retention
-- while deliberately leaving UPDATE forbidden: *"a trigger that allowed UPDATE under a
-- setting would make 'correcting' a record expressible."* So there is no write-then-fill
-- shape available here and none is needed — `core/broker.py` already collects
-- `duration_ms` and `response_bytes` after execution and before its single `_audit(...)`
-- call, and usage a tool reports arrives in the same window and rides the same INSERT.
-- No second write, no second table, nothing in the hot path that was not there.
--
-- ## Nullable, which is the opposite of 045's choice on `runs`, on purpose
--
-- 045 wrote `NOT NULL DEFAULT 0` and argued it: on `runs` every row is a model run, so
-- a zero is honest — *"those runs genuinely spent tokens nobody counted."*
--
-- On `audit` that argument inverts. Almost every row here is a tool call that touched no
-- model at all, and `0` would say *spent nothing* where the truth is *not applicable* —
-- which is exactly the distinction `normalize_audit_record` already draws for
-- `response_bytes` (*"NULL — never ran, rather than ran in zero time"*). A NULL also
-- keeps a refused call and a call that reported nothing out of every SUM by
-- construction, rather than by remembering to exclude them; and it is what the partial
-- index below is predicated on, which is what keeps the gate's read off the rows that
-- have nothing to contribute.
--
-- `model` is NOT NULL DEFAULT '' — 045's reading of an unrecorded model, and
-- `vetted_tools.server_name`'s before it. A usage report that names no model is stored
-- with `''` and priced by nobody: `core/usage.model_family` returns `''` for it and
-- `estimate_cost` hands back NULL rather than blending it into somebody else's rate.
--
-- ## No cost column, for the third time in this schema
--
-- 045's Amendment 3 (*"a stored dollar figure is a frozen estimate that reads like an
-- invoice"*) and 046's repetition of it both stand and both apply harder here: a door
-- call's rate is a customer's contract with a vendor this platform does not sign. Rates
-- stay off the write path, in `core/usage.RATES` and the operator's
-- `SHIPYARD_MODEL_RATES`, and the arithmetic happens at read time in `price_buckets`.
--
-- ## What this deliberately does not add
--
-- **No `SCHEMA_VERSION` bump.** `core/audit.py`'s rule is that the version moves when a
-- field's *meaning* changes, never when one is added; a reader that has never seen these
-- columns reads a v7 row correctly and gets NULLs, which is the truth about it.
--
-- **No backfill.** Rows written before this migration have NULL usage and are simply not
-- part of any sum. A deployment upgrading into this starts its day looking cheaper than
-- it was, the same concession 045 made in its own words.

ALTER TABLE audit
    -- What answered, when a tool reported one. Not the model an agent is configured
    -- with: a brokered model call names its own model in its own request, and an alias
    -- resolves to a dated id that is what an invoice is computed against.
    ADD COLUMN model              TEXT NOT NULL DEFAULT '',
    ADD COLUMN input_tokens       BIGINT,
    ADD COLUMN output_tokens      BIGINT,
    ADD COLUMN cache_read_tokens  BIGINT,
    ADD COLUMN cache_write_tokens BIGINT;

-- Counters count up — 045's `runs_tokens_are_not_negative`, named the same way for the
-- same reason (migration 031's lesson: a constraint somebody must later find deserves a
-- name its own migration wrote).
--
-- It bites harder here than it did there. On `runs` the number came from a reply this
-- process had just received; here it comes from **a connector's response body**, which
-- is a vendor's text and, through a REST binding, a value the vetter pointed at rather
-- than one anybody validated. `core/usage.parse_report` refuses garbage one layer up and
-- logs it; this is what makes that a property of the table rather than a promise kept by
-- one function. A negative counter would subtract from somebody's ceiling — a connector
-- able to spend a principal's allowance downward is the one lie in this direction that
-- costs money.
--
-- `NULL OR >=` per counter rather than a blanket comparison: SQL's three-valued logic
-- would make a single `input_tokens >= 0` unknown-not-false on a NULL row, which passes,
-- but spelling it leaves nothing for a reader to work out.
ALTER TABLE audit
    ADD CONSTRAINT audit_tokens_are_not_negative CHECK (
        (input_tokens       IS NULL OR input_tokens       >= 0)
        AND (output_tokens      IS NULL OR output_tokens      >= 0)
        AND (cache_read_tokens  IS NULL OR cache_read_tokens  >= 0)
        AND (cache_write_tokens IS NULL OR cache_write_tokens >= 0)
    );

-- The door's sibling of `runs_principal_finished` (046), and the gate's whole read:
--
--     WHERE tenant_id = ? AND run_id LIKE 'door-%' AND ts >= ?
--       AND principal_kind = ? AND principal_id = ? AND input_tokens IS NOT NULL
--     GROUP BY model
--
-- **Partial on `input_tokens IS NOT NULL`, which is this index's whole economics.** On
-- every deployment whose tools report no usage — which is every deployment today, and
-- most deployments after 045c ships too — this index is *empty*: it costs an insert
-- nothing but the predicate test, and it occupies no pages. On a deployment that does
-- broker model calls it holds exactly the rows that can contribute to a sum, which on a
-- busy tenant is a small fraction of an append-only table that also holds every ordinary
-- tool call.
--
-- That is the answer to the obvious objection — an index on a partitioned, append-only,
-- write-heavy table, added to serve a read on the hot path of every door call. The
-- predicate is what makes the write side approximately free, and the INCLUDE is what
-- makes the read index-only. Both are measured below rather than asserted.
--
-- `ts DESC` matches 046's `finished_at DESC` and the reason carries over: the read is a
-- window with no LIMIT, so the window column must be in the key or the scan walks
-- everything the principal has ever done.
--
-- The counters and `model` ride as payload for 046's reason, restated because it is the
-- half people remove: cost is tokens x the rate for the model that produced them, so the
-- aggregate must group by model or the arithmetic is a blended rate — the thing
-- `estimate_cost` refuses one layer up. They are not key columns because nothing searches
-- or orders by them.
--
-- ## `run_id` is payload, and the first draft left it out
--
-- `LIKE 'door-%'` is a prefix match the planner cannot use as an access path through a
-- non-C-collation index, so it looked like a filter that belonged in the heap — and it
-- was written that way, on the argument that the partial predicate had already excluded
-- every run's row because a run's tokens live on `runs`.
--
-- **That argument is wrong, and measuring it is what showed the cost.** A *run* can call
-- a brokered model tool too: the broker is one path, so an agent on the bench that calls
-- a model connector writes an `audit` row with real counters and an ordinary run id.
-- `run_id LIKE 'door-%'` is therefore load-bearing rather than decorative — it is what
-- keeps the bench's spend out of the door's ceiling — and leaving it off the index turned
-- what should be an index-only scan into an Index Scan with a heap fetch per row.
--
-- Carried, it costs 17% of the index and the plan becomes Index Only.
--
-- ## Measured rather than argued, on 046's precedent
--
-- 210,000 audit rows across 200 principals, 10,000 of them carrying usage — a deployment
-- brokering a model connector beside its ordinary tools. One principal's one-day window,
-- Postgres 16, warm cache:
--
--     with this index          Index Only Scan, 9 buffers, 0.017 ms, index 1264 kB
--     without run_id carried   Index Scan,      9 buffers, 0.019 ms, index 1080 kB
--     without it entirely      Bitmap Heap Scan, 3629 buffers, 1.829 ms,
--                              "Rows Removed by Filter: 14,900"
--
-- Those fourteen thousand removed rows are every call anybody in the tenant made that
-- day, read to answer a question about one credential — the cost that grows with the
-- tenant rather than with the answer, and the reason this index exists rather than a
-- comment saying `audit_recent` is close enough.
--
-- The write side, on the same 210,000 rows: `ALTER TABLE` adding all five columns is
-- **1 ms** (metadata-only, 041's 16ms over 200,000 rows is the bar and this clears it
-- because none of the five is NOT NULL without a constant default), the CHECK is 14 ms,
-- and building the index is 20 ms. The whole migration chain from empty runs in 213 ms.
--
-- On the partitioned parent, so it propagates to every partition present and future
-- (041's note, and the same is true of the ALTERs above).
CREATE INDEX audit_principal_usage
    ON audit (tenant_id, principal_kind, principal_id, ts DESC)
    INCLUDE (run_id, model, input_tokens, output_tokens,
             cache_read_tokens, cache_write_tokens)
    WHERE input_tokens IS NOT NULL;
