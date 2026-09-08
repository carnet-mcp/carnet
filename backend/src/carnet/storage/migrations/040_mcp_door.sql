-- The MCP door's two schema costs. Step 033b — decisions 1 through 4 of plan 033.
--
-- Two changes, and the second is at the foot of this file: a table holding what a
-- machine token has spent through `/mcp` today, and one widened CHECK so that a refusal
-- at the door can be recorded at all. They ride one migration because they are one
-- step's cost, and because the second was found by running the first.
--
-- ## The budget table
--
-- ## Why this is a table and not a counter in the process
--
-- Every other budget in this system is per **run**: `core/limits.py` holds mutable
-- counters on a `RunContext`, they die with the run, and two runs can never interfere.
-- That works because a run is a bounded thing with an owner and an end.
--
-- A tool-mode door call is not a run (decision 4: no prompt, no config, no version, so
-- a `runs` row would lie about all three). What bounds a caller there is the caller
-- itself — one machine token, over a window — and that is a fact about a credential
-- rather than about a unit of work. Nothing in the process outlives a request to hold
-- it.
--
-- The deciding argument is decision 9's, and it is availability rather than tidiness:
-- **the door puts Shipyard in the path of somebody's production agents, so the API has
-- to be able to run as more than one process.** N replicas each enforcing an in-memory
-- copy of "1000 calls a day" is a 1000N ceiling wearing a 1000 label, which is worse
-- than having no dial at all — an operator reads the number, believes it, and is wrong
-- by a factor nobody wrote down. A row in Postgres is the same ceiling whoever serves
-- the request.
--
-- ## The window is a day, and it is stored rather than computed
--
-- `window_start` is a DATE, and the *caller* supplies it (`shipyard/door.py` computes
-- `datetime.now(timezone.utc).date()`). Two reasons, and the second is the one that
-- matters:
--
--   - The in-memory store and this one must agree exactly, and they cannot if one
--     reads a Python clock and the other reads the database's. The contract suite runs
--     both against the same assertions — which is how 033a's missing column was found,
--     and the lesson applied one step early this time.
--   - "The window is the UTC day" is a **policy** statement, and policy belongs above
--     storage. This layer stores a counter keyed by a window; it has no opinion about
--     how long a window is.
--
-- No sweep, no expiry job. A finished day's row is a few dozen bytes and is exactly the
-- usage history an operator would want if they ever ask what a token has been doing;
-- migration 029's retention sweep is where a deletion policy would go if one is ever
-- wanted, and inventing one here for a table with no reader would be inventing a
-- schedule to delete evidence.
--
-- ## What this table is not
--
-- Not a rate limit — `runs.RUNS_PER_HOUR` already bounds run submission per principal
-- and covers agent mode when it lands, because agent mode *is* `runs.submit`. This
-- bounds the path that submits nothing: tool-mode calls, which produce no run row and
-- would otherwise draw on no ceiling at all.
--
-- Not per-connector or per-tool. The dial a deployment wants first is "how much may
-- this credential spend", and a finer one is a column on this table later rather than
-- a different table.

CREATE TABLE mcp_budget (
    tenant_id       TEXT        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The machine token this window belongs to. The composite foreign key is migration
    -- 033's, for its reason: `api_tokens` is keyed by `id` alone, and keying only on
    -- that would let one customer's budget row name another customer's token. CASCADE
    -- so a deleted tenant takes its counters with it — and note that revoking a token
    -- deliberately does *not* delete anything here, because a token row is never
    -- deleted either (see migration 031).
    token_id        TEXT        NOT NULL,

    -- The window this counter covers, as a date. UTC, decided by the caller — see the
    -- header. A DATE rather than a timestamp because a window has no meaningful instant
    -- and comparing dates is what the primary key does.
    window_start    DATE        NOT NULL,

    -- Calls admitted in this window. Incremented by exactly one statement (see
    -- `spend_mcp_call`), which is what makes the ceiling hold under concurrency without
    -- a read-then-write window: two replicas racing at 999 produce 1000 and a refusal,
    -- never 1001.
    --
    -- **Admitted, not attempted.** A call refused by the permission check never reaches
    -- the budget, exactly as `Budget.reserve` is ordered after `permissions.check` in
    -- the broker — a denial must not push a caller toward exhaustion.
    calls           INTEGER     NOT NULL DEFAULT 0 CHECK (calls >= 0),

    PRIMARY KEY (tenant_id, token_id, window_start),

    FOREIGN KEY (tenant_id, token_id)
        REFERENCES api_tokens (tenant_id, id) ON DELETE CASCADE
);

-- Row-level security: the one line migration 037 says a new tenant-keyed table costs,
-- and the contract suite's catalog guard fails by name when it is forgotten. The tenant
-- role reaches its own rows and no others; the owner (the worker, rotation, the
-- migration runner) is exempt, which is why FORCE is deliberately not set here either.
ALTER TABLE mcp_budget ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mcp_budget TO agent_runtime_tenant
    USING (tenant_id = agent_runtime_tenant_id());

-- No index beyond the primary key. Every read and every write names all three key
-- columns — "what has this token spent in this window" is the only question anybody
-- asks — so the primary key index is the whole access pattern.


-- ## A denial can now be about a tool, and the door is what made that true
--
-- Migration 028 wrote `CHECK (resource_kind IN ('agent', 'admin'))`, and that was
-- complete: every refusal this system could record was about a **grant**, produced by
-- one of the two seams `access/denials.py` names — `grants.require` and
-- `roles.require_admin` — so an agent by name and the administrative surface were
-- genuinely everything a denial could be about.
--
-- The door adds a refusal that is about neither. A machine token asking `tools/call` for
-- a name that appears in no agent it is granted is an attempt on a named thing, and it
-- reaches no broker: there is no agent to attribute an audit record to, and inventing
-- one would put a row in an append-only table naming an agent that had nothing to do
-- with the call. So the audit log correctly says nothing, and without this widening a
-- token probing tool names would leave **no trace anywhere at all** — which is the one
-- outcome the denial log exists to prevent.
--
-- Found by running the door rather than by reading the constraint. `denials.record` is
-- best-effort by contract — evidence must never cost enforcement — so the refusal was
-- served correctly, byte for byte, and the record was logged and dropped. That is the
-- fail-safe keeping its promise, and it is exactly why the promise is not a substitute
-- for the column admitting what the code writes.
--
-- Dropped and recreated rather than widened in place: a CHECK has no ALTER, and naming
-- the constraint explicitly is migration 031's lesson — 030's inline CHECKs landed with
-- a suffix that appeared nowhere in their own migration, so a `DROP CONSTRAINT IF
-- EXISTS` on the obvious name was silent and left the narrow constraint standing. This
-- one asks the catalog for the constraint's real name instead of assuming it.
DO $$
DECLARE
    existing text;
BEGIN
    SELECT c.conname
      INTO existing
      FROM pg_constraint c
     WHERE c.conrelid = 'access_denials'::regclass
       AND c.contype = 'c'
       AND pg_get_constraintdef(c.oid) LIKE '%resource_kind%';

    IF existing IS NULL THEN
        RAISE EXCEPTION
            'migration 040 expected a CHECK on access_denials.resource_kind (migration '
            '028 created one) and found none. Widening a constraint that is not there '
            'would leave the column accepting anything, so this refuses instead.';
    END IF;

    EXECUTE format('ALTER TABLE access_denials DROP CONSTRAINT %I', existing);
END $$;

ALTER TABLE access_denials
    ADD CONSTRAINT access_denials_resource_kind_check
    CHECK (resource_kind IN ('agent', 'admin', 'tool'));
