-- A run, as a row. The thing that has been missing since 004.
--
-- Until now a run existed only as a `run_id` stamped onto audit records, so "what is
-- run X?" was answered by grouping the audit log. That makes a run *derived* rather
-- than recorded, and three things follow from it:
--
--   - A run that called no tools produces no audit records, so it does not exist. The
--     API hands back a run id and then answers 404 on it. That is the gap this chunk
--     is here to close.
--   - There is nowhere to put a status. "complete" was whatever the request handler
--     happened to return, computed at the moment of returning it.
--   - A run has no representation outside the process executing it, so a restart loses
--     it and nothing can be recovered.
--
-- After this, the row is authoritative for the run and the audit records stay
-- authoritative for the calls it made. They answer different questions and must not
-- both answer the same one — a row saying `complete` and a reconstruction saying
-- otherwise is exactly the disagreement this codebase keeps refusing to build.
--
-- ## This table is also the queue
--
-- Not a separate queue and a separate record, which is the deciding argument for
-- Postgres over Redis and it is not the obvious one. Durability is not the point and
-- volume is not the point — an agent run takes seconds to minutes, so this is at most
-- thousands of rows a day per customer, five orders of magnitude below where a broker's
-- speed is detectable. The point is that **the queue entry and the run record must
-- never disagree.** Here they are one row and enqueueing is one INSERT. Across two
-- systems you get a job with no record or a record with no job, and the standard repair
-- is a transactional outbox — which is a Postgres queue plus Redis.
--
-- The claim columns (`claimed_by`, `claimed_at`, `lease_expires_at`, `attempt`) are
-- written by nothing in this chunk. They are here because schema is the expensive thing
-- to add late and a claim loop is the next chunk; the same reason `run_id` and `status`
-- were in the HTTP response from the first version.
--
-- ## What this table holds
--
-- `task` and `answer` are free text a person typed and a model produced. That makes
-- this personal data in a way the audit log's redacted arguments were deliberately
-- designed not to be, and **retention is undesigned**. Encrypting them at rest is now
-- possible (`core/crypto.py`) and is deliberately not done here: it is a key-scope and
-- retention decision, and folding it into this migration would settle it by accident.

CREATE TABLE runs (
    -- Insertion order, and it is what "newest first" means.
    --
    -- Not decoration and not a second primary key. `created_at` is not a usable sort
    -- key on its own: three runs submitted inside one clock tick share a timestamp, and
    -- then the list order is decided by whatever the tiebreak is — which for a random
    -- id is no order at all. Found by running it: `datetime.now()` on Windows advances
    -- about every 15ms, so three submissions in a loop were genuinely simultaneous and
    -- the list came back shuffled.
    --
    -- The same reasoning gave `audit` its BIGINT IDENTITY, where the comment reads
    -- "insertion order IS the ordering guarantee". A run list is read newest-first by a
    -- person deciding what happened most recently, and "most recently" has to be a fact
    -- rather than a coin toss.
    --
    -- Deliberately not exposed above storage. It is an ordering device, not an
    -- identity — a caller that learned to use it would be depending on a
    -- single-database counter that nothing else in this schema promises.
    seq              BIGINT      GENERATED ALWAYS AS IDENTITY,

    -- **Globally unique, not per tenant**, which is the one surprising thing here.
    --
    -- The claim query in the next chunk selects a queued row across every customer and
    -- then updates it by id — a worker serves everybody, and filtering by tenant there
    -- would mean a worker per tenant. That query is only correct if an id names one row
    -- in the whole table.
    --
    -- The cost is honest: `run_id` is `uuid4().hex[:12]`, which is 48 bits, so at a
    -- billion runs a collision is not merely possible. This makes that arrive as a
    -- failed INSERT on one request rather than as two customers' audit records quietly
    -- merging under one id — which is what already happens in `audit`, where nothing
    -- enforces uniqueness at all. Widening the id is a change to `RunContext` and is
    -- not this chunk.
    run_id           TEXT        PRIMARY KEY,

    tenant_id        TEXT        NOT NULL REFERENCES tenants(id),

    -- The agent's **name**, with no foreign key to `agents`, and that is deliberate.
    -- Every other reference to an agent in this schema cascades on delete, because a
    -- grant on a deleted agent is a row that reactivates when the name is reused. A run
    -- is the opposite: it is history. Deleting an agent must not delete the record of
    -- what it did, and an owner who could erase their agent's trail by deleting it has
    -- an audit log that answers to the person it is auditing.
    agent            TEXT        NOT NULL,

    -- Who the run acts for. The pair rather than a `users` FK, matching `audit` — a
    -- principal may be `system:cli`, which is not a row in `users`.
    principal_kind   TEXT        NOT NULL,
    principal_id     TEXT        NOT NULL,

    task             TEXT        NOT NULL,

    -- A closed set, and each value is a different thing a person does next:
    --
    --   queued       accepted, nothing has run
    --   running      claimed, lease live
    --   complete     finished with an answer
    --   incomplete   hit MAX_TURNS. It ran, it spent, there is no answer
    --   failed       raised. `error` says what
    --   cancelled    asked to stop, and stopped
    --   interrupted  its lease expired. Started, unknown how far, NEEDS A PERSON
    --
    -- `interrupted` is the one worth defending, and nothing writes it yet. Folding it
    -- into `failed` would lose the distinction between "this did not work" and "this may
    -- have half-happened" — the same distinction `audit.outcome = 'unknown'` draws for a
    -- single write, and for the same reason: an agent's writes reach real systems.
    status           TEXT        NOT NULL DEFAULT 'queued'
                     CHECK (status IN ('queued', 'running', 'complete', 'incomplete',
                                       'failed', 'cancelled', 'interrupted')),

    -- NULL until there is one, and NULL is not ''. A run that completed with an empty
    -- answer and a run that has no answer yet are different states, and a NOT NULL
    -- DEFAULT '' would collapse them into the one a UI renders as a blank reply.
    answer           TEXT,

    error            TEXT        NOT NULL DEFAULT '',

    -- Caller-supplied, unique per tenant. An enterprise client retries: their HTTP
    -- library retries, their service mesh retries, their integration platform retries on
    -- a 502 that happened *after* we accepted the request. Without this each retry is
    -- another agent run — more model spend, more writes to their systems.
    --
    -- '' rather than NULL for "the caller did not supply one", with the unique index
    -- below made partial to match. NULL would work too (NULLs do not collide in a unique
    -- index) but then two representations of "absent" exist and code has to handle both.
    idempotency_key  TEXT        NOT NULL DEFAULT '',

    -- The claim, written by nothing in this chunk. See the note above.
    claimed_by       TEXT        NOT NULL DEFAULT '',
    claimed_at       TIMESTAMPTZ,
    lease_expires_at TIMESTAMPTZ,
    attempt          INTEGER     NOT NULL DEFAULT 0,

    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at       TIMESTAMPTZ,
    finished_at      TIMESTAMPTZ,

    -- Time only moves forwards. Cheap, and it is what catches a status transition
    -- somebody wrote in the wrong order.
    --
    -- Note what is deliberately NOT asserted: that a finished run has started. A run
    -- cancelled while still `queued` finishes without ever having started, and that is
    -- a legitimate row rather than a bug — so the constraint that looks obviously right
    -- would have to be dropped again the moment cancellation lands.
    CHECK (started_at IS NULL OR started_at >= created_at),
    CHECK (finished_at IS NULL OR finished_at >= created_at)
);

-- "One retry, one run." Scoped `(tenant_id, idempotency_key)` and **never global**:
-- keys are chosen by customers and two of them will pick '1'.
--
-- Partial, so the overwhelming majority of runs — which supply no key — do not all
-- collide on ''.
CREATE UNIQUE INDEX runs_idempotency ON runs (tenant_id, idempotency_key)
    WHERE idempotency_key <> '';

-- The list view: this tenant's runs, newest first. On `seq` rather than `created_at`,
-- because that is what the sort actually uses — see the column comment.
CREATE INDEX runs_recent ON runs (tenant_id, seq DESC);

-- Lookup by unique prefix, which is what `--compare` and `GET /runs/{id}` accept
-- because twelve hex characters is a lot to type. `text_pattern_ops` is what makes
-- `LIKE 'abc%'` use an index; the default collation-aware ops do not.
CREATE INDEX runs_by_prefix ON runs (tenant_id, run_id text_pattern_ops);

-- The claim, next chunk. Partial because queued rows are a tiny and shrinking fraction
-- of the table, which is exactly when a partial index earns its keep — the scan stays
-- proportional to the backlog rather than to the history.
CREATE INDEX runs_queued ON runs (created_at) WHERE status = 'queued';

-- Lease recovery, next chunk. "Which claimed runs belong to a worker that stopped
-- heartbeating?"
CREATE INDEX runs_leases ON runs (lease_expires_at) WHERE status = 'running';
