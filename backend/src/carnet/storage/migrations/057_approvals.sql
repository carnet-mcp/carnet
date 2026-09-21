-- A call a person has to allow before the broker will make it. Step 114, plan
-- `docs/plans/114-a-refusal-with-a-ticket.md`.
--
-- ## What a row is
--
-- An agent's permission list may name tools that need a yes (`permissions.approval`).
-- When the broker reaches one at step 2.5, it does not hold the connection — `PREMISE.md`
-- says `tools/call` returns or refuses, and parking a thread for minutes on a call that
-- costs ~430ms is the async job model agent mode was withdrawn for. It **refuses with a
-- ticket**, and this table is the ticket: the state that decides whether the next
-- identical call is admitted.
--
-- ## The one table in this schema with a lifecycle
--
-- Every table added since 022 is either append-only evidence (`audit`, `admin_audit`,
-- `access_denials`) or standing configuration (`agents`, `connectors`, `groups`). This is
-- neither. It is a small state machine a caller drives and a person resolves:
--
--         pending ──grant──▶ granted ──spend──▶ spent
--            │                   │
--            │                   └── granted_until passes, asked again ──▶ pending
--            └──deny──▶ denied ── the request window passes, asked again ──▶ pending
--
-- **The evidence is not in here.** Who said yes, to what, and when goes to `admin_audit`
-- — the log of *who changed who may do what* — written in the transaction that moves the
-- state, exactly as `grant.create` and `role.grant` are. This table is allowed to be
-- mutable because the permanent record of every decision taken on it is somewhere that is
-- not. `action` needs no migration for the two new verbs: 022 deliberately left that
-- column `<> ''` rather than an enum, *"the set grows every time a method comes into
-- scope"*, and this is the fourth time that has paid.
--
-- And the *call's* record is where it always was. The refusal writes an ordinary
-- `decision='deny'` audit row carrying `held for approval as REQ-…`; the admitted call
-- writes an ordinary `decision='allow'` one. `spent_call_id` below is the correlation
-- between the two — which call the yes actually bought.
--
-- ## One row per distinct call, not one per attempt
--
-- `UNIQUE (tenant_id, fingerprint)`. An agent that retries thirty times produces one row
-- with `asked_count = 30`, not thirty rows, and there are two reasons:
--
--   *The screen.* An approver looking at the same request thirty times cannot work, and
--   `asked_count` with `last_asked_at` carries the one fact a list of duplicates does not
--   — that it is **still** being asked for.
--
--   *The unmetered write, for the fourth time at this door.* An append-only attempt log
--   driven by a caller is a table a granted token fills at will; migration 028's own
--   `resource_id` guard and `MCP_MAX_CALL_BYTES` are the same lesson twice over. One
--   upserted row per distinct call is bounded by the agent's own behaviour. The broker
--   additionally reaches this **after** its budget step, so opening a ticket costs the
--   caller a call from `CARNET_MCP_CALLS_PER_DAY`.
--
-- ## What the fingerprint covers, and what it may hold
--
-- sha256 over the caller (kind and id), the attributed agent's name, the tool name, and
-- the **recorded** arguments — `audit.redact_arguments`' output, the same bytes the audit
-- row holds. So `arguments` below discloses nothing the audit log does not already hold,
-- which is what lets the approver's screen show what is being asked for without opening a
-- new disclosure class: an argument the vetting redacts is a digest here too.
--
-- The caller is in the fingerprint deliberately. An approval is for *this credential's*
-- call; a yes for a staging token must not admit production's.
--
-- ## Deletion
--
-- `ON DELETE CASCADE`, like every table holding product state, and deliberately **not**
-- in `TENANT_BLOCKING_TABLES`: a pending approval must not be able to block a customer's
-- deletion. No foreign key to `agents` — the row holds the agent's name as it stood,
-- which is migration 035's rule and the reason a rename writes its own record.

CREATE TABLE approvals (
    id              BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id       TEXT        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Present from the first row, for the reason `audit.v` is: it is what makes a later
    -- migration a filter on a field rather than a guess from which keys exist.
    v               SMALLINT    NOT NULL,

    -- What the model is told to relay, and what a person searches for. Twelve hex
    -- characters behind `REQ-`, matching `door.new_call_id`'s shape and arithmetic: an
    -- id is copied out of a sentence by hand, and two of them colliding is somebody
    -- approving the wrong call.
    request_id      TEXT        NOT NULL CHECK (request_id <> ''),

    -- The identity of the call itself. See the header.
    fingerprint     TEXT        NOT NULL CHECK (fingerprint <> ''),

    -- Who would make it, and under which permission list. `agent` is the one the union
    -- rule attributed the call to — the same name the audit row will carry.
    agent           TEXT        NOT NULL CHECK (agent <> ''),
    tool            TEXT        NOT NULL CHECK (tool <> ''),
    arguments       JSONB       NOT NULL,
    principal_kind  TEXT        NOT NULL CHECK (principal_kind IN ('user', 'system', 'machine')),
    principal_id    TEXT        NOT NULL,
    -- Whom the call is for, when the door carried an acting-for claim. '' otherwise, on
    -- `access_denials.held`'s precedent — an empty string is the headline case and a NULL
    -- would make every reader write a coalesce.
    acting_for      TEXT        NOT NULL DEFAULT '',

    state           TEXT        NOT NULL
                                CHECK (state IN ('pending', 'granted', 'denied', 'spent')),

    -- When it was first asked for, and when it was last asked for. Both, because an
    -- approver needs to tell *asked once this morning* from *asked every second since*.
    requested_at    TIMESTAMPTZ NOT NULL,
    last_asked_at   TIMESTAMPTZ NOT NULL,
    asked_count     INTEGER     NOT NULL DEFAULT 1 CHECK (asked_count > 0),

    -- Who answered. Empty until somebody does — the pair, on `access_denials`'
    -- principal_kind/principal_id precedent, because a decision is always a person and
    -- an id without its kind is an id nothing can look up.
    decided_by_kind TEXT        NOT NULL DEFAULT '',
    decided_by_id   TEXT        NOT NULL DEFAULT '',
    decided_at      TIMESTAMPTZ,
    -- What they said about it, if anything. A short free-text note **typed by the
    -- approver**, which makes this the one column here that is not derived from a call —
    -- bounded by the route that accepts it, for `access_denials.resource_id`'s reason.
    note            TEXT        NOT NULL DEFAULT '',

    -- How long the yes stays spendable. NULL until granted. A grant is single-use *and*
    -- time-boxed: *once* alone is unusable, because between the yes and the agent's next
    -- attempt there is a person walking back to their desk.
    granted_until   TIMESTAMPTZ,

    -- Which call the yes actually bought. NULL / '' until spent.
    spent_at        TIMESTAMPTZ,
    spent_call_id   TEXT        NOT NULL DEFAULT ''
);

-- The identity of a call, and the constraint the upsert in `claim_approval` conflicts on.
CREATE UNIQUE INDEX approvals_fingerprint ON approvals (tenant_id, fingerprint);

-- What a person relayed out of a model's sentence, looked up by hand.
CREATE UNIQUE INDEX approvals_request_id ON approvals (tenant_id, request_id);

-- "What is waiting for me?", which is how the screen reads this table. `agent` is in the
-- index because the reader is filtered by what the caller holds `editor` on.
CREATE INDEX approvals_open ON approvals (tenant_id, state, last_asked_at DESC);

-- 037's one line per tenant-keyed table.
ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON approvals TO agent_runtime_tenant
    USING (tenant_id = agent_runtime_tenant_id());
