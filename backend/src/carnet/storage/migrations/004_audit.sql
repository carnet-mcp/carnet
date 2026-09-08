-- The audit trail. One row per brokered call — allowed, denied, or failed.
--
-- Flat columns rather than a JSON blob, because these are the things you filter on:
-- `effect` makes "every write last quarter" a WHERE clause rather than an archaeology
-- project, and `run_id` is what turns "what did this agent ever do?" into "what did
-- that run do?".

CREATE TABLE audit (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id       TEXT        NOT NULL REFERENCES tenants(id),

    -- Schema version, present from the first record. It is what makes a later
    -- migration a filter on a field rather than a guess from which keys exist.
    v               SMALLINT    NOT NULL,
    ts              TIMESTAMPTZ NOT NULL,

    run_id          TEXT        NOT NULL,
    principal_kind  TEXT        NOT NULL,
    principal_id    TEXT        NOT NULL,
    agent           TEXT        NOT NULL,
    tool            TEXT        NOT NULL,

    -- '' when the tool was not in the registry — we could not describe it, so we
    -- cannot claim to know what it would have done.
    effect          TEXT        NOT NULL DEFAULT '',

    -- Already redacted by core/audit.py before it reaches here. Free text is hashed
    -- by the tool's own policy; credential-shaped names are hashed unconditionally,
    -- because a DENIED call is still logged and a smuggled secret must not land in a
    -- record we keep forever.
    args            JSONB       NOT NULL,

    decision        TEXT        NOT NULL CHECK (decision IN ('allow', 'deny')),
    reason          TEXT        NOT NULL DEFAULT '',

    -- '' when the call was denied and nothing ran. 'unknown' is reserved for a write
    -- that reached an external system and never answered: it may or may not have
    -- taken effect, and this row is the only place that will ever say so.
    outcome         TEXT        NOT NULL DEFAULT ''
                    CHECK (outcome IN ('', 'ok', 'error', 'oversize', 'unknown')),

    duration_ms     INTEGER,
    response_bytes  BIGINT
);

-- Every record from one run, in order.
CREATE INDEX audit_run ON audit (tenant_id, run_id, id);

-- The recent-runs view.
CREATE INDEX audit_recent ON audit (tenant_id, ts DESC);

-- "Every write last quarter" — the query the design promises, made cheap.
CREATE INDEX audit_writes ON audit (tenant_id, ts DESC) WHERE effect = 'write';

-- Denials are the most important records and the rarest, which is exactly when a
-- partial index earns its keep.
CREATE INDEX audit_denials ON audit (tenant_id, ts DESC) WHERE decision = 'deny';
