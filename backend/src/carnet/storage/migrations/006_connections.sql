-- Delegated credentials: shape only. Nothing reads this yet.
--
-- Connector credentials are environment variables today — a *shared* secret, so every
-- principal acts with whatever account the operator configured. That is correct for a
-- headless CLI and wrong for anything interactive, which is why
-- `credentials.for_connector` already takes a principal it currently ignores.
--
-- The table exists now for the same reason that parameter does: adding it later means
-- changing the credential module, the broker's call site and every connector at once,
-- while adding it now costs a migration nobody reads. The real vault — a KMS key that
-- unwraps here and nowhere else — belongs with the access layer.

CREATE TABLE connections (
    tenant_id       TEXT        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Keyed by principal, because a delegated credential is the caller's own account
    -- and the vendor enforces what that account can see. Two people running the same
    -- ticket agent must reach two different sets of tickets, and no policy of ours
    -- produces that — it is the credential that differs.
    principal_kind  TEXT        NOT NULL,
    principal_id    TEXT        NOT NULL,

    -- Keyed by connector, not by tool: one GitHub token serves every GitHub tool.
    connector_id    TEXT        NOT NULL,

    ciphertext      BYTEA       NOT NULL,
    key_id          TEXT        NOT NULL,

    -- Two failures this will have to tell apart, because a person has to act on them:
    -- never connected (no row) and expired (a row whose expires_at has passed). A
    -- single "no credential" answer would send someone to the wrong place.
    expires_at      TIMESTAMPTZ,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, principal_kind, principal_id, connector_id)
);
