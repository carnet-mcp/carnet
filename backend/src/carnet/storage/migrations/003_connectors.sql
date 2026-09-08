-- Vetted MCP servers, and the per-tool vetting decisions that make them usable.
--
-- Two tables rather than one manifest blob, for two reasons. Vetting is a per-tool
-- review — `vetted_by` and `vetted_at` are the connector-admin persona's audit trail,
-- and they belong on the row being reviewed. And "which writes are vetted anywhere in
-- this tenant" should be a WHERE clause, not a JSONB traversal.

CREATE TABLE connectors (
    tenant_id   TEXT        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id          TEXT        NOT NULL,             -- 'github-mcp'
    description TEXT        NOT NULL DEFAULT '',

    -- How to start the server and where it expects its credential. Not a secret:
    -- `credential_env` is the NAME of an environment variable, never its value.
    launch      JSONB       NOT NULL,

    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, id)

    -- There is deliberately NO read_only column. It is derived from the vetted
    -- effects below (see Connector.read_only): vet a write and the mode comes off by
    -- itself, for exactly as long as that write stays vetted. A stored copy is free
    -- to disagree with the allowlist it is supposed to defend, which is the entire
    -- reason it is computed. The storage layer refuses a manifest carrying one.
);

CREATE TABLE vetted_tools (
    tenant_id          TEXT        NOT NULL,
    connector_id       TEXT        NOT NULL,
    remote_name        TEXT        NOT NULL,      -- as the server advertises it

    -- The annotation the server cannot make for us. MCP supplies a name, a
    -- description and a schema; it does not say whether a call mutates anything, nor
    -- which argument is the resource worth scoping on. `readOnlyHint` is advisory and
    -- self-declared, and an enterprise boundary cannot rest on a claim made by the
    -- component being constrained.
    effect             TEXT        NOT NULL CHECK (effect IN ('read', 'write')),
    resources          JSONB       NOT NULL DEFAULT '[]',

    local_name         TEXT,
    max_response_bytes BIGINT,

    -- Who approved this tool, and when. The review record, not just the result.
    vetted_by          TEXT        NOT NULL DEFAULT '',
    vetted_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, connector_id, remote_name),
    FOREIGN KEY (tenant_id, connector_id)
        REFERENCES connectors(tenant_id, id) ON DELETE CASCADE
);

-- "Show me every write anyone vetted" — the question a security review asks first.
CREATE INDEX vetted_tools_writes
    ON vetted_tools (tenant_id)
    WHERE effect = 'write';
