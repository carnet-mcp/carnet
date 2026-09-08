-- Agent configs, as rows.
--
-- The config is JSONB rather than a column per field, deliberately. The shape is
-- defined once, in agents/__init__.py, and validated there; splitting it across
-- columns would make the schema a second definition of what an agent is, free to
-- drift from the one the policy engine reads.

CREATE TABLE agents (
    tenant_id   TEXT        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT        NOT NULL,
    config      JSONB       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, name),

    -- The broker trusts config->>'name' as the agent's identity and writes it into
    -- every audit record. A row whose key disagreed with its body would misattribute
    -- everything that agent ever did. This was an import-time check when configs were
    -- modules; it must not get weaker just because they became data.
    CONSTRAINT agent_name_matches_config CHECK (config->>'name' = name)
);
