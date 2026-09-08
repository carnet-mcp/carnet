-- Who may run which agent.
--
-- The product's premise is that anyone with access can use an agent, and when they do
-- it acts on *their* data. Until now the first half of that sentence had no
-- implementation: an agent belonged to a tenant, and every principal in the tenant
-- could run everything.
--
-- ## This is not the permission model
--
-- There are two questions and they must not collapse into one:
--
--     grants        may this PERSON use this agent?      asked once, before a run
--     permissions   may this AGENT do this thing?        asked on every tool call
--
-- The second is `core/permissions.py`, which has survived four steps without learning
-- what a user is. Answering "who may use this" there would put identity inside the
-- policy engine, and the whole layering argument is that the policy engine knows
-- nothing about who is asking beyond the principal it is handed.
--
-- So this table is read where an agent is *loaded for a run*, and the broker never
-- sees it.
--
-- ## Absence is denial, and denial looks like absence
--
-- There is no `public` flag and no wildcard row. An agent nobody has been granted is
-- an agent nobody can run, including the person who created it — which is deliberate,
-- because "it worked until we added sharing" is a better failure than a default that
-- quietly shares.
--
-- The API reports a missing grant as **404, not 403**. A 403 confirms that something
-- exists in a tenant you cannot see, which is a small leak and a free one to close.

CREATE TABLE agent_grants (
    tenant_id      TEXT        NOT NULL,
    agent_name     TEXT        NOT NULL,

    -- Names a principal, not a group. Groups are a second indirection — a mapping from
    -- IdP claims to local roles — and they want a reason and a step of their own.
    -- Sharing with forty people is forty rows until then, and forty rows is honest.
    --
    -- `principal_kind` is here so a system principal can be granted an agent too: a
    -- scheduler running a customer's nightly job needs the same permission a person
    -- does, and giving it a special case would be the exception that erodes this.
    principal_kind TEXT        NOT NULL CHECK (principal_kind IN ('user', 'system')),
    principal_id   TEXT        NOT NULL,

    granted_by     TEXT        NOT NULL DEFAULT '',
    granted_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, agent_name, principal_kind, principal_id),

    -- Cascades: a grant on a deleted agent is not a grant, it is a row that will
    -- quietly reactivate if the name is ever reused.
    FOREIGN KEY (tenant_id, agent_name)
        REFERENCES agents(tenant_id, name) ON DELETE CASCADE
);

-- "What can I run?" — the first query the UI will make.
CREATE INDEX agent_grants_by_principal
    ON agent_grants (tenant_id, principal_kind, principal_id);
