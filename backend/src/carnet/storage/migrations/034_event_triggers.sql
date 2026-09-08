-- Event triggers: the first entrance where nobody signed in upstream. Step 023.
--
-- Every door until now had a human somewhere behind it: a person signs in (005), a
-- person mints a token at a shell and a machine presents it (020), a person schedules a
-- token and the platform fires it (022). A trigger's caller is an outside system that
-- never signed into anything and holds nothing from the customer's identity provider.
--
-- The answer is that the door mints no new kind of authority -- it RESOLVES to authority
-- that already exists. A delivery proves it holds this row's secret; the row names a
-- machine token; the token belongs to a person; the token's grants say what it may run.
-- Every delivery re-reads that whole chain (`tokens.act_for`, `grants.require`), so
-- revoking the token, disabling its owner, unsharing the agent or suspending the tenant
-- each stop the trigger at its next delivery with no rule written twice. What is new is
-- only the authenticator -- an HMAC over the request body instead of a bearer -- never
-- the authority.
--
-- ## Why the secret is sealed rather than hashed, unlike `api_tokens.secret_hash`
--
-- Migration 031 hashes because a presented secret can be hashed and compared. An HMAC
-- verifier is handed no secret -- it must COMPUTE `HMAC(secret, body)` and compare
-- signatures, which requires the raw secret at every delivery. So this row seals it
-- under `core/crypto.py` (AES-256-GCM, additional data binding it to this exact row),
-- and 020's sentence "hashing keeps these rows out of the key-rotation problem" does
-- not carry over: trigger secrets join `connections`, `connector_oauth` and
-- `pending_authorizations` in the population a key rotation must one day re-encrypt.
-- Stated here because it is the one cost of the HMAC design worth a reader's pause --
-- the alternative (a bearer-style secret in a header, hashable) travels on every
-- delivery through every proxy log on the path and binds nothing to the body.
--
-- ## What bounds the spend, since a door spends money on every hit
--
-- Nothing in this table -- deliberately. A schedule's bounds are structural (cadence
-- floor, no backfill, no overlap) because a clock is ours; a sender's clock is not.
-- The bound is per-principal rate limiting in `runs.submit`, which this migration's
-- second statement (the index below) makes affordable: every fire, every schedule and
-- every curl by one principal counts against one ceiling, in the one function all of
-- them cross.
--
-- ## The two foreign keys
--
-- Both are migration 033's, argument for argument. The agent key makes a trigger
-- cascade with its agent: standing configuration naming a deleted agent is a row that
-- reactivates when somebody reuses the name -- at somebody else's agent, as somebody
-- else's machine, from a URL an outside system still holds. The token key says SAME
-- TENANT, which a single-column key cannot say, and it can be composite because 033
-- already built `api_tokens_tenant_id_id` to make exactly this shape legal.

CREATE TABLE triggers (
    -- 'trg_' + 16 hex. Sixteen rather than schedules' twelve on `api_tokens.id`'s
    -- reasoning: this id travels in a URL that lives in an outside system's
    -- configuration and in every proxy log between it and us. It is a lookup key
    -- rather than a secret -- possession of the URL without the secret buys a 404 --
    -- but an identifier that public earns the wider space.
    id               TEXT        PRIMARY KEY,

    tenant_id        TEXT        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    agent_name       TEXT        NOT NULL,

    -- The machine a delivery acts as. Never the person who created the trigger: a
    -- trigger outlives its author's session, team and employment, and a delivery
    -- carrying a person's authority would be authority nobody can revoke without
    -- deleting the person. Migration 033's argument, verbatim, because it is the same
    -- decision.
    token_id         TEXT        NOT NULL,

    -- What this trigger is, to a person reading a list. Schedules have no name and
    -- need none -- their cadence describes them. A trigger's other half lives in
    -- somebody else's configuration screen, and "which of these three is the Jira one"
    -- must be answerable from `--list-triggers` without opening three external systems.
    name             TEXT        NOT NULL CHECK (name <> ''),

    -- What the agent is asked to do, with the delivery's payload appended under a
    -- delimiter. Redacted from administrative records exactly as `schedules.task` and
    -- `default_task` are -- migration 022's rule reaches this column by name.
    task             TEXT        NOT NULL CHECK (task <> ''),

    -- The HMAC secret, sealed under the active key. `nonce || ciphertext || tag`, the
    -- single-BYTEA shape `connections.credential_sealed` established. The additional
    -- data binds (tenant_id, trigger id), so a blob copied into another row -- or
    -- another tenant's row -- fails to authenticate rather than firing as them.
    secret_sealed    BYTEA       NOT NULL,
    secret_key_id    TEXT        NOT NULL CHECK (secret_key_id <> ''),

    enabled          BOOLEAN     NOT NULL DEFAULT true,

    -- The stamp a VERIFIED delivery leaves, fired or refused. One row deep, the
    -- schedules bargain: the runs it produced are in `runs`, addressable by this
    -- trigger's idempotency-key prefix, and what these columns answer is "why is
    -- nothing happening", which has no other source. An unverified delivery -- wrong
    -- signature, unknown id -- writes NOTHING here: an unauthenticated flood must not
    -- become a write per request.
    last_delivery_at TIMESTAMPTZ,
    last_run_id      TEXT        NOT NULL DEFAULT '',
    last_outcome     TEXT        NOT NULL DEFAULT '',

    created_by       TEXT        NOT NULL CHECK (created_by <> ''),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

    FOREIGN KEY (tenant_id, agent_name)
        REFERENCES agents (tenant_id, name) ON DELETE CASCADE,

    -- CASCADE for the tenant's sake, exactly as migration 033 argues: nothing deletes
    -- an `api_tokens` row (revocation is a stamp), so the only DELETE this clause ever
    -- sees is a tenant deletion, where this row is going anyway through its own key.
    FOREIGN KEY (tenant_id, token_id)
        REFERENCES api_tokens (tenant_id, id) ON DELETE CASCADE
);

-- The door's read is `find_trigger(id)` -- the primary key -- so the only index this
-- table needs is for listings and the agent cascade, `schedules_by_agent`'s twin.
CREATE INDEX triggers_by_agent ON triggers (tenant_id, agent_name);

-- The rate limit's index, and it is on `runs` rather than on anything new: every run
-- row already names its principal, so "how many runs has this principal created in the
-- last hour" is a COUNT over this index rather than a counter table with its own
-- retention story and its own store-unreachable policy. The `derived rather than
-- stored` argument (`runs_of`, the declined `runs.agent_version`) applied to a limit.
CREATE INDEX runs_by_principal
    ON runs (tenant_id, principal_kind, principal_id, created_at DESC);
