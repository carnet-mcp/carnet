-- The administrative audit log: who granted this, and who took it away?
--
-- ## The asymmetry this closes
--
-- Every storage method that carries an actor is an addition. Every method that removes
-- something carries none:
--
--     grant_agent          granted_by      revoke_agent            —
--     add_pending_grant    granted_by      delete_pending_grant    —
--     create_group         created_by      delete_group            —
--     add_group_member     added_by        remove_group_member     —
--     transfer_ownership   granted_by      delete_agent            —
--
-- That is not an oversight repeated five times. It falls out of the schema honestly: an
-- actor column lives **on the row**, so a row that is being deleted has nowhere to put
-- one. `agent_grants.granted_by` records who granted access and is destroyed by the
-- revocation it should have recorded.
--
-- So the schema can answer "who gave Sam access?" and cannot answer "who took it away?"
-- — and the second is the question asked after an incident, by somebody who already
-- knows the answer to the first. This table is the half the row-shaped design cannot
-- hold.
--
-- ## Why not `audit`
--
-- `audit` is tool-call shaped: run_id, tool, effect, args, decision, outcome,
-- duration_ms, response_bytes. "Priya revoked Sam's editor grant on triage-bot" has
-- none of those. Forcing it in costs eight nullable columns plus a `record_type`
-- discriminator — and then `audit_query.py`, `GET /runs` and all three partial indexes
-- (`audit_run`, `audit_writes`, `audit_denials`) need a `WHERE record_type = 'call'`
-- they do not have today. Every one of those is a place to forget it, and forgetting it
-- means a tool-call view that silently includes administrative records.
--
-- Two logs answering two questions, and neither answering the other's — the same
-- argument migration 015 made when it split `runs` out of the audit records that were
-- being grouped to fake it.
--
-- Reused from `audit` deliberately: the append-only trigger from 005, verbatim in
-- shape, and the `v` schema-version column from 004, present from the first record.
--
-- ## What a record must never hold
--
-- `detail` holds what CHANGED — a role, the field names, the scope — and never the
-- contents of every field. No credential, no token, and **no agent system prompt**. The
-- first two are obvious; the third is the one somebody will add, because an agent's
-- `system` field is free text a person typed, which is exactly the class `audit`'s
-- redaction exists to keep out of a record kept forever.

CREATE TABLE admin_audit (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id   TEXT        NOT NULL REFERENCES tenants(id),

    -- Present from the first record, for the reason `audit.v` is: it is what makes a
    -- later migration a filter on a field rather than a guess from which keys exist.
    v           SMALLINT    NOT NULL,
    ts          TIMESTAMPTZ NOT NULL,

    -- Who did it. A PRINCIPAL, never a group — a group may hold a grant and may not
    -- act. The CHECK goes in the column and not only in `PRINCIPAL_KINDS`, on migration
    -- 017's precedent: a rule that lives in a Python constant is one the next caller
    -- widens, and a test written in the same language as the constant does not survive
    -- somebody widening it.
    actor_kind  TEXT        NOT NULL CHECK (actor_kind IN ('user', 'system')),

    -- Never empty, and that is the point of decision 3. A nullable or blank actor is a
    -- record that says nobody did it, which is worse than no record: it looks like an
    -- answer. Unattended work passes a `system:` principal — the same hole with a name
    -- that 005 already accepts.
    actor_id    TEXT        NOT NULL CHECK (actor_id <> ''),

    -- 'agent.create', 'grant.revoke', 'group.member.remove', … The vocabulary lives in
    -- `ADMIN_ACTIONS` rather than in a CHECK here, and that is the one place this table
    -- deliberately departs from the rule above: the set grows every time a method comes
    -- into scope (connectors, users, IdPs, connections are all named as later work), and
    -- a CHECK would make each of those an ALTER on an append-only table. The shape is
    -- what matters and the shape is constrained — `'<noun>.<verb>'`, non-empty.
    action      TEXT        NOT NULL CHECK (action <> ''),

    -- What it was done to. 'agent' or 'group' today; a grant is recorded against the
    -- agent it is on, because "what happened to triage-bot" is the question asked.
    target_kind TEXT        NOT NULL CHECK (target_kind <> ''),
    target_id   TEXT        NOT NULL CHECK (target_id <> ''),

    -- The shape differs per action, which is what makes this JSONB and the rest of the
    -- table flat: these columns are what you filter on, and `detail` is what you read
    -- once you have found the row.
    detail      JSONB       NOT NULL DEFAULT '{}'
);

-- "What has been done in this tenant lately", which is how the log is read when nobody
-- has a specific question yet.
CREATE INDEX admin_audit_recent ON admin_audit (tenant_id, ts DESC, id DESC);

-- "Everything that ever happened to this agent" — the incident query, and the reason a
-- grant is recorded against its agent rather than against its grantee.
CREATE INDEX admin_audit_target ON admin_audit (tenant_id, target_kind, target_id, id);

-- "Everything this person did", which is the other half of the same incident.
CREATE INDEX admin_audit_actor ON admin_audit (tenant_id, actor_kind, actor_id, id);

-- Append-only, enforced by the database rather than by convention — 005's function, in
-- its own copy rather than shared. `audit_is_append_only()` names `audit` in the
-- sentence it raises, and a record that tells somebody to go and look at the wrong table
-- is worse than a duplicated four-line function.
--
-- Retention deletion, when it exists, has to drop this trigger explicitly. That is the
-- intended friction, and this table inherits `audit`'s unanswered retention question
-- without making it worse.
CREATE FUNCTION admin_audit_is_append_only() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'admin_audit is append-only: % is not permitted', TG_OP
        USING HINT = 'It is the only record of who took access away. Drop the trigger '
                     'deliberately if you are implementing retention.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER admin_audit_no_update
    BEFORE UPDATE ON admin_audit
    FOR EACH ROW EXECUTE FUNCTION admin_audit_is_append_only();

CREATE TRIGGER admin_audit_no_delete
    BEFORE DELETE ON admin_audit
    FOR EACH ROW EXECUTE FUNCTION admin_audit_is_append_only();

-- The same deliberate consequence 005 records: `tenant_id` references tenants(id)
-- WITHOUT ON DELETE CASCADE, so a tenant with administrative records cannot be removed.
-- You cannot offboard a customer and silently erase the record of who was given access
-- to what, and who took it back.
