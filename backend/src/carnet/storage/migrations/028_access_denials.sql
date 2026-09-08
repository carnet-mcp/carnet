-- The access-denial log: who tried, and was refused?
--
-- ## The gap this closes
--
-- A grant check that denies produces no record. `grants.require` refuses somebody and
-- writes one line to stdout, which vanishes with the container — so "who tried to run an
-- agent they may not?" is unanswerable, and it is the question asked after an incident,
-- by somebody who already knows what the agent did and now wants to know who was probing
-- it. Sharper still: the 404 rule deliberately makes an ungranted agent
-- indistinguishable from an absent one *to the caller*, which means an enumeration sweep
-- over plausible names is also indistinguishable *to us* unless somebody was watching
-- stdout at the time. The anti-enumeration answer and the absence of a record are two
-- separate decisions wearing one behavior, and only the first was decided.
--
-- Every denial is attributable by construction: `require` runs after authentication, so
-- there is no anonymous path to it. A record always names a real principal.
--
-- ## Why not `audit`, and why not `admin_audit`
--
-- Migration 022's argument, re-spent: `audit` is tool-call shaped and its records carry
-- a `run_id` — a denied *access* has no run, because the refusal is precisely that no
-- run came to exist. `admin_audit` has no public append method, and its absence is the
-- design: records there are written inside the transaction that performs the write, and
-- a denial performs no write and rides no transaction. Recording one there would mean
-- adding the public append 022 deliberately refused.
--
-- Three questions, three logs: what did the agent do (`audit`), who changed who may do
-- it (`admin_audit`), who tried and was refused (this).
--
-- Reused from 022 deliberately: the append-only trigger from 005, verbatim in shape,
-- and the `v` schema-version column from 004, present from the first record.
--
-- ## What a record can never hold
--
-- No user free text, structurally: `require(principal, agent_name, required)` is
-- everything the seam sees. The task text lives in the request body, which `require` is
-- never handed, so the redaction discipline `audit` needs is unnecessary here — the
-- shape of the seam already excludes the class.

CREATE TABLE access_denials (
    id              BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id       TEXT        NOT NULL REFERENCES tenants(id),

    -- Present from the first record, for the reason `audit.v` is: it is what makes a
    -- later migration a filter on a field rather than a guess from which keys exist.
    v               SMALLINT    NOT NULL,
    ts              TIMESTAMPTZ NOT NULL,

    -- Who asked. A PRINCIPAL, never a group — a group holds grants and never makes a
    -- request. The CHECK goes in the column and not only in `PRINCIPAL_KINDS`, on
    -- migration 017's precedent.
    principal_kind  TEXT        NOT NULL CHECK (principal_kind IN ('user', 'system')),
    principal_id    TEXT        NOT NULL,

    -- What was refused: an agent by name, or the administrative surface. Whether a
    -- denied agent *exists* is deliberately unrecorded — `require` does not know, and
    -- teaching it would cost a second storage read on the refusal path purely for this
    -- log's benefit. An operator holding the log can look the name up themselves.
    resource_kind   TEXT        NOT NULL CHECK (resource_kind IN ('agent', 'admin')),
    resource_id     TEXT        NOT NULL,

    -- The level the request needed, and the level actually held ('' for none). A `user`
    -- probing for `editor` reads differently from a stranger probing at all, and this
    -- pair is what says which.
    required        TEXT        NOT NULL,
    held            TEXT        NOT NULL DEFAULT ''
);

-- "Who has been refused in this tenant lately", which is how the log is read when
-- nobody has a specific question yet.
CREATE INDEX access_denials_recent ON access_denials (tenant_id, ts DESC, id DESC);

-- "What else did this person probe?" — one half of the incident query.
CREATE INDEX access_denials_principal
    ON access_denials (tenant_id, principal_kind, principal_id, id);

-- "Who probed payroll-bot?" — the other half.
CREATE INDEX access_denials_resource
    ON access_denials (tenant_id, resource_kind, resource_id, id);

-- Append-only, enforced by the database rather than by convention — 005's function, in
-- its own copy rather than shared, so the sentence it raises names the right table.
--
-- Retention deletion, when it exists, has to drop this trigger explicitly. That is the
-- intended friction, and this table joins its two siblings in the unanswered retention
-- question without making it worse.
CREATE FUNCTION access_denials_is_append_only() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'access_denials is append-only: % is not permitted', TG_OP
        USING HINT = 'It is the only record of who tried and was refused. Drop the '
                     'trigger deliberately if you are implementing retention.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER access_denials_no_update
    BEFORE UPDATE ON access_denials
    FOR EACH ROW EXECUTE FUNCTION access_denials_is_append_only();

CREATE TRIGGER access_denials_no_delete
    BEFORE DELETE ON access_denials
    FOR EACH ROW EXECUTE FUNCTION access_denials_is_append_only();

-- The same deliberate consequence 005 and 022 record: `tenant_id` references
-- tenants(id) WITHOUT ON DELETE CASCADE, so a tenant with denial records cannot be
-- removed. You cannot offboard a customer and silently erase the record of who was
-- probing what.
