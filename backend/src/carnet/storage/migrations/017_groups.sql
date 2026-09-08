-- Sharing with "the support team".
--
-- Migration 009 wrote the reason this exists into the schema, one line under the column
-- it constrains:
--
--     Names a principal, not a group. Groups are a second indirection -- a mapping from
--     IdP claims to local roles -- and they want a reason and a step of their own.
--
-- The reason is ordering rather than demand. `agent_grants` names principals, so sharing
-- with forty people is forty rows, and no enterprise shares with individuals. The next
-- step is the write path and a UI, and a grant that can name a group is a different
-- thing to build a form against than one that cannot. This is the last cheap moment.
--
-- ## A group is a GRANTEE, never a PRINCIPAL
--
-- The load-bearing decision, and the seductive wrong answer is one line: add 'group' to
-- the kinds `agent_grants` already permits and be done. What makes it wrong is what else
-- that vocabulary guards.
--
--     connections   (tenant, principal_kind, principal_id, connector)  -> a sealed credential
--     runs          principal_kind, principal_id                       -> who a run acts for
--     audit         principal_kind, principal_id                       -> who did it
--
-- A principal is who ACTS. Widening that idea makes a group able to hold a delegated
-- credential, which is the precise inversion of step 7a -- there the entire point is that
-- a credential belongs to one person and is bound to (tenant, principal, connector) as
-- GCM additional data. A group credential is an operator credential wearing a team's name.
--
-- So the two vocabularies are split, and this file is where the split becomes physical:
--
--     principal kinds   user, system            who may ACT
--     grantee kinds     user, system, group     who may be GRANTED
--
-- ## The columns are renamed, and that is not tidiness
--
-- `agent_grants.principal_kind` would now hold a value that is not a principal -- a
-- column whose name states an invariant this migration makes false. The concrete cost is
-- a split this step creates: after it, some lookups RESOLVE a person through their groups
-- (`agent_grant_role`, `granted_agent_names`) and some operate on a LITERAL row
-- (`grant_agent`, `revoke_agent`). Sharing one parameter name between them is how a
-- resolving revoke that removes nothing, or a literal check that misses group access,
-- gets written and reviewed without anybody seeing it.
--
-- Renaming is free today and is not free after a UI reads these keys.
--
-- ## The three CHECK constraints that are not about groups
--
-- `agent_grants` was the ONLY table with a CHECK on this column. `audit` (004),
-- `connections` (006) and `runs` (015) declare it `TEXT NOT NULL` and nothing else, so
-- `check_principal_kind` in Python was not one of two layers there -- it was the whole
-- defense, and widening one frozenset would have opened all three with no resistance.
--
-- The step plan defends that with a test. A test written in the same language as the
-- constant does not survive somebody widening the constant: it fails, and it reads as
-- fallout from the change rather than as the change being refused. So the guarantee goes
-- where it cannot be edited by the code it constrains.

-- --- the tables -------------------------------------------------------------------

CREATE TABLE groups (
    tenant_id    TEXT        NOT NULL REFERENCES tenants(id),

    -- `g_<hex>`, opaque, in the shape `u_<hex>` already uses. Never derived from the
    -- name: a group that is renamed is the same group, and every grant naming it has to
    -- survive the rename untouched.
    group_id     TEXT        NOT NULL,

    -- Unique per tenant because this is how a person refers to a group on the CLI, and
    -- two groups called "support" is a command whose meaning depends on insertion order.
    name         TEXT        NOT NULL,
    description  TEXT        NOT NULL DEFAULT '',

    -- For 9b, and in now rather than then. Directory-backed membership resolves a
    -- customer's own group from a token claim, and whether that claim carries a name or
    -- an id is a per-provider question with a real token behind it -- exactly like
    -- `subject_claim` in migration 010. Nullable and unique per tenant, so 9b is a
    -- backfill rather than a schema change on a populated table.
    external_id  TEXT,

    created_by   TEXT        NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, group_id),
    UNIQUE (tenant_id, name),
    UNIQUE (tenant_id, external_id)
);

CREATE TABLE group_members (
    tenant_id       TEXT        NOT NULL,
    group_id        TEXT        NOT NULL,

    -- **A principal, so a group cannot be a member of a group.** Nested groups are
    -- refused here, by the vocabulary that already exists, rather than by a new rule
    -- plus cycle detection on a check that runs before every run.
    --
    -- `system` is permitted deliberately. A scheduler belonging to a group is exactly as
    -- legitimate as a scheduler holding a grant, which migration 009 already argued for,
    -- and excluding it is the special case that erodes the rule.
    principal_kind  TEXT        NOT NULL CHECK (principal_kind IN ('user', 'system')),
    principal_id    TEXT        NOT NULL,

    added_by        TEXT        NOT NULL DEFAULT '',
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, group_id, principal_kind, principal_id),

    FOREIGN KEY (tenant_id, group_id)
        REFERENCES groups(tenant_id, group_id) ON DELETE CASCADE
);

-- **The whole performance story of this step, and it goes in with the table.**
--
-- The permission check runs before every run and `granted_agent_names` filters every
-- list view. Both now have to get from a person to the groups they are in, and without
-- this index that half is a sequential scan on the hot path. `agent_grants_by_grantee`
-- covers the direct half already.
CREATE INDEX group_members_by_principal
    ON group_members (tenant_id, principal_kind, principal_id);

-- --- agent_grants learns about grantees --------------------------------------------

ALTER TABLE agent_grants RENAME COLUMN principal_kind TO grantee_kind;
ALTER TABLE agent_grants RENAME COLUMN principal_id   TO grantee_id;
ALTER INDEX agent_grants_by_principal RENAME TO agent_grants_by_grantee;

-- The inline CHECK from 009, named by Postgres' own convention. Dropped rather than
-- edited, because a CHECK cannot be altered in place.
ALTER TABLE agent_grants DROP CONSTRAINT IF EXISTS agent_grants_principal_kind_check;

ALTER TABLE agent_grants
    ADD CONSTRAINT agent_grants_grantee_kind_check
        CHECK (grantee_kind IN ('user', 'system', 'group'));

-- **A group may not own an agent**, enforced here rather than remembered in Python.
--
-- The precedent is `PENDING_ROLES`, which excludes `owner` because an agent owned by an
-- address that is never claimed is an orphan. A group-owned agent is the same orphan
-- with more people around it: everyone in the group may delete it, nobody is accountable
-- for it, and `transfer` has no meaning when the recipient is a set.
--
-- `agent_grants_one_owner` cannot express this. It is a partial unique index on
-- (tenant, agent) WHERE role = 'owner', and a group owner satisfies it perfectly -- so
-- without this line the database would happily accept one and the only thing refusing it
-- would be a tuple in `storage/base.py`.
--
-- This will be asked for. The answer when it is: a team-owned agent is a *different
-- feature*, about who is on the hook when an agent misbehaves, and it wants an
-- escalation path rather than a role.
ALTER TABLE agent_grants
    ADD CONSTRAINT agent_grants_no_group_owner
        CHECK (NOT (grantee_kind = 'group' AND role = 'owner'));

-- Deleting a group takes the access with it.
--
-- This wants to be `REFERENCES groups(tenant_id, group_id) ON DELETE CASCADE` and cannot
-- be: `grantee_id` names a user, a system principal or a group depending on the column
-- beside it, and a foreign key cannot be conditional. The alternatives were a second
-- grants table -- which makes "who has access?" a union again and re-opens the
-- two-writes-that-disagree problem migration 011 closed -- or cleanup code in Python,
-- which is a rule that holds only while every caller remembers it.
--
-- Without this, `group_members` still cascades, so nobody would *inherit* anything from a
-- deleted group. The damage would be quieter than that: a row in `who_has_access` naming
-- a group that no longer exists, granting nothing, looking exactly like access.
CREATE FUNCTION drop_grants_for_deleted_group() RETURNS TRIGGER AS $$
BEGIN
    DELETE FROM agent_grants
     WHERE tenant_id = OLD.tenant_id
       AND grantee_kind = 'group'
       AND grantee_id = OLD.group_id;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER groups_cascade_grants
    AFTER DELETE ON groups
    FOR EACH ROW EXECUTE FUNCTION drop_grants_for_deleted_group();

-- --- what a principal is, stated where Python cannot widen it ----------------------
--
-- See the header. These three tables have carried this column since 004, 006 and 015
-- with no constraint on it at all.
--
-- `connections` and `runs` are validated against existing rows. Both are bounded -- one
-- row per person per connector, and runs are subject to retention -- so the scan is
-- cheap and the constraint is proven against history as well as against the future.

ALTER TABLE connections
    ADD CONSTRAINT connections_principal_kind_check
        CHECK (principal_kind IN ('user', 'system'));

ALTER TABLE runs
    ADD CONSTRAINT runs_principal_kind_check
        CHECK (principal_kind IN ('user', 'system'));

-- `audit` is NOT VALID, and it is the one table where that is the right answer. It is
-- append-only and unbounded -- retention on it is still undesigned -- so validating it
-- means an ACCESS EXCLUSIVE lock and a full scan of the largest table in the schema, on
-- a deployment where the only thing that would find is history that no code path could
-- have written. `check_principal_kind` has guarded every insert since 004.
--
-- NOT VALID still enforces on every future INSERT and UPDATE, which is the entire
-- security property. It declines only to re-prove the past.
--
-- To finish the job on a database where the scan is affordable, out of migration and
-- outside a transaction:
--
--     ALTER TABLE audit VALIDATE CONSTRAINT audit_principal_kind_check;
ALTER TABLE audit
    ADD CONSTRAINT audit_principal_kind_check
        CHECK (principal_kind IN ('user', 'system')) NOT VALID;
