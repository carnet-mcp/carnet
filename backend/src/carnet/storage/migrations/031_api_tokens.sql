-- A machine caller: a credential a cron job, a CI pipeline or a webhook receiver
-- presents, resolving to a principal that is not a person.
--
-- Every API caller until now has been a human. `api/deps.py` ends at `users.resolve`,
-- which needs a subject claim and gates first-time creation on an email domain, so the
-- things agents are deployed *into* could not submit a run at all. This is the register's
-- "middle verb": deploy.
--
-- ## The third kind, and why it is not `system`
--
-- The obvious implementation is a privilege escalation. `access/roles.py` treats every
-- `system` principal as an administrator -- before storage is touched -- and says so in
-- its own docstring, which records that this is safe *because no HTTP caller can be one*.
-- Migration 026's header states the same property. So a machine token minting a `system`
-- principal would make every API token a tenant administrator, quietly, with no row to
-- revoke and nothing in the log calling it an escalation.
--
-- The alternative -- keep `system` and make always-admin conditional -- was rejected. It
-- re-decides the bootstrap (who appoints the first admin), the CLI principal, and
-- lockout-impossibility, all of which 12b settled deliberately and none of which this
-- step has an argument about. So: a third kind, `machine`, which is an administrator
-- nowhere and gets its access the way everybody else does, from a grant.
--
-- ## What a machine may and may not be, expressed as constraints rather than as habit
--
-- Widened here -- a machine may act, own a run, be denied, hold a group membership, hold
-- a delegated credential, and be granted an agent:
--
--     runs.principal_kind            it submits runs, and the row is who submitted
--     audit.principal_kind           its calls are recorded like anybody's
--     access_denials.principal_kind  its refusals are recorded like anybody's
--     group_members.principal_kind   a group of service accounts is legitimate
--     connections.principal_kind     an operator may provision a credential for one
--     agent_grants.grantee_kind      the whole point: access is a grant, not an exemption
--
-- **Left narrow, deliberately, and each is a control rather than an oversight:**
--
--     platform_roles.principal_kind  a machine may never hold a platform role. This is
--                                    the second half of not being an heir to always-admin
--                                    -- refusing the shortcut is worth nothing if the
--                                    long way round is open.
--     admin_audit.actor_kind         no machine performs an administrative act. No code
--                                    path lets one reach a method that writes such a
--                                    record, and this constraint is the tripwire if one
--                                    ever appears.
--
-- A machine also cannot claim a pending grant: those are addressed to an email address,
-- a machine has none, and `check_claimant` already refuses every kind but `user`. That
-- one needed no DDL, which is the shape of a rule that was already right.
--
-- ## A machine is granted `user` and nothing higher
--
-- `agent_grants_no_machine_above_user` is `agent_grants_no_group_owner`'s argument at a
-- different address. A machine runs an agent; editing one and sharing one are acts with
-- somebody's judgment in them, and a credential that lives in a CI variable is the wrong
-- place for that judgment to live. Widening this later is additive; narrowing it after
-- somebody has granted `editor` to a pipeline is a breaking change to their setup.
--
-- ## THE CONSTRAINT NAMES IN THIS FILE ARE NOT THE ONES MIGRATION 030 APPEARS TO CREATE
--
-- Read this before editing anything below, because it cost a real defect's worth of
-- confusion and the source text of 030 will actively mislead you.
--
-- 030 renames each log table aside (`audit` -> `audit_old`) and creates a new partitioned
-- one under the original name. **A rename carries the old table's constraints with it,
-- names and all** -- the same lesson 019 recorded about indexes, one door over -- and
-- Postgres' automatic naming for an inline `CHECK` avoids a name already taken. So every
-- constraint 030 declared *inline* landed with a `1` suffix that appears nowhere in its
-- source:
--
--     access_denials_principal_kind_check1     <- inline in 030's CREATE TABLE
--     admin_audit_actor_kind_check1            <- inline
--     audit_principal_kind_check               <- explicit ADD CONSTRAINT, kept its name
--
-- Read out of `pg_constraint` on the deployment's own Postgres 16.14 rather than out of
-- the migration. `DROP CONSTRAINT IF EXISTS access_denials_principal_kind_check` -- the
-- name any reader would write -- silently does nothing, and `IF EXISTS` is what makes it
-- silent: the narrow constraint survives, and the first machine denial fails at runtime
-- against a control this migration believed it had widened. Both spellings are dropped
-- below, every re-add is **explicitly named** so no later migration inherits this, and
-- the assertion at the foot of the file fails loudly rather than trusting any of it.

CREATE TABLE api_tokens (
    -- Ours and opaque, like `users.id`, and for the same reason: it becomes
    -- `Principal.id` and lands in every audit record, so it is never derived from
    -- anything a person can change. `m_` rather than `u_` so a record's subject is
    -- legible at a glance in a log that mixes them.
    id              TEXT        PRIMARY KEY,

    tenant_id       TEXT        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- What a person calls it in `--list-tokens`. Unique among a tenant's **live** tokens
    -- -- see the partial index below, which is not the obvious `UNIQUE (tenant_id, name)`
    -- and was one before an edge hunt.
    name            TEXT        NOT NULL CHECK (name <> ''),

    -- **A machine has an owner who is a person.** The register's constraint, and it has
    -- teeth rather than being decoration: resolution re-reads this row every request and
    -- refuses when the owner is missing or disabled, so offboarding a person offboards
    -- their machines at the next call.
    --
    -- No foreign key to `users`, matching `connections` and `platform_roles`. There the
    -- reason is that a `system` id exists in no table; here it is migration 006's other
    -- half -- a token must survive its owner's row long enough to be *found* and revoked,
    -- and a cascade would delete the evidence instead. The liveness check is in
    -- `access/tokens.py`, where it can produce a sentence.
    owner_id        TEXT        NOT NULL CHECK (owner_id <> ''),

    -- **Hashed, never sealed**, and this is a deliberate departure from every other
    -- secret in this schema.
    --
    -- `connections`, `connector_oauth` and `pending_authorizations` all hold AES-GCM
    -- ciphertext under `AGENT_RUNTIME_SECRET_KEY`, because something later needs the
    -- plaintext back. Nothing ever needs this one back: a verifier compares. So it is a
    -- digest, and two things follow that a sealed column would not give. A database dump
    -- does not impersonate every machine in it. And these rows are not another population
    -- the key rotation has to reach -- which matters more than it looks, because the
    -- old-key list makes rotation *possible* and nothing re-encrypts a row onto the new
    -- key, so a rotation started today cannot finish. This table declines to join that
    -- problem rather than enlarging it.
    --
    -- Self-describing, on `localidp/accounts.py`'s record shape: `sha256$<hex>`, so a
    -- change of algorithm is a rehash-on-next-use rather than a schema change. Plain
    -- SHA-256 over a domain separator and 32 bytes from `secrets.token_urlsafe` -- not
    -- scrypt, which exists to stretch a low-entropy human password. There is no password
    -- here to stretch, and this comparison sits on the hot path of every machine request.
    secret_hash     TEXT        NOT NULL CHECK (secret_hash <> ''),

    created_by      TEXT        NOT NULL CHECK (created_by <> ''),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- NULL means no expiry, and there is deliberately no default.
    --
    -- An expiry nobody has diarised is a scheduled outage in a cron job at 3am; the
    -- honest control is revocation, which is immediate and checked against this table on
    -- every request rather than waiting for a lifetime to elapse. A deployment that wants
    -- expiry asks for it by name (`--expires-days`).
    expires_at      TIMESTAMPTZ,

    -- **Revocation is a stamp, not a delete**, and unlike `platform_roles` -- where
    -- migration 026 argued the opposite for its own table -- this row must survive its
    -- own revocation. It is the only place a `machine:m_...` string in three years of
    -- audit records resolves to a name and an owner. A role row proves nothing after it
    -- is gone because the log records the grant; a token id is a *subject* in records
    -- that outlive it.
    revoked_at      TIMESTAMPTZ,
    revoked_by      TEXT        NOT NULL DEFAULT '',

    -- Stamped on every resolution, which is the cost `record_user_login` already pays on
    -- every human request. It is what answers "is this token still used" in an
    -- offboarding review, and that question has no other source.
    last_used_at    TIMESTAMPTZ
);

-- **A name is unique among LIVE tokens, not among all of them**, and the difference is
-- the whole point.
--
-- The obvious `UNIQUE (tenant_id, name)` burns a name permanently on revocation. Read
-- that back through the moment this feature is actually used in anger: a token leaks, an
-- operator revokes `nightly-ci`, and then cannot mint its replacement under the name the
-- pipeline's configuration already refers to. The workaround is `nightly-ci-2`, which is
-- how a deployment ends up with names nobody can map to systems.
--
-- Deliberately **not** migration 029's tombstone argument, which burns a tenant id
-- forever so that a recycled id can never make one customer's records look like
-- another's. The two differ because of what carries identity: a tenant id *is* the
-- identity, and this name is a label on a row whose identity is `id`. Every record a
-- machine writes names `machine:m_...`, never the name — so reusing one confuses no
-- audit query, and `--list-tokens` shows revoked rows with their revocation date beside
-- the live one.
--
-- A partial unique index, on the pattern this schema already uses three times:
-- `runs_idempotency`, `agent_grants_one_owner` and `runs_one_live_child`.
CREATE UNIQUE INDEX api_tokens_one_live_name
    ON api_tokens (tenant_id, name) WHERE revoked_at IS NULL;

-- The read on the request path is by primary key, so no index is added for it.
-- `--list-tokens` is a sequential scan of a table with single-digit rows, exactly as
-- migration 026 argued for `platform_roles`: an index ahead of a measurement is a
-- decision nobody can undo without wondering what it was for.


-- --- the third kind, where a machine is allowed ------------------------------------

-- `runs` and `connections` are validated against existing rows: both are bounded, so the
-- scan is cheap and the constraint is proven against history as well as the future. This
-- is migration 017's reasoning for the same two tables, unchanged.

ALTER TABLE runs DROP CONSTRAINT IF EXISTS runs_principal_kind_check;
ALTER TABLE runs
    ADD CONSTRAINT runs_principal_kind_check
        CHECK (principal_kind IN ('user', 'system', 'machine'));

ALTER TABLE connections DROP CONSTRAINT IF EXISTS connections_principal_kind_check;
ALTER TABLE connections
    ADD CONSTRAINT connections_principal_kind_check
        CHECK (principal_kind IN ('user', 'system', 'machine'));

ALTER TABLE group_members DROP CONSTRAINT IF EXISTS group_members_principal_kind_check;
ALTER TABLE group_members
    ADD CONSTRAINT group_members_principal_kind_check
        CHECK (principal_kind IN ('user', 'system', 'machine'));

ALTER TABLE agent_grants DROP CONSTRAINT IF EXISTS agent_grants_grantee_kind_check;
ALTER TABLE agent_grants
    ADD CONSTRAINT agent_grants_grantee_kind_check
        CHECK (grantee_kind IN ('user', 'system', 'group', 'machine'));

-- The ladder's ceiling for a machine. See the header.
ALTER TABLE agent_grants
    ADD CONSTRAINT agent_grants_no_machine_above_user
        CHECK (NOT (grantee_kind = 'machine' AND role <> 'user'));


-- --- the two partitioned logs ------------------------------------------------------
--
-- `NOT VALID` on both, which reproduces exactly what 017 and 030 chose for `audit` and
-- extends it to `access_denials` for the same reason: these are append-only and
-- unbounded, and validating means an ACCESS EXCLUSIVE lock and a full scan to re-prove
-- history that no code path could have written. `check_principal_kind` has guarded every
-- insert since 004.
--
-- **Measured on 16.14 rather than assumed**, because the interaction of `NOT VALID` with
-- partitioning is not obvious and the failure would be silent: adding a `NOT VALID` CHECK
-- to a partitioned *parent* clones it onto every existing partition, onto partitions
-- created months later, and refuses a bad INSERT through the parent in both. That is the
-- same shape 019 measured for triggers -- the parent is where you attach, and the clone
-- is the per-partition enforcement -- and it means the widening holds for months that do
-- not exist yet.
--
-- To finish the job on a database where the scan is affordable, out of migration and
-- outside a transaction:
--
--     ALTER TABLE audit          VALIDATE CONSTRAINT audit_principal_kind_check;
--     ALTER TABLE access_denials VALIDATE CONSTRAINT access_denials_principal_kind_check;

ALTER TABLE audit DROP CONSTRAINT IF EXISTS audit_principal_kind_check;
ALTER TABLE audit DROP CONSTRAINT IF EXISTS audit_principal_kind_check1;
ALTER TABLE audit
    ADD CONSTRAINT audit_principal_kind_check
        CHECK (principal_kind IN ('user', 'system', 'machine')) NOT VALID;

-- Both spellings. The second is the one that is actually there -- see the header.
ALTER TABLE access_denials DROP CONSTRAINT IF EXISTS access_denials_principal_kind_check;
ALTER TABLE access_denials DROP CONSTRAINT IF EXISTS access_denials_principal_kind_check1;
ALTER TABLE access_denials
    ADD CONSTRAINT access_denials_principal_kind_check
        CHECK (principal_kind IN ('user', 'system', 'machine')) NOT VALID;


-- --- the assertion, because every line above rests on a name read out of a catalog ---
--
-- Two halves, and the second is the more important one. That the widened columns accept
-- `machine` is the feature; that `platform_roles` and `admin_audit` still **refuse** it
-- is the security property, and a migration that silently widened one of those by
-- catching it in a loop somebody generalised would be the escalation this whole step
-- exists to avoid.
--
-- Written against `pg_get_constraintdef` rather than against constraint names, so it
-- keeps working when the next migration renames something -- and so it would have caught
-- the `1` suffix that made this block necessary.

DO $$
DECLARE
    offender TEXT;
BEGIN
    -- Must accept 'machine': no surviving CHECK on the column may omit it.
    SELECT format('%s.%s (%s)', c.conrelid::regclass, c.conname,
                  pg_get_constraintdef(c.oid))
      INTO offender
      FROM pg_constraint c
      JOIN (VALUES ('runs', 'principal_kind'),
                   ('connections', 'principal_kind'),
                   ('group_members', 'principal_kind'),
                   ('audit', 'principal_kind'),
                   ('access_denials', 'principal_kind'),
                   ('agent_grants', 'grantee_kind')) AS t(tbl, col)
        ON c.conrelid = t.tbl::regclass
     WHERE c.contype = 'c'
       AND pg_get_constraintdef(c.oid) LIKE '%' || t.col || '%'
       AND pg_get_constraintdef(c.oid) LIKE '%''user''%'
       AND pg_get_constraintdef(c.oid) NOT LIKE '%''machine''%'
     LIMIT 1;

    IF offender IS NOT NULL THEN
        RAISE EXCEPTION
            'migration 031 left a constraint that still refuses machine: %. The live '
            'constraint name is probably not the one this file drops -- read '
            'pg_constraint, not the migration above it.', offender;
    END IF;

    -- Must still refuse 'machine'. A machine administers nothing and performs no
    -- administrative act; see the header.
    SELECT format('%s.%s', c.conrelid::regclass, c.conname)
      INTO offender
      FROM pg_constraint c
      JOIN (VALUES ('platform_roles', 'principal_kind'),
                   ('admin_audit', 'actor_kind')) AS t(tbl, col)
        ON c.conrelid = t.tbl::regclass
     WHERE c.contype = 'c'
       AND pg_get_constraintdef(c.oid) LIKE '%' || t.col || '%'
       AND pg_get_constraintdef(c.oid) LIKE '%''machine''%'
     LIMIT 1;

    IF offender IS NOT NULL THEN
        RAISE EXCEPTION
            'migration 031 widened % , which must stay narrow: a machine principal may '
            'not hold a platform role or perform an administrative act. That is the '
            'other half of not inheriting the always-admin system rule.', offender;
    END IF;
END
$$;
