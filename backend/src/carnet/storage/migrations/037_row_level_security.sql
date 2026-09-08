-- Row-level security: the database's own opinion about tenancy. Step 029.
--
-- Every query in `storage/postgres.py` filters on `tenant_id`, and until this file
-- nothing checked that any of them did. `002_agents.sql` put tenancy in the schema from
-- the first migration; this puts it in the *enforcement*: a role the policies apply to,
-- one policy per table, and a session setting that names which tenant a connection is
-- currently serving. The application half — taking the role and binding the setting on
-- every scoped borrow, and never on the worker's — is `PostgresStorage._connection()`,
-- and the reasoning is `docs/plans/029-row-level-security.md`.
--
-- ## The one migration that touches anything outside this database
--
-- A role is cluster-global. Creating it needs CREATEROLE, **once per cluster** — the
-- only privilege any migration has ever needed beyond owning the tables. Where the
-- migrating role lacks it, the DO block below refuses with the two statements an
-- administrator runs first, and re-running --migrate then proceeds. Two databases in
-- one cluster share the role harmlessly: it is NOLOGIN, and everything it may touch is
-- granted per database.
--
-- ## Who the policies deliberately do not apply to
--
-- Only `agent_runtime_tenant`. The login role owns these tables (it created them —
-- nothing else can run migrations), and an owner is exempt from row-level security
-- unless FORCE ROW LEVEL SECURITY is set, **which it deliberately is not**: the worker's
-- claim loop, the scheduler, key rotation and the migration runner itself are
-- cross-tenant by design (`claim_run` is "the only method in this interface that does
-- not take a tenant"), and they run as the owner precisely so that no policy expression,
-- however written, can filter the queue. BYPASSRLS was rejected rather than skipped:
-- only a superuser may grant it, and the deployment shape this exists for — somebody
-- else's managed Postgres — is exactly where no superuser is available.

-- The role. NOLOGIN: it is taken with SET ROLE by a connection that already
-- authenticated as the owner, never presented as a credential of its own.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime_tenant') THEN
        BEGIN
            CREATE ROLE agent_runtime_tenant NOLOGIN;
        EXCEPTION
            WHEN duplicate_object THEN
                -- Two databases in one cluster migrating at the same moment. The
                -- migration lock is per database, so this race is real and losing it
                -- means the role now exists, which is what this file wanted anyway.
                NULL;
            WHEN insufficient_privilege THEN
                RAISE EXCEPTION 'migration 037 must create the agent_runtime_tenant '
                    'role and role % may not (it lacks CREATEROLE). Have an '
                    'administrator run: CREATE ROLE agent_runtime_tenant NOLOGIN; '
                    'GRANT agent_runtime_tenant TO %; then re-run --migrate.',
                    current_user, current_user;
        END;
    END IF;
END $$;

-- Membership, so the serving role can SET ROLE into it. Granted to current_user —
-- the migrating role and the serving role are the same role, because there is one
-- AGENT_RUNTIME_DATABASE_URL and always has been.
--
-- **The requirement is membership, and granting is only the means** — which is not a
-- distinction worth drawing until you meet the case that separates them, and testing
-- found it. A second deployment in a cluster where this role already exists is
-- migrated by a role that did not create it: under PostgreSQL 16's CREATEROLE rules,
-- such a role may not grant a role it does not administer, *even when it is already a
-- member*. An unconditional GRANT therefore refused a database where nothing was
-- wrong — and refused it again after an administrator ran the remedy the refusal
-- named, because the remedy grants membership and the code was testing the right to
-- grant. A refusal whose remedy does not remedy is a dead end, so the membership is
-- checked first and the GRANT is attempted only when it is actually missing.
--
-- **'SET', not 'MEMBER'** — the second PG16 CREATEROLE subtlety in this file, found
-- by step 030's compose artifact, whose bundled database migrates as an ordinary
-- CREATEROLE role (the RDS-master shape). A role that *creates* a role receives an
-- implicit membership row carrying only ADMIN OPTION — no SET, no INHERIT — so
-- pg_has_role(..., 'MEMBER') answers true while SET ROLE is still denied: this block
-- skipped the GRANT and every entry point then refused at its first scoped borrow.
-- What the serving role actually needs is the right to SET ROLE into the tenant
-- role, and 'SET' asks exactly that. The GRANT below works in that case because
-- ADMIN OPTION is precisely the right to grant the role — including to yourself.
DO $$
BEGIN
    IF NOT pg_has_role(current_user, 'agent_runtime_tenant', 'SET') THEN
        BEGIN
            EXECUTE format('GRANT agent_runtime_tenant TO %I', current_user);
        EXCEPTION
            WHEN insufficient_privilege THEN
                RAISE EXCEPTION 'role % is not a member of agent_runtime_tenant and '
                    'may not grant it to itself (that role exists already and was '
                    'created by somebody else). Have an administrator run: GRANT '
                    'agent_runtime_tenant TO %; then re-run --migrate.',
                    current_user, current_user;
        END;
    END IF;
END $$;

-- ## The policy's right-hand side raises rather than filters
--
-- The obvious expression — NULLIF(current_setting('agent_runtime.tenant_id', true), '')
-- — returns NULL when the setting is unbound, and `tenant_id = NULL` filters every row
-- silently. That is the exact failure this step exists to kill: a query that returns
-- zero rows because the connection lost its tenant looks byte-identical to a query that
-- found nothing. So the policy calls a function that RAISES when the role is active and
-- no tenant is bound, naming the seam that should have bound one. Unreachable through
-- `_connection()`, which sets the role and the tenant in a single statement — which
-- makes this sentence the tripwire for the first hand-written path that does not.
-- The wording covers **both** ways a query reaches this function with nothing bound,
-- because testing found the second one and the first sentence libelled it. Policies
-- apply to a role that is a *member* of `agent_runtime_tenant`, not only to one that
-- has `SET ROLE`d into it — so a serving role granted membership but not owning the
-- tables meets this on an ordinary unscoped query, and being told "the role is active"
-- sends it looking in the wrong place.
CREATE FUNCTION agent_runtime_tenant_id() RETURNS text
LANGUAGE plpgsql STABLE AS $$
DECLARE
    bound text;
BEGIN
    bound := current_setting('agent_runtime.tenant_id', true);
    IF bound IS NULL OR bound = '' THEN
        RAISE EXCEPTION 'row-level security is in force for this connection and no '
            'tenant is bound. Connections must be handed out by '
            'PostgresStorage._connection(), which binds agent_runtime.tenant_id and '
            'the role in one statement. If this arrived from an ordinary unscoped '
            'query, the connecting role is a member of agent_runtime_tenant but does '
            'not own these tables — serve as the role that runs migrations.'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN bound;
END;
$$;

-- What the tenant role may do: read and write rows, never DDL (no CREATE on the
-- schema), through whatever the policies leave visible. Sequences are the log tables'
-- identity columns; EXECUTE covers the policy function itself and the partition
-- helpers a scoped session can invoke without table-creation rights anyway.
GRANT USAGE ON SCHEMA public TO agent_runtime_tenant;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO agent_runtime_tenant;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO agent_runtime_tenant;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO agent_runtime_tenant;

-- And the same for every table a *future* migration creates, so from here on tenancy
-- costs a new table exactly one CREATE POLICY line in its own migration — the contract
-- suite's catalog guard fails CI by name when that line is forgotten. Default
-- privileges attach to the creating role, which is the migrating role, which is the
-- only role that ever creates tables here.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO agent_runtime_tenant;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO agent_runtime_tenant;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT EXECUTE ON FUNCTIONS TO agent_runtime_tenant;

-- ## The policies, from the catalog rather than from a list
--
-- Every non-partition table in `public` with a `tenant_id` column — 24 of them today —
-- walked from pg_attribute the way this repo's guard tests walk it, so this file cannot
-- disagree with the schema it runs against (an e2e database, a partially upgraded one,
-- a future one). Partitions are excluded as every catalog walk here excludes them: rows
-- reach a partition through its parent, and the parent's policy governs the query.
--
-- FOR ALL with no separate WITH CHECK, deliberately: the USING expression then also
-- checks new rows, so a scoped INSERT or UPDATE naming another tenant is refused out
-- loud ("new row violates row-level security policy") rather than redirected or
-- silently dropped.
--
-- `tenant_tombstones` is swept up by the walk and that is fine on purpose: a scoped
-- session can see at most its own tombstone, a row that cannot coexist with the tenant
-- being served, so the policy is vacuous there rather than wrong — and a uniform rule
-- beats a third special case the guard test would have to narrate.
DO $$
DECLARE
    t text;
BEGIN
    FOR t IN
        SELECT c.relname
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public'
           AND c.relkind IN ('r', 'p')
           AND NOT c.relispartition
           AND EXISTS (
               SELECT 1
                 FROM pg_attribute a
                WHERE a.attrelid = c.oid
                  AND a.attname = 'tenant_id'
                  AND a.attnum > 0
                  AND NOT a.attisdropped
           )
         ORDER BY c.relname
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I TO agent_runtime_tenant '
            'USING (tenant_id = agent_runtime_tenant_id())', t);
    END LOOP;
END $$;

-- The two tables the walk cannot reach, each decided rather than defaulted.
--
-- `tenants` keys the tenant in `id`, and a scoped session must see its own row:
-- `_require_tenant` reads it on every write path, and a policy that hid it would turn
-- every scoped write into "tenant does not exist".
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenants TO agent_runtime_tenant
    USING (id = agent_runtime_tenant_id());

-- `schema_migrations` gets row-level security **with no policy**: for the tenant role
-- that is default-deny, which is the answer — no scoped session has any business in the
-- ledger, and an empty read there should stay impossible rather than merely unused.
ALTER TABLE schema_migrations ENABLE ROW LEVEL SECURITY;
