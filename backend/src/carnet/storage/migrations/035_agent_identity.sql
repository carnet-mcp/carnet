-- An agent gets an identity that is not its name. Step 025, build-order 5b.
--
-- `agents` has been keyed `PRIMARY KEY (tenant_id, name)` since migration 002, and 019
-- wrote down what that costs in the clearest terms this schema has:
--
--     the identity the broker enforces against, per agent_name_matches_config
--     the key the row is stored under            PRIMARY KEY (tenant_id, name)
--     the path segment in GET /agents/{name}
--     the string written into every audit record
--
-- Four jobs, one string. Three of them are about *display and addressing* -- what a
-- person types, reads and bookmarks -- and one is about *identity*, which is the thing
-- that must never change. Binding them together means the display half cannot move
-- without the identity half moving with it, and that is why this system has no rename:
-- `save_agent` is an upsert on the name, so a "rename" writes a second agent and leaves
-- the first behind holding every grant.
--
-- ## What this actually buys, because "namespacing" is the wrong name for it
--
-- The register's row is titled *agent namespace collisions* -- two teams want `triage`,
-- one cannot have it. The tempting fix is hierarchical names, `team-a/triage`, and step
-- 025's plan declines it for three reasons, the shortest of which is that a slash cannot
-- be routed: all nineteen agent routes take a bare `{name}` path parameter, and uvicorn
-- decodes percent-encoding before Starlette routes -- which this codebase already
-- discovered in migration 023's territory and wrote into `api/schemas.py`.
--
-- The reason that matters more is that hierarchy does not cure the disease. The name
-- would still be the key, so the second team's arrival would still be a 409, and moving
-- an existing `triage` into a namespace would still be a rename -- the operation the
-- flat key makes impossible. What actually resolves a collision is that the incumbent
-- can become `support-triage` in one action **and keep everything**: its grants, its
-- pending grants, its version history, its schedules, its triggers, and the run history
-- that names it. That is what this migration is for. The 409 stays, because
-- `UNIQUE (tenant_id, name)` stays -- two agents answering one URL is not a namespace,
-- it is a coin toss -- but the name becomes negotiable.
--
-- ## This decision has been made twice already in this schema, both times the other way
--
-- `users.user_id` is `u_<hex>`, and 010's comment says it is "opaque, and never derived
-- from anything that can change". `groups.group_id` is `g_<hex>`, and migration 017 is
-- explicit about why:
--
--     Never derived from the name: a group that is renamed is the same group, and every
--     grant naming it has to survive the rename untouched.
--
-- Agents were the only long-lived entity in this system still keyed by their display
-- string. `a_<hex>` is the same shape and the same argument, one table over.
--
-- ## Why the child tables lose `agent_name` rather than keeping it beside `agent_id`
--
-- A denormalised name in five tables is a rename that writes five tables, which is the
-- disease with an id column added. So the name goes, the id stays, and the listings that
-- need a name to show a person get one by join. The FIELDS tuples in `storage/base.py`
-- are unchanged by this migration on purpose: `SCHEDULE_FIELDS` still carries
-- `agent_name`, both stores still produce it, and nothing above `storage/` learns a new
-- vocabulary. What changed is where the string comes from -- a column that could drift,
-- now a join that cannot.
--
-- ## What is deliberately NOT re-keyed
--
-- `audit`, `admin_audit` and `access_denials` keep their plain name strings, and `runs`
-- keeps `runs.agent`. Those are records of what happened, and a string that meant
-- something in its moment is better history than an id needing a join to read in a
-- terminal -- 019's own 64-character argument. Identity across a rename stays
-- reconstructable twice over: every audit record carries `run_id` and the run row now
-- carries `agent_id`, and the `agent.rename` admin record is the explicit old-to-new
-- join. Re-keying the append-only partitioned tables would also mean rewriting history
-- to say something it did not say, which is the one thing an append-only log may not do.

-- --- agents grows an identity ------------------------------------------------------

-- Nullable for exactly as long as the backfill below takes. The generated value is the
-- SQL twin of `access/groups.py`'s `f"g_{uuid.uuid4().hex[:16]}"` -- same prefix
-- convention, same 16 hex characters, same uuid4 source. `gen_random_uuid()` is in core
-- Postgres since 13; nothing here needs pgcrypto.
ALTER TABLE agents ADD COLUMN agent_id TEXT;

UPDATE agents
   SET agent_id = 'a_' || substr(replace(gen_random_uuid()::text, '-', ''), 1, 16);

ALTER TABLE agents ALTER COLUMN agent_id SET NOT NULL;

-- The shape rule, matching `AGENT_ID_RE` in storage/base.py. Here for migration 019's
-- reason, restated: a rule that lives only in Python is a rule the next caller skips,
-- and both stores mint these.
ALTER TABLE agents
    ADD CONSTRAINT agent_id_is_opaque
        CHECK (agent_id ~ '^a_[0-9a-f]{16}$');

-- Built as an index rather than a constraint because the five foreign keys below need a
-- unique target *now*, while `agents_pkey` is still `(tenant_id, name)` and still has
-- those five keys pointing at it. It is promoted to the primary key at the bottom of
-- this file, once nothing references the old one.
CREATE UNIQUE INDEX agents_by_id ON agents (tenant_id, agent_id);

-- --- agent_grants (009, 011, 017) ---------------------------------------------------

ALTER TABLE agent_grants ADD COLUMN agent_id TEXT;

UPDATE agent_grants g
   SET agent_id = a.agent_id
  FROM agents a
 WHERE a.tenant_id = g.tenant_id AND a.name = g.agent_name;

ALTER TABLE agent_grants ALTER COLUMN agent_id SET NOT NULL;

ALTER TABLE agent_grants DROP CONSTRAINT agent_grants_tenant_id_agent_name_fkey;
ALTER TABLE agent_grants DROP CONSTRAINT agent_grants_pkey;

ALTER TABLE agent_grants
    ADD CONSTRAINT agent_grants_pkey
        PRIMARY KEY (tenant_id, agent_id, grantee_kind, grantee_id);

-- Named explicitly rather than left to Postgres' convention, because `create_agent`
-- catches a violation of this key by name to tell "that name is taken" apart from every
-- other unique violation, and an auto-generated name is a string this codebase would be
-- reading out of a comment.
ALTER TABLE agent_grants
    ADD CONSTRAINT agent_grants_agent_fkey
        FOREIGN KEY (tenant_id, agent_id)
        REFERENCES agents (tenant_id, agent_id) ON DELETE CASCADE;

-- 011's one-owner rule, re-keyed. Dropped and rebuilt rather than altered: an index
-- cannot change its columns in place, and this one is load-bearing enough that
-- rebuilding it where a reviewer can see the WHERE clause is the point.
--
-- **Dropped before the column, not after.** `DROP COLUMN agent_name` would take this
-- index with it silently -- Postgres removes whatever depends on a dropped column -- and
-- the rebuild below would then be the only thing standing between this table and two
-- owners on one agent. Found by writing them in the other order: the explicit DROP INDEX
-- failed with *"index does not exist"*, which is the loud version of a rule that had
-- already been deleted by a line that never mentioned it.
DROP INDEX agent_grants_one_owner;

ALTER TABLE agent_grants DROP COLUMN agent_name;

CREATE UNIQUE INDEX agent_grants_one_owner
    ON agent_grants (tenant_id, agent_id) WHERE role = 'owner';

-- --- pending_grants (012) -----------------------------------------------------------

ALTER TABLE pending_grants ADD COLUMN agent_id TEXT;

UPDATE pending_grants p
   SET agent_id = a.agent_id
  FROM agents a
 WHERE a.tenant_id = p.tenant_id AND a.name = p.agent_name;

ALTER TABLE pending_grants ALTER COLUMN agent_id SET NOT NULL;

ALTER TABLE pending_grants DROP CONSTRAINT pending_grants_tenant_id_agent_name_fkey;
ALTER TABLE pending_grants DROP CONSTRAINT pending_grants_pkey;

ALTER TABLE pending_grants
    ADD CONSTRAINT pending_grants_pkey PRIMARY KEY (tenant_id, agent_id, email);

ALTER TABLE pending_grants
    ADD CONSTRAINT pending_grants_agent_fkey
        FOREIGN KEY (tenant_id, agent_id)
        REFERENCES agents (tenant_id, agent_id) ON DELETE CASCADE;

ALTER TABLE pending_grants DROP COLUMN agent_name;

-- --- agent_versions (032) -----------------------------------------------------------
--
-- The table this migration is most *for*. Its key was `(tenant_id, agent_name, version)`,
-- which is why 032 had to cascade history with the agent and say so in a comment: a
-- `triage` deleted today and re-created next week would otherwise open a history screen
-- full of the first author's prompts. That cascade stays -- deleting an agent still
-- deletes its history, and now for the honest reason rather than the key's reason -- but
-- a *rename* no longer touches this table at all, which is the whole point.

ALTER TABLE agent_versions ADD COLUMN agent_id TEXT;

UPDATE agent_versions v
   SET agent_id = a.agent_id
  FROM agents a
 WHERE a.tenant_id = v.tenant_id AND a.name = v.agent_name;

ALTER TABLE agent_versions ALTER COLUMN agent_id SET NOT NULL;

-- The self-referential key first: it points at this table's own primary key, so it has
-- to be gone before that key can move.
ALTER TABLE agent_versions
    DROP CONSTRAINT agent_versions_tenant_id_agent_name_restored_from_fkey;
ALTER TABLE agent_versions DROP CONSTRAINT agent_versions_tenant_id_agent_name_fkey;
ALTER TABLE agent_versions DROP CONSTRAINT agent_versions_pkey;

ALTER TABLE agent_versions
    ADD CONSTRAINT agent_versions_pkey PRIMARY KEY (tenant_id, agent_id, version);

ALTER TABLE agent_versions
    ADD CONSTRAINT agent_versions_agent_fkey
        FOREIGN KEY (tenant_id, agent_id)
        REFERENCES agents (tenant_id, agent_id) ON DELETE CASCADE;

-- 032's "a restore names a version that exists", re-keyed and now named on purpose --
-- `RESTORED_FROM_FK` in storage/base.py catches this by name to answer "no such version"
-- instead of `_translate`'s "unknown tenant".
ALTER TABLE agent_versions
    ADD CONSTRAINT agent_versions_restored_from_fkey
        FOREIGN KEY (tenant_id, agent_id, restored_from)
        REFERENCES agent_versions (tenant_id, agent_id, version) ON DELETE CASCADE;

-- **Dropped rather than re-keyed, and that is a decision.** 032's
-- `agent_version_name_matches_config` enforced that a stored config's `name` agreed with
-- the row's key, on 002's reasoning: a row whose key disagreed with its body would offer
-- to restore one agent's configuration onto another. The key is no longer the name, so
-- the constraint no longer describes anything structural -- and after a rename it would
-- be actively false for every version written before it, since those configs record what
-- the agent was called at the time.
--
-- What a version's `config->>'name'` becomes is what it always really was: a snapshot of
-- what the config said when it was written. `agents.restore` normalises it to the live
-- name on the way back out (step 025 decision 7), so restoring Tuesday's prompt cannot
-- also un-rename the agent.
ALTER TABLE agent_versions DROP CONSTRAINT agent_version_name_matches_config;

ALTER TABLE agent_versions DROP COLUMN agent_name;

-- --- schedules (033) and triggers (034) ---------------------------------------------
--
-- The two cheapest, because both are already keyed by their own opaque id and carry the
-- agent as an ordinary column. Their idempotency keys -- `sched:<id>:<due instant>` and
-- `trig:<id>:<sha256>` -- are derived from *those* ids and have never contained a name,
-- so nothing about replay protection moves here.

ALTER TABLE schedules ADD COLUMN agent_id TEXT;

UPDATE schedules s
   SET agent_id = a.agent_id
  FROM agents a
 WHERE a.tenant_id = s.tenant_id AND a.name = s.agent_name;

ALTER TABLE schedules ALTER COLUMN agent_id SET NOT NULL;

ALTER TABLE schedules DROP CONSTRAINT schedules_tenant_id_agent_name_fkey;

ALTER TABLE schedules
    ADD CONSTRAINT schedules_agent_fkey
        FOREIGN KEY (tenant_id, agent_id)
        REFERENCES agents (tenant_id, agent_id) ON DELETE CASCADE;

DROP INDEX schedules_by_agent;
ALTER TABLE schedules DROP COLUMN agent_name;
CREATE INDEX schedules_by_agent ON schedules (tenant_id, agent_id);

ALTER TABLE triggers ADD COLUMN agent_id TEXT;

UPDATE triggers t
   SET agent_id = a.agent_id
  FROM agents a
 WHERE a.tenant_id = t.tenant_id AND a.name = t.agent_name;

ALTER TABLE triggers ALTER COLUMN agent_id SET NOT NULL;

ALTER TABLE triggers DROP CONSTRAINT triggers_tenant_id_agent_name_fkey;

ALTER TABLE triggers
    ADD CONSTRAINT triggers_agent_fkey
        FOREIGN KEY (tenant_id, agent_id)
        REFERENCES agents (tenant_id, agent_id) ON DELETE CASCADE;

DROP INDEX triggers_by_agent;
ALTER TABLE triggers DROP COLUMN agent_name;
CREATE INDEX triggers_by_agent ON triggers (tenant_id, agent_id);

-- --- agents takes its new key -------------------------------------------------------
--
-- Nothing references `agents_pkey` any more, so it can go. `USING INDEX` promotes the
-- index built at the top of this file rather than building a second one.

ALTER TABLE agents DROP CONSTRAINT agents_pkey;
ALTER TABLE agents ADD CONSTRAINT agents_pkey PRIMARY KEY USING INDEX agents_by_id;

-- **The name stays unique per tenant, and this is not a leftover.** It is the URL, the
-- thing a person types on the CLI, and the string every audit record carries. Two agents
-- sharing one address would make `GET /agents/triage` a coin toss, and the collision 409
-- this step is nominally about is the *right* answer to a second `triage` -- what was
-- missing was any way for the first one to move out of the way.
ALTER TABLE agents
    ADD CONSTRAINT agents_name_unique UNIQUE (tenant_id, name);

-- `agent_name_matches_config` from 002 **stays**, unlike its twin on `agent_versions`.
-- The name is no longer the key, but the broker still reads `config->>'name'` as the
-- agent's identity and writes it into every audit record it produces -- so this is still
-- what keeps future audit strings attributed to the row that made them. A rename updates
-- the column and the config together, in one statement, because of this constraint.

-- --- runs learns the id, and keeps the name -----------------------------------------
--
-- **Nullable, and with no foreign key**, which is 015's decision restated rather than
-- reversed: a run is history and must survive its agent, so there is nothing here to
-- cascade and nothing to point at once the agent is gone.
--
-- What it adds is a spine for the four comparisons that used to be made on the name --
-- the worker's config load, run-list visibility, the follow-up turn's parent check, and
-- idempotency conflict detection. Each of those silently changed meaning across a
-- rename, and two of them changed meaning across a delete-and-recreate: a new `triage`
-- inherited the old one's run history because the strings matched.
--
-- `runs.agent` stays exactly as it was, holding the name as submitted. It is the display
-- history and the tombstone -- for a run whose agent has since been deleted it is the
-- only thing left that says what ran.
ALTER TABLE runs ADD COLUMN agent_id TEXT;

UPDATE runs r
   SET agent_id = a.agent_id
  FROM agents a
 WHERE a.tenant_id = r.tenant_id AND a.name = r.agent;

-- Rows left NULL are runs whose agent was already deleted before this migration, and
-- they keep exactly the behaviour they have today: visible to whoever submitted them,
-- matched by no agent, resolvable by nothing. Nothing new can be asserted about them and
-- nothing tries to.
CREATE INDEX runs_by_agent ON runs (tenant_id, agent_id) WHERE agent_id IS NOT NULL;
