-- Config version history: what the prompt said yesterday. Step 021.
--
-- `agents.config` is overwritten in place by all three of its writers, so an edit
-- destroys the configuration it replaces and nothing anywhere keeps a copy. That makes
-- this the register's only *irrecoverable* row: every other deferred item costs the same
-- in three months, and this one costs a version per edit until it exists.
--
-- ## Why the log could not have held it
--
-- Migration 022 forbids it by name -- "no agent system prompt ... the one somebody will
-- add" -- and `agent_detail` in storage/base.py implements that refusal, emitting field
-- *names*, tools and scope so "somebody changed the model" is answerable and "what did
-- the prompt say" is not. That rule is unchanged by this migration and stays unchanged.
--
-- It is also the wrong table on its own terms. Since 019 the three log tables are
-- monthly partitions and retention is a partition drop, so a history kept there would
-- evaporate at the window: a feature that deletes the thing it exists to keep.
--
-- So two tables answering two questions. `admin_audit` records **every write** -- who,
-- when, which fields -- and is pruned. `agent_versions` records **every distinct state**
-- and lives exactly as long as the agent.
--
-- ## Not "a table kept forever", which is the objection this answers
--
-- `agent_detail`'s docstring pre-refused the lazy version of this step: a copy of the
-- prompt "in a table kept forever". The foreign key below is the answer. Versions
-- cascade with the agent, `agents.tenant_id` already cascades with the tenant, so a
-- delete still deletes and 018's erasure story gains no obstacle -- `agents` is absent
-- from TENANT_BLOCKING_TABLES for exactly this reason and this table joins it there.
--
-- The cost of that cascade, stated because it is a real one: deleting an agent deletes
-- its history. The alternative -- keep the rows, on the precedent that a run survives
-- its agent -- is worse here, because the primary key is (tenant_id, name). A `triage`
-- deleted today and re-created next week by somebody else would open a history screen
-- full of the first author's prompts. A run *names* an agent; a version *is* one.

-- The live version number. Every config write that changes something advances it, and
-- the version row it writes takes the new value, so `agents.version` always names a row
-- in `agent_versions` and the newest one always holds what `agents.config` holds.
--
-- A counter rather than a sequence, and per agent rather than global, because the row
-- this column sits on is the serialization point: every writer of one agent takes its
-- lock, so `version + 1` read off the locked row cannot collide. That is a claim about
-- concurrency rather than a comment, and the suite measures it with eight threads.
--
-- DEFAULT 1 is what makes the backfill below honest for existing rows: they have one
-- version, and it is the one they are holding.
ALTER TABLE agents ADD COLUMN version INTEGER NOT NULL DEFAULT 1;

CREATE TABLE agent_versions (
    tenant_id     TEXT        NOT NULL,
    agent_name    TEXT        NOT NULL,
    version       INTEGER     NOT NULL,
    config        JSONB       NOT NULL,

    -- **No DEFAULT now(), deliberately.** This is the `updated_at` the same statement
    -- assigned to the agent row, passed in rather than generated again, so a version's
    -- timestamp is exactly the instant that configuration became live. A second now()
    -- would be equal in Postgres (one transaction timestamp) and *not* equal in the
    -- in-memory store, which is drift in the direction nobody notices.
    --
    -- **What this does NOT mean, stated because the first draft of this comment said it
    -- did:** an ETag does not name a version. A save that changes nothing advances
    -- `agents.updated_at` and writes no version row, so a live agent's ETag is routinely
    -- newer than any timestamp in its history. The interval reading survives — version N
    -- was live from its `created_at` until N+1's — and that is the one to rely on.
    created_at    TIMESTAMPTZ NOT NULL,

    -- The actor string the write already carried: `user:u_...` from a route,
    -- `system:cli` from --seed, the owner from a create, `migration:032` below. Not a
    -- foreign key to `users`, on 006's precedent -- a grant survives its granter, and
    -- so must the record of who wrote a config.
    created_by    TEXT        NOT NULL,

    -- create | save | update | restore | migration. Deliberately **not** a CHECK, on
    -- migration 022's reasoning for ADMIN_ACTIONS: a vocabulary that grows with the
    -- code does not want a migration per value. VERSION_SOURCES in storage/base.py is
    -- where it lives, and both stores validate against it.
    source        TEXT        NOT NULL,

    -- Set exactly when `source` is 'restore'. A restore is a *new* version whose
    -- content is an old one -- never a pointer moving backwards -- so the timeline
    -- stays monotonic, "what was live on Tuesday" stays an interval lookup rather than
    -- a replay of pointer moves, and a bad restore is itself restorable.
    restored_from INTEGER     NULL,

    -- The read is always "this agent's versions, newest first", which this serves. No
    -- second index: there is no other question anybody asks of this table.
    PRIMARY KEY (tenant_id, agent_name, version),

    FOREIGN KEY (tenant_id, agent_name)
        REFERENCES agents (tenant_id, name) ON DELETE CASCADE,

    -- **A restore names a version that exists**, enforced rather than assumed. Found by
    -- the edge hunt: `update_agent` is a public storage method and it accepted
    -- `restored_from=99` and `restored_from=-5` happily, writing a row pointing at a
    -- version that never was. Unreachable through `agents.restore`, which reads the
    -- version first — and `check_prune_batch`'s rule applies: the next caller will not
    -- know that.
    --
    -- Self-referential, so it costs no second table, and NULL skips it — which is every
    -- row that is not a restore. Nothing cascades from it that the agent-level cascade
    -- above does not already take.
    FOREIGN KEY (tenant_id, agent_name, restored_from)
        REFERENCES agent_versions (tenant_id, agent_name, version) ON DELETE CASCADE,

    -- 002's constraint, one table over, for the same reason: the config carries the
    -- agent's identity and a row whose key disagreed with its body would offer to
    -- restore one agent's configuration onto another.
    -- `IS NOT DISTINCT FROM` rather than `=`, and the difference is a config with **no**
    -- name at all: `config->>'name'` is then NULL, `NULL = 'triage'` is unknown, and a
    -- CHECK accepts everything it cannot call false. So the obvious spelling admits
    -- exactly the row this constraint exists to refuse — one whose body does not say
    -- which agent it is. (002's own version of this constraint has the same hole; it is
    -- not this migration's to change, and it is worth knowing about.)
    CONSTRAINT agent_version_name_matches_config
        CHECK (config->>'name' IS NOT DISTINCT FROM agent_name),

    CONSTRAINT agent_version_is_positive CHECK (version >= 1),

    -- Both directions. A restore with no source is a record that cannot say what it
    -- restored; a `restored_from` on an ordinary edit is a claim nobody made.
    CONSTRAINT agent_version_restore_names_one
        CHECK ((restored_from IS NOT NULL) = (source = 'restore'))
);

-- **Refuse a corrupt row with a sentence naming it, before the backfill trips on it.**
--
-- Found by running this migration against a database holding an agent whose config has
-- no `name` key. 002's CHECK is `config->>'name' = name`, and NULL = 'x' is unknown, so
-- such a row is *representable* — every application path refuses it in Python
-- (`check_agent_name`), but hand-run SQL does not go through Python. The backfill below
-- would then violate this table's stricter CHECK, and the whole migration would fail
-- with a bare constraint error naming no row: a blocked upgrade whose operator has to
-- reverse-engineer which of ten thousand agents is the bad one.
--
-- Migration 031's precedent: a DO block that fails the migration *with the answer in
-- the message*. The transaction still rolls back either way; the difference is between
-- an error that says which rows to fix and one that says only that something is wrong.
DO $$
DECLARE
    bad TEXT;
BEGIN
    SELECT string_agg(format('%I.%I', tenant_id, name), ', ')
      INTO bad
      FROM agents
     WHERE config->>'name' IS DISTINCT FROM name;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION USING MESSAGE = format(
            'migration 032 refuses to run: %s hold(s) a config whose name does not '
            'match its row — only hand-written SQL can produce this state, and the '
            'version history would misattribute every configuration it copied. Fix the '
            'row(s), then re-run.', bad);
    END IF;
END $$;

-- Version 1 for every agent that already exists.
--
-- **Said plainly, because a backfill that looks like history is worse than none: this
-- is the config as of the migration, not as first written.** Every edit before this
-- point is gone and nothing here recovers it.
--
-- What it does assert is only what it can know. `updated_at` is exactly when this
-- configuration became live, which is what the column means. `migration:032` is the
-- author, on the precedent of `granted_by = 'migration:011'` on every agent that
-- migration adopted -- a sentinel that reads as one, rather than a person who did not
-- do it. Compare 015, which deliberately did *not* backfill runs, because a backfill
-- there would have had to assert a status nobody ever recorded.
INSERT INTO agent_versions (
    tenant_id, agent_name, version, config, created_at, created_by, source
)
SELECT tenant_id, name, 1, config, updated_at, 'migration:032', 'migration'
  FROM agents;
