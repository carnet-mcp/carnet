-- Access gains a level, and an agent gains an owner.
--
-- Migration 009 made access a boolean: a principal is granted an agent or they are
-- not. That was the whole of what step 005 sketched, and it is not what sharing turns
-- out to mean. Asked what it should feel like, the answer was a Google Doc — type an
-- email, that person has access; give somebody editing access and they can share it
-- on. Boolean access cannot express the second half of either sentence.
--
-- ## A document has two verbs; an agent has three
--
-- A doc is viewed or edited. An agent is viewed (its prompt, its tools, what it may
-- reach), edited (any of that changed) — and **run**, which spends API credits, reaches
-- real systems through the broker, and writes.
--
-- Running is the reason to share an agent at all, and it maps onto neither verb a
-- document has. Copying Docs' names literally would make `viewer` the level that lets
-- somebody spend money and post to GitHub, which is a name that actively misinforms the
-- person choosing it. Same ladder, named for the verbs here:
--
--     user     run it; see its tools and scope
--     editor   ... and edit the config, and share it on
--     owner    ... and delete it, and hand it to somebody else
--
-- Each level contains the one below, so a check is `role >= required` against an
-- ordered ladder rather than a matrix nobody can hold in their head.
--
-- There is deliberately no level that may look but not run. An agent nobody may run is
-- a config file, and reviewing one without using it is a different feature with a
-- different reason.

ALTER TABLE agent_grants
    ADD COLUMN role TEXT NOT NULL DEFAULT 'user'
        CHECK (role IN ('user', 'editor', 'owner'));

-- The DEFAULT exists for the ALTER and for nothing else. No database that matters has
-- a row here yet; if one did, the bottom of the ladder is the right thing to assume,
-- because the alternative is a migration that quietly promotes somebody.

-- Exactly one owner per agent, enforced rather than remembered.
--
-- Ownership as a role on this table rather than a column on `agents` is the load-bearing
-- choice. As a column, ownership and sharing would live in two places: every question
-- worth asking ("who has access?", "what may I run?") becomes a union across them, and
-- a transfer becomes an update here plus a delete-and-insert there — two writes that can
-- disagree, leaving an agent with two owners or none. As a role, `list_agent_grants`
-- already answers the first, `granted_agent_names` already answers the second, and this
-- index makes "one owner" a property of the data instead of a convention in the code.
CREATE UNIQUE INDEX agent_grants_one_owner
    ON agent_grants (tenant_id, agent_name) WHERE role = 'owner';

-- Adoption: every agent that already exists gets an owner.
--
-- `issue-reporter`, `minimal` and `minimal-http` are rows today and `--seed` writes
-- more. None records who made it and none has a grant, so the moment `grants.check` is
-- consulted every one of them is unrunnable by everybody, including whoever created it.
--
-- They are adopted by ('system', 'cli') because that is true: they were created by the
-- CLI, under the CLI's system principal. It is also visibly not a person, so "who owns
-- this?" has an answer that prompts a transfer rather than one that looks settled.
--
-- The friendlier option — grant every agent to every user in its tenant — was rejected.
-- It would write "everyone always had access" into a table whose entire purpose is to
-- record decisions somebody made, and the only thing distinguishing it from forty real
-- grants would be a string in `granted_by`.
-- Two guards, and they defend different constraints. Dropping either one turns this
-- statement from "adopt the orphans" into "fail if anything is already adopted", which
-- is a migration that aborts rather than one that finishes.
--
--   WHERE NOT EXISTS   the partial unique index. Nothing can be an owner at the moment
--                      this first runs — the column did not exist a few lines ago — so
--                      it is unreachable going forward. It is here because a statement
--                      whose safety depends on the order of the file above it is one
--                      that breaks silently when somebody re-runs it by hand, which is
--                      exactly what happens while investigating an incident.
--
--   ON CONFLICT        the primary key. `system:cli` may already hold a *lower* grant on
--                      an agent, granted before roles existed. Left as DO NOTHING that
--                      agent would keep no owner at all, which is the one outcome this
--                      migration exists to prevent — so it is promoted instead.
INSERT INTO agent_grants (
    tenant_id, agent_name, principal_kind, principal_id, role, granted_by
)
SELECT a.tenant_id, a.name, 'system', 'cli', 'owner', 'migration:011'
  FROM agents a
 WHERE NOT EXISTS (
       SELECT 1 FROM agent_grants g
        WHERE g.tenant_id = a.tenant_id
          AND g.agent_name = a.name
          AND g.role = 'owner'
       )
    ON CONFLICT (tenant_id, agent_name, principal_kind, principal_id)
    DO UPDATE SET role = 'owner', granted_by = 'migration:011';
