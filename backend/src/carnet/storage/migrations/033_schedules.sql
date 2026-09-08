-- Scheduling: a machine caller with a clock. Step 022.
--
-- The register's sentence is the whole design -- "a schedule is a machine caller with a
-- clock: it consumes 020's api_tokens and grants, opens no new inbound door." Everything
-- below follows from taking that literally rather than building a second way in.
--
-- ## What a fire is, and what it is not
--
-- A fire is `POST /runs` performed by the platform on a timer, as a `machine` principal
-- that already exists. It is **not** a new kind of authority: the token is checked at
-- every fire exactly as `access/tokens.py` checks it on every request, the grant is
-- checked through `grants.require` exactly as the route checks it, and a refusal is
-- recorded in `access_denials` exactly as a refused curl is. So revoking a token,
-- disabling its owner, unsharing the agent or suspending the tenant each stop the
-- schedule at its next due instant with no rule written twice.
--
-- The consequence worth stating: **this table holds no credential.** A schedule names a
-- token by id; the secret lives nowhere and is never needed, because nothing here
-- presents a credential -- the scheduler constructs the principal in-process from the
-- row it already trusts. A stolen `schedules` row is a piece of configuration.
--
-- ## What bounds the spend, since 020's "a machine can submit at loop speed" row is open
--
-- Three structural bounds rather than a budget, which stays 8d's:
--
--     the cadence vocabulary   the tightest expressible schedule is hourly (SCHEDULE_
--                              CADENCES in storage/base.py). There is no every-N-minutes,
--                              deliberately, and adding one is the door that row warns of
--     no backfill              workers down across ten due instants fire ONCE on recovery
--                              and compute the next from now. An outage is not a bill
--     no overlap               a fire whose previous run is still live is skipped, so an
--                              agent slower than its cadence cannot compound into a queue
--
-- ## The two foreign keys, and why the second one is a key rather than a Python check
--
-- The agent key makes a schedule cascade with its agent, on `agent_grants`' argument:
-- standing configuration naming a deleted agent is not configuration, it is a row that
-- reactivates when somebody reuses the name. A run *names* an agent and survives it; a
-- grant and a schedule *are* about one and do not.
--
-- The token key says **same tenant**, which is the half a single-column FK could not say.
-- Step 021 learnt this at `restored_from`: the plan thought a correlation CHECK sufficed,
-- the edge hunt wrote a row pointing at a version that never existed, and the fix was a
-- real composite key. A schedule firing another customer's token would be the same defect
-- with a blast radius, so it is a key here from the start -- and the UNIQUE index above
-- the table exists only to make that key legal, since `api_tokens` is keyed by `id` alone.

-- **This index must exist before the table below, and that is a fact rather than a
-- preference.** The composite foreign key on (tenant_id, token_id) needs a unique index
-- covering exactly those columns of `api_tokens`, and `api_tokens` is keyed by `id`
-- alone -- so with this statement below the CREATE TABLE, Postgres refuses the whole
-- migration with *"there is no unique constraint matching given keys for referenced
-- table"*. Found by running it, which is the only way this file was ever going to say so.
--
-- It adds no uniqueness the primary key does not already imply: `id` is unique, so
-- `(tenant_id, id)` cannot repeat. It exists purely to make the key legal.
--
-- Named explicitly, on 020's constraint-name lesson: an auto-generated name is one that
-- appears nowhere in this file and that the next migration's `DROP ... IF EXISTS` would
-- silently fail to find. The end-to-end check reads this name and both key names back out
-- of the catalog rather than trusting this comment.
CREATE UNIQUE INDEX api_tokens_tenant_id_id ON api_tokens (tenant_id, id);

CREATE TABLE schedules (
    -- Ours and opaque, on `api_tokens.id`'s reasoning: it lands in log lines and in
    -- every idempotency key this feature writes, so it is never derived from anything a
    -- person can change. `sch_` so it is legible beside `m_` and `u_` without a lookup.
    id            TEXT        PRIMARY KEY,

    tenant_id     TEXT        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    agent_name    TEXT        NOT NULL,

    -- **The machine this fires as.** Not the person who created it: a schedule runs while
    -- its author is asleep, offboarded, or on another team, and a fire carrying a
    -- person's authority would be an authority nobody can revoke without deleting the
    -- person. See the header.
    token_id      TEXT        NOT NULL,

    -- What the agent is asked to do, every time. Redacted from administrative records the
    -- way `default_task` is -- migration 022's rule reaches this column by name, and
    -- `agent_detail`'s AGENT_DETAIL_REDACTED is the precedent: the log records that a
    -- schedule was created and never what it says.
    task          TEXT        NOT NULL CHECK (task <> ''),

    -- {"every":"day","at":"07:30"} | {"every":"week","on":"monday","at":"07:30"} |
    -- {"every":"hour","at":":15"}. JSONB rather than three columns because the shape is a
    -- discriminated union and two of its three arms would be NULL in every row.
    --
    -- Deliberately **no CHECK**, on migration 032's reasoning for `source`: a vocabulary
    -- that grows with the code does not want a migration per value. `check_cadence` in
    -- storage/base.py is where it lives, and both stores call it.
    cadence       JSONB       NOT NULL,

    -- **An IANA name, required, with no default.** The one field a person creating a
    -- schedule must think about, and the reason is that "every morning at 7:30" is a
    -- claim about a wall clock rather than about UTC. A default of UTC would silently
    -- turn that sentence into 3am for whoever typed it -- every day, forever, with
    -- nothing anywhere reading as wrong.
    --
    -- Validated against `zoneinfo` at every write in both stores, never at fire time: a
    -- schedule that cannot compute its next fire is one that fails in a worker loop at
    -- 3am instead of in front of the person who created it.
    timezone      TEXT        NOT NULL CHECK (timezone <> ''),

    enabled       BOOLEAN     NOT NULL DEFAULT true,

    -- **The next instant this is due, in UTC, recomputed after every fire** from the
    -- cadence and the zone -- never by adding 24 hours, which is what would make 07:30
    -- Berlin drift into 06:30 Berlin at the DST transition.
    --
    -- It is also the compare-and-set value the scheduler advances against (10d's
    -- `updated_at` device at a different address) and the instant that goes into the
    -- fire's idempotency key. Those three jobs are one column on purpose: a fire is
    -- identified by which due instant it was for, and a second column naming that would
    -- be a second thing to keep in step.
    next_fire_at  TIMESTAMPTZ NOT NULL,

    last_fired_at TIMESTAMPTZ,

    -- The run the last fire produced, or '' when the last fire produced none. Read by the
    -- overlap check -- a fire is skipped while this run is still live -- so it is load
    -- bearing rather than decorative.
    last_run_id   TEXT        NOT NULL DEFAULT '',

    -- What happened, in a sentence, for the operator reading `--list-schedules`. A fire
    -- that is refused (revoked token, revoked grant, invalid config, suspended tenant)
    -- advances like any other and leaves its refusal here.
    --
    -- **One row deep, and that is the decision.** A per-fire history is a fourth
    -- append-only table with its own retention story, and the fires that produced work
    -- are already in `runs` -- addressable by this schedule's idempotency-key prefix. So
    -- what this holds is the answer to "why is nothing happening", which is the question
    -- that has no other source.
    last_outcome  TEXT        NOT NULL DEFAULT '',

    created_by    TEXT        NOT NULL CHECK (created_by <> ''),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    FOREIGN KEY (tenant_id, agent_name)
        REFERENCES agents (tenant_id, name) ON DELETE CASCADE,

    -- **ON DELETE CASCADE, and it is about the tenant rather than about tokens.** Nothing
    -- deletes an `api_tokens` row -- revocation is a stamp, migration 031 argues it at
    -- length -- so the only DELETE this clause can ever see is the one a tenant deletion
    -- cascades, where the schedule is going anyway through its own tenant key. Written as
    -- CASCADE rather than left to default NO ACTION so that deletion cannot depend on
    -- which of two cascade paths Postgres walks first.
    FOREIGN KEY (tenant_id, token_id)
        REFERENCES api_tokens (tenant_id, id) ON DELETE CASCADE
);

-- The scheduler's only read: "what is due". Partial, because a disabled schedule is never
-- due and indexing one costs a row in the index for every schedule somebody turned off
-- and left. `api_tokens_one_live_name` and `runs_one_live_child` are the same device.
CREATE INDEX schedules_due ON schedules (next_fire_at) WHERE enabled;

-- `--list-schedules` and the per-agent read. A tenant has single-digit schedules today,
-- which is migration 026's argument for adding no index at all -- but this one is not a
-- guess about scale: it is the key the deletion cascade walks and the ordering every
-- listing uses, and both are statements rather than measurements.
CREATE INDEX schedules_by_agent ON schedules (tenant_id, agent_name);
