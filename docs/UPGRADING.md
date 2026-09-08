# Upgrading

This is the contract between a release of Carnet and the database it runs
against. It exists because the tables may not be ours: when this runs in your cloud,
against your Postgres, the numbered migrations stop being an internal convenience and
become something you are entitled to rely on.

Everything below is enforced by code or asserted by CI. Where it is neither, it says so.

---

## Requirements

**PostgreSQL 16 or later.** `--migrate` checks the server version before it does
anything and refuses an older one by name.

Sixteen is what continuous integration actually runs against. The oldest version whose
*features* we use is 15 — migration `007_tenant_idps.sql` needs `UNIQUE NULLS NOT
DISTINCT` — but nothing tests 15, and a version nothing runs against is a guess with a
number on it. If you need 15, say so and it becomes a tested configuration or a
documented refusal; it will not be left ambiguous.

**A dedicated database.** Not a dedicated *server* — one database, holding nothing else.

Migrations create their tables unqualified, so they land in whatever `search_path`
resolves to, which is `public`. Pointed at a database that already holds something, this
runtime would share a namespace with it, and two schemas that have never heard of each
other would eventually collide over a table name.

The runner refuses rather than warns: if the database contains tables and has no
migration ledger, `--migrate` stops and tells you to create an empty one. A refusal
writes nothing — not even the ledger table — so pointing it at the wrong database costs
you nothing but the error message.

We considered putting everything in a named schema instead. It was declined: it is a
migration over every table plus a `search_path` on every pooled connection, to buy
collision *avoidance*, where `CREATE DATABASE carnet` buys collision
*impossibility* in one line.

---

## Migration 037: row-level security, and the one thing it touches outside your database

From 0.5.0 the database itself enforces tenant isolation: every table carries a policy,
and the server takes a restricted role (`agent_runtime_tenant`) with the tenant bound in
a session setting whenever it serves an authenticated request. Three things about that
are yours to know rather than ours to assume:

**It creates a role, which is cluster-global.** Migration 037 is the only migration that
touches anything outside the database it runs in. Creating a role needs `CREATEROLE`,
**once per cluster**. If the role you migrate with does not have it, the migration
refuses with the two statements an administrator can run instead:

```
CREATE ROLE agent_runtime_tenant NOLOGIN;
GRANT agent_runtime_tenant TO <your migrating role>;
```

then re-run `carnet --migrate`. The refusal rolls back whole, like any other
migration failure. The role is `NOLOGIN` — it is never a credential, only something the
server's own connections switch into — and two of our databases in one cluster share it
harmlessly, because everything it may touch is granted per database.

**A second deployment in the same cluster needs only the `GRANT`.** The role already
exists, so nothing has to create it; what your second deployment's role needs is
*membership*. If it did not create the role it cannot grant itself membership, and the
migration says so and names the one line an administrator runs. Once that is done,
`--migrate` proceeds — the requirement is membership, not the right to grant it.

**Which database has been migrated is not answered by the role.** Because the role is
cluster-global, a database that has never seen migration 037 sits in a cluster where the
role already exists. The startup check therefore asks a database-local question (does
this database have the policy function?), and its refusal says to run `--migrate`.

**Serve with the role that migrates.** The policies exempt the tables' *owner* — that is
what keeps the deliberately cross-tenant sweeps (key rotation, retention) working
unchanged, and it works for an ordinary role: ownership is the exemption, not superuser
status.

If you migrate as one role and serve as another, the serving role is not the owner and
row-level security default-denies it everything. **Every entry point refuses to start**
— the server and the CLI alike — with a sentence naming this. That refusal is the
important part: without it a server reads *nothing at all* and looks healthy doing it,
because a query denied by a policy returns zero rows rather than an error.
`--migrate` is deliberately exempt, since it runs before the store is configured; that
is what lets an un-migrated database be brought up to date.

**No `BYPASSRLS`, anywhere, on purpose.** Only a superuser may grant it, and on managed
Postgres (RDS, Cloud SQL) you do not have one. Nothing in this runtime needs it: the
owner exemption above is the whole bypass, and it is something you already have.

---

## The promise

**Forward-only.** There is no `down`. A migration that turns out to be wrong is
corrected by a new numbered migration, never by editing or reversing the old one.

**Never renumbered.** A migration's number is its name, and the ledger in your database
is keyed by it. CI asserts the numbering is contiguous from 001, unique, and
zero-padded — the padding is what makes alphabetical order and numerical order the same
order, which the runner depends on.

**One ledger, and it may name more than one series.** `NNN_name.sql` is the *core*
series and it has exactly one author, which is Carnet itself. A separately installed
distribution may add its own migrations under its own prefix — `ee_NNN_name.sql` — and
they are recorded in the same `schema_migrations` table, because that table is the
answer to *what has been applied to this database* and two answers to that is worse than
one. The consequence for you is one sentence: **your ledger may contain rows a given
build does not recognise, and that is not an error.** A build refuses a version it is
*behind on within a series it ships*; it has no opinion about a series it does not ship.
`--migrate` says so when it finds such rows.

**Never edited once released.** Every applied migration's SHA-256 is recorded in your
database when it runs. Every later run re-checks it, and a file that has changed since
it was applied stops the upgrade and names itself. This matters because an edited
migration makes one version number mean two different schemas, and nothing downstream can
tell which one it is looking at afterwards.

**Upgrade from any released version, in one command.** However many releases behind you
are, `carnet --migrate` brings you to current. There is no stepping stone, no
"upgrade to 0.4 first". CI proves this on every change — see *What CI checks*.

**Each migration is atomic.** One transaction per file, with the ledger row written
inside that same transaction. A migration that fails leaves *nothing* behind: not a
half-applied schema, and not a ledger row claiming it ran. You are cleanly at a known
version, which is what makes the recovery below "fix it and run it again" rather than
"restore from backup".

**Your rows survive.** Every migration that rewrites a table is exercised in CI against
tables already full of data, and the rows are compared before and after — by value, with
their identifiers, not by counting them.

---

## Upgrading

### 1. Back up, and verify the backup restores

```
pg_dump --format=custom --file=carnet-$(date +%F).dump "$CARNET_DATABASE_URL"
```

**Restore it somewhere before you continue.** A backup that has never been restored is a
file, not a backup.

```
createdb carnet_restore_test
pg_restore --dbname=carnet_restore_test carnet-$(date +%F).dump
```

One known wrinkle worth checking on your version: `audit`, `admin_audit` and
`access_denials` are partitioned tables with identity columns, and `pg_dump`'s handling
of identity columns on a partitioned parent is only fully blessed in PostgreSQL 17. On
16 the restore above is the check that it worked for you.

### 2. Stop the writers

Stop every server. Migrations take locks, and a writer holding a
transaction open across one turns a fast migration into a queue — see *Lock time*.

If you cannot stop everything — a rolling deploy where several replicas start together
and each runs `--migrate` — that is safe: they take a lock, one does the work, and the
rest wait and then find nothing to do. Waiting is deliberate, so a replica never starts
against a half-migrated schema. It does mean a replica's start-up can block for as long
as the migration takes, which is the number in *Lock time*.

### 3. Migrate

```
carnet --migrate
```

Under the compose deployment (`deploy/`), steps 2–4 are `docker compose up -d
--build`: the `migrate` service is a one-shot job the API waits on, so
the ordering this section asks of an operator is enforced by the dependency graph.

It prints each migration as it lands, with how long it took:

```
  [migrate] applied 030_partition_log_tables in 5.77s
  [migrate] applied 031_api_tokens in 0.06s
```

Running it when there is nothing to do is safe and is how you check where you are:
it prints `Already up to date.`

### 4. Start, and confirm

```
curl -s localhost:8000/health
{"status":"ok","storage":"configured","version":"0.3.0"}
```

`carnet --version` answers the same question from a shell.

### 5. Settings a release added, which no migration can supply

**A release can require a new setting, and a database check will never tell you.**
Everything above verifies the schema; a deployment can pass all of it, report healthy,
and still be unusable because a new variable is unset. That is not hypothetical — it is
how 0.6.0 shipped a stack nobody could sign in to — so a release that adds a required
setting names it here, and this is the list.

**Step 086 — no setting, and one thing to re-vet if you want it.**
Nothing is required and no migration lands. Two capabilities arrive on the *approval* of
a tool rather than in the environment:

- **A scope line can name a model family** — `{"anthropic.model": {"write": ["haiku"]}}`
  admits every haiku id the vendor ships, including the one dated after you wrote the
  policy. **A tool vetted before this release declares no families**, so a family scope
  against it matches nothing and refuses — which is the state it is in today, and is
  deliberate: defaulting a vocabulary onto stored rows would widen a policy by upgrading.
  Vet the tool again with `--resource-family anthropic.model=opus,sonnet,haiku`, or
  re-apply the shipped recipe, which now carries its vendor's families. Every scope
  naming an exact id or `*` keeps meaning exactly what it meant.
- **A price can live on the connector's binding** — `--pricing '{"gpt-5": {...}}'` at vet
  time, in USD per million tokens, keyed as `CARNET_MODEL_RATES` is keyed. It fills in
  under `CARNET_MODEL_RATES`, which still replaces the built-in table entirely and still
  wins where both name a model. With neither set, an unpriced model is still *named* as
  unpriced rather than counted as free.

**Step 083 — one defaulted setting, and one rule for a custom ingress.**
`CARNET_OAUTH_TOKEN_DAYS` (default 30, `0` for no expiry) is how long a token minted by
an MCP client's OAuth consent lives; the flow issues no refresh token, so an expiry is a
re-consent, which for a person still signed in at their provider is one click. Nothing
needs setting. **If your ingress is not the shipped Caddyfile**, add one rule: forward
`/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server` to
the API **with the path intact** — RFC 9728 and RFC 8414 put those documents at the origin
root, not under `/api`, and an SPA fallback would answer them with `index.html` and a 200,
which an MCP client reports as a JSON parse error about a server that is plainly up. The
shipped Caddyfile, the Vite dev proxy and `--local` all carry the rule. Every URL in those
documents derives from `CARNET_PUBLIC_ORIGIN`, so a value that is wrong for the connector
callback is now wrong for three documents as well.

**Step 078 — settings that are no longer read, and one that never needs setting.**
The runtime left the tree, and with it every setting it read: `CARNET_BENCH`,
`CARNET_WORKERS`, `CARNET_RUN_LEASE`, `CARNET_RUN_HEARTBEAT`,
`CARNET_RUN_DEADLINE`, `CARNET_WORKER_POLL`, `CARNET_SCHEDULER_POLL`,
`CARNET_RUN_WAIT_MAX`, `CARNET_RUN_WAIT_TICK`, `CARNET_RUN_WAIT_SLOTS`,
`CARNET_RUNS_PER_HOUR`, `CARNET_USER_USD_PER_DAY`, `CARNET_USER_TOKENS_PER_DAY`,
`CARNET_MAX_CONVERSATION_TURNS`, `CARNET_MAX_DELIVERY_BYTES`,
`CARNET_BLOCKED_FILE_TYPES` and `CARNET_SCIM_MAX_BODY_BYTES`. A value left in your
environment is ignored, not refused. **`ANTHROPIC_API_KEY` is no longer read at all**: a
brokered model call spends under its connector's own credential, and there is no
platform model key. Remove it from the deployment's environment; nothing needs it.

**`CARNET_VAULT_*` — optional, and nothing changes until you set it (070).**
A connector's shared credential may now be a location in your own 1Password vault
(`--credential-ref 'op://Engineering/Jira/credential'`) rather than a variable this
deployment holds. **No migration and no default behaviour changes**: with these unset,
every existing connector keeps working exactly as it did, and a connector that names a
reference refuses at its first call with a sentence saying which two variables are missing.

- **`CARNET_VAULT_URL`** and **`CARNET_VAULT_TOKEN`** — a 1Password Connect endpoint
  and a service-account token. Both are needed or neither does anything.
  **`CARNET_VAULT_TIMEOUT_SECONDS`** (default 3) is a budget for resolving one reference
  across every hop it takes, not a per-request timeout.
- **What it buys, and the sentence to give a security questionnaire**: the secret is not at
  rest in our database, and its lifetime in our process is one call. Not *we cannot read
  it* — the service-account token opens every item behind every reference, which is true of
  any vault integration that resolves at request time.
- **What it costs**: one to three requests to your vault on every call, no cache, and a
  connector that stops working while your vault is down. Write references with 1Password
  **ids** rather than names on a hot path — an id costs one request and a name costs three.
- If your vault is on your own network, its host also belongs in
  `CARNET_EGRESS_INTERNAL_HOSTS`.

**Group claims — membership from your directory (033e).**
Nothing about an existing deployment changes: migration 043 adds three nullable
columns (`tenant_idps.groups_claim`, `users.directory_digest`,
`users.directory_synced_at`) with no defaults and no backfill, and until an identity
provider is given a `groups_claim` **group membership works exactly as it does
today** — `--group-add` and the group screen are the only things that change it. What
is new, once you configure it:

- **`--add-idp … --groups-claim CLAIM`** names the claim your provider puts groups in
  (Entra emits object ids in `groups`; Okta emits names, under whatever the
  authorization server calls it). `--add-idp` is an upsert, so it now prints the claim
  mapping it wrote — re-running it without `--groups-claim` clears the claim, the same
  way it already clears `--domain`, and the printed line is where you see that.
- **`--group-link GROUP DIRECTORY_ID`** hands a group's membership to the directory:
  from then on its members are whoever the claim names, applied at each person's next
  sign-in. The command prints how many people are in it now, because any the directory
  does not name are removed as they sign in. **`--group-unlink GROUP`** stops that and
  removes nobody. Both are on the group screen too, and `PATCH /groups/{id}` is the
  route.
- **A linked group's people are the directory's**: adding or removing a *person* by
  hand is refused with a sentence naming the group's directory id, because the next
  sign-in would undo it. `system` and `machine` members are unaffected — the
  reconciliation only ever writes the row of the person signing in.
- **A claim value that matches no group creates nothing.** You create the group and
  stamp its directory id; unmatched values are logged so you can see what your
  directory is offering. A group with no directory id is never touched.
- **What this is not**: offboarding. Membership changes when somebody next signs in
  with a token carrying the new claim, so a person removed from a group in your
  directory keeps what it gave them until then — as they do today, and SCIM is still
  the answer for the leaver path. Disabling an account still cuts it off at the next
  request, unchanged.
- **A token that withholds the claim is not a token that says "no groups"**: Entra
  omits `groups` when somebody is in more groups than a token may carry and says so in
  `_claim_names`. That case changes nothing and is logged as an error — filter the
  claim at the provider (Entra can emit only the groups assigned to this application).
  A claim carrying more than 200 values, or one longer than 256 characters, is refused
  whole for the same reason: a partial membership would be a removal.

**Personal tokens — a machine token that resolves its owner's access (033d).**
Nothing about an existing deployment changes: migration 042 adds one column
(`api_tokens.acts_as_owner`, default false) and false is precisely true of every
token already minted — all of them keep 020's behaviour exactly. What is new:

- **`--mint-token NAME WHO --as-owner` mints a personal token**: its access is its
  owner's — the owner's grants and group memberships, capped at `user` like every
  machine — live as the owner's access changes, and gone at the next request when
  the owner is disabled. It is Priya's-editor shape: no admin grant needed before it
  can see a tool, because the owner's access is the grant.
- **A personal token may hold no access of its own.** Sharing an agent with one, or
  adding one to a group, is refused with a sentence naming the owner — a grant of
  its own could hand it something its owner does not have. Service tokens (the
  default, and every existing token) are untouched: grant them directly or through
  groups exactly as before.
- **It is still a machine principal**: audited as `machine:<id>`, never an
  administrator anywhere (even when its owner is one), still bounded by
  `CARNET_MCP_CALLS_PER_DAY` per token. Whose token wrote a record is derived from
  the `api_tokens` row (`--list-tokens` shows kind and owner); nothing new is stored
  per record.
- **Tools vetted `identity: user` act as the owner's connected account** when called
  through a personal token — the account the owner connected in their browser, with
  no second credential to paste. An acting-for on the call (033c) still takes
  precedence; the two compose.

**Acting-for — a shared service can now say whom a door call is for (033c).**
Nothing about an existing deployment changes: the new request field is optional, the
new setting is defaulted, and both new columns default to exactly what was true of
every existing row. What is new:

- **A `tools/call` through the MCP door may carry an acting-for identity** — one key,
  `com.carnet/acting-for`, in the call's `_meta`, per call. Two forms, and the audit
  log never collapses them: **verified** (`{"token": …}` — the person's own IdP token,
  forwarded, and checked against the same registered identity provider browser logins
  are; nothing is trusted) and **asserted** (`{"email": …}` — believed, only where a
  connector opts in). This is what makes `identity: user` tools usable through the
  door: the call resolves *that person's* connected account, the vendor enforces what
  they may see, and a person with no connection is refused naming the one to make.
  Acting-for changes **whose account and what the log says, never authorization** —
  the token's grants still bound what may be called, and the token's daily ceiling is
  still the one that spends.
- **`allow_asserted_identity`, per connector, default off.** The resting posture is
  *verified or nothing*; a tenant that wants the cheaper path turns it on per
  connector (`carnet --set-asserted-identity <connector> on`, or the connector
  screen) and the administrative log records who and when. An asserted identity is
  exactly as honest as the calling application — enable it only for callers you
  would give a shared credential to.
- **The audit record gains `acting_for` and `identity_source`**
  (`verified` | `asserted` | `none`) on every brokered call, denials included. Rows
  written before this release read `none`, which is precisely true of them.
- **`CARNET_MCP_MAX_ACTING_FOR_BYTES`, default 16384**, bounds the acting-for value
  the way `CARNET_MCP_MAX_CALL_BYTES` bounds arguments — it rides beside them in
  `_meta`, so it needs its own bound. 16 KiB clears any real IdP token (Entra tokens
  with group claims run to several KB); raise it only if yours genuinely exceed that.

A verified acting-for names a person who has **signed in at least once** — a tool
call creates nobody — and forwards a token from the same provider registered with
`--add-idp`. Migration 041 adds the connector flag and the two audit columns, and
applies like any other.

**The MCP door — a new route, and one new setting that is defaulted (033b).** This
release serves an MCP endpoint at `POST /mcp`, so a machine token can be pasted into
Cursor or your own agent's MCP client and reach the tools it is granted through the
broker — and, since step 083, a client that speaks OAuth (Claude Desktop, Claude.ai,
Cursor) connects with the URL alone and ends up holding the same kind of token, minted
after the person signs in and approves. **Nothing about an existing deployment changes**: no route was
altered, no default moved, and a deployment that never points a client at `/mcp` behaves
exactly as it did.

Four things worth knowing before you point one at it:

- **It authenticates with a machine token** (`carnet --mint-token <name>`), in the
  `Authorization` header and never in the URL. A person's sign-in token is refused with
  a 403 naming that command — it would expire within the hour, so a client configured
  with one works this afternoon and fails tomorrow.
- **What it advertises is the grant list**, nothing more: the union of the tools of the
  agents that token is granted, each keeping its own agent's scope. Revoking a grant
  removes the tool at the client's next `tools/list`, and revoking the token closes it
  entirely. There is deliberately no separate "expose over MCP" switch to drift out of
  step with your grants.
- **`CARNET_MCP_CALLS_PER_DAY`, default 1000**, bounds what one token may call through
  the door in a UTC day. It is counted in Postgres rather than in the server process, so
  it is the same ceiling however many API replicas you run; `0` disables it. Every call
  through the door is audited exactly like any other brokered call.
- **`CARNET_MCP_MAX_CALL_BYTES`, default 65536**, bounds the arguments one call may
  carry. Worth knowing because it is *not* redundant with the ceiling above: a call the
  broker denies spends no budget — deliberately, so an agent fixing its own scope
  mistakes cannot exhaust its day — and still records its arguments in the append-only
  audit log. This is what limits how much an authenticated caller can put in that table.
  Raise it only if a legitimate tool genuinely takes arguments that large.
- **Tools vetted `identity: user` need the call to say whose account** — either the
  token's own connected account, or an acting-for identity on the call (033c, above).
  A call that names nobody with a connection is *refused* naming the connection to
  make — never quietly served from the shared credential.

Migration 040 adds one table (`mcp_budget`) and widens one CHECK
(`access_denials.resource_kind` now also admits `tool`, so a door refusal can be
recorded), and applies like any other.

**Whose account a vetted tool acts as is now part of the vetting (033a).** Each vetted
tool carries an `identity` — `service` (the connector's shared credential, always; a
caller's connected account is never consulted) or `user` (the caller's own connected
account, always; refused with the connection to make when they have none). The old
behaviour — try the caller's connection, fall back to the shared credential — is
retired, because which account a call went out as depended on whether the caller
happened to have connected one, a condition nobody stated at approval time. **A tool
vetted before this release reads as `service`.** If people in your tenant relied on
their own connected accounts through a tool, re-vet it with identity `user`
(`--vet <connector> --tool <name> --identity user`); until then their calls use the
shared credential and the audit rows say `shared`. Migration 039 adds the column
(`vetted_tools.identity`, default `service`) and applies like any other.

**The renames — this package has been called three things.** `agent-runtime` became
`shipyard` at 0.8.0, and `shipyard` became **`carnet`** in the release this document now
describes. Each time the pip name, the CLI command, every import and the whole
environment prefix moved together in one release, with no dual-prefix transition: nothing
was deployed at either rename, so both breaks are clean.

**A retired variable is refused at startup**, never silently ignored — both
`AGENT_RUNTIME_*` and `SHIPYARD_*` raise on the way up, naming every offending variable
and its `CARNET_*` replacement. Rename them in your environment and start again. A prefix
that was quietly skipped instead would be a deployment losing its configuration without
saying so, which is the failure this whole document exists to prevent.

**The identifiers migrations created inside the database keep the oldest name**, because
migrations are never edited once released: the `agent_runtime_tenant` role and the
`agent_runtime.tenant_id` session variable (037), and the `agent_runtime.retention`
session variable (029). They are two renames stale and they are correct — a role name is
not a brand, and changing one would move a checksum and refuse your database.

**0.8.0 — the run wait.** Three settings arrived with it and left again in step 078;
see the 078 entry above. Migration 038 (one nullable column on `runs`) applies like any
other and is now a column nothing reads.

**0.7.0 — the identity provider the browser talks to.** Two new variables in
`deploy/.env`, and without them **the deployment comes up healthy and no person can
sign in**:

```
CARNET_OIDC_ISSUER=https://your-issuer.example.com
CARNET_OIDC_CLIENT_ID=your-spa-client-id
```

The issuer must be **the same string** you gave `--add-idp --issuer`: one is how the
API verifies a token, the other is how the browser obtains one, and a deployment where
they disagree fails at sign-in rather than at boot. Google-shaped providers, whose
token endpoint is on a second origin, additionally need
`CARNET_OIDC_EXTRA_ORIGINS=https://oauth2.googleapis.com` —
`deploy/.env.example` documents both. Setting them is `docker compose up -d front`:
the front door composes its config and its Content-Security-Policy at container
start, so a changed value needs the container recreated, not just the file saved.

Nothing here is a database change, so `--migrate` neither checks it nor can. What
does check it is `GET /config.json` on the running deployment: it answers
`application/json` naming your issuer when this is right, and **404** when it is not.

---

## When a migration fails

**You are at a known version, and the database is consistent.** The failed migration
rolled back whole. Nothing is half-applied.

1. **Read the error.** It names the migration, and where the cause is a row rather than
   the schema, it names the row. A migration that refuses because your data does not fit
   the new shape is telling you about a decision only you can make.
2. **Fix what it named**, then run `carnet --migrate` again. Everything that
   already applied is skipped; it resumes at the one that failed.
3. **Restore is the fallback, not the first move.** It costs you every write since the
   dump, and the failure mode above does not require it.

There are no down migrations. If you need one, that is a conversation — the register
tracks it, triggered by exactly this: the first failed production migration.

### Refusals that are not migration failures

These stop the run before any migration executes, and none of them change anything:

| What it says | What happened | What to do |
| --- | --- | --- |
| requires PostgreSQL 16 or later | The server is older than the floor | Upgrade the server |
| already contains tables … not ours to migrate | Pointed at a shared or wrong database | Point at a dedicated, empty database |
| database is ahead of this checkout | The database was migrated by a **newer** build than the one you are running, in a series this build ships | Deploy the newer version; migrations are forward-only |
| migration series … collides / is not a directory | An installed distribution registered a migration series this one cannot place | Report it to whoever ships that distribution; nothing was applied |
| migration NNN has changed since it was applied | A released migration file was edited | Restore the released file, or make the change a new migration |

---

## Lock time

Migrations that rewrite whole tables are the ones worth planning around. CI measures
this on every run, over deliberately populated tables, and prints the five slowest.

At **200,000 audit rows** on CI hardware:

| Migration | What it does | Time |
| --- | --- | --- |
| `030_partition_log_tables` | Converts three log tables to monthly partitions, copying every row | **5.77s** |
| `035_agent_identity` | Re-keys five tables onto an opaque agent id | 0.93s |
| everything else | Schema changes on small tables | under 0.3s each |

Scale from your own row counts: 030 is proportional to the size of `audit`, which is the
largest table in most deployments. At two million audit rows expect roughly a minute; at
twenty million, plan a window. `SELECT count(*) FROM audit;` before you start.

CI fails if any single migration exceeds 60 seconds at its fixture size, which catches a
migration that became pathological rather than merely large.

### Migration 050 builds an index on `audit`, and it is not concurrent

Step 066 adds `audit_door`, a partial index over the door's own traffic:

```sql
CREATE INDEX audit_door ON audit (tenant_id, ts DESC) WHERE run_id LIKE 'door-%';
```

**It takes a lock that blocks writes to `audit` while it builds**, and `audit` is the
table every brokered tool call writes to. `CREATE INDEX CONCURRENTLY` is not available
here: `audit` is partitioned (migration 030) and Postgres refuses `CONCURRENTLY` on a
partitioned parent. The alternative is building on each partition concurrently and
attaching them to an `ONLY` parent index, which this migration runner does not do and
which leaves an invalid parent index behind if it is interrupted.

So it is a short pause rather than a silent risk, and you are already stopped: step 2 of
the upgrade above has you stop the writers, and this is one of the reasons that step
exists. The build is proportional to the number of `door-` rows rather than to the whole
table — an index over a `WHERE` clause only indexes the rows that match — so a deployment
with heavy run traffic and light door traffic builds it in almost no time.

If you want the figure before you start:

```sql
SELECT count(*) FROM audit WHERE run_id LIKE 'door-%';
```

### Migration 051 adds a column to `connector_oauth`, and costs nothing

Step 068 adds `scope_notes`:

```sql
ALTER TABLE connector_oauth ADD COLUMN scope_notes JSONB NOT NULL DEFAULT '{}';
```

`connector_oauth` holds one row per connector with a consent flow, so it is tens of rows
in the largest deployment anybody has. Postgres 11 and later add a `NOT NULL` column with
a constant default without rewriting the table, so this is a catalogue update and a brief
`ACCESS EXCLUSIVE` lock on a table nothing reads on a hot path. There is nothing to plan
around.

**What it changes for you is not the schema but a screen.** Every existing consent flow
gets `'{}'`, which is the truth about all of them: they were configured when there was
nowhere to put a sentence. The Connections page goes on showing bare scope strings for
them, exactly as it did before, until somebody re-runs `--set-oauth` with
`--scope-notes`. The admin form carries existing notes through a re-save but has no box
to author one. Nothing breaks and nothing is back-filled — describing a scope on
somebody's behalf is precisely what this column exists to stop the platform doing.

---

### Migration 052 makes `users.subject` nullable and adds `scim_tokens`

Step 071. Three changes, none of which touches a row that exists:

```sql
ALTER TABLE users ALTER COLUMN subject DROP NOT NULL;
ALTER TABLE users ADD COLUMN external_id TEXT;
CREATE UNIQUE INDEX users_by_external_id ON users (tenant_id, issuer, external_id)
    WHERE external_id IS NOT NULL;
CREATE TABLE scim_tokens (...);
```

`users` has one row per person, so the index is built in the time it takes to read a few
thousand rows, and dropping a `NOT NULL` is a catalogue update. Every existing person keeps
their subject and reads `external_id` as `NULL`, which is the truth: nothing has
provisioned them yet.

**What it changes for you.** The `scim_tokens` table exists and nothing in this tree
writes it (step 078). `--disable-user` and `--enable-user` are the surface that can cut
somebody off before their token expires: `users.status` has had a `disabled` value since
migration 008 and nothing could
set it.

### Migration 053 adds `oauth_clients` and `oauth_codes`, and touches nothing that exists

Step 083. Two new tables and one index, no `ALTER`:

```sql
CREATE TABLE oauth_clients (...);   -- no tenant_id: a client registers before anybody signs in
CREATE TABLE oauth_codes (...);     -- tenant-keyed, hashed, single-use
CREATE INDEX oauth_codes_by_tenant ON oauth_codes (tenant_id);
```

Both are created empty and both get row-level security: `oauth_codes` with 037's tenant
policy, `oauth_clients` with a policy that shows every scoped session the whole table,
because a row there belongs to no tenant. Nothing is back-filled — in particular no
client row is invented for tokens minted before the door spoke OAuth, and
`scripts/e2e_upgrade.py`'s `before_053` stage asserts exactly that. `api_tokens` is not
touched; a token minted through the flow is an ordinary row there, named for the client.
Lock time is the two `CREATE TABLE`s, which is none.

---

## What `--seed` will and will not touch

`carnet --seed` writes the shipped example agent and connector into a tenant. It
is safe to re-run, and deployments that run it on every boot are the case it is built
for.

**It never overwrites a configuration a human wrote.** If you have edited the shipped
agent, or created one of your own under a name we also ship, `--seed` leaves it alone
and says so:

```
Seeded tenant 'acme' with the shipped agent and connector.
  left 'issue-reporter' alone: its configuration was last written by user:u-priya,
  and --seed never overwrites a config a human wrote.
```

Two things it does do, which surprise people:

- If you **rename** the shipped agent, its name is free, and the next `--seed` writes a
  fresh shipped agent into it. You end up with both. Nothing is lost — your renamed
  agent keeps its identity, grants and history.
- An agent that has not been touched since before the version-history migration
  (`032`) has no human author on record, so it is treated as ours and refreshed. Any
  edit made after that protects it.

---

## What CI checks, on every change

The `upgrade` job in `.github/workflows/tests.yml` is the evidence behind this document.
It does what you would do:

1. Builds the **oldest supported schema** and populates it with rows in the shapes that
   era's code actually wrote — old column names, old keys, no columns that did not exist
   yet. A backfill can only be tested against rows that predate it.
2. Applies **every migration forward, one at a time**, timing each.
3. Asserts **every row survived** — compared as whole rows including identifiers, with
   deliberate gaps in the id sequences so a migration that renumbered everything could
   not pass by coincidence.
4. Runs the **full storage contract suite** against that upgraded database, rather than
   against a freshly built one.

The fixture is `backend/scripts/e2e_upgrade.py`, and it is cumulative: each release that
ships migrations appends one stage to it. It is code rather than a database dump on
purpose — a dump is data nobody reviews, and "which release produced this one" becomes
archaeology.
