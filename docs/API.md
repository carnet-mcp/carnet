# The HTTP API

The routes the browser uses, and the ones a client of your own would. Every route takes
the tenant from the caller's identity and never from a parameter; a person authenticates
with their identity provider's token and a machine with an `art_` token.

For the complete list of routes with one line each, see
[CAPABILITIES.md](CAPABILITIES.md). This document is the reasoning behind them.


```bash
pip install -e ".[dev,api,access]"
uvicorn carnet.api:app

curl localhost:8000/health
curl localhost:8000/agents -H "Authorization: Bearer $TOKEN"
```

Interactive docs at `/docs`; the OpenAPI document at `/openapi.json`.

That command is development. **Deploying it** — TLS, the reverse proxy,
migrations, a real database — is `deploy/`: a compose file and the front door, with a
README written for the platform team that runs it in their own cloud.

| | |
| --- | --- |
| `GET /health` | liveness. No auth, no storage read — it must answer when both are broken |
| `GET /agents` | this tenant's agents, **including broken ones**, each with its reason |
| `GET /agents/{name}` | one agent: capability (`tools`) and reach (`scope`), the whole stored config, **your own role on it**, and an **`ETag`**. A broken agent answers **200 with `valid: false`** — it is the agent you came to fix |
| `GET /tools` | the catalogue: everything this tenant may grant, **and which of it writes**. The one route with no grant filter — see below |
| `POST /agents` | create one. **201**, and the caller becomes its owner **in the same transaction** — never an upsert, so a name somebody else uses is a **409** rather than a silent replacement |
| `POST /agents/validate` | a dry run over the same validator. Writes nothing, needs no grant. `{"valid": true}` or a **422** carrying the validator's own sentence |
| `PATCH /agents/{name}` | **`editor`.** A *partial* config, merged at the top level, and **conditional on `If-Match`** — no precondition is a **428**, a stale one is a **409** naming the keys that differ |
| `DELETE /agents/{name}` | **`owner`**, and a real delete. **204**. Its grants cascade; `audit` and `admin_audit` keep the history |
| `GET /agents/{name}/access` | **`user`.** Who can reach it, at what level, and **through which group** — plus the addresses still waiting for a first sign-in, as a separate list |
| `PUT /agents/{name}/grants/{kind}/{id}` | **`editor`.** Share it. `kind` is `user`, `group` or `email`; the answer says `granted` or `pending`, which is the distinction 006 hid from the sharer |
| `DELETE /agents/{name}/grants/{kind}/{id}` | **`editor`.** **204**. Revoking somebody whose access is inherited is a **400** naming the group, not a silent no-op |
| `GET /me` | who you are here, and **whether you may administer this workspace**. No role required — a non-administrator calls it precisely in order to be told they are not one |
| `GET /admin-audit` | **`admin`.** The administrative log — *who changed who may do what* — oldest first, `limit` capped by the signature. Reading it is deliberately **not** itself recorded |
| `GET /groups` | this tenant's groups: id, name, description. **No grant filter**, like `GET /tools` — it is the menu an `editor` picks from when sharing |
| `POST /groups` | **`admin`.** Create one. **201**, carrying the opaque `group_id` grants will name |
| `GET /groups/{id}` | **`admin`**, because it carries **membership** — "who is in every group" is a directory of the company, where a name only says a team exists |
| `DELETE /groups/{id}` | **`admin`.** **204**, and every access the group carried goes with it, on every agent |
| `PUT`/`DELETE /groups/{id}/members/{kind}/{id}` | **`admin`.** Idempotent, and the body says whether anything **changed** — "added" and "was already there" are different facts |

### One rule: `def`, never `async def`

FastAPI is async-first and this runtime is synchronous end to end. The whole
accommodation is that **every endpoint is a plain `def`**, so FastAPI runs it in a
threadpool and the synchronous broker stays synchronous. An `async def` endpoint calling
`broker.call` blocks the event loop, and the symptom is not a slow request — it is the
server ceasing to answer under load while every individual piece looks correct.

`tests/test_api.py` asserts it by walking the route table, because a rule that lives in
a docstring is one somebody breaks in six months.

Taking FastAPI does not contradict hand-writing the MCP client rather than using the
`mcp` SDK. That rejected four dependencies for a **three-method** protocol subset — a
large dependency for a small surface. This is the opposite trade: a large surface, whose
OpenAPI generation and request validation are exactly what a UI consumes.

### The tenant is never a parameter

```
GET /agents                 ✓   tenant comes off the Principal
GET /tenants/{t}/agents     ✗   never
```

A tenant in a path or a query is the caller asserting *which customer's data to read*,
which is the assertion the trust boundary exists to refuse — and it would be enforced by
remembering to check it on every route, which is the same shape as the missed-`WHERE`
leak already listed under known limits. `api/deps.py` is the one place a `Principal` is
built; everything below takes the tenant off it, exactly as the CLI does.

### Authentication: every customer brings their own SSO

A request carries a bearer token from **the customer's own identity provider** — Okta,
Microsoft Entra, Google Workspace, anything speaking OIDC. Nobody creates a password
here, and access follows the employee record their IT team already maintains.

```
Authorization: Bearer <jwt>
        │
        ▼
peek the issuer (unverified — it only chooses which keys to check against)
        │
        ├─ tenant_idps: issuer (+ a discriminating claim) -> tenant, jwks_uri, audience
        │        └── unregistered ──► 401
        │
        ├─ verify: signature, algorithm, iss, aud, exp, nbf
        │        └── any failure ──► 401
        │
        ├─ users: (issuer, subject) -> principal, created on first login IF the
        │         email domain is one this provider may vouch for
        │        └── unlisted domain, disabled account ──► 403
        ▼
Principal.user(id, tenant_id)      tenant from OUR row, never from a claim
```

**The tenant never comes from the token.** A provider can be configured to put an
organisation id in a claim, and trusting it would make the customer's IdP authoritative
over our tenancy — a mis-mapped claim in someone else's admin console becoming a
cross-tenant read here, in a setting we cannot see or audit. The token proves *who*; a
row we own decides *whose data*.

**All of the above is how a token is *verified*. A browser also has to *obtain* one**,
and that is declared separately, at the deployment: `CARNET_OIDC_ISSUER` and
`CARNET_OIDC_CLIENT_ID` in `deploy/.env`, from which the front door serves both the
runtime config the app fetches and the Content-Security-Policy the browser enforces.
The issuer there must be the same string `--add-idp --issuer` registers — one is how a
token is checked, the other is where it comes from, and a deployment where they
disagree comes up healthy and cannot sign anybody in. `deploy/README.md` is the
narrative; `docs/UPGRADING.md` names it as a required setting.

**One issuer does not always mean one customer.** Okta gives each customer their own
issuer and Entra one per directory, so routing is a lookup. Google Workspace shares
`https://accounts.google.com` across every organisation on it — so a row may also carry
a discriminating claim (`hd`), read from the *verified* claims. A registration without
one claims the whole issuer and cannot coexist with a discriminated one; that rule is
enforced when a provider is registered, because no `UNIQUE` can state it.

**401 and 403 are not interchangeable.** A 401 means authenticate again — expired,
forged, or not ours. A 403 means authenticating again will not help: you are genuinely
who you say and still may not use this. A UI that cannot tell them apart either loops on
a login that cannot succeed or gives up on one that would.

Onboarding a customer is deliberately not self-serve, and there is no admin API — see
the CLI commands under **Run**. Whoever can run them already has the database.

### Sharing: an agent belongs to somebody

Authenticating proves who you are. It does not get you an agent — every agent is shared
with named people, and absence is denial. Three levels, and they are named for the verbs
an agent has rather than a document's:

| | May |
| --- | --- |
| `user` | run it; see its tools and what it may reach |
| `editor` | ... and edit its config, and share it on |
| `owner` | ... and delete it, and hand it to somebody else |

**Every row of that table is now true in code**, which it was not until 10d: `editor`'s
editing half was inert for four steps because `routes_agents.py` was read-only, and
`owner`'s deletion half had never been reachable at all.

Delete is `owner` and not `editor`, and it is the one asymmetry worth arguing. `unshare`
already refuses to revoke the owner on the grounds that *an editor who may orphan an
agent may take it from the person who made it* — and an editor who may **delete** it can
do worse than orphan it.

Each level contains the one below, so a check is one comparison. A Google Doc has two
verbs, view and edit; an agent has a third — **run** — and that is the one that spends
API credits and writes to real systems. Calling that level `viewer` would be a name that
actively misinforms whoever picks it, so it is `user`.

Exactly one owner per agent, enforced by a partial unique index rather than remembered.
Ownership is a role on the grant row rather than a column on `agents`, so one table
answers both "who has access?" and "what may I run?", and a transfer is one statement
instead of two writes that can disagree. A transfer demotes the previous owner to
`editor`: handing an agent over almost never means "and lock me out of it".

```bash
carnet --share-agent triage priya@acme.com --role editor
carnet --unshare-agent triage priya@acme.com
carnet --agent-access triage        # who has access, and who is still waiting
carnet --admin-log                  # ... and who took it away
```

#### Who took it away

`--agent-access` answers *who has access now*. The other question — *who changed it, and
when* — is `admin_audit`, from migration 022, and it exists because the grant table
cannot answer it: `agent_grants.granted_by` records who granted access and is destroyed
by the revocation it should have recorded.

Every write that changes who may do what leaves a record, **in the same transaction as
the write**, so a record cannot be missing from a write that succeeded:

```
when                 who              what                  to                    detail
2026-08-08T03:45:22  system:cli       grant.create          agent:issue-reporter  grantee_kind=group, role=editor
2026-08-08T03:45:23  system:cli       grant.revoke          agent:issue-reporter  grantee_kind=group, role=editor
2026-08-08T03:45:23  system:cli       group.delete          group:g_6f5b10cf      name=oncall, members=1, grants=1
```

Three things worth knowing before relying on it.

**It records changes, not attempts.** Revoking a grant nobody had, deleting an agent that
was never there, adding somebody already in a group — all silent. A log that also
recorded attempts would make *"who took Sam's access away"* ambiguous in exactly the
situation it is asked in.

**`detail` says what changed, never the contents of every field.** No credential, no
token, and no agent system prompt — that last one is free text a person typed, which is
the class the audit log's redaction already exists to keep out of a record kept forever.
The consequence: you cannot reconstruct an agent's configuration at a past date from
this. It says the scope changed and what it changed to, not what the prompt said.

**`GET /admin-audit` exists as of step 12b, and the reasoning that kept it out for two
steps is why it waited rather than why it never arrived.** Reading this needs a
tenant-admin role, which this platform did not have — the same wall group administration
hit — and *a read route retrofitted with authorization later is worse than no route*. So
the authorization went in first and the route second. It was the decision in this design
most worth arguing with, because a log nobody can read is a log nobody notices is broken:
a customer's operations team could not answer *"who gave this person access"* about a
product their staff use all day.

`--admin-log` stays, and not only for symmetry: it is the reader that works when the API
is down, and during the bootstrap, where there is by definition no administrator to sign
in as.

#### Sharing with somebody who has not logged in

An address is what a person knows about a colleague. A **principal** is what
`agent_grants` names — and one does not exist until its owner signs in, because the
`users` row is keyed `(issuer, subject)` and a subject only ever arrives inside a token.
**There is no way to make a user row from an email address.**

So a share resolves one of two ways, and which one is invisible to the person sharing:

```
--share-agent triage priya@acme.com
        │
        ├─ somebody in this tenant already has that address
        │      └──►  a grant, immediately
        │
        └─ nobody by that address has ever logged in
               └──►  pending_grants, claimed at their first login
```

Claiming happens **at a first login and whenever a recorded address changes** — not on
every request, which would put a write in front of every read to catch a case that is
rare by construction. A claim never demotes: shared at `user` while already an editor,
the grant stays `editor`, because a login is the worst possible moment to discover that
access has narrowed.

Two places this deliberately does not behave like a Google Doc, both security:

- **A share to a domain none of this customer's providers may vouch for is refused, at
  share time.** Docs lets you share with any address on earth. Here that address names
  somebody who can never authenticate into this tenant — every login is gated on the
  same domain list — so the grant is either inert forever or the first half of a route
  across the tenant boundary. Refusing when a person is present to be told why is the
  whole value; a pending row that silently never lands looks exactly like one waiting
  patiently.
- **No link sharing**, no public flag, no wildcard row. Absence stays denial.

**Ownership cannot be left waiting on an address.** Ownership is transferred, and an
agent owned by a row that is never claimed is an orphan created on purpose. `--role
owner` against an address that resolves works; against one that does not, it is refused
with the suggestion to share at `editor` instead.

Emails are lowercased on the way in and matched case-insensitively. The local part is
case-sensitive by RFC 5321 and case-insensitive at every provider anybody actually uses,
so being right about the standard would only mean the grant never lands.

An address is the handle a human types. **It is not a credential and not an identity** —
resolving one here establishes nothing about who anybody is, and the person still
arrives with a signed token and is identified by their subject exactly as before.

**An agent nobody shared with you is a 404, not a 403**, and this is the row people want
to change. A 403 is the honest status for "you are who you say and may not have this",
which is exactly why it is wrong here: it confirms the agent exists. In a tenant shared
with colleagues, a 403 sweep over plausible names enumerates the company's agents, and
the enumeration is worth more than the access.

That makes the ordering inside each route load-bearing. **The grant check runs before the
config is loaded**, because an invalid config is a 422 — so checking access second would
answer 404 for an agent that does not exist and 422 for an ungranted one that does, and
the leak reopens through a status code nobody thinks of as an authorization decision.

**This is not the permission model.** Two questions, and collapsing them puts identity
into the policy engine:

```
grants        may this PERSON use this agent?      once, before a run exists
permissions   may this AGENT do this thing?        on every tool call
```

`core/permissions.py` has gone six steps without learning what a user is, and
`tests/test_grants.py` asserts that by reading the module's source — the failure mode is
a helpful import somebody adds without noticing what it costs.

The CLI is checked like anybody else rather than exempt. Migration 011 adopted every
pre-existing agent to `system:cli`, so it works on an existing database and stops working
on one that has been transferred away. Exempting it would mean the operator's path never
exercises the rule every other path is held to — so a sharing bug would be invisible from
the one interface used to investigate it.

### Groups: sharing with the support team

No enterprise shares with individuals. Sharing with forty people was forty rows, and when
somebody joined the team nothing followed them.

```bash
carnet --add-group support "The support team"
carnet --group-add support priya@acme.com
carnet --share-agent triage group:support --role user
carnet --groups support            # who is in it
```

#### A group is a grantee, never a principal

The load-bearing decision, and the seductive wrong answer is a one-line CHECK. Two
vocabularies, and only one of them may act:

```
principal kinds   user, system            who ACTS      runs, audit, connections
grantee kinds     user, system, group     who is GRANTED    agent_grants only
```

Widening the first would make a group able to **hold a delegated credential**, which is
the precise inversion of the credentials work: there, a credential belongs to one person
and is bound to `(tenant, principal, connector)` as GCM additional data. A group
credential is an operator credential wearing a team's name.

Until migration 017, `agent_grants` was the **only** table with a CHECK on that column —
`audit`, `connections` and `runs` declared it `TEXT NOT NULL` and nothing else, so a
Python frozenset was the entire defense on all three. 017 puts the constraint in the
database, because a test written in the same language as the constant does not survive
somebody widening the constant: it fails, and it reads as fallout rather than as a
refusal.

The columns are renamed to `grantee_kind` / `grantee_id` for the same reason the split
exists. After this step some lookups **resolve** a person through their groups and some
operate on a **literal** row, and sharing one parameter name between them is how a
resolving revoke that removes nothing gets written and reviewed without anybody seeing it.

#### The rules, and what each one costs

| | |
| --- | --- |
| **Effective role is the highest of direct and inherited** | you cannot demote somebody below their group |
| **A group may not own an agent** | ownership keeps a person's name on it |
| **Members are principals**, so nesting is refused by `check_principal_kind` | no new rule, no cycle detection |
| **The check stays one query** | a join now, not a point lookup |

Highest-wins rather than direct-overrides-inherited. The alternative reads as more
precise and produces a trap: somebody already granted `user` individually silently does
not gain what the rest of their team has, and the two people differ for a reason invisible
in the grant list and in any UI built on it.

Its cost is stated rather than hidden, and refused loudly rather than quietly obeyed:

```
$ carnet --unshare-agent triage u_sam
error: 'u_sam' has no grant of their own on 'triage' — their access comes from
group:g_c6b1bdd7f6de45ba. Removing a grant that does not exist would report success and
change nothing. Take them out of the group, or unshare the group itself.
```

So `--agent-access` says *how* each person has it, because without that the list is
unactionable in the exact situation it is read in — an owner sees Sam, removes Sam, and
Sam still has access:

```
principal                    role      how                       granted by
group:g_c6b1bdd7f6de45ba     user      direct                    system:cli
system:cli                   owner     direct                    seed
user:u_priya                 user      group:g_c6b1bdd7f6de45ba  <unrecorded>
user:u_sam                   user      group:g_c6b1bdd7f6de45ba  <unrecorded>
```

#### A group is not a wildcard

Absence is denial and there is still no public flag, no share link and no wildcard row.
The test that separates a group from those: *can you answer "who exactly can reach this
agent right now?" with a finite list?* A wildcard cannot — that is what makes it
dangerous, because nobody can enumerate the blast radius after an incident. A group can:
membership is rows, and `--agent-access` expands it. A group is **indirection**, closer to
a mailing list than to `*`.

Directory-backed membership is the next chunk and it is where that stops being free: once
membership comes from a token claim we would know who has logged in and been placed in a
group, not who *would* be.

#### One query, and the index that makes it one

The check runs before every run and filters every list view, so it is a single round trip
by requirement:

```sql
SELECT role FROM agent_grants
 WHERE tenant_id = %s AND agent_name = %s
   AND ( (grantee_kind = %s AND grantee_id = %s)
      OR (grantee_kind = 'group' AND grantee_id IN (
             SELECT group_id FROM group_members
              WHERE tenant_id = %s AND principal_kind = %s AND principal_id = %s)) )
 ORDER BY array_position(%s::text[], role) DESC
 LIMIT 1
```

The ladder is **passed in** rather than written into the SQL. Ordering by `role` itself
would be alphabetical — `editor` < `owner` < `user` — which is the ladder upside down and
would return `user` for somebody who owns the agent. `group_members_by_principal` is what
gets from a person to their groups, and it goes in with the table.

`test_the_permission_check_is_one_statement` counts the store's round trips against real
Postgres with fifty agents, because "one query" is the kind of requirement that is true
when written and false three refactors later.

#### Deleting a group takes the access with it

Membership cascades by foreign key. The **grants** go by a trigger, because
`grantee_id` names a different table depending on the column beside it and a foreign key
cannot be conditional. Without it, `group_members` would still cascade and nobody would
inherit anything — the damage would be quieter: a row in `--agent-access` naming a group
that no longer exists, granting nothing, looking exactly like access.

#### Known limits

- **A person's effective access is a computed thing.** "Why can Sam run this?" needs a
  join where it used to be a row.
- ~~**Group membership is a second thing to revoke**, and revocation is still only as fast
  as token expiry. Nothing tells us when somebody leaves a team — groups make SCIM's
  absence worse, not better, because membership is now load-bearing.~~ Built — step 071,
  and held back from this tree (078): `--disable-user` is the leaver's door here.
- **An empty group grants nothing and looks like access.** The CLI warns at share time;
  it is still a state a UI has to have wording for.
- ~~**There is no HTTP route for group administration and must not be one yet.**~~
  **Step 12b.** Mutating a group required a `system` principal — the CLI — because there
  was no tenant-admin role, and anybody who could add themselves to a group holding an
  `editor` grant would have been promoting themselves. It now requires the `admin`
  platform role, which preserves that restriction exactly rather than relaxing it: what
  changed is that a *person* can hold it, by a row somebody granted. Sharing an agent
  *with* a group is unaffected and always was: that needs `editor` on the agent, so
  filling a group grants nobody anything until somebody who could already share does.
- **Listing groups is open and listing membership is not**, and the line was audited
  rather than assumed. A name discloses that a team exists, which the org chart already
  does, and an `editor` sharing with a group has to pick one — a catalogue that cannot be
  read cannot be shared with. *Who is in every group* is a directory of the company, and
  the one legitimate non-admin need — **who will this share reach** — is already answered
  per agent by `GET /agents/{name}/access`.
- **There is still no group-management UI.** The routes exist; their consumer today is the
  same engineer who runs `--add-group`, and the non-technical one arrives with 12c.

### Offboarding: somebody leaves

Claims are a pull on presence; a person deleted in the customer's IdP never signs in
again, so nothing reconciles, so nothing revokes — until somebody says so:

```
carnet --disable-user their.address@example.com
```

**What it does**, decided rather than inherited: everything that acts *as* the person
stops, and nothing the person *made* is deleted. Their sign-in is refused, every API token
they own is refused at its next call, and an acting-for identity resolving to them is
refused. Their agents, grants, group memberships and connections are untouched. There is
no hard delete — every audit row they ever produced names their id — so a disable is
what there is, and `--enable-user` reverses it. `--list-users` shows who is here.
`docs/runbooks/offboarding.md` is the procedure, run.

### Platform roles: who may administer this tenant

One role, `admin`, from migration 026. It answers a question about the **tenant** where
the sharing ladder answers a question about one agent, and until step 12b it did not exist
— which had stacked four features behind it: group administration (9a), a read route for
the administrative log (11), the vetting screen (12), and consent-flow configuration (7b).

```bash
carnet --grant-role admin priya@acme.com
carnet --list-roles
carnet --revoke-role admin priya@acme.com
```

#### An admin is not a superuser

**Holding `admin` grants access to no agent, no run and no connection.** `access/roles.py`
never consults `agent_grants` and `access/grants.py` never consults `platform_roles`; an
admin with no grant on an agent gets the same 404 as a stranger, and a test says so in
both stores.

The argument is the delegated-credentials work's, one level up. That exists because *an
operator holding everybody's tokens* is the failure it prevents — and an `admin` that
implied agent access would rebuild that operator under a different name, one grant away.
What an admin gets is tenant **configuration**; what they do not get is tenant **data**.

#### `system` is always an administrator, and that is the bootstrap

HTTP structurally cannot mint a `system` principal: every path through `api/deps.py` ends
at `users.resolve`, which returns `Principal.user(...)`. Two things follow, and both are
decisions rather than conveniences.

*Who grants the first admin?* Whoever has the shell — which is this deployment's actual
root of trust, rather than a self-serve ceremony pretending otherwise. And **lockout is
impossible**, so revoking the last administrator is allowed: a "cannot remove the last
admin" rule would guard a failure that cannot occur here, and would become wrong the day
role administration moves to HTTP, where it has to be re-decided rather than inherited.
The CLI warns loudly instead.

#### Granting stays on the CLI

There is no `PUT /roles/...`, deliberately. A role model whose first version lets admins
mint admins over HTTP hands a compromised admin token the one thing it lacks, in the step
whose purpose is containment — and the administrative log recording an escalation is not
preventing one.

A role is granted to a principal that **exists**. An address nobody has logged in with is
refused, which is the connections rule and sharper: *a role is not an invitation*, because
a pending admin grant promotes whoever eventually claims a mistyped or recycled address,
silently, at login, weeks after somebody typed it.

#### Known limits

- **One bit of granularity.** "May vet connectors but not read the log" is not
  expressible. Deliberate — the evidence for the right split does not exist yet, and
  collapsing a wrongly split role is a breaking change where widening one is additive.
- **An admin's 403 does not say who to ask.** A directory of who to phish is not an error
  message's job; the cost is a person asking a colleague instead of reading a screen.
- **The always-admin `system` rule is a convention pinned by tests, not by types.** If a
  future entry point mints `system` principals from network input, that precondition
  breaks — `test_http_can_never_mint_a_system_principal` is the tripwire.

### Editing, and what happens when two editors disagree

`PATCH /agents/{name}` is **conditional**. `GET` returns the agent's `updated_at` as an
`ETag` and as a field; a save sends it back as `If-Match`, and the store compares it
inside the same statement that writes:

```sql
UPDATE agents SET config = %s, updated_at = now()
 WHERE tenant_id = %s AND name = %s AND updated_at = %s
```

**The guard cannot live in the route.** Read-then-write there has a window between the two
in which the other editor commits, and that window is precisely the lost update the
timestamp exists to catch — so it is one statement in storage, next to `create_agent`'s
transaction and for the same reason. A `PATCH` with no `If-Match` is a **428** rather than
a permissive default, because last-write-wins is how one person silently reverts another's
scope narrowing and it fails invisibly by construction.

A stale save is a **409** carrying the current `updated_at` and **the top-level keys the
request disagrees with the stored config about** — not "what the other person did", which
nothing here can answer, but the exact set this save would have overwritten. An empty list
means the save was a no-op and can simply be retried.

**Not a hash of the config.** A hash cannot tell "changed" from "changed and changed
back", and it would be a second answer to a question the schema has had a column for since
migration 002. `updated_at` is also what a UI wants to *show*, which a hash is not.

#### A partial config, merged at the top level

The body is a **patch**, not a config, and that is a decision taken on a confirmed
finding rather than a preference. `frontend/src/lib/draft.ts` has `toConfig` and no
inverse; the shipped `issue-reporter` carries `default_task` and `deny_demo_task`, and no
step of the create form asks about either. An edit screen built from the create form and
saving the whole config **deletes both**, and nothing anywhere reports it.

- **A key that is absent is untouched**, so `default_task` survives because the form never
  sends it rather than because somebody remembered to carry it.
- **`permissions` is replaced as a unit**, never deep-merged. `tools` and `scope` are
  cross-checked in both directions by `_validate_scope_matches_tools`, so a merge that
  updated one and kept the other is the one way to produce a config the validator refuses
  through a route that looks like it is working.
- **`name` is not patchable.** It is the URL, the storage key, the broker's identity and
  the string in every audit record. A body naming a different one is a **400**, never a
  silent ignore.

The cost, stated rather than hidden: **there is no way to *remove* an optional field over
HTTP.** Sending `{"limits": {}}` clears the limits, because whole-value replacement applies
to every top-level key; sending nothing leaves them. Deleting `default_task` entirely needs
the CLI.

#### Deleting

A real delete. The row goes, `agent_grants` and `pending_grants` cascade, and `audit` and
`admin_audit` keep the history because neither has a foreign key that would take it. Soft
delete was refused for the reason this codebase has refused it three times: a disabled
agent still holding grant rows is a row that grants nothing and looks like access.

### Which failure is which status

| Condition | Status |
| --- | --- |
| unknown agent, unknown tenant | 404 |
| an agent nobody shared with you | 404, **the same 404** |
| the agent exists and its config is invalid | **200 with `valid: false`** on the read; 422 on the write that would put it to use |
| a `PATCH` with no `If-Match` | 428 |
| a `PATCH` from a version somebody else has replaced | 409, with `updated_at` and `changed` |
| a `PATCH` whose body names a different agent | 400 — renaming is a different operation |
| a share you may make and that cannot be made | 400 (`ShareRefused`), never the 404 |
| storage unavailable | 503 |

**A brokered denial is not an HTTP error.** The broker refusing a tool call is the system
working as designed: the model is told and carries on. It surfaces as a `denied` count on
a 200, the same way the door log shows it. Mapping it to a 403 would report a successful
enforcement as a server failure, and would make the most important records in the audit
log look like outages.



