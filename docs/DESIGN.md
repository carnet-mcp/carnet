# Design

Why Carnet is shaped the way it is. This is the design record: the layering that keeps
the broker the only path to a tool, what the trust boundary actually covers, how two
tenants stay apart, what a permission means, and what the audit log is for.

It is written for somebody deciding whether to trust this or change it. If you only want
to run it, the [README](../README.md) and the [guide](GUIDE.md) are enough.

## Layout

```
carnet/
├── backend/
│   ├── pyproject.toml              deps, entry point, pytest config
│   ├── src/carnet/
│   │   ├── config.py               paths, ceilings, settings — read once at import
│   │   ├── cli.py                  command-line entry point: onboarding, roles, tokens, connectors
│   │   ├── bootstrap.py            wiring: choose a store, seed the shipped examples
│   │   ├── door.py                 the MCP door: what a token may call, and calling it
│   │   ├── maintenance.py          the log sweep: partitions and retention
│   │   ├── metrics.py              in-process counters for GET /metrics
│   │   ├── rotation.py             finishing a key rotation
│   │   ├── api/                    the HTTP entry point
│   │   │   ├── __init__.py         the app, the lifespan, the def-not-async rule
│   │   │   ├── deps.py             where a request becomes a Principal
│   │   │   ├── errors.py           which failure becomes which status code
│   │   │   ├── schemas.py          the OpenAPI surface
│   │   │   ├── routes_mcp.py       /mcp — the door, speaking MCP
│   │   │   ├── routes_agents.py    permission lists: create, edit, share, history
│   │   │   ├── routes_tools.py     the catalogue
│   │   │   ├── routes_connections.py  a person's own connected accounts
│   │   │   ├── routes_groups.py
│   │   │   ├── routes_admin.py     /me, tokens, the overview, the logs
│   │   │   └── routes_admin_connectors.py  registering and vetting connectors
│   │   ├── access/                 who a caller is: OIDC, users, groups, roles, grants, tokens
│   │   ├── core/                   the broker — knows no tool, no agent
│   │   │   ├── broker.py           the only path from a caller to a tool
│   │   │   ├── permissions.py      may this agent, for this principal, do this?
│   │   │   ├── patterns.py         resource pattern matching
│   │   │   ├── limits.py           has this call already done too much?
│   │   │   ├── credentials.py      the only module that reads secrets
│   │   │   ├── vault.py            a credential resolved from the customer's vault
│   │   │   ├── crypto.py           the only module that holds a key
│   │   │   ├── principal.py        who a call is made for, and for which tenant
│   │   │   ├── context.py          the call: id, principal, budget
│   │   │   ├── usage.py            what a brokered model call cost
│   │   │   ├── audit.py            what happened?
│   │   │   └── audit_query.py      reading it back
│   │   ├── tools/                  one module per tool family
│   │   │   ├── base.py             the Tool and Resource types
│   │   │   ├── validation.py       descriptor rules (used by both registries)
│   │   │   ├── messaging.py
│   │   │   ├── rest/               REST connectors, and the model connector
│   │   │   └── mcp/                connectors: vetted MCP servers
│   │   │       ├── __init__.py     per-tenant connector loading, connect()
│   │   │       ├── transport.py    how messages reach a server (stdio and HTTP)
│   │   │       ├── client.py       the protocol subset + session pool
│   │   │       ├── binding.py      the allowlist: manifest × advertisement
│   │   │       ├── egress.py       which hosts a tenant will let us dial
│   │   │       └── connectors/
│   │   │           └── github.py   the GitHub vetting manifest (seed data)
│   │   ├── agents/
│   │   │   └── __init__.py         the loader: save/get/load + validation
│   │   ├── localidp/               `carnet --local`: a real OIDC provider on your machine
│   │   └── storage/
│   │       ├── __init__.py         configure() / active() — one store per process
│   │       ├── base.py             the Storage protocol
│   │       ├── memory.py           in-memory — what the tests run against
│   │       ├── postgres.py         psycopg3, raw SQL
│   │       ├── migrate.py          numbered SQL, applied in order
│   │       └── migrations/         001_tenants … 052_scim
│   ├── scripts/                    end-to-end checks against real Postgres and real servers
│   └── tests/
│       ├── conftest.py             isolated var dir + a fresh store per test
│       ├── test_door.py            /mcp, end to end through the broker
│       ├── test_broker.py          the enforcement boundary
│       ├── test_tenancy.py         one customer's data is not another's
│       ├── test_storage_contract.py  both implementations, same assertions
│       ├── test_agents.py          validation at write time and load time
│       ├── test_permissions.py     capability and reach
│       ├── test_patterns.py        the matcher
│       ├── test_mcp.py             protocol subset and the allowlist
│       ├── test_transport_http.py  did this maybe happen?
│       ├── test_limits.py          the budget dials
│       ├── test_tools.py           descriptor validation
│       ├── test_credentials.py     lookup key, injected-kwarg contract
│       ├── test_api.py             the entry point, and where the tenant comes from
│       └── test_concurrency.py     what a second thread breaks
├── frontend/                       React 19 + Vite, hand-written CSS
├── deploy/                         compose, the image, the front door
└── var/                            runtime artifacts (gitignored)
```

`tools/__init__.py` is the two-registry module described below, and `core/__init__.py`
re-exports the handful of names entry points need.

**Layering rule.** Each layer imports downward, never upward:

```
cli / (api)   entry points — construct the principal, carry the tenant
agents/       who exists and what they may do   (config only)
core/         the broker                        (knows no tool, no agent)
tools/        what can actually be done         (knows no agent, no policy)
storage/      rows in, rows out                 (knows no agent, no tool, no policy)
config.py     paths, defaults, limits           (knows nothing)
```

Storage sits *below* `tools/` rather than inside `core/`, and the placement is forced:
`core/` is forbidden from knowing what an agent is, while the agent loader needs the
store. Putting it underneath keeps every import pointing downward.

`bootstrap.py` is the exception that proves the rule — it imports across layers
because composing them is exactly what an entry point is for.

The one invariant worth protecting: **nothing outside `core/` may call a tool
implementation directly.** There is no `execute_tool` helper and no public dispatch —
the only route is `core.broker.call`, which is where permissions, credentials, and
audit are enforced. An import of a tool implementation outside `core/` or `tests/` is a bug.

`api/` was an empty growth slot from the first commit and is now the second entry
point. Remaining slots: more modules under `tools/` and `agents/`, and `frontend/` as
its own project with its own build.


## Running two of anything at once

A threadpool is the first thing in this project's life to run two of anything, and four
pieces of process-global state were written for a single-threaded loop. None of them is
hard to fix and **all of them fail silently**, which is why they were the substance of
the API step rather than a follow-up to it.

| What | Fix |
| --- | --- |
| One database connection | `psycopg_pool`. The helper had to change shape too — it returned a live cursor, and a connection cannot go back to the pool while a caller holds one onto it |
| A shared MCP session | a lock per session. See below |
| The session pool dict | a lock, plus creation through `get_or_create` so two threads cannot both build a session and orphan one |
| The bound tool registry | a lock. Safe on CPython by accident before, which is not a property to rest a tenant boundary on |
| `InMemoryStorage` | a lock. Its docstring said "not thread-safe, deliberately" — true until this |

### Why a shared session needed a lock, specifically

Two threads sharing one MCP session do not merely race. A session is one pipe with one
id counter, and `_await` **discards** any message whose id is not the one it is waiting
for — correct while a single thread owns the pipe, and how server-initiated
notifications get ignored:

```
thread A  send(id=7) ─┐
thread B  send(id=8) ─┼─►  one pipe, one inbox queue
                      │
          A reads the reply to 8, discards it (not the id it wants), waits on
          B waits for a reply that has already been thrown away → times out
          B raises TransportError(delivered=True) → outcome="unknown"
```

B did nothing wrong and is recorded as a write that **may have taken effect and needs a
person** — the one lie the delivered/ambiguous mapping exists to prevent. Driving the
pre-lock code with eight threads, **seven of the eight** calls came back that way.

The cost is real: two callers sharing a connector *and* a credential take turns at their
tool calls. Acceptable because a call is short, and it stops being a shared key at all
once credentials are delegated. The measurable trigger for moving to several sessions
per key is when waiting on that lock is a material fraction of call duration —
`duration_ms` is already in the audit log for exactly this kind of question.

### Idle eviction stopped being deferrable

Sessions now expire after `MCP_SESSION_IDLE_TTL` and the pool is capped at
`MCP_SESSION_POOL_MAX`, evicting least-recently-used. Both numbers are invented, and
that is a smaller sin than it was: they are bounds where there were none, not tuning.
Deferring them was right while a CLI process exited and took its sessions with it, and
expired the moment the process became long-lived — a connector nobody has used since
Tuesday is a container still running.

Eviction happens opportunistically on every `get` and `put`, which covers a busy server
completely and an idle one not at all — and an idle server is the exact case a TTL
exists for. So the API also runs a background sweep every
`MCP_SESSION_PRUNE_INTERVAL`, started and stopped by the lifespan. The CLI does not
need one; it exits.

`tests/test_concurrency.py` holds all of this in place, driving real threads through the
real objects rather than asserting that a lock exists.

### Verified against the real thing

The suite starts nothing, so the claims above were also checked end to end against real
Postgres and two real MCP servers:

| | |
| --- | --- |
| the Docker connector, bound from a request thread | `github-mcp: bound 3, excluded 6 unvetted` |
| GitHub's **hosted** endpoint, credential per request | `github-remote: bound 1, excluded 43 unvetted` |
| three calls, one bind | the pooled session was reused, not respawned |
| a refusal over HTTP | **200** with `denied: 1`, message byte-identical to the CLI's |

One audit trail, and nothing below the entry point learned that HTTP exists.

## The trust boundary

```
model output ──► runtimes/simple.py ──► broker.call(ctx, config, name, input)
 (untrusted)         (Tier 1)             │
                                          │  BOTH are server-side: the run context
                                          │  (id, principal, budget) is built by the
                                          │  runtime, the agent is loaded from storage
                                          │  for the run's tenant. Neither is
                                          │  model-generated.
                                          ▼
                          1. permissions.check()      ── deny ──► audit + error to model
                          2. budget.reserve()                     (nothing executed,
                          3. credentials.for_tool()                no credential read)
                          4. execute → size cap → audit
```

The model contributes only a tool name and arguments. There is no parameter through
which it can assert *who it is*, *whose authority it acts under*, or *how much budget
it has left* — so it can claim neither another agent's permissions, another user's
access, nor a fresh allowance.

Steps 1 and 2 answer different questions. Scoping bounds what a call may **reach**; the
budget bounds how much it may **do** within that reach.

**Actor vs authority.** The agent is the actor; the principal is the authority it
acts under — the machine token at the door, or the person it says it is acting for.

## Storage and tenancy

Agents, connectors, vetting decisions and the audit trail are rows. Every table
carries a `tenant_id` from the first migration, because retrofitting tenancy means
backfilling a column nobody knows the value of, on tables already being read by code
that does not filter on it.

Two implementations behind one `Storage` protocol: Postgres for real, in-memory for
tests. That seam is what lets the suite keep the property it has always had — it starts
nothing, calls nothing, and finishes in about a second. The risk of a fake is that it
permits what the real thing refuses, so `tests/test_storage_contract.py` runs **one set
of assertions against both**, and every rule Postgres enforces with a constraint is
enforced in Python too: the tenant foreign key, the agent-name check, the refusal to
store a derived field, ordering, and deep-copy on read and write.

### Where the tenant lives

On the **`Principal`**, not on the `RunContext`. A principal belongs to a tenant,
including a system one: the operator's CLI acting for a customer is that customer's
operator. Because the principal is already threaded through the broker, the
audit log, the credential lookup and the permission check, all four got tenancy without
growing a parameter — and `RunContext.tenant_id` derives from it rather than storing a
second copy that could disagree.

`Principal` has **no default tenant**. A defaulted tenant on a frozen security-relevant
dataclass is how a construction site quietly ends up in the wrong customer's data.

### Vetting is per tenant, and that is a security boundary

Two customers can both run the official GitHub MCP server and expose different tools
from it — one vets reads only, the other also vets a write. So the tool registry is
split along a line that is not a filing convenience:

| | Scope | Why |
| --- | --- | --- |
| hand-written tools (`post_message`) | process-global | they are code; every tenant gets the same one |
| connector-bound tools | **per tenant** | vetting is a tenant's decision about a tenant's server |

A single registry keyed by tool name would let one customer's vetting decide what
another customer's agents can call. That is a cross-tenant authorization leak requiring
nothing more exotic than two companies both using GitHub, and `test_tenancy.py` asserts
it directly. Session pooling is keyed by tenant for the same reason: a live session is
bound to the manifest it was bound against.

In the broker this cost **one line** — `tool_registry.get(tool_name, ctx.tenant_id)`.
`permissions.check`, `patterns` and `limits` were not touched, which is what the
resource-type indirection was for.

### Validation moved without weakening

Configs used to be modules, so `validate()` ran at import and a bad grant stopped the
process from starting. Now:

- **write time** — `agents.save()` validates and refuses, so an invalid config never
  becomes a row. A form user gets exactly the errors the import used to raise.
- **load time** — still fail-closed, because a row valid when written can stop being
  valid. Delete a connector and every agent granting its tools is dangling.

One property did change, deliberately: a bad agent no longer stops the process. It
raises when someone tries to run it, and listing skips it and says so. "It cannot start
broken" is a property of a single-tenant process — one customer's bad row must not take
the platform down for everyone else. "It cannot *run* broken" is the property that
mattered, and `get()` raises rather than returning `None`, so a broken agent is never
silently a missing one.

### Schema

Thirty-five migrations, plain SQL, applied in order by a small runner. Not Alembic: its real
value is autogenerating a diff from declarative models, which needs an ORM we
deliberately do not have — without that it is a runner with more machinery, and plain
files mean a reviewer reads the exact DDL that will run.

| Table | Holds |
| --- | --- |
| `tenants` | the customer |
| `agents` | one JSONB config per agent, keyed `(tenant_id, name)` |
| `connectors` | how to reach a vetted server |
| `vetted_tools` | the per-tool review record: effect, resources, who approved it |
| `audit` | one row per brokered call |
| `connections` | delegated credentials: one person's sealed token per connector |
| `agent_grants` | who may use an agent, and at what level. Keyed by **grantee** |
| `groups` / `group_members` | a name and a set of principals. Grantees, never principals |
| `admin_audit` | who changed who may do what — the log the row-shaped design could not hold |
| `connector_oauth` / `pending_authorizations` | a connector's consent flow, and one in progress |
| `tenant_egress_hosts` | what this platform will dial for this customer |
| `platform_roles` | who may administer this tenant. `admin`, and the set is closed |

Three things the database enforces that a dict cannot:

- `CHECK (config->>'name' = name)`. The broker trusts `config["name"]` as identity and
  writes it into every audit record, so a row whose key disagreed with its body would
  misattribute everything that agent ever did. That was an import-time check; this is
  where it went.
- **`audit` is append-only**, via a trigger that refuses UPDATE and DELETE. A JSONL file
  was append-only because of what it is; a table is mutable by default, and an audit log
  somebody can edit is a weaker artifact than the one it replaced. A trigger rather than
  a `REVOKE`, because a revoke does nothing when the app connects as the owner.
  Retention deletion will have to drop it explicitly — that friction is the point.
- **No `ON DELETE CASCADE` from `tenants` to `audit`.** You cannot remove a customer and
  silently erase the record of what their agents did.
- **`principal_kind IN ('user','system')` on `audit` and `connections`**, added by
  017. Until then `agent_grants` was the only table constraining that column, so a Python
  frozenset was the whole defense on the three where a wrong value is a security
  inversion. `audit`'s is `NOT VALID` — it enforces on every future write and declines to
  re-scan the one unbounded table in the schema to re-prove history no code path could
  have written. To finish it where the scan is affordable:
  `ALTER TABLE audit VALIDATE CONSTRAINT audit_principal_kind_check;`

- **`principal_kind IN ('user','system')` on `platform_roles`**, from 026, and it is the
  same CHECK for a sharper reason: a group holding an administrative role would make group
  membership self-service promotion, because anybody who may add a member could then make
  an administrator.

There is deliberately **no `read_only` column**. It stays derived from the vetted
effects — see below — and a stored copy is free to disagree with the allowlist it
defends.

## Permissions — capability and reach

A grant has two dimensions: **which tools** an agent may call, and **which resources**
those calls may touch.

```python
"permissions": {
    "tools": ["github_mcp_list_issues", "post_message"],
    "scope": {
        "github.repo":  {"read":  ["anthropics/*"]},
        "chat.channel": {"write": ["#eng"]},
    },
}
```

Scope is written against **resource types**, not argument names. Each tool declares
which of its arguments are resources of which type, so one `github.repo` grant covers
every tool that touches a repo — including tools we didn't write, whatever each one
calls its arguments. That indirection is what makes the model survive arbitrary MCP
servers (see below).

Rules, all fail-closed:

- A tool not in `tools` is denied. No implicit grants.
- A tool not in the registry is denied — we can't scope what we can't describe.
- A declared resource argument that wasn't supplied is denied.
- A resource type with no grant **at that tool's effect** is denied. Grants are
  per-effect with no implication: `write` does not confer `read`.
- Arguments that aren't declared resources are unconstrained — `limit` is data.
- Any credential-shaped argument (`webhook_url`, `token`, `api_key`, …) is denied
  outright — those come from the broker, so the model supplying one is a red flag.

The `tools` list is also the single source of truth for which schemas the model sees.
That's ergonomics, not security — the broker re-checks every call regardless.

### Composed identifiers

A resource is not always one argument. GitHub's REST API — and so its MCP server —
takes `owner` and `repo` separately, so a tool wrapping it declares:

```python
resources=[Resource("github.repo", ["owner", "repo"], template="{owner}/{repo}")]
```

The grant above is unchanged. That is the whole point of writing policy against
resource types: a tool we didn't write, naming its arguments differently and splitting
the identifier across two of them, falls under the same `anthropics/*`.

A list rather than a dict keyed by resource type, because a tool may touch two
resources of the *same* type — a `copy_issue(from_repo, to_repo)` declares two
`github.repo` entries and both are checked.

Composition brings one rule of its own: **a component may not contain `/`**. Given
`{owner}/{repo}` and a grant of `anthropics/**`, a `repo` of `../../torvalds/linux`
composes to a value the matcher admits, and the tool then builds a request path
pointing at a repository nobody granted. This is prefix confusion's composite cousin —
`patterns.py` defends the pattern side, and nothing but this defends the component
side. It applies to composition only: a single argument used whole *is* the
identifier, and the slash in `anthropics/sdk` is its structure.

### Scoping to the caller

```python
"scope": {"tickets.assignee": {"read": ["${principal.id}"]}}
```

Resolved against the principal at check time: one config, any number of users, each
reaching only their own rows. A caller-scoped pattern under a **system** principal is
an explicit denial — a system principal has no user to scope to, so that config is an
error worth surfacing rather than a silent non-match.

### Pattern syntax

Segment-aware, splitting on `/`:

| Pattern | Matches | Does not match |
| --- | --- | --- |
| `anthropics/sdk` | exactly that | anything else |
| `anthropics/*` | `anthropics/sdk` | `anthropics/a/b`, `anthropics` |
| `project/**` | `project/42`, `project/42/board/7` | `project` |
| `#eng` | `#eng` | `#random` |

Comparison is always segment-whole, so `org/*` cannot match `org-evil/repo`. Prefix
confusion isn't a case to remember — it isn't expressible. Deliberately **not regex**:
anchoring mistakes and catastrophic backtracking are a poor trade in a check that runs
on every tool call. Matching is case-sensitive; normalizing identifiers is a
connector-vetting concern.

Malformed patterns raise at config load, not at call time — a pattern that can never
match is a policy that denies everything, which is safe but baffling at 3am.

## Tool descriptors, and what MCP does not give you

MCP supplies a **catalog and execution**: a server advertises tools via `tools/list`
and runs them via `tools/call`. It does **not** supply authorization. The protocol has
no per-agent or per-user permission model, and the server sees one client connection —
it cannot tell which of your agents, acting for which user, is calling.

So a `Tool` doesn't disappear once MCP is wired in; it stops being hand-written:

| Field | Source |
| --- | --- |
| `name`, `description`, `input_schema` | copied from the server's advertisement |
| `impl` | generated proxy that calls `tools/call` |
| `effect`, `resources` | **added by us at vetting time** |

The server can't author that last row. Given `create_work_item(project, type, title,
description)` it tells us four argument names; it does not tell us that `project` is
the thing worth scoping on while `title` is data, that this is a write, or that its
"project" maps to our `ado.project`. MCP's `readOnlyHint` is advisory and
self-declared — an enterprise boundary can't rest on a claim made by the component
being constrained.

Per connector this is roughly two annotations per tool, once. That's what "vetted and
scoped" concretely means.

### Vetting is an allowlist, not a filter

A connector manifest names the tools we expose. Binding intersects it with what the
server actually advertises, and each of the three outcomes is deliberate:

| | |
| --- | --- |
| advertised, not vetted | **excluded and reported.** A server that adds `delete_repository` in v1.4 does not become callable because nobody remembered to exclude it. |
| vetted, not advertised | **raise.** A vetted tool that vanished is drift; guessing which of the rest replaced it isn't this layer's call. |
| vetted, schema moved | **raise**, via `tools/validation.py`. If `repo` became `repository`, our resource declaration names an argument that never arrives — enforced in review, absent in fact. |

The shipped GitHub connector vets **three** tools out of the hundred-odd the server
advertises — `list_issues`, `issue_read`, and one write, `add_issue_comment`. That
ratio is the point: you don't vet a server, you vet the tools you want, and the rest
stay invisible to every agent on the platform.

`search_issues` is deliberately unvetted, and the reason is the interesting one. It
*does* take `owner` and `repo` — but both are optional, and `query` is not. The query
is GitHub's own search syntax and may carry its own `repo:` qualifier, so two arguments
can disagree about what the call reaches and the server decides which wins. Scoping the
pair we can see would be a constraint that reads as enforced while the query goes
wherever it likes, and parsing a vendor's query grammar to work out what a call will
touch is exactly the guess a permission check must not make. Unscopeable, therefore
unvetted.

### Adding a connector

A connector is a `Connector` object saved for a tenant, and nothing in `core/` changes:

```python
tools.save_connector(tenant_id, Connector(
    id="jira",
    launch=Launch(command=(...), credential_env="JIRA_TOKEN"),
    vetted=[
        Vetted("search_issues", effect="read",
               resources=[Resource("jira.project", "projectKey")]),
    ],
))
```

`save_connector` validates the manifest and refuses one whose namespaced tool names
would shadow a hand-written tool — a check that used to run at import and now runs at
the moment the data arrives, which is when somebody can still do something about it.

Still deliberately not self-serve. The two-persona split is unchanged: a **connector
admin** decides which of a server's tools to expose and annotates each one's effect and
resources; an **agent creator** picks from what has already been vetted. Only the
mechanism moved — vetting is a reviewed decision recorded as data (`vetted_by`,
`vetted_at`) rather than a code change, which is what makes a connector-admin UI
possible without touching the policy engine.

Tool names are namespaced by connector id — `github_mcp_list_issues` — so two servers
may both offer `list_issues`, a connector can't shadow a hand-written tool (refused
when the connector is saved), and an audit record says which path a call took without
a cross-reference.

Connecting is lazy and per-agent: a connector is a container, and an agent that
touches no GitHub tool shouldn't pay for a GitHub server. `run_agent` connects only
what the agent's granted tools need, before the model sees a schema list. Failure
**raises** — a tool missing from that list is a gap the model improvises around, which
is a silent degrade in the one place a loud failure costs nothing. If a connector
somehow isn't bound, `tools.get(name, tenant)` returns None and the broker refuses a
tool it cannot describe; that's the backstop, not the plan.

### What the connector actually cost

The reason GitHub was the first connector: a hand-written `get_github_issues` already
existed, so the same agent could run the same task down each path and the audit log
could answer what changed. Same prompt, same grants, same repo — only the tool differs.
(The hand-written tool has since been retired; this is the run that decided it.)

```
                  issue-reporter            issue-reporter-mcp
tool calls        2                         3      <-- differs
denied            0                         0
writes            1                         1
oversize          0                         0
response bytes    2812                      25384  <-- differs
tool time (ms)    531                       1953   <-- differs

  A: get_github_issues[ok] -> post_message[ok]
  B: github_mcp_list_issues[ok] -> github_mcp_list_issues[ok] -> post_message[ok]
```

**The security abstraction holds.** Asked to overstep, both refuse with a
byte-identical message:

```
github.repo 'torvalds/linux' is outside this agent's 'read' scope.
Allowed: anthropics/anthropic-sdk-python
```

— even though the MCP tool supplied `owner: "torvalds"` and `repo: "linux"` as two
separate arguments. One grant, written before the connector existed, constrains a tool
that names its arguments differently and splits the identifier across two of them.
Same decision, same audit shape, same wording.

**The cost is real.** 9× the bytes and 3.7× the time. Two calls instead of one,
because the server paginates and the model followed the cursor. An earlier run against
the unfiltered response returned **77,710 bytes** and blew `MAX_RESPONSE_BYTES` — the
cap working exactly as designed, including telling the caller how to recover. The
model then found the server's `fields` parameter on its own and narrowed the request,
which is why the run above passes. Byte ceilings for connector tools should be set
from this data rather than guessed; logging `response_bytes` on passing calls is what
makes that possible.

**The semantics do not carry, and that is the finding worth having.** The two paths
gave different answers to the same question:

| | reported |
| --- | --- |
| `get_github_issues` | 12 open issues |
| `github_mcp_list_issues` | 146 open issues |
| GitHub search API (truth) | **146** |

The hand-written tool is the one that is wrong. It requests 30 items, filters out pull
requests, and returns `{"count": 12}` — a number that looks complete and isn't, with
nothing in the payload saying so. The connector paginated and got all 146.

Nothing in the broker could have caught this. Permissions bound what a tool may
*reach*; budgets bound how much it may *do*. Neither has an opinion about whether a
tool answers the question correctly. **Vetting a connector is a security review, not a
correctness review** — a scoped, audited, budgeted tool can still be wrong, and swapping
one for another can silently change what an agent tells someone.

### Two transports, and why there are two

| | Credential | Sessions |
| --- | --- | --- |
| **stdio** | env var at process launch, held for the process's life | one subprocess |
| **Streamable HTTP** | a header, **per request** — no long-lived process holds it | one endpoint |

That difference is not a deployment preference. Per-user credentials over stdio would
mean one long-lived subprocess per user, each sitting on a plaintext secret readable by
anything that can read the process table. HTTP is what makes delegated credentials
possible at all, which is why it was built before the access layer rather than after.

A connector says which it speaks, and there is **no fallback between them.** Quietly
substituting one for the other because the first would not start would be substituting
a security posture.

```python
StdioLaunch(command=("docker", "run", ...), credential_env="GITHUB_PERSONAL_ACCESS_TOKEN")

HttpLaunch(url="https://api.example.com/mcp/", credential_env="EXAMPLE_TOKEN",
           credential_header="Authorization", credential_prefix="Bearer ")
```

Either way the row names *where* the secret comes from and never the secret itself.
Adding the second shape needed no migration — `connectors.launch` is JSONB, and a row
without a `kind` is stdio, so anything written before this existed keeps working.

One thing is lost over HTTP and worth stating: **read-only mode is a launch-time
switch, and there is no launch.** `Connector.read_only` is still derived and still
correct, it simply has nothing to act on. That costs a layer of defence in depth and no
more — the allowlist was always the actual control, and pointing this at GitHub's
hosted endpoint shows exactly what that means:

```
[mcp] github-remote: bound 1, excluded 43 unvetted
      (add_comment_to_pending_review, add_issue_comment, create_branch,
       create_or_update_file, delete_file, merge_pull_request, push_files, ...)
```

44 tools advertised, including every destructive one, because nothing asked the server
to be read-only and nothing could. One is callable. That ratio is the argument for
allowlisting rather than filtering, made by a real server rather than by assertion.

**The subset stays a subset.** POST for every message; both content types accepted
because the server chooses which to answer with; `Mcp-Session-Id` carried once
assigned; re-initialize on a 404. No client→server GET stream (we handle no
server-initiated requests), no resumability, no cancellation, and **no OAuth** — that
is a per-user consent flow, so it belongs with the access layer, and servers requiring
it cannot be used yet.

Verified against GitHub's hosted endpoint, and the interesting part is what the server
chose: it answers every request with `text/event-stream`, never `application/json`. A
client that had treated SSE as the optional half would not have worked at all.

A connector's manifest names the environment variable its credential lives in, and
that is deliberate rather than convenient. A map in `credentials.py` keyed by connector
id could only answer for connectors somebody had edited that file for, so every new one
would authenticate as nobody — which is exactly what the first real run did, with a
401. A connector admin already supplies `StdioLaunch.command`, which the platform
executes; naming an environment variable grants strictly less. The platform's own
secrets are refused regardless.

### Ambiguous writes

A write that reaches an external system and never answers may or may not have taken
effect. From inside the process that looks identical to a write that never left — and
the two call for opposite responses. One is safe to retry; the other is how one
comment becomes five.

So the transport records which it was. Failing to write to a pipe is a different event
from writing successfully and hearing nothing, and it is knowable at the moment it
happens and unreconstructable afterwards:

| | the model is told | audited as |
| --- | --- | --- |
| never delivered | "nothing happened" | `error` |
| delivered, no reply | "this MAY have taken effect; do not repeat it" | `unknown` |

`unknown` only applies to writes — an unanswered read changed nothing either way. It
is its own outcome in the audit log and on the door log because it is the one outcome
that needs a person: nobody can tell from here whether the thing happened.

Any tool may claim this, not just MCP ones — a hand-written HTTP POST that times out
has exactly the same problem. It sets `may_have_completed` on its error result and
the broker does the rest.

**Over HTTP there are more ways to be ambiguous**, and this table is the whole of the
mapping. Getting a row wrong does not fail loudly — it silently turns "this might have
happened" into "this definitely did not", which is the one lie the audit log must never
tell.

| What happened | delivered | Why |
| --- | --- | --- |
| DNS failure, connection refused, TLS failure | no | Never reached the server. |
| Timeout before the request was written | no | Same. |
| Read timeout after it was written | **yes** | It is on the wire. The server may be acting on it. |
| 5xx | **yes** | It reached the server; partial processing is possible. |
| 4xx | no | Rejected before dispatch. The tool did not run. |
| 404 for an expired session | no | The server does not know the session, so it cannot have executed under it. |
| **SSE stream drops before the response** | **yes** | The spec says explicitly this is not cancellation. Maximally ambiguous. |

Two of those are load-bearing in opposite directions. The **404** row is what makes
re-initializing and retrying once safe — even for a write, because nothing ran. The
**dropped stream** row is why such a retry is never automatic: there, the server may
well still be working.

The bias where it is genuinely unclear — a connection that broke for reasons the client
cannot classify — is **say delivered**. A false "delivered" costs a person a glance at a
run that was fine; a false "not delivered" costs the truth. But the common cases are
mapped exactly rather than biased, because if every outage produced ambiguous writes
then `unknown` would stop meaning anything, and it is valuable precisely because it is
rare.

### Read-only mode is derived, never written down

A server's read-only switch is defence in depth — the allowlist decides which tools
exist — but as a constant it drifts. Vet a write and someone has to remember to turn
it off; remove that write later and nobody remembers to turn it back on. Either way
the flag stops describing intent while still looking like it does.

So `Connector.read_only` is computed from the vetted effects, and the shipped connector
demonstrates the mechanism in both directions. While only reads were vetted, GitHub's
server was launched read-only and did not advertise `issue_write`, `add_issue_comment`
or `sub_issue_write` at all — 6 tools instead of 9. Vetting `add_issue_comment` took
the mode off **by itself**, with no flag to remember; un-vet it and read-only comes
back the same way, for exactly as long as no write is vetted.

That is the property: nobody ever edits the switch, so it cannot describe an intent
that stopped being true.

This survived the move to a database, which is where the argument for deriving it gets
tested rather than asserted: there is **no `read_only` column**, the storage layer
refuses a manifest carrying one rather than dropping it quietly, and the value is
recomputed when a row becomes a `Connector`. Two tenants vetting the same server
differently get different modes, from the same code, with nothing written down.

### Two registries

| | |
| --- | --- |
| `get(name, tenant)` | tools callable right now. Hand-written always; connector tools once bound for that tenant. |
| `known_names(tenant)` | every name that tenant recognises, including vetted-but-unconnected. |

Agent configs validate against `known_names`, so granting an MCP tool is checked when
the config is saved rather than failing at the first run. The broker looks in `get`.
Both fail closed, and both are tenant-scoped — a tenant that has vetted nothing knows
only the hand-written tools, which is where every new customer starts.

Agent validation also cross-checks reach against capability in both directions: a
granted tool whose resource type has no grant at its effect (every call would be
denied), and a grant no granted tool can use (a leftover, or the visible half of a
misspelling). Resource types are bare strings with no registry, so `github.repos` for
`github.repo` is a policy that denies everything — safe, and baffling at 3am.

**Descriptors are validated whenever a `Tool` is built** — at import for hand-written
tools, at bind time for connector ones — because each failure is a policy that would
look enforced in review and not be:

- A `Resource` naming an argument the schema lacks — a constraint that can never fire.
- A resource composed from several arguments with no template — joining values into an
  identifier without a stated shape is a guess.
- A template naming an argument the resource doesn't declare, or ignoring one it does.
- A `write` tool declaring no resources — unscopeable by construction.
- An `effect` that isn't `read` or `write`.
- An agent granting a tool name that isn't registered, or a malformed scope pattern.

The first rule was written for hand-authored tools, where such a failure is a typo.
Against an MCP server it does more: it is what catches a connector renaming `repo` to
`repository` in a later version and silently unhooking our scoping from the argument
it was written against.

These run at **bind** time and not earlier, and they have to: checking a `Resource`
against the schema it names requires the server's advertisement, which does not exist
until something connects. Saving a connector validates what *is* knowable without a
server — legal tool names, no duplicates, no collision with a hand-written tool — and
the rest waits for the advertisement it is checked against.

### Coverage

1313 tests by default; 1677 with a Postgres DSN set; and 225 in `frontend/` via
`npm test`. The weight is on
`tests/test_patterns.py` (the matcher, including the prefix-confusion set),
`tests/test_permissions.py` (capability, reach, per-effect grants, composed
identifiers, caller substitution), and `tests/test_mcp.py` (the protocol subset, result
normalization, and — carrying most of the weight — the allowlist).
`tests/test_tenancy.py` covers where the tenant lives and the cross-tenant leak the
per-tenant registry closes; `tests/test_storage_contract.py` runs one set of assertions
against both storage implementations; `tests/test_agents.py` covers validation at write
time and load time; `tests/test_transport_http.py` covers the delivered/ambiguity
mapping above, one test per row. `tests/test_limits.py` covers each budget dial and the ordering
rules above; `tests/test_tools.py` covers descriptor validation;
`tests/test_credentials.py` covers the lookup key, the injected-kwarg contract and the
three outcomes of the delegated read path;
`tests/test_broker.py` covers enforcement, redaction, principal, run correlation, and
the size cap; `tests/test_runtimes.py` covers tier dispatch and the turn limit.

Three carry the credentials step, and the weight in each is on a refusal rather than on
the feature. `tests/test_crypto.py` is mostly about what must *not* decrypt — a row moved
to another user, tenant or connector; a flipped byte; an unknown key — plus the refusal
to start without one and the refusal to invent one. `tests/test_connections.py` covers
the write half: sealed before it is a row, nothing returning it afterwards, reconnecting
replacing rather than accumulating. `tests/test_delegation.py` is the separation
property, and it is the file to read first — its central test failed against the code as
it stood, with one user's call going out under another user's credential.

`tests/test_groups.py` carries the groups step, and its weight is on the two things
somebody would quietly undo: that a group cannot hold a credential, own a run or appear in
an audit record, and that `core/permissions.py` still does not know what a user — or a
group — is, asserted by reading its source. Both are also constrained in migration 017,
because a test written in the same language as a constant does not survive somebody
widening the constant. `test_the_permission_check_is_one_statement` in the contract suite
counts the store's round trips against real Postgres with a person in a group holding
grants on fifty agents; it was mutation-checked, and breaking it the obvious way fails
with "the permission check took 2 round trips".

Two carry the API step. `tests/test_api.py` covers the entry point — the `def`-not-`async`
rule, asserted by walking the route table; that no route accepts a tenant from the
caller; the error table one test per row; and the dev-auth hole, asserted **because** it
is a hole, so closing it is a test change somebody makes on purpose.
`tests/test_concurrency.py` drives real threads through the real objects, and its first
test is the one the step exists for: eight threads, one pooled session, and every reply
reaching the caller that asked for it.

`tests/test_roles.py` carries platform roles, and its weight is on one assertion:
`test_holding_admin_grants_access_to_no_agent_run_or_connection`. **An admin is not a
superuser** — the ladder still answers who may use an agent, `for_connector` still answers
whose credential a call acts with, and a role row changes neither. The argument is step
7b's, one level up: delegated credentials exist so that no operator holds everybody's
tokens, and an `admin` that implied agent access would rebuild that operator under a new
name. Two more are about rules that fail *silently* rather than loudly:
`test_every_admin_route_carries_the_dependency` walks the route table against a written-down
list, because an administrative route missing its dependency **works** — for the wrong
person; and `test_http_can_never_mint_a_system_principal` pins the precondition the
always-admin rule for `system` rests on.

**And one property no test can hold**, which is why the route-table walk exists rather
than being decoration: on the group routes the dependency is *redundant* with
`access/groups.py`'s own `require_admin`, so removing either one alone changes no
observable behaviour. Only `GET /admin-audit` — which reads storage directly — fails
visibly without it. Driving the product cannot tell you the dependency is still on a
group route; walking the route table can.

The suite makes no network calls, starts no subprocess, and **connects to no
database** — every MCP test drives a fake transport, and storage is in-memory. Set
`CARNET_TEST_DSN` to run the storage contract against real Postgres as well:

```bash
CARNET_TEST_DSN=postgresql://localhost/carnet_test pytest -q
```

That database is **dropped and rebuilt at the start of the session**, so point it at a
throwaway. It has to be rebuilt rather than cleaned between tests, because the audit
table refuses DELETE by design.

`frontend/` has a suite as of 10b, and it exists because of two bugs rather than a
policy. `src/lib/api.test.ts` asserts the **URLs the app puts on the wire** — the class
of assertion that would have caught the dev proxy claiming `/agents` and `/runs`, paths
the app also owns, so a *reload* returned the API's 401 JSON where the app should be.
`src/features/agents/AgentDetailPage.test.tsx` asserts the permissions screen says which
tools write, and the singular sentence that shipped reading "One tool that alter a
system". Both were mutation-checked by reintroducing the original bug.

`jsdom` is pinned to `^26`: version 30 needs Node ≥ 22, and on 20 the suite does not
fail, it fails to *collect*, with `ERR_REQUIRE_ESM` from a transitive dependency. CI
pins Node 22 so it is not the more permissive of the two.

`src/lib/auth.test.ts` drives the real `silentSignIn` on fake timers, because what it
asserts is *when* it gives up: a provider refusing `prompt=none` answers with a page
rather than a redirect, so nothing posts back and the wait used to run to the 20s
timeout. Getting that file stable took one real fix — `authorizeUrl` awaits a genuine
`crypto.subtle.digest`, which fake timers do not control, so the tests raced the module
and the *failure count varied run to run*. The harness now waits for the iframe to be in
the document before driving it.

That was the suite at 10b; it has grown with every screen since, has lint since 035m,
and CI drives the built app through a real browser since 035j.

## Response size cap

Every tool response is measured after execution and before it reaches the model.
Over the limit, the payload is **discarded** and replaced with an error stating the
size and the ceiling.

- Default `config.MAX_RESPONSE_BYTES` = 64 KiB; `Tool.max_response_bytes` overrides
  per tool.
- Enforced in the broker, never in a tool — a cap inside an implementation would only
  protect tools we wrote, which is the opposite of the point once MCP-backed tools
  arrive.
- **Refused, not truncated.** A clipped JSON payload is malformed JSON the model has
  to guess at; a clean refusal is something it can act on by narrowing its request.
- Sizes are logged even when they pass (`response_bytes`), so future caps can be set
  from data rather than guessed. For reference, 12 GitHub issues serialize to ~2.7 KB.

This is a security control, not a performance one: unbounded tool output is how
injected instructions reach the model from content an agent reads.

## What bounds a call, and what an agent's `limits` block does here

The broker consumes a `Spending` at step 2 of every call — it checks a ceiling and, on
success, consumes against it. **There is one implementation, and it is the door's.**

**`TokenBudget` is what a door call gets**, and it is the ceiling that is real here: per
token, per UTC day, counted in Postgres so it holds across replicas. Three environment
variables, and the next section is about them — see **A daily allowance**. It ignores
which tool was called, deliberately: a door caller makes one call per request under its
own credential, so the dial that matters is how much that credential may spend in total.

**There was a second implementation, `Budget`, and step 084 deleted it.** It counted four
per-run dials — `max_calls`, `max_calls_per_tool`, `max_writes`, `max_response_bytes` —
overridable per agent by a `limits` block, and *nothing in this tree ever constructed
one*: its only caller was `RunContext.start`, which belonged to the model loop step 078
deleted. Correct code that enforced nothing is worse than absent code, because somebody
greps for where a ceiling is applied and finds it. So on this deployment:

```python
"limits": {"max_writes": 0}     # accepted, validated, stored — and read by nothing
```

An agent's `limits` block is still checked when it is written — an unknown key or a
negative number is refused, with a sentence — and still stored untouched through an edit,
because a config written for a tree that *does* run agents must stay valid and stay
intact. The four key names live in `agents.KNOWN_LIMITS` now, which is the whole of what
084 kept: a vocabulary, so a typo is refused rather than stored as a ceiling nobody can
read back. It bounds nothing at the door. The agent's own page says so, under **Stored,
and not read here**; step 081 removed the controls that used to author it, because a tick
box promising *every write is refused before it reaches a system* over a dial nothing
reads is worse than no tick box.

The ordering is still load-bearing for whoever builds the second implementation, and
`TokenBudget` follows it:

- **The budget runs after the permission check**, so a call refused on scope costs
  nothing. A denial must not push a caller toward exhaustion.
- **Counters are consumed before execution**, because the point is to bound calls that
  reach an external system, and a call that fails still hit it.
- **Money is checked before the call count**, because the count *consumes*: checking it
  first would charge a call to a caller about to be refused for spend.

Two ceilings do still apply to every brokered call and are not part of any of this: the
per-response size cap above (`MAX_RESPONSE_BYTES`, and a tool's own lower one), and the
egress rules on what a connector may dial.

## A daily allowance

Two ceilings at the door, both per token, both counted in Postgres so they are the same
ceiling however many API replicas serve:

```
CARNET_MCP_CALLS_PER_DAY=1000      # calls one token may make in a UTC day
CARNET_MCP_USD_PER_DAY=300         # what one token may spend at a brokered model
CARNET_MCP_TOKENS_PER_DAY=50000000 # the net underneath it
```

The spend dials exist because a brokered call may reach a model (045c) and the
connector reports what it cost; an unpriced model costs `$0.00` against the dollar
ceiling, so the token ceiling is the net that catches it. Whichever is met first
refuses, with a sentence naming the figure and the dial. A refused call spends nothing.
The **Overview** renders the door's traffic, spend and refusals for an administrator,
and every token's own page shows what it has spent against its allowance.

## Credentials

`core/credentials.py` is the only module that reads secrets. The broker fetches them
*after* authorizing a call and injects them as keyword-only arguments the tool schema
does not contain. They never appear in the agent config, the tool arguments, the
model's context, or the audit log.

Channels map to *per-channel* webhook URLs, making the lookup a second enforcement
point: a channel with no mapping has no secret to send with.

Lookups are keyed by **(tool, principal)**, because there are two kinds of credential
and only one is a property of the tool alone:

| Kind | Example | Varies by caller? |
| --- | --- | --- |
| **shared** | the `#eng` webhook — one organisational secret | no |
| **delegated** | each user connects their own account; the vendor enforces what it can see | yes |

A ticket agent run by two people must reach two different sets of tickets, and no
policy of ours produces that — it is the credential that differs. The principal sat in
that signature for four steps before anything read it, so that delegation would be a
lookup rather than a change to this signature, the broker's call site and every
connector at once.

### Delegated credentials: the agent acts on *your* data

Each person connects their own account. The credential is encrypted at rest and
decrypted only at the moment a tool call has already been authorized.

```bash
carnet --connect-account github-remote priya@acme.com --label "@priya-acme"
carnet --list-connections          # who is connected, and as whom
carnet --disconnect-account github-remote priya@acme.com
```

**The credential is never an argument.** It arrives on a hidden prompt, or piped —
because a token in `argv` is a token in shell history and in the process table, on the
one command whose entire subject is a secret.

```bash
echo "$TOKEN" | carnet --connect-account github-remote priya@acme.com
```

### …and, as of step 7b, the credential a person gives themselves

Every command above is one an **operator** runs, which means the operator obtains and
sees each person's third-party token — precisely the thing delegated credentials exist to
avoid. The agent is meant to act as Priya rather than as the operator, and until 7b the
only way to arrange that required the operator to hold Priya's secret.

An administrator configures the consent flow once per connector:

```bash
carnet --allow-host auth.atlassian.com               # the TOKEN endpoint's host
carnet --set-oauth jira \
    --auth-server https://auth.atlassian.com \
    --client-id <id> \
    --scope read:jira-work --scope offline_access      # offline_access → a refresh token
# reads the client secret from a hidden prompt, or piped. Never from argv.
```

and then it is self-serve. A person opens **Connections**, clicks Connect, approves at
*Atlassian's* consent screen, and lands back on a row that says `Connected as
priya@acme.com` — a label the provider supplied rather than one anybody typed.

```
browser: click Connect Jira
   │  an authenticated API call, so we know whose connection this is
   ▼
POST /connectors/jira/connect   → mint `state`, return the provider's authorize URL
   │  a TOP-LEVEL navigation, not a fetch
   ▼
Atlassian's consent screen → approve
   │  Atlassian redirects the browser to us
   ▼
GET /connect/callback?code=…&state=…   ← a plain navigation, NO bearer token on it
   │  look up `state` → the principal, the connector, the PKCE verifier
   │  POST the token endpoint (client secret + PKCE) → access + refresh
   │  connect_account(...)                            ← 7a's function, unchanged
   ▼
browser lands on "jira is connected"   ← and never saw a token
```

**The token never touches the browser**, which is the decision the whole shape follows
from. Login's token is for us and the SPA holds it to call our own API; a connector token
is for *Atlassian* and is used server-side, so a browser holding it is an exfiltration
surface for zero benefit.

**The callback trusts `state`, not the request**, which is the security crux. A
provider's redirect is a top-level navigation carrying no bearer token, so "whose
connection is this" cannot come from the request — it rides in an opaque, single-use,
short-lived row minted while the person *was* authenticated. That is also the CSRF
defence: a `state` we never issued finds nothing, and a replayed one finds nothing
because the row is consumed atomically.

**The access token is refreshed before each run that needs it.** Without that, a
connection dies in about an hour and the person re-consents hourly — a consent flow whose
output expires before anybody notices it worked. Most providers *rotate* refresh tokens
and invalidate the old one on every use, so two runs refreshing at once is a lost update
that stores a token the provider has already killed and breaks the connection permanently
with nothing saying why. Two mechanisms: a compare-and-set on the row's own version, and
a single-flight lock so eight concurrent runs make **one** token-endpoint call rather
than eight. A refresh that loses the race re-reads and uses the winner's token; it never
retries the exchange, because the token it holds is spent and reuse is what trips a
provider's breach detection.

A `400 invalid_grant` is terminal: the connection is marked as needing re-consent, the
person is told in the provider's own words, and the run is refused rather than falling
back to the shared credential — which would mean the agent acting as the *operator* while
the log reported it as them.

**Disconnecting revokes upstream, and deletes locally regardless.** Deleting our row
alone leaves a live token at the provider; for an OAuth connection RFC 7009 gives us a
revocation endpoint and having obtained the token on somebody's behalf we are the right
party to hand it back. Revoke *then* delete, because delete-then-revoke loses the token
needed to revoke — and the delete is unconditional, because a provider that is down must
not leave somebody unable to end a connection they have asked to end. Whether revocation
succeeded is reported and recorded, so *"is that token still live at Atlassian"* has an
answer.

What 7b deliberately does **not** change: `--connect-account` still works on an
OAuth-configured connector and writes a `static` row. A person with a personal access
token should not be blocked because an administrator later added a consent flow, and
refusing would make configuring OAuth a destructive act for everyone already connected.

Three outcomes at read time, and the third is the reason this is written out rather
than being a one-line lookup:

```
for_connector(connector, principal, env_var)
        │
        ├─ no row                      ──►  the environment variable, exactly as before
        ├─ a row that decrypts         ──►  that person's own credential
        └─ a row that will not decrypt ──►  raise. Never the environment variable.
```

Falling back on the third would mean the agent acting as the **operator** while the
person believes it is acting as them — reaching data they have no access to, and
attributing it to them in a log kept forever. A broken credential has to look broken.
An expired row gets its own message, which is why `connections.expires_at` is nullable
rather than absent: never connected and connected-but-expired send a person to two
different places.

#### The key

**AES-256-GCM, and the key is supplied or the process refuses to start.** It is never
auto-generated. A key that regenerates makes every stored credential silently
unreadable — not at write time, not at boot, but the first time somebody's agent runs,
on a row that looks perfectly fine.

```bash
carnet --generate-key            # prints one; storing it is your job
export CARNET_SECRET_KEY=<key>
```

Required whenever there is a durable store, and by the HTTP server regardless. Without
a database the store is a dict that dies with the process, so no connection can
pre-exist or outlive it and a key would protect nothing — which is what keeps the
property that a fresh clone runs an agent with nothing installed and nothing running.

**The ciphertext is bound to its row.** GCM authenticates additional data for free, so
encrypting against `(tenant, principal, connector)` means a row lifted into another
user's row — or another tenant's — *fails to decrypt* rather than working. The database
cannot express that; a primary key stops two rows colliding and has no opinion about a
value moved between them. It is the cheapest cross-tenant defence available in a system
whose stated known limit is that tenant isolation is enforced by the application.

That binding is length-prefixed rather than joined on a separator, because
`"|".join(parts)` lets two different rows produce one string as soon as a value can
contain the separator. Free to prevent now, and impossible to fix later without
re-encrypting every row.

**`key_id` is derived from the key, never assigned** — the same argument as
`Connector.read_only` being derived: a value somebody maintains by hand is free to stop
being true. Rotation is therefore a list: `CARNET_SECRET_KEY` encrypts,
`CARNET_SECRET_KEYS_OLD` is a comma-separated decrypt-only set, and each row says
which key it still needs.

`core/crypto.py` is the only module that holds a key, the same containment
`credentials.py` has for secrets. The interface is seal/open rather than "give me the
key bytes", because with a KMS the key never leaves the service — an interface handing
out keys would have foreclosed the upgrade it exists to allow. `tenant_id` is a
parameter on both operations for the same shape-before-the-thing reason `principal` was:
every tenant resolves to the same key today, and per-customer keys later are a new class
rather than a re-encryption of every row.

#### Where this cannot be used

**A stdio connector cannot carry a per-user credential, and says so.** It takes its
credential from the environment at launch and holds it for the process's life, so one
server cannot act as two people. A `connections` row for one is refused at connect time,
loudly — ignoring it and using the environment variable would be the same untruth as the
third outcome above, arriving by a different route. The check lives in `tools/mcp`, where
the transport is known; `core/credentials.py` is told a variable *name* and deliberately
never learns what an MCP server is.

The shipped GitHub connector is stdio, so delegation there needs the one-row switch to
the hosted HTTP endpoint.

#### Two people, two sessions

The session pool is keyed `(tenant, connector, credential-fingerprint)`, which
anticipated this — two users never share a session bound with somebody else's token.

What did **not** survive contact was `ensure_available`. Binding is a fact about a
*tenant's* vetting; a session is a fact about the *caller's* credential, and the two were
welded together: once anybody had run an agent its tools were registered, so the check
"are the tools bound?" returned early and the second user of the day never got a session
at all. Their calls then fell through to a proxy fallback that borrowed whichever session
was to hand — the first user's. Priya connects her own account, runs the agent, and
reaches Sam's data because Sam ran it first that morning. No error, and the audit record
says Priya.

Both halves are fixed: a session is ensured for every run's credential, and a missing
session is **created under the right credential, never borrowed**. That is what makes
the pool cap and the idle TTL latency decisions rather than correctness ones.
`tests/test_delegation.py` asserts the separation rather than the fix.

A connector's credential is keyed by **connector, not tool** — one GitHub token serves
every GitHub tool, so keying by tool would be twenty copies of one fact. The broker
passes `tool.connector` so `credentials.py` never learns what an MCP server is.

**Where the vendor's enforcement stops.** Once a delegated credential is in play it's
tempting to think the vendor is doing the security. It isn't doing *ours*. A user's
token is strictly more powerful than the agent should be — she can see fifty repos;
the agent may touch one. Two bounds, neither substituting for the other:

- the vendor bounds what **the user** can reach
- our grants bound what **the agent** may reach on that user's behalf

## Chat delivery

`post_message` picks its transport from the webhook URL shape, so the same tool and
the same permission model work for all three:

| Backend | Setup | Env var |
| --- | --- | --- |
| **Local outbox** (default) | none | none — appends to `var/outbox.jsonl` |
| **Discord** | create a channel webhook (~1 min) | `WEBHOOK_URL_ENG` |
| **Slack** | create an incoming webhook | `WEBHOOK_URL_ENG` |

```bash
export WEBHOOK_URL_ENG="https://discord.com/api/webhooks/..."
```

That's the only change — no code edit. Add channels in `CHANNEL_WEBHOOK_ENV`
(`core/credentials.py`) and grant them in an agent's permissions.

## Audit log

One row per brokered call — allowed, denied, or failed. Denials are the most important
records, so they're never skipped.

```json
{"v":6,"ts":"2026-08-02T20:08:23.074+00:00","tenant_id":"default",
 "run_id":"e1ddbff6585d",
 "principal_kind":"system","principal_id":"cli",
 "agent":"issue-reporter","tool":"post_message","effect":"write",
 "args":{"channel":"#eng","text":"sha256:d3872206522a (len=2147)"},
 "decision":"allow","reason":"","outcome":"ok","credential":"shared",
 "duration_ms":0,"response_bytes":147}
```

`credential` is `delegated`, `shared`, or absent when the tool needed no secret or
nothing ran. It was added **with** delegated credentials rather than after, and the
reason is the whole argument for having a schema version at all: a record says who a run
acted *for* and said nothing about whose credential it *used*. Those two facts could not
disagree while there was one credential and it was the operator's. They disagree the
moment delegation ships — somebody with no connection falls back to the environment
variable, and the record reads as though the call went out as them. Whoever audits that
write six months later is wrong about the account it was made from, and the account is
what decides what the write could reach.

Deliberately *which kind*, never *whose*. A second person's identifier in a table that
is append-only by trigger, with retention still undesigned, to answer a question
`principal_id` mostly answers already — what was missing is the one bit that column
cannot carry: whether those two are the same person.

`run_id` is the correlation id, `door-<hex>` for a door call — without it you can only
ask "what did this agent ever do?", never "what happened in that one call?". The column
is named for a runtime this tree no longer has; the name stays because released
migrations are immutable. `outcome` is one of `ok`,
`error`, `oversize`, `unknown`, or empty when the call was denied and nothing ran. `effect` makes
"show me every write last quarter" a filter rather than an archaeology project. `v` is
the schema version — present from the first record, which is what made the move to
Postgres a filter on a field rather than a guess from which keys exist. It is now `6`;
`5` marked `tenant_id` and `6` marks `credential`.

The table is **append-only** and enforced as such; see the schema section above.

Redaction is two-layered: the tool's own `redact_args` hashes free text, and
credential-shaped names are hashed *always* — a denied call is still logged, and a
smuggled secret must not land in a log we keep forever. Policy-relevant arguments
(`repo`, `channel`) are stored in the clear; they're the point of the log.

`audit.py` depends on nothing but `config`, `credentials` and `storage` — the per-tool
policy is passed in by the broker, so audit has no knowledge of the tool registry.
That is what made swapping the JSONL writer for a database a change to this one file,
and `audit_query.py` — deliberately built as its reading half — a change to one more.

## Adding a tool

Everything about a tool lives on one `Tool` object in one module — schema, impl, and
redaction policy — so a tool can't half-exist.

1. In `tools/<family>.py`, write the function and append a `Tool(...)` to `TOOLS`.
   Credentials arrive as keyword-only args; never read `os.environ` in a tool.
2. Declare its descriptor: `effect` (`read`/`write`) and `resources`, a list of
   `Resource(type, args, template=None)`. Validated at import.
3. New family? Add one import line to `tools/__init__.py`.
4. Needs a secret? Add the lookup to `core/credentials.for_tool`.
5. Returns unusually large or unusually untrusted output? Set `max_response_bytes`.
6. Grant it in an agent's `permissions` — add the name to `tools`, and the resource
   type to `scope` if it declares one.

New *constraint kinds* (regex, numeric ceiling, time window) go in
`core/permissions._check_resource`, which is shaped to accept them; the broker doesn't
change.

## Adding an agent

`agents.save(tenant_id, config)`. It validates first, so an invalid config never
becomes a row, and the errors are the ones a person has to read at 3am.

A config's `name` is the key it is stored under — the broker trusts it as identity, so
a mismatch would misattribute audit records. Enforced by a `CHECK` constraint as well
as by the loader.

`bootstrap.py` carries the shipped example — a permission list granting two tools with
a scope each. It is what `--seed` writes, and it is the worked example of a real grant.

