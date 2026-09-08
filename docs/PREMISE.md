# What Carnet is

**This document outranks every other document in the repository.** Where anything
disagrees with it — a plan, a docstring, a comment, this repo's own README as it stood
before this was written — this is right and that is out of date. It is maintained, unlike
the step plans, which are historical records and are never edited after the fact.

---

## One sentence

**Carnet is an MCP tool.** People connect their own assistant to `/mcp` and every tool
call it makes goes through our broker — scoped to that caller, under a credential they
never hold, revocable, metered and audited.

That is the product. There is no second product.

## The one mode: tool mode

A caller connects to `/mcp` with a token. `tools/list` returns the tools that token may
call. `tools/call` runs one, through the broker, and writes one audit row.

What this displaces is fifty personal tokens on fifty laptops. Without it, each employee
installs the GitHub MCP server locally under a credential nobody can revoke and nothing
records. With it: one endpoint, per-caller scope, a budget, an audit trail, and a token
that can be revoked without moving the URL.

**Distribution, not capability.** Every call admitted through the door is already
possible in the product's own chat. The door is not a new power. It is the same power,
brokered.

**Governed means routed.** The promise is that every call *routed through the door*
is scoped, metered and audited — and that sentence is the one to sell, because it is
provable in the audit log. The wider sentence — *every call the agent makes* is
governed — is not true and no connector makes it true: an agent on a customer's
machine can dial a vendor directly, and one that can execute code always will be able
to. Making the wider sentence true means running agents inside infrastructure this
platform controls, with egress blocked except through the door; that is registered
future work (DEFERRED.md, the egress-control row), not an implied present capability.
Widening *which kinds of call can be routed* — REST APIs, model calls — is plan 045's
arc and does not change this boundary.

## Agent mode is withdrawn, permanently

Plan 033 named a second mode — **agent mode**, an agent exposed as a single MCP tool
where `tools/call` submits a run and holds for the answer. Four plan documents describe
it as "coming", in nine separate sentences.

**It is not coming. It was never built, and it is now cancelled rather than pending.**

Nothing implements it. There is no flag, no branch, no dead code path — the entire
footprint was forward-looking sentences. Anyone who finds one of those sentences has
found a stale promise, not a roadmap item.

One sentence promising it still exists in this tree, and it is worth knowing why it was
not deleted: `storage/migrations/040_mcp_door.sql` says so in a comment. Released
migrations are checksummed, and a changed hash makes the runner refuse the database — a
comment is not worth a broken deployment for everyone already running one. It is covered
by this document. Every mention that *could* be removed has been.

## The word "agent" means a permission list

This is the sentence most likely to prevent a future mistake, so it gets its own section.

**An agent in Carnet is a named set of tools, each with a scope, plus limits.** It is a
permission bundle. It is what a token is granted, and it is how the door decides what a
connected assistant may touch:

```
token → grants → agents → tools + scope → what /mcp will serve and allow
```

`door._granted_agents` reads every granted agent's config on **every single door call**,
deliberately uncached, because *"a revocation that takes effect in 'up to 30 seconds' is
not a revocation."* 033b's union rule is defined in terms of agents: a token sees the
union of the tools of the agents it is granted, each tool keeping its own agent's scope.

**So agents cannot be removed.** Not "would be expensive to remove" — remove them and the
door has no scoping at all, and every token becomes all-or-nothing. Agents are the
permission model. The word is imperfect and it is load-bearing.

## There is no runtime in this tree

Carnet used to be able to *run* an agent itself — a queue, workers, a model loop,
schedules, triggers and the screens for all of it, kept as a bench for trying an agent
before wiring it up elsewhere. **Step 078 deleted it.** This tree is the door and what
the door scopes by, and nothing in it executes an agent or holds a model key. The
`runs`, `schedules`, `triggers` and `files` tables still exist, because released
migrations are immutable and checksummed; nothing reads them.

## The consequence people get wrong first

**A door call is not a run.** 033b decision 4, and it has teeth:

```
a door call  →  NO runs row   +  ONE audit row, correlation id `door-<hex>`
```

A tool-mode call has no prompt, no config and no version, so a `runs` row would be untrue
about all three — and since step 078 there is nothing that writes one.

**Therefore: anything measuring `runs` is measuring nothing.** Usage, adoption and
governance all read `audit` filtered on `run_id LIKE 'door-%'`
(`storage.DOOR_CALL_ID_PREFIX`). This mistake has already been made once, in the first
draft of plan 041, which built an entire dashboard on `runs`.

## Not the product, stated plainly

- **Not** a platform for building and running autonomous agents. It runs none.
- **Not** an agent marketplace, an orchestration framework, or a workflow engine.
- **Not** a model provider or a gateway to one. The door spends no model tokens at all.

## When this document changes

If the premise moves again — and it has moved twice, on 2026-08-10 and 2026-08-12 — this
file is edited and the date below changes. That is the whole maintenance rule. A premise
nobody can find is how the last two reversals cost as much as they did.

*Last settled: 2026-08-27. Supersedes the framing anywhere else in this repository.*
