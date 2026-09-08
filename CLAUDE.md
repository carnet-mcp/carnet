# Carnet — read this first

## The premise, in full: [docs/PREMISE.md](docs/PREMISE.md)

Read it before planning anything. The short version is below, and the short version has
been enough to get it wrong before.

## Carnet is an MCP tool

People connect their own assistant to `/mcp`, and every tool call goes through our broker
— scoped per caller, under a credential they never hold, revocable, metered, audited.
**That is the product.**

**Tool mode is the only mode.** `tools/list` returns what a token may call; `tools/call`
runs one through the broker. **Agent mode — an agent exposed as one MCP tool — is
withdrawn permanently.** It was never built — there is no flag, no branch and no dead
code path; the whole footprint was forward-looking sentences. One survives, in a comment
in migration `040`, and it stays because released migrations are checksummed and a
comment is not worth a broken deployment. It is a stale promise, not a roadmap item.

## Two things not to get wrong

**1. "Agent" means a permission list.** A named set of tools, each with a scope, plus
limits. It is what a token is granted and how the door decides what an assistant may
touch. `door._granted_agents` reads it on every door call, uncached, on purpose. Agents
cannot be removed — remove them and the door has no scoping and every token becomes
all-or-nothing.

**2. A door call is not a run.** It writes **no `runs` row** — one `audit` row with a
`door-<hex>` correlation id. Nothing in this tree writes a `runs` row; anything reading
one is measuring nothing. Usage, adoption and governance read `audit` filtered `run_id LIKE 'door-%'`
(`storage.DOOR_CALL_ID_PREFIX`). A customer making ten thousand door calls a week has an
empty `runs` table. This has been got wrong once already, and it cost a rewrite.

## There is no runtime in this tree

Carnet used to carry a bench — a queue, workers, a model loop, schedules, triggers and
their screens — for trying an agent before wiring it up elsewhere. **Step 078 deleted
it from this tree.** Do not add a way to execute an agent here; new capability goes to
the door. The `runs`, `schedules`, `triggers` and `files` tables still exist because
released migrations are immutable; nothing reads them.

## House rules that bind edits

- **[`docs/PREMISE.md`](docs/PREMISE.md) outranks every other document here**, this one
  included. Where a docstring, a comment or the README disagrees with it, the premise is
  right and the other is out of date.
- **Released migrations are immutable.** They are checksummed and the runner refuses a
  database whose hashes moved. Add a new numbered migration instead.
- **Write the reasoning before the code**, then the code, then an edge-case pass. The two
  parts worth the most are what you deliberately left undone and what you know is still
  wrong; both belong in the pull request, and a reviewer reads them before the diff.
- **A docstring here carries the argument, not just the description.** Most of the
  reasoning in this tree lives beside the code it explains, and that is deliberate —
  when you change what a function does, the paragraph above it is part of the change.

## Layout, and the layering rule

`backend/src/carnet/` — `api/` and `cli.py` are entry points; `door.py` is the MCP door;
`core/` holds the broker, permissions and credentials and knows no tool and no agent;
`tools/` knows no agent and no policy; `storage/` is rows in, rows out. Each layer imports
downward, never upward. `frontend/` is React 19 + Vite with **no UI library, no CSS
framework and no charting dependency** — hand-written CSS over a design-token layer, and
that has been declined on purpose more than once.
