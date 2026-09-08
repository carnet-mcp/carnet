# Contributing

Read [`docs/PREMISE.md`](docs/PREMISE.md) first. It outranks every other document here,
including this one, and it exists because the thing this project is has been got wrong
before — by people who had read the README.

The short version: **Carnet is an MCP tool.** People connect their own assistant to
`/mcp` and every call goes through a broker — scoped per caller, under a credential they
never hold, revocable, metered, audited. It does not run agents. There is no runtime in
this tree.

## Sign your commits — the DCO

This project uses the [Developer Certificate of Origin](DCO), version 1.1. There is no
CLA and nothing to sign up for. You certify the DCO by adding a line to each commit
message:

```
Signed-off-by: Jane Doe <jane@example.com>
```

`git commit -s` adds it for you, using your configured `user.name` and `user.email`. The
name must be a real one you can be reached at — that is the whole content of the
certification.

A [CI job](.github/workflows/dco.yml) checks every commit in a pull request and names the
one that is missing it. To fix a branch you have already written:

```bash
git rebase --signoff main      # or the branch you are targeting
git push --force-with-lease
```

## The invariants, and the tests that already hold them

The rules here are unusually enforceable, so most of this section is a pointer to the
test that will tell you before a reviewer does.

| Rule | What holds it |
| --- | --- |
| **Imports go downward only.** `api/` and `cli.py` are entry points, `door.py` is the MCP door, `core/` knows no tool and no agent, `tools/` knows no agent and no policy, `storage/` is rows in and rows out | Read the layout in [`CLAUDE.md`](CLAUDE.md). Not test-enforced in general; the one seam that is, is below |
| **The server never imports the local IdP** | `test_the_server_never_imports_the_local_idp` — it reads the import graph, not a convention |
| **Every endpoint is sync** | `test_every_endpoint_is_sync` walks the live route table |
| **Both stores answer identically** | `tests/test_storage_contract.py` runs the same assertions against the in-memory store and real Postgres. A behaviour only one of them has is the bug this suite exists to find |
| **A grant is what the door reads** | `tests/test_grants.py`, which reads a module's source rather than trusting a call |
| **A patch that omits a field does not delete it** | `test_a_patch_that_omits_a_field_does_not_delete_it`. The edit path sends only what changed; anything that makes an omission a deletion is a silent data loss |

### The four that no test enforces, and that get broken first

1. **[`docs/PREMISE.md`](docs/PREMISE.md) outranks every other document here.** Where a
   docstring, a comment, this file or the README disagrees with it, the premise is right
   and the other one is out of date — say so in the pull request rather than working
   around it. Two sentences in it prevent most of the mistakes worth preventing: an
   **agent** is a permission list rather than a thing that runs, and **a door call is not
   a run**.

2. **Released migrations are immutable.** They are checksummed, and the runner refuses a
   database whose hashes moved. Changing one that has shipped breaks every existing
   deployment. Add a new numbered migration.

3. **The frontend takes no UI library, no CSS framework and no charting dependency.**
   Hand-written CSS over a design-token layer. This has been declined deliberately more
   than once; a pull request adding one will be closed regardless of its merits.

4. **A door call is not a run.** It writes **no `runs` row** — one `audit` row with a
   `door-<hex>` correlation id. Anything measuring `runs` is measuring nothing. The
   `runs`, `schedules`, `triggers` and `files` tables exist only because released
   migrations are immutable, and nothing reads them.

## Reasoning first, then code

Every change here is made the same way: decide what you are doing and write down why,
then write the code, then go looking for the edges. The two parts worth the most are the
ones people skip — **what you deliberately left undone**, and **what you know is still
wrong**. A known limit you state is a limit; the same limit unstated is a defect somebody
finds later, and by then it is a surprise as well as a defect.

Put that reasoning in the pull request description. The template has a section for each.
For a small fix it is a paragraph, not a ceremony; for anything that moves a boundary —
what the broker admits, what a scope means, what storage promises — it is most of the
work, and a reviewer will ask for it before they read the diff.

## Running the gates

Everything below runs locally with no secrets and no network. CI runs the same things.

```bash
cd backend
.venv/bin/ruff check src tests scripts
.venv/bin/mypy
.venv/bin/python scripts/check_versions.py
.venv/bin/python -m pytest -q                          # the fast suite, in memory
```

The in-memory suite is fast on purpose and that speed is a design constraint. The real
one needs a database:

```bash
CARNET_TEST_DSN=postgresql://postgres:test@localhost:5433/carnet_test \
  .venv/bin/python -m pytest -q
```

**Run long suites in the foreground.** Backgrounded sweeps get memory-killed and look
like hung tests.

The frontend:

```bash
cd frontend
npm run typecheck && npm run lint && npx vitest run && npm run build
```

There are 35 end-to-end scripts in `backend/scripts/`. They put a route in front of a
real database and are the only tests that do; a few of them run in CI and the rest run by
hand. If your change touches the door, the OAuth flow or storage, run the relevant one:

```bash
export CARNET_E2E_PG=postgresql://postgres:test@localhost:5433/postgres
.venv/bin/python scripts/e2e_mcp_door.py        # drives the official MCP SDK
.venv/bin/python scripts/e2e_oauth_door.py
.venv/bin/python scripts/e2e_rls.py
```

## Pull requests

Fill in the template — it asks what the change is, what you ran, and whether a plan
document accompanies it. Every CI job is fork-safe: none of them reads a secret, so a
pull request from a fork gets the same ten green checks a branch does.

Small and focused beats large and complete. A change that needs a paragraph of
justification should have that paragraph in a plan document rather than in the pull
request description, because the plan is what survives.

## Code of conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
