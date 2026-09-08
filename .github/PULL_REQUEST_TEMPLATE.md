<!--
  Read CONTRIBUTING.md if you have not. The three things most likely to send a pull
  request back are not about code style:
    - the change contradicts docs/PREMISE.md, which outranks every other document here
    - a released migration was changed (they are checksummed; add a new numbered one)
    - a UI library, CSS framework or charting dependency was added to frontend/
-->

## What this changes

<!-- One or two sentences. What was wrong or missing, and what it does now. -->

## Why

<!--
  The reasoning. If this changes a boundary — what the broker admits, what a scope
  means, what storage promises — write it out here before the diff, because that is the
  part a reviewer reads first.
-->

## What you ran

<!-- Delete what does not apply. Say what failed, if anything did — a red result you
     name is worth more than a green one you assert. -->

- [ ] `ruff check src tests scripts` and `mypy`
- [ ] `pytest -q` — the fast suite, in memory
- [ ] `pytest -q` with `CARNET_TEST_DSN` set — the storage contract against real Postgres
- [ ] `npm run typecheck && npm run lint && npx vitest run && npm run build`
- [ ] End-to-end scripts, named here:
- [ ] Nothing — this changes documentation only

## Checklist

- [ ] **Every commit is signed off** (`git commit -s`) — see the [DCO](../blob/HEAD/DCO).
      There is no CLA. CI checks this and will name the commit that is missing it.
- [ ] This does not contradict [`docs/PREMISE.md`](../blob/HEAD/docs/PREMISE.md), or it
      says where it does and why.
- [ ] I did not modify a released migration. New behaviour is a new numbered migration.
- [ ] If this adds behaviour, there is a test that fails without it.
- [ ] If this touches storage, both stores answer the same and the contract suite says so.

## Anything left undone

<!--
  The most useful section here, and the one worth writing carefully. What you chose not
  to do and why, and what you know is still wrong. A known limit stated is a limit;
  a known limit omitted is a defect someone finds later.
-->
