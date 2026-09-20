#!/usr/bin/env bash
# The `red` job's decision, as a file something can run. Step 110 decision 12, extracted
# in the pass after 110f.
#
# It lived inline in `tests.yml`, where nothing could execute it: the one part of the
# gate that reports on the gate was the one part the gate did not test, and a notifier
# nobody has seen fire is a notifier nobody should trust. Here it is a script, driven by
# environment variables and reaching GitHub only through `gh`, which is what lets
# `backend/tests/test_workflows.py` run it against a stub and check every branch — that
# it opens an issue when none is open, adds to the open one when there is one, names only
# the jobs that did not pass, and puts the ref and the commit in the title.
#
# What it still cannot prove is that GitHub runs it: `if: failure() && …` is the
# workflow's condition, not this script's, and the only proof of that is a real red run
# on `main` or a tag — which has not happened yet, and is a known gap rather than an
# oversight.
#
#   NEEDS    the `needs` context as JSON — {"job": {"result": "failure"}, …}
#   RUN_URL  where the run is
#   EVENT    push, schedule, workflow_dispatch
#   GITHUB_REF_NAME / GITHUB_SHA / GITHUB_SERVER_URL / GITHUB_REPOSITORY  as GitHub sets them
set -euo pipefail

short="${GITHUB_SHA::7}"
title="CI is red on ${GITHUB_REF_NAME} at ${short}"

# Only the jobs that did not pass. `success` is excluded rather than `failure` selected,
# so a job that was cancelled or skipped is named too — a gate that half-ran is not a
# gate that passed, and the reader needs to know which half.
failed="$(printf '%s' "$NEEDS" | jq -r '
  to_entries[] | select(.value.result != "success")
  | "- `\(.key)`: \(.value.result)"')"

body="$(cat <<EOF
The \`tests\` workflow went red on \`${GITHUB_REF_NAME}\` at ${short}, on a \`${EVENT}\` run.

Run: ${RUN_URL}
Commit: ${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/commit/${GITHUB_SHA}

Jobs that did not pass:
${failed}

Opened by the \`red\` job in \`.github/workflows/tests.yml\` (step 110, decision 12). Close it when the gate is green again; while it is open, later red runs are added here as comments rather than as new issues.
EOF
)"

# The label is how "the open one" is found. `--force` makes this idempotent rather than a
# failure on the second run.
gh label create ci-red --color B60205 --force \
  --description "the tests workflow is red on main or a tag; opened by the workflow itself"

existing="$(gh issue list --label ci-red --state open --limit 1 --json number --jq '.[0].number // empty')"
if [ -n "$existing" ]; then
  echo "adding to open issue #${existing}"
  gh issue comment "$existing" --body "$body"
else
  echo "opening a new issue"
  gh issue create --title "$title" --label ci-red --body "$body"
fi
