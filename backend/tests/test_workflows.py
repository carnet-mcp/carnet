"""The two workflows hold together the way their comments say they do. Step 110.

`tests.yml`'s `red` job is the answer to a gate that went red on 2026-09-10 and was read
by nobody: it runs when any test job has failed on `main` or a tag and opens an issue.
It can only see the jobs listed in its `needs`, and there is no way in that syntax to
say *everything else* — so a job added to the file without being added to that list is
a job whose failure goes unread, which is the defect the job exists for, one level down.
This holds the two lists together, the way `test_capabilities.py` holds the catalogue to
the code: by reading the file rather than remembering it.

`release.yml` publishes a pair since step 110, decision 11, and the pair must be built
from the two targets the compose file names, tagged alike, and both signed. A front
image published under the API's tags, or unsigned, is a worse artefact than none, because
a reader would assume the two are alike.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess

import yaml

REPO = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github" / "workflows"


def load(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def test_red_needs_every_test_job():
    tests = load("tests.yml")
    jobs = tests["jobs"]
    red = jobs["red"]
    test_jobs = sorted(name for name in jobs if name != "red")
    assert sorted(red["needs"]) == test_jobs, (
        "a test job is missing from `red`'s needs, so its failure would open no issue"
    )
    # Only where somebody should hear about it: never on a pull request, where a
    # fork's token could not write an issue and the red is the contributor's to read.
    assert "failure()" in red["if"]
    assert "refs/heads/main" in red["if"] and "refs/tags/v" in red["if"]
    assert "pull_request" not in red["if"]
    # The one write permission in the file, scoped to the one job that needs it. Every
    # test job stays fork-safe by carrying none.
    assert red["permissions"] == {"contents": "read", "issues": "write"}
    for name in test_jobs:
        assert "permissions" not in jobs[name], f"{name} took a permission it did not have"


def test_the_gate_runs_weekly_on_its_own():
    # `on` parses as the boolean True under YAML 1.1, which is what PyYAML speaks.
    on = load("tests.yml")[True]
    assert on["push"]["branches"] == ["main"]
    crons = [entry["cron"] for entry in on["schedule"]]
    assert len(crons) == 1
    minute, hour, dom, month, dow = crons[0].split()
    assert (dom, month) == ("*", "*") and dow != "*", "weekly means one day of the week"


def test_release_publishes_the_pair_alike():
    release = load("release.yml")
    jobs = release["jobs"]
    built = {}
    for name in ("image", "front"):
        steps = {step.get("name"): step for step in jobs[name]["steps"]}
        build = steps["Build and push"]["with"]
        meta = steps["Work out the tags"]["with"]
        built[name] = (build["target"], meta["images"], meta["tags"], build["platforms"])
        # Signed, by digest, in every job that pushes.
        assert "cosign sign --yes" in steps["Sign the image"]["run"]
        assert "${DIGEST}" in steps["Sign the image"]["run"]
    assert built["image"][0] == "api" and built["front"][0] == "front"
    assert built["front"][1] == built["image"][1] + "-front"
    # Same tag rules and the same architectures, so `carnet:0.12.0` and
    # `carnet-front:0.12.0` name one release.
    assert built["front"][2] == built["image"][2]
    assert built["front"][3] == built["image"][3]
    # Each image has a smoke that pulls anonymously — the package-is-private defect.
    for smoke, needs in (("smoke", "image"), ("smoke-front", "front")):
        assert jobs[smoke]["needs"] == needs
        pull = jobs[smoke]["steps"][0]["run"] if "run" in jobs[smoke]["steps"][0] else jobs[smoke]["steps"][1]["run"]
        assert "docker logout ghcr.io" in pull


def test_the_compose_file_names_the_targets_the_release_builds():
    """The pair the release publishes is the pair the compose file runs, by target and by
    the setting that swaps in the published name."""
    compose = (REPO / "deploy" / "compose.yaml").read_text(encoding="utf-8")
    assert "target: api" in compose and "target: front" in compose
    assert "${CARNET_API_IMAGE:-carnet-api}" in compose
    assert "${CARNET_FRONT_IMAGE:-carnet-front}" in compose
    example = (REPO / "deploy" / ".env.example").read_text(encoding="utf-8")
    for name in ("CARNET_API_IMAGE", "CARNET_FRONT_IMAGE"):
        assert re.search(rf"^#?{name}=", example, re.M), f"{name} is not in .env.example"


# --- the notifier, run rather than read -------------------------------------------------
#
# `red` opens the issue that says the gate is red, and until the pass after 110f it was
# inline YAML: the one part of the gate that reports on the gate was the one part nothing
# could execute. These drive `.github/scripts/report-red.sh` with a stub on `PATH` in
# place of `gh`, which is the only seam it has — it makes no other outside call — and
# assert what it would have done.
#
# What they cannot prove is that GitHub runs it at all. `if: failure() && …` is the
# workflow's own, and the only proof of that is a red run on `main` or a tag; the tests
# above hold the condition and the needs-list instead.

REPORT_RED = REPO / ".github" / "scripts" / "report-red.sh"

# A `gh` that records its arguments instead of reaching GitHub. `issue list` answers
# with whatever the test put in `ISSUE_LIST`, which is the one reply the script branches
# on.
FAKE_GH = """#!/usr/bin/env bash
printf '%s\\0' "$@" >> "$GH_CALLS"
if [ "$1 $2" = "issue list" ]; then
  printf '%s' "${ISSUE_LIST:-}"
fi
exit 0
"""

NEEDS = json.dumps(
    {
        "versions": {"result": "success"},
        "lint": {"result": "success"},
        "fast": {"result": "failure"},
        "postgres": {"result": "success"},
        "upgrade": {"result": "cancelled"},
        "browser": {"result": "success"},
        "deploy": {"result": "success"},
        "supply-chain": {"result": "success"},
        "frontend": {"result": "success"},
    }
)


def run_notifier(tmp_path, *, open_issue: str = "") -> list[list[str]]:
    """Run the script with a stubbed `gh`, and return the calls it made."""
    binaries = tmp_path / "bin"
    binaries.mkdir()
    (binaries / "gh").write_text(FAKE_GH, encoding="utf-8")
    (binaries / "gh").chmod(0o755)
    calls = tmp_path / "calls"

    result = subprocess.run(
        ["bash", str(REPORT_RED)],
        capture_output=True,
        text=True,
        env={
            "PATH": f"{binaries}:{os.environ['PATH']}",
            "GH_CALLS": str(calls),
            "ISSUE_LIST": open_issue,
            "NEEDS": NEEDS,
            "RUN_URL": "https://github.example.com/acme/carnet/actions/runs/42",
            "EVENT": "schedule",
            "GITHUB_REF_NAME": "main",
            "GITHUB_SHA": "0123456789abcdef0123456789abcdef01234567",
            "GITHUB_SERVER_URL": "https://github.example.com",
            "GITHUB_REPOSITORY": "acme/carnet",
        },
    )
    assert result.returncode == 0, result.stderr

    raw = calls.read_text(encoding="utf-8").split("\0")[:-1]
    grouped: list[list[str]] = []
    for argument in raw:
        if argument in {"label", "issue"} and grouped and grouped[-1]:
            grouped.append([])
        if not grouped:
            grouped.append([])
        grouped[-1].append(argument)
    return grouped


def test_the_notifier_opens_an_issue_when_none_is_open(tmp_path):
    calls = run_notifier(tmp_path)
    created = next(call for call in calls if call[:2] == ["issue", "create"])

    title = created[created.index("--title") + 1]
    body = created[created.index("--body") + 1]

    # The ref and the commit, so two red branches do not read as one issue.
    assert title == "CI is red on main at 0123456"
    assert "--label" in created and created[created.index("--label") + 1] == "ci-red"
    # Only the jobs that did not pass, and a cancelled one is named too: a gate that
    # half-ran is not a gate that passed.
    assert "- `fast`: failure" in body
    assert "- `upgrade`: cancelled" in body
    assert "`lint`" not in body
    assert "https://github.example.com/acme/carnet/actions/runs/42" in body
    assert "schedule" in body


def test_the_notifier_adds_to_the_open_issue_rather_than_opening_a_second(tmp_path):
    """A gate that stays red is one thread. Opening an issue per push is how a red week
    becomes forty issues and nobody reads any of them."""
    calls = run_notifier(tmp_path, open_issue="77")

    assert not any(call[:2] == ["issue", "create"] for call in calls)
    commented = next(call for call in calls if call[:2] == ["issue", "comment"])
    assert commented[2] == "77"
    assert "- `fast`: failure" in commented[commented.index("--body") + 1]


def test_the_notifier_makes_its_own_label_idempotently(tmp_path):
    """The label is how *the open one* is found, so the first ever red run has to create
    it — and every run after that must not fail because it exists."""
    (label,) = [call for call in run_notifier(tmp_path) if call[0] == "label"]

    assert label[:3] == ["label", "create", "ci-red"]
    assert "--force" in label


def test_the_workflow_runs_the_script_and_can_reach_it(tmp_path):
    """The extraction's own trap: a step that runs a file in the repository needs the
    repository. Without the checkout this job would fail on `No such file`, which is a
    notifier that does not notify."""
    red = load("tests.yml")["jobs"]["red"]
    steps = red["steps"]

    assert any(step.get("uses", "").startswith("actions/checkout") for step in steps)
    assert any("report-red.sh" in (step.get("run") or "") for step in steps)
    assert REPORT_RED.exists() and os.access(REPORT_RED, os.X_OK)


def test_the_front_smoke_runs_the_script_that_can_be_run_by_hand():
    """Step 110 decision 11's smoke was inline bash, so the only way to check a
    published image was to publish one. It is `deploy/smoke-front.sh` now — the same
    file CI runs and a person runs against a pulled tag before cutting a release — and
    a job that runs a file from the repository has to check the repository out."""
    smoke = load("release.yml")["jobs"]["smoke-front"]
    steps = smoke["steps"]
    script = REPO / "deploy" / "smoke-front.sh"

    assert any(step.get("uses", "").startswith("actions/checkout") for step in steps)
    assert any("smoke-front.sh" in (step.get("run") or "") for step in steps)
    assert script.exists() and os.access(script, os.X_OK)
    # The pull stays in the workflow: *the package is public* is the one thing only a
    # published image can answer, and it is what the job is for.
    assert any("docker logout ghcr.io" in (step.get("run") or "") for step in steps)
