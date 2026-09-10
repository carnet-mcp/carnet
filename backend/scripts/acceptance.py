"""The acceptance pass: every end-to-end harness in the tree, run for real, in order. Step 099.

**A harness of harnesses, and a script rather than a test.** It asserts nothing of its own
and cannot fail for a reason of its own; everything it knows it learned from a harness that
already existed. The thirty-six scripts beside it (plan 099 counted thirty-seven) were invoked by hand, one at a time, for
months — a pass nobody repeats and a report nobody can reproduce. This is the one command:

    cd backend && CARNET_E2E_PG=postgresql://postgres:test@localhost:55432 \\
        .venv/bin/python scripts/acceptance.py

What it does for each harness, in the order below:

  - runs it in **its own process**, with `CARNET_E2E_PG` passed through — every harness
    splices its own database name into that base DSN and drops-and-creates it, which is
    what keeps one failure from poisoning the next;
  - streams its output to the console and to `var/acceptance/<name>.log`;
  - records the exit code, the wall time, the `N/M checks passed` line, every line that
    begins `FAIL`, and every `SKIPPED:` line — on the CI job's own rule that a silent skip
    is a green run that tested nothing;
  - **does not stop on failure.** A failing harness is a finding, not an abort, because the
    object of the pass is a complete picture.

It writes `var/acceptance.json` — the machine-readable summary a report is written from,
and the thing to keep beside a release. Re-running with `--only` merges into that file
rather than replacing it, so a fix can be re-proven one harness at a time without losing
the rest of the census.

## The order

Five tiers, each depending on the one before it in the sense that a failure there makes
the next tier's failures uninformative: **schema** (can the migrations build a database at
all), **storage** (do rows behave), **api** (does HTTP behave), **browser** (does the bundle
behave), **artefact** (does the shipped image behave). Within a tier the order is the order
the steps were written in.

## Decision 1 of plan 099, enforced here

`ANTHROPIC_API_KEY` is **stripped from every child's environment** unless `--spend` is
passed. The two harnesses that dial a vendor (`e2e_door_spend`, `e2e_model_connector`)
then skip loudly, and the report records the skip as a gap. A green pass must not depend on
somebody else's uptime or on a credential this repository cannot hold.

## The one harness that is three processes

`e2e_browser_roles.py` was written for three terminals: `browser_world.py`, a Vite dev
server and the script. It has never run in CI for that reason. Here the runner *is* the
three terminals — it starts the world, waits for its sentence, starts Vite on a port of its
own, runs the script, and tears both down — so the roles check is finally a thing one
command repeats.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
BACKEND = HERE.parent
REPO = BACKEND.parent
VAR = BACKEND / "var"
LOGS = VAR / "acceptance"
SUMMARY = VAR / "acceptance.json"

# (name, tier, timeout_seconds, needs)  — `needs` is what the harness cannot run without,
# named so the summary can say *why* something skipped rather than that it did.
HARNESSES: list[tuple[str, str, int, tuple[str, ...]]] = [
    # schema — the migrations, as a customer runs them
    ("e2e_upgrade", "schema", 900, ()),
    ("e2e_migration_series", "schema", 600, ()),
    ("e2e_partitioning", "schema", 600, ()),
    ("e2e_versions", "schema", 600, ()),
    # storage — rows, policies, triggers, the sealed columns
    ("e2e_rls", "storage", 900, ("dns",)),
    ("e2e_tenant_deletion", "storage", 600, ()),
    ("e2e_key_rotation", "storage", 600, ()),
    ("e2e_overview", "storage", 600, ()),
    # api — real HTTP, real CLI, a database with columns
    ("e2e_write_path", "api", 600, ()),
    ("e2e_edges", "api", 600, ()),
    ("e2e_local_login", "api", 600, ()),
    ("e2e_admin_onboarding", "api", 600, ()),
    ("e2e_registration", "api", 600, ()),
    ("e2e_recipe_registration", "api", 600, ()),
    ("e2e_http_connector", "api", 600, ("dns",)),
    ("e2e_rest_connector", "api", 600, ("dns",)),
    ("e2e_created_to_connected", "api", 600, ()),
    ("e2e_machine_caller", "api", 600, ()),
    ("e2e_mcp_door", "api", 900, ("dns",)),
    ("e2e_oauth_consent", "api", 600, ()),
    ("e2e_oauth_edges", "api", 600, ("dns",)),
    ("e2e_oauth_door", "api", 900, ("dns",)),
    ("e2e_platform_roles", "api", 600, ()),
    ("e2e_roles_edges", "api", 600, ()),
    ("e2e_directory_groups", "api", 600, ()),
    ("e2e_simulate", "api", 600, ()),
    ("e2e_pointer_credential", "api", 600, ()),
    ("e2e_door_spend", "api", 600, ("vendor",)),
    ("e2e_model_connector", "api", 600, ("vendor",)),
    # step 099's four, for the ten journeys nothing covered
    ("e2e_file_workflows", "api", 600, ("dns",)),
    ("e2e_open_admin", "api", 600, ()),
    ("e2e_team_journey", "api", 600, ("dns",)),
    ("e2e_openai_surface", "api", 900, ("dns",)),
    ("e2e_audit_stream", "api", 600, ("dns",)),
    # browser — real Chromium
    ("e2e_browser_local", "browser", 900, ("browser", "npm")),
    ("e2e_browser_admin", "browser", 1200, ("browser", "npm", "dns")),
    ("e2e_browser_overview", "browser", 900, ("browser", "npm")),
    ("e2e_browser_roles", "browser", 900, ("browser", "npm")),
    # artefact — the image and the compose stack
    ("e2e_deploy", "artefact", 1800, ("docker",)),
    ("e2e_browser_deploy", "artefact", 1200, ("docker", "browser")),
    ("e2e_file_door", "artefact", 900, ("docker",)),
]

CHECKS_LINE = re.compile(r"(\d+)/(\d+) checks passed")
FAIL_LINE = re.compile(r"^\s*FAIL(?:ED)?[: ]")
SKIP_LINE = re.compile(r"SKIPPED:\s*(.*)")


def say(what: str) -> None:
    print(f"\n##### {what}", flush=True)


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def child_env(base_dsn: str, spend: bool) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items()}
    if not spend:
        env.pop("ANTHROPIC_API_KEY", None)
    env["CARNET_E2E_PG"] = base_dsn
    env["PYTHONUNBUFFERED"] = "1"
    # A harness that starts uvicorn must not inherit a database URL that points it at
    # the developer's own world (`backend/.env` is sourced by habit).
    env.pop("CARNET_DATABASE_URL", None)
    env.pop("CARNET_FILE", None)
    return env


def stream(proc: subprocess.Popen, log: pathlib.Path, timeout: int, prefix: str) -> tuple[int, str, bool]:
    """Pump a child's merged output to the console and the log until it exits or times out.

    Returns (exit code, captured text, timed_out).
    """
    lines: list[str] = []
    started = time.monotonic()
    timed_out = False
    assert proc.stdout is not None
    with log.open("w") as out:
        while True:
            line = proc.stdout.readline()
            if line:
                text = line.decode("utf-8", "replace")
                lines.append(text)
                out.write(text)
                out.flush()
                sys.stdout.write(f"{prefix}{text}")
                sys.stdout.flush()
            elif proc.poll() is not None:
                break
            if time.monotonic() - started > timeout and proc.poll() is None:
                timed_out = True
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    proc.wait(15)
                except Exception:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                note = f"\n[acceptance] timed out after {timeout}s\n"
                lines.append(note)
                out.write(note)
                break
    return proc.returncode if proc.returncode is not None else -1, "".join(lines), timed_out


def summarise(name: str, tier: str, code: int, text: str, wall: float, timed_out: bool,
              log: pathlib.Path) -> dict:
    checks = None
    for m in CHECKS_LINE.finditer(text):
        checks = {"passed": int(m.group(1)), "total": int(m.group(2))}
    skips = [m.group(1).strip() for m in SKIP_LINE.finditer(text)]
    fails = [ln.rstrip() for ln in text.splitlines() if FAIL_LINE.match(ln)]
    if timed_out:
        status = "timeout"
    elif skips and code == 0 and (checks is None or checks["total"] == 0):
        status = "skip"
    elif code == 0 and checks is not None and checks["passed"] == checks["total"]:
        status = "pass"
    elif code == 0 and checks is None:
        # exited clean but printed no verdict line: treat as a skip if it said so,
        # otherwise as an error, because a harness that proves nothing must not be green
        status = "skip" if skips else "error"
    else:
        status = "fail"
    return {
        "name": name,
        "tier": tier,
        "status": status,
        "exit": code,
        "wall_s": round(wall, 1),
        "checks": checks,
        "skips": skips,
        "failures": fails[:40],
        "log": str(log.relative_to(BACKEND)),
        "ran_at": now(),
    }


def run_plain(name: str, tier: str, timeout: int, env: dict[str, str],
              extra: tuple[str, ...] = ()) -> dict:
    log = LOGS / f"{name}.log"
    started = time.monotonic()
    proc = subprocess.Popen(
        [sys.executable, str(HERE / f"{name}.py"), *extra],
        cwd=str(BACKEND), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    code, text, timed_out = stream(proc, log, timeout, "  | ")
    return summarise(name, tier, code, text, time.monotonic() - started, timed_out, log)


def _wait_for_line(proc: subprocess.Popen, needle: str, log, seconds: int) -> bool:
    deadline = time.monotonic() + seconds
    assert proc.stdout is not None
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                return False
            time.sleep(0.1)
            continue
        text = line.decode("utf-8", "replace")
        log.write(text)
        log.flush()
        sys.stdout.write(f"  [world] {text}")
        if needle in text:
            return True
    return False


def _wait_http(url: str, seconds: int) -> bool:
    import httpx
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            httpx.get(url, timeout=1)
            return True
        except Exception:
            time.sleep(0.5)
    return False


def _stop(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(15)
    except Exception:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            pass


def run_browser_roles(tier: str, timeout: int, env: dict[str, str], base_dsn: str) -> dict:
    """The three terminals, held by one process. Ports of its own, so it runs beside a
    developer's `--local` or a leftover Vite on 8080."""
    import base64
    from urllib.parse import urlsplit, urlunsplit

    name = "e2e_browser_roles"
    log = LOGS / f"{name}.log"
    started = time.monotonic()
    api_port, app_port = 8017, 8087
    parts = urlsplit(base_dsn)
    world_dsn = urlunsplit((parts.scheme, parts.netloc, "/carnet_browser", parts.query, parts.fragment))
    key = base64.b64encode(os.urandom(32)).decode()
    env = {**env, "CARNET_SECRET_KEY": key, "BROWSER_WORLD_API_PORT": str(api_port)}
    world = vite = None
    text = ""
    code, timed_out = -1, False
    with log.open("w") as out:
        try:
            world = subprocess.Popen(
                [sys.executable, str(HERE / "browser_world.py")],
                cwd=str(BACKEND), env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
            )
            if not _wait_for_line(world, "world is up.", out, 120):
                out.write("[acceptance] browser_world.py never said 'world is up.'\n")
                raise RuntimeError("world")
            vite = subprocess.Popen(
                ["npm", "run", "dev", "--", "--port", str(app_port), "--strictPort"],
                cwd=str(REPO / "frontend"),
                env={**env,
                     "VITE_OIDC_ISSUER": "http://127.0.0.1:8902",
                     "VITE_OIDC_CLIENT_ID": "dev",
                     "VITE_OIDC_SCOPES": "openid",
                     "VITE_API_ORIGIN": f"http://127.0.0.1:{api_port}"},
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
            )
            if not _wait_http(f"http://localhost:{app_port}/", 90):
                out.write("[acceptance] the Vite dev server never answered\n")
                raise RuntimeError("vite")
            proc = subprocess.Popen(
                [sys.executable, str(HERE / f"{name}.py")],
                cwd=str(BACKEND),
                env={**env, "WORLD_DSN": world_dsn,
                     "BROWSER_APP_ORIGIN": f"http://localhost:{app_port}"},
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
            )
        except RuntimeError:
            code = 1
        else:
            out.close()
            script_log = LOGS / f"{name}.script.log"
            code, text, timed_out = stream(proc, script_log, timeout, "  | ")
            with log.open("a") as out2:
                out2.write(text)
        finally:
            _stop(vite)
            _stop(world)
    return summarise(name, tier, code, text, time.monotonic() - started, timed_out, log)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--only", help="comma-separated harness names (without .py)")
    ap.add_argument("--tier", help="comma-separated tiers: schema,storage,api,browser,artefact")
    ap.add_argument("--spend", action="store_true",
                    help="keep ANTHROPIC_API_KEY in the environment so the vendor harnesses run")
    ap.add_argument("--fresh", action="store_true", help="start a new summary instead of merging")
    ap.add_argument("--list", action="store_true", help="print the order and exit")
    args = ap.parse_args()

    if args.list:
        for name, tier, timeout, needs in HARNESSES:
            print(f"{tier:9} {name:28} {timeout:5}s  {' '.join(needs)}")
        return 0

    base_dsn = os.environ.get("CARNET_E2E_PG")
    if not base_dsn:
        print("CARNET_E2E_PG is not set: a base DSN with no database name, e.g. "
              "postgresql://postgres:test@localhost:55432", file=sys.stderr)
        return 2

    chosen = HARNESSES
    if args.only:
        wanted = {n.strip() for n in args.only.split(",")}
        unknown = wanted - {h[0] for h in HARNESSES}
        if unknown:
            print(f"unknown harness: {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2
        chosen = [h for h in HARNESSES if h[0] in wanted]
    if args.tier:
        tiers = {t.strip() for t in args.tier.split(",")}
        chosen = [h for h in chosen if h[1] in tiers]

    LOGS.mkdir(parents=True, exist_ok=True)
    env = child_env(base_dsn, args.spend)

    previous: dict = {}
    if SUMMARY.exists() and not args.fresh:
        try:
            previous = {h["name"]: h for h in json.loads(SUMMARY.read_text())["harnesses"]}
        except Exception:
            previous = {}

    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=str(REPO),
                            capture_output=True, text=True).stdout.strip()
    results: dict[str, dict] = dict(previous)
    pass_started = now()
    for name, tier, timeout, needs in chosen:
        say(f"{tier}: {name}")
        if name == "e2e_browser_roles":
            result = run_browser_roles(tier, timeout, env, base_dsn)
        else:
            # Decision 1: without `--spend` the two vendor harnesses run their local
            # half and say `SKIPPED:` for the live one, which the summary records.
            extra = ("--offline",) if "vendor" in needs and not args.spend else ()
            result = run_plain(name, tier, timeout, env, extra)
        result["needs"] = list(needs)
        results[name] = result
        verdict = result["status"].upper()
        checks = result["checks"]
        detail = f"{checks['passed']}/{checks['total']}" if checks else "no verdict line"
        print(f"##### {name}: {verdict} ({detail}, exit {result['exit']}, {result['wall_s']}s)", flush=True)
        for s in result["skips"]:
            print(f"#####   skipped: {s}")
        # write after every harness, so a killed pass still leaves its census behind
        ordered = [results[h[0]] for h in HARNESSES if h[0] in results]
        SUMMARY.write_text(json.dumps({
            "commit": commit, "started": pass_started, "updated": now(),
            "base_dsn_host": base_dsn.split("@")[-1], "spend": args.spend,
            "harnesses": ordered,
        }, indent=2) + "\n")

    say("summary")
    ordered = [results[h[0]] for h in HARNESSES if h[0] in results]
    width = max(len(r["name"]) for r in ordered)
    for r in ordered:
        checks = r["checks"]
        detail = f"{checks['passed']:>4}/{checks['total']:<4}" if checks else "    -/-   "
        print(f"  {r['status']:8} {r['name']:{width}}  {detail}  {r['wall_s']:7.1f}s  {r['tier']}")
    counts = {}
    for r in ordered:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print("  " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())))
    print(f"  written to {SUMMARY.relative_to(BACKEND)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
