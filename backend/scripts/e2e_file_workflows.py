"""The fileborne door as a person's editing session. Step 099, journeys A1 and A7–A10.

`e2e_file_door.py` proves the *artefact*: the image, a file, one call, one refusal, the
line on stdout. What it does not walk is the hour before that — a person alone on a
laptop, copying the example, getting the file wrong in the ways people get files wrong,
and being told which line. Nor the hour after: an MCP server on the same machine, the
plain-http refusal and the consent that lifts it; `--discover` against a live server and
the block it prints pasted back in; two tokens with two scopes; a REST API that is not an
MCP server at all. Those are the journeys plan 099 found nothing covering.

    cd backend && .venv/bin/python scripts/e2e_file_workflows.py

**No Docker and no database.** The door here is `uvicorn` from this checkout with
`CARNET_FILE` set — the same application the image runs, minus the image, which
`e2e_file_door.py` already proves. The CLI is the real CLI in its own process, because
`--check-file` and `--discover` are what a person types, and their exit codes and the
sentence on stderr are the interface. Costs nothing: no vendor, no key, no money.

The servers it dials live at `localtest.me`, a public name for 127.0.0.1, for the reason
every other harness here gives: `egress` refuses a literal loopback address before any
allowlist is read, and a name is what a person would put in the file.

## The scenes

  A1   the editing session      copy the example; be refused for a literal secret, for an
                                unset variable, for a misspelt key — each naming the
                                line — then pass
  A7   the server next door     plain http is refused with the consent named; the consent
                                lifts it; the call goes out under the file's credential
  A8   --discover, then paste   the printed block, pasted verbatim, is refused for the
                                write tool it left unscoped — the decision the comment
                                says is yours — and passes once the resources are added
  A9   two tokens, two scopes   each token lists only its own agent's tools and is
                                refused the other's by name
  A10  a REST API in the file   a `rest` connector with an authored tool, called through
                                the door, the request read back off the wire
"""

from __future__ import annotations

import http.server
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
BACKEND = HERE.parent
REPO = BACKEND.parent
EXAMPLE = REPO / "carnet.example.yaml"
SCRATCH = BACKEND / "var" / "e2e_file_workflows"

HOST = "localtest.me"
DOOR_PORT = 8147
MCP_PORT = 8951
REST_PORT = 8952
DOOR = f"http://127.0.0.1:{DOOR_PORT}"

JIRA_SECRET = "jira-secret-7c1d"
WEATHER_SECRET = "weather-key-2a9e"

sys.path.insert(0, str(HERE))
from e2e_file_door import TinyMcp  # noqa: E402 — the same three-method server

CHECKS: list = []


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok, actual, expected))
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: {actual!r}" + ("" if ok else f"  (expected {expected!r})"))
    return ok


def says(label, text, fragment):
    ok = fragment in str(text)
    CHECKS.append((label, ok, text, fragment))
    print(f"  {'ok  ' if ok else 'FAIL'} {label}" + ("" if ok else f"\n        wanted {fragment!r} in {str(text)[:400]!r}"))
    return ok


def say(what):
    print(f"\n=== {what}", flush=True)


def report() -> int:
    say("summary")
    failed = [label for label, ok, *_ in CHECKS if not ok]
    print(f"  {len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    for label in failed:
        print(f"  FAILED: {label}")
    return 1 if failed else 0


# --- the two servers next door ---------------------------------------------------------


class TinyRest(http.server.BaseHTTPRequestHandler):
    """A plain JSON API that does not describe itself: GET /forecast/{city}."""

    seen: list = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        TinyRest.seen.append({"path": self.path, "x-api-key": self.headers.get("x-api-key")})
        city = self.path.rsplit("/", 1)[-1]
        body = json.dumps({"city": city, "forecast": "light rain"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(handler, port):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# --- the person's tools ------------------------------------------------------------------


def base_env(**extra) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("CARNET_")}
    env.update({
        "JIRA_TOKEN": JIRA_SECRET,
        "WEATHER_KEY": WEATHER_SECRET,
        "PYTHONUNBUFFERED": "1",
    })
    env.update(extra)
    return env


def carnet(*args, env: dict, stdin: str | None = None):
    """The real CLI in its own process. Prints what it said, returns the result."""
    result = subprocess.run(
        [sys.executable, "-m", "carnet.cli", *args],
        cwd=str(BACKEND), env=env, input=stdin, capture_output=True, text=True,
    )
    print("      $ carnet " + " ".join(args))
    for line in (result.stdout + result.stderr).strip().splitlines()[:12]:
        print(f"        {line}")
    return result


def check_file(path: pathlib.Path, env: dict):
    return carnet("--check-file", str(path), env=env)


def mcp(token: str, method: str, params=None, id_=1):
    request = urllib.request.Request(
        f"{DOOR}/mcp",
        data=json.dumps({"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}}).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, None


class Door:
    """`uvicorn` with `CARNET_FILE`, stdout captured line by line for step 096's line."""

    def __init__(self, file: pathlib.Path, env: dict):
        self.lines: list[str] = []
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port", str(DOOR_PORT)],
            cwd=str(BACKEND),
            env={**env, "CARNET_FILE": str(file)},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.stderr: list[str] = []
        threading.Thread(target=self._pump, args=(self.proc.stdout, self.lines), daemon=True).start()
        threading.Thread(target=self._pump, args=(self.proc.stderr, self.stderr), daemon=True).start()

    @staticmethod
    def _pump(stream, into):
        for line in stream:
            into.append(line.rstrip("\n"))

    def wait(self, seconds=30) -> bool:
        deadline = time.time() + seconds
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return False
            try:
                with urllib.request.urlopen(f"{DOOR}/health", timeout=2) as r:
                    if r.status == 200:
                        return True
            except Exception:  # noqa: BLE001 — not up yet
                time.sleep(0.3)
        return False

    def audit_lines(self) -> list[dict]:
        out = []
        for line in self.lines:
            if line.startswith("{"):
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
        return out

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# --- A1: the editing session --------------------------------------------------------------


def a1_the_editing_session(workdir: pathlib.Path, laptop: str) -> None:
    say("A1: copy the example and check it — the file as shipped passes")
    file = workdir / "carnet.yaml"
    shutil.copy(EXAMPLE, file)
    env = base_env(CARNET_TOKEN_LAPTOP=laptop)
    done = check_file(file, env)
    check("the shipped example checks clean", done.returncode, 0)
    says("and the summary counts what it declares", done.stdout,
         "2 connector(s), 3 tool(s), 2 agent(s), 1 token(s)")

    say("A1: a made-up token secret is refused — it must be what --new-token printed")
    done = check_file(file, base_env(CARNET_TOKEN_LAPTOP="my-own-password"))
    check("refused", done.returncode != 0, True)
    says("naming the key", done.stderr, "tokens.laptop.secret")
    says("and the shape it wants", done.stderr, "the whole line `carnet --new-token` printed")

    say("A1: a literal secret is refused, naming the line")
    original = file.read_text()
    file.write_text(original.replace("credential: ${JIRA_TOKEN}", "credential: hunter2-literal"))
    done = check_file(file, env)
    check("refused", done.returncode != 0, True)
    says("naming the key", done.stderr, "connectors.jira.credential")
    says("and the rule", done.stderr, "must be a pointer into the environment")

    say("A1: an unset variable is refused before the door ever starts")
    file.write_text(original)
    without = {k: v for k, v in env.items() if k != "WEATHER_KEY"}
    done = check_file(file, without)
    check("refused", done.returncode != 0, True)
    says("naming the variable", done.stderr, "${WEATHER_KEY} is not set in this environment")
    says("and the remedy", done.stderr, "export it, or pass it to the container")

    say("A1: a misspelt key is refused rather than ignored")
    file.write_text(original.replace("    tools:\n      - name: search_issues", "    tool:\n      - name: search_issues", 1))
    done = check_file(file, env)
    check("refused", done.returncode != 0, True)
    says("naming the key", done.stderr, "unknown key(s) tool")
    says("and what is allowed instead", done.stderr, "tools")

    say("A1: a token secret that names one of Carnet's own settings is refused")
    file.write_text(original.replace("${CARNET_TOKEN_LAPTOP}", "${CARNET_SECRET_KEY}"))
    done = check_file(file, {**env, "CARNET_SECRET_KEY": "x"})
    check("refused", done.returncode != 0, True)
    says("with the reservation named", done.stderr, "CARNET_TOKEN_* are reserved")

    say("A1: fixed, it passes, and the fix was one line")
    file.write_text(original)
    done = check_file(file, env)
    check("passes again", done.returncode, 0)


# --- A7, A9, A10: one file, one boot ---------------------------------------------------------


def the_laptop_file() -> str:
    return f"""
connectors:
  jira:
    url: http://{HOST}:{MCP_PORT}/mcp/
    credential: ${{JIRA_TOKEN}}
    tools:
      - name: search_issues
        effect: read
        resources: [{{type: jira.project, args: [project]}}]
      - name: create_issue
        effect: write
        resources: [{{type: jira.project, args: [project]}}]
  weather:
    kind: rest
    url: http://{HOST}:{REST_PORT}
    credential: ${{WEATHER_KEY}}
    credential_header: x-api-key
    credential_prefix: ""
    tools:
      - name: forecast
        effect: read
        method: GET
        path: /forecast/{{city}}
        schema:
          type: object
          properties:
            city: {{type: string}}
          required: [city]
agents:
  triage:
    tools: [jira_search_issues, weather_forecast]
    scope:
      jira.project: {{read: [ACME]}}
  filer:
    tools: [jira_create_issue]
    scope:
      jira.project: {{write: [ACME]}}
tokens:
  laptop:
    secret: ${{CARNET_TOKEN_LAPTOP}}
    agents: [triage]
  ci:
    secret: ${{CARNET_TOKEN_CI}}
    agents: [filer]
"""


def a7_a9_a10(workdir: pathlib.Path, laptop: str, ci: str) -> None:
    file = workdir / "laptop.yaml"
    file.write_text(the_laptop_file())
    env = base_env(CARNET_TOKEN_LAPTOP=laptop, CARNET_TOKEN_CI=ci)

    say("A7: a server on this machine is plain http, and the file is refused for it")
    done = check_file(file, env)
    check("refused", done.returncode != 0, True)
    says("naming the connector", done.stderr, "connectors.jira")
    says("and why", done.stderr, "is not https")
    says("and the consent that lifts it", done.stderr, "CARNET_EGRESS_INTERNAL_HOSTS")

    say("A7: with the consent, the same file passes")
    env["CARNET_EGRESS_INTERNAL_HOSTS"] = HOST
    done = check_file(file, env)
    check("passes", done.returncode, 0)
    says("counting both connectors", done.stdout, "2 connector(s), 3 tool(s), 2 agent(s), 2 token(s)")

    say("A7: the door comes up from the file, with no database and no key")
    door = Door(file, env)
    try:
        if not check("uvicorn answers /health", door.wait(), True):
            print("\n".join(door.stderr[-30:]))
            return

        TinyMcp.seen.clear()
        status, listed = mcp(laptop, "tools/list")
        check("the laptop token lists triage's two tools",
              sorted(t["name"] for t in listed["result"]["tools"]),
              ["jira_search_issues", "weather_forecast"])
        status, answer = mcp(laptop, "tools/call",
                             {"name": "jira_search_issues", "arguments": {"project": "ACME"}})
        text = json.loads(answer["result"]["content"][0]["text"])
        check("the call reached the server next door under ${JIRA_TOKEN}",
              text["authorization"], f"Bearer {JIRA_SECRET}")

        say("A9: two tokens, two agents, and each sees only its own")
        status, listed = mcp(ci, "tools/list")
        check("the ci token lists filer's one tool",
              [t["name"] for t in listed["result"]["tools"]], ["jira_create_issue"])
        status, refused = mcp(ci, "tools/call",
                              {"name": "jira_search_issues", "arguments": {"project": "ACME"}})
        says("ci asking for triage's tool is refused by name",
             (refused.get("error") or {}).get("message", ""),
             "no agent this token is granted provides a tool called 'jira_search_issues'")
        status, refused = mcp(laptop, "tools/call",
                              {"name": "jira_create_issue", "arguments": {"project": "ACME", "title": "x"}})
        says("and laptop asking for filer's is refused the same way",
             (refused.get("error") or {}).get("message", ""),
             "provides a tool called 'jira_create_issue'")
        status, answer = mcp(ci, "tools/call",
                             {"name": "jira_create_issue", "arguments": {"project": "ACME", "title": "x"}})
        check("ci's own write goes through", answer["result"].get("isError", False), False)
        status, denied = mcp(ci, "tools/call",
                             {"name": "jira_create_issue", "arguments": {"project": "OTHER", "title": "x"}})
        check("and outside its scope it is a broker denial", denied["result"].get("isError"), True)
        check("the server saw exactly the two allowed calls",
              [p["arguments"].get("project") for p in TinyMcp.seen], ["ACME", "ACME"])

        say("A10: the REST API in the file, called through the door")
        TinyRest.seen.clear()
        status, answer = mcp(laptop, "tools/call",
                             {"name": "weather_forecast", "arguments": {"city": "paris"}})
        check("the call is a result", answer["result"].get("isError", False), False)
        body = json.loads(answer["result"]["content"][0]["text"])
        check("carrying the API's answer", body.get("forecast"), "light rain")
        check("the request was rendered from the path template and the header the file named",
              TinyRest.seen, [{"path": "/forecast/paris", "x-api-key": WEATHER_SECRET}])

        say("A6, again, under uvicorn: the line on stdout, one per call and per refusal")
        time.sleep(0.5)
        kinds = [(line["type"], line.get("decision") or line.get("required")) for line in door.audit_lines()]
        check("the stream has one entry per act, in order", kinds,
              [("audit", "allow"), ("denial", "grant"), ("denial", "grant"),
               ("audit", "allow"), ("audit", "deny"), ("audit", "allow")])
        rest_line = [line for line in door.audit_lines() if line.get("tool") == "weather_forecast"][0]
        check("and the REST call's line names its agent and credential kind",
              (rest_line["agent"], rest_line["credential"]), ("triage", "shared"))
    finally:
        door.stop()


# --- A8: --discover, then paste -----------------------------------------------------------


def a8_discover_then_paste(workdir: pathlib.Path, laptop: str) -> None:
    say("A8: a connector with no tools yet, and --discover against the live server")
    file = workdir / "discover.yaml"
    head = f"""
connectors:
  jira:
    url: http://{HOST}:{MCP_PORT}/mcp/
    credential: ${{JIRA_TOKEN}}
"""
    tail = """
agents:
  triage:
    tools: [jira_search_issues, jira_create_issue]
    scope:
      jira.project: {read: [ACME], write: [ACME]}
tokens:
  laptop:
    secret: ${CARNET_TOKEN_LAPTOP}
    agents: [triage]
"""
    env = base_env(CARNET_TOKEN_LAPTOP=laptop, CARNET_EGRESS_INTERNAL_HOSTS=HOST)
    file.write_text(head)
    done = check_file(file, env)
    check("a connector with no tools is a valid file", done.returncode, 0)
    says("declaring nothing callable", done.stdout, "1 connector(s), 0 tool(s)")

    done = carnet("--discover", "jira", env={**env, "CARNET_FILE": str(file)})
    check("--discover exits 0", done.returncode, 0)
    says("it dialled the real server", done.stdout, "2 tool(s) advertised, 0 vetted")
    says("and printed where to paste", done.stdout, "under connectors.jira:")
    block = done.stdout.split("under connectors.jira:", 1)[1].strip("\n")
    check("the block starts with tools:", block.lstrip().startswith("tools:"), True)
    says("the read-only hint became effect: read", block, "effect: read")
    says("and no hint became write, the cautious default", block, "effect: write")
    says("with the argument names beside each", block, "arguments:")

    say("A8: pasted verbatim, the write tool is unscoped — and that refusal is the point")
    file.write_text(head.rstrip("\n") + "\n" + block + "\n" + tail)
    done = check_file(file, env)
    check("refused", done.returncode != 0, True)
    says("naming the tool that needs a decision", done.stderr, "create_issue")

    say("A8: the person adds the resources the comment told them to, and it passes")
    scoped = "\n".join(
        line + ("\n        resources: [{type: jira.project, args: [project]}]" if line.strip().startswith("- name:") else "")
        for line in block.splitlines()
    )
    file.write_text(head.rstrip("\n") + "\n" + scoped + "\n" + tail)
    done = check_file(file, env)
    if not check("passes", done.returncode, 0):
        print(file.read_text())
        return
    says("with both tools declared", done.stdout, "1 connector(s), 2 tool(s), 1 agent(s), 1 token(s)")

    say("A8: and the file it produced runs")
    door = Door(file, env)
    try:
        if not check("the door comes up from the pasted file", door.wait(), True):
            print("\n".join(door.stderr[-30:]))
            return
        status, listed = mcp(laptop, "tools/list")
        check("both discovered tools are callable",
              sorted(t["name"] for t in listed["result"]["tools"]),
              ["jira_create_issue", "jira_search_issues"])
        check("and the server's read-only hint survived the round trip",
              next(t for t in listed["result"]["tools"] if t["name"] == "jira_search_issues").get("annotations"),
              {"readOnlyHint": True})
    finally:
        door.stop()


def main() -> int:
    if socket.gethostbyname(HOST) != "127.0.0.1":
        print(f"SKIPPED: {HOST} did not resolve to 127.0.0.1; this needs outbound DNS")
        return 0
    for port in (DOOR_PORT, MCP_PORT, REST_PORT):
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                raise SystemExit(f"port {port} is taken; this script refuses to guess")

    shutil.rmtree(SCRATCH, ignore_errors=True)
    SCRATCH.mkdir(parents=True)
    mcp_server = serve(TinyMcp, MCP_PORT)
    rest_server = serve(TinyRest, REST_PORT)

    say("minting two tokens the way a person does — offline, no store")
    minted = [carnet("--new-token", env=base_env()).stdout.strip().splitlines()[0] for _ in range(2)]
    laptop, ci = minted
    check("two presentable tokens", [t.startswith("art_") for t in minted], [True, True])
    check("and they differ", laptop != ci, True)

    try:
        a1_the_editing_session(SCRATCH, laptop)
        a7_a9_a10(SCRATCH, laptop, ci)
        a8_discover_then_paste(SCRATCH, laptop)
    finally:
        mcp_server.shutdown()
        rest_server.shutdown()
        shutil.rmtree(SCRATCH, ignore_errors=True)
    return report()


if __name__ == "__main__":
    sys.exit(main())
