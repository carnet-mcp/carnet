"""The fileborne door, as an artefact, driven end to end. Step 098.

**Not a test, and here for what the suite structurally cannot do** — `e2e_deploy.py`'s
sentence, one artefact over. The suite proves `carnetfile` against a faked transport.
What it cannot prove is that the *image* comes up from a file with no database and no
encryption key, dials a real HTTP MCP server over a real socket, presents the credential
it was pointed at, lists the granted tool and only that, refuses an ungranted name with
the door's own sentence, refuses a call outside scope with a broker denial, and prints
step 096's line for each on the container's stdout. Every one of those is a fact about
the artefact, and this is the file to run after changing anything it touches.

One scene, `the_first_five_minutes`, and it is plan 094's target sentence run
literally: a file, `docker run`, a call that works, a call that is refused with a
reason — and the log line that proves both.

## The server this dials

A tiny MCP server in this process — the three-method JSON-RPC subset over plain HTTP,
`202` for a notification, `application/json` for everything else — that echoes the
`Authorization` header it received into every `tools/call` result. That is how the
script asserts *whose credential* the door presented, from outside the container, which
is otherwise invisible: a real server decides the account from the header and never says.

The container reaches it through `host.docker.internal`, with
`CARNET_EGRESS_INTERNAL_HOSTS` naming that host so plain http and a private address are
consented to — exactly what a laptop running its own MCP server does, and exactly what
`carnet.example.yaml`'s last comment says to do. `--add-host host.docker.internal:
host-gateway` for a bare Linux engine, which does not resolve the name on its own (054).

    cd backend && .venv/bin/python scripts/e2e_file_door.py

Needs Docker. Skips loudly — always the word `SKIPPED:` — when it is absent, which the
CI job greps for and fails on: there, a silent skip is a green build that tested nothing.
"""

import http.server
import json
import pathlib
import subprocess
import shutil
import sys
import threading
import time
import urllib.error
import urllib.request

REPO = pathlib.Path(__file__).resolve().parents[2]
DOCKERFILE = REPO / "deploy" / "Dockerfile"
# Under the repository, not a system temp dir: Docker Desktop shares the checkout with
# its engine and not `/var/folders`, and a bind mount from an unshared path arrives as
# an empty directory — which is what the loader now refuses with a sentence, found here.
SCRATCH = pathlib.Path(__file__).resolve().parent.parent / "var" / "e2e_file_door"
IMAGE = "carnet-api"
CONTAINER = "carnet_e2e_file_door"
DOOR_PORT = 8794
SECRET = "the-shared-jira-secret"

CHECKS = []


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok, actual, expected))
    mark = "ok  " if ok else "FAIL"
    print(f"  {mark} {label}: {actual!r}" + ("" if ok else f"  (expected {expected!r})"))
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


def preflight() -> str | None:
    try:
        done = subprocess.run(["docker", "info"], capture_output=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "Docker is not available"
    return None if done.returncode == 0 else "Docker is not available"


# --- the server the door dials --------------------------------------------------------

ADVERTISED = [
    {
        "name": "search_issues",
        "description": "Search issues in a project.",
        "inputSchema": {
            "type": "object",
            "properties": {"project": {"type": "string"}, "jql": {"type": "string"}},
            "required": ["project"],
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "create_issue",
        "description": "Open an issue.",
        "inputSchema": {
            "type": "object",
            "properties": {"project": {"type": "string"}, "title": {"type": "string"}},
            "required": ["project", "title"],
        },
    },
]


class TinyMcp(http.server.BaseHTTPRequestHandler):
    """The subset `tools/mcp/transport.py` speaks, and nothing more."""

    seen: list = []

    def log_message(self, *args):  # quiet
        pass

    def do_DELETE(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        message = json.loads(self.rfile.read(length) or b"{}")
        if "id" not in message:
            self.send_response(202)
            self.end_headers()
            return
        method = message.get("method")
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "tiny-jira", "version": "0.1"},
            }
        elif method == "tools/list":
            result = {"tools": ADVERTISED}
        elif method == "tools/call":
            TinyMcp.seen.append(message["params"])
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {"authorization": self.headers.get("Authorization") or ""}
                        ),
                    }
                ]
            }
        else:
            result = {}
        body = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve_tiny_mcp():
    server = http.server.ThreadingHTTPServer(("0.0.0.0", 0), TinyMcp)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


# --- the door -------------------------------------------------------------------------


def mcp(token: str, method: str, params=None):
    request = urllib.request.Request(
        f"http://localhost:{DOOR_PORT}/mcp",
        data=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
        ).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, None


def wait_for(url: str, seconds: int = 60) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                if response.status == 200:
                    return True
        except Exception:  # noqa: BLE001 - not up yet
            pass
        if subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER],
            capture_output=True, text=True,
        ).stdout.strip() != "true":
            return False
        time.sleep(1)
    return False


def the_file(mcp_port: int) -> str:
    return f"""
connectors:
  jira:
    url: http://host.docker.internal:{mcp_port}/mcp/
    credential: ${{JIRA_TOKEN}}
    tools:
      - name: search_issues
        effect: read
        resources: [{{type: jira.project, args: [project]}}]
      - name: create_issue
        effect: write
        resources: [{{type: jira.project, args: [project]}}]
agents:
  triage:
    tools: [jira_search_issues]
    scope:
      jira.project: {{read: [ACME]}}
tokens:
  laptop:
    secret: ${{CARNET_TOKEN_LAPTOP}}
    agents: [triage]
"""


def the_first_five_minutes(token: str, mcp_port: int, workdir: pathlib.Path) -> None:
    say("the first five minutes: a file, docker run, a call, a refusal, and the line")
    (workdir / "carnet.yaml").write_text(the_file(mcp_port), encoding="utf-8")

    subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)
    run = subprocess.run(
        [
            "docker", "run", "-d", "--name", CONTAINER,
            "--add-host", "host.docker.internal:host-gateway",
            "-p", f"{DOOR_PORT}:8000",
            "-v", f"{workdir / 'carnet.yaml'}:/carnet.yaml:ro",
            "-e", "CARNET_FILE=/carnet.yaml",
            "-e", f"JIRA_TOKEN={SECRET}",
            "-e", f"CARNET_TOKEN_LAPTOP={token}",
            "-e", "CARNET_EGRESS_INTERNAL_HOSTS=host.docker.internal",
            # Deliberately absent: CARNET_DATABASE_URL and CARNET_SECRET_KEY. Their
            # absence is the artefact.
            IMAGE,
        ],
        capture_output=True, text=True,
    )
    if not check("the container started", run.returncode, 0):
        print(run.stderr)
        return

    up = wait_for(f"http://localhost:{DOOR_PORT}/health")
    if not check("the door answers /health with no database and no key", up, True):
        print(subprocess.run(["docker", "logs", CONTAINER], capture_output=True, text=True).stderr)
        return

    status, ready = mcp("", "tools/list")
    check("no token is a 401", status, 401)

    status, listed = mcp(token, "tools/list")
    check("tools/list is the agent's tools and only those",
          [t["name"] for t in listed["result"]["tools"]], ["jira_search_issues"])
    check("the vendor's read-only hint reaches the client",
          listed["result"]["tools"][0]["annotations"], {"readOnlyHint": True})

    status, answer = mcp(token, "tools/call",
                         {"name": "jira_search_issues", "arguments": {"project": "ACME"}})
    text = json.loads(answer["result"]["content"][0]["text"])
    check("the call went out under the ${JIRA_TOKEN} credential",
          text["authorization"], f"Bearer {SECRET}")
    check("the result carries its audit id in _meta",
          str(answer["result"].get("_meta", {}).get("com.carnet/call-id", "")).startswith("door-"),
          True)

    status, refused = mcp(token, "tools/call",
                          {"name": "jira_create_issue", "arguments": {"project": "ACME"}})
    check("an ungranted name is refused with the door's sentence",
          "no agent this token is granted provides a tool called 'jira_create_issue'"
          in (refused.get("error") or {}).get("message", ""), True)

    status, denied = mcp(token, "tools/call",
                         {"name": "jira_search_issues", "arguments": {"project": "OTHER"}})
    check("a call outside scope is a broker denial, not a server error",
          "OTHER" in json.dumps(denied), True)
    check("the server was reached once, for the allowed call only",
          [p["arguments"] for p in TinyMcp.seen], [{"project": "ACME"}])

    logs = subprocess.run(["docker", "logs", CONTAINER], capture_output=True, text=True)
    lines = [json.loads(line) for line in logs.stdout.splitlines() if line.startswith("{")]
    kinds = [(line["type"], line.get("decision") or line.get("required")) for line in lines]
    check("stdout carries one line per call and per refusal, in order",
          kinds, [("audit", "allow"), ("denial", "grant"), ("audit", "deny")])
    allowed = next(line for line in lines if line.get("decision") == "allow")
    check("the allowed line names the tool, the agent and the credential kind",
          (allowed["tool"], allowed["agent"], allowed["credential"]),
          ("jira_search_issues", "triage", "shared"))


def main() -> int:
    reason = preflight()
    if reason:
        print(f"SKIPPED: {reason}")
        return 0

    say("building the api image")
    build = subprocess.run(
        ["docker", "build", "-q", "-t", IMAGE, "--target", "api", "-f", str(DOCKERFILE), str(REPO)],
        capture_output=True, text=True,
    )
    if not check("the image builds", build.returncode, 0):
        print(build.stderr)
        return 1

    # The token, minted the way a person mints it — inside the image, with no store.
    minted = subprocess.run(
        ["docker", "run", "--rm", IMAGE, "carnet", "--new-token"],
        capture_output=True, text=True,
    )
    token = minted.stdout.strip().splitlines()[0] if minted.stdout.strip() else ""
    if not check("--new-token prints a token", token.startswith("art_"), True):
        print(minted.stderr)
        return 1

    server, port = serve_tiny_mcp()
    SCRATCH.mkdir(parents=True, exist_ok=True)
    try:
        the_first_five_minutes(token, port, SCRATCH)
    finally:
        server.shutdown()
        subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)
        shutil.rmtree(SCRATCH, ignore_errors=True)
    return report()


if __name__ == "__main__":
    sys.exit(main())
