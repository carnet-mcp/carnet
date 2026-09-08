"""A customer-registered REST connector, over a real socket, end to end. Step 045a.

The REST twin of `e2e_http_connector.py`, and it proves the things the unit suite
fakes: a real JSON API on a real socket, real Postgres, the real CLI in its own
process, and the door driven over HTTP framing — with every request the API actually
received as the evidence.

    --allow-host -> --add-connector --kind rest -> --vet (authored binding)
        -> bind (no session) -> broker -> requests -> a live API
        -> and the same arc again through POST /mcp

What it asserts that nothing in-process can:

  **The rendered request is real.** The path template, the URL-encoding, the query
  mapping, the JSON body and the per-request credential header are read back off the
  wire, not off a fake's kwargs.

  **Two people, two credentials, one connector.** `identity: "user"` REST tools carry
  the acting person's own token per request — finding 5 of the plan closed, observed
  in the server's access record.

  **A redirect is not followed.** The egress check ran against the URL we built, so a
  3xx pointing elsewhere comes back as a tool error rather than a dial the check
  never saw.

## Why the host is `localtest.me`

Same reason as `e2e_http_connector.py`, verbatim: the egress check refuses loopback
by address whatever a tenant approves, and `localtest.me` is a public DNS name that
resolves to 127.0.0.1 — the documented rebinding gap, reachable on purpose.

    cd backend && .venv/bin/python scripts/e2e_rest_connector.py

Needs Postgres started first, and outbound DNS for `localtest.me`. Costs nothing: no
model is called and the API is local.
"""

import json
import os
import pathlib
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit, urlunsplit

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_e2e_rest"


def dsn_for(database: str) -> str:
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


DSN = dsn_for(DB)
TENANT = "e2erest"

HOST = "localtest.me"
PORT = 8933
BASE = f"http://{HOST}:{PORT}/v1"

PRIYA = "user:u_priya"

SCHEMA = json.dumps(
    {
        "type": "object",
        "properties": {
            "owner": {"type": "string"},
            "repo": {"type": "string"},
            "state": {"type": "string"},
        },
        "required": ["owner", "repo"],
    }
)

WRITE_SCHEMA = json.dumps(
    {
        "type": "object",
        "properties": {
            "owner": {"type": "string"},
            "repo": {"type": "string"},
            "title": {"type": "string"},
        },
        "required": ["owner", "repo", "title"],
    }
)

# Every request the API saw: method, path, query, Authorization, body. The evidence.
SEEN = []
SEEN_LOCK = threading.Lock()


class TrackerAPI(BaseHTTPRequestHandler):
    """A small, honest JSON API. No MCP anywhere — that is the point."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _record(self, body=None):
        split = urlsplit(self.path)
        with SEEN_LOCK:
            SEEN.append(
                {
                    "method": self.command,
                    "path": split.path,
                    "query": {k: v[0] for k, v in parse_qs(split.query).items()},
                    "authorization": self.headers.get("Authorization"),
                    "accept": self.headers.get("Accept"),
                    "body": body,
                }
            )
        return split

    def _answer(self, status, payload=None, content_type="application/json", location=None):
        body = b"" if payload is None else json.dumps(payload).encode()
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        split = self._record()
        token = (self.headers.get("Authorization") or "").removeprefix("Bearer ")
        if not token:
            return self._answer(401, {"message": "who are you? bad token: <none>"})

        parts = split.path.strip("/").split("/")  # v1 repos {owner} {repo} issues
        if len(parts) == 5 and parts[1] == "repos" and parts[4] == "issues":
            owner, repo = parts[2], parts[3]
            if repo == "moved":
                return self._answer(302, None, location="http://169.254.169.254/latest/")
            if repo == "html":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                page = b"<html>a login page, not an API</html>"
                self.send_header("Content-Length", str(len(page)))
                self.end_headers()
                self.wfile.write(page)
                return
            if repo == "gone":
                return self._answer(404, {"message": f"no repository {owner}/{repo}"})
            return self._answer(
                200,
                {
                    "issues": [{"number": 1, "title": f"an issue in {repo}"}],
                    "seen_authorization": self.headers.get("Authorization"),
                },
            )
        return self._answer(404, {"message": "unknown path"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        body = json.loads(raw) if raw else None
        self._record(body)
        return self._answer(201, {"number": 7, "created": True})


CHECKS = []


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((ok, label))
    print(f"{'  ok' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        expected: {expected!r}")
        print(f"        actual:   {actual!r}")
    return ok


def says(label, actual, fragment):
    ok = fragment in str(actual)
    CHECKS.append((ok, label))
    print(f"{'  ok' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        wanted {fragment!r} in: {actual!r}")
    return ok


def step(what):
    print(f"\n=== {what}", flush=True)


def cli(*args):
    """The real command, in its own process, against the same database — the shape an
    administrator actually uses, and the only shape that can fail like one."""
    result = subprocess.run(
        [sys.executable, "-m", "carnet.cli", *args],
        env={**os.environ, "CARNET_TENANT": TENANT},
        capture_output=True,
        text=True,
    )
    print("      $ carnet " + " ".join(a if len(a) < 60 else a[:57] + "..." for a in args))
    for line in (result.stdout + result.stderr).splitlines()[:6]:
        print(f"        {line}")
    return result


def main():
    import psycopg

    if socket.gethostbyname(HOST) != "127.0.0.1":
        raise SystemExit(f"{HOST} did not resolve to 127.0.0.1; this script needs DNS")

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")

    os.environ["CARNET_DATABASE_URL"] = DSN
    # Step 058: the dial vets DNS answers, and localtest.me resolves to loopback
    # on purpose — the operator (this script) consents to its own machine.
    os.environ["CARNET_EGRESS_INTERNAL_HOSTS"] = "localtest.me"
    os.environ.setdefault("CARNET_SECRET_KEY", _generate_key())
    os.environ["TRACKER_TOKEN"] = "the-shared-service-token"

    from fastapi.testclient import TestClient

    from carnet import agents, storage, tools
    from carnet.access import connections, tokens
    from carnet.api import create_app
    from carnet.core import broker, crypto
    from carnet.core.context import RunContext
    from carnet.core.credentials import DELEGATED, for_connector
    from carnet.core.principal import Principal
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage
    from carnet.tools import mcp

    migrate.apply(DSN)
    store = storage.configure(PostgresStorage(DSN))
    crypto.configure(crypto.from_environment())
    store.create_tenant(TENANT, "045a REST end to end")

    server = ThreadingHTTPServer(("127.0.0.1", PORT), TrackerAPI)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    try:
        # --- registration, through the real CLI ----------------------------------

        step("an unapproved host refuses registration, and nothing is dialled")

        refused = cli("--add-connector", "tracker", "--kind", "rest", "--url", BASE)
        check("refused with an exit code", refused.returncode != 0, True)
        says("naming the remedy", refused.stderr, "has not approved the host")
        check("nothing reached the API", len(SEEN), 0)

        step("--allow-host, then --add-connector --kind rest")

        cli("--allow-host", HOST, "the tracker's API")
        registered = cli(
            "--add-connector", "tracker", "--kind", "rest", "--url", BASE,
            "--credential-env", "TRACKER_TOKEN",
            "--description", "Acme's issue tracker, plain REST",
        )
        check("registered", registered.returncode, 0)
        says("and the next step is vetting, not discovery", registered.stdout, "--vet")

        connector = mcp.get_connector(TENANT, "tracker")
        check("the stored row is a rest launch", connector.transport_kind, "rest")
        check("registration contacted nothing", len(SEEN), 0)

        step("--discover has nothing to discover, and says what to do instead")

        nothing = cli("--discover", "tracker")
        check("refused", nothing.returncode != 0, True)
        says("with the remedy in the sentence", nothing.stderr, "does not describe itself")

        # --- vetting is authoring, through the real CLI ---------------------------

        step("--vet with an authored schema and binding, one read and one write")

        vetted = cli(
            "--vet", "tracker", "--tool", "list_issues", "--effect", "read",
            "--identity", "user",
            "--method", "GET", "--path", "/repos/{owner}/{repo}/issues",
            "--query", "state", "--schema", SCHEMA,
            "--resource", "github.repo={owner}/{repo}:owner,repo",
            "--tool-description", "List issues in a repository.",
            "--note", "Read-only. Scope to the repos a team owns.",
        )
        check("vetted", vetted.returncode, 0)
        says("as the caller's own account", vetted.stdout, "as-user")
        says("and no server was consulted", vetted.stdout, "no server consulted")

        wrote = cli(
            "--vet", "tracker", "--tool", "create_issue", "--effect", "write",
            "--method", "POST", "--path", "/repos/{owner}/{repo}/issues",
            "--body", "title", "--schema", WRITE_SCHEMA,
            "--resource", "github.repo={owner}/{repo}:owner,repo",
            "--tool-description", "Open an issue.",
        )
        check("the write vetted too", wrote.returncode, 0)

        review = store.load_vetting_record(TENANT)
        check("two review rows, structurally empty of any server",
              [(r["remote_name"], r["server_name"], r["vetted_arguments"]) for r in review],
              [("create_issue", "", []), ("list_issues", "", [])])

        step("the refusals a vetter actually hits, each with a sentence")

        unmapped = cli(
            "--vet", "tracker", "--tool", "broken", "--effect", "read",
            "--method", "GET", "--path", "/repos/{owner}/{repo}/issues",
            "--schema", SCHEMA,  # `state` mapped nowhere
            "--resource", "github.repo={owner}/{repo}:owner,repo",
            "--tool-description", "x",
        )
        check("a property mapped nowhere refuses", unmapped.returncode != 0, True)
        says("naming it", unmapped.stderr, "'state'")

        missing = cli(
            "--vet", "tracker", "--tool", "broken", "--effect", "read",
            "--schema", SCHEMA,
        )
        check("a rest vet without its binding refuses", missing.returncode != 0, True)
        says("naming what is missing", missing.stderr, "--method")

        check("neither refusal stored anything",
              sorted(v.remote_name for v in mcp.get_connector(TENANT, "tracker").vetted),
              ["create_issue", "list_issues"])

        # --- the agent, and brokered calls over the real socket -------------------

        step("an agent granting both tools, and two people with their own accounts")

        config = {
            "name": "issue-clerk",
            "system": "You read and file issues.",
            "runtime": "simple",
            "permissions": {
                "tools": ["tracker_list_issues", "tracker_create_issue"],
                # "acme corp/*" exists for the URL-encoding scene below: the matcher
                # composes "acme corp/platform", which "acme/*" rightly refuses.
                "scope": {"github.repo": {"read": ["acme/*", "acme corp/*"],
                                          "write": ["acme/platform"]}},
            },
        }
        agents.validate(TENANT, config)
        store.create_agent(TENANT, config, "user", "u_priya")

        priya = Principal.user("u_priya", TENANT)
        sam = Principal.user("u_sam", TENANT)
        connections.connect_account(priya, "tracker", "priya-token",
                                    account_label="priya@acme.com", actor="system:cli")
        connections.connect_account(sam, "tracker", "sam-token",
                                    account_label="sam@acme.com", actor="system:cli")

        def credential_for(principal):
            def resolve(connector_id, env_var=None, ref=None):
                credential = for_connector(connector_id, principal, env_var, ref=ref)
                if credential is None:
                    return None, False
                return credential.value, credential.source == DELEGATED

            return resolve

        step("a brokered read, as priya: the rendered request is real")

        tools.ensure_available(TENANT, config, credential_for=credential_for(priya))
        check("and no MCP session exists anywhere", mcp.POOL._sessions, {})

        ctx = RunContext(run_id="r-priya", principal=priya, budget=_budget())
        seen_before = len(SEEN)
        result = broker.call(ctx, config, "tracker_list_issues",
                             {"owner": "acme", "repo": "platform", "state": "open"})

        check("the call succeeded", "error" not in result, True)
        says("and the API's answer came back", json.dumps(result), "an issue in platform")
        sent = SEEN[seen_before]
        check("GET, on the rendered path", (sent["method"], sent["path"]),
              ("GET", "/v1/repos/acme/platform/issues"))
        check("the query mapping travelled as a query", sent["query"], {"state": "open"})
        check("carrying PRIYA's own token, per request",
              sent["authorization"], "Bearer priya-token")

        step("the same tool, as sam, carries SAM's token — one connector, two people")

        tools.ensure_available(TENANT, config, credential_for=credential_for(sam))
        ctx_sam = RunContext(run_id="r-sam", principal=sam, budget=_budget())
        seen_before = len(SEEN)
        broker.call(ctx_sam, config, "tracker_list_issues",
                    {"owner": "acme", "repo": "platform"})
        check("sam's credential on the wire",
              SEEN[seen_before]["authorization"], "Bearer sam-token")

        step("a write carries its JSON body, and only its mapped arguments")

        seen_before = len(SEEN)
        filed = broker.call(ctx, config, "tracker_create_issue",
                            {"owner": "acme", "repo": "platform", "title": "It broke"})
        check("created", filed.get("number"), 7)
        sent = SEEN[seen_before]
        check("POST with the body mapping", (sent["method"], sent["body"]),
              ("POST", {"title": "It broke"}))

        step("a path value is one URL-encoded segment, never spliced")

        seen_before = len(SEEN)
        broker.call(ctx, config, "tracker_list_issues",
                    {"owner": "acme corp", "repo": "platform"})
        check("the encoded path arrived", SEEN[seen_before]["path"],
              "/v1/repos/acme%20corp/platform/issues")

        seen_before = len(SEEN)
        spliced = broker.call(ctx, config, "tracker_list_issues",
                              {"owner": "acme/../../admin", "repo": "platform"})
        says("a slash refuses, naming the argument", spliced.get("error"), "owner")
        check("and NOTHING was sent", len(SEEN) - seen_before, 0)

        step("the failure shapes, from a real server")

        answered = broker.call(ctx, config, "tracker_list_issues",
                               {"owner": "acme", "repo": "gone"})
        says("a 404 is a tool error with the status", answered.get("error"), "404")
        says("and the vendor's own words", answered.get("error"), "no repository")
        check("never the URL", HOST in str(answered.get("error")), False)

        html = broker.call(ctx, config, "tracker_list_issues",
                           {"owner": "acme", "repo": "html"})
        says("non-JSON names the content type", html.get("error"), "text/html")

        redirected = broker.call(ctx, config, "tracker_list_issues",
                                 {"owner": "acme", "repo": "moved"})
        says("a redirect is NOT followed — it is a tool error", redirected.get("error"), "302")
        check("and the metadata service was never dialled",
              any("169.254" in str(s) for s in SEEN), False)

        step("the scope refuses before anything is sent")

        seen_before = len(SEEN)
        refused = broker.call(ctx, config, "tracker_list_issues",
                              {"owner": "rivals", "repo": "secrets"})
        says("out-of-scope refused", refused.get("error"), "Denied by broker")
        check("nothing reached the API", len(SEEN) - seen_before, 0)

        # --- the same arc through the door -----------------------------------------

        step("the door: a machine token drives the same tool through POST /mcp")

        store.create_user(TENANT, {"id": "u_priya", "issuer": "https://idp.example",
                                   "subject": "00u1", "email": "priya@acme.com"})
        row, presented = tokens.mint(TENANT, "priya-cursor", "u_priya", actor="system:cli")
        store.grant_agent(TENANT, "issue-clerk", "machine", row["id"],
                          role="user", granted_by=PRIYA, actor=PRIYA)
        # Through the door the caller IS the token, so a `user`-identity tool reads
        # the token's own connection — test_door's rule, exercised here over a real
        # socket. The label makes whose account reached the API unmistakable.
        machine = Principal.machine(row["id"], TENANT)
        connections.connect_account(machine, "tracker", "cursors-own-token",
                                    account_label="priya's editor", actor="system:cli")

        client = TestClient(create_app())
        auth = {"Authorization": f"Bearer {presented}"}

        listed = client.post("/mcp", headers=auth, json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/list",
        }).json()["result"]["tools"]
        check("tools/list is the grant list, with the authored schema",
              sorted(t["name"] for t in listed),
              ["tracker_create_issue", "tracker_list_issues"])
        listed_read = next(t for t in listed if t["name"] == "tracker_list_issues")
        check("the schema is the vetter's words", listed_read["inputSchema"], json.loads(SCHEMA))

        seen_before = len(SEEN)
        called = client.post("/mcp", headers=auth, json={
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "tracker_list_issues",
                       "arguments": {"owner": "acme", "repo": "platform"}},
        }).json()["result"]
        check("the door call succeeded", called.get("isError") is not True, True)
        says("with the API's answer", json.dumps(called), "an issue in platform")
        check("as the token's own connected account, per request",
              SEEN[seen_before]["authorization"], "Bearer cursors-own-token")

        step("a door call is not a run: one audit row, door-prefixed, no runs row")

        records = store.audit_records(TENANT)
        door_calls = [r for r in records if r["run_id"].startswith(storage.DOOR_CALL_ID_PREFIX)]
        check("exactly one door correlation id", len(door_calls), 1)
        check("and the runs table is empty of it",
              [r for r in store.list_runs(TENANT)], [])

        step("revoking the host stops the next call at dial time, vetting kept")

        store.revoke_host(TENANT, HOST, actor=PRIYA)
        seen_before = len(SEEN)
        stopped = client.post("/mcp", headers=auth, json={
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "tracker_list_issues",
                       "arguments": {"owner": "acme", "repo": "platform"}},
        }).json()["result"]
        check("refused", stopped.get("isError"), True)
        says("by egress", json.dumps(stopped), "EgressRefused")
        check("nothing dialled", len(SEEN) - seen_before, 0)
        check("the vetting survived",
              sorted(v.remote_name for v in mcp.get_connector(TENANT, "tracker").vetted),
              ["create_issue", "list_issues"])

        store.close()
    finally:
        server.shutdown()

    failed = [label for ok, label in CHECKS if not ok]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        print("\nFAILED:")
        for label in failed:
            print(f"  - {label}")
        raise SystemExit(1)


class _Unmetered:
    """A `core.limits.Spending` that never refuses. Step 084.

    The broker consumes a budget at step 2 of every call, so anything driving
    `broker.call` directly has to hand it one. This script used a permissive
    `core.limits.Budget` until 084 deleted it — a real enforcer, borrowed for its side
    effect by a script that is about a connector and not about a ceiling. Six lines that
    say so beat an import for its side effect, and `door.TokenBudget` would drag in
    storage and a spend ceiling this script has no opinion about.
    """

    def reserve(self, tool):
        from carnet.core.permissions import ALLOW

        return ALLOW

    def add_bytes(self, count):
        """Nothing. `door.TokenBudget.add_bytes` does the same and says why."""


def _budget():
    return _Unmetered()


def _generate_key():
    import base64
    import os as _os

    return base64.b64encode(_os.urandom(32)).decode()


if __name__ == "__main__":
    sys.exit(main())
