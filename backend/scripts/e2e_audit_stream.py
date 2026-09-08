"""The audit line on stdout, on the platform artefact — and a colleague leaving. Step 099,
journeys D8 and D9.

Step 096 put one JSON object per brokered call and per refusal on the server's stdout, so
a deployment's log pipeline gets the audit trail without a database query. `e2e_file_door`
reads it off a container running from a file; `tests/test_audit_stdout.py` reads it off a
captured stream against the in-memory store. Nobody had read it off **uvicorn with
Postgres behind it** — the platform artefact, where the line has a real tenant, the row it
mirrors is in a partitioned table, and the correlation id on the line is the one in the
row. That is D8.

D9 is the offboarding question, asked the way an operator asks it: *a colleague has left;
I ran one command; does their assistant stop, and can I see that it stopped?* The real
`carnet --disable-user` in its own process; the next door call with the token they minted;
what the stream says about it; and `--enable-user` to prove the refusal was the switch and
not a side effect.

    cd backend && CARNET_E2E_PG=postgresql://postgres:test@localhost:55432 \\
        .venv/bin/python scripts/e2e_audit_stream.py

Costs nothing: the upstream is a tiny MCP server in this process at `localtest.me`.
"""

from __future__ import annotations

import base64
import http.server
import json
import os
import pathlib
import socket
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit, urlunsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from e2e_file_door import TinyMcp  # noqa: E402

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_audit_stream"
BASE_DSN = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"

ISSUER = "https://e2e-audit-stream.local"
AUDIENCE = "api://default"
JWKS_PORT = 8914
API_PORT = 8145
MCP_PORT = 8953
API = f"http://127.0.0.1:{API_PORT}"
TENANT = "e2estream"
HOST = "localtest.me"
SHARED = "acme-shared-token-51c0"

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True)
JWK.update({"kid": "k1", "use": "sig", "alg": "RS256"})


def dsn_for(database: str) -> str:
    parts = urlsplit(BASE_DSN)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


def token(sub, email):
    now = int(time.time())
    return jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": sub, "email": email, "iat": now, "exp": now + 3600},
        KEY, algorithm="RS256", headers={"kid": "k1"},
    )


class Jwks(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"keys": [JWK]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


CHECKS: list = []


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok, actual, expected))
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: {actual!r}" + ("" if ok else f"  (expected {expected!r})"))
    return ok


def says(label, text, fragment):
    ok = fragment in str(text)
    CHECKS.append((label, ok, text, fragment))
    print(f"  {'ok  ' if ok else 'FAIL'} {label}" + ("" if ok else f"\n        wanted {fragment!r} in {str(text)[:300]!r}"))
    return ok


def say(what):
    print(f"\n=== {what}", flush=True)


def cli(*args):
    result = subprocess.run(
        [sys.executable, "-m", "carnet.cli", *args],
        env={**os.environ}, capture_output=True, text=True,
    )
    print("      $ carnet " + " ".join(args))
    for line in (result.stdout + result.stderr).strip().splitlines()[:8]:
        print(f"        {line}")
    return result


class Stream:
    """uvicorn, with its stdout read line by line — the pipeline's view."""

    def __init__(self):
        self.lines: list[str] = []
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port", str(API_PORT)],
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        threading.Thread(target=self._pump, daemon=True).start()
        for _ in range(60):
            if self.proc.poll() is not None:
                raise SystemExit("uvicorn exited")
            try:
                httpx.get(f"{API}/health", timeout=1)
                return
            except Exception:  # noqa: BLE001
                time.sleep(0.5)
        raise SystemExit("uvicorn did not come up")

    def _pump(self):
        for line in self.proc.stdout:
            self.lines.append(line.rstrip("\n"))

    def records(self) -> list[dict]:
        out = []
        for line in self.lines:
            if line.startswith("{"):
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
        return out

    def since(self, n: int) -> list[dict]:
        time.sleep(0.4)
        return self.records()[n:]

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def rpc(bearer: str, method: str, params=None, id_=1):
    r = httpx.post(f"{API}/mcp", headers={"Authorization": f"Bearer {bearer}"},
                   json={"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}},
                   timeout=30)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text


def main() -> int:
    import psycopg

    if socket.gethostbyname(HOST) != "127.0.0.1":
        print(f"SKIPPED: {HOST} did not resolve to 127.0.0.1; this needs outbound DNS")
        return 0

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")
    dsn = dsn_for(DB)
    os.environ["CARNET_DATABASE_URL"] = dsn
    os.environ["CARNET_SECRET_KEY"] = base64.b64encode(os.urandom(32)).decode()
    os.environ["CARNET_TENANT"] = TENANT
    os.environ["CARNET_EGRESS_INTERNAL_HOSTS"] = HOST
    os.environ["ACME_TOKEN"] = SHARED
    os.environ.pop("CARNET_AUDIT_STDOUT", None)  # the default is the artefact's default

    from carnet import storage, tools
    from carnet.core import crypto
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage
    from carnet.tools.base import Resource

    migrate.apply(dsn)
    store = storage.configure(PostgresStorage(dsn))
    crypto.configure(crypto.from_environment())
    store.create_tenant(TENANT, "096 on the platform")
    store.save_tenant_idp(TENANT, {
        "issuer": ISSUER, "jwks_uri": f"http://127.0.0.1:{JWKS_PORT}/jwks.json",
        "audience": AUDIENCE, "allowed_domains": ("acme.com",),
    })
    # The servers first: `vet_tool` dials the connector to check the tool it is told about.
    jwks = http.server.ThreadingHTTPServer(("127.0.0.1", JWKS_PORT), Jwks)
    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", MCP_PORT), TinyMcp)
    for server in (jwks, upstream):
        threading.Thread(target=server.serve_forever, daemon=True).start()

    store.allow_host(TENANT, HOST, actor="system:cli", note="our tracker")
    tools.register_connector(TENANT, "acme", url=f"http://{HOST}:{MCP_PORT}/mcp/",
                             credential_env="ACME_TOKEN", description="Acme's tracker",
                             actor="system:cli")
    tools.vet_tool(TENANT, "acme", "search_issues", effect="read", identity="service",
                   resources=(Resource("jira.project", ["project"]),),
                   actor="system:cli", credential=SHARED)
    tools.vet_tool(TENANT, "acme", "create_issue", effect="write", identity="service",
                   resources=(Resource("jira.project", ["project"]),),
                   actor="system:cli", credential=SHARED)

    stream = Stream()
    c = httpx.Client(base_url=API, timeout=20)
    priya = {"Authorization": f"Bearer {token('00u-priya', 'priya@acme.com')}"}
    try:
        say("priya builds an agent and mints the token her assistant will use")
        made = c.post("/agents", headers=priya, json={
            "name": "triage",
            "permissions": {"tools": ["acme_search_issues"], "scope": {"jira.project": {"read": ["ACME"]}}},
        })
        check("agent created", made.status_code, 201)
        minted = c.post("/me/tokens", headers=priya, json={"name": "my-assistant"})
        check("token minted", minted.status_code, 201)
        assistant = minted.json()["token"]
        token_id = minted.json()["id"]
        check("nothing has reached the stream yet", [r["type"] for r in stream.records()], [])

        say("D8: one allowed call, and the line a pipeline would read")
        n = len(stream.records())
        status, answer = rpc(assistant, "tools/call", {"name": "acme_search_issues", "arguments": {"project": "ACME"}})
        check("the call went through", (status, answer["result"].get("isError", False)), (200, False))
        call_id = answer["result"]["_meta"]["com.carnet/call-id"]
        lines = stream.since(n)
        check("exactly one line arrived", len(lines), 1)
        line = lines[0] if lines else {}
        check("it is an audit line for this tenant", (line.get("type"), line.get("tenant_id")), ("audit", TENANT))
        check("allowed, ok, by a machine, under the shared credential",
              (line.get("decision"), line.get("outcome"), line.get("principal_kind"), line.get("credential")),
              ("allow", "ok", "machine", "shared"))
        check("naming the tool, the agent and the arguments",
              (line.get("tool"), line.get("agent"), line.get("args")),
              ("acme_search_issues", "triage", {"project": "ACME"}))
        check("and its correlation id is the one the client got in _meta", line.get("run_id"), call_id)
        check("with a duration, as an integer of milliseconds", isinstance(line.get("duration_ms"), int), True)

        say("D8: the line mirrors the row — same id, same decision, in the partitioned table")
        with psycopg.connect(dsn) as conn:
            rows = conn.execute(
                "SELECT run_id, decision, outcome, tool FROM audit WHERE run_id = %s", (call_id,)
            ).fetchall()
        check("one row with that id", len(rows), 1)
        if rows:
            check("and it says what the line says", rows[0], (call_id, "allow", "ok", "acme_search_issues"))

        say("D8: a scope denial and a grant denial each arrive as their own line")
        n = len(stream.records())
        rpc(assistant, "tools/call", {"name": "acme_search_issues", "arguments": {"project": "OTHER"}}, id_=2)
        rpc(assistant, "tools/call", {"name": "acme_create_issue", "arguments": {"project": "ACME", "title": "x"}}, id_=3)
        lines = stream.since(n)
        check("two lines, in order",
              [(ln["type"], ln.get("decision") or ln.get("required")) for ln in lines],
              [("audit", "deny"), ("denial", "grant")])
        if len(lines) == 2:
            says("the scope denial carries its reason", lines[0].get("reason"), "OTHER")
            check("the grant denial names the tool nobody granted",
                  (lines[1].get("resource_kind"), lines[1].get("resource_id")), ("tool", "acme_create_issue"))
        check("the upstream saw only the allowed call", [p["arguments"] for p in TinyMcp.seen], [{"project": "ACME"}])

        say("D9: priya leaves. One command, in its own process")
        done = cli("--disable-user", "priya@acme.com")
        check("the command succeeded", done.returncode, 0)
        says("and said what happens next", done.stdout, "every API token they own is refused at its next call")

        say("D9: her assistant's next call is refused, and her own sign-in too")
        n = len(stream.records())
        status, refused = rpc(assistant, "tools/call", {"name": "acme_search_issues", "arguments": {"project": "ACME"}}, id_=4)
        check("the token is refused at the door", status, 403)
        says("with the reason", json.dumps(refused), "no longer an active account")
        check("tools/list is refused too", rpc(assistant, "tools/list", id_=5)[0], 403)
        check("her session is refused", c.get("/agents", headers=priya).status_code, 403)
        lines = stream.since(n)
        check("no allow line was written for the refused calls",
              [ln for ln in lines if ln.get("decision") == "allow"], [])
        print(f"        (the stream said: {[(ln['type'], ln.get('reason') or ln.get('required')) for ln in lines]!r})")
        check("the upstream was not reached", len(TinyMcp.seen), 1)
        listed = store.list_api_tokens(TENANT)
        mine = next(row for row in listed if row["id"] == token_id)
        check("the token row itself was not revoked — the owner was disabled", mine.get("revoked_at"), None)

        say("D9: --enable-user, and the same token works again — it was the switch")
        done = cli("--enable-user", "priya@acme.com")
        check("re-enabled", done.returncode, 0)
        status, answer = rpc(assistant, "tools/call", {"name": "acme_search_issues", "arguments": {"project": "ACME"}}, id_=6)
        check("the call goes through again", (status, answer["result"].get("isError", False)), (200, False))
        check("disabling twice is a no-op that says so",
              "already" in cli("--enable-user", "priya@acme.com").stdout, True)

        say("D8: the switch — CARNET_AUDIT_STDOUT=off — silences the stream and nothing else")
        stream.stop()
        os.environ["CARNET_AUDIT_STDOUT"] = "off"
        stream = Stream()
        status, answer = rpc(assistant, "tools/call", {"name": "acme_search_issues", "arguments": {"project": "ACME"}}, id_=7)
        check("the call still goes through", status, 200)
        time.sleep(0.4)
        check("and nothing reached stdout", stream.records(), [])
        with psycopg.connect(dsn) as conn:
            count = conn.execute("SELECT count(*) FROM audit").fetchone()[0]
        check("while the table still counts every decision", count, 4)
    finally:
        stream.stop()
        jwks.shutdown()
        upstream.shutdown()
        store.close()

    failed = [label for label, ok, *_ in CHECKS if not ok]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    for label in failed:
        print(f"  FAILED: {label}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
