"""`CARNET_OPEN_ADMIN`, over real HTTP against real Postgres. Step 099, journey B8.

Step 097 added the switch for the four-person team that does not want an administrator:
with it on, every signed-in *person* administers, no role row is written, and turning it
off restores the gate exactly. `tests/test_roles.py` proves the predicate against the
in-memory store; nothing had put the switch in front of a database, a real sign-in, a
real API token and the administrative log — which is where a person would look to find
out who did what while the door was open.

    cd backend && CARNET_E2E_PG=postgresql://postgres:test@localhost:55432 \\
        .venv/bin/python scripts/e2e_open_admin.py

Two boots of the same database, because the switch is read at startup:

  1. **off** — two people sign in; both are refused the administrative surface, in the
     server's own words.
  2. **on** — the same two people administer: they approve a host, register a connector,
     create a group, read the administrative log — and **the log names each of them**,
     not a shared or system principal. A machine token minted by one of them is still
     refused: the switch is for people. `platform_roles` stays empty throughout.
  3. **off again** — the gate is back, and what they administered while it was open is
     still there: the switch changed who may act, not what was done.

Costs nothing: no vendor, no MCP server, no browser.
"""

from __future__ import annotations

import base64
import http.server
import json
import os
import pathlib
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit, urlunsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_open_admin"
BASE_DSN = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"

ISSUER = "https://e2e-open-admin.local"
AUDIENCE = "api://default"
JWKS_PORT = 8911
API_PORT = 8141
API = f"http://127.0.0.1:{API_PORT}"
TENANT = "e2eopen"

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


class Api:
    def __init__(self, open_admin: str):
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port", str(API_PORT)],
            env={**os.environ, "CARNET_OPEN_ADMIN": open_admin},
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )
        for _ in range(60):
            if self.proc.poll() is not None:
                raise SystemExit(f"uvicorn exited: {self.proc.stderr.read()[-2000:]}")
            try:
                httpx.get(f"{API}/health", timeout=1)
                return
            except Exception:  # noqa: BLE001
                time.sleep(0.5)
        raise SystemExit("uvicorn did not come up")

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def main() -> int:
    import psycopg

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")
    dsn = dsn_for(DB)
    os.environ["CARNET_DATABASE_URL"] = dsn
    os.environ["CARNET_SECRET_KEY"] = base64.b64encode(os.urandom(32)).decode()
    os.environ["CARNET_TENANT"] = TENANT
    os.environ.pop("CARNET_OPEN_ADMIN", None)

    from carnet import storage
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    migrate.apply(dsn)
    store = storage.configure(PostgresStorage(dsn))
    store.create_tenant(TENANT, "097 end to end")
    store.save_tenant_idp(TENANT, {
        "issuer": ISSUER, "jwks_uri": f"http://127.0.0.1:{JWKS_PORT}/jwks.json",
        "audience": AUDIENCE, "allowed_domains": ("acme.com",),
    })
    jwks = http.server.ThreadingHTTPServer(("127.0.0.1", JWKS_PORT), Jwks)
    threading.Thread(target=jwks.serve_forever, daemon=True).start()

    priya = {"Authorization": f"Bearer {token('00u-priya', 'priya@acme.com')}"}
    sam = {"Authorization": f"Bearer {token('00u-sam', 'sam@acme.com')}"}
    c = httpx.Client(base_url=API, timeout=20)

    try:
        say("1. the switch is off: two people sign in and neither administers")
        api = Api("off")
        try:
            check("priya is signed in, and not an admin", c.get("/me", headers=priya).json()["admin"], False)
            check("sam likewise", c.get("/me", headers=sam).json()["admin"], False)
            refused = c.get("/admin-audit", headers=priya)
            check("GET /admin-audit is refused", refused.status_code, 403)
            says("in the server's words", refused.json()["detail"], "administrator")
            check("POST /admin/hosts is refused", c.post("/admin/hosts", json={"host": "mcp.example.com"}, headers=sam).status_code, 403)
            check("POST /groups is refused", c.post("/groups", json={"name": "oncall"}, headers=sam).status_code, 403)
            check("no role row exists", store.list_platform_roles(TENANT), [])
        finally:
            api.stop()

        say("2. the switch is on: the same people, the same database, and both administer")
        api = Api("on")
        try:
            check("priya is now an admin, says /me", c.get("/me", headers=priya).json()["admin"], True)
            check("and so is sam", c.get("/me", headers=sam).json()["admin"], True)
            check("and still no role row was written", store.list_platform_roles(TENANT), [])

            approved = c.post("/admin/hosts", json={"host": "mcp.example.com", "note": "our Jira"}, headers=priya)
            check("priya approves a host", approved.status_code, 200)
            registered = c.post("/admin/connectors", json={
                "connector_id": "jira", "url": "https://mcp.example.com/mcp",
                "credential_env": "JIRA_TOKEN", "description": "Jira",
            }, headers=priya)
            check("and registers a connector", registered.status_code, 201)
            group = c.post("/groups", json={"name": "oncall"}, headers=sam)
            check("sam creates a group", group.status_code, 201)
            log = c.get("/admin-audit", headers=sam)
            check("sam reads the administrative log", log.status_code, 200)
            actors = {row["action"]: f"{row['actor_kind']}:{row['actor_id']}" for row in log.json()}
            priya_id = c.get("/me", headers=priya).json()["principal"]
            sam_id = c.get("/me", headers=sam).json()["principal"]
            check("the host approval names priya, not a shared principal",
                  actors.get("egress.allow"), priya_id)
            check("the connector registration names priya", actors.get("connector.create"), priya_id)
            check("the group creation names sam", actors.get("group.create"), sam_id)

            say("2. the switch is for people — a machine token is still refused")
            minted = c.post("/me/tokens", json={"name": "sam's assistant"}, headers=sam)
            check("sam mints a token", minted.status_code, 201)
            machine = {"Authorization": f"Bearer {minted.json()['token']}"}
            check("it is a machine, says /me", c.get("/me", headers=machine).json()["kind"], "machine")
            check("and it is not an administrator", c.get("/me", headers=machine).json()["admin"], False)
            check("GET /admin-audit with it is refused", c.get("/admin-audit", headers=machine).status_code, 403)
            check("POST /groups with it is refused",
                  c.post("/groups", json={"name": "x"}, headers=machine).status_code, 403)
        finally:
            api.stop()

        say("3. off again: the gate is back, and what was done stays done")
        api = Api("off")
        try:
            check("priya is not an admin", c.get("/me", headers=priya).json()["admin"], False)
            check("GET /admin-audit is refused again", c.get("/admin-audit", headers=priya).status_code, 403)
            check("the connector they registered is still there",
                  [row["id"] for row in store.load_connectors(TENANT)], ["jira"])
            check("and the group", [g["name"] for g in store.list_groups(TENANT)], ["oncall"])
            check("and the host", sorted(row["host"] for row in store.allowed_hosts(TENANT)), ["mcp.example.com"])
            check("the log kept every record with its real actor",
                  sorted(set(a for a in actors.values())), sorted({priya_id, sam_id}))
        finally:
            api.stop()

        say("a value that is neither on nor off refuses to start")
        proc = subprocess.run(
            [sys.executable, "-c", "import carnet.config"],
            env={**os.environ, "CARNET_OPEN_ADMIN": "yes"}, capture_output=True, text=True,
        )
        check("import refused", proc.returncode != 0, True)
        says("naming the values", proc.stderr, "must be 'on' or 'off'")
    finally:
        jwks.shutdown()
        store.close()

    failed = [label for label, ok, *_ in CHECKS if not ok]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    for label in failed:
        print(f"  FAILED: {label}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
