"""The platform-role seam, over real HTTP, against real Postgres, from both sides.

**Not a test, and it is here because of what the suite structurally cannot do.**
`tests/test_api.py` runs against the in-memory store — `isolated_storage` is autouse and
always will be — so nothing in the suite puts an administrative route in front of a
database with a `platform_roles` table, a CHECK constraint and a foreign key. Every other
step that shipped a migration and a route added one of these for the same reason.

It also does the one thing no test can: **the grant is a real `carnet
--grant-role` subprocess**, so the arc that actually happens in a deployment — an engineer
at a terminal, a person in a browser — is the arc under test rather than a function call
standing in for it.

    cd backend && .venv/bin/python scripts/e2e_platform_roles.py

Needs Postgres started first. The DSN defaults to the unix socket this project uses and
can be pointed elsewhere:

    CARNET_E2E_PG=postgresql://postgres:postgres@localhost:55432 \
        .venv/bin/python scripts/e2e_platform_roles.py

It builds its own database (`carnet_roles_e2e`) and drops it on the way in, so it
does **not** touch `carnet_demo`. **Costs nothing** — no run is submitted, so no
model is called and no connector is launched.

What it does not replace: a browser. The nav item a non-admin must not see is
`verification 9` of the plan and is a thing somebody has to look at.
"""

import http.server
import json
import os
import pathlib
import subprocess
import sys
import threading
import time

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_roles_e2e"
BASE_DSN = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
ISSUER = "https://e2e-platform-roles.local"
AUDIENCE = "api://default"
JWKS_PORT = 8907
API_PORT = 8129
API = f"http://127.0.0.1:{API_PORT}"
TENANT = "e2eroles"

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True)
JWK.update({"kid": "k1", "use": "sig", "alg": "RS256"})


def dsn_for(database: str) -> str:
    """`BASE_DSN` with a database name spliced in, for both DSN spellings this runs under.

    A socket DSN carries its host in the query string (`postgresql://postgres:@/?host=…`)
    and a TCP one does not, so this cannot be a string concatenation — which is how the
    first version of it silently connected to the `postgres` database and reported that
    the migration had already been applied.
    """
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(BASE_DSN)
    return urlunsplit(
        (parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment)
    )


def token(sub, email):
    now = int(time.time())
    return jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": sub,
            "email": email,
            "iat": now,
            "exp": now + 3600,
        },
        KEY,
        algorithm="RS256",
        headers={"kid": "k1"},
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


CHECKS = []


def check(label, actual, expected):
    """**Every line this prints is an assertion**, and prints either way.

    `e2e_write_path.py`'s device, and its reason: the first version of that script printed
    and asserted almost nothing, which made it a demonstration — it would have gone on
    looking correct while quietly reporting a 500.
    """
    ok = actual == expected
    CHECKS.append((label, ok, actual, expected))
    mark = "ok  " if ok else "FAIL"
    print(f"  {mark} {label}: {actual!r}" + ("" if ok else f"  (expected {expected!r})"))
    return ok


def say(what):
    print(f"\n=== {what}", flush=True)


def cli(*args):
    """Run the real command, in its own process, against the same database.

    A subprocess rather than `cli.main()` in-process, because the thing being verified is
    that **an engineer at a terminal can grant a role a browser then honours** — two
    processes, one database, which is the only shape that can fail.
    """
    result = subprocess.run(
        [sys.executable, "-m", "carnet.cli", *args],
        env={**os.environ, "CARNET_TENANT": TENANT},
        capture_output=True,
        text=True,
    )
    print("      $ carnet " + " ".join(args))
    for line in (result.stdout + result.stderr).splitlines():
        print(f"        {line}")
    return result


def main():
    import psycopg

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")

    dsn = dsn_for(DB)
    os.environ["CARNET_DATABASE_URL"] = dsn
    os.environ["CARNET_SECRET_KEY"] = (
        os.environ.get("CARNET_SECRET_KEY") or _generate_key()
    )
    os.environ["CARNET_WORKERS"] = "0"
    os.environ["CARNET_TENANT"] = TENANT

    from carnet import bootstrap, storage
    from carnet.storage import migrate

    migrate.apply(dsn)

    from carnet.storage.postgres import PostgresStorage

    store = storage.configure(PostgresStorage(dsn))
    store.create_tenant(TENANT, "12b end to end")
    bootstrap.seed_tenant(TENANT)
    store.save_tenant_idp(
        TENANT,
        {
            "issuer": ISSUER,
            "jwks_uri": f"http://127.0.0.1:{JWKS_PORT}/jwks.json",
            "audience": AUDIENCE,
            "allowed_domains": ("acme.com",),
        },
    )

    server = http.server.ThreadingHTTPServer(("127.0.0.1", JWKS_PORT), Jwks)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port", str(API_PORT)],
        env={**os.environ},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(60):
            try:
                httpx.get(f"{API}/health", timeout=1)
                break
            except Exception:
                time.sleep(0.5)
        else:
            raise SystemExit("uvicorn did not come up")

        run(store)
    finally:
        api.terminate()
        api.wait(timeout=10)
        server.shutdown()
        store.close()


def _generate_key():
    import base64
    import os as _os

    return base64.b64encode(_os.urandom(32)).decode()


def run(store):
    priya = {"Authorization": f"Bearer {token('00u-priya', 'priya@acme.com')}"}
    sam = {"Authorization": f"Bearer {token('00u-sam', 'sam@acme.com')}"}
    c = httpx.Client(base_url=API, timeout=20)

    say("both people sign in. Nobody is an administrator, and the CLI is")
    check("priya's first request works", c.get("/agents", headers=priya).status_code, 200)
    check("sam's too", c.get("/agents", headers=sam).status_code, 200)
    check("GET /me says priya is not an admin", c.get("/me", headers=priya).json()["admin"], False)
    check("and names her by her email", c.get("/me", headers=priya).json()["email"], "priya@acme.com")
    check("--list-roles finds nothing", store.list_platform_roles(TENANT), [])

    say("the four refusals, and each carries a sentence a person can act on")
    refused = c.get("/admin-audit", headers=priya)
    check("GET /admin-audit", refused.status_code, 403)
    check("  says you are not one", "administrator" in refused.json()["detail"], True)
    check("  and how to become one", "grant" in refused.json()["detail"], True)
    check("  and names NO current admins", "sam" in refused.json()["detail"], False)
    check("POST /groups", c.post("/groups", json={"name": "x"}, headers=priya).status_code, 403)
    check("GET /groups/{id}", c.get("/groups/g-nope", headers=priya).status_code, 403)
    check("PUT a member", c.put("/groups/g-nope/members/user/u-1", headers=priya).status_code, 403)
    check("DELETE a member", c.delete("/groups/g-nope/members/user/u-1", headers=priya).status_code, 403)
    check("DELETE /groups/{id}", c.delete("/groups/g-nope", headers=priya).status_code, 403)

    say("and an unauthenticated caller gets 401, not 403 — identity before role")
    check("no token on /admin-audit", c.get("/admin-audit").status_code, 401)
    check("no token on POST /groups", c.post("/groups", json={"name": "x"}).status_code, 401)
    check("a garbage token", c.get("/admin-audit", headers={"Authorization": "Bearer nope"}).status_code, 401)

    say("the menu is readable and the directory is not — decision 6's line")
    check("GET /groups is 200 for a non-admin", c.get("/groups", headers=priya).status_code, 200)

    say("an engineer at a terminal grants the role. A DIFFERENT PROCESS, one database")
    granted = cli("--grant-role", "admin", "priya@acme.com")
    check("the command succeeded", granted.returncode, 0)
    check("and said it is not a master key", "no agent" in granted.stdout, True)

    say("the same browser session, unchanged, is now an administrator")
    check("GET /me", c.get("/me", headers=priya).json()["admin"], True)
    log = c.get("/admin-audit", headers=priya)
    check("GET /admin-audit", log.status_code, 200)
    check("and it is the log 011 built", "role.grant" in [r["action"] for r in log.json()], True)
    check("sam is still refused", c.get("/admin-audit", headers=sam).status_code, 403)

    say("group administration over HTTP — 9a's oldest debt, paid")
    created = c.post(
        "/groups", json={"name": "oncall", "description": "who carries the pager"},
        headers=priya,
    )
    check("POST /groups", created.status_code, 201)
    group_id = created.json().get("group_id", "")
    check("the id is opaque and ours", group_id.startswith("g_"), True)
    check("a duplicate name is a 400, not a 503",
          c.post("/groups", json={"name": "oncall"}, headers=priya).status_code, 400)

    sam_id = store.find_user_by_email(TENANT, "sam@acme.com")["id"]
    added = c.put(f"/groups/{group_id}/members/user/{sam_id}", headers=priya)
    check("PUT a member", added.status_code, 200)
    check("  and it says it changed something", added.json().get("changed"), True)
    check("  a second time says it did not",
          c.put(f"/groups/{group_id}/members/user/{sam_id}", headers=priya).json().get("changed"),
          False)

    detail = c.get(f"/groups/{group_id}", headers=priya)
    check("GET /groups/{id} carries the membership", detail.status_code, 200)
    check("  which is sam", [m["id"] for m in detail.json().get("members", [])], [sam_id])
    check("sam cannot read it", c.get(f"/groups/{group_id}", headers=sam).status_code, 403)
    check("but he can read the menu",
          [g["name"] for g in c.get("/groups", headers=sam).json()], ["oncall"])
    check("and the menu carries no membership",
          "members" in c.get("/groups", headers=sam).json()[0], False)

    say("a group cannot be a member of a group, and a missing one is a 400 not a 500")
    check("nesting refused", c.put(f"/groups/{group_id}/members/group/g-x", headers=priya).status_code, 400)
    check("no such group", c.get("/groups/g-nope", headers=priya).status_code, 400)

    say("AN ADMIN IS NOT A SUPERUSER — the boundary migration 026 states in the schema")
    check("the seeded agent belongs to system:cli",
          store.agent_grant_role(TENANT, "issue-reporter", "user", _id(store, "priya@acme.com")),
          None)
    check("GET /agents lists none of it", c.get("/agents", headers=priya).json(), [])
    check("GET /agents/issue-reporter is 404, not 403",
          c.get("/agents/issue-reporter", headers=priya).status_code, 404)
    check("and she is still an administrator", c.get("/me", headers=priya).json()["admin"], True)

    say("granting to an address nobody has used is refused — a role is not an invitation")
    pending = cli("--grant-role", "admin", "newhire@acme.com")
    check("refused", pending.returncode != 0, True)
    check("  with the sentence", "not an invitation" in pending.stderr, True)
    check("  and nothing was written",
          [r["principal_id"] for r in store.list_platform_roles(TENANT)],
          [_id(store, "priya@acme.com")])

    say("revoked, and the same session is refused again")
    revoked = cli("--revoke-role", "admin", "priya@acme.com")
    check("the command succeeded", revoked.returncode, 0)
    check("  and warned that nobody is left", "no administrators" in revoked.stderr, True)
    check("GET /admin-audit", c.get("/admin-audit", headers=priya).status_code, 403)
    check("GET /me", c.get("/me", headers=priya).json()["admin"], False)
    check("POST /groups", c.post("/groups", json={"name": "y"}, headers=priya).status_code, 403)

    say("revoking again is a no-op and records nothing")
    before = len(store.admin_audit_records(TENANT, action="role.revoke"))
    again = cli("--revoke-role", "admin", "priya@acme.com")
    check("said so", "Nothing to do" in again.stdout, True)
    check("and wrote no second record",
          len(store.admin_audit_records(TENANT, action="role.revoke")), before)

    say("re-granted: three records, and the most recent yes is the one that stands")
    cli("--grant-role", "admin", "priya@acme.com")
    priya_id = _id(store, "priya@acme.com")
    role_records = [
        r for r in store.admin_audit_records(TENANT)
        if r["action"] in ("role.grant", "role.revoke")
    ]
    for r in role_records:
        print(
            f"        {r['ts'][11:19]}  {r['actor_kind']}:{r['actor_id'][:16]:20}"
            f"{r['action']:14}{r['target_kind']}:{r['target_id']}"
        )
    check("three of them", [r["action"] for r in role_records],
          ["role.grant", "role.revoke", "role.grant"])
    check("every one names the person it was about",
          {r["target_id"] for r in role_records}, {priya_id})
    check("and the target kind is the one 12b added",
          {r["target_kind"] for r in role_records}, {"user"})
    check("actor is the shell every time",
          {f"{r['actor_kind']}:{r['actor_id']}" for r in role_records}, {"system:cli"})
    check("and she is an administrator again", c.get("/me", headers=priya).json()["admin"], True)

    say("reading the log is not itself recorded")
    before_reads = len(store.admin_audit_records(TENANT))
    for _ in range(3):
        c.get("/admin-audit", headers=priya)
    check("no records added", len(store.admin_audit_records(TENANT)), before_reads)

    say("the log answers only for this tenant, and the limit is capped by the signature")
    check("limit=1 returns one", len(c.get("/admin-audit?limit=1", headers=priya).json()), 1)
    check("limit=0 is a 422", c.get("/admin-audit?limit=0", headers=priya).status_code, 422)
    check("limit=1000000 is a 422 rather than silent truncation",
          c.get("/admin-audit?limit=1000000", headers=priya).status_code, 422)

    say("no secret and no prompt reached any of it")
    everything = json.dumps(store.admin_audit_records(TENANT))
    check("no encryption key", os.environ["CARNET_SECRET_KEY"] in everything, False)
    check("no agent prompt", "You are" in everything, False)

    failed = [label for label, ok, *_ in CHECKS if not ok]
    say(f"{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        for label in failed:
            print("  FAILED:", label)
        raise SystemExit(1)


def _id(store, email):
    return store.find_user_by_email(TENANT, email)["id"]


if __name__ == "__main__":
    main()
