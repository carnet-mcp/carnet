"""The machine caller, over real HTTP, against real Postgres, from the terminal outward.

**Not a test, and it is here because of what the suite structurally cannot do.**
`tests/test_api.py` runs against the in-memory store — `isolated_storage` is autouse and
always will be — so nothing in the suite puts the token door in front of a database with
an `api_tokens` table, six widened CHECK constraints and two deliberately narrow ones.
Every step that shipped a migration and a route has added one of these for the same
reason.

It also does the two things no test can. **The token is minted by a real `carnet
--mint-token` subprocess and read off its stdout**, which is the only place that secret
ever exists — so the arc under test is the one a deployment actually performs, an
engineer at a terminal handing a string to a pipeline. And the constraint names are
asserted against `pg_constraint` rather than against the migration's source text, which
is the specific thing that went wrong on the way in: migration 030's inline CHECKs landed
with a `1` suffix that appears nowhere in 030, so the obvious `DROP CONSTRAINT IF EXISTS`
would have been silent and the narrow constraint would have survived.

    cd backend && .venv/bin/python scripts/e2e_machine_caller.py

Needs Postgres started first. The DSN defaults to the unix socket this project uses and
can be pointed elsewhere:

    CARNET_E2E_PG=postgresql://postgres:postgres@localhost:55432/ \
        .venv/bin/python scripts/e2e_machine_caller.py

It builds its own database (`carnet_machine_e2e`) and drops it on the way in, so
it does **not** touch `carnet_demo`. **Costs nothing** — the run it submits is
claimed by no worker (`CARNET_WORKERS=0`), so no model is called.

What it does not replace: a browser. There is no screen for any of this, deliberately —
minting is CLI-only, and that is decision 3 rather than an omission.
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
DB = "carnet_machine_e2e"
BASE_DSN = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
ISSUER = "https://e2e-machine-caller.local"
AUDIENCE = "api://default"
JWKS_PORT = 8911
API_PORT = 8133
API = f"http://127.0.0.1:{API_PORT}"
TENANT = "e2emachine"

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True)
JWK.update({"kid": "k1", "use": "sig", "alg": "RS256"})

AGENT = {
    "name": "nightly-summary",
    "system": "You summarize things.",
    "permissions": {
        "tools": ["post_message"],
        "scope": {"chat.channel": {"write": ["#eng"]}},
    },
}


def dsn_for(database: str) -> str:
    """`BASE_DSN` with a database name spliced in, for both DSN spellings this runs under."""
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
    """**Every line this prints is an assertion**, and prints either way."""
    ok = actual == expected
    CHECKS.append((label, ok, actual, expected))
    mark = "ok  " if ok else "FAIL"
    print(f"  {mark} {label}: {actual!r}" + ("" if ok else f"  (expected {expected!r})"))
    return ok


def field(value, *path, default="<missing>"):
    """Reach into a structure without raising. 12c's `detail()` doctrine.

    A broken thing must report everything that is broken: the first version of
    `e2e_tenant_deletion.py` crashed at the first `None` and reported one failure where
    twenty-two followed.
    """
    for key in path:
        try:
            value = value[key]
        except (KeyError, IndexError, TypeError):
            return default
    return value


def say(what):
    print(f"\n=== {what}", flush=True)


def cli(*args, quiet=False):
    """Run the real command, in its own process, against the same database."""
    result = subprocess.run(
        [sys.executable, "-m", "carnet.cli", *args],
        env={**os.environ, "CARNET_TENANT": TENANT},
        capture_output=True,
        text=True,
    )
    print("      $ carnet " + " ".join(args))
    if not quiet:
        for line in (result.stdout + result.stderr).splitlines():
            # The PythonFinalizationError traceback at interpreter shutdown is a known
            # pre-existing annoyance on 3.14 — see the handoff. It is noise here.
            if "PythonFinalization" in line or "psycopg_pool" in line:
                continue
            print(f"        {line}")
    return result


def token_string(said: str) -> str:
    """The credential out of what `--mint-token` printed. The only copy there is."""
    for line in said.splitlines():
        if line.strip().startswith("art_"):
            return line.strip()
    return ""


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
    # No worker: the run must reach `queued` and stay there, so nothing calls a model.
    os.environ["CARNET_WORKERS"] = "0"
    os.environ["CARNET_TENANT"] = TENANT

    from carnet import storage
    from carnet.storage import migrate

    migrate.apply(dsn)

    from carnet.storage.postgres import PostgresStorage

    store = storage.configure(PostgresStorage(dsn))
    store.create_tenant(TENANT, "020 end to end")
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

        run(store, dsn)
    finally:
        api.terminate()
        api.wait(timeout=10)
        server.shutdown()
        store.close()


def _generate_key():
    import base64
    import os as _os

    return base64.b64encode(_os.urandom(32)).decode()


def run(store, dsn):
    import psycopg

    priya = {"Authorization": f"Bearer {token('00u-priya', 'priya@acme.com')}"}
    c = httpx.Client(base_url=API, timeout=20)

    say("a person signs in, so there is somebody a token can belong to")
    check("priya's first request works", c.get("/agents", headers=priya).status_code, 200)
    priya_id = field(store.find_user_by_email(TENANT, "priya@acme.com"), "id")
    check("she has a user row", priya_id.startswith("u_"), True)
    store.create_agent(TENANT, AGENT, "user", priya_id)
    check("and owns an agent", field(store.get_agent(TENANT, AGENT["name"]), "name"),
          AGENT["name"])

    say("the CHECK constraints, read out of pg_constraint rather than out of a migration")
    # **This is the assertion the step's one real defect would have failed.** Migration
    # 030 declared its CHECKs inline, so the rename that preceded it pushed them to
    # `..._check1` — a name that appears nowhere in 030's source. `DROP CONSTRAINT IF
    # EXISTS <the obvious name>` is silent, and the narrow constraint would have survived
    # while 031 read as though it had widened it.
    with psycopg.connect(dsn, autocommit=True) as conn:
        defs = {
            f"{row[0]}": row[1]
            for row in conn.execute(
                "SELECT conrelid::regclass::text || '.' || conname, "
                "pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE contype = 'c' AND pg_get_constraintdef(oid) LIKE '%kind%' "
                "AND conrelid::regclass::text NOT LIKE '%\\_p2%'"
            ).fetchall()
        }
    widened = {
        name.split(".")[0]
        for name, body in defs.items()
        if "machine" in body and "no_machine" not in name
    }
    check("six columns admit a machine", widened,
          {"runs", "connections", "group_members", "audit", "access_denials",
           "agent_grants"})
    narrow = {
        name.split(".")[0]
        for name, body in defs.items()
        if "'user'" in body and "machine" not in body
    }
    check("and two deliberately do not", narrow, {"platform_roles", "admin_audit"})
    check("the machine ladder ceiling exists",
          any("no_machine_above_user" in name for name in defs), True)

    say("minting is a real subprocess, and the secret exists exactly once")
    minted = cli("--mint-token", "nightly-ci", "priya@acme.com")
    check("--mint-token exits 0", minted.returncode, 0)
    presented = token_string(minted.stdout)
    check("it printed a credential", presented.startswith("art_m_"), True)
    check("exactly once", minted.stdout.count(presented), 1)
    check("and said so", "only time that string exists" in minted.stdout, True)

    token_id = presented[len("art_"):].split(".")[0]
    secret = presented.rsplit(".", 1)[1] if "." in presented else "<none>"
    row = store.find_api_token(token_id)
    check("the row stores a digest, not the secret", field(row, "secret_hash").startswith("sha256$"), True)
    check("the secret is nowhere in the row", secret in json.dumps(row, default=str), False)
    check("it is owned by priya", field(row, "owner_id"), priya_id)
    check("it never expires", field(row, "expires_at"), None)
    check("and has never been used", field(row, "last_used_at"), None)

    machine = {"Authorization": f"Bearer {presented}"}

    say("THE TRAP: a machine is an administrator nowhere")
    check("GET /admin-audit is refused", c.get("/admin-audit", headers=machine).status_code, 403)
    check("so is POST /groups", c.post("/groups", json={"name": "x"}, headers=machine).status_code, 403)
    check("GET /me says not an admin", field(c.get("/me", headers=machine).json(), "admin"), False)
    denials = [d for d in store.denial_records(TENANT) if d["principal_kind"] == "machine"]
    check("the refusals are in the denial log", len(denials) >= 2, True)
    check("naming the machine", {d["principal_id"] for d in denials}, {token_id})
    check("the CLI cannot make it one either",
          cli("--grant-role", "admin", f"machine:{token_id}").returncode, 2)
    check("and no role landed", store.list_platform_roles(TENANT), [])

    say("it holds no access until somebody grants it — like anybody else")
    denied = c.get(f"/agents/{AGENT['name']}", headers=machine)
    check("GET /agents/{name} is a 404, the same one a stranger gets", denied.status_code, 404)
    check("and it names no agent", "nightly-summary" in field(denied.json(), "detail"), True)

    # **The owner grants it, over HTTP, from the app.** Not the CLI: `--share-agent` runs
    # as `system:cli`, and holding `admin` grants access to no agent — migration 026's
    # "an admin is not a superuser", which this script assumed away on the first attempt
    # and which cost two checks that were passing for the wrong reason. The CLI path is
    # exercised below on an agent the shell actually owns.
    put = c.put(
        f"/agents/{AGENT['name']}/grants/machine/{token_id}",
        json={"role": "user"},
        headers=priya,
    )
    check("the owner grants it over HTTP", put.status_code, 200)
    check("and the outcome is granted, not pending", field(put.json(), "outcome"), "granted")

    # The ladder cap through the route, which is where somebody would actually hit it.
    # Asserted on the **status and the sentence**, because a 400 for the wrong reason is
    # what the first version of this script recorded as a pass.
    too_high = c.put(
        f"/agents/{AGENT['name']}/grants/machine/{token_id}",
        json={"role": "editor"},
        headers=priya,
    )
    check("editor over HTTP is a 400", too_high.status_code, 400)
    check("  and says why", "a machine may be granted" in field(too_high.json(), "detail"), True)
    check("  and the grant is unchanged",
          store.agent_grant_role(TENANT, AGENT["name"], "machine", token_id), "user")

    access = c.get(f"/agents/{AGENT['name']}/access", headers=priya).json()
    entries = {(e["kind"], e["id"]): e["role"] for e in field(access, "access", default=[])}
    check("who_has_access lists the machine", entries.get(("machine", token_id)), "user")
    check("beside the person", entries.get(("user", priya_id)), "owner")

    # And the CLI surface, on an agent the shell owns — so both doors are driven rather
    # than one being inherited silently.
    shell_agent = {**AGENT, "name": "shell-owned"}
    store.create_agent(TENANT, shell_agent, "system", "cli")
    check("--share-agent to a machine works",
          cli("--share-agent", "shell-owned", f"machine:{token_id}",
              "--role", "user").returncode, 0)
    check("  and the grant is real",
          store.agent_grant_role(TENANT, "shell-owned", "machine", token_id), "user")
    editor_cli = cli("--share-agent", "shell-owned", f"machine:{token_id}",
                     "--role", "editor")
    check("editor on the CLI is refused", editor_cli.returncode, 2)
    check("  for the machine reason, not for a missing grant",
          "a machine may be granted" in (editor_cli.stdout + editor_cli.stderr), True)

    say("and now it can reach the agent, which is the whole point of the step")
    reached = c.get(f"/agents/{AGENT['name']}", headers=machine)
    check("GET /agents/{name} is 200", reached.status_code, 200)
    check("last_used_at is stamped now", field(store.find_api_token(token_id), "last_used_at") is not None, True)

    say("every bad credential gets one sentence, byte for byte the human one")
    human = c.get("/agents", headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.e30.x"})
    check("a forged JWT is 401", human.status_code, 401)
    for label, bad in (
        ("unknown id", "art_m_nosuchtokenatall.secret"),
        ("wrong secret", presented.rsplit(".", 1)[0] + ".wrong"),
        ("no separator", presented.rsplit(".", 1)[0]),
        ("prefix alone", "art_"),
    ):
        response = c.get("/agents", headers={"Authorization": f"Bearer {bad}"})
        check(f"  {label} is 401", response.status_code, 401)
        check(f"  {label} says the same thing", response.json(), human.json())

    say("suspension closes the machine door with the same sentence as the human one")
    store.set_tenant_status(TENANT, "suspended")
    suspended_human = c.get("/agents", headers=priya)
    suspended_machine = c.get("/agents", headers=machine)
    check("the person is 403", suspended_human.status_code, 403)
    check("the machine is 403", suspended_machine.status_code, 403)
    check("and the sentence is identical", suspended_machine.json(), suspended_human.json())
    store.set_tenant_status(TENANT, "active")
    check("both work again after resuming", c.get("/agents", headers=machine).status_code, 200)

    say("disabling the owner closes their machines — the offboarding property")
    store.set_user_status(TENANT, priya_id, "disabled", actor="system:cli")
    orphaned = c.get("/agents", headers=machine)
    check("the machine is 403", orphaned.status_code, 403)
    check("and says why", "owner of this API token" in field(orphaned.json(), "detail"), True)
    store.set_user_status(TENANT, priya_id, "active", actor="system:cli")
    check("and works again when they return", c.get("/agents", headers=machine).status_code, 200)

    # **Not the exact-instant boundary**, and saying so matters: time passes between
    # minting a token and presenting it, so a token expiring "now" is already stale by
    # the time it arrives and `<` and `<=` both refuse it. Mutating the comparison left
    # this whole script green, which is how that was found. The strict boundary is
    # asserted against a frozen clock in `test_the_expiry_boundary_is_strict_at_the_exact_instant`;
    # what this proves is the coarse property, over real HTTP.
    say("expiry: a passed token is refused and a future one is not")
    from datetime import datetime, timedelta, timezone

    from carnet.access import tokens as tokens_module

    live = []
    for label, when in (
        ("past", datetime.now(timezone.utc) - timedelta(seconds=1)),
        ("future", datetime.now(timezone.utc) + timedelta(hours=1)),
    ):
        _, string = tokens_module.mint(
            TENANT, f"expiry-{label}", priya_id, actor="system:cli", expires_at=when
        )
        if c.get("/agents", headers={"Authorization": f"Bearer {string}"}).status_code == 200:
            live.append(label)
    check("only the future one resolves", live, ["future"])

    say("revocation closes the door and leaves the row")
    revoked = cli("--revoke-token", token_id)
    check("--revoke-token exits 0", revoked.returncode, 0)
    check("the next request is 401", c.get("/agents", headers=machine).status_code, 401)
    check("with the same sentence as everything else",
          c.get("/agents", headers=machine).json(), human.json())
    check("the row survives", store.find_api_token(token_id) is not None, True)
    check("stamped with who did it", field(store.find_api_token(token_id), "revoked_by"), "system:cli")
    check("revoking again is idempotent", cli("--revoke-token", token_id).returncode, 0)

    say("and the audit trail names the machine, years after the token is closed")
    records = store.admin_audit_records(TENANT)
    token_records = [r for r in records if r["action"].startswith("token.")]
    # Counted rather than ordered: three tokens were minted (one here, two by the expiry
    # checks above) and one revoked, and asserting the sequence would be asserting this
    # script's own order of operations rather than the log's behaviour.
    check("three mints are recorded",
          sum(1 for r in token_records if r["action"] == "token.mint"), 3)
    check("and one revoke, not two despite revoking twice",
          sum(1 for r in token_records if r["action"] == "token.revoke"), 1)
    check("against the machine as target", {r["target_kind"] for r in token_records}, {"machine"})
    check("the actor is always the shell, never a machine",
          {f"{r['actor_kind']}:{r['actor_id']}" for r in token_records}, {"system:cli"})
    check("the mint record names the owner",
          field([r for r in token_records if r["action"] == "token.mint"][0], "detail", "owner"),
          priya_id)

    say("no secret reached any record")
    everything = json.dumps(records, default=str) + json.dumps(
        store.audit_records(TENANT), default=str
    )
    check("not the token", secret in everything, False)
    check("not the encryption key", os.environ["CARNET_SECRET_KEY"] in everything, False)

    say("--list-tokens shows what exists and what happened to it")
    listed = cli("--list-tokens")
    check("it lists the revoked one", "revoked" in listed.stdout, True)
    check("and the live ones", "expiry-future" in listed.stdout, True)
    check("no hash is printed", "sha256$" in listed.stdout, False)

    failed = [label for label, ok, *_ in CHECKS if not ok]
    say(f"{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        for label in failed:
            print("  FAILED:", label)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
