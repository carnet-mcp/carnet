"""The whole write path, over real HTTP, against real Postgres, as two signed people.

**Not a test, and it is here because of what the suite structurally cannot do.**
`tests/test_api.py` runs against the in-memory store — `isolated_storage` is autouse — so
until 10d nothing in this project had taken a write route through FastAPI to a database
that has columns. 10a's dev-proxy bug is the standing reminder that *"no test could have
caught it"* is a real category here, and this is the cheapest thing that closes some of it.

It builds its own world and throws it away: a database of its own, a tenant, a
locally-signed identity provider whose JWKS is served on a socket, and uvicorn in its own
process. It does **not** touch `carnet_demo`, which is hand-made and holds the real
Okta registration.

    cd backend && .venv/bin/python scripts/e2e_write_path.py

Needs Postgres reachable first: `CARNET_E2E_PG` is the base DSN it splices a database name into.

**Costs nothing.** No run is submitted, so no model is called and no connector is
launched. Add either of those deliberately, and say so out loud first.

**What it does not replace:** a browser, and two real Okta accounts. Every bug in this
project's history was found by looking at the thing, and this looks at the API rather than
at the screens.
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
from urllib.parse import urlsplit, urlunsplit

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_e2e"


def dsn_for(database: str) -> str:
    """Where Postgres is. The socket this project has used, unless told otherwise.

    `CARNET_E2E_PG` is a base DSN with **no database name**, and it exists because
    the machine changed — twice. A hardcoded unix socket is a fact about one laptop, and
    on a machine running Postgres in a container the failure is a connection error three
    functions into a script whose whole job is to reach a database.

    Not a concatenation: a socket DSN carries its host in the query string and a TCP one
    does not, so the database name is spliced into the path.
    """
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


DSN = dsn_for(DB)
ISSUER = "https://e2e-write-path.local"
AUDIENCE = "api://default"
JWKS_PORT = 8901
API = "http://127.0.0.1:8123"
TENANT = "e2ewrite"

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True)
JWK.update({"kid": "k1", "use": "sig", "alg": "RS256"})


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


def say(what):
    print(f"\n=== {what}", flush=True)


def main():
    import psycopg

    # A database of its own, dropped at the end. `carnet_demo` is hand-made and
    # holds the real Okta registration; writing this arc into it would be litter.
    with psycopg.connect(
        dsn_for("postgres"), autocommit=True
    ) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")

    os.environ["CARNET_DATABASE_URL"] = DSN
    os.environ["CARNET_SECRET_KEY"] = os.environ.get(
        "CARNET_SECRET_KEY", ""
    ) or _generate_key()
    os.environ["WORKERS"] = "0"

    from carnet import bootstrap, storage
    from carnet.storage import migrate

    migrate.apply(DSN)
    from carnet.storage.postgres import PostgresStorage

    store = storage.configure(PostgresStorage(DSN))
    store.create_tenant(TENANT, "10d end to end")
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
    store.close()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", JWKS_PORT), Jwks)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port", "8123"],
        env={**os.environ, "CARNET_TENANT": TENANT},
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

        run(store_dsn=DSN)
    finally:
        api.terminate()
        api.wait(timeout=10)
        server.shutdown()


def _generate_key():
    import base64
    import os as _os

    return base64.b64encode(_os.urandom(32)).decode()


CHECKS = []


def check(label, actual, expected):
    """**Every line this prints is an assertion.**

    The first version of this script printed and asserted almost nothing, which made it a
    demonstration: it would have gone on looking correct while quietly reporting a 500. A
    demonstration nobody re-runs is worth less than a test; a demonstration that fails
    loudly is worth more than one, because it fails against a real database.

    Prints either way, because reading the trail is half of what this is for.
    """
    # Reads with `.get` at the call sites rather than `[...]`, so a route that answers
    # the wrong shape produces a **failed check** and the run continues to the summary
    # rather than a traceback three checks in. A broken thing should tell you everything
    # that is broken.
    ok = actual == expected
    CHECKS.append((label, ok, actual, expected))
    mark = "ok  " if ok else "FAIL"
    print(f"  {mark} {label}: {actual!r}" + ("" if ok else f"  (expected {expected!r})"))
    return ok


def run(store_dsn):
    priya = {"Authorization": f"Bearer {token('00u-priya', 'priya@acme.com')}"}
    sam = {"Authorization": f"Bearer {token('00u-sam', 'sam@acme.com')}"}
    c = httpx.Client(base_url=API, timeout=20)

    # Step 012 added two fields to `ToolSummary`, and this is the only place in the
    # project where the catalogue route is answered by a database with columns. Nothing
    # renders them yet — the vetting screen is 12c and needs a role that does not exist —
    # so the check is that the route carries what `--list-tools` prints. `tools.catalogue`
    # is shared between the two precisely so they cannot drift, and a route that silently
    # dropped a field would be that drift arriving through the response.
    say("the catalogue route carries the review record, including what it was vetted against")
    groups = c.get("/tools", headers=priya).json()
    connector_tools = [t for g in groups if g["origin"] == "connector" for t in g["tools"]]
    check("the seeded connector's tools are listed", bool(connector_tools), True)
    check(
        "every entry carries all four review fields",
        all(
            {"vetted_by", "vetted_at", "server_name", "server_version"} <= set(t)
            for t in connector_tools
        ),
        True,
    )
    # `--seed` contacts no server, so it has nothing to record about one. Empty rather
    # than absent, and never invented — the same sentence migration 023 makes.
    check(
        "and --seed's rows say so honestly rather than inventing a version",
        {t["server_version"] for t in connector_tools},
        {""},
    )

    say("both people log in; the seeded agents belong to system:cli, so neither sees any")
    check("priya sees nothing", c.get("/agents", headers=priya).json(), [])
    check("sam sees nothing", c.get("/agents", headers=sam).json(), [])

    say("priya creates an agent through the form's own shape")
    draft = {
        "name": "triage-bot",
        "system": "You summarise open issues.",
        "runtime": "simple",
        "model": "claude-haiku-4-5",
        "permissions": {
            "tools": ["post_message"],
            "scope": {"chat.channel": {"write": ["#eng"]}},
        },
        "limits": {"max_calls": 3},
    }
    created = c.post("/agents", json=draft, headers=priya)
    check("POST /agents", created.status_code, 201)
    check("Location", created.headers.get("Location"), "/agents/triage-bot")

    say("she opens it — the ETag comes back in the header AND the body")
    opened = c.get("/agents/triage-bot", headers=priya)
    body = opened.json()
    check("GET /agents/triage-bot", opened.status_code, 200)
    check("ETag matches the body", opened.headers["ETag"], f'"{body["updated_at"]}"')
    check("your_role", body["your_role"], "owner")
    # The whole config comes back, including what no wizard step asks about. An edit form
    # built from `system`/`scope`/`limits` alone sends back a config missing those.
    check("config is the whole config", body["config"], draft)

    say("she shares it with sam at editor, by address, and the outcome says which")
    shared = c.put(
        "/agents/triage-bot/grants/email/sam@acme.com",
        json={"role": "editor"},
        headers=priya,
    )
    check("PUT grants/email (known address)", shared.status_code, 200)
    check("outcome", shared.json()["outcome"], "granted")

    say("and with somebody who has never logged in — the other outcome")
    pending = c.put(
        "/agents/triage-bot/grants/email/newhire@acme.com",
        json={"role": "user"},
        headers=priya,
    )
    check("PUT grants/email (unknown address)", pending.status_code, 200)
    check("outcome", pending.json()["outcome"], "pending")

    say("the share sheet: who, at what level, how — and who is still waiting")
    sheet = c.get("/agents/triage-bot/access", headers=priya).json()
    for row in sheet["access"]:
        print(f"       {row['kind']:6} {row['id'][:24]:26} {row['role']:8} via={row['via']}")
    check("two people can reach it", len(sheet["access"]), 2)
    check("roles", sorted(r["role"] for r in sheet["access"]), ["editor", "owner"])
    check("waiting is a separate list", [w["email"] for w in sheet["waiting"]],
          ["newhire@acme.com"])
    check("and is not merged into access",
          [r["id"] for r in sheet["access"] if "@" in r["id"]], [])

    say("A PATCH WITH NO If-Match — the thing this step refuses")
    check("428 rather than a permissive write",
          c.patch("/agents/triage-bot", json={"system": "x"}, headers=priya).status_code,
          428)
    check("and nothing changed",
          c.get("/agents/triage-bot", headers=priya).json()["system"], draft["system"])

    say("a PATCH that renames is a 400, not a silent ignore")
    etag0 = c.get("/agents/triage-bot", headers=priya).json()["updated_at"]
    renamed = c.patch("/agents/triage-bot", json={"name": "other"},
                      headers={**priya, "If-Match": f'"{etag0}"'})
    check("400", renamed.status_code, 400)
    check("and no agent by the new name",
          c.get("/agents/other", headers=priya).status_code, 404)

    say("BOTH EDITORS OPEN IT. Same version, neither has written.")
    her = c.get("/agents/triage-bot", headers=priya).json()["updated_at"]
    his = c.get("/agents/triage-bot", headers=sam).json()["updated_at"]
    print("       priya holds", her)
    print("       sam holds  ", his)
    check("both hold the same version", her, his)

    say("priya narrows the scope and saves")
    narrowed = c.patch(
        "/agents/triage-bot",
        json={"permissions": {"tools": [], "scope": {}}},
        headers={**priya, "If-Match": f'"{her}"'},
    )
    check("her save lands", narrowed.status_code, 200)
    check("tools now", narrowed.json()["tools"], [])
    check("and the ETag advanced", narrowed.json()["updated_at"] > her, True)

    say("SAM SAVES THE VERSION HE LOADED. Without the guard this reverts her narrowing.")
    stale = c.patch(
        "/agents/triage-bot",
        json={"permissions": draft["permissions"]},
        headers={**sam, "If-Match": f'"{his}"'},
    )
    check("his save is REFUSED", stale.status_code, 409)
    check("and it says which keys differ", stale.json().get("changed"), ["permissions"])
    check("carrying the version to reload", stale.json().get("updated_at"),
          narrowed.json().get("updated_at"))
    check("HER NARROWING SURVIVED",
          c.get("/agents/triage-bot", headers=priya).json()["tools"], [])

    say("sam reloads and his edit lands")
    fresh = c.get("/agents/triage-bot", headers=sam).json()["updated_at"]
    again = c.patch(
        "/agents/triage-bot",
        json={"system": "Rewritten by sam."},
        headers={**sam, "If-Match": f'"{fresh}"'},
    )
    check("his edit lands after a reload", again.status_code, 200)
    check("system", again.json()["system"], "Rewritten by sam.")

    say("A PATCH THAT OMITS A FIELD DOES NOT DELETE IT — a key no wizard step knows")
    store = _store(store_dsn)
    # Written the way a seed writes one: a stored config carrying a key the form never
    # asks about, which is exactly the field a whole-config save would silently drop.
    store.create_agent(
        TENANT,
        {"name": "keeper", "note": "kept by the merge",
         "permissions": {"tools": ["post_message"], "scope": {"chat.channel": {"write": ["#eng"]}}}},
        "user", _id_of(store, "priya@acme.com"),
    )
    before = store.get_agent(TENANT, "keeper")["config"]
    check("the row carries the extra key", before.get("note"), "kept by the merge")
    etag = c.get("/agents/keeper", headers=priya).json()["updated_at"]
    edited = c.patch(
        "/agents/keeper",
        json={"system": "Rewritten."},
        headers={**priya, "If-Match": f'"{etag}"'},
    )
    after = store.get_agent(TENANT, "keeper")["config"]
    check("the patch lands", edited.status_code, 200)
    check("system changed", after["system"], "Rewritten.")
    check("THE EXTRA KEY SURVIVED", after.get("note"), "kept by the merge")
    check("and the row's key set only gained what was sent",
          sorted(after), sorted(set(before) | {"system"}))

    say("a broken agent OPENS (200) and running it still refuses (422), same sentence")
    store.save_agent(
        TENANT,
        {"name": "broken", "permissions": {"tools": ["gone_away"], "scope": {}}},
        actor="system:cli",
    )
    store.grant_agent(
        TENANT, "broken", "user", _id_of(store, "priya@acme.com"),
        role="owner", actor="system:cli",
    )
    opened = c.get("/agents/broken", headers=priya)
    check("GET /agents/broken", opened.status_code, 200)
    check("valid", opened.json()["valid"], False)

    say("sam may edit and may NOT delete — the one asymmetry")
    check("sam (editor) DELETE", c.delete("/agents/triage-bot", headers=sam).status_code, 404)
    check("and it is still there",
          c.get("/agents/triage-bot", headers=sam).status_code, 200)
    check("priya (owner) DELETE",
          c.delete("/agents/triage-bot", headers=priya).status_code, 204)
    check("gone", c.get("/agents/triage-bot", headers=priya).status_code, 404)
    check("twice is 404, not 204",
          c.delete("/agents/triage-bot", headers=priya).status_code, 404)
    check("and its grants went with it",
          store.list_agent_grants(TENANT, "triage-bot"), [])

    say("the administrative log — every one of these named a person")
    for r in store.admin_audit_records(TENANT):
        detail = ", ".join(
            f"{k}={v}" for k, v in sorted(r["detail"].items()) if v not in (None, [], {})
        )
        print(
            f"  {r['ts'][11:19]}  {r['actor_kind']}:{r['actor_id'][:20]:22}"
            f"{r['action']:22}{r['target_kind']}:{r['target_id'][:18]:22}{detail[:70]}"
        )

    records = store.admin_audit_records(TENANT)
    check("every record names a principal",
          sorted({r["actor_kind"] for r in records}), ["system", "user"])
    check("none of them is empty",
          [r for r in records if not r["actor_id"]], [])
    check("the edits are attributed to the two people who made them",
          [r["actor_id"][-4:] for r in records if r["action"] == "agent.update"],
          [_id_of(store, "priya@acme.com")[-4:], _id_of(store, "sam@acme.com")[-4:],
           _id_of(store, "priya@acme.com")[-4:]])

    say("no agent's system prompt reached the log")
    check("NO PROMPT IN THE LOG",
          "Rewritten by sam." in json.dumps(records), False)
    store.close()

    failed = [label for label, ok, *_ in CHECKS if not ok]
    say(f"{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        for label in failed:
            print("  FAILED:", label)
        raise SystemExit(1)


def _store(dsn):
    from carnet.storage.postgres import PostgresStorage

    return PostgresStorage(dsn)


def _id_of(store, email):
    return store.find_user_by_email(TENANT, email)["id"]


if __name__ == "__main__":
    main()
