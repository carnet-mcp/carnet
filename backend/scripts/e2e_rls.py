"""Two tenants, one server, one pool — and the database refusing to mix them. Steps 029, 085.

**Not a test, and here for what the suite structurally cannot do.** The contract suite
proves the policies against one `PostgresStorage`, in one process, with `tenancy.scoped()`
called directly — no server, no middleware, no threadpool copy, no pool contention.
`tests/test_api.py` proves the other half — the middleware's cell, and
`principal_from_request` binding a tenant to it — against the **in-memory** store, which
has no policies. Nothing anywhere puts the two together, and the seam between them is two
paragraphs of `storage/tenancy.py` about a mutable cell shared by reference across
threadpool copies. This script is that seam, with a socket in the way:

  - the session variable survives the pool being **shared**: two tenants' assistants
    alternate over the same recycled connections, and each door call sees exactly its
    own rows;
  - the database's own answer, with no `WHERE` clause anywhere;
  - a role with no tenant bound answers with a **sentence**, not zero rows — and the
    sentence still names all three things it was written to name;
  - the one tenantless loop this tree has — `LogMaintainer`'s retention sweep, in the
    serving process — crosses both tenants while the door is being called, because its
    exemption comes from **ownership** and not from being a superuser;
  - and the BYOC shape, where every one of 029's and 030's defects hid: an ordinary
    role in a cluster that already has the tenant role, a serving role that owns
    nothing, and a creator holding `ADMIN OPTION` without `SET`.

What this script deliberately does **not** contain is the queue. Step 078 deleted the
runtime; the deleted version of this file drove a worker through half its scenes, and
085 re-homes those three onto what a door-only deployment actually runs. **No `runs` row
is written here** — a door call is not a run.

    cd backend && .venv/bin/python scripts/e2e_rls.py

Needs Postgres, and outbound DNS for `localtest.me` — `egress.check` refuses a literal
loopback address before any allowlist is read, so a real upstream must be reached by a
name. `CARNET_E2E_PG` overrides where the database is:

    CARNET_E2E_PG=postgresql://postgres:test@localhost:5433/ \
        .venv/bin/python scripts/e2e_rls.py

**Costs nothing and calls no model.** The door spends no model tokens at all; the
upstream MCP server is a thread in this process.

**What green here does not say.** RLS is a bug boundary on the multi-user surface, not
process isolation: the serving role owns the tables, `RESET ROLE` is one statement away,
and SQL injection is answered by parameterized queries rather than by a role (029's
standing known limit). And that every table carries a policy is the contract suite's
catalog walk, not this script's — this one is the deployment shape.
"""

import base64
import concurrent.futures
import datetime as dt
import http.server
import json
import os
import pathlib
import socket
import statistics
import tempfile
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
DB = "carnet_e2e_rls"


def dsn_for(database: str) -> str:
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit(
        (parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment)
    )


DSN = dsn_for(DB)
AUDIENCE = "api://default"
JWKS_PORT = 8918
API_PORT = 8134
# Stamped on the server's connections so `pg_stat_activity` can tell the API's pool
# apart from this script's own — which is what lets a scene count the backends the
# server actually holds, and take them away.
API_APPNAME = "carnet-e2e-rls-api"
API = f"http://127.0.0.1:{API_PORT}"
DOOR = f"{API}/mcp"

# The upstream MCP server both tenants have vetted, reached by a public name that
# resolves to loopback — `e2e_mcp_door.py`'s reason, and the same consent.
UPSTREAM_HOST = "localtest.me"
UPSTREAM_PORT = 8919

# Two tenants, two issuers, one signing key: what separates them is exactly what
# separates them in production — the issuer each tenant registered, nothing else.
ACME = "acme"
GLOBEX = "globex"
ISSUER = {
    ACME: "https://e2e-rls-acme.local",
    GLOBEX: "https://e2e-rls-globex.local",
}
DOMAIN = {ACME: "acme.com", GLOBEX: "globex.com"}
ADMIN_SUBJECT = "00u-admin"
ADMIN_ID = {ACME: "u-acme-admin", GLOBEX: "u-globex-admin"}
ACTOR = "system:cli"

# Each tenant's own connector, its own credential, and one tool it vetted. Different
# names on purpose: a leak in either direction is then visible by name in `tools/list`
# and by credential at the upstream, rather than having to be inferred.
CONNECTOR = {ACME: "acmetracker", GLOBEX: "globextracker"}
REMOTE = {ACME: "list_issues", GLOBEX: "list_tickets"}
TOOL = {t: f"{CONNECTOR[t]}_{REMOTE[t]}" for t in (ACME, GLOBEX)}
CREDENTIAL = {ACME: "acme-service-token", GLOBEX: "globex-service-token"}
CREDENTIAL_ENV = {ACME: "ACME_TOKEN", GLOBEX: "GLOBEX_TOKEN"}
AGENT = {ACME: "acme-triage", GLOBEX: "globex-triage"}
# The resource each tenant's scope line names, in the two-segment shape `core/patterns.py`
# compares whole segments of: `{owner}/{repo}`.
OWNER_ARG = {ACME: "acme", GLOBEX: "globex"}
REPO_ARG = "tracker"

# The wire key the call id rides under, spelled as a literal on purpose: this asserts a
# contract, and importing the constant would assert that a name equals itself.
CALL_ID_KEY = "com.carnet/call-id"

TOOLS = [
    {
        "name": "list_issues",
        "description": "List issues in a repository.",
        "inputSchema": {
            "type": "object",
            "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}},
            "required": ["owner", "repo"],
        },
    },
    {
        "name": "list_tickets",
        "description": "List tickets in a repository.",
        "inputSchema": {
            "type": "object",
            "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}},
            "required": ["owner", "repo"],
        },
    },
]

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True)
JWK.update({"kid": "k1", "use": "sig", "alg": "RS256"})

SEEN: list = []
SEEN_LOCK = threading.Lock()


def token(tenant, sub, email):
    now = int(time.time())
    return jwt.encode(
        {
            "iss": ISSUER[tenant],
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


class Upstream(http.server.BaseHTTPRequestHandler):
    """Both customers' MCP server. `e2e_mcp_door.py`'s, trimmed to two tools.

    It records the credential it was called with, which is what makes a session shared
    across two tenants visible here rather than only in a pool's internals.
    """

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        message = json.loads(self.rfile.read(length) or "{}")

        with SEEN_LOCK:
            SEEN.append(
                {
                    "method": message.get("method"),
                    "authorization": self.headers.get("Authorization"),
                    "arguments": (message.get("params") or {}).get("arguments"),
                }
            )

        if "id" not in message:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        method = message["method"]
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "tracker", "version": "1.0.0"},
            }
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            arguments = (message.get("params") or {}).get("arguments") or {}
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "items": [{"number": 1, "repo": arguments.get("repo")}],
                                "seen_authorization": self.headers.get("Authorization"),
                            }
                        ),
                    }
                ]
            }
        else:
            result = {}

        body = json.dumps(
            {"jsonrpc": "2.0", "id": message["id"], "result": result}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


CHECKS: list = []


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok, actual, expected))
    mark = "  ok" if ok else "FAIL"
    print(f"{mark}  {label}: {actual!r}" + ("" if ok else f"  (expected {expected!r})"))
    return ok


def say(what):
    print(f"\n=== {what}", flush=True)


def scene(fn, *args):
    """Run one scene; a scene that raises is a **failed check**, not a dead script.

    Same argument as `report()` one level down. A mutation that poisons the store makes
    the next scene raise, and a traceback there would take the verdict of every later
    scene with it — including the BYOC ones, which run against different databases and
    are unaffected by whatever broke. The exception's text is the check's value, so it
    is on the transcript rather than swallowed.
    """
    try:
        fn(*args)
    except Exception as exc:  # noqa: BLE001 - the traceback would cost the summary
        check(f"the scene '{fn.__name__}' ran to the end",
              f"{type(exc).__name__}: {exc}"[:160], "completed")
        return None
    return None


def report() -> int:
    """The verdict, over **every** check this run made.

    A function rather than a tail on the last scene, and that is not tidiness: the
    summary used to live at the end of the first scene set, so the BYOC scenes that
    follow it reported into a total nobody printed and could not fail the script. A
    scene added after the summary is a scene whose failures are invisible — which is
    the same silent-pass shape this step exists to argue against.
    """
    say("summary")
    failed = [label for label, ok, *_ in CHECKS if not ok]
    print(f"  {len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    for label in failed:
        print(f"  FAILED: {label}")
    return 1 if failed else 0


# --- talking to the door ---------------------------------------------------------


def rpc(secret, method, params=None, mid=1):
    return httpx.post(
        DOOR,
        json={"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}},
        headers={"Authorization": f"Bearer {secret}"},
        timeout=30,
    )


def tool_names(secret) -> list:
    """The tools this token may call, or `[]` for anything that is not an answer.

    Defensive on purpose, and for the same reason `report()` is a function: a door that
    answers 500 must make this script go **red with a summary**, not stop at a traceback
    with every later scene unreported. Each of 085's five mutations was checked for
    exactly that as well as for going red.
    """
    body = rpc(secret, "tools/list").json()
    result = body.get("result") or {}
    return sorted(t["name"] for t in result.get("tools", []))


def call(secret, name, owner):
    """One `tools/call`. Returns (isError, call id or None, the answer)."""
    body = rpc(
        secret,
        "tools/call",
        {"name": name, "arguments": {"owner": owner, "repo": REPO_ARG}},
    ).json()
    result = body.get("result")
    if not isinstance(result, dict):
        return True, None, body.get("error")
    call_id = (result.get("_meta") or {}).get(CALL_ID_KEY)
    return result.get("isError"), call_id, result.get("structuredContent")


def admin(tenant):
    return {"Authorization": f"Bearer {token(tenant, ADMIN_SUBJECT, f'admin@{DOMAIN[tenant]}')}"}


# --- the scenes ------------------------------------------------------------------


def the_shape_of_the_role(store):
    from carnet.storage import TENANT_ROLE

    say("the role the migration created, shaped as decided")
    role = store._fetchone(
        "SELECT rolcanlogin, rolbypassrls, rolsuper FROM pg_roles WHERE rolname = %s",
        (TENANT_ROLE,),
    )
    check("NOLOGIN, no BYPASSRLS, not a superuser", role, (False, False, False))
    check("the server's own startup check passes", store.verify_tenant_isolation(), None)


def two_tenants_over_one_pool(secrets) -> dict:
    """The handoff's first question, at the deployment shape and through the door.

    A pooled connection carrying the previous borrower's tenant would surface here as
    the other tenant's tool in this token's list, or as a call this token may not make
    succeeding. Each round is a full door call — grants read, policy adjudicated, audit
    row written — rather than a bare SELECT.

    **The sharing is measured rather than assumed**, and the measurement corrected the
    sentence that used to stand here. *"Twenty alternating rounds cycle every pooled
    connection many times over"* is what the deleted version of this file claimed, and it
    is false: `psycopg_pool` hands a sequential caller the **same** connection every
    time, so twenty alternating rounds are twenty borrows of one backend. That is the
    harder case rather than a weaker one — one physical connection carrying two tenants
    in turn is exactly what overwrite-at-borrow has to survive — but it is a different
    claim, so `the_pool_is_actually_shared` below counts backends instead of asserting
    them, and the concurrent scene is where more than one is in play.
    """
    say("two tenants alternating over one shared pool, twenty rounds of door calls")
    ids = {ACME: [], GLOBEX: []}
    leaked_listings = 0
    refused = 0
    for _ in range(20):
        for tenant in (ACME, GLOBEX):
            other = GLOBEX if tenant is ACME else ACME
            names = tool_names(secrets[tenant])
            if names != [TOOL[tenant]]:
                leaked_listings += 1
            failed, call_id, answer = call(secrets[tenant], TOOL[tenant],
                                           OWNER_ARG[tenant])
            if failed or call_id is None:
                refused += 1
            else:
                ids[tenant].append(call_id)
            # And the other tenant's tool is not merely absent from the listing: naming
            # it is refused, which is the half a client could otherwise route around.
            crossed = rpc(
                secrets[tenant],
                "tools/call",
                {"name": TOOL[other],
                 "arguments": {"owner": OWNER_ARG[other], "repo": REPO_ARG}},
            ).json()
            if "error" not in crossed:
                leaked_listings += 1

    check("every listing showed exactly its own tenant's tool", leaked_listings, 0)
    check("every door call succeeded", refused, 0)
    check("forty call ids came back, all distinct",
          len(set(ids[ACME]) | set(ids[GLOBEX])), 40)

    with SEEN_LOCK:
        calls = [s for s in SEEN if s["method"] == "tools/call"]
    by_owner = {
        t: {s["authorization"] for s in calls
            if (s["arguments"] or {}).get("owner") == OWNER_ARG[t]}
        for t in (ACME, GLOBEX)
    }
    check("the upstream saw acme's calls under acme's credential only",
          by_owner[ACME], {f"Bearer {CREDENTIAL[ACME]}"})
    check("...and globex's under globex's",
          by_owner[GLOBEX], {f"Bearer {CREDENTIAL[GLOBEX]}"})
    return ids


def the_pool_is_actually_shared():
    """Which physical backend served which tenant — the claim, counted.

    A separate pool rather than the API's, because this is the one thing the door cannot
    show: nothing in an MCP response names the connection that answered.

    What must be true is not *"many connections were used"* — it is that **one physical
    connection carried both tenants in turn and filtered correctly for each**. A pool
    that quietly gave each tenant its own connection forever would pass a leak test by
    accident.

    **A pool of exactly one, on purpose.** The first version of this scene used two and
    asked whether some backend had served both; that is true of nearly every run and
    false of a few, because which connection a pool hands back is its business and not a
    property under test. A flaky proof is worse than no proof. `max_size=1` makes the
    interleaving certain, and it is also the strictest case: every borrow is the same
    backend, so every borrow depends on the previous one having been reset.
    """
    from carnet.storage import tenancy
    from carnet.storage.postgres import PostgresStorage

    say("the pool is actually shared — which backend served which tenant")
    small = PostgresStorage(DSN, min_size=1, max_size=1)
    try:
        served, filtered = {}, 0
        for i in range(20):
            tenant = ACME if i % 2 == 0 else GLOBEX
            with tenancy.scoped(tenant):
                pid = small._fetchone("SELECT pg_backend_pid()")[0]
                rows = [r[0] for r in small._fetchall("SELECT id FROM tenants")]
            served.setdefault(pid, set()).add(tenant)
            filtered += rows == [tenant]
        both = [pid for pid, tenants in served.items() if len(tenants) == 2]
        check("every scoped borrow saw exactly its own tenant", filtered, 20)
        check("one backend carried both tenants, ten times each", len(both), 1)
    finally:
        small.close()


def the_databases_own_answer(store):
    """No WHERE clause anywhere. What comes back is what the database decided to show."""
    import psycopg

    from carnet.storage import TENANT_GUC, TENANT_ROLE

    say("the database's own answer, with no WHERE clause anywhere")
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute(
            "SELECT set_config(%s, %s, false), set_config('role', %s, false)",
            (TENANT_GUC, ACME, TENANT_ROLE),
        )
        check("SELECT * FROM tenants shows one tenant",
              [r[0] for r in conn.execute("SELECT id FROM tenants").fetchall()], [ACME])
        for table in ("agents", "api_tokens", "audit", "agent_grants", "mcp_budget"):
            seen = {
                r[0] for r in conn.execute(
                    f"SELECT DISTINCT tenant_id FROM {table}"
                ).fetchall()
            }
            check(f"SELECT * FROM {table} shows one tenant", seen, {ACME})

        try:
            conn.execute(
                "INSERT INTO groups (tenant_id, group_id, name) VALUES (%s, %s, %s)",
                (GLOBEX, "g-sneak", "Sneak"),
            )
            check("a scoped write for the other tenant is refused", "accepted", "refused")
        except psycopg.Error as exc:
            check("a scoped write for the other tenant is refused out loud",
                  "row-level security" in str(exc), True)

        touched = conn.execute(
            "UPDATE agents SET updated_at = now() WHERE tenant_id = %s", (GLOBEX,)
        ).rowcount
        check("a scoped UPDATE of the other tenant matches nothing", touched, 0)


def the_unbound_role_is_loud():
    """Decision 6's loud half, and all three clauses the sentence was written to carry.

    The contract suite pins the first clause. The other two were each added because
    testing found the case: the seam that should have bound a tenant, and the second way
    this function is reached — a serving role that is a *member* but owns nothing, which
    the first wording libelled.
    """
    import psycopg

    from carnet.storage import TENANT_ROLE

    say("the role with no tenant bound answers with a sentence, not zero rows")
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute(f"SET ROLE {TENANT_ROLE}")
        try:
            conn.execute("SELECT count(*) FROM agents")
            check("an unbound scoped read raises", "returned rows", "raised")
        except psycopg.Error as exc:
            check("an unbound scoped read raises", "no tenant is bound" in str(exc), True)
            check("and the sentence names the seam that should have bound one",
                  "_connection" in str(exc), True)
            check("and the other way it is reached",
                  "does not own these tables" in str(exc), True)


def a_call_id_from_the_other_tenant(store, secrets, ids):
    """The re-homed *"a run id from the other tenant is a 404"*.

    083 hands every `tools/call` result the id of its own audit row, so the object
    probed across the tenant boundary is one the product gave out. Asked for three
    ways — at the screen, in the database with no tenant predicate, and at the door.
    """
    import psycopg

    from carnet.storage import TENANT_GUC, TENANT_ROLE

    say("a call id from the other tenant is invisible — screen, database, door")
    # `or [...]` rather than an index: a scene that raises before `report()` runs takes
    # every later scene's verdict with it, which is the failure `report()` itself exists
    # to prevent one level up. A run where the calls did not happen must go **red**, not
    # traceback.
    mine = (ids[ACME] or ["door-none"])[-1]
    theirs = (ids[GLOBEX] or ["door-none"])[-1]

    listed = httpx.get(f"{API}/admin/door-calls", params={"limit": 200},
                       headers=admin(ACME), timeout=30).json()
    seen = {row["run_id"] for row in listed}
    check("acme's administrator sees acme's own call", mine in seen, True)
    check("...and not globex's", theirs in seen, False)
    check("...and every row listed is a door call",
          bool(listed) and all(row["run_id"].startswith("door-") for row in listed), True)
    check("...and no runs row was written for any of them",
          store._fetchone("SELECT count(*) FROM runs")[0], 0)

    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute(
            "SELECT set_config(%s, %s, false), set_config('role', %s, false)",
            (TENANT_GUC, ACME, TENANT_ROLE),
        )
        found = conn.execute(
            "SELECT count(*) FROM audit WHERE run_id = %s", (theirs,)
        ).fetchone()
        check("the database cannot even see it", found[0], 0)
        own = conn.execute(
            "SELECT count(*) FROM audit WHERE run_id = %s", (mine,)
        ).fetchone()
        check("...while its own is right there", own[0], 1)

    unscoped = store._fetchone(
        "SELECT tenant_id FROM audit WHERE run_id = %s", (theirs,)
    )
    check("and the owner, unscoped, confirms the row exists and is globex's",
          unscoped and unscoped[0], GLOBEX)

    # And the attempt itself is recorded — in the caller's tenant, and only there.
    # `DoorRefused` writes no `audit` row on purpose (there is no agent to attribute one
    # to), so `access_denials` is the only place a cross-tenant tool name leaves a mark,
    # and a proof that stopped at "it was refused" would not have found out which.
    before = {t: len(store.denial_records(t, limit=200)) for t in (ACME, GLOBEX)}
    refused = rpc(secrets[ACME], "tools/call",
                  {"name": TOOL[GLOBEX],
                   "arguments": {"owner": OWNER_ARG[GLOBEX], "repo": REPO_ARG}}).json()
    check("naming the other tenant's tool is an error, not a result",
          "error" in refused, True)
    after = {t: len(store.denial_records(t, limit=200)) for t in (ACME, GLOBEX)}
    check("...recorded once, in the caller's tenant",
          after[ACME] - before[ACME], 1)
    check("...and not at all in the tenant whose tool was named",
          after[GLOBEX] - before[GLOBEX], 0)


def one_unscoped_sweep_crosses_both(store, secrets):
    """The re-homed *"one unscoped worker drains both tenants' queues"*.

    029 decision 4's subject was never the worker: it was that the tenantless loops stay
    whole under RLS, and that their exemption comes from **ownership** rather than from
    being a superuser. The worker is gone; this tree's one tenantless loop is
    `LogMaintainer`, in the serving process, running `maintenance.sweep_log_tables` —
    partition DDL against a policied parent, and a partition drop that takes every
    tenant's rows at once.

    Driven by the **server's own thread** (`CARNET_RETENTION_SWEEP=2` in its
    environment), not by this process, because a sweep this process ran would prove
    ownership works for *this* connection and say nothing about a daemon thread with an
    empty context in a process that is also serving scoped requests.

    If RLS broke this loop, nothing would say so: the prune would remove zero rows and
    the horizon would stop being extended, and the failure would arrive months later as
    `missing_partition` on somebody's audit append.
    """
    say("one unscoped sweep, in the serving process, crosses both tenants")
    old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=120)
    store.ensure_log_partitions(back_to=old - dt.timedelta(days=40))
    for tenant in (ACME, GLOBEX):
        store.append_audit(tenant, {
            "v": 7, "ts": old, "run_id": f"door-ancient{tenant[:4]}",
            "principal_kind": "machine", "principal_id": "t-old",
            "agent": AGENT[tenant], "tool": TOOL[tenant], "effect": "read",
            "args": {}, "decision": "allow", "outcome": "ok",
        })
    check("both tenants have a record older than the retention window",
          [len(store.audit_records(t, run_id=f"door-ancient{t[:4]}"))
           for t in (ACME, GLOBEX)], [1, 1])

    # One call per tenant, remembered by id: what the sweep must NOT take. "some rows
    # are left" is not the claim — a partition drop that took this month would leave
    # plenty of rows and still be the outage this check exists to catch.
    fresh = {}
    for tenant in (ACME, GLOBEX):
        fresh[tenant] = call(secrets[tenant], TOOL[tenant], OWNER_ARG[tenant])[1]
    check("a fresh call in this month's partition, per tenant",
          [bool(fresh[t]) for t in (ACME, GLOBEX)], [True, True])

    # The door keeps being called while the sweep runs, which is the whole shape: a
    # scoped borrow and an unscoped one on the same pool at the same time.
    deadline = time.time() + 30
    swept = False
    while time.time() < deadline:
        call(secrets[ACME], TOOL[ACME], OWNER_ARG[ACME])
        call(secrets[GLOBEX], TOOL[GLOBEX], OWNER_ARG[GLOBEX])
        if not any(store.audit_records(t, run_id=f"door-ancient{t[:4]}")
                   for t in (ACME, GLOBEX)):
            swept = True
            break
        time.sleep(1)

    check("the server's own sweep removed both tenants' expired rows", swept, True)
    check("...and left this month's calls alone, by id",
          [len(store.audit_records(t, run_id=fresh[t])) for t in (ACME, GLOBEX)], [1, 1])
    pruned = {
        t: store.admin_audit_records(t, action="retention.prune", limit=10)
        for t in (ACME, GLOBEX)
    }
    check("...and it wrote one retention record per affected tenant",
          [len(pruned[ACME]) >= 1, len(pruned[GLOBEX]) >= 1], [True, True])


def the_pool_loses_its_connections(store, secrets):
    """Every connection the server holds is terminated underneath it. Found by 085's pass.

    `_connection()` claims three things, and the third — *discard on a failed reset* —
    is the one nothing exercises: a connection that cannot prove it is unscoped is
    closed rather than pooled. The cheapest real version of that is a database that
    takes the connections away: `pg_terminate_backend` on every backend the API holds,
    while both tenants are calling.

    The property is **not** that nothing fails. Some calls must fail, and an honest 503
    is the right answer to a connection that died mid-request. The property is that
    **no answer is another tenant's**, and that the pool comes back rather than serving
    a poisoned connection forever.
    """
    say("every connection the server holds, terminated underneath it")
    import psycopg

    for tenant in (ACME, GLOBEX):
        call(secrets[tenant], TOOL[tenant], OWNER_ARG[tenant])
    with psycopg.connect(DSN, autocommit=True) as conn:
        killed = conn.execute(
            "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity"
            " WHERE application_name = %s AND pid <> pg_backend_pid()",
            (API_APPNAME,),
        ).fetchone()[0]
    check("the server's backends were taken away", killed > 0, True)

    crossed, outcomes = 0, []
    for _ in range(10):
        for tenant in (ACME, GLOBEX):
            other = GLOBEX if tenant is ACME else ACME
            if TOOL[other] in tool_names(secrets[tenant]):
                crossed += 1
            failed, call_id, _ = call(secrets[tenant], TOOL[tenant], OWNER_ARG[tenant])
            outcomes.append(not failed)
    check("no listing carried the other tenant's tool", crossed, 0)
    # The tail rather than a proportion: how many calls the kill takes with it is the
    # database's business and varies, but a pool that has recovered answers everything
    # after it. A threshold over the whole batch is a flake waiting for a slow machine.
    check("and the pool recovered — every call after the first ten answered",
          all(outcomes[10:]), True)
    print(f"  ({outcomes.count(False)} of {len(outcomes)} calls were taken by the kill)")
    # Over everything written by this run, not just by this scene: no tenant's log holds
    # a call to the other's tool. The owner asks, unscoped, so the policy is not what is
    # producing the answer.
    mixed = store._fetchone(
        "SELECT count(*) FROM audit"
        " WHERE (tenant_id = %s AND tool = %s) OR (tenant_id = %s AND tool = %s)",
        (ACME, TOOL[GLOBEX], GLOBEX, TOOL[ACME]),
    )[0]
    check("...and neither tenant's log holds a call to the other's tool", mixed, 0)


def the_audit_record_the_database_refused(store, secrets, var_dir):
    """Where a tenant's audit record goes when the append cannot happen. Step 060.

    Found by 085's edge pass, and kept because it is the one exit from the isolation
    model this script is otherwise about: an executed call whose `audit` insert fails is
    **not** lost and is **not** refused — 060 writes it to `var/audit-fallback.jsonl`
    with its tenant and the database's own sentence, and logs CRITICAL. Nothing else
    drives that against a real server: `tests/test_broker.py` proves it with the path
    monkeypatched and the fake store.

    Staged the way it actually happens — a month with no partition, which is what a
    deployment that outran its horizon meets — by detaching this month's partition for
    the length of one call.
    """
    import psycopg

    say("an executed call whose audit row the database refuses")
    now = dt.datetime.now(dt.timezone.utc)
    month = now.strftime("audit_p%Y_%m")
    start = now.replace(day=1).strftime("%Y-%m-%d")
    end = (now.replace(day=1) + dt.timedelta(days=32)).replace(day=1).strftime("%Y-%m-%d")
    fallback = var_dir / "audit-fallback.jsonl"

    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute(f"ALTER TABLE audit DETACH PARTITION {month}")
    try:
        failed, call_id, _ = call(secrets[ACME], TOOL[ACME], OWNER_ARG[ACME])
        # The call ran. Refusing it now would be a lie about work that happened, which
        # is `_record_to_fallback`'s own argument, so the caller is told it succeeded.
        check("the call still succeeds, because it already happened", not failed, True)
        check("no audit row reached the table", store.audit_records(ACME, run_id=call_id), [])
    finally:
        with psycopg.connect(DSN, autocommit=True) as conn:
            conn.execute(f"ALTER TABLE audit ATTACH PARTITION {month} "
                         f"FOR VALUES FROM ('{start}') TO ('{end}')")

    lines = [json.loads(line) for line in
             fallback.read_text().splitlines() if line.strip()] if fallback.exists() else []
    kept = [row for row in lines if row.get("run_id") == call_id]
    check("the record landed in the outbox instead", len(kept), 1)
    if kept:
        check("...naming the tenant it belonged to", kept[0].get("tenant_id"), ACME)
        check("...and why the database refused it",
              "no partition" in kept[0].get("append_error", ""), True)
    check("and the next call is audited normally, in the table",
          bool(store.audit_records(
              ACME, run_id=call(secrets[ACME], TOOL[ACME], OWNER_ARG[ACME])[1])), True)


def concurrent_door_calls(secrets):
    """The re-homed *"concurrent cross-tenant requests with the API's own worker"*.

    The shape a deployment runs in: the process answering scoped door calls is also the
    process sweeping across every tenant, in threads that must never inherit a request's
    scope. Sequential rounds cannot see a cell shared between two in-flight requests;
    this can.
    """
    say("eighty concurrent door calls, two tenants, the sweep running underneath")

    def one(tenant):
        names = tool_names(secrets[tenant])
        failed, call_id, _ = call(secrets[tenant], TOOL[tenant], OWNER_ARG[tenant])
        return names == [TOOL[tenant]] and not failed and call_id is not None

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = []
        for _ in range(40):
            futures.append(pool.submit(one, ACME))
            futures.append(pool.submit(one, GLOBEX))
        results = [f.result() for f in futures]
    check("80 concurrent scoped door calls, none crossed", all(results), True)

    # And the concurrency was real: the server's pool grew past the one connection the
    # sequential scenes reuse. Stamped `application_name` is what makes the server's
    # backends countable apart from this script's own.
    import psycopg

    with psycopg.connect(DSN, autocommit=True) as conn:
        backends = conn.execute(
            "SELECT count(*) FROM pg_stat_activity WHERE application_name = %s",
            (API_APPNAME,),
        ).fetchone()[0]
    check("...spread over more than one of the server's connections", backends > 1, True)


def the_migration_runner():
    from carnet.storage import migrate

    say("the migration runner, as the plain table owner")
    check("re-running at head applies nothing and refuses nothing", migrate.apply(DSN), [])


def what_the_scope_costs(store):
    """Printed rather than claimed, so the register's two citations point at a number.

    One extra round trip per scoped borrow. A bound is deliberately not asserted on the
    difference — it is a socket-local number on whatever machine ran it — but a scoped
    read taking milliseconds would be a different design and that is worth failing on.
    """
    from carnet.storage import tenancy

    say("what the scope costs, printed rather than claimed")

    def timed(fn, rounds=200):
        samples = []
        for _ in range(rounds):
            start = time.perf_counter()
            fn()
            samples.append((time.perf_counter() - start) * 1000)
        return statistics.median(samples)

    def unscoped_read():
        store._fetchone("SELECT id FROM tenants WHERE id = %s", (ACME,))

    def scoped_read():
        with tenancy.scoped(ACME):
            store._fetchone("SELECT id FROM tenants WHERE id = %s", (ACME,))

    plain, scoped_ms = timed(unscoped_read), timed(scoped_read)
    print(f"  median unscoped read: {plain:.3f} ms")
    print(f"  median scoped read:   {scoped_ms:.3f} ms  "
          f"(+{scoped_ms - plain:.3f} ms, the set_config round trip and the policy)")
    check("a scoped read stays under 5 ms on a local socket", scoped_ms < 5.0, True)


# --- BYOC: somebody else's Postgres, owned by an ordinary role --------------------


def the_byoc_roles():
    """The customer's own database, owned by an ordinary role. Step 029's testing pass.

    Everything above runs as the local superuser, and **a superuser bypasses row-level
    security by itself** — so none of it proves the design works where it is meant to:
    somebody else's Postgres, where the application role is ordinary. This scene builds
    that, and it is the scene that found the two defects 029's testing pass fixed:

      - migration 037 refused a second deployment in a cluster where the role already
        existed, *and refused it again after an administrator ran the remedy the refusal
        named*, because it tested the right to grant rather than membership;
      - a serving role that owns nothing and is a member of nothing read **zero rows
        with no error**, so a maintenance sweep would have pruned nothing forever while
        looking healthy.

    `e2e_deploy.py`'s `the_managed_database` covers the *`CREATEROLE` master* — the RDS
    shape — through the real compose artifact. This covers the role with no `CREATEROLE`
    at all, and the two failure modes above, which that scene does not reach.

    Needs a superuser to create roles. Skipped, loudly, when there is not one.
    """
    import psycopg

    from carnet.storage import TENANT_ROLE, migrate, tenancy
    from carnet.storage.postgres import PostgresStorage

    adm = dsn_for("postgres")
    with psycopg.connect(adm, autocommit=True) as conn:
        if not conn.execute(
            "SELECT usesuper FROM pg_user WHERE usename = current_user"
        ).fetchone()[0]:
            print("  SKIPPED: needs a superuser to create roles")
            return

    owner, server, stranger = "e2e_rls_owner", "e2e_rls_server", "e2e_rls_stranger"
    db = "carnet_e2e_rls_byoc"
    with psycopg.connect(adm, autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {db}")
        for role in (owner, server, stranger):
            try:
                conn.execute(f"REASSIGN OWNED BY {role} TO current_user")
                conn.execute(f"DROP OWNED BY {role}")
            except psycopg.Error:
                pass
            conn.execute(f"DROP ROLE IF EXISTS {role}")
        # No CREATEROLE on purpose: the flagship case is a cluster where the role
        # already exists, which is where an unconditional GRANT went wrong.
        conn.execute(f"CREATE ROLE {owner} LOGIN PASSWORD 'pw' CREATEDB")
        conn.execute(f"CREATE ROLE {server} LOGIN PASSWORD 'pw'")
        conn.execute(f"CREATE ROLE {stranger} LOGIN PASSWORD 'pw'")

    def as_role(role, database=db):
        parts = urlsplit(dsn_for(database))
        host = parts.netloc.split("@")[-1]
        return urlunsplit((parts.scheme, f"{role}:pw@{host}", f"/{database}",
                           parts.query, parts.fragment))

    with psycopg.connect(as_role(owner, "postgres"), autocommit=True) as conn:
        conn.execute(f"CREATE DATABASE {db}")

    say("BYOC: migrating as an ordinary role, in a cluster that already has the role")
    try:
        migrate.apply(as_role(owner))
        check("037 refuses when membership is missing", "applied", "refused")
    except Exception as exc:  # noqa: BLE001 - the refusal is the subject
        check("037 refuses when membership is missing", "not a member" in str(exc), True)
        check("and the refusal names a remedy an administrator can run",
              f"GRANT {TENANT_ROLE} TO {owner}" in str(exc), True)

    with psycopg.connect(adm, autocommit=True) as conn:
        conn.execute(f"GRANT {TENANT_ROLE} TO {owner}")
    # Compared against the newest migration **on disk**, not a name typed here. The
    # literal was `037_row_level_security`, which was the newest when this was written —
    # so the check silently broke the day 038 landed. What it means to assert is
    # "--migrate ran to the end", and that is a fact about the directory.
    check("after the administrator runs exactly that, --migrate completes",
          migrate.apply(as_role(owner))[-1], migrate.available()[-1][0])

    store = PostgresStorage(as_role(owner), min_size=1, max_size=3)
    with psycopg.connect(as_role(owner), autocommit=True) as conn:
        who = conn.execute(
            "SELECT r.rolname, r.rolsuper FROM pg_class c "
            " JOIN pg_namespace n ON n.oid = c.relnamespace "
            " JOIN pg_roles r ON r.oid = c.relowner "
            " WHERE n.nspname = 'public' AND c.relname = 'tenants'").fetchone()
    check("the tables are owned by an ordinary, non-superuser role", who, (owner, False))

    say("BYOC: the unscoped sweep still crosses tenants for a non-superuser owner")
    # The load-bearing question, re-homed: the sweep's exemption is supposed to come
    # from *ownership*; if it were quietly coming from superuser-ness, every BYOC
    # deployment's retention would silently stop and its partition horizon would stop
    # moving. `maintenance.sweep_log_tables` is these two calls; they are driven
    # directly rather than through it so that the process-global store is left alone.
    old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=120)
    for tenant in (ACME, GLOBEX):
        store.create_tenant(tenant, tenant.title())
    created = store.ensure_log_partitions(back_to=old - dt.timedelta(days=40))
    check("an ordinary owner can create partitions on a policied table",
          len(created) > 0, True)
    for tenant in (ACME, GLOBEX):
        store.append_audit(tenant, {
            "v": 7, "ts": old, "run_id": f"door-byoc{tenant[:4]}",
            "principal_kind": "machine", "principal_id": "t-old", "agent": "a",
            "tool": "t", "effect": "read", "args": {}, "decision": "allow",
            "outcome": "ok",
        })
    check("an unscoped read sees both tenants",
          sorted(r[0] for r in store._fetchall("SELECT id FROM tenants")),
          sorted([ACME, GLOBEX]))
    counts = store.prune_log_records(dt.datetime.now(dt.timezone.utc)
                                     - dt.timedelta(days=30))
    check("one unscoped prune removed rows for both tenants",
          counts.get("audit", 0) >= 2, True)
    check("...and both tenants' expired rows are gone",
          [len(store.audit_records(t)) for t in (ACME, GLOBEX)], [0, 0])

    say("BYOC: and scoping still filters for that same ordinary role")
    with tenancy.scoped(ACME):
        check("a scoped read filters",
              [r[0] for r in store._fetchall("SELECT id FROM tenants")], [ACME])
    check("the owner's startup check passes", store.verify_tenant_isolation(), None)
    store.close()

    say("BYOC: a serving role that is not the owner fails closed at startup")
    with psycopg.connect(as_role(owner), autocommit=True) as conn:
        for role in (server, stranger):
            conn.execute(f"GRANT USAGE ON SCHEMA public TO {role}")
            conn.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES "
                         f"IN SCHEMA public TO {role}")
    with psycopg.connect(adm, autocommit=True) as conn:
        conn.execute(f"GRANT {TENANT_ROLE} TO {server}")

    for role, why in ((server, "a member that does not own the tables"),
                      (stranger, "neither a member nor the owner")):
        probe = PostgresStorage(as_role(role), min_size=1, max_size=2)
        try:
            probe.verify_tenant_isolation()
            check(f"startup refuses for {why}", "started", "refused")
        except Exception as exc:  # noqa: BLE001 - the refusal is the subject
            check(f"startup refuses for {why}", isinstance(exc, Exception), True)
            check(f"...and says why ({role})",
                  "owned by" in str(exc) or "not a member" in str(exc), True)
        probe.close()

    # The one that was silent before 029's testing pass: not a member, not the owner, so
    # no policy applies and RLS default-denies — zero rows, no error, forever.
    strange = PostgresStorage(as_role(stranger), min_size=1, max_size=2)
    check("without the startup check, that role would have read zero rows silently",
          strange._fetchall("SELECT id FROM tenants"), [])
    strange.close()

    with psycopg.connect(adm, autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {db}")
        for role in (owner, server, stranger):
            try:
                conn.execute(f"REASSIGN OWNED BY {role} TO current_user")
                conn.execute(f"DROP OWNED BY {role}")
            except psycopg.Error:
                pass
            conn.execute(f"DROP ROLE IF EXISTS {role}")


def the_creator_role():
    """The role that CREATEs the tenant role itself — the RDS-master shape. Step 030.

    The third PG16 CREATEROLE subtlety: a role's creator receives an implicit membership
    carrying **only ADMIN OPTION** — no SET, no INHERIT — so `pg_has_role(..., 'MEMBER')`
    answers true, migration 037 skipped its GRANT, and every entry point refused at the
    first scoped borrow with "permission denied to set role". A local superuser can never
    reproduce it (superusers may SET ROLE to anything), which is this scene's reason to
    exist. `e2e_deploy.py` asserts the *fixed* state through compose; this reproduces the
    state that produced the defect.

    The cluster's tenant role already exists here, so the creator's implicit grant is
    *reproduced* rather than re-created: superuser grants `WITH ADMIN TRUE, SET FALSE,
    INHERIT FALSE`, byte-for-byte the state PG16 leaves a creator in. 037's membership
    block must then notice SET is missing and use the ADMIN OPTION to self-grant — the
    remedy path with no administrator in it.

    Needs a superuser to set the stage. Skipped, loudly, when there is not one.
    """
    import psycopg

    from carnet.storage import TENANT_ROLE, migrate, tenancy
    from carnet.storage.postgres import PostgresStorage

    adm = dsn_for("postgres")
    with psycopg.connect(adm, autocommit=True) as conn:
        if not conn.execute(
            "SELECT usesuper FROM pg_user WHERE usename = current_user"
        ).fetchone()[0]:
            print("  SKIPPED: needs a superuser to create roles")
            return

    creator = "e2e_rls_creator"
    db = "carnet_e2e_rls_creator"
    with psycopg.connect(adm, autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {db}")
        try:
            conn.execute(f"REASSIGN OWNED BY {creator} TO current_user")
            conn.execute(f"DROP OWNED BY {creator}")
        except psycopg.Error:
            pass
        conn.execute(f"DROP ROLE IF EXISTS {creator}")
        conn.execute(f"CREATE ROLE {creator} LOGIN PASSWORD 'pw' CREATEDB CREATEROLE")
        conn.execute(
            f"GRANT {TENANT_ROLE} TO {creator} WITH ADMIN TRUE, SET FALSE, INHERIT FALSE"
        )

    def as_creator(database):
        parts = urlsplit(dsn_for(database))
        host = parts.netloc.split("@")[-1]
        return urlunsplit((parts.scheme, f"{creator}:pw@{host}", f"/{database}",
                           parts.query, parts.fragment))

    with psycopg.connect(as_creator("postgres"), autocommit=True) as conn:
        conn.execute(f"CREATE DATABASE {db}")
        member, settable = conn.execute(
            f"SELECT pg_has_role(current_user, '{TENANT_ROLE}', 'MEMBER'),"
            f"       pg_has_role(current_user, '{TENANT_ROLE}', 'SET')"
        ).fetchone()
    say("creator: ADMIN OPTION alone — the state that fooled a 'MEMBER' check")
    check("'MEMBER' answers true for the admin-only grant", member, True)
    check("...while SET ROLE is still impossible", settable, False)

    check("--migrate completes anyway, self-granting via the ADMIN OPTION",
          migrate.apply(as_creator(db))[-1], migrate.available()[-1][0])

    store = PostgresStorage(as_creator(db), min_size=1, max_size=2)
    check("the creator's startup check passes", store.verify_tenant_isolation(), None)
    store.create_tenant(ACME, ACME.title())
    with tenancy.scoped(ACME):
        check("and a scoped read actually takes the role",
              [r[0] for r in store._fetchall("SELECT id FROM tenants")], [ACME])
    store.close()

    with psycopg.connect(adm, autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {db}")
        try:
            conn.execute(f"REASSIGN OWNED BY {creator} TO current_user")
            conn.execute(f"DROP OWNED BY {creator}")
        except psycopg.Error:
            pass
        conn.execute(f"DROP ROLE IF EXISTS {creator}")


# --- the world ---------------------------------------------------------------------


def _generate_key():
    return base64.b64encode(os.urandom(32)).decode()


def build_the_world(store):
    """Two customers, on one deployment, each having vetted its own half of one server."""
    from carnet import agents, tools
    from carnet.access import tokens as machine_tokens
    from carnet.tools.base import Resource

    secrets = {}
    for tenant in (ACME, GLOBEX):
        store.create_tenant(tenant, tenant.title())
        store.create_user(tenant, {
            "id": ADMIN_ID[tenant],
            "issuer": ISSUER[tenant],
            "subject": ADMIN_SUBJECT,
            "email": f"admin@{DOMAIN[tenant]}",
        })
        store.save_tenant_idp(tenant, {
            "issuer": ISSUER[tenant],
            "jwks_uri": f"http://127.0.0.1:{JWKS_PORT}/jwks.json",
            "audience": AUDIENCE,
            "allowed_domains": (DOMAIN[tenant],),
        })
        store.grant_platform_role(tenant, "user", ADMIN_ID[tenant], "admin", actor=ACTOR)

        store.allow_host(tenant, UPSTREAM_HOST, actor=ACTOR, note="the tracker")
        tools.register_connector(
            tenant,
            CONNECTOR[tenant],
            url=f"http://{UPSTREAM_HOST}:{UPSTREAM_PORT}/mcp",
            credential_env=CREDENTIAL_ENV[tenant],
            description=f"{tenant}'s issue tracker",
            actor=ACTOR,
        )
        tools.vet_tool(
            tenant,
            CONNECTOR[tenant],
            REMOTE[tenant],
            effect="read",
            identity="service",
            resources=(Resource("github.repo", ["owner", "repo"],
                                template="{owner}/{repo}"),),
            actor=ACTOR,
            credential=CREDENTIAL[tenant],
        )
        agents.save(tenant, {
            "name": AGENT[tenant],
            "permissions": {
                "tools": [TOOL[tenant]],
                "scope": {"github.repo": {"read": [f"{OWNER_ARG[tenant]}/*"]}},
            },
        }, actor=ACTOR)

        row, secret = machine_tokens.mint(
            tenant, f"{tenant}-assistant", ADMIN_ID[tenant], actor=ACTOR
        )
        store.grant_agent(tenant, AGENT[tenant], "machine", row["id"],
                          role="user", granted_by=ACTOR, actor=ACTOR)
        secrets[tenant] = secret
    return secrets


def main():
    import psycopg

    if socket.gethostbyname(UPSTREAM_HOST) != "127.0.0.1":
        raise SystemExit(f"{UPSTREAM_HOST} did not resolve to 127.0.0.1; this needs DNS")

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")

    os.environ["CARNET_DATABASE_URL"] = DSN
    os.environ.setdefault("CARNET_SECRET_KEY", _generate_key())
    # Step 058: the dial vets DNS answers, and localtest.me resolves to loopback on
    # purpose — the operator (this script) consents to its own machine.
    os.environ["CARNET_EGRESS_INTERNAL_HOSTS"] = UPSTREAM_HOST
    for tenant in (ACME, GLOBEX):
        os.environ[CREDENTIAL_ENV[tenant]] = CREDENTIAL[tenant]

    from carnet import storage
    from carnet.core import crypto
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    migrate.apply(DSN)
    store = storage.configure(PostgresStorage(DSN))
    crypto.configure(crypto.from_environment())

    var_dir = pathlib.Path(tempfile.mkdtemp(prefix="e2e-rls-var-"))

    jwks = http.server.ThreadingHTTPServer(("127.0.0.1", JWKS_PORT), Jwks)
    threading.Thread(target=jwks.serve_forever, daemon=True).start()
    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", UPSTREAM_PORT), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()

    secrets = build_the_world(store)

    # **Retention lives in the API's environment, not in this one.** The sweep this
    # script asserts must be the server's own `LogMaintainer` thread — an unscoped
    # daemon in the process that is also serving scoped door calls — so this process
    # must not be able to do it, and a second sweeper would make the assertion a race.
    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port", str(API_PORT)],
        env={**os.environ,
             "PGAPPNAME": API_APPNAME,
             # Its own var/, so the outbox scene reads the file this server wrote and
             # the repository's `var/` is left alone.
             "CARNET_VAR_DIR": str(var_dir),
             "CARNET_RETENTION_DAYS": "30",
             "CARNET_RETENTION_SWEEP": "2"},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(60):
            try:
                httpx.get(f"{API}/health", timeout=1)
                break
            except Exception:  # noqa: BLE001 - waiting for a socket
                time.sleep(0.5)
        else:
            raise SystemExit("the API did not come up")

        ids = {ACME: [], GLOBEX: []}

        def the_pool_scene():
            ids.update(two_tenants_over_one_pool(secrets))

        scene(the_shape_of_the_role, store)
        scene(the_pool_scene)
        scene(the_pool_is_actually_shared)
        scene(the_databases_own_answer, store)
        scene(the_unbound_role_is_loud)
        scene(a_call_id_from_the_other_tenant, store, secrets, ids)
        scene(one_unscoped_sweep_crosses_both, store, secrets)
        scene(concurrent_door_calls, secrets)
        scene(the_pool_loses_its_connections, store, secrets)
        scene(the_audit_record_the_database_refused, store, secrets, var_dir)
        scene(the_migration_runner)
        scene(what_the_scope_costs, store)
        scene(the_byoc_roles)
        scene(the_creator_role)
        verdict = report()
    finally:
        api.terminate()
        api.wait(timeout=10)
        jwks.shutdown()
        upstream.shutdown()
        store.close()
    raise SystemExit(verdict)


if __name__ == "__main__":
    main()
