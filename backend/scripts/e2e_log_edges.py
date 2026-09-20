"""The cursor, the lookup and the connection probe at their edges, over real HTTP
against real Postgres.

Plan 107 D10 and D11 shipped in 110f: every log row carries the store's own sequence
number, the three log routes answer newest first, `?before=<id>` turns the page,
`GET /admin/users?email=` answers one person, `GET /connections` says which agents act
as the caller on each connector, and `POST /connectors/{id}/connection/test` dials the
server under the caller's own account. The route tests drive all of that against the
in-memory store. **Four of the properties below cannot fail there**, which is why this
is a script:

  - **The sequence is one column per table and it is shared by every tenant.** Postgres
    hands out `BIGINT GENERATED ALWAYS AS IDENTITY` across the whole table, so two
    customers writing at once interleave in one number line. A cursor that walked
    *positions* rather than ids would skip rows the moment another tenant wrote between
    two pages, and against a single-tenant fixture it would look perfect.
  - **`before` is a WHERE clause, not a slice.** The route asks for the newest N rows
    older than an id, which in SQL is `ORDER BY id DESC LIMIT n` inside a subquery and
    a re-sort outside it. Get the parameter order wrong and the fake still passes,
    because the fake is a list comprehension.
  - **Ordering is by insertion and not by the stamp.** The door log's `ts` is written
    by its caller, so three rows can land in an order their timestamps contradict. A
    reader that sorted by `ts` would pass every fixture in the suite and put a
    customer's most recent call in the middle of the page.
  - **A real dial.** The connection probe opens a socket to an MCP server under a
    credential that was sealed by this deployment's key and read back through psycopg.

It found two defects, both now fixed and both covered by the route suite as well:
`?email=` with a blank value fell through to `"" == ""` and answered with every person
who has no address, and the probe dialled a **REST** connector as though it spoke MCP
and answered 500.

**It builds its own world** — a database, two tenants, two identity providers, a fake
MCP server and the API — so it needs nobody at a keyboard and touches nothing else.

    cd backend && .venv/bin/python scripts/e2e_log_edges.py

**Costs nothing.** No model is called; the only server dialled is the one this script
serves on loopback.
"""

import json
import os
import pathlib
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import urlsplit, urlunsplit

import httpx

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_log_edges"

TENANT = "logedge"
OTHER = "globexlog"
IDP_PORT = 8912
OTHER_IDP_PORT = 8913
API_PORT = 8134
MCP_PORT = 8135
DEAD_PORT = 8136  # nothing ever listens here, on purpose

API = f"http://127.0.0.1:{API_PORT}"
# Resolves to 127.0.0.1 and is not a literal IP, so the egress check passes on the name.
MCP_HOST = "localtest.me"
MCP_URL = f"http://{MCP_HOST}:{MCP_PORT}/mcp"
DEAD_URL = f"http://{MCP_HOST}:{DEAD_PORT}/mcp"

PRIYA = "priya@acme.com"
SAM = "sam@acme.com"
MALLORY = "mallory@acme.com"
ACTOR = "system:cli"

# A page, as the screens ask for one. The routes cap at their own maximum; this is the
# number the frontend's `LOG_PAGE` sends.
PAGE = 100

CHECKS = []


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok))
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: {actual!r}"
          + ("" if ok else f"  (expected {expected!r})"))


def say(what):
    print(f"\n=== {what}", flush=True)


def dsn_for(database: str) -> str:
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


DSN = dsn_for(DB)

TOOLS = [
    {
        "name": "list_issues",
        "description": "List issues in a repository.",
        "inputSchema": {
            "type": "object",
            "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}},
            "required": ["owner"],
        },
    },
    {
        "name": "create_issue",
        "description": "Open an issue in a repository.",
        "inputSchema": {
            "type": "object",
            "properties": {"owner": {"type": "string"}, "title": {"type": "string"}},
            "required": ["owner", "title"],
        },
    },
    {
        "name": "whoami",
        "description": "Who the credential belongs to.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


class MCPServer(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        message = json.loads(self.rfile.read(length) or "{}")
        if "id" not in message:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if message["method"] == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "acme-mcp-server", "version": "4.1.0"},
            }
        elif message["method"] == "tools/list":
            result = {"tools": TOOLS}
        elif message["method"] == "tools/call":
            result = {
                "content": [{"type": "text", "text": json.dumps([{"id": 41}])}],
                "isError": False,
            }
        else:
            result = {}

        body = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Mcp-Session-Id", "sess-1")
        self.end_headers()
        self.wfile.write(body)


def _wait(url, seconds=60):
    for _ in range(seconds * 2):
        try:
            httpx.get(url, timeout=1)
            return
        except Exception:
            time.sleep(0.5)
    raise SystemExit(f"{url} never answered")


def _key():
    import base64
    import os as _os

    return base64.b64encode(_os.urandom(32)).decode()


def cli(*args, tenant=TENANT):
    return subprocess.run(
        [sys.executable, "-m", "carnet.cli", *args],
        env={**os.environ, "CARNET_TENANT": tenant},
        capture_output=True,
        text=True,
    )


def main():
    import psycopg

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import dev_idp

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")

    os.environ["CARNET_DATABASE_URL"] = DSN
    os.environ.setdefault("CARNET_SECRET_KEY", _key())
    os.environ["CARNET_WORKERS"] = "0"
    os.environ["CARNET_TENANT"] = TENANT
    # A shared credential that really is set on this deployment, so *the probe does not
    # fall through to it* is asserted against a deployment where falling through would
    # have worked.
    os.environ["ACME_TOKEN"] = "MARKER-SHARED-CREDENTIAL"
    # The operator consenting to its own loopback server, which is what lets a plain
    # `http://` connector be registered at all. Set before the API starts, because the
    # door and the probe both read it.
    os.environ["CARNET_EGRESS_INTERNAL_HOSTS"] = MCP_HOST

    _, provider = dev_idp.serve(IDP_PORT)
    _, elsewhere = dev_idp.serve(OTHER_IDP_PORT)

    from carnet import bootstrap, storage
    from carnet.core import crypto
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    # This process writes connections directly, which means sealing — an entry point's
    # job, and this script is one.
    crypto.configure(crypto.from_environment())
    migrate.apply(DSN)
    store = storage.configure(PostgresStorage(DSN))
    for tenant, name, prov in ((TENANT, "Log Edge", provider), (OTHER, "Globex Log", elsewhere)):
        store.create_tenant(tenant, name)
        store.save_tenant_idp(tenant, {
            "issuer": prov.issuer, "jwks_uri": f"{prov.issuer}/v1/keys",
            "audience": dev_idp.AUDIENCE, "subject_claim": "uid", "email_claim": "sub",
            "allowed_domains": ("acme.com",),
        })
        bootstrap.seed_tenant(tenant)

    mcp = ThreadingHTTPServer(("127.0.0.1", MCP_PORT), MCPServer)
    Thread(target=mcp.serve_forever, daemon=True).start()

    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port", str(API_PORT)],
        env={**os.environ},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        _wait(f"{API}/health")
        run(store, provider, elsewhere)
    finally:
        api.terminate()
        api.wait(timeout=10)
        mcp.shutdown()
        store.close()

    failed = [label for label, ok in CHECKS if not ok]
    say(f"{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    for label in failed:
        print("  FAILED:", label)
    raise SystemExit(1 if failed else 0)


def run(store, provider, elsewhere):
    import dev_idp

    def token(prov, email):
        return dev_idp.Provider.token_for(prov, email)

    priya = {"Authorization": f"Bearer {token(provider, PRIYA)}"}
    sam = {"Authorization": f"Bearer {token(provider, SAM)}"}
    mallory = {"Authorization": f"Bearer {token(elsewhere, MALLORY)}"}
    c = httpx.Client(base_url=API, timeout=60)

    # Nobody exists until they have made one request: the row is keyed on the subject
    # inside a token, which only arrives with one.
    for headers in (priya, sam, mallory):
        c.get("/me", headers=headers)

    her = store.find_user_by_email(TENANT, PRIYA)["id"]
    his = store.find_user_by_email(TENANT, SAM)["id"]
    cli("--grant-role", "admin", PRIYA)
    cli("--grant-role", "admin", MALLORY, tenant=OTHER)
    check("priya administers logedge", c.get("/me", headers=priya).json()["admin"], True)
    check("sam does not", c.get("/me", headers=sam).json()["admin"], False)

    edges_of_the_cursor(c, priya, sam, store)
    the_walk(c, priya, store)
    two_customers_in_one_sequence(c, priya, mallory, store)
    the_other_two_logs(c, priya, sam, store, her)
    looking_somebody_up(c, priya, sam, store, her, his)
    what_uses_a_connection(c, priya, sam, store, her, his)
    testing_a_connection(c, priya, sam, store, her)
    who_may_sign_in_is_recorded(c, priya, store)
    taking_a_connector_out_of_service(c, priya, store, her)


# --- the cursor ---------------------------------------------------------------------


def _hosts(c, headers, count, prefix):
    """`count` administrative records, written the way an administrator writes them."""
    for i in range(count):
        c.post("/admin/hosts", json={"host": f"{prefix}{i}.example"}, headers=headers)


def _ids(rows):
    return [row["id"] for row in rows]


def edges_of_the_cursor(c, priya, sam, store):
    say("every row carries the store's own sequence number, and it rises with insertion")
    _hosts(c, priya, 5, "first")
    page = c.get("/admin-audit", headers=priya).json()
    check("every row has an id", all(isinstance(r.get("id"), int) for r in page), True)
    check("ids are unique", len(set(_ids(page))), len(page))
    check("newest first", _ids(page), sorted(_ids(page), reverse=True))
    check("and the newest row is the last thing written",
          page[0]["target_id"], "first4.example")
    check("while the store still answers oldest first, which is what --admin-log prints",
          _ids(store.admin_audit_records(TENANT))[:1],
          [min(_ids(store.admin_audit_records(TENANT)))])
    printed = cli("--admin-log")
    check("and --admin-log still reads it", printed.returncode, 0)
    check("printing the oldest row first, as it always has",
          printed.stdout.index("first0.example") < printed.stdout.index("first4.example"), True)

    say("the cursor's own edges: what it refuses, and what it answers with nothing")
    check("before=0 is a 422 naming the field, not an empty list",
          c.get("/admin-audit?before=0", headers=priya).status_code, 422)
    check("before=-1 too", c.get("/admin-audit?before=-1", headers=priya).status_code, 422)
    check("before=abc too", c.get("/admin-audit?before=abc", headers=priya).status_code, 422)
    check("before=1.5 too", c.get("/admin-audit?before=1.5", headers=priya).status_code, 422)
    check("before= (blank) too", c.get("/admin-audit?before=", headers=priya).status_code, 422)
    check("before=1 is legal and answers with nothing, because no row is older than the first",
          c.get("/admin-audit?before=1", headers=priya).json(), [])
    everything = c.get(f"/admin-audit?limit={PAGE}", headers=priya).json()
    check("before=<the oldest id there is> is empty",
          c.get(f"/admin-audit?before={min(_ids(everything))}", headers=priya).json(), [])
    check("before=<the newest> is everything but the newest",
          _ids(c.get(f"/admin-audit?before={max(_ids(everything))}", headers=priya).json()),
          sorted(_ids(everything), reverse=True)[1:])
    huge = c.get("/admin-audit?before=9223372036854775807", headers=priya)
    check("a cursor past the end of the log is the whole log, not an error",
          (huge.status_code, _ids(huge.json())), (200, sorted(_ids(everything), reverse=True)))

    say("before and limit together take the NEWEST n older than the cursor")
    ordered = sorted(_ids(everything), reverse=True)
    cursor = ordered[1]
    two = c.get(f"/admin-audit?before={cursor}&limit=2", headers=priya).json()
    check("two rows", len(two), 2)
    check("and they are the two directly below the cursor, newest first",
          _ids(two), [i for i in ordered if i < cursor][:2])
    check("limit=0 is still a 422", c.get("/admin-audit?limit=0", headers=priya).status_code, 422)
    check("an over-large limit is a 422, never a silent truncation",
          c.get("/admin-audit?limit=100000", headers=priya).status_code, 422)

    say("the cursor is behind the role, like everything else on this route")
    check("sam gets 403 with a cursor, not a page",
          c.get("/admin-audit?before=5", headers=sam).status_code, 403)
    check("and 403 before 422: the role is decided before the query is parsed",
          c.get("/admin-audit?before=0", headers=sam).status_code, 403)
    check("a stranger gets 401 with a cursor", c.get("/admin-audit?before=5").status_code, 401)


def the_walk(c, priya, store):
    say("a log of 250 rows, walked to the end one page at a time: no repeat, no gap")
    _hosts(c, priya, 245, "walk")
    whole = store.admin_audit_records(TENANT)
    expected = sorted((r["id"] for r in whole), reverse=True)

    seen, pages, cursor = [], 0, None
    while True:
        query = f"/admin-audit?limit={PAGE}" + (f"&before={cursor}" if cursor else "")
        page = c.get(query, headers=priya).json()
        pages += 1
        seen.extend(_ids(page))
        if len(page) < PAGE:
            break
        cursor = min(_ids(page))
        if pages > 20:
            break
    check("three pages reach the end of 250 rows", pages, 3)
    check("no row was seen twice", len(seen), len(set(seen)))
    check("and the walk is the whole log, in order", seen, expected)

    say("a row written BETWEEN two pages moves nothing — the promise a cursor makes")
    first = c.get(f"/admin-audit?limit={PAGE}", headers=priya).json()
    _hosts(c, priya, 3, "interleaved")
    second = c.get(f"/admin-audit?limit={PAGE}&before={min(_ids(first))}", headers=priya).json()
    check("the second page repeats nothing from the first",
          set(_ids(first)) & set(_ids(second)), set())
    check("and skips nothing: it begins exactly below the first page",
          max(_ids(second)), min(_ids(first)) - 1)
    check("the three new rows are above the first page, where they belong",
          [r["target_id"] for r in c.get("/admin-audit?limit=3", headers=priya).json()],
          ["interleaved2.example", "interleaved1.example", "interleaved0.example"])

    say("sixty rows written in a tight loop read back in the order they landed")
    for i in range(60):
        store.allow_host(TENANT, f"tight{i}.example", actor=ACTOR)
    top = c.get("/admin-audit?limit=60", headers=priya).json()
    check("ids strictly descend", _ids(top), sorted(_ids(top), reverse=True))
    check("and the newest row is the last one written", top[0]["target_id"], "tight59.example")


def two_customers_in_one_sequence(c, priya, mallory, store):
    say("TWO CUSTOMERS WRITING AT ONCE — one number line, and neither may skip a row")
    for i in range(30):
        c.post("/admin/hosts", json={"host": f"mine{i}.example"}, headers=priya)
        c.post("/admin/hosts", json={"host": f"theirs{i}.example"}, headers=mallory)

    mine = [r["id"] for r in store.admin_audit_records(TENANT)]
    theirs = [r["id"] for r in store.admin_audit_records(OTHER)]
    check("the two tenants' ids interleave in one sequence, which is the whole risk",
          any(t in range(min(mine), max(mine)) for t in theirs), True)

    seen, cursor = [], None
    while True:
        query = "/admin-audit?limit=20" + (f"&before={cursor}" if cursor else "")
        page = c.get(query, headers=priya).json()
        seen.extend(_ids(page))
        if len(page) < 20:
            break
        cursor = min(_ids(page))
    check("walking one tenant's log reaches every one of its rows", sorted(seen), sorted(mine))
    check("and not one of the other tenant's", set(seen) & set(theirs), set())

    theirs_page = c.get("/admin-audit?limit=5", headers=mallory).json()
    check("the other customer's own page is theirs alone",
          set(_ids(theirs_page)) <= set(theirs), True)
    check("a cursor from one tenant's log cannot pull rows out of another's",
          set(_ids(c.get(f"/admin-audit?before={max(mine)}&limit=100", headers=mallory).json()))
          & set(mine), set())


def the_other_two_logs(c, priya, sam, store, her):
    say("the denial log: the same cursor, over rows written by being refused")
    for _ in range(120):
        c.get("/admin-audit", headers=sam)
    denials = c.get(f"/admin/denials?limit={PAGE}", headers=priya).json()
    check("every denial carries an id", all(isinstance(r.get("id"), int) for r in denials), True)
    check("newest first", _ids(denials), sorted(_ids(denials), reverse=True))
    check("before=0 is a 422", c.get("/admin/denials?before=0", headers=priya).status_code, 422)
    older = c.get(f"/admin/denials?limit={PAGE}&before={min(_ids(denials))}", headers=priya).json()
    check("the page below repeats nothing", set(_ids(older)) & set(_ids(denials)), set())
    check("and begins directly below it", max(_ids(older)), min(_ids(denials)) - 1)
    check("the cursor composes with a filter",
          {r["resource_kind"] for r in c.get(
              f"/admin/denials?resource_kind=admin&before={min(_ids(denials))}&limit=5",
              headers=priya).json()},
          {"admin"})
    check("and a filter that matches nothing is an empty page, not an error",
          c.get("/admin/denials?resource_kind=tool&limit=5", headers=priya).json(), [])
    check("a kind the server does not have is still a 422 with a cursor on it",
          c.get("/admin/denials?resource_kind=tools&before=9", headers=priya).status_code, 422)

    say("the door log: ids on seeded traffic, and the cursor over it")
    for i in range(150):
        store.append_audit(TENANT, {
            "v": 7, "ts": "2026-08-02T10:00:00.000+00:00",
            "run_id": f"door-{i:012x}", "principal_kind": "machine",
            "principal_id": "tok_seed", "agent": "triage",
            "tool": "acme_list_issues" if i % 2 else "acme_create_issue",
            "effect": "read", "args": {}, "decision": "allow", "outcome": "ok",
            "identity_source": "none",
        })
    calls = c.get(f"/admin/door-calls?limit={PAGE}", headers=priya).json()
    check("every door row carries an id", all(isinstance(r.get("id"), int) for r in calls), True)
    check("newest first", _ids(calls), sorted(_ids(calls), reverse=True))
    check("before=0 is a 422", c.get("/admin/door-calls?before=0", headers=priya).status_code, 422)
    below = c.get(f"/admin/door-calls?limit={PAGE}&before={min(_ids(calls))}", headers=priya).json()
    check("the page below repeats nothing", set(_ids(below)) & set(_ids(calls)), set())
    check("and begins directly below it", max(_ids(below)), min(_ids(calls)) - 1)

    filtered = c.get("/admin/door-calls?tool=acme_list_issues&limit=10", headers=priya).json()
    check("a filter narrows the page", {r["tool"] for r in filtered}, {"acme_list_issues"})
    paged = c.get(
        f"/admin/door-calls?tool=acme_list_issues&before={min(_ids(filtered))}&limit=10",
        headers=priya).json()
    check("and the cursor composes with it rather than replacing it",
          {r["tool"] for r in paged}, {"acme_list_issues"})
    check("the filtered walk skips no matching row",
          max(_ids(paged)) < min(_ids(filtered)), True)
    check("a cursor with a date window and a filter is still one question",
          c.get("/admin/door-calls?since=2026-08-01&until=2026-08-03&decision=allow"
                f"&before={min(_ids(calls))}&limit=5", headers=priya).status_code, 200)
    check("and a malformed date is a 422 even with a legal cursor",
          c.get("/admin/door-calls?since=not-a-date&before=5", headers=priya).status_code, 422)


# --- looking somebody up by the address they are known by ----------------------------


def looking_somebody_up(c, priya, sam, store, her, his):
    say("one person, by exact address — what matches, what does not, and who may ask")
    found = c.get("/admin/users", params={"email": PRIYA}, headers=priya).json()
    check("the exact address answers one person", [r["id"] for r in found], [her])
    check("and the row says what the screen needs",
          (found[0]["email"], found[0]["status"], found[0]["signed_in"]),
          (PRIYA, "active", True))

    check("matched without regard to case, in both directions",
          [r["id"] for r in c.get("/admin/users", params={"email": "PRIYA@ACME.COM"},
                                  headers=priya).json()], [her])
    check("and around surrounding space, which is what a paste carries",
          [r["id"] for r in c.get("/admin/users", params={"email": f"  {PRIYA} "},
                                  headers=priya).json()], [her])
    check("an address nobody here is known by is an empty answer, not a 404",
          c.get("/admin/users", params={"email": "nobody@acme.com"}, headers=priya).json(), [])
    check("a prefix is NOT a search: this is exact or nothing",
          c.get("/admin/users", params={"email": "priya@"}, headers=priya).json(), [])
    check("and neither is a SQL wildcard, which is a value here and not syntax",
          c.get("/admin/users", params={"email": "%@acme.com"}, headers=priya).json(), [])
    check("nor the other one",
          c.get("/admin/users", params={"email": "_riya@acme.com"}, headers=priya).json(), [])
    # Percent-encoded, because a lone surrogate cannot be encoded into a query string by
    # a client that means well — which is exactly why the hostile spelling is the one
    # worth sending. Step 087 made this class reach every route as a refusal.
    check("a lone surrogate is answered, never a 500",
          c.get("/admin/users?email=%ED%A0%80@acme.com",
                headers=priya).status_code in (200, 400, 422), True)
    check("and a very long one is answered rather than crashed",
          c.get("/admin/users", params={"email": "x" * 4000 + "@acme.com"},
                headers=priya).status_code, 200)

    say("the lookup is one statement with the store's, and it is behind the role")
    check("it agrees with find_user_by_email, which is what sharing has always used",
          c.get("/admin/users", params={"email": PRIYA}, headers=priya).json()[0]["id"],
          store.find_user_by_email(TENANT, PRIYA)["id"])
    check("sam cannot look anybody up",
          c.get("/admin/users", params={"email": PRIYA}, headers=sam).status_code, 403)
    check("a stranger cannot either",
          c.get("/admin/users", params={"email": PRIYA}).status_code, 401)

    say("a blank address is not an address")
    blank = c.get("/admin/users", params={"email": ""}, headers=priya)
    check("?email= (blank) is refused, not answered with a listing", blank.status_code, 400)
    check("and the refusal says what to do instead",
          "whole list" in blank.json()["detail"], True)
    spaces = c.get("/admin/users", params={"email": "   "}, headers=priya)
    check("a boxful of spaces is the same refusal", spaces.status_code, 400)
    check("while no parameter at all is still the whole listing",
          len(c.get("/admin/users", headers=priya).json()) >= 2, True)

    say("a person the directory sent and who has never signed in")
    store.create_user(TENANT, {
        "id": "u-pushed", "issuer": "https://scim.example.com", "subject": "ext-1",
        "email": "pushed@acme.com", "display_name": "Pushed Person",
    })
    pushed = c.get("/admin/users", params={"email": "pushed@acme.com"}, headers=priya).json()
    check("is found by address", [r["id"] for r in pushed], ["u-pushed"])
    check("and is honestly marked as never having been here", pushed[0]["signed_in"], False)

    say("a person with no address at all, which is what a blank lookup must not find")
    store.create_user(TENANT, {
        "id": "u-nameless", "issuer": "https://scim.example.com", "subject": "ext-2",
        "email": "", "display_name": "No Address",
    })
    check("the blank lookup does not hand them out — the defect this found",
          c.get("/admin/users", params={"email": ""}, headers=priya).status_code, 400)
    check("and the full listing does contain them, because they are here",
          any(r["id"] == "u-nameless" for r in c.get("/admin/users", headers=priya).json()), True)

    say("two providers, one address — the ambiguity 110d made easy to create")
    store.create_user(TENANT, {
        "id": "u-twin", "issuer": "https://other-idp.example.com", "subject": "twin-1",
        "email": PRIYA, "display_name": "Priya Elsewhere",
    })
    twins = c.get("/admin/users", params={"email": PRIYA}, headers=priya).json()
    check("the route reports BOTH rather than choosing one",
          sorted(r["id"] for r in twins), sorted([her, "u-twin"]))

    say("a disabled person is still somebody you can add to a group")
    c.post(f"/admin/users/{his}/disable", headers=priya)
    off = c.get("/admin/users", params={"email": SAM}, headers=priya).json()
    check("found", [r["id"] for r in off], [his])
    check("and said to be cut off, so the screen can say so", off[0]["status"], "disabled")
    c.post(f"/admin/users/{his}/enable", headers=priya)
    check("and back", c.get("/admin/users", params={"email": SAM},
                            headers=priya).json()[0]["status"], "active")

    say("one customer's directory is invisible to another's administrator")
    check("mallory's tenant has nobody by priya's address",
          c.get("/admin/users", params={"email": PRIYA},
                headers={"Authorization": priya["Authorization"]}).status_code, 200)
    check("and priya's has nobody by mallory's",
          c.get("/admin/users", params={"email": MALLORY}, headers=priya).json(), [])


# --- what uses a connection ----------------------------------------------------------


def _setup_connectors(store):
    from carnet import agents, tools

    store.allow_host(TENANT, MCP_HOST, actor=ACTOR)
    tools.register_connector(TENANT, "acme", url=MCP_URL, credential_env="ACME_TOKEN",
                             description="The fake MCP server.", actor=ACTOR)
    tools.vet_tool(TENANT, "acme", "list_issues", effect="read", identity="user", actor=ACTOR)
    # `read` because the effect is not what is under test here and a write must declare
    # a resource; `service` is the half that matters — this tool acts as nobody.
    tools.vet_tool(TENANT, "acme", "create_issue", effect="read", identity="service",
                   actor=ACTOR)
    # A local name that is not the prefixed remote one: `used_by` must compare what an
    # agent was granted, which is this, and not what the server calls it.
    tools.vet_tool(TENANT, "acme", "whoami", effect="read", identity="user",
                   local_name="me", actor=ACTOR)

    # A second connector whose only approved tool acts as the service. Nothing may ever
    # list it under *used by*, whatever anybody is granted.
    tools.register_connector(TENANT, "shared", url=MCP_URL, actor=ACTOR)
    tools.vet_tool(TENANT, "shared", "list_issues", effect="read", identity="service",
                   actor=ACTOR)

    # A connector that is registered and has nothing approved on it at all.
    tools.register_connector(TENANT, "empty", url=MCP_URL, actor=ACTOR)

    for name, granted in (
        ("triage", ["acme_list_issues"]),
        ("filer", ["acme_create_issue"]),
        ("shorty", ["me"]),
        ("nobodys", ["acme_list_issues"]),
        ("viagroup", ["acme_list_issues"]),
        ("gone", ["acme_list_issues"]),
    ):
        agents.save(TENANT, {
            "name": name, "system": "x",
            "permissions": {"tools": granted, "scope": {}},
        }, actor=ACTOR)


def what_uses_a_connection(c, priya, sam, store, her, his):
    from carnet.access import tokens

    _setup_connectors(store)
    for name in ("triage", "filer", "shorty", "gone"):
        store.grant_agent(TENANT, name, "user", her, role="owner", actor=ACTOR)

    group = c.post("/groups", json={"name": "oncall"}, headers=priya).json()
    c.put(f"/groups/{group['group_id']}/members/user/{her}", headers=priya)
    store.grant_agent(TENANT, "viagroup", "group", group["group_id"], role="user", actor=ACTOR)

    say("a connection says which agents act as YOU there, and says nothing else")
    rows = {r["connector_id"]: r for r in c.get("/connections", headers=priya).json()}
    check("the agents whose granted tool acts as the caller, sorted",
          rows["acme"]["used_by"], ["gone", "shorty", "triage", "viagroup"])
    check("a tool granted through a GROUP counts, because the door counts it",
          "viagroup" in rows["acme"]["used_by"], True)
    check("a local name that is not the remote one is matched as granted",
          "shorty" in rows["acme"]["used_by"], True)
    check("an agent whose tool acts as the SERVICE is not listed, and that is the truth",
          "filer" in rows["acme"]["used_by"], False)
    check("nor is an agent nobody granted her", "nobodys" in rows["acme"]["used_by"], False)
    check("a connector whose every approved tool is a service tool lists nobody",
          rows["shared"]["used_by"], [])
    check("and one with nothing approved lists nobody", rows["empty"]["used_by"], [])
    check("used_by is on EVERY row, whatever its state",
          all(isinstance(r["used_by"], list) for r in rows.values()), True)

    say("somebody with no grants at all")
    his_rows = {r["connector_id"]: r for r in c.get("/connections", headers=sam).json()}
    check("sees the connectors", sorted(his_rows) >= ["acme"], True)
    check("and nothing under used by, because nothing of his acts as him",
          his_rows["acme"]["used_by"], [])

    say("a personal token lists its OWNER's agents, exactly as the door scopes it")
    personal, personal_secret = tokens.mint(TENANT, "priya-laptop", her, actor=ACTOR,
                                            acts_as_owner=True)
    mine = {r["connector_id"]: r for r in c.get(
        "/connections", headers={"Authorization": f"Bearer {personal_secret}"}).json()}
    check("her agents, through her token", mine["acme"]["used_by"],
          ["gone", "shorty", "triage", "viagroup"])

    say("a service token lists what the TOKEN was granted, and not its minter's")
    service, service_secret = tokens.mint(TENANT, "nightly", her, actor=ACTOR)
    store.grant_agent(TENANT, "filer", "machine", service["id"], role="user", actor=ACTOR)
    theirs = {r["connector_id"]: r for r in c.get(
        "/connections", headers={"Authorization": f"Bearer {service_secret}"}).json()}
    check("only the service agent, which acts as nobody, so nothing is listed",
          theirs["acme"]["used_by"], [])
    store.grant_agent(TENANT, "triage", "machine", service["id"], role="user", actor=ACTOR)
    theirs = {r["connector_id"]: r for r in c.get(
        "/connections", headers={"Authorization": f"Bearer {service_secret}"}).json()}
    check("and the caller-identity one once it is granted", theirs["acme"]["used_by"], ["triage"])

    say("an agent that is deleted stops being a dependency, and breaks nothing")
    from carnet import agents

    agents.delete(TENANT, "gone", actor=ACTOR)
    after = {r["connector_id"]: r for r in c.get("/connections", headers=priya).json()}
    check("it is gone from used by", "gone" in after["acme"]["used_by"], False)
    check("and the rest of the row survived", after["acme"]["used_by"],
          ["shorty", "triage", "viagroup"])


# --- testing a connection ------------------------------------------------------------


def testing_a_connection(c, priya, sam, store, her):
    from carnet.access import connections
    from carnet.core.principal import Principal

    say("the probe refuses rather than falling through to somebody else's credential")
    check("ACME_TOKEN is set on this deployment, so a shared credential really exists",
          bool(os.environ.get("ACME_TOKEN")), True)
    refused = c.post("/connectors/acme/connection/test", headers=priya)
    check("400", refused.status_code, 400)
    check("and it says what is missing", "no account connected" in refused.json()["detail"], True)
    check("a connector nobody registered is a 400 naming what is registered",
          c.post("/connectors/nope/connection/test", headers=priya).status_code, 400)
    check("a stranger gets 401", c.post("/connectors/acme/connection/test").status_code, 401)
    check("and GET is not a method this route has",
          c.get("/connectors/acme/connection/test", headers=priya).status_code, 405)

    say("with her own account connected, the server answers under it")
    connections.connect_account(Principal(kind="user", id=her, tenant_id=TENANT),
                                "acme", "MARKER-PRIYA-CREDENTIAL",
                                account_label=PRIYA, actor=ACTOR)
    good = c.post("/connectors/acme/connection/test", headers=priya)
    check("200", good.status_code, 200)
    check("the server named itself", good.json()["server"], "acme-mcp-server v4.1.0")
    check("and said how many tools it offers", good.json()["tools"], len(TOOLS))

    say("it is the caller's own row, so it is not behind the administrator's role")
    his = store.find_user_by_email(TENANT, SAM)["id"]
    connections.connect_account(Principal(kind="user", id=his, tenant_id=TENANT),
                                "acme", "MARKER-SAM-CREDENTIAL",
                                account_label=SAM, actor=ACTOR)
    check("sam, who administers nothing, may test his own connection",
          c.post("/connectors/acme/connection/test", headers=sam).status_code, 200)

    say("a server that is not there is a 502 — their outage, not our fault and not ours")
    from carnet import tools as _tools

    _tools.register_connector(TENANT, "dead", url=DEAD_URL, actor=ACTOR)
    connections.connect_account(Principal(kind="user", id=her, tenant_id=TENANT),
                                "dead", "MARKER", actor=ACTOR)
    down = c.post("/connectors/dead/connection/test", headers=priya)
    check("502", down.status_code, 502)
    check("carrying the transport's own sentence", bool(down.json()["detail"]), True)

    say("a REST connector does not describe itself, and the probe must say so")
    _tools.register_connector(TENANT, "billing", url="https://localtest.me/api",
                              kind="rest", actor=ACTOR)
    connections.connect_account(Principal(kind="user", id=her, tenant_id=TENANT),
                                "billing", "MARKER", actor=ACTOR)
    rest = c.post("/connectors/billing/connection/test", headers=priya)
    check("refused, rather than dialled as though it spoke MCP", rest.status_code, 400)
    check("and the refusal names the reason",
          "does not describe itself" in rest.json().get("detail", ""), True)

    say("a connection whose grant the provider withdrew")
    store.mark_connection_reconsent(TENANT, "user", her, "acme",
                                    reason="The account owner revoked access.")
    stale = c.post("/connectors/acme/connection/test", headers=priya)
    check("is a sentence somebody can act on, never a 500", stale.status_code in (400, 502), True)
    check("and it says the connection needs remaking",
          "revoked" in stale.text or "reconnect" in stale.text.lower(), True)

    say("and once disconnected it is the first refusal again")
    c.delete("/connectors/acme/connection", headers=priya)
    gone = c.post("/connectors/acme/connection/test", headers=priya)
    check("400", gone.status_code, 400)
    check("with the same sentence as before anybody connected",
          "no account connected" in gone.json()["detail"], True)


# --- the two acts that used to leave no trace ------------------------------------------


def who_may_sign_in_is_recorded(c, priya, store):
    """Registering and removing an identity provider, and the record each leaves.

    Who may sign in **at all** was the last change in this product a person could make
    without leaving a trace — noted as open when 110d shipped the screen, closed in the
    pass after 110f. Driven here as well as in the route suite because the record is
    written inside the store's transaction, and only a real transaction can be rolled
    back: a registration that is refused must leave no record of itself.
    """
    issuer = "https://extra.okta.example.com"
    body = {
        "issuer": issuer,
        "jwks_uri": f"{issuer}/v1/keys",
        "audience": "carnet",
        "subject_claim": "sub",
        "email_claim": "email",
        "allowed_domains": ["acme.com"],
    }

    say("registering an identity provider is recorded, with the person who did it")
    registered = c.post("/admin/idps", json=body, headers=priya)
    check("registered", registered.status_code, 200)
    rows = [r for r in store.admin_audit_records(TENANT) if r["action"].startswith("idp.")]
    check("one record", len(rows), 1)
    check("naming the provider", (rows[0]["action"], rows[0]["target_kind"], rows[0]["target_id"]),
          ("idp.save", "idp", issuer))
    check("and the person, not the deployment", rows[0]["actor_kind"], "user")
    check("the detail is the row, less the issuer it is already keyed by",
          rows[0]["detail"]["allowed_domains"], ["acme.com"])
    check("and no secret is in it, because a provider has none",
          "jwks_uri" in rows[0]["detail"] and "secret" not in str(rows[0]["detail"]).lower(), True)

    say("rotating its key set is a second decision, so it is a second record")
    c.post("/admin/idps", json={**body, "jwks_uri": f"{issuer}/v1/keys/rotated"}, headers=priya)
    rows = [r for r in store.admin_audit_records(TENANT) if r["action"] == "idp.save"]
    check("two records", len(rows), 2)
    check("the second says what moved", rows[-1]["detail"]["jwks_uri"], f"{issuer}/v1/keys/rotated")

    say("a registration the store refuses leaves no record of itself")
    before = len(store.admin_audit_records(TENANT))
    refused = c.post("/admin/idps", json={**body, "jwks_uri": "not-a-url"}, headers=priya)
    check("refused", refused.status_code, 400)
    check("and nothing was written", len(store.admin_audit_records(TENANT)), before)

    say("removing it is recorded; removing what is not there is not")
    c.request("DELETE", "/admin/idps", params={"issuer": issuer}, headers=priya)
    removals = [r for r in store.admin_audit_records(TENANT) if r["action"] == "idp.remove"]
    check("one record", len(removals), 1)
    c.request("DELETE", "/admin/idps", params={"issuer": "https://nobody.example.com"}, headers=priya)
    check("and an idempotent removal that found nothing wrote nothing",
          len([r for r in store.admin_audit_records(TENANT) if r["action"] == "idp.remove"]), 1)


def taking_a_connector_out_of_service(c, priya, store, her):
    """Deregistering a connector people are connected to. Migration 021 refuses it as a
    side effect and the pass after 110f made the deliberate version reachable: the
    refusal counts the accounts, and the opt-in removes them in the same transaction.
    Only a real database can show the transaction — and the tenant clause."""
    from carnet.access import connections
    from carnet.core.principal import Principal

    # Priya disconnected hers at the end of the probe scene; sam still holds one. Two
    # again, so the refusal's plural is the one a real deployment reads.
    connections.connect_account(Principal(kind="user", id=her, tenant_id=TENANT),
                                "acme", "MARKER-AGAIN", account_label=PRIYA, actor=ACTOR)

    say("the refusal counts the people it is protecting")
    refused = c.delete("/admin/connectors/acme", headers=priya)
    check("409", refused.status_code, 409)
    check("naming how many", "2 connected accounts" in refused.json()["detail"], True)
    check("and the connector is still there",
          c.get("/admin/connectors/acme", headers=priya).status_code, 200)

    say("another connector's connections are not in the blast radius")
    connections.connect_account(Principal(kind="user", id=her, tenant_id=TENANT),
                                "shared", "MARKER", actor=ACTOR)

    say("asked for deliberately, it takes them with it — and says how many")
    gone = c.delete("/admin/connectors/acme", params={"disconnect_accounts": "true"},
                    headers=priya)
    check("200", gone.status_code, 200)
    check("the count is in the answer, because those people must revoke at the provider",
          gone.json(), {"connector_id": "acme", "removed": True, "disconnected": 2})
    check("the connector is gone", c.get("/admin/connectors/acme", headers=priya).status_code, 400)
    check("its connections are gone",
          store.find_connection(TENANT, "user", her, "acme"), None)
    check("and the OTHER connector's connection is untouched",
          store.find_connection(TENANT, "user", her, "shared") is not None, True)

    record = [
        r for r in store.admin_audit_records(TENANT, action="connector.delete")
        if r["target_id"] == "acme"
    ][-1]
    check("the record counts the people", record["detail"]["disconnected"], 2)

    say("and with nobody connected the flag is an opt-in to a consequence, not an instruction")
    gone = c.delete("/admin/connectors/empty", params={"disconnect_accounts": "true"},
                    headers=priya)
    check("nothing was disconnected", gone.json()["disconnected"], 0)
    record = [
        r for r in store.admin_audit_records(TENANT, action="connector.delete")
        if r["target_id"] == "empty"
    ][-1]
    check("and the record does not imply somebody was",
          "disconnected" in (record["detail"] or {}), False)


if __name__ == "__main__":
    main()
