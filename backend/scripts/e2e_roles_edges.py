"""Platform roles at their edges, over real HTTP against real Postgres.

`scripts/e2e_platform_roles.py` walks the arc: refused, granted, allowed, revoked,
refused. This walks the corners, and the corners are where a permission model is either
right or quietly wrong — **eight callers granting one role at once, an admin of one
tenant reaching for another, a suspended customer, a disabled administrator, a group
whose deletion takes grants with it, and every place a status code is a decision rather
than a default.**

Three of these can only fail against a real database, which is why this is a script and
not a test:

  - **concurrency.** The in-memory store is too fast to expose a race, and the upsert
    behind `--grant-role` is a real `ON CONFLICT DO UPDATE` competing with itself.
  - **the CHECK constraints.** `check_platform_role` refuses a group in Python; migration
    026 refuses it in the column. Only one of those is still standing if somebody edits a
    frozenset, and only a database can say so.
  - **the cascade.** Deleting a tenant takes its roles; deleting a group takes its grants
    by a trigger. Both are DDL, and the fake reimplements them in Python.

**It builds its own world** — a database, two tenants, two identity providers via
`scripts/dev_idp.py` — so it needs nobody at a keyboard and touches nothing else.

    cd backend && .venv/bin/python scripts/e2e_roles_edges.py

**Costs nothing.** No run is submitted, so no model is called and no connector launched.
"""

import concurrent.futures as futures
import os
import pathlib
import subprocess
import sys
import time
from urllib.parse import urlsplit, urlunsplit

import httpx

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_roles_edges"


def dsn_for(database: str) -> str:
    """Where Postgres is. The socket this project has used, unless told otherwise.

    `CARNET_E2E_PG` is a base DSN with **no database name**. Not a concatenation:
    a socket DSN carries its host in the query string and a TCP one does not.
    """
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


DSN = dsn_for(DB)
TENANT = "rolesedge"
OTHER = "globexedge"
IDP_PORT = 8908
OTHER_IDP_PORT = 8909
API_PORT = 8130
API = f"http://127.0.0.1:{API_PORT}"

CHECKS = []


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok))
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: {actual!r}"
          + ("" if ok else f"  (expected {expected!r})"))


def say(what):
    print(f"\n=== {what}", flush=True)


def cli(*args, tenant=TENANT):
    """The real command, in its own process, against the same database."""
    return subprocess.run(
        [sys.executable, "-m", "carnet.cli", *args],
        env={**os.environ, "CARNET_TENANT": tenant},
        capture_output=True,
        text=True,
    )


AGENT = {
    "name": "payroll-bot",
    "runtime": "simple",
    "system": "You read payroll.",
    "model": "claude-haiku-4-5",
    "permissions": {"tools": ["post_message"],
                    "scope": {"chat.channel": {"write": ["#eng"]}}},
    "limits": {"max_calls": 3},
}


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

    _, provider = dev_idp.serve(IDP_PORT)
    # A **second** provider for a second customer. Two tenants sharing one issuer would
    # be a different test — of the discriminator — and would make "an admin of A reaching
    # into B" unexpressible, since one token would resolve to one tenant either way.
    _, elsewhere = dev_idp.serve(OTHER_IDP_PORT)

    from carnet import bootstrap, storage
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    migrate.apply(DSN)
    store = storage.configure(PostgresStorage(DSN))
    for tenant, name, prov in ((TENANT, "Roles Edge", provider),
                               (OTHER, "Globex Edge", elsewhere)):
        store.create_tenant(tenant, name)
        store.save_tenant_idp(tenant, {
            "issuer": prov.issuer, "jwks_uri": f"{prov.issuer}/v1/keys",
            "audience": dev_idp.AUDIENCE, "subject_claim": "uid", "email_claim": "sub",
            "allowed_domains": ("acme.com",),
        })
    bootstrap.seed_tenant(TENANT)

    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "carnet.api:app",
         "--port", str(API_PORT)],
        env={**os.environ, "CARNET_TENANT": TENANT},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        _wait(f"{API}/health")
        run(store, provider, elsewhere)
    finally:
        api.terminate()
        api.wait(timeout=10)
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

    priya = {"Authorization": f"Bearer {token(provider, 'priya@acme.com')}"}
    sam = {"Authorization": f"Bearer {token(provider, 'sam@acme.com')}"}
    outsider = {"Authorization": f"Bearer {token(elsewhere, 'mallory@acme.com')}"}
    c = httpx.Client(base_url=API, timeout=30)

    for headers in (priya, sam, outsider):
        c.get("/agents", headers=headers)

    priya_id = store.find_user_by_email(TENANT, "priya@acme.com")["id"]
    sam_id = store.find_user_by_email(TENANT, "sam@acme.com")["id"]
    mallory_id = store.find_user_by_email(OTHER, "mallory@acme.com")["id"]

    # --- authentication comes first, always ------------------------------------------
    say("identity before role: an unauthenticated caller must not learn a route exists")
    ADMIN_ROUTES = [
        ("GET", "/admin-audit"),
        ("POST", "/groups"),
        ("GET", "/groups/g-x"),
        ("DELETE", "/groups/g-x"),
        ("PUT", "/groups/g-x/members/user/u-1"),
        ("DELETE", "/groups/g-x/members/user/u-1"),
    ]
    for method, path in ADMIN_ROUTES:
        check(f"no token: {method} {path}",
              c.request(method, path, json={"name": "x"}).status_code, 401)
    check("a garbage token is 401, not 403",
          c.get("/admin-audit", headers={"Authorization": "Bearer nonsense"}).status_code, 401)
    check("a token with no Bearer prefix is 401",
          c.get("/admin-audit", headers={"Authorization": "nonsense"}).status_code, 401)

    # **Every admin route, from an authenticated non-administrator.** The 401 sweep above
    # proves ordering and nothing about the role; this is the half that catches a route
    # whose dependency somebody swapped back to `principal_from_request`, which is a
    # change that *works* — for the wrong person. Found by mutating exactly that and
    # watching this script still pass, which is what a mutation check is for.
    say("authenticated, and not an administrator: every admin route refuses him")
    for method, path in ADMIN_ROUTES:
        check(f"sam: {method} {path}",
              c.request(method, path, json={"name": "his"}, headers=sam).status_code, 403)
    check("and nothing he tried was created",
          [g for g in store.list_groups(TENANT) if g["name"] == "his"], [])
    check("while the two open routes answer him",
          (c.get("/groups", headers=sam).status_code, c.get("/me", headers=sam).status_code),
          (200, 200))

    say("and the routes ARE published, which is the whole argument for 403 over 404")
    document = c.get("/openapi.json").json()["paths"]
    check("/admin-audit is in the OpenAPI document", "/admin-audit" in document, True)
    check("/groups too", "/groups" in document, True)
    check("so is /me", "/me" in document, True)

    # --- the refusal itself ----------------------------------------------------------
    say("the 403 body is a sentence and nothing else")
    refused = c.get("/admin-audit", headers=priya)
    check("403", refused.status_code, 403)
    check("one field, `detail`", _keys(refused), ["detail"])
    check("it says what you are not", "administrator" in _detail(refused), True)
    check("it says what to do", "grant it" in _detail(refused), True)
    check("and it leaks no id", priya_id in _detail(refused), False)

    # --- concurrency, which is why this is a script -----------------------------------
    say("EIGHT CALLERS GRANT THE SAME ROLE AT ONCE — one row, eight decisions recorded")
    results = _in_parallel(8, lambda i: cli("--grant-role", "admin", "priya@acme.com"))
    check("every command succeeded", {r.returncode for r in results}, {0})
    check("ONE ROW", len([r for r in store.list_platform_roles(TENANT)
                          if r["principal_id"] == priya_id]), 1)
    check("eight records, because a second approval is a second decision",
          len([r for r in store.admin_audit_records(TENANT, action="role.grant")
               if r["target_id"] == priya_id]), 8)
    check("and she is an administrator", c.get("/me", headers=priya).json()["admin"], True)

    say("EIGHT REVOKE AT ONCE — exactly one removes a row, and exactly one record lands")
    before = len(store.admin_audit_records(TENANT, action="role.revoke"))
    said = _in_parallel(8, lambda i: cli("--revoke-role", "admin", "priya@acme.com"))
    check("every command succeeded", {r.returncode for r in said}, {0})
    check("exactly one says it removed something",
          sum(1 for r in said if "no longer an administrator" in r.stdout), 1)
    check("the other seven say there was nothing to do",
          sum(1 for r in said if "Nothing to do" in r.stdout), 7)
    check("ONE record, not eight",
          len(store.admin_audit_records(TENANT, action="role.revoke")) - before, 1)
    check("and the row is gone", store.has_platform_role(TENANT, "user", priya_id, "admin"), False)

    say("re-granting refreshes granted_at, so the most recent yes is the one that stands")
    cli("--grant-role", "admin", "priya@acme.com")
    first = _row(store, priya_id)["granted_at"]
    time.sleep(0.05)
    cli("--grant-role", "admin", "priya@acme.com")
    check("granted_at moved forward", _row(store, priya_id)["granted_at"] > first, True)

    # --- one tenant cannot reach another ---------------------------------------------
    say("an administrator of ANOTHER customer is nobody here")
    cli("--grant-role", "admin", "mallory@acme.com", tenant=OTHER)
    check("mallory is an admin of globexedge",
          store.has_platform_role(OTHER, "user", mallory_id, "admin"), True)
    check("and holds nothing here",
          store.has_platform_role(TENANT, "user", mallory_id, "admin"), False)
    # **Her requests are not refused, and expecting a 403 was wrong about the model.**
    # The tenant comes off the principal and never off the URL, so this one server answers
    # for every customer: her token resolves to `globexedge`, where she IS an
    # administrator. What must be true is not that she is refused — it is that what she
    # gets is *hers*, and that nothing of this tenant's is in it.
    hers = c.get("/admin-audit", headers=outsider)
    check("her own log is readable, because it is HERS", hers.status_code, 200)
    check("and holds only her own tenant's records",
          {r["target_id"] for r in hers.json()} & {priya_id, sam_id}, set())
    made_there = c.post("/groups", json={"name": "theirs"}, headers=outsider)
    check("a group she creates is created in HER tenant", made_there.status_code, 201)
    check("and is invisible here",
          "theirs" in [g["name"] for g in c.get("/groups", headers=priya).json()], False)
    check("while it is visible there",
          "theirs" in [g["name"] for g in c.get("/groups", headers=outsider).json()], True)

    say("and the log an admin CAN read is their own tenant's only")
    theirs = [r["target_id"] for r in c.get("/admin-audit", headers=priya).json()]
    check("mallory never appears in rolesedge's log", mallory_id in theirs, False)
    check("priya does", priya_id in theirs, True)
    check("and the role she holds there is not a row here",
          store.has_platform_role(TENANT, "user", mallory_id, "admin"), False)

    # --- group administration, at its corners ----------------------------------------
    say("creating a group: the refusals")
    check("an empty name is a 400",
          c.post("/groups", json={"name": ""}, headers=priya).status_code, 400)
    check("whitespace is the same thing",
          c.post("/groups", json={"name": "   "}, headers=priya).status_code, 400)
    check("no name at all is FastAPI's 422",
          c.post("/groups", json={}, headers=priya).status_code, 422)

    made = c.post("/groups", json={"name": "oncall", "description": "the pager"},
                  headers=priya)
    check("a good one is 201", made.status_code, 201)
    group = made.json()["group_id"]
    check("the name is taken now",
          c.post("/groups", json={"name": "oncall"}, headers=priya).status_code, 400)

    # **Linked to a directory group of its own, and deliberately not `oncall`** — since
    # 033e a linked group's people come from the claim, so the membership edges below
    # would all be refused if this section handed its group to a directory. The
    # uniqueness being checked is the one migration 017 wrote and nothing read until
    # 033e; the seam that refuses hand edits is `e2e_directory_groups.py`'s business.
    linked = c.post("/groups", json={"name": "from-entra", "external_id": "dir-1"},
                    headers=priya)
    check("a group may be linked to a directory group", linked.status_code, 201)
    check("and that directory id is taken now",
          c.post("/groups", json={"name": "other", "external_id": "dir-1"},
                 headers=priya).status_code, 400)
    # **And still the administrator's**, because this customer's provider names no
    # groups claim: the seam refuses hand edits only while the directory is actually
    # speaking, or a group linked before its provider was configured would be editable
    # by nobody — filled by nothing, and refused to everybody. The refusal itself is
    # `e2e_directory_groups.py`'s scene, where a claim is configured.
    check("a person may still be added to it, because nothing fills it",
          c.put(f"/groups/{linked.json()['group_id']}/members/user/{sam_id}",
                headers=priya).status_code, 200)

    say("membership: idempotent, and the body says whether anything changed")
    check("adding sam", c.put(f"/groups/{group}/members/user/{sam_id}",
                              headers=priya).json()["changed"], True)
    check("again", c.put(f"/groups/{group}/members/user/{sam_id}",
                         headers=priya).json()["changed"], False)
    check("a system principal may be a member",
          c.put(f"/groups/{group}/members/system/nightly", headers=priya).json()["changed"], True)
    check("a group may NOT",
          c.put(f"/groups/{group}/members/group/g-other", headers=priya).status_code, 400)
    check("removing somebody who is not in it is 200 and changed=false",
          c.delete(f"/groups/{group}/members/user/u-nobody", headers=priya).json()["changed"], False)

    say("member ids that carry characters a URL cares about — one path segment each")
    for label, ident in (("a colon", "system:nightly-2"), ("a space", "a b"),
                         ("an address", "sam.jones@acme.com"), ("a dot", "a.b")):
        landed = c.put(f"/groups/{group}/members/user/{_quote(ident)}", headers=priya)
        check(f"{label} survives encoding", landed.status_code, 200)
    stored = {m["id"] for m in c.get(f"/groups/{group}", headers=priya).json()["members"]}
    check("and each is stored as typed rather than as its encoding",
          {"system:nightly-2", "a b", "sam.jones@acme.com", "a.b"} <= stored, True)

    # **A `/` is a 404 even percent-encoded, and it is NOT this step's.** uvicorn decodes
    # `%2F` before Starlette routes, so `a%2Fb` becomes two segments and matches nothing.
    # Checked against 10d's grant routes and against an agent name — a path segment since
    # 10a — and all three behave identically. It fails **closed**, which is the property
    # that matters: it 404s rather than addressing a different resource. The cost is that
    # a `system` principal whose operator-chosen id contains a slash is unaddressable over
    # HTTP; our own ids (`u_…`, `g_…`) never contain one.
    say("and a slash is a 404 on every route in this API that has a path segment")
    check("a group member",
          c.put(f"/groups/{group}/members/user/{_quote('a/b')}", headers=priya).status_code, 404)
    check("10d's grant route, identically",
          c.put(f"/agents/issue-reporter/grants/user/{_quote('a/b')}",
                json={"role": "user"}, headers=priya).status_code, 404)
    check("and an agent name, which has been one since 10a",
          c.get(f"/agents/{_quote('a/b')}", headers=priya).status_code, 404)

    say("the menu is readable by a non-admin; the directory is not")
    menu = c.get("/groups", headers=sam)
    check("GET /groups is 200", menu.status_code, 200)
    check("with names", sorted(g["name"] for g in menu.json()), ["from-entra", "oncall"])
    check("and NO membership", "members" in menu.json()[0], False)
    check("and no member count either — a count is the first step of a directory",
          "member_count" in menu.json()[0], False)
    # Nor which groups a directory fills: `external_id` is on the admin-only detail
    # shape, and the menu stayed exactly as narrow as 12b argued it should be.
    check("and not the directory link", "external_id" in menu.json()[0], False)
    check("GET /groups/{id} is 403 for him", c.get(f"/groups/{group}", headers=sam).status_code, 403)

    say("deleting a group takes every access it carried, in the database")
    posted = c.post("/agents", json=AGENT, headers=priya)
    check("priya creates an agent", posted.status_code, 201)
    shared = c.put(f"/agents/payroll-bot/grants/group/{group}",
                   json={"role": "editor"}, headers=priya)
    check("and shares it with the group", shared.status_code, 200)
    check("sam reaches it THROUGH the group",
          c.get("/agents/payroll-bot", headers=sam).status_code, 200)
    check("with no grant row of his own",
          store.direct_agent_grant_role(TENANT, "payroll-bot", "user", sam_id), None)

    check("delete the group", c.delete(f"/groups/{group}", headers=priya).status_code, 204)
    check("HIS ACCESS IS GONE", c.get("/agents/payroll-bot", headers=sam).status_code, 404)
    check("the grant row went with it",
          [g for g in store.list_agent_grants(TENANT, "payroll-bot")
           if g["grantee_kind"] == "group"], [])
    check("deleting it again is still 204",
          c.delete(f"/groups/{group}", headers=priya).status_code, 204)
    check("and reading it is a 400 naming the id",
          group in c.get(f"/groups/{group}", headers=priya).json()["detail"], True)

    # --- an admin is not a superuser, at the edges ------------------------------------
    say("AN ADMIN IS NOT A SUPERUSER — sam's agent, priya's role")
    c.put(f"/agents/payroll-bot/grants/user/{sam_id}", json={"role": "owner"}, headers=priya)
    c.delete(f"/agents/payroll-bot/grants/user/{priya_id}", headers=sam)
    check("priya has no grant left", store.agent_grant_role(TENANT, "payroll-bot", "user", priya_id), None)
    check("GET /agents/payroll-bot is 404", c.get("/agents/payroll-bot", headers=priya).status_code, 404)
    check("PATCH is 404", c.patch("/agents/payroll-bot", json={"system": "mine"},
                                  headers={**priya, "If-Match": '"x"'}).status_code, 404)
    check("DELETE is 404", c.delete("/agents/payroll-bot", headers=priya).status_code, 404)
    check("the access sheet is 404", c.get("/agents/payroll-bot/access", headers=priya).status_code, 404)
    check("she cannot share it with herself",
          c.put(f"/agents/payroll-bot/grants/user/{priya_id}", json={"role": "owner"},
                headers=priya).status_code, 404)
    check("and she is STILL an administrator", c.get("/me", headers=priya).json()["admin"], True)

    # --- the log's own edges ----------------------------------------------------------
    say("the administrative log: ordering, the cap, and what a read does not do")
    everything = c.get("/admin-audit?limit=1000", headers=priya).json()
    check("oldest first", everything[0]["action"], "connector.save")
    tail = c.get("/admin-audit?limit=3", headers=priya).json()
    check("a limit returns the most recent N", len(tail), 3)
    check("still oldest-first within the result",
          [r["action"] for r in tail], [r["action"] for r in everything[-3:]])
    check("limit=0 is a 422, not an empty list",
          c.get("/admin-audit?limit=0", headers=priya).status_code, 422)
    check("a limit past the cap is a 422 rather than silent truncation",
          c.get("/admin-audit?limit=1001", headers=priya).status_code, 422)
    check("the cap itself is allowed", c.get("/admin-audit?limit=1000", headers=priya).status_code, 200)
    check("a non-numeric limit is a 422",
          c.get("/admin-audit?limit=all", headers=priya).status_code, 422)

    before_reads = len(store.admin_audit_records(TENANT))
    for _ in range(5):
        c.get("/admin-audit", headers=priya)
    check("READING IS NOT RECORDED", len(store.admin_audit_records(TENANT)), before_reads)

    say("a role granted to a system principal is logged as one, not as a person")
    cli("--grant-role", "admin", "system:nightly")
    nightly = [r for r in store.admin_audit_records(TENANT, action="role.grant")
               if r["target_id"] == "nightly"]
    check("one record", len(nightly), 1)
    check("target_kind is `system`", nightly[0]["target_kind"], "system")
    check("--list-roles shows it",
          "system:nightly" in cli("--list-roles").stdout, True)

    # --- who a role does and does not follow ------------------------------------------
    say("a disabled administrator: the row survives, the login does not")
    cli("--grant-role", "admin", "sam@acme.com")
    check("sam is an administrator", c.get("/me", headers=sam).json()["admin"], True)
    store.set_user_status(TENANT, sam_id, "disabled", actor="system:cli")
    check("his token stops working entirely", c.get("/me", headers=sam).status_code, 403)
    check("and the row is still there — two acts, two records",
          store.has_platform_role(TENANT, "user", sam_id, "admin"), True)
    check("revoking it separately still works", cli("--revoke-role", "admin", "sam@acme.com").returncode, 0)
    check("and now it is gone", store.has_platform_role(TENANT, "user", sam_id, "admin"), False)
    store.set_user_status(TENANT, sam_id, "active", actor="system:cli")

    say("a suspended customer: administration goes with everything else")
    store.set_tenant_status(TENANT, "suspended")
    check("GET /admin-audit", c.get("/admin-audit", headers=priya).status_code, 403)
    check("GET /me", c.get("/me", headers=priya).status_code, 403)
    check("POST /groups", c.post("/groups", json={"name": "x"}, headers=priya).status_code, 403)
    check("but the CLI still administers it, which is who suspended it",
          cli("--list-roles").returncode, 0)
    store.set_tenant_status(TENANT, "active")
    check("and it comes back", c.get("/admin-audit", headers=priya).status_code, 200)

    # --- /me --------------------------------------------------------------------------
    say("GET /me, and the string it hands a person to compare with the log")
    me = c.get("/me", headers=priya).json()
    check("the principal is spelled as the log spells an actor",
          me["principal"], f"user:{priya_id}")
    actors = {f"{r['actor_kind']}:{r['actor_id']}"
              for r in store.admin_audit_records(TENANT) if r["actor_kind"] == "user"}
    check("and that string is one of them", me["principal"] in actors, True)
    check("email from our row", me["email"], "priya@acme.com")
    check("no role required — sam is not an admin and still gets an answer",
          c.get("/me", headers=sam).json()["admin"], False)
    check("and it tells him who he is", c.get("/me", headers=sam).json()["email"], "sam@acme.com")

    # --- the refusals the CLI owns -----------------------------------------------------
    say("the CLI's own refusals")
    check("an address nobody has used",
          "not an invitation" in cli("--grant-role", "admin", "ghost@acme.com").stderr, True)
    check("a group", "group cannot hold" in cli("--grant-role", "admin", "group:g-1").stderr, True)
    check("a role that is not one",
          "PLATFORM_ROLES" in cli("--grant-role", "auditor", "priya@acme.com").stderr, True)
    check("and none of those wrote a row",
          sorted({r["principal_id"] for r in store.list_platform_roles(TENANT)}),
          sorted({priya_id, "nightly"}))

    say("last one out: revoking the final administrator is allowed and says so")
    cli("--revoke-role", "admin", "system:nightly")
    last = cli("--revoke-role", "admin", "priya@acme.com")
    check("allowed", last.returncode, 0)
    check("and loud", "no administrators" in last.stderr, True)
    check("the table is empty", store.list_platform_roles(TENANT), [])
    check("nobody can administer it in the product",
          c.get("/admin-audit", headers=priya).status_code, 403)
    check("and the shell still can — which is why the rule is safe",
          cli("--list-roles").returncode, 0)
    check("the way back works", cli("--grant-role", "admin", "priya@acme.com").returncode, 0)
    check("and it does", c.get("/admin-audit", headers=priya).status_code, 200)

    say("no secret reached the log")
    import json as _json
    everything = _json.dumps(store.admin_audit_records(TENANT))
    check("not the encryption key", os.environ["CARNET_SECRET_KEY"] in everything, False)
    check("not an agent's prompt", "You read payroll" in everything, False)


def _keys(response):
    """The body's field names, or a marker. **Never a raise.**

    `sorted(response.json())` was fine until a mutation check made this route answer 200
    with a *list*, and the script died on `'<' not supported between dicts` three checks
    in — reporting one failure where it should have reported the twenty that followed.
    `check()`'s whole doctrine is that a broken thing tells you everything that is broken.
    """
    body = response.json()
    return sorted(body) if isinstance(body, dict) else f"<not an object: {type(body).__name__}>"


def _detail(response):
    body = response.json()
    return body.get("detail", "") if isinstance(body, dict) else ""


def _row(store, principal_id):
    return [r for r in store.list_platform_roles(TENANT)
            if r["principal_id"] == principal_id][0]


def _in_parallel(n, work):
    """`n` real processes at once. A thread pool of subprocesses, because the thing under
    test is two callers competing for one row through two connections."""
    with futures.ThreadPoolExecutor(max_workers=n) as pool:
        return [f.result() for f in [pool.submit(work, i) for i in range(n)]]


def _quote(value):
    from urllib.parse import quote

    return quote(value, safe="")


def _wait(url, seconds=45):
    for _ in range(seconds * 2):
        try:
            httpx.get(url, timeout=1)
            return
        except Exception:
            time.sleep(0.5)
    raise SystemExit(f"{url} never answered")


def _key():
    import base64

    return base64.b64encode(os.urandom(32)).decode()


if __name__ == "__main__":
    main()
