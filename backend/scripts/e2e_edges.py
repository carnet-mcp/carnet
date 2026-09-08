"""The edges, over real HTTP against real Postgres. Where the app is asked to do the
things it is meant to refuse.

`scripts/e2e_write_path.py` walks the happy path of the write routes. This walks the
corners: reused idempotency keys, concurrent creates of one name, concurrent edits from
one version, revoking access that is inherited, suspending a customer mid-flight, running
an agent that is broken, cancelling twice, cancelling too late, and every place a status
code is a decision rather than a default.

**It builds its own world** — a database, a tenant, and `scripts/dev_idp.py` — so it needs
nobody at a keyboard and touches nothing else.

**It calls no model and launches no connector, so it spends nothing.** That is also its
limit, and it is worth stating: the run *path* is exercised as far as the queue, and what
a run does once a worker claims it needs `ANTHROPIC_API_KEY` and is a different script.

    cd backend && .venv/bin/python scripts/e2e_edges.py
"""

import concurrent.futures as futures
import os
import pathlib
import subprocess
import sys
import time

import httpx
from urllib.parse import urlsplit, urlunsplit

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_edges"


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
TENANT = "edges"
IDP_PORT = 8903
API_PORT = 8124
API = f"http://127.0.0.1:{API_PORT}"

CHECKS = []


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok))
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: {actual!r}"
          + ("" if ok else f"  (expected {expected!r})"))


def say(what):
    print(f"\n=== {what}", flush=True)


AGENT = {
    "name": "edges-bot",
    "runtime": "simple",
    "system": "You summarise things.",
    "model": "claude-haiku-4-5",
    "permissions": {"tools": ["post_message"],
                    "scope": {"chat.channel": {"write": ["#eng"]}}},
    "limits": {"max_calls": 3},
}


def main():
    import psycopg

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import dev_idp

    with psycopg.connect(dsn_for("postgres"),
                         autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")

    os.environ["CARNET_DATABASE_URL"] = DSN
    os.environ.setdefault("CARNET_SECRET_KEY", _key())
    # **Nothing claims.** A queued run has to stay queued for half of what is below, and
    # the variable is `CARNET_WORKERS` — `WORKERS=0` sets something nothing reads,
    # which is how a seeded queued run got executed during 10d's browser check.
    os.environ["CARNET_WORKERS"] = "0"

    _, provider = dev_idp.serve(IDP_PORT)

    from carnet import bootstrap, storage
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    migrate.apply(DSN)
    store = storage.configure(PostgresStorage(DSN))
    store.create_tenant(TENANT, "Edges")
    bootstrap.seed_tenant(TENANT)
    store.save_tenant_idp(TENANT, {
        "issuer": provider.issuer, "jwks_uri": f"{provider.issuer}/v1/keys",
        "audience": dev_idp.AUDIENCE, "subject_claim": "uid", "email_claim": "sub",
        "allowed_domains": ("acme.com",),
    })

    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "carnet.api:app",
         "--port", str(API_PORT)],
        env={**os.environ, "CARNET_TENANT": TENANT},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        _wait(f"{API}/health")
        run(store, provider)
    finally:
        api.terminate()
        api.wait(timeout=10)
        store.close()

    failed = [label for label, ok in CHECKS if not ok]
    say(f"{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    for label in failed:
        print("  FAILED:", label)
    raise SystemExit(1 if failed else 0)


def run(store, provider):
    import dev_idp

    def token(email):
        provider.be(email)
        return dev_idp.Provider.token_for(provider, email)

    priya = {"Authorization": f"Bearer {token('priya@acme.com')}"}
    sam = {"Authorization": f"Bearer {token('sam@acme.com')}"}
    c = httpx.Client(base_url=API, timeout=30)
    c.get("/agents", headers=priya)
    c.get("/agents", headers=sam)
    me = store.find_user_by_email(TENANT, "priya@acme.com")["id"]
    them = store.find_user_by_email(TENANT, "sam@acme.com")["id"]

    # --- creating ------------------------------------------------------------------
    say("creating: the name is the key, and only one caller can have it")
    made = c.post("/agents", json=AGENT, headers=priya)
    check("first create", made.status_code, 201)
    check("a second, by somebody else, is refused",
          c.post("/agents", json={**AGENT, "system": "mine"}, headers=sam).status_code, 409)
    check("and they got no foothold",
          c.get("/agents/edges-bot", headers=sam).status_code, 404)

    say("EIGHT CALLERS RACING FOR ONE NAME — exactly one may win")
    def create(n):
        return c.post("/agents", json={**AGENT, "name": "contested"}, headers=priya).status_code
    with futures.ThreadPoolExecutor(max_workers=8) as pool:
        codes = list(pool.map(create, range(8)))
    check("one 201", codes.count(201), 1)
    check("seven 409", codes.count(409), 7)
    check("and exactly one row exists",
          len([a for a in store.load_agents(TENANT) if a["name"] == "contested"]), 1)

    say("names the column refuses, through the route")
    for name in ("Edges Bot", "edges_bot", "-edges", "edges-", "edges--bot", "a" * 65):
        code = c.post("/agents", json={**AGENT, "name": name}, headers=priya).status_code
        check(f"{name!r}", code, 422)
    check("and 'validate' is reserved",
          c.post("/agents", json={**AGENT, "name": "validate"}, headers=priya).status_code,
          422)

    say("a config the validator refuses in both directions")
    check("a granted tool with no scope row",
          c.post("/agents", json={**AGENT, "name": "no-scope",
                                  "permissions": {"tools": ["post_message"], "scope": {}}},
                 headers=priya).status_code, 422)
    check("a scope row no granted tool touches",
          c.post("/agents", json={**AGENT, "name": "no-tool",
                                  "permissions": {"tools": [], "scope": {
                                      "chat.channel": {"write": ["#eng"]}}}},
                 headers=priya).status_code, 422)
    check("an unknown tool",
          c.post("/agents", json={**AGENT, "name": "ghost",
                                  "permissions": {"tools": ["nope"], "scope": {}}},
                 headers=priya).status_code, 422)
    check("an unknown limit",
          c.post("/agents", json={**AGENT, "name": "odd-limit",
                                  "limits": {"max_biscuits": 3}}, headers=priya).status_code,
          422)
    check("a negative limit",
          c.post("/agents", json={**AGENT, "name": "neg", "limits": {"max_calls": -1}},
                 headers=priya).status_code, 422)
    check("a boolean where a limit goes",
          c.post("/agents", json={**AGENT, "name": "boolish", "limits": {"max_calls": True}},
                 headers=priya).status_code, 422)
    check("nothing was written by any of them",
          [a["name"] for a in store.load_agents(TENANT)],
          ["contested", "edges-bot", "issue-reporter"])

    # --- editing -------------------------------------------------------------------
    say("editing: the precondition, and the shapes of a bad one")
    etag = c.get("/agents/edges-bot", headers=priya).json()["updated_at"]
    check("no If-Match", c.patch("/agents/edges-bot", json={"system": "x"},
                                 headers=priya).status_code, 428)
    for header, why in [("nonsense", "not a timestamp"),
                        ('"2026-08-08"', "truncated"),
                        ('"2026-08-08T04:12:33.482391"', "no time zone"),
                        ("*", "the any-version wildcard")]:
        code = c.patch("/agents/edges-bot", json={"system": "x"},
                       headers={**priya, "If-Match": header}).status_code
        check(f"If-Match {why}", code, 400)
    check("a name that differs",
          c.patch("/agents/edges-bot", json={"name": "other"},
                  headers={**priya, "If-Match": f'"{etag}"'}).status_code, 400)
    check("an unknown key",
          c.patch("/agents/edges-bot", json={"nonsense": 1},
                  headers={**priya, "If-Match": f'"{etag}"'}).status_code, 422)
    check("a patch that breaks the config",
          c.patch("/agents/edges-bot", json={"permissions": {"tools": [], "scope": {}}},
                  headers={**priya, "If-Match": f'"{etag}"'}).status_code, 200)
    check("and it really is empty now",
          store.get_agent(TENANT, "edges-bot")["config"]["permissions"]["tools"], [])

    say("EIGHT EDITS FROM ONE VERSION — exactly one may land")
    base = c.get("/agents/edges-bot", headers=priya).json()["updated_at"]
    def edit(n):
        return c.patch("/agents/edges-bot", json={"system": f"edited by {n}"},
                       headers={**priya, "If-Match": f'"{base}"'}).status_code
    with futures.ThreadPoolExecutor(max_workers=8) as pool:
        codes = list(pool.map(edit, range(8)))
    check("one 200", codes.count(200), 1)
    check("seven 409", codes.count(409), 7)
    check("one update recorded",
          len(store.admin_audit_records(TENANT, action="agent.update")), 2)

    # --- sharing -------------------------------------------------------------------
    say("sharing: the refusals that are not 404s")
    check("a grantee kind that is not one",
          c.put("/agents/edges-bot/grants/robot/r1", json={"role": "user"},
                headers=priya).status_code, 400)
    check("a role that is not one",
          c.put(f"/agents/edges-bot/grants/user/{them}", json={"role": "admin"},
                headers=priya).status_code, 400)
    check("a group that does not exist",
          c.put("/agents/edges-bot/grants/group/nope", json={"role": "user"},
                headers=priya).status_code, 400)
    check("an address on a domain no provider vouches for",
          c.put("/agents/edges-bot/grants/email/x@elsewhere.example",
                json={"role": "user"}, headers=priya).status_code, 400)
    check("owner to an address nobody has claimed",
          c.put("/agents/edges-bot/grants/email/new@acme.com",
                json={"role": "owner"}, headers=priya).status_code, 400)
    check("revoking the owner",
          c.delete(f"/agents/edges-bot/grants/user/{me}", headers=priya).status_code, 404)
    check("and the owner still owns it",
          store.direct_agent_grant_role(TENANT, "edges-bot", "user", me), "owner")

    say("revoking access that is inherited is refused, by name")
    store.create_group(TENANT, "g1", "oncall", actor="system:cli")
    store.add_group_member(TENANT, "g1", "user", them, actor="system:cli")
    c.put("/agents/edges-bot/grants/group/g1", json={"role": "user"}, headers=priya)
    refused = c.delete(f"/agents/edges-bot/grants/user/{them}", headers=priya)
    check("400, not a silent no-op", refused.status_code, 400)
    check("and it names the group", "g1" in refused.json()["detail"], True)
    check("so their access is untouched",
          c.get("/agents/edges-bot", headers=sam).status_code, 200)

    say("sharing at owner is a TRANSFER, and needs owner rather than editor")
    c.put(f"/agents/edges-bot/grants/user/{them}", json={"role": "editor"}, headers=priya)
    check("an editor cannot hand it on",
          c.put(f"/agents/edges-bot/grants/user/{them}", json={"role": "owner"},
                headers=sam).status_code, 404)
    check("the owner can",
          c.put(f"/agents/edges-bot/grants/user/{them}", json={"role": "owner"},
                headers=priya).status_code, 200)
    check("and the previous owner is demoted, not evicted",
          store.direct_agent_grant_role(TENANT, "edges-bot", "user", me), "editor")
    # Put it back, so the rest of this script owns it.
    c.put(f"/agents/edges-bot/grants/user/{me}", json={"role": "owner"}, headers=sam)

    # --- the tenant ------------------------------------------------------------------
    say("suspending the customer closes the doors work arrives through")
    store.set_tenant_status(TENANT, "suspended")
    check("a token stops working", c.get("/agents", headers=priya).status_code, 403)
    store.set_tenant_status(TENANT, "active")
    check("and resuming lets them back in",
          c.get("/agents", headers=priya).status_code, 200)

    say("the log: every one of those refusals wrote nothing")
    actions = [r["action"] for r in store.admin_audit_records(TENANT)]
    # Two successful creates — `edges-bot` and `contested`. `wrecked` was written with
    # `save_agent`, which is `agent.save`, and every refused create wrote nothing.
    check("only the creates that happened are recorded",
          actions.count("agent.create"), 2)
    check("and every record names a principal",
          sorted({r["actor_kind"] for r in store.admin_audit_records(TENANT)}),
          ["system", "user"])

    # --- the denial log (015) --------------------------------------------------------
    say("the denial log: the refusals above were also written down, attributed")
    check("a probe of a name that never existed is the same 404",
          c.get("/agents/payroll-bot", headers=sam).status_code, 404)
    probes = [r["resource_id"]
              for r in store.denial_records(TENANT, principal_kind="user",
                                            principal_id=them)]
    check("sam's probe is attributed to sam", "payroll-bot" in probes, True)
    check("and so was his early foothold attempt", "edges-bot" in probes, True)

    say("the log records its own door, and opens for an administrator over HTTP")
    check("a non-admin reader is refused",
          c.get("/admin/denials", headers=sam).status_code, 403)
    store.grant_platform_role(TENANT, "user", me, "admin", actor="system:cli")
    over_http = c.get(f"/admin/denials?principal_id={them}", headers=priya).json()
    check("an admin finds the probe, attributed",
          "payroll-bot" in [r["resource_id"] for r in over_http], True)
    check("and sam's refused read of this very log is its newest row",
          (store.denial_records(TENANT, limit=1)[0]["resource_kind"],
           store.denial_records(TENANT, limit=1)[0]["principal_id"]),
          ("admin", them))

    # --- what the refusals were about (035b) -----------------------------------------
    #
    # `denial_records` has taken `resource_kind` since 015 and the route never forwarded
    # it, so until now the only way to ask "which of these came from the door" was to
    # fetch a capped page and filter it in the client — which is a lie about completeness
    # in a log view. Driven here rather than in `e2e_mcp_door.py` because by this point
    # the tenant holds refusals of two different kinds without anything being staged for
    # it: sam's probes wrote `agent`, and sam's refused read of this log wrote `admin`.
    say("the log can be asked what the refusals were about, by the server")
    everything = c.get("/admin/denials", headers=priya).json()
    check("both kinds are in the unfiltered log",
          sorted({r["resource_kind"] for r in everything}), ["admin", "agent"])

    agents_only = c.get("/admin/denials?resource_kind=agent", headers=priya).json()
    check("filtering to agents leaves the agent probes",
          "payroll-bot" in [r["resource_id"] for r in agents_only], True)
    check("and drops the administrative ones",
          sorted({r["resource_kind"] for r in agents_only}), ["agent"])

    admin_only = c.get("/admin/denials?resource_kind=admin", headers=priya).json()
    check("filtering to the administrative surface is the other half",
          sorted({r["resource_kind"] for r in admin_only}), ["admin"])
    # Summed over the kinds actually present rather than over the two this scene happens
    # to produce: a future step that drives a door call through this script should not
    # have to notice a hardcoded pair here to keep the check honest.
    by_kind = {k: c.get(f"/admin/denials?resource_kind={k}", headers=priya).json()
               for k in sorted({r["resource_kind"] for r in everything})}
    check("the filtered halves add up to the whole, whatever kinds are in it",
          sum(len(rows) for rows in by_kind.values()), len(everything))

    # The kind the door writes. Nothing in this script goes through `/mcp`, so the honest
    # answer is an empty list — which is the point: a *kind the column admits* answers
    # `[]`, and a kind it does not admit answers 422 rather than pretending to be one.
    check("a kind the column admits but this tenant has none of is an empty list",
          c.get("/admin/denials?resource_kind=tool", headers=priya).json(), [])
    check("a kind it cannot hold is refused rather than answered empty",
          c.get("/admin/denials?resource_kind=tools", headers=priya).status_code, 422)
    check("and a stranger still learns nothing about the parameter",
          c.get("/admin/denials?resource_kind=tools").status_code, 401)

    check("the filters compose, as they do in the store",
          [r["resource_id"] for r in c.get(
              f"/admin/denials?resource_kind=agent&principal_id={them}",
              headers=priya).json()],
          [r["resource_id"] for r in store.denial_records(
              TENANT, resource_kind="agent", principal_id=them)])


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
