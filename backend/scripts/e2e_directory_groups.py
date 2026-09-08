"""Group membership from the customer's directory, over real HTTP against real Postgres.

Step 033e, end to end: a provider registered with a `groups_claim`, a group linked to a
directory group, and **real signed tokens** whose claims change between requests — which
is the one thing a unit test cannot stage convincingly, because the whole feature is a
side effect of a token arriving.

What only this can prove:

  - the reconciliation happens inside **authentication**, on the same request that reads
    an agent list, rather than in some job nobody has started;
  - access follows the claim through the real permission check, in both directions;
  - the marker means the work happens **once per token** and not once per request, which
    is a count of queries against a database rather than of calls to a fake;
  - linking an existing group from the CLI takes over a membership that already exists,
    and the seams refuse the hand edits that would fight it;
  - a personal token (033d) sees its owner's directory groups, which is the two steps
    composing where they meet.

    cd backend && .venv/bin/python scripts/e2e_directory_groups.py

Needs Postgres. **Costs nothing**: no run is submitted, so no model is called.
"""

import os
import pathlib
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit, urlunsplit

import httpx

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_directory_groups"


def dsn_for(database: str) -> str:
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


DSN = dsn_for(DB)
TENANT = "dirgroups"
IDP_PORT = 8912
API_PORT = 8134
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
    "name": "rota-bot",
    "runtime": "simple",
    "system": "You read the rota.",
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

    from carnet import storage
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    migrate.apply(DSN)
    store = storage.configure(PostgresStorage(DSN))
    store.create_tenant(TENANT, "Directory Groups")

    # Registered through the **real command**, because `--groups-claim` and the claim
    # mapping it prints are half of what this step ships.
    said = cli(
        "--add-idp", TENANT,
        "--issuer", provider.issuer,
        "--jwks-uri", f"{provider.issuer}/v1/keys",
        "--audience", dev_idp.AUDIENCE,
        "--subject-claim", "uid",
        "--email-claim", "sub",
        "--groups-claim", "groups",
        "--domain", "acme.com",
    )
    check("--add-idp accepted a groups claim", said.returncode, 0)
    check("...and printed the mapping it wrote",
          "groups=groups" in said.stdout, True)

    # **The server's log is evidence here**, unusually: the one thing that says a
    # reconciliation ran at all — rather than that its outcome was the same — is the
    # line it writes, and the API runs in another process where a counter cannot reach.
    log = pathlib.Path(tempfile.mkdtemp(prefix=f"{DB}-")) / "api.log"
    with log.open("w") as sink:
        api = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port", str(API_PORT)],
            env={**os.environ, "CARNET_TENANT": TENANT},
            stdout=sink, stderr=subprocess.STDOUT,
        )
        try:
            _wait(f"{API}/health")
            run(store, provider, log)
        finally:
            api.terminate()
            api.wait(timeout=10)
            store.close()

    failed = [label for label, ok in CHECKS if not ok]
    say(f"{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    for label in failed:
        print("  FAILED:", label)
    raise SystemExit(1 if failed else 0)


def run(store, provider, log):
    import dev_idp

    c = httpx.Client(base_url=API, timeout=30)

    def logged(fragment):
        """How many times the server has said this. The reconciliation's own voice."""
        return log.read_text(errors="replace").count(fragment)

    def be(email, groups):
        """What this person's *next* token will claim. The directory, changing."""
        httpx.get(f"{provider.issuer}/_be/{email}?groups={','.join(groups)}", timeout=5)

    def token(email):
        return {"Authorization": f"Bearer {dev_idp.Provider.token_for(provider, email)}"}

    def members(group_id):
        return sorted(
            f"{m['principal_kind']}:{m['principal_id']}"
            for m in store.list_group_members(TENANT, group_id)
        )

    # --- the claim is the membership --------------------------------------------------

    say("a group linked at creation fills from the claim, on the first request")
    made = cli("--add-group", "eng", "The engineers")
    check("--add-group", made.returncode, 0)
    eng = store.find_group_by_name(TENANT, "eng")["group_id"]
    linked = cli("--group-link", "eng", "dir-eng")
    check("--group-link", linked.returncode, 0)
    check("...and it said nothing is at risk yet",
          "person(s) are in it now" in linked.stderr, False)

    be("priya@acme.com", ["dir-eng"])
    check("priya signs in", c.get("/me", headers=token("priya@acme.com")).status_code, 200)
    priya = store.find_user_by_email(TENANT, "priya@acme.com")["id"]
    check("...and the directory put her in eng", members(eng), [f"user:{priya}"])

    say("the writes are the ordinary ones, and the directory signs them")
    records = [
        r for r in store.admin_audit_records(TENANT) if r["action"].startswith("group.")
    ]
    check("group.create, group.link, group.member.add",
          [r["action"] for r in records],
          ["group.create", "group.link", "group.member.add"])
    check("the membership was written by the directory",
          (records[-1]["actor_kind"], records[-1]["actor_id"]), ("system", "directory"))

    say("access follows the claim through the real permission check")
    store.save_agent(TENANT, AGENT, actor="system:cli")
    store.grant_agent(TENANT, AGENT["name"], "group", eng, role="user", actor="system:cli")
    check("she can see the agent her group holds",
          _names(c.get("/agents", headers=token("priya@acme.com"))), [AGENT["name"]])

    say("the same token twice does the work once, and a new claim set does it again")
    # An unmatched value is what makes the work *audible*: it is logged once per claim
    # set, and would be logged once per request if the marker were not consulted.
    be("priya@acme.com", ["dir-eng", "dir-nobody-mapped"])
    same = token("priya@acme.com")
    c.get("/agents", headers=same)
    c.get("/agents", headers=same)
    c.get("/agents", headers=same)
    time.sleep(0.3)
    check("three requests, one reconciliation", logged("match no group here"), 1)

    be("priya@acme.com", ["dir-eng", "dir-still-nobody"])
    c.get("/agents", headers=token("priya@acme.com"))
    time.sleep(0.3)
    check("a changed claim set reconciles again", logged("match no group here"), 2)

    say("the directory drops her, and the next token says so")
    be("priya@acme.com", [])
    check("she signs in again", c.get("/agents", headers=token("priya@acme.com")).status_code, 200)
    check("...and is out of the group", members(eng), [])
    check("...so the agent is gone from her list",
          _names(c.get("/agents", headers=token("priya@acme.com"))), [])

    # --- what it must never touch -----------------------------------------------------

    say("a group nobody linked is the administrator's, in both directions")
    cli("--add-group", "by-hand", "Kept by hand")
    by_hand = store.find_group_by_name(TENANT, "by-hand")["group_id"]
    added = cli("--group-add", "by-hand", priya)
    check("--group-add on an unlinked group", added.returncode, 0)

    be("priya@acme.com", ["dir-eng"])
    c.get("/agents", headers=token("priya@acme.com"))
    check("the directory's group filled again", members(eng), [f"user:{priya}"])
    check("...and the hand-made one was untouched", members(by_hand), [f"user:{priya}"])

    say("the seams refuse the hand edits that would fight the directory")
    refused = cli("--group-add", "eng", "u_someone_else")
    check("--group-add on a linked group is refused", refused.returncode != 0, True)
    check("...naming where the change belongs",
          "follows your directory" in refused.stderr, True)
    refused = cli("--group-remove", "eng", priya)
    check("--group-remove likewise", refused.returncode != 0, True)
    check("...and she is still in it", members(eng), [f"user:{priya}"])

    say("a scheduler in a linked group is nobody's business but the admin's")
    kept = cli("--group-add", "eng", "system:nightly")
    check("a system member is accepted", kept.returncode, 0)
    be("priya@acme.com", [])
    c.get("/agents", headers=token("priya@acme.com"))
    check("the claim removed the person and not the scheduler",
          members(eng), ["system:nightly"])

    # --- taking over a group that already exists --------------------------------------

    say("linking an existing group says what it costs the people in it now")
    cli("--add-group", "ops", "The operators")
    ops = store.find_group_by_name(TENANT, "ops")["group_id"]
    cli("--group-add", "ops", priya)
    taken = cli("--group-link", "ops", "dir-ops")
    check("--group-link on a filled group", taken.returncode, 0)
    check("...counted who is at risk before it happened",
          "1 person(s) are in it now" in taken.stderr, True)
    check("...and removed nobody yet", members(ops), [f"user:{priya}"])

    be("priya@acme.com", ["dir-eng"])
    c.get("/agents", headers=token("priya@acme.com"))
    check("her next sign-in applies the directory's answer", members(ops), [])

    say("the same link, over HTTP, under the tenant database role")
    # **Not a duplicate of the CLI scene.** `--group-link` runs unscoped as the table
    # owner; a request runs as `agent_runtime_tenant` with migration 037's policies
    # bound, and this write touches three tables — `groups`, the partitioned
    # `admin_audit`, and `users` (the markers). Every API test in the suite uses the
    # in-memory store, so this is the only thing that says the scoped path works at all.
    store.grant_platform_role(TENANT, "user", priya, "admin", actor="system:cli")
    made = c.post("/groups", json={"name": "support"}, headers=token("priya@acme.com"))
    check("a group over HTTP", made.status_code, 201)
    support = made.json()["group_id"]

    patched = c.patch(f"/groups/{support}", json={"external_id": "dir-support"},
                      headers=token("priya@acme.com"))
    check("PATCH links it", patched.status_code, 200)
    check("...and says so", patched.json()["external_id"], "dir-support")
    check("...through RLS, so the row really moved",
          store.get_group(TENANT, support)["external_id"], "dir-support")
    check("...and it cleared the markers it had to",
          _synced(store, priya), None)
    check("a person may not be hand-added to it over HTTP",
          c.put(f"/groups/{support}/members/user/{priya}",
                headers=token("priya@acme.com")).status_code, 400)
    check("PATCH unlinks with an explicit null",
          c.patch(f"/groups/{support}", json={"external_id": None},
                  headers=token("priya@acme.com")).json()["external_id"], None)
    check("whitespace is refused rather than read as an unlink",
          c.patch(f"/groups/{support}", json={"external_id": "   "},
                  headers=token("priya@acme.com")).status_code, 400)

    say("the edge cases a real database has an opinion about")
    # A NUL cannot be stored in a Postgres TEXT at all: unrefused, it arrives as
    # `StorageError` and renders as *"storage unavailable: try again later"* about a
    # value that will never be accepted. The others are the shapes that make a group
    # nothing can fill and nobody can edit.
    for label, bad in (
        ("a NUL", "dir\x00eng"),
        ("an interior newline", "dir\neng"),
        ("300 characters", "d" * 300),
        ("blank", "   "),
    ):
        refused = c.post("/groups", json={"name": f"bad-{label}", "external_id": bad},
                         headers=token("priya@acme.com"))
        check(f"POST /groups refuses {label}", refused.status_code, 400)
    check("...and a padded one is stored as it will be compared",
          c.post("/groups", json={"name": "padded", "external_id": " dir-padded\t"},
                 headers=token("priya@acme.com")).json()["external_id"], "dir-padded")

    say("re-running the registration does not stampede the whole workspace")
    # A sign-in first, because the scenes above linked a group and therefore cleared
    # every marker in the workspace — which is the behaviour under test one paragraph
    # down, in the other direction.
    c.get("/agents", headers=token("priya@acme.com"))
    before = _synced(store, priya)
    check("there is a marker to lose", before is not None, True)
    again = cli(
        "--add-idp", TENANT,
        "--issuer", provider.issuer,
        "--jwks-uri", f"{provider.issuer}/v1/keys",
        "--audience", dev_idp.AUDIENCE,
        "--subject-claim", "uid", "--email-claim", "sub",
        "--groups-claim", "groups", "--domain", "acme.com",
    )
    check("--add-idp again", again.returncode, 0)
    check("...and the marker survived it", _synced(store, priya), before)

    say("a directory id another group holds is refused")
    clash = cli("--group-link", "by-hand", "dir-ops")
    check("refused", clash.returncode != 0, True)
    check("...with the sentence about the directory, not about the name",
          "already has a group linked to directory" in clash.stderr, True)

    say("unlinking removes nobody and hands the group back")
    cli("--group-unlink", "ops")
    cli("--group-add", "ops", priya)
    check("the admin may edit it again", members(ops), [f"user:{priya}"])
    be("priya@acme.com", [])
    c.get("/agents", headers=token("priya@acme.com"))
    check("...and the directory has stopped speaking for it",
          members(ops), [f"user:{priya}"])

    # --- what the claim is refused for ------------------------------------------------

    say("an overage token is not an empty membership")
    be("priya@acme.com", ["dir-eng"])
    c.get("/agents", headers=token("priya@acme.com"))
    check("priya is back in eng", members(eng), ["system:nightly", f"user:{priya}"])

    overage = _forge(provider, "priya@acme.com", {
        "_claim_names": {"groups": {"essential": True, "source": "src1"}},
        "_claim_sources": {"src1": {"endpoint": "https://graph.example/v1.0/users/x"}},
    })
    check("the overage token authenticates",
          c.get("/agents", headers={"Authorization": f"Bearer {overage}"}).status_code, 200)
    check("...and changed nothing at all",
          members(eng), ["system:nightly", f"user:{priya}"])

    say("an oversized claim is refused whole rather than truncated")
    huge = _forge(provider, "priya@acme.com", {"groups": [f"dir-{n}" for n in range(500)]})
    check("it authenticates",
          c.get("/agents", headers={"Authorization": f"Bearer {huge}"}).status_code, 200)
    check("...and removed nobody", members(eng), ["system:nightly", f"user:{priya}"])

    say("an unmatched value creates nothing")
    check("no group was minted",
          sorted(g["name"] for g in store.list_groups(TENANT)),
          ["by-hand", "eng", "ops", "padded", "support"])

    # --- the sheet says its answer is partial -----------------------------------------

    say("the share sheet marks the group whose membership it cannot promise")
    store.grant_agent(TENANT, AGENT["name"], "user", priya, role="owner", actor="system:cli")
    store.grant_agent(TENANT, AGENT["name"], "group", by_hand, role="user", actor="system:cli")
    sheet = c.get(f"/agents/{AGENT['name']}/access", headers=token("priya@acme.com")).json()
    marked = {row["id"]: row["directory"] for row in sheet["access"] if row["kind"] == "group"}
    check("the linked group is marked and the hand-made one is not",
          marked, {eng: True, by_hand: False})

    # --- 033d, where the two steps meet -----------------------------------------------

    say("a personal token sees its owner's directory groups")
    minted = cli("--mint-token", "priya-cursor", priya, "--as-owner")
    check("--mint-token --as-owner", minted.returncode, 0)
    secret = next(
        line.split()[-1] for line in minted.stdout.splitlines() if "art_" in line
    ).strip()
    headers = {"Authorization": f"Bearer {secret}"}

    # A second agent, reachable **only** through the directory's group: by now Priya owns
    # the first one outright, so it would stay in her token's list however her membership
    # moved — and a check that cannot fail is worse than no check.
    only_via_group = {**AGENT, "name": "rota-reader"}
    store.save_agent(TENANT, only_via_group, actor="system:cli")
    store.grant_agent(TENANT, "rota-reader", "group", eng, role="user", actor="system:cli")

    check("it lists the agent she reaches only through the directory's group",
          _names(c.get("/agents", headers=headers)), ["rota-bot", "rota-reader"])

    be("priya@acme.com", [])
    c.get("/agents", headers=token("priya@acme.com"))
    check("...and loses it when the directory drops her",
          _names(c.get("/agents", headers=headers)), ["rota-bot"])

    c.close()


def _synced(store, user_id):
    """This person's reconciliation marker, straight out of the table."""
    row = store.get_user(TENANT, user_id)
    return row["directory_digest"]


def _names(response):
    """The agent names in a listing, whatever shape the route answers with."""
    body = response.json()
    rows = body["agents"] if isinstance(body, dict) else body
    return sorted(row["name"] for row in rows)


def _forge(provider, email, extra):
    """A token like `token_for`, plus claims `dev_idp` has no reason to offer.

    The overage shape and a 500-value claim are provider misconfigurations rather than
    features, so they are built here instead of teaching the fake provider to emit them —
    the fake stays a fake of a working directory.
    """
    import dev_idp
    import jwt

    now = int(time.time())
    return jwt.encode(
        {
            "iss": provider.issuer,
            "aud": dev_idp.AUDIENCE,
            "sub": email,
            "uid": f"u_{email.split('@')[0]}",
            "iat": now,
            "exp": now + 3600,
            **extra,
        },
        dev_idp.KEY,
        algorithm="RS256",
        headers={"kid": "dev"},
    )


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
