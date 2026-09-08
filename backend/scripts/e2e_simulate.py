"""The simulator against the door, end to end, on real Postgres. Step 069.

**Not a test, and here for the reason `e2e_recipe_registration.py` is**: `tests/` runs
against the in-memory store by default, and the one claim this step lives or dies on is
that *the simulator gives the verdict the door gives* — which is a claim about the
enforcement path, and the enforcement path reads rows.

What it drives, in the order the argument runs:

  1. **The agreement.** Three granted agents carrying one tool at three bounds, and for
     each of six argument sets: `simulate` first, then a **real door call**, then the
     `audit` row that call wrote. Verdict, attributed agent and refusal sentence must
     match. This is the whole step; everything below is a property that decays quietly.
  2. **No socket.** The transport is replaced with one that raises, and the simulator
     still answers — including for a connector tool nothing has bound.
  3. **No row, anywhere.** Counted in Postgres, over a hundred simulations, across
     `audit`, `access_denials` and `admin_audit`.
  4. **Not a credential oracle.** A colleague's token and a token that never existed
     refuse byte-identically, through the real HTTP route.
  5. **Reading is not using.** `last_used_at` is untouched by both readers.

    cd backend && .venv/bin/python scripts/e2e_simulate.py

Needs Postgres. `CARNET_E2E_PG` is a base DSN with no database name.

Costs nothing: no model is called and nothing leaves the machine.
"""

import os
import pathlib
import sys
from urllib.parse import urlsplit, urlunsplit

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_e2e_simulate"

TENANT = "e2esim"
ACTOR = "system:cli"
TOOL = "post_message"

CHECKS = []


def dsn_for(database: str) -> str:
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit(
        (parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment)
    )


DSN = dsn_for(DB)


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok))
    print(
        f"  {'ok  ' if ok else 'FAIL'} {label}: {actual!r}"
        + ("" if ok else f"  (expected {expected!r})")
    )


def step(what):
    print(f"\n=== {what}", flush=True)


def main():
    import dataclasses

    import psycopg

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB} WITH (FORCE)")
        conn.execute(f"CREATE DATABASE {DB}")

    os.environ["CARNET_DATABASE_URL"] = DSN
    from carnet.core import crypto

    os.environ.setdefault("CARNET_SECRET_KEY", crypto.generate_key())

    from carnet import agents, door, storage, tools
    from carnet.access import tokens
    from carnet.core import Principal
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    crypto.configure(crypto.from_environment())
    migrate.apply(DSN)
    store = storage.configure(PostgresStorage(DSN))
    store.create_tenant(TENANT, "069 end to end")
    store.create_user(
        TENANT,
        {
            "id": "u-me",
            "issuer": "https://idp.example",
            "subject": "00u1",
            "email": "me@e2e.example",
        },
    )
    store.create_user(
        TENANT,
        {
            "id": "u-them",
            "issuer": "https://idp.example",
            "subject": "00u2",
            "email": "them@e2e.example",
        },
    )

    # Three agents, one tool, three bounds — the shape 033b's union rule makes hard and
    # the reason this step exists. Sorted by name they are narrow, security, triage, and
    # attribution follows that order.
    for name, channels in (
        ("narrow", ["#ops"]),
        ("security", ["#sec"]),
        ("triage", ["#eng", "#ops"]),
    ):
        agents.save(
            TENANT,
            {
                "name": name,
                "system": "irrelevant",
                "runtime": "simple",
                "permissions": {
                    "tools": [TOOL],
                    "scope": {"chat.channel": {"write": channels}},
                },
            },
            actor=ACTOR,
        )

    row, _presented = tokens.mint(TENANT, "laptop", "u-me", actor=ACTOR)
    for name in ("narrow", "security", "triage"):
        store.grant_agent(TENANT, name, "machine", row["id"], role="user", actor=ACTOR)
    mine = Principal.machine(row["id"], TENANT)

    theirs, _ = tokens.mint(TENANT, "not-yours", "u-them", actor=ACTOR)

    # --- 1. the agreement --------------------------------------------------------------

    step("the simulator says what the door does, checked against the audit row")

    # The tool is made harmless rather than mocked away: the broker still runs steps 0-3
    # unchanged, so the permission decision and the record it writes are the real ones.
    real = tools.REGISTRY[TOOL]
    tools.REGISTRY[TOOL] = dataclasses.replace(
        real, impl=lambda *a, token=None, **kw: {"delivered": True}
    )

    cases = [
        {"channel": "#ops", "text": "x"},      # narrow allows, triage too — narrow wins
        {"channel": "#eng", "text": "x"},      # only triage
        {"channel": "#sec", "text": "x"},      # only security
        {"channel": "#random", "text": "x"},   # nobody
        {"channel": "#OPS", "text": "x"},      # the matcher is case-sensitive
        {"text": "x"},                         # no resource argument at all
    ]

    for arguments in cases:
        simulated = door.simulate(mine, TOOL, dict(arguments))
        before = len(store.audit_records(TENANT))
        door.call_tool(mine, TOOL, dict(arguments))
        record = store.audit_records(TENANT)[before]

        label = arguments.get("channel", "<no channel>")
        check(
            f"{label}: verdict",
            simulated["verdict"] == "allowed",
            record["decision"] == "allow",
        )
        check(f"{label}: attributed agent", simulated["attributed_to"], record["agent"])
        if record["decision"] == "deny":
            check(f"{label}: refusal sentence", simulated["reason"], record["reason"])

    # And a tool nothing grants, which never reaches the broker at all.
    absent = door.simulate(mine, "no_such_tool", {})
    check("an ungranted name is refused", absent["verdict"], "refused")
    check("...with the door's own rule", absent["rule"], "not_granted")
    check("...and nothing was considered", absent["considered"], [])

    step("and the union rule is visible before the call rather than after it")

    shared = door.reach(mine)["by_tool"][0]
    check("one row per tool", shared["tool"], TOOL)
    check(
        "every agent that carries it, in the door's order",
        [g["agent"] for g in shared["granted_by"]],
        ["narrow", "security", "triage"],
    )
    check(
        "each with only the patterns that decide",
        [g["applies"]["chat.channel"] for g in shared["granted_by"]],
        [["#ops"], ["#sec"], ["#eng", "#ops"]],
    )
    check(
        "and no attribution, because that needs the arguments",
        "attributed_to" in shared,
        False,
    )

    # --- 2. no socket ------------------------------------------------------------------

    step("nothing dials, asserted by making it impossible")

    from carnet.tools import mcp

    def refuse(*args, **kwargs):
        raise AssertionError("a simulation must not dial anything")

    opened = mcp.ensure_session
    connected = mcp.connect
    mcp.ensure_session = refuse
    mcp.connect = refuse
    try:
        check(
            "the simulator answers with every transport seam refusing",
            door.simulate(mine, TOOL, {"channel": "#ops"})["verdict"],
            "allowed",
        )
        check(
            "and so does the transpose",
            door.reach(mine)["by_tool"][0]["tool"],
            TOOL,
        )
    finally:
        mcp.ensure_session = opened
        mcp.connect = connected

    # --- 3. no row, anywhere -----------------------------------------------------------

    step("a hundred simulations write nothing, counted in Postgres")

    def counts():
        with psycopg.connect(DSN) as conn:
            return tuple(
                conn.execute(f"select count(*) from {table}").fetchone()[0]
                for table in ("audit", "access_denials", "admin_audit")
            )

    before = counts()
    for i in range(100):
        door.simulate(mine, TOOL, {"channel": "#ops" if i % 2 else "#random"})
        door.reach(mine)
    check("audit, access_denials and admin_audit are unmoved", counts(), before)

    # --- 4. not a credential oracle ----------------------------------------------------

    step("a token you may not aim refuses as one that does not exist")

    from fastapi.testclient import TestClient

    from carnet.api import create_app
    from carnet.api.deps import principal_from_request

    app = create_app()
    app.dependency_overrides[principal_from_request] = lambda: Principal.user(
        "u-me", TENANT
    )
    client = TestClient(app)

    def simulate_over_http(token_id):
        return client.post(
            f"/me/tokens/{token_id}/simulate",
            json={"tool": TOOL, "arguments": {"channel": "#ops"}},
        )

    ok = simulate_over_http(row["id"])
    check("my own token answers", ok.status_code, 200)
    check("...with the same verdict", ok.json()["verdict"], "allowed")
    check("...and the same attribution", ok.json()["attributed_to"], "narrow")

    colleague = simulate_over_http(theirs["id"])
    invented = simulate_over_http("m_000000000000")
    check("a colleague's token", colleague.status_code, 400)
    check("an id that never existed", invented.status_code, 400)
    check(
        "byte-identical apart from the id the caller supplied",
        colleague.json()["detail"].replace(theirs["id"], "X"),
        invented.json()["detail"].replace("m_000000000000", "X"),
    )
    check("and the owner is not named", "u-them" in colleague.json()["detail"], False)

    # --- 5. reading is not using -------------------------------------------------------

    step("neither reader stamps the column that says a credential was used")

    client.get(f"/me/tokens/{row['id']}/reach")
    simulate_over_http(row["id"])
    check(
        "last_used_at is untouched by both",
        store.find_api_token(row["id"])["last_used_at"],
        None,
    )

    tools.REGISTRY[TOOL] = real

    passed = sum(1 for _label, ok in CHECKS if ok)
    failed = [label for label, ok in CHECKS if not ok]
    print(f"\n=== {passed}/{len(CHECKS)} checks passed")
    for label in failed:
        print(f"  FAILED: {label}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
