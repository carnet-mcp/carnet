"""What a door call costs, before and after a pointer credential. Step 070, decision 9.

**An instrument, not a test.** It asserts nothing and it fails nothing. It prints two
numbers with one variable changed between them, and it stays in the tree because the
argument it settles is one somebody will re-open:

  1. **The baseline.** Step 069 left a measurement undone and a number that is worse
     than the note it left: `agents.get` re-validates on every read, and
     `_validate_scope_matches_tools` walks this tenant's connectors once per granted
     tool, on `door._granted_agents`, i.e. on every door call. This counts the storage
     reads and times the call.
  2. **The cost of the claim.** The same call against a connector whose shared
     credential is an `op://` reference, resolved through a fake 1Password Connect
     server on loopback. The difference is what a customer pays for *the secret is not
     at rest in our database*.

**Why this step does not fix (1) while adding (2).** It is the obvious thing to do and
it destroys the measurement: with the baseline moving in the same commit, nobody can say
afterwards what the pointer cost, and *what did the pointer cost* is the number this
feature will be argued about for as long as it exists. Two numbers taken with one
variable changed are worth more than a faster door and no numbers. The fan-out fix earns
its own step against a number that already exists.

The vault here is on loopback, so the network time it reports is a floor — a real
Connect server across a network adds its own round trip to each hop. What the numbers
are honest about is the **shape**: how many hops, and how much of a door call is the
hops rather than us.

    cd backend && .venv/bin/python scripts/measure_door.py

Needs Postgres, and outbound DNS for `localtest.me` — which resolves to 127.0.0.1 and is
how every e2e script here reaches a local stub through the real egress path. `CARNET_E2E_PG`
is a base DSN with no database name. Costs nothing: no model is called and no request
leaves the machine.
"""

import json
import os
import pathlib
import statistics
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit, urlunsplit

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_measure_door"

TENANT = "e2emeasure"
ACTOR = "system:cli"
CALLS = 40

VAULT_ITEM = {
    "id": "aaaaaaaaaaaaaaaaaaaaaaaaaa",
    "title": "Tracker",
    "fields": [{"id": "credential", "label": "credential", "value": "s3cr3t-token"}],
}


def dsn_for(database: str) -> str:
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit(
        (parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment)
    )


DSN = dsn_for(DB)


class Connect(BaseHTTPRequestHandler):
    """The smallest 1Password Connect that answers the three shapes `core/vault` asks."""

    hits = []

    def log_message(self, *args):  # silence
        pass

    def do_GET(self):
        split = urlsplit(self.path)
        Connect.hits.append(split.path)
        query = parse_qs(split.query)
        wanted = (query.get("filter") or [""])[0]

        if split.path == "/v1/vaults":
            body = [{"id": "bbbbbbbbbbbbbbbbbbbbbbbbbb", "name": "Engineering"}]
            body = [row for row in body if f'name eq "{row["name"]}"' == wanted]
        elif split.path.endswith("/items"):
            body = [{"id": VAULT_ITEM["id"], "title": VAULT_ITEM["title"]}]
            body = [row for row in body if f'title eq "{row["title"]}"' == wanted]
        else:
            body = VAULT_ITEM

        payload = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class Vendor(BaseHTTPRequestHandler):
    """The vendor a REST connector tool calls. Answers anything, records nothing."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        payload = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def timed(fn, times=CALLS):
    """Median and p90 in milliseconds. Median because one GC pause is not the story."""
    samples = []
    for _ in range(times):
        started = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - started) * 1000)
    samples.sort()
    return statistics.median(samples), samples[int(len(samples) * 0.9)]


def main():
    import dataclasses

    import psycopg

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB} WITH (FORCE)")
        conn.execute(f"CREATE DATABASE {DB}")

    os.environ["CARNET_DATABASE_URL"] = DSN
    from carnet.core import crypto

    os.environ.setdefault("CARNET_SECRET_KEY", crypto.generate_key())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Connect)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    vault_url = f"http://127.0.0.1:{server.server_address[1]}"

    from carnet import agents, config, door, storage, tools
    from carnet.access import tokens
    from carnet.core import Principal
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    config.VAULT_URL = vault_url
    config.VAULT_TOKEN = "connect-token"

    crypto.configure(crypto.from_environment())
    migrate.apply(DSN)
    store = storage.configure(PostgresStorage(DSN))
    store.create_tenant(TENANT, "070 measurement")
    store.create_user(
        TENANT,
        {
            "id": "u-me",
            "issuer": "https://idp.example",
            "subject": "00u1",
            "email": "me@e2e.example",
        },
    )

    agents.save(
        TENANT,
        {
            "name": "measured",
            "system": "irrelevant",
            "runtime": "simple",
            "permissions": {
                "tools": ["post_message"],
                "scope": {"chat.channel": {"write": ["#eng"]}},
            },
        },
        actor=ACTOR,
    )
    row, _ = tokens.mint(TENANT, "laptop", "u-me", actor=ACTOR)
    store.grant_agent(TENANT, "measured", "machine", row["id"], role="user", actor=ACTOR)
    principal = Principal.machine(row["id"], TENANT)

    real = tools.REGISTRY["post_message"]
    tools.REGISTRY["post_message"] = dataclasses.replace(
        real, impl=lambda *a, **kw: {"delivered": True}
    )

    reads = {"n": 0}
    original = PostgresStorage.load_connectors

    def counted(self, tenant_id):
        reads["n"] += 1
        return original(self, tenant_id)

    PostgresStorage.load_connectors = counted

    print(f"\n=== a door call, {CALLS} of them, one builtin tool, no connectors")
    reads["n"] = 0
    median, p90 = timed(lambda: door.call_tool(principal, "post_message", {"channel": "#eng", "text": "x"}))
    print(f"  median            {median:7.1f} ms")
    print(f"  p90               {p90:7.1f} ms")
    print(f"  load_connectors   {reads['n'] / CALLS:7.1f} per call")

    # --- the fan-out 069 left, made visible: one connector, N vetted tools -----------
    print("\n=== the same call for an agent granting N connector tools (069's row)")
    store.allow_host(TENANT, "tracker.example", actor=ACTOR, note="measurement")
    tools.register_connector(
        TENANT,
        "tracker",
        url="https://tracker.example",
        kind="rest",
        credential_env="TRACKER_TOKEN",
        actor=ACTOR,
    )

    for count in (1, 10, 30):
        names = []
        for index in range(count):
            store.vet_tool(
                TENANT,
                "tracker",
                {
                    "remote_name": f"op{index}",
                    "effect": "read",
                    "identity": "service",
                    "resources": [{"type": "tracker.issue", "args": ["id"]}],
                    "binding": {
                        "method": "GET",
                        "path": f"/op{index}/{{id}}",
                        "input_schema": {
                            "type": "object",
                            "properties": {"id": {"type": "string"}},
                            "required": ["id"],
                            "additionalProperties": False,
                        },
                    },
                    "description": "measured",
                },
                actor=ACTOR,
            )
            names.append(f"tracker_op{index}")

        agents.save(
            TENANT,
            {
                "name": f"fanout{count}",
                "system": "irrelevant",
                "runtime": "simple",
                "permissions": {
                    "tools": names,
                    "scope": {"tracker.issue": {"read": ["*"]}},
                },
            },
            actor=ACTOR,
        )
        store.grant_agent(
            TENANT, f"fanout{count}", "machine", row["id"], role="user", actor=ACTOR
        )
        reads["n"] = 0
        listed, _ = timed(lambda: door.list_tools(principal), times=10)
        print(
            f"  {count:2d} granted tools:  tools/list median {listed:6.1f} ms, "
            f"{reads['n'] / 10:5.1f} load_connectors per call"
        )
        store.revoke_agent(TENANT, f"fanout{count}", "machine", row["id"], actor=ACTOR)

    # --- what a pointer costs, alone --------------------------------------------------
    print("\n=== resolving one op:// reference against a vault on loopback")
    from carnet.core import vault

    for label, pointer in (
        ("by name  (3 hops)", "op://Engineering/Tracker/credential"),
        ("by id    (1 hop) ", f"op://bbbbbbbbbbbbbbbbbbbbbbbbbb/{VAULT_ITEM['id']}/credential"),
    ):
        parsed = vault.parse(pointer)
        Connect.hits.clear()
        median, p90 = timed(lambda p=parsed: vault.resolve(p))
        print(
            f"  {label}  median {median:6.1f} ms, p90 {p90:6.1f} ms, "
            f"{len(Connect.hits) / CALLS:.1f} requests per resolution"
        )

    # --- and in a whole door call, which is the number that decides -------------------
    #
    # The same REST tool, called through the door, with the connector's shared credential
    # held two ways. One variable: `credential_env` -> `credential_ref`. The vendor is a
    # loopback stub, so what moves between the two rows is the vault and nothing else.
    print("\n=== a whole door call to a REST connector, env vs pointer")

    vendor = ThreadingHTTPServer(("127.0.0.1", 0), Vendor)
    threading.Thread(target=vendor.serve_forever, daemon=True).start()
    # `localtest.me` resolves to 127.0.0.1 in public DNS, which is how every other e2e
    # script here reaches a local stub through the real egress path — a tenant connector
    # may not name a loopback literal, and this measures the real path or it measures
    # nothing.
    vendor_url = f"http://localtest.me:{vendor.server_address[1]}"
    store.allow_host(TENANT, "localtest.me", actor=ACTOR, note="the fake vendor")
    os.environ["TRACKER_TOKEN"] = "env-token"
    config.EGRESS_INTERNAL_HOSTS = frozenset({"localtest.me"})

    def priced(**credential):
        """Re-register `priced` with one credential shape, and re-vet its one tool."""
        try:
            store.delete_connector(TENANT, "priced", actor=ACTOR)
        except Exception:  # noqa: BLE001 - first time round there is nothing to delete
            pass
        tools.reset_bound()
        tools.register_connector(
            TENANT, "priced", url=vendor_url, kind="rest", actor=ACTOR, **credential
        )
        store.vet_tool(
            TENANT,
            "priced",
            {
                "remote_name": "op0",
                "effect": "read",
                "identity": "service",
                "resources": [{"type": "tracker.issue", "args": ["id"]}],
                "binding": {
                    "method": "GET",
                    "path": "/issue/{id}",
                    "input_schema": {
                        "type": "object",
                        "properties": {"id": {"type": "string"}},
                        "required": ["id"],
                        "additionalProperties": False,
                    },
                },
                "description": "measured",
            },
            actor=ACTOR,
        )

    priced(credential_env="TRACKER_TOKEN")
    agents.save(
        TENANT,
        {
            "name": "one",
            "system": "irrelevant",
            "runtime": "simple",
            "permissions": {
                "tools": ["priced_op0"],
                "scope": {"tracker.issue": {"read": ["*"]}},
            },
        },
        actor=ACTOR,
    )
    store.grant_agent(TENANT, "one", "machine", row["id"], role="user", actor=ACTOR)

    for label, credential in (
        ("credential_env         ", {"credential_env": "TRACKER_TOKEN"}),
        ("credential_ref, by name", {"credential_ref": "op://Engineering/Tracker/credential"}),
        (
            "credential_ref, by id  ",
            {
                "credential_ref": "op://bbbbbbbbbbbbbbbbbbbbbbbbbb/"
                f"{VAULT_ITEM['id']}/credential"
            },
        ),
    ):
        priced(**credential)
        Connect.hits.clear()
        median, p90 = timed(
            lambda: door.call_tool(principal, "priced_op0", {"id": "1"}), times=20
        )
        print(
            f"  {label}  median {median:6.1f} ms, p90 {p90:6.1f} ms, "
            f"{len(Connect.hits) / 20:.1f} vault requests per call"
        )

    vendor.shutdown()

    print(
        "\nThe vault is on loopback, so these are floors: a real Connect server adds a\n"
        "network round trip per hop. What the shape says is that a name-addressed\n"
        "reference costs three of them and an id-addressed one costs a single request —\n"
        "which is why the README tells people to use ids on a hot path.\n"
    )
    server.shutdown()


if __name__ == "__main__":
    main()
