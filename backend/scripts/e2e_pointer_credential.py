"""A credential we do not hold, end to end, on real Postgres. Step 070.

**Not a test, and here for the reason `e2e_simulate.py` is**: `tests/` runs against the
in-memory store by default, and the claims this step lives or dies on are claims about
rows and about a socket. Two in particular cannot be made in-process at all:

  **The secret is nowhere.** Asserted by grepping the *database* — every audit row, the
  connector's own manifest, and every column of every table this call touched — for the
  literal value the vault returned. A test that checks a return value proves the credential
  arrived; only this proves it did not also stay.

  **The vault is a real dependency.** It is started, called, made *slow*, made to *lie*,
  and then **stopped with the server still running** — which is the failure mode a
  customer will actually meet and the one a mocked resolver cannot show. Nothing here
  patches `vault.resolve`.

What it drives, in order:

  1. Register a connector whose credential is `op://…`, vet a tool, call it through the
     door. The vendor sees the secret; the database never does.
  2. **The audit row is identical** to the same call with `--credential-env`, column for
     column. Plan 067 asked for "identical except for the credential kind"; there is no
     such exception, because `credential_kind` was never in an audit row.
  3. Stop the vault. The door refuses, naming the vault and the item, and the refusal
     reaches the caller rather than a generic credential error.
  4. Slow the vault past the deadline. Case 4 rather than case 5, inside the budget.
  5. A pointer at a field that is not there, and at a field that is empty — two different
     sentences, and neither carries the item's other field labels.
  6. `door.simulate` says exactly what it said before a pointer existed: `credential` is
     still in `not_checked`, and simulating opens no socket to the vault.

    cd backend && .venv/bin/python scripts/e2e_pointer_credential.py

Needs Postgres, and outbound DNS for `localtest.me` — which resolves to 127.0.0.1 and is
how every e2e script here reaches a local stub through the real egress path.
`CARNET_E2E_PG` is a base DSN with no database name.

Costs nothing: no model is called and no request leaves the machine.
"""

import json
import os
import pathlib
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit, urlunsplit

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_e2e_pointer"

TENANT = "e2evault"
ACTOR = "system:cli"

# The value the vault holds. Distinctive on purpose: step 3 greps the whole database for
# it, and a secret that looked like anything else would make that search meaningless.
SECRET = "ghp_070_MARKER_never_at_rest"
VAULT_ID = "bbbbbbbbbbbbbbbbbbbbbbbbbb"
ITEM_ID = "aaaaaaaaaaaaaaaaaaaaaaaaaa"

ITEM = {
    "id": ITEM_ID,
    "title": "Tracker Deploy Key",
    "fields": [
        {"id": "cred1", "label": "credential", "value": SECRET},
        {"id": "cred2", "label": "blank", "value": ""},
    ],
}

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


class Vault(BaseHTTPRequestHandler):
    """A 1Password Connect that can be slow, broken, or lying."""

    delay = 0.0
    status = 200
    body = None
    hits = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        if Vault.delay:
            time.sleep(Vault.delay)

        split = urlsplit(self.path)
        Vault.hits.append(split.path)
        wanted = (parse_qs(split.query).get("filter") or [""])[0]

        if Vault.status != 200:
            self.send_response(Vault.status)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if Vault.body is not None:
            payload = Vault.body
        elif split.path == "/v1/vaults":
            rows = [{"id": VAULT_ID, "name": "Engineering"}]
            payload = json.dumps(
                [r for r in rows if f'name eq "{r["name"]}"' == wanted]
            ).encode()
        elif split.path.endswith("/items"):
            rows = [{"id": ITEM_ID, "title": ITEM["title"]}]
            payload = json.dumps(
                [r for r in rows if f'title eq "{r["title"]}"' == wanted]
            ).encode()
        else:
            payload = json.dumps(ITEM).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class Vendor(BaseHTTPRequestHandler):
    """The API a REST tool calls. Records what credential it was presented with, which is
    the only place in this script the secret is legitimately observed."""

    presented = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        Vendor.presented.append(self.headers.get("Authorization") or "")
        payload = b'{"issue": "one"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.01), daemon=True
    ).start()
    return server, server.server_address[1]


def main():
    import psycopg

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB} WITH (FORCE)")
        conn.execute(f"CREATE DATABASE {DB}")

    os.environ["CARNET_DATABASE_URL"] = DSN
    from carnet.core import crypto

    os.environ.setdefault("CARNET_SECRET_KEY", crypto.generate_key())

    vault_server, vault_port = serve(Vault)
    vendor_server, vendor_port = serve(Vendor)

    from carnet import agents, config, door, storage, tools
    from carnet.access import tokens
    from carnet.core import Principal
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    config.VAULT_URL = f"http://127.0.0.1:{vault_port}"
    config.VAULT_TOKEN = "connect-service-account-token"
    config.VAULT_TIMEOUT_SECONDS = 2.0
    # The vendor is reached the way every e2e here reaches a local stub: through the real
    # egress path, on a public name that resolves to loopback, with the operator naming
    # their own network. The **vault** needs none of this — it dials under operator
    # consent, because its address is the deployment's own setting rather than a row.
    config.EGRESS_INTERNAL_HOSTS = frozenset({"localtest.me"})
    vendor_url = f"http://localtest.me:{vendor_port}"

    crypto.configure(crypto.from_environment())
    migrate.apply(DSN)
    store = storage.configure(PostgresStorage(DSN))
    store.create_tenant(TENANT, "070 end to end")
    store.create_user(
        TENANT,
        {
            "id": "u-me",
            "issuer": "https://idp.example",
            "subject": "00u1",
            "email": "me@e2e.example",
        },
    )
    store.allow_host(TENANT, "localtest.me", actor=ACTOR, note="the vendor stub")

    def register(connector_id, **credential):
        tools.reset_bound()
        tools.register_connector(
            TENANT, connector_id, url=vendor_url, kind="rest", actor=ACTOR, **credential
        )
        store.vet_tool(
            TENANT,
            connector_id,
            {
                "remote_name": "get_issue",
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
                "description": "one issue",
            },
            actor=ACTOR,
        )

    register("vaulted", credential_ref=f"op://Engineering/{ITEM['title']}/credential")
    register("plain", credential_env="TRACKER_TOKEN")
    os.environ["TRACKER_TOKEN"] = SECRET

    for name, tool in (("uses-vault", "vaulted_get_issue"), ("uses-env", "plain_get_issue")):
        agents.save(
            TENANT,
            {
                "name": name,
                "system": "irrelevant",
                "runtime": "simple",
                "permissions": {
                    "tools": [tool],
                    "scope": {"tracker.issue": {"read": ["*"]}},
                },
            },
            actor=ACTOR,
        )

    row, _presented = tokens.mint(TENANT, "laptop", "u-me", actor=ACTOR)
    for name in ("uses-vault", "uses-env"):
        store.grant_agent(TENANT, name, "machine", row["id"], role="user", actor=ACTOR)
    caller = Principal.machine(row["id"], TENANT)

    # --- 1. the call ------------------------------------------------------------------

    step("a door call resolves the pointer and the vendor sees the secret")

    result = door.call_tool(caller, "vaulted_get_issue", {"id": "1"})
    check("the tool answered", result.get("issue"), "one")
    check("the vendor was given the vault's value", Vendor.presented[-1], f"Bearer {SECRET}")
    check("...in three requests to the vault", len(Vault.hits), 3)

    # --- 2. nowhere at rest -----------------------------------------------------------

    step("and the secret is in no column of any table")

    with psycopg.connect(DSN, autocommit=True) as conn:
        columns = conn.execute(
            """
            SELECT table_name, column_name
              FROM information_schema.columns
             WHERE table_schema = 'public'
               AND data_type IN ('text','character varying','jsonb','json')
            """
        ).fetchall()
        # Every text-shaped column of every table, walked from the catalog rather than
        # from a list somebody maintains — 018's "nothing left behind" test, pointed at a
        # value instead of at rows.
        found = []
        for table, column in columns:
            hits = conn.execute(
                f'SELECT count(*) FROM "{table}" WHERE "{column}"::text LIKE %s',
                (f"%{SECRET}%",),
            ).fetchone()[0]
            if hits:
                found.append(f"{table}.{column}")

    check("columns containing the secret", found, [])
    manifest = next(c for c in store.load_connectors(TENANT) if c["id"] == "vaulted")
    check(
        "and the manifest holds the LOCATION instead",
        manifest["launch"]["credential_ref"],
        f"op://Engineering/{ITEM['title']}/credential",
    )
    check("...with no variable beside it", manifest["launch"]["credential_env"], None)

    # --- 3. the audit row -------------------------------------------------------------

    step("the audit row is identical to an environment-variable call, not merely similar")

    before = len(store.audit_records(TENANT))
    door.call_tool(caller, "plain_get_issue", {"id": "1"})
    env_row = store.audit_records(TENANT)[before]
    vault_row = store.audit_records(TENANT)[before - 1]

    volatile = {"ts", "id", "run_id", "duration_ms", "agent", "tool", "response_bytes"}
    check(
        "every column but the volatile ones and the tool's own name",
        {k: v for k, v in vault_row.items() if k not in volatile},
        {k: v for k, v in env_row.items() if k not in volatile},
    )
    check("...including `credential`", vault_row["credential"], "shared")

    # --- 4. the vault stops -----------------------------------------------------------

    step("the vault is stopped with the door still running")

    vault_server.shutdown()
    vault_server.server_close()
    tools.reset_bound()

    stopped = door.call_tool(caller, "vaulted_get_issue", {"id": "1"})
    refusal = stopped.get("error") or ""
    check("the call did not happen", bool(refusal), True)
    check(
        "the refusal names the item",
        "op://Engineering/Tracker%20Deploy%20Key/credential" in refusal,
        True,
    )
    check("...and the vault", config.VAULT_URL in refusal, True)
    check(
        "...and says it is not a credential problem",
        "not a permission problem and not a missing credential" in refusal,
        True,
    )
    check("...and never the secret", SECRET in refusal, False)

    last = store.audit_records(TENANT)[-1]
    check("it is audited as an allowed call that errored", last["decision"], "allow")
    check("...with the sentence in the record", last["outcome"], "error")

    # --- 5. the vault is slow, then lies ----------------------------------------------

    vault_server, vault_port = serve(Vault)
    config.VAULT_URL = f"http://127.0.0.1:{vault_port}"

    step("the vault is slow past the deadline")

    config.VAULT_TIMEOUT_SECONDS = 0.4
    Vault.delay = 0.3
    started = time.monotonic()
    slow = door.call_tool(caller, "vaulted_get_issue", {"id": "1"})
    elapsed = time.monotonic() - started
    Vault.delay = 0.0
    config.VAULT_TIMEOUT_SECONDS = 2.0

    check("refused", bool(slow.get("error")), True)
    check("...at the budget rather than per hop", elapsed < 0.9, True)
    check("...naming the budget", "0.4s budget" in (slow.get("error") or ""), True)

    step("a pointer at a field that is missing, and at one that is empty")

    tools.reset_bound()
    store.delete_connector(TENANT, "vaulted", actor=ACTOR)
    register("vaulted", credential_ref=f"op://{VAULT_ID}/{ITEM_ID}/nope")
    missing = door.call_tool(caller, "vaulted_get_issue", {"id": "1"}).get("error") or ""
    check("the field is named", "'nope'" in missing, True)
    check("...and the item's other labels are NOT", "blank" in missing, False)
    check("...and the remedy is the shell", "--check-credential" in missing, True)

    tools.reset_bound()
    store.delete_connector(TENANT, "vaulted", actor=ACTOR)
    register("vaulted", credential_ref=f"op://{VAULT_ID}/{ITEM_ID}/blank")
    empty = door.call_tool(caller, "vaulted_get_issue", {"id": "1"}).get("error") or ""
    check("an empty field says the reference worked", "the field it names is empty" in empty, True)
    check(
        "...rather than reading as no credential",
        "not a configuration problem at this end" in empty,
        True,
    )

    # --- 6. the simulator is unchanged, and dials nothing ------------------------------

    step("door.simulate says what it said before a pointer existed")

    tools.reset_bound()
    store.delete_connector(TENANT, "vaulted", actor=ACTOR)
    register("vaulted", credential_ref=f"op://Engineering/{ITEM['title']}/credential")

    Vault.hits.clear()
    simulated = door.simulate(caller, "vaulted_get_issue", {"id": "1"})
    check("allowed", simulated["verdict"], "allowed")
    check("credential is still unchecked", "credential" in simulated["not_checked"], True)
    check("and nothing dialled the vault", Vault.hits, [])

    passed = sum(1 for _, ok in CHECKS if ok)
    print(f"\n=== {passed}/{len(CHECKS)} checks passed")
    vault_server.shutdown()
    vendor_server.shutdown()
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
