"""Registering a connector end to end, against real Postgres, and into the agent form.

**Not a test, and it is here for the reason `e2e_write_path.py` is**: `tests/` runs
against the in-memory store by default, so nothing in the suite takes this arc through a
database that has columns — and this step adds a migration, two new tables' worth of
columns, and a write method whose whole purpose is *not* to behave like the one beside it.

The arc is plan 012's first verification, in the order the commands are meant to be run:

    --allow-host        the host, or nothing is dialled
    --add-connector     the row, so a credential has somewhere to live. Vets nothing.
    --discover          what it offers, and the argument names --vet needs
    --vet               one tool at a time, appended
    the catalogue       what the form would offer
    agents.validate     what the form would save

Plus the four properties that only mean anything against the real store: that nine vetted
tools survive a tenth, that the review record names a person and a server version, that a
host nobody approved is never dialled, and that an unscopeable write is refused by the
column rather than by the interface.

    cd backend && .venv/bin/python scripts/e2e_registration.py

Needs Postgres reachable first: `CARNET_E2E_PG` is the base DSN it splices a database name into.

**Costs nothing and contacts nothing.** The MCP server is a scripted fake passed in as a
transport; no socket is opened, no container is started, and no model is called. That is
not a shortcut — it is the point of the transport seam, and it means this can run in CI
next to everything else.

The database it leaves behind is safe to drop and is recreated on every run.
"""

import os
import pathlib
import sys
from urllib.parse import urlsplit, urlunsplit

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_e2e_registration"


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
TENANT = "e2ereg"

PRIYA = "user:u_priya"
HOST = "mcp.acme-internal.com"
URL = f"https://{HOST}/mcp"

# What the fake Jira server advertises. `create_issue` is the write worth scoping,
# `delete_project` is the one nobody vets — the case the allowlist exists for.
ADVERTISED = [
    {
        "name": "create_issue",
        "description": "Create an issue in a Jira project.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "projectKey": {"type": "string"},
                "summary": {"type": "string"},
            },
            "required": ["projectKey", "summary"],
        },
    },
    {
        "name": "search_issues",
        "description": "Search issues with JQL.",
        "inputSchema": {
            "type": "object",
            "properties": {"jql": {"type": "string"}},
            "required": ["jql"],
        },
    },
    {
        "name": "delete_project",
        "description": "Delete a Jira project and everything in it.",
        "inputSchema": {
            "type": "object",
            "properties": {"projectKey": {"type": "string"}},
            "required": ["projectKey"],
        },
    },
]

CHECKS = []


def check(label, actual, expected):
    """**Every line this prints is an assertion.** `e2e_write_path.py`'s device, verbatim.

    The first version of that script printed and asserted almost nothing, which made it a
    demonstration — it would have gone on looking correct while quietly reporting a 500.
    """
    ok = actual == expected
    CHECKS.append((ok, label))
    mark = "  ok" if ok else "FAIL"
    print(f"{mark}  {label}")
    if not ok:
        print(f"        expected: {expected!r}")
        print(f"        actual:   {actual!r}")
    return ok


def says(label, actual, fragment):
    """A check on a *sentence*, for the refusals whose whole value is what they say."""
    ok = fragment in str(actual)
    CHECKS.append((ok, label))
    print(f"{'  ok' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        wanted {fragment!r} in: {actual!r}")
    return ok


def step(what):
    print(f"\n=== {what}", flush=True)


class FakeJira:
    """A scripted MCP server. Version and advertisement are both settable, because
    re-vetting against a server that has *moved* is the whole of decision 6."""

    def __init__(self, tools_=None, version="2.3.0"):
        self.tools = ADVERTISED if tools_ is None else tools_
        self.version = version

    def send(self, message):
        if "id" not in message:
            return None
        method = message["method"]
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "jira-mcp-server", "version": self.version},
            }
        elif method == "tools/list":
            result = {"tools": self.tools}
        else:
            result = {"content": [{"type": "text", "text": "{}"}]}
        return {"jsonrpc": "2.0", "id": message["id"], "result": result}

    def set_protocol_version(self, version):
        pass

    def close(self):
        pass


def main():
    import psycopg

    with psycopg.connect(
        dsn_for("postgres"), autocommit=True
    ) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")

    os.environ["CARNET_DATABASE_URL"] = DSN
    os.environ.setdefault("CARNET_SECRET_KEY", _generate_key())

    from carnet import agents, storage, tools
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage
    from carnet.tools import mcp
    from carnet.tools.base import Resource

    applied = migrate.apply(DSN)
    check("migrations applied include 023", "023_connector_registration" in applied, True)

    store = storage.configure(PostgresStorage(DSN))
    store.create_tenant(TENANT, "012 end to end")

    # --- the host ------------------------------------------------------------------

    step("an empty allowlist denies, which is the state every new customer starts in")

    check("no hosts approved", store.allowed_hosts(TENANT), [])
    try:
        tools.register_connector(TENANT, "jira", url=URL, actor=PRIYA)
        check("registering an unapproved host is refused", "no refusal", "refused")
    except mcp.EgressRefused as exc:
        says("registering an unapproved host is refused", exc, "has not approved the host")
        says("…and the refusal names the command that fixes it", exc, f"--allow-host {HOST}")
    check("nothing was registered", store.get_connector(TENANT, "jira"), None)

    step("--allow-host")

    store.allow_host(TENANT, HOST, actor=PRIYA, note="security approved 2026-08")
    row = store.allowed_hosts(TENANT)[0]
    check("host approved", row["host"], HOST)
    check("…by a named person", row["allowed_by"], PRIYA)
    check("…with the note kept", row["note"], "security approved 2026-08")

    # --- registration ---------------------------------------------------------------

    step("--add-connector — the row, so a credential has somewhere to live. Vets nothing.")

    tools.register_connector(
        TENANT,
        "jira",
        url=URL,
        credential_env="JIRA_TOKEN",
        description="Jira, issues only",
        actor=PRIYA,
    )
    connector = mcp.get_connector(TENANT, "jira")
    check("registered", connector.id, "jira")
    check("vets nothing", list(connector.vetted), [])
    check("contributes no tools", connector.declared_names(), set())
    check("and speaks HTTP", connector.transport_kind, "http")

    # Migration 021's ordering, which is why registration is its own command.
    store.save_connection(
        TENANT,
        "user",
        "u_priya",
        "jira",
        ciphertext=b"sealed",
        key_id="k1",
        account_label="priya@acme.com",
        actor=PRIYA,
    )
    check(
        "a credential can now be sealed against it",
        store.find_connection(TENANT, "user", "u_priya", "jira")["connector_id"],
        "jira",
    )

    step("registering the same id again is refused rather than replacing")

    try:
        tools.register_connector(TENANT, "jira", url=URL, actor=PRIYA)
        check("second --add-connector refused", "no refusal", "refused")
    except storage.ConnectorExistsError as exc:
        says("second --add-connector refused", exc, "already has a connector")

    # --- discovery ------------------------------------------------------------------

    step("--discover — the input schemas, which is the only thing that makes --vet answerable")

    seen = mcp.discovery.discover(TENANT, connector, "tok", transport=FakeJira())
    check("server identified itself", mcp.discovery.server_label(seen["server"]), "jira-mcp-server v2.3.0")
    check("three tools advertised", sorted(t["name"] for t in seen["tools"]),
          ["create_issue", "delete_project", "search_issues"])
    check(
        "and the argument names --resource needs are visible",
        sorted((seen["tools"][0]["inputSchema"]["properties"])),
        ["projectKey", "summary"],
    )
    check("discovery vetted nothing", list(mcp.get_connector(TENANT, "jira").vetted), [])

    # --- vetting ---------------------------------------------------------------------

    step("--vet — one tool at a time, appended")

    recorded = tools.vet_tool(
        TENANT,
        "jira",
        "create_issue",
        effect="write",
        resources=(Resource("jira.project", "projectKey"),),
        note="Creates a ticket somebody will be paged about.",
        actor=PRIYA,
        transport=FakeJira(),
    )
    check("local name", recorded["local_name"], "jira_create_issue")
    check("effect", recorded["effect"], "write")
    check("resource", recorded["resources"], ["jira.project"])
    check("vetted against", recorded["server"], "jira-mcp-server v2.3.0")

    review = store.load_vetting_record(TENANT)[0]
    check("vetted_by finally names a person", review["vetted_by"], PRIYA)
    check("server_name recorded", review["server_name"], "jira-mcp-server")
    check("server_version recorded", review["server_version"], "2.3.0")

    step("a write with no resource is refused by the column, not by the interface")

    try:
        store.vet_tool(
            TENANT,
            "jira",
            {"remote_name": "delete_project", "effect": "write", "resources": []},
            actor=PRIYA,
        )
        check("unscopeable write refused at storage", "no refusal", "refused")
    except storage.StorageError as exc:
        says("unscopeable write refused at storage", exc, "unscopeable")
    check(
        "…and nothing was written",
        [v.remote_name for v in mcp.get_connector(TENANT, "jira").vetted],
        ["create_issue"],
    )

    # --- the form --------------------------------------------------------------------

    step("the catalogue, which is what the agent form offers")

    catalogue = tools.catalogue(TENANT)
    jira = next(group for group in catalogue if group["id"] == "jira")
    entry = jira["tools"][0]
    check("in the catalogue", entry["name"], "jira_create_issue")
    check("marked as a write", entry["effect"], "write")
    check("scoped to a resource type", entry["resources"], [{"type": "jira.project"}])
    check("the vendor's own description", entry["description"], "Create an issue in a Jira project.")
    check("our note, separately", entry["note"], "Creates a ticket somebody will be paged about.")
    check("and who approved it", entry["vetted_by"], PRIYA)
    check("against what", entry["server_version"], "2.3.0")

    check(
        "delete_project is advertised and invisible to every agent",
        "jira_delete_project" in tools.known_names(TENANT),
        False,
    )

    step("agents.validate — what the form would save")

    agents.validate(
        TENANT,
        {
            "name": "ticket-filer",
            "system": "You file tickets.",
            "permissions": {
                "tools": ["jira_create_issue"],
                "scope": {"jira.project": {"write": ["ACME"]}},
            },
        },
    )
    check("an agent granting the newly vetted tool validates", True, True)

    try:
        agents.validate(
            TENANT,
            {
                "name": "wrecker",
                "system": "…",
                "permissions": {"tools": ["jira_delete_project"], "scope": {}},
            },
        )
        check("an agent granting an unvetted tool is refused", "accepted", "refused")
    except Exception as exc:  # noqa: BLE001 - the refusal's class is agents/, not ours
        says("an agent granting an unvetted tool is refused", exc, "jira_delete_project")

    # --- nine survive a tenth ---------------------------------------------------------

    step("nine vetted tools survive vetting a tenth")

    many = [
        {
            "name": f"tool_{n}",
            "description": f"Tool {n}.",
            "inputSchema": {"type": "object", "properties": {"projectKey": {"type": "string"}}},
        }
        for n in range(9)
    ]
    server = FakeJira(tools_=ADVERTISED + many)
    for n in range(9):
        tools.vet_tool(
            TENANT, "jira", f"tool_{n}", effect="read", actor=PRIYA, transport=server
        )

    check("nine plus the first", len(mcp.get_connector(TENANT, "jira").vetted), 10)

    tools.vet_tool(
        TENANT, "jira", "search_issues", effect="read", actor=PRIYA, transport=server
    )
    check("the eleventh did not replace them", len(mcp.get_connector(TENANT, "jira").vetted), 11)
    check("each keeps its own review", len(store.load_vetting_record(TENANT)), 11)

    # --- drift -------------------------------------------------------------------------

    step("a renamed argument names the version it was vetted against, and the argument")

    moved = [
        {
            **ADVERTISED[0],
            "inputSchema": {
                "type": "object",
                "properties": {"project": {"type": "string"}, "summary": {"type": "string"}},
                "required": ["project", "summary"],
            },
        },
        *ADVERTISED[1:],
        *many,
    ]
    vetting = {
        (r["connector_id"], r["remote_name"]): r for r in store.load_vetting_record(TENANT)
    }
    refusals = mcp.discovery.refusals(
        mcp.discovery.review(mcp.get_connector(TENANT, "jira"), moved, vetting)
    )
    check("one refusal", len(refusals), 1)
    if refusals:
        says("names the argument that moved", refusals[0]["message"], "'projectKey'")
        says("names what it was vetted against", refusals[0]["message"], "jira-mcp-server v2.3.0")
        says("names what would stop being scoped", refusals[0]["message"], "jira.project")

    step("and vetting anything new is refused while that drift stands")

    try:
        tools.vet_tool(
            TENANT,
            "jira",
            "search_issues",
            effect="read",
            actor=PRIYA,
            transport=FakeJira(tools_=moved, version="3.0.0"),
        )
        check("vetting refused while drifted", "accepted", "refused")
    except tools.RegistrationRefused as exc:
        says("vetting refused while drifted", exc, "no longer matches")

    # --- egress at dial time ------------------------------------------------------------

    step("revoking the host stops the connector and keeps its vetting")

    store.revoke_host(TENANT, HOST, actor=PRIYA)
    try:
        mcp._transport_for(TENANT, mcp.get_connector(TENANT, "jira"), None)
        check("dialling a revoked host is refused", "dialled", "refused")
    except mcp.EgressRefused as exc:
        says("dialling a revoked host is refused", exc, "has not approved the host")
    check(
        "…and eleven vetted tools are still there",
        len(mcp.get_connector(TENANT, "jira").vetted),
        11,
    )

    # --- the administrative log ---------------------------------------------------------

    step("the administrative log, which now covers connectors and egress")

    actions = [r["action"] for r in store.admin_audit_records(TENANT)]
    for action in ("egress.allow", "connector.create", "connector.vet", "egress.revoke"):
        check(f"{action} recorded", action in actions, True)
    check(
        "every record names a principal",
        all(r["actor_id"] for r in store.admin_audit_records(TENANT)),
        True,
    )
    check(
        "the refused unscopeable write left no record",
        sum(1 for r in store.admin_audit_records(TENANT)
            if r["action"] == "connector.vet" and r["detail"].get("remote_name") == "delete_project"),
        0,
    )

    store.close()

    failed = [label for ok, label in CHECKS if not ok]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        print("\nFAILED:")
        for label in failed:
            print(f"  - {label}")
        raise SystemExit(1)
    print(f"\nDrop {DB} when you like; it is recreated on every run.")


def _generate_key():
    import base64
    import os as _os

    return base64.b64encode(_os.urandom(32)).decode()


if __name__ == "__main__":
    sys.exit(main())
