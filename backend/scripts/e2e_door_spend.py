"""What a door call spends, against a real model, over a real socket. Step 045b.

**This is the only script in the tree that spends money.** It brokers real calls to a
real vendor's model API through the door and asserts that Carnet counted them, priced
them, showed them and refused on them. Everything else about 045b is fakes; the numbers
here come off the wire.

    --allow-host api.anthropic.com
        -> a `rest` connector whose credential is its own env var
        -> one vetted tool with a usage_map
        -> POST /mcp  tools/call
        -> a live Messages API
        -> audit row carries the vendor's own token counts
        -> door_spend_today prices them, the budget route shows them,
           the ceiling refuses the next call

## What this proves that the unit suite cannot

**The counters are the vendor's.** `test_door.py` hands the broker a number it wrote
itself. Here the number is whatever Anthropic billed, lifted out of the response body by
a `usage_map` a vetter authored, and compared against the body the door handed back.

**045c is reachable today.** No model-specific code exists — this is 045a's REST
connector plus 045b's meter, and the payoff sentence of plan 045 (*"an outside agent
holds one secret, its Carnet token, for both its thinking and its tools"*) is driven
end to end rather than promised.

**The oversize path still bills.** A model answer past the response cap is discarded
before it reaches the caller, and the money is spent anyway. Only a live call produces a
response whose size is not chosen by the test.

## Cost

Eleven model calls at `max_tokens` 8-16 on Haiku. Well under a cent. The model is named
in `MODEL` and nothing here depends on which one it is.

    cd backend && .venv/bin/python scripts/e2e_door_spend.py

Needs Postgres started first, `ANTHROPIC_API_KEY` in `backend/.env`, and outbound DNS.
`--offline` skips every live call and runs the local-fake half alone, which is what CI
would run if this were ever wired into it: the vendor half costs money and needs a
secret, so it is a hand-run script by the same rule as `e2e_deploy.py`.
"""

import json
import os
import pathlib
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urlunsplit

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_e2e_door_spend"


def dsn_for(database: str) -> str:
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


DSN = dsn_for(DB)
TENANT = "e2espend"
PRIYA = "user:u_priya"

VENDOR_HOST = "api.anthropic.com"
VENDOR_URL = f"https://{VENDOR_HOST}/v1"

# Haiku: the cheapest family the built-in rate table knows, so the dollar assertions
# below are real prices rather than a model nobody has a rate for.
MODEL = "claude-haiku-4-5-20251001"

# The local fake, for the half that must not be a vendor's behaviour: a connector that
# lies about what it spent. No real API can be made to report -1 tokens.
FAKE_HOST = "localtest.me"
# Overridable, because step 099's runner found a day-old `demo_world.py` holding 8934
# on the machine the acceptance pass ran on — a port nobody can move is a harness
# nobody can run beside anything.
FAKE_PORT = int(os.environ.get("CARNET_E2E_FAKE_PORT", "8934"))
FAKE_URL = f"http://{FAKE_HOST}:{FAKE_PORT}/v1"

# The vetter's words. A REST API describes nothing, so the schema, the request mapping
# and the usage map are all authored — 045a's stated cost, and here it is what makes a
# model call an ordinary brokered tool.
ANSWER_SCHEMA = {
    "type": "object",
    "properties": {
        "model": {"type": "string", "description": "which model to think with"},
        "max_tokens": {"type": "integer"},
        "messages": {"type": "array", "description": "the conversation so far"},
    },
    "required": ["model", "max_tokens", "messages"],
}

# Where the counters live in a Messages API reply. The four names on the left are
# `core/usage.TokenUsage`'s fields; the paths on the right are the vendor's spelling, and
# the two differ (`cache_creation_input_tokens` is a cache *write*) which is the whole
# reason this is a mapping rather than a convention.
USAGE_MAP = {
    "model": "model",
    "input_tokens": "usage.input_tokens",
    "output_tokens": "usage.output_tokens",
    "cache_read_tokens": "usage.cache_read_input_tokens",
    "cache_write_tokens": "usage.cache_creation_input_tokens",
}

CHECKS = []
SPENT_CALLS = 0


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((ok, label))
    print(f"{'  ok' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        expected: {expected!r}")
        print(f"        actual:   {actual!r}")
    return ok


def says(label, actual, fragment):
    ok = fragment in str(actual)
    CHECKS.append((ok, label))
    print(f"{'  ok' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        wanted {fragment!r} in: {str(actual)[:300]!r}")
    return ok


def truthy(label, actual):
    ok = bool(actual)
    CHECKS.append((ok, label))
    print(f"{'  ok' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        wanted something truthy, got: {actual!r}")
    return ok


def step(what):
    print(f"\n=== {what}", flush=True)


# --- the local fake, for what a vendor cannot be made to do -------------------------


class LyingAPI(BaseHTTPRequestHandler):
    """A connector that reports whatever `?report=` asks for.

    Here because the refusal being tested is *a connector lying about its own spend*,
    and no real vendor will emit a negative counter on request. Everything else in this
    script is the real API.
    """

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        which = urlsplit(self.path).path.rsplit("/", 1)[-1]
        payload = {
            "negative": {"model": MODEL, "usage": {"input_tokens": -1_000_000}},
            "absurd": {"model": MODEL, "usage": {"input_tokens": 10**15}},
            "text": {"model": MODEL, "usage": {"input_tokens": "loads"}},
            "boolean": {"model": MODEL, "usage": {"input_tokens": True}},
            "partial": {"model": MODEL, "usage": {"input_tokens": 100, "output_tokens": -1}},
            "smuggled": {
                "model": MODEL,
                "carnet_reported_usage": {"model": MODEL, "input_tokens": 10**9},
            },
            "honest": {"model": MODEL, "usage": {"input_tokens": 10, "output_tokens": 2}},
        }.get(which, {"model": MODEL})
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    import psycopg

    offline = "--offline" in sys.argv

    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key and not offline:
        raise SystemExit(
            "ANTHROPIC_API_KEY is not set. It lives in backend/.env; this script is the "
            "one that spends money, so it will not run without it. Use --offline to run "
            "the local-fake half alone."
        )
    if socket.gethostbyname(FAKE_HOST) != "127.0.0.1":
        raise SystemExit(f"{FAKE_HOST} did not resolve to 127.0.0.1; this script needs DNS")

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")

    os.environ["CARNET_DATABASE_URL"] = DSN
    # Step 058: the dial vets DNS answers, and localtest.me resolves to loopback
    # on purpose — the operator (this script) consents to its own machine.
    os.environ["CARNET_EGRESS_INTERNAL_HOSTS"] = "localtest.me"
    os.environ.setdefault("CARNET_SECRET_KEY", _generate_key())
    # **The connector's key is its own variable, never the platform's.**
    # `config.is_platform_env` (step 050) refuses `ANTHROPIC_API_KEY` by name for a
    # connector credential, and the refusal is asserted below rather than merely
    # respected. Same secret, different name, and the different name is the control.
    os.environ["MODELAPI_TOKEN"] = key or "unused-offline"
    os.environ["LIAR_TOKEN"] = "unused"

    from fastapi.testclient import TestClient

    from carnet import agents, config, door, storage, tools
    from carnet.access import tokens
    from carnet.api import create_app
    from carnet.core import crypto
    from carnet.core.principal import Principal
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage
    from carnet.tools import mcp
    from carnet.tools.base import Resource

    migrate.apply(DSN)
    store = storage.configure(PostgresStorage(DSN))
    crypto.configure(crypto.from_environment())
    store.create_tenant(TENANT, "045b door spend end to end")
    store.create_user(TENANT, {"id": "u_priya", "issuer": "https://idp.example",
                               "subject": "00u1", "email": "priya@acme.com"})

    server = ThreadingHTTPServer(("127.0.0.1", FAKE_PORT), LyingAPI)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def audit_rows():
        return store.audit_records(TENANT)

    def last():
        return audit_rows()[-1]

    def spend_of(row):
        return (row["model"], row["input_tokens"], row["output_tokens"],
                row["cache_read_tokens"], row["cache_write_tokens"])

    try:
        # --- registration ---------------------------------------------------------

        step("the platform's own key may not become a connector credential")

        store.allow_host(TENANT, VENDOR_HOST, actor=PRIYA, note="the model vendor")
        store.allow_host(TENANT, FAKE_HOST, actor=PRIYA, note="a connector that lies")

        from carnet.core import credentials

        # Step 050 widened the one-name `PLATFORM_SECRETS` denylist into
        # `config.is_platform_env`, enforced at registration as well as the read.
        check("ANTHROPIC_API_KEY is the platform's by name (050's predicate)",
              config.is_platform_env("ANTHROPIC_API_KEY"), True)
        refused_env = None
        try:
            tools.register_connector(
                TENANT, "badmodel", url=VENDOR_URL, kind="rest",
                credential_env="ANTHROPIC_API_KEY", actor=PRIYA,
            )
            for_it = mcp.get_connector(TENANT, "badmodel")
            credentials.for_session("badmodel", Principal.system("cli", TENANT),
                                    for_it.launch.credential_env)
        except Exception as exc:  # noqa: BLE001 - the refusal is the assertion
            refused_env = f"{type(exc).__name__}: {exc}"
        says("and naming it as a connector credential is refused", refused_env,
             "ANTHROPIC_API_KEY")

        step("a model API is an ordinary REST connector — no model-specific code")

        # Through `save_connector` rather than `register_connector`, and that is a
        # **finding rather than a preference**: `RestLaunch` carries `credential_header`
        # and `credential_prefix` precisely so a vendor insisting on `x-api-key` can be
        # registered — its own comment names 045c as the customer — and neither
        # `register_connector` nor the CLI can set either one. The manifest path is the
        # only writer that reaches them today.
        vendor = mcp.Connector(
            id="modelapi",
            launch=mcp.RestLaunch(
                url=VENDOR_URL,
                credential_env="MODELAPI_TOKEN",
                credential_header="x-api-key",
                credential_prefix="",
                headers={"anthropic-version": "2023-06-01"},
            ),
            description="A model, brokered like any other API.",
            vetted=[
                mcp.Vetted(
                    "answer", effect="read", identity="service",
                    description="Ask a model a question.",
                    resources=[Resource("modelapi.model", "model")],
                    binding={
                        "method": "POST", "path": "/messages",
                        "body": ["model", "max_tokens", "messages"],
                        "input_schema": ANSWER_SCHEMA,
                        "usage_map": USAGE_MAP,
                    },
                ),
            ],
        )
        tools.save_connector(TENANT, vendor, actor=PRIYA)
        check("registered with no discovery and no session",
              mcp.get_connector(TENANT, "modelapi").transport_kind, "rest")

        step("a scope line makes 'may think with this model, not that one'")

        # The resource type is `modelapi.model` mapped to the `model` argument, so model
        # choice is an ordinary scope line through the existing matcher — plan 045's claim,
        # exercised here with no code that knows what a model is.
        #
        # **And exercised is the word: the first version of this used `claude-haiku-*`,
        # which the matcher refuses.** `core/patterns.py` compares *whole segments* split
        # on `/` and has no prefix wildcard, deliberately — its docstring makes prefix
        # confusion "not expressible" on purpose. A model id has no separators, so a
        # family glob is one segment that equals nothing. The scope has to name exact
        # dated ids, and a new release of the same family fails closed until somebody
        # edits it. Asserted in both directions below, and registered for 045c.
        agents.save(TENANT, {
            "name": "thinker",
            "runtime": "simple",
            "system": "You answer questions.",
            "permissions": {
                "tools": ["modelapi_answer"],
                "scope": {"modelapi.model": {"read": [MODEL]}},
            },
        }, actor=PRIYA)

        row, presented = tokens.mint(TENANT, "priya-cursor", "u_priya", actor="system:cli")
        store.grant_agent(TENANT, "thinker", "machine", row["id"],
                          role="user", granted_by=PRIYA, actor=PRIYA)
        machine = Principal.machine(row["id"], TENANT)

        client = TestClient(create_app())
        auth = {"Authorization": f"Bearer {presented}"}

        def call(name="modelapi_answer", **arguments):
            global SPENT_CALLS
            SPENT_CALLS += 1
            return client.post("/mcp", headers=auth, json={
                "jsonrpc": "2.0", "id": SPENT_CALLS, "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }).json()["result"]

        def ask(text="Say the single word: ok", max_tokens=16, model=MODEL):
            return call(model=model, max_tokens=max_tokens,
                        messages=[{"role": "user", "content": text}])

        listed = client.post("/mcp", headers=auth, json={
            "jsonrpc": "2.0", "id": 0, "method": "tools/list",
        }).json()["result"]["tools"]
        check("the door serves it as one ordinary tool",
              [t["name"] for t in listed], ["modelapi_answer"])

        if offline:
            print("\nSKIPPED: every live model call — --offline, so no vendor was dialled "
                  "and nothing was spent; the live half is unproven by this run")
        else:
            # --- the live arc ------------------------------------------------------

            step("a real brokered model call, and the vendor's own counters on the row")

            answered = ask()
            if answered.get("isError"):
                print(f"        vendor/door said: {json.dumps(answered)[:500]}")
            check("the call succeeded", answered.get("isError") is not True, True)
            body = json.loads(answered["content"][0]["text"])
            truthy("the vendor answered with content", body.get("content"))

            record = last()
            check("the correlation id is a door call, not a run",
                  record["run_id"].startswith(storage.DOOR_CALL_ID_PREFIX), True)
            check("and no runs row exists at all", list(store.list_runs(TENANT)), [])

            # The evidence: the row's counters ARE the body's counters.
            vendor_usage = body["usage"]
            check("input tokens are the vendor's own",
                  record["input_tokens"], vendor_usage["input_tokens"])
            check("output tokens are the vendor's own",
                  record["output_tokens"], vendor_usage["output_tokens"])
            check("the model recorded is the one that answered",
                  record["model"], body["model"])
            truthy("and they are real numbers, not zeros", record["input_tokens"] > 0)

            check("the reserved key never reached the caller",
                  "carnet_reported_usage" in json.dumps(body), False)

            step("priced by the door's own arithmetic, and shown where a person looks")

            spend = door.door_spend_today(machine)
            truthy("door_spend_today prices it above zero", spend["usd"] > 0)
            check("with no unpriced models", spend["unpriced_models"], [])
            check("and one model bucket", len(spend["by_model"]), 1)

            budget = client.get(f"/me/tokens/{row['id']}/budget", headers=auth)
            # A machine may not read this route — it is owner-or-admin — so the
            # assertion is that the *arithmetic* is one function, which the route calls.
            check("the budget route refuses a machine reading its own row",
                  budget.status_code in (400, 403), True)
            check("the screen's number and the gate's number are one function",
                  door.door_spend_today(machine)["usd"], spend["usd"])

            step("a family glob is not a scope line, and that is the matcher's design")

            from carnet.core import patterns

            check("an exact id matches", patterns.matches(MODEL, MODEL), True)
            check("a family prefix does not — there is no prefix wildcard",
                  patterns.matches("claude-haiku-*", MODEL), False)
            check("nor does a bare star, because a model id is one segment and that is it",
                  patterns.matches("*", MODEL), True)
            print("        NOTE: 'this token may think with the small model but not the")
            print("        large one' therefore means enumerating dated ids. A new Haiku")
            print("        release fails closed until the scope is edited. 045c's problem;")
            print("        registered in DEFERRED.md rather than solved here.")

            step("a model outside the scope line is refused before anything is dialled")

            before = len(audit_rows())
            refused = ask(model="claude-opus-4-20250514")
            check("refused by the broker", refused.get("isError"), True)
            says("as a policy denial", json.dumps(refused), "Denied by broker")
            denial = last()
            check("one audit row, a deny", (len(audit_rows()) - before, denial["decision"]),
                  (1, "deny"))
            check("carrying no usage, because nothing ran", denial["input_tokens"], None)

            step("an answer past the response cap is discarded and billed anyway")

            # The one edge case only a live call can produce: the vendor charged, the
            # broker threw the payload away, and the money is still on the row.
            store.vet_tool(TENANT, "modelapi", {
                "remote_name": "answer",
                "effect": "read", "identity": "service",
                "description": "Ask a model a question.",
                "resources": [{"type": "modelapi.model", "args": ["model"]}],
                "max_response_bytes": 200,
                "binding": {
                    "method": "POST", "path": "/messages",
                    "body": ["model", "max_tokens", "messages"],
                    "input_schema": ANSWER_SCHEMA, "usage_map": USAGE_MAP,
                },
            }, actor=PRIYA)

            big = ask("Write four sentences about the sea.", max_tokens=200)
            check("the caller got a refusal rather than a clipped payload",
                  big.get("isError"), True)
            says("naming the size limit", json.dumps(big), "size limit")
            oversized = last()
            check("recorded as oversize", oversized["outcome"], "oversize")
            truthy("and the tokens it spent are on the row anyway",
                   (oversized["input_tokens"] or 0) > 0)

            # Put the tool back the way it was.
            store.vet_tool(TENANT, "modelapi", {
                "remote_name": "answer",
                "effect": "read", "identity": "service",
                "description": "Ask a model a question.",
                "resources": [{"type": "modelapi.model", "args": ["model"]}],
                "binding": {
                    "method": "POST", "path": "/messages",
                    "body": ["model", "max_tokens", "messages"],
                    "input_schema": ANSWER_SCHEMA, "usage_map": USAGE_MAP,
                },
            }, actor=PRIYA)

            step("a vendor error spends nothing and says so")

            broke = call(model=MODEL, max_tokens=-5,
                         messages=[{"role": "user", "content": "hi"}])
            check("the caller is told", broke.get("isError"), True)
            errored = last()
            check("outcome is error", errored["outcome"], "error")
            check("and nothing was billed, because nothing was generated",
                  errored["input_tokens"], None)

            step("the ceiling: the crossing call completes, the next one is refused")

            spent_now = door.door_spend_today(machine)["usd"]
            # A ceiling just under what has already been spent, so the next call is the
            # one refused — read-then-decide, stated as a number.
            config.MCP_USD_PER_DAY = round(spent_now * 0.5, 10)
            blocked = ask()
            check("the next call is refused", blocked.get("isError"), True)
            reason = last()["reason"]
            says("with the door's spend marker", reason, storage.SPEND_REFUSAL_MARKER)
            says("naming the dial an operator would turn", reason,
                 "CARNET_MCP_USD_PER_DAY")
            says("and quoting the figure the screen shows", reason,
                 f"${spent_now:,.2f}")
            check("the refusal is an ordinary deny row", last()["decision"], "deny")
            check("that spent nothing itself", last()["input_tokens"], None)

            step("a spend refusal does not burn the call allowance")

            config.MCP_CALLS_PER_DAY = 1000
            calls_before = store.mcp_calls_spent(TENANT, row["id"], door.budget_window())
            for _ in range(3):
                ask()
            check("three refusals, no calls consumed",
                  store.mcp_calls_spent(TENANT, row["id"], door.budget_window()),
                  calls_before)

            step("retries never double-count, because a refusal records no usage")

            check("spend is unchanged by the refusals",
                  door.door_spend_today(machine)["usd"], spent_now)

            step("the dial off frees it again, mid-incident, with no restart")

            config.MCP_USD_PER_DAY = 0.0
            freed = ask()
            check("the same credential is served again", freed.get("isError") is not True, True)
            truthy("and the new call added to the day",
                   door.door_spend_today(machine)["usd"] > spent_now)

            step("a second credential has its own allowance")

            other_row, other_presented = tokens.mint(
                TENANT, "second-bot", "u_priya", actor="system:cli")
            store.grant_agent(TENANT, "thinker", "machine", other_row["id"],
                              role="user", granted_by=PRIYA, actor=PRIYA)
            other = Principal.machine(other_row["id"], TENANT)
            check("which starts at nothing despite the first one's spend",
                  door.door_spend_today(other)["usd"], 0)

            second_client = TestClient(create_app())
            second_answered = second_client.post("/mcp", headers={
                "Authorization": f"Bearer {other_presented}"
            }, json={
                "jsonrpc": "2.0", "id": 99, "method": "tools/call",
                "params": {"name": "modelapi_answer", "arguments": {
                    "model": MODEL, "max_tokens": 8,
                    "messages": [{"role": "user", "content": "Say: ok"}]}},
            }).json()["result"]
            check("and meters separately", second_answered.get("isError") is not True, True)
            truthy("the second token has its own figure",
                   door.door_spend_today(other)["usd"] > 0)
            truthy("and the first one's is untouched by it",
                   door.door_spend_today(machine)["usd"] > door.door_spend_today(other)["usd"])

            step("what the prompt left in the append-only log")

            prompts = [r for r in audit_rows() if r.get("args", {}).get("messages")]
            truthy("this connector's prompts are in the log, because it vets none away",
                   prompts)
            check("and in the clear, since nothing here declared a redaction",
                  any("sha256:" in str(r["args"]["messages"]) for r in prompts), False)
            print("        NOTE: that is this script's connector, not the platform's")
            print("        limit any more. 045c added `redact_args` to a vetted tool")
            print("        (migration 049) and both README recipes mark `messages`;")
            print("        `scripts/e2e_model_connector.py` drives the redacted path")
            print("        against the same live vendor. This connector is left")
            print("        unredacted on purpose, so 045b's own arc keeps asserting")
            print("        what it always asserted.")

        # --- what a vendor cannot be made to do -----------------------------------

        step("a connector that lies about its spend cannot spend somebody's ceiling")

        liar = mcp.Connector(
            id="liar",
            launch=mcp.RestLaunch(url=FAKE_URL, credential_env="LIAR_TOKEN"),
            description="A connector that reports whatever it likes.",
            vetted=[
                mcp.Vetted(
                    "report", effect="read", identity="service",
                    description="Report usage.",
                    binding={
                        "method": "POST", "path": "/say/{kind}",
                        "input_schema": {"type": "object",
                                         "properties": {"kind": {"type": "string"}},
                                         "required": ["kind"]},
                        "usage_map": USAGE_MAP,
                    },
                ),
            ],
        )
        tools.save_connector(TENANT, liar, actor=PRIYA)
        agents.save(TENANT, {
            "name": "reporter", "runtime": "simple", "system": "x",
            "permissions": {"tools": ["liar_report"], "scope": {}},
        }, actor=PRIYA)
        store.grant_agent(TENANT, "reporter", "machine", row["id"],
                          role="user", granted_by=PRIYA, actor=PRIYA)
        config.MCP_USD_PER_DAY = 0.0

        for kind in ("negative", "absurd", "text", "boolean", "partial", "smuggled"):
            result = call("liar_report", kind=kind)
            check(f"a {kind} report leaves the call working",
                  result.get("isError") is not True, True)
            check(f"and records nothing rather than a number ({kind})",
                  spend_of(last()), ("", None, None, None, None))

        honest = call("liar_report", kind="honest")
        check("while an honest report is recorded", spend_of(last()),
              (MODEL, 10, 2, 0, 0))
        check("the call still worked", honest.get("isError") is not True, True)

        step("an ordinary tool that reports nothing records NULL, never zero")

        # `liar_report` with an unknown kind answers `{"model": ...}` and no usage at all.
        call("liar_report", kind="silent")
        check("no usage reported means not-applicable, not spent-nothing",
              spend_of(last())[1:], (None, None, None, None))

        step("one tenant's door spend is never another's")

        store.create_tenant("e2eother", "Somebody else")
        other_spend = store.door_spend_since(
            "e2eother", door.day_window() if hasattr(door, "day_window")
            else __import__("carnet.core.usage", fromlist=["day_window"]).day_window(),
            principal_kind="machine", principal_id=row["id"])
        check("the same credential id in another tenant sums to nothing",
              other_spend, [])

        step("the ceiling reads the dial fresh, so an operator can turn it mid-incident")

        config.MCP_USD_PER_DAY = 0.0
        check("off means the gate does not even look",
              door.TokenBudget(machine, 1000)._over_spend_ceiling(), None)
        config.MCP_USD_PER_DAY = -1.0
        check("a negative value is off too, not a ceiling of zero",
              door.TokenBudget(machine, 1000)._over_spend_ceiling(), None)
        config.MCP_TOKENS_PER_DAY = 1
        refusal = door.TokenBudget(machine, 1000)._over_spend_ceiling()
        truthy("but a token ceiling of 1 refuses", refusal is not None)
        says("naming the token dial", getattr(refusal, "reason", ""),
             "CARNET_MCP_TOKENS_PER_DAY")
        config.MCP_TOKENS_PER_DAY = 0

        store.close()
    finally:
        server.shutdown()

    failed = [label for ok, label in CHECKS if not ok]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        print("\nFAILED:")
        for label in failed:
            print(f"  - {label}")
        raise SystemExit(1)


def _generate_key():
    import base64
    import os as _os

    return base64.b64encode(_os.urandom(32)).decode()


if __name__ == "__main__":
    sys.exit(main())
