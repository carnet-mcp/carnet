"""The model connector, over a real socket to a real vendor. Step 045c.

045b's script proved a model call can be brokered. This proves the three things 045c
added, and it drives the paths 045b's script had to route *around*:

    register_connector(credential_header=..., credential_prefix="", headers=...)
        -> a real vendor that reads `x-api-key` and demands a version header,
           registered the way an administrator registers one rather than through
           the wholesale `--seed` writer, which was the only reach before 045c

    --redact-arg messages
        -> a real prompt through a real model, and the append-only row holding a
           hash of it rather than the conversation

    CARNET_MODEL_RATES, keys included
        -> an operator's own key reaching an operator's own model, which returned
           $0.00 before this step however correct the file was

## Two providers, and only one of them can be real here

The claim under test is that no provider is special, which needs two. The Anthropic half
is **live** — real key, real socket, real counters, real money. The second provider is a
local HTTP server speaking OpenAI's response shape, because there is no OpenAI key in
this repository and inventing one would make a script that pretends to have dialled it.
What that costs is stated rather than hidden: the fake proves the *shape* is
provider-neutral (a different credential header, a different `usage_map`, a different
rate key, an isolated scope) and the live half proves the wire is real.

It is also the only way to demonstrate decision 3's payoff against a model the built-in
table genuinely cannot price. Every Anthropic id contains `opus`, `sonnet` or `haiku`, so
no live call can show the $0.00-before/priced-after transition that was the whole blocker.
`gpt-5-mini` can, and the fake is what serves it.

## Cost

Seven model calls at `max_tokens` 8-16 on Haiku. Well under a cent.

    cd backend && .venv/bin/python scripts/e2e_model_connector.py

Needs Postgres started, `ANTHROPIC_API_KEY` in `backend/.env`, and outbound DNS.
`--offline` runs the fake-vendor half alone.
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
DB = "carnet_e2e_model_connector"


def dsn_for(database: str) -> str:
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


DSN = dsn_for(DB)
TENANT = "e2emodel"
PRIYA = "user:u_priya"

VENDOR_HOST = "api.anthropic.com"
VENDOR_URL = f"https://{VENDOR_HOST}/v1"
MODEL = "claude-haiku-4-5-20251001"

FAKE_HOST = "localtest.me"
FAKE_PORT = 8937
FAKE_URL = f"http://{FAKE_HOST}:{FAKE_PORT}/v1"
FAKE_MODEL = "gpt-5-mini"

# The prompt whose text must not survive into the audit log. Distinctive on purpose: the
# assertion is a substring search over the whole recorded row, so a fragment that could
# occur by accident would pass for the wrong reason.
SECRET_PROMPT = "zarquon-9 severance terms"

CHAT_SCHEMA = {
    "type": "object",
    "properties": {
        "model": {"type": "string", "description": "which model to think with"},
        "max_tokens": {"type": "integer"},
        "messages": {"type": "array", "description": "the conversation so far"},
    },
    "required": ["model", "max_tokens", "messages"],
}

ANTHROPIC_USAGE_MAP = {
    "model": "model",
    "input_tokens": "usage.input_tokens",
    "output_tokens": "usage.output_tokens",
    "cache_read_tokens": "usage.cache_read_input_tokens",
    "cache_write_tokens": "usage.cache_creation_input_tokens",
}

# The same four counters under another vendor's names. Nothing between the two knows
# which provider it is reading, which is the point of having both.
OPENAI_USAGE_MAP = {
    "model": "model",
    "input_tokens": "usage.prompt_tokens",
    "output_tokens": "usage.completion_tokens",
}

# The operator's own price list. `gpt-5` is a key the built-in table has never heard of —
# that is decision 3's whole subject — and the exact dated Haiku id is here to prove
# longest-key-first: it must beat the built-in `haiku` family for the same model.
OPERATOR_RATES = {
    "gpt-5": {"input": 1.25, "output": 10.00, "cache_read": 0.125, "cache_write": 0.0},
    MODEL: {"input": 2.00, "output": 8.00, "cache_read": 0.2, "cache_write": 2.5},
}

CHECKS = []
CALLS = 0


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


class OpenAIShaped(BaseHTTPRequestHandler):
    """A second vendor, answering in OpenAI's shape. Records what it was sent."""

    protocol_version = "HTTP/1.1"
    seen = []

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        OpenAIShaped.seen.append({
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": json.loads(raw or b"{}"),
        })
        payload = {
            "model": FAKE_MODEL,
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            "usage": {"prompt_tokens": 1_000_000, "completion_tokens": 100},
        }
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
            "ANTHROPIC_API_KEY is not set. It lives in backend/.env; this script spends "
            "money, so it will not run without it. Use --offline for the fake half."
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
    os.environ["ANTHROPIC_BROKERED_KEY"] = key or "unused-offline"
    os.environ["OPENAI_BROKERED_KEY"] = "sk-fake-openai"

    from fastapi.testclient import TestClient

    from carnet import agents, config, door, storage, tools
    from carnet.access import tokens
    from carnet.api import create_app
    from carnet.core import crypto
    from carnet.core.principal import Principal
    from carnet.core.usage import estimate_cost, model_family, rates, TokenUsage
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage
    from carnet.tools import mcp
    from carnet.tools.base import Resource

    migrate.apply(DSN)
    store = storage.configure(PostgresStorage(DSN))
    crypto.configure(crypto.from_environment())
    store.create_tenant(TENANT, "045c model connector end to end")
    store.create_user(TENANT, {"id": "u_priya", "issuer": "https://idp.example",
                               "subject": "00u1", "email": "priya@acme.com"})

    server = ThreadingHTTPServer(("127.0.0.1", FAKE_PORT), OpenAIShaped)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def last():
        return store.audit_records(TENANT)[-1]

    rates_file = pathlib.Path(os.environ.get("TMPDIR", "/tmp")) / "e2e_model_rates.json"

    try:
        step("migration 049 is on this database, with the shape 045c needs")

        with psycopg.connect(DSN) as conn:
            column = conn.execute(
                "SELECT data_type, is_nullable, column_default FROM "
                "information_schema.columns WHERE table_name = 'vetted_tools' "
                "AND column_name = 'redact_args'"
            ).fetchone()
        check("vetted_tools.redact_args exists as jsonb", column[0], "jsonb")
        check("NOT NULL, because every tool has an answer", column[1], "NO")
        says("defaulting to the empty list, which is what every older row meant",
             column[2], "[]")

        step("both providers registered the way an administrator registers one")

        store.allow_host(TENANT, VENDOR_HOST, actor=PRIYA, note="the model vendor")
        store.allow_host(TENANT, FAKE_HOST, actor=PRIYA, note="the second provider")

        # **`register_connector`, not `save_connector`.** 045b's script had to use the
        # wholesale manifest writer with a comment saying why; this is the reach that
        # was missing, and a wrong header here is a 401 from a real vendor rather than
        # an assertion this script gets to make about itself.
        tools.register_connector(
            TENANT, "anthropic", url=VENDOR_URL, kind="rest",
            credential_env="ANTHROPIC_BROKERED_KEY",
            credential_header="x-api-key", credential_prefix="",
            headers={"anthropic-version": "2023-06-01"},
            description="Anthropic, the Messages API", actor=PRIYA,
        )
        tools.register_connector(
            TENANT, "openai", url=FAKE_URL, kind="rest",
            credential_env="OPENAI_BROKERED_KEY",
            description="A second provider, chat completions only", actor=PRIYA,
        )

        anthropic = mcp.get_connector(TENANT, "anthropic").launch
        openai = mcp.get_connector(TENANT, "openai").launch
        check("the vendor's own header survived the round trip",
              anthropic.credential_header, "x-api-key")
        check("and an EMPTY prefix stayed empty rather than becoming 'Bearer '",
              anthropic.credential_prefix, "")
        check("its non-secret version header is stored beside it",
              anthropic.headers, {"anthropic-version": "2023-06-01"})
        check("the other provider kept the default nobody set",
              (openai.credential_header, openai.credential_prefix),
              ("Authorization", "Bearer "))

        step("vetting authors the binding, the scope resource and the redaction")

        for connector, usage_map, path in (
            ("anthropic", ANTHROPIC_USAGE_MAP, "/messages"),
            ("openai", OPENAI_USAGE_MAP, "/chat/completions"),
        ):
            tools.vet_tool(
                TENANT, connector, "chat", effect="write",
                resources=(Resource(f"{connector}.model", "model"),),
                actor=PRIYA, description=f"Think with a model on {connector}.",
                redact_args=("messages",),
                binding={"method": "POST", "path": path,
                         "body": ["model", "max_tokens", "messages"],
                         "input_schema": CHAT_SCHEMA, "usage_map": usage_map},
            )
        vetted = mcp.get_connector(TENANT, "anthropic").vetted[0]
        check("the redaction is on the stored approval", list(vetted.redact_args), ["messages"])

        says("a redaction naming an argument the schema lacks is refused at the form",
             _refusal(lambda: tools.vet_tool(
                 TENANT, "anthropic", "chat", effect="write",
                 resources=(Resource("anthropic.model", "model"),), actor=PRIYA,
                 description="d", redact_args=("mesages",),
                 binding={"method": "POST", "path": "/messages",
                          "body": ["model", "max_tokens", "messages"],
                          "input_schema": CHAT_SCHEMA, "usage_map": ANTHROPIC_USAGE_MAP})),
             "mesages")

        step("one scope line per provider, and a wildcard that stays inside its own")

        agents.save(TENANT, {
            "name": "thinker",
            "runtime": "simple",
            "system": "You answer questions.",
            "permissions": {
                "tools": ["anthropic_chat", "openai_chat"],
                "scope": {
                    "anthropic.model": {"write": [MODEL]},
                    "openai.model": {"write": ["*"]},
                },
            },
        }, actor=PRIYA)

        row, presented = tokens.mint(TENANT, "priya-cursor", "u_priya", actor="system:cli")
        store.grant_agent(TENANT, "thinker", "machine", row["id"],
                          role="user", granted_by=PRIYA, actor=PRIYA)
        machine = Principal.machine(row["id"], TENANT)
        client = TestClient(create_app())
        auth = {"Authorization": f"Bearer {presented}"}

        def call(name, **arguments):
            global CALLS
            CALLS += 1
            return client.post("/mcp", headers=auth, json={
                "jsonrpc": "2.0", "id": CALLS, "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }).json()["result"]

        def ask(text="Say the single word: ok", model=MODEL, max_tokens=16, **extra):
            return call("anthropic_chat", model=model, max_tokens=max_tokens,
                        messages=[{"role": "user", "content": text}], **extra)

        listed = client.post("/mcp", headers=auth, json={
            "jsonrpc": "2.0", "id": 0, "method": "tools/list",
        }).json()["result"]["tools"]
        check("the door serves both as ordinary tools",
              sorted(t["name"] for t in listed), ["anthropic_chat", "openai_chat"])

        # --- the second provider, which is local ---------------------------------

        step("the second provider: another header, another usage_map, another rate key")

        answered = call("openai_chat", model=FAKE_MODEL, max_tokens=8,
                        messages=[{"role": "user", "content": "hello"}])
        check("it answered", answered.get("isError") is not True, True)
        sent = OpenAIShaped.seen[-1]
        check("presented as Authorization: Bearer, which nobody had to configure",
              sent["headers"].get("authorization"), "Bearer sk-fake-openai")
        record = last()
        check("its own spelling of the counters reached our columns",
              (record["model"], record["input_tokens"], record["output_tokens"]),
              (FAKE_MODEL, 1_000_000, 100))

        step("the blocker 045c existed to remove")

        usage = TokenUsage(input_tokens=1_000_000, output_tokens=100)
        check("the built-in table cannot price this vendor's model at all",
              model_family(FAKE_MODEL), "")
        check("so it costs nothing however many tokens it burned",
              estimate_cost(FAKE_MODEL, usage), None)
        check("and the operator's own key reaches it",
              model_family(FAKE_MODEL, OPERATOR_RATES), "gpt-5")
        truthy("pricing it for real",
               estimate_cost(FAKE_MODEL, usage, OPERATOR_RATES) > 1.2)

        rates_file.write_text(json.dumps(OPERATOR_RATES))
        config.MODEL_RATES_PATH = str(rates_file)
        priced = door.door_spend_today(machine)
        check("with the file in force the door prices it", priced["unpriced_models"], [])
        truthy("above zero", priced["usd"] > 1.2)

        config.MODEL_RATES_PATH = ""
        unpriced = door.door_spend_today(machine)
        check("without it the same tokens are named as unpriced",
              unpriced["unpriced_models"], [FAKE_MODEL])
        check("and cost nothing", unpriced["usd"], 0)
        check("while the token count is identical either way — rates change what a "
              "number is worth, never what was counted",
              unpriced["tokens"], priced["tokens"])

        step("longest key first, so an exact contract price beats a family list price")

        check("the built-in table reads the family", model_family(MODEL), "haiku")
        check("the operator's exact dated key wins over the built-in family",
              model_family(MODEL, OPERATOR_RATES), MODEL)

        step("scope: a model is a resource, namespaced per provider")

        leaked = call("anthropic_chat", model=FAKE_MODEL, max_tokens=8,
                      messages=[{"role": "user", "content": "hi"}])
        check("a wildcard on one provider reaches nothing on the other",
              leaked.get("isError"), True)
        says("refused by the ordinary matcher, naming the resource type",
             last()["reason"], "anthropic.model")
        check("and the refusal wrote a deny row rather than dialling",
              last()["decision"], "deny")

        step("an argument outside the authored schema is refused, not dropped")

        streamed = ask(stream=True)
        check("stream: true does not reach the vendor", streamed.get("isError"), True)
        says("and the caller is told why", json.dumps(streamed), "stream")

        if offline:
            print("\nSKIPPED: every live model call — --offline, so no vendor was dialled "
                  "and nothing was spent; the live half is unproven by this run")
        else:
            step("a real brokered model call, through the header the vendor demands")

            answered = ask()
            if answered.get("isError"):
                print(f"        vendor/door said: {json.dumps(answered)[:500]}")
            check("the live call succeeded — a wrong header would be a 401 here",
                  answered.get("isError") is not True, True)
            body = json.loads(answered["content"][0]["text"])
            truthy("the vendor answered with content", body.get("content"))

            record = last()
            check("the vendor's own input counter is on the row",
                  record["input_tokens"], body["usage"]["input_tokens"])
            check("and its own output counter",
                  record["output_tokens"], body["usage"]["output_tokens"])
            check("recorded under the model that actually answered",
                  record["model"], body["model"])
            check("as a door call, with no runs row anywhere",
                  (record["run_id"].startswith(storage.DOOR_CALL_ID_PREFIX),
                   list(store.list_runs(TENANT))), (True, []))

            step("what a real prompt left in the append-only log")

            ask(text=SECRET_PROMPT)
            record = last()
            recorded = json.dumps(record)
            check("the prompt is nowhere in the row", SECRET_PROMPT in recorded, False)
            says("it is a hash of it", record["args"]["messages"], "sha256:")
            says("with the length, so a reader knows something was there",
                 record["args"]["messages"], "len=")
            check("while the scoped argument stays readable, because scope is reviewable",
                  record["args"]["model"], MODEL)
            check("and the call itself worked", record["decision"], "allow")
            truthy("and was metered", record["input_tokens"] > 0)

            # The whole table, not just this row: a redaction that applied to the
            # allowed call and not the denied one would leak every refused prompt.
            everything = json.dumps(store.audit_records(TENANT))
            check("no prompt text anywhere in the tenant's whole audit log",
                  SECRET_PROMPT in everything, False)

            step("a refused call's prompt is redacted too — the direction that matters")

            call("anthropic_chat", model="claude-opus-4-nope", max_tokens=8,
                 messages=[{"role": "user", "content": SECRET_PROMPT}])
            denied = last()
            check("refused by scope", denied["decision"], "deny")
            says("and its prompt is a hash, not the conversation",
                 denied["args"]["messages"], "sha256:")
            check("nothing of it in the clear", SECRET_PROMPT in json.dumps(denied), False)

            step("the operator's own prices, on real spend, refusing the next call")

            config.MODEL_RATES_PATH = str(rates_file)
            check("the report says which list it used", config.model_rates_label(),
                  str(rates_file))
            spend = door.door_spend_today(machine)
            truthy("priced against the operator's contract, not the snapshot",
                   spend["usd"] > 0)
            check("nothing unpriced", spend["unpriced_models"], [])

            config.MCP_USD_PER_DAY = round(spend["usd"] / 2, 6)
            refused = ask()
            check("the next call is refused on money", refused.get("isError"), True)
            says("naming the dial an operator would raise", last()["reason"],
                 "CARNET_MCP_USD_PER_DAY")
            says("and marking it a spend refusal", last()["reason"],
                 storage.SPEND_REFUSAL_MARKER)
            config.MCP_USD_PER_DAY = 0.0

            step("the token ceiling is the one that bounds an unpriced provider")

            config.MODEL_RATES_PATH = ""
            after = door.door_spend_today(machine)
            says("the fake provider is named as unpriced with no rate file",
                 after["unpriced_models"], FAKE_MODEL)
            check("and the dollar figure excludes it", after["usd"] < spend["usd"], True)
            config.MCP_TOKENS_PER_DAY = 1000
            stopped = ask()
            check("the token net refuses regardless of price", stopped.get("isError"), True)
            says("naming the vendor-neutral dial", last()["reason"],
                 "CARNET_MCP_TOKENS_PER_DAY")
            says("and naming what the dollar figure could not value", last()["reason"],
                 FAKE_MODEL)
            config.MCP_TOKENS_PER_DAY = 0

        step("a malformed rate file: the ceiling holds, the report says which file")

        rates_file.write_text(json.dumps({"gpt-5": {"input": -1, "output": 1,
                                                    "cache_read": 1, "cache_write": 1}}))
        config.MODEL_RATES_PATH = str(rates_file)
        check("a negative rate is refused rather than making spend fall",
              _refusal(config.model_rates) is not None, True)
        says("with the file named", _refusal(config.model_rates), str(rates_file))
        check("and the door degrades to list prices rather than refusing the day",
              rates(), None)

        rates_file.write_text(json.dumps(["gpt-5"]))
        says("a table that is not an object is a sentence, not an AttributeError",
             _refusal(config.model_rates), "not a list")
        config.MODEL_RATES_PATH = ""

        step("086: a scope line that names a family rather than a dated id")

        # 080's E8, driven rather than argued. `core/patterns.py` compares whole segments
        # split on "/" and a model id has no separator, so before this the only two
        # expressible policies over a model were *this exact dated id* and *every model
        # on this vendor* — and a new dated release of the same family failed closed
        # until somebody edited every scope naming it.
        agents.save(TENANT, {
            "name": "thinker", "runtime": "simple", "system": "You answer questions.",
            "permissions": {
                "tools": ["anthropic_chat", "openai_chat"],
                "scope": {
                    "anthropic.model": {"write": ["claude-haiku-*"]},
                    "openai.model": {"write": ["*"]},
                },
            },
        }, actor=PRIYA)
        wildcard = ask()
        check("a prefix wildcard is one literal segment and matches nothing",
              wildcard.get("isError"), True)
        says("refused by the ordinary matcher", last()["reason"], "anthropic.model")

        # The fix is not a prefix wildcard — that is the bug the matcher exists to make
        # inexpressible. It is a family the vetter declares, matched as a run of whole
        # tokens, with the matcher untouched.
        tools.vet_tool(
            TENANT, "anthropic", "chat", effect="write",
            resources=(Resource("anthropic.model", "model",
                                families=("opus", "sonnet", "haiku")),),
            actor=PRIYA, description="Think with a model on anthropic.",
            redact_args=("messages",),
            binding={"method": "POST", "path": "/messages",
                     "body": ["model", "max_tokens", "messages"],
                     "input_schema": CHAT_SCHEMA, "usage_map": ANTHROPIC_USAGE_MAP},
        )
        agents.save(TENANT, {
            "name": "thinker", "runtime": "simple", "system": "You answer questions.",
            "permissions": {
                "tools": ["anthropic_chat", "openai_chat"],
                "scope": {
                    "anthropic.model": {"write": ["haiku"]},
                    "openai.model": {"write": ["*"]},
                },
            },
        }, actor=PRIYA)

        # The release nobody has seen yet, answered with no call: the vendor would 404 an
        # id it does not serve, and what is under test is the door's verdict.
        future = door.simulate(machine, "anthropic_chat",
                               {"model": "claude-haiku-9-9-29991231",
                                "max_tokens": 8, "messages": []})
        check("a dated id this deployment has never seen is admitted by family",
              future["verdict"], "allowed")
        larger = door.simulate(machine, "anthropic_chat",
                               {"model": "claude-opus-5-20260910",
                                "max_tokens": 8, "messages": []})
        check("and a family narrows — it is not a wildcard with extra words",
              larger["verdict"], "refused")
        says("naming the family it derived, so the word that would have worked is said",
             larger["reason"], "family 'opus'")

        step("086: a price on the binding, with no rate file anywhere")

        # 080's E5. `config.MODEL_RATES_PATH` is "" for the rest of this script, so the
        # deployment's table is the built-in three and cannot value a GPT id at all —
        # which is the state every customer registering a second provider starts in.
        config.MODEL_RATES_PATH = ""
        before = door.door_spend_today(machine)
        says("with no price anywhere the door names the model as unpriced",
             before["unpriced_models"], FAKE_MODEL)

        tools.vet_tool(
            TENANT, "openai", "chat", effect="write",
            resources=(Resource("openai.model", "model", families=("gpt-5", "gpt-4")),),
            actor=PRIYA, description="Think with a model on openai.",
            redact_args=("messages",),
            binding={"method": "POST", "path": "/chat/completions",
                     "body": ["model", "max_tokens", "messages"],
                     "input_schema": CHAT_SCHEMA, "usage_map": OPENAI_USAGE_MAP,
                     "pricing": OPERATOR_RATES},
        )
        after_price = door.door_spend_today(machine)
        check("the price the person with the key wrote makes the figure a figure",
              after_price["unpriced_models"], [])
        truthy("and it is the same arithmetic the file produced",
               after_price["usd"] > 1.2)

        # **The write path the vet flags do not cross.** `save_connector` is `--seed` and
        # any manifest writer, and until 086's edge pass drove it, the rate rules lived
        # one layer above the storage boundary — so a seeded `{"gpt-5": {}}` stored fine
        # and made every metered door call in that tenant raise `KeyError: 'input'` out
        # of `estimate_cost`. Driven here against the real database, because that is
        # where it was found and a unit test over a fake would not have found it.
        seeded = dict(store.get_connector(TENANT, "openai"))
        seeded["vetted"] = [dict(v) for v in seeded["vetted"]]
        seeded["vetted"][0]["binding"] = dict(seeded["vetted"][0]["binding"],
                                              pricing={"gpt-5": {}})
        says("a rate object with no counters is refused by the wholesale write too",
             _refusal(lambda: store.save_connector(TENANT, seeded, actor=PRIYA)),
             "missing")

        seeded["vetted"][0]["binding"] = dict(
            seeded["vetted"][0]["binding"],
            pricing={"gpt-5": {"input": float("inf"), "output": 1.0,
                               "cache_read": 0.0, "cache_write": 0.0}})
        says("and an infinite rate, which would refuse every call forever",
             _refusal(lambda: store.save_connector(TENANT, seeded, actor=PRIYA)),
             "not finite")

        says("a negative rate on a binding is refused where the vetter is standing",
             _refusal(lambda: tools.vet_tool(
                 TENANT, "openai", "chat", effect="write",
                 resources=(Resource("openai.model", "model"),), actor=PRIYA,
                 description="d", redact_args=("messages",),
                 binding={"method": "POST", "path": "/chat/completions",
                          "body": ["model", "max_tokens", "messages"],
                          "input_schema": CHAT_SCHEMA, "usage_map": OPENAI_USAGE_MAP,
                          "pricing": {"gpt-5": {"input": -1, "output": 1,
                                                "cache_read": 1, "cache_write": 1}}})),
             "negative")

        if not offline:
            step("086: the family scope, against the real vendor, over a real socket")

            # The one thing no fake can show: a scope naming a family admitting a call
            # the vendor actually served and billed. 045b's live run is where this gap
            # was found; this is the same wire proving it closed.
            config.MCP_USD_PER_DAY = 0.0
            config.MCP_TOKENS_PER_DAY = 0
            lived = ask()
            if lived.get("isError"):
                print(f"        vendor/door said: {json.dumps(lived)[:500]}")
            check("a family scope admitted a real model call",
                  lived.get("isError") is not True, True)
            record = last()
            check("scoped by family, recorded by exact id",
                  record["args"]["model"], MODEL)
            check("allowed, and metered off the wire",
                  (record["decision"], record["input_tokens"] > 0), ("allow", True))

        step("the platform's own model key is still not a connector credential")

        # Step 050 moved this from a one-name denylist (`PLATFORM_SECRETS`) to a
        # predicate over the platform's whole surface, enforced at registration as
        # well as at the credential read — so the connector can no longer even be
        # registered, and the refusal is the earlier, better one.
        check("ANTHROPIC_API_KEY is the platform's by name (050's predicate)",
              config.is_platform_env("ANTHROPIC_API_KEY"), True)
        says("and registering a connector that names it is refused at the door",
             _refusal(lambda: tools.register_connector(
                 TENANT, "borrowed", url=VENDOR_URL, kind="rest",
                 credential_env="ANTHROPIC_API_KEY", actor=PRIYA)),
             "ANTHROPIC_API_KEY")

    finally:
        server.shutdown()
        if rates_file.exists():
            rates_file.unlink()

    failed = [label for ok, label in CHECKS if not ok]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        print("\nFAILED:")
        for label in failed:
            print(f"  - {label}")
        raise SystemExit(1)


def _refusal(thunk):
    """Run `thunk` and return the refusal it raised, or None if it did not raise."""
    try:
        thunk()
    except Exception as exc:  # noqa: BLE001 - the refusal is the assertion
        return f"{type(exc).__name__}: {exc}"
    return None


def _generate_key():
    import base64
    import os as _os

    return base64.b64encode(_os.urandom(32)).decode()


if __name__ == "__main__":
    sys.exit(main())
