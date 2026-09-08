"""Use the product. A real Claude, as the MCP client, against the real door.

    cd backend && uv pip install -e ".[harness]"    # the anthropic SDK, this script's alone
    .venv/bin/python scripts/use_the_product.py --yes-this-spends-money

**This is not a simulation and nothing here is written to the database by hand.** It is
the application being used, and the rows appear because of it:

    a real Claude          the Anthropic Messages API, with tool use — the same thing
                           Cursor or Claude Desktop is when it holds an MCP connection
    a real door            POST /mcp on whatever API is already running, with a real
                           machine token minted through `tokens.mint`
    a real broker          every call checked against the agent's grant and scope,
                           audited, budgeted — the product's own path, untouched
    a real vendor          DeepWiki (`mcp.deepwiki.com`), a third party on the public
                           internet, already registered and vetted in this database

The loop is the one an MCP client runs: `tools/list` to discover what it may touch, hand
the model a task and those tool definitions, and when it asks for a tool, make the call
**through the door** and hand the result back. The model decides which tool and which
arguments; nothing here scripts that. When it reaches past its scope the broker refuses
it, the refusal is audited, and the refusal text is what the model reads next — which is
how a real caller discovers the edge of its grant.

**It spends money**, which is why the flag is required. Haiku, short answers, a few
dozen sessions: cents. The other scripts here that spend are `e2e_model_connector.py`
and `e2e_door_spend.py`, under a brokered key.

**It writes to the database the running API is pointed at** — `CARNET_DATABASE_URL`
from `backend/.env` — and creates nothing except its own token. It drops nothing.
"""

import argparse
import json
import os
import pathlib
import random
import sys
import time

import httpx

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

API = os.environ.get("USE_PRODUCT_API", "http://127.0.0.1:8000")
MODEL = os.environ.get("USE_PRODUCT_MODEL", "claude-haiku-4-5-20251001")
AGENT = "repo-explainer"
TOKEN_NAME = "cursor-desktop"

# What somebody would actually ask an assistant that holds this connection. Written as
# tasks rather than as tool calls: which tool answers each one, and with what arguments,
# is the model's decision and the whole point of using a real one.
TASKS = [
    "What is the overall architecture of the anthropics/anthropic-sdk-python repo?",
    "How does anthropics/anthropic-sdk-python handle retries and timeouts?",
    "Summarise the documentation topics available for anthropics/anthropic-sdk-python.",
    "In anthropics/anthropic-sdk-python, how do the sync and async clients differ?",
    "Does anthropics/anthropic-sdk-python support streaming, and how?",
    "What error types does anthropics/anthropic-sdk-python define?",
    "How is authentication configured in anthropics/anthropic-sdk-python?",
    "What does the message batches API look like in anthropics/anthropic-sdk-python?",
    "How does anthropics/anthropic-sdk-python integrate with Bedrock or Vertex?",
    "What is the request lifecycle in anthropics/anthropic-sdk-python?",
    "How do I install and get started with anthropics/anthropic-sdk-python?",
    "What tooling does anthropics/anthropic-sdk-python use for testing?",
    # Deliberately outside the agent's scope: the grant names one repo, and these name
    # others. The model will try, the broker will refuse, and the refusal is a real
    # audited row — which is what the governance charts are about.
    "What is the architecture of the facebook/react repo?",
    "Explain how vercel/next.js does routing.",
    "Summarise the docs for openai/openai-python.",
]


def say(what):
    print(f"\n=== {what}", flush=True)


# Whom this client is acting for. A real Cursor or Claude Desktop multiplexes many
# people over one connection, so the person is named per call in `_meta` rather than
# per session — and the door believes an *asserted* address only where the connector
# opted in (`allow_asserted_identity`). Set to a real address in this tenant.
ACTING_FOR = os.environ.get("USE_PRODUCT_ACTING_FOR", "")


def door(secret, method, params=None, message_id=1, timeout=120):
    body = {"jsonrpc": "2.0", "id": message_id, "method": method}
    if params is not None:
        if ACTING_FOR and method == "tools/call":
            params = {
                **params,
                "_meta": {"com.carnet/acting-for": {"email": ACTING_FOR}},
            }
        body["params"] = params
    response = httpx.post(
        f"{API}/mcp", json=body,
        headers={"Authorization": f"Bearer {secret}"}, timeout=timeout,
    )
    try:
        return response.json()
    except Exception:
        return {"error": {"message": response.text[:400]}}


def ensure_token():
    """A machine token for this client, granted the agent — minted once and reused.

    Through `tokens.mint`, which is the only thing that can produce one: the secret is
    generated there, hashed there, and returned to exactly one caller. Saved beside this
    script so a second run is the same client coming back rather than a new one.
    """
    from carnet import storage
    from carnet.access import tokens
    from carnet.core import crypto
    from carnet.storage.postgres import PostgresStorage

    kept = pathlib.Path(__file__).parent / ".use_the_product_token"
    tenant = os.environ["CARNET_TENANT"]

    crypto.configure(crypto.from_environment())
    store = storage.configure(PostgresStorage(os.environ["CARNET_DATABASE_URL"]))

    if kept.exists():
        secret = kept.read_text().strip()
        try:
            # `resolve` raises rather than returning None — it is the door's own check,
            # so a token this refuses is one the door would refuse too.
            tokens.resolve(secret)
            store.close()
            return secret
        except Exception:
            pass

    owner = store.list_users(tenant)[0]["id"]
    row, secret = tokens.mint(tenant, TOKEN_NAME, owner, actor=f"user:{owner}")
    store.grant_agent(tenant, AGENT, "machine", row["id"], role="user",
                      granted_by=f"user:{owner}", actor=f"user:{owner}")
    store.close()

    kept.write_text(secret)
    kept.chmod(0o600)
    print(f"  minted {row['id']} and granted it '{AGENT}'")
    return secret


def as_anthropic_tools(listed):
    """The door's `tools/list` answer, in the shape the Messages API takes.

    A straight rename: MCP calls the schema `inputSchema`, the Messages API calls it
    `input_schema`. Nothing is filtered — what the door advertises is exactly what the
    model is offered, which is what makes the model's choice a real one.
    """
    return [
        {
            "name": tool["name"],
            "description": tool.get("description") or "",
            "input_schema": tool.get("inputSchema") or {"type": "object"},
        }
        for tool in listed
    ]


def session(client, secret, tools, task, counter):
    """One task, run the way an MCP client runs one: model, tool, door, model.

    Returns (turns, calls, refusals). The model may call several tools or none; both are
    real outcomes and neither is steered.
    """
    messages = [{"role": "user", "content": task}]
    calls = refusals = turns = 0

    for _ in range(6):
        turns += 1
        reply = client.messages.create(
            model=MODEL, max_tokens=700, tools=tools, messages=messages,
        )
        blocks = [
            {"type": "text", "text": b.text} if b.type == "text"
            else {"type": "tool_use", "id": b.id, "name": b.name, "input": b.input}
            for b in reply.content
        ]
        messages.append({"role": "assistant", "content": blocks})

        wants = [b for b in reply.content if b.type == "tool_use"]
        if not wants:
            answer = " ".join(b.text for b in reply.content if b.type == "text")
            print(f"    answered: {answer.strip()[:110]}")
            break

        results = []
        for want in wants:
            counter[0] += 1
            calls += 1
            print(f"    -> {want.name}({json.dumps(want.input)[:70]})")
            answer = door(
                secret, "tools/call",
                {"name": want.name, "arguments": want.input},
                message_id=counter[0],
            )
            payload = answer.get("result", {})
            text = ""
            for part in payload.get("content", []):
                if part.get("type") == "text":
                    text += part["text"]
            if not text:
                text = json.dumps(answer.get("error") or payload)[:600]
            if payload.get("isError") or "denied_by" in text or "Denied by broker" in text:
                refusals += 1
                print(f"       REFUSED: {text[:100]}")
            results.append({
                "type": "tool_result", "tool_use_id": want.id,
                "content": text[:6000],
            })
        messages.append({"role": "user", "content": results})

    return turns, calls, refusals


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--yes-this-spends-money", action="store_true")
    parser.add_argument("--tasks", type=int, default=30)
    args = parser.parse_args()

    if not args.yes_this_spends_money:
        raise SystemExit(
            "This calls the real Anthropic API and spends real money (cents).\n"
            "Re-run with --yes-this-spends-money."
        )

    import anthropic

    for needed in ("ANTHROPIC_API_KEY", "CARNET_DATABASE_URL", "CARNET_TENANT"):
        if not os.environ.get(needed):
            raise SystemExit(f"{needed} is not set — source backend/.env first")

    try:
        httpx.get(f"{API}/health", timeout=5)
    except Exception:
        raise SystemExit(
            f"nothing is answering at {API} — start the API first"
        ) from None

    say(f"a machine token for this client, against {API}")
    secret = ensure_token()

    say("tools/list — what this credential may touch")
    listed = door(secret, "tools/list", message_id=1).get("result", {}).get("tools", [])
    if not listed:
        raise SystemExit("the door advertised no tools — is the agent granted?")
    for tool in listed:
        print(f"  - {tool['name']}")
    tools = as_anthropic_tools(listed)

    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    rng = random.Random()
    counter = [1]
    totals = {"sessions": 0, "calls": 0, "refusals": 0, "turns": 0}

    say(f"using it: {args.tasks} tasks, each a real Claude deciding for itself")
    for n in range(args.tasks):
        task = TASKS[n % len(TASKS)] if n < len(TASKS) else rng.choice(TASKS)
        print(f"\n  [{n + 1}/{args.tasks}] {task}")
        try:
            turns, calls, refusals = session(client, secret, tools, task, counter)
        except Exception as exc:  # a real API can fail; the run continues
            print(f"    session failed: {type(exc).__name__}: {exc}")
            continue
        totals["sessions"] += 1
        totals["turns"] += turns
        totals["calls"] += calls
        totals["refusals"] += refusals
        time.sleep(0.4)

    say("what actually happened")
    for key, value in totals.items():
        print(f"  {key:10} {value}")
    print(f"\n  every one of those {totals['calls']} calls is a row in `audit`,")
    print("  written by the broker, with its own timestamp. Nothing was inserted.")


if __name__ == "__main__":
    main()
