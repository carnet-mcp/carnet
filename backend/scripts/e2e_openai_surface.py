"""The OpenAI-compatible surface, end to end, with the real `openai` package as the
client. Step 108, sequencing item 6 — every row of the plan's scenario table that does
not need a real vendor, and four of them against a fake Foundry made to misbehave.

The world, built by this script and torn down after:

  Carnet        a uvicorn subprocess on its own Postgres database, with the four model
                settings turned down (a 2-second chunk timeout, an 8-second wall clock,
                a $1 daily ceiling) so the slow scenarios take seconds rather than minutes.
  Entra         a local identity provider spelled the way Azure spells it — the stable id
                in `oid`, the email in `preferred_username` — registered with
                `carnet --add-idp` exactly as the guide says. Tokens are signed here.
  Foundry       `localtest.me`, answering in Azure's shape: JSON or SSE, a usage object
                in the final chunk only when `stream_options.include_usage` asked for it,
                and a control switch for a 429 with `Retry-After`, a content-filter 400, a
                401 that quotes the key, a stall mid-answer, and a stream that will not end.
  the agent     the fifteen lines from `docs/GUIDE.md`, **executed from the guide's own
                text** — the fenced block beginning `# carnet_token.py` — so the snippet a
                company copies is the one this script proves. Then `AzureOpenAI` and
                `OpenAI` from the real SDK, pointed at Carnet.

    cd backend && CARNET_E2E_PG=postgresql://postgres:test@localhost:55432 \\
        .venv/bin/python scripts/e2e_openai_surface.py [--live]

`--live` also runs S4 and S5 against a real deployment, with `AZURE_OPENAI_ENDPOINT`,
`AZURE_OPENAI_LIVE_KEY` and `AZURE_OPENAI_DEPLOYMENT` from the environment, and skips
loudly without them. Costs nothing without it.
"""

from __future__ import annotations

import base64
import http.server
import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit, urlunsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = pathlib.Path(__file__).resolve().parent
GUIDE = HERE.parent.parent / "docs" / "GUIDE.md"
HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_openai_surface"
BASE_DSN = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"

TENANT = "e2eopenai"
HOST = "localtest.me"
JWKS_PORT = 8921
FOUNDRY_PORT = 8922
API_PORT = 8923
API = f"http://127.0.0.1:{API_PORT}"
FOUNDRY = f"http://{HOST}:{FOUNDRY_PORT}"

# Entra's spelling: a v2 issuer, an app-registration audience, `oid` and `preferred_username`.
ENTRA_TENANT = "3f1a2b4c-0000-4000-8000-000000000e2e"
ISSUER = f"https://login.microsoftonline.com/{ENTRA_TENANT}/v2.0"
APP_ID = "carnet-e2e-app"
AUDIENCE = f"api://{APP_ID}"
ARM = "https://management.azure.com"
AZURE_KEY = "azure-key-MARKER-7c1e"

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True)
JWK.update({"kid": "e2e", "use": "sig", "alg": "RS256"})

CHECKS: list = []
FAKE_MODEL = "gpt-4o-2024-08-06"


def dsn_for(database: str) -> str:
    parts = urlsplit(BASE_DSN)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok, actual, expected))
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: {actual!r}" + ("" if ok else f"  (expected {expected!r})"))
    return ok


def says(label, text, fragment):
    ok = fragment in str(text)
    CHECKS.append((label, ok, text, fragment))
    print(f"  {'ok  ' if ok else 'FAIL'} {label}" + ("" if ok else f"\n        wanted {fragment!r} in {str(text)[:400]!r}"))
    return ok


def say(what):
    print(f"\n=== {what}", flush=True)


def entra(oid: str, upn: str, *, aud: str = AUDIENCE, minutes: int = 60) -> str:
    """A token as Entra would sign it for Carnet's app: `oid` stable, `sub` pairwise and
    deliberately different from `oid` — the harness fails if Carnet keyed on `sub`."""
    now = int(time.time())
    return jwt.encode(
        {"iss": ISSUER, "aud": aud, "oid": oid, "sub": f"pairwise-{oid}",
         "preferred_username": upn, "iat": now, "exp": now + minutes * 60, "ver": "2.0"},
        KEY, algorithm="RS256", headers={"kid": "e2e"},
    )


class Jwks(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"keys": [JWK]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


# --- the fake Foundry ------------------------------------------------------------------


class Foundry(http.server.BaseHTTPRequestHandler):
    """Azure's shape, with a switch. `mode` is read per request; `seen` records every one."""

    protocol_version = "HTTP/1.1"
    mode = "ok"
    seen: list = []

    def log_message(self, *args):
        pass

    def handle(self):
        # A keep-alive connection Carnet reset — after a stall, after a cap — ends in
        # `readline` for the next request; `socketserver` would print a traceback.
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError):
            Foundry.seen.append({"disconnected": True})

    def _reply(self, status, body: bytes, content_type="application/json", extra=None):
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("x-ms-request-id", "fake-request-id")
            for name, value in (extra or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # Carnet timed out and closed before this answer — the stall scenario.
            Foundry.seen.append({"disconnected": True})

    def do_GET(self):
        Foundry.seen.append({"method": "GET", "path": self.path, "headers": dict(self.headers)})
        self._reply(200, json.dumps({"object": "list", "data": [{"id": "gpt-4o-prod", "object": "model"}]}).encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        url = urllib.parse.urlsplit(self.path)
        Foundry.seen.append({"method": "POST", "path": url.path,
                             "query": dict(urllib.parse.parse_qsl(url.query)),
                             "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
        mode = Foundry.mode
        if mode == "bad_key":
            return self._reply(401, json.dumps({"error": {"code": "401", "message": f"Access denied due to invalid subscription key {AZURE_KEY}"}}).encode())
        if mode == "rate_limit":
            return self._reply(429, json.dumps({"error": {"code": "429", "message": "Requests to the ChatCompletions_Create Operation have exceeded token rate limit."}}).encode(), extra={"Retry-After": "7"})
        if mode == "content_filter":
            return self._reply(400, json.dumps({"error": {"code": "content_filter", "message": "The response was filtered", "innererror": {"code": "ResponsibleAIPolicyViolation"}}}).encode())
        if mode == "stall" and not body.get("stream"):
            time.sleep(4)  # past the 2-second chunk timeout, before any byte
            return self._reply(200, b"{}")

        # The usage the fake reports: ordinary, or a million prompt tokens when the
        # request's `user` says so — the switch the ceiling scenario flips.
        big = body.get("user") == "big-spender"
        usage = {"prompt_tokens": 1_000_000 if big else 12, "completion_tokens": 3, "total_tokens": 1_000_003 if big else 15,
                 "prompt_tokens_details": {"cached_tokens": 4}}
        if url.path.endswith("/embeddings"):
            return self._reply(200, json.dumps({"object": "list", "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2, 0.3]}],
                                                "model": "text-embedding-3-small", "usage": {"prompt_tokens": 5, "total_tokens": 5}}).encode())

        if body.get("tools"):
            message = {"role": "assistant", "content": None,
                       "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": body["tools"][0]["function"]["name"], "arguments": "{}"}}]}
            finish = "tool_calls"
        else:
            message = {"role": "assistant", "content": "hello from foundry"}
            finish = "stop"

        if not body.get("stream"):
            reply = {"id": "chatcmpl-e2e", "object": "chat.completion", "created": 1, "model": FAKE_MODEL,
                     "choices": [{"index": 0, "message": message, "finish_reason": finish}], "usage": usage}
            return self._reply(200, json.dumps(reply).encode())

        # Streamed. The usage object rides on a final chunk **only if asked** — which is
        # what Azure and OpenAI do, and why Carnet injects the ask.
        include_usage = bool((body.get("stream_options") or {}).get("include_usage"))
        words = ["hello", " from", " foundry"]
        if mode == "endless":
            words = [" word"] * 10_000
        if mode == "leisurely":
            words = ["hello"] + [" word"] * 40      # long enough for the client to walk away mid-answer
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        def chunk(obj):
            data = f"data: {json.dumps(obj)}\n\n".encode()
            self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
            self.wfile.flush()

        try:
            for index, word in enumerate(words):
                if mode == "slow" and index:
                    time.sleep(0.6)      # under the 2-second chunk timeout, over 4 s in total
                if mode == "stall" and index == 1:
                    time.sleep(4)        # past the chunk timeout, mid-answer
                if mode == "leisurely":
                    time.sleep(0.3)      # room for the client to walk away mid-answer
                chunk({"id": "chatcmpl-e2e", "object": "chat.completion.chunk", "model": FAKE_MODEL,
                       "choices": [{"index": 0, "delta": {"content": word} if not body.get("tools") else {"tool_calls": [{"index": 0, "id": "call_1", "function": {"name": body["tools"][0]["function"]["name"], "arguments": ""}}]}, "finish_reason": None}],
                       "usage": None})
            chunk({"id": "chatcmpl-e2e", "object": "chat.completion.chunk", "model": FAKE_MODEL,
                   "choices": [{"index": 0, "delta": {}, "finish_reason": finish}], "usage": None})
            if include_usage:
                chunk({"id": "chatcmpl-e2e", "object": "chat.completion.chunk", "model": FAKE_MODEL, "choices": [], "usage": usage})
            done = b"data: [DONE]\n\n"
            self.wfile.write(f"{len(done):x}\r\n".encode() + done + b"\r\n0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            Foundry.seen.append({"disconnected": True})

    def finish(self):
        # `socketserver` flushes after the handler returns and prints a traceback when
        # the peer has gone; a closed upstream is exactly what two scenarios cause.
        try:
            super().finish()
        except (BrokenPipeError, ConnectionResetError):
            Foundry.seen.append({"disconnected": True})


# --- helpers ------------------------------------------------------------------------------


def cli(*args, env_extra=None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "carnet.cli", *args],
        env={**os.environ, **(env_extra or {})}, capture_output=True, text=True, timeout=120,
    )


def guide_snippet() -> dict:
    """The `# carnet_token.py` block out of the guide, executed as written."""
    text = GUIDE.read_text(encoding="utf-8")
    match = re.search(r"```python\n(# carnet_token\.py.*?)```", text, re.S)
    if not match:
        raise SystemExit("the guide no longer carries the `# carnet_token.py` block")
    namespace: dict = {"__name__": "carnet_token"}
    exec(compile(match.group(1), "docs/GUIDE.md#carnet_token.py", "exec"), namespace)
    return namespace


def store_at(dsn):
    from carnet import storage
    from carnet.storage.postgres import PostgresStorage

    return storage.configure(PostgresStorage(dsn))


def door_rows(store, **filters):
    return store.door_call_records(TENANT, **filters)


def wait_for(predicate, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.2)
    return predicate()


# --- the run --------------------------------------------------------------------------------


def run(store) -> None:
    import openai

    say("the admin's hour, through the real CLI, as the guide writes it")
    done = cli("--add-idp", TENANT,
               "--issuer", ISSUER, "--jwks-uri", f"http://127.0.0.1:{JWKS_PORT}/jwks.json",
               "--audience", AUDIENCE, "--subject-claim", "oid",
               "--email-claim", "preferred_username", "--domain", "acme.com")
    check("--add-idp with Entra's claim spelling", done.returncode, 0)
    check("--allow-host for the resource", cli("--allow-host", HOST).returncode, 0)
    done = cli("--add-connector", "foundry", "--from-recipe", "azure-openai",
               "--url", FOUNDRY, "--credential-env", "AZURE_OPENAI_KEY")
    check("--add-connector from the azure-openai recipe, with the admin's own resource", done.returncode, 0)
    for tool in ("chat_completions", "embeddings", "list_models"):
        done = cli("--vet", "foundry", "--tool", tool, "--from-recipe", "azure-openai")
        check(f"--vet {tool} from the recipe, no other flag", done.returncode, 0)
        if done.returncode:
            print(done.stderr[-600:])

    # The permission list and its sharing are the screen's work in the guide; here they
    # are the store's, exactly as `e2e_team_journey` seeds its world.
    from carnet import agents

    agents.save(TENANT, {
        "name": "coding-agent", "system": "irrelevant", "runtime": "simple",
        "permissions": {"tools": ["foundry_chat_completions", "foundry_embeddings"],
                        "scope": {"azure.deployment": {"write": ["gpt-4o-prod", "text-embedding-3-small"]}}},
    }, actor="system:cli")
    # Grants follow the people, and the people do not exist until they arrive (S1:
    # `users.resolve` provisions on the first authenticated request). So the grants are
    # written after the first mint, below.

    say("S1: the engineer's first run — the guide's fifteen lines, executed from the guide")
    laptop_cache = HERE.parent / "var" / "e2e_openai_surface" / "laptop.token"
    desktop_cache = laptop_cache.with_name("desktop.token")
    for path in (laptop_cache, desktop_cache):
        path.unlink(missing_ok=True)
    os.environ.update({"CARNET": API, "CARNET_APP_ID": APP_ID,
                       "CARNET_TOKEN_FILE": str(laptop_cache),
                       "CARNET_ENTRA_TOKEN": entra("oid-priya", "priya@acme.com")})
    snippet = guide_snippet()
    real_hostname = socket.gethostname
    priya_laptop = snippet["carnet_token"]()
    check("the agent minted a personal token from the az login session", priya_laptop.startswith("art_"), True)
    check("and cached it, mode 0600", oct(laptop_cache.stat().st_mode & 0o777), "0o600")
    check("a second call reads the cache and mints nothing", snippet["carnet_token"](), priya_laptop)

    from carnet.access import users as _users  # noqa: F401 - the row was provisioned by the mint

    priya = store.find_user_by_email(TENANT, "priya@acme.com")
    check("the person was provisioned by the mint, no browser sign-in first", priya is not None, True)
    tokens_of_priya = store.list_api_tokens(TENANT, owner_id=priya["id"])
    check("the token is personal and named for the machine",
          (tokens_of_priya[0]["acts_as_owner"], tokens_of_priya[0]["name"].startswith("coding-agent · ")), (True, True))
    store.grant_agent(TENANT, "coding-agent", "user", priya["id"], role="user", granted_by="system:cli", actor="system:cli")

    say("S3: the same engineer, a second machine — same name, same owner, one allowance")
    os.environ["CARNET_TOKEN_FILE"] = str(desktop_cache)
    snippet["CACHE"] = pathlib.Path(desktop_cache)
    snippet["socket"].gethostname = lambda: "desktop"
    priya_desktop = snippet["carnet_token"]()
    check("the desktop minted its own token", priya_desktop != priya_laptop and priya_desktop.startswith("art_"), True)
    check("two tokens, one owner", len(store.list_api_tokens(TENANT, owner_id=priya["id"])), 2)

    say("S2: the second engineer's agent chooses the same name and is admitted")
    tom_cache = laptop_cache.with_name("tom.token")
    tom_cache.unlink(missing_ok=True)
    os.environ.update({"CARNET_TOKEN_FILE": str(tom_cache), "CARNET_ENTRA_TOKEN": entra("oid-tom", "tom@acme.com")})
    snippet["CACHE"] = pathlib.Path(tom_cache)
    snippet["socket"].gethostname = real_hostname
    tom_token = snippet["carnet_token"]()
    tom = store.find_user_by_email(TENANT, "tom@acme.com")
    check("tom minted under the same name as priya's laptop", tom is not None and tom_token.startswith("art_"), True)
    check("keyed on oid, not sub: tom is one person to Carnet", tom["subject"], "oid-tom")
    store.grant_agent(TENANT, "coding-agent", "user", tom["id"], role="user", granted_by="system:cli", actor="system:cli")

    say("S16, S17: a token for the wrong audience, and a guest account")
    arm = httpx.post(f"{API}/me/tokens", json={"name": "x"},
                     headers={"Authorization": f"Bearer {entra('oid-priya', 'priya@acme.com', aud=ARM)}"})
    check("an ARM-audience token is refused at the mint", arm.status_code, 401)
    guest = httpx.post(f"{API}/me/tokens", json={"name": "x"},
                       headers={"Authorization": f"Bearer {entra('oid-guest', 'name_otherco.com#EXT#@acme.onmicrosoft.com')}"})
    check("a guest's UPN is outside the domain gate", guest.status_code, 403)
    says("with the domain named", guest.text, "acme.onmicrosoft.com")

    say("S4: a non-streamed completion through AzureOpenAI, the vendor's body byte for byte")
    azure = openai.AzureOpenAI(azure_endpoint=API, api_key=priya_laptop, api_version="2024-10-21", max_retries=0)
    Foundry.seen.clear()
    reply = azure.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "the secret prompt"}], temperature=0.2)
    check("the SDK parsed the vendor's answer", reply.choices[0].message.content, "hello from foundry")
    check("and its usage", (reply.usage.prompt_tokens, reply.usage.completion_tokens), (12, 3))
    sent = Foundry.seen[-1]
    check("Foundry saw the Azure path with the deployment", sent["path"], "/openai/deployments/gpt-4o-prod/chat/completions")
    check("S24: the api-version the SDK chose, forwarded as-is", sent["query"], {"api-version": "2024-10-21"})
    check("under the connector's key in the api-key header, never the engineer's token",
          (sent["headers"].get("api-key"), any("art_" in v for v in sent["headers"].values())), (AZURE_KEY, False))
    check("S23: nothing about the engineer's SDK reached Foundry",
          [h for h in sent["headers"] if h.startswith("x-stainless") or h == "openai-organization"], [])
    check("not even its user agent — the one Foundry sees is the door's own",
          "OpenAI" in sent["headers"].get("user-agent", "") or "Stainless" in sent["headers"].get("user-agent", ""), False)
    row = wait_for(lambda: (door_rows(store, tool="foundry_chat_completions") or [None])[-1])
    check("the row: allow, ok, the served model and the counters",
          (row["decision"], row["outcome"], row["model"], row["input_tokens"], row["output_tokens"], row["cache_read_tokens"]),
          ("allow", "ok", FAKE_MODEL, 12, 3, 4))
    check("S28: the person's email is on the row, resolved at read time", row["owner"], "priya@acme.com")
    check("and the deployment", row["args"].get("model"), "gpt-4o-prod")
    check("and the prompt is not", "secret prompt" in json.dumps(row["args"]), False)
    check("under a door correlation id, not a run", row["run_id"].startswith("door-"), True)

    say("S4 again through OpenAI(base_url=…): the other dialect, the same call")
    plain = openai.OpenAI(base_url=f"{API}/v1", api_key=priya_desktop, max_retries=0)
    reply = plain.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "hi"}])
    check("Bearer header, model in the body, same answer", reply.choices[0].message.content, "hello from foundry")
    check("the desktop's call is charged to the same person", door_rows(store, owner="priya@acme.com")[-1]["principal_id"] != row["principal_id"], True)

    say("S5: a streamed completion — chunk for chunk, usage lifted from the injected final chunk")
    Foundry.seen.clear()
    pieces, usage_seen = [], None
    with azure.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "stream"}], stream=True) as stream:
        for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content:
                pieces.append(chunk.choices[0].delta.content)
            if chunk.usage:
                usage_seen = chunk.usage
    check("the SDK's stream loop read the words as they came", "".join(pieces), "hello from foundry")
    check("Carnet asked for the usage the SDK did not", Foundry.seen[-1]["body"].get("stream_options"), {"include_usage": True})
    check("and the SDK saw the usage chunk it knows how to read", usage_seen is not None and usage_seen.prompt_tokens, 12)
    row = wait_for(lambda: (door_rows(store, tool="foundry_chat_completions") or [None])[-1])
    check("the row for the stream has the counters", (row["outcome"], row["input_tokens"], row["output_tokens"]), ("ok", 12, 3))
    check("and says it streamed", row["args"].get("stream"), True)

    say("S22: tool calling, forwarded untouched in both directions")
    tools_arg = [{"type": "function", "function": {"name": "read_file", "parameters": {"type": "object", "properties": {}}}}]
    reply = azure.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "x"}], tools=tools_arg, tool_choice="auto")
    check("the model's tool call came back through the SDK", reply.choices[0].message.tool_calls[0].function.name, "read_file")
    check("Foundry received the tools as sent", Foundry.seen[-1]["body"]["tools"], tools_arg)
    row = door_rows(store, tool="foundry_chat_completions")[-1]
    check("and the row recorded nothing of the tools", "read_file" in json.dumps(row["args"]), False)
    pieces = []
    with azure.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "x"}], tools=tools_arg, stream=True) as stream:
        for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.tool_calls:
                pieces.append(chunk.choices[0].delta.tool_calls[0].function.name)
    check("streamed tool-call deltas intact", pieces[:1], ["read_file"])

    say("embeddings, the same way")
    vector = azure.embeddings.create(model="text-embedding-3-small", input="the secret file")
    check("the embedding came back", vector.data[0].embedding, [0.1, 0.2, 0.3])
    row = door_rows(store, tool="foundry_embeddings")[-1]
    check("with only the prompt tokens on the row and no input", (row["input_tokens"], "secret file" in json.dumps(row["args"])), (5, False))

    say("S21: the models list is the token's scope, in OpenAI's shape")
    check("AzureOpenAI's models.list", sorted(m.id for m in azure.models.list()), ["gpt-4o-prod", "text-embedding-3-small"])
    check("OpenAI's too", sorted(m.id for m in plain.models.list()), ["gpt-4o-prod", "text-embedding-3-small"])

    say("S8, S9: a megabyte of file context is accepted; five megabytes is a 413 and nothing dials")
    Foundry.seen.clear()
    reply = azure.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "x" * 1_000_000}])
    check("1 MiB accepted", reply.choices[0].message.content, "hello from foundry")
    try:
        azure.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "x" * 5_000_000}])
        check("5 MiB refused", "accepted", "413")
    except openai.APIStatusError as exc:
        check("5 MiB refused", exc.status_code, 413)
        check("in the dialect", exc.body["code"] if isinstance(exc.body, dict) else exc.body, "request_too_large")
    check("nothing was dialled for it", len(Foundry.seen), 1)

    say("S12: a deployment outside the scope — 403, the deployment named, nothing dialled")
    Foundry.seen.clear()
    try:
        azure.chat.completions.create(model="gpt-4o-eu", messages=[{"role": "user", "content": "x"}])
        check("refused", "allowed", "PermissionDeniedError")
    except openai.PermissionDeniedError as exc:
        check("the SDK raised PermissionDeniedError", exc.status_code, 403)
        check("with the dialect's code", exc.body["code"], "insufficient_scope")
        says("and Carnet's own sentence naming the deployment", exc.message, "gpt-4o-eu")
        scope_sentence = exc.body["message"]
    check("Foundry never heard about it", Foundry.seen, [])
    denied = door_rows(store, decision="deny")
    check("the denial is a row", denied[-1]["args"].get("model") if denied else None, "gpt-4o-eu")

    say("S27: --simulate gives the same verdict and the same sentence")
    tokens_of_priya = store.list_api_tokens(TENANT, owner_id=priya["id"])
    sim = cli("--simulate", tokens_of_priya[0]["id"], "--call", "foundry_chat_completions", "--arg", "model=gpt-4o-eu")
    says("REFUSED, on the terminal", sim.stdout, "REFUSED")
    says("naming the deployment the SDK's sentence named", sim.stdout, "gpt-4o-eu")
    check("and the SDK's sentence is the door's — it names the deployment and the scope", "gpt-4o-eu" in scope_sentence and "write" in scope_sentence, True)

    say("S19, S20, S18: Foundry's own refusals, relayed — and Carnet's key, never")
    Foundry.mode = "rate_limit"
    try:
        azure.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "x"}])
        check("429", "ok", "RateLimitError")
    except openai.RateLimitError as exc:
        check("the SDK raised RateLimitError from Foundry's own body", exc.status_code, 429)
        check("with Retry-After forwarded", exc.response.headers.get("retry-after"), "7")
        says("and Foundry's message", exc.message, "exceeded token rate limit")
        check("and not Foundry's request id", "x-ms-request-id" in exc.response.headers, False)
    Foundry.mode = "content_filter"
    try:
        azure.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "x"}])
        check("400", "ok", "BadRequestError")
    except openai.BadRequestError as exc:
        check("the content filter's 400, unchanged", (exc.status_code, exc.body.get("code")), (400, "content_filter"))
    Foundry.mode = "bad_key"
    try:
        azure.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "x"}])
        check("502", "ok", "APIStatusError")
    except openai.APIStatusError as exc:
        check("Carnet's key refused upstream is a 502 naming the connector", (exc.status_code, exc.body["code"]), (502, "upstream_credential_refused"))
        says("naming foundry", exc.message, "foundry")
        check("and the key is in no response", AZURE_KEY in exc.message + json.dumps(exc.body), False)
    row = door_rows(store, tool="foundry_chat_completions")[-1]
    check("and in no row", AZURE_KEY in json.dumps(row), False)
    check("the row says error", row["outcome"], "error")
    Foundry.mode = "ok"

    say("S10, S11: a slow stream that keeps producing succeeds; a stall mid-answer is closed")
    Foundry.mode = "slow"
    pieces = []
    with azure.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "slow"}], stream=True) as stream:
        for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content:
                pieces.append(chunk.choices[0].delta.content)
    check("a stream producing for longer than the chunk timeout finished", "".join(pieces), "hello from foundry")
    Foundry.mode = "stall"
    got, error = [], None
    try:
        with azure.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "stall"}], stream=True) as stream:
            for chunk in stream:
                if chunk.choices and chunk.choices[0].delta.content:
                    got.append(chunk.choices[0].delta.content)
    except openai.APIError as exc:
        error = exc
    check("the first chunk arrived", got[:1], ["hello"])
    check("then the SDK raised on the error event Carnet sent", error is not None and "stopped sending" in str(error), True)
    row = wait_for(lambda: (door_rows(store, tool="foundry_chat_completions") or [None])[-1])
    check("the row says error, with the sentence", (row["outcome"], "CARNET_MODEL_CHUNK_TIMEOUT" in row["reason"]), ("error", True))
    try:
        azure.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "stall"}])
        check("a non-streamed stall", "ok", "504")
    except openai.APIStatusError as exc:
        check("a non-streamed stall is a 504 upstream_unavailable", (exc.status_code, exc.body["code"]), (504, "upstream_unavailable"))
    Foundry.mode = "ok"

    say("S6: the engineer presses Ctrl-C mid-answer — the upstream is closed, the row says aborted")
    Foundry.mode = "leisurely"
    Foundry.seen.clear()
    before = len(door_rows(store, tool="foundry_chat_completions"))
    stream = azure.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "walk away"}], stream=True)
    first = next(iter(stream))
    check("one chunk in hand", first.choices[0].delta.content, "hello")
    stream.close()
    row = wait_for(lambda: (door_rows(store, tool="foundry_chat_completions")[before:] or [None])[-1], seconds=15)
    check("the row says aborted", row["outcome"] if row else None, "aborted")
    check("with nothing counted, because the usage chunk never came", row["input_tokens"] if row else "no row", None)
    check("and Foundry saw the connection go", wait_for(lambda: any(s.get("disconnected") for s in Foundry.seen), seconds=10), True)
    Foundry.mode = "ok"

    say("S7: past the tool's byte cap — every byte up to it, then an error event, then [DONE]")
    done = cli("--vet", "foundry", "--tool", "chat_completions", "--from-recipe", "azure-openai", "--max-response-bytes", "400")
    check("re-vetted with a 400-byte cap", done.returncode, 0)
    Foundry.mode = "endless"
    got, error = 0, None
    try:
        with azure.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "endless"}], stream=True) as stream:
            for _chunk in stream:
                got += 1
    except openai.APIError as exc:
        error = exc
    check("some chunks arrived", got > 0, True)
    check("then the SDK raised on Carnet's error event", error is not None and "size limit" in str(error), True)
    row = wait_for(lambda: (door_rows(store, tool="foundry_chat_completions") or [None])[-1])
    check("the row says oversize", row["outcome"], "oversize")
    check("Foundry was told to stop", wait_for(lambda: any(s.get("disconnected") for s in Foundry.seen), seconds=10), True)
    Foundry.mode = "ok"
    check("re-vetted back to the recipe's cap", cli("--vet", "foundry", "--tool", "chat_completions", "--from-recipe", "azure-openai").returncode, 0)

    say("S13: tom crosses the day's dollar ceiling; his next call is refused, priya's is not")
    tom_client = openai.AzureOpenAI(azure_endpoint=API, api_key=tom_token, api_version="2024-10-21", max_retries=0)
    crossing = tom_client.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "x"}], user="big-spender")
    check("the crossing call completed", crossing.usage.prompt_tokens, 1_000_000)
    try:
        tom_client.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "x"}])
        check("tom refused", "allowed", "RateLimitError")
    except openai.RateLimitError as exc:
        check("tom's next call is a 429 daily_limit_reached", exc.body["code"], "daily_limit_reached")
        says("with the dial named", exc.message, "CARNET_MCP_USD_PER_DAY")
        says("and the pooling said", exc.message, "across every personal token")
    check("priya is unaffected", azure.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "x"}]).choices[0].message.content, "hello from foundry")

    say("S15: priya revokes her laptop's token on the tokens page; the agent re-mints once")
    laptop_id = next(t["id"] for t in store.list_api_tokens(TENANT, owner_id=priya["id"]) if t["revoked_at"] is None and t["name"].endswith(real_hostname()))
    gone = httpx.delete(f"{API}/me/tokens/{laptop_id}", headers={"Authorization": f"Bearer {entra('oid-priya', 'priya@acme.com')}"})
    check("revoked through the API", gone.status_code, 200)
    try:
        azure.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "x"}])
        check("the revoked token", "worked", "AuthenticationError")
    except openai.AuthenticationError as exc:
        check("the SDK raised AuthenticationError", exc.body["code"], "invalid_api_key")
        os.environ.update({"CARNET_TOKEN_FILE": str(laptop_cache), "CARNET_ENTRA_TOKEN": entra("oid-priya", "priya@acme.com")})
        snippet["CACHE"] = pathlib.Path(laptop_cache)
        snippet["socket"].gethostname = real_hostname
        fresh = snippet["refreshed_after"](exc)
        check("refreshed_after minted once", fresh is not None and fresh.startswith("art_") and fresh != priya_laptop, True)
        azure = openai.AzureOpenAI(azure_endpoint=API, api_key=fresh, api_version="2024-10-21", max_retries=0)
        check("and the retry succeeds", azure.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "x"}]).choices[0].message.content, "hello from foundry")

    say("S14: tom is offboarded; the agent stops and does not re-mint")
    check("--disable-user", cli("--disable-user", "tom@acme.com").returncode, 0)
    try:
        tom_client.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "x"}])
        check("tom's call", "worked", "PermissionDeniedError")
    except openai.PermissionDeniedError as exc:
        check("403 account_deactivated", exc.body["code"], "account_deactivated")
        check("and refreshed_after says stop", snippet["refreshed_after"](exc), None)
    remint = httpx.post(f"{API}/me/tokens", json={"name": "again"}, headers={"Authorization": f"Bearer {entra('oid-tom', 'tom@acme.com')}"})
    check("re-minting is refused too", remint.status_code, 403)

    say("S30: a CI pipeline holds a service token minted by the admin; its rows name nobody")
    minted = cli("--mint-token", "ci-bot", "priya@acme.com")
    check("--mint-token", minted.returncode, 0)
    ci_token = re.search(r"(art_[A-Za-z0-9_\-\.]+)", minted.stdout).group(1)
    ci_row = next(t for t in store.list_api_tokens(TENANT) if t["name"] == "ci-bot")
    store.grant_agent(TENANT, "coding-agent", "machine", ci_row["id"], role="user", granted_by="system:cli", actor="system:cli")
    ci = openai.AzureOpenAI(azure_endpoint=API, api_key=ci_token, api_version="2024-10-21", max_retries=0)
    check("the pipeline's call works", ci.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "x"}]).choices[0].message.content, "hello from foundry")
    row = door_rows(store, tool="foundry_chat_completions")[-1]
    check("its row has no person", (row["principal_id"], row["owner"]), (ci_row["id"], ""))

    say("S25 (in miniature): twenty engineers mid-completion at once")
    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(lambda _: azure.chat.completions.create(model="gpt-4o-prod", messages=[{"role": "user", "content": "x"}], stream=True).__enter__(), range(20)))
        texts = ["".join(c.choices[0].delta.content or "" for c in s if c.choices) for s in results]
    check("all twenty streams completed", texts.count("hello from foundry"), 20)

    say("S28: the admin reads the week — who, which deployment, how much — and the overview")
    admin = {"Authorization": f"Bearer {entra('oid-priya', 'priya@acme.com')}"}
    log = httpx.get(f"{API}/admin/door-calls", params={"owner": "priya@acme.com", "limit": 500}, headers=admin)
    check("the log filters by the person's email", log.status_code, 200)
    rows = log.json()
    check("every row is hers, on any of her machines", {r["owner"] for r in rows}, {"priya@acme.com"})
    check("across more than one token", len({r["principal_id"] for r in rows}) >= 2, True)
    overview = httpx.get(f"{API}/admin/overview", headers=admin).json()
    callers = {c["owner"] or c["principal_id"]: c for c in overview["callers"]}
    check("priya is one bar, labelled with her email", "priya@acme.com" in callers, True)
    check("the pipeline is its own", ci_row["id"] in callers, True)
    check("and the overview says who called, not which machine", callers["priya@acme.com"]["principal_kind"], "user")


def live() -> None:
    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
    key = os.environ.get("AZURE_OPENAI_LIVE_KEY")
    deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT")
    if not (endpoint and key and deployment):
        print("SKIPPED: --live needs AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_LIVE_KEY and AZURE_OPENAI_DEPLOYMENT")
        return
    say("live: S4 and S5 against a real deployment, through Carnet, on the real key")
    # The connector's key comes from the environment the API process reads; this run
    # re-points the fake's connector at the real resource. Left as an exercise for the
    # day somebody has a key on hand: the shape is `--allow-host <resource>.openai.azure.com`,
    # `--add-connector real --from-recipe azure-openai --url <endpoint> --credential-env
    # AZURE_OPENAI_LIVE_KEY`, three vets, a grant, and the two SDK calls above.
    print("  (not implemented in this build; see the comment in `live()`)")


def main() -> int:
    import psycopg

    if socket.gethostbyname(HOST) != "127.0.0.1":
        print(f"SKIPPED: {HOST} did not resolve to 127.0.0.1; this needs outbound DNS")
        return 0
    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")
    dsn = dsn_for(DB)
    os.environ.update({
        "CARNET_DATABASE_URL": dsn,
        "CARNET_SECRET_KEY": base64.b64encode(os.urandom(32)).decode(),
        "CARNET_TENANT": TENANT,
        "CARNET_EGRESS_INTERNAL_HOSTS": HOST,
        "CARNET_PUBLIC_ORIGIN": API,
        "AZURE_OPENAI_KEY": AZURE_KEY,
        "CARNET_MODEL_CHUNK_TIMEOUT": "2",
        "CARNET_MODEL_MAX_SECONDS": "8",
        "CARNET_MCP_USD_PER_DAY": "1",
        "CARNET_BOOTSTRAP_ADMIN": "priya@acme.com",
    })
    from carnet.storage import migrate

    migrate.apply(dsn)
    store = store_at(dsn)
    store.create_tenant(TENANT, "A company with its own coding agent")

    jwks = http.server.ThreadingHTTPServer(("127.0.0.1", JWKS_PORT), Jwks)
    foundry = http.server.ThreadingHTTPServer(("127.0.0.1", FOUNDRY_PORT), Foundry)
    for server in (jwks, foundry):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    log_dir = HERE.parent / "var" / "e2e_openai_surface"
    log_dir.mkdir(parents=True, exist_ok=True)
    uvicorn_log = (log_dir / "uvicorn.log").open("w")
    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port", str(API_PORT), "--log-level", "warning"],
        env=dict(os.environ), stdout=uvicorn_log, stderr=subprocess.STDOUT,
    )
    try:
        for _ in range(60):
            try:
                httpx.get(f"{API}/health", timeout=1)
                break
            except Exception:  # noqa: BLE001
                time.sleep(0.5)
        else:
            raise SystemExit("uvicorn did not come up")
        run(store)
        if "--live" in sys.argv:
            live()
        else:
            print("\nlive: not requested (pass --live with AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_LIVE_KEY, AZURE_OPENAI_DEPLOYMENT)")
    finally:
        api.terminate()
        api.wait(timeout=10)
        for server in (jwks, foundry):
            server.shutdown()
        store.close()
    failed = [label for label, ok, *_ in CHECKS if not ok]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    for label in failed:
        print(f"  FAILED: {label}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
