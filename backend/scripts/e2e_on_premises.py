"""Plan 109, driven as the customer who could not install it.

The failure that prompted the plan was reported rather than reproduced: *"i tried
installing this in the closed env of a bank and it was not possible."* This script is
the reproduction, and then the proof that decisions 1–4 answer it. Everything here is a
real socket, a real certificate and a real process — the point is the environment, which
is the class the other harnesses cannot see because they all run on an open network.

The world, built by this script and torn down after:

  Acme Corporate Root   a CA created here, which signs BOTH servers below. Nothing in
                        this world is signed by a public root, so a deployment that
                        cannot be told about a corporate CA cannot dial anything —
                        which is the on-premises normal case and decision 2's subject.
  the internal gateway  `localtest.me`, TLS, answering in Azure's OpenAI shape. A
                        public name resolving to loopback, which is a private answer
                        the operator must consent to (`egress.forbidden_reason` refuses
                        loopback and private alike, and consents to them alike).
  the vendor            `vendor.invalid`, TLS, the same shape. `.invalid` is reserved
                        by RFC 2606 and resolves NOWHERE, so it is reachable only
                        through the proxy — which is the shape of every external name
                        behind a CONNECT proxy, and the case decision 3 exists for.
  the proxy             a CONNECT proxy that resolves `vendor.invalid` itself and
                        records every target it is asked for. Its log is how "the
                        internal gateway was dialled direct" is proven rather than
                        asserted.
  Carnet                a uvicorn subprocess on its own Postgres database, restarted
                        per configuration — because `config.py` reads the environment
                        at import, which is exactly what a container restart does.

    cd backend && CARNET_E2E_PG=postgresql://postgres:test@localhost:55432 \\
        .venv/bin/python scripts/e2e_on_premises.py [--live]

`--live` adds the last scene: a real Anthropic call through the proxy, with the
corporate root concatenated onto the public roots — the remedy `.env.example` documents
for `REQUESTS_CA_BUNDLE` replacing rather than adding. It needs `ANTHROPIC_BROKERED_KEY`
and outbound internet, and skips loudly without them. Costs a fraction of a cent.
"""

from __future__ import annotations

import base64
import datetime
import http.server
import json
import os
import pathlib
import select
import socket
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit, urlunsplit

import httpx

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

DB = "carnet_on_premises"
BASE_DSN = os.environ.get("CARNET_E2E_PG") or "postgresql://postgres:test@localhost:55432"
TENANT = "e2eonprem"
ADMIN = "user:u_ops"

INTERNAL_HOST = "localtest.me"
VENDOR_HOST = "vendor.invalid"
GATEWAY_PORT = 8931
VENDOR_PORT = 8932
PLAIN_PORT = 8935
PROXY_PORT = 8933
API_PORT = 8934

GATEWAY = f"https://{INTERNAL_HOST}:{GATEWAY_PORT}"
# An internal service that is not TLS at all, which on an estate is the common case and
# is what decision 1 moved the in-clear rule for.
PLAIN = f"http://{INTERNAL_HOST}:{PLAIN_PORT}"
VENDOR = f"https://{VENDOR_HOST}:{VENDOR_PORT}"
PROXY = f"http://127.0.0.1:{PROXY_PORT}"
API = f"http://127.0.0.1:{API_PORT}"

# The claim an on-premises operator writes. Both families, because a name answers with
# every record it has and every answer is vetted — `localtest.me` answers ::1 as well,
# and a v4-only claim refuses it. That is the sharp edge of decision 1 and it belongs
# in a script somebody reads.
CLAIM = "127.0.0.0/8,::1/128"

GATEWAY_KEY = "gateway-key-MARKER-3f9a"
VENDOR_KEY = "vendor-key-MARKER-b71c"
DEPLOYMENT = "gpt-4o-prod"
VENDOR_MODEL = "vendor-model"

SCRATCH = HERE.parent / "var" / "e2e_on_premises"
CHECKS: list = []


# --- the report -------------------------------------------------------------------

def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok))
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: {actual!r}"
          + ("" if ok else f"  (expected {expected!r})"))
    return ok


def says(label, text, fragment):
    return check(label, fragment in (text or ""), True)


def say(what):
    print(f"\n== {what}")


def dsn_for(database: str) -> str:
    parts = urlsplit(BASE_DSN)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query,
                       parts.fragment))


# --- the corporate CA, and two servers it signs -------------------------------------

def corporate_pki() -> dict:
    """A CA, two leaves, and the files a deployment is pointed at.

    The CA is the whole reason decision 2 exists: on an intercepting network every
    certificate the deployment sees is signed by this, and a container that cannot be
    told about it fails every TLS dial with a certificate error naming nothing useful.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    SCRATCH.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Acme Corporate Root")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        # A key identifier on both halves of the chain, because Python verifies
        # strictly and refuses a chain without one — and because every corporate CA
        # in existence issues them, so leaving them out would make this world less
        # like the estate it stands in for, not more.
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                       critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    made = {"ca_pem": ca.public_bytes(serialization.Encoding.PEM)}
    for label, host in (("gateway", INTERNAL_HOST), ("vendor", VENDOR_HOST)):
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(ca_name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]),
                           critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        cert_path = SCRATCH / f"{label}-cert.pem"
        key_path = SCRATCH / f"{label}-key.pem"
        cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        made[label] = (str(cert_path), str(key_path))

    ca_only = SCRATCH / "corporate-ca.pem"
    ca_only.write_bytes(made["ca_pem"])
    made["ca_only"] = str(ca_only)

    # The remedy `.env.example` documents, built here so the live scene can prove it:
    # REQUESTS_CA_BUNDLE replaces the public roots, so a deployment that also dials the
    # internet concatenates them.
    try:
        import certifi

        both = SCRATCH / "corporate-ca-and-public.pem"
        both.write_bytes(made["ca_pem"] + pathlib.Path(certifi.where()).read_bytes())
        made["ca_and_public"] = str(both)
    except ImportError:
        made["ca_and_public"] = ""
    return made


class ModelGateway(http.server.BaseHTTPRequestHandler):
    """An OpenAI-shaped endpoint, JSON or SSE, recording what it was asked.

    Stands in for both the company's internal model gateway and an external vendor;
    which one it is, is decided by the port it is bound to.
    """

    seen: list = []
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        payload = json.loads(raw or b"{}")
        ModelGateway.seen.append({
            "port": self.server.server_address[1],
            "path": self.path,
            "host": self.headers.get("Host"),
            "api_key": self.headers.get("api-key"),
            "authorization": self.headers.get("Authorization"),
            "model": payload.get("model"),
            "stream": bool(payload.get("stream")),
        })
        who = "the internal gateway" if self.server.server_address[1] == GATEWAY_PORT \
            else "the vendor"
        if payload.get("stream"):
            # **Chunked, framed by hand.** `http.server` speaks HTTP/1.1 here and adds
            # no framing of its own, so an SSE response with neither Content-Length nor
            # Transfer-Encoding has no defined length — the client waits for a close
            # that keep-alive never sends, and the reader times out with the upstream
            # looking stalled. This script found that by being written the naive way
            # first; `e2e_openai_surface`'s fake had it right all along.
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()

            def chunk(obj):
                data = f"data: {json.dumps(obj)}\n\n".encode()
                self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
                self.wfile.flush()

            for word in ("hello", " from", " " + who.replace("the ", "")):
                chunk({"id": "c1", "object": "chat.completion.chunk",
                       "model": payload.get("model"),
                       "choices": [{"index": 0, "delta": {"content": word},
                                    "finish_reason": None}], "usage": None})
                time.sleep(0.05)
            chunk({"id": "c1", "object": "chat.completion.chunk",
                   "model": payload.get("model"),
                   "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                   "usage": None})
            # The surface asks for this (`_inject_usage`), and a real vendor answers it
            # as a final chunk carrying NO choices — which is why the reader below must
            # not assume every chunk has one.
            if (payload.get("stream_options") or {}).get("include_usage"):
                chunk({"id": "c1", "object": "chat.completion.chunk",
                       "model": payload.get("model"), "choices": [],
                       "usage": {"prompt_tokens": 11, "completion_tokens": 3,
                                 "total_tokens": 14}})
            done = b"data: [DONE]\n\n"
            self.wfile.write(f"{len(done):x}\r\n".encode() + done + b"\r\n0\r\n\r\n")
            self.wfile.flush()
            return
        body = json.dumps({
            "id": "chatcmpl-e2e", "object": "chat.completion",
            "model": payload.get("model"),
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant",
                                     "content": f"hello from {who}"}}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ConnectProxy(http.server.BaseHTTPRequestHandler):
    """The building's outbound proxy. It resolves; nothing behind it does.

    `connects` is the evidence for the half of decision 3 that is easiest to assert
    and hardest to believe: that the operator's own network is dialled DIRECT and
    never appears here.
    """

    connects: list = []
    credentials: list = []
    protocol_version = "HTTP/1.1"
    allow_internet = False

    def log_message(self, *_args):
        pass

    def do_CONNECT(self):
        ConnectProxy.connects.append(self.path)
        ConnectProxy.credentials.append(self.headers.get("Proxy-Authorization"))
        host, _, port = self.path.rpartition(":")
        try:
            if host == VENDOR_HOST:
                far = socket.create_connection(("127.0.0.1", VENDOR_PORT), timeout=10)
            elif ConnectProxy.allow_internet:
                far = socket.create_connection((host, int(port)), timeout=15)
            else:
                self.send_error(502, "this proxy reaches only the vendor")
                return
        except OSError as exc:
            self.send_error(502, f"proxy could not reach {self.path}: {exc}")
            return
        self.send_response(200, "Connection established")
        self.end_headers()
        near = self.connection
        self.close_connection = True
        pairs = {near: far, far: near}
        try:
            while True:
                readable, _, _ = select.select(list(pairs), [], [], 30)
                if not readable:
                    break
                for sock in readable:
                    data = sock.recv(65536)
                    if not data:
                        return
                    pairs[sock].sendall(data)
        except OSError:
            pass
        finally:
            far.close()


# --- the deployment, started and restarted the way an operator restarts it ----------

class Deployment:
    """One `docker compose up` worth of Carnet: a uvicorn on the shared database.

    A context manager because every scene here is *a different .env*, and `config.py`
    reads the environment at import — so a setting changes by restarting, which is what
    an operator does and what makes these scenes honest.
    """

    def __init__(self, label: str, **env):
        self.label = label
        self.env = env
        self.process = None
        self.log = SCRATCH / f"uvicorn-{label}.log"

    def __enter__(self):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        handle = self.log.open("w")
        self.process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "carnet.api:app",
             "--port", str(API_PORT), "--log-level", "warning"],
            env={**base_env(), **self.env}, stdout=handle, stderr=subprocess.STDOUT,
        )
        for _ in range(80):
            if self.process.poll() is not None:
                raise SystemExit(
                    f"the deployment '{self.label}' exited at start:\n"
                    + self.log.read_text()[-2000:]
                )
            try:
                httpx.get(f"{API}/health", timeout=1)
                return self
            except Exception:  # noqa: BLE001
                time.sleep(0.25)
        raise SystemExit(f"the deployment '{self.label}' never answered")

    def __exit__(self, *_exc):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
        return False


def base_env() -> dict:
    """The environment every scene starts from: no claim, no proxy, no CA."""
    clean = {k: v for k, v in os.environ.items()
             if not k.startswith(("CARNET_", "REQUESTS_CA", "CURL_CA"))
             and k.upper() not in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY")}
    clean.update({
        "CARNET_DATABASE_URL": dsn_for(DB),
        "CARNET_SECRET_KEY": SECRET_KEY,
        "CARNET_TENANT": TENANT,
        "CARNET_PUBLIC_ORIGIN": API,
        "GATEWAY_KEY": GATEWAY_KEY,
        "VENDOR_KEY": VENDOR_KEY,
        "ANTHROPIC_BROKERED_KEY": os.environ.get("ANTHROPIC_BROKERED_KEY", "unused"),
        "CARNET_MODEL_CHUNK_TIMEOUT": "10",
        "CARNET_MODEL_MAX_SECONDS": "30",
        "PYTHONPATH": str(HERE.parent / "src"),
    })
    return clean


def starts_with(**env) -> tuple[bool, str]:
    """Does a process with this environment get as far as reading its settings?

    `python -c "import carnet.config"` is what a container start does first, and every
    refusal decision 1 and 3 add is raised there — so this is the real failure mode,
    at the real moment, without the cost of a server.
    """
    done = subprocess.run(
        [sys.executable, "-c", "import carnet.config"],
        env={**base_env(), **env}, capture_output=True, text=True, timeout=60,
    )
    return done.returncode == 0, done.stdout + done.stderr


# --- the seed: an administrator's hour, before anybody calls anything ----------------

def mcp_connector_exists(tenant_id: str, connector_id: str):
    from carnet.tools import mcp

    try:
        return mcp.get_connector(tenant_id, connector_id)
    except Exception:  # noqa: BLE001
        return None


def seed(store) -> str:
    """Two connectors, two vetted chat tools, one agent, one token. The token is what
    an engineer pastes into their coding agent."""
    from carnet import agents, tools
    from carnet.access import tokens
    from carnet.tools.base import Resource

    store.create_tenant(TENANT, "A bank, on its own network")
    store.create_user(TENANT, {"id": "u_ops", "issuer": "https://idp.acme.internal",
                               "subject": "ops-1", "email": "ops@acme.com"})
    store.allow_host(TENANT, INTERNAL_HOST, actor=ADMIN, note="the internal gateway")
    store.allow_host(TENANT, VENDOR_HOST, actor=ADMIN, note="the external vendor")

    recipe = json.loads(
        (HERE.parent / "src" / "carnet" / "access" / "recipes" / "azure-openai.json")
        .read_text()
    )
    chat = next(t for t in recipe["tools"] if t["remote_name"] == "chat_completions")

    tools.register_connector(
        TENANT, "gateway", url=GATEWAY, kind="rest",
        credential_env="GATEWAY_KEY", credential_header="api-key",
        credential_prefix="", description="The company's own model gateway",
        actor=ADMIN,
    )
    check("an https connector on a private name registers with NO claim at all — "
          "which is why the bank's install looked like it had worked",
          bool(mcp_connector_exists(TENANT, "gateway")), True)
    tools.vet_tool(
        TENANT, "gateway", "chat_completions", effect="write",
        resources=(Resource("azure.deployment", "model"),), actor=ADMIN,
        description=chat["description"], redact_args=tuple(chat["redact_args"]),
        max_response_bytes=chat["max_response_bytes"], binding=chat["binding"],
    )

    # A second connector with its OWN resource type, which is what makes the surface's
    # `_choose` pick by scope rather than by name order — two connectors, two regions,
    # exactly as routes_openai's docstring describes.
    # OpenAI's own shape rather than Azure's: no deployment in the path, the model in
    # the body. `check_binding` refuses the alternative — an argument the schema
    # declares and the binding maps nowhere — which is how this script learned it.
    vendor_binding = dict(chat["binding"])
    vendor_binding["path"] = "/v1/chat/completions"
    vendor_binding["body"] = ["model", *chat["binding"]["body"]]
    tools.register_connector(
        TENANT, "vendor", url=VENDOR, kind="rest",
        credential_env="VENDOR_KEY", description="A vendor out on the internet",
        actor=ADMIN,
    )
    tools.vet_tool(
        TENANT, "vendor", "chat_completions", effect="write",
        resources=(Resource("vendor.deployment", "model"),), actor=ADMIN,
        description="A completion from the vendor.",
        redact_args=tuple(chat["redact_args"]),
        max_response_bytes=chat["max_response_bytes"], binding=vendor_binding,
    )

    # An internal service with no TLS — an estate is full of them — and two connectors
    # that exist only to be refused: a public plain-http URL, and a name the proxy will
    # not reach. Both are dialled through `/mcp` rather than the model surface, because
    # what is under test is the dial and a `tools/call` names its tool outright.
    store.allow_host(TENANT, "example.com", actor=ADMIN, note="a public plain-http URL")
    store.allow_host(TENANT, "other.invalid", actor=ADMIN, note="the proxy will refuse")
    plain_binding = dict(chat["binding"])
    plain_binding["path"] = "/v1/chat/completions"
    plain_binding["body"] = ["model", *chat["binding"]["body"]]

    # **Registering a plain-http connector needs the claim in the REGISTERING process,
    # not only in the server's.** `egress.check` runs here too, and the CLI reads the
    # same `config` — which is right, and is why an administrator runs
    # `docker compose exec api carnet --add-connector` rather than a shell of their own.
    # The refusal is asserted rather than avoided, because it is the one an admin meets.
    from carnet import config
    from carnet.tools import mcp as _mcp

    refused = ""
    try:
        tools.register_connector(
            TENANT, "plain", url=PLAIN, kind="rest", credential_env="GATEWAY_KEY",
            credential_header="api-key", credential_prefix="",
            description="An internal service with no TLS", actor=ADMIN,
        )
    except _mcp.EgressRefused as exc:
        refused = str(exc)
    check("registering a plain-http connector with no claim in this process is refused",
          "not https" in refused, True)
    says("naming the setting, and that a network in CIDR may go in it", refused,
         "CARNET_EGRESS_INTERNAL_HOSTS")

    # Now as the administrator has it: inside the deployment, where the claim is set.
    import ipaddress

    config.EGRESS_INTERNAL_NETWORKS = tuple(
        ipaddress.ip_network(entry) for entry in CLAIM.split(",")
    )
    tools.register_connector(
        TENANT, "plain", url=PLAIN, kind="rest", credential_env="GATEWAY_KEY",
        credential_header="api-key", credential_prefix="",
        description="An internal service with no TLS", actor=ADMIN,
    )
    tools.vet_tool(
        TENANT, "plain", "chat_completions", effect="write",
        resources=(Resource("plain.deployment", "model"),), actor=ADMIN,
        description="A completion from the estate's plain-http service.",
        redact_args=tuple(chat["redact_args"]), binding=plain_binding,
    )
    for connector_id, url, note in (
        ("publichttp", "http://example.com", "a public name over plain http"),
        ("unreachable", "https://other.invalid", "a name the proxy refuses"),
    ):
        tools.register_connector(
            TENANT, connector_id, url=url, kind="rest",
            description=note, actor=ADMIN,
        )
        tools.vet_tool(
            TENANT, connector_id, "ping", effect="read", resources=(), actor=ADMIN,
            description=f"Dial {note}.",
            binding={"method": "GET", "path": "/", "body": [],
                     "input_schema": {"type": "object", "properties": {}}},
        )

    agents.save(TENANT, {
        "name": "coding-agent", "runtime": "simple", "system": "irrelevant",
        "permissions": {
            "tools": ["gateway_chat_completions", "vendor_chat_completions",
                      "plain_chat_completions", "publichttp_ping", "unreachable_ping"],
            "scope": {"azure.deployment": {"write": [DEPLOYMENT]},
                      "vendor.deployment": {"write": [VENDOR_MODEL]},
                      "plain.deployment": {"write": ["plain-model"]}},
        },
    }, actor=ADMIN)

    row, presented = tokens.mint(TENANT, "priya-laptop", "u_ops", actor="system:cli")
    store.grant_agent(TENANT, "coding-agent", "machine", row["id"], role="user",
                      granted_by=ADMIN, actor=ADMIN)
    return presented


# --- talking to the deployment the way the engineer's agent does --------------------

def completion(token: str, model: str, *, stream: bool = False, timeout: float = 30.0):
    body = {"model": model, "messages": [{"role": "user", "content": "say hello"}]}
    if stream:
        body["stream"] = True
    return httpx.post(f"{API}/v1/chat/completions", json=body, timeout=timeout,
                      headers={"Authorization": f"Bearer {token}"})


def streamed(token: str, model: str, timeout: float = 30.0) -> dict:
    """One streamed completion, read the way an SDK reads one.

    Returns the text the deltas reassemble into, the usage the last chunk carried, and
    any error EVENT — because a stalled or refused stream still answers 200 and still
    ends with `[DONE]`, so status and the sentinel prove nothing on their own. The
    first draft of this script asserted only those two and called a stream that
    carried nothing but an error a pass.
    """
    body = {"model": model, "stream": True,
            "messages": [{"role": "user", "content": "say hello"}]}
    events: list = []
    with httpx.stream("POST", f"{API}/v1/chat/completions", json=body, timeout=timeout,
                      headers={"Authorization": f"Bearer {token}"}) as response:
        if response.status_code != 200:
            response.read()
            return {"status": response.status_code, "text": "", "events": [],
                    "usage": None, "error": response.text}
        for line in response.iter_lines():
            if line.startswith("data: "):
                events.append(line[6:])

    text, usage, error = "", None, ""
    for event in events:
        if event == "[DONE]":
            continue
        parsed = json.loads(event)
        if "error" in parsed:
            error = parsed["error"].get("message", "an error with no message")
            continue
        usage = parsed.get("usage") or usage
        for choice in parsed.get("choices") or []:
            text += (choice.get("delta") or {}).get("content", "")
    return {"status": 200, "text": text, "events": events, "usage": usage,
            "error": error}


def call(token: str, tool: str, **arguments) -> dict:
    """One `tools/call` through the door — the product's own path, and the one that
    names its tool rather than letting the model surface choose."""
    answer = httpx.post(f"{API}/mcp", timeout=60,
                        headers={"Authorization": f"Bearer {token}"},
                        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                              "params": {"name": tool, "arguments": arguments}})
    return answer.json().get("result", answer.json())


def last_row(store):
    rows = store.audit_records(TENANT)
    return rows[-1] if rows else {}


# --- the scenes ---------------------------------------------------------------------

def the_install_that_failed(token, store, pki) -> None:
    """The bank, on the release before this one. Registration succeeds and every call
    fails — which is the worst shape a failure can have, because the administrator has
    every reason to believe the connector is configured."""
    say("the install that failed: an estate on private addresses, no claim, no CA")

    with Deployment("no-claim"):
        answer = completion(token, DEPLOYMENT)
        check("a call to the internal gateway is refused", answer.status_code, 502)
        detail = answer.text
        says("because the name resolves inside somebody's network", detail, "private" if "private" in detail else "loopback")
        says("and the refusal names the setting that would consent", detail,
             "CARNET_EGRESS_INTERNAL_HOSTS")
        says("...and says a network in CIDR is what may go in it", detail, "CIDR")

    say("the remedy the operator reaches for first, and why it was not enough")
    ok, output = starts_with(CARNET_EGRESS_INTERNAL_HOSTS="0.0.0.0/0")
    check("claiming everything is refused at start rather than quietly ignored", ok, False)
    says("naming the range no operator may consent to", output, "169.254.0.0/16")
    says("and what to write instead", output, "10.0.0.0/8")

    ok, output = starts_with(CARNET_EGRESS_INTERNAL_HOSTS="10.0.0.1/8")
    check("a claim with host bits set is refused rather than widened", ok, False)
    says("naming the network they meant", output, "10.0.0.0/8")

    ok, output = starts_with(CARNET_EGRESS_INTERNAL_HOSTS="acme.corp/8")
    check("a hostname wearing a prefix is refused rather than kept as a name", ok, False)
    says("saying what a network looks like", output, "CIDR")


def the_estate_in_one_line(token, store, pki) -> None:
    """Decision 1, and the measure of it: ONE entry, and every internal name works —
    including one nobody thought of when the entry was written."""
    say("the estate in one line: the claim, and the CA that makes TLS possible at all")

    with Deployment("claim-no-ca", CARNET_EGRESS_INTERNAL_HOSTS=CLAIM):
        answer = completion(token, DEPLOYMENT)
        check("with the claim but no corporate CA, the dial still fails", answer.status_code, 502)
        says("on TLS — the other half of an on-premises install, and the surface "
             "names the class rather than quoting a body that tends to carry a key",
             answer.text, "SSLError")

    with Deployment("claim", CARNET_EGRESS_INTERNAL_HOSTS=CLAIM,
                    REQUESTS_CA_BUNDLE=pki["ca_only"]):
        ModelGateway.seen.clear()
        answer = completion(token, DEPLOYMENT)
        check("with both, the internal gateway answers", answer.status_code, 200)
        body = answer.json()
        check("and the body is the gateway's own, byte for byte",
              body["choices"][0]["message"]["content"], "hello from the internal gateway")
        sent = ModelGateway.seen[-1]
        check("the gateway saw the Azure path with the deployment",
              sent["path"], f"/openai/deployments/{DEPLOYMENT}/chat/completions")
        check("under the connector's own key, never the engineer's token",
              (sent["api_key"], sent["authorization"]), (GATEWAY_KEY, None))
        check("and the Host header it serves, because the socket went to the address",
              sent["host"], f"{INTERNAL_HOST}:{GATEWAY_PORT}")

        row = last_row(store)
        check("the call is on the audit log as an allowed door call",
              (row.get("decision"), row.get("tool")), ("allow", "gateway_chat_completions"))
        check("with the counters the vendor reported",
              (row.get("input_tokens"), row.get("output_tokens")), (11, 3))
        check("and the prompt is NOT on it", "say hello" in json.dumps(row), False)

    say("the point of a network claim: a second internal service, no .env edit")
    with Deployment("claim-second", CARNET_EGRESS_INTERNAL_HOSTS=CLAIM,
                    REQUESTS_CA_BUNDLE=pki["ca_only"]):
        # The administrator registers another internal connector at a DIFFERENT name on
        # the same network. Before 109 this was an .env edit and a restart per service.
        done = subprocess.run(
            [sys.executable, "-m", "carnet.cli", "--allow-host", "second.localtest.me"],
            env=base_env() | {"CARNET_EGRESS_INTERNAL_HOSTS": CLAIM},
            capture_output=True, text=True, timeout=60)
        if done.returncode:
            print("   ", done.stderr.strip()[-300:])
        check("a second internal host is approved", done.returncode, 0)
        probe = httpx.get(f"{API}/health/ready", timeout=10)
        check("and the deployment never restarted to learn about it",
              probe.status_code, 200)


def the_model_gateway(token, store, pki) -> None:
    """Plan 109 item 0: everything above applies to step 108's OpenAI surface too, and
    the half that is not the same is streaming."""
    say("the coding agent's own path: a streamed completion from the internal gateway")

    with Deployment("stream", CARNET_EGRESS_INTERNAL_HOSTS=CLAIM,
                    REQUESTS_CA_BUNDLE=pki["ca_only"]):
        ModelGateway.seen.clear()
        stream = streamed(token, DEPLOYMENT)
        check("the stream answered 200", stream["status"], 200)
        check("and carried no error event", stream["error"], "")
        check("and ended the way an SDK expects", stream["events"][-1], "[DONE]")
        check("the deltas reassemble into the gateway's answer", stream["text"],
              "hello from internal gateway")
        check("the gateway was asked to stream", ModelGateway.seen[-1]["stream"], True)
        check("and the surface asked it for usage, which a plain client does not",
              stream["usage"], {"prompt_tokens": 11, "completion_tokens": 3,
                                "total_tokens": 14})

        row = last_row(store)
        check("the streamed call wrote its own audit row when the iteration ended",
              (row.get("decision"), row.get("outcome")), ("allow", "ok"))
        check("with the counters lifted out of the final chunk",
              (row.get("input_tokens"), row.get("output_tokens")), (11, 3))

        say("and the scope still decides: a deployment nobody granted")
        refused = completion(token, "gpt-4o-unapproved")
        check("an ungranted deployment is refused by the surface", refused.status_code, 403)
        says("in OpenAI's error dialect, so the SDK raises rather than parses",
             refused.text, "error")


def through_the_proxy(token, store, pki) -> None:
    """Decision 3. The two halves that matter: the internet goes through the proxy BY
    NAME, and the operator's own network does not go through it at all."""
    say("the building's proxy: a vendor that resolves nowhere, and an estate that does")

    resolves = True
    try:
        socket.getaddrinfo(VENDOR_HOST, 443)
    except OSError:
        resolves = False
    check(f"{VENDOR_HOST} resolves nowhere on this machine, as RFC 2606 promises",
          resolves, False)

    with Deployment("proxy", CARNET_EGRESS_INTERNAL_HOSTS=CLAIM,
                    REQUESTS_CA_BUNDLE=pki["ca_only"], CARNET_EGRESS_PROXY=PROXY):
        ConnectProxy.connects.clear()
        ModelGateway.seen.clear()

        answer = completion(token, VENDOR_MODEL)
        check("the vendor answers, though nothing here can resolve its name",
              answer.status_code, 200)
        check("because the proxy resolved it",
              answer.json()["choices"][0]["message"]["content"], "hello from the vendor")
        check("and the proxy was asked for the NAME, never a locally-resolved address",
              ConnectProxy.connects, [f"{VENDOR_HOST}:{VENDOR_PORT}"])

        say("the half that is easy to get wrong: the estate is dialled direct")
        before = list(ConnectProxy.connects)
        internal = completion(token, DEPLOYMENT)
        check("the internal gateway still answers under a proxy", internal.status_code, 200)
        check("...and the proxy never saw it", ConnectProxy.connects, before)
        check("...and it was still pinned, because the Host header says the name",
              ModelGateway.seen[-1]["host"], f"{INTERNAL_HOST}:{GATEWAY_PORT}")

        say("a streamed completion through the proxy — the case a buffering proxy kills")
        ConnectProxy.connects.clear()
        stream = streamed(token, VENDOR_MODEL)
        check("the stream answered 200 through the tunnel", stream["status"], 200)
        check("and carried no error event — a buffering proxy would show HERE, as a "
              "chunk timeout on a deployment that is working",
              stream["error"], "")
        check("the deltas reassemble into the vendor's answer, through the tunnel",
              stream["text"], "hello from vendor")
        check("and the usage chunk survived it", stream["usage"] is not None, True)
        check("through the proxy, by name",
              ConnectProxy.connects, [f"{VENDOR_HOST}:{VENDOR_PORT}"])

    say("what the proxy may NOT decide: this deployment's own metadata service")
    ok, output = starts_with(CARNET_EGRESS_INTERNAL_HOSTS="169.254.0.0/16",
                             CARNET_EGRESS_PROXY=PROXY)
    check("a claim on link-local is refused at start, proxy or no proxy", ok, False)
    says("naming what lives there", output, "metadata")

    say("an ambient proxy: the deployment that was working by accident")
    ok, output = starts_with(HTTPS_PROXY=PROXY, CARNET_EGRESS_INTERNAL_HOSTS=CLAIM)
    check("HTTPS_PROXY alone refuses to start", ok, False)
    says("naming the ambient variable", output, "HTTPS_PROXY")
    says("and the setting that would honour it", output, f"CARNET_EGRESS_PROXY={PROXY}")
    ok, _ = starts_with(HTTPS_PROXY=PROXY, CARNET_EGRESS_PROXY=PROXY,
                        CARNET_EGRESS_INTERNAL_HOSTS=CLAIM)
    check("declared, the ambient one is simply ignored and the deployment starts", ok, True)

    say("the settings an operator mistypes")
    ok, output = starts_with(CARNET_EGRESS_PROXY="socks5://proxy.corp:1080")
    check("a SOCKS proxy is refused, rather than silently unused", ok, False)
    says("saying so", output, "SOCKS")
    ok, output = starts_with(REQUESTS_CA_BUNDLE=str(SCRATCH / "not-there.pem"))
    check("a CA bundle that is not there refuses at start", ok, False)
    says("naming the mount rather than failing three days later on a handshake",
         output, "REQUESTS_CA_BUNDLE")


def the_edges(token, store, pki) -> None:
    """The adversarial hour. Every one of these is a sentence in the documentation that
    would otherwise be unproven, or a shape an operator reaches by accident."""
    say("plain http on the estate, which is what decision 1 moved the rule for")

    with Deployment("edges", CARNET_EGRESS_INTERNAL_HOSTS=CLAIM,
                    REQUESTS_CA_BUNDLE=pki["ca_only"]):
        ModelGateway.seen.clear()
        result = call(token, "plain_chat_completions", model="plain-model",
                      messages=[{"role": "user", "content": "say hello"}])
        check("an internal service with no TLS answers, because every address it "
              "resolves to is inside the claim", result.get("isError") is True, False)
        check("...and it was still pinned: the socket went to the address, the Host "
              "header carries the name",
              ModelGateway.seen[-1]["host"], f"{INTERNAL_HOST}:{PLAIN_PORT}")

        say("the cost decision 1 states: a PUBLIC plain-http URL, refused at the dial")
        refused = call(token, "publichttp_ping")
        check("refused", refused.get("isError"), True)
        body = json.dumps(refused)
        says("on the credential crossing wire that is not the operator's, in clear",
             body, "not https")
        says("and it is the ANSWER that decided, not the name — registration passed",
             body, "resolves to")
        # **`allow`, with `outcome: error` — and that is the right vocabulary, not a
        # defect.** `decision` records what the PERMISSION layer decided, and the
        # permission was fine: this token may call this tool. What failed is the dial,
        # which is a tool-level failure and belongs in `outcome`. A `deny` row is for a
        # grant or a scope, and reading one here would make an egress refusal
        # indistinguishable from an access-review finding. This script asserted `deny`
        # first, on an assumption, and the product was right.
        row = last_row(store)
        check("the refusal is recorded as an allowed call that failed at the dial, "
              "because the permission was never the problem",
              (row.get("decision"), row.get("outcome")), ("allow", "error"))
        says("with the whole refusal, remedy included, on the row a reviewer reads",
             row.get("reason"), "CARNET_EGRESS_INTERNAL_HOSTS")

    say("a proxy that refuses, which is what a corporate proxy does most days")
    with Deployment("edges-proxy", CARNET_EGRESS_INTERNAL_HOSTS=CLAIM,
                    REQUESTS_CA_BUNDLE=pki["ca_only"], CARNET_EGRESS_PROXY=PROXY):
        ConnectProxy.connects.clear()
        refused = call(token, "unreachable_ping")
        check("the caller is told the call failed rather than left waiting",
              refused.get("isError"), True)
        says("naming the connector, so an operator knows which allowlist to look at",
             json.dumps(refused), "unreachable")
        check("and the proxy was asked, which is where the operator should look next",
              ConnectProxy.connects, ["other.invalid:443"])

    say("NO_PROXY is never read, and that is a promise worth a test")
    with Deployment("no-proxy-var", CARNET_EGRESS_INTERNAL_HOSTS=CLAIM,
                    REQUESTS_CA_BUNDLE=pki["ca_only"], CARNET_EGRESS_PROXY=PROXY,
                    NO_PROXY=f"{VENDOR_HOST},{INTERNAL_HOST}"):
        ConnectProxy.connects.clear()
        answer = completion(token, VENDOR_MODEL)
        check("the vendor still goes through the proxy with NO_PROXY naming it",
              (answer.status_code, ConnectProxy.connects),
              (200, [f"{VENDOR_HOST}:{VENDOR_PORT}"]))
        check("...because the bypass is the operator's own networks, not a second list",
              completion(token, DEPLOYMENT).status_code, 200)

    say("a proxy that wants credentials, which .env.example says works")
    ConnectProxy.credentials.clear()
    ConnectProxy.connects.clear()
    authed = f"http://carnet:s3cret@127.0.0.1:{PROXY_PORT}"
    with Deployment("proxy-auth", CARNET_EGRESS_INTERNAL_HOSTS=CLAIM,
                    REQUESTS_CA_BUNDLE=pki["ca_only"], CARNET_EGRESS_PROXY=authed):
        answer = completion(token, VENDOR_MODEL)
        check("the call succeeds through a proxy with credentials in its URL",
              answer.status_code, 200)
        import base64 as _b64

        expected = "Basic " + _b64.b64encode(b"carnet:s3cret").decode()
        check("and the proxy was handed them on the CONNECT",
              ConnectProxy.credentials[-1], expected)

    say("the lower-case spelling of an ambient proxy, which is the commoner one")
    ok, output = starts_with(https_proxy=PROXY, CARNET_EGRESS_INTERNAL_HOSTS=CLAIM)
    check("https_proxy refuses to start too", ok, False)
    says("naming it as typed", output, "https_proxy")

    say("a claim that is not a network at all, and one that is only nearly one")
    for entry, fragment in (("10.0.0.0/8/8", "not a network"),
                            ("10.0.0.0-10.255.255.255", "address range"),
                            ("10.0.0", "a resolver would accept it"),
                            ("/8", "not a network"),
                            ("10.0.0.0/", "not a network")):
        ok, output = starts_with(CARNET_EGRESS_INTERNAL_HOSTS=f"jira.corp,{entry}")
        check(f"'{entry}' refuses at start", ok, False)
        says("with a sentence that names it", output, entry)
        says("and says what was wrong", output, fragment)

    say("the entries that are legitimate and easy to doubt")
    for entry in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8",
                  "127.0.0.1", "::1/128", "10.0.0.0/7", "jira.corp",
                  # Names a resolver cannot read as an address, which the refusal above
                  # must not reach: hyphens and digits are ordinary in a hostname.
                  "mcp-01.corp", "10-4-service.acme.internal"):
        ok, output = starts_with(CARNET_EGRESS_INTERNAL_HOSTS=entry)
        check(f"'{entry}' is accepted", ok, True)
        if not ok:
            print("   ", output.strip()[-300:])


def the_front_door(pki) -> None:
    """Decision 4, at the level this script can reach: the image's own entrypoint.

    The full three-mode drive and a real handshake are `e2e_deploy.py`'s
    `the_operators_certificate`; what is worth repeating here is the refusal an
    on-premises operator meets first, because they are the ones who will use `files`.
    """
    say("the front door's certificate, for an estate whose CA is its own")
    built = subprocess.run(["docker", "image", "inspect", "carnet-front"],
                           capture_output=True)
    if built.returncode != 0:
        # Deliberately not the word the CI guard watches for: decision 4's full proof —
        # three modes and a real handshake against a mounted certificate — is
        # `e2e_deploy.the_operators_certificate`, in the job that builds the image.
        # What is repeated here is the refusal an on-premises operator meets first.
        print("  (carnet-front is not built here; e2e_deploy.py proves this fully)")
        return
    for label, env, expect in (
        ("unset is today's behaviour", {}, "TLS="),
        ("internal is Caddy's own CA", {"CARNET_TLS_MODE": "internal"},
         "TLS=tls internal"),
    ):
        args = []
        for key, value in env.items():
            args += ["-e", f"{key}={value}"]
        done = subprocess.run(
            ["docker", "run", "--rm", *args, "carnet-front", "sh", "-c",
             'echo "TLS=$CARNET_TLS"'], capture_output=True, text=True)
        check(label, done.stdout.strip(), expect)
    done = subprocess.run(
        ["docker", "run", "--rm", "-e", "CARNET_TLS_MODE=files", "carnet-front",
         "sh", "-c", "true"], capture_output=True, text=True)
    check("files without the mounted pair refuses, naming the mount",
          done.returncode != 0 and "/etc/carnet/tls/cert.pem" in done.stderr, True)


def the_live_vendor(token, store, pki) -> None:
    """The last unproven thing: a real vendor, on the real internet, through the proxy,
    with the corporate root concatenated onto the public ones."""
    say("live: a real model call, through the proxy, with a concatenated CA bundle")

    key = os.environ.get("ANTHROPIC_BROKERED_KEY", "")
    if not key or key == "unused":
        print("  SKIPPED: no ANTHROPIC_BROKERED_KEY; the live leg proves nothing here")
        return
    if not pki["ca_and_public"]:
        print("  SKIPPED: certifi is absent, so the concatenated bundle cannot be built")
        return
    try:
        socket.getaddrinfo("api.anthropic.com", 443)
    except OSError:
        print("  SKIPPED: no outbound DNS for api.anthropic.com")
        return

    from carnet import storage, tools
    from carnet.tools.base import Resource

    store.allow_host(TENANT, "api.anthropic.com", actor=ADMIN, note="the live vendor")
    tools.register_connector(
        TENANT, "anthropic", url="https://api.anthropic.com", kind="rest",
        credential_env="ANTHROPIC_BROKERED_KEY", credential_header="x-api-key",
        credential_prefix="", headers={"anthropic-version": "2023-06-01"},
        description="Anthropic, the Messages API", actor=ADMIN,
    )
    tools.vet_tool(
        TENANT, "anthropic", "chat", effect="write",
        resources=(Resource("anthropic.model", "model"),), actor=ADMIN,
        description="Think with a model.", redact_args=("messages",),
        binding={"method": "POST", "path": "/v1/messages",
                 "body": ["model", "max_tokens", "messages"],
                 "input_schema": {
                     "type": "object",
                     "properties": {"model": {"type": "string"},
                                    "max_tokens": {"type": "integer"},
                                    "messages": {"type": "array"}},
                     "required": ["model", "max_tokens", "messages"]},
                 "usage_map": {"model": "model",
                               "input_tokens": "usage.input_tokens",
                               "output_tokens": "usage.output_tokens"}},
    )
    from carnet import agents

    agents.save(TENANT, {
        "name": "coding-agent", "runtime": "simple", "system": "irrelevant",
        "permissions": {
            "tools": ["gateway_chat_completions", "vendor_chat_completions",
                      "anthropic_chat"],
            "scope": {"azure.deployment": {"write": [DEPLOYMENT]},
                      "vendor.deployment": {"write": [VENDOR_MODEL]},
                      "anthropic.model": {"write": ["claude-haiku-4-5-20251001"]}},
        },
    }, actor=ADMIN)
    storage.active()  # the agent edit is committed before the server reads it

    ConnectProxy.allow_internet = True
    ConnectProxy.connects.clear()
    with Deployment("live", CARNET_EGRESS_INTERNAL_HOSTS=CLAIM,
                    REQUESTS_CA_BUNDLE=pki["ca_and_public"], CARNET_EGRESS_PROXY=PROXY,
                    ANTHROPIC_BROKERED_KEY=key):
        answer = httpx.post(f"{API}/mcp", timeout=60,
                            headers={"Authorization": f"Bearer {token}"},
                            json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                  "params": {"name": "anthropic_chat", "arguments": {
                                      "model": "claude-haiku-4-5-20251001",
                                      "max_tokens": 16,
                                      "messages": [{"role": "user",
                                                    "content": "Reply with the single word: ok"}]}}})
        check("the door answered", answer.status_code, 200)
        result = answer.json().get("result", {})
        check("and the call was not an error", result.get("isError") is True, False)
        body = json.dumps(result)
        says("a real model replied through the tunnel", body.lower(), "ok")
        check("the proxy carried it, by name",
              [c for c in ConnectProxy.connects if c.startswith("api.anthropic.com")],
              ["api.anthropic.com:443"])
        row = last_row(store)
        check("and it is on the audit log with real counters",
              (row.get("decision"), (row.get("input_tokens") or 0) > 0), ("allow", True))

    say("and the trap the documentation names: the corporate root ALONE")
    # `.env.example` and `UPGRADING.md` both say REQUESTS_CA_BUNDLE *replaces* the
    # bundled public roots rather than adding to them, and tell an operator who also
    # dials the internet to concatenate. That sentence is either true or it is a
    # support ticket, so it is asserted against the real internet rather than believed.
    with Deployment("live-ca-only", CARNET_EGRESS_INTERNAL_HOSTS=CLAIM,
                    REQUESTS_CA_BUNDLE=pki["ca_only"], CARNET_EGRESS_PROXY=PROXY,
                    ANTHROPIC_BROKERED_KEY=key):
        refused = call(token, "anthropic_chat", model="claude-haiku-4-5-20251001",
                       max_tokens=8,
                       messages=[{"role": "user", "content": "Reply: ok"}])
        check("a real vendor's certificate does not verify against the corporate root "
              "alone — the file replaces the public roots, exactly as documented",
              refused.get("isError"), True)
        says("and the failure is a TLS one, which is the shape of the ticket this "
             "sentence exists to prevent",
             json.dumps(refused), "SSL")
    ConnectProxy.allow_internet = False


# --- the run ------------------------------------------------------------------------

SECRET_KEY = base64.b64encode(os.urandom(32)).decode()


def main() -> int:
    import psycopg

    if socket.gethostbyname(INTERNAL_HOST) != "127.0.0.1":
        print(f"SKIPPED: {INTERNAL_HOST} did not resolve to 127.0.0.1; this needs DNS")
        return 0

    pki = corporate_pki()
    SCRATCH.mkdir(parents=True, exist_ok=True)

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")

    os.environ.update({
        "CARNET_DATABASE_URL": dsn_for(DB),
        "CARNET_SECRET_KEY": SECRET_KEY,
        "CARNET_TENANT": TENANT,
        "GATEWAY_KEY": GATEWAY_KEY,
        "VENDOR_KEY": VENDOR_KEY,
    })
    for name in ("CARNET_EGRESS_INTERNAL_HOSTS", "CARNET_EGRESS_PROXY",
                 "REQUESTS_CA_BUNDLE", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"):
        os.environ.pop(name, None)

    from carnet import storage
    from carnet.core import crypto
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    migrate.apply(dsn_for(DB))
    store = storage.configure(PostgresStorage(dsn_for(DB)))
    crypto.configure(crypto.from_environment())
    token = seed(store)

    servers: list = []
    servers.append(http.server.ThreadingHTTPServer(("127.0.0.1", PLAIN_PORT),
                                                   ModelGateway))
    for port, cert in ((GATEWAY_PORT, pki["gateway"]), (VENDOR_PORT, pki["vendor"])):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", port), ModelGateway)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*cert)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        servers.append(server)
    servers.append(http.server.ThreadingHTTPServer(("127.0.0.1", PROXY_PORT),
                                                   ConnectProxy))
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()

    try:
        for scene in (the_install_that_failed, the_estate_in_one_line,
                      the_model_gateway, through_the_proxy, the_edges):
            try:
                scene(token, store, pki)
            except Exception as exc:  # noqa: BLE001 - reported, never swallowed
                check(f"the scene {scene.__name__} ran to the end",
                      f"{type(exc).__name__}: {exc}", "no exception")
        try:
            the_front_door(pki)
        except Exception as exc:  # noqa: BLE001
            check("the scene the_front_door ran to the end",
                  f"{type(exc).__name__}: {exc}", "no exception")
        if "--live" in sys.argv:
            try:
                the_live_vendor(token, store, pki)
            except Exception as exc:  # noqa: BLE001
                check("the scene the_live_vendor ran to the end",
                      f"{type(exc).__name__}: {exc}", "no exception")
        else:
            print("\nlive: not requested (pass --live with ANTHROPIC_BROKERED_KEY set)")
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        store.close()

    failed = [label for label, ok in CHECKS if not ok]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    for label in failed:
        print(f"  FAILED: {label}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
