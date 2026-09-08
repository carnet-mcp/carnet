"""A real person signs into the DEPLOYED stack, against a provider that is not Okta.

Plan 031, tiers 2 and 3 — and tier 3 is the one nothing else can substitute for:
**CSP is enforced by a browser and by nothing else.** curl and httpx ignore it
entirely, which is precisely how a 64-check deploy e2e stayed green while every
sign-in on every provider was impossible. `e2e_deploy.py`'s `the_sign_in_wiring`
asserts the served config and policy *say* the right things; this script proves a
browser, obeying that policy, can actually complete the token exchange — and that
the policy still blocks everything it should.

The identity provider here is a throwaway OIDC stub in this process, and three of its
properties are the point:

  - **Its endpoint paths are deliberately not Okta's** (`/oauth2/authorize`, not
    `/v1/authorize`). The SPA resolves them from the stub's discovery document, so a
    regression to Okta-shaped path concatenation fails here by name instead of
    passing because the fixture happened to look like Okta — the exact blind spot
    that shipped the CSP defect.
  - **It is on its own origin**, unlike `carnet --local`, whose one-origin
    design keeps everything inside `'self'` — the one case that can never catch a
    `connect-src` mistake. Cross-origin is the whole test.
  - **It can put its token endpoint on a SECOND origin**, which is Google's real
    shape (`accounts.google.com` issues, `oauth2.googleapis.com` exchanges) and the
    only reason `CARNET_OIDC_EXTRA_ORIGINS` exists. That scene is also this
    script's mutation: with the variable unset the exchange must be **blocked**, so
    a green run proves the policy is enforced rather than merely present.

It is *kinder* than a real provider in one way `dev_idp.py` already documents:
everybody is always signed in, so `prompt=none` succeeds and the browser lands in
the app with nobody clicking anything. Refusal shapes and renewal timing are
`e2e_browser_local.py`'s subject, not this script's.

    cd backend && .venv/bin/python scripts/e2e_browser_deploy.py

Needs Docker with the compose plugin, `playwright` with its Chromium, and — for the
API container to fetch the stub's JWKS — `host.docker.internal` resolving inside
containers. Docker Desktop provides that by itself; a plain Linux engine does not,
so `CARNET_E2E_ADD_HOST=1` makes this script wire it — a compose *override* file
adding `host-gateway`, rather than an edit to the shipped compose.yaml for a test's
convenience — which is how CI runs it (the `deploy` job, step 054). With neither,
the browser tiers skip loudly, always with the word `SKIPPED:`, which that CI job
greps for and fails on. Its own compose project and ports, so it can run beside a
real stack. Costs nothing: no run is submitted — and since step 042 none could be,
because the door-only artifact does not register the route, which is now one of the
scenes.
"""

import base64
import hashlib
import http.server
import json
import os
import pathlib
import secrets
import subprocess
import sys
import threading
import time
import urllib.parse

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

REPO = pathlib.Path(__file__).resolve().parents[2]
COMPOSE_FILE = REPO / "deploy" / "compose.yaml"
SCRATCH = pathlib.Path(__file__).resolve().parent.parent / "var"

PROJECT = "carnet_e2e_signin"
HTTP_PORT = 8794
HTTPS_PORT = 8795
STUB_PORT = 8796
STUB_TOKEN_PORT = 8797
FRONT = f"https://localhost:{HTTPS_PORT}"

# The issuer as the BROWSER reaches it. Loopback, so a TLS-less stub is still a
# "potentially trustworthy origin" and neither mixed-content rules nor the CSP's
# scheme have to be bent for it.
ISSUER = f"http://127.0.0.1:{STUB_PORT}"
# The second origin, for the Google shape. Same host, different port — which is a
# different *origin* to a browser, and that is the only thing this scene needs.
TOKEN_ORIGIN = f"http://127.0.0.1:{STUB_TOKEN_PORT}"
# The same stub as the API CONTAINER reaches it: Docker Desktop maps
# host.docker.internal to this host. The issuer *claim* stays the browser-facing one —
# `--add-idp` matches tokens on `iss`, and `--jwks-uri` is separately configurable for
# exactly this kind of split view.
JWKS_URI_FROM_CONTAINER = f"http://host.docker.internal:{STUB_PORT}/oauth2/jwks"

CLIENT_ID = "carnet-e2e-spa"
TENANT = "e2esignin"
PERSON = "priya@example.test"

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True)
JWK.update({"kid": "e2e", "use": "sig", "alg": "RS256"})

# Installed in every document before any of its own script runs, so a violation
# cannot happen before somebody is listening for it. This is the only way to ask a
# browser "did my policy block anything I did not intend" — and the happy-path scenes
# assert the answer is *nothing*, which is what catches a directive tightened too far.
VIOLATION_COLLECTOR = """
window.__csp = [];
document.addEventListener('securitypolicyviolation', (e) => {
  window.__csp.push({directive: e.violatedDirective, blocked: e.blockedURI});
});
"""

CHECKS = []


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok, actual, expected))
    print(f"{'  ok' if ok else 'FAIL'}  {label}"
          + ("" if ok else f"  (got {actual!r}, wanted {expected!r})"), flush=True)
    return ok


def say(what):
    print(f"\n=== {what}", flush=True)


def report() -> int:
    failed = [row for row in CHECKS if not row[1]]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed", flush=True)
    for label, _ok, actual, expected in failed:
        print(f"  FAILED  {label}  (got {actual!r}, wanted {expected!r})")
    return 1 if failed else 0


def mint(sub: str, email: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {"iss": ISSUER, "aud": CLIENT_ID, "sub": sub, "email": email,
         "iat": now, "exp": now + 3600},
        KEY,
        algorithm="RS256",
        headers={"kid": "e2e"},
    )


class Stub(http.server.BaseHTTPRequestHandler):
    """The throwaway provider. Spec-shaped where it matters, generous where it may be.

    Class-level state, because ThreadingHTTPServer instantiates a handler per request
    — and because the *two* servers (issuer origin, token origin) are the same class
    and must share the issued codes.
    """

    codes: dict = {}  # code -> (challenge, redirect_uri, client_id)
    exchanges = 0
    token_origin = ISSUER  # flipped to TOKEN_ORIGIN for the Google-shape scene

    def _send(self, code, body: bytes, content_type="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # The token endpoint is called cross-origin from the app's page; without this
        # the browser blocks the *response* and the failure reads like the CSP one.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        query = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}

        if url.path == "/.well-known/openid-configuration":
            return self._send(200, json.dumps({
                "issuer": ISSUER,
                # NOT /v1/*. See the module docstring: these paths are the trap for
                # a regression to Okta-shaped concatenation.
                "authorization_endpoint": f"{ISSUER}/oauth2/authorize",
                "token_endpoint": f"{Stub.token_origin}/oauth2/token",
                "jwks_uri": f"{ISSUER}/oauth2/jwks",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "code_challenge_methods_supported": ["S256"],
            }).encode())

        if url.path == "/oauth2/jwks":
            return self._send(200, json.dumps({"keys": [JWK]}).encode())

        if url.path == "/framer":
            # A page on somebody else's origin that tries to frame the app. The only
            # way to ask a browser whether `frame-ancestors` still protects anything.
            return self._send(
                200,
                f'<!doctype html><title>framer</title>'
                f'<iframe src="{FRONT}/" width="600" height="400"></iframe>'.encode(),
                "text/html; charset=utf-8",
            )

        if url.path == "/oauth2/authorize":
            if query.get("client_id") != CLIENT_ID or not query.get("code_challenge"):
                return self._send(400, b'{"error":"invalid_request"}')
            code = secrets.token_urlsafe(24)
            Stub.codes[code] = (query["code_challenge"], query.get("redirect_uri", ""),
                                query["client_id"])
            redirect = query.get("redirect_uri", "")
            state = urllib.parse.quote(query.get("state", ""))
            joiner = "&" if "?" in redirect else "?"
            self.send_response(302)
            self.send_header(
                "Location",
                f"{redirect}{joiner}code={urllib.parse.quote(code)}&state={state}",
            )
            self.send_header("Content-Length", "0")
            self.end_headers()
            return None

        return self._send(404, b'{"error":"not_found"}')

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        if url.path != "/oauth2/token":
            return self._send(404, b'{"error":"not_found"}')
        length = int(self.headers.get("Content-Length", 0))
        form = {k: v[0] for k, v in
                urllib.parse.parse_qs(self.rfile.read(length).decode()).items()}
        held = Stub.codes.pop(form.get("code", ""), None)
        digest = hashlib.sha256(form.get("code_verifier", "").encode()).digest()
        hashed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        if (held is None or form.get("grant_type") != "authorization_code"
                or held[0] != hashed or held[1] != form.get("redirect_uri")
                or held[2] != form.get("client_id")):
            return self._send(400, b'{"error":"invalid_grant"}')
        Stub.exchanges += 1
        return self._send(200, json.dumps({
            "access_token": mint("e2e|priya", PERSON),
            "token_type": "Bearer",
            "expires_in": 3600,
        }).encode())


def compose(*args, **kwargs):
    files = ["-f", str(COMPOSE_FILE)]
    if ADD_HOST:
        files += ["-f", str(OVERRIDE_FILE)]
    return subprocess.run(
        ["docker", "compose", "-p", PROJECT, *files,
         "--env-file", str(ENV_FILE), *args],
        **kwargs,
    )


ENV_FILE = SCRATCH / "e2e_browser_deploy.env"
BASE_ENV: dict = {}

# Opt-in, and an override file rather than a compose.yaml edit, deliberately: on
# Docker Desktop `host.docker.internal` already resolves and the artifact should be
# driven exactly as shipped; a plain Linux engine (CI) needs the mapping, and it is a
# property of this test's world — the stub issuer lives on the host — not of the
# deployment.
ADD_HOST = bool(os.environ.get("CARNET_E2E_ADD_HOST"))
OVERRIDE_FILE = SCRATCH / "e2e_browser_deploy.override.yaml"


def write_env(**overrides) -> None:
    """The stack's `.env`. Overrides change the *front door's* declaration only, so
    the API and the database are untouched between scenes — 030's testing
    pass learned that regenerating a whole env to change one setting hands the API a
    password its database never heard of."""
    values = {**BASE_ENV, **overrides}
    ENV_FILE.write_text("".join(f"{k}={v}\n" for k, v in values.items()))


def preflight() -> str | None:
    for probe, missing in (
        (["docker", "info"], "Docker is not available"),
        (["docker", "compose", "version"], "the docker compose plugin is missing"),
    ):
        try:
            if subprocess.run(probe, capture_output=True, timeout=30).returncode != 0:
                return missing
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return missing
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError:
        return "playwright is not installed"
    return None


def container_reaches_stub() -> bool:
    """Can the API container reach this process? Docker Desktop: yes, via
    host.docker.internal. Plain Linux: only with extra wiring this script does not
    impose on the artifact — so it skips instead."""
    probe = compose(
        "exec", "-T", "api", "python", "-c",
        f"import socket; socket.create_connection(('host.docker.internal', "
        f"{STUB_PORT}), 5)",
        capture_output=True, text=True,
    )
    return probe.returncode == 0


def wait_for(url: str, client: httpx.Client, deadline_s: float = 180.0) -> bool:
    stop = time.monotonic() + deadline_s
    while time.monotonic() < stop:
        try:
            if client.get(url).status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(2)
    return False


def restart_front(**overrides) -> None:
    """Re-declare the provider and bring the front door back on it."""
    write_env(**overrides)
    compose("up", "-d", "front", capture_output=True, text=True)
    with httpx.Client(verify=False, timeout=15) as client:
        wait_for(f"{FRONT}/api/health", client, deadline_s=90)


def sign_in(browser, expect_signed_in: bool):
    """One clean browser, one page load, one verdict. Returns (mounted, violations)."""
    context = browser.new_context(ignore_https_errors=True)
    context.add_init_script(VIOLATION_COLLECTOR)
    page = context.new_page()
    console: list = []
    page.on("console", lambda m: console.append(f"{m.type}: {m.text}"))
    try:
        page.goto(FRONT)
        try:
            if expect_signed_in:
                page.wait_for_selector("aside.sidebar", timeout=30000)
                mounted = True
            else:
                # The sign-in screen is what a failed boot renders; waiting for it is
                # the positive form of "did not get in".
                page.wait_for_selector("button.btn.primary", timeout=30000)
                mounted = False
        except Exception:
            mounted = page.locator("aside.sidebar").count() > 0
            print("  console during the attempt:")
            for line in console[-15:]:
                print(f"    {line}")
        page.wait_for_timeout(500)
        violations = page.evaluate("window.__csp || []")
        who = (page.locator(".whoami").inner_text()
               if mounted and page.locator(".whoami").count() else "")
        # Every sentence on the screen, joined. The sign-in screen carries two
        # `p.sentence` — its standing invitation and, when there is one, the reason
        # the last attempt failed — so asking for "the" sentence is a strict-mode
        # violation, and asking for the first or the last is a bet on their order.
        reason = "\n".join(page.locator("p.sentence").all_inner_texts())
        return mounted, violations, who, reason, page, context
    except Exception:
        context.close()
        raise


def the_single_origin_provider(browser) -> None:
    """The ordinary shape: one provider origin, declared, and a person gets in."""
    say("a person opens the deployed app; the stub holds a session, so the silent "
        "path signs them in with nobody clicking anything")
    before = Stub.exchanges
    mounted, violations, who, _reason, _page, context = sign_in(browser, True)
    check("the app mounted signed-in — discovery, authorize, callback and the "
          "cross-origin token exchange, all under the served CSP", mounted, True)
    check("...as the person the stub vouched for", PERSON in who, True)
    check("...and the exchange really crossed origins into the stub",
          Stub.exchanges > before, True)
    # The check that catches a directive tightened too far. A policy that blocks a
    # font, an inline style or an image breaks the app in a way no HTTP check sees,
    # and the app still "mounts" — so mounting is not enough evidence on its own.
    check("...with the browser reporting NO policy violation of any kind",
          violations, [])
    context.close()


def the_policy_still_refuses(browser) -> None:
    """The other half: a policy that permits the provider must permit nothing else."""
    say("the policy still blocks everywhere else — asked of the browser itself")
    context = browser.new_context(ignore_https_errors=True)
    context.add_init_script(VIOLATION_COLLECTOR)
    page = context.new_page()
    page.goto(FRONT)
    page.wait_for_selector("aside.sidebar", timeout=30000)

    blocked = page.evaluate(
        """() => new Promise(resolve => {
             document.addEventListener('securitypolicyviolation',
               e => resolve(e.violatedDirective), {once: true});
             fetch('http://127.0.0.1:9/never-allowed').catch(() => {});
             setTimeout(() => resolve('no violation'), 3000);
           })"""
    )
    # Only a browser can make this check: an HTTP client would happily connect.
    check("a fetch to an undeclared origin violates connect-src", blocked,
          "connect-src")
    context.close()

    say("frame-ancestors: 'self' let the renewal iframe live — it must still refuse "
        "a stranger")
    # The security half of the 'none' -> 'self' change. 030 added frame-ancestors for
    # clickjacking; 031 loosened it exactly enough for the app to frame its own
    # callback, and this is the proof that "exactly enough" is what happened.
    outer = browser.new_context(ignore_https_errors=True)
    framer = outer.new_page()
    complaints: list = []
    framer.on("console", lambda m: complaints.append(m.text))
    framer.goto(f"{ISSUER}/framer")
    framer.wait_for_timeout(2500)
    refused = any("frame-ancestors" in c or "Refused to frame" in c
                  for c in complaints)
    if not refused:
        print(f"  console on the framing page: {complaints[-5:]}")
    check("another origin cannot frame the app", refused, True)
    outer.close()


def the_google_shape(browser) -> None:
    """A token endpoint on a second origin — and the mutation that proves the policy.

    This is the only scene that exercises `CARNET_OIDC_EXTRA_ORIGINS`, whose entire
    reason to exist is Google: `accounts.google.com` issues and
    `oauth2.googleapis.com` exchanges. Undeclared first, on purpose — if sign-in
    succeeded there, `connect-src` would be decorative and every other check in this
    file would be worth nothing.
    """
    Stub.token_origin = TOKEN_ORIGIN
    try:
        say("the Google shape, undeclared: the token endpoint moves to a second "
            "origin and NOTHING says so — the exchange must be refused")
        restart_front(CARNET_OIDC_EXTRA_ORIGINS="")
        before = Stub.exchanges
        mounted, violations, _who, reason, _page, context = sign_in(browser, False)
        check("the person does NOT get in", mounted, False)
        check("...the browser blocked the exchange at connect-src",
              any(v["directive"] == "connect-src"
                  and TOKEN_ORIGIN in v["blocked"] for v in violations), True)
        check("...the stub was never asked to exchange anything",
              Stub.exchanges, before)
        # The sentence a customer would read. It names all three causes because a
        # browser refuses to tell a script which one it was.
        check("...and the screen names the token endpoint as unreachable",
              "token endpoint" in reason, True)
        context.close()

        say("the Google shape, declared: CARNET_OIDC_EXTRA_ORIGINS names the second "
            "origin and the same sign-in completes")
        restart_front(CARNET_OIDC_EXTRA_ORIGINS=TOKEN_ORIGIN)
        with httpx.Client(verify=False, timeout=15) as client:
            policy = client.get(f"{FRONT}/").headers.get("content-security-policy", "")
        check("the served CSP now names both origins",
              ISSUER in policy and TOKEN_ORIGIN in policy, True)
        before = Stub.exchanges
        mounted, violations, who, _reason, _page, context = sign_in(browser, True)
        check("the person gets in against a split-origin provider", mounted, True)
        check("...as themselves", PERSON in who, True)
        check("...the exchange reached the second origin",
              Stub.exchanges > before, True)
        check("...and nothing was blocked this time", violations, [])
        context.close()
    finally:
        Stub.token_origin = ISSUER
        restart_front(CARNET_OIDC_EXTRA_ORIGINS="")


def main() -> int:
    global BASE_ENV

    reason = preflight()
    if reason:
        print(f"SKIPPED: {reason}. The browser deploy e2e needs a container runtime "
              "and playwright; everything else in scripts/ still runs.")
        return 0

    from carnet.core import crypto
    from playwright.sync_api import sync_playwright

    SCRATCH.mkdir(parents=True, exist_ok=True)
    if ADD_HOST:
        OVERRIDE_FILE.write_text(
            "services:\n"
            "  api:\n"
            "    extra_hosts:\n"
            '      - "host.docker.internal:host-gateway"\n'
        )
    BASE_ENV = {
        "CARNET_DOMAIN": "localhost",
        "CARNET_SECRET_KEY": crypto.generate_key(),
        "COMPOSE_PROFILES": "bundled-db",
        "CARNET_DB_PASSWORD": secrets.token_hex(16),
        "CARNET_HTTP_PORT": str(HTTP_PORT),
        "CARNET_HTTPS_PORT": str(HTTPS_PORT),
        "CARNET_OIDC_ISSUER": ISSUER,
        "CARNET_OIDC_CLIENT_ID": CLIENT_ID,
    }
    write_env()

    servers = [
        http.server.ThreadingHTTPServer(("0.0.0.0", STUB_PORT), Stub),
        http.server.ThreadingHTTPServer(("0.0.0.0", STUB_TOKEN_PORT), Stub),
    ]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()

    try:
        say("up: the real artifact, declaring the stub as its identity provider")
        built = compose("up", "-d", "--build", capture_output=True, text=True)
        if not check("docker compose up succeeds", built.returncode, 0):
            print(built.stderr[-2000:])
            return report()

        with httpx.Client(verify=False, timeout=15) as client:
            answered = wait_for(f"{FRONT}/api/health", client)
        if not check("the front door answers", answered, True):
            # `up` exits 0 for a stack whose front container is restart-looping, and
            # a container that exits *successfully* leaves no log to read. Ask docker
            # what state it is in, since the container will not volunteer it.
            state = compose("ps", "--format", "json", "front",
                            capture_output=True, text=True).stdout.strip()
            logs = compose("logs", "--tail", "30", "front",
                           capture_output=True, text=True)
            print(f"  front container: {state[:400]}")
            print(f"  front logs: {(logs.stdout + logs.stderr)[-1500:] or '(none)'}")
            return report()

        if not container_reaches_stub():
            print("SKIPPED: the api container cannot reach host.docker.internal, so "
                  "it could never fetch the stub's JWKS. Docker Desktop provides "
                  "this; on a plain Linux engine set CARNET_E2E_ADD_HOST=1 and "
                  "this script wires it itself. The wiring tier still ran in "
                  "e2e_deploy.py.")
            return report()

        say("the backend half: the same issuer, registered through the real CLI")
        added = compose("exec", "-T", "api", "carnet",
                        "--add-tenant", TENANT, "Sign-in Corp",
                        capture_output=True, text=True)
        check("--add-tenant", added.returncode, 0)
        idp = compose("exec", "-T", "api", "carnet",
                      "--add-idp", TENANT,
                      "--issuer", ISSUER,
                      "--jwks-uri", JWKS_URI_FROM_CONTAINER,
                      "--audience", CLIENT_ID,
                      "--domain", "example.test",
                      capture_output=True, text=True)
        if not check("--add-idp takes the non-Okta issuer", idp.returncode, 0):
            print(idp.stderr[-1000:])

        say("tier 2: a token from the non-Okta issuer, through the front door")
        with httpx.Client(verify=False, timeout=30) as client:
            me = client.get(
                f"{FRONT}/api/me",
                headers={"Authorization": f"Bearer {mint('e2e|priya', PERSON)}"},
            )
            check("/api/me accepts it", me.status_code, 200)
            check("...for the right person",
                  me.status_code == 200 and me.json().get("email"), PERSON)

        say("the run surface is absent from the deployed door, not forbidden")
        # What the deployed artifact must prove is the tree's claim at this layer (step
        # 078): the run-submission route is not registered — a 404 under a *valid* bearer, so this is absence, not an
        # auth refusal wearing absence's number — and the OpenAPI document does not
        # advertise what would 404.
        with httpx.Client(verify=False, timeout=30) as client:
            headers = {"Authorization": f"Bearer {mint('e2e|priya', PERSON)}"}
            accepted = client.post(f"{FRONT}/api/runs", headers=headers,
                                   json={"agent": "waiter", "task": "hold"})
            check("run submission does not exist in the door-only artifact",
                  accepted.status_code, 404)
            spec = client.get(f"{FRONT}/api/openapi.json").json()
            check("...and openapi.json does not advertise it",
                  [p for p in spec.get("paths", {}) if p.startswith("/runs")], [])

        say("tier 3: the browser — the only judge a CSP has")
        with sync_playwright() as p:
            # The front door's TLS is Caddy's own CA on a localhost trial; the browser
            # not trusting it is expected and not what this script is about.
            browser = p.chromium.launch()
            try:
                for scene in (the_single_origin_provider, the_policy_still_refuses,
                              the_google_shape):
                    try:
                        scene(browser)
                    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
                        check(f"the scene {scene.__name__} ran to the end",
                              f"{type(exc).__name__}: {exc}", "no exception")
            finally:
                browser.close()
    finally:
        say("down (volumes too)")
        compose("down", "-v", "--remove-orphans", "-t", "5",
                capture_output=True, text=True)
        ENV_FILE.unlink(missing_ok=True)
        OVERRIDE_FILE.unlink(missing_ok=True)
        for server in servers:
            server.shutdown()
            server.server_close()
    return report()


if __name__ == "__main__":
    sys.exit(main())
