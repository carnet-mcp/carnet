"""The administration surface in a real browser, from an empty database. One command.

12c's one done-when that is not a test: *the whole wizard as the bootstrap admin, from a
fresh world, no CLI after `uvicorn` starts, ending with a second signed-in person seeing a
Connect button.*

    cd backend && .venv/bin/python scripts/e2e_browser_admin.py

**It starts everything itself** — the dev identity provider, a real MCP server, uvicorn,
and the Vite dev server — rather than asking for three terminals the way
`browser_world.py` + `e2e_browser_roles.py` do. That is not tidiness: this check is about
a *sequence* an administrator performs, and a setup that takes three coordinated commands
is one nobody re-runs after changing a form. The cost is a slower start-up and a
dependency on `npm`, both of which are worth it for a check somebody will actually repeat.

## What it looks at, and why each one needs a browser rather than a request

```
the nav item                 only administrators see it — and priya only becomes one by
                             logging in, so this is the bootstrap variable observed from
                             the outside
the ordering                 registration genuinely unavailable until a host exists, with
                             the reason on screen rather than a disabled control
a pasted URL                 the sentence about what to strip, rendered where it was typed
a never-dialled host         approved, marked in the list, and NOT counted as a host that
                             unlocks registration
discovery                    argument names and requiredness on screen — the one thing a
                             person cannot guess, and the reason the screen exists
approving a tool             a resource picked from the discovered names, and the refusal
                             when a write has nothing to scope it to
the consent flow             a password field, a redirect URI on success, and the word
                             "stored" rather than a masked secret
her own connection            what is behind it when it lapses, and — the negative
                             that matters — nothing about an access token that expired
                             two hours ago and will be renewed by the next run
sam                          a Connect button, having administered nothing
the six dark routes          035j: the door's traffic as a row written by one real
                             /mcp call, sam's refusal read back on the denial log,
                             an old version's own words, and the three truths of a
                             world where nothing has run — conversations' doors,
                             the runs list's honest empty, and a 404 in the
                             server's sentence
```

Every one of these is a rendering decision. `e2e_admin_onboarding.py` already proves the
routes; what it cannot prove is that a person can find the next thing to do, which is the
entire content of "self-serve".

**Costs nothing.** No run is submitted, so no model is called, and the MCP server is a
local socket.

Needs `playwright` and its Chromium (`uv pip install playwright && playwright install
chromium`), `npm` with the frontend's dependencies installed, Postgres up, and outbound
DNS for `localtest.me` — see `e2e_http_connector.py` for why the host cannot be a literal
loopback address.
"""

import json
import os
import pathlib
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urlunsplit

import httpx
from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parent.parent
FRONTEND = ROOT.parent / "frontend"

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_browser_admin"
BASE_DSN = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"

TENANT = "browseradmin"
IDP_PORT = 8903
API_PORT = 8004
# **Its own port, not 8080, and `--strictPort`.** The first run of this script silently
# attached to a Vite dev server somebody had left running from another session — one
# started without `VITE_OIDC_ISSUER`, which at the time fell back to a hardcoded *real
# Okta org*, so the browser sat on a password form until the timeout. `wait_for(APP)`
# had cheerfully reported the app was up, because something was answering. (That
# fallback is gone — an unconfigured app now says so instead of sending people to
# somebody else's provider — but attaching to the wrong dev server is still a way to
# test a page this script did not build.)
#
# A port nobody else uses makes that unlikely, and `--strictPort` makes it *loud*: Vite
# refuses to start rather than quietly taking the next free port, which is the failure
# mode that produced twenty minutes of debugging a screen that was not the one under test.
MCP_PORT = 8933
APP_PORT = 8085

APP = f"http://localhost:{APP_PORT}"
IDP = f"http://127.0.0.1:{IDP_PORT}"

# Resolves to 127.0.0.1 and is not a literal IP, so the egress check passes on the name.
HOST = "localtest.me"
MCP_URL = f"http://{HOST}:{MCP_PORT}/mcp"

BOOTSTRAP_EMAIL = "priya@acme.com"
SECOND_PERSON = "sam@acme.com"

TOOLS = [
    {
        "name": "list_issues",
        "description": "List issues in a repository.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "state": {"type": "string"},
            },
            "required": ["owner", "repo"],
        },
    },
    {
        "name": "delete_repository",
        "description": "Delete a repository and everything in it.",
        "inputSchema": {
            "type": "object",
            "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}},
            "required": ["owner", "repo"],
        },
    },
]

CHECKS = []


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok))
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: {actual!r}" + ("" if ok else f"  (expected {expected!r})"))


def says(label, actual, fragment):
    ok = fragment in (actual or "")
    CHECKS.append((label, ok))
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: {fragment!r} present={ok}")


def say(what):
    print(f"\n=== {what}", flush=True)


def dsn_for(database: str) -> str:
    parts = urlsplit(BASE_DSN)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


class MCPServer(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        message = json.loads(self.rfile.read(length) or "{}")
        if "id" not in message:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if message["method"] == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "acme-mcp-server", "version": "4.1.0"},
            }
        elif message["method"] == "tools/list":
            result = {"tools": TOOLS}
        elif message["method"] == "tools/call":
            # 035j. A real answer rather than `{}`, because the door-traffic scene makes
            # one genuine `tools/call` through the door and an empty result would be
            # recorded as a malformed upstream rather than a call that worked.
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps([{"id": 41, "title": "Fix the deploy"}]),
                    }
                ],
                "isError": False,
            }
        else:
            result = {}

        body = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Mcp-Session-Id", "sess-1")
        self.end_headers()
        self.wfile.write(body)


def wait_for(url, seconds=90):
    for _ in range(seconds * 2):
        try:
            httpx.get(url, timeout=1)
            return
        except Exception:
            time.sleep(0.5)
    raise SystemExit(f"{url} never answered")


def refuse_if_taken(*ports):
    """Refuse to start if somebody else already holds one of these ports.

    **Because attaching to somebody else's server is worse than not starting.** This
    script's first run found a Vite dev server left over from another session on 8080,
    configured against the real Okta org; every wait-for succeeded, the browser was sent
    to a real password form, and the failure surfaced thirty seconds later as a missing
    CSS selector. A check that costs one socket each turns that into a sentence.
    """
    import socket

    for port in ports:
        with socket.socket() as probe:
            probe.settimeout(0.5)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                raise SystemExit(
                    f"something is already listening on 127.0.0.1:{port}. This script "
                    "starts its own identity provider, API, MCP server and dev server, "
                    "and attaching to somebody else's would test the wrong thing — the "
                    "first time that happened the browser was sent to a real Okta org. "
                    "Stop it, or change the port constants at the top of this file."
                )


def main():
    import base64

    import psycopg

    refuse_if_taken(IDP_PORT, API_PORT, MCP_PORT, APP_PORT)

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import dev_idp

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")

    dsn = dsn_for(DB)
    os.environ["CARNET_DATABASE_URL"] = dsn
    # Step 058: the dial vets DNS answers, and localtest.me resolves to loopback
    # on purpose — the operator (this script) consents to its own machine.
    os.environ["CARNET_EGRESS_INTERNAL_HOSTS"] = "localtest.me"
    os.environ.setdefault("CARNET_SECRET_KEY", base64.b64encode(os.urandom(32)).decode())
    os.environ["CARNET_WORKERS"] = "0"
    os.environ["CARNET_TENANT"] = TENANT

    _, provider = dev_idp.serve(IDP_PORT)

    from carnet import storage
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    migrate.apply(dsn)
    store = storage.configure(PostgresStorage(dsn))

    # **A tenant and an identity provider, and nothing else.** No seed, no connector, no
    # allowlist entry, no role, and — unlike `browser_world.py` — no user rows either.
    # Both people are created by logging in, which is what makes the first screen priya
    # sees evidence about the bootstrap variable rather than about a fixture.
    store.create_tenant(TENANT, "12c browser check")
    store.save_tenant_idp(
        TENANT,
        {
            "issuer": provider.issuer,
            "jwks_uri": f"{provider.issuer}/v1/keys",
            "audience": dev_idp.AUDIENCE,
            "subject_claim": "uid",
            "email_claim": "sub",
            "allowed_domains": ("acme.com",),
        },
    )
    store.close()

    mcp = ThreadingHTTPServer(("127.0.0.1", MCP_PORT), MCPServer)
    threading.Thread(target=mcp.serve_forever, daemon=True).start()

    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port", str(API_PORT)],
        env={**os.environ, "CARNET_BOOTSTRAP_ADMIN": BOOTSTRAP_EMAIL},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    vite = subprocess.Popen(
        ["npm", "run", "dev", "--", "--port", str(APP_PORT), "--strictPort"],
        cwd=str(FRONTEND),
        env={
            **os.environ,
            "VITE_OIDC_ISSUER": provider.issuer,
            "VITE_OIDC_CLIENT_ID": "dev",
            "VITE_OIDC_SCOPES": "openid",
            # The dev server proxies `/api` onward, and this run's API is not on the
            # default port either — see `API_PORT`.
            "VITE_API_ORIGIN": f"http://127.0.0.1:{API_PORT}",
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        wait_for(f"http://127.0.0.1:{API_PORT}/health")
        wait_for(APP)
        drive()
    finally:
        api.terminate()
        vite.terminate()
        mcp.shutdown()

    failed = [label for label, ok in CHECKS if not ok]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    for label in failed:
        print(f"  FAILED  {label}")
    raise SystemExit(1 if failed else 0)


def nav(page):
    return [t.strip() for t in page.locator("nav.sidebar-nav a").all_inner_texts()]


def sign_in(page, email):
    """Sign in as `email`. **Through the button, because silent renewal 400s.**

    `/_be/<email>` decides who the *next* authorization is for, so the whole of "sign in as
    somebody else" is one request to the provider before navigating.

    The waiting is the part that is not obvious, and getting it wrong cost this script its
    first run. A page load tries **silent renewal first** — an iframe with `prompt=none` —
    and only falls back to a Sign in button when that fails. In stock headless Chromium it
    always fails, with the same 400 `DEFERRED.md` records against Okta and 10d's browser
    check confirmed is not browser-specific: third-party cookies are gone, and the
    provider cannot see a session in an iframe.

    So there are two possible next states and a *race* between them, and code that checked
    for the button immediately found nothing and then waited thirty seconds for a shell
    that was never going to render. This waits for **either**, which is also the honest
    shape: whichever way a real person gets in, the assertions after it are the same.
    """
    httpx.get(f"{IDP}/_be/{email}", timeout=5)
    page.goto(f"{APP}/agents")
    page.wait_for_selector("aside.sidebar, button.btn.primary", timeout=30000)
    if page.locator("button.btn.primary").count():
        page.click("button.btn.primary")
    page.wait_for_selector("aside.sidebar", timeout=30000)
    page.wait_for_timeout(1500)


def drive():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()

        # --- the bootstrap variable, observed from outside -------------------------

        say("priya signs in for the first time — nobody has ever administered this workspace")
        sign_in(page, BOOTSTRAP_EMAIL)
        check("she is signed in", BOOTSTRAP_EMAIL in page.content(), True)
        # The whole of decision 1, seen the way a person sees it: she did nothing but log
        # in, and the nav item is there.
        check("and the audit log is offered", "Audit log" in nav(page), True)

        # **The redesign moved these**, and the scene says what the product now does
        # rather than what it did. The three sections used to sit in a sub-navigation
        # *behind* Administration; the sidebar carries them directly now (see the note
        # in `styles/features.css` where that class was deleted). What still has to be
        # true is decision 1's actual claim — an administrator is offered all three,
        # and the non-admin scene below is offered none of them.
        say("the three sections, offered in the sidebar to an administrator")
        page.click("nav.sidebar-nav a:has-text('Audit log')")
        check(
            "Audit log, Groups, Connectors",
            [i for i in nav(page) if i in ("Audit log", "Groups", "Connectors")],
            ["Audit log", "Groups", "Connectors"],
        )
        # **Waited for, not read immediately.** The log is fetched after the shell paints,
        # so reading `page.content()` straight after the nav renders is a race — it passed
        # on one run and failed on the next, which is worse than failing every time.
        page.wait_for_selector("table", timeout=15000)
        says("and the log already names her appointment", page.content(), "system:bootstrap")

        # --- the ordering ------------------------------------------------------------

        say("Connectors: nothing can be registered, and the page says why")
        page.click("nav.sidebar-nav a:has-text('Connectors')")
        # **Waited on the sentence, not on the card.** The heading paints before the
        # allowlist request answers, and 091 put the words "Approved hosts" in a
        # second place — the gate paragraph that points at this card — so the heading is
        # not even unambiguous any more. Wait for the thing being asserted: the empty
        # state's own first sentence, which nothing else on the page says.
        page.wait_for_selector("text=No approved hosts", timeout=15000)
        says(
            "an empty allowlist denies",
            page.content(),
            "Connectors can only connect to approved hosts",
        )
        check(
            "and there is no Register button to press",
            page.locator("button:has-text('Register')").count(),
            0,
        )

        say("she pastes a URL where a host belongs")
        page.fill("input[placeholder='mcp.acme.com']", MCP_URL)
        page.click("button:has-text('Approve')")
        page.wait_for_timeout(1200)
        # The whole reason the host goes in a body rather than a path segment: a `/` in a
        # path is a bare 404 with nothing to say, and this is what it says instead.
        says("the sentence tells her what to strip", page.content(), "just the hostname")
        check(
            "and registration is still unavailable",
            page.locator("button:has-text('Register')").count(),
            0,
        )

        say("she approves localhost by mistake — recorded, and marked")
        page.fill("input[placeholder='mcp.acme.com']", "localhost")
        page.click("button:has-text('Approve')")
        page.wait_for_timeout(1200)
        says("she is told it will not be dialled", page.content(), "will NOT be dialled")
        # The tag in the table, not the notice above the form that says the same words.
        check("the row is marked in the list",
              page.locator("td span.tag:has-text('not reachable')").count() >= 1, True)
        # **A warning is not an approval.** A host that can never be dialled must not
        # unlock the stage that depends on one, or the refusal arrives at the first run
        # instead of here.
        check(
            "and it does not unlock registration",
            page.locator("button:has-text('Register')").count(),
            0,
        )

        say("she approves the real one")
        page.fill("input[placeholder='mcp.acme.com']", HOST)
        page.click("button:has-text('Approve')")
        page.wait_for_timeout(1200)
        check(
            "registration is offered now",
            page.locator("button:has-text('Register')").count(),
            1,
        )

        # --- registration --------------------------------------------------------------

        # Step 070, and it is here rather than in its own section because the thing worth
        # observing is a *choice on this form* rather than a page: the credential is
        # either ours to hold or the customer's, the server refuses both being set, and a
        # form with two boxes is a form somebody fills in both of. What a browser adds
        # over `ConnectorsPage.test.tsx` is that the second box genuinely is not on the
        # page until the choice is made — under the served CSP, with the real stylesheet.
        say("first she reads what the form offers about where the credential lives")
        check(
            "the variable box is there and the vault box is not",
            (
                page.locator("input[placeholder='JIRA_TOKEN']").count(),
                page.locator("input[placeholder='op://Engineering/Jira/credential']").count(),
            ),
            (1, 0),
        )
        # The radio's own label, because `text=` is a case-insensitive substring and
        # "vault reference" is also the name of the field that appears once it is chosen.
        page.click("label.choice:has-text('Vault reference')")
        page.wait_for_timeout(400)
        check(
            "choosing the vault swaps them, so both can never be typed",
            (
                page.locator("input[placeholder='JIRA_TOKEN']").count(),
                page.locator("input[placeholder='op://Engineering/Jira/credential']").count(),
            ),
            (0, 1),
        )
        # The cost, on the screen where the choice is made. An option presented as a free
        # upgrade would be the form promising something the runtime cannot keep: one to
        # three requests to somebody else's service on every call, and a connector that
        # stops working while their vault is down.
        says("with what it costs said on the option itself", page.content(), "on every call")
        says("...including the failure it adds", page.content(), "while the vault is unavailable")

        say("she goes back to a credential this deployment holds, and registers")
        # Same anchor: "environment variable" is also in the credential field's hint.
        page.click("label.choice:has-text('Environment variable')")
        page.wait_for_timeout(400)

        page.fill("input[placeholder='jira']", "acme")
        page.fill("input[placeholder='https://mcp.acme.com/mcp']", MCP_URL)
        page.click("button:has-text('Register')")
        page.wait_for_timeout(1500)
        # Registering answers with a card rather than a notice now, so the sentence
        # that says nothing is approved yet is the card's own — scoped to it, because
        # the form below the cards ends with "approve the tools" in its own words.
        acme_card = page.locator("div.conn-card:has-text('acme')").first.inner_text()
        says("and is told nothing is approved yet", acme_card, "No tools approved yet")
        says("with the next thing to do", acme_card, "Open it to discover and approve tools")

        say("she opens it")
        page.click("div.conn-card:has-text('acme') a.btn:has-text('Open')")
        page.wait_for_selector("text=Registration", timeout=15000)
        says("nothing is approved yet", page.content(), "No tools approved")
        check(
            "and nothing has been dialled to say so",
            page.locator("text=acme-mcp-server").count(),
            0,
        )

        # --- discovery -------------------------------------------------------------------

        say("she looks at the server")
        page.click("button:has-text('Discover')")
        page.wait_for_selector("text=acme-mcp-server v4.1.0", timeout=30000)
        content = page.content()
        # **The reason the screen exists.** Not the tool names — the argument names, and
        # which of them are optional.
        says("owner is required", content, "owner (string, required)")
        says("repo is required", content, "repo (string, required)")
        says("state is optional", content, "state (string, optional)")
        says("the unvetted write is listed too", content, "delete_repository")

        # --- approving a tool --------------------------------------------------------

        say("she approves the read, scoped to a repository")
        page.click("div.row:has-text('list_issues') button:has-text('Approve…')")
        page.wait_for_selector("button:has-text('Add a resource')", timeout=15000)
        page.click("button:has-text('Add a resource')")
        page.fill("input[placeholder='jira.project']", "github.repo")
        # **Scoped to the resource row, not indexed within the form.** This was
        # `select >> nth=1`, which meant "the second select on the card" — true only
        # while the form had exactly two, and silently wrong the moment 033a added the
        # "Acts as" one between them: the script then tried to set an argument name on
        # the identity picker and spun until it timed out. The argument picker is the
        # select that sits beside the resource-type input, and saying so cannot drift.
        page.select_option("div.spread:has(input[placeholder='jira.project']) select", "repo")

        # 035g. **The one refusal this form makes itself**, and the reason it does: the
        # server's bound on this field is `Field(gt=0)` and therefore a 422, which the SPA
        # renders as `response.statusText` — "Unprocessable Entity", a status line in the
        # box where every other refusal on this page is a paragraph. A stored zero refuses
        # every response the tool will ever return, so the form says so instead.
        say("she types a zero into the response ceiling")
        tool_row = page.locator("div.row:has-text('list_issues')")
        tool_row.locator("input[type='number']").fill("0")
        # **Exact, and scoped to the row.** The submit is the one word "Approve"; an
        # unapproved row's toggle says "Approve…", an approved one's says "Edit
        # approval", and a re-approval submit says "Approve again" — all of which a
        # `has-text` substring would also match.
        tool_row.locator("button:text-is('Approve')").click()
        page.wait_for_timeout(800)
        says(
            "the form says what a zero would do",
            tool_row.inner_text(),
            "denies every response",
        )
        # The card is titled "Approved tools" whether or not anything is, so the assertion
        # is the sentence that says nothing is — the state a wizard has to be able to
        # render, and the one this refusal must leave the connector in.
        says(
            "and nothing was approved",
            page.locator("section.card:has-text('Approved tools')").inner_text(),
            "No tools approved",
        )

        say("she gives a real one, with a sentence about who owns the project")
        tool_row.locator("input[type='number']").fill("200000")
        page.get_by_label(re.compile(r"^Note")).fill("Finance owns this repository.")
        tool_row.locator("button:text-is('Approve')").click()
        page.wait_for_timeout(2000)
        says("it is approved, against a named server version", page.content(), "against acme-mcp-server v4.1.0")
        says("under the name a grant will use", page.content(), "acme_list_issues")

        say("she tries the write with nothing to scope it to")
        page.reload()
        page.wait_for_selector("button:has-text('Discover')", timeout=15000)
        page.click("button:has-text('Discover')")
        page.wait_for_selector("text=acme-mcp-server v4.1.0", timeout=30000)
        page.click("div.row:has-text('delete_repository') button:has-text('Approve…')")
        # By label rather than by ordinal, for the same reason as above.
        page.select_option(
            "div.row:has-text('delete_repository') select:has(option[value='write'])", "write"
        )
        page.wait_for_timeout(300)
        # The screen says it before the button is pressed, and the server says it after.
        says("the form warns first", page.content(),
             "A write tool with no resource cannot be approved")
        page.click("div.row:has-text('delete_repository') button:text-is('Approve')")
        page.wait_for_timeout(2000)
        # Until 12c this was a 500 — "Internal Server Error", to somebody whose remedy was
        # one more field.
        says("and the refusal says what to do instead", page.content(), "mark it read")

        say("the approved tool is on the connector, and the refused one is not")
        page.reload()
        page.wait_for_selector("text=Approved tools", timeout=15000)
        check("one approved tool", page.locator("text=acme_list_issues").count() >= 1, True)
        check(
            "and no approved write",
            page.locator("text=acme_delete_repository").count(),
            0,
        )
        # 035g. **Scoped to the row.** The note is also in the form above this table, in
        # the box she typed it into, so a page-wide check would pass on her own input and
        # prove nothing about the table — the `text=acme` lesson this file has now paid for
        # four times, at a table rather than a listing.
        approved = page.locator("section.card:has-text('Approved tools') table")
        says(
            "and the sentence she wrote at approval time is shown back",
            approved.inner_text(),
            "Finance owns this repository.",
        )
        says(
            "with the ceiling, as a size, and refused rather than truncated",
            approved.inner_text(),
            "195.3 kB are denied",
        )

        # 035g's edge pass found this one: `vet_tool` upserts the **whole row**, and this
        # form opened empty on `Approve again` — so pressing it on a scoped write and
        # changing nothing downgraded it to an unscoped read and erased the note. A mocked
        # api module cannot prove a form, which is why it is also checked here.
        say("she opens the approved tool again, and finds her own review in the form")
        page.click("button:has-text('Discover')")
        page.wait_for_selector("text=acme-mcp-server v4.1.0", timeout=30000)
        # **"Edit approval", not "Approve…"** — the words pass (107a) made the row's
        # toggle say which of the two things it does, and `list_issues` was approved two
        # scenes ago. The other two call sites in this file are first approvals and still
        # read "Approve…"; the submit inside the open form is still "Approve again".
        page.click("div.row:has-text('list_issues') button:has-text('Edit approval')")
        page.wait_for_timeout(500)
        again = page.locator("div.row:has-text('list_issues')")
        check(
            "the sentence she wrote is in the box",
            again.get_by_label(re.compile(r"^Note")).input_value(),
            "Finance owns this repository.",
        )
        check(
            "and the ceiling she set",
            again.locator("input[type='number']").input_value(),
            "200000",
        )
        check(
            "and what it touches",
            again.locator("input[placeholder='jira.project']").input_value(),
            "github.repo",
        )
        # The one half the wire deliberately does not return — `ResourceType` is `{type}`
        # alone, because a client handed the argument names would be invited to build a
        # scope out of them. So the picker is empty and the screen says so.
        says("with the half the API will not hand back", again.inner_text(),
             "Pick the argument for each again")

        say("and pressing approve without picking it again is refused, not dropped")
        page.click("button:has-text('Approve again')")
        page.wait_for_timeout(800)
        says(
            "because a dropped resource is a scope somebody named and did not get",
            again.inner_text(),
            "Pick one, or remove the row",
        )
        page.reload()
        page.wait_for_selector("text=Approved tools", timeout=15000)
        says(
            "and the approval is exactly as it was",
            page.locator("section.card:has-text('Approved tools') table").inner_text(),
            "Finance owns this repository.",
        )

        # --- the consent flow -----------------------------------------------------------

        say("she configures an OAuth app")
        page.click("button:has-text('Set up OAuth app')")
        page.wait_for_selector("text=Authorize endpoint", timeout=15000)
        secret = page.locator("input[type='password']")
        check("the secret field is a password field", secret.count(), 1)

        page.fill("input[placeholder='https://auth.acme.com/authorize']", f"https://{HOST}/authorize")
        page.fill("input[placeholder='https://auth.acme.com/token']", f"https://{HOST}/token")
        page.get_by_label("Client ID").fill("client-abc")
        secret.fill("MARKER-CLIENT-SECRET-b71a")
        page.fill("input[placeholder='read:jira-work offline_access']", "read:issues offline_access")

        # 035g. **The refusal that is a paragraph, and the reason a form and not a JSON
        # box.** Every value here is an `<input>`'s value, so `dict[str, str]` is true by
        # construction and no keystroke can produce a 422 — which means the seven reserved
        # names come back as 400s carrying the sentence that explains the security design.
        say("she tries to set the one parameter that would make her tenant forgeable")
        page.click("button:has-text('Add a parameter')")
        page.fill("input[placeholder='audience']", "state")
        page.fill("input[placeholder='api.atlassian.com']", "guessable")
        page.click("button:has-text('Save OAuth app')")
        page.wait_for_timeout(1500)
        says(
            "and is told why the platform builds that one itself",
            page.content(),
            "makes every consent flow in this tenant forgeable",
        )
        says("verbatim, callback and all", page.content(), "the callback carries no token")

        say("she sets the one her provider actually mandates")
        page.fill("input[placeholder='audience']", "audience")
        page.fill("input[placeholder='api.atlassian.com']", "api.acme.com")
        page.click("button:has-text('Save OAuth app')")
        page.wait_for_timeout(2000)

        content = page.content()
        says("the redirect URI to register at the provider is shown", content, "/connect/callback")
        check("the secret is nowhere on the page", "MARKER-CLIENT-SECRET-b71a" in content, False)
        says("and the stored state says stored", content, "stored")
        # Not `••••••`, which would imply the value can be read back. It cannot, by anybody.
        check("with no masked echo", "•" in content, False)
        # The read half plan 035 never named: a connector a CLI had configured with an
        # audience showed an administrator nothing about it. Scoped to the OAuth app
        # card, because the form above it holds the same string in a box she typed it into.
        flow = page.locator("section.card:has-text('OAuth app')").inner_text()
        says("and what it also sends is on the screen at last", flow, "audience=api.acme.com")

        # 035g. The `PUT` replaces wholesale — that is how a rotated secret is installed —
        # so a blank Replace form is a data-loss control. It opens with what is stored.
        say("she presses Replace, and finds her own configuration in it")
        page.click("button:text-is('Replace')")
        page.wait_for_timeout(800)
        check(
            "the scopes she set are still in the box",
            page.locator("input[placeholder='read:jira-work offline_access']").input_value(),
            "read:issues offline_access",
        )
        check(
            "and so is the parameter",
            page.locator("input[placeholder='audience']").input_value(),
            "audience",
        )
        check(
            "the secret is not, and cannot be",
            page.locator("input[type='password']").input_value(),
            "",
        )
        says(
            "which the screen says rather than leaving her to find at the button",
            page.content(),
            "replaces the whole OAuth app",
        )
        page.click("button:has-text('Cancel')")
        page.wait_for_timeout(500)

        # --- a connector born believing a caller ---------------------------------------

        say("she registers a second connector that trusts its caller from birth")
        page.goto(f"{APP}/admin/connectors")
        # **Waited on the card, not on the page.** 091 moved the allowlist below the
        # connectors, so its heading no longer implies the connector list has landed —
        # and the two are fetched in parallel. Wait for the thing being read.
        page.wait_for_selector("div.conn-card:has-text('acme')", timeout=15000)
        acme_row = page.locator("div.conn-card:has-text('acme')").first
        check(
            "the first one is not marked, because verified-or-nothing is the posture",
            "asserted identity" in acme_row.inner_text(),
            False,
        )

        page.fill("input[placeholder='jira']", "trusted")
        page.fill("input[placeholder='https://mcp.acme.com/mcp']", MCP_URL)
        page.check("input[type='checkbox']")
        page.click("button:has-text('Register')")
        page.wait_for_timeout(1500)

        # **Scoped to the card.** The registration form below these cards describes the
        # same control in the same words — deliberately, so two screens cannot word one
        # control differently — and a page-wide check would pass on the form's own copy.
        trusted_row = page.locator("div.conn-card:has-text('trusted')").inner_text()
        says("the row says so at a glance", trusted_row, "asserted identity")
        says("and says what it is worth", trusted_row, "without verification")
        check(
            "and the first connector is still unmarked",
            "asserted identity"
            in page.locator("div.conn-card:has-text('acme')").first.inner_text(),
            False,
        )

        say("and the flag really landed at registration rather than only in the form")
        page.click("div.conn-card:has-text('trusted') a.btn:has-text('Open')")
        # On the heading, exactly: "on behalf of" is also inside the card's own sentence
        # and in the registration copy, so a `text=` substring would wait for nothing.
        page.wait_for_selector("h2:text-is('On behalf of')", timeout=15000)
        says(
            "the connector's own page states the posture it was born with",
            page.locator("section.card:has(h2:text-is('On behalf of'))").inner_text(),
            "without verification",
        )
        check(
            "and offers the one deliberate action that would change it back",
            page.locator("button:has-text('Stop accepting asserted identity')").count(),
            1,
        )

        # --- groups ------------------------------------------------------------------

        say("she makes a group")
        page.goto(f"{APP}/admin/groups")
        page.wait_for_selector("text=New group", timeout=15000)
        # Anchored, because `get_by_label` matches the accessible name as a
        # **case-insensitive substring** and `Field` folds its hint into that name. 033e
        # added a "Directory group" field whose hint reads *"…an object id in Entra, a
        # name in Okta."* — so a bare "Name" began matching two inputs and this script
        # has been failing since that step landed. Nothing caught it: the browser checks
        # are not in CI, which is the standing gap 035j exists to close.
        #
        # Anchored with `^Name` and not `^Name\b`: `Field` renders label and hint as
        # adjacent spans, so the accessible name arrives as "NameWhat people will call
        # it…" with no separator, and there is no word boundary to match.
        page.get_by_label(re.compile(r"^Name")).fill("oncall")
        page.click("button:has-text('Create group')")
        page.wait_for_timeout(1500)
        check("it is listed", page.locator("text=oncall").count() >= 1, True)

        page.click("button:has-text('Members')")
        page.wait_for_timeout(1200)
        says("an empty group reaches nobody", page.content(), "No members yet")

        # Step 035h. **Both kinds are labelled**, and which one is the norm is a property
        # of the deployment — so a single badge would be read as *the exception* by every
        # reader and half of them would read it backwards. The second group is linked at
        # creation, through the field 033e added.
        say("a group says where its membership comes from, before anybody opens it")
        page.get_by_label(re.compile(r"^Name")).fill("eng")
        page.get_by_label(re.compile(r"^Directory group")).fill("dir-eng-8f2c")
        page.click("button:has-text('Create group')")
        page.wait_for_timeout(1500)

        # **Scoped to the row, not to the page** — the create form's own hint says "The
        # group's id in your directory", so a page-wide assertion here would pass on copy
        # that has nothing to do with these labels. That file has now paid for the
        # substring lesson six times.
        eng = page.locator(".row:has-text('eng')").first.inner_text()
        oncall = page.locator(".row:has-text('oncall')").first.inner_text()
        says("the linked one is from the directory", eng, "from your directory")
        says("and says where its members come from", eng, "Membership comes from your directory")
        says("the hand-made one is managed here", oncall, "managed here")
        check(
            "and is not also called a directory group",
            "from your directory" in oncall,
            False,
        )
        # A count is the first step of the company directory this shape refuses to be, and
        # a badge that fetched each group's membership would rebuild it out of N requests.
        # The negative is the assertion: the listing carries no member count at all.
        check(
            "and no member count arrived with the badge",
            re.search(r"\d+ (member|people|person)", eng) is not None,
            False,
        )

        say("deleting names the consequence rather than asking twice")
        page.click("button:has-text('Delete group')")
        page.wait_for_timeout(500)
        content = page.content()
        says("it says what goes", content, "lose access to every agent shared with this group")
        says("and what stays", content, "Access they hold directly is unaffected")
        # The way out is the notice's own Cancel; scoped there because the open group
        # below it has forms of its own.
        check("with a way out", page.locator(".notice button:has-text('Cancel')").count(), 1)
        page.click(".notice button:has-text('Cancel')")

        # --- her tokens, 035c ------------------------------------------------------

        # **The one thing about this chunk only a browser can answer.** The suite drives
        # the route and `TokensPage.test.tsx` drives the page against a mocked module;
        # neither can tell you that a Postgres BOOLEAN reaches a badge. Two tokens
        # differing in exactly one flag, minted here rather than seeded before uvicorn
        # because `owner_id` is priya's user row and that row is created by her signing
        # in — which happened on screen, forty checks ago.
        say("priya's tokens say which of them acts as her")
        from carnet import storage as _storage
        from carnet.access import tokens as _tokens
        from carnet.storage.postgres import PostgresStorage as _Pg

        # The DSN off the environment rather than off `main`'s local: `drive()` is a
        # module-level function and this is the same string uvicorn was handed.
        minting = _storage.configure(_Pg(os.environ["CARNET_DATABASE_URL"]))
        her = minting.find_user_by_email(TENANT, BOOTSTRAP_EMAIL)["id"]
        _tokens.mint(TENANT, "nightly-ci", her, actor="system:cli")
        # The secret is kept, not discarded: 035j's door-traffic scene presents it at
        # `/mcp` for one real tool call. That call spends one unit of this token's
        # budget, which is why the scene runs *after* the budget assertions below —
        # "4 of 1,000" is pinned first, then the fifth call is made.
        cursor, cursor_secret = _tokens.mint(
            TENANT, "priya-cursor", her, actor="system:cli", acts_as_owner=True
        )
        # 035d needs something for that token to reach, and the tool it reaches is the one
        # she approved on screen forty checks ago — `acme_list_issues`, vetted through the
        # real form against the real server. Granted to **her** rather than to the token,
        # which is what a personal token's whole access is made of.
        minting.save_agent(
            TENANT,
            {
                "name": "triage",
                "runtime": "simple",
                "system": "You triage issues.",
                "permissions": {
                    "tools": ["acme_list_issues"],
                    "scope": {"github.repo": {"read": ["acme/*"]}},
                },
            },
            actor="system:cli",
        )
        minting.grant_agent(
            TENANT, "triage", "user", her, role="user",
            granted_by="system:cli", actor="system:cli",
        )
        # 035e needs something for that token to have *spent*, and it has to be real rows
        # in `mcp_budget` rather than a stub: the figure on the page is the number the
        # door's own statement wrote, read back through a route, rendered under a CSP.
        # Two windows, so the week below is not one row and six blanks — a dense series
        # with a gap in it is the shape the zero-fill exists for.
        from datetime import timedelta

        from carnet import door as _door

        # Under the *owner's* key, not the token's: `priya-cursor` is a personal token,
        # and since migration 054 its day is hers across every personal token she holds
        # — the page reads `door.budget_subject`, which is what the door writes under.
        _today = _door.budget_window()
        for _ in range(4):
            minting.spend_mcp_call(TENANT, her, _today, ceiling=1000)
        minting.spend_mcp_call(TENANT, her, _today - timedelta(days=3), ceiling=1000)
        minting.close()

        page.goto(f"{APP}/tokens")
        try:
            page.wait_for_selector("text=priya-cursor", timeout=15000)
        except Exception:
            pass
        content = page.content()
        says("the personal one is marked", content, "personal")
        says("and the service one is not the same word", content, "service")
        says("with the consequence spelled out", content, "your access")
        # Category 2's rule narrowed in 044, and the check narrows with it: the page
        # said *no mint, no revoke, no form* until step 044 let a **session** mint for
        # itself (the route still refuses every machine caller, which is what the rule
        # always protected — no credential that survives its presenter can create
        # another). So the one control here is the mint, owned by the caller, and
        # nothing on this page grants to anybody else.
        # **Names, not a count — the second time this section learned that lesson.**
        # It counted `main button == 1` until 075 put the connect card's dialect tabs on
        # this page, and eight inert tab controls made a true claim read as a broken one:
        # 9 where 1 was expected, with nothing about the page's actual behaviour changed.
        # The identical shape was fixed on the token *detail* page during 070's edge pass
        # and the reasoning is quoted there: a count of one says nothing about what the
        # one is, and a count of nine says nothing about whether any of them grants.
        #
        # Tabs are excluded by role rather than by name, so a ninth dialect does not
        # reopen this. What is asserted is what the section is about: every control that
        # is not a tab is the caller minting for themselves.
        check(
            "and the page's only non-tab control is the session's own mint (044) — "
            "nothing grants to anybody else",
            sorted(page.locator("main button:not([role='tab'])").all_inner_texts()),
            ["Generate token"],
        )
        says("...and the tabs beside it only choose a snippet (075)",
             page.locator("main button[role='tab']").first.get_attribute("aria-controls"),
             "panel-")

        # --- what that token reaches, 035d ------------------------------------------
        #
        # **The half only a browser can answer, and it is not the same half as 035c's.**
        # That chunk needed a real Postgres BOOLEAN to become a rendered badge. This one
        # needs a *link* to reach a route that exists, under the served CSP, with a real
        # session — and then needs the door's own computation, over rows Postgres
        # resolved, to arrive as a section on a page. `TokenDetailPage.test.tsx` drives a
        # mocked module and cannot fail on any of that.
        #
        # It also pins the shape decision where somebody would undo it: reach is reached
        # by **navigating**, not by expanding a row — the listing's one button is the
        # mint, never a per-row expander.

        say("she follows a token to what it can actually reach")
        page.click("a:has-text('priya-cursor')")
        try:
            # **On the heading, exactly, not on `text=Access`.** Playwright's `text=` is
            # a case-insensitive substring match, and the spinner beside it says
            # *"Loading access…"* — so the loose selector matched the loading state in
            # 0.02s and every assertion after it read a page that had not answered yet.
            # `:text-is` also keeps "Access by tool" from answering for this card.
            # `e2e_mcp_door`'s own lesson at a third address: wait for the thing being
            # asserted, never for a string that was already there.
            page.wait_for_selector("h2:text-is('Access')", timeout=20000)
        except Exception:
            pass
        content = page.content()
        says("the URL is the token's own", page.url, cursor["id"])
        says("the agent her access runs through is named", content, "triage")
        says("and the tool she approved on screen is under it", content, "acme_list_issues")
        says("with that agent's own scope, not a union of anybody's", content, "acme/*")
        says("saying whose grants answered, which for a personal token is a person",
             content, f"user:{her}")
        says("and why one tool can appear under two agents at two scopes",
             content, "decided per call")
        # Category 2 again, at the screen that names permissions. A Revoke did arrive
        # (046's arc put it on the token's own page) — and a revoke is the rule's own
        # direction, a narrowing, not a grant. What must still be absent is anything
        # that *widens*: no grant, no share, no scope edit.
        #
        # **This used to assert `count() == 1` and 069 broke it by adding a second
        # control that is entirely legitimate** — the simulator's *Check*, a question
        # that writes no row and changes nothing (069 decision 3).
        # The count was standing in for the claim and it stopped being able to: a count
        # of one says nothing about *what* the one is, and a count of two says nothing
        # about whether the second grants. So the names are asserted instead, which is
        # the property the section is actually about and which a new control cannot pass
        # by accident. Found by running this script during step 070's edge pass — 069
        # shipped a headless e2e and never ran this one.
        check(
            "every control on this page narrows or asks; none grants",
            sorted(page.locator("main button").all_inner_texts()),
            ["Check", "Revoke token"],
        )

        # --- and why it might stop working, 035e ------------------------------------
        #
        # The same argument as the section above, at the other table: `mcp_budget` rows
        # written by the door's own statement have to reach a figure on a page. What
        # `TokenDetailPage.test.tsx` cannot fail on is the round trip — the route
        # existing under the served CSP, `window` agreeing with the server's UTC day, and
        # the dense week surviving JSON.
        #
        # **Waited on the heading, not on a substring.** The card's own spinner says
        # *"Loading usage…"*, so `text=Usage` would match the loading state — and the
        # rail's Usage link besides — the lesson this file already carries twice and
        # `e2e_mcp_door` a third time.

        say("and she reads why it might stop working, which was nowhere before")
        try:
            page.wait_for_selector("h2:text-is('Usage')", timeout=20000)
        except Exception:
            pass
        content = page.content()
        says("the count is against the ceiling, not on its own", content, "4 of 1,000")
        says("labelled allowed rather than made", content, "requests allowed today")
        # Trap 2 on screen: a token denied five hundred times a day appears here as
        # whatever it succeeded at, and the page has to say so rather than let a reader
        # take this for the token's whole activity.
        says("with what that excludes said out loud", content, "Allowed requests only")
        says("and the quiet days present rather than missing", content, "Day (UTC)")
        check(
            "seven windows, dense — a gap would redraw a quiet day as if it had not happened",
            page.locator("table:has-text('Requests allowed') tbody tr").count(),
            7,
        )
        check(
            "and nothing here raises a ceiling, which would be a grant — the controls "
            "are still only the revoke and the simulator's question",
            sorted(page.locator("main button").all_inner_texts()),
            ["Check", "Revoke token"],
        )

        # --- her own connection, 035f ------------------------------------------------
        #
        # **The tier this chunk needs, and the only one that can fail on it.** 035f is a
        # rendering: three stored instants become three sentences, and the whole of the
        # chunk's judgement is about which of them a row is allowed to say. The suite
        # drives the route against the memory store and `ConnectionsPage.test.tsx` drives
        # the page against a mocked module — neither can tell you that a `TIMESTAMPTZ`
        # survives psycopg, pydantic, JSON and `toLocaleString` into a sentence, under the
        # served CSP.
        #
        # Seeded rather than consented, because a consent flow needs a provider to be at
        # and this connector's is `https://localtest.me/authorize`, which nothing serves.
        # The credential is a placeholder and is never opened: `GET /connections` reads
        # metadata only, which is the property `list_connections` enforces in storage.
        #
        # `expires_at` is deliberately **in the past** and `credential_kind` is `oauth`,
        # which is the resting state of a healthy connection between runs — the access
        # token is renewed at the start of the next run that needs it. So the check below
        # that the page says *nothing* about an expiry is the chunk's central negative,
        # against a real column rather than a fixture.
        say("priya's own connection says what is behind it when it lapses")
        from datetime import datetime, timedelta, timezone

        # A handle of its own: `minting` was closed after the budget rows above, and a
        # pool that is closed stays closed.
        seeding = _storage.configure(_Pg(os.environ["CARNET_DATABASE_URL"]))
        now = datetime.now(timezone.utc)
        seeding.save_connection(
            TENANT,
            "user",
            her,
            "acme",
            ciphertext=b"placeholder-never-opened",
            key_id="k-e2e",
            credential_kind="oauth",
            expires_at=now - timedelta(hours=2),
            refresh_expires_at=now + timedelta(days=90),
            account_label=BOOTSTRAP_EMAIL,
            actor="system:cli",
        )

        # **A second connector, and it is the branch that was wrong.** `legacy` carries a
        # credential an administrator pasted in, which expired in 2020, on a connector
        # that *does* have a consent flow configured. Three things only a real render can
        # settle, all of them 035f decisions:
        #
        #   - the **past** tense. A lapse already behind you is not "lapses on"; the first
        #     version of this said it was, on the row whose next run fails.
        #   - the **year**. `on()` omits it, so a 2020 expiry and a 2099 one both came out
        #     as a bare month and day — the difference between *act now* and *nothing to
        #     do*, erased by the formatter.
        #   - **no scope line beside a pasted credential**, even though this connector has
        #     an OAuth application with scopes. A static credential never met a consent
        #     screen, and ungating on `state` alone would print that screen's ask over a
        #     token somebody typed into a terminal.
        from carnet import tools as _tools
        from carnet.access import oauth as _oauth
        from carnet.core import crypto as _crypto

        # The API subprocess configures crypto from the environment at start-up; this
        # process never has, because nothing it does until now seals anything.
        # `save_connection` takes ciphertext and needs no key — `oauth.configure` seals a
        # client secret and does. Same variable the servers were handed.
        _crypto.configure(_crypto.from_environment())

        _tools.register_connector(
            TENANT, "legacy", url=f"http://{HOST}:{MCP_PORT}/mcp", actor="system:cli"
        )
        _oauth.configure(
            TENANT, "legacy",
            authorize_endpoint=f"https://{HOST}/authorize",
            token_endpoint=f"https://{HOST}/token",
            client_id="legacy-client", client_secret="MARKER-LEGACY-SECRET",
            scopes=("read:everything",), actor="system:cli",
        )
        seeding.save_connection(
            TENANT, "user", her, "legacy",
            ciphertext=b"placeholder-never-opened", key_id="k-e2e",
            credential_kind="static",
            expires_at=datetime(2020, 6, 15, 12, tzinfo=timezone.utc),
            account_label="build-server",
            actor="system:cli",
        )
        seeding.close()

        page.goto(f"{APP}/connections")
        # **Waited on the thing being asserted.** `text=` is a case-insensitive substring
        # match and this file has paid for that three times — `text=acme` matches the
        # connector's name, the tenant, and the address in the top bar, all of which are
        # rendered before `GET /connections` has answered.
        try:
            page.wait_for_selector("text=This connection lapses on", timeout=20000)
        except Exception:
            pass
        content = page.content()
        # **Scoped to the row, not to the page — and that is a lesson this file just
        # paid for a second time.** These were page-wide substring checks when there was
        # one connection on screen. Adding `legacy` below made the *negative* one pass
        # against the wrong row: `legacy` says "This credential expired on" truthfully,
        # and a `not in page.content()` assertion cannot tell which row said it. Same
        # family as the `text=acme` lesson three sections up — a substring is not a
        # subject.
        acme_row = page.locator(".conn-card.connection:has-text('acme')")
        acme = acme_row.inner_text()
        says("connected, and as whom", acme, f"Connected as {BOOTSTRAP_EMAIL}")
        says("with when the connection itself lapses", acme, "This connection lapses on")
        says("and that renewing is what happens until then", acme, "renews itself until then")
        # **The negative that is the whole of trap 2.** Her access token expired two hours
        # ago and the connection is fine; a page that rendered `expires_at` wherever it
        # was set would tell the majority of healthy connections they had expired and
        # invite somebody to reconnect one that needs nothing.
        check(
            "and NOTHING about the access token that expired two hours ago",
            "credential expired on" in acme or "credential expires on" in acme,
            False,
        )
        says("what the connector asks for, on a row that is already connected",
             content, "acme asks for: read:issues")
        # The sentence 035f exists to not ship without. `scopes` is the OAuth
        # application's configured ask; what she granted is stored nowhere, so an
        # administrator widening it would otherwise make this page describe her live
        # credential with scopes it never had.
        says("said to be the ask and not a record of what she granted",
             content, "not what this connection was granted")
        says("and when the credential last changed", content, "Last changed")

        say("and the credential an administrator pasted in says it is already dead")
        legacy = page.locator(".conn-card.connection:has-text('legacy')").inner_text()
        says("in the past tense, which is the row whose next run fails",
             legacy, "This credential expired on")
        # The year is the whole reason these three stamps do not use `on()`. Without it a
        # lapse five years old reads as last June.
        says("with the year, so 2020 is not read as this June", legacy, "2020")
        says("and marked as an administrator's", legacy, "added by an administrator")
        # Decision 3, at the only tier that can show it: `legacy` HAS an OAuth application
        # with `read:everything` configured, and this credential never went near it.
        check(
            "and NO consent-screen ask printed over a token somebody typed in",
            "read:everything" in legacy,
            False,
        )
        check(
            "two rows, two Disconnects, and nothing here refreshes or grants",
            page.locator("main button").count(),
            2,
        )

        # --- sharing with a group, 035h -------------------------------------------------

        # **The share sheet has never been driven in a browser.** `grep -l "Who can reach
        # it"` (its heading then; it is "Sharing" now) over this directory returned
        # nothing before this block: every assertion
        # about it since 10d has been against a mocked `api` module, which cannot tell you
        # that a Postgres `external_id` reaches a `<select>`, or that the two paths this
        # boolean travels — `list_groups` for the menu, `who_has_access` for the row —
        # agree about the same group.
        #
        # And the capability itself is what 035h added: `ShareBox` passed `email` as the
        # grantee kind literally, so an agent could be shared with a group from the CLI and
        # from nowhere in the product, while `GET /groups` was argued open in four separate
        # places on the strength of *"the menu an editor picks from when sharing"*.
        say("priya shares an agent with a group, which the product could not do before")
        # Its own store, like the two seeding blocks above: each closes its pool when it is
        # done, so a handle from forty checks ago is a `PoolClosed` rather than a warning.
        sharing = _storage.configure(_Pg(os.environ["CARNET_DATABASE_URL"]))
        # **`runtime`, `system` and `output` are all seeded here on purpose — step 081.**
        # No screen authors any of them: this deployment reads `permissions` off an agent
        # and nothing else, so the browser's job is to *show* them without claiming
        # anything enforces them. Written the way a customer's would be — by `--seed` or
        # by curl — which is the only way they can arrive now.
        sharing.save_agent(
            TENANT,
            {
                "name": "rota",
                "runtime": "simple",
                "system": "You publish the rota.",
                "output": {"schema": {
                    "type": "object",
                    "properties": {"rota": {"type": "string"}},
                    "required": ["rota"],
                    "additionalProperties": False,
                }},
            },
            actor="system:cli",
        )
        # `owner`, because sharing needs `editor` and the sheet's controls are the ladder's
        # answer rather than a flag per verb.
        sharing.grant_agent(
            TENANT, "rota", "user", her, role="owner",
            granted_by="system:cli", actor="system:cli",
        )
        linked = next(
            row for row in sharing.list_groups(TENANT) if row["name"] == "eng"
        )
        sharing.close()

        page.goto(f"{APP}/agents/rota")
        # Exactly the sheet's heading: "sharing" is also in the page's own prose.
        page.wait_for_selector("h2:text-is('Sharing')", timeout=15000)

        # One control, not a second Share button: pick who, then the level, then Share.
        page.get_by_role("radio", name=re.compile("A group")).click()
        page.wait_for_timeout(800)

        # The menu, with **both** kinds labelled — the same decision the group listing
        # takes, worded for a different question. An administrator is asking *may I edit
        # this*; a sharer is asking *who does this reach*.
        options = page.locator("select option").all_inner_texts()
        says(
            "the directory-backed group says who it reaches",
            " | ".join(options),
            "whoever your directory puts in it",
        )
        says(
            "and the hand-made one says who puts them there",
            " | ".join(options),
            "whoever an administrator puts in it",
        )

        page.get_by_label(re.compile(r"^Group")).select_option(linked["group_id"])
        page.wait_for_timeout(500)
        says(
            "and picking it says what cannot be listed",
            page.content(),
            "Its members are not listed here",
        )

        page.click("button:has-text('Share')")
        page.wait_for_timeout(2000)

        # **The cross-check this whole chunk rests on.** The badge in the menu came from
        # `list_groups`; this sentence comes from `who_has_access`, which computes the same
        # bit in a different function from a different query. Two paths, one answer, both
        # rendered — and the row is the scope, because the sheet also carries a paragraph
        # naming every followed group.
        shared_row = page.locator("tr:has-text('%s')" % linked["group_id"]).first
        text = shared_row.inner_text()
        says("the group is on the sheet", text, linked["group_id"])
        says(
            "and the sheet agrees with the badge about where its people come from",
            text,
            "everybody your directory puts in it",
        )
        check(
            "and does not claim to know everybody in it",
            "everybody in this group" in text,
            False,
        )
        says(
            "and says what a directory-backed group costs the reader",
            page.content(),
            "listed after their next sign-in",
        )

        # --- 081: what is stored and not read, shown as exactly that --------------------
        #
        # This replaced the schema editor 035i built. That control let priya author a
        # JSON Schema into `output.schema` and took two refusals off the server's hands,
        # which was careful work over a key nothing reads — `agents.check_output` was the
        # completion-time half of 024's contract and its one caller was `runs.execute`,
        # which this tree does not have. The *reader* half of 035i's register row is what
        # survives, and it is the half that was actually asked for.

        say("priya opens the agent and sees what is stored without being read")
        page.goto(f"{APP}/agents/rota")
        page.wait_for_selector("h2:text-is('Unused settings')", timeout=15000)

        stored_card = page.locator("section:has(h2:text-is('Unused settings'))").first
        text = stored_card.inner_text()
        says("the schema she was sent is on the page", text, '"rota"')
        says(
            "and it is pretty-printed rather than the one line it arrived on",
            text,
            '\n    "type": "object"',
        )
        says("beside the briefing, which is also stored and also unread", text,
             "You publish the rota.")
        says("and the tier a config may still name", text, "simple")
        says(
            "under a sentence that claims nothing enforces any of it",
            text,
            "does not read them",
        )
        check(
            "and no card claims a run is checked against the schema",
            "every run is checked against this" in page.content(),
            False,
        )

        say("and the edit screen offers no way to author any of it")
        page.goto(f"{APP}/agents/rota/edit")
        # `rota` is granted no tools, so the resources step is `Empty` rather than the
        # question card — wait on the page title instead, which paints only once both
        # the agent and the catalogue have answered.
        page.wait_for_selector("h1:text-is('Edit rota')", timeout=15000)
        content = page.content()
        check("no JSON Schema box", page.get_by_label(re.compile("JSON Schema")).count(), 0)
        check("no per-run ceilings", "Tool calls per run" in content, False)
        check("no write ceiling wearing a promise", "may not change anything" in content, False)
        check("no privacy tick over runs that do not exist", "private to them" in content, False)

        # Back to the detail page, which is where the rename scene below starts. The block
        # this replaced ended there by saving; nothing here saves, so it says so.
        page.goto(f"{APP}/agents/rota")
        page.wait_for_selector("h2:text-is('Sharing')", timeout=15000)

        say("and she renames the agent, which the browser could not do at all")
        # `owner`. An editor's press would answer 404 about the agent on screen, because
        # `grants.require` says the same sentence for ungranted, too-low and absent.
        page.click("button:has-text('Rename')")
        page.wait_for_timeout(400)
        says(
            "she is told what comes with it, before what breaks",
            page.content(),
            "are kept",
        )
        says("and then what breaks", page.content(), "There is no redirect")

        # The default state of this form — opened, unchanged — is a 422 the server answers
        # with a paragraph about version history. Pre-empted, because it is not a mistake
        # about the name.
        # The box's submit is the one word "Rename", the same word as the toolbar
        # button that opened it — which is not rendered while the box is open, but
        # scoping to the notice says so rather than relying on it.
        check(
            "renaming to the name it already has is blocked rather than earned",
            page.locator(".notice button:text-is('Rename')").is_disabled(),
            True,
        )
        says("with the reason said", page.content(), "The name is already rota")

        page.get_by_label(re.compile("New name")).fill("Rota 2026")
        page.wait_for_timeout(400)
        says(
            "a name that is not a slug is blocked in the words the server would use",
            page.content(),
            "lowercase letters, digits and single hyphens",
        )

        page.get_by_label(re.compile("New name")).fill("rota-2026")
        page.wait_for_timeout(400)
        says(
            "and the two addresses read as they will actually read",
            page.content(),
            "/agents/rota → /agents/rota-2026",
        )

        page.click(".notice button:text-is('Rename')")
        # **Wait for the URL, not for a selector.** The share sheet is on this same page,
        # so `wait_for_selector("h2:text-is('Sharing')")` returns instantly against the page
        # that is already rendered and every assertion after it reads the *old* screen.
        # That is this file's substring lesson in its other form: a wait that is already
        # satisfied is not a wait. Caught by three probes failing for one reason.
        page.wait_for_url(re.compile(r"/agents/rota-2026$"), timeout=15000)
        page.wait_for_selector("h2:text-is('Sharing')", timeout=15000)
        check("the agent is at its new address", page.url.endswith("/agents/rota-2026"), True)

        # **Everything survives it**, asserted through the things rather than through the
        # row: the grant priya has, the group share made forty lines above, and the schema
        # written a page ago.
        says(
            "the group share came with it",
            page.locator("tr:has-text('%s')" % linked["group_id"]).first.inner_text(),
            linked["group_id"],
        )
        says(
            "and so did the schema nobody can edit here",
            page.locator("section:has(h2:text-is('Unused settings'))").first.inner_text(),
            '"rota"',
        )
        check(
            "and she is still its owner, so the verb is still offered",
            page.locator("button:has-text('Rename')").count(),
            1,
        )

        # Decision 9 of 025, measured in a browser for the first time: no redirect, no
        # memory of former names, so the old address is an ordinary 404.
        page.goto(f"{APP}/agents/rota")
        page.wait_for_timeout(1500)
        says("the old URL is a plain 404 with no redirect", page.content(), "no agent named 'rota'")
        check("and it did not quietly follow the rename", page.url.endswith("/agents/rota"), True)

        # --- the second person ---------------------------------------------------------

        say("sam signs in for the first time, having administered nothing")
        page.context.clear_cookies()
        sam_page = browser.new_context().new_page()
        sign_in(sam_page, SECOND_PERSON)
        check("he is signed in", SECOND_PERSON in sam_page.content(), True)
        # The bootstrap variable is inert now, and this is the outside view of that.
        check("and the audit log is NOT offered", "Audit log" in nav(sam_page), False)

        say("he types the URL anyway, and is refused with a sentence")
        sam_page.goto(f"{APP}/admin/connectors")
        sam_page.wait_for_timeout(2000)
        says("the server's own words", sam_page.content(), "administrator")
        check(
            "and no host form is rendered to him",
            sam_page.locator("input[placeholder='mcp.acme.com']").count(),
            0,
        )

        say("and his own token page tells him he has none, without offering to help")
        sam_page.goto(f"{APP}/tokens")
        try:
            sam_page.wait_for_selector("text=No access tokens", timeout=15000)
        except Exception:
            pass
        # The nav item is outside the administrative group, so unlike `/admin/connectors`
        # two checks up this is a place he is *meant* to be — and an empty answer here is
        # a true one rather than a refusal.
        check("Access tokens is offered to him", "Access tokens" in nav(sam_page), True)
        says("and the empty state is a sentence", sam_page.content(), "No access tokens")
        # 044 moved minting into the page itself, so the empty state points at the
        # page's own control rather than at a terminal — the stale `--mint-token`
        # remedy plan 049's audit flagged is gone from the copy, and this check moved
        # with it. "Generate a token", not "Generate token": the sentence, not the button.
        says("pointing at the generate control on the page, not at a terminal",
             sam_page.content(), "Generate a token")

        say("but he can connect his own account — which is the whole point")
        sam_page.goto(f"{APP}/connections")
        # **Wait for the thing being asserted, not for a substring that was already on
        # the page.** This used to wait for `text=acme` — which matches `sam@acme.com`
        # in the top bar, rendered the instant the shell mounts and long before
        # `GET /connections` answers. So it waited for nothing, and the two checks
        # below raced the fetch: one of them had been losing that race and failing on
        # `main` before step 031 came near this file, and 031's extra round trip (the
        # provider's discovery document) shifted the timing enough to make the other
        # one lose it too.
        #
        # Waiting for the *spinner* to leave was tried and is no better: at the moment
        # of the call React may not have mounted this page yet, so there is nothing to
        # be absent and "gone" is true immediately. A positive wait on the rendered row
        # is the only one that means anything. The timeout is swallowed on purpose —
        # the checks below then report a count of zero, which says what happened, where
        # a Playwright traceback would only say where.
        try:
            sam_page.wait_for_selector("button:has-text('Connect')", timeout=15000)
        except Exception:
            pass
        # **Both of them**, which is a stronger statement of the same point than the
        # count-of-one this replaced: sam administers nothing and is offered every
        # connector the tenant has a consent flow for. The count broke the moment a
        # second connector existed, which is what a bare count is worth.
        for connector in ("acme", "legacy"):
            check(
                f"the Connect button is there for {connector}",
                sam_page.locator(
                    f".conn-card.connection:has-text('{connector}') button:has-text('Connect')"
                ).count(),
                1,
            )
        says("and he is told what it will ask for", sam_page.content(), "read:issues")
        # Nothing of priya's reaches him: her connections are hers, and the row he sees
        # for the same connector carries none of her facts.
        check(
            "and none of priya's connection is on his page",
            "build-server" in sam_page.content() or BOOTSTRAP_EMAIL in sam_page.content(),
            False,
        )

        say("and the tool priya approved is in the agent form's catalogue")
        # **On the tools step, not the first one.** The wizard opens on the name, so the
        # first version of this check looked at a screen the catalogue is not on and
        # reported a missing tool that was there — a test bug, and the kind that would
        # have been read as a product bug by whoever ran this next.
        sam_page.goto(f"{APP}/agents/new")
        sam_page.wait_for_selector("input[placeholder='Triage bot']", timeout=15000)
        sam_page.fill("input[placeholder='Triage bot']", "issue summariser")
        # Step one wants a name and nothing else since 078 — the door reads no
        # instructions, so the wizard asks for none.
        sam_page.click("button:has-text('Continue')")
        sam_page.wait_for_timeout(2500)

        content = sam_page.content()
        # The end of the arc: a tool a colleague approved through the product this
        # morning, offered in the form of somebody who administers nothing.
        says("acme_list_issues is offered", content, "acme_list_issues")
        check(
            "and the write nobody approved is not",
            "delete_repository" in content,
            False,
        )

        # --- 035j: the routes no browser had ever driven ---------------------------
        #
        # Plan 035 counted the dark routes at nine, its handoff at eight; measured
        # against these scripts by reading *clicks* as well as `page.goto`, it is six —
        # `/tokens/:tokenId` and `/admin/connectors/:connectorId` were already driven
        # above, by navigation a `grep page.goto` cannot see. The scenes below close
        # the count, under the two rules this script lives by:
        #
        #   - **costs nothing** still holds. No run is submitted, so `/runs` is
        #     asserted as its true empty and `/runs/:id` as the server's own 404. A
        #     mocked module can render those sentences; only a browser proves the
        #     route is reachable under the served CSP and that the failure path is a
        #     sentence rather than a blank page.
        #   - **the world writes its own rows.** sam's deep link below *is* the denial
        #     the admin then reads, and the door row comes from one genuine
        #     `tools/call` through `/mcp` — written by the door's own code, not seeded
        #     in its shape.

        say("sam deep-links to the door log, and the refusal itself becomes a row")
        sam_page.goto(f"{APP}/admin/door-calls")
        try:
            sam_page.wait_for_selector("text=Signing in again", timeout=15000)
        except Exception:
            pass
        says(
            "the server's own sentence, rendered through Failure",
            sam_page.content(),
            "administrator",
        )
        says(
            "with the sentence that saves a useless re-login",
            sam_page.content(),
            "Signing in again will not change this",
        )

        say("a client presents priya's personal token at the door — one real call")
        # After the budget scene on purpose: this spends one unit of priya-cursor's
        # budget, and "4 of 1,000" was pinned first. Trap 5 — a pass that mutates
        # shared state owns what it mutates, and this one states both of its mutations.
        #
        # The second mutation: `acme_list_issues` acts as the **caller's own account**,
        # and priya's seeded acme connection is deliberately expired, with a placeholder
        # ciphertext that must never be opened — the resting state 035f's negative
        # asserts, which the door (correctly) refuses with "Reconnect that account". A
        # door call opens the credential, so her connection is replaced here with a
        # live, properly sealed one, through the same `connect_account` the CLI uses.
        # Every assertion that read the expired connection has already run, and nothing
        # after this scene reads her connections again.
        from carnet.access import connections as _connections
        from carnet.core.principal import Principal as _Principal

        relinking = _storage.configure(_Pg(os.environ["CARNET_DATABASE_URL"]))
        _connections.connect_account(
            _Principal(kind="user", id=her, tenant_id=TENANT),
            "acme",
            "MARKER-DOOR-CREDENTIAL",
            account_label=BOOTSTRAP_EMAIL,
            actor="system:cli",
        )
        relinking.close()

        door = httpx.post(
            f"http://127.0.0.1:{API_PORT}/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "acme_list_issues",
                    "arguments": {"owner": "acme", "repo": "acme/site"},
                },
            },
            headers={
                "Authorization": f"Bearer {cursor_secret}",
                "Accept": "application/json",
            },
            timeout=30,
        )
        check("the door answers 200", door.status_code, 200)
        check(
            "and the upstream's answer came back through it",
            door.json().get("result", {}).get("isError"),
            False,
        )

        say("priya reads the door's traffic, which is 035a's screen doing its job")
        admin = browser.new_context().new_page()
        sign_in(admin, BOOTSTRAP_EMAIL)
        admin.goto(f"{APP}/admin/door-calls")
        try:
            admin.wait_for_selector("text=acme_list_issues", timeout=15000)
        except Exception:
            pass
        content = admin.content()
        says("the tool is on the row", content, "acme_list_issues")
        says("under the agent whose scope decided the call", content, "triage")
        # Step 108, decision 5: the call was made with `priya-cursor`, a personal token,
        # and the row names the person — the email — with the machine beneath. The
        # column is *called by*, not *actor*, because that is the question asked.
        says("and the person behind the personal token — the email, not just the token id",
             content, BOOTSTRAP_EMAIL)
        says("under a column that asks the question a customer asks", content, "Called by")
        # Scoped to a table cell, not the page: a bare `says(content, "allow")` was
        # measured passing against the *empty* state during this scene's development —
        # the 035l class, a pin that "will fail loudly" and never fails.
        check(
            "the decision is the word allow, on the row",
            admin.locator("td .badge:has-text('allow')").count() >= 1,
            True,
        )
        # 033c's rule, observed on a real row: a token acting for nobody is a stated
        # fact, never an empty cell that reads as missing data.
        says("and a call made for nobody says so in words", content, "nobody named")

        say("and the denial log — the route nothing in a browser had called until 035b")
        admin.goto(f"{APP}/admin/denials")
        try:
            admin.wait_for_selector("table", timeout=15000)
        except Exception:
            pass
        content = admin.content()
        # sam's deep links above are these rows: refused by `roles.require_admin`,
        # recorded by its hook, read back here by the person who administers. The row
        # carries his opaque principal id, not his email — the log renders what the
        # record holds, so the assertion reads the id the same way the page does.
        reading = _storage.configure(_Pg(os.environ["CARNET_DATABASE_URL"]))
        sam_id = reading.find_user_by_email(TENANT, SECOND_PERSON)["id"]
        reading.close()
        says("sam's refusal is a row, under his principal id", content, sam_id)
        says(
            "and what he held is the word nothing, not a blank cell",
            content,
            "nothing",
        )

        say("she looks at what the rota agent said in an earlier version")
        # The route's own docstring is why this is a `goto`: a version page is "a link
        # somebody sends", and the sent link — a cold load of a deep URL, the class the
        # dev-proxy collision bug lived in — is the thing only a browser can check. The
        # history's half of the contract is the href it writes, asserted first.
        admin.goto(f"{APP}/agents/rota-2026")
        admin.wait_for_selector("a:has-text('v1')", timeout=15000)
        check(
            "the history links the version by URL",
            admin.locator("a:has-text('v1')").first.get_attribute("href"),
            "/agents/rota-2026/versions/1",
        )
        admin.goto(f"{APP}/agents/rota-2026/versions/1")
        try:
            admin.wait_for_selector("h2:text-is('Instructions')", timeout=15000)
        except Exception:
            pass
        content = admin.content()
        says("the version page carries the version in its title", content, "· v1")
        # Scoped to the card: the hint that pins these words to a version is three
        # words, and "version" is all over this page.
        says(
            "and the instructions card says whose words these are",
            admin.locator("section.card:has(h2:text-is('Instructions'))").inner_text(),
            "in this version",
        )

        browser.close()


if __name__ == "__main__":
    main()
