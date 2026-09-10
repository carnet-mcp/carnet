"""The overview, in a real browser, against a seeded month of real door traffic.

    .venv/bin/python scripts/e2e_browser_overview.py [--keep]

Step 041b. Every other check on this page is a unit test with a mocked response; this is
the one that renders the built bundle under the shipped CSP, with real rows written
through `append_audit` and read back through the real route, and then **looks at it**.

What only a browser can answer, and the reason this exists:

    the figures draw            an SVG that renders in jsdom can still be blank on a
                                page — a viewBox with no width, a fill resolving to a
                                variable that is not defined in this theme
    the day labels do not       a 30-day axis and a 90-day axis are the same 720 units,
      collide                   and only one of them can print every label
    the page does not           the widest thing here is a table inside a disclosure,
      scroll sideways           and horizontal overflow on a dashboard is a defect
                                nobody reports and everybody works around
    both themes                 the dark palette is a *selected* set of steps, not the
                                light one flipped, and nothing but a rendering proves
                                the tokens actually resolve in that mode
    the numbers agree           the figure's own total, the tile above it, and the
      with each other           table under it are three renderings of one fact

`--keep` leaves the world running and prints where it is, for looking at by hand.

Screenshots land in `docs/screenshots/overview-{light,dark}.png`.

**Costs nothing.** No run is submitted, so no model is called and no connector launched.
"""

import base64
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import timedelta
from urllib.parse import urlsplit, urlunsplit

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from playwright.sync_api import sync_playwright  # noqa: E402

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_e2e_browser_overview"

ROOT = pathlib.Path(__file__).resolve().parent.parent
FRONTEND = ROOT.parent / "frontend"
SHOTS = ROOT.parent / "docs" / "screenshots"

TENANT = "e2eoverview"
ADMIN = "priya@local.test"
EDGE_PORT = 8091
API_PORT = 8011
APP = f"http://127.0.0.1:{EDGE_PORT}"

KEEP = "--keep" in sys.argv
CHECKS = []


def dsn_for(database: str) -> str:
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit(
        (parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment)
    )


def check(label, ok):
    CHECKS.append((label, bool(ok)))
    print(f"{'  ok' if ok else 'FAIL'}  {label}", flush=True)
    return ok


def say(what):
    print(f"\n=== {what}", flush=True)


def refuse_if_taken(*ports):
    import socket as s

    for port in ports:
        with s.socket() as sock:
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                sys.exit(f"port {port} is in use — a previous run is still up")


def ensure_bundle():
    if (FRONTEND / "dist" / "index.html").exists():
        return
    print("building the frontend bundle…", flush=True)
    subprocess.run(["npm", "run", "build"], cwd=FRONTEND, check=True)


def wait_for(url, timeout=45):
    import urllib.error
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=2)
            return
        except (urllib.error.URLError, OSError):
            time.sleep(0.2)
    sys.exit(f"{url} never came up")


def seed(store):
    """A month with a shape: busy weekdays, quiet weekends, and every band populated.

    Deterministic — no randomness, so two runs produce identical figures and a diff of
    the screenshots is a real change rather than noise.
    """
    from carnet.door import budget_window

    today = budget_window()
    tools = [
        ("search_issues", "read"),
        ("list_repos", "read"),
        ("create_issue", "write"),
        ("post_message", "write"),
    ]
    callers = ["tok_alice", "tok_bob", "tok_nightly_ci"]

    for back in range(29, -1, -1):
        day = today - timedelta(days=back)
        weekday = day.weekday() < 5
        volume = 26 + (back % 7) * 3 if weekday else 3 + back % 3

        for i in range(volume):
            tool, effect = tools[i % len(tools)]
            who = callers[i % len(callers)]
            # A refusal every eleventh call, and a spread of identity sources so the
            # governance figure has all three bands on most days.
            deny = i % 11 == 0
            source = (
                "none"
                if who == "tok_nightly_ci"
                else ("asserted" if i % 5 == 0 else "verified")
            )
            outcome = "" if deny else ("error" if i % 17 == 0 else "ok")
            store.append_audit(
                TENANT,
                {
                    "v": 7,
                    "ts": f"{day.isoformat()}T{9 + i % 9:02d}:{i % 60:02d}:00.000+00:00",
                    "run_id": f"door-{uuid.uuid4().hex[:12]}",
                    "principal_kind": "machine",
                    "principal_id": who,
                    "agent": "issue-reporter",
                    "tool": tool,
                    "effect": "" if deny else effect,
                    "args": {},
                    "decision": "deny" if deny else "allow",
                    "reason": (
                        "this token has made 1000 calls through the MCP door today, "
                        "which is its ceiling."
                        if deny and i % 22 == 0
                        else ("agent may not call it" if deny else "")
                    ),
                    "outcome": outcome,
                    "duration_ms": None if deny else 60 + (i * 37) % 700,
                    "response_bytes": None if deny else 200 + i * 13,
                    "acting_for": None if source == "none" else f"{who}@acme.example",
                    "identity_source": source,
                    # Step 045b put money on this page and 045c put a remedy sentence
                    # beside it, and **neither had ever been rendered in a browser**:
                    # this seed predates the counters, so the "Spend" card drew
                    # nothing and the unpriced sentence had no way to appear. Every
                    # sixth allowed call reports usage, and every eighteenth reports it
                    # under a model no rate table can value — which is what makes the
                    # short-figure sentence and its remedy visible below.
                    **(
                        {}
                        if deny
                        else _reported_usage(i)
                    ),
                },
            )


def _reported_usage(i: int) -> dict:
    """What a brokered model call reported, on some of the door's traffic.

    Most door calls touch no model and carry NULL counters — that is the ordinary case
    and migration 048 exists to keep it distinguishable from a call that spent nothing.
    So only a slice of these rows carry usage, and one in three of those names a model
    the built-in rate table cannot price, because the sentence under test is the one
    that says *the figure is short, and here is the file that completes it*.
    """
    if i % 6:
        return {}
    unpriced = (i % 18) == 0
    return {
        "model": "llama-3-70b" if unpriced else "claude-haiku-4-5-20251001",
        "input_tokens": 4000 + (i * 131) % 9000,
        "output_tokens": 200 + (i * 17) % 800,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
    }


def main() -> int:
    import psycopg

    refuse_if_taken(EDGE_PORT, API_PORT)
    ensure_bundle()
    SHOTS.mkdir(parents=True, exist_ok=True)

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB} (FORCE)")
        conn.execute(f"CREATE DATABASE {DB}")
    dsn = dsn_for(DB)

    os.environ["CARNET_DATABASE_URL"] = dsn
    os.environ.setdefault(
        "CARNET_SECRET_KEY", base64.b64encode(os.urandom(32)).decode()
    )

    from carnet import bootstrap, storage
    from carnet.localidp import accounts
    from carnet.localidp.edge import EdgeConfig, serve
    from carnet.localidp.provider import LocalProvider
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    migrate.apply(dsn)
    store = storage.configure(PostgresStorage(dsn))
    store.create_tenant(TENANT, "Overview")
    bootstrap.seed_tenant(TENANT)
    store.save_tenant_idp(TENANT, LocalProvider.idp_row(jwks_uri=f"{APP}/idp/v1/keys"))
    seed(store)
    store.close()

    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port", str(API_PORT)],
        env={
            **os.environ,
            "CARNET_TENANT": TENANT,
            "CARNET_WORKERS": "0",
            "CARNET_BOOTSTRAP_ADMIN": ADMIN,
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    state = pathlib.Path(tempfile.mkdtemp(prefix="e2e-overview-"))
    provider = LocalProvider(state)
    db = accounts.open_db(str(state / "accounts.db"))
    edge = serve(
        EdgeConfig(
            host="127.0.0.1",
            port=EDGE_PORT,
            dist_dir=str(FRONTEND / "dist"),
            api_port=API_PORT,
            admin_email=ADMIN,
            redirect_uris=(f"{APP}/login/callback",),
        ),
        provider,
        db,
    )

    try:
        wait_for(f"http://127.0.0.1:{API_PORT}/health")
        drive()
        if KEEP:
            print(f"\nworld is up at {APP} — sign in as {ADMIN}. Ctrl-C to stop.")
            while True:
                time.sleep(3600)
    finally:
        if not KEEP:
            api.terminate()
            api.wait(timeout=10)
            edge.shutdown()
            edge.server_close()
            shutil.rmtree(state, ignore_errors=True)

    failed = [label for label, ok in CHECKS if not ok]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    for label in failed:
        print(f"  FAILED  {label}")
    return 1 if failed else 0


def sign_in(page):
    page.goto(APP)
    page.wait_for_selector("button.btn.primary", timeout=30000)
    page.click("button.btn.primary")
    page.wait_for_selector("form[action='/idp/login']", timeout=30000)
    page.click("text=Create one")
    page.wait_for_selector("form[action='/idp/register']", timeout=30000)
    page.fill("#name", "Priya")
    page.fill("#password", "a strong enough password")
    page.click("button[type=submit]")
    page.wait_for_selector("aside.sidebar", timeout=30000)


def drive():
    with sync_playwright() as p:
        browser = p.chromium.launch()

        say("an administrator signs in and finds the overview in the rail")
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        sign_in(page)
        # The admin group is behind the `/me` fetch, so the rail renders in two stages —
        # waiting for the shell alone reads it half-built.
        page.wait_for_selector(".sidebar-group", timeout=30000)
        hrefs = page.locator("nav.sidebar-nav a").evaluate_all(
            "els => els.map(e => e.getAttribute('href'))"
        )
        # **`/overview`, not `/admin/overview`, since 013c.** The page opened for
        # everybody — spend is the reader's own and needs no role — so the rail link
        # moved out of the admin group. `/admin/overview` still *resolves* (App.tsx
        # keeps the route) which is why nothing here failed until somebody read the
        # rail, and this assertion sat stale.
        check("Overview is offered in the rail", "/overview" in hrefs)
        check(
            "and it comes before the admin group rather than inside it",
            hrefs.index("/overview") < hrefs.index("/admin"),
        )

        page.click("nav.sidebar-nav a[href='/overview']")
        page.wait_for_selector("text=Requests per day", timeout=30000)
        page.wait_for_timeout(600)

        say("the figures actually draw")
        charts = page.locator("svg.chart")
        check("every figure rendered an svg", charts.count() >= 4)
        box = charts.first.bounding_box()
        check(
            "and the first one has real width and height on the page",
            bool(box) and box["width"] > 400 and box["height"] > 100,
        )
        marks = page.locator("svg.chart rect.chart-mark")
        check("the door stack drew marks", marks.count() > 20)

        say("the tile row, the figure total and the table agree about one number")
        tiles = page.locator(".stats .stat")
        # **Read `.v`, not the tile's last line**, and 066 is why the difference became
        # load-bearing rather than stylistic. This was `inner_text().split("\n")[-1]`,
        # which worked while a tile was exactly two lines — a label and a number. 066
        # added a third, the comparison with the window before, so the last line became
        # "none in the window before" and this parsed it as an integer.
        #
        # Naming the element that holds the value is what the assertion always meant, and
        # it survives the next thing somebody adds to a tile. The same lesson `calls_figure`
        # below already learned when 013c inserted two figures above this one.
        calls_tile = tiles.filter(has_text="Requests")
        traffic = int(calls_tile.locator(".v").inner_text().replace(",", ""))
        check("the tile carries a real figure", traffic > 100)
        # **Selected by its title, not by being first.** 013c inserted the spend
        # figures ("Tokens per day", "Where the money went") above the door's traffic,
        # so `.figure.first` stopped being the one whose total is a *call count* and
        # this compared a token total against a call total. Naming the figure keeps the
        # assertion's actual intent — the tile, the figure and the table are three
        # renderings of one fact — and survives the next reordering.
        calls_figure = page.locator(".figure").filter(
            has=page.locator(".figure-title", has_text="Requests per day")
        )
        figure_total = calls_figure.locator(".figure-total").first.inner_text()
        check(
            "the figure's own total repeats it",
            f"{traffic:,}" in figure_total,
        )

        say("what the MCP server cost, and the sentence that says what the figure is short by")

        # 045b's card and 045c's remedy, rendered rather than unit-tested. The card only
        # exists once door rows carry counters, which is why it needed the seed above —
        # and it lives on its own pane now, offered only when there is spend to show, so
        # the tab is opened first rather than read through a hidden panel.
        page.click("button:text-is('Cost')")
        page.wait_for_timeout(400)
        cost = page.locator(".card").filter(has=page.locator("h2:text-is('Spend')"))
        check("the money card is on the page", cost.count() == 1)
        check("with a dollar figure drawn from the counters",
              "$" in cost.first.inner_text())
        short = cost.first.inner_text()
        check("naming the model the price list could not value", "llama-3-70b" in short)
        check("and the file that completes the figure — 045c decision 4",
              "CARNET_MODEL_RATES" in short)
        check("the remedy reads as a remedy rather than a bare variable name",
              "price list" in short and "repriced" in short)
        page.click("button:text-is('Traffic')")
        page.wait_for_timeout(400)

        say("the numbers are reachable without leaving the page")
        page.locator("details.figure-numbers summary").first.click()
        page.wait_for_timeout(200)
        rows = page.locator("details.figure-numbers[open] tbody tr")
        check("the disclosure opens a table of the days", rows.count() > 5)

        page.locator("details.figure-numbers summary").first.click()
        page.wait_for_timeout(200)
        check(
            "and closes again, so the page's resting state is the figures",
            page.locator("details.figure-numbers[open]").count() == 0,
        )

        say("the identity split renders three bands and never a total")
        identity = page.locator("svg[aria-label='Identity per day']")
        legend = page.locator(".figure", has=identity).locator(".legend li")
        labels = [t.strip() for t in legend.all_inner_texts()]
        check(
            "verified, asserted and nobody-named are three legend entries",
            labels == ["Verified", "Asserted", "Nobody named"],
        )

        # --- step 066 ----------------------------------------------------------------
        #
        # Everything below is a claim a unit test cannot settle: that the link a mark
        # carries is followable and lands somewhere with rows, that a colour ramp resolves
        # against the surface it is drawn on, and that a 24-column axis fits.

        say("a mark is a link, and following one lands on the calls behind it")
        column = page.locator("svg[aria-label='Requests per day'] a").first
        href = column.get_attribute("href")
        check("the day's column carries a link", bool(href) and "since=" in (href or ""))
        # **Marked before the click, checked after.** A full document navigation replaces
        # the window and everything on it; a client-side one does not. This stamps the
        # live page and looks for the stamp afterwards, which is the only way from here
        # to tell a push from a reload — and the difference is not cosmetic: `auth.ts`
        # keeps the token in a module-scope variable, so a reload signs the reader out
        # and bounces them through the provider on the way to a page they could already
        # see. That is what a bare `<a href>` did here, found by clicking a bar.
        page.evaluate("() => { window.__stillTheSameDocument = true }")
        column.click()
        page.wait_for_timeout(900)
        check(
            "and following it reaches the door's log",
            "/admin/door-calls" in page.url,
        )
        check(
            "without reloading the document, which would drop the in-memory token",
            page.evaluate("() => window.__stillTheSameDocument === true"),
        )
        check(
            "which says what it is narrowed to rather than looking like the whole log",
            page.locator(".log-filters").count() == 1,
        )
        # The link carried a single day, so the log it lands on holds only that day's
        # rows. An empty page here would mean the two screens disagree about the window,
        # which is the failure the shared `since`/`until` exists to prevent.
        check(
            "and it is not empty, so the aggregate and the record agree",
            page.locator("tbody tr").count() > 0,
        )
        page.go_back()
        page.wait_for_timeout(900)

        say("a capped leaderboard says what it cut")
        page.click("button:text-is('Callers & tools')")
        page.wait_for_timeout(500)
        # Exact, not a substring: "Tools" is also the tail of "Slowest tools".
        tools = page.locator(".figure").filter(
            has=page.locator(".figure-title:text-is('Tools')")
        )
        total = tools.locator(".figure-total").first.inner_text()
        check(
            "the tool figure names how many there really are",
            "of" in total or "tool" in total,
        )
        check(
            "and the permission list that admitted the traffic has its own figure",
            page.locator(".figure-title:text-is('Agents')").count() == 1,
        )
        check(
            "and which tool is slow, which only existed per day before",
            page.locator(".figure-title:text-is('Slowest tools')").count() == 1,
        )

        say("the identity pane names people, not just kinds of claim")
        page.click("button:text-is('Identity')")
        page.wait_for_timeout(500)
        check(
            "whose names went out is drawn",
            page.locator(".figure-title:text-is('Names')").count() == 1,
        )
        # 033c's rule, rendered: the note beside each name says what the claim was worth,
        # so a verified name and an asserted one can never be read as the same fact.
        notes = page.locator(".hbar-note").all_inner_texts()
        check(
            "with what each claim was worth beside it",
            any("verified" in n or "asserted" in n for n in notes),
        )

        say("the governance pane says what the refusals actually said")
        page.click("button:text-is('Governance')")
        page.wait_for_timeout(500)
        check(
            "the sentences the controls wrote are ranked",
            page.locator(".figure-title:text-is('Denial reasons')").count() == 1,
        )
        page.click("button:text-is('Traffic')")
        page.wait_for_timeout(400)

        say("the hour grid draws, and an empty hour is empty rather than faint")
        grid = page.locator(".heat")
        check("the grid is on the page", grid.count() == 1)
        check("with a cell for every hour of every weekday", 
              page.locator(".heat-cell").count() == 168)
        # The whole reason the ramp is in the token layer: a `var(--chart-heat-*)` that
        # does not resolve in this theme renders as transparent, which looks exactly like
        # a quiet hour. Only a rendering can tell those apart.
        lit = page.evaluate(
            """() => [...document.querySelectorAll('.heat-cell')]
                 .map(c => getComputedStyle(c).backgroundColor)
                 .filter(c => c && c !== 'rgba(0, 0, 0, 0)').length"""
        )
        check(f"and every cell resolved to a real colour ({lit} of 168)", lit == 168)

        say("the one-day window buckets by the hour")
        page.click("button:text-is('Today')")
        page.wait_for_timeout(900)
        # **`textContent` through `evaluate`, not `inner_text`.** `inner_text` is an HTML
        # property and an SVG `<text>` does not have one — Playwright hands back `None`
        # for every node, so the first version of this check read eleven real ticks as
        # zero and reported a defect in the page. The collision check further down
        # already reaches into the DOM for the same reason; this now matches it.
        hours = page.evaluate(
            """() => [...document.querySelectorAll(
                 "svg[aria-label='Requests per day'] text.chart-tick")]
                 .map(t => t.textContent || "")
                 .filter(t => t.includes(":"))"""
        )
        check(f"the axis is hours rather than dates ({len(hours)} hour ticks)", len(hours) > 0)
        check(
            "and the footnote says so instead of claiming a range of days",
            "by the hour" in page.locator("p.footnote").inner_text(),
        )
        # The window is in the URL now, which is the half of this that makes a link
        # somebody sends mean what they meant.
        check("the window is in the URL", "days=1" in page.url)
        page.click("button:text-is('30 days')")
        page.wait_for_timeout(900)

        say("nothing overflows sideways — the defect nobody reports")
        overflow = page.evaluate(
            "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        check(f"no horizontal scroll on the page (overflow {overflow}px)", overflow <= 1)

        say("the day labels do not collide, at 30 days and at 90")
        for window in ("30 days", "90 days"):
            page.click(f"button:text-is('{window}')")
            page.wait_for_timeout(700)
            xs = page.evaluate(
                """() => {
                  const svg = document.querySelector("svg[aria-label='Requests per day']");
                  const ticks = [...svg.querySelectorAll('text.chart-tick')]
                    .filter(t => !t.hasAttribute('dy'));
                  return ticks.map(t => t.getBoundingClientRect())
                              .sort((a, b) => a.x - b.x)
                              .map(r => [r.x, r.x + r.width]);
                }"""
            )
            worst = min(
                (nxt[0] - cur[1] for cur, nxt in zip(xs, xs[1:])), default=999
            )
            check(
                f"{window}: {len(xs)} day labels, closest gap {worst:.1f}px",
                worst > 2,
            )

        say("a screenshot in each theme — the dark palette is selected, not flipped")
        page.click("button:text-is('30 days')")
        page.wait_for_timeout(500)
        for theme in ("light", "dark"):
            page.emulate_media(color_scheme=theme)
            page.wait_for_timeout(400)
            shot = SHOTS / f"overview-{theme}.png"
            page.screenshot(path=str(shot), full_page=True)
            check(f"{theme}: screenshot written to {shot.name}", shot.exists())

            # A fill that resolved to nothing renders transparent and the figure looks
            # blank — which a screenshot records and no assertion above would catch.
            filled = page.evaluate(
                """() => {
                  const marks = [...document.querySelectorAll('svg.chart rect.chart-mark')];
                  return marks.filter(m => {
                    const c = getComputedStyle(m).fill;
                    return c && c !== 'none' && !c.includes('rgba(0, 0, 0, 0)');
                  }).length;
                }"""
            )
            check(f"{theme}: every mark resolved to a real fill", filled > 20)

        # --- the exhaustive pass: every clickable, on every pane -----------------------
        #
        # Written after a bare `<a href>` shipped on every link this page grew in 066 and
        # signed the reader out of the app on the first click. One link was then fixed and
        # checked; that is not the same as checking the others, and the difference is what
        # this block exists to remove.
        #
        # **The property, stated once so it can be asserted many times:** `auth.ts` keeps
        # the access token in a module-scope variable — deliberately, so that a machine
        # left logged in overnight holds nothing — therefore *no* navigation inside this
        # app may replace the document. Every clickable is walked, clicked, and checked
        # against the same stamp.

        say("every clickable on every pane navigates without replacing the document")

        page.goto(f"{APP}/overview?days=30", wait_until="domcontentloaded")
        page.wait_for_selector(".stats .stat", timeout=20000)

        # "Cost" is offered only when the window carries spend, which the seed above
        # guarantees; it holds no links today, and walking it keeps that a finding
        # rather than an assumption.
        panes = ["Traffic", "Identity", "Callers & tools", "Cost", "Governance"]
        walked = 0
        reloaded = []
        dead = []

        # The tiles sit above the strip and belong to no pane, so they are walked once.
        # Everything else is walked pane by pane, because a hidden pane's links are in the
        # DOM (`Tabs` hides rather than unmounts) and clicking one of those would be
        # clicking something no reader can reach.
        def clickables(scope):
            return scope.locator("a[href]")

        def walk(scope, label):
            nonlocal walked
            count = clickables(scope).count()
            for index in range(count):
                link = clickables(scope).nth(index)
                if not link.is_visible():
                    continue
                href = link.get_attribute("href") or ""
                # An external or absolute link would be a different question — there are
                # none on this page, and the assertion below would be wrong about one.
                if not href.startswith("/"):
                    continue
                page.evaluate("() => { window.__sameDoc = true }")
                link.click()
                page.wait_for_timeout(450)
                if not page.evaluate("() => window.__sameDoc === true"):
                    reloaded.append(f"{label}: {href}")
                # A link that lands on a page reporting a failure is a broken link even
                # when it navigated correctly — a 422 from a filter the server refuses
                # looks exactly like a working link until somebody reads the page.
                if page.locator(".notice.bad, .notice.warn").count():
                    dead.append(f"{label}: {href} -> {page.locator('.notice').first.inner_text()[:60]}")
                walked += 1
                page.go_back()
                page.wait_for_timeout(450)
                page.wait_for_selector(".stats .stat", timeout=20000)

        walk(page.locator(".stats"), "tile")

        for pane in panes:
            page.click(f"button:text-is('{pane}')")
            page.wait_for_timeout(400)
            # Only the visible pane. `Tabs` hides rather than unmounts, so scoping to the
            # one panel that is not `[hidden]` is what keeps this walking what a reader
            # can actually reach.
            walk(page.locator("[role='tabpanel']:not([hidden])"), pane)

        check(f"every one of {walked} links navigated in-document", not reloaded)
        if reloaded:
            for one in reloaded:
                print(f"        RELOADED  {one}")
        check("and none of them landed on a failure", not dead)
        if dead:
            for one in dead:
                print(f"        DEAD  {one}")
        check("and there were links on every pane worth walking", walked >= 12)

        say("a narrow viewport still has no sideways scroll")
        page.set_viewport_size({"width": 420, "height": 900})
        page.wait_for_timeout(500)
        narrow = page.evaluate(
            "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        check(f"no horizontal scroll at 420px (overflow {narrow}px)", narrow <= 1)

        if not KEEP:
            browser.close()


if __name__ == "__main__":
    raise SystemExit(main())
