"""The local sign-in, in a real browser, under the CSP that ships.

**The one assertion no headless test can make**: the built bundle — `frontend/dist`,
with `index.html`'s real Content-Security-Policy, no dev-server relaxation — served
from one origin beside the provider and the API, signs a person in. And the assertion
this deployment is uniquely able to make: **a reload re-enters silently.** Against the
real org, `prompt=none` dies on third-party cookies in every headless browser this
project has ever driven; here the provider's session cookie is first-party in the
renewal iframe, so the silent path is exercised for real, for the first time.

    cd backend && .venv/bin/python scripts/e2e_browser_local.py

Needs `playwright` and its Chromium, `npm` (to build `frontend/dist` if it is
missing), and Postgres. Its own ports; refuses to start if any is taken. The database
it leaves behind is safe to drop. Costs nothing: no run is submitted.
"""

import base64
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit, urlunsplit

from playwright.sync_api import sync_playwright

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_e2e_browser_local"

ROOT = pathlib.Path(__file__).resolve().parent.parent
FRONTEND = ROOT.parent / "frontend"


def dsn_for(database: str) -> str:
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


TENANT = "e2ebrowserlocal"
ADMIN = "priya@local.test"
EDGE_PORT = 8088
API_PORT = 8007
APP = f"http://127.0.0.1:{EDGE_PORT}"

CHECKS = []


def check(label, ok):
    CHECKS.append((label, bool(ok)))
    print(f"{'  ok' if ok else 'FAIL'}  {label}", flush=True)
    return ok


def say(what):
    print(f"\n=== {what}", flush=True)


def refuse_if_taken(*ports):
    for port in ports:
        with socket.socket() as probe:
            probe.settimeout(0.5)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                raise SystemExit(
                    f"something is already listening on 127.0.0.1:{port}. Stop it, or "
                    "edit the port constants at the top of this file."
                )


def wait_for(url, seconds=60):
    import httpx

    for _ in range(seconds * 2):
        try:
            httpx.get(url, timeout=1)
            return
        except Exception:
            time.sleep(0.5)
    raise SystemExit(f"{url} never answered")


def ensure_bundle():
    from carnet.localidp.frontdoor import bundle_is_stale

    if not bundle_is_stale():
        return
    if not shutil.which("npm"):
        raise SystemExit("frontend/dist is missing or stale and npm is not on PATH.")
    print("Building frontend/dist (missing or stale)...", flush=True)
    if not (FRONTEND / "node_modules").exists():
        subprocess.run(["npm", "ci"], cwd=str(FRONTEND), check=True)
    subprocess.run(["npm", "run", "build"], cwd=str(FRONTEND), check=True)


def main() -> int:
    import psycopg

    refuse_if_taken(EDGE_PORT, API_PORT)
    ensure_bundle()

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
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
    store.create_tenant(TENANT, "Browser Local")
    bootstrap.seed_tenant(TENANT)
    store.save_tenant_idp(TENANT, LocalProvider.idp_row(jwks_uri=f"{APP}/idp/v1/keys"))
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

    state = pathlib.Path(tempfile.mkdtemp(prefix="e2e-browser-local-"))
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
    finally:
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


def nav(page):
    return [t.strip() for t in page.locator("nav.sidebar-nav a").all_inner_texts()]


def drive():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()

        say("a stranger opens the app: the built bundle, the shipped CSP, no session")
        page.goto(APP)
        # Boot tries silent sign-in first; the provider answers `login_required`
        # instantly (a conformant redirect, not a 400 page), so the Sign in button is
        # the next thing on screen.
        page.wait_for_selector("button.btn.primary", timeout=30000)
        check("the sign-in screen appears, fast", True)

        say("the button leads to the provider's own login page")
        page.click("button.btn.primary")
        page.wait_for_selector("form[action='/idp/login']", timeout=30000)
        check("the provider's login form renders", True)

        say("no account yet - through Create one, which the first-run page prefills")
        page.click("text=Create one")
        page.wait_for_selector("form[action='/idp/register']", timeout=30000)
        check(
            "the admin address is prefilled",
            page.locator("#email").input_value() == ADMIN,
        )
        check(
            "and the page says the first account becomes the administrator",
            page.locator("p.first").count() == 1,
        )
        page.fill("#name", "Priya")
        page.fill("#password", "a strong enough password")
        page.click("button[type=submit]")

        say("registering finished the flow: the SPA exchanged the code and mounted")
        page.wait_for_selector("aside.sidebar", timeout=30000)
        page.wait_for_timeout(1500)
        check("the shell renders under the shipped CSP", True)
        check("named by address in the corner", ADMIN in page.locator(".whoami").inner_text())
        check("the first account is the administrator", "Audit log" in nav(page))

        say("the marquee assertion: a reload re-enters SILENTLY")
        page.reload()
        # No button click. If the silent path is broken this waits out the timeout on
        # a sign-in screen — the exact failure the same-origin design exists to end.
        page.wait_for_selector("aside.sidebar", timeout=30000)
        check(
            "the shell is back with nobody pressing anything",
            page.locator("button.btn.primary").count() == 0,
        )

        say("sign out clears the page's token; the provider session survives — as the button's own tooltip says")
        page.click("text=Sign out")
        page.wait_for_selector("button.btn.primary", timeout=30000)
        page.click("button.btn.primary")
        # No password: the provider still holds their session, so the authorize
        # round-trip issues a code straight away. The same thing Okta would do.
        page.wait_for_selector("aside.sidebar", timeout=30000)
        page.wait_for_timeout(1500)
        check(
            "signing back in needed no password",
            ADMIN in page.locator(".whoami").inner_text(),
        )

        say("the second person — a fresh browser profile, so a fresh provider session")
        second = browser.new_context()
        sam_page = second.new_page()
        sam_page.goto(APP)
        sam_page.wait_for_selector("button.btn.primary", timeout=30000)
        sam_page.click("button.btn.primary")
        sam_page.wait_for_selector("form[action='/idp/login']", timeout=30000)
        sam_page.click("text=Create one")
        sam_page.wait_for_selector("form[action='/idp/register']", timeout=30000)
        check(
            "the second register page prefills nothing",
            sam_page.locator("#email").input_value() == "",
        )
        check(
            "and no longer promises the administrator seat",
            sam_page.locator("p.first").count() == 0,
        )
        sam_page.fill("#email", "sam@local.test")
        sam_page.fill("#password", "another password")
        sam_page.click("button[type=submit]")
        sam_page.wait_for_selector("aside.sidebar", timeout=30000)
        sam_page.wait_for_timeout(1500)
        check("sam is in", "sam@local.test" in sam_page.locator(".whoami").inner_text())
        check("sam has no Audit log item", "Audit log" not in nav(sam_page))

        say("and two people are signed in at once, from one provider — per-browser sessions")
        check(
            "priya's tab still says priya",
            ADMIN in page.locator(".whoami").inner_text(),
        )

        browser.close()


if __name__ == "__main__":
    sys.exit(main())
