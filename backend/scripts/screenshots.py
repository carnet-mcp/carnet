"""Screenshots of the real product, for the README. Step 106.

    cd backend && CARNET_E2E_PG=postgresql://postgres:test@localhost:55432 \
        .venv/bin/python scripts/screenshots.py

**Generated, never hand-collected.** The previous set was taken by hand in August, went
stale the moment the product was renamed and the navigation was redesigned, and was
gitignored — so the README of a product with a web interface showed no picture of it.
A screenshot nobody can regenerate is a screenshot that is wrong within a month.

This builds its own world, drives the **built bundle** through the local identity
provider's edge — the same shape `carnet --local` serves, so what is photographed is what
a person actually gets — and writes PNGs into `docs/screenshots/readme/`, which is the one
path under `docs/screenshots/` that is **not** gitignored, because these ship.

The month of door traffic behind the overview is `e2e_browser_overview.seed`, reused
rather than reinvented: it is deterministic, so re-running this produces the same figures
and a diff of the images is a real change rather than noise.
"""

from __future__ import annotations

import base64
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

ROOT = HERE.parent
FRONTEND = ROOT.parent / "frontend"
OUT = ROOT.parent / "docs" / "screenshots" / "readme"

DB = "carnet_screenshots"
TENANT = "acme"
ADMIN = "priya@local.test"
EDGE_PORT = 8093
API_PORT = 8013
APP = f"http://127.0.0.1:{EDGE_PORT}"
VIEW = {"width": 1440, "height": 900}

import e2e_browser_overview as _ov  # noqa: E402
from e2e_browser_overview import (  # noqa: E402
    dsn_for, refuse_if_taken, seed, wait_for,
)

# `seed` writes against the module-level tenant of the harness it came from. Point it at
# ours rather than copying two hundred lines of deterministic traffic into this file.
_ov.TENANT = TENANT


def say(what):
    print(f"  {what}", flush=True)


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


def shot(page, name, *, full=False):
    page.wait_for_timeout(700)
    path = OUT / f"{name}.png"
    page.screenshot(path=str(path), full_page=full)
    kb = path.stat().st_size // 1024
    say(f"{name}.png  ({kb} KB)")


def world():
    """Everything the screens need something to show."""
    import psycopg

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB} (FORCE)")
        conn.execute(f"CREATE DATABASE {DB}")
    dsn = dsn_for(DB)
    os.environ["CARNET_DATABASE_URL"] = dsn
    os.environ.setdefault("CARNET_SECRET_KEY", base64.b64encode(os.urandom(32)).decode())
    os.environ["JIRA_TOKEN"] = "not-a-real-token"

    from carnet import agents, bootstrap, storage, tools
    from carnet.core import crypto
    from carnet.localidp.provider import LocalProvider
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage
    from carnet.tools.base import Resource
    from carnet.tools.mcp.binding import Connector, HttpLaunch, Vetted

    migrate.apply(dsn)
    store = storage.configure(PostgresStorage(dsn))
    crypto.configure(crypto.from_environment())
    store.create_tenant(TENANT, "Acme")
    bootstrap.seed_tenant(TENANT)
    store.save_tenant_idp(TENANT, LocalProvider.idp_row(jwks_uri=f"{APP}/idp/v1/keys"))

    # A connector with tools vetted at both effects, so the catalogue and the vetting
    # screen have something with shape to it.
    store.allow_host(TENANT, "mcp.atlassian.example", actor="system:cli", note="Jira")
    # Built and saved directly rather than through `vet_tool`, which dials the server to
    # confirm the tool is really advertised — correct for a person vetting, impossible
    # against a host that exists only in a screenshot.
    connector = Connector(
        id="jira",
        description="Jira, over its MCP server",
        launch=HttpLaunch(url="https://mcp.atlassian.example/mcp", credential_env="JIRA_TOKEN"),
        vetted=tuple(
            Vetted(
                remote_name=name,
                effect=effect,
                identity="service",
                resources=(Resource("jira.project", ["project"]),),
                note=note,
                description=desc,
            )
            for name, effect, note, desc in (
                ("search_issues", "read", "", "Search issues in a project."),
                ("create_issue", "write",
                 "Notifies everyone watching the project.", "Open an issue."),
            )
        ),
    )
    tools.save_connector(TENANT, connector, actor="system:cli")

    agents.save(TENANT, {
        "name": "triage",
        "permissions": {"tools": ["jira_search_issues"],
                        "scope": {"jira.project": {"read": ["ACME", "PLATFORM"]}}},
    }, actor="system:cli")
    agents.save(TENANT, {
        "name": "issue-filer",
        "permissions": {"tools": ["jira_create_issue"],
                        "scope": {"jira.project": {"write": ["ACME"]}}},
    }, actor="system:cli")

    seed(store)
    store.close()
    return dsn


def main() -> int:
    refuse_if_taken(EDGE_PORT, API_PORT)
    # **Always rebuilt, never reused.** `ensure_bundle` returns early when a `dist/`
    # exists at all, which is right for a harness asserting behaviour and wrong here:
    # what this script writes is a photograph, and a photograph of a bundle somebody
    # built last week is a stale screenshot that looks freshly generated. The words
    # pass (107a) was caught by exactly this — the run produced six PNGs of the
    # previous vocabulary and reported success.
    say("building the frontend bundle (always, so what is photographed is this tree)")
    subprocess.run(["npm", "run", "build"], cwd=FRONTEND, check=True,
                   stdout=subprocess.DEVNULL)
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    world()

    from playwright.sync_api import sync_playwright

    from carnet.localidp import accounts
    from carnet.localidp.edge import EdgeConfig, serve
    from carnet.localidp.provider import LocalProvider

    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port", str(API_PORT)],
        env={**os.environ, "CARNET_TENANT": TENANT, "CARNET_BOOTSTRAP_ADMIN": ADMIN},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    state = pathlib.Path(tempfile.mkdtemp(prefix="shots-"))
    provider = LocalProvider(state)
    db = accounts.open_db(str(state / "accounts.db"))
    edge = serve(
        EdgeConfig(host="127.0.0.1", port=EDGE_PORT, dist_dir=str(FRONTEND / "dist"),
                   api_port=API_PORT, admin_email=ADMIN,
                   redirect_uris=(f"{APP}/login/callback",)),
        provider, db,
    )
    try:
        wait_for(f"http://127.0.0.1:{API_PORT}/health")
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport=VIEW, device_scale_factor=2)
            sign_in(page)
            page.wait_for_selector(".sidebar-group", timeout=30000)

            page.click("nav.sidebar-nav a[href='/overview']")
            page.wait_for_selector("text=Requests per day", timeout=30000)
            shot(page, "overview")

            page.goto(f"{APP}/admin/door-calls")
            page.wait_for_selector("table", timeout=30000)
            shot(page, "request-log")

            page.goto(f"{APP}/connections")
            page.wait_for_selector("main", timeout=30000)
            shot(page, "connections")

            page.goto(f"{APP}/agents")
            page.wait_for_selector("main", timeout=30000)
            shot(page, "agents")

            page.goto(f"{APP}/admin/connectors/jira")
            page.wait_for_selector("main", timeout=30000)
            shot(page, "connector-tools")

            page.goto(f"{APP}/agents/triage")
            page.wait_for_selector("main", timeout=30000)
            shot(page, "agent-detail")

            browser.close()
    finally:
        api.terminate()
        api.wait(timeout=10)
        edge.shutdown()
        edge.server_close()
        shutil.rmtree(state, ignore_errors=True)

    print(f"\nwrote {len(list(OUT.glob('*.png')))} screenshots to {OUT.relative_to(ROOT.parent)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
