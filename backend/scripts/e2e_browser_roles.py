"""The platform role, in a real browser — 12b's one done-when that is not a test.

*Sign in as a non-administrator and confirm the Administration nav item is absent and the
deep link renders the 403 sentence.* The `your_role` class of bug — a screen offering a
control that refuses the person it was rendered for — has only ever been found by looking,
and this is the first check in this project that looks **without a person at the
keyboard**.

## What it took to make that possible, which is a bug this script found

`scripts/dev_idp.py` and `scripts/browser_world.py` were written in 10d and described in
the handoff as *"a browser check that needs nobody at the keyboard"*. **That had never
been true.** The shipped CSP in `frontend/index.html` named `'self'` and
`https://*.okta.com` in `connect-src` and `frame-src`, and the dev provider is on
`127.0.0.1:8902` — so the silent-renewal iframe was refused, and then the token exchange
was refused, surfacing as *"could not reach the identity provider's token endpoint"*: a
sentence about CORS that sends whoever reads it to configure a Trusted Origin that does not
exist. `vite.config.ts` answered it by adding the configured issuer to the **dev** copy of
the policy, beside the `unsafe-inline` relaxation that was there for the same reason.

**Step 031 removed the need for that half.** `connect-src` and `frame-src` left the meta
tag entirely — they name a deployment's identity provider, which a bundle cannot know —
and are served as a header by the front door instead. The dev server serves no such
header, so a dev-mode page now imposes no connection restriction at all and any provider
works, which is why `relaxCspForDev` is down to the one `script-src` line. What still
ships strictly is the deployed artifact, and `scripts/e2e_browser_deploy.py` is where
that policy is driven by a real browser.

## Running it

Three processes, in three terminals:

    CARNET_E2E_PG=postgresql://... .venv/bin/python scripts/browser_world.py

    cd ../frontend && VITE_OIDC_ISSUER=http://127.0.0.1:8902 \
        VITE_OIDC_CLIENT_ID=dev VITE_OIDC_SCOPES=openid npm run dev

    WORLD_DSN=postgresql://.../carnet_browser \
        CARNET_SECRET_KEY=$(carnet --generate-key) \
        .venv/bin/python scripts/e2e_browser_roles.py

Needs `playwright` and its Chromium: `uv pip install playwright && playwright install
chromium`. It is the `browser` extra rather than a base dependency, and CI does not run
this — a headless browser in the test job is a different decision from a browser check
somebody can repeat.

**Costs nothing.** No run is submitted, so no model is called and no connector is launched.
"""

import os
import pathlib
import subprocess
import sys

import httpx
from playwright.sync_api import sync_playwright

# `BROWSER_APP_ORIGIN` for `BROWSER_WORLD_API_PORT`'s reason: 8080 is taken on any machine
# already running the SPA, and a check that cannot start is a check nobody runs.
APP = os.environ.get("BROWSER_APP_ORIGIN", "http://localhost:8080")
IDP = "http://127.0.0.1:8902"
CHECKS = []


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok))
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: {actual!r}" + ("" if ok else f"  (expected {expected!r})"))


def say(what):
    print(f"\n=== {what}", flush=True)


def cli(*args):
    result = subprocess.run(
        [sys.executable, "-m", "carnet.cli", *args],
        cwd=str(pathlib.Path(__file__).resolve().parent.parent),
        env={
            **os.environ,
            "CARNET_DATABASE_URL": os.environ["WORLD_DSN"],
            "CARNET_TENANT": "browser",
        },
        capture_output=True,
        text=True,
    )
    print(f"      $ carnet {' '.join(args)}")
    for line in (result.stdout + result.stderr).splitlines():
        print(f"        {line}")
    return result


def nav_items(page):
    return [t.strip() for t in page.locator("nav.sidebar-nav a").all_inner_texts()]


def seed_an_agent_priya_cannot_reach():
    """One agent owned by sam and shared with nobody else.

    `browser_world.py` gives priya an editor grant on `issue-reporter` and ownership of
    `team-bot`, so neither of those can show that a role grants no agent access. This is
    the row that can.
    """
    os.environ["CARNET_DATABASE_URL"] = os.environ["WORLD_DSN"]
    from carnet import storage
    from carnet.storage.postgres import PostgresStorage

    store = storage.configure(PostgresStorage(os.environ["WORLD_DSN"]))
    if store.get_agent("browser", "payroll-bot") is None:
        store.create_agent(
            "browser",
            {
                "name": "payroll-bot",
                "runtime": "simple",
                "system": "You read payroll.",
                "model": "claude-haiku-4-5",
                "permissions": {"tools": [], "scope": {}},
            },
            "user",
            "u_sam",
        )
    store.close()


def main():
    seed_an_agent_priya_cannot_reach()
    httpx.get(f"{IDP}/_be/priya@acme.com", timeout=5)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()

        say("priya signs in. She is not an administrator")
        page.goto(f"{APP}/agents")
        # Silent renewal against the dev provider. It was impossible until 12b — the
        # shipped meta CSP named only `'self'` and `*.okta.com` for
        # `frame-src`/`connect-src`, so the iframe and then the token exchange were
        # both refused — and since 031 those two directives are not in the meta at all
        # (the front door serves them; the dev server serves no header), so nothing
        # here is policy-restricted. The Sign in button is the fallback.
        if page.locator("button.btn.primary").count():
            page.click("button.btn.primary")
        page.wait_for_selector("aside.sidebar", timeout=30000)
        page.wait_for_timeout(1500)
        check("she is signed in", "priya@acme.com" in page.content(), True)
        # The member's nav, as it stands after 078 deleted the runtime (Agents,
        # Conversations and Runs went with it), 091–093 renamed what stayed, and the
        # vocabulary pass renamed it again (Tokens → Access tokens, Overview → Usage).
        # Step 099's census found this check still asserting the 014 nav — the harness
        # had rotted, not the product.
        check("the nav offers four items", nav_items(page),
              ["Agents", "Connections", "Access tokens", "Usage"])
        check("and NOT the audit log", "Audit log" in nav_items(page), False)

        say("she types the URL anyway — the route exists and the server refuses her")
        page.goto(f"{APP}/admin")
        page.wait_for_timeout(1500)
        body = page.inner_text("main")
        # The page head paints before the request answers, so the title is what says
        # the route rendered at all; the 403 sentence below it is the server's.
        check("the page renders", "Audit log" in body, True)
        check("with the server's own sentence", "you are not one" in body, True)
        check("and what to do about it", "can grant it" in body, True)
        check("and it does not offer to sign her in again",
              "Signing in again will not change this" in body, True)
        check("no table", page.locator("table").count(), 0)

        say("an engineer grants the role at a terminal")
        granted = cli("--grant-role", "admin", "priya@acme.com")
        check("the command succeeded", granted.returncode, 0)

        say("she reloads. Nothing about her session changed")
        page.goto(f"{APP}/agents")
        page.wait_for_timeout(2000)
        # **Five items, not one.** The redesign moved Groups and Connectors out of a
        # sub-navigation behind Administration and into the sidebar itself, and the
        # door's two logs (041, 045) joined them, so what a new administrator gains is
        # all five at once. The property under test is unchanged and is asserted from
        # both sides: nothing administrative is offered before the grant, all of it
        # after, and the counterpart check below watches them disappear again on revoke.
        check("the nav now offers the five administrative sections", nav_items(page),
              ["Agents", "Connections", "Access tokens", "Usage",
               "Audit log", "Request log", "Access denied", "Groups", "Connectors"])

        say("and the log is a screen")
        # Anchored to the rail: `text=` is a case-insensitive substring match, and
        # "audit log" is a phrase the pages themselves use in hints and ledes.
        page.click("nav.sidebar-nav a:has-text('Audit log')")
        page.wait_for_timeout(2000)
        body = page.inner_text("main")
        check("the log rendered", "role.grant" in body, True)
        check("naming who did it", "system:cli" in body, True)
        check("and what it was about", "user:u_priya" in body, True)
        check("with the group share the world was built with", "grant.create" in body, True)
        check("a table exists now", page.locator("table").count(), 1)
        if os.environ.get("SHOT"):
            page.screenshot(path=os.environ["SHOT"], full_page=True)

        say("AN ADMIN IS NOT A SUPERUSER — her agent list is unchanged")
        page.goto(f"{APP}/agents")
        page.wait_for_timeout(2000)
        listed = page.inner_text("main")
        check("payroll-bot is sam's and she is an administrator",
              "payroll-bot" in listed, False)
        check("she sees exactly what was shared with her",
              sorted(t for t in ("issue-reporter", "team-bot") if t in listed),
              ["issue-reporter", "team-bot"])
        page.goto(f"{APP}/agents/payroll-bot")
        page.wait_for_timeout(1500)
        check("and opening it by URL is a 404 she cannot tell from an absent agent",
              "no agent" in page.inner_text("main").lower(), True)

        say("revoked at the terminal, and the screen goes away")
        cli("--revoke-role", "admin", "priya@acme.com")
        page.goto(f"{APP}/agents")
        page.wait_for_timeout(2000)
        check("the nav is four again", nav_items(page),
              ["Agents", "Connections", "Access tokens", "Usage"])
        page.goto(f"{APP}/admin")
        page.wait_for_timeout(1500)
        check("and the deep link refuses her again",
              "you are not one" in page.inner_text("main"), True)

        browser.close()

    failed = [label for label, ok in CHECKS if not ok]
    say(f"{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    for label in failed:
        print("  FAILED:", label)
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
