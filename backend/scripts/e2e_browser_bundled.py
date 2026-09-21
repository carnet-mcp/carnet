"""A stranger installs Carnet and signs in, in a real browser. Step 121.

    cd backend && .venv/bin/python scripts/e2e_browser_bundled.py

This is the acceptance evidence for the whole of plan 121, and it is a browser script
rather than an HTTP one for the reason plan 031 paid for once: **a CSP is enforced by a
browser and by nothing else.** `e2e_deploy.py` proves the front door *says* the right
things — the bundled `/config.json`, the `/idp/*` route, a policy identical to the
unconfigured one. Only this proves somebody can actually complete a sign-in under that
policy, in the app's own JavaScript, against the provider the deployment runs itself.

What it drives is the claim, in the order a stranger meets it:

  - a stack brought up with `CARNET_IDP=bundled` and **nothing else configured** — no
    issuer, no client id, no second product;
  - `carnet --setup` running as a compose service, creating the tenant and registering
    the provider, with **no `docker compose exec` anywhere in this file**;
  - the app, opened cold, offering to create the first account with the administrator's
    address already filled in from `CARNET_BOOTSTRAP_ADMIN`;
  - that account signing in and arriving as an **administrator**, because the
    appointment happens at first sign-in against the same variable;
  - a second person being refused, because registration is closed — which on a bundled
    provider is the whole of the admission control;
  - a reload coming back signed in with nothing clicked, because the provider's cookie
    is first-party on this one origin;
  - and the browser reporting **no policy violations at all**, which is what says the
    one-origin design actually holds rather than merely looks right.

`e2e_browser_deploy.py` is the sibling and the opposite case: an external provider on
its own origin, which is where a `connect-src` mistake hides. That one needs an OIDC
stub, `host.docker.internal` and two ports, and skips loudly without them. This one
needs none of it — the provider is inside the stack — which is the same sentence this
step is about, stated as a test's own dependency list.

Its own compose project and ports, so it runs beside a real stack. Costs nothing: no
model key, no run, no outbound call.
"""

import pathlib
import secrets
import subprocess
import sys
import time

import httpx

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

REPO = pathlib.Path(__file__).resolve().parents[2]
COMPOSE_FILE = REPO / "deploy" / "compose.yaml"
SCRATCH = pathlib.Path(__file__).resolve().parent.parent / "var"

PROJECT = "carnet_e2e_bundled"
HTTP_PORT = 8798
HTTPS_PORT = 8799
FRONT = f"https://localhost:{HTTPS_PORT}"

ADMIN = "priya@example.test"
STRANGER = "sam@example.test"
PASSWORD = "a strong enough password"

ENV_FILE = SCRATCH / "e2e_browser_bundled.env"

# Installed before any of the document's own script runs, so a violation cannot happen
# before somebody is listening. The happy path asserts the answer is *nothing*: a
# bundled deployment serves the same policy as an unconfigured one, so any violation
# here means the one-origin design has stopped holding.
VIOLATION_COLLECTOR = """
window.__csp = [];
document.addEventListener('securitypolicyviolation', (e) => {
  window.__csp.push({directive: e.violatedDirective, blocked: e.blockedURI});
});
"""

CHECKS = []


def check(label, actual, expected=True):
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


def compose(*args, **kwargs):
    return subprocess.run(
        ["docker", "compose", "-p", PROJECT, "-f", str(COMPOSE_FILE),
         "--env-file", str(ENV_FILE), *args],
        **kwargs,
    )


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


def wait_for(url: str, client: httpx.Client, deadline_s: float = 180.0) -> bool:
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        try:
            if client.get(url).status_code < 500:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(1)
    return False


def write_env() -> None:
    """The `.env` a person would have after `deploy/setup.sh`, minus the questions.

    **Every CARNET_OIDC_* setting is absent, and that is the point of the file**: a
    bundled deployment declares one thing about identity and nothing else. The front
    door refuses this combination beside an issuer, so a stray one here would fail at
    start rather than quietly run two providers.
    """
    ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    ENV_FILE.write_text("".join(f"{k}={v}\n" for k, v in {
        "CARNET_DOMAIN": "localhost",
        "CARNET_TLS_MODE": "internal",
        "CARNET_SECRET_KEY": secrets.token_urlsafe(32),
        "CARNET_BOOTSTRAP_ADMIN": ADMIN,
        "CARNET_TENANT_NAME": "Sign-in Corp",
        "CARNET_IDP": "bundled",
        "CARNET_IDP_REGISTRATION": "closed",
        "COMPOSE_PROFILES": "bundled-db,bundled-idp",
        "CARNET_DB_PASSWORD": "carnet",
        "CARNET_HTTP_PORT": HTTP_PORT,
        "CARNET_HTTPS_PORT": HTTPS_PORT,
        "CARNET_PUBLIC_ORIGIN": f"{FRONT}/api",
    }.items()))


def new_page(browser):
    context = browser.new_context(ignore_https_errors=True)
    context.add_init_script(VIOLATION_COLLECTOR)
    return context, context.new_page()


def violations(page) -> list:
    return page.evaluate("window.__csp || []")


def the_first_account(page) -> None:
    """Cold app to signed-in administrator, with nothing typed that .env did not say.

    The register page's prefill is not a convenience here, it is the join: the address
    the bundled provider creates an account for has to be the one
    `CARNET_BOOTSTRAP_ADMIN` names, or the person lands on a working sign-in with no
    administrator and nothing saying why — the footgun `deploy/README.md` warned about
    in its own words and this step set out to end.
    """
    say("the first account: a stranger, a browser, and nothing else configured")
    page.goto(FRONT, wait_until="networkidle")
    check("the app offers to sign in rather than reporting a missing provider",
          page.locator("button.btn.primary").count() >= 1)

    page.click("button.btn.primary")
    page.wait_for_load_state("networkidle")
    check("...and lands on the provider this deployment runs itself",
          "/idp/" in page.url)

    page.click("text=Create one")
    page.wait_for_load_state("networkidle")
    check("the first-run page prefills the address .env named",
          page.locator("#email").input_value(), ADMIN)
    check("...and says it is the first account",
          page.locator("p.first").count(), 1)

    page.fill("#name", "Priya")
    page.fill("#password", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle")

    check("registering lands back in the app", FRONT in page.url and "/idp/" not in page.url)
    check("...signed in as that person",
          ADMIN in page.locator(".whoami").inner_text())
    # The appointment is the API's, at first sign-in, against the same variable —
    # so an administrative screen in the navigation is the evidence that the two
    # halves of `CARNET_BOOTSTRAP_ADMIN` met.
    nav = " ".join(page.locator("nav.sidebar-nav a").all_inner_texts()).lower()
    check("...and an administrator, appointed by the bootstrap variable",
          "admin" in nav or "people" in nav or "connectors" in nav)

    check("and the browser blocked nothing on the way",
          violations(page), [])


def the_closed_door(browser) -> None:
    """The second person is refused, and that refusal is the admission control.

    On a bundled provider the tenant's `allowed_domains` is `"*"` — legal for this one
    issuer because the provider *is* the account authority — so the domain gate decides
    nothing and `CARNET_IDP_REGISTRATION` decides everything. A deployment reachable
    from the internet with this open is a stranger creating an account.
    """
    say("the closed door: the whole admission control, on one setting")
    context, page = new_page(browser)
    try:
        page.goto(f"{FRONT}/idp/register", wait_until="networkidle")
        body = page.locator("body").inner_text().lower()
        check("the register page is closed once somebody holds the first account",
              "closed" in body or "not open" in body)
        check("...and there is no form to type into",
              page.locator("#password").count(), 0)

        # Through the POST as well, because a page that merely hides the form is a
        # decoration: `accounts.create_account` settles it inside the INSERT.
        posted = page.request.post(
            f"{FRONT}/idp/register",
            form={"email": STRANGER, "password": PASSWORD, "name": "Sam"},
            ignore_https_errors=True,
        )
        check("...and posting the form directly is refused too", posted.status, 403)
    finally:
        context.close()


def the_silent_return(page) -> None:
    """Reload, and come back signed in without touching anything.

    **The same context as `the_first_account`, on purpose.** A fresh one would have no
    cookie and would prove only that a stranger is asked to sign in. What is under test
    is the return: the provider's session cookie is first-party on this one origin,
    so the app's hidden `prompt=none` frame can complete — and that frame's last hop is
    `/login/callback` rendered inside this app, which is why the policy says
    `frame-ancestors 'self'` rather than `'none'` (a browser convicted that choice once
    already, in plan 031).

    Asserted through the UI rather than through `/api/me`, and the distinction is the
    product's: the API takes a **bearer token** the app holds in memory, not a cookie.
    A request made by the browser's own client would carry the cookie, no bearer, and a
    401 — which would say nothing about whether the person is signed in. The name in
    the corner is what says it.
    """
    say("the silent return: a reload, and nobody is asked to sign in again")
    page.goto(FRONT, wait_until="networkidle")
    # The renewal is a hidden frame and a token exchange, so it can land after the
    # network goes quiet. Waiting for the name is waiting for the thing itself.
    page.wait_for_selector(".whoami", timeout=20000)

    check("still signed in, with nothing clicked",
          ADMIN in page.locator(".whoami").inner_text())
    check("...so no sign-in button is offered",
          page.locator("button.btn.primary").count(), 0)
    check("and still no policy violations", violations(page), [])


def main() -> int:
    reason = preflight()
    if reason:
        print(f"SKIPPED: {reason}. This tier is the only judge a CSP has; the wiring "
              "tier still ran in e2e_deploy.py.")
        return 0

    from playwright.sync_api import sync_playwright

    write_env()
    try:
        say("up: one declaration about identity, and nothing else")
        # Plain `up -d`, not `--wait`: compose treats the one-shot `setup` service
        # exiting as a failure and returns 1 for a stack that is perfectly fine (see
        # compose.yaml). Readiness is the health poll below, which is what actually
        # answers the question.
        built = compose("up", "-d", "--build", capture_output=True, text=True)
        if not check("the stack comes up", built.returncode, 0):
            print((built.stdout + built.stderr)[-2000:])
            return report()

        with httpx.Client(verify=False, timeout=15) as client:
            answered = wait_for(f"{FRONT}/api/health", client)
        if not check("the front door answers", answered, True):
            logs = compose("logs", "--tail", "30", "front",
                           capture_output=True, text=True)
            print(f"  front logs: {(logs.stdout + logs.stderr)[-1500:] or '(none)'}")
            return report()

        say("the install finished itself: no `docker compose exec` in this file")
        logs = compose("logs", "setup", capture_output=True, text=True).stdout
        check("the setup service created the tenant", "created" in logs)
        check("...and registered the provider", "registered" in logs)
        check("...and said the deployment is ready", "Ready. Open" in logs)

        with httpx.Client(verify=False, timeout=15) as client:
            config = client.get(f"{FRONT}/config.json")
            check("the app is pointed at the bundled provider, origin-relative",
                  config.status_code == 200 and config.json().get("issuer"), "/idp")
            policy = client.get(f"{FRONT}/").headers.get("content-security-policy", "")
            # The one-origin design in one assertion: no provider-dependent source at
            # all, which is what lets the shipped policy cover the token exchange.
            check("...under a policy that names no other origin",
                  "connect-src 'self';" in policy and "https://" not in policy)

        say("the browser: the only judge a CSP has")
        with sync_playwright() as p:
            browser = p.chromium.launch()
            # One context for the two scenes that are one person's session, and a
            # fresh one inside `the_closed_door` for the stranger who is refused.
            context, page = new_page(browser)
            try:
                for scene, subject in (
                    (the_first_account, page),
                    (the_closed_door, browser),
                    (the_silent_return, page),
                ):
                    try:
                        scene(subject)
                    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
                        check(f"the scene {scene.__name__} ran to the end",
                              f"{type(exc).__name__}: {exc}", "no exception")
            finally:
                context.close()
                browser.close()
    finally:
        say("down (volumes too)")
        compose("down", "-v", "--remove-orphans", "-t", "5",
                capture_output=True, text=True)
        ENV_FILE.unlink(missing_ok=True)
    return report()


if __name__ == "__main__":
    sys.exit(main())
