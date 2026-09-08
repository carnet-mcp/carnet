"""The deployment artifact, driven end to end. Step 030, and its testing pass.

**Not a test, and here for what the suite structurally cannot do.** The suite proves
the application; nothing in it can prove the *artifact* — that `deploy/compose.yaml`
builds, comes up in order (migrate before serve), terminates TLS, refuses an oversized
unauthenticated body at the proxy rather than in the app, rewrites `/api/*`, serves
the bundle with the SPA fallback, and does all of it against a database whose serving
role is **not a superuser** — the BYOC shape, which is where 029's testing pass found
every one of its defects hiding.

Eight scenes — six landing on decisions in `docs/plans/030-deployment-artifacts.md`,
and two (`the_sign_in_wiring`, `the_provider_declaration`) on
`docs/plans/031-deployed-sign-in.md`:

  - `the_first_five_minutes`  the README's day-one commands, run verbatim, plus the
                              two refusals decision 10 promises. This is the scene
                              that found the chicken-and-egg: compose interpolates
                              the whole file for *every* subcommand, so while the
                              secret key is unset even `compose build` refuses — and
                              the remedy for that refusal is a compose command.
  - `the_running_stack`       TLS, the rewrite, the fallback, the per-path body
                              limits, the non-superuser owner, the door-only shape
                              (no worker service, no run routes) — and the
                              CLI-in-a-container path the
                              README tells a platform team to use on day one.
  - `the_sign_in_wiring`      plan 031, tier 1: `/config.json` is real JSON naming
                              the declared issuer (never the SPA fallback — the
                              200-with-HTML that masked a deployment nobody could
                              sign into), the served CSP's connect-src carries the
                              issuer's *origin*, and the mutations: unconfigured is
                              a real 404, half-configured refuses with a sentence.
  - `the_provider_declaration`
                              the front door's entrypoint across its whole input
                              space, driven directly with `docker run` rather than a
                              stack per case: every issuer shape a real provider
                              uses, the second origin Google needs, and the eight
                              ways to declare one wrong that must be refusals rather
                              than a malformed policy.
  - `the_knobs`               every setting the application reads is reachable from
                              `.env` — `environment:` is a closed list, and what it
                              omits is not defaulted but unreachable.
  - `the_second_coming`       stop and start again: state survives, `--migrate`
                              finds nothing to do, what comes back is the door's
                              services and nothing more — and readiness (not
                              liveness) notices a stopped database (step 056).
  - `the_owner_check_can_go_red`
                              the non-superuser owner check, mutated both ways —
                              a green check that cannot go red is not evidence.
                              (The proxy body-limit mutation retired here with
                              042's door-only default; its docstring says why.)
  - `the_managed_database`    decision 9, and the actual BYOC target: profile off,
                              an external Postgres this stack does not own, reached
                              by hostname over a network it did not create — and,
                              because that cluster already hosts a deployment, the
                              second-deployment refusal and the remedy that clears it.

    cd backend && .venv/bin/python scripts/e2e_deploy.py

Needs Docker and the compose plugin. `the_managed_database` additionally needs a
Postgres *outside* the stack: `CARNET_E2E_PG` for the DSN and
`CARNET_E2E_PG_CONTAINER` (default `carnet-pg`) for the container to
attach. Every scene skips loudly rather than silently when its world is absent —
always with the word `SKIPPED:`, which the CI job greps for and fails on, because
there a silent skip is a green build that tested nothing. In CI since step 054
(the `deploy` job), after plan 049 found the register row's trigger had fired: the
drift this script would have caught in a pull request reached an audit instead.
Costs nothing and calls no model: nothing in the stack is asked to run an agent.
"""

import json
import os
import pathlib
import re
import secrets
import subprocess
import sys
import time
from urllib.parse import urlsplit, urlunsplit

import httpx

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

REPO = pathlib.Path(__file__).resolve().parents[2]
DEPLOY = REPO / "deploy"
COMPOSE_FILE = DEPLOY / "compose.yaml"
SCRATCH = pathlib.Path(__file__).resolve().parent.parent / "var"

PROJECT = "carnet_e2e_deploy"
MANAGED_PROJECT = "carnet_e2e_managed"

# Uncommon ports, so the e2e can run beside a real `--local` or another stack. The
# redirect check below tolerates the port being absent from Location: Caddy redirects
# to the site address, which is portless, and that is correct for the real 80/443.
HTTP_PORT = 8790
HTTPS_PORT = 8791
FRONT = f"https://localhost:{HTTPS_PORT}"
MANAGED_HTTPS_PORT = 8793

# The declared browser identity provider (plan 031). Nothing serves this issuer —
# tier 1 is about the *wiring*, not the provider: /config.json and the CSP must both
# name it, from one declaration. The issuer deliberately carries a path so the
# origin-derivation is actually exercised. e2e_browser_deploy.py is where a live
# (non-Okta) provider answers.
IDP_ISSUER = "https://idp.example.com/oauth2/default"
IDP_ORIGIN = "https://idp.example.com"
IDP_CLIENT = "e2e-spa-client"

CHECKS = []


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok, actual, expected))
    mark = "ok  " if ok else "FAIL"
    print(f"  {mark} {label}: {actual!r}" + ("" if ok else f"  (expected {expected!r})"))
    return ok


def say(what):
    print(f"\n=== {what}", flush=True)


def report() -> int:
    """The verdict over **every** check, however many scenes ran.

    `e2e_rls.py`'s lesson, inherited rather than re-learned: a summary printed inside
    one scene is a later scene whose failures cannot fail the script.
    """
    say("summary")
    failed = [label for label, ok, *_ in CHECKS if not ok]
    print(f"  {len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    for label in failed:
        print(f"  FAILED: {label}")
    return 1 if failed else 0


def compose(*args, project=PROJECT, env_file=None, **kwargs):
    env_file = env_file or ENV_FILE
    return subprocess.run(
        ["docker", "compose", "-p", project, "-f", str(COMPOSE_FILE),
         "--env-file", str(env_file), *args],
        **kwargs,
    )


def preflight() -> str | None:
    """The reason to skip, or None to proceed."""
    for probe, missing in (
        (["docker", "info"], "Docker is not available"),
        (["docker", "compose", "version"], "the docker compose plugin is not installed"),
    ):
        try:
            done = subprocess.run(probe, capture_output=True, timeout=30)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return missing
        if done.returncode != 0:
            return missing
    return None


ENV_FILE = None  # the default stack's env; set in main() so teardown can find it


def write_env(path: pathlib.Path, **overrides) -> pathlib.Path:
    """A throwaway .env, the way a platform team would write a real one.

    The secret key comes from the same generator `--generate-key` uses, because the
    e2e should hand the stack exactly what the README tells a person to hand it. The
    database password is hex on purpose: it is interpolated into a DSN, so a value
    carrying `@`, `/`, `#` or `$` would break the URL rather than the deployment —
    a trap `.env.example` now names.
    """
    from carnet.core import crypto

    values = {
        "CARNET_DOMAIN": "localhost",
        "CARNET_SECRET_KEY": crypto.generate_key(),
        "COMPOSE_PROFILES": "bundled-db",
        "CARNET_DB_PASSWORD": secrets.token_hex(16),
        "CARNET_HTTP_PORT": str(HTTP_PORT),
        "CARNET_HTTPS_PORT": str(HTTPS_PORT),
        # The browser's identity provider, declared the way a platform team would.
        # A path-bearing issuer on purpose: the entrypoint must derive the CSP
        # *origin* from it, and an issuer that IS its origin would let a derivation
        # bug pass unnoticed.
        "CARNET_OIDC_ISSUER": IDP_ISSUER,
        "CARNET_OIDC_CLIENT_ID": IDP_CLIENT,
    }
    values.update({k: v for k, v in overrides.items() if v is not None})
    for absent in [k for k, v in overrides.items() if v is None]:
        values.pop(absent, None)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{k}={v}\n" for k, v in values.items()))
    return path


def variant_env(path: pathlib.Path, **overrides) -> pathlib.Path:
    """A copy of the running stack's `.env` with a value or two changed.

    Not `write_env`, and the difference cost a run: `write_env` mints a fresh key and
    a fresh database password every time, so using it to change one setting on a
    *live* stack hands the API a password the database has never heard of. Anything
    that reconfigures a running service has to start from what that service is
    already using.
    """
    values = dict(
        line.split("=", 1) for line in ENV_FILE.read_text().splitlines() if "=" in line
    )
    values.update(overrides)
    path.write_text("".join(f"{k}={v}\n" for k, v in values.items()))
    return path


def drop_database(admin_dsn: str, database: str) -> bool:
    """Evict whatever still holds a database, then drop it. Retries.

    A plain `DROP DATABASE` after `docker compose down` is not enough, twice over.
    `down` returns when the containers are *gone*, which is not the instant their
    backends are; and a connection whose container was cut off the network rather
    than stopped leaves the server with no FIN to notice, so it holds the database
    **idle for as long as TCP keepalive takes** — hours. Terminating first fixes the
    second, retrying fixes the first.
    """
    import psycopg

    for _attempt in range(15):
        try:
            with psycopg.connect(admin_dsn, autocommit=True) as conn:
                conn.execute(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = %s AND pid <> pg_backend_pid()", (database,)
                )
                conn.execute(f"DROP DATABASE IF EXISTS {database}")
            return True
        except psycopg.errors.ObjectInUse:
            time.sleep(1)
    return False


def wait_for(url: str, client: httpx.Client, deadline_s: float = 150.0) -> bool:
    stop = time.monotonic() + deadline_s
    while time.monotonic() < stop:
        try:
            if client.get(url).status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(2)
    return False


def container_state(service, project=PROJECT, env_file=None):
    """(State, RestartCount) for one service's first container, or (None, None)."""
    listed = compose("ps", "--format", "json", service, project=project,
                     env_file=env_file, capture_output=True, text=True)
    rows = [json.loads(line) for line in listed.stdout.splitlines() if line.strip()]
    if not rows:
        return None, None
    ids = compose("ps", "-q", service, project=project, env_file=env_file,
                  capture_output=True, text=True).stdout.split()
    restarts = subprocess.run(
        ["docker", "inspect", "-f", "{{.RestartCount}}", ids[0]],
        capture_output=True, text=True,
    ).stdout.strip() if ids else None
    return rows[0].get("State"), restarts


# --- the scenes ----------------------------------------------------------------------


def the_first_five_minutes() -> None:
    """`deploy/README.md`'s day-one commands, run verbatim, and decision 10's refusals.

    **The scene that found the artifact's own dead end.** The README used to say to
    generate the key with `docker compose run --rm --no-deps migrate carnet
    --generate-key`. Compose interpolates the *entire* file for every subcommand, so
    with `CARNET_SECRET_KEY` empty — which is how `.env.example` ships, and
    must ship, because a working default key would be a known key on every
    deployment — that command refuses, and so does `compose build`. The remedy for
    the refusal was a command the refusal forbade.

    This is migration 037's defect wearing different clothes: *a refusal whose remedy
    does not remedy*. The fix is the same shape too — keep the refusal, make the
    remedy reachable — by having the one command that must run before the key exists
    reach around compose to plain `docker`.
    """
    say("day one: the refusals, and the remedy that has to survive them")

    example = write_env(SCRATCH / "e2e_deploy_example.env",
                        CARNET_SECRET_KEY="")
    refused = compose("build", env_file=example, capture_output=True, text=True)
    check("with no key, compose refuses every subcommand — build included",
          refused.returncode != 0, True)
    check("...and the refusal names --generate-key",
          "--generate-key" in refused.stderr, True)

    # The remedy, exactly as `deploy/README.md` now prints it: plain docker, no
    # compose, no interpolation — so it works in the state that needs it.
    built = subprocess.run(
        ["docker", "build", "-q", "-t", "carnet-api", "--target", "api",
         "-f", str(DEPLOY / "Dockerfile"), str(REPO)],
        capture_output=True, text=True,
    )
    check("the README's remedy builds the image without compose", built.returncode, 0)
    keyed = subprocess.run(
        ["docker", "run", "--rm", "carnet-api", "carnet", "--generate-key"],
        capture_output=True, text=True,
    )
    key = keyed.stdout.strip()
    check("...and prints a usable key in the very state that refuses compose",
          keyed.returncode == 0 and len(key) == 44 and key.endswith("="), True)

    nodomain = write_env(SCRATCH / "e2e_deploy_nodomain.env", CARNET_DOMAIN="")
    refused = compose("config", env_file=nodomain, capture_output=True, text=True)
    check("an unset CARNET_DOMAIN refuses too (no deployment may ship the default)",
          refused.returncode != 0 and "CARNET_DOMAIN" in refused.stderr, True)

    # The one variable that is genuinely optional, asserted so a later `:?` typo on it
    # cannot pass unnoticed: a deployment may appoint its first admin from the CLI.
    noadmin = write_env(SCRATCH / "e2e_deploy_noadmin.env",
                        CARNET_BOOTSTRAP_ADMIN=None)
    fine = compose("config", env_file=noadmin, capture_output=True, text=True)
    check("but the bootstrap admin stays optional", fine.returncode, 0)

    for leftover in (example, nodomain, noadmin):
        leftover.unlink(missing_ok=True)


def the_running_stack() -> None:
    """Up, and every claim the front door makes, probed from outside."""
    from carnet import __version__

    say("build the images (first run compiles the bundle; later runs are cache)")
    built = compose("build", capture_output=True, text=True)
    check("docker compose build succeeds", built.returncode, 0)
    if built.returncode != 0:
        print(built.stderr[-2000:])
        return

    say("up, and wait for the front door")
    up = compose("up", "-d", capture_output=True, text=True)
    check("docker compose up succeeds", up.returncode, 0)
    if up.returncode != 0:
        print(up.stderr[-2000:])
        return

    # verify=False: localhost is signed by Caddy's internal CA, and the check here is
    # that TLS is *on* — a public CA cannot sign localhost and the e2e should not
    # mutate the machine's trust store to pretend otherwise.
    with httpx.Client(verify=False, timeout=15) as client:
        if not check("the API answers through TLS at the front door",
                     wait_for(f"{FRONT}/api/health", client), True):
            logs = compose("logs", "--tail", "40", "api", capture_output=True, text=True)
            print(logs.stdout[-3000:])
            return

        say("the front door's contract, decision by decision")
        health = client.get(f"{FRONT}/api/health")
        check("/api/health reaches uvicorn (prefix rewrite)", health.status_code, 200)
        check("and the deployment is this checkout's version",
              health.json().get("version") if health.status_code == 200 else None,
              __version__)
        ready = client.get(f"{FRONT}/api/health/ready")
        # Step 056: the readiness sibling, which unlike /health makes a real round
        # trip. `storage` naming postgres is part of the check — "ready, against
        # memory" in this stack would mean the DSN never reached the process.
        check("/api/health/ready answers 200, and the ground it touched is postgres",
              ready.status_code == 200 and ready.json().get("storage") == "postgres",
              True)

        spec = client.get(f"{FRONT}/api/openapi.json")
        check("/api/openapi.json answers (the rewrite is a prefix, not one route)",
              spec.status_code == 200 and "paths" in spec.json(), True)
        # --root-path, decision 11: the document has to describe the only address a
        # person can actually reach it at, or /api/docs loads and then fetches into
        # the SPA. `servers` is what carries that, and it is generated, not written.
        check("...and openapi.json's server prefix is the published one, not '/'",
              [s.get("url") for s in spec.json().get("servers", [])], ["/api"])
        docs = client.get(f"{FRONT}/api/docs")
        check("/api/docs is reachable through the front door", docs.status_code, 200)

        index = client.get(f"{FRONT}/")
        check("/ serves the bundle", index.status_code == 200
              and "text/html" in index.headers.get("content-type", ""), True)
        deep = client.get(f"{FRONT}/agents/abc123")
        check("a deep link reloads into the app (SPA fallback)",
              deep.status_code == 200 and deep.text == index.text, True)
        missing_asset = client.get(f"{FRONT}/assets/nope-does-not-exist.js")
        # The fallback must not swallow a missing *asset* into index.html: that turns
        # a bad build into a page that loads and then fails on a MIME type, which is
        # the least diagnosable failure a bundle has.
        check("but a missing asset is not swallowed into index.html",
              missing_asset.text != index.text, True)

        # Step 083. The door's OAuth discovery documents live at the origin root and
        # are the API's; before the Caddyfile forwarded them, the SPA fallback answered
        # them with index.html and a 200 — the /config.json defect at a new address.
        discovery = client.get(f"{FRONT}/.well-known/oauth-protected-resource/api/mcp")
        check("/.well-known/oauth-protected-resource/api/mcp is the API's document, "
              "not the SPA fallback",
              discovery.status_code == 200
              and "application/json" in discovery.headers.get("content-type", "")
              and discovery.json().get("resource", "").endswith("/api/mcp"), True)
        server_doc = client.get(f"{FRONT}/.well-known/oauth-authorization-server")
        check("...and the authorization-server document names the front door's endpoints",
              server_doc.status_code == 200
              and server_doc.json().get("token_endpoint", "").endswith("/api/oauth/token")
              and server_doc.json().get("authorization_endpoint", "").endswith("/oauth/authorize"),
              True)
        challenged = client.post(f"{FRONT}/api/mcp",
                                 json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        check("and an unauthenticated door answers 401 naming the metadata",
              challenged.status_code == 401
              and "resource_metadata=" in challenged.headers.get("www-authenticate", ""),
              True)

        redirect = client.get(f"http://localhost:{HTTP_PORT}/",
                              follow_redirects=False)
        check("plain HTTP is a redirect to HTTPS",
              300 <= redirect.status_code < 400
              and redirect.headers.get("location", "").startswith("https://"), True)

        say("the response headers the bundle cannot set for itself")
        # `frame-ancestors` is ignored by the spec when it arrives in a <meta> tag, so
        # before the front door set it the deployed app had no clickjacking defence at
        # all — on a page that holds the access token in memory. 'self', not 'none':
        # the silent-renewal iframe renders this app's own /login/callback, and 'none'
        # blocks it — every silent re-entry fails (found by a real browser in
        # e2e_browser_local.py).
        check("the front door supplies frame-ancestors, which a meta CSP cannot",
              "frame-ancestors 'self'"
              in index.headers.get("content-security-policy", ""), True)
        check("...and the bundle's own meta policy still pins script-src",
              "script-src 'self'" in index.text, True)
        check("...while naming no provider — that half moved to the front door",
              "okta.com" in index.text, False)
        check("nosniff is set", index.headers.get("x-content-type-options"), "nosniff")
        check("and the referrer is never sent — an OAuth code must not ride in one",
              index.headers.get("referrer-policy"), "no-referrer")
        # Deliberately absent on a localhost trial: HSTS ignores the port, so pinning
        # `localhost` would force HTTPS on every other local dev server on the machine.
        check("HSTS is withheld on a localhost trial, on purpose",
              "strict-transport-security" in
              {k.lower() for k in index.headers}, False)

        say("the body limits: per path, and enforced in front of the app")
        # WHO refuses an oversized body is deliberately not asserted, because it is
        # genuinely a race. The proxy's `max_size` trips only as the body is read, and
        # an unregistered route answers 404 without consuming a byte — so whether the
        # client sees the proxy's 413 or the absent route's 404 depends on which
        # response wins (both were observed across runs of this script, same image,
        # same Caddy). What must never happen is a 2xx, or anything buffering the
        # flood: both are refusals in front of any buffering.
        big = b"x" * (128 * 1024)
        hooks = client.post(f"{FRONT}/api/hooks/e2e", content=big)
        check(f"a 128 KiB delivery is refused (HTTP {hooks.status_code})",
              hooks.status_code in (404, 413), True)

        def chunks():
            for _ in range(128):
                yield b"x" * 1024

        chunked = client.post(f"{FRONT}/api/hooks/e2e", content=chunks())
        # The same race as above, minus even the possibility of an up-front check:
        # a chunked request has no Content-Length at all.
        check("chunked — no Content-Length to check — is refused before buffering "
              f"(HTTP {chunked.status_code})",
              chunked.status_code in (404, 413), True)

        # The near side of the limit, so the check above is a *limit* and not a door
        # that refuses everything: 32 KiB is under 64 KiB and passes the proxy. The
        # app's answer is the deliberate 404 — 023's no-oracle rule for an unknown
        # trigger, and since 042 the same 404 by absence, because a door-only
        # deployment registers no hooks router at all.
        ok_delivery = client.post(f"{FRONT}/api/hooks/e2e", content=b"x" * 32768)
        check(f"a 32 KiB delivery passes the proxy and reaches the app "
              f"(HTTP {ok_delivery.status_code})",
              ok_delivery.status_code != 413, True)

        upload = client.post(f"{FRONT}/api/files", content=b"x" * (5 * 1024 * 1024))
        # The property is that the *proxy* passed it — the limit is per-path — and the
        # refusal is the app's own (4xx: unauthenticated, or not multipart). The label
        # carries the status so a failure names what actually answered.
        check(f"a 5 MiB body elsewhere reaches the app (HTTP {upload.status_code}, "
              "not the proxy's 413)",
              upload.status_code != 413 and 400 <= upload.status_code < 500, True)

        say("the database underneath is the BYOC shape")
        check("the tables are owned by the app role, and it is not a superuser",
              table_owner(), "carnet_app|false")

        say("the artifact is the door, and states so two ways")
        # Step 078: there is no worker service and no run-submission surface. The
        # first statement is that no such container exists. The second is that the
        # route is not registered at all — a 404, the truth, rather than a 403
        # guarding something that does not exist. Unauthenticated on purpose: an
        # absent route answers 404 before anything asks who is calling, so a 401
        # here would mean the surface exists after all.
        state, _ = container_state("worker")
        check("no worker container exists in the stack", state, None)
        runs = client.post(f"{FRONT}/api/runs", json={"agent": "e2e", "task": "x"})
        check("run submission is unregistered, not forbidden (404)",
              runs.status_code, 404)

        say("the containers stayed up — running, never restarted, well after boot")
        # 029's boot refusal makes a mis-wired serving role a crash loop, so zero
        # restarts well after migrate finished is the check that the isolation boot
        # check passed in the process that serves.
        time.sleep(10)
        state, restarts = container_state("api")
        check("the api container is running", state, "running")
        check("and has never crash-looped", restarts, "0")

        # **The same question asked of the front door, and it is not redundant.**
        # `docker compose up` exits 0 for a stack whose front container is in a
        # restart loop, and a container that exits *successfully* logs nothing to
        # explain itself — which is exactly what an ENTRYPOINT with no CMD did to
        # this image (`exec "$@"` with nothing to exec: exit 0, no output, forever).
        # Every other check here reaches the app *through* the front door, so they
        # all fail together and none of them says which thing is broken. This one
        # names it.
        state, restarts = container_state("front")
        check("the front container is running", state, "running")
        check("and it has never crash-looped either", restarts, "0")

        say("what the containers are, underneath")
        # An image that serves as root is a finding in any enterprise review, and it
        # is one `USER` line away from being one here.
        whoami = compose("exec", "-T", "api", "id", "-u",
                         capture_output=True, text=True)
        check("the API does not run as root", whoami.stdout.strip() != "0", True)
        # The outbox is the last thing in var/ that is still a file, and a named
        # volume mounted over a directory the image created can arrive root-owned —
        # which would fail on the first agent run that posts a message with no
        # webhook configured, long after anybody is watching the deploy.
        writable = compose(
            "exec", "-T", "api", "python", "-c",
            "import os,pathlib;"
            "p=pathlib.Path(os.environ['CARNET_VAR_DIR'])/'e2e-probe';"
            "p.write_text('ok');print(p.read_text());p.unlink()",
            capture_output=True, text=True,
        )
        check("...and can write its var directory (the outbox lives there)",
              writable.stdout.strip(), "ok")

        say("the CLI inside the container — the README's own day-one commands")
        # Every onboarding instruction in `deploy/README.md` is one of these. A
        # command a platform team is told to run, that nothing runs, is the defect
        # class this project has already paid for once (the WORKERS=0 handoff bug).
        added = compose("exec", "-T", "api", "carnet",
                        "--add-tenant", "e2e", "E2E Corp",
                        capture_output=True, text=True)
        check("`--add-tenant` works in the api container", added.returncode, 0)
        seeded = compose("exec", "-T", "api", "carnet", "--seed",
                         capture_output=True, text=True)
        check("`--seed` works in the api container", seeded.returncode, 0)
        # And the CLI reached the *same* database the API serves from — one DSN,
        # decision 7. Asked of the database rather than of the CLI's own exit code.
        check("...and the row landed in the database the stack serves",
              psql("SELECT id FROM tenants WHERE id = 'e2e'"), "e2e")


def the_sign_in_wiring() -> None:
    """Plan 031, tier 1: the two halves of browser sign-in, from one declaration.

    This scene is the one that would have caught both shipped defects without a
    browser. The old e2e asserted the bundle was *served* and went 64/64 while nobody
    could sign in — because `GET /config.json` answered 200 with `index.html` through
    the SPA fallback, so "200" and "not 404" prove nothing here. Every check below is
    therefore about content type, parse, and *values*: the served config names the
    declared issuer, the served CSP names the issuer's ORIGIN, and the two can never
    disagree because the entrypoint derives both from CARNET_OIDC_*.

    And the mutations, because the SPA fallback is exactly what masked this: an
    unconfigured deployment must answer a real 404, and a half-configured one must
    refuse to serve at all, with a sentence naming the missing variable.
    """
    say("the sign-in wiring: /config.json and the CSP, fed from one declaration")

    with httpx.Client(verify=False, timeout=15) as client:
        found = client.get(f"{FRONT}/config.json")
        index = client.get(f"{FRONT}/")
        check("/config.json answers 200", found.status_code, 200)
        check("...as application/json, NOT the SPA fallback's text/html",
              found.headers.get("content-type", "").split(";")[0],
              "application/json")
        check("...and it is not index.html wearing a different name",
              found.text != index.text, True)
        try:
            config = found.json()
        except ValueError:
            config = {}
        check("...it parses, and names the declared issuer",
              config.get("issuer"), IDP_ISSUER)
        check("...and the declared client id", config.get("client_id"), IDP_CLIENT)
        check("...and usable scopes", config.get("scopes"), "openid profile email")

        policy = index.headers.get("content-security-policy", "")
        connect = next((d for d in policy.split(";") if "connect-src" in d), "")
        frame = next((d for d in policy.split(";")
                      if "frame-src" in d and "ancestors" not in d), "")
        # The invariant that keeps the two halves from disagreeing, checkable
        # without a browser: whatever /config.json names, the CSP must allow. The
        # ORIGIN, not the issuer — the issuer carries a path and a CSP source is
        # scheme://host[:port], which is the derivation the entrypoint exists for.
        check("the served CSP's connect-src contains the issuer's origin",
              IDP_ORIGIN in connect, True)
        check("...and frame-src does too (the silent-renewal iframe)",
              IDP_ORIGIN in frame, True)
        check("...with no wildcard source in either",
              "*" in connect + frame, False)
        check("...and script-src still 'self', without 'unsafe-inline'",
              "script-src 'self'" in policy
              and "unsafe-inline" not in policy.split("style-src")[0], True)

    say("mutation: remove the declaration, and absence must be a real 404")
    unconfigured = variant_env(SCRATCH / "e2e_deploy_no_idp.env",
                               CARNET_OIDC_ISSUER="", CARNET_OIDC_CLIENT_ID="")
    try:
        compose("up", "-d", "front", env_file=unconfigured,
                capture_output=True, text=True)
        with httpx.Client(verify=False, timeout=15) as client:
            wait_for(f"{FRONT}/api/health", client, deadline_s=90)
            gone = client.get(f"{FRONT}/config.json")
            index = client.get(f"{FRONT}/")
        # THE check. The defect shipped because this was a 200 with HTML; the SPA
        # fallback must never catch this path again.
        check("an unconfigured /config.json is a 404, not index.html with a 200",
              gone.status_code, 404)
        check("...and the CSP tightens to 'self' alone",
              "connect-src 'self';" in index.headers.get(
                  "content-security-policy", ""), True)

        say("mutation: half a configuration must refuse loudly, not serve quietly")
        half = variant_env(SCRATCH / "e2e_deploy_half_idp.env",
                           CARNET_OIDC_CLIENT_ID="")
        compose("up", "-d", "front", env_file=half, capture_output=True, text=True)
        time.sleep(3)
        logs = compose("logs", "--tail", "10", "front", env_file=half,
                       capture_output=True, text=True)
        check("the front door refuses, naming the missing variable",
              "CARNET_OIDC_CLIENT_ID" in logs.stdout + logs.stderr, True)
        half.unlink(missing_ok=True)
    finally:
        unconfigured.unlink(missing_ok=True)
        compose("up", "-d", "front", capture_output=True, text=True)

    with httpx.Client(verify=False, timeout=15) as client:
        wait_for(f"{FRONT}/api/health", client, deadline_s=90)
        restored = client.get(f"{FRONT}/config.json")
    check("and the restored front door serves the declaration again",
          restored.status_code == 200
          and restored.json().get("issuer") == IDP_ISSUER, True)


def the_provider_declaration() -> None:
    """The front door's entrypoint, driven across its input space directly.

    `deploy/frontdoor-entrypoint.sh` is the branchiest file in `deploy/` and the one
    place a mistyped `.env` becomes either a malformed security policy or a silently
    ignored setting. Driving it through a whole `compose up` per case would cost
    minutes; `docker run` against the same image costs a second, because the
    entrypoint ends in `exec "$@"` and will therefore run whatever it is handed.

    That last property is itself under test here. It was added to fix an image that
    ignored its own command — and it immediately caused a worse defect, because
    **setting ENTRYPOINT resets the base image's CMD to null**: `"$@"` was empty,
    `exec` ran nothing, and the container exited **0** with no log line at all, over
    and over, while `docker compose up` reported success. The Dockerfile restates CMD
    now; `the_running_stack` asserts the container is running and has never restarted,
    and this scene asserts the command still flows through.
    """
    say("the provider declaration: every way to get CARNET_OIDC_* wrong")

    def run(**env):
        args = []
        for key, value in env.items():
            args += ["-e", f"{key}={value}"]
        return subprocess.run(
            ["docker", "run", "--rm", *args, "carnet-front", "sh", "-c",
             'echo "CSP=$CARNET_CSP"; cat /srv/config.json 2>/dev/null'],
            capture_output=True, text=True,
        )

    def csp_of(**env) -> str:
        done = run(**env)
        for line in done.stdout.splitlines():
            if line.startswith("CSP="):
                return line[4:]
        return ""

    ok = "carnet-e2e"
    # The origin is *derived* from the issuer, because asking a deployer for both is
    # two places to disagree — so every issuer shape a real provider uses has to
    # survive it. Okta puts the authorization server in a path, Entra puts the tenant
    # there, Keycloak the realm, Google nothing at all.
    for label, issuer, origin in (
        ("no path at all (Google)", "https://accounts.google.com",
         "https://accounts.google.com"),
        ("a path (Okta, Entra, Keycloak)", "https://acme.okta.com/oauth2/default",
         "https://acme.okta.com"),
        ("a port", "https://kc.example.com:8443/realms/acme",
         "https://kc.example.com:8443"),
        ("a trailing slash", "https://idp.example.com/", "https://idp.example.com"),
    ):
        check(f"the CSP origin is derived from an issuer with {label}",
              f"connect-src 'self' {origin};" in
              csp_of(CARNET_OIDC_ISSUER=issuer, CARNET_OIDC_CLIENT_ID=ok), True)

    # Google is the reason this variable exists: it issues at accounts.google.com and
    # exchanges at oauth2.googleapis.com, so a policy naming only the issuer blocks
    # the token exchange. The first version of this validation refused *every* valid
    # origin (its glob counted the two slashes in `https://`), so the documented answer
    # for Google could never have worked. e2e_browser_deploy.py drives it in a browser.
    check("a second origin can be declared beside the issuer",
          "connect-src 'self' https://accounts.google.com https://oauth2.googleapis.com;"
          in csp_of(CARNET_OIDC_ISSUER="https://accounts.google.com",
                    CARNET_OIDC_CLIENT_ID=ok,
                    CARNET_OIDC_EXTRA_ORIGINS="https://oauth2.googleapis.com"), True)

    check("with no provider declared, the policy is 'self' alone",
          "connect-src 'self'; frame-src 'self';" in csp_of(), True)

    # Each of these produces either a malformed CSP, a malformed JSON document, or a
    # setting that does nothing — all three of which fail later, quieter, and in a
    # browser. 030's testing pass found the "does nothing" shape in `environment:`;
    # this is the same lesson applied to the file written one step after it.
    for label, env in (
        ("an issuer with no client id", {"CARNET_OIDC_ISSUER": "https://i.test"}),
        ("a client id with no issuer", {"CARNET_OIDC_CLIENT_ID": ok}),
        ("extra origins with no issuer",
         {"CARNET_OIDC_EXTRA_ORIGINS": "https://x.test"}),
        ("scopes with no issuer", {"CARNET_OIDC_SCOPES": "openid"}),
        ("an issuer with no scheme",
         {"CARNET_OIDC_ISSUER": "idp.test", "CARNET_OIDC_CLIENT_ID": ok}),
        ("a quote, which would end the policy early",
         {"CARNET_OIDC_ISSUER": 'https://i.test" ; script-src *',
          "CARNET_OIDC_CLIENT_ID": ok}),
        ("a wildcard, which is a CSP source pasted where a URL goes",
         {"CARNET_OIDC_ISSUER": "https://*.okta.com",
          "CARNET_OIDC_CLIENT_ID": ok}),
        ("a bare * as an extra origin, which would open connect-src entirely",
         {"CARNET_OIDC_ISSUER": "https://i.test", "CARNET_OIDC_CLIENT_ID": ok,
          "CARNET_OIDC_EXTRA_ORIGINS": "*"}),
    ):
        done = run(**env)
        check(f"the front door refuses {label}",
              done.returncode != 0 and "front door:" in done.stderr, True)

    version = subprocess.run(
        ["docker", "run", "--rm", "-e", "CARNET_OIDC_ISSUER=https://i.test",
         "-e", f"CARNET_OIDC_CLIENT_ID={ok}", "carnet-front", "caddy", "version"],
        capture_output=True, text=True,
    )
    check("and the image still runs the command it is given, not one of its own",
          version.stdout.startswith("v2."), True)


def the_knobs() -> None:
    """Every setting the application reads has to be reachable from `.env`.

    **`environment:` is a closed list**, and that is the defect this scene was written
    for: a variable not named there is not "defaulted", it is *unreachable* — set it
    in `.env` and nothing happens, silently. The artifact shipped with five of the
    twenty-two `CARNET_*` variables the code reads, and the omissions included
    `CARNET_SECRET_KEYS_OLD`, which is the whole of step 026's key rotation:
    the procedure in `docs/UPGRADING.md` could not be performed on this deployment at
    all. Several others carry a comment in `config.py` promising they are
    "overridable without a deploy".

    The check is the honest one — read the variable back *out of a running container*,
    which is the only thing that proves the path from `.env` to the process.
    """
    say("the knobs: what .env can actually reach inside the containers")

    from carnet import config as app_config

    package = pathlib.Path(app_config.__file__).parent
    read_by_the_app = re.findall(
        r"CARNET_[A-Z_]+",
        (package / "config.py").read_text() + (package / "core" / "crypto.py").read_text(),
    )
    # Five names the regex catches that are not deployment settings: the dev-auth bypass
    # is deleted rather than disabled (config.py says so), VAR_DIR and LOCAL_STATE are set
    # by the image and by `--local`, TENANT is a CLI default rather than a server one, and
    # CARNET_CONNECTOR_ is not a variable at all — it is the prefix reserved for a
    # connector's own credential env var (step 050), which a connector row names, not .env.
    #
    # Three more since step 095, all the fileborne door's: CARNET_FILE selects the
    # *other* artefact and is refused beside CARNET_DATABASE_URL at import, so the
    # compose stack must never declare it; CARNET_TOKEN_ is the prefix reserved for the
    # file's token variables, the way CARNET_CONNECTOR_ is for a connector's; and
    # CARNET_TOKEN_ALICE is the example name in config.py's comment. Step 099's census
    # found this list two steps behind the code.
    not_a_deployment_setting = {
        "CARNET_INSECURE_DEV_AUTH", "CARNET_VAR_DIR",
        "CARNET_LOCAL_STATE", "CARNET_TENANT", "CARNET_CONNECTOR_",
        "CARNET_FILE", "CARNET_TOKEN_", "CARNET_TOKEN_ALICE",
    }
    wanted = set(read_by_the_app) - not_a_deployment_setting
    declared = set(re.findall(r"CARNET_[A-Z_]+", COMPOSE_FILE.read_text()))
    check("every application setting is reachable from .env",
          sorted(wanted - declared), [])

    # And the path works end to end, proven on the setting whose absence made key
    # rotation impossible: put a value in the environment, read it back from inside.
    probe = compose(
        "run", "--rm", "--no-deps", "-T",
        "-e", "CARNET_SECRET_KEYS_OLD=rotation-probe",
        "-e", "CARNET_RETENTION_DAYS=90",
        "api", "python", "-c",
        "import os; print(os.environ.get('CARNET_SECRET_KEYS_OLD'),"
        " os.environ.get('CARNET_RETENTION_DAYS'))",
        capture_output=True, text=True,
    )
    check("...and a value set outside arrives inside the container",
          probe.stdout.strip().endswith("rotation-probe 90"), True)

    # Decision 6, asserted where it is actually decided: the rendered service set is
    # the door's, and no worker service exists under any profile. A render, not an
    # `up`.
    rendered = compose("config", "--format", "json", capture_output=True, text=True)
    services = json.loads(rendered.stdout)["services"]
    check("the render has no worker service", "worker" in services, False)


def the_second_coming() -> None:
    """Restart — the operation a deployment survives after day one, decision 6."""
    say("stop everything, start it again: state survives, --migrate finds nothing")

    compose("stop", "-t", "5", capture_output=True, text=True)
    up = compose("up", "-d", capture_output=True, text=True)
    check("the stack comes back up", up.returncode, 0)

    with httpx.Client(verify=False, timeout=15) as client:
        check("the front door answers again", wait_for(f"{FRONT}/api/health", client),
              True)
    check("the tenant created before the restart is still there",
          psql("SELECT id FROM tenants WHERE id = 'e2e'"), "e2e")

    logs = compose("logs", "--no-log-prefix", "migrate", capture_output=True, text=True)
    check("the second --migrate found nothing to do (idempotent by checksum)",
          "Already up to date" in logs.stdout, True)

    say("and what came back is the door, nothing more")
    # What a restart must prove is that the service set is still exactly the door's.
    listed = compose("ps", "-a", "--format", "json", capture_output=True, text=True)
    names = sorted({json.loads(line)["Service"]
                    for line in listed.stdout.splitlines() if line.strip()})
    check("the services after a restart are the door's four",
          names, ["api", "db", "front", "migrate"])

    say("readiness tells the truth about the database; liveness deliberately does not")
    # Step 056, the red half asserted in the one place a real database can actually
    # go away: /health answers whatever the database is doing (restart me if THIS
    # fails), /health/ready makes one real round trip (route around me if THIS
    # fails). The compose healthcheck and the README's ingress contract point at the
    # second, and this is the check that says the two probes really do diverge.
    compose("stop", "-t", "5", "db", capture_output=True, text=True)
    with httpx.Client(verify=False, timeout=30) as client:
        live = client.get(f"{FRONT}/api/health")
        gone = client.get(f"{FRONT}/api/health/ready")
    check("with the database stopped, /health still answers 200 (liveness)",
          live.status_code, 200)
    check("...while /health/ready answers 503 (readiness)", gone.status_code, 503)
    check("...with a sentence, not a bare status",
          gone.status_code == 503 and bool(gone.json().get("detail")), True)
    compose("start", "db", capture_output=True, text=True)
    recovered = False
    with httpx.Client(verify=False, timeout=30) as client:
        stop = time.monotonic() + 90
        while time.monotonic() < stop:
            try:
                if client.get(f"{FRONT}/api/health/ready").status_code == 200:
                    recovered = True
                    break
            except httpx.HTTPError:
                pass
            time.sleep(2)
    check("...and readiness recovers when the database returns", recovered, True)


def the_managed_database() -> None:
    """Decision 9: the profile off, and a Postgres this stack does not own.

    The actual BYOC target — RDS, Cloud SQL, Azure — and the claim the compose file
    makes that nothing else here tests: drop `COMPOSE_PROFILES=bundled-db`, set
    `CARNET_DATABASE_URL`, and it is the same file. `required: false` on every
    `depends_on: db` is what has to hold for that.

    The external database is reached **by hostname over a network this stack did not
    create** — the container is attached to the project's network between `up
    --no-start` and `up` — because that is what a managed endpoint is: a name the
    application resolves and does not manage. The role is `NOSUPERUSER CREATEROLE`,
    the managed-master shape, so migration 037 creates the tenant role itself. That
    is the path that found 030's `SET`-vs-`MEMBER` defect.
    """
    say("decision 9: no bundled database, an external Postgres, reached by name")

    base = os.environ.get("CARNET_E2E_PG")
    holder = os.environ.get("CARNET_E2E_PG_CONTAINER") or "carnet-pg"
    if not base:
        print("  SKIPPED: needs CARNET_E2E_PG — a Postgres outside the stack")
        return
    running = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", holder],
        capture_output=True, text=True,
    )
    if running.stdout.strip() != "true":
        print(f"  SKIPPED: container {holder!r} is not running; "
              "set CARNET_E2E_PG_CONTAINER")
        return

    import psycopg

    role, password, db = "carnet_managed", secrets.token_hex(16), "carnet_managed_e2e"

    def dsn(database):
        parts = urlsplit(base)
        return urlunsplit((parts.scheme, parts.netloc, f"/{database}",
                           parts.query, parts.fragment))

    check("the previous run's database could be cleared away",
          drop_database(dsn("postgres"), db), True)
    with psycopg.connect(dsn("postgres"), autocommit=True) as conn:
        try:
            conn.execute(f"REASSIGN OWNED BY {role} TO current_user")
            conn.execute(f"DROP OWNED BY {role}")
        except psycopg.Error:
            pass
        conn.execute(f"DROP ROLE IF EXISTS {role}")
        # The managed-master shape: ordinary, but able to create the tenant role.
        conn.execute(
            f"CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER CREATEROLE"
        )
        conn.execute(f"CREATE DATABASE {db} OWNER {role}")
        # **The precondition of the refusal scene below, established rather than
        # inherited.** That scene is about a *second* deployment into a cluster that
        # already has the tenant role — the role is cluster-global, this deployment did
        # not create it, so PG16 refuses to let it grant itself membership. Until this
        # line the scene never created the role: it passed only where an earlier run had
        # left one behind, which is every developer's long-lived container and no CI
        # service container. It therefore passed locally, passed the last time CI ran it
        # on a machine that had one, and failed the first time this branch was put
        # through CI — three checks red for a reason that had nothing to do with the
        # seventeen commits under review. Created by the cluster's own administrator,
        # never by `role`, because "somebody else created it" is the whole scenario.
        conn.execute(
            "DO $$ BEGIN "
            "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime_tenant') "
            "THEN CREATE ROLE agent_runtime_tenant NOLOGIN; END IF; END $$"
        )

    env = write_env(
        SCRATCH / "e2e_deploy_managed.env",
        COMPOSE_PROFILES=None,  # the bundled database is not even created
        CARNET_HTTPS_PORT=str(MANAGED_HTTPS_PORT),
        CARNET_HTTP_PORT="8792",
        CARNET_DATABASE_URL=(
            f"postgresql://{role}:{password}@{holder}:5432/{db}"
        ),
    )
    network = f"{MANAGED_PROJECT}_default"
    front = f"https://localhost:{MANAGED_HTTPS_PORT}"

    try:
        created = compose("up", "--no-start", project=MANAGED_PROJECT, env_file=env,
                          capture_output=True, text=True)
        check("with the profile off, the stack builds with no db service",
              created.returncode, 0)
        services = compose("ps", "-a", "--format", "json", project=MANAGED_PROJECT,
                           env_file=env, capture_output=True, text=True)
        names = sorted(json.loads(line)["Service"]
                       for line in services.stdout.splitlines() if line.strip())
        check("...and `db` is not among the containers",
              names, ["api", "front", "migrate"])

        subprocess.run(["docker", "network", "connect", network, holder],
                       capture_output=True, text=True)

        # **A second deployment in a cluster that already has the tenant role**, which
        # is what staging-beside-production means and what this shared cluster is. The
        # role is cluster-global and this one did not create it, so PG16 will not let
        # it grant itself membership: 037 refuses, `migrate` exits non-zero, and
        # because everything depends on migrate completing, the stack does not come
        # up. That is correct — the alternative starts and reads nobody's rows — but
        # the artifact has to *say* so, which is what the e2e is holding in place.
        say("a second deployment in the cluster: the refusal, then its remedy")
        refused = compose("up", "-d", project=MANAGED_PROJECT, env_file=env,
                          capture_output=True, text=True)
        check("the stack refuses to come up rather than serving nothing",
              refused.returncode != 0, True)
        logs = compose("logs", "--no-log-prefix", "migrate", project=MANAGED_PROJECT,
                       env_file=env, capture_output=True, text=True)
        check("...and migrate's log names the one line an administrator runs",
              f"GRANT agent_runtime_tenant TO {role}" in logs.stdout, True)
        state, _ = container_state("api", project=MANAGED_PROJECT, env_file=env)
        check("...and the API never started against the un-migrated database",
              state in (None, "created", "exited"), True)

        # Exactly the remedy the refusal printed, run by the cluster's administrator —
        # `deploy/README.md` now carries it. 029's rule, at the deployment layer: a
        # refusal whose remedy does not remedy is a dead end.
        with psycopg.connect(dsn("postgres"), autocommit=True) as conn:
            conn.execute(f"GRANT agent_runtime_tenant TO {role}")
        started = compose("up", "-d", project=MANAGED_PROJECT, env_file=env,
                          capture_output=True, text=True)
        check("after the administrator runs it, the stack comes up unchanged",
              started.returncode, 0)

        with httpx.Client(verify=False, timeout=15) as client:
            answered = wait_for(f"{front}/api/health", client)
            if not check("the front door answers, served from a database it does "
                         "not own", answered, True):
                logs = compose("logs", "--tail", "30", "migrate", "api",
                               project=MANAGED_PROJECT, env_file=env,
                               capture_output=True, text=True)
                print(logs.stdout[-3000:])

        with psycopg.connect(dsn(db)) as conn:
            owner = conn.execute(
                "SELECT r.rolname || '|' || r.rolsuper FROM pg_class c"
                " JOIN pg_namespace n ON n.oid = c.relnamespace"
                " JOIN pg_roles r ON r.oid = c.relowner"
                " WHERE n.nspname = 'public' AND c.relname = 'tenants'"
            ).fetchone()
            settable = conn.execute(
                "SELECT pg_has_role(%s, 'agent_runtime_tenant', 'SET')", (role,)
            ).fetchone()
        check("the managed database's tables are owned by the ordinary role",
              owner and owner[0], f"{role}|false")
        # The 030 defect, asserted on the path that produced it: this role *created*
        # the tenant role, so it holds ADMIN OPTION — and must also hold SET.
        check("...which created the tenant role and can still SET ROLE into it",
              settable and settable[0], True)

        # Since 042 the API is the process that carries the isolation boot check in
        # the default stack; zero restarts is what says it passed against a database
        # this deployment does not own.
        state, restarts = container_state("api", project=MANAGED_PROJECT,
                                          env_file=env)
        check("the API runs against the managed database", state, "running")
        check("...without crash-looping", restarts, "0")
    finally:
        # **Stop the containers before cutting the network, not after.** Disconnecting
        # first strands every open connection: the server sees no FIN, so the backends
        # sit idle holding the database until TCP keepalive gives up — hours — and the
        # *next* run cannot even create its database. Stopping first lets the pools
        # close properly, which is what makes the drop below ordinary.
        compose("down", "-v", "--remove-orphans", "-t", "5", project=MANAGED_PROJECT,
                env_file=env, capture_output=True, text=True)
        subprocess.run(["docker", "network", "disconnect", "-f", network, holder],
                       capture_output=True, text=True)
        check("the managed database could be dropped at the end",
              drop_database(dsn("postgres"), db), True)

        with psycopg.connect(dsn("postgres"), autocommit=True) as conn:
            try:
                conn.execute(f"REASSIGN OWNED BY {role} TO current_user")
                conn.execute(f"DROP OWNED BY {role}")
            except psycopg.Error:
                pass
            conn.execute(f"DROP ROLE IF EXISTS {role}")
        env.unlink(missing_ok=True)


def the_owner_check_can_go_red() -> None:
    """Break the artifact on purpose, and confirm the checks above notice.

    The house discipline, applied to infrastructure: 029 rewrote a test that passed
    with its own subject removed, and the non-superuser owner — 029's whole blind
    spot — is the check here that carries enough weight to deserve the same
    treatment. A check that cannot go red is decoration.

    **The proxy body-limit mutation that used to open this scene is retired, and the
    reason is recorded rather than papered over.** 023's boundary — the proxy, not
    the app, refuses an oversized delivery — was provable while the app had a hooks
    route that read bodies: raise the app's ceiling, and a 413 for 128 KiB could
    only be the front door's. Since 042 the door-only artifact registers no hooks
    router at all, so the app answers 404 without reading a byte, the proxy's
    mid-stream ceiling has nothing to trip on, and the two responses genuinely race
    (this script observed both statuses across runs of one image). A check on one
    status is a coin flip; a check on either cannot go red; and a flaky deploy job
    teaches people to ignore red, which is worse than either.
    """
    say("mutation: give the app role superuser, the thing decision 8 exists to prevent")
    psql("ALTER ROLE carnet_app SUPERUSER", superuser=True)
    check("the owner check notices a superuser serving role",
          table_owner(), "carnet_app|true")
    psql("ALTER ROLE carnet_app NOSUPERUSER", superuser=True)
    check("...and notices when it is put back", table_owner(), "carnet_app|false")


# --- talking to the bundled database -------------------------------------------------


def psql(sql: str, superuser: bool = False) -> str:
    """One scalar out of the bundled database, over `compose exec`.

    `-U postgres` because this reaches in as the *administrator* of the container to
    ask questions about the app role — the opposite of what the stack itself does,
    which is the point: nothing the application uses may be a superuser.
    """
    done = compose("exec", "-T", "db", "psql", "-U", "postgres", "-d", "carnet",
                   "-tA", "-c", sql, capture_output=True, text=True)
    return done.stdout.strip()


def table_owner() -> str:
    # `|| r.rolsuper` casts the boolean to text, which prints 'false' — unlike a bare
    # boolean column, which psql would render 'f'.
    return psql(
        "SELECT r.rolname || '|' || r.rolsuper FROM pg_class c"
        " JOIN pg_namespace n ON n.oid = c.relnamespace"
        " JOIN pg_roles r ON r.oid = c.relowner"
        " WHERE n.nspname = 'public' AND c.relname = 'tenants'"
    )


def main() -> int:
    global ENV_FILE

    reason = preflight()
    if reason:
        print(f"SKIPPED: {reason}. The deploy e2e needs a container runtime; "
              "everything else in scripts/ still runs.")
        return 0

    ENV_FILE = write_env(SCRATCH / "e2e_deploy.env")
    try:
        for scene in (the_first_five_minutes, the_running_stack, the_sign_in_wiring,
                      the_provider_declaration, the_knobs, the_second_coming,
                      the_owner_check_can_go_red, the_managed_database):
            # One scene's crash must not cost the verdict on every other scene, and
            # must not be mistaken for a pass. `e2e_rls.py` learned the same lesson
            # about a summary that could be skipped; this is its other half — the
            # first version of this script died in a teardown and exited without
            # printing a report at all.
            try:
                scene()
            except Exception as exc:  # noqa: BLE001 - reported, not swallowed
                check(f"the scene {scene.__name__} ran to the end",
                      f"{type(exc).__name__}: {exc}", "no exception")
    finally:
        say("down (volumes too; the images stay for the next run's cache)")
        try:
            compose("down", "-v", "--remove-orphans", "-t", "5",
                    capture_output=True, text=True)
            ENV_FILE.unlink(missing_ok=True)
        except Exception as exc:  # noqa: BLE001 - a failed teardown is not a verdict
            print(f"  (teardown did not finish cleanly: {exc})")
    return report()


if __name__ == "__main__":
    os.chdir(REPO)
    sys.exit(main())
