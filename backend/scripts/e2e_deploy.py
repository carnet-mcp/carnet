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

  - `the_one_command`         step 121: `deploy/setup.sh` is day one now, and the
                              two refusals that protect a key it must never
                              overwrite. The README agrees, asserted rather than
                              assumed.
  - `the_first_five_minutes`  the README's by-hand day one, run verbatim, plus the
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
  - `the_operators_certificate`
                              step 109: CARNET_TLS_MODE across its three modes,
                              driven like the provider declaration, and the one
                              thing a directive cannot prove — a real handshake
                              presents the mounted certificate, not Caddy's own.
  - `the_knobs`               every setting the application reads is reachable from
                              `.env` — `environment:` is a closed list, and what it
                              omits is not defaulted but unreachable. Since 109 the
                              front door's own settings and the network variables
                              that are not ours by name are held to the same rule.
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

import hashlib
import json
import os
import pathlib
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
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


def the_one_command() -> None:
    """`deploy/setup.sh`, and the two refusals that protect somebody's key (step 121).

    The script is interactive and stands a stack up, which this file already does its
    own way — so what is driven here is the part that must be right whatever anybody
    types at it. The full run is a hand-run, reported in the step.

    **Run against a copy in the scratch directory, never against `deploy/` itself.**
    Both refusals happen before the script reads or writes anything else, so a lone
    copy of the file is enough to reach them — and the alternative, moving a real
    `.env` aside to make room for the test, is a test that can lose somebody's key if
    it dies in the middle. That is the same property the refusal itself is for.

    The first refusal is the load-bearing one. `.env` holds the key that opens every
    delegated credential this deployment has stored and there is no copy anywhere else,
    so a setup script that can overwrite one is a setup script that can destroy a
    running deployment's data from a mistyped command. It refuses under every flag,
    because there is no flag.
    """
    say("day one: one command, and the file it will not overwrite")

    setup = DEPLOY / "setup.sh"
    check("setup.sh is executable, or `./setup.sh` is not the instruction",
          os.access(setup, os.X_OK), True)

    sandbox = SCRATCH / "e2e_deploy_setup"
    shutil.rmtree(sandbox, ignore_errors=True)
    sandbox.mkdir(parents=True)
    shutil.copy2(setup, sandbox / "setup.sh")

    def run_it() -> subprocess.CompletedProcess:
        return subprocess.run(["sh", "./setup.sh"], cwd=sandbox,
                              stdin=subprocess.DEVNULL, capture_output=True, text=True)

    piped = run_it()
    check("with no terminal it refuses and names the by-hand path",
          piped.returncode != 0 and "docker compose up -d --build" in piped.stderr, True)

    # And with a file present it says *that* instead — the ordering is the finding, not
    # a preference. With the terminal check first, somebody piping into this script on
    # a deployment that was already set up was told to copy .env.example to .env, which
    # is advice to create the file that already exists and holds their key.
    (sandbox / ".env").write_text("CARNET_SECRET_KEY=not-a-real-key\n")
    guarded = run_it()
    check("an existing .env is refused before anything else is even checked",
          guarded.returncode != 0 and "already exists" in guarded.stderr, True)
    check("...and the refusal says why that file matters",
          "CARNET_SECRET_KEY" in guarded.stderr, True)
    check("...and it really is untouched",
          (sandbox / ".env").read_text().strip(), "CARNET_SECRET_KEY=not-a-real-key")

    shutil.rmtree(sandbox, ignore_errors=True)

    # The README is the other half of this promise: day one is one command there too.
    readme = (DEPLOY / "README.md").read_text()
    day_one = readme[readme.index("## Day one"):readme.index("**Upgrades:**")]
    check("the README's day one is that command", "./setup.sh" in day_one, True)
    check("...and the by-hand path is still printed for a team that wants it",
          "cp .env.example .env" in day_one, True)


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
        # A domain always, because compose always supplies one (`:?`) and the
        # entrypoint's `acme` branch reads it since step 121 — a case run without one
        # is a case the deployment cannot produce.
        env.setdefault("CARNET_DOMAIN", "carnet.example.com")
        args = []
        for key, value in env.items():
            args += ["-e", f"{key}={value}"]
        return subprocess.run(
            ["docker", "run", "--rm", *args, "carnet-front", "sh", "-c",
             'echo "CSP=$CARNET_CSP"; cat /srv/config.json 2>/dev/null; '
             'echo "ROUTE=$(cat /etc/caddy/idp.caddy)"'],
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
        ["docker", "run", "--rm", "-e", "CARNET_DOMAIN=carnet.example.com",
         "-e", "CARNET_OIDC_ISSUER=https://i.test",
         "-e", f"CARNET_OIDC_CLIENT_ID={ok}", "carnet-front", "caddy", "version"],
        capture_output=True, text=True,
    )
    check("and the image still runs the command it is given, not one of its own",
          version.stdout.startswith("v2."), True)

    # --- step 121: the third artifact, and the choice between providers -------------
    #
    # `CARNET_IDP` turns the same one declaration into a THIRD thing: whether /idp/*
    # reaches a provider at all. The route is a file the Caddyfile imports
    # unconditionally, so "no bundled provider" is an empty file rather than an absent
    # one — an import that may or may not resolve is a routing table that depends on
    # whether a previous boot happened to write one.
    bundled = run(CARNET_IDP="bundled", COMPOSE_PROFILES="bundled-db,bundled-idp")
    check("bundled writes the provider's own /config.json, origin-relative",
          '"issuer": "/idp"' in bundled.stdout
          and '"client_id": "carnet-local"' in bundled.stdout, True)
    check("bundled routes /idp/* to the provider service",
          "reverse_proxy idp:8080" in bundled.stdout, True)
    # The point of one origin, asserted rather than described: the bundled policy is
    # byte-for-byte the policy a deployment with NO provider serves, because an
    # origin-relative issuer needs no provider-dependent source. If this ever differs,
    # the shipped `connect-src 'self'` has stopped covering the token exchange.
    check("and its CSP is exactly the unconfigured one — one origin, no exception",
          csp_of(CARNET_IDP="bundled", COMPOSE_PROFILES="bundled-idp")
          == csp_of(), True)

    external = run(CARNET_OIDC_ISSUER="https://acme.okta.com/oauth2/default",
                   CARNET_OIDC_CLIENT_ID=ok)
    check("an external provider routes /idp/* nowhere, and the file is empty not absent",
          "ROUTE=" in external.stdout
          and "reverse_proxy idp" not in external.stdout, True)

    # A deployment that predates CARNET_IDP must upgrade untouched, and one with no
    # provider at all must still come up: this container also serves /api/mcp, so
    # refusing to boot over a *browser* setting would take the MCP door down with it.
    # **That corrects plan 121's decision 3**, which asked for a refusal here.
    quiet = run()
    check("no provider declared at all still comes up, as it did before 121",
          quiet.returncode == 0 and "ROUTE=" in quiet.stdout, True)
    check("and says so on stderr rather than leaving a sign-in screen to explain it",
          "no identity provider is declared" in quiet.stderr
          and "/api/mcp is unaffected" in quiet.stderr, True)

    # Every way to make the two halves of the choice disagree. The compose profile is
    # the one thing here that cannot be derived — a container is not told which
    # profiles were activated — so it is passed in and checked, which is the
    # difference between a sentence and a 502 on the sign-in page.
    for label, env in (
        ("bundled with no bundled-idp profile, which would 502",
         {"CARNET_IDP": "bundled"}),
        ("the bundled-idp profile with an external provider",
         {"CARNET_IDP": "external", "COMPOSE_PROFILES": "bundled-idp"}),
        ("bundled beside an issuer, where nothing says which one signs",
         {"CARNET_IDP": "bundled", "COMPOSE_PROFILES": "bundled-idp",
          "CARNET_OIDC_ISSUER": "https://i.test", "CARNET_OIDC_CLIENT_ID": ok}),
        ("bundled beside a scopes setting nothing would request",
         {"CARNET_IDP": "bundled", "COMPOSE_PROFILES": "bundled-idp",
          "CARNET_OIDC_SCOPES": "openid"}),
        ("a CARNET_IDP that is neither", {"CARNET_IDP": "yes"}),
    ):
        done = run(**env)
        check(f"the front door refuses {label}",
              done.returncode != 0 and "front door:" in done.stderr, True)

    for mode, profiles in (("bundled", "bundled-idp"), ("external", "")):
        adapted = subprocess.run(
            ["docker", "run", "--rm", "-e", "CARNET_DOMAIN=carnet.example.com",
             "-e", f"CARNET_IDP={mode}", "-e", f"COMPOSE_PROFILES={profiles}",
             *(["-e", "CARNET_OIDC_ISSUER=https://i.test",
                "-e", f"CARNET_OIDC_CLIENT_ID={ok}"] if mode == "external" else []),
             "carnet-front", "caddy", "validate", "--config", "/etc/caddy/Caddyfile",
             "--adapter", "caddyfile"],
            capture_output=True, text=True,
        )
        # An imported file Caddy cannot parse is a front door that does not start, and
        # the empty half is the one a reader doubts: `import` of an empty file.
        check(f"and the Caddyfile still adapts under CARNET_IDP={mode}",
              "Valid configuration" in adapted.stderr + adapted.stdout, True)


def _self_signed(name: str) -> tuple[bytes, bytes, str]:
    """A certificate and key for `name`, PEM, and the SHA-256 of the certificate's
    DER — the fingerprint a handshake can be compared against."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()),
        hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
    )


def the_operators_certificate() -> None:
    """Step 109, decision 4: the front door serves a certificate somebody else issued.

    Three modes through one variable, and the entrypoint composes the Caddyfile's
    `tls` line from it the way it composes the CSP — so the modes are driven with
    `docker run` the way `the_provider_declaration` drives the provider, a second per
    case. Then the one thing a directive cannot prove: a front door alone on a port,
    the pair mounted where `files` expects it, and the certificate a real handshake
    presents compared byte-for-byte to the one mounted. No API behind it, because a
    handshake needs none.
    """
    say("the operator's certificate: CARNET_TLS_MODE across its three modes")

    def run(**env):
        # CARNET_DOMAIN always, because compose always supplies it (`:?`) and since
        # step 121 the `acme` branch reads it — a case run without one is a case the
        # deployment cannot produce.
        env.setdefault("CARNET_DOMAIN", "carnet.example.com")
        args = []
        for key, value in env.items():
            args += ["-e", f"{key}={value}"]
        return subprocess.run(
            ["docker", "run", "--rm", *args, "carnet-front", "sh", "-c",
             'echo "TLS=$CARNET_TLS"'],
            capture_output=True, text=True,
        )

    check("unset is today's behaviour: no tls directive, so ACME or localhost's own CA",
          run().stdout.strip(), "TLS=")
    check("acme says so explicitly and means the same",
          run(CARNET_TLS_MODE="acme").stdout.strip(), "TLS=")
    check("internal is Caddy's own CA for any name",
          run(CARNET_TLS_MODE="internal").stdout.strip(), "TLS=tls internal")

    # Step 121. `acme` is the default, so the name it cannot work for is the one a
    # self-serve installer is most likely to have: a VM reached by address. The
    # failure it replaces is the least legible in the stack — a front door that comes
    # up, serves nothing usable, and retries an ACME challenge for minutes in a log
    # nobody is reading, while the browser names no cause.
    for label, domain in (("an address", "10.0.0.5"),
                          ("a single-label name", "carnet"),
                          ("nothing at all", "")):
        refused = run(CARNET_DOMAIN=domain)
        check(f"acme refuses {label}, and names the mode that works",
              refused.returncode != 0
              and ("internal" in refused.stderr or "no name" in refused.stderr), True)
    # And the two that Caddy really does issue for itself, which the documented trial
    # rests on: a refusal that caught these would break `localhost` for everybody.
    for domain in ("localhost", "app.localhost"):
        check(f"...but {domain} is still fine, because Caddy signs it itself",
              run(CARNET_DOMAIN=domain).stdout.strip(), "TLS=")
    check("...and the address is served the moment a mode that can is chosen",
          run(CARNET_DOMAIN="10.0.0.5", CARNET_TLS_MODE="internal").stdout.strip(),
          "TLS=tls internal")
    missing = run(CARNET_TLS_MODE="files")
    check("files without the files refuses at start, naming the mount",
          missing.returncode != 0 and "/etc/carnet/tls/cert.pem" in missing.stderr
          and "compose.yaml" in missing.stderr, True)
    bogus = run(CARNET_TLS_MODE="letsencrypt")
    check("a mode that is not one of the three refuses, naming them",
          bogus.returncode != 0 and "acme, internal or files" in bogus.stderr, True)

    tls_dir = SCRATCH / "e2e_deploy_tls"
    tls_dir.mkdir(parents=True, exist_ok=True)
    cert_pem, key_pem, fingerprint = _self_signed("localhost")
    (tls_dir / "cert.pem").write_bytes(cert_pem)
    (tls_dir / "key.pem").write_bytes(key_pem)
    port = HTTPS_PORT + 5
    name = "carnet_e2e_tls_front"
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    started = subprocess.run(
        ["docker", "run", "-d", "--name", name,
         "-e", "CARNET_DOMAIN=localhost", "-e", "CARNET_TLS_MODE=files",
         "-v", f"{tls_dir}:/etc/carnet/tls:ro", "-p", f"{port}:443", "carnet-front"],
        capture_output=True, text=True,
    )
    try:
        check("the front door starts in files mode with the pair mounted",
              started.returncode, 0)
        presented = None
        deadline = time.time() + 60
        while time.time() < deadline and presented is None:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection(("127.0.0.1", port), timeout=5) as raw, \
                        context.wrap_socket(raw, server_hostname="localhost") as tls:
                    presented = tls.getpeercert(binary_form=True)
            except OSError:
                time.sleep(1)
        check("...and the certificate a handshake presents is the mounted one, "
              "not Caddy's own",
              hashlib.sha256(presented).hexdigest() if presented else None, fingerprint)
        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
        check("...and nothing was obtained from any issuer",
              "obtaining certificate" in (logs.stdout + logs.stderr), False)
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


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
        (package / "config.py").read_text() + (package / "core" / "crypto.py").read_text()
        # Step 109: the front door reads settings of its own, in its entrypoint, and
        # CARNET_TLS_MODE was the first one that could have shipped unreachable.
        + (DEPLOY / "frontdoor-entrypoint.sh").read_text()
        # Step 121: so does the bundled provider, in its own entry point.
        + (package / "localidp" / "service.py").read_text(),
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
    #
    # And three the entrypoint contributes (109): CARNET_CSP and CARNET_TLS are what
    # it *exports* to the Caddyfile, not settings anybody sets; CARNET_OIDC_ is the
    # prefix as it appears in a refusal's wording.
    #
    # And one from step 121, on CARNET_VAR_DIR's reasoning exactly: CARNET_IDP_STATE is
    # a path *inside* the provider's container, where compose mounts its volume. A
    # deployment that moved it would have moved the mount, which is an edit to
    # compose.yaml rather than a line in .env — so offering it in the closed list would
    # be offering a way to separate the provider from its own accounts database.
    not_a_deployment_setting = {
        "CARNET_INSECURE_DEV_AUTH", "CARNET_VAR_DIR",
        "CARNET_LOCAL_STATE", "CARNET_TENANT", "CARNET_CONNECTOR_",
        "CARNET_FILE", "CARNET_TOKEN_", "CARNET_TOKEN_ALICE",
        "CARNET_CSP", "CARNET_TLS", "CARNET_OIDC_", "CARNET_IDP_STATE",
    }
    wanted = set(read_by_the_app) - not_a_deployment_setting
    compose_text = COMPOSE_FILE.read_text()
    declared = set(re.findall(r"CARNET_[A-Z_]+", compose_text))
    check("every application setting is reachable from .env",
          sorted(wanted - declared), [])

    # Step 109. The network variables are not ours by name, so the regex cannot see
    # them and they are held to the rule by hand. REQUESTS_CA_BUNDLE is what
    # `requests` — every dial — reads for a corporate CA. SSL_CERT_FILE must NOT be
    # declared: a blank value, which this closed list hands the container for every
    # unset variable, makes OpenSSL load a file named "" and leaves Python's trust
    # store empty — checked in the image's own base, 0 roots against 150. A variable
    # that breaks TLS by being left unset is worse than one that cannot be set.
    check("the corporate CA variable is reachable from .env",
          "REQUESTS_CA_BUNDLE:" in compose_text, True)
    check("...and the one a blank value would break TLS with is not offered",
          "SSL_CERT_FILE:" in compose_text, False)
    # Step 109, decisions 5 and 6. Two settings no process reads — compose itself
    # does, at build and at `up` — so the census above cannot see them either, and
    # they are held to the rule by hand: the mirror the base images come from, and
    # the whole database reference for an image that arrived in a tarball.
    # Step 110, decision 11 added two more of the same kind: the built images by name,
    # for the team that pulls the published pair rather than building.
    check("the registry prefix, the database image and the two built images are reachable from .env",
          [name for name in ("CARNET_BASE_REGISTRY", "CARNET_DB_IMAGE",
                             "CARNET_API_IMAGE", "CARNET_FRONT_IMAGE")
           if name not in compose_text], [])

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


MIRROR_PORT = HTTPS_PORT + 6


def the_internal_registry() -> None:
    """Step 109, decision 5: the registry is an argument; the digest is not.

    An on-premises policy says images come from the company's mirror, and until this
    step obeying it meant editing three FROM lines — spending the reproducibility the
    pins exist for. Three claims, each checked against a real thing rather than a
    rendered file:

    - The argument reaches every base image. Proven negatively, with a mirror that
      does not exist: the refusal names the full path it tried, prefix and digest.
    - A mirror preserves the digest and the build accepts the pin from it. Proven with
      a real pull-through registry on this machine — the shape of every Harbor proxy
      cache and Artifactory remote — whose own access log then says what the build
      asked it for: the pinned manifest, by digest, and nothing by tag.
    - What comes out is what went in. The image built through the mirror has the same
      layers as the one built from Docker Hub, which is what *the same bytes from a
      different address* means when it is checked rather than asserted.
    """
    say("the internal registry: one prefix, the same digests")

    compose_text = COMPOSE_FILE.read_text()
    pinned_db = re.search(r"postgres:16@sha256:[0-9a-f]{64}", compose_text).group(0)
    dockerfile = (DEPLOY / "Dockerfile").read_text()
    pinned_python = re.search(r"python:3\.12-slim@(sha256:[0-9a-f]{64})", dockerfile).group(1)

    def rendered(env_file):
        out = compose("config", "--format", "json", env_file=env_file,
                      capture_output=True, text=True)
        return json.loads(out.stdout)["services"] if out.returncode == 0 else {}

    services = rendered(ENV_FILE)
    check("with nothing set the bases come from Docker Hub, by its full name",
          sorted({services[s]["build"]["args"]["BASE_REGISTRY"]
                  for s in ("migrate", "api", "front")}), ["docker.io"])
    check("...and so does the pinned database image",
          services["db"]["image"], f"docker.io/library/{pinned_db}")

    mirror = "harbor.example.internal/dockerhub"
    mirrored = variant_env(SCRATCH / "e2e_deploy_mirror.env", CARNET_BASE_REGISTRY=mirror)
    services = rendered(mirrored)
    check("one line in .env retargets all three builds at the mirror",
          sorted({services[s]["build"]["args"]["BASE_REGISTRY"]
                  for s in ("migrate", "api", "front")}), [mirror])
    check("...and the database image, with the digest kept",
          services["db"]["image"], f"{mirror}/library/{pinned_db}")
    mirrored.unlink(missing_ok=True)

    nowhere = subprocess.run(
        ["docker", "build", "--build-arg", "BASE_REGISTRY=127.0.0.1:1/nowhere",
         "--target", "api", "-f", str(DEPLOY / "Dockerfile"), str(REPO)],
        capture_output=True, text=True,
    )
    check("a mirror that does not exist refuses, naming the path it tried",
          nowhere.returncode != 0
          and f"127.0.0.1:1/nowhere/library/python:3.12-slim@{pinned_python}"
          in nowhere.stderr, True)

    say("a real pull-through mirror, the shape of a Harbor proxy cache")
    name = "carnet_e2e_mirror"
    tag = "carnet_e2e_mirror_api"
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    started = subprocess.run(
        ["docker", "run", "-d", "--name", name, "-p", f"{MIRROR_PORT}:5000",
         "-e", "REGISTRY_PROXY_REMOTEURL=https://registry-1.docker.io", "registry:2"],
        capture_output=True, text=True,
    )
    try:
        check("the mirror starts", started.returncode, 0)
        with httpx.Client(timeout=5) as client:
            check("...and answers the registry API",
                  wait_for(f"http://127.0.0.1:{MIRROR_PORT}/v2/", client, 60), True)
        prefix = f"localhost:{MIRROR_PORT}"
        seen = subprocess.run(
            ["docker", "buildx", "imagetools", "inspect",
             f"{prefix}/library/python:3.12-slim@{pinned_python}"],
            capture_output=True, text=True,
        )
        check("the pinned python resolves through the mirror to the same digest",
              seen.returncode == 0 and f"Digest:    {pinned_python}" in seen.stdout, True)
        built = subprocess.run(
            ["docker", "build", "-q", "--build-arg", f"BASE_REGISTRY={prefix}",
             "--target", "api", "-t", tag, "-f", str(DEPLOY / "Dockerfile"), str(REPO)],
            capture_output=True, text=True,
        )
        check("the api image builds with its base from the mirror", built.returncode, 0)
        if built.returncode != 0:
            print(built.stderr[-1500:])

        def layers(image):
            out = subprocess.run(
                ["docker", "image", "inspect", "--format", "{{join .RootFS.Layers \" \"}}",
                 image], capture_output=True, text=True)
            return out.stdout.strip()

        check("...and it is the same image as the one built from Docker Hub",
              layers(tag) == layers("carnet-api") and layers(tag) != "", True)
        log = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
        asked = log.stdout + log.stderr
        check("the mirror's own log says the build asked it for the pin, by digest",
              f"/v2/library/python/manifests/{pinned_python}" in asked, True)
        check("...and never by tag", "/v2/library/python/manifests/3.12-slim" in asked,
              False)
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        subprocess.run(["docker", "rmi", tag], capture_output=True)


def the_carried_artefact() -> None:
    """Step 109, decision 6: the artefact a person carries in.

    The sealed estate is provable only by a machine with its network cable out, and
    that stays a hand-run procedure — `docs/OFFLINE.md` is its checklist. What a
    connected runner can prove is everything short of the cable: that the bundle
    builds from this checkout; carries every file the document promises; verifies
    with its own `verify.sh` before `docker load` and again after it, by layer list,
    which is the comparison that survives the two image stores naming an image
    differently; that its MANIFEST names this commit and this version; and — the
    offline claim in the one form a connected machine can check — that every image
    the far side's compose file names came out of the tarball, so nothing is left for
    a registry to answer.
    """
    from carnet import __version__

    say("the carried artefact: the offline bundle, built and verified both sides")

    out = SCRATCH / "e2e_deploy_offline"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    # Step 110, decision 10: signed, under a key made for this run and thrown away. The
    # real key is a person's and never sees a runner; what this proves is the mechanism
    # — that the far side's `openssl dgst -verify` accepts what the connected side's
    # `--sign-key` wrote, and rejects one altered byte in either the sums or the
    # signature — not who holds the key.
    key = out / "throwaway.key"
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout",
                    "-out", str(key)], check=True, capture_output=True)
    made = subprocess.run(
        [str(REPO / "backend" / "scripts" / "offline_bundle.sh"), "--out", str(out),
         "--sign-key", str(key)],
        capture_output=True, text=True,
    )
    check("offline_bundle.sh runs to the end, signing as it goes", made.returncode, 0)
    if made.returncode != 0:
        print(made.stderr[-2000:])
        return
    tarball = pathlib.Path(made.stdout.strip().splitlines()[-1])
    check("...and prints the tarball it wrote", tarball.is_file(), True)
    check("...named for the version and the platform",
          tarball.name.startswith(f"carnet-offline-{__version__}-linux-"), True)

    try:
        with tarfile.open(tarball) as archive:
            archive.extractall(out, filter="data")
        inside = out / tarball.stem
        promised = ["images.tar.gz", "MANIFEST", "SHA256SUMS", "SHA256SUMS.sig",
                    "carnet-release.pub", "verify.sh",
                    "carnet.example.yaml", "LICENSE", "deploy/compose.yaml",
                    "deploy/.env.example", "deploy/initdb/01-app-role.sh",
                    "deploy/Caddyfile", "docs/OFFLINE.md", "docs/UPGRADING.md",
                    "docs/GUIDE.md"]
        check("every file docs/OFFLINE.md promises is in it",
              [f for f in promised if not (inside / f).is_file()], [])
        check("...and no live .env came along", (inside / "deploy" / ".env").exists(),
              False)

        manifest = (inside / "MANIFEST").read_text()
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=REPO,
                                capture_output=True, text=True).stdout.strip()
        check("MANIFEST names this version", f"version:  {__version__}" in manifest, True)
        check("...and this commit", f"commit:   {commit}" in manifest, True)
        check("...and says what the signature does and does not prove",
              "signed:   SHA256SUMS.sig" in manifest
              and "does not say the key is still in the right hands" in manifest, True)
        fingerprint = subprocess.run(
            "openssl pkey -pubin -in carnet-release.pub -outform DER | openssl dgst -sha256",
            shell=True, cwd=inside, capture_output=True, text=True,
        ).stdout.strip().split("= ")[-1]
        check("...and names the key's fingerprint, for the far side to compare",
              fingerprint in manifest, True)

        before = subprocess.run(["sh", "verify.sh"], cwd=inside,
                                capture_output=True, text=True)
        check("verify.sh: every file matches SHA256SUMS",
              before.returncode == 0 and "every file matches" in before.stdout, True)
        check("...and SHA256SUMS is signed by the key in the bundle, fingerprint printed",
              "is signed by the key in carnet-release.pub" in before.stdout
              and fingerprint in before.stdout, True)
        (inside / "MANIFEST").write_text(manifest + "\n")
        tampered = subprocess.run(["sh", "verify.sh"], cwd=inside,
                                  capture_output=True, text=True)
        check("...and one altered byte fails it, saying not to load",
              tampered.returncode != 0 and "do not load" in tampered.stderr, True)
        (inside / "MANIFEST").write_text(manifest)

        # The signature's own two failures: the sums re-written by somebody without the
        # key (a whole consistent bundle, every file matching — and no signature that
        # matches it), and the signature file itself altered.
        sums = (inside / "SHA256SUMS").read_bytes()
        (inside / "SHA256SUMS").write_bytes(sums + b"# one more line\n")
        resigned = subprocess.run(["sh", "verify.sh"], cwd=inside,
                                  capture_output=True, text=True)
        check("...and a SHA256SUMS the key did not sign fails, saying not to load",
              resigned.returncode != 0 and "does not verify" in resigned.stderr, True)
        (inside / "SHA256SUMS").write_bytes(sums)
        sig = (inside / "SHA256SUMS.sig").read_bytes()
        (inside / "SHA256SUMS.sig").write_bytes(sig[:-1] + bytes([sig[-1] ^ 0x01]))
        bent = subprocess.run(["sh", "verify.sh"], cwd=inside,
                              capture_output=True, text=True)
        check("...and one altered byte in the signature fails it",
              bent.returncode != 0 and "does not verify" in bent.stderr, True)
        (inside / "SHA256SUMS.sig").write_bytes(sig)
        # An unsigned bundle is not a failure; it is said, in one line, never passed
        # over — the checksums still stand and the reader is told what they are worth.
        (inside / "SHA256SUMS.sig").rename(inside / "SHA256SUMS.sig.aside")
        unsigned = subprocess.run(["sh", "verify.sh"], cwd=inside,
                                  capture_output=True, text=True)
        check("...and with no signature at all it passes the sums and says it is unsigned",
              unsigned.returncode == 0 and "not signed" in unsigned.stdout, True)
        (inside / "SHA256SUMS.sig.aside").rename(inside / "SHA256SUMS.sig")
        # A machine with no openssl: the sentence, not a silent pass. PATH emptied of
        # everything but a directory holding `sh`'s needs — the script uses sha256sum
        # or shasum, so one of those must remain reachable.
        bare = out / "bare-path"
        bare.mkdir(exist_ok=True)
        for name in ("sh", "dirname", "sha256sum", "shasum", "sed", "wc", "tr", "grep",
                     "cat", "awk"):
            found = shutil.which(name)
            if found and not (bare / name).exists():
                (bare / name).symlink_to(found)
        without = subprocess.run(["sh", "verify.sh"], cwd=inside, capture_output=True,
                                 text=True, env={**os.environ, "PATH": str(bare)})
        check("...and with no openssl it says the signature was NOT checked",
              without.returncode == 0 and "openssl is not on this machine" in without.stdout,
              True)

        loaded = subprocess.run(["docker", "load", "-i", str(inside / "images.tar.gz")],
                                capture_output=True, text=True)
        check("docker load takes the images", loaded.returncode, 0)
        after = subprocess.run(["sh", "verify.sh", "--loaded"], cwd=inside,
                               capture_output=True, text=True)
        check("verify.sh --loaded: what Docker holds is what MANIFEST names",
              after.returncode == 0 and after.stdout.count("is the image in MANIFEST") == 3,
              True)

        the_far_side(inside)
    finally:
        shutil.rmtree(out, ignore_errors=True)


ESTATE_PROJECT = "carnet_e2e_estate"
ESTATE_HTTP = HTTPS_PORT + 7
ESTATE_HTTPS = HTTPS_PORT + 8


def the_far_side(bundle: pathlib.Path) -> None:
    """`docker compose up -d`, from the bundle, with no --build and nothing to pull.

    The one claim that matters and the one a checklist cannot make. Everything above
    is about the tarball; this is about whether the estate has a working deployment
    afterwards — brought up from the bundle's OWN compose file, against the images
    `docker load` supplied, on a `.env` written the way `docs/OFFLINE.md` says to
    write one. What a connected runner cannot do is pull the cable out, so the
    no-network claim is made the way it can be: compose is asked for images that are
    all present, and its output is read for any attempt to fetch or build.

    It is a second compose project on its own ports, so it neither sees nor disturbs
    the stack the rest of this script is running.
    """
    from carnet.core import crypto

    say("the far side: up from the bundle, no --build, nothing pulled")

    env_path = bundle / "deploy" / ".env"
    values = dict(
        line.split("=", 1) for line in
        (bundle / "deploy" / ".env.example").read_text().splitlines()
        if "=" in line and not line.startswith("#")
    )
    values.update({
        "CARNET_SECRET_KEY": crypto.generate_key(),
        "CARNET_DOMAIN": "localhost",
        # An intranet name's certificate, which is the estate's case: ACME cannot
        # reach a sealed network and `files` would need a CA nobody here has.
        "CARNET_TLS_MODE": "internal",
        # The setting that exists for this environment alone (decision 6): the loaded
        # tag, because a loaded image carries no registry digest to match the pin.
        "CARNET_DB_IMAGE": "postgres:16",
        "CARNET_EGRESS_INTERNAL_HOSTS": "10.0.0.0/8,fd00::/8",
        "CARNET_HTTP_PORT": str(ESTATE_HTTP),
        "CARNET_HTTPS_PORT": str(ESTATE_HTTPS),
        "CARNET_OIDC_ISSUER": "https://idp.corp.example/oauth2/estate",
        "CARNET_OIDC_CLIENT_ID": "carnet-estate",
    })
    env_path.write_text("".join(f"{k}={v}\n" for k, v in values.items()))

    def estate(*args, **kwargs):
        return subprocess.run(
            ["docker", "compose", "-p", ESTATE_PROJECT,
             "-f", str(bundle / "deploy" / "compose.yaml"),
             "--env-file", str(env_path), *args],
            **kwargs,
        )

    try:
        up = estate("up", "-d", capture_output=True, text=True)
        check("docker compose up -d succeeds from the bundle", up.returncode, 0)
        if up.returncode != 0:
            print((up.stdout + up.stderr)[-2000:])
            return
        noise = (up.stdout + up.stderr).lower()
        check("...and nothing was pulled or built on the way",
              [word for word in ("pulling", "building", "manifest unknown",
                                 "pull access denied") if word in noise], [])

        with httpx.Client(verify=False, timeout=15) as client:
            base = f"https://localhost:{ESTATE_HTTPS}"
            check("the estate's front door answers readiness over TLS",
                  wait_for(f"{base}/api/health/ready", client), True)
            health = client.get(f"{base}/api/health").json()
            check("...and serves the version the MANIFEST names",
                  health.get("version"),
                  next(line.split()[1] for line in
                       (bundle / "MANIFEST").read_text().splitlines()
                       if line.startswith("version:")))
            check("the bundle's own SPA is served",
                  client.get(f"{base}/").status_code, 200)
            check("...under a CSP naming the estate's own provider",
                  "https://idp.corp.example" in
                  client.get(f"{base}/").headers.get("content-security-policy", ""),
                  True)
            check("/config.json is the estate's provider, not ours",
                  client.get(f"{base}/config.json").json()["issuer"],
                  "https://idp.corp.example/oauth2/estate")
            # The door is live and refusing, which is the half a sealed estate can
            # check without an identity provider to sign into.
            refused = client.post(f"{base}/api/mcp", json={
                "jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            check("the door answers an unauthenticated call with a challenge",
                  (refused.status_code,
                   "Bearer" in refused.headers.get("www-authenticate", "")),
                  (401, True))

        logs = estate("logs", "migrate", capture_output=True, text=True).stdout
        check("the migration ran before anything served",
              "migration" in logs.lower() or "applied" in logs.lower(), True)
        check("the database is the tag the bundle carried, not a digest",
              subprocess.run(
                  ["docker", "inspect", "-f", "{{.Config.Image}}",
                   estate("ps", "-q", "db", capture_output=True,
                          text=True).stdout.split()[0]],
                  capture_output=True, text=True).stdout.strip(), "postgres:16")
        # ACME is the thing that cannot work here, so it must not have been tried.
        front = estate("logs", "front", capture_output=True, text=True)
        check("no issuer on the internet was contacted for the certificate",
              [word for word in ("acme-v02", "letsencrypt", "zerossl")
               if word in (front.stdout + front.stderr).lower()], [])
    finally:
        estate("down", "-v", "--remove-orphans", "-t", "5",
               capture_output=True, text=True)


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
    # Five since step 121: `setup` joins `migrate` as a one-shot that runs on every
    # `up`. **`idp` is deliberately not in this list** — this world declares no
    # provider, so the `bundled-idp` profile is off and the bundled one does not
    # exist, which is the assertion that a deployment bringing its own identity
    # provider runs nothing extra for the one it did not ask for.
    listed = compose("ps", "-a", "--format", "json", capture_output=True, text=True)
    names = sorted({json.loads(line)["Service"]
                    for line in listed.stdout.splitlines() if line.strip()})
    check("the services after a restart are the door's, and no provider it did not ask for",
          names, ["api", "db", "front", "migrate", "setup"])

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
        for scene in (the_first_five_minutes, the_one_command, the_running_stack,
                      the_sign_in_wiring,
                      the_provider_declaration, the_operators_certificate, the_knobs,
                      the_internal_registry, the_carried_artefact, the_second_coming,
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
