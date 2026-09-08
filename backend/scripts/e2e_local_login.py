"""The local identity provider end to end: register, sign in, be the administrator.

**Not a test, and not the front door either.** `carnet --local` composes this
same world for a person and asserts nothing; this composes it for assertions and
throws it away — the harness/front-door split `DEFERRED.md` requires. What only this
can prove: that a password typed into the provider's own form becomes a token the API
accepts **through the production verification path**, against real Postgres, with the
first account arriving as the first administrator through `CARNET_BOOTSTRAP_ADMIN`.

The arc, in the order a stranger meets it:

    GET  /config.json          how the SPA finds the provider
    GET  /idp/.well-known/openid-configuration
                               ...and how it finds the provider's endpoints
    GET  /idp/register         the first-account page, admin address prefilled
    POST /idp/register         account created, flow finished, code issued
    POST /idp/v1/token         code + PKCE verifier -> a real RS256 token
    GET  /api/me               the token through uvicorn: they are the administrator
    ...and a second person, who is not

    cd backend && .venv/bin/python scripts/e2e_local_login.py

Needs Postgres started first. The database it leaves behind is safe to drop and is
recreated on every run. **Costs nothing**: no run is submitted, no model is called.
"""

import base64
import hashlib
import os
import pathlib
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
from urllib.parse import urlsplit, urlunsplit

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_e2e_local"


def dsn_for(database: str) -> str:
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


DSN = dsn_for(DB)
TENANT = "e2elocal"
ADMIN = "priya@local.test"

EDGE_PORT = 8087
API_PORT = 8006

BASE = f"http://127.0.0.1:{EDGE_PORT}"
REDIRECT = f"http://127.0.0.1:{EDGE_PORT}/login/callback"

CHECKS = []


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((ok, label))
    print(f"{'  ok' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        expected: {expected!r}")
        print(f"        actual:   {actual!r}")
    return ok


def says(label, actual, fragment):
    ok = fragment in str(actual)
    CHECKS.append((ok, label))
    print(f"{'  ok' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        wanted {fragment!r} in: {actual!r}")
    return ok


def step(what):
    print(f"\n=== {what}", flush=True)


def refuse_if_taken(*ports):
    for port in ports:
        with socket.socket() as probe:
            probe.settimeout(0.5)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                raise SystemExit(
                    f"something is already listening on 127.0.0.1:{port}. This script "
                    "starts its own provider and API; stop the other thing or edit the "
                    "port constants."
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


def pkce_pair():
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def flow(challenge, **extra):
    return {
        "client_id": "carnet-local",
        "response_type": "code",
        "redirect_uri": REDIRECT,
        "state": "s-e2e",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        **extra,
    }


def register(httpx, email, password):
    """Register through the form and finish the exchange; returns the bearer token."""
    verifier, challenge = pkce_pair()
    created = httpx.post(
        f"{BASE}/idp/register",
        data={**flow(challenge), "email": email, "password": password},
    )
    if created.status_code != 302:
        return None, created
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(created.headers["location"]).query)
    exchanged = httpx.post(
        f"{BASE}/idp/v1/token",
        data={
            "grant_type": "authorization_code",
            "code": query["code"][0],
            "code_verifier": verifier,
            "redirect_uri": REDIRECT,
            "client_id": "carnet-local",
        },
    )
    return exchanged.json().get("access_token"), created


def main() -> int:
    import httpx
    import psycopg

    refuse_if_taken(EDGE_PORT, API_PORT)

    state = pathlib.Path(tempfile.mkdtemp(prefix="e2e-local-"))
    dist = state / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html><title>app</title>")

    step("a fresh database, migrated, with the provider row the front door would write")
    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")

    os.environ["CARNET_DATABASE_URL"] = DSN
    os.environ.setdefault(
        "CARNET_SECRET_KEY", base64.b64encode(os.urandom(32)).decode()
    )

    from carnet import bootstrap, storage
    from carnet.localidp import accounts
    from carnet.localidp.edge import EdgeConfig, serve
    from carnet.localidp.provider import LocalProvider
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    migrate.apply(DSN)
    store = storage.configure(PostgresStorage(DSN))
    store.create_tenant(TENANT, "Local E2E")
    bootstrap.seed_tenant(TENANT)
    store.save_tenant_idp(
        TENANT, LocalProvider.idp_row(jwks_uri=f"{BASE}/idp/v1/keys")
    )
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

    provider = LocalProvider(state)
    db = accounts.open_db(str(state / "accounts.db"))
    cfg = EdgeConfig(
        host="127.0.0.1",
        port=EDGE_PORT,
        dist_dir=str(dist),
        api_port=API_PORT,
        admin_email=ADMIN,
        redirect_uris=(REDIRECT,),
    )
    edge = serve(cfg, provider, db)

    try:
        wait_for(f"http://127.0.0.1:{API_PORT}/health")

        step("the SPA finds its provider at runtime")
        served = httpx.get(f"{BASE}/config.json")
        # The content type is the assertion, not the status: the defect this whole
        # arrangement exists to prevent answered 200 with `index.html` through a SPA
        # fallback, so "it returned 200" is exactly the evidence that proved nothing.
        check("served as JSON, not swallowed by the SPA fallback",
              served.headers["content-type"].split(";")[0], "application/json")
        config = served.json()
        check("the issuer is origin-relative", config["issuer"], "/idp")
        check("the client id", config["client_id"], "carnet-local")

        step("...and finds the provider's endpoints from its discovery document")
        # Since 031 the app resolves these rather than concatenating Okta-shaped
        # `/v1/*` paths onto the issuer. This is the non-browser half of that;
        # e2e_browser_local.py proves a real browser follows them.
        doc = httpx.get(f"{BASE}/idp/.well-known/openid-configuration")
        check("the discovery document is served", doc.status_code, 200)
        check("...naming the authorize endpoint",
              doc.json()["authorization_endpoint"], "/idp/v1/authorize")
        check("...and the token endpoint", doc.json()["token_endpoint"],
              "/idp/v1/token")

        step("the first-account page knows who it is waiting for")
        page = httpx.get(f"{BASE}/idp/register")
        says("the admin address is prefilled", page.text, ADMIN)
        says("and the page says what the first account becomes", page.text, "becomes the administrator")

        step("the administrator registers, through the form, over real HTTP")
        token, created = register(httpx, ADMIN, "a strong enough password")
        check("register finishes the flow with a redirect", created.status_code, 302)
        says("the session cookie is HttpOnly", created.headers.get("set-cookie", ""), "HttpOnly")
        check("the exchange produced a token", token is not None, True)

        auth = {"Authorization": f"Bearer {token}"}
        me = httpx.get(f"{BASE}/api/me", headers=auth)
        check("the API accepts the token through the production path", me.status_code, 200)
        check("and they are the administrator", me.json().get("admin"), True)
        check("named by their address", me.json().get("email"), ADMIN)

        step("the appointment is in the log, with the bootstrap actor")
        log = httpx.get(f"{BASE}/api/admin-audit", headers=auth)
        check("the log answers an administrator", log.status_code, 200)
        grants = [r for r in log.json() if r.get("action") == "role.grant"]
        check("the grant is recorded", len(grants), 1)
        check(
            "by system:bootstrap",
            (grants[0]["actor_kind"], grants[0]["actor_id"]) if grants else None,
            ("system", "bootstrap"),
        )

        step("the second person registers, and is somebody — not an administrator")
        sam_token, _ = register(httpx, "sam@local.test", "another password")
        sam = {"Authorization": f"Bearer {sam_token}"}
        sam_me = httpx.get(f"{BASE}/api/me", headers=sam)
        check("sam is authenticated", sam_me.status_code, 200)
        check("sam is not an administrator", sam_me.json().get("admin"), False)
        sam_log = httpx.get(f"{BASE}/api/admin-audit", headers=sam)
        check("and the log refuses him", sam_log.status_code, 403)

        step("a wrong password is one sentence, not an oracle")
        _, challenge = pkce_pair()
        wrong = httpx.post(
            f"{BASE}/idp/login",
            data={**flow(challenge), "email": ADMIN, "password": "not it"},
        )
        unknown = httpx.post(
            f"{BASE}/idp/login",
            data={**flow(challenge), "email": "ghost@local.test", "password": "not it"},
        )
        check("wrong password refused", wrong.status_code, 400)
        check("unknown address refused identically", unknown.status_code, 400)
        check(
            "with the same sentence",
            "do not match" in wrong.text and "do not match" in unknown.text,
            True,
        )

        step("the administrator builds an agent through the product")
        draft = {
            "name": "hello-local",
            "system": "You answer briefly.",
            "runtime": "simple",
            "model": "claude-haiku-4-5",
            "permissions": {
                "tools": ["post_message"],
                "scope": {"chat.channel": {"write": ["#local"]}},
            },
            "limits": {"max_calls": 3},
        }
        made = httpx.post(f"{BASE}/api/agents", json=draft, headers=auth)
        check("POST /api/agents through the proxy", made.status_code, 201)
        check(
            "and it is theirs",
            httpx.get(f"{BASE}/api/agents/hello-local", headers=auth).json()["your_role"],
            "owner",
        )

        step("silent renewal works: the session cookie answers prompt=none")
        cookie = created.headers["set-cookie"].split(";")[0]
        _, challenge = pkce_pair()
        silent = httpx.get(
            f"{BASE}/idp/v1/authorize",
            params=flow(challenge, prompt="none"),
            headers={"Cookie": cookie},
        )
        check("a session gets a code without a screen", silent.status_code, 302)
        says("a code, not an error", silent.headers.get("location", ""), "code=")

        step("the signing key persists: a restarted provider honours the old token")
        edge.shutdown()
        edge.server_close()
        edge2 = serve(cfg, LocalProvider(state), accounts.open_db(str(state / "accounts.db")))
        again = httpx.get(f"{BASE}/api/me", headers=auth)
        check("the token from before the restart still answers", again.status_code, 200)
        edge2.shutdown()
        edge2.server_close()

        step("somebody else's local provider is not this one")
        other = LocalProvider(state / "other")
        forged = other.mint({"id": "lu_evil", "email": "evil@local.test", "display_name": ""})
        refused = httpx.get(
            f"http://127.0.0.1:{API_PORT}/me",
            headers={"Authorization": f"Bearer {forged}"},
        )
        check("same issuer, same audience, different keys: 401", refused.status_code, 401)

    finally:
        api.terminate()
        api.wait(timeout=10)
        try:
            edge.shutdown()
        except Exception:
            pass
        shutil.rmtree(state, ignore_errors=True)

    failed = [label for ok, label in CHECKS if not ok]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed.")
    if failed:
        for label in failed:
            print(f"  FAILED: {label}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
