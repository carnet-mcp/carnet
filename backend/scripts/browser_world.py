"""Build a world a browser can sign into, and keep it up. The setup half of the check.

    .venv/bin/python scripts/browser_world.py

Starts three things and blocks:

    127.0.0.1:8902   scripts/dev_idp.py     signs people in without a person
    127.0.0.1:8000   uvicorn                the API, against carnet_browser
    (you)            npm run dev            the SPA on 8080, pointed at the IdP above

It creates its own database and tenant and drops nothing else. The tenant holds:

    issue-reporter   the seeded agent, with `default_task` and `deny_demo_task`.
                     priya is an **editor**, so Edit appears and Delete does not
    team-bot         owned by priya, and reachable by sam **through a group**

That last one is the point. The share sheet's `via` column — *"through g-oncall"*, with no
Remove button beside it — is the state 9a created and nothing has ever rendered, and it is
the one the whole screen exists for: somebody revokes a grant, watches the agent stay
visible through a team, and concludes the revoke failed.

The frontend needs three env vars, printed on startup.
"""

import os
import pathlib
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit, urlunsplit

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_browser"


def _dsn(database: str) -> str:
    """Where Postgres is. The socket this project has used, unless told otherwise.

    `CARNET_E2E_PG` is a base DSN with no database name, and it exists because
    **the machine changed**: this file hardcoded a unix socket that a laptop running
    Postgres in a container does not have, and the failure is a connection error three
    functions into a script whose whole job is to get a browser onto a screen.

    Not a concatenation. A socket DSN carries its host in the query string and a TCP one
    does not, so the database name has to be spliced into the path.
    """
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


DSN = _dsn(DB)
TENANT = "browser"
IDP_PORT = 8902
# Overridable because 8000 is the port everybody's own dev server is already on. Found by
# trying to run this on a machine that had one: the world refused to start, and the check
# it sets up is one this project wants somebody to actually repeat. The frontend follows
# through `VITE_API_ORIGIN`, which vite.config.ts already reads.
API_PORT = int(os.environ.get("BROWSER_WORLD_API_PORT", "8000"))

PEOPLE = {"priya@acme.com": "u_priya", "sam@acme.com": "u_sam"}


def main():
    import psycopg

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import dev_idp

    with psycopg.connect(_dsn("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")

    os.environ["CARNET_DATABASE_URL"] = DSN
    os.environ.setdefault("CARNET_SECRET_KEY", _key())
    # **One worker, deliberately.** This line read `WORKERS = "0"` and had done since
    # 10d, which set a variable **nothing reads** — the name is `CARNET_WORKERS`,
    # and `e2e_edges.py` documents the same trap after a seeded queued run executed
    # during 10d's browser check. So this world has always run a worker, contrary to its
    # own intent, and every screen built against it was built on that accident.
    #
    # Made explicit rather than corrected to 0, because the browser checks **need** one:
    # a conversation with no worker is a page that never leaves "Queued", and 014's
    # thread view is the first screen whose whole subject is a run that finished.
    os.environ["CARNET_WORKERS"] = "1"

    _, provider = dev_idp.serve(IDP_PORT)

    from carnet import bootstrap, storage
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    migrate.apply(DSN)
    store = storage.configure(PostgresStorage(DSN))
    store.create_tenant(TENANT, "Browser check")
    bootstrap.seed_tenant(TENANT)
    store.save_tenant_idp(
        TENANT,
        {
            "issuer": provider.issuer,
            "jwks_uri": f"{provider.issuer}/v1/keys",
            "audience": dev_idp.AUDIENCE,
            # The real org's mapping, not the spec's — see migration 010.
            "subject_claim": "uid",
            "email_claim": "sub",
            "allowed_domains": ("acme.com",),
        },
    )

    # Both people exist before either signs in, so a grant can name them. In production
    # this is what a first login does; here it is the same two rows written directly,
    # because the browser check is about the screens rather than about just-in-time user
    # creation, which `test_api.py` already covers end to end.
    for email, uid in PEOPLE.items():
        store.create_user(
            TENANT,
            {"id": uid, "issuer": provider.issuer, "subject": uid, "email": email},
        )

    # priya can **edit** the seeded agent and does not own it — `--seed` claims ownership
    # itself, and an agent has exactly one owner. That is the pairing the screens need:
    # the Edit button appears and Delete does not.
    store.grant_agent(TENANT, "issue-reporter", "user", "u_priya",
                      role="editor", actor="system:cli")

    # And one she does own, so the delete path is reachable. Created through
    # `create_agent`, which is the route's own method, so the owner grant is real.
    store.create_agent(
        TENANT,
        {
            "name": "team-bot",
            "runtime": "simple",
            "system": "You summarise open issues and post them to the team channel.",
            "model": "claude-haiku-4-5",
            "permissions": {
                "tools": ["post_message"],
                "scope": {"chat.channel": {"write": ["#eng"]}},
            },
            "limits": {"max_calls": 3},
        },
        "user",
        "u_priya",
    )

    # **And sam reaches it only through a group.** No grant row names him, which is the
    # whole state the share sheet's `via` column exists to render.
    store.create_group(TENANT, "g-oncall", "oncall", created_by="system:cli",
                       actor="system:cli")
    store.add_group_member(TENANT, "g-oncall", "user", "u_sam", actor="system:cli")
    store.grant_agent(TENANT, "team-bot", "group", "g-oncall",
                      role="editor", actor="system:cli")
    store.close()

    # `--stub-model` swaps uvicorn for `scripts/api_with_stub_model.py`, which patches
    # the model call in its own process before importing the app. That is what lets the
    # conversation check drive real runs — submit, claim, execute, record, render — with
    # no API key and no spend. The stub lives in `scripts/` and nothing in `src/` knows
    # it exists; see that file for why it is a harness rather than a mode.
    stubbed = "--stub-model" in sys.argv
    command = (
        [sys.executable, str(pathlib.Path(__file__).resolve().parent / "api_with_stub_model.py")]
        if stubbed
        else [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port", str(API_PORT)]
    )
    api = subprocess.Popen(
        command,
        env={**os.environ, "CARNET_TENANT": TENANT, "API_PORT": str(API_PORT)},
        stdout=None if stubbed else subprocess.DEVNULL,
        stderr=None if stubbed else subprocess.DEVNULL,
    )
    _wait(f"http://127.0.0.1:{API_PORT}/health")

    print("world is up.")
    print(f"  api    http://127.0.0.1:{API_PORT}   ({DB}, tenant '{TENANT}')")
    print(f"  idp    {provider.issuer}")
    print(f"  people {', '.join(PEOPLE)}")
    print()
    print("start the frontend with:")
    print(f"  VITE_OIDC_ISSUER={provider.issuer} \\")
    print("  VITE_OIDC_CLIENT_ID=dev VITE_OIDC_SCOPES=openid \\")
    print("  npm run dev")
    sys.stdout.flush()

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        api.terminate()


def _wait(url, seconds=45):
    import httpx

    for _ in range(seconds * 2):
        try:
            httpx.get(url, timeout=1)
            return
        except Exception:
            time.sleep(0.5)
    raise SystemExit(f"{url} never answered")


def _key():
    import base64

    return base64.b64encode(os.urandom(32)).decode()


if __name__ == "__main__":
    main()
