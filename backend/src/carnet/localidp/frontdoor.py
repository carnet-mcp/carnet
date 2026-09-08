"""`carnet --local`: the whole product, one command, one URL.

    cd backend && .venv/bin/carnet --local

First run: asks who the administrator is, generates and persists the encryption key,
initialises a private Postgres cluster (or uses `CARNET_DATABASE_URL` if set),
migrates, seeds the shipped example agent, registers the local identity provider,
builds the frontend if the bundle is missing, starts the API and the edge, and prints
the URL. Second run: reuses all of it — the state directory (`var/local/` by default)
is the deployment.

This is a front door, not a harness. `scripts/e2e_*.py` build worlds in order to
assert about them and drop them; this builds one world in order to hand it to a
person, and asserts nothing. The two must not merge: a harness accretes assertions,
and a front door must accrete nothing.

What the pieces trust each other with, spelled out because it is the point:

  - uvicorn binds loopback only; the network-facing process is the edge, and the API
    is only reachable through its `/api/*` proxy.
  - the API knows nothing of this module. It gets a database URL, a secret key and a
    bootstrap email through the environment — the same three a production deployment
    sets — and verifies tokens through the same path it would verify Okta's.
"""

import base64
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from . import accounts as accounts_db
from .edge import EdgeConfig, serve
from .provider import LocalProvider

BACKEND = Path(__file__).resolve().parents[3]
FRONTEND = BACKEND.parent / "frontend"

DB_NAME = "carnet_local"
TENANT = "default"


def run(parser, args) -> None:
    state = Path(os.environ.get("CARNET_LOCAL_STATE") or "var/local").resolve()
    # Said before anything is created (063): state is CWD-relative, so running from
    # another directory silently starts a NEW deployment — new key, new accounts, the
    # old one's connectors nowhere in sight — and the wrong-directory mistake should
    # announce itself in the first second, not surface as "where did everything go".
    if state.exists() and any(state.iterdir()):
        print(f"front door: using the existing local deployment at {state}")
    else:
        print(
            f"front door: creating a NEW local deployment at {state} — if you meant "
            "an existing one, stop this and run from that deployment's directory "
            "(the state is wherever var/local was created)."
        )
    state.mkdir(parents=True, exist_ok=True)

    settings = _settings(state, args)
    if args.local_fresh:
        _fresh(state, settings)

    # Before the database and the API are brought up: a taken port found *after* them
    # is a traceback on top of half a world, and the commonest cause is a previous
    # `--local` still running — which the sentence should say.
    with socket.socket() as probe:
        probe.settimeout(0.5)
        if probe.connect_ex((settings["host"], settings["port"])) == 0:
            raise SystemExit(
                f"something is already listening on {settings['host']}:"
                f"{settings['port']} — usually a previous `carnet --local` "
                "still running. Stop it, or pass --port."
            )

    secret_key = _secret_key(state)
    dsn, stop_pg = _database(parser, state)

    _prepare_store(dsn, settings)
    _ensure_bundle(parser)

    api_port = _free_port()
    api = _start_api(dsn, secret_key, settings, api_port)

    db = accounts_db.open_db(str(state / "accounts.db"))
    provider = LocalProvider(state)
    cfg = EdgeConfig(
        host=settings["host"],
        port=settings["port"],
        dist_dir=str(FRONTEND / "dist"),
        api_port=api_port,
        registration=settings["registration"],
        admin_email=settings["admin"],
        redirect_uris=_redirect_uris(settings),
        # Secure cookie exactly when a browser reaches this deployment over HTTPS — an
        # `https` public URL (step 052, B3). A plain-http origin must not, or the browser
        # drops the cookie and login silently fails.
        secure_cookie=str(settings.get("public_url", "")).startswith("https://"),
    )
    try:
        _wait_for_api(api, api_port)
        edge = serve(cfg, provider, db)
    except Exception:
        api.terminate()
        if stop_pg:
            stop_pg()
        raise

    # SIGTERM must reach the same cleanup Ctrl-C reaches. Its default is dying on the
    # spot — no finally, so uvicorn is orphaned still holding its port and its
    # database pool. Found as ten zombie APIs and 72 stale sessions after a probe
    # that stopped this process the way systemd and docker stop everything.
    def _terminated(*_):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _terminated)

    _banner(cfg, settings, state)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        edge.shutdown()
        api.terminate()
        api.wait(timeout=10)
        if stop_pg:
            stop_pg()


# --- settings, persisted so the second run is the same deployment ------------------


def _settings(state: Path, args) -> dict:
    path = state / "state.json"
    settings = json.loads(path.read_text()) if path.exists() else {}

    if args.local_admin:
        settings["admin"] = args.local_admin.strip()
    if not settings.get("admin"):
        if not sys.stdin.isatty():
            raise SystemExit(
                "--local needs to know who the first administrator is. Pass "
                "--admin you@example.com (there is no terminal to ask on)."
            )
        settings["admin"] = input(
            "Email address for the first administrator (yours): "
        ).strip()
    # However it arrived — flag, prompt, or an old state file somebody edited. This
    # address is matched against the account the person registers; a typo here is an
    # administrator who never arrives, discovered only by its absence.
    if not accounts_db._EMAIL.match(settings["admin"]):
        raise SystemExit(
            f"{settings['admin']!r} does not look like an email address, and it has "
            "to match the account you will register."
        )

    if args.local_port:
        settings["port"] = args.local_port
    settings.setdefault("port", 8080)
    if args.local_host:
        settings["host"] = args.local_host
    settings.setdefault("host", "127.0.0.1")
    if args.local_public_url:
        settings["public_url"] = _public_origin(args.local_public_url)
    if args.local_registration:
        settings["registration"] = args.local_registration
    # Default closed when this deployment is exposed — a public URL is set, or the bind
    # host is not loopback (step 052, blocker B3) — and open on a loopback trial. An
    # explicit `--registration` above wins, and a value already persisted from a previous
    # run is kept; only a first run with no explicit choice takes this default. The first
    # account is admitted even when closed (edge._register), so an exposed fresh
    # deployment can still appoint its first administrator.
    exposed = bool(settings.get("public_url")) or settings["host"] not in (
        "127.0.0.1",
        "localhost",
    )
    settings.setdefault("registration", "closed" if exposed else "open")

    path.write_text(json.dumps(settings, indent=2) + "\n")
    return settings


def _public_origin(raw: str) -> str:
    """The name a browser elsewhere reaches this deployment at, checked rather than taken.

    An **origin**: scheme, host, optional port, and nothing after it. A path, query or
    fragment here is somebody pasting the address bar of a page rather than the address of
    the deployment, and the two differ in exactly the way that makes sign-in fail later
    with a message about a redirect nobody wrote — `config.py`'s validating-reader
    argument, at the one place where a wrong value cannot be discovered until a second
    person tries to use it.
    """
    from urllib.parse import urlsplit

    parts = urlsplit(raw.strip().rstrip("/"))
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise SystemExit(
            f"--public-url must be an http(s) origin, got: {raw!r}\n"
            "  Example: --public-url https://box.tailnet.ts.net"
        )
    if parts.path or parts.query or parts.fragment:
        raise SystemExit(
            f"--public-url is an origin, not a page: {raw!r} carries a path.\n"
            f"  Use {parts.scheme}://{parts.netloc}"
        )
    return f"{parts.scheme}://{parts.netloc}"


def _fresh(state: Path, settings: dict) -> None:
    print(
        "--fresh drops the local database and every account. Agents, runs, "
        "credentials, users: all of it."
    )
    if input("Type 'fresh' to confirm: ").strip() != "fresh":
        raise SystemExit("nothing dropped.")
    for leftover in state.glob("accounts.db*"):  # the db, and its -wal/-shm
        leftover.unlink()
    # A fresh world with zero accounts and `registration: closed` carried over is a
    # deployment nobody can ever enter — the first account has no way in. Found by
    # the lifecycle probe running --fresh on a state that had been closed.
    if settings.get("registration") == "closed":
        print("Registration was closed; a fresh start reopens it.")
        settings["registration"] = "open"
        (state / "state.json").write_text(json.dumps(settings, indent=2) + "\n")
    settings["_drop_database"] = True


def _secret_key(state: Path) -> str:
    """The encryption key, generated once and persisted with the deployment.

    The production stance is that this key is printed once and the operator owns it
    (`--generate-key`). Here the state directory *is* the deployment, so the key
    lives beside the database it unlocks — the same trust boundary, one directory.
    """
    path = state / "secret.key"
    if not path.exists():
        path.write_text(base64.b64encode(secrets.token_bytes(32)).decode())
        os.chmod(path, 0o600)
    key = path.read_text().strip()

    # **Step 046: say so when the environment's key is not this deployment's.** The
    # deployment itself is fine — it runs under this file, always — but any *other*
    # tool the operator runs against the same database (a provisioning script, a
    # one-off `--connect-account`) reads CARNET_SECRET_KEY from the environment and
    # seals rows this server can then never decrypt. That failure is silent: the
    # connector drops out of tools/list with one log line, and nothing anywhere says
    # why. One warning at startup is the cheapest place to make it loud.
    shadowed = os.environ.get("CARNET_SECRET_KEY", "").strip()
    if shadowed and shadowed != key:
        print(
            "WARNING: CARNET_SECRET_KEY is set in the environment but --local runs "
            f"under its own key ({path}). Anything else you run with that variable — "
            "a script sealing a credential, a CLI --connect-account — will encrypt "
            "rows this deployment cannot read, and the symptom is a connector "
            "quietly missing from tools/list. Unset it, or point your tools at "
            "the deployment's key file.",
            file=sys.stderr,
        )

    return key


# --- the database ------------------------------------------------------------------


def _database(parser, state: Path):
    """A DSN and a stop function. Yours if you set one, otherwise ours.

    The private cluster listens on a unix socket only — no TCP port to collide with
    or to expose — and stops when the front door does.
    """
    if os.environ.get("CARNET_DATABASE_URL"):
        return os.environ["CARNET_DATABASE_URL"], None

    if not shutil.which("initdb") or not shutil.which("pg_ctl"):
        parser.error(
            "--local needs Postgres. Either set CARNET_DATABASE_URL to a "
            "database you run, or install Postgres so its `initdb`/`pg_ctl` are on "
            "PATH (macOS: `brew install postgresql@16` and follow its PATH note)."
        )

    cluster = state / "pg"
    sock = state / "pg-sock"
    sock.mkdir(exist_ok=True)
    log = state / "pg.log"

    if not (cluster / "PG_VERSION").exists():
        print("Initialising a private Postgres cluster (first run only)...")
        subprocess.run(
            ["initdb", "-D", str(cluster), "-U", "postgres", "--auth=trust", "-E", "UTF8"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )

    options = f"-c listen_addresses='' -c unix_socket_directories='{sock}'"
    running = (
        subprocess.run(
            ["pg_ctl", "-D", str(cluster), "status"], capture_output=True
        ).returncode
        == 0
    )
    started_here = False
    if not running:
        subprocess.run(
            ["pg_ctl", "-D", str(cluster), "-o", options, "-l", str(log), "start"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        started_here = True

    def stop():
        subprocess.run(
            ["pg_ctl", "-D", str(cluster), "stop", "-m", "fast"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    return f"postgresql://postgres:@/{DB_NAME}?host={sock}", (stop if started_here else None)


def _split_dsn(dsn: str) -> tuple[str, str]:
    """The database this DSN names, and a maintenance DSN beside it.

    Parsed, never assumed: an operator-supplied `CARNET_DATABASE_URL` names
    whatever database they chose, and the first version — a string-replace of our own
    default name — silently connected maintenance to *their* not-yet-existing
    database and died with a FATAL about it. Found by the lifecycle probe on its
    first externally-configured run.
    """
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(dsn)
    name = parts.path.lstrip("/")
    if not name:
        raise SystemExit(
            "CARNET_DATABASE_URL names no database. End it with /<dbname>."
        )
    maintenance = urlunsplit(
        (parts.scheme, parts.netloc, "/postgres", parts.query, parts.fragment)
    )
    return name, maintenance


def _prepare_store(dsn: str, settings: dict) -> None:
    import psycopg

    from carnet import bootstrap, storage
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    name, maintenance = _split_dsn(dsn)
    with psycopg.connect(maintenance, autocommit=True) as conn:
        if settings.pop("_drop_database", None):
            # FORCE, because the commonest thing still attached is a worker or a
            # previous run's pool that did not die cleanly — and the operator just
            # typed a confirmation whose whole meaning is "drop it anyway". Without
            # it this fails with ObjectInUse, found by the lifecycle probe.
            conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        exists = conn.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s", (name,)
        ).fetchone()
        if not exists:
            conn.execute(f'CREATE DATABASE "{name}"')

    migrate.apply(dsn)
    store = storage.configure(PostgresStorage(dsn))
    created = store.get_tenant(TENANT) is None
    if created:
        store.create_tenant(TENANT, "Local")
        # The shipped example agent, so the first screen is not an empty catalogue.
        # Once, on creation — a real database's contents are the deployment's, and
        # re-seeding on every start would resurrect anything they deleted.
        bootstrap.seed_tenant(TENANT)
    store.save_tenant_idp(
        TENANT,
        LocalProvider.idp_row(
            jwks_uri=f"http://127.0.0.1:{settings['port']}/idp/v1/keys"
        ),
    )
    store.close()


# --- the processes -----------------------------------------------------------------


def bundle_is_stale() -> bool:
    """True when `dist/` is missing or older than any source it was built from.

    A stale bundle is worse than a missing one: it runs, looks right, and lacks the
    change somebody just made — the browser e2e found exactly this, serving a
    two-day-old bundle that still carried the previous auth flow.
    """
    built = FRONTEND / "dist" / "index.html"
    if not built.exists():
        return True
    threshold = built.stat().st_mtime
    sources = [FRONTEND / "index.html", FRONTEND / "vite.config.ts"]
    sources += list((FRONTEND / "src").rglob("*"))
    return any(
        path.stat().st_mtime > threshold for path in sources if path.is_file()
    )


def _ensure_bundle(parser) -> None:
    if not bundle_is_stale():
        return
    if not shutil.which("npm"):
        parser.error(
            "the frontend bundle is missing and npm is not on PATH. Install Node, or "
            "build `frontend/dist` on a machine that has it (`npm ci && npm run "
            "build` in frontend/)."
        )
    print("Building the frontend (first run only; a few minutes)...")
    if not (FRONTEND / "node_modules").exists():
        subprocess.run(["npm", "ci"], cwd=str(FRONTEND), check=True)
    subprocess.run(["npm", "run", "build"], cwd=str(FRONTEND), check=True)


def _start_api(dsn: str, secret_key: str, settings: dict, api_port: int):
    # The origin the API hands out as its own — connector OAuth callbacks are the reader.
    # Under a public name the loopback one is not merely inelegant but wrong: a consent
    # flow would send the provider to an address the person's browser cannot reach.
    origin = settings.get("public_url") or (
        f"http://{'localhost' if settings['host'] == '127.0.0.1' else settings['host']}:{settings['port']}"
    )
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "carnet.api:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(api_port),
        ],
        env={
            **os.environ,
            "CARNET_DATABASE_URL": dsn,
            "CARNET_SECRET_KEY": secret_key,
            "CARNET_TENANT": TENANT,
            "CARNET_BOOTSTRAP_ADMIN": settings["admin"],
            "CARNET_PUBLIC_ORIGIN": f"{origin}/api",
        },
    )


def _wait_for_api(api, api_port: int, seconds: int = 60) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if api.poll() is not None:
            raise SystemExit(
                f"the API exited with code {api.returncode} before it was healthy — "
                "its output is above."
            )
        with socket.socket() as probe:
            probe.settimeout(0.5)
            if probe.connect_ex(("127.0.0.1", api_port)) == 0:
                return
        time.sleep(0.3)
    raise SystemExit("the API never answered on its port.")


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _redirect_uris(settings: dict) -> tuple[str, ...]:
    port = settings["port"]
    uris = {
        f"http://localhost:{port}/login/callback",
        f"http://127.0.0.1:{port}/login/callback",
    }
    if settings["host"] not in ("127.0.0.1", "localhost"):
        uris.add(f"http://{settings['host']}:{port}/login/callback")
    # Step 043, and it ADDS rather than replaces: the operator's own browser is still on
    # localhost while a colleague is on the public name, and a list that swapped one for
    # the other would break the operator at the moment they configured somebody else.
    if settings.get("public_url"):
        uris.add(f"{settings['public_url']}/login/callback")
    return tuple(sorted(uris))


def _banner(cfg: EdgeConfig, settings: dict, state: Path) -> None:
    warning = ""
    if settings["host"] != "127.0.0.1":
        warning = f"""
  ! This is bound to {settings['host']}, not loopback. Everything — passwords,
  ! tokens, run output — crosses the network in PLAIN HTTP. Put a TLS reverse
  ! proxy in front of it before anybody you do not trust shares the network,
  ! and consider `--registration closed` once your team has accounts.
"""
    public = ""
    if settings.get("public_url"):
        closing = (
            "  Registration is OPEN, so anyone with this link can create an account.\n"
            "  ! Close it once the people you meant to invite have registered:\n"
            "  !     carnet --local --registration closed\n"
            if settings["registration"] == "open"
            else "  Registration is closed: the link reaches a sign-in screen and no more.\n"
        )
        public = f"""
  SEND THEM THIS:  {settings['public_url']}
  (this machine has to stay awake — the deployment is only up while it is)
{closing}"""

    print(
        f"""
================================================================================
  OPEN THIS:   {cfg.origin}
================================================================================
{public}
  Sign in with an account you create on the way in. The first account —
  {settings['admin']}, per your answer — becomes the administrator.
{warning}
  What this is: the product, plus a local identity provider this machine runs.
  The API verifies its tokens exactly as it would verify Okta's — same code,
  same checks. What it is not: a bypass. There is no way to a token but a
  password this provider checked.

  Registration is {settings['registration']}. State lives in {state} — copy it to
  keep the deployment, delete it (or run --fresh) to start over.
  Reset a password:  python -m carnet.localidp --reset-password EMAIL

  Ctrl-C stops everything; the data stays.
================================================================================
""",
        flush=True,
    )
