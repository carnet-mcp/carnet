"""The HTTP entry point.

    uvicorn carnet.api:app

## `def`, never `async def`

FastAPI is async-first and this runtime is synchronous end to end. The whole of the
accommodation is one rule:

    **Every endpoint function is `def`, not `async def`.**

FastAPI runs a `def` endpoint in a threadpool, so the synchronous broker stays
synchronous and nothing below this package learns that a web framework exists. An
`async def` endpoint calling `broker.call` would block the event loop, and the failure
mode is not a slow request — it is the whole server stopping under load while every
individual piece looks fine.

`tests/test_api.py` asserts this by walking the route table. A rule that lives only in
a docstring is a rule somebody breaks in six months, and this one is invisible until
production.

## What this package is, and what it is not

It is an **entry point**, the same kind of thing as `cli.py`: it establishes a
`Principal`, calls down, and formats what comes back. It may compose layers — that is
what entry points are for — but it must not reach into them.

Nothing here touches `permissions.py`, `patterns.py`, `limits.py`, or the signature of
`broker.call`. That bet has now won four times: tenancy cost the broker one line, the
MCP connector cost it none, the HTTP transport cost it none, and this cost it none. If
a future change to this package needs the policy engine to move, the seam was not what
it claimed to be.

## The threadpool is the reason for the rest of this step

A threadpool means more than one thread, and this server is the first thing in the
project's life to run two of anything. The session pool, the bound tool registry, the
database connection and the in-memory store were all written for a single-threaded
loop. That work is in `tools/mcp/client.py`, `tools/__init__.py`, `storage/postgres.py`
and `storage/memory.py`, and `tests/test_concurrency.py` is what holds it in place.
"""

import json
import logging
import sys
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

from .. import __version__, bootstrap, config, maintenance, storage
from ..access import oauth_server
from ..core import audit
from ..storage import tenancy
from ..tools import mcp
from . import (
    errors,
    routes_admin,
    routes_admin_connectors,
    routes_agents,
    routes_connections,
    routes_groups,
    routes_mcp,
    routes_oauth,
    routes_openai,
    routes_tools,
)
from .schemas import Health, Ready

log = logging.getLogger(__name__)


class SessionPruner:
    """Sweeps expired MCP sessions on a timer, for as long as the process lives.

    The pool already evicts opportunistically, on every `get` and `put`. That covers a
    busy server completely — and an idle one not at all, which is precisely the case
    the TTL was added for. A connector nobody has touched since Tuesday is only
    retired by something that goes looking for it, and on a quiet server nothing does.

    A daemon thread rather than an async task, because the pool it sweeps is
    synchronous and closing a session terminates a subprocess. Started and stopped by
    the lifespan, so a test can build the app without acquiring a background thread.
    """

    def __init__(self, pool, interval: float):
        self._pool = pool
        self._interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._loop, name="mcp-session-prune", daemon=True
        )
        self._thread.start()

    def _loop(self) -> None:
        # `wait` rather than `sleep`: shutdown does not have to outlast one interval.
        while not self._stop.wait(self._interval):
            self.sweep_once()

    def sweep_once(self) -> int:
        try:
            retired = self._pool.prune()
        except Exception:  # noqa: BLE001 - a sweep must never kill the thread
            log.exception("session prune failed")
            return 0
        if retired:
            log.info("retired %d idle MCP session(s)", retired)
        return retired

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)


class LogMaintainer:
    """Keeps the log tables writable and the retention window enforced. Step 060.

    `maintenance.sweep_log_tables` — partitions extended past the horizon, retention
    pruned — on the serving process, which every deployment has. Before step 060 it
    ran on a process the shipped deployment did not start, and an API that outlived
    the three-month partition horizon met `missing_partition` on the audit append
    *after* a call had run.

    Started in every API process, deliberately: the sweep is idempotent,
    `ensure_log_partitions` takes an advisory lock, and "is some other process doing
    this?" is exactly the topology question a maintenance loop must not depend on.
    `SessionPruner`'s shape otherwise — a daemon thread the lifespan starts and stops,
    whose sweep never kills its own loop.
    """

    def __init__(self, interval: float):
        self._interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._loop, name="log-maintenance", daemon=True
        )
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            self.sweep_once()

    def sweep_once(self) -> dict:
        swept: dict = {}
        try:
            swept = maintenance.sweep_log_tables()
        except Exception:  # noqa: BLE001 - a sweep must never kill the thread
            log.exception("log maintenance failed")
        # 083. Expired authorization codes and never-consented client registrations —
        # the two things an unauthenticated caller can leave behind. On this loop
        # because it is the one every deployment runs, and separately guarded so a
        # failure here cannot cost the partitions above their sweep.
        try:
            swept["oauth"] = oauth_server.sweep()
        except Exception:  # noqa: BLE001
            log.exception("oauth sweep failed")
        return swept

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)


class JsonLogFormatter(logging.Formatter):
    """One object per line, for a log pipeline. Step 057.

    Five fields, stdlib only — a logging dependency for five fields would be the
    code-for-sport trade `pyproject.toml` declines in the other direction. `default=str`
    so an unserializable argument degrades to its repr instead of killing the log line,
    which is the one failure a formatter must never have.
    """

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def configure_logging(level: int | None = None) -> None:
    """Set up logging for the server process.

    Done by the entry point and nowhere else — a library that calls `basicConfig`
    steals logging from whatever embeds it. `cli.py` configures its own, differently,
    and neither has to know about the other.

    Level and format come from `CARNET_LOG_LEVEL` / `CARNET_LOG_FORMAT` (step
    057), validated in `config.py` so a typo refuses at import instead of silently
    meaning `info`. The scope stays the `carnet` logger: uvicorn's loggers belong
    to uvicorn, and stealing them would be `basicConfig`'s sin with a narrower alibi.
    """
    handler = logging.StreamHandler()
    handler.setFormatter(
        JsonLogFormatter()
        if config.LOG_FORMAT == "json"
        else logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    )
    logger = logging.getLogger("carnet")
    logger.handlers[:] = [handler]
    logger.setLevel(
        level if level is not None else getattr(logging, config.LOG_LEVEL.upper())
    )
    logger.propagate = False

    # Step 096: the audit line. Its own handler on stdout with a bare `%(message)s`
    # formatter — the message already IS the JSON object — and no propagation, so
    # the line never passes through the wrapper above in either format. Off means a
    # NullHandler rather than no handler: `logging`'s last-resort handler would
    # otherwise catch the records, and a setting that means "silent" must be silent.
    line = logging.getLogger(audit.AUDIT_LOGGER)
    line.propagate = False
    line.setLevel(logging.INFO)
    if config.AUDIT_STDOUT:
        sink = _StdoutHandler()
        sink.setFormatter(logging.Formatter("%(message)s"))
        line.handlers[:] = [sink]
    else:
        line.handlers[:] = [logging.NullHandler()]


class _StdoutHandler(logging.StreamHandler):
    """A `StreamHandler` that resolves `sys.stdout` at emit time, not at construction.

    `StreamHandler(sys.stdout)` captures the object that was `sys.stdout` when the
    lifespan started, and anything that swaps the stream afterwards — a test's capture,
    an operator's redirect — is missed for the life of the process. The audit line's
    whole contract is *stdout, now*, so it asks for the current one on every record.
    """

    def __init__(self):
        super().__init__(stream=None)

    @property
    def stream(self):
        return sys.stdout

    @stream.setter
    def stream(self, value):
        # `StreamHandler.__init__` assigns; the assignment is deliberately ignored.
        pass


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Start-up and shut-down, once per process.

    `async` because that is the interface Starlette offers; it does no I/O of its own
    and awaits nothing. The endpoints are what must stay `def`.

    Storage is configured here rather than per request, and **not seeded** when a real
    database is present: its contents are the customer's, and overwriting them every
    time a server restarts would be astonishing. Same rule the CLI follows.

    The encryption key is **required here regardless of the store**, which is stricter
    than the CLI. A server is multi-user, and acting as the person who asked is the
    reason it exists — so a server that comes up unable to read a delegated credential
    is one that will refuse somebody's call later for a reason nobody configured. It
    raises, and a lifespan that raises is a server that does not start, which is the
    intended outcome: this is a startup failure with a one-line fix, not an outage.
    """
    configure_logging()

    # `bootstrap.configure` also verifies that tenant scoping can work against this
    # database and refuses to return a store when it cannot (step 029) — at startup,
    # not at first use, which is `configure_crypto`'s argument applied to the second
    # thing a misconfigured deployment gets silently wrong.
    bootstrap.configure(seed=not config.DATABASE_URL)
    # Step 095: the fileborne door does not need the key. The argument above — a
    # server is multi-user and a `connections` row may be written at any moment — is
    # false of it in both halves: nobody signs in, no route can seal a credential
    # without a `user` principal, and the store dies with the process. A required
    # variable protecting nothing is one more line in a `docker run` that 094 wants
    # under five minutes. Every database deployment keeps the requirement exactly.
    bootstrap.configure_crypto(required=not config.CARNET_FILE)
    if config.CARNET_FILE:
        log.info("storage: %s (in-memory, not durable)", config.CARNET_FILE)
    else:
        log.info(
            "storage: %s",
            "postgres" if config.DATABASE_URL else "in-memory (not durable)",
        )

    pruner = SessionPruner(mcp.POOL, config.MCP_SESSION_PRUNE_INTERVAL)
    pruner.start()

    # Step 060: partitions and retention, on the process every deployment has. One
    # sweep immediately, so a deployment restarted after months away is writable
    # before the first request rather than within the hour.
    maintainer = LogMaintainer(config.RETENTION_SWEEP_INTERVAL)
    maintainer.sweep_once()
    maintainer.start()

    # Step 108, decision 14. Every route is sync `def`, so one open model stream is one
    # thread in this pool for the life of the completion, and Starlette's default of
    # forty would cap a company at forty engineers mid-completion. Set here rather than
    # at import because the limiter belongs to the running loop, which is what a
    # lifespan is. The 201st stream waits for a thread rather than being refused.
    import anyio

    anyio.to_thread.current_default_thread_limiter().total_tokens = config.THREADS

    try:
        yield
    finally:
        pruner.stop()
        maintainer.stop()
        # Sessions hold subprocesses and open connections. Neither belongs to a
        # request, so neither gets cleaned up by one ending.
        mcp.POOL.reset()
        store = storage.active() if _storage_configured() else None
        if store is not None and hasattr(store, "close"):
            store.close()
        storage.reset()


def _storage_configured() -> bool:
    try:
        storage.active()
    except storage.StorageError:
        return False
    return True


class TenantScopeMiddleware:
    """Install an empty tenant scope for each request. Step 029.

    Pure ASGI, and it must be: the cell has to be set in the request's own task
    context, on the event loop, *before* FastAPI copies that context into a threadpool
    for each `def` dependency and endpoint. Those copies share the cell by reference,
    which is what lets `principal_from_request` (one thread) bind a tenant that
    `_connection()` (another thread) can read. Setting the ContextVar inside the
    dependency instead would land in that dependency's private copy and vanish —
    the exact silent failure `tenancy.py`'s docstring narrates.

    The middleware knows no tenant and reads no storage; it only makes a place for the
    dependency to put one. A request that never authenticates (`/health`, the docs,
    a refused bearer) leaves the cell empty and every borrow unscoped.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            tenancy.begin_request()
        await self.app(scope, receive, send)


def create_app() -> FastAPI:
    app = FastAPI(
        title="carnet",
        description=(
            "Brokered tool-use runtime. The agent holds no tool credentials and "
            "cannot call a tool directly; every call goes through the broker, which "
            "checks permissions, supplies the credential, executes, and audits."
        ),
        # `__version__`, at last: this was a literal, went stale at 0.4.0, and the 029
        # handoff flagged it. /health always answered from `__version__`; now the
        # OpenAPI document agrees with it.
        version=__version__,
        lifespan=lifespan,
    )

    app.add_middleware(TenantScopeMiddleware)
    errors.install(app)
    routes_openai.install(app)
    app.include_router(routes_agents.router)
    app.include_router(routes_tools.router)
    app.include_router(routes_connections.router)
    # 12b. Two routers rather than one: `routes_groups` is a resource, and
    # `routes_admin` is the administrative surface itself — `/me` and the log. They
    # are separate files because 12c adds vetting and consent configuration to the
    # second and nothing to the first.
    #
    # **12c made that a third file rather than a bigger second one**, which is worth
    # recording because the line above predicted otherwise. `routes_admin` is `/me` and
    # the log: two routes, both read-only, and a docstring about what an administrative
    # log is for. Connector onboarding is ten routes that dial third parties, seal
    # secrets and write vetting records, and folding it in would have left a file whose
    # docstring described a tenth of it. The prediction was about *which surface* grows,
    # and it was right about that.
    app.include_router(routes_groups.router)
    # 033b. The outward door: this API speaking MCP rather than consuming it. Its own
    # file because it is the only router here that answers a
    # protocol instead of a resource, so "every endpoint is one JSON-RPC method" is a
    # file-level fact a reader can point at rather than one route's quirk inside
    # another. Note what it is *not*: a second enforcement path. It authenticates
    # through `principal_from_request` like everything above it and calls the same
    # broker, which is the whole reason decision 4 could say a door is one route.
    app.include_router(routes_mcp.router)
    app.include_router(routes_openai.router)
    # 083. The door as an OAuth resource server: the two `.well-known` documents,
    # registration, consent and the exchange. Its own file because four of its routes
    # carry no principal — see `deps.OPEN_SURFACE` — and a file whose docstring says
    # so is easier to audit than four exceptions spread across resource routers.
    app.include_router(routes_oauth.router)
    app.include_router(routes_admin.router)
    app.include_router(routes_admin_connectors.router)

    @app.get("/health", response_model=Health, tags=["meta"])
    def health() -> Health:
        """Liveness. No auth, no storage read — it must answer when they are broken.

        The version comes from the imported module attribute, so it costs no read and
        keeps that promise intact.
        """
        return Health(
            status="ok",
            storage="configured" if _storage_configured() else "unconfigured",
            version=__version__,
        )

    @app.get("/health/ready", response_model=Ready, tags=["meta"])
    def ready() -> Ready:
        """Readiness. One real database round trip — route around me when this fails.

        `/health` above is the liveness half and deliberately reads nothing (restart
        me when *that* fails); this is the sibling that touches the ground, step 056.
        The 503 carries the store's own sentence, which for the deployment mistakes
        `_connection` tells apart includes the remedy, not just the fact. No auth,
        like its sibling: the things that read probes hold no tokens.
        """
        try:
            storage.active().ping()
        except storage.StorageError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return Ready(
            status="ready",
            storage="postgres" if config.DATABASE_URL else "memory",
        )

    return app


app = create_app()

__all__ = [
    "LogMaintainer",
    "SessionPruner",
    "app",
    "configure_logging",
    "create_app",
    "lifespan",
]
