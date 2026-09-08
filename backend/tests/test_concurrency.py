"""What a second thread breaks.

Everything in this file passes trivially in a single-threaded process, which is why
none of it existed before there was a server. A threadpool-backed HTTP layer is the
first thing in this project's life to run two of anything at once, and four pieces of
process-global state were written on the assumption that nothing would.

The important property of these tests is that **they fail loudly against the code as it
was**. A concurrency bug that only shows up as a flaky test under load is one somebody
reruns CI over; the point of driving real threads through the real objects here is to
turn that into a red build.

The sharpest case is the first one. Two threads sharing one MCP session do not merely
race — they cross each other's replies, and the loser is recorded in the audit log as a
write that *may have taken effect and needs a person*. That is the one lie the whole
delivered/ambiguous mapping from step 003 exists to prevent, and it would have been
reintroduced by the transport layer being fine and the layer above it being shared.
"""

import json
import os
import queue
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from carnet import storage, tools
from carnet.tools import mcp
from carnet.tools.base import Resource, Tool
from carnet.tools.mcp.binding import Connector, StdioLaunch, Vetted
from carnet.tools.mcp.client import Session, SessionPool
from carnet.tools.mcp.transport import TransportError

from conftest import TEST_ACTOR, TEST_TENANT

THREADS = 8

# A connector small enough to reason about. The shipped GitHub manifest would work
# too, and would couple this file to whatever it vets next.
CONNECTOR = Connector(
    id="fake",
    launch=StdioLaunch(command=("/bin/true",), credential_env="FAKE_TOKEN"),
    vetted=(
        Vetted("echo", effect="read", resources=(Resource("fake.thing", "thing"),)),
    ),
)

ADVERTISED = [
    {
        "name": "echo",
        "description": "Echoes its arguments.",
        "inputSchema": {
            "type": "object",
            "properties": {"thing": {"type": "string"}},
            "required": ["thing"],
        },
    }
]


def _run(target, count=THREADS):
    """Start `count` threads on `target(n)`, wait, and return nothing.

    Deliberately not a ThreadPoolExecutor: its `submit` swallows exceptions into
    futures nobody reads, and a test that passes because the failure was captured in an
    object it never inspects is worse than no test.
    """
    threads = [threading.Thread(target=target, args=(n,)) for n in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert not [t for t in threads if t.is_alive()], "a worker thread hung"


class PipeTransport:
    """One outbound stream, one shared inbox, replies matched by id.

    This is the shape of `StdioTransport`, which is what makes it a fair test rather
    than a convenient one: a single queue, and a reader that **discards** any message
    whose id is not the one it is waiting for. That discard rule is correct while one
    thread owns the pipe — it is how server-initiated notifications get ignored — and
    it is the exact mechanism by which two threads destroy each other's replies.

    Answers all three transport methods, explicitly, for the reason the real ones do.
    """

    def __init__(self, delay=0.004):
        self._inbox: queue.Queue = queue.Queue()
        self._delay = delay
        self.protocol_version = None
        self.closed = False
        self.sends = 0
        self.concurrent = 0
        self.max_concurrent = 0
        self._counters = threading.Lock()

    def send(self, message):
        with self._counters:
            self.sends += 1
            self.concurrent += 1
            self.max_concurrent = max(self.max_concurrent, self.concurrent)
        try:
            if "id" not in message:
                return None

            # The server writes its reply into the one stream both threads read from.
            self._inbox.put(
                {"jsonrpc": "2.0", "id": message["id"], "result": _reply_for(message)}
            )
            # Widen the window. Without this the GIL hides the race often enough that
            # the test would be the flaky thing it exists to prevent.
            time.sleep(self._delay)
            return self._await(message["id"])
        finally:
            with self._counters:
                self.concurrent -= 1

    def _await(self, message_id):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                reply = self._inbox.get(timeout=0.05)
            except queue.Empty:
                continue
            if reply.get("id") == message_id:
                return reply
            # Not ours. Dropped, exactly as StdioTransport drops it.
        raise TransportError(f"no reply for {message_id}", delivered=True)

    def set_protocol_version(self, version):
        self.protocol_version = version

    def close(self):
        self.closed = True


def _reply_for(message):
    method = message["method"]
    if method == "initialize":
        return {"protocolVersion": "2025-06-18", "serverInfo": {"name": "fake"}}
    if method == "tools/list":
        return {"tools": ADVERTISED}
    if method == "tools/call":
        arguments = (message.get("params") or {}).get("arguments") or {}
        # Echoed back, so a caller can prove it received *its own* reply rather than
        # merely receiving one.
        return {"content": [{"type": "text", "text": json.dumps(arguments)}]}
    return {}


class FakeSession:
    """Something the pool can hold and close. It never speaks a protocol."""

    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


# --- the session itself ----------------------------------------------------------


def test_one_shared_session_routes_every_reply_to_its_own_caller():
    """The test this step exists for.

    Eight threads, one pooled session, eight distinct arguments. Each thread must get
    back what it sent. Unlocked, a thread reads a reply belonging to another, discards
    it as not-its-id, and both end up wrong — one times out into a `delivered=True`
    transport error, which the broker records as `outcome="unknown"`.
    """
    transport = PipeTransport()
    session = Session(transport)
    session.initialize()

    results: dict = {}
    lock = threading.Lock()

    def worker(n):
        result = session.call_tool("echo", {"marker": str(n)})
        with lock:
            results[n] = result

    _run(worker)

    assert results == {n: {"marker": str(n)} for n in range(THREADS)}
    assert transport.max_concurrent == 1, "two threads were inside one transport at once"


def test_request_ids_are_never_reused_under_concurrency():
    """`_next_id` is a read-modify-write. Two threads can take the same id, and two
    live requests with one id is a reply that legitimately matches the wrong caller —
    undetectable from either end."""
    transport = PipeTransport(delay=0.001)
    session = Session(transport)
    session.initialize()

    seen: list = []
    lock = threading.Lock()
    original = transport.send

    def recording_send(message):
        if "id" in message:
            with lock:
                seen.append(message["id"])
        return original(message)

    transport.send = recording_send

    _run(lambda n: session.call_tool("echo", {"marker": str(n)}))

    assert len(seen) == len(set(seen)), f"duplicate request ids: {sorted(seen)}"


# --- the pool --------------------------------------------------------------------


def test_concurrent_connects_build_exactly_one_session(monkeypatch, isolated_storage):
    """Check-then-set builds two sessions and keeps one. The other is a live
    subprocess with no handle left pointing at it."""
    tools.save_connector(TEST_TENANT, CONNECTOR, actor=TEST_ACTOR)
    connector = mcp.get_connector(TEST_TENANT, "fake")

    built: list = []
    lock = threading.Lock()

    def transport_for(_tenant_id, _connector, _credential):
        with lock:
            built.append(_connector.id)
        # A real one costs a container start; this costs enough to overlap.
        time.sleep(0.02)
        return PipeTransport()

    monkeypatch.setattr(mcp, "_transport_for", transport_for)

    _run(lambda n: mcp.connect(TEST_TENANT, connector, "shared-token"))

    assert built == ["fake"], f"built {len(built)} sessions for one connector"


def test_two_tenants_never_share_a_session(monkeypatch, isolated_storage):
    """The existing tenancy property, now under threads. A live session is bound to
    the manifest it was bound against; sharing one across tenants would serve a
    customer an allowlist they never approved."""
    store = storage.active()
    for tenant in ("acme", "globex"):
        store.create_tenant(tenant, tenant)
        tools.save_connector(tenant, CONNECTOR, actor=TEST_ACTOR)

    monkeypatch.setattr(mcp, "_transport_for", lambda tenant, c, cred: PipeTransport())

    def worker(n):
        tenant = "acme" if n % 2 == 0 else "globex"
        mcp.connect(tenant, mcp.get_connector(tenant, "fake"), "same-token")

    _run(worker)

    acme = mcp.POOL.get("acme", "fake", "same-token")
    globex = mcp.POOL.get("globex", "fake", "same-token")
    assert acme is not None and globex is not None
    assert acme is not globex


def test_an_idle_session_is_evicted_and_closed():
    """A CLI exited and took its sessions with it. A server does not, so a connector
    nobody has used since Tuesday is a container still running."""
    pool = SessionPool(idle_ttl=0.05, max_size=10)
    session = FakeSession()
    pool.put("t", "fake", None, session)

    assert pool.get("t", "fake", None) is session

    time.sleep(0.08)

    assert pool.prune() == 1
    assert session.closed is True
    assert pool.get("t", "fake", None) is None


def test_an_idle_server_actually_sweeps():
    """The pool evicts on `get` and `put`, which covers a busy server and not an idle
    one — and an idle server is the case the TTL exists for. Without something on a
    timer, a session nobody touches again is held forever by the eviction policy that
    was supposed to retire it.

    Driven a step at a time rather than by waiting on the thread, so the assertion is
    about the sweep and not about whether a sleep was long enough.
    """
    # Both extras: importing `carnet.api` pulls in `access/`, which needs
    # PyJWT. Guarding only on fastapi passes the check and then fails on the
    # import, which is how the Postgres CI job went red.
    pytest.importorskip("fastapi", reason="install the 'api' extra to run this")
    pytest.importorskip("jwt", reason="install the 'access' extra to run this")
    from carnet.api import SessionPruner

    pool = SessionPool(idle_ttl=0.05, max_size=10)
    session = FakeSession()
    pool.put("t", "fake", None, session)

    pruner = SessionPruner(pool, interval=3600)  # never fires on its own

    assert pruner.sweep_once() == 0, "retired a session that was not yet idle"
    time.sleep(0.08)
    assert pruner.sweep_once() == 1
    assert session.closed is True


def test_the_pruner_starts_and_stops_with_the_process():
    # Both extras: importing `carnet.api` pulls in `access/`, which needs
    # PyJWT. Guarding only on fastapi passes the check and then fails on the
    # import, which is how the Postgres CI job went red.
    pytest.importorskip("fastapi", reason="install the 'api' extra to run this")
    pytest.importorskip("jwt", reason="install the 'access' extra to run this")
    from carnet.api import SessionPruner

    pool = SessionPool(idle_ttl=0.02, max_size=10)
    session = FakeSession()
    pool.put("t", "fake", None, session)

    pruner = SessionPruner(pool, interval=0.01)
    pruner.start()
    try:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not session.closed:
            time.sleep(0.01)
    finally:
        pruner.stop()

    assert session.closed is True, "the background sweep never ran"
    assert pruner._thread is not None and not pruner._thread.is_alive()


def test_a_failing_sweep_does_not_kill_the_thread():
    """A sweep that raises must not silently end idle eviction for the process."""
    # Both extras: importing `carnet.api` pulls in `access/`, which needs
    # PyJWT. Guarding only on fastapi passes the check and then fails on the
    # import, which is how the Postgres CI job went red.
    pytest.importorskip("fastapi", reason="install the 'api' extra to run this")
    pytest.importorskip("jwt", reason="install the 'access' extra to run this")
    from carnet.api import SessionPruner

    class _Exploding:
        def prune(self):
            raise RuntimeError("boom")

    pruner = SessionPruner(_Exploding(), interval=3600)

    assert pruner.sweep_once() == 0
    assert pruner.sweep_once() == 0


def test_use_keeps_a_session_alive():
    """The TTL is idle time, not age. A connector in constant use is not retired for
    having been started first."""
    pool = SessionPool(idle_ttl=0.15, max_size=10)
    session = FakeSession()
    pool.put("t", "fake", None, session)

    for _ in range(4):
        time.sleep(0.05)
        assert pool.get("t", "fake", None) is session

    assert session.closed is False


def test_the_pool_is_capped_and_evicts_least_recently_used():
    """With delegated credentials the key space is per user, so an unbounded pool is
    one subprocess per person who ever ran anything."""
    pool = SessionPool(idle_ttl=0, max_size=2)
    first, second, third = FakeSession(), FakeSession(), FakeSession()

    pool.put("t", "a", None, first)
    pool.put("t", "b", None, second)
    pool.get("t", "a", None)  # touch: `first` is now the most recent
    pool.put("t", "c", None, third)

    assert second.closed is True, "evicted the wrong one — cap is LRU, not FIFO"
    assert first.closed is False and third.closed is False
    assert pool.get("t", "b", None) is None
    assert pool.get("t", "a", None) is first
    # Counted, because the cap is an invented number and an eviction is otherwise
    # silent — it costs the next caller a handshake and raises no error, so a pool a
    # tenth the size it should be is indistinguishable from a slow server.
    assert pool.overflow_evictions == 1


def test_a_pool_under_its_cap_never_reports_an_eviction():
    """The counter has to mean something, so it must not tick on TTL expiry or on an
    explicit evict — only on being over capacity, which is the one the number fixes."""
    pool = SessionPool(idle_ttl=0, max_size=4)

    pool.put("t", "a", None, FakeSession())
    pool.put("t", "b", None, FakeSession())
    pool.evict("t", "a", None)

    assert pool.overflow_evictions == 0


def test_concurrent_pool_writes_lose_nothing():
    pool = SessionPool(idle_ttl=0, max_size=1000)
    sessions = {n: FakeSession() for n in range(THREADS * 4)}

    _run(
        lambda n: [
            pool.put("t", f"c{n}-{i}", None, sessions[n * 4 + i]) for i in range(4)
        ],
        count=THREADS,
    )

    live = [s for s in sessions.values() if not s.closed]
    assert len(live) == len(sessions)


# --- the bound registry ----------------------------------------------------------


def _tool(name):
    return Tool(
        name=name,
        description="x",
        input_schema={"type": "object", "properties": {"thing": {"type": "string"}}},
        impl=lambda **kw: {},
        effect="read",
        resources=(Resource("fake.thing", "thing"),),
        connector="fake",
    )


def test_concurrent_registration_loses_nothing(isolated_storage):
    """`_BOUND.setdefault` followed by an item assignment is safe on CPython by
    accident. Resting a tenant boundary on that is not the same as it being correct."""
    _run(lambda n: tools.register(TEST_TENANT, _tool(f"fake_t{n}")))

    for n in range(THREADS):
        assert tools.get(f"fake_t{n}", TEST_TENANT) is not None


def test_two_tenants_registering_at_once_stay_separate(isolated_storage):
    store = storage.active()
    for tenant in ("acme", "globex"):
        store.create_tenant(tenant, tenant)

    def worker(n):
        tenant = "acme" if n % 2 == 0 else "globex"
        tools.register(tenant, _tool(f"fake_{tenant}_{n}"))

    _run(worker)

    for n in range(THREADS):
        tenant = "acme" if n % 2 == 0 else "globex"
        other = "globex" if tenant == "acme" else "acme"
        name = f"fake_{tenant}_{n}"
        assert tools.get(name, tenant) is not None
        assert tools.get(name, other) is None, "a tool leaked across tenants"


# --- storage ---------------------------------------------------------------------


def test_in_memory_storage_survives_concurrent_writers():
    """The fake must not be less safe than the real implementation. A contract suite
    that runs the same assertions against both is worth nothing if the two disagree
    about whether they can be called from two threads."""
    store = storage.InMemoryStorage()
    store.create_tenant("t", "T")

    def worker(n):
        for i in range(20):
            store.save_agent("t", {"name": f"a{n}-{i}", "system": "s"}, actor="system:cli")
            store.append_audit(
                "t",
                {
                    "v": 5,
                    "ts": "2026-08-02T00:00:00.000+00:00",
                    "run_id": f"r{n}",
                    "principal_kind": "system",
                    "principal_id": "test",
                    "agent": f"a{n}",
                    "tool": "post_message",
                    "decision": "allow",
                },
            )

    _run(worker)

    assert len(store.load_agents("t")) == THREADS * 20
    assert len(store.audit_records("t")) == THREADS * 20


def test_four_processes_migrating_at_once_is_one_migration_and_three_waits():
    """Two replicas booting together both run `--migrate`. 027's testing pass.

    The **data** was never at risk — each migration is its own transaction, so the
    losers rolled back whole. The *operator* was: three of four died on
    `pg_type_typname_nsp_index`, a Postgres catalog index, which tells somebody
    debugging a failed deploy exactly nothing about migrations. An advisory lock held
    across the read and the writes turns that into three processes waiting and then
    finding nothing to do, which is what a rolling deploy needs to survive.

    Its own database, because the whole point is racing an empty one to head.
    """
    import concurrent.futures

    dsn = os.environ.get("CARNET_TEST_DSN")
    if not dsn:
        pytest.skip("CARNET_TEST_DSN not set")
    try:
        import psycopg

        from carnet.storage import migrate
    except ImportError as exc:  # pragma: no cover - psycopg is an optional extra
        pytest.skip(f"psycopg not installed: {exc}")

    base, _, name = dsn.rpartition("/")
    racing = f"{name}_migrate_race"
    with psycopg.connect(f"{base}/postgres", autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {racing} WITH (FORCE)")
        conn.execute(f"CREATE DATABASE {racing}")
    target = f"{base}/{racing}"

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            applied = list(pool.map(lambda _: migrate.apply(target), range(4)))

        # Exactly one run did the work; the rest waited and found it done. Asserted as
        # a total rather than per-run, because which thread wins is not the property.
        assert sum(len(run) for run in applied) == len(migrate.available())
        assert sorted(len(run) for run in applied)[-1] == len(migrate.available())

        with psycopg.connect(target, autocommit=True) as conn:
            rows = conn.execute(
                "SELECT count(*), count(DISTINCT version) FROM schema_migrations"
            ).fetchone()
        assert rows == (len(migrate.available()), len(migrate.available()))
        assert migrate.apply(target) == []
    finally:
        with psycopg.connect(f"{base}/postgres", autocommit=True) as conn:
            conn.execute(f"DROP DATABASE IF EXISTS {racing} WITH (FORCE)")


@pytest.fixture
def pg_store():
    """A `PostgresStorage` against the real engine, or a skip.

    Separate from the contract suite's session fixture, which drops and rebuilds the
    schema. This one only applies migrations, which is idempotent, so the two can run
    in either order.
    """
    dsn = os.environ.get("CARNET_TEST_DSN")
    if not dsn:
        pytest.skip("CARNET_TEST_DSN not set")

    try:
        from carnet.storage import migrate
        from carnet.storage.postgres import PostgresStorage
    except ImportError as exc:  # pragma: no cover - psycopg is an optional extra
        pytest.skip(f"psycopg not installed: {exc}")

    migrate.apply(dsn)
    store = PostgresStorage(dsn, min_size=2, max_size=5)
    yield store
    store.close()


def test_postgres_survives_concurrent_writers(pg_store):
    """The reason the single connection became a pool.

    A psycopg connection is not safe for concurrent use, and the failure is not a
    clean exception — interleaved cursors on one connection return each other's rows.
    Everything else in this suite runs against the in-memory store, so without this
    the change that motivated the whole step would be tested only single-threaded.

    Note `max_size=5` against 8 threads: the pool is deliberately smaller than the
    concurrency, so this also exercises waiting for a connection rather than always
    finding a free one.
    """
    tenant = "t-pg-concurrency"
    pg_store.create_tenant(tenant, "PG Concurrency")

    errors: list = []

    def worker(n):
        try:
            for i in range(10):
                pg_store.save_agent(tenant, {"name": f"a{n}-{i}", "system": "s"}, actor="system:cli")
                # Interleave a read with the writes: a read borrowing a connection
                # mid-write is the shape that broke on a shared one.
                pg_store.get_agent(tenant, f"a{n}-{i}")
        except Exception as exc:  # noqa: BLE001 - the failure IS the finding
            errors.append(exc)

    _run(worker)

    assert not errors, f"concurrent access failed: {errors[0]!r}"
    names = {config["name"] for config in pg_store.load_agents(tenant)}
    assert len(names) == THREADS * 10, "writes were lost or overwrote each other"


def test_two_editors_and_the_second_is_refused(pg_store):
    """**The property step 10d exists for, with the read genuinely interleaved.**

    Both editors open the agent, so both hold the same `updated_at`. Only then does either
    save. Without the `AND updated_at = %s` the second write lands and silently reverts
    the first person's scope narrowing — the config goes back to granting a write tool,
    and nothing anywhere records that a permission was widened.

    Postgres-only, and not because it is slow. The in-memory store is too fast to expose a
    window at all, which is why every concurrency assertion that matters in this project
    lives in this file behind a real engine.

    **Mutation-check**: drop `AND updated_at = %s` from `update_agent` in postgres.py and
    this fails — `narrowed` comes back holding the tools again.
    """
    # **A fresh tenant per run.** This was `"t-pg-two-editors"`, which made the test
    # pass exactly once per database: `admin_audit` is append-only by trigger, so the
    # final assertion — one `agent.update` record, naming Priya — sees the previous run's
    # record too and fails. CI never noticed, because its container is new every time.
    # Locally it fails on the second run, which is precisely when somebody is
    # mutation-checking and will mis-attribute it to their mutation. Found doing exactly
    # that, in step 7b.
    tenant = f"t-pg-two-editors-{uuid.uuid4().hex[:8]}"
    pg_store.create_tenant(tenant, "Two Editors")
    config = {
        "name": "contended",
        "permissions": {
            "tools": ["post_message"],
            "scope": {"chat.channel": {"write": ["#eng"]}},
        },
    }
    pg_store.save_agent(tenant, config, actor="system:cli")

    # Both read. Neither has written yet — this is the window, and it is the whole test.
    priya = pg_store.get_agent(tenant, "contended")
    sam = pg_store.get_agent(tenant, "contended")
    assert priya["updated_at"] == sam["updated_at"]

    narrowed = pg_store.update_agent(
        tenant,
        {**config, "permissions": {"tools": [], "scope": {}}},
        actor="user:u-priya",
        if_unchanged_since=priya["updated_at"],
    )
    assert narrowed is not None, "the first save should land"

    stale = pg_store.update_agent(
        tenant,
        sam["config"],
        actor="user:u-sam",
        if_unchanged_since=sam["updated_at"],
    )

    assert stale is None, "a write from a version that is gone must not land"
    assert pg_store.get_agent(tenant, "contended")["config"]["permissions"]["tools"] == []
    # And the refused save left no record, because nothing changed.
    updates = pg_store.admin_audit_records(tenant, action="agent.update")
    assert [r["actor_id"] for r in updates] == ["u-priya"]


def test_only_one_of_eight_concurrent_edits_from_one_version_wins(pg_store):
    """The same guard under real contention rather than a scripted interleaving.

    Eight threads read the same version and all save. Exactly one may succeed: a
    compare-and-set that let two through from one base is one that lets a scope narrowing
    be reverted, and the difference between "usually right" and "right" is only visible
    with threads.
    """
    tenant = f"t-pg-edit-race-{uuid.uuid4().hex[:8]}"   # see the test above
    pg_store.create_tenant(tenant, "Edit Race")
    pg_store.save_agent(tenant, {"name": "contended", "system": "start"}, actor="system:cli")
    base = pg_store.get_agent(tenant, "contended")["updated_at"]

    won: list = []
    errors: list = []

    def worker(n):
        try:
            row = pg_store.update_agent(
                tenant,
                {"name": "contended", "system": f"edited by {n}"},
                actor=f"user:u-{n}",
                if_unchanged_since=base,
            )
            if row is not None:
                won.append(n)
        except Exception as exc:  # noqa: BLE001 - the failure IS the finding
            errors.append(exc)

    _run(worker)

    assert not errors, f"concurrent edits raised: {errors[0]!r}"
    assert len(won) == 1, f"{len(won)} writers thought they had won: {won}"
    stored = pg_store.get_agent(tenant, "contended")["config"]["system"]
    assert stored == f"edited by {won[0]}"
    # One record, naming the one who actually wrote. Seven silent losers.
    records = pg_store.admin_audit_records(tenant, action="agent.update")
    assert [r["actor_id"] for r in records] == [f"u-{won[0]}"]
    # And one version, for the same reason: seven of these wrote no configuration, so
    # there are seven states that never existed and must not be offered for restore.
    versions = pg_store.list_agent_versions(tenant, "contended")
    assert [row["version"] for row in versions] == [2, 1]
    assert versions[0]["created_by"] == f"user:u-{won[0]}"


def test_eight_writers_creating_one_new_agent_leave_one_version(pg_store):
    """The upsert path's version numbering, which is not the compare-and-set's.

    `save_agent` has no guard — it is `--seed`'s method and re-running it is the
    documented usage — so eight threads seeding one tenant at once all *land*. The
    insert branch takes `DEFAULT 1` and the conflict branch takes `agents.version +
    (config IS DISTINCT FROM EXCLUDED.config)`, and with one identical config that is
    1 either way. So: one row, one version, no error.

    The window this covers exists nowhere else. The invariant tests reach `save_agent`
    sequentially, where an insert can never race a conflicting insert — and it is the
    branch a deployment runs on every boot, from however many processes it starts.

    **Mutation-check**: replace the conditional increment in the `DO UPDATE` branch with
    a plain `agents.version + 1` and this fails with several versions of one config —
    the seeded-history-of-nothing this step's suppression exists to prevent, arriving
    through concurrency rather than through repetition.
    """
    tenant = f"t-pg-seed-race-{uuid.uuid4().hex[:8]}"   # see the tests above
    pg_store.create_tenant(tenant, "Seed Race")
    config = {"name": "seeded", "system": "the shipped agent"}

    errors: list = []

    def worker(n):
        try:
            pg_store.save_agent(tenant, config, actor="system:cli")
        except Exception as exc:  # noqa: BLE001 - the failure IS the finding
            errors.append(exc)

    _run(worker)

    assert not errors, f"concurrent seeding raised: {errors[0]!r}"
    versions = pg_store.list_agent_versions(tenant, "seeded")
    assert [row["version"] for row in versions] == [1], (
        f"{len(versions)} versions of one identical config"
    )
    assert pg_store.get_agent(tenant, "seeded")["version"] == 1
    # Through `get_agent_version`, because the list projection carries no config — which
    # is the point of having two methods, and it caught this line being written.
    assert pg_store.get_agent_version(tenant, "seeded", 1)["config"] == config


def test_eight_successive_editors_number_their_versions_without_a_gap(pg_store):
    """**The concurrency claim step 021 makes, measured rather than reasoned about.**

    The design says a per-agent counter needs no sequence, because the `agents` row is
    the serialization point: every writer of one agent takes its lock, so `version + 1`
    read off that row cannot collide. This is that claim under threads.

    Each worker retries from a fresh read, so all eight *land* rather than seven losing —
    which is what makes the numbering interesting: eight writes to one row, and the
    history must be 1 through 9 exactly once each. A gap means a config was stored with
    no version; a duplicate means two configs claim one number and a restore is
    ambiguous.

    Postgres-only, and for this file's usual reason: the in-memory store holds one lock
    for the whole write and cannot expose the window at all.

    **Mutation-check**: drop `version + (config IS DISTINCT FROM %s)::int` back to a
    plain `version + 1` and the numbering still holds — that is not what this catches.
    Compute the number with `SELECT max(version) + 1` in a separate statement instead
    and it fails with duplicates, which is the shape somebody will reach for.
    """
    tenant = f"t-pg-version-race-{uuid.uuid4().hex[:8]}"   # see the tests above
    pg_store.create_tenant(tenant, "Version Race")
    pg_store.save_agent(
        tenant, {"name": "contended", "system": "start"}, actor="system:cli"
    )

    errors: list = []

    def worker(n):
        # Retry on a lost race rather than giving up, so every worker eventually writes.
        # The bound is generous: eight threads cannot lose more than eight times each
        # without something being wrong, and a hang here is a finding too.
        for _ in range(40):
            try:
                row = pg_store.get_agent(tenant, "contended")
                if pg_store.update_agent(
                    tenant,
                    {"name": "contended", "system": f"edited by {n}"},
                    actor=f"user:u-{n}",
                    if_unchanged_since=row["updated_at"],
                ) is not None:
                    return
            except Exception as exc:  # noqa: BLE001 - the failure IS the finding
                errors.append(exc)
                return
        errors.append(AssertionError(f"worker {n} never landed a write"))

    _run(worker)

    assert not errors, f"concurrent edits raised: {errors[0]!r}"

    versions = pg_store.list_agent_versions(tenant, "contended", limit=100)
    numbers = sorted(row["version"] for row in versions)
    assert numbers == list(range(1, 10)), f"gaps or duplicates: {numbers}"
    assert pg_store.get_agent(tenant, "contended")["version"] == 9
    # Every writer is in the history exactly once, and the newest version is what is live.
    assert sorted(row["created_by"] for row in versions) == (
        ["system:cli"] + sorted(f"user:u-{n}" for n in range(8))
    )
    assert pg_store.get_agent_version(tenant, "contended", 9)["config"] == (
        pg_store.get_agent(tenant, "contended")["config"]
    )


def test_a_failed_re_vetting_leaves_the_previous_allowlist_intact(pg_store):
    """`save_connector` replaces a connector's vetted tools by deleting them and
    re-inserting. Under one autocommit connection those were two statements with an
    invisible gap between them; behind a server the gap is real, and what it tears is
    the allowlist — a tenant briefly exposing tools nobody vetted, or none at all.

    Asserted through a failure mid-replacement, which is the only way to observe the
    transaction from outside.
    """
    tenant = "t-pg-revet"
    pg_store.create_tenant(tenant, "PG Revet")

    def manifest(vetted):
        return {
            "id": "fake",
            "description": "",
            "launch": {"kind": "stdio", "command": ["/bin/true"]},
            "vetted": vetted,
        }

    def tool(name, effect="read"):
        return {
            "remote_name": name,
            "effect": effect,
            "resources": [],
            "local_name": None,
            "max_response_bytes": None,
        }

    pg_store.save_connector(tenant, manifest([tool("alpha"), tool("beta")]), actor=TEST_ACTOR)
    assert len(pg_store.get_connector(tenant, "fake")["vetted"]) == 2

    # The second row has no `remote_name`, so the insert loop raises partway through —
    # after the DELETE has already run.
    with pytest.raises(storage.StorageError):
        pg_store.save_connector(tenant, manifest([tool("gamma"), {"effect": "read"}]), actor=TEST_ACTOR)

    surviving = [v["remote_name"] for v in pg_store.get_connector(tenant, "fake")["vetted"]]
    assert surviving == ["alpha", "beta"], (
        "a failed re-vetting left a torn allowlist: " f"{surviving}"
    )


# How many records the writer below is allowed to produce.
#
# **The bound is the fix for a test that did not terminate**, and the reason it did not
# is worth keeping. The writer appended without limit for as long as the reader ran, and
# each of the reader's 200 passes deep-copies the *whole* list — so read N costs O(N) and
# the run costs O(N²), with N set by however fast the machine is. Measured here on an
# idle laptop: 645,000 records by read 50, 1.1s per read, and the reader losing ground
# every pass. It never finished. On the machine this was written on it presumably did,
# which is the only reason it shipped.
#
# A test whose termination depends on the ratio of two thread speeds is not a slow test,
# it is a test with no bound. 20,000 is enough that the reader's early passes genuinely
# race a live append — which is the property under test — and the whole thing is over in
# well under a second.
AUDIT_WRITER_RECORDS = 20_000


def test_reading_audit_while_writing_does_not_raise():
    """`audit_records` iterates the list it is filtering. Doing that while another
    thread appends is the one operation here that raises rather than merely returning
    something stale."""
    store = storage.InMemoryStorage()
    store.create_tenant("t", "T")
    stop = threading.Event()
    errors: list = []

    def writer():
        n = 0
        while not stop.is_set() and n < AUDIT_WRITER_RECORDS:
            store.append_audit(
                "t",
                {
                    "v": 5,
                    "ts": "2026-08-02T00:00:00.000+00:00",
                    "run_id": f"r{n}",
                    "principal_kind": "system",
                    "principal_id": "test",
                    "agent": "a",
                    "tool": "post_message",
                    "decision": "allow",
                },
            )
            n += 1

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    try:
        for _ in range(200):
            try:
                store.audit_records("t")
            except Exception as exc:  # noqa: BLE001 - the failure IS the finding
                errors.append(exc)
                break
    finally:
        stop.set()
        thread.join(timeout=5)

    assert not errors, f"reading while writing raised: {errors[0]!r}"


# --- the access layer under threads -----------------------------------------------
#
# Both of these were missed by the chunk-3 tests and found by probing afterwards, and
# both are the same shape as the session-pool bug from step 004: correct single-
# threaded, wrong behind a threadpool, and silent either way.


def _idp_fixtures():
    """A signing key, a token factory, and a provider row. Local to this section."""
    pytest.importorskip("jwt", reason="install the 'access' extra")
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def jwk():
        entry = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
        entry.update({"kid": "k1", "use": "sig", "alg": "RS256"})
        return entry

    def token(issuer, audience, subject, email="priya@acme.com"):
        now = int(time.time())
        return jwt.encode(
            {
                "iss": issuer,
                "aud": audience,
                "sub": subject,
                "iat": now,
                "exp": now + 300,
                "email": email,
            },
            key,
            algorithm="RS256",
            headers={"kid": "k1"},
        )

    return jwk, token


def test_simultaneous_first_logins_produce_one_person(pg_store):
    """A person's very first request, twice at once — a UI opening two panels, a
    refresh, a retry.

    `users.resolve` looks somebody up and then creates them, so every thread that
    arrives before the first insert lands sees nobody and tries to create. Against
    Postgres, twelve concurrent first logins produced **eleven failures** before this
    was handled, each surfacing as a 503 on somebody's first ever visit.

    Postgres and not the in-memory store, deliberately: in memory the lookup and the
    insert are dict operations too fast to yield the GIL, so the threads serialise by
    accident and the race is invisible. The fake is not lying — it is too quick to be
    honest. Same lesson as NULLS NOT DISTINCT.
    """
    from carnet import storage as storage_module
    from carnet.access import oidc, providers, users
    from carnet.access.oidc import JwksCache

    jwk, token = _idp_fixtures()

    marker = uuid.uuid4().hex[:8]
    issuer = f"https://race-{marker}.okta.example"
    tenant = f"t-race-{marker}"
    subject = f"00u-{marker}"

    pg_store.create_tenant(tenant, "Race")
    pg_store.save_tenant_idp(
        tenant,
        {
            "issuer": issuer,
            "jwks_uri": f"{issuer}/v1/keys",
            "audience": "api://default",
            "allowed_domains": ("acme.com",),
        },
    )
    storage_module.configure(pg_store)

    cache = JwksCache(fetch=lambda uri: oidc.keys_from_jwks({"keys": [jwk()]}))
    # Verified once, so every thread races on the part that actually races.
    provider, claims = providers.resolve(
        token(issuer, "api://default", subject), cache
    )

    results: list = []
    errors: list = []
    gate = threading.Barrier(THREADS)

    def worker(_n):
        gate.wait()
        try:
            results.append(users.resolve(provider, claims))
        except Exception as exc:  # noqa: BLE001 - the failure IS the finding
            errors.append(exc)

    _run(worker)

    assert not errors, f"a concurrent first login failed: {errors[0]!r}"
    assert len(pg_store.list_users(tenant)) == 1, "created more than one person"
    assert len({p.id for p in results}) == 1, "handed out two identities for one person"


def test_simultaneous_transfers_leave_exactly_one_owner(pg_store):
    """Eight people hand the same agent to eight different successors at once.

    `transfer_agent_ownership` is demote-then-promote inside one transaction, and the
    order is forced by the partial unique index — the incumbent must step down before a
    successor steps up. Between those two statements the agent has **no owner**, and the
    whole question is whether anybody else can act during that gap.

    Postgres and not the in-memory store, for the reason this file keeps finding: in
    memory the whole transfer happens under one lock in a few dict operations, too fast
    to yield the GIL, so the threads serialise by accident and prove nothing about the
    index they are supposed to be testing.

    What must be true afterwards is not "every transfer succeeded" — they cannot all
    have. It is that the invariant never broke: one owner, and every thread that was
    told it succeeded was telling the truth.
    """
    marker = uuid.uuid4().hex[:8]
    tenant = f"t-xfer-{marker}"

    pg_store.create_tenant(tenant, "Transfer")
    pg_store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    pg_store.grant_agent(tenant, "reporter", "user", "u-0", role="owner", actor="system:cli")

    winners: list = []
    refused: list = []
    gate = threading.Barrier(THREADS)

    def worker(n):
        gate.wait()
        try:
            pg_store.transfer_agent_ownership(
                tenant, "reporter", "user", f"u-{n + 1}",
                granted_by="u-0", actor="user:u-0",
            )
            winners.append(f"u-{n + 1}")
        except storage.StorageError as exc:
            # A loser is fine and expected. A *silent* loser would not be.
            refused.append(exc)

    _run(worker)

    owners = [
        g["grantee_id"]
        for g in pg_store.list_agent_grants(tenant, "reporter")
        if g["role"] == "owner"
    ]

    assert len(owners) == 1, f"the index let {len(owners)} owners through: {owners}"
    assert winners, "every transfer was refused, so nothing was actually exercised"
    assert owners[0] in winners, (
        f"'{owners[0]}' owns the agent but was never told the transfer succeeded"
    )

    # And a loser is told something a person can act on. Untranslated, this arrives as
    # the text of a unique constraint, which reads as the server breaking rather than as
    # somebody else having got there first.
    assert refused, "nothing raced, so the message below was not exercised"
    for exc in refused:
        assert "changed while this transfer was in flight" in str(exc), str(exc)


def test_simultaneous_first_logins_claim_a_pending_grant_once(pg_store):
    """A person's first request, eight times at once, with an agent waiting on their
    address.

    Two races stacked on one another, and the second is new. Every thread finds no user
    and tries to create one — that is the race chunk 3 survives — and every thread that
    gets past it then tries to claim the same pending row. A `SELECT` followed by a
    `DELETE` would let several threads see the row and all insert; the claim is a
    `DELETE ... RETURNING` inside a transaction so exactly one of them takes it.

    What must hold is not that every thread claims. It is that the grant lands, once,
    at the right level, and that nothing raises on somebody's very first visit.
    """
    from carnet import storage as storage_module
    from carnet.access import oidc, providers, users
    from carnet.access.oidc import JwksCache

    jwk, token = _idp_fixtures()

    marker = uuid.uuid4().hex[:8]
    issuer = f"https://claim-{marker}.okta.example"
    tenant = f"t-claim-{marker}"
    subject = f"00u-{marker}"
    email = f"newhire-{marker}@acme.com"

    pg_store.create_tenant(tenant, "Claim")
    pg_store.save_tenant_idp(
        tenant,
        {
            "issuer": issuer,
            "jwks_uri": f"{issuer}/v1/keys",
            "audience": "api://default",
            "allowed_domains": ("acme.com",),
        },
    )
    pg_store.save_agent(tenant, {"name": "reporter"}, actor="system:cli")
    pg_store.add_pending_grant(tenant, "reporter", email, role="editor", actor="system:cli")
    storage_module.configure(pg_store)

    cache = JwksCache(fetch=lambda uri: oidc.keys_from_jwks({"keys": [jwk()]}))
    provider, claims = providers.resolve(
        token(issuer, "api://default", subject, email=email), cache
    )

    results: list = []
    errors: list = []
    gate = threading.Barrier(THREADS)

    def worker(_n):
        gate.wait()
        try:
            results.append(users.resolve(provider, claims))
        except Exception as exc:  # noqa: BLE001 - the failure IS the finding
            errors.append(exc)

    _run(worker)

    assert not errors, f"a concurrent first login failed: {errors[0]!r}"
    assert len(pg_store.list_users(tenant)) == 1, "created more than one person"

    principal = results[0]
    assert pg_store.agent_grant_role(tenant, "reporter", "user", principal.id) == "editor"
    assert pg_store.list_pending_grants(tenant, "reporter") == [], "the row was not consumed"
    assert len(pg_store.list_agent_grants(tenant, "reporter")) == 1


def test_a_cold_key_cache_fetches_once():
    """This object is process-wide and endpoints run in a threadpool, so a restart
    under load means every in-flight request misses at once.

    Measured before the fix: eight concurrent misses, eight fetches of the same key
    set. Nothing breaks — they all get the same answer — but it is a thundering herd
    at a customer's identity provider on every restart, which is exactly when they are
    least inclined to be forgiving.
    """
    from carnet.access import oidc
    from carnet.access.oidc import JwksCache

    jwk, _token = _idp_fixtures()

    fetches: list = []
    lock = threading.Lock()

    def slow_fetch(uri):
        with lock:
            fetches.append(uri)
        time.sleep(0.05)  # wide enough that every thread is inside the miss
        return oidc.keys_from_jwks({"keys": [jwk()]})

    cache = JwksCache(fetch=slow_fetch)
    gate = threading.Barrier(THREADS)

    def worker(_n):
        gate.wait()
        cache.key_for("https://example.test/keys", "k1")

    _run(worker)

    assert len(fetches) == 1, f"{len(fetches)} threads each dialled the provider"


# --- cancellation across a process boundary ------------------------------------------
#
# **The test that matters for 8c**, and the one that cannot be written against the
# in-memory store — which is not a limitation of the fake but the entire point. In
# memory, a `Cancellation` reachable from the canceller is the *same object* the broker
# checks, so a passing test would prove that a Python attribute assignment works.
#
# In production the canceller is an API process and the run is a thread in a worker
# process, and the only thing they share is a database. So: two `PostgresStorage`
# instances with two independent connection pools, a run executing under one, a cancel
# written through the other, and a heartbeat as the only bridge.


# --- 7b: eight concurrent refreshes make one token-endpoint call ----------------------
#
# Decision 11, and **Postgres-only** for the reason 10d found writing the same shape of
# test for `update_agent`: the in-memory store's refresh lock is a `threading.Lock` in one
# interpreter, which serialises threads and proves nothing about two workers. The property
# a deployment needs is an advisory lock in the database, and only the database can
# demonstrate it.


def _oauth_world(pg_store, tenant, *, rotate=True):
    """A tenant with a connector, a consent flow, and one connected person.

    Built through the real functions rather than by inserting rows, because what is under
    test is the interaction between the lock, the compare-and-set and the exchange — and a
    fixture that wrote the row directly could seal a credential the refresh cannot open.
    """
    from carnet import storage as storage_module
    from carnet import tools as tools_module
    from carnet.access import oauth
    from carnet.core import Principal, crypto

    # Bare, not `from tests.` — see the note in test_api.py: the dotted form only
    # resolves under `python -m pytest` and broke CI, which runs `pytest` bare.
    from test_oauth import ACCESS_TOKEN, CLIENT_SECRET, FakeProvider

    crypto.configure(crypto.LocalKeyCipher(b"\x2a" * crypto.KEY_BYTES))
    storage_module.configure(pg_store)

    pg_store.create_tenant(tenant, "Refresh Race")
    pg_store.allow_host(tenant, "auth.example.com", actor="system:test")
    tools_module.register_connector(
        tenant, "jira", url="https://auth.example.com/mcp", actor="system:test"
    )
    oauth.configure(
        tenant,
        "jira",
        authorize_endpoint="https://auth.example.com/authorize",
        token_endpoint="https://auth.example.com/token",
        client_id="client-abc",
        client_secret=CLIENT_SECRET,
        scopes=("offline_access",),
        actor="system:test",
    )

    priya = Principal.user("u_priya", tenant)
    fake = FakeProvider(rotate=rotate)
    return priya, fake, oauth, ACCESS_TOKEN


def test_eight_concurrent_refreshes_make_one_token_endpoint_call(pg_store, monkeypatch):
    """The plan's sixth verification, and the one that needed a real database.

    Eight runs for one person start at once — the ordinary case, because `POST /runs` is a
    queue with a worker — and all eight see an expired access token. Without the
    single-flight lock that is eight exchanges of which **seven come back
    `invalid_grant`**, because most providers rotate refresh tokens and kill the old one
    on every use. Seven failures is not merely waste: it is eight requests carrying a spent
    credential arriving at a customer's identity provider inside a second, which is what
    credential stuffing looks like from their side.

    Three assertions, and each fails to a different bug:

      one exchange      the lock is missing or is taken after the row is read
      one winner        the compare-and-set is missing
      every loser uses  a loser retried the exchange instead of re-reading, which is the
      the winner's      thing that trips a provider's breach detection

    **Mutation-checks**, both run rather than claimed:
      - make `refresh_lock` a no-op contextmanager  -> the first assertion fails with 8
      - drop `AND updated_at = %s` from `update_connection_credential` -> the row ends up
        holding a spent refresh token and the *next* refresh fails, which the last
        assertion catches
    """
    import threading

    from carnet import storage as storage_module
    from carnet.core import credentials

    # A fresh tenant per run. The contract suite drops and rebuilds its schema; this
    # fixture only applies migrations, so a fixed name would collide with the previous
    # run's rows at `create_connector`, which is an INSERT with no ON CONFLICT by design.
    tenant = f"t-pg-refresh-race-{uuid.uuid4().hex[:8]}"
    priya, fake, oauth, access_marker = _oauth_world(pg_store, tenant)
    monkeypatch.setattr(oauth, "_post_form", fake)

    # Connect, then backdate the access token so every thread sees a stale row.
    url = oauth.begin(priya, "jira", redirect_uri="https://x/connect/callback")
    oauth.complete(url.split("state=")[1].split("&")[0], "code")
    row = pg_store.find_connection(tenant, "user", "u_priya", "jira")
    pg_store.update_connection_credential(
        tenant, "user", "u_priya", "jira",
        ciphertext=row["ciphertext"], key_id=row["key_id"],
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=5),
        refresh_expires_at=None,
        if_updated_at=row["updated_at"],
    )
    exchanges_before = len(fake.token_calls)

    refreshed: list = []
    errors: list = []
    ready = threading.Barrier(THREADS)

    def worker(n):
        try:
            # A barrier, so the eight genuinely overlap. Without it the first thread
            # finishes before the eighth starts and the test passes with no lock at all —
            # which is the way this shape of test usually fails to test anything.
            ready.wait(timeout=10)
            if oauth.refresh_connection(priya, "jira"):
                refreshed.append(n)
        except Exception as exc:  # noqa: BLE001 - the failure IS the finding
            errors.append(exc)

    _run(worker)

    assert not errors, f"a concurrent refresh raised: {errors[0]!r}"

    exchanges = len(fake.token_calls) - exchanges_before
    assert exchanges == 1, (
        f"{exchanges} token-endpoint calls for one expired connection. Seven of these "
        "would be invalid_grant at a real rotating provider, and all eight would look "
        "like credential stuffing in their logs."
    )
    assert len(refreshed) == 1, f"{len(refreshed)} threads thought they had refreshed"

    # Every loser uses the winner's token rather than failing — which is the half that
    # says they re-read rather than retried.
    storage_module.configure(pg_store)
    assert (
        credentials.for_connector("jira", priya, identity="user").value
        == f"{access_marker}-2"
    )

    # And the connection is still refreshable, which is what a lost update destroys: a
    # row holding a refresh token the provider already invalidated is broken forever.
    row = pg_store.find_connection(tenant, "user", "u_priya", "jira")
    pg_store.update_connection_credential(
        tenant, "user", "u_priya", "jira",
        ciphertext=row["ciphertext"], key_id=row["key_id"],
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=5),
        refresh_expires_at=None,
        if_updated_at=row["updated_at"],
    )
    assert oauth.refresh_connection(priya, "jira") is True, (
        "the connection is no longer refreshable, which is what a lost update produces: "
        "a stored refresh token the provider has already killed"
    )


def test_a_refresh_from_a_version_that_is_gone_does_not_land(pg_store):
    """The compare-and-set on its own, with the read interleaved deliberately.

    The threaded test above cannot distinguish "the lock worked" from "the compare-and-set
    worked", because under a working lock the second write never happens. This one removes
    the lock from the question entirely.
    """
    from carnet.core import crypto

    tenant = f"t-pg-refresh-cas-{uuid.uuid4().hex[:8]}"
    crypto.configure(crypto.LocalKeyCipher(b"\x2a" * crypto.KEY_BYTES))
    pg_store.create_tenant(tenant, "Refresh CAS")
    pg_store.create_connector(
        tenant, "jira", launch={"kind": "http", "url": "https://x/mcp"}, actor="system:test"
    )
    pg_store.save_connection(
        tenant, "user", "u_priya", "jira",
        ciphertext=b"first", key_id="k1", actor="system:test",
    )

    # Both read the same version. This is the window, and it is the whole test.
    first = pg_store.find_connection(tenant, "user", "u_priya", "jira")
    second = pg_store.find_connection(tenant, "user", "u_priya", "jira")
    assert first["updated_at"] == second["updated_at"]

    landed = pg_store.update_connection_credential(
        tenant, "user", "u_priya", "jira",
        ciphertext=b"refreshed-by-A", key_id="k1",
        expires_at=None, refresh_expires_at=None,
        if_updated_at=first["updated_at"],
    )
    assert landed is not None, "the first refresh should land"

    stale = pg_store.update_connection_credential(
        tenant, "user", "u_priya", "jira",
        ciphertext=b"refreshed-by-B", key_id="k1",
        expires_at=None, refresh_expires_at=None,
        if_updated_at=second["updated_at"],
    )

    assert stale is None, "a refresh from a version that is gone must not land"
    # B's token is the one the provider killed when A refreshed. Storing it would break
    # this connection permanently with nothing anywhere saying why.
    assert pg_store.find_connection(tenant, "user", "u_priya", "jira")[
        "ciphertext"
    ] == b"refreshed-by-A"


def test_eight_concurrent_restores_keep_the_invariant(pg_store):
    """Restores racing restores, which no other test drives concurrently.

    Each worker retries a restore of a different old version until it lands. What must
    survive: dense numbering, every restore row naming its origin, and the live config
    equal to the newest version — the invariant, under the one write pattern that reads
    a version before writing one.
    """
    tenant = f"t-pg-restore-race-{uuid.uuid4().hex[:8]}"   # see the tests above
    pg_store.create_tenant(tenant, "Restore Race")
    config = {"name": "contended", "system": "v1"}
    pg_store.save_agent(tenant, config, actor="system:cli")
    for n in range(2, 6):
        row = pg_store.get_agent(tenant, "contended")
        pg_store.update_agent(
            tenant, {**config, "system": f"v{n}"}, actor="user:u-0",
            if_unchanged_since=row["updated_at"],
        )

    errors: list = []

    def worker(n):
        target = (n % 4) + 1
        for _ in range(40):
            try:
                row = pg_store.get_agent(tenant, "contended")
                if pg_store.update_agent(
                    tenant,
                    pg_store.get_agent_version(tenant, "contended", target)["config"],
                    actor=f"user:u-{n}",
                    if_unchanged_since=row["updated_at"],
                    restored_from=target,
                ) is not None:
                    return
            except Exception as exc:  # noqa: BLE001 - the failure IS the finding
                errors.append(exc)
                return
        errors.append(AssertionError(f"worker {n} never landed a restore"))

    _run(worker)

    assert not errors, f"concurrent restores raised: {errors[0]!r}"
    history = pg_store.list_agent_versions(tenant, "contended", limit=100)
    numbers = [row["version"] for row in history]
    assert numbers == list(range(numbers[0], 0, -1)), f"gaps or duplicates: {numbers}"
    restores = [row for row in history if row["source"] == "restore"]
    assert restores and all(r["restored_from"] is not None for r in restores)
    live = pg_store.get_agent(tenant, "contended")
    assert pg_store.get_agent_version(tenant, "contended", live["version"])["config"] == (
        live["config"]
    )


def test_interleaved_tenant_scopes_never_cross_on_a_shared_pool(pg_store):
    """Step 029's sharpest hazard, driven with threads on a pool smaller than the
    thread count: two tenants hammering scoped reads through the same recycled
    connections, each asserting on every borrow that the database shows it exactly its
    own rows — a `SELECT` with no WHERE clause, so the policy is the only thing
    filtering. A single leaked `agent_runtime.tenant_id` between borrows fails this
    loudly, which is the point: in production it would have returned data."""
    from carnet.storage import tenancy

    stem = uuid.uuid4().hex[:8]
    tenants = [f"scope-{stem}-a", f"scope-{stem}-b"]
    for name in tenants:
        pg_store.create_tenant(name, name)
        pg_store.create_group(name, f"g-{name}", name, actor="system:test")

    failures: queue.Queue = queue.Queue()

    def hammer(tenant_id: str) -> None:
        try:
            for _ in range(60):
                with tenancy.scoped(tenant_id):
                    seen = {
                        row[0]
                        for row in pg_store._fetchall(
                            "SELECT id FROM tenants WHERE id LIKE %s",
                            (f"scope-{stem}-%",),
                        )
                    }
                    if seen != {tenant_id}:
                        failures.put((tenant_id, seen))
                # An unscoped read between scoped ones, from the same pool: it must
                # see both tenants, or the reset discipline broke the other way.
                both = {
                    row[0]
                    for row in pg_store._fetchall(
                        "SELECT id FROM tenants WHERE id LIKE %s",
                        (f"scope-{stem}-%",),
                    )
                }
                if both != set(tenants):
                    failures.put((f"unscoped via {tenant_id}", both))
        except Exception as exc:  # noqa: BLE001 - reported through the queue
            failures.put((tenant_id, repr(exc)))

    threads = [threading.Thread(target=hammer, args=(name,)) for name in tenants]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert failures.empty(), list(failures.queue)


# --- the MCP door's per-token budget, against the statement that enforces it ---------
#
# Step 033b, and it belongs here rather than in `test_door.py` for the reason this whole
# file exists: the ceiling is one `INSERT ... ON CONFLICT DO UPDATE ... WHERE` (migration
# 040), and a statement's atomicity is exactly what passes trivially until two things run
# at once. `test_door.py` drives the door single-threaded against the in-memory store,
# which answers with a comparison under a lock — the same answer by a different mechanism,
# which is the shape that agrees until it does not.
#
# The property is the one decision 9 rests on: **the ceiling must be the ceiling however
# many processes are enforcing it.** A read-then-write would admit every racer.


def test_the_door_budget_is_a_ceiling_under_concurrency(pg_store):
    """Sixteen threads, a ceiling of five. Exactly five may pass.

    The mutation this fails against is the obvious implementation — `SELECT calls`, then
    `UPDATE ... SET calls = calls + 1` — which admits all sixteen at 4/5 because every
    one of them reads four. That version passes every single-threaded test in this
    repository.

    Sixteen against a pool of five, deliberately, so this also exercises waiting for a
    connection rather than always finding a free one.
    """
    tenant = f"t-door-budget-{uuid.uuid4().hex[:8]}"
    pg_store.create_tenant(tenant, "Door Budget")
    token_id = f"m_{uuid.uuid4().hex[:16]}"
    pg_store.create_api_token(
        tenant,
        {"id": token_id, "name": "racer", "owner_id": "u-1", "secret_hash": "sha256$x"},
        actor=TEST_ACTOR,
    )
    window = datetime.now(timezone.utc).date()

    ceiling = 5
    admitted: queue.Queue = queue.Queue()
    refused: queue.Queue = queue.Queue()

    def spend():
        try:
            got = pg_store.spend_mcp_call(tenant, token_id, window, ceiling=ceiling)
        except Exception as exc:  # noqa: BLE001 - reported rather than lost in a thread
            admitted.put(f"raised {exc!r}")
            return
        (admitted if got is not None else refused).put(got)

    threads = [threading.Thread(target=spend) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert admitted.qsize() == ceiling, list(admitted.queue)
    assert refused.qsize() == 16 - ceiling

    # Every admitted call got a distinct count, and they are exactly 1..ceiling — so the
    # counter was never handed out twice, which a lost update would show as a duplicate.
    assert sorted(admitted.queue) == list(range(1, ceiling + 1))
    assert pg_store.mcp_calls_spent(tenant, token_id, window) == ceiling


def test_two_replicas_share_one_door_budget(pg_store):
    """Decision 9's actual claim, with two stores standing in for two API processes.

    Two `PostgresStorage` instances are two pools and two sets of connections — which is
    what a second replica *is*, from the database's side. A budget spent through one has
    to be spent through the other, or "1000 calls a day" is a per-process number wearing
    a deployment-wide label, which is worse than no dial at all.

    This is the half of decision 9's test list step 033b owes. The other half — a grant
    revoked on replica A refused by replica B — needs no new machinery, because grants
    are read per request from storage with no cache anywhere (decision 12 refuses one by
    name), and `test_tenant_scope.py` already holds that reads cross the pool boundary.
    """
    from carnet.storage.postgres import PostgresStorage

    tenant = f"t-door-replica-{uuid.uuid4().hex[:8]}"
    pg_store.create_tenant(tenant, "Door Replicas")
    token_id = f"m_{uuid.uuid4().hex[:16]}"
    pg_store.create_api_token(
        tenant,
        {"id": token_id, "name": "shared", "owner_id": "u-1", "secret_hash": "sha256$x"},
        actor=TEST_ACTOR,
    )
    window = datetime.now(timezone.utc).date()

    replica_b = PostgresStorage(os.environ["CARNET_TEST_DSN"], min_size=1, max_size=2)
    try:
        assert pg_store.spend_mcp_call(tenant, token_id, window, ceiling=2) == 1
        # The second replica continues the same count rather than starting its own.
        assert replica_b.spend_mcp_call(tenant, token_id, window, ceiling=2) == 2
        assert replica_b.spend_mcp_call(tenant, token_id, window, ceiling=2) is None
        # And the first replica is refused too, immediately — no cache to go stale.
        assert pg_store.spend_mcp_call(tenant, token_id, window, ceiling=2) is None
    finally:
        replica_b.close()
