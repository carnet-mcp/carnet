"""Shared fixtures.

The three fixtures here are autouse, and for the same reason: they isolate a
*process-wide* thing that a test module should not have to remember about. A test file
that forgets one does not fail — it quietly writes into the real audit log, shares a
store with whatever ran before it, or encrypts under a key another test chose. Quiet
failures in test infrastructure are the expensive kind, because the suite stays green
while it stops meaning anything.
"""


import pytest

from carnet import config, storage, tools
from carnet.core import crypto
from carnet.tools import mcp, messaging  # noqa: E402
from carnet.tools.mcp.connectors.github import CONNECTOR as GITHUB  # noqa: E402

# The tenant most tests act in. Tests about tenancy itself create their own.
TEST_TENANT = "t-test"

# Who a test is acting as when the identity does not matter to what it is asserting.
# A `system:` principal because that is what an unattended caller is — see
# `storage.SYSTEM_ACTOR`, which this deliberately is not: tests that assert on the
# *content* of an administrative record need an actor distinguishable from `--seed`'s,
# or "who wrote this row" has the same answer either way and the assertion proves
# nothing.
TEST_ACTOR = "system:test"

# The host every HTTP connector fixture in this suite dials. One host rather than a
# set, because the fixtures already agree on it and a second would be a second thing to
# keep in sync. Approved in
# `isolated_storage` so the egress allowlist does not have to be set up by every test
# that happens to touch a connector — the allowlist has its own tests, and a fixture
# that made every unrelated test carry it would make those tests about egress.
TEST_HOST = "api.example.com"


class Recording:
    """A `core.limits.Spending` that writes down what the broker did to it. Step 084.

    The broker consumes a budget at step 2 of every call — `reserve(tool)` before it
    executes, `add_bytes(n)` after — so anything driving `broker.call` directly has to
    hand it one. Until 084 that was `core.limits.Budget` with its four dials wound high:
    a real enforcer, borrowed for its side effect by tests that were about a connector, a
    credential or an egress rule and not about a ceiling at all.

    `Budget` is gone — its only caller, `RunContext.start`, had no caller of its own —
    and the honest replacement is not `door.TokenBudget`. That one reads storage and a
    spend ceiling, which is more world than a REST test wants; it also **ignores the tool
    it is handed** and its `add_bytes` **deliberately does nothing**, so it cannot see
    either half of what the broker passes it. This can, which is why `test_limits.py`
    uses it to pin the seat itself.

    `refuse` is the reason to hand back, or None to allow.
    """

    def __init__(self, refuse: "str | None" = None):
        self.refuse = refuse
        self.reserved: list = []
        self.bytes: list = []

    def reserve(self, tool):
        from carnet.core.permissions import ALLOW, Decision

        self.reserved.append(tool)
        return ALLOW if self.refuse is None else Decision(False, self.refuse)

    def add_bytes(self, count) -> None:
        self.bytes.append(count)


class Unmetered(Recording):
    """A `Recording` nobody reads back. The name is the whole of it.

    Most call sites need a budget only because the broker's signature does. Saying
    `Unmetered()` there says *this test is not about a ceiling*, which `Recording()`
    would not.
    """


def run_context(principal, budget=None, run_id=None):
    """A `RunContext` for a test driving `broker.call` directly. Step 084.

    **Neither constructor fits, and that is not an oversight.** `RunContext.start` built
    a `Budget` from an agent's `limits` block and went with it; `for_call` is the door's
    and mints a `door-<hex>` id, which would make every audit row a test wrote look like
    a door call to `overview`'s predicate and to anybody reading the log. So this builds
    the dataclass, with a real run id from the one function that mints them.

    A fresh id and a fresh budget per call, deliberately: a shared context shares
    counters, and tests that spend each other's allowance are tests that pass in one
    order and fail in another.
    """
    from carnet.core.context import RunContext, new_run_id

    return RunContext(
        run_id=run_id or new_run_id(),
        principal=principal,
        budget=Unmetered() if budget is None else budget,
    )


def read_audit(tenant_id=TEST_TENANT):
    """Audit records for a tenant, oldest first.

    This used to open `audit.jsonl` and parse lines. It is now a query, and the fact
    that every assertion built on it kept its shape is the evidence that audit.py and
    audit_query.py were worth building as a pair.
    """
    return storage.active().audit_records(tenant_id)


@pytest.fixture(autouse=True)
def isolated_var_dir(tmp_path, monkeypatch):
    """Point the outbox at a temp dir so tests never touch var/.

    `messaging` binds this path at import time (`from ..config import X`), so patching
    config alone is not enough — the module-level name must be patched too.

    The audit log used to need the same treatment and no longer does: it writes
    through storage, and `isolated_storage` gives each test its own. What is left here
    is the outbox, which is still a file because `post_message` with no webhook
    configured is still a file.
    """
    monkeypatch.setattr(config, "VAR_DIR", tmp_path)
    monkeypatch.setattr(config, "OUTBOX_PATH", tmp_path / "outbox.jsonl")
    # Step 060's degraded-mode sink is a file for the outbox's reason, and gets the
    # outbox's isolation: `audit._record_to_fallback` reads it off `config` at call
    # time, so the attribute patch is the whole treatment.
    monkeypatch.setattr(
        config, "AUDIT_FALLBACK_PATH", tmp_path / "audit-fallback.jsonl"
    )
    monkeypatch.setattr(messaging, "OUTBOX_PATH", tmp_path / "outbox.jsonl")
    return tmp_path


@pytest.fixture(autouse=True)
def isolated_storage():
    """A fresh in-memory store per test, with `TEST_TENANT` already created.

    Per test, never shared: a store carried between tests would let one test's agents
    and audit records leak into the next, which is the storage-layer version of the
    reason `RunContext` is a fixture rather than a module constant.

    Deliberately **not seeded** with the shipped agents. A test that wants them says
    so via `bootstrap.seed_tenant`; the rest get an empty tenant, so nothing passes by
    accident because `issue-reporter` happened to be lying around.
    """
    store = storage.configure(storage.InMemoryStorage())
    store.create_tenant(TEST_TENANT, "Test Tenant")
    # Migration 023's allowlist, pre-approved for the host the HTTP fixtures use. Every
    # test that dials one would otherwise have to set this up, which would turn tests
    # about delegation and binding into tests about egress. The allowlist's own
    # behaviour — including that an **empty** one denies — is asserted in
    # `test_egress.py`, against tenants this fixture has not touched.
    store.allow_host(TEST_TENANT, TEST_HOST, actor=TEST_ACTOR)
    yield store
    storage.reset()
    tools.reset_bound()
    mcp.POOL.reset()


@pytest.fixture(autouse=True)
def isolated_crypto():
    """A fixed, throwaway encryption key per test.

    Autouse for the same reason as the store: the cipher is process-wide, and a test
    that reads or writes a delegated credential without one would either raise
    somewhere unhelpful or — worse — inherit whatever key the previous test configured
    and pass for the wrong reason.

    A constant key rather than a random one, so a failing assertion about ciphertext is
    reproducible. Nothing here is a secret; `CARNET_SECRET_KEY` is never read by
    the suite, which is also what keeps a developer's real key out of it.
    """
    crypto.configure(crypto.LocalKeyCipher(b"\x2a" * crypto.KEY_BYTES))
    yield
    crypto.reset()


@pytest.fixture
def vetted_github(isolated_storage):
    """The shipped GitHub connector, vetted for `TEST_TENANT`.

    Explicit rather than autouse. Which connectors a tenant has vetted is now a
    property of that tenant's data, so a test that wants connector tools to exist has
    to say so — and a test that does not gets a tenant with none, which is the state
    every new customer starts in.
    """
    tools.save_connector(TEST_TENANT, GITHUB, actor=TEST_ACTOR)
    return GITHUB
