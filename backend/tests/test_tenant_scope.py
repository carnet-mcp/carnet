"""The tenant scope's own mechanics. Step 029.

What lives here is the contextvar machinery itself — the cell, the bracket, the
thread-copy hop — separated from what the contract suite asserts (which rows a scoped
*database connection* can see) and from what `test_api.py` asserts (that a real request
wires the seam end to end). These are the tests that would catch the machinery lying
before either of those noticed: a cell that leaks between contexts, a bracket that does
not restore, a thread that inherits a scope it was never given.
"""

import contextvars
import threading

import pytest

from carnet.storage import InMemoryStorage, StorageError, tenancy

from conftest import TEST_ACTOR


def test_no_scope_is_the_default_and_the_worker_shape():
    """A fresh context — which is what every plain `threading.Thread` gets — has no
    scope. This is the property that keeps the worker, the scheduler and the CLI
    unscoped without any of them opting out."""
    assert tenancy.current_tenant() is None


def test_scope_to_fills_the_cell_the_middleware_installed():
    def request():
        tenancy.begin_request()
        assert tenancy.current_tenant() is None

        # The dependency and the endpoint each run in a *copy* of the request context
        # (FastAPI's threadpool). The dependency's copy mutates the shared cell; the
        # endpoint's copy must see it — that reference-sharing is the entire reason the
        # cell exists, and setting the ContextVar itself in the dependency would fail
        # exactly this test.
        dependency_copy = contextvars.copy_context()
        dependency_copy.run(tenancy.scope_to, "t-a")

        endpoint_copy = contextvars.copy_context()
        assert endpoint_copy.run(tenancy.current_tenant) == "t-a"

    contextvars.copy_context().run(request)
    # And nothing escaped the "request": this context never installed a cell.
    assert tenancy.current_tenant() is None


def test_begin_request_gives_each_request_its_own_cell():
    def one_request(tenant):
        tenancy.begin_request()
        tenancy.scope_to(tenant)
        return tenancy.current_tenant()

    assert contextvars.copy_context().run(one_request, "t-a") == "t-a"
    assert contextvars.copy_context().run(one_request, "t-b") == "t-b"
    assert tenancy.current_tenant() is None


def test_the_bracket_restores_what_it_found():
    with tenancy.scoped("t-outer"):
        assert tenancy.current_tenant() == "t-outer"
        with tenancy.scoped("t-inner"):
            assert tenancy.current_tenant() == "t-inner"
        assert tenancy.current_tenant() == "t-outer"
    assert tenancy.current_tenant() is None


def test_the_bracket_restores_on_the_way_out_of_an_exception():
    """The `triggers.deliver` lesson, pinned: a delivery that raises must not leave its
    tenant on the thread — the next direct caller in the same thread would inherit it,
    which is exactly the leak that broke 25 unrelated tests during this step's build."""
    with pytest.raises(RuntimeError):
        with tenancy.scoped("t-a"):
            raise RuntimeError("the delivery failed")
    assert tenancy.current_tenant() is None


def test_a_new_thread_never_inherits_a_scope():
    seen = []
    with tenancy.scoped("t-a"):
        thread = threading.Thread(target=lambda: seen.append(tenancy.current_tenant()))
        thread.start()
        thread.join()
    assert seen == [None]


def test_the_fakes_guard_reads_positional_and_keyword_tenants_alike():
    """The wrapper finds `tenant_id` wherever the caller put it. A guard that only
    checked one spelling would be a rule with a bypass nobody chose."""
    store = InMemoryStorage()
    store.create_tenant("t-a", "A")
    store.create_tenant("t-b", "B")

    with tenancy.scoped("t-a"):
        assert store.get_tenant("t-a")["id"] == "t-a"
        assert store.get_tenant(tenant_id="t-a")["id"] == "t-a"
        with pytest.raises(StorageError, match="tenant scope violation"):
            store.get_tenant("t-b")
        with pytest.raises(StorageError, match="tenant scope violation"):
            store.get_tenant(tenant_id="t-b")

    # Unscoped, the same calls are ordinary — the guard is about scope, not access.
    assert store.get_tenant("t-b")["id"] == "t-b"


def test_the_fakes_guard_leaves_tenantless_methods_alone():
    """`find_api_token`, `claim_run`, `list_tenants` and their kin take no `tenant_id`
    and produce or cross tenants by design; the guard must not invent an opinion about
    them. `list_tenants` under a scope answering *both* tenants is the pinned half of
    the known divergence: on Postgres the policy would show only the scope's row."""
    store = InMemoryStorage()
    store.create_tenant("t-a", "A")
    store.create_tenant("t-b", "B")

    with tenancy.scoped("t-a"):
        assert {row["id"] for row in store.list_tenants()} == {"t-a", "t-b"}


def test_the_guard_survives_a_mutation_that_would_disable_it():
    """The guard is installed by a loop over the class; a refactor that renamed the
    parameter or skipped the install would leave every method unguarded and every test
    above vacuously green. One direct probe: the wrapper is actually in place."""
    method = InMemoryStorage.__dict__["create_group"]
    assert method.__wrapped__ is not None  # functools.wraps leaves the original here


def test_a_guarded_write_refuses_before_touching_anything():
    store = InMemoryStorage()
    store.create_tenant("t-a", "A")
    store.create_tenant("t-b", "B")

    with tenancy.scoped("t-a"):
        with pytest.raises(StorageError, match="tenant scope violation"):
            store.create_group("t-b", "g-x", "Foreign", actor=TEST_ACTOR)

    assert store.list_groups("t-b") == []
