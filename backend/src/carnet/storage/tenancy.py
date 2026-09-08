"""The ambient tenant scope — who a borrowed connection is allowed to answer for.

Step 029. This module is the seam between *who is asking* (the access layer knows) and
*which rows the database will show* (`PostgresStorage._connection()` enforces, by taking
the ``agent_runtime_tenant`` role and binding ``agent_runtime.tenant_id`` — see migration
037). It holds one fact: the tenant of the request currently being served, or nothing.

## Why a mutable cell inside the contextvar, not the contextvar alone

Every endpoint in this API is ``def``, pinned by ``test_every_endpoint_is_sync`` — so
FastAPI runs the auth dependency and the endpoint in **separate threadpool calls, each
with its own copy of the request's context**. A ``ContextVar.set()`` inside
``principal_from_request`` would land in the dependency's copy and vanish before the
endpoint runs. The middleware therefore installs an empty mutable cell in the request's
own task context; every threadpool copy shares that object by reference, so the
dependency's ``scope_to()`` is visible to the endpoint and to every storage call it
makes.

## Who never has a scope, on purpose

The API's own maintenance thread (``LogMaintainer`` — partitions and retention, plus
083's OAuth sweep), key rotation, the migration runner and the CLI all run in plain
threads with empty contexts and never call ``scope_to``. That is not a gap: their
queries are deliberately cross-tenant — ``prune_log_records`` drops a month of every
tenant's log rows at once, and takes no tenant — and the policies in migration 037 apply
only to the tenant role, which an unscoped borrow never takes. An unscoped borrow is
byte-identical to what every borrow was before this module existed.

**This paragraph named the worker and the scheduler until step 085.** Step 078 deleted
both; what it did not delete is the property, because the sweep above inherited their
position exactly — an unscoped loop in a process that is also serving scoped requests,
whose exemption comes from *ownership* rather than from any privilege. ``e2e_rls.py``
drives that shape against a real server.
"""

from contextlib import contextmanager
from contextvars import ContextVar


class _Cell:
    """One request's scope. Mutable on purpose — see the module docstring."""

    __slots__ = ("tenant_id",)

    def __init__(self) -> None:
        self.tenant_id: str | None = None


_cell: ContextVar[_Cell | None] = ContextVar("carnet_tenant_scope", default=None)


def begin_request() -> None:
    """Install a fresh, empty cell. Called by the API middleware, per request.

    Fresh rather than reused: the cell is what crosses thread-context copies, so a
    request must never inherit the previous request's object. Each request is its own
    asyncio task and tasks copy context at creation, which is what keeps two concurrent
    requests' cells apart without a lock.
    """
    _cell.set(_Cell())


def scope_to(tenant_id: str) -> None:
    """Bind the current scope to one tenant.

    Two callers, one per place a tenant becomes known: ``deps.principal_from_request``,
    once a credential resolves to a `Principal` — the one door every authenticated route
    passes through, the MCP door included — and ``access/oauth_server``'s token exchange
    (step 083), once the authorization code row has named the tenant it was issued for.
    A third place binds a tenant with the ``scoped()`` bracket below rather than with
    this function — ``access/oauth.complete``, whose comment says why. It was
    ``triggers.deliver`` in that third position until step 078 deleted the trigger door. When no cell was installed (a caller outside a request —
    tests driving a module directly), one is created in this thread's context, which
    scopes the remainder of the thread's work exactly as the request path would.
    """
    cell = _cell.get()
    if cell is None:
        cell = _Cell()
        _cell.set(cell)
    cell.tenant_id = tenant_id


def current_tenant() -> str | None:
    """The tenant the current context is serving, or None for the unscoped paths."""
    cell = _cell.get()
    return cell.tenant_id if cell is not None else None


@contextmanager
def scoped(tenant_id: str):
    """A bounded scope, restored on exit. For tests and for future per-task scoping.

    ``scope_to`` deliberately does not restore — a request ends and its context dies
    with its task, so there is nothing to restore *to*. Anything longer-lived than a
    request (a test, or one day the worker's execution phase) wants the bracket instead,
    so a scope cannot outlive the work it was opened for.
    """
    cell = _cell.get()
    if cell is None:
        cell = _Cell()
        token = _cell.set(cell)
        try:
            cell.tenant_id = tenant_id
            yield
        finally:
            _cell.reset(token)
        return

    previous = cell.tenant_id
    cell.tenant_id = tenant_id
    try:
        yield
    finally:
        cell.tenant_id = previous
