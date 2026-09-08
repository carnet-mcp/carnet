"""MCP connectors: which vetted servers a tenant has, and connecting to them.

A connector used to be a module under `connectors/` plus an import line. It is now a
row, loaded per tenant — and that change is not cosmetic. **Vetting is a tenant's own
decision about a tenant's own server.** Two customers can both run the official GitHub
MCP server and expose different tools from it: one vets reads only, the other also vets
a write. Neither may inherit the other's judgment.

That is why nothing here is a process-global registry any more. A global keyed by tool
name would let one customer's vetting decide what another customer's agents can call,
which is a cross-tenant authorization leak produced by nothing more exotic than two
companies both using GitHub.

Connecting is still deliberately **lazy and per-agent**. Every connector is a container
or a subprocess; an agent that touches no GitHub tool should not pay for a GitHub
server. `tools.ensure_available()` asks which connectors an agent's granted tools belong
to and connects only those.

Failure to connect **raises**. The alternative is an agent that runs with a tool missing
from its schema list, improvises around the gap, and reports something plausible — a
silent degrade in the one place a loud failure costs nothing.
"""

from ... import storage
from . import discovery, egress
from .binding import (
    TOOL_NAME_RE,
    Connector,
    HttpLaunch,
    RestLaunch,
    StdioLaunch,
    Vetted,
    bind,
    from_manifest,
    to_manifest,
    vetted_to_dict,
)
from .egress import EgressRefused
from .client import Session, SessionPool
from .transport import HttpTransport, SessionExpired, StdioTransport, TransportError

# Live sessions, shared across runs. See SessionPool for why this is process-global
# where Budget is per-run.
POOL = SessionPool()


def connectors_for(tenant_id: str) -> list:
    """Every connector this tenant has vetted, as `Connector` objects, ordered by id.

    Loaded on demand with no cache. A cache here would have to be tenant-keyed and
    invalidated on write, and the failure mode of getting that wrong is not a stale
    read — it is one tenant serving another tenant's allowlist. Not worth the risk at
    this scale; when it becomes worth it, that is what it has to get right.
    """
    return [
        from_manifest(manifest)
        for manifest in storage.active().load_connectors(tenant_id)
    ]


def get_connector(tenant_id: str, connector_id: str) -> Connector | None:
    manifest = storage.active().get_connector(tenant_id, connector_id)
    return from_manifest(manifest) if manifest is not None else None


def owner_of(tool_name: str, tenant_id: str) -> Connector | None:
    """Which of this tenant's connectors contributes this tool name, if any."""
    for connector in connectors_for(tenant_id):
        if tool_name in connector.declared_names():
            return connector
    return None


def declared_names(tenant_id: str) -> set:
    """Every tool name this tenant's connectors will contribute once bound.

    Known without connecting, so an agent granting an MCP tool is validated when it is
    saved rather than failing at the first run.
    """
    names = set()
    for connector in connectors_for(tenant_id):
        names |= connector.declared_names()
    return names


def declared_resource_types(tenant_id: str) -> dict:
    """local tool name -> {(resource type, effect)}, without connecting."""
    types = {}
    for connector in connectors_for(tenant_id):
        types.update(connector.declared_resource_types())
    return types


def _transport_for(tenant_id: str, connector: Connector, credential: str | None):
    """Build the transport this connector's manifest names.

    **No fallback between kinds, ever.** stdio holds a credential in a process
    environment for that process's lifetime and HTTP does not, so the two have
    different security properties — quietly substituting one for the other because the
    first would not start would be substituting a security posture. A connector that
    cannot be reached the way it says it should be reached is a failure, not a hint.

    **The egress check is here**, before the transport object exists, because this is the
    one place a transport is built — the same argument that makes `core.broker.call` the
    only route to a tool. A check at registration alone would be a check a stored row
    outlives: revoke a host and every connector already registered against it would keep
    dialling, which is a control that works until somebody uses it.

    It applies to connectors we ship as well as connectors a customer registers, and
    that is deliberate. A provenance exemption is a branch where the check does not run,
    and a branch where the check does not run is the branch everything eventually takes.
    The cost is real and worth stating: a tenant holding an HTTP connector from before
    migration 023 stops connecting until its host is approved.

    `tenant_id` is a new parameter for exactly this, and it is required rather than
    optional. An egress check that could be skipped by omitting an argument is one that
    gets skipped.
    """
    if connector.transport_kind == HttpLaunch.KIND:
        egress.check(tenant_id, connector.launch.url)
        return HttpTransport(
            connector.launch.url, headers=connector.launch_headers(credential)
        )

    # Fail loudly rather than falling through to the stdio branch below, whose
    # AttributeError on a launch with no `command` would send a reader to the wrong
    # module. A REST connector has no MCP transport at all: `tools/rest.bind` binds it
    # without a session, and `ensure_available` dispatches before this is reached.
    if connector.transport_kind == RestLaunch.KIND:
        raise RuntimeError(
            f"connector '{connector.id}' is a REST connector and has no MCP "
            "transport — it binds from its stored bindings without a session. "
            "Reaching this is a dispatch bug, not a configuration problem."
        )

    # Nothing to check. A command has no host — which is decision 3's other half and one
    # of the three reasons decision 2 refuses stdio for anything a customer registers:
    # the egress question is only *one* question when the answer to "where does this
    # go" is a URL.
    return StdioTransport(
        connector.launch.command, env=connector.launch_env(credential)
    )


def _initialized(transport) -> Session:
    """A session that has completed its handshake. The factory `get_or_create` wants."""
    session = Session(transport)
    session.initialize()
    return session


class DelegationUnsupported(RuntimeError):
    """A per-user credential exists for a connector whose transport cannot carry one.

    Its own class rather than a `TransportError`: nothing was sent, nothing failed, and
    the fix is a configuration change by an administrator rather than a retry.
    """


def supports_delegation(connector: Connector) -> bool:
    """Whether this connector's transport can carry a per-user credential at all.

    The predicate under `check_delegation_supported`, split out in 7b because that
    function's *message* is written for one caller and 7b added a second with a different
    situation. It refuses at run time, when a `connections` row already exists, and says
    so: *"A personal account is connected for this connector"*. Configuring a consent
    flow happens before anybody has connected anything, so borrowing that sentence there
    asserted something untrue about the tenant — found by running `--set-oauth` against
    the shipped stdio connector and reading what came back.

    So the fact is shared and the sentence is not. Two callers, two situations, one rule.

    The fact itself lives on `Connector` since 033a, because a third reader appeared —
    `Connector.validate()` refuses a `user` identity on a transport that cannot carry
    one — and a predicate stated in three places is 021's defect waiting to happen.
    """
    return connector.carries_per_user_credentials


def check_delegation_supported(connector: Connector) -> None:
    """Refuse a delegated credential on a transport that cannot hold one.

    stdio takes its credential from the environment at process launch and holds it for
    that process's life, so **one server cannot act as two people**. HTTP sends the
    credential as a header per request, which is the entire reason it was built before
    the access layer rather than after.

    The choice when a `connections` row meets a stdio connector is between ignoring the
    row and refusing the run, and it has to be the refusal: silently using the shared
    environment variable would mean the agent acting as the *operator* while the person
    believes it is acting as them. That is the same untruth the credential read path
    refuses to tell, arriving by a different route — so it gets refused in both places.

    It lives here rather than in `core/credentials.py` because that module is told an
    environment variable *name* and deliberately never learns what an MCP server is.
    This one owns the `Connector` and already decides the transport, so it is the layer
    where a launch kind means anything.
    """
    if supports_delegation(connector):
        return

    raise DelegationUnsupported(
        f"connector '{connector.id}' speaks stdio, and a stdio server takes its "
        "credential from the environment when it starts and holds it for as long as it "
        "runs — so it cannot act as two people. A personal account is connected for "
        "this connector, and falling back to the platform's shared credential would "
        "mean acting as the operator while the audit log reported it as you.\n"
        "  Either move the connector to the HTTP transport, or disconnect the account:\n"
        f"    carnet --disconnect-account {connector.id}"
    )


def ensure_session(
    tenant_id: str, connector: Connector, credential: str | None, transport=None
) -> None:
    """Open a session for this credential if there is not one already. Binds nothing.

    **Binding is a tenant fact; a session is a credential fact.** Which tools exist
    comes from a tenant's vetting and is identical for everybody in it. Which account a
    call goes out as comes from the caller's own credential. Welding the two together —
    "the tools are registered, so there is nothing to do" — is what let a second user
    inherit the first one's session.

    So this exists to be the cheap half. A run by somebody who already has a live
    session does nothing at all; a run by somebody new pays one handshake and no
    `tools/list`, because the allowlist it would return has already been intersected
    for this tenant and cannot differ per user.
    """
    POOL.get_or_create(
        tenant_id,
        connector.id,
        credential,
        lambda: _initialized(transport or _transport_for(tenant_id, connector, credential)),
    )


def connect(tenant_id: str, connector: Connector, credential: str | None, transport=None) -> tuple:
    """Open a session if needed, then bind. Returns (tools, excluded_names).

    Sessions are keyed by tenant as well as credential. Two tenants must never share a
    live session even if they somehow configured the same credential: the session is
    bound to one tenant's manifest, and handing it to another would serve that tenant
    an allowlist it never approved.

    `transport` is injectable so tests never spawn anything. Nothing else passes it.

    Built through `get_or_create` rather than get-then-put: behind a server two runs
    can reach an unconnected connector at the same instant, and the loser of a plain
    check-then-set orphans a live subprocess that nothing will ever close.
    """

    session, created = POOL.get_or_create(
        tenant_id,
        connector.id,
        credential,
        lambda: _initialized(transport or _transport_for(tenant_id, connector, credential)),
    )
    reused = not created

    def call(remote_name, arguments, token):
        # Re-resolved per call rather than closed over: the credential decides the
        # session, and once credentials are delegated two callers of the same tool
        # must land on different ones.
        #
        # **Created when missing, never borrowed.** This used to fall back to the
        # session `connect` opened — which was invisible while every principal shared
        # one credential, and a cross-user leak the moment they stopped: a caller whose
        # session had been evicted would silently transact on whoever's session was
        # captured here. The pool is keyed by credential, so a miss means *this*
        # caller's session is gone, never that somebody else's will do.
        #
        # The cost of a miss is therefore a handshake, which is what makes the pool cap
        # and the idle TTL latency decisions rather than correctness ones.
        target, _ = POOL.get_or_create(
            tenant_id,
            connector.id,
            token,
            lambda: _initialized(transport or _transport_for(tenant_id, connector, token)),
        )
        return target.call_tool(remote_name, arguments)

    # `list_tools()` is the first thing that actually touches the server, which makes
    # it the natural place a stale pooled session reveals itself — a subprocess that
    # died between runs, or an endpoint that recycled. Probing on every connect would
    # cost a round trip to learn what this already tells us for free.
    #
    # Retried once, and only for a session we did not just create: a genuinely
    # unreachable server should be reported, not dialled twice per run. Safe to retry
    # because `tools/list` is a read — a tool *call* is never retried this way.
    try:
        advertised = session.list_tools()
    except TransportError:
        if not reused or transport is not None:
            raise
        POOL.evict(tenant_id, connector.id, credential)
        session, _ = POOL.get_or_create(
            tenant_id,
            connector.id,
            credential,
            lambda: _initialized(_transport_for(tenant_id, connector, credential)),
        )
        advertised = session.list_tools()

    return bind(connector, advertised, call)


__all__ = [
    "POOL",
    "TOOL_NAME_RE",
    "Connector",
    "DelegationUnsupported",
    "EgressRefused",
    "HttpLaunch",
    "HttpTransport",
    "RestLaunch",
    "Session",
    "SessionExpired",
    "SessionPool",
    "StdioLaunch",
    "StdioTransport",
    "TransportError",
    "Vetted",
    "bind",
    "check_delegation_supported",
    "connect",
    "connectors_for",
    "declared_names",
    "declared_resource_types",
    "discovery",
    "egress",
    "ensure_session",
    "from_manifest",
    "get_connector",
    "owner_of",
    "supports_delegation",
    "to_manifest",
    "vetted_to_dict",
]
