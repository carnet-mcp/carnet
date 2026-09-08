"""Tool registry — every tool the platform knows about, keyed by name.

Adding a tool family: create a module beside this one exporting a `TOOLS` list, then
add one import line below. Adding a tool to an existing family touches only that
module. A connector contributes tools here too — generated from `tools/list`, with
effect and resources added at vetting time — and everything downstream is unchanged.

Two registries, split along a line that is a security boundary rather than a filing
convenience:

    REGISTRY      hand-written tools. **Process-global**, because they are code: every
                  tenant gets the same `post_message`, and it is the same object.
    _BOUND        connector tools, **per tenant**, populated when a connector binds.

Connector tools cannot be global. Vetting is a tenant's own decision about a tenant's
own server, so two customers running the same MCP server can expose different tools
from it — one vets reads only, the other also vets a write. A single registry keyed by
tool name would let the second customer's vetting decide what the first customer's
agents can call. That is a cross-tenant authorization leak, and it needs nothing more
exotic than two companies both using GitHub.

Two sets of names, and the difference still matters:

    get(name, tenant)          tools callable right now for this tenant
    known_names(tenant)        every name this tenant recognises, including vetted
                               connector tools nobody has connected yet

An agent config is validated against `known_names`, so granting an MCP tool is checked
when the config is saved rather than failing at the first run. The broker looks in
`get()`, so an unbound tool is refused rather than improvised — fail-closed either way.

Note: tool names must match ^[a-zA-Z0-9_-]{1,64}$ per the Messages API, so dotted
names like `github.get_issues` aren't expressible. Connector tools are namespaced
with underscores instead: `github_mcp_list_issues`.
"""

import json
import logging
import threading
from dataclasses import replace

from .. import config, storage
from .base import MAY_HAVE_COMPLETED, REPORTED_USAGE, Resource, Tool, uncallable
from .messaging import TOOLS as _MESSAGING_TOOLS
from .validation import VALID_EFFECTS, VALID_IDENTITIES, validate

log = logging.getLogger(__name__)

# Imported after validation so a connector manifest can use it without a cycle.
from . import mcp  # noqa: E402  isort:skip

# After mcp, which it builds on: `tools/rest` is the second connector kind (045a) —
# same Tool objects out, no session underneath.
from . import rest as rest_binding  # noqa: E402  isort:skip

# Hand-written tools are now the exception rather than the rule. `post_message` is
# here because there is no vendor to get it from — it picks Slack, Discord or a local
# file from the URL shape, which is our logic, not an API someone else publishes.
# Anything that *is* a wrapper around a vendor API belongs in a connector.
_ALL = [
    *_MESSAGING_TOOLS,
]

for _tool in _ALL:
    validate(_tool)

REGISTRY: dict[str, Tool] = {tool.name: tool for tool in _ALL}

# Fail loudly at import time rather than silently shadowing a tool.
if len(REGISTRY) != len(_ALL):
    raise RuntimeError("Duplicate tool name in registry")

# Connector tools, per tenant. Populated by `register()` when a connector binds and
# never at import, because which connectors exist is now a question about a row.
#
# Guarded, because a server binds for two tenants at once. CPython's GIL happens to
# make the individual dict operations here atomic, so the unlocked version was safe by
# accident rather than by design — and "safe on this interpreter, for these exact
# statements" is not a property worth resting a tenant boundary on.
_BOUND: dict[str, dict[str, Tool]] = {}
_BOUND_LOCK = threading.RLock()


def get(name: str, tenant_id: str) -> Tool | None:
    """Look up a callable tool by name, for this tenant. None if unknown.

    Hand-written tools are checked first. A connector must not be able to shadow one —
    the name in a grant, and in an audit record, has to mean exactly one thing. That
    collision is refused when the connector is saved (see `save_connector`); checking
    static first is the backstop, and it resolves in favour of the tool we wrote.

    A vetted-but-unbound connector tool returns None here. That is deliberate: the
    broker refuses what it cannot describe, so a failed connection cannot become a
    call that runs unscoped.
    """
    static = REGISTRY.get(name)
    if static is not None:
        return static
    with _BOUND_LOCK:
        return _BOUND.get(tenant_id, {}).get(name)


def describe(name: str, tenant_id: str) -> Tool | None:
    """What the permission check would read about this name. None if unknown. Step 069.

    The accessor beside `get`, and the pair is worth reading together because the
    difference between them is a real state rather than a convenience:

        get(name, tenant)        can this be CALLED?         None when unbound
        describe(name, tenant)   what would the CHECK read?   a row, never a socket

    A tool that describes but does not get is **vetted-and-unbound**, which is the
    ordinary state of every connector tool on a process that has not served a call for
    it yet. A simulator built on `get` would therefore answer *"not a registered tool"*
    for a tenant's whole catalogue on the first page load after a restart — a false
    verdict, in the reassuring direction, produced by a cold cache.

    **Nothing this returns can run.** A hand-written tool's real implementation is right
    there in `REGISTRY`, and handing it out is exactly what must not happen, so it is
    replaced by `uncallable` on the way past — see that function. The rule is uniform
    because a half-uniform one is a rule nobody can state.

    **What it does not answer.** Whether the connector will bind, whether the caller has
    a credential, whether the server still advertises the tool. `permissions.check`
    reads none of those, and neither does this: the whole point is that *permitted* is
    settled by rows while *available* needs a handshake. A caller conflating them is
    door.simulate's `not_checked` list, not this function's problem.

    One name is `describe_all`'s single-element case, and is written that way rather than
    beside it — see there for why asking about several at once is not the same as asking
    about one several times.
    """
    return describe_all([name], tenant_id)[name]


def describe_all(names, tenant_id: str) -> dict[str, Tool | None]:
    """`describe`, for several names, over **one** read of this tenant's connectors.

    Step 069's edge pass, and it exists because the obvious loop is quadratic in a place
    that is read on a page load. `describe` resolves a connector tool through
    `mcp.owner_of`, which walks `connectors_for` — a storage read — so calling it once
    per granted tool made `door.reach` cost **one `load_connectors` per tool**: 61 reads
    for a token granted 30, where 1 is enough. Nothing was wrong with the answers; the
    cost simply grew with the thing being described.

    Builtins never reach the loop at all, so a set of hand-written names still costs no
    storage read.

    Returns a dict keyed by **every** name asked for, with `None` for the ones nothing
    describes — so a caller iterating its own list never has to decide whether a missing
    key means *unknown* or *forgot to ask*.
    """
    found: dict[str, Tool | None] = {}
    unresolved = set()
    for name in names:
        static = REGISTRY.get(name)
        if static is not None:
            # Static first, and a connector must not be able to shadow one — `get`'s
            # rule, and the same backstop, resolving in favour of the tool we wrote.
            found[name] = replace(static, impl=uncallable)
        else:
            found[name] = None
            unresolved.add(name)

    if unresolved:
        # `connectors_for` is ordered by id, and a name is claimed by the **first**
        # connector that declares it — `owner_of`'s rule, which the single-name version
        # of this used to get for free by calling it. Two connectors contributing one
        # local name is refused at `save_connector` (`check_no_collision`) and so should
        # not arise; when it does, both readers must pick the same one.
        for connector in mcp.connectors_for(tenant_id):
            for vetted in connector.vetted:
                local = connector.local_name(vetted)
                if local in unresolved:
                    found[local] = mcp.binding.described(connector, vetted)
                    unresolved.discard(local)
            if not unresolved:
                break

    return found


def known_names(tenant_id: str) -> frozenset:
    """Every tool name this tenant recognises, bound or not.

    Used by agent validation, which is why it counts vetted-but-unconnected tools: a
    grant naming an MCP tool is legitimate before anyone has connected to its server.
    """
    return frozenset(REGISTRY) | mcp.declared_names(tenant_id)


def is_known(name: str, tenant_id: str) -> bool:
    """Is this a name this tenant recognises, bound or not?"""
    return name in known_names(tenant_id)


# --- the catalogue ----------------------------------------------------------------

# What the built-in group calls itself. Not "platform" or a vendor name: these are code
# in this repository, and the honest description of where they came from is that they
# arrived with the software rather than from anybody's review.
BUILTIN_ORIGIN = "builtin"
CONNECTOR_ORIGIN = "connector"
BUILTIN_DESCRIPTION = "Tools that ship with the platform."


def catalogue(tenant_id: str) -> list[dict]:
    """Everything this tenant may grant, grouped by where it came from.

    The union of both registries, as plain data — because `known_names` is the union
    and `agents.validate` accepts a grant naming either half. A catalogue of
    *connectors* could not describe `post_message`, which is in the grant of
    `issue-reporter`, the one worked example this repo ships.

    Lives here rather than in the route for the reason `access/connections.py` holds
    the credential logic: `GET /tools` and `--list-tools` must answer the same
    question, and two readers of one table is how they stop agreeing.

    **No server is contacted.** Connector tools are described from the stored manifest,
    not from `tools/list`, so this answers with every connector's server stopped. That
    is the whole of migration 018's argument: a page about *choosing* a tool must not
    depend on servers being *up*, and text that can change after approval was not part
    of the approval.

    `origin` is a field rather than an omission. The two halves have genuinely
    different provenance — one was vetted by somebody in this tenant and carries their
    name, the other is code in this repository and carries nobody's — and presenting
    them as one undifferentiated list would hide the difference that decides who to ask
    when something is wrong.
    """
    review = _review_record(tenant_id)

    groups = [
        {
            "origin": BUILTIN_ORIGIN,
            "id": "",
            "description": BUILTIN_DESCRIPTION,
            "tools": [_builtin_entry(tool) for tool in REGISTRY.values()],
        }
    ]

    # `connectors_for` is ordered by id, so the groups are too.
    for connector in mcp.connectors_for(tenant_id):
        groups.append(
            {
                "origin": CONNECTOR_ORIGIN,
                "id": connector.id,
                "description": connector.description,
                "tools": [
                    _connector_entry(connector, vetted, review)
                    for vetted in connector.vetted
                ],
            }
        )

    return groups


def _review_record(tenant_id: str) -> dict:
    """`(connector_id, remote_name) -> the review row`, from storage. See `VETTING_FIELDS`.

    Read separately from the manifest because it *is* separate: provenance is a column
    the database owns, never something a caller asserts by passing a dict. See
    `Storage.load_vetting_record`.
    """
    return {
        (row["connector_id"], row["remote_name"]): row
        for row in storage.active().load_vetting_record(tenant_id)
    }


def _resource_types(resources) -> list[dict]:
    """Resource **types**, and nothing else. Decision 2 of the plan.

    `Resource("github.repo", ["owner", "repo"], template="{owner}/{repo}")` is how a
    repo is composed out of one server's two arguments. Policy never learns that, and
    that indirection is what lets one `github.repo` grant cover every tool touching a
    repo including tools we did not write. Handing `args` and `template` to a client
    invites it to build a scope out of argument names, which is the coupling the type
    exists to prevent — and it would be invisible until a second connector named the
    same resource differently.

    Deduplicated, in declaration order: a tool may declare two resources of the same
    type (`copy_issue(from_repo, to_repo)`), and both are checked, but a catalogue
    listing `github.repo` twice says nothing a reader can act on.
    """
    seen, types = set(), []
    for ref in resources:
        if ref.type in seen:
            continue
        seen.add(ref.type)
        types.append({"type": ref.type})
    return types


def _builtin_entry(tool: Tool) -> dict:
    """One hand-written tool, as a catalogue row.

    `vetted_by` and `vetted_at` are empty. **Not omitted** — a client rendering "vetted
    by" needs one shape — and empty rather than `"platform"`, because inventing a
    reviewer for something nobody reviewed is exactly the false assurance the
    `vetted_tools` table exists to avoid. Their provenance is this repository's git
    history, which is not a thing this function can return.

    The description is the tool's own, which is the text the **model** is given. That
    is a known limit rather than an oversight: a second, human-facing description would
    be a second sentence about one tool, free to drift from the one that actually
    reaches the model. What a model is told a tool does is a real thing to show
    somebody deciding whether to grant it.
    """
    return {
        "name": tool.name,
        # Absent rather than empty: only one of the two halves has an upstream, and
        # saying so is the honest way to render the difference.
        "remote_name": None,
        "description": tool.description,
        "note": "",
        "effect": tool.effect,
        "identity": tool.identity,
        "resources": _resource_types(tool.resources),
        "max_response_bytes": tool.max_response_bytes,
        "vetted_by": "",
        "vetted_at": "",
        # Empty for the same reason `vetted_by` is: a hand-written tool was never vetted
        # against a server advertisement, because there is no server. Present rather than
        # omitted so one client shape renders both halves.
        "server_name": "",
        "server_version": "",
    }


def _connector_entry(connector, vetted, review: dict) -> dict:
    """One vetted connector tool, as a catalogue row.

    `name` is the **local** name, because that is what a grant says and what the audit
    log records. `remote_name` is what the server calls it, and it is here because the
    two differ and somebody reading a vendor's documentation needs the second one.
    """
    record = review.get((connector.id, vetted.remote_name), {})
    return {
        "name": connector.local_name(vetted),
        "remote_name": vetted.remote_name,
        "description": vetted.description,
        "note": vetted.note,
        "effect": vetted.effect,
        "identity": vetted.identity,
        "resources": _resource_types(vetted.resources),
        "max_response_bytes": vetted.max_response_bytes,
        "vetted_by": record.get("vetted_by", ""),
        "vetted_at": record.get("vetted_at", ""),
        # What the server called itself when this tool was approved — migration 023.
        # Empty on anything `--seed` wrote and on anything vetted before 023, because
        # neither contacted a server, and empty is what that says.
        "server_name": record.get("server_name", ""),
        "server_version": record.get("server_version", ""),
    }


def check_no_collision(connector) -> None:
    """Refuse a connector whose namespaced names would shadow hand-written tools.

    Extracted from `save_connector` in step 012 because registration now has a second
    path into the same namespace — `--vet` adds one tool at a time and must be subject
    to the identical rule. A check that lived only in the wholesale save would be one
    the incremental path silently skipped, which is how `github_mcp_post_message` ends
    up meaning two different things depending on which command created it.

    The check used to run at import over a global connector list. It is a question about
    *this tenant's* namespace and about the moment the data arrives, which is why it
    moved here and why it stays here.
    """
    colliding = frozenset(REGISTRY) & connector.declared_names()
    if colliding:
        raise RuntimeError(
            f"connector '{connector.id}' contributes {sorted(colliding)}, which "
            "collide with hand-written tools. A grant naming one of these would be "
            "ambiguous."
        )


def save_connector(tenant_id: str, connector, *, actor) -> None:
    """Vet a connector for this tenant: check it, then store it, wholesale.

    **This is `--seed`'s method.** It replaces the whole allowlist, which is right for a
    shipped module that *is* the allowlist and wrong for registration — see
    `storage.vet_tool`, which is what `--vet` uses and which appends.
    """
    connector.validate()
    check_no_collision(connector)

    storage.active().save_connector(tenant_id, mcp.to_manifest(connector), actor=actor)


# --- registration -----------------------------------------------------------------
#
# The customer-facing half of connector onboarding. Until step 012 a connector was a
# Python module and adding one was a change to our source and a release of our product;
# these three functions are the distance from "we integrate for you" to "you bring your
# own", and they are deliberately not one function.


class RegistrationRefused(RuntimeError):
    """A registration or vetting request cannot be honoured, and it is the caller's fault.

    Its own class for the reason `AgentNameTaken` and `EgressRefused` have theirs: every
    other `RuntimeError` out of this package means something broke, and this one means
    the platform is working perfectly and the request describes something that must not
    exist. The CLI turns it into a `parser.error`, which is a sentence and an exit code
    rather than a traceback.
    """


# Decision 2, and the sentence a customer actually reads when they hit it.
#
# The plan justifies refusing stdio by the shared-infrastructure argument — we would be
# spawning arbitrary customer-supplied code, and the only thing between it and every
# other tenant is that we chose to run it. **On a single-tenant deployment that argument
# does not hold**: there is no other tenant, and the trust boundary is the customer's
# own. The decision survives anyway, on the two reasons that do not depend on tenancy:
#
#   1. **HTTP is the only transport that can carry a per-user credential.** A stdio
#      server takes its credential from the environment at launch and holds it for the
#      process's life, so a self-serve stdio connector would be one where every user of
#      every agent shares one service account — see `check_delegation_supported`, which
#      already refuses that combination at run time. Refusing the transport at
#      registration makes delegated credentials the default for everything a customer
#      adds, which is the behaviour step 7a built and the shipped connector still cannot
#      use.
#
#   2. **The egress question becomes one question.** A URL has a host and the allowlist
#      has something to check; a command has no such thing.
#
# The cost, stated rather than minimised: a customer whose MCP server speaks stdio must
# put HTTP in front of it. That is a smaller ask than it sounds — it is one line in the
# common SDKs and there are off-the-shelf shims — but it is a real one, and it is the
# first thing to revisit if it turns out to be the common case rather than the rare one.
STDIO_REFUSED = (
    "a registered connector must speak HTTP, so --add-connector takes --url and not a "
    "command.\n"
    "  Why: a stdio server takes its credential from the environment when it starts and "
    "holds it for as long as it runs, so it cannot act as two people — every user of "
    "every agent would share one service account. HTTP sends the credential per request, "
    "which is what makes per-user credentials possible at all.\n"
    "  If your server speaks stdio, you do not have to rewrite it — put HTTP in front of "
    "it and host it yourself. `mcp-proxy` and `supergateway` are off-the-shelf shims, "
    "and both the Python and TypeScript MCP SDKs switch transport in one line "
    "(FastMCP: `mcp.run(transport=\"streamable-http\")`).\n"
    "  Connectors that ship with the platform keep stdio. The distinction is not "
    "transport, it is provenance: code we ship versus code you name."
)


def register_connector(
    tenant_id: str,
    connector_id: str,
    *,
    url: str,
    kind: str = "http",
    credential_env: str = "",
    credential_ref: str = "",
    credential_header: str | None = None,
    credential_prefix: str | None = None,
    headers: dict | None = None,
    description: str = "",
    allow_asserted_identity: bool = False,
    # Step 068: the id of the checked-in recipe these values came from, for the
    # administrative record and nothing else. This layer neither reads recipes nor knows
    # what one is — `access/recipes.py` does, one layer up — so this is a string passed
    # through, which is the whole of `tools/` knowing no policy.
    from_recipe: str = "",
    actor: str,
) -> None:
    """Register a connector. **Vets nothing.**

    The row, so a credential has somewhere to live. Migration 021's foreign key means a
    credential cannot be sealed against a connector that does not exist, and discovery
    needs a credential — a server will not list its tools to an unauthenticated caller —
    so *connect, look, then decide whether to register* is not expressible. This is the
    method that resolves that ordering, and the ordering is why it exists separately
    from vetting rather than as a flag on it.

    `credential_header`, `credential_prefix` and `headers` are how a vendor that does not
    want `Authorization: Bearer` is registered — step 045c, and until it they were fields
    on `HttpLaunch`/`RestLaunch` that **no administrator could reach**. This function
    always built `launch_cls(url=..., credential_env=...)`, so the only writer that ever
    set them was `save_connector`, the wholesale `--seed` path. `RestLaunch`'s own comment
    had already named the customer — *"`x-api-key` with no prefix is the first named
    customer (plan 045c)"* — and a field that looks supported and is unreachable is worse
    than an absent one, which is why `DEFERRED.md` carried it as a row rather than a note.

    None means *the launch's own default* for each, which is what keeps every existing
    caller meaning exactly what it meant. `""` is a real value and is not None: an API
    wanting the bare token in its header (`x-api-key`) is registered with an empty
    prefix, and `_launch_from_dict` already distinguishes the two on the way back out.

    The URL's host is checked against the tenant's egress allowlist **here as well as at
    dial time**, and the redundancy is the point: a refusal at registration is one a
    person can act on while they still have the command in their shell, where the same
    refusal three days later at the first run is a mystery. The dial-time check is the
    one that is load-bearing, because a stored row outlives the moment it was written and
    a host can be revoked after it was approved.
    """
    if not url:
        raise RegistrationRefused(STDIO_REFUSED)

    # `kind` decides which launch shape the row carries — step 045a. Defaulted to
    # `http` so every existing caller means exactly what it meant; failed closed on
    # anything else, on `_launch_from_dict`'s reasoning: the kinds have different
    # security properties, and guessing between them would be guessing at those.
    if kind not in (mcp.HttpLaunch.KIND, mcp.RestLaunch.KIND):
        raise RegistrationRefused(
            f"--kind must be 'http' (a Streamable HTTP MCP server) or 'rest' (a "
            f"plain REST API), not {kind!r}. stdio is refused for anything a "
            "customer registers — see --add-connector's help."
        )
    launch_cls = mcp.RestLaunch if kind == mcp.RestLaunch.KIND else mcp.HttpLaunch

    # Constructing the launch is itself a check: both `__post_init__`s refuse a URL
    # that is not http(s), with a message that says why a value causing an outbound
    # request is checked rather than assumed.
    # Only the keys that were actually given, so each unset one takes the dataclass's
    # own default rather than a None this function would have to translate.
    presented = {
        key: value
        for key, value in (
            ("credential_header", credential_header),
            ("credential_prefix", credential_prefix),
            ("headers", dict(headers) if headers else None),
        )
        if value is not None
    }
    launch = launch_cls(
        url=url,
        credential_env=credential_env or None,
        credential_ref=credential_ref or None,
        **presented,
    )

    # Step 070: one or the other, never both. Refused here as well as at the read
    # (`core.credentials._shared_credential`), on the same two-place reasoning the two
    # checks below use — and here first, because a refusal while the command is still in
    # somebody's shell is one they can act on, where the same refusal at the first door
    # call three days later is a mystery.
    if launch.credential_env and launch.credential_ref:
        raise RegistrationRefused(
            "a connector's shared credential is either an environment variable this "
            "deployment holds (--credential-env) or a reference into your own vault "
            "that is read at call time (--credential-ref) — not both. There is no rule "
            "for which would win, and inventing one would decide which secret gets "
            "sent to a vendor."
        )

    # **The pointer's SYNTAX is not checked here, and the reason is the layering.**
    # `core/vault.py` owns what an `op://` reference means, and `tools/` may not import
    # `core/` — the direction `config.py` states beside `is_platform_env`. So the
    # friendly, early refusal for a malformed reference lives at the entry points that
    # may import both (`cli.py`, `api/routes_admin_connectors.py`), and the load-bearing
    # one lives at the read (`core.credentials._reference_credential`), which is the
    # same two-place shape `mcp.egress.check` and `config.is_platform_env` already use.
    # A wholesale `--seed` that skipped the entry points writes a row that refuses at
    # first use, naming the syntax — not one that silently authenticates as nobody.
    #
    # The both-set rule *is* checked here, because it needs no vocabulary at all.

    # A connector may not name one of the platform's own environment variables — step
    # 050, blocker B1 of plan 049. Refused here as well as at the credential read
    # (`core.credentials._shared_credential`), for `mcp.egress.check`'s reason on the
    # next line: a refusal at registration is one a person can act on while the command
    # is still in their shell; the read-time check is the load-bearing backstop for a
    # row that outlives this moment or a path that skipped it.
    if launch.credential_env and config.is_platform_env(launch.credential_env):
        raise RegistrationRefused(
            f"credential_env {launch.credential_env!r} is one of the platform's own "
            "environment variables and is never sent to a vetted server — it would "
            "hand this connector the deployment's own secret. A connector's credential "
            "must be its own: a variable outside the CARNET_ namespace, or one under "
            "CARNET_CONNECTOR_."
        )

    mcp.egress.check(tenant_id, launch.url)

    storage.active().create_connector(
        tenant_id,
        connector_id,
        launch=mcp.to_manifest(mcp.Connector(id=connector_id, launch=launch))["launch"],
        description=description,
        allow_asserted_identity=allow_asserted_identity,
        from_recipe=from_recipe,
        actor=actor,
    )


def set_asserted_identity(
    tenant_id: str, connector_id: str, allowed: bool, *, actor: str
) -> None:
    """Turn asserted acting-for on or off for one connector. Step 033c.

    A security control changing state, so it is its own verb with its own
    administrative record (`connector.asserted_identity`, naming the actor and the new
    value) rather than a field on some broader edit. The storage layer refuses a
    connector nobody registered; there is no enable-on-toggle for the same reason
    there is no create-on-vet.

    What it gates: whether an *asserted* acting-for through the MCP door — an email
    the caller supplies, believed rather than verified — is accepted for this server's
    tools. Off is the posture (verified or nothing); turning it on is trust in the
    calling application, with a name on the change.
    """
    storage.active().set_asserted_identity(tenant_id, connector_id, allowed, actor=actor)


def vet_tool(
    tenant_id: str,
    connector_id: str,
    remote_name: str,
    *,
    effect: str,
    identity: str = "service",
    resources: tuple = (),
    note: str = "",
    local_name: str | None = None,
    max_response_bytes: int | None = None,
    actor: str,
    credential: str | None = None,
    transport=None,
    binding: dict | None = None,
    description: str = "",
    redact_args: tuple = (),
) -> dict:
    """Approve one tool on a registered connector. Returns what was recorded.

    Six checks, in an order chosen so the cheapest refusal a person can act on comes
    first and the one that costs a round trip comes only after the rest have passed:

    1. the connector is registered — otherwise there is nothing to vet a tool *on*
    2. the server advertises this tool — you cannot approve something nobody offers
    3. the annotation validates **against the advertised schema**, which is where
       `--resource jira.project=projectKey` meets the fact that this server calls it
       `project`, and where an unscopeable write is refused with a sentence
    4. the local name is legal and does not shadow a hand-written tool
    5. nothing already vetted on this connector has drifted (decision 6)
    6. the write itself, which stamps who, when, and against what

    Step 3 is the one that makes the whole command work. `validate()` compares the
    descriptor to the schema the server just sent, so the argument-existence rule fires
    at the moment somebody typed the argument name rather than at the first run — which
    is the difference between a typo and an outage.

    Step 5 is the part that is easy to leave out and expensive to omit. Vetting a tenth
    tool on a server whose first nine have drifted would be approving a new thing on top
    of a manifest that no longer binds, and the operator would not find out until the
    next run of an unrelated agent.
    """
    connector = mcp.get_connector(tenant_id, connector_id)
    if connector is None:
        raise RegistrationRefused(
            storage.NO_SUCH_CONNECTOR_TO_VET.format(
                connector=connector_id, tenant=tenant_id
            )
        )

    # Step 045a: a REST connector's vetting is authoring, not reviewing — there is
    # no server to ask, so the six checks above become a different set and live in
    # their own function rather than as branches through every one of these.
    if connector.transport_kind == mcp.RestLaunch.KIND:
        return _vet_rest_tool(
            tenant_id,
            connector,
            remote_name,
            effect=effect,
            identity=identity,
            resources=resources,
            note=note,
            local_name=local_name,
            max_response_bytes=max_response_bytes,
            actor=actor,
            binding=binding,
            description=description,
            redact_args=redact_args,
        )

    # The REST-only inputs, refused rather than dropped on an MCP connector: the
    # description is copied from the server's advertisement and the schema is
    # discovered, so accepting either here would store words the approval did not
    # come from — and a field silently ignored reads as honoured.
    if binding is not None or description:
        raise RegistrationRefused(
            f"'{connector_id}' is an MCP server: its tools' schemas are discovered "
            "and their descriptions are copied from the advertisement, so a request "
            "binding or an authored description has no meaning here. Those inputs "
            "belong to REST connectors (--kind rest)."
        )

    # A per-person identity needs a transport that can carry a per-person credential.
    # Refused at vet time — where the person deciding is still at the form — rather
    # than at the first run, where the same fact arrives as a mystery. Only shipped
    # connectors can be stdio (registration refuses it), which is exactly where a
    # guard that cannot rely on registration's refusal belongs.
    #
    # **Not the only guard, deliberately.** `Connector.validate()` refuses the same
    # combination inside `from_manifest`, which is what covers `save_connector`'s
    # wholesale write and every subsequent load. This one exists for its sentence.
    if identity == "user" and not mcp.supports_delegation(connector):
        raise RegistrationRefused(
            f"'{remote_name}' cannot act as the person calling it: connector "
            f"'{connector_id}' speaks stdio, which takes its credential from the "
            "environment at launch and holds it for the process's life — one server "
            "cannot act as two people. Move the connector to the HTTP transport, or "
            "vet the tool with identity 'service'."
        )

    seen = mcp.discovery.discover(tenant_id, connector, credential, transport=transport)
    advertised = {tool.get("name"): tool for tool in seen["tools"]}

    spec = advertised.get(remote_name)
    if spec is None:
        offered = ", ".join(sorted(name for name in advertised if name)) or "<none>"
        raise RegistrationRefused(
            f"'{connector_id}' does not advertise a tool called '{remote_name}'. "
            f"It offers: {offered}."
        )

    vetted = mcp.Vetted(
        remote_name=remote_name,
        effect=effect,
        identity=identity,
        resources=resources,
        local_name=local_name,
        max_response_bytes=max_response_bytes,
        # The vendor's words, copied at vetting time rather than restated. Same decision
        # migration 018 made and for the same reason: a catalogue must answer with the
        # server stopped, and a description we wrote would drift from what the tool does.
        description=spec.get("description") or spec.get("title") or "",
        note=note,
        # Checked against the schema the server just advertised, one call down in
        # `validate` — so a redaction naming an argument this tool does not take is
        # refused while the person who typed it is still at the form. Step 045c.
        redact_args=redact_args,
    )

    # Checks 3 and 4, and **they are re-raised as `RegistrationRefused` rather than left
    # as the bare `RuntimeError` `validate` throws.**
    #
    # Every one of these is a caller error with a sentence already written for exactly
    # this reader: *this write declares no resources*, *this argument is not in the input
    # schema*, *this local name shadows a hand-written tool*. The CLI has always turned
    # them into a `parser.error` by catching `RuntimeError` at the call site, which worked
    # because a terminal has one caller.
    #
    # 12c added a second, and a route has no such catch-all: a bare `RuntimeError` is an
    # unmapped exception and therefore a **500**. So the three commonest mistakes anybody
    # can make on a vetting form — a write with nothing to scope it to, a resource
    # pointing at an argument that does not exist, a name collision — would each have
    # answered *"Internal Server Error"* to an administrator whose remedy was to change
    # one field. Found by driving the route, which is the fifth time this codebase has
    # found this shape and the first time the fix was one level below the entry point.
    #
    # `RegistrationRefused` is a `RuntimeError`, so the CLI's existing except tuple is
    # unaffected and its message is unchanged.
    try:
        validate(
            Tool(
                name=connector.local_name(vetted),
                description=vetted.description,
                input_schema=spec.get("inputSchema")
                or {"type": "object", "properties": {}},
                impl=lambda **_: None,
                effect=vetted.effect,
                identity=vetted.identity,
                resources=vetted.resources,
                redact_args=frozenset(vetted.redact_args),
            )
        )

        # The namespace checks, run over the connector as it *would be* — which is the
        # only way to catch a local name that collides with a tool this same connector
        # already vets, as well as one that shadows a hand-written tool.
        candidate = mcp.Connector(
            id=connector.id,
            launch=connector.launch,
            description=connector.description,
            vetted=[v for v in connector.vetted if v.remote_name != remote_name]
            + [vetted],
        )
        candidate.validate()
        check_no_collision(candidate)
    except RegistrationRefused:
        raise
    except RuntimeError as exc:
        raise RegistrationRefused(str(exc)) from exc

    vetting = {
        (row["connector_id"], row["remote_name"]): row
        for row in storage.active().load_vetting_record(tenant_id)
    }
    drift = mcp.discovery.refusals(
        mcp.discovery.review(connector, seen["tools"], vetting)
    )
    if drift:
        raise RegistrationRefused(
            "this connector's existing vetting no longer matches what the server "
            "advertises, so nothing new was approved on it:\n\n"
            + "\n\n".join(f"  - {finding['message']}" for finding in drift)
        )

    server = seen["server"]
    storage.active().vet_tool(
        tenant_id,
        connector_id,
        # Through the same function `to_manifest` uses, so a tool written one at a time
        # and a tool written wholesale produce byte-identical rows. Two serializers for
        # one shape is how `--seed` and `--vet` start disagreeing about a `template`.
        mcp.vetted_to_dict(vetted),
        actor=actor,
        server_name=server.get("name") or "",
        server_version=server.get("version") or "",
        # The baseline a later `--discover` diffs against. Names only — they are what a
        # `Resource` binds to, and storing the whole schema would put a copy of a
        # vendor's contract in our database free to drift from the vendor's.
        vetted_arguments=tuple(
            (spec.get("inputSchema") or {}).get("properties") or {}
        ),
    )

    return {
        "local_name": connector.local_name(vetted),
        "remote_name": remote_name,
        "effect": vetted.effect,
        "identity": vetted.identity,
        "resources": [ref.type for ref in vetted.resources],
        "server": mcp.discovery.server_label(server),
        "actor": actor,
    }


def _vet_rest_tool(
    tenant_id: str,
    connector,
    remote_name: str,
    *,
    effect: str,
    identity: str,
    resources: tuple,
    note: str,
    local_name: str | None,
    max_response_bytes: int | None,
    actor: str,
    binding: dict | None,
    description: str,
    redact_args: tuple = (),
) -> dict:
    """Approve one tool on a REST connector — step 045a. Nothing is dialled.

    What replaces the MCP path's six checks, and what is honestly absent:

      - **No advertisement lookup, no description copy, no server identity.** The
        review record is structurally empty (`server_name`/`server_version` are
        `''`, no `vetted_arguments` baseline) — the state `--seed` rows already
        occupy and the review screens already render. The schema, the mapping and
        the description are the vetter's words; the drift detection discovery buys
        is simply absent, and the record says so rather than inventing a version.
      - **What is checked instead**: the binding is well-formed and self-consistent
        (`rest.check_binding` — every path/query/body argument exists in the
        authored schema, every schema property is mapped somewhere), every resource
        argument exists in that schema (`validate`, degraded from a drift detector
        to a self-consistency check, as the plan states), the local name is legal
        and collides with nothing, and the identity/effect vocabulary as ever.
    """
    if binding is None:
        raise RegistrationRefused(
            f"'{connector.id}' is a REST connector, and a REST API does not "
            "describe itself: vetting a tool means authoring what discovery would "
            "have supplied. Give the request binding — the method, the path "
            "template, the input schema, and where each argument travels "
            "(--method, --path, --schema, --query/--body)."
        )

    vetted = mcp.Vetted(
        remote_name=remote_name,
        effect=effect,
        identity=identity,
        resources=resources,
        local_name=local_name,
        max_response_bytes=max_response_bytes,
        # The vetter's words — there is no vendor advertisement to copy from.
        description=description or "",
        note=note,
        binding=binding,
        # Checked against the *authored* schema by `validate` below — the same
        # self-consistency degradation the plan states for `resources` on this path,
        # and the only way a model connector's prompt argument can be kept out of the
        # audit log. Step 045c.
        redact_args=redact_args,
    )
    name = connector.local_name(vetted)

    # Re-raised as `RegistrationRefused` for the reason the MCP branch documents at
    # length: every one of these is a caller error with a sentence written for the
    # person at the form, and a bare RuntimeError through a route is a 500.
    try:
        rest_binding.check_binding(name, binding)

        validate(
            Tool(
                name=name,
                description=vetted.description,
                input_schema=binding["input_schema"],
                impl=lambda **_: None,
                effect=vetted.effect,
                identity=vetted.identity,
                resources=vetted.resources,
                redact_args=frozenset(vetted.redact_args),
            )
        )

        # The namespace checks, over the connector as it *would be* — the same
        # device as the MCP branch, and it also runs `Connector.validate()`'s
        # kind/binding implication over every existing row.
        candidate = mcp.Connector(
            id=connector.id,
            launch=connector.launch,
            description=connector.description,
            vetted=[v for v in connector.vetted if v.remote_name != remote_name]
            + [vetted],
            allow_asserted_identity=connector.allow_asserted_identity,
        )
        candidate.validate()
        check_no_collision(candidate)
    except RegistrationRefused:
        raise
    except RuntimeError as exc:
        raise RegistrationRefused(str(exc)) from exc

    storage.active().vet_tool(
        tenant_id,
        connector.id,
        mcp.vetted_to_dict(vetted),
        actor=actor,
        # Structurally empty on purpose — nothing was contacted, and inventing a
        # server identity for a plain API would be the one lie the review record
        # exists not to tell.
        server_name="",
        server_version="",
        vetted_arguments=(),
    )

    return {
        "local_name": name,
        "remote_name": remote_name,
        "effect": vetted.effect,
        "identity": vetted.identity,
        "resources": [ref.type for ref in vetted.resources],
        # Empty, not a label: no server said anything.
        "server": "",
        "actor": actor,
    }


def resource_types_for(name: str, tenant_id: str) -> set:
    """{(resource type, effect)} this tool declares, whether or not it is bound.

    Static tools answer from their descriptor; connector tools from this tenant's
    manifest, which is why an agent's scope can be cross-checked when it is saved.
    """
    tool = REGISTRY.get(name)
    if tool is not None:
        return {(ref.type, tool.effect) for ref in tool.resources}
    return mcp.declared_resource_types(tenant_id).get(name, set())


def register(tenant_id: str, tool: Tool) -> None:
    """Add a bound connector tool to this tenant's callable registry."""
    validate(tool)

    if tool.name in REGISTRY:
        raise RuntimeError(
            f"tool '{tool.name}' is a hand-written tool and may not be shadowed by "
            f"connector '{tool.connector}'"
        )

    with _BOUND_LOCK:
        bound = _BOUND.setdefault(tenant_id, {})
        existing = bound.get(tool.name)
        if existing is not None and existing.connector != tool.connector:
            raise RuntimeError(
                f"tool '{tool.name}' is already registered by another source"
            )
        bound[tool.name] = tool


def ensure_available(tenant_id: str, agent: dict, credential_for=None) -> None:
    """Connect whatever this agent's granted tools need, and nothing else.

    Called once per call by the broker, so every entry point — the CLI, a future
    HTTP layer, the scheduler — inherits it rather than each remembering.

    `credential_for(connector_id, env_var, ref)` returns `(value, delegated)`: the secret to
    open a session with, and whether it is this caller's own rather than the
    organisation's. The second half exists because a connector that cannot carry a
    per-user credential has to refuse rather than silently use the shared one, and this
    is the only place where the transport and the credential's origin are both known.

    Connecting is lazy and per-agent because a connector is a container: an agent
    that touches no GitHub tool should not pay for a GitHub server. It is idempotent
    — a live session is reused, so the second run of the day spawns nothing.

    **Two separate questions, and collapsing them was a cross-user leak.** Whether this
    tenant's tools are bound is a fact about the tenant's vetting, identical for
    everybody in it and true for the rest of the process once anybody has run. Whether
    a session exists for *this run's credential* is a fact about the caller. This used
    to return early on the first question alone, so the second user of the day never
    got a session and their calls fell through to the first user's — reaching that
    person's data while the audit log recorded their own name. See
    `tests/test_delegation.py`, which asserts the separation rather than the fix.
    """
    granted = agent.get("permissions", {}).get("tools", [])
    if not granted:
        return

    unbound = {name for name in granted if get(name, tenant_id) is None}

    for connector in _connectors_for(granted, tenant_id):
        # **A re-vetted tool has to rebind, or the approval is a screen and not a
        # control.** `_BOUND` holds `Tool` objects snapshotted at the last bind, and
        # the broker reads `effect`, `resources`, `identity` and `credential_env` off
        # them — so an admin who changes any of those saw storage and the admin screen
        # agree with them while every run in this process kept using the old
        # descriptor, until somebody restarted the API. 033a is what made that
        # intolerable rather than untidy: `identity` decides *whose account* a call is
        # made as, so a stale one is a credential the approval did not authorize.
        #
        # Free, and that is why it is here rather than in an invalidation hook: the
        # manifest was already re-read this run (`_connectors_for` is a storage read),
        # so this is a comparison against rows already in hand — no extra query, and
        # correct across N API processes, where a process-local cache bust would not
        # be. A rebind costs one `tools/list` on the run that first notices.
        stale = _stale_names(connector, tenant_id)
        if stale:
            log.info(
                "%s: re-vetted since binding, rebinding %s",
                connector.id,
                ", ".join(sorted(stale)),
            )
        unbound |= stale & set(granted)
        # Step 045a: a REST connector binds without a session — there is no server
        # to handshake with, no pool entry to warm, and the credential travels per
        # call through the broker rather than per session through here. Everything
        # the MCP path does after this point is session machinery, so the dispatch
        # is a branch here and not a seam below.
        #
        # **This branch moved above the credential read in step 070, and it is a fix
        # rather than a tidy.** `rest_binding.bind` takes no credential, so the value
        # was fetched and discarded — its only reader was `check_delegation_supported`,
        # which can refuse **only stdio** (`carries_per_user_credentials` admits `rest`
        # explicitly, plan 045a finding 5), so for a REST connector the call was a
        # guaranteed no-op. Free while a credential was an environment variable or a
        # row; a **network round trip to the customer's vault, on every door call**,
        # once one can be a pointer. Measured at 6 vault requests for a call that needs
        # 3, in `scripts/measure_door.py`, which is how it was found at all.
        #
        # What it changes besides cost: a REST connector whose *delegated* credential is
        # expired or flagged used to fail here, during binding. It now fails in the
        # broker's step 3, per call — which is where 045a says that credential is read,
        # and which produces an audited `allow`/`error` naming the connection instead of
        # a bind failure naming nothing.
        if connector.transport_kind == mcp.RestLaunch.KIND:
            if connector.declared_names() & unbound:
                for tool in rest_binding.bind(tenant_id, connector):
                    register(tenant_id, tool)
            continue

        # The manifest names where its credential lives — a variable, or since 070 an
        # `op://` reference into the customer's own vault — so the lookup is told where
        # to read rather than having to already know. Passed as strings, not a
        # connector: core/credentials.py still never learns what an MCP server is, and
        # does not learn what a vault is either.
        #
        # An HTTP MCP connector therefore resolves a pointer **twice per call**: a
        # session is keyed by the credential itself, so `ensure_session` below cannot
        # know whether it already has one without resolving. That is structural rather
        # than sloppy — recorded in `DEFERRED.md` and in the plan's known limits rather
        # than fixed here, because closing it means changing how a session is keyed.
        #
        # `(value, delegated)` rather than the credential object `core/` builds, because
        # this layer sits *below* core and may not import from it. A bare pair carries
        # the one bit that matters here without a type or a vocabulary crossing the
        # boundary in the wrong direction.
        credential, delegated = (
            credential_for(
                connector.id,
                connector.launch.credential_env,
                getattr(connector.launch, "credential_ref", None),
            )
            if credential_for
            else (None, False)
        )

        if delegated:
            # Before anything is opened. A connector that cannot carry a per-user
            # credential must fail the run rather than quietly using the shared one.
            mcp.check_delegation_supported(connector)

        if not connector.declared_names() & unbound:
            # Already bound for this tenant, so there is no allowlist to re-intersect —
            # but this caller may still be new. One handshake at most, and nothing at
            # all for somebody who has run today.
            mcp.ensure_session(tenant_id, connector, credential)
            continue

        tools, excluded = mcp.connect(tenant_id, connector, credential)
        for tool in tools:
            register(tenant_id, tool)
        if excluded:
            # Reported, not silent. "The server offers 94 tools we do not expose" is
            # the sentence that makes the allowlist visible to whoever is watching —
            # which behind a server means a log, since there is no terminal to print to.
            log.info(
                "%s: bound %d, excluded %d unvetted (%s%s)",
                connector.id,
                len(tools),
                len(excluded),
                ", ".join(excluded[:5]),
                ", ..." if len(excluded) > 5 else "",
            )


def _descriptor(
    effect,
    identity,
    credential_env,
    max_response_bytes,
    resources,
    binding=None,
    credential_ref=None,
) -> tuple:
    """The part of a bound tool that came from the **vetting**, as a comparable value.

    Everything here is a field `bind()` copies from the manifest onto the `Tool`, so a
    tool bound from a given manifest compares equal to it by construction — which is
    what keeps `_stale_names` from reporting drift on every run and rebinding forever.
    Deliberately *not* the description or the input schema: those come from the server
    rather than from the approval, and a vendor rewording a sentence is not a reason to
    re-handshake mid-run.

    `binding` is the exception that proves that rule (045a): a REST tool's request
    shape *is* part of the approval — a re-vetted path or method must rebind, or the
    old closure keeps making the old request until a restart. Serialized because a
    dict does not hash and two JSONB round trips must compare equal.
    """
    return (
        effect,
        identity,
        credential_env,
        max_response_bytes,
        # `families` rides here for `binding`'s reason one paragraph up: a re-vet that
        # widens or narrows a family changes *what the broker will admit*, and a bound
        # tool snapshotted before it would keep answering the old policy until somebody
        # restarted the API. Step 086.
        tuple(
            (ref.type, tuple(ref.args), ref.template, tuple(ref.families))
            for ref in resources
        ),
        json.dumps(binding, sort_keys=True) if binding is not None else None,
        # Step 070. A changed pointer must make a bound tool stale for exactly the
        # reason a changed `credential_env` does: `_BOUND` holds `Tool` objects
        # snapshotted at the last bind, so an admin who repoints a connector at a
        # different vault item would see storage and the admin screen agree with them
        # while every call in this process kept reading the old one, until somebody
        # restarted the API. That is 033a's stale-`identity` defect at a new address,
        # and here the stale value decides *which secret is sent to a vendor*.
        credential_ref,
    )


def _stale_names(connector, tenant_id: str) -> set:
    """Bound tools of this connector whose vetting has changed since they bound.

    An unbound name is not stale — it is absent, which `ensure_available` already
    handles and which must not be reported twice.
    """
    stale = set()
    for vetted in connector.vetted:
        name = connector.local_name(vetted)
        bound = get(name, tenant_id)
        if bound is None or bound.connector != connector.id:
            continue
        current = _descriptor(
            vetted.effect,
            vetted.identity,
            connector.launch.credential_env,
            vetted.max_response_bytes,
            vetted.resources,
            vetted.binding,
            getattr(connector.launch, "credential_ref", None),
        )
        if _descriptor(
            bound.effect,
            bound.identity,
            bound.credential_env,
            bound.max_response_bytes,
            bound.resources,
            bound.binding,
            bound.credential_ref,
        ) != current:
            stale.add(name)
    return stale


def connectors_for_agent(agent: dict, tenant_id: str) -> list:
    """Which connectors this agent's granted tools come from. The public `_connectors_for`.

    Exists because 7b gave that question a **second** asker. `ensure_available` has always
    computed it to decide what to connect; `access/oauth.refresh_for_run` now computes it
    to decide what to refresh — and the two must not be able to disagree. A connector the
    refresh misses and the run then connects to is a run using an expired token and
    reporting a third party's 401, which is precisely the failure decision 5 names as
    worth writing a test against.

    So one function, and both callers go through it. `access/` may import `tools/` — the
    graph runs `access → core → tools` — which is the same direction that forbids the
    refresh living in a runtime.
    """
    return _connectors_for(agent.get("permissions", {}).get("tools", []) or [], tenant_id)


def _connectors_for(names, tenant_id: str) -> list:
    """The connectors owning these tool names, each once, in a stable order.

    One storage read rather than one per name. `mcp.owner_of` loads every connector to
    answer about a single tool, so asking it in a loop was already N reads per run —
    tolerable while this ran only on the first run of the process, and worth fixing now
    that it runs on every one. `connectors_for` is ordered by id, so the result is too.
    """
    wanted = set(names)
    return [
        connector
        for connector in mcp.connectors_for(tenant_id)
        if connector.declared_names() & wanted
    ]


def schemas_for(names, tenant_id: str) -> list[dict]:
    """The schemas for a set of tool names, in registry order.

    Used to show an agent only the tools it's permitted to call. Unknown names are
    skipped rather than raising: a permission entry for a tool that doesn't exist yet
    is a config problem the broker reports at call time, not a crash here.
    """
    wanted = set(names)
    schemas = [tool.schema for name, tool in REGISTRY.items() if name in wanted]
    with _BOUND_LOCK:
        bound = list(_BOUND.get(tenant_id, {}).items())
    schemas += [tool.schema for name, tool in bound if name in wanted]
    return schemas


def reset_bound(tenant_id: str | None = None) -> None:
    """Forget bound connector tools. For tests, and for a connector being re-vetted.

    Sessions are separate — see `mcp.POOL.reset()`. This drops only what binding put
    in the registry.
    """
    with _BOUND_LOCK:
        if tenant_id is None:
            _BOUND.clear()
        else:
            _BOUND.pop(tenant_id, None)


__all__ = [
    "BUILTIN_DESCRIPTION",
    "BUILTIN_ORIGIN",
    "CONNECTOR_ORIGIN",
    "MAY_HAVE_COMPLETED",
    "REGISTRY",
    "REPORTED_USAGE",
    "Resource",
    "Tool",
    "VALID_EFFECTS",
    "VALID_IDENTITIES",
    "catalogue",
    "connectors_for_agent",
    "ensure_available",
    "get",
    "is_known",
    "known_names",
    "register",
    "reset_bound",
    "resource_types_for",
    "check_no_collision",
    "RegistrationRefused",
    "register_connector",
    "save_connector",
    "vet_tool",
    "schemas_for",
    "validate",
]
