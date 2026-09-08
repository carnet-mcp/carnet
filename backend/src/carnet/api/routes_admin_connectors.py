"""Connector onboarding over HTTP: hosts, registration, discovery, vetting, consent.

The other three features 12b's role was blocking. `--allow-host`, `--add-connector`,
`--discover` and `--vet` have been CLI-only since 012 and `--set-oauth` since 7b, and
both files say why in the same words: *the same wall*. There is a role now, so these are
the routes.

## Every one of these is a thin caller of a seam that already exists

```
GET/POST/DELETE /admin/hosts              storage.allowed_hosts / allow_host / revoke_host
POST   /admin/connectors                  tools.register_connector
POST   /admin/connectors/{id}/discovery   mcp.discovery.discover + .review
PUT    /admin/connectors/{id}/tools/{n}   tools.vet_tool
PUT    /admin/connectors/{id}/oauth       oauth.configure
DELETE /admin/connectors/{id}/oauth       oauth.unconfigure
```

**No new storage method, anywhere in this step** — the first step since 006 that can say
that. 012 and 7b built these seams for a caller that did not exist yet, which is the
"shape before the thing" bet paying again, and it means the correctness burden is
already carried below: `vet_tool` runs six checks including *the server advertises this*
and *the annotation validates against the advertised schema*, so a screen built on it
cannot approve a tool nobody offers or scope one to an argument that does not exist.

## Why `/admin/connectors` is not the `GET /connectors` this API refused

`routes_tools.py` refused one, and that refusal holds: *"a second route over the same
rows is a second answer to 'what may I grant'."* That decision is about the **grant
menu**, which `GET /tools` answers for everybody. This answers a different question —
*what is registered, what is vetted, what has a consent flow* — for a different audience,
and it lives under `/admin` so the two cannot be mistaken for each other.

Which is the rule for URL shapes in this step: **a noun with a non-admin half stays
top-level** (`/groups` has its menu, `/connections` is self-serve), **an admin-only noun
is prefixed**. Group routes therefore stay where 12b put them; moving them for symmetry
would break a shipped surface to make a table look tidy.

## The two guards that had to move before any of this existed

Both were in `cli.py`, and a route calling the seam directly would have gone around them:

  - **the stdio refusal on `--set-oauth`** is now in `access/oauth.configure`, so
    `PUT .../oauth` inherits it rather than reimplementing it
  - **the never-dialled warning on `--allow-host`** is now `egress.approval_warning`,
    a sentence rather than a reason, because over HTTP there is no stderr to print to
    and `POST /admin/hosts` has to carry it in the body

That is `groups.members`' lesson twice: the CLI and the API must answer the same question
the same way, and two readers of one rule is how they stop agreeing.

## Discovery is the one route here that touches somebody else's network

`POST`, although it writes nothing — it causes an outbound connection to a third party,
which is not a safe method's contract, and a GET that dials out would be dialled by
anything that prefetches links.

It is a third-party round trip on a threadpool thread, which is acceptable for two
reasons and only those two: it is bounded by the transport's timeout, and it **holds no
database connection across the call**. Every storage read happens before the dial. That
second property is 7b's pool lesson stated as a rule for a new route rather than
rediscovered — do not refactor a `storage.active()` call into the middle of it.
"""

import logging

from fastapi import APIRouter, Depends

from .. import storage, tools
from ..access import oauth, recipes
from ..core import Principal, credentials, vault
from ..storage import ValueRefused
from ..tools import mcp
from ..tools.base import Resource
from .deps import admin_from_request
from .routes_connections import _redirect_uri
from .schemas import (
    AssertedIdentityRequest,
    ConnectorDetail,
    ConnectorRequest,
    ConnectorSummary,
    DiscoveredArgument,
    DiscoveredTool,
    DiscoveryFinding,
    DiscoveryResult,
    HostApproved,
    HostEntry,
    HostRequest,
    HostRevoked,
    OAuthApp,
    OAuthConfigured,
    OAuthRequest,
    Recipe,
    RecipeHost,
    RecipeTool,
    ResourceType,
    VetOutcome,
    VetRequest,
    VettedTool,
)

log = logging.getLogger(__name__)

router = APIRouter(tags=["administration"])


# --- the egress allowlist -------------------------------------------------------------


@router.get("/admin/hosts", response_model=list[HostEntry])
def list_hosts(principal: Principal = Depends(admin_from_request)):
    """Every host this tenant will let us dial, and who approved each.

    **An empty list means this tenant can dial nothing**, which is a fact about the
    allowlist's semantics rather than about the response being empty: an empty allowlist
    denies rather than permits, and a customer who has approved no hosts has approved no
    hosts. The screen says so; this returns the rows.

    `warning` is computed per row rather than stored. The rule about which addresses can
    never be dialled is code — loopback, private ranges, the link-local block cloud
    metadata lives on — and a copy of a rule in a column is a copy that goes stale the
    first time the rule changes.
    """
    return [
        HostEntry(
            host=row["host"],
            allowed_by=row.get("allowed_by") or "",
            allowed_at=str(row.get("allowed_at") or ""),
            note=row.get("note") or "",
            warning=mcp.egress.approval_warning(row["host"]),
        )
        for row in storage.active().allowed_hosts(principal.tenant_id)
    ]


@router.post("/admin/hosts", response_model=HostApproved)
def approve_host(
    request: HostRequest, principal: Principal = Depends(admin_from_request)
):
    """Approve a host. **200 with a `warning`, and the host comes in the body.**

    A URL where a host belongs is a **400 carrying `normalize_host`'s own sentence**,
    which is the whole reason this is not `PUT /admin/hosts/{host}`. 12b's edge pass
    established that a `/` in a path segment is a routing 404 even percent-encoded —
    uvicorn decodes before Starlette routes — so an administrator pasting
    `https://mcp.acme.com/mcp`, which is exactly what people paste, would get a bare 404
    where there is a sentence explaining what to strip.

    200 rather than 201, and idempotent: re-approving updates the note. There is no new
    resource at a new URL to point at, and `allow_host` is an upsert by design.

    The `warning` is the CLI's stderr as a field, and it is why this answers with a body
    at all. Approving `localhost` writes a legitimate row and changes nothing about what
    will be dialled; being told plain *yes* about a control that is not in force is the
    precise failure `tools/mcp/egress.py` is written against.
    """
    store = storage.active()
    # `allow_host` normalizes and refuses anything that is not a bare host, raising a
    # `StorageError` whose message is written for this reader. It arrives as a 400 through
    # the handler `normalize_host`'s refusals already had.
    store.allow_host(
        principal.tenant_id,
        request.host,
        actor=str(principal),
        note=request.note or "",
    )

    # The normalized spelling, because that is what landed in the table and what every
    # other route will name. A caller who sent `Example.COM.` gets `example.com` back and
    # can trust that the string they were handed is the one to revoke.
    host = storage.normalize_host(request.host)

    return HostApproved(
        host=host,
        note=request.note or "",
        warning=mcp.egress.approval_warning(host),
    )


@router.delete("/admin/hosts/{host}", response_model=HostRevoked)
def revoke_host(host: str, principal: Principal = Depends(admin_from_request)):
    """Withdraw a host. **200 with `stranded`, not 204**, and connectors are not touched.

    A path segment here where approval takes a body, and the asymmetry is usage rather
    than taste: this clicks a row *this API rendered*, which is always a bare normalized
    hostname and therefore never carries the slash that would 404.

    The body exists for `stranded` — the connectors now pointing at a host nobody will
    dial. They keep their registration and their whole vetting record and will refuse to
    connect until it is approved again. Deleting them instead would destroy the record of
    which tools somebody approved, which is the one thing this schema goes out of its way
    to keep; saying nothing would let an administrator believe a customer's Jira
    integration was removed when the row is still there waiting.
    """
    store = storage.active()
    removed = store.revoke_host(principal.tenant_id, host, actor=str(principal))

    normalized = storage.normalize_host(host)
    # Any launch with a URL — HTTP MCP and REST alike (045a). Keyed on the launch
    # having a URL rather than on an enumeration of kinds, so the next kind that
    # dials a host is stranded-visible without anyone remembering this line.
    stranded = [
        connector.id
        for connector in mcp.connectors_for(principal.tenant_id)
        if getattr(connector.launch, "url", "")
        and mcp.egress.host_of(connector.launch.url) == normalized
    ]

    return HostRevoked(host=normalized, removed=removed, stranded=stranded)


# --- connectors ------------------------------------------------------------------------


@router.get("/admin/recipes", response_model=list[Recipe])
def list_recipes(principal: Principal = Depends(admin_from_request)):
    """The connector presets this build ships. **Reads files; touches no tenant.**

    Step 068. Every value here pre-fills a form and decides nothing — the response
    carries no client id, approves no host and vets no tool, and each of those is a
    property of the files rather than of this projection (`access/recipes.py`).

    Admin-gated even though the content is identical for every tenant and is in the
    public repository. Not for secrecy — there is none — but because this is a control
    on the registration screen, and a route that answers to any signed-in caller invites
    a client to render an administrative affordance to somebody who cannot use it. The
    same reasoning `GET /admin/hosts` applies to a list of hostnames.

    A malformed file is **this build's** defect and answers 500 rather than dropping the
    recipe from the list: a catalogue quietly one shorter than it should be is how a
    broken preset survives a release. `RecipeRefused` names the file.
    """
    return [
        Recipe(
            id=item["id"],
            name=item["name"],
            description=item.get("description", ""),
            verified_on=item.get("verified_on"),
            verified_by=item.get("verified_by") or "",
            verified_against=item.get("verified_against") or "",
            # Computed, never stored — `HostEntry.warning`'s precedent. The rule about
            # when a check stops counting is code, and a copy of it in a file goes stale
            # the first time the rule changes.
            staleness=recipes.staleness(item),
            hosts=[RecipeHost(**host) for host in item["hosts"]],
            connector=item["connector"],
            oauth=item.get("oauth"),
            tools=[RecipeTool(**tool) for tool in item.get("tools") or ()],
        )
        for item in recipes.catalogue()
    ]


@router.get("/admin/connectors", response_model=list[ConnectorSummary])
def list_connectors(principal: Principal = Depends(admin_from_request)):
    """Every registered connector: what is vetted on it, and whether it is self-servable.

    **Contacts nothing.** Everything here is the stored manifest, the review record and
    the OAuth row, so this page renders with every customer's server stopped — migration
    018's argument, which applies to an administration screen at least as much as to the
    catalogue. Looking at a *server* is a separate, deliberate click.
    """
    return [
        ConnectorSummary(**_summary(principal.tenant_id, connector))
        for connector in mcp.connectors_for(principal.tenant_id)
    ]



def _recipe_hint(recipe_id: str | None) -> str:
    """The `from_recipe` line for `admin_audit.detail`, or `""` when it cannot be earned.

    Rule 1 of step 068: nothing in the database may depend on a recipe, and that includes
    the *registration* depending on the recipe file being well-formed. `recipes.load`
    raises `RecipeRefused` for a file this build shipped broken — a defect of the build,
    not of the registration in hand — and the first draft let that propagate, which made
    a provenance hint able to fail the write it was annotating. Unknown and malformed
    are treated alike here: the hint is dropped and the row is written, because a log
    line is not allowed to be load-bearing.
    """
    if not recipe_id:
        return ""
    try:
        return recipe_id if recipes.load(recipe_id) else ""
    except recipes.RecipeRefused:
        return ""

@router.post("/admin/connectors", response_model=ConnectorSummary, status_code=201)
def register_connector(
    request: ConnectorRequest, principal: Principal = Depends(admin_from_request)
):
    """Register a connector. **201, and it vets nothing** — the body says so and so does
    this.

    The ordering migration 021 forces, and the reason registration and vetting are two
    operations rather than one with a flag: a credential cannot be sealed against a
    connector that does not exist, and no server lists its tools to an unauthenticated
    caller, so *connect, look, then decide whether to register* is not expressible. The
    row comes first, and nothing this connector offers is reachable until somebody
    approves a tool on it one at a time.

    A connector id that is taken is a **409** through `ConnectorExistsError`, on
    `AgentNameTaken`'s reasoning exactly: the alternative is an upsert, and `--seed`'s
    upsert replaces a vetted allowlist wholesale. An administrator who has approved nine
    tools and re-registers by mistake must not lose nine to a command whose only visible
    effect is *the row exists*.

    A URL whose host is not approved is a **400** through `EgressRefused`, checked here as
    well as at dial time. The redundancy is 012's and is the point: a refusal somebody
    gets while they are still on this screen is one they can act on, where the same
    refusal three days later at the first run is a mystery.
    """
    if request.credential_ref:
        # Parsed here rather than inside `register_connector`, and it is the layering
        # rather than a preference: `core/vault` owns what an `op://` reference means and
        # `tools/` may not import `core/`. So the friendly refusal lives at the entry
        # points that may import both — this route and `cli.py` — and the load-bearing
        # one at the credential read. `config.is_platform_env`'s two-place shape.
        try:
            vault.parse(request.credential_ref)
        except vault.VaultError as exc:
            raise ValueRefused(str(exc)) from exc

    tools.register_connector(
        principal.tenant_id,
        request.connector_id,
        url=request.url,
        kind=request.kind,
        credential_env=request.credential_env or "",
        credential_ref=request.credential_ref or "",
        credential_header=request.credential_header,
        credential_prefix=request.credential_prefix,
        headers=dict(request.headers) or None,
        description=request.description or "",
        allow_asserted_identity=request.allow_asserted_identity,
        # Checked against this build's catalogue before it is recorded — see
        # `ConnectorRequest.from_recipe`. An unknown id is **dropped rather than
        # refused**: the registration itself is correct and complete, and failing it over
        # a provenance hint would make a log line load-bearing, which is exactly what
        # rule 1 says a recipe must never become.
        from_recipe=_recipe_hint(request.from_recipe),
        actor=str(principal),
    )

    connector = mcp.get_connector(principal.tenant_id, request.connector_id)
    return ConnectorSummary(**_summary(principal.tenant_id, connector))


@router.put(
    "/admin/connectors/{connector_id}/asserted-identity",
    response_model=ConnectorSummary,
)
def set_asserted_identity(
    connector_id: str,
    request: AssertedIdentityRequest,
    principal: Principal = Depends(admin_from_request),
):
    """Turn asserted acting-for on or off for one connector. Step 033c.

    Its own verb on its own URL, on `PUT .../tools/{name}`'s reasoning: the write is
    keyed by what it is about, and what this is about is one security control on one
    connector. What it gates is whether the MCP door *believes* an unverified
    acting-for — an email a calling service asserts — for this server's tools; a
    verified acting-for (the person's own forwarded IdP token) needs no switch,
    because nothing about it is taken on trust.

    Idempotent by nature and recorded on every call: `connector.asserted_identity` in
    the administrative log names who and which way, which is the row the plan's
    *"who approved that"* question is answered from.

    A connector nobody registered is a **400** through `RegistrationRefused` with the
    storage layer's own sentence — trust in a caller for a server that does not exist
    is not a state to be able to reach.
    """
    try:
        tools.set_asserted_identity(
            principal.tenant_id, connector_id, request.allowed, actor=str(principal)
        )
    except storage.NoSuchConnectorError as exc:
        raise tools.RegistrationRefused(str(exc)) from exc

    connector = mcp.get_connector(principal.tenant_id, connector_id)
    return ConnectorSummary(**_summary(principal.tenant_id, connector))


@router.get("/admin/connectors/{connector_id}", response_model=ConnectorDetail)
def get_connector(
    connector_id: str, principal: Principal = Depends(admin_from_request)
):
    """One connector, and **what was approved on it, by whom, against what version**.

    A connector that is not registered is a **400** naming what is, rather than a 404. The
    caller has already proved they administer this tenant, so which connectors exist is
    not a secret from them — the same call `GET /groups/{id}` makes, and the opposite of
    the agent routes' 404, which hide an agent's existence because a 403 sweep over
    plausible names enumerates the company.
    """
    connector = _connector_or_refuse(principal.tenant_id, connector_id)
    review = _review_record(principal.tenant_id)

    return ConnectorDetail(
        **_summary(principal.tenant_id, connector),
        tools=[_vetted_tool(connector, vetted, review) for vetted in connector.vetted],
    )


@router.post(
    "/admin/connectors/{connector_id}/discovery", response_model=DiscoveryResult
)
def discover(connector_id: str, principal: Principal = Depends(admin_from_request)):
    """Ask the server what it offers **right now**, with each tool's argument names.

    The argument names are the entire reason this exists. Everything else on the vetting
    screen is a judgment a person makes — is this a read or a write, which noun does it
    touch — and the one thing they cannot guess is what *this* server calls the argument
    that carries the identifier, and whether it is required. A form that offered a free
    text box there would be a form whose commonest outcome is a refusal from
    `tools.validate` at submit.

    **Discovers with the caller's own stored connection**, read exactly as
    `cli._discovery_credential` reads it — never a prompt, never a body field. `None` is
    legal and not an error: an unauthenticated MCP server is a real thing, and if this one
    wants a credential its own refusal is a better message than any guess made here about
    whether one was needed. A credential that exists and is *broken* is different from one
    that is absent, and is raised rather than swallowed — discovering anonymously because
    somebody's token expired would produce a tool list that does not describe what their
    runs can see.

    **The wizard cannot express `--who`**, and that is a stated limit rather than an
    oversight: discovering with somebody else's connection is a real CLI capability with
    no safe shape in a browser. The caller's own connection or nothing.

    A server that is down is a **502** carrying the transport's sentence — the customer's
    own server did not answer, which is a gateway failure rather than our outage and
    rather than the caller's mistake. A 503 would claim our storage is broken.
    """
    connector = _connector_or_refuse(principal.tenant_id, connector_id)

    # A REST API does not describe itself — there is nothing to discover. Refused
    # with the remedy in it, on `STDIO_REFUSED`'s precedent: a refusal that says what
    # to do instead, rather than an empty success that reads as "no tools offered".
    if connector.transport_kind == mcp.RestLaunch.KIND:
        raise tools.RegistrationRefused(
            f"'{connector_id}' is a REST API and does not describe itself; there is "
            "nothing to discover. Vet each tool with its authored schema and "
            "binding instead — the method, the path template, and where each "
            "argument travels."
        )

    # **Every storage read finishes before the dial**, and this ordering is load-bearing
    # rather than tidy — see the module docstring. `for_discovery` reads `connections` and
    # `_review_record` reads `vetted_tools`; both are done before a socket is opened, so
    # no pooled connection is held across a third party's latency.
    #
    # `for_discovery`, not `for_connector`: discovery precedes vetting, so there is no
    # identity to consult, and the admin's own sealed credential is the one to look with.
    # Both halves of the shared credential off the manifest, as `cli._discovery_credential`
    # passes them. Step 070's first draft passed only `credential_env` here, so a
    # connector registered with a vault reference discovered and vetted *unauthenticated*
    # from this screen while the CLI resolved the pointer — the same connector, two
    # answers, and the browser's was the wrong one.
    credential = credentials.for_discovery(
        connector.id,
        principal,
        getattr(connector.launch, "credential_env", None),
        getattr(connector.launch, "credential_ref", None),
    )
    review = _review_record(principal.tenant_id)

    seen = mcp.discovery.discover(
        principal.tenant_id,
        connector,
        credential.value if credential is not None else None,
    )

    advertised = seen["tools"]
    vetted = {v.remote_name for v in connector.vetted}
    findings = mcp.discovery.review(connector, advertised, review)

    return DiscoveryResult(
        server=mcp.discovery.server_label(seen["server"]),
        tools=[
            _discovered(connector, spec, vetted)
            for spec in sorted(advertised, key=lambda t: t.get("name") or "")
        ],
        findings=[
            DiscoveryFinding(severity=f["severity"], message=f["message"])
            for f in findings
        ],
    )


@router.put(
    "/admin/connectors/{connector_id}/tools/{remote_name}", response_model=VetOutcome
)
def vet_tool(
    connector_id: str,
    remote_name: str,
    request: VetRequest,
    principal: Principal = Depends(admin_from_request),
):
    """Approve one tool. **Appended, never replacing**, and re-vetting restamps that row.

    `PUT` on a URL naming the tool, matching `PUT /agents/{name}/grants/{kind}/{id}`: the
    write is keyed by what it is about, and the URL is that key. Re-vetting overwrites
    that tool's row and no other and records again, which is `storage.vet_tool`'s existing
    rule — *a new review overwrites the old rather than being edited underneath its name*.

    One tool per request, so a failed tenth never costs nine. That is `--vet`'s decision
    and it matters more here, because a form is where somebody works through a whole
    server's tool list in one sitting.

    Everything that could be wrong is refused below this with a sentence, and all of it
    arrives as a **400**: a tool the server does not advertise, named beside what it does
    offer; a resource pointing at an argument that does not exist; a local name that
    would shadow a hand-written tool; and — the one that is easy to leave out — a
    connector whose *existing* vetting has drifted, because approving a tenth tool on top
    of nine that no longer bind is a change nobody would find out about until an unrelated
    agent's next run.

    This dials the server, so it inherits discovery's 502 and its ordering rule.
    """
    connector = _connector_or_refuse(principal.tenant_id, connector_id)
    # `for_discovery`: vetting re-discovers to check the tool against what the server
    # advertises right now, and that read authenticates the way discovery does. A
    # REST connector dials nothing at vet time, so no credential is read for one —
    # a person whose stored connection has expired must still be able to vet.
    is_rest = connector.transport_kind == mcp.RestLaunch.KIND
    credential = (
        None
        if is_rest
        else credentials.for_discovery(
            connector.id,
            principal,
            getattr(connector.launch, "credential_env", None),
            getattr(connector.launch, "credential_ref", None),
        )
    )

    recorded = tools.vet_tool(
        principal.tenant_id,
        connector_id,
        remote_name,
        effect=request.effect,
        identity=request.identity,
        # Structured, and turned into a `Resource` here rather than parsed from a string.
        # `cli._parse_resource` owns the `TYPE=ARG` spelling and says why it must stay
        # there: it is a command-line spelling, and the moment `Resource` learns one an
        # HTTP route accepts the same string.
        resources=tuple(
            Resource(
                spec.type,
                tuple(spec.args),
                template=spec.template,
                families=tuple(spec.families),
            )
            for spec in request.resources
        ),
        note=request.note or "",
        local_name=request.local_name,
        max_response_bytes=request.max_response_bytes,
        actor=str(principal),
        credential=credential.value if credential is not None else None,
        # REST only, refused with a sentence on MCP — see `VetRequest`. Dumped to a
        # plain dict here because everything below the routes speaks rows, not
        # pydantic models.
        binding=request.binding.model_dump() if request.binding is not None else None,
        description=request.description or "",
        redact_args=tuple(request.redact_args),
    )

    return VetOutcome(**recorded)


# --- the consent flow --------------------------------------------------------------


@router.put("/admin/connectors/{connector_id}/oauth", response_model=OAuthConfigured)
def configure_oauth(
    connector_id: str,
    request: OAuthRequest,
    principal: Principal = Depends(admin_from_request),
):
    """Configure a connector's consent flow. **The secret goes in and never comes back.**

    `_read_secret`'s rule is *never argv*, because argv is shell history and the process
    table; the HTTP equivalent is *never a query string*, because that is server logs and
    browser history. So the secret is a body field, sealed with the same crypto as a
    credential and bound to `(tenant, connector)`, and the response is built from
    `OAUTH_APP_PUBLIC_FIELDS` — a projection deliberately ordered so a reader is
    structurally unable to acquire the sealed value on the way past.

    There is no masked echo either, which is a smaller decision with the same shape:
    `••••••` implies retrievability, and nothing in this system can retrieve it for a
    person. The screen renders the word *stored*.

    **Refused on a stdio connector, from the access layer.** That guard spent 7b in
    `cli._set_oauth` and had to move before this route could exist — otherwise an
    administrator configures a consent flow here, somebody completes a screen at a third
    party granting real access, and the credential could never be presented. See
    `oauth.STDIO_CONSENT_REFUSED`; this route inherits it rather than restating it.

    An upsert, and re-running is how a rotated client secret is installed. Refusing a
    second configure would make rotation a delete-then-create with a window in which
    nobody can connect.

    Two things come back that are not stored anywhere: the `redirect_uri` to register at
    the provider, because the person who has to do that is standing right here, and the
    offline-access warning, because a provider that issues no refresh token produces a
    connection that works for an hour and then asks to be redone.
    """
    row = oauth.configure(
        principal.tenant_id,
        connector_id,
        authorize_endpoint=request.authorize_endpoint,
        token_endpoint=request.token_endpoint,
        revoke_endpoint=request.revoke_endpoint or "",
        client_id=request.client_id,
        client_secret=request.client_secret,
        scopes=tuple(request.scopes),
        authorize_params=dict(request.authorize_params),
        # Migration 051. Dumped back to plain dicts because the storage layer checks them
        # against the scopes — a note naming a scope this request does not ask for is a
        # 400 from `normalize_scope_notes`, which is a thing only that layer can say.
        scope_notes={
            scope: note.model_dump() for scope, note in request.scope_notes.items()
        },
        actor=str(principal),
    )

    warnings = []
    if not any("offline" in scope for scope in row["scopes"]):
        # A warning rather than a refusal, on `--allow-host localhost`'s precedent: every
        # provider spells this differently and refusing on a guess about a vendor's
        # vocabulary would block a correct setup.
        warnings.append(
            "No scope here looks like offline access, so this provider may issue no "
            "refresh token. The connection would then work until the access token "
            "expires — about an hour — and ask the person to connect again."
        )
    if not row["revoke_endpoint"]:
        warnings.append(
            "No revocation endpoint, so disconnecting will delete the credential here "
            "and leave the token live at the provider."
        )

    return OAuthConfigured(
        app=_oauth_app(row), redirect_uri=_redirect_uri(), warnings=warnings
    )


@router.delete("/admin/connectors/{connector_id}/oauth", response_model=HostRevoked)
def unconfigure_oauth(
    connector_id: str, principal: Principal = Depends(admin_from_request)
):
    """Remove a consent flow. **Credentials people already gave are untouched**, and the
    response says so by not pretending otherwise.

    Cascading to the credentials is what somebody will assume happened, and migration
    021's argument is why it does not: destroying the evidence that people consented, as a
    side effect of an administrative action about configuration. What they lose is the
    ability to *renew* — each connection works until its access token expires and then
    asks to be reconnected, with nothing to reconnect through until a flow is configured
    again.

    200 with `removed` rather than 204, on `MemberOutcome`'s reasoning: removing something
    that was not there is not an error, and an administrator who cannot tell a no-op from
    a change cannot tell a working control from a broken one.

    `HostRevoked` is reused deliberately — `{id, removed, stranded}` is exactly this
    shape, with `stranded` empty because nothing is ever stranded by this. A second model
    with the same three fields would be a second thing to keep in step for no reader's
    benefit.
    """
    removed = oauth.unconfigure(principal.tenant_id, connector_id, actor=str(principal))

    return HostRevoked(host=connector_id, removed=removed, stranded=[])


# --- projections ---------------------------------------------------------------------


def _connector_or_refuse(tenant_id: str, connector_id: str):
    """The registered connector, or a 400 naming what is registered.

    `tools.vet_tool` makes the same refusal with the same sentence for the same reason, so
    a connector id typed wrongly reads identically whichever route it was typed into.
    """
    connector = mcp.get_connector(tenant_id, connector_id)
    if connector is None:
        raise tools.RegistrationRefused(
            storage.NO_SUCH_CONNECTOR_TO_VET.format(
                connector=connector_id, tenant=tenant_id
            )
        )
    return connector


def _review_record(tenant_id: str) -> dict:
    """`(connector_id, remote_name) -> the review row`. See `Storage.load_vetting_record`.

    Read separately from the manifest because it *is* separate: provenance is a column the
    database owns, never something a caller asserts by passing a dict.
    """
    return {
        (row["connector_id"], row["remote_name"]): row
        for row in storage.active().load_vetting_record(tenant_id)
    }


def _summary(tenant_id: str, connector) -> dict:
    """The fields both connector shapes share, written once because `ConnectorDetail`
    extends `ConnectorSummary` and a second spelling is how the two stop agreeing."""
    url = getattr(connector.launch, "url", "") or ""
    host = mcp.egress.host_of(url) if url else ""
    approved = {row["host"] for row in storage.active().allowed_hosts(tenant_id)}
    configured = oauth.configured(tenant_id).get(connector.id)

    return {
        "connector_id": connector.id,
        "description": connector.description or "",
        "transport": connector.transport_kind,
        "url": url,
        "credential_env": getattr(connector.launch, "credential_env", None) or "",
        "credential_ref": getattr(connector.launch, "credential_ref", None) or "",
        "vetted": len(connector.vetted),
        "writes": sum(1 for v in connector.vetted if v.effect == "write"),
        "host": host,
        "host_allowed": bool(host) and host in approved,
        "oauth": _oauth_app(configured) if configured else None,
        "allow_asserted_identity": connector.allow_asserted_identity,
    }


def _oauth_app(row: dict) -> OAuthApp:
    """A stored OAuth row as its public shape.

    Built field by field rather than by `OAuthApp(**row)`, and that is the containment
    rather than a style: an explicit projection cannot start carrying a column somebody
    adds to the table later. `**row` would have shipped `client_secret` the day the
    storage layer's public tuple was widened by accident.
    """
    return OAuthApp(
        connector_id=row["connector_id"],
        authorize_endpoint=row["authorize_endpoint"],
        token_endpoint=row["token_endpoint"],
        revoke_endpoint=row.get("revoke_endpoint") or "",
        client_id=row["client_id"],
        scopes=list(row.get("scopes") or ()),
        authorize_params=dict(row.get("authorize_params") or {}),
        scope_notes=dict(row.get("scope_notes") or {}),
        configured_by=row.get("configured_by") or "",
        configured_at=str(row.get("configured_at") or ""),
    )


def _vetted_tool(connector, vetted, review: dict) -> VettedTool:
    """One approved tool, with the provenance the catalogue also shows.

    Resource **types** and nothing else, which is `tools._resource_types`' decision and
    holds here too: handing a client `args` and `template` invites it to build a scope out
    of argument names, and that indirection is exactly what lets one `github.repo` grant
    cover every tool touching a repo. The vetting *form* is told argument names, by
    discovery, which is a different question asked at a different moment.
    """
    record = review.get((connector.id, vetted.remote_name), {})
    seen, types = set(), []
    for ref in vetted.resources:
        if ref.type not in seen:
            seen.add(ref.type)
            types.append(ResourceType(type=ref.type))

    return VettedTool(
        name=connector.local_name(vetted),
        remote_name=vetted.remote_name,
        description=vetted.description or "",
        note=vetted.note or "",
        effect=vetted.effect,
        identity=vetted.identity,
        resources=types,
        max_response_bytes=vetted.max_response_bytes,
        vetted_by=record.get("vetted_by", "") or "",
        vetted_at=str(record.get("vetted_at", "") or ""),
        server_name=record.get("server_name", "") or "",
        server_version=record.get("server_version", "") or "",
    )


def _discovered(connector, spec: dict, vetted: set) -> DiscoveredTool:
    """One advertised tool, with its arguments spelled out.

    The same projection `cli._schema_lines` prints, as data. Types and requiredness both,
    because `--resource TYPE=ARG` needs the exact name and because an optional argument
    that widens reach when it is absent is the case `connectors/github.py` documents at
    length — invisible without the second field.
    """
    name = spec.get("name") or ""
    schema = spec.get("inputSchema") or {}
    properties = schema.get("properties") or {}
    required = set(schema.get("required") or ())

    arguments = []
    for argument in sorted(properties):
        described = properties[argument] if isinstance(properties[argument], dict) else {}
        kind = described.get("type") or "any"
        if isinstance(kind, list):
            kind = "|".join(str(k) for k in kind)
        arguments.append(
            DiscoveredArgument(
                name=argument, type=str(kind), required=argument in required
            )
        )

    return DiscoveredTool(
        name=name,
        description=(spec.get("description") or spec.get("title") or "").strip(),
        arguments=arguments,
        vetted=name in vetted,
        # What it would be called here, shown before anybody commits to it rather than
        # left for them to learn from a name-collision refusal.
        local_name=connector.local_name(mcp.Vetted(remote_name=name)) if name else "",
    )
