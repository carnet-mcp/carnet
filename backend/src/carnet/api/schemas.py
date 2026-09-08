"""Request and response shapes — the OpenAPI surface.

This is the half of FastAPI that earns the dependency: a UI, and eventually a customer,
reads these rather than guessing from example payloads.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..storage import GRANTEE_KINDS

# The `runs.status` column, as a type. Documented once, in migration 015, where each
# value is written down beside what a person does about it.
#
# `queued` and `running` cannot be returned by `POST /runs` yet — it still blocks — but
# `GET /runs/{id}` can already return `running` for a run another request started, which
# is the first time this API has been able to describe work in flight.
RunStatus = Literal[
    "queued",
    "running",
    "complete",
    "incomplete",
    "failed",
    "cancelled",
    "interrupted",
]


class AgentSummary(BaseModel):
    """One agent as a list row."""

    name: str
    # Migration 035's `agent_id`, and it is **additive and optional to use**. Every URL in
    # this API and every field a client sends still speaks the name — step 025 decided the
    # name stays the address — so nothing needs this. What it is for is a machine consumer
    # that wants an identity a rename cannot move: `name` is a label now, and a client
    # correlating runs across a rename has something stable to hold.
    #
    # There is deliberately no `/agents/{id}` route. One spelling is worth more than two,
    # which is migration 019's own sentence, and an opaque id in a URL is precisely what
    # names exist to avoid.
    id: str = ""
    # `str | None` since 081, for `AgentDraft.runtime`'s reason one layer out: a row
    # reporting `"simple"` about an agent whose stored config names no tier is the same
    # invention, made at read time instead of write time. `None` is what a door-only
    # config actually says about this, which is nothing.
    #
    # **Nullable and still required, which is deliberate and is not the same choice
    # `AgentDraft` makes.** `ConnectionSummary` states the convention this follows:
    # *required means the key is sent*, and three of its fields are null on a connector
    # nobody has connected. A default here would drop `runtime` out of the OpenAPI
    # document's `required` list while the server went on sending it on every row — a
    # generated client would stop expecting a key it always gets. The request body is the
    # opposite case and takes the default: there, absence is what a caller sends.
    runtime: str | None
    tools: list[str] = Field(default_factory=list)
    valid: bool = True
    # Why it is unusable, when it is. Reported rather than omitted: a form user needs
    # to see the broken row, and hiding it is how it stays broken.
    error: str | None = None


class AgentDetail(AgentSummary):
    system: str = ""
    scope: dict = Field(default_factory=dict)
    limits: dict = Field(default_factory=dict)

    # **The ETag, and it is a body field as well as a header.**
    #
    # ISO-8601 at **full precision**, deliberately unlike `_stamp` in routes_admin.py,
    # which truncates to seconds because a person reads it. Nothing reads this: it goes
    # straight back in an `If-Match`, where it is compared to `agents.updated_at` by a
    # SQL predicate. A value rounded to the second matches no row, so the compare-and-set
    # would refuse every save — a guard that is not a guard but a wall.
    #
    # Not a hash of the config. A hash cannot tell "changed" from "changed and changed
    # back", and it would be a second answer to a question the schema already has a
    # column for. `updated_at` is also the thing a UI wants to *show*, which a hash is
    # never going to be.
    updated_at: str = ""
    # **The caller's own effective role**, and it is here because a screen without it
    # renders buttons that 404 at the person they were rendered for.
    #
    # `DELETE` is `owner` and `PATCH` is `editor`, so a detail page has to know which of
    # those to offer — and nothing else in this API tells a client who it is. Not a set of
    # booleans per verb: what a level permits is policy and lives in `access/grants.py`,
    # and a client that branches on the ladder is one place, where `may_edit` /
    # `may_delete` / `may_share` is three that can disagree with it.
    #
    # It is the role `grants.require` already computed on the way in, handed back rather
    # than asked for a second time. Deliberately **not** on `AgentSummary`: the list is a
    # list of names and this is a question asked about one agent.
    your_role: str = ""
    # **The live version number, and it is not a second ETag.** Step 021.
    #
    # `If-Match` still takes `updated_at` above, and changing that would invalidate every
    # client to re-decide 010d for no gain — the compare-and-set is identical either way.
    # What this is for is naming a row in the agent's history, which a person reads as
    # "v7" and a timestamp is not. It is also the one number that distinguishes a save
    # that changed something from a save that did not: `updated_at` moves on both.
    version: int = 1
    # The whole stored config, verbatim, and the field an edit screen actually needs.
    #
    # `system`, `scope` and `limits` above are the same data spelled for a reader, and
    # they are **not** the whole config: `issue-reporter` carries `default_task` and
    # `deny_demo_task`, which no shape in this file mentions. An edit form built from the
    # reader's fields alone would send back a config missing both — which is exactly the
    # finding decision 2 exists for, arriving through the response instead of the request.
    config: dict = Field(default_factory=dict)


class AgentPermissions(BaseModel):
    """Capability and reach, in the config's own shape.

    `scope` is typed all the way down rather than left as `dict`, and that is a guard
    rather than documentation. `agents.validate` iterates it — `for effect, grants in
    by_effect.items()` — so a body posting `{"github.repo": "read"}` would raise an
    AttributeError deep inside the validator and arrive as a 500. The validator is
    written to refuse *wrong policies* in sentences a person can act on; refusing
    *wrong types* is this layer's job, and the two do not belong in one function.
    """

    model_config = ConfigDict(extra="forbid")

    tools: list[str] = Field(default_factory=list)
    # {resource_type: {effect: [patterns]}}
    scope: dict[str, dict[str, list[str]]] = Field(default_factory=dict)


class AgentOutput(BaseModel):
    """The output contract, in the config's own shape. Step 024.

    `schema` is a reserved name on pydantic's BaseModel, so the field is `json_schema`
    with `schema` as its alias — the wire and the stored config both spell it `schema`,
    and `to_config`/`to_patch` dump by alias so the internal name never leaks into a
    row. **Deliberately no `populate_by_name`**: with it, the internal name was a
    second accepted spelling on the wire (found by sending one), and two spellings of
    one key is a contract wart that outlives whoever knew why. Every *policy*
    question — is it valid JSON Schema, is the root an object, does every object close
    itself — is answered by `agents.validate`, which owns the sentences; this shape
    contributes type refusal and the OpenAPI document, `AgentPermissions`' division of
    labour exactly.
    """

    model_config = ConfigDict(extra="forbid")

    json_schema: dict = Field(alias="schema")


class AgentDraft(BaseModel):
    """**The request body is the config.** There is no creation-specific shape.

    This is 010's decision 1 at the place it is most tempting to break. A friendlier
    request shape — `tools` at the top level, scope as a list of rows, a `share_with`
    array — would be a second definition of what an agent is, translated by a mapping
    layer that agrees with `agents.validate` only for as long as somebody maintains it.
    The mapping layer is where the form and the enforcement drift apart, and the whole
    argument for one representation is that a draft can be round-tripped through the
    same function the server will use.

    So this model enumerates the config's fields and adds nothing. What it contributes
    is the OpenAPI document and type refusal, not meaning: every *policy* question —
    is that tool real, does the scope match the tools, is that a legal pattern, is that
    limit a known one — is answered by `agents.validate`, which owns the sentences.

    `extra="forbid"`, deliberately, and it is the one place this model is stricter than
    the dict it mirrors. A config with `systen` instead of `system` is stored happily
    today and produces an agent that was told nothing; a typo in a key is silent in
    exactly the way a typo in a *value* is not. Forbidding extras can drift closed — a
    new config field is refused here until this model learns it — and that failure is
    loud, arrives at the developer who added the field, and is a line of code. The other
    direction is a stored row nobody can explain.
    """

    model_config = ConfigDict(extra="forbid")

    # Not pattern-constrained here, on purpose. A pydantic mismatch arrives as FastAPI's
    # list-shaped 422, which a client renders as "the request was not in a shape the
    # server accepts" — and the name rule is the one error in this whole body most likely
    # to be read by somebody non-technical. `agents.validate` refuses it with a sentence
    # that says what to type instead.
    name: str
    # `str | None = None` since 044, on `model`'s pattern: the wizard sends no
    # `system` at all, and `= ""` was quietly writing an empty briefing into every such
    # config — a key nobody supplied, rendered by `--list` and review as if somebody
    # had. `exclude_none` keeps the absence absent; an agent with no instructions and an
    # agent told the empty string are now the same stored shape they always were in
    # meaning.
    system: str | None = None
    # `str | None = None` since 081, and it is the one place the *server* invented a key.
    # `= DEFAULT_RUNTIME` meant every agent created over HTTP stored `"runtime": "simple"`
    # — a tier from a concept this tree deleted — while `bootstrap.py`'s seeded example
    # stored none, so the shipped example and an API-created agent disagreed about the
    # shape of a config. Accepting one somebody sends is right (a config authored for a
    # tree that has a runtime stays intact); minting one nobody sent is drift that 021's
    # version history cannot attribute to anybody.
    runtime: str | None = None
    permissions: AgentPermissions = Field(default_factory=AgentPermissions)
    # `dict[str, Any]` rather than `dict[str, int]`, so that `{"max_calls": true}` reaches
    # the validator's own message — which explains that 0 is legal and what it buys —
    # instead of being coerced to 1 by pydantic on the way past.
    limits: dict[str, Any] = Field(default_factory=dict)
    model: str | None = None
    max_tokens: int | None = None
    # Step 014, decision 8: every run of this agent visible only to whoever ran it —
    # the list, the run page, cancel and the thread all collapse to *yours only*, and
    # threads are never openable. Colleagues stop seeing each other's use; the audit
    # trail and the operator's CLI see everything they always did. Unset means false,
    # and `exclude_none` keeps it absent from the stored config rather than null.
    private_runs: bool | None = None
    # Step 024: the answer becomes a contract. Optional and `exclude_none`-dropped like
    # `model`, so an agent that never mentions it stores no key and answers in prose.
    output: AgentOutput | None = None

    def to_config(self) -> dict:
        """The plain dict every layer below this one speaks.

        `exclude_none` so an unset `model` is *absent* rather than stored as null. The
        difference matters at read: `config.get("model")` returning None is the signal
        to use the tenant default, and a literal null in the row means the same thing
        only by coincidence.

        `by_alias` for exactly one field: `AgentOutput.json_schema` must land in the
        config spelled `schema`. Every other field's alias is its name.
        """
        return self.model_dump(exclude_none=True, by_alias=True)


class AgentCreated(BaseModel):
    """What `POST /agents` answers. Small on purpose.

    It carries the owner because that is the half of this request a caller did not send
    and cannot see anywhere else yet — there is no route that lists an agent's grants
    until 10d. An agent whose creation did not claim ownership is the failure four
    handoffs have warned about, and this is where it would be visible.
    """

    name: str
    # `kind:id`, the same spelling as everywhere else this system names a principal.
    owner: str


class AgentRename(BaseModel):
    """What `POST /agents/{name}/rename` takes. One field, and that is the design.

    Step 025. Not part of `AgentPatch`, because a rename is not an edit: it is `owner`
    rather than `editor`, it takes no `If-Match`, and `PATCH` already answers a body-borne
    `name` with a 400 whose job is to teach that the name is not a field. See the route.

    `extra="forbid"`, matching every other body in this file: a rename carrying a `system`
    key somebody expected to be applied is a request half-honoured, and a caller who
    misread the shape should be told rather than partially obeyed.

    The value is not validated here beyond being a non-empty string. The rules — the slug
    shape from migration 019 and the reserved names — live in `agents.rename` and produce
    the validator's own sentences, so the CLI and this route refuse identically and a
    person reads the same words either way.
    """

    model_config = ConfigDict(extra="forbid")

    new_name: str = Field(min_length=1)


class AgentPatch(BaseModel):
    """What `PATCH /agents/{name}` takes: **a partial config, merged at the top level.**

    Decision 2 of 010d, and the shape is the decision. Every field is optional and every
    field defaults to `None`; `to_patch()` drops the ones nobody sent, so the merge in
    `agents.merge` sees only what this request is actually changing.

    The alternative was a whole-config `PUT`, matching 10c's *"the request body is the
    config"*. It is the more honest verb for what a form does and it was rejected on a
    confirmed finding: `draft.ts` has `toConfig` and no inverse, the shipped
    `issue-reporter` carries `default_task` and `deny_demo_task`, and no wizard step asks
    about either. A `PUT` puts the burden of losslessness on every client forever; a
    merge puts it in one place and then removes it.

    **`name` is present and is not patchable**, which is why it is here at all. It is the
    URL, the storage key, the broker's identity and the string in every audit record;
    renaming is a different operation with its own questions — what happens to the runs,
    the grants, the log — and it is not this step's. A body carrying a `name` that
    differs from the path is a **400**, not a silent ignore: dropping it quietly would
    tell somebody their rename worked.

    `extra="forbid"` for the reason `AgentDraft` has it: a config with `systen` for
    `system` would merge happily and produce an agent that was told nothing.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    system: str | None = None
    runtime: str | None = None
    permissions: AgentPermissions | None = None
    limits: dict[str, Any] | None = None
    model: str | None = None
    max_tokens: int | None = None
    private_runs: bool | None = None
    # Step 024. A patch carrying an explicit `"output": null` merges the null in and is
    # then refused by the validator with the sentence about removal needing the CLI —
    # the standing merge cost, refused loudly rather than stored quietly.
    output: AgentOutput | None = None

    def to_patch(self) -> dict:
        """The keys this request sent, and no others.

        `exclude_unset` rather than `exclude_none`, and the difference is the whole
        method. `AgentDraft.to_config` drops nulls because an unset `model` must be
        *absent* from a config rather than stored as one. Here absence already means
        something else — **do not touch this key** — so the two have to be told apart by
        whether the client wrote the field, which is what pydantic's "unset" is.

        `name` is dropped: it is checked against the path by the route and never merged.
        `by_alias` for `AgentDraft.to_config`'s one reason: `output.json_schema` must
        merge into the config spelled `schema`.
        """
        return {
            key: value
            for key, value in self.model_dump(exclude_unset=True, by_alias=True).items()
            if key != "name"
        }


class AgentVersionSummary(BaseModel):
    """One row of an agent's history. Step 021.

    **No config**, and that is the same decision `list_agent_versions` makes in storage:
    a history card shows dates and authors, and fifty configs down the wire to render one
    is fifty system prompts nobody asked for. `GET /agents/{name}/versions/{version}` is
    how a client asks for one.

    **`valid` is evaluated when this is read, never when the version was written**, which
    is the field worth understanding. A version is a configuration that *was* live, and
    what may be live moves under it — a tool un-vetted last week makes a version from
    last month unrestorable. So a screen offering a restore has to be told before the
    click rather than by a 422 afterwards, and the sentence in `error` is the validator's
    own, exactly as it is on `AgentSummary`.
    """

    version: int
    # The instant this configuration became live — the agent's `updated_at` at the time,
    # so version N was live from here until N+1's. Full precision for `AgentDetail`'s
    # reason: a client may hand it back as an `If-Match`.
    created_at: str
    # An actor string, not a person: `user:u_...`, `system:cli` for a seeded row, and
    # `migration:032` for the one version that predates this feature. A screen that
    # rendered those as names would be inventing three people.
    created_by: str
    # create | save | update | restore | migration — `VERSION_SOURCES`, and the union is
    # deliberately not restated as a `Literal` here. 020's fourth finding was a hand-typed
    # copy of a vocabulary going stale against the frozenset it mirrored; a plain `str`
    # cannot go stale, and the values a client branches on are the two it renders
    # differently.
    source: str
    # The version this one was restored from, or null. Set exactly when `source` is
    # `restore`, which migration 032 enforces as a CHECK.
    restored_from: int | None = None
    valid: bool = True
    error: str | None = None


class AgentVersion(AgentVersionSummary):
    """One stored configuration, whole.

    `config` is the config **as it was written**, not merged with anything and not
    repaired. That is what makes it restorable and it is also the trap a client must not
    walk into: sending this back through `PATCH` does not restore it, because a merge
    keeps every key the old config does not have. `POST .../restore` exists for that
    reason.
    """

    config: dict = Field(default_factory=dict)


class AgentAccessEntry(BaseModel):
    """One row of the share sheet: who, at what level, and — the decision — **how**.

    `via` is not a nicety. The moment unsharing exists in a UI, somebody revokes a grant,
    watches the agent stay visible through a group, and concludes the revoke failed.
    `unshare` already refuses that case loudly with a sentence naming the group; the
    screen has to say the same thing *before* they try.
    """

    # **Derived from `GRANTEE_KINDS` rather than written out**, and step 020 is why.
    #
    # It was `Literal["user", "system", "group"]` — a fourth copy of a vocabulary that
    # already lives in a frozenset and a CHECK constraint. Adding `machine` to both of
    # those left this one behind, so the first share sheet holding a machine grantee
    # answered **500**: the grant was correct, the storage layer was correct, and the
    # response model refused to describe what it was handed. Found by driving the route,
    # invisible to every test that did not.
    #
    # This is 010's predicted `types.ts` drift arriving one layer earlier, and the fix is
    # the one that step named: derive one from the other. A kind added to `GRANTEE_KINDS`
    # is now describable here without anybody remembering to come and look.
    kind: Literal[tuple(sorted(GRANTEE_KINDS))]  # type: ignore[valid-type]
    id: str
    # The **effective** role: the highest of what they hold directly and through a group.
    role: str
    # The role they hold in their own right, or null for access that is entirely
    # inherited. Null and `role` are different facts and a screen needs both.
    direct: str | None = None
    # The groups they reach it through, possibly empty. A group's own row has this empty
    # and `direct` set.
    via: list[str] = Field(default_factory=list)
    # `kind:id` of whoever wrote the grant row, or '' for one that is inherited. Free
    # text — migration 011 filled it with `'migration:011'` — so it is shown and never
    # parsed. See `grant_agent`, where `granted_by` and `actor` are argued apart.
    granted_by: str = ""
    # Step 033e, on a group's own row: this group's membership comes from the customer's
    # directory, so the people listed under it are the ones who have **signed in** since
    # being placed there rather than everybody who will be. The completeness this sheet
    # used to promise is what a directory takes away, and saying so is the whole reason
    # for the field — see `who_has_access`.
    directory: bool = False


class PendingGrant(BaseModel):
    """An address shared with that has never logged in.

    A separate list from `access` rather than a row in it, because merging them would
    report access that does not exist: nobody has this, and somebody *will* if a person
    ever arrives at that address. Nothing expires these and nothing notifies anybody.
    """

    email: str
    role: str
    granted_by: str = ""


class AgentAccess(BaseModel):
    """What `GET /agents/{name}/access` answers. Readable at `user`.

    Deliberately the bottom of the ladder, matching `who_has_access`: somebody about to
    run an agent that acts on **their** data should be able to see who else can reach it.
    """

    access: list[AgentAccessEntry] = Field(default_factory=list)
    waiting: list[PendingGrant] = Field(default_factory=list)


class GrantRequest(BaseModel):
    """The body of a `PUT` on a grant. One field, because the URL carries the grantee."""

    model_config = ConfigDict(extra="forbid")

    role: str = "user"


class GrantOutcome(BaseModel):
    """What a `PUT` on a grant answers, and the field 006 deliberately hid.

    `share_by_email` has returned `"granted"` or `"pending"` since 006 and made it
    invisible to the sharer by design. It stops being invisible here, because the two
    states look identical on a screen and only one of them means anybody actually has
    access — a sharer who cannot tell them apart says "I shared that with her weeks ago"
    some time later.
    """

    outcome: Literal["granted", "pending"]
    kind: str
    id: str
    role: str


class DraftVerdict(BaseModel):
    """What `POST /agents/validate` answers when the answer is yes.

    There is no `valid: false` branch. An invalid draft is a **422 carrying the
    validator's own sentence**, which is the same response `POST /agents` gives it — so
    a client that renders the dry run correctly renders the real thing correctly, and
    the wizard cannot develop a second opinion about what an error looks like.
    """

    valid: Literal[True] = True


class ResourceType(BaseModel):
    """What a tool touches, as a **type** and nothing else.

    An object rather than a bare string, and that is the whole of the design here. A
    resource is `Resource("github.repo", ["owner", "repo"], template="{owner}/{repo}")`
    — a type composed out of one server's two argument names — and policy never learns
    the second half. Handing `args` and `template` to a client invites it to build a
    scope out of argument names, which is the coupling the type exists to prevent, and
    it would be invisible until a second connector named the same resource differently.

    So the object has one field today and is a place for a display name to arrive
    later, rather than a string that would have to become an object to gain one.
    """

    type: str


class ToolSummary(BaseModel):
    """One tool somebody could grant, with the annotation that says what it does.

    `effect` is the field this whole route exists for. It is the one thing MCP cannot
    tell us about itself — `readOnlyHint` is advisory and self-declared, and an
    enterprise boundary cannot rest on a claim made by the component being constrained
    — so a person vets a server one tool at a time and writes it down. It has been in
    `vetted_tools` since migration 003 and, until this route, was exposed to nobody.
    """

    # The **local** name: what a grant says and what the audit log records.
    name: str
    # What the server calls it. `null` for a built-in, which is the honest way to say
    # that only one of the two halves has an upstream.
    remote_name: str | None = None
    # The vendor's own words, stored at vetting time rather than fetched — so this
    # answers with the connector's server stopped, and cannot change under a grant
    # somebody already approved. See migration 018.
    description: str = ""
    # Ours, and optional: what somebody here should know before granting it.
    note: str = ""
    effect: Literal["read", "write"]
    # Whose account this tool acts as — step 033a, decided at vetting time exactly as
    # `effect` is. `service` is the connector's shared credential, the caller's
    # connections never consulted; `user` is the caller's own connected account,
    # refused when they have none, never the shared fallback.
    identity: Literal["service", "user"] = "service"
    resources: list[ResourceType] = Field(default_factory=list)
    max_response_bytes: int | None = None
    # The review record. Empty for a built-in — **not omitted**, because a client
    # rendering "vetted by" needs one shape, and empty rather than "platform", because
    # inventing a reviewer for something nobody reviewed is the false assurance the
    # vetting table exists to avoid.
    #
    # `vetted_by` was `""` on every connector tool for two steps, because nothing vetted.
    # Step 012's `--vet` is the writer, so a tool approved through it names a person here.
    vetted_by: str = ""
    vetted_at: str = ""

    # What the server called itself when this tool was approved — migration 023.
    #
    # Exposed here rather than left to the CLI **because `catalogue()` is shared**, and
    # the reason it is shared is written into `tools.catalogue`: `GET /tools` and
    # `--list-tools` must answer the same question, and two readers of one table is how
    # they stop agreeing. A route that silently dropped a field the CLI prints would be
    # that failure arriving through the response instead of through a second query.
    #
    # Nothing renders it yet — the vetting screen is 12c and needs a role that does not
    # exist. That is a reason for no *screen*, not a reason for the data to be absent
    # when somebody builds one.
    server_name: str = ""
    server_version: str = ""


class ToolGroup(BaseModel):
    """Tools that came from one place, and which place that is.

    `origin` is a field rather than an omission. A built-in is code in this repository;
    a connector tool was vetted by somebody in this tenant and carries their name.
    Presenting them as one undifferentiated list would hide the difference that decides
    who to ask when something is wrong.
    """

    origin: Literal["builtin", "connector"]
    # The connector id. `""` for the built-in group, which has no id because it is not
    # a connector — there is exactly one of it.
    id: str = ""
    description: str = ""
    tools: list[ToolSummary] = Field(default_factory=list)


class ConnectionState:
    """The three-and-a-half states a connector can be in for one person. Step 7b.

    Constants rather than a bare `Literal`, because `routes_connections._state_of`
    computes them and a client renders them — two places, and a typo in either is a row
    that renders as nothing at all. The `Literal` below is built from these, so the two
    cannot drift.

    `RECONNECT` is the half. It is `CONNECTED` in the sense that a row exists, and
    `CONNECTABLE` in the sense that the person has something to do — and collapsing it
    into either loses the reason, which is the thing they need. It exists because a
    provider can revoke consent at any time and the first anybody hears of it is a run
    failing; this is that fact, on a screen, before the run.
    """

    CONNECTED = "connected"
    CONNECTABLE = "connectable"
    RECONNECT = "reconnect"
    UNAVAILABLE = "unavailable"


class ScopeNote(BaseModel):
    """What one OAuth scope permits, for the person being asked to grant it. Step 068.

    `access` is copied from onecli's `permissions` array and is deliberately **not**
    `VettedTool.effect`. `effect` is per tool, is a judgment a vetter made, and the broker
    enforces it on every call. This is per scope, is a sentence a vendor wrote, and this
    platform enforces nothing with it — it is a label on somebody else's permission. See
    migration 051 for why collapsing the two would be a mistake rather than a tidy-up.
    """

    name: str = ""
    description: str = ""
    access: Literal["read", "write"]


class ConnectionSummary(BaseModel):
    """One row of the Connections page: a connector, and where this person stands with it.

    Deliberately **not** keyed by principal and carrying no principal field. This shape is
    only ever returned for the caller — see `routes_connections`, which has no way to ask
    about anybody else, and that module for why 12b's tenant-admin role did not change it.

    **Every field is required — 035f, and it is 035c's decision 1 arriving at its fourth
    model.** The route supplies all ten kwargs unconditionally, so a default here would
    describe a state that cannot arise, and the OpenAPI document would type a person's
    connection state as possibly-absent. It said exactly that until 035f: `required` was
    `['connector_id', 'state']` and the six fields the route always sent were optional.
    035d broke the same rule on five fields and its edge pass caught it **in the document
    rather than in the model**, which is why
    `test_the_connections_response_declares_every_field_as_required` asserts against
    `/openapi.json`.

    Required is not the same as non-null and three fields here prove it: an unconnected row
    sends `expires_at`, `refresh_expires_at` and `updated_at` as `null`, because there is
    no connection to have them. The key is always sent; the value says whether there is a
    fact.

    **Three instants, all `datetime` — this model is the file's exception on purpose.**
    Every other stamp in this file is a `str` converted by a per-route `_stamp` helper.
    `expires_at` has been a `datetime` since 7b, and 035f put the two new ones beside it
    rather than beside the file: two spellings of *an instant* inside one response is a
    distinction a reader would have to trace to two chunks to explain, a generated client
    would type one as a `Date` and the other as a string, and the route would gain a third
    place in this repository that converts a stamp. FastAPI serialises all three to ISO, so
    the wire is identical either way and `types.ts` calls all of them `string`. The
    file-wide split is older than 035f and is a register row rather than this model's to
    fix.
    """

    connector_id: str
    description: str
    state: Literal["connected", "connectable", "reconnect", "unavailable"]

    # Whose account, according to the **provider** for an OAuth connection and according
    # to whoever typed it for a pasted one. 7a's README flagged that distinction as a
    # known weakness and predicted 7b would fix half of it; it did — see
    # `oauth._account_label`, including what "verified" does and does not mean there.
    account_label: str

    # `static` | `oauth` | `''` when not connected. Rendered, because the two are
    # genuinely different things to a person: one of them they can renew themselves and
    # the other renews silently, and one of them an operator has seen.
    #
    # It is also the field that decides what the two expiries below *mean*, which is why
    # a client must never read either of them without it. See `expires_at`.
    credential_kind: str

    # The **access** token's expiry, or null. Not a countdown and not a warning — a
    # connection with a refresh token is renewed before every run that needs it, so this
    # is only interesting for the ones without.
    #
    # **035f found the sharper reason, by reading the refresh path rather than this
    # comment.** `refresh_for_run` renews at the *start of a run* and `_stale` skips the
    # exchange while there is life left, so a healthy OAuth connection's `expires_at` is
    # in the past for most of the time it exists and is renewed to a future instant moments
    # before anything needs it. A client that rendered this field on an OAuth row would
    # therefore tell the *majority of healthy connections* that they had expired. It is
    # renderable on a `static` row, where nothing renews and a past instant is dead —
    # `credentials.for_connector` refuses that row with a sentence naming this date.
    expires_at: datetime | None

    # The **refresh** token's own expiry, or null — migration 024, on the wire since 035f.
    # A different fact from `expires_at`: this one is when the *connection* lapses, after
    # which no amount of renewing helps and the person has to consent again. Migration
    # 024's own argument for the column is the argument for putting it here: *"Without the
    # column, 'this connection will need re-consenting' cannot be predicted at all, only
    # discovered by a run failing"* — and until 035f it was predicted nowhere, because the
    # column was stored, projected by both stores, handed to this route, and never named.
    #
    # **Null means two things and neither is "this will not lapse".** Most providers
    # volunteer no refresh lifetime at all (Atlassian's 90 days and Google's indefinite
    # tokens are both silence), and a connection carrying no refresh token *whatever* also
    # reads null here until the next refresh converts it to `reconnect` with a reason. A
    # client says nothing for null rather than inventing reassurance from it.
    #
    # It survives a renewal that keeps the same refresh token and is dropped by one that
    # rotates it — `oauth.refresh_connection` carries that argument, and the asymmetry is
    # the point: the value describes *a particular token*, so it outlives a refresh only
    # for as long as the token does.
    refresh_expires_at: datetime | None

    # When this connection last changed, or null when there is none — migration 013, on the
    # wire since 035f.
    #
    # **It is the row's compare-and-set token, and that is what kind of fact it is.**
    # `update_connection_credential` renews with `WHERE ... AND updated_at = %s` and
    # refuses a call that supplies none, because a refresh with no precondition is
    # last-write-wins and stores a refresh token the provider has already invalidated. So
    # this is a *version*, published because it is also the answer to migration 013's
    # question — *"'when did this last change' is the first question asked when somebody's
    # agent starts failing"* — and it is read-only on the wire: no route accepts it back,
    # and a client that echoed it would be handing a lock token to a surface that has no
    # lock.
    #
    # **The word is *changed*.** A reconnection bumps it, a refresh bumps it, and a
    # re-labelling bumps it, so *connected* (which is `created_at`'s word) and *refreshed*
    # (which is wrong on a static row) are both narrower than the fact. `--list-connections`
    # printed this under the heading `connected` until 035f corrected it.
    updated_at: datetime | None

    # The provider's own reason this stopped working, or ''. Non-empty exactly when
    # `state` is `reconnect`. Rendered rather than paraphrased: "reconnect" is what to do
    # and this is what tells somebody whether doing it will help.
    reconsent_reason: str

    # What the consent screen will ask for. Shown *before* somebody clicks Connect,
    # because the alternative is that the first time they learn what they are agreeing to
    # is on a third party's page — and the honest place to say "this will be able to read
    # your Jira issues" is the button that causes it.
    #
    # **This is the OAuth *application's* configured ask and NOT a granted scope, which is
    # the trap in the field's name — 035f.** It comes from `connector_oauth.scopes` via
    # `oauth.configured`, it is the list `oauth.begin` joins into the authorize query, and
    # it describes what a consent flow *would* request right now. What a particular person
    # actually consented to is **stored nowhere**: there is no `granted_scopes` column,
    # `OAuthTokens` drops the provider's `scope` echo on purpose, and `_tokens_from` never
    # reads it.
    #
    # So a client that renders this beside a *connected* row is answering a different
    # question from the one the row invites, and must say which: an administrator who
    # widens the app's scopes afterwards would otherwise make the screen claim a live
    # credential carries scopes it never had. It is meaningless beside a `static`
    # credential, which never met a consent screen at all. See `DEFERRED.md` — storing the
    # granted scope is a migration and is the real fix.
    scopes: list[str]

    # What those scopes *permit*, in words — migration 051, and this is the field the
    # whole of step 068's storage half exists for. `scopes` above is honest and useless
    # to the reader it is shown to: somebody who is not an administrator, clicking
    # Connect, being asked to grant `write:jira-work`.
    #
    # Keyed by scope, and a scope with nothing to say has no key rather than an empty
    # entry — `offline_access` is bookkeeping and inventing a sentence for it would be
    # this platform describing somebody else's permission from a guess.
    #
    # Carries the same caveat as `scopes` and for the same reason: it describes what a
    # consent flow would ask for now, not what anybody granted.
    scope_notes: dict[str, ScopeNote] = Field(default_factory=dict)


class ConsentStart(BaseModel):
    """Where to send the browser. **Never a token, and there is nothing else here.**

    A URL rather than a redirect, because `fetch` follows a 302 transparently and would
    pull the provider's consent HTML into a promise nobody can render. The client assigns
    `window.location` — a top-level navigation, which is what the flow requires.
    """

    authorize_url: str


class DisconnectOutcome(BaseModel):
    """What `DELETE /connectors/{id}/connection` answers.

    `revoked_upstream` is the field this shape exists for, and it is **three-valued**:

        true    the provider was told, and acknowledged
        false   we tried and could not. The token may still be live upstream
        null    there was nobody to tell — a pasted credential, or a provider that
                publishes no revocation endpoint

    Decision 12 makes the local delete unconditional so that a provider outage cannot
    trap somebody in a connection they have asked to end. The cost of that is exactly this
    ambiguity, and a `bool` would resolve it by guessing.
    """

    disconnected: bool
    revoked_upstream: bool | None = None


class Me(BaseModel):
    """Who the caller is, here. The first route in this API about the **caller**.

    `AgentDetail.your_role` is the precedent, one level up. 10d added it because *"a
    screen without it renders buttons that 404 at the person they were rendered for"* —
    and an Administration nav item has the identical problem for the whole application. A
    SPA reads display claims off its own token, and a token knows nothing about a row in
    `platform_roles`, so without this the app can only discover it is not an administrator
    by rendering a link and watching it 403.

    **Deliberately tiny, and deliberately not a settings surface.** It answers "who am I,
    here" and nothing else. Three future screens need exactly that — the admin nav item,
    the vetting screen, and role administration when it exists.

    `admin` is a bool rather than a list of roles, matching `PLATFORM_ROLES` having one
    member. It becomes a list on the day there are two, which is an additive change to a
    field nobody is branching on more finely than this.

    `mcp_url` is a fact about *this deployment* rather than about the caller, and it
    is here for the reason `admin` is: it is configuration the bundle cannot know, and a
    build-time guess cannot be wrong *later* — it is wrong from the first deployment
    that configures differently, and the same bundle is served to every one of them.
    """

    principal: str
    kind: str
    email: str = ""
    display_name: str = ""
    admin: bool
    # Step 044 — the door's dialable address is `PUBLIC_ORIGIN + "/mcp"`, configuration
    # the bundle cannot know, and the connect card that renders it must not guess at it
    # from its own origin — behind a proxy the two genuinely differ. Empty-string default
    # so a new bundle against an older API shows no address rather than a wrong one.
    mcp_url: str = ""


class AdminRecord(BaseModel):
    """One row of the administrative log — *who changed who may do what*.

    The shape is `ADMIN_AUDIT_FIELDS` less `tenant_id`, which the caller already knows
    because it came off their principal and could not have come from anywhere else.

    `detail` is `dict` and stays `dict`. It differs per action by design — a role, a
    grantee, a list of field names — and pinning it to a model here would be this schema
    inventing a shape the writer never agreed to, then failing to serialize a record the
    log holds. `--admin-log` prints it the same way, unstructured, for the same reason.
    """

    v: int
    ts: str
    actor_kind: str
    actor_id: str
    action: str
    target_kind: str
    target_id: str
    detail: dict = Field(default_factory=dict)


class DenialRecord(BaseModel):
    """One row of the access-denial log — *who tried, and was refused*.

    The shape is `DENIAL_FIELDS` less `tenant_id`, `AdminRecord`'s convention: the
    caller already knows their tenant because it came off their principal and could not
    have come from anywhere else.

    Flat, with no `detail`, and that is the seam's shape showing through: `require` sees
    a principal, a name and a level, and nothing else — no request body, no free text —
    so there is nothing unstructured for a record to carry.

    **`held` has no default, and 035b removed the one it had.** It is `DoorCallRecord`'s
    strict-versus-default question asked one model over, and it comes out the same way:
    `''` is a *real value* in this column — the principal held nothing, which is the
    headline case and the whole difference between a stranger probing and a `user`
    probing for `editor`. So a default would not stand in for an absent field; it would
    make the model **invent "they held nothing"** for a record that never said so, in a
    log kept to be read after an incident. A 500 is the better failure. It costs nothing:
    the column is `NOT NULL DEFAULT ''` (migration 028), so Postgres cannot return a row
    without it, and since 035b's projection in `memory.record_denial` neither can the
    fake.

    `resource_kind` stays a plain `str` here and on the screen. The vocabulary is
    `DENIAL_RESOURCE_KINDS` and the route's *filter* is derived from it — but a response
    model that restated it would be `AgentAccessEntry.kind`'s bug waiting to happen from
    the other end: a kind the store legitimately holds and the model refuses to describe
    is a 500 over a correct record.
    """

    v: int
    ts: str
    principal_kind: str
    principal_id: str
    resource_kind: str
    resource_id: str
    required: str
    held: str


class DoorCallRecord(BaseModel):
    """One brokered call that came through the **MCP door** — step 035a.

    Not a fourth log. This is a row of `audit`, the same table `GET /runs/{id}` reads,
    selected by the one thing that separates a door call from a run: a correlation id
    shaped `door-<hex>`, which `runs.get`'s prefix match can never resolve. Every field
    the door added in schema version 7 — `acting_for`, `identity_source` — lands only on
    these rows, which is why the reader had to exist before any of it was legible.

    **Two stored fields are deliberately not declared here, and their absence is the
    redaction.** `args` is caller-supplied free text; `core/audit._redact` already keeps
    secrets out of it, but the class of thing it holds is not what an admin listing is
    for, and a record kept forever should not put it on a screen by default.
    `credential` is a lookup key — *which kind* of secret a call went out with — that
    nobody asked to read in a browser. Both stay in the stored record, and both are
    returned by `door_call_records`, for the CLI and for an incident query.

    **The mechanism is pydantic's default `extra="ignore"`, and here that is intended
    rather than inherited.** Every request body in this file carries
    `extra="forbid"`; the three log records do not, because they are built from a dict
    the store owns and are meant to project a subset of it. 035c found the mirror image
    of this — `OwnedToken` silently dropping `acts_as_owner`, a field the wire *should*
    have carried — so the difference is worth stating: a dropped field is a bug when the
    model meant to declare it and a policy when it did not. Adding `args` or
    `credential` to this model would be undoing a decision, not fixing an oversight.

    `identity_source` is `"verified" | "asserted" | "none"` and the three are never
    collapsed here or on the screen that renders them. An asserted name is worth exactly
    what the calling app's honesty is worth, and a row that hid the difference would
    upgrade it.
    """

    v: int
    ts: str
    # The `door-<hex>` correlation id. Carried rather than hidden: it is what ties this
    # row to the same call in a CLI query, and it is the visible proof that a door call
    # is not a run.
    run_id: str
    principal_kind: str
    principal_id: str
    agent: str
    tool: str
    effect: str = ""
    decision: str
    reason: str = ""
    outcome: str = ""
    duration_ms: int | None = None
    response_bytes: int | None = None
    acting_for: str | None = None
    identity_source: str
    # What the call spent at a model, when the tool reported it. Step 045b.
    #
    # **Declared here where `args` and `credential` deliberately are not**, and the
    # difference is the same one this class's docstring draws: those two are redacted
    # from the listing because of the *class of thing* they hold. Token counts are the
    # opposite — they are the answer to *why is this credential being refused*, which is
    # exactly the question somebody opens this listing with.
    #
    # `None` on nearly every row, and never `0`: the call touched no model, which is not
    # the same fact as a model call that spent nothing. Migration 048 keeps them apart in
    # the column and this keeps them apart on the wire; a client rendering `0` where the
    # store said NULL would report every tool call as a free model call.
    model: str = ""
    input_tokens: int | None = None
    output_tokens: int | None = None
    cache_read_tokens: int | None = None
    cache_write_tokens: int | None = None


class GroupSummary(BaseModel):
    """A group as the **menu**: enough to pick one, and no membership.

    Readable by anybody authenticated in the tenant, on `GET /tools`' argument one noun
    over — an `editor` sharing an agent with a group has to pick one, and until 12b the
    share sheet could only take an id somebody was told out of band. What a name discloses
    is that a team exists, which the org chart already does.

    **The diner arrived in 035h, and 12b is when the waiting started.** This shape,
    `deps.ADMIN_SURFACE`, `routes_groups.list_groups` and `access/groups.list_groups` all
    argue the disclosure on the strength of an `editor` picking a group to share with, and
    there was no such caller:
    `ShareSheet.tsx` had no group control at all and hardcoded `email` as the grantee kind,
    so sharing with a group was reachable only from the CLI. Four arguments for one consumer
    that had never been written, and nothing failed. See `DEFERRED.md`.

    `member_count` is deliberately **not** here. A count is the first step of the
    directory this shape refuses to be, and the one legitimate non-admin need — *who will
    this share reach* — is answered per agent by `GET /agents/{name}/access`.
    """

    group_id: str
    name: str
    description: str = ""
    # Step 035h. **The boolean, never the id.** Whether this group's membership comes from
    # the customer's directory is a property of the workspace and it changes what sharing
    # with the group means — the people it reaches are whoever the directory names, applied
    # at each person's next sign-in, and nobody here adds or removes them. The `external_id`
    # itself is a customer's Entra object id and stays on the admin-only `GroupDetail`.
    #
    # The split is `AgentAccessEntry.directory`'s exactly, and that field is the reason this
    # one is not a new disclosure: the same bit has been served at `user` since 033e, per
    # agent, to anybody holding a grant on it. What is new is that the *menu* carries it, so
    # an editor picking a group is told which kind they picked before they share rather than
    # after.
    directory: bool = False


class GroupMemberEntry(BaseModel):
    """One member of a group. **Admin-only**, and the reason is in `GroupDetail`."""

    kind: str
    id: str
    added_by: str = ""


class GroupDetail(GroupSummary):
    """A group **with its membership**, which is what makes it administrator-only.

    "Who is in every group" is a directory of the company, and it is a different question
    from "who will this share reach" — which `who_has_access` already answers, per agent,
    for an agent the reader holds a grant on. See `access/groups.members`, where the same
    split is enforced one layer down so the CLI and this route cannot disagree about it.
    """

    external_id: str | None = None
    created_by: str = ""
    members: list[GroupMemberEntry] = Field(default_factory=list)


class GroupRequest(BaseModel):
    """`POST /groups`. A name, and optionally the two things a directory link needs."""

    name: str
    description: str = ""
    # Nullable, and NULL is not '' — see `GROUP_FIELDS`. A group linked to a directory
    # group with an empty id and one never linked are different states, and 9b reads this
    # column to tell them apart.
    external_id: str | None = None


class GroupLinkRequest(BaseModel):
    """`PATCH /groups/{id}`. The one field of a group that may be edited after creation.

    Its own body rather than a general group patch, on `agent.restore`'s argument: what
    this decides is *who may change who is in this group*, and a body that could also
    carry a name would bury that decision in a diff. `null` unlinks and removes nobody.

    **The field is required and unknown keys are refused**, which the edge-case pass
    made non-negotiable: with a default, `PATCH {}` and `PATCH {"externalId": …}` — a
    probe, and a camel-cased typo — both answered **200 having unlinked the group**,
    silently taking its membership off the directory. That is the same
    reported-success-for-the-opposite failure `groups.link` refuses a *blank* value to
    prevent, walking in through the one shape that guard cannot see. Unlinking is
    spelled `{"external_id": null}` and nothing else is.
    """

    model_config = ConfigDict(extra="forbid")

    external_id: str | None


class MemberOutcome(BaseModel):
    """What a membership write answers, and it says whether anything **changed**.

    `PUT` is idempotent and `DELETE` is too, so both succeed either way — and "added" and
    "was already in it" are different facts about the world. A 204 on both would make an
    administrator unable to tell a no-op from a change, which is the same complaint
    `GrantOutcome` exists to answer for sharing.
    """

    group_id: str
    kind: str
    id: str
    changed: bool


# --- the administration surface (12c) -------------------------------------------------
#
# Connector onboarding, as shapes. Everything below is administrator-only and lives under
# `/admin` for finding 7's rule: a noun with a non-admin half stays top-level (`/groups`
# has its menu, `/connections` is self-serve), and an admin-only noun is prefixed. That is
# what keeps `GET /admin/connectors` from becoming the second answer to *what may I grant*
# that `routes_tools.py` refused to add.


class HostEntry(BaseModel):
    """One row of the egress allowlist: a host somebody approved, and who.

    **An empty allowlist denies everything**, which is a reading `tools/mcp/egress.py`
    owns rather than this shape — a list of no rows here means a tenant that can dial
    nothing, not a tenant with no opinion.
    """

    host: str
    allowed_by: str = ""
    allowed_at: str = ""
    note: str = ""
    # Non-empty exactly when this host will never be dialled whatever the allowlist says
    # — a loopback name, a private range, the link-local address cloud metadata lives on.
    # Computed per read rather than stored, because the rule is code and a stored copy of
    # a rule is a rule that goes stale. See `egress.approval_warning`.
    warning: str = ""


class HostRequest(BaseModel):
    """`POST /admin/hosts`. **The host is in the body, and that is a decision.**

    12b's edge pass established that a `/` in a path segment is a routing 404 even
    percent-encoded, because uvicorn decodes before Starlette routes. Approval is where
    free text arrives — people paste `https://mcp.acme.com/mcp` when adding a host — so a
    path-segment route would answer a bare 404 where `normalize_host` has a sentence
    explaining exactly what to strip. In the body, the refusal can speak.

    Revocation is the other way round and `DELETE /admin/hosts/{host}` keeps its
    addressable URL, because it clicks on a row this API itself rendered: always a bare
    normalized hostname, which never carries a slash.
    """

    host: str
    note: str = ""


class HostApproved(BaseModel):
    """What approving a host answers. **200 with a `warning`, not 204.**

    The warning is the whole reason this is not a 204. `--allow-host` prints it to stderr
    and over HTTP there is no stderr, so an administrator approving `localhost` would be
    told yes about a control that is not in force — the precise failure `egress.py` is
    written against. Same sentence as the terminal's, from `egress.approval_warning`.
    """

    host: str
    note: str = ""
    warning: str = ""


class HostRevoked(BaseModel):
    """What revoking a host answers. **200 with a body, not 204** — see `stranded`.

    `removed` is false when the host was not approved in the first place, on
    `MemberOutcome`'s reasoning: idempotent either way, and an administrator who cannot
    tell a no-op from a change cannot tell a working control from a broken one.

    `stranded` is the connectors now pointing at a host nobody will dial. They keep their
    registration and their vetting and will refuse to connect until it is approved again —
    which is `revoke_host`'s deliberate behaviour and the thing somebody will otherwise
    assume did not happen. A 204 has nowhere to say it.
    """

    host: str
    removed: bool
    stranded: list[str] = Field(default_factory=list)


class OAuthApp(BaseModel):
    """A connector's consent flow, **public fields only**.

    This is `storage.OAUTH_APP_PUBLIC_FIELDS` as a model, and the correspondence is
    asserted by a test rather than maintained by care. The sealed `client_secret` and its
    `key_id` are deliberately the last two columns of `OAUTH_APP_FIELDS` and are not in
    the public tuple, so a reader that asks for the public projection is *structurally
    unable* to acquire the secret on the way past — 7b's containment, which this step only
    has to not route around.

    There is no masked echo of the secret anywhere in this API, and that is deliberate
    rather than an omission: `••••••` implies the value is retrievable, and it is not. The
    screen renders the word *stored*.
    """

    connector_id: str
    authorize_endpoint: str
    token_endpoint: str
    revoke_endpoint: str = ""
    client_id: str
    scopes: list[str] = Field(default_factory=list)
    authorize_params: dict = Field(default_factory=dict)
    # Migration 051: what each scope permits, in words. The most *public* field on this
    # model — its whole purpose is to be rendered to a non-administrator at the moment
    # they consent, which is a weaker audience than anything else here has.
    scope_notes: dict[str, ScopeNote] = Field(default_factory=dict)
    configured_by: str = ""
    configured_at: str = ""


class OAuthRequest(BaseModel):
    """`PUT /admin/connectors/{id}/oauth`. The secret rides in the **body**.

    `_read_secret`'s rule is *never argv*, because argv is shell history and the process
    table. The HTTP equivalent is *never a query string*, which is server logs and browser
    history, so this is a body on a `PUT` and the client sends it over TLS once.

    **The secret is required and non-empty**, refused by the schema rather than by a
    branch, so a blank one is a 422 naming the field. A blank secret stored silently is a
    consent flow that works right up until the first token exchange, at which point it
    fails at a third party for a reason nothing here recorded.

    `authorize_endpoint` and `token_endpoint` are both required, unlike `--set-oauth`'s
    `--auth-server` shorthand. The guess that a base URL implies `/authorize` and `/token`
    is a convenience for somebody typing, and a form has two boxes: what is usually right
    is not what an API should default to when the caller can simply say.
    """

    authorize_endpoint: str = Field(min_length=1)
    token_endpoint: str = Field(min_length=1)
    revoke_endpoint: str = ""
    client_id: str = Field(min_length=1)
    client_secret: str = Field(min_length=1)
    scopes: list[str] = Field(default_factory=list)
    # Provider-specific, and the first real provider needed two — Atlassian mandates
    # `audience` and `prompt`. See migration 025.
    authorize_params: dict[str, str] = Field(default_factory=dict)
    # Migration 051. Refused by `normalize_scope_notes` when it describes a scope this
    # request does not ask for, which arrives here as a 400 naming both lists — a typed
    # model can say the shape is wrong and only the storage layer can say the note
    # describes a permission nobody is granting.
    scope_notes: dict[str, ScopeNote] = Field(default_factory=dict)


class OAuthConfigured(BaseModel):
    """What configuring a consent flow answers: the public fields, and the two things
    the person standing there still has to do.

    `redirect_uri` is the one real onboarding ask in the whole flow, and it is returned
    rather than documented because the person who must register it at the provider is
    looking at this response. Same value for every connector on a deployment.

    `warnings` is a list rather than a string because there can be more than one and
    because a client renders them as a list. Today it holds the offline-access warning:
    a **warning and not a refusal**, on `--allow-host localhost`'s precedent — every
    provider spells that scope differently and refusing on a guess about a vendor's
    vocabulary would block a correct setup.
    """

    app: OAuthApp
    redirect_uri: str
    warnings: list[str] = Field(default_factory=list)


class RecipeHost(BaseModel):
    """One host a recipe needs allowed, and why. Step 068.

    **The `why` is not decoration.** Approving a host widens where a tenant's processes
    may dial, which 044 called the sharpest administrative act in the product, and the
    person clicking approve is being asked to make that judgment. *The recipe said so* is
    not a reason anybody can weigh, so a recipe with a host and no sentence is refused at
    load rather than rendered as a bare hostname.
    """

    host: str
    why: str = ""


class RecipeTool(BaseModel):
    """A tool a recipe **proposes**, in the shape the vetting form pre-fills from.

    Not a `VetRequest` and deliberately not reusing it: a `VetRequest` is a decision
    somebody made, and this is a suggestion nobody has looked at. They have the same
    fields today and the day they diverge is the day the distinction matters — a shared
    model is how a proposal quietly becomes an approval because one route accepted it.

    Nothing here has been vetted. Each still goes through
    `PUT /admin/connectors/{id}/tools/{name}` one at a time, which is 012's judgment and
    is why there is no bulk-apply anywhere in this step.
    """

    remote_name: str
    effect: Literal["read", "write"]
    identity: Literal["service", "user"] = "service"
    resources: list[dict] = Field(default_factory=list)
    local_name: str | None = None
    max_response_bytes: int | None = None
    description: str = ""
    note: str = ""
    redact_args: list[str] = Field(default_factory=list)
    binding: dict | None = None


class Recipe(BaseModel):
    """A checked-in preset that pre-fills connector registration. Step 068.

    Carries no `client_id` and no `client_secret`, and that is a property of the files
    rather than of this projection — see `access/recipes.py`, which refuses a recipe
    holding either.

    `staleness` is computed at read time, never stored: `HostEntry.warning`'s precedent,
    and the same argument. The rule about when a check stops counting is code, and a copy
    of it in a file goes stale the first time the rule changes.
    """

    id: str
    name: str
    description: str = ""
    # `null` means nobody here has completed a consent flow against this vendor. The
    # screen renders that as a sentence rather than hiding it: a wrong-but-editable
    # prefill beats a blank form, provided it does not claim to have been checked.
    verified_on: str | None = None
    verified_by: str = ""
    verified_against: str = ""
    staleness: Literal["verified", "stale", "unverified"]
    hosts: list[RecipeHost] = Field(default_factory=list)
    # The registration defaults, in `ConnectorRequest`'s own vocabulary so the form can
    # apply them field for field without a translation layer nobody would keep correct.
    connector: dict
    oauth: dict | None = None
    tools: list[RecipeTool] = Field(default_factory=list)


class ConnectorRequest(BaseModel):
    """`POST /admin/connectors`. **Registers, and vets nothing.**

    The ordering migration 021 forces: a credential cannot be sealed against a connector
    that does not exist, and discovery needs a credential because no server lists its
    tools to an unauthenticated caller. So *connect, look, then decide whether to
    register* is not expressible, and the row comes first.

    `url` is required and there is no command field, which is `tools.STDIO_REFUSED`
    expressed as a schema: a registered connector speaks HTTP, because HTTP is the only
    transport that can carry a per-user credential. An empty one still reaches
    `register_connector`, which answers with the full three-paragraph explanation rather
    than a field name.
    """

    connector_id: str = Field(min_length=1)
    url: str = ""
    # Which kind of connector this URL is — step 045a. `http` is a Streamable HTTP
    # MCP server, the only kind that existed before; `rest` is a plain REST API whose
    # tools are vetted with authored bindings rather than discovered. Defaulted so
    # every existing caller means what it meant.
    kind: Literal["http", "rest"] = "http"
    # The environment variable this server's credential is presented in. Named on the
    # manifest rather than guessed, so `core/credentials.py` is told where to read and
    # never learns what an MCP server is.
    credential_env: str = ""
    # Or where it lives in the customer's own vault — step 070, `op://vault/item/field`,
    # read at call time and never stored here. Mutually exclusive with `credential_env`;
    # the route parses it and `tools.register_connector` refuses both being set.
    #
    # A **location**, never a value, exactly as `credential_env` is a name and never a
    # value — so like that field this one is shown back on the detail response, and
    # unlike a `headers` entry there is nothing sealed on either side of it.
    credential_ref: str = ""
    # Where the credential goes — step 045c. `None` means *the launch's own default*
    # (`Authorization`, `Bearer `), which is what most servers and most APIs want and
    # what every caller predating these fields meant. An empty `credential_prefix` is a
    # **real value**, not an absence: an API wanting the bare token in an `x-api-key`
    # header is registered with `""`, and the storage layer already distinguishes the
    # two on the way back out.
    credential_header: str | None = None
    credential_prefix: str | None = None
    # Non-secret headers sent on every request — a vendor's API version, most often.
    # Separate from the credential for the reason the launch keeps them separate: which
    # of the two is the secret should be obvious. Nothing here is sealed, and the
    # response shows it, which is the difference from `credential_env`.
    headers: dict[str, str] = Field(default_factory=dict)
    description: str = ""
    # Step 033c: whether an *asserted* acting-for through the MCP door is believed for
    # this server's tools. Default false — verified or nothing — and settable at
    # registration so a connector born trusting a caller says so from its first
    # administrative record. Toggled later through its own route, because a security
    # control changing state deserves its own log line.
    allow_asserted_identity: bool = False
    # Step 068. **Provenance, never a link.** The id of the checked-in recipe whose
    # values the client used to fill this form, written into `admin_audit.detail` and
    # nowhere else — no column, no foreign key, no join, so deleting a recipe can never
    # orphan anything.
    #
    # The route checks it names a recipe this build ships before recording it. The caller
    # asserts it and could still assert one it did not use; what the check stops is a
    # client writing arbitrary text into an append-only administrative log, which is
    # `vetted_by`'s objection at a much lower stake.
    from_recipe: str = ""


class AssertedIdentityRequest(BaseModel):
    """`PUT /admin/connectors/{id}/asserted-identity`. One boolean, deliberately.

    A dedicated request for a dedicated verb: this is trust in a calling application
    being switched, and folding it into a broader edit would bury the change in a diff
    a reader has to hunt through. The administrative record it writes
    (`connector.asserted_identity`) names the actor and the new value.
    """

    allowed: bool


class VettedTool(BaseModel):
    """One approved tool, as an administrator sees it — the catalogue row plus provenance.

    `name` is the **local** name, which is what a grant says and what the audit log
    records; `remote_name` is what the server calls it. Both, because they differ and
    somebody reading a vendor's documentation needs the second one.
    """

    name: str
    remote_name: str
    description: str = ""
    note: str = ""
    effect: str
    # Whose account it acts as — see `ToolSummary.identity`.
    identity: str = "service"
    resources: list[ResourceType] = Field(default_factory=list)
    max_response_bytes: int | None = None
    vetted_by: str = ""
    vetted_at: str = ""
    # What the server called itself when this tool was approved — migration 023. Empty on
    # anything `--seed` wrote, because it contacted no server, and empty is what that says.
    server_name: str = ""
    server_version: str = ""


class ConnectorSummary(BaseModel):
    """One registered connector, as an administration list row.

    Answers the three questions the list is read for — *is it registered, is anything
    vetted on it, can people connect to it themselves* — and answers them without
    contacting anything. `writes` is broken out from `vetted` because the read/write
    annotation is the one property of a tool that decides whether a mistake is
    recoverable, and a count of tools that hides it is a count nobody can act on.
    """

    connector_id: str
    description: str = ""
    transport: str
    url: str = ""
    credential_env: str = ""
    # Step 070. `""` when this connector's credential is an environment variable or
    # absent; an `op://vault/item/field` location otherwise. On the **summary** row and
    # not only the detail, because *which of our connectors do we not hold the secret
    # for* is a question an administrator asks about the list rather than about one, and
    # it is the sentence this whole step exists to let them say.
    credential_ref: str = ""
    vetted: int
    writes: int
    # Whether the host this connector points at is on the tenant's allowlist **right
    # now**. Registration checks it too, and a stored row outlives the moment it was
    # written: a host can be revoked after a connector was registered against it, which is
    # exactly the state `stranded` reports from the other direction.
    host: str = ""
    host_allowed: bool = False
    # Present when a consent flow is configured, absent otherwise. Absent is the third
    # state on the Connections page — *no consent flow yet, ask an administrator* — and
    # it is a distinct fact from "configured with no scopes".
    oauth: OAuthApp | None = None
    # Step 033c: whether an asserted acting-for through the MCP door is believed for
    # this server's tools. On the list row because "which of our connectors accept
    # asserted identity" is the question a security review asks of this screen.
    allow_asserted_identity: bool = False


class ConnectorDetail(ConnectorSummary):
    """One connector with **what was approved on it**, and by whom.

    The vetted list is read from the stored manifest and the review record, so this
    answers with the server stopped. That is migration 018's whole argument and it applies
    here as much as to the catalogue: a page about what somebody approved must not depend
    on the thing they approved it against being up. Looking at the *server* is
    `POST /admin/connectors/{id}/discovery`, which is a separate click for that reason.
    """

    tools: list[VettedTool] = Field(default_factory=list)


class DiscoveredArgument(BaseModel):
    """One argument of an advertised tool. **The reason discovery exists.**

    `--discover` was added in 012 because the argument names are the only part of vetting
    a person cannot guess: `--resource jira.project=projectKey` needs the exact name this
    server uses, and `required` decides whether a tool is scopeable at all — an optional
    argument that widens reach when it is absent is the case `validation.py` names, and it
    is invisible without this field.
    """

    name: str
    type: str = "any"
    required: bool = False


class DiscoveredTool(BaseModel):
    """One tool a server advertises **right now**, with its schema and its vetted mark."""

    name: str
    description: str = ""
    arguments: list[DiscoveredArgument] = Field(default_factory=list)
    vetted: bool = False
    # What this tool would be called here if it were vetted with no override. Computed so
    # the form can show it before anybody commits to it, rather than a person discovering
    # the namespacing rule from an error.
    local_name: str = ""


class DiscoveryFinding(BaseModel):
    """One thing that changed since this connector was vetted.

    `severity` is `refuse` or `report` and it is a threshold rather than a taxonomy — see
    `mcp.discovery.review`. A `refuse` finding is what `vet_tool` blocks on, so a screen
    that renders these has to render the difference: one means *stop*, the other means
    *know about this*.
    """

    severity: str
    message: str


class DiscoveryResult(BaseModel):
    """What a live look at a customer's own server answers.

    **A POST, although it writes nothing.** It causes an outbound connection to a third
    party, which is not a safe method's contract, and a GET that dials out is a GET that
    anything prefetching links would dial for you.
    """

    server: str
    tools: list[DiscoveredTool] = Field(default_factory=list)
    findings: list[DiscoveryFinding] = Field(default_factory=list)


class ResourceSpec(BaseModel):
    """A `Resource`, as a request shape — **structured, never the CLI's string.**

    `cli._parse_resource` accepts `TYPE=ARG` and `TYPE={a}/{b}:a,b`, and its docstring
    says exactly why that spelling stays in the CLI: *"Parsed here rather than in `tools/`
    because it is a command-line spelling of a `Resource`, and `Resource` itself must not
    learn one — the moment it does, an HTTP route ends up accepting the same string."*
    This is that instruction honoured rather than discovered.

    `args` is a list because a resource can be composed from more than one argument:
    GitHub's API splits a repo across `owner` and `repo`, so a descriptor that could name
    only one could not scope the one connector this repo ships. `template` says how they
    combine and is required when there is more than one — gluing two values together
    without a stated shape is a guess, and `tools.validate` refuses it.
    """

    type: str = Field(min_length=1)
    args: list[str] = Field(min_length=1)
    template: str | None = None
    # The families this identifier's id space is divided into, so a scope line can name
    # one instead of a dated id — step 086, 080's E8. Empty for every resource that has
    # no such notion, which is almost all of them. `min_length=1` on the member rather
    # than on the list: an empty *list* means "no families", and an empty *name* is a
    # token run inside every identifier and so a scope line that admits everything.
    families: list[str] = Field(default_factory=list)


class RestBindingSpec(BaseModel):
    """The request binding of a REST connector's tool — step 045a, structured.

    What discovery would have supplied, authored by the vetter: how to make the
    call. Structured rather than a raw dict on `ResourceSpec`'s reasoning — the CLI
    owns its own spelling (`--method`, `--path`, `--schema`), and a route accepting
    an unshaped mapping would defer every field error to a storage sentence when a
    422 can name the field. The cross-checks that need the whole picture — every
    schema property mapped somewhere, path placeholders present in the schema — stay
    in `tools/rest.check_binding`, one answer for both the CLI and this route.
    """

    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    # A template joined to the connector's base URL; `{argument}` segments name
    # arguments from `input_schema`.
    path: str = Field(min_length=1)
    # Which arguments travel where. Everything unmapped is refused at vet time
    # rather than guessed at call time.
    query: list[str] = Field(default_factory=list)
    body: list[str] = Field(default_factory=list)
    # The authored schema — what the model sees, and what resource declarations
    # validate against. There is no server to discover one from.
    input_schema: dict
    # Optional: where token usage lives in a response. Stored and validated by 045a,
    # consumed by 045c's model connector.
    usage_map: dict[str, str] | None = None
    # Optional: what this vendor's models cost, in USD per million tokens, keyed the way
    # `CARNET_MODEL_RATES` is keyed. Step 086, 080's E5 — beside `usage_map` because it
    # is the same kind of fact about the same vendor, written by the same person in the
    # same approval: that one says where the counters are, this one says what they cost.
    # Unshaped as `dict` here and validated in `tools/rest.check_binding`, which owns
    # every cross-check on a binding and is the one answer for this route and the CLI.
    pricing: dict | None = None


class VetRequest(BaseModel):
    """`PUT /admin/connectors/{id}/tools/{remote_name}`. Approve one tool.

    **Append, never replace.** The remote name is in the URL because it is the key of the
    write — the same reason `PUT /agents/{name}/grants/{kind}/{id}` is keyed by grantee —
    and re-vetting upserts *that* row and records again, which is `storage.vet_tool`'s
    existing rule: a new review overwrites the old rather than being edited underneath its
    name.

    One tool per request, so a failed tenth never costs nine. That is `--vet`'s decision
    and it matters more through a form than through a terminal, because a form is where
    somebody works through a server's whole tool list in one sitting.

    Nothing here can approve a tool the server does not advertise or scope one to an
    argument that does not exist: `tools.vet_tool` runs six checks against the schema the
    server sends at that moment, and both of those are refusals with sentences. The form's
    real job is showing the argument names, which is what `DiscoveredArgument` is for.
    """

    effect: Literal["read", "write"]
    # Whose account the tool acts as — the third judgment an approval makes, beside
    # `effect` and `resources`. Defaulted to `service` so a form that predates the
    # field approves what a missing key means everywhere else.
    identity: Literal["service", "user"] = "service"
    resources: list[ResourceSpec] = Field(default_factory=list)
    note: str = ""
    # Needed when prefix + remote name would run past the 64 characters the Messages API
    # allows in a tool name, and useful when a server's naming is unbearable.
    local_name: str | None = None
    # **Bounded here, and `null` is not the same value as `0`.** `null` means *use
    # `config.MAX_RESPONSE_BYTES`* and is the right answer for nearly every tool. A zero
    # reaches `broker._bound_response` as the cap outright, so the tool refuses every
    # response it will ever return — telling the model to narrow a request that cannot be
    # narrowed, with nothing anywhere recording that somebody typed a zero into a form.
    #
    # Refused by the schema rather than by a branch, on `OAuthRequest.client_secret`'s
    # reasoning: a value stored silently that breaks at the first real use is worse than a
    # 422 naming the field. It is the inverse of `DEFERRED.md`'s `max_tokens: null` row,
    # where null is the hazard and a number is safe; here null is correct and zero is the
    # hazard.
    #
    # **`strict` is not tidiness, and the edge pass is what found it.** Pydantic's lax mode
    # accepts `True` for an `int`, and `gt=0` is happy with the 1 it becomes — so a JSON
    # `true` here stored a **one-byte** ceiling, which is the same tool-killing row a zero
    # would have been, arriving through the one door the bound left open. `False` was
    # already refused, by `gt=0`, which is how confusing the pair was. This codebase
    # refuses a bool where an int goes in two other places on the same argument —
    # `agents.validate`'s limits and `storage.check_limit` — so this is the file's rule and
    # not a new one. Strict also refuses `"4096"`, and a string is not a byte count.
    #
    # **`le` is the column.** `vetted_tools.max_response_bytes` is a `BIGINT` (migration
    # 003), and one past its top reached psycopg as a numeric-out-of-range, became a
    # `StorageError`, and was answered **503 — try again later** about a value no amount of
    # later will accept. A 422 naming the field is what a permanent refusal is.
    #
    # 035g adds all three because 035g adds the input. `--max-response-bytes` does not come
    # through this model and is still unbounded — a register row, not an omission.
    max_response_bytes: int | None = Field(
        default=None, gt=0, le=2**63 - 1, strict=True
    )

    # REST connectors only, both of them — step 045a. On a REST connector the
    # binding is required and the description is the vetter's words, because a REST
    # API describes nothing; on an MCP connector both are refused with a sentence
    # (`tools.vet_tool`), because there the schema is discovered and the description
    # is copied from the advertisement.
    binding: RestBindingSpec | None = None
    description: str = ""

    # Which of this tool's arguments the audit log hashes rather than stores — step
    # 045c, and not REST-only: an MCP tool whose argument is somebody's free text has
    # the same problem, and `tools/validation.validate` checks these names against
    # whichever schema the connector kind has. A name the schema does not carry is a
    # **400**, because a redaction that never applies is a record claiming a value is
    # hidden while the append-only log holds it in the clear.
    redact_args: list[str] = Field(default_factory=list)


class VetOutcome(BaseModel):
    """What approving one tool answers: what was recorded, and against what.

    `server` is the label the server gave for itself at the moment of approval — migration
    023's point. It is recorded rather than trusted, and returned so the person who just
    approved something can see what they approved it against.
    """

    local_name: str
    remote_name: str
    effect: str
    identity: str
    resources: list[str] = Field(default_factory=list)
    server: str
    actor: str


class OwnedToken(BaseModel):
    """One API token the caller owns. Step 022b, `GET /me/tokens`.

    **`API_TOKEN_PUBLIC_FIELDS` less `tenant_id`**, which the caller already knows for
    `AdminRecord`'s reason. There is no secret here and there structurally cannot be:
    `find_api_token` is the only storage method that returns the hash, and this route
    does not call it.

    **Revoked and expired rows are included, with the fields that say so.** The listing
    is a record of what exists and what happened to it — `--list-tokens`' rule — and it
    is the *picker* that greys out what cannot be scheduled. A route that filtered them
    would make the one person entitled to the whole answer the one person who cannot see
    it, and would answer "you have no tokens" to somebody who has three dead ones.

    This exists because a schedule fires as a machine and a person may only schedule the
    machines they own, so a browser has to be able to *see* them. It is deliberately
    narrower than the register's `GET /admin/tokens` row, which serves an operations team
    and stays open: since step 044 a session can also mint and revoke its own
    (`POST /me/tokens` and its DELETE), with the machine guard carrying 12b's refusal.

    **`extra="ignore"` is inherited here and it was a bug, which is the opposite of what
    it is on `DoorCallRecord` — step 035c.** That model omits `args` and `credential`
    *deliberately*, and its absences are the redaction. This model omitted
    `acts_as_owner` by oversight: the column has existed since migration 042, both stores
    return it in `API_TOKEN_PUBLIC_FIELDS`, `my_tokens` hands it in with the rest of the
    row — and pydantic dropped it silently for three steps, because a model drops what it
    does not name. So the two cases must not be read as one rule: **a dropped field is a
    policy when the model meant not to declare it and a bug when it meant to**, and
    adding `args` here would be undoing a decision while adding this was fixing one.

    A docstring does not catch the next one. `test_the_token_listing_declares_every_public_field`
    walks the response's keys against `API_TOKEN_PUBLIC_FIELDS`, which is 023b's device
    for `TRIGGER_FIELDS` one table over and the only thing that would have caught this.
    """

    id: str
    name: str
    owner_id: str
    # **No default, and the field the plan wrote as `= False`.** `False` is the honest
    # reading of an old *row* — migration 042 backfills nothing on exactly that basis —
    # but a pydantic default is about a *key missing from a dict*, which is a different
    # fact. Both stores project through `API_TOKEN_PUBLIC_FIELDS` and the contract suite
    # asserts set-equality against it, so the key cannot be absent; a default would be an
    # unreachable standing instruction, and the wrong one. If a store ever stopped
    # returning this column, `= False` would describe every personal token as a service
    # token — a credential carrying its owner's whole access rendered as one holding only
    # its own. That is the reassuring direction, which is why nobody would notice it.
    acts_as_owner: bool
    created_by: str
    created_at: str
    # Three nulls that mean three different things, and a picker branches on all three:
    # never expires, never revoked, never used.
    expires_at: str | None = None
    revoked_at: str | None = None
    revoked_by: str | None = None
    last_used_at: str | None = None


class MintToken(BaseModel):
    """The body of `POST /me/tokens`. Step 044.

    **No `owner` field, and the absence is the design**: the route mints for its caller,
    always. Minting *for someone else* is the CLI's, with an operator at a terminal —
    the browser's shape is self-serve, and a body that could name another owner would be
    the amplification 12b refused, back one field at a time.

    `acts_as_owner` defaults **true** — the opposite of the CLI's default, on purpose.
    The person minting here is connecting their own assistant, and a personal token that
    can run whatever they can run is that shape; a service token that can run nothing
    until someone shares an agent with it is the deliberate, flagged choice.

    `expires_days >= 1` is the CLI's rule verbatim: there is no spelling of "expires
    immediately", and "no expiry" is spelled by omission.
    """

    name: str
    acts_as_owner: bool = True
    expires_days: int | None = Field(default=None, ge=1)


class MintedToken(OwnedToken):
    """What a mint answers: the row, plus **the only copy of the secret**. Step 044.

    `token` is the presented string, and this response is the one place it ever exists —
    `tokens.mint`'s contract, unchanged by having an HTTP caller. The secret-absence
    test family names this field as a deliberate exception, the way the trigger
    create's secret is (023b's register row: *a create route may return the secret
    once*). Everything else is `OwnedToken`, inherited rather than restated, so the row
    a mint shows and the row the listing shows cannot drift apart.
    """

    token: str


class TokenRevoked(BaseModel):
    """What `DELETE /me/tokens/{id}` answers. Step 044.

    `changed` is `MemberOutcome`'s device: the storage call is idempotent, so both a
    revocation and a re-revocation succeed — and "revoked just now" and "was already
    dead" are different facts about the world that a bare 204 would collapse.
    """

    id: str
    revoked_at: str | None = None
    changed: bool


class DoorRefusal(BaseModel):
    """The newest call the door itself refused for one of this agent's tools. Step 074.

    Not an audit row: the door refuses *before* the broker when no granted agent
    provides the tool, or an acting-for claim fails, and writes one `access_denials`
    row instead. `reason` is that row's `required` — `grant` or `acting-for` — and the
    card renders the door's own sentence for each rather than a second opinion. `token`
    is the principal id the refusal was written against, so the person watching can
    tell *my token* from *somebody else's*.
    """

    at: str
    tool: str
    token: str
    reason: str


class DoorActivity(BaseModel):
    """Whether anyone has knocked on this agent through the MCP door. Step 044.

    Two scalars, for the ten minutes after somebody pastes the endpoint into their
    assistant and watches. The count includes denials — a refused call still *arrived*,
    and arrival is the question — and restarts across a rename, because the audit log
    keeps old names on purpose (035i).

    **`last_refusal` (074) is the third.** `calls` counts what reached the broker; a
    call the door turned away at its own threshold is in neither number, and until 070
    the card rendered *nothing tried* and *everything refused* as the same sentence. It
    is always sent when one exists — a refusal newer than `last_call_at` is news on a
    connected agent too — and the card decides what to say.
    """

    calls: int
    last_call_at: str | None = None
    last_refusal: DoorRefusal | None = None


class ReachableAgent(BaseModel):
    """One agent a token is granted, in the shape a permission is read in. Step 035d.

    **`Reach.tsx`'s `Reachable` over the wire**, deliberately: that component is what
    the agent detail page and the create wizard both render a permission model with, and
    a token's reach rendering through anything else would be a second description of the
    only thing in this system that decides what an agent may do. So the field names are
    its field names, and the browser type satisfies it structurally rather than by
    importing anything.

    **What this drops is a policy, not an oversight, and 035c is why the difference has
    to be written down.** The dict this is built from is `agents.get`'s — the whole
    stored config — so `system`, `runtime`, `limits`, `model`, `output` and whatever a
    config grows next are all present and all discarded here. That is `DoorCallRecord`
    omitting `args`, not `OwnedToken` omitting `acts_as_owner`: this answers *what may
    this credential call*, and re-sending an agent's instructions to explain a permission
    would be a different route's job done badly.

    The boundary that is asserted is therefore `AgentPermissions`, not the config —
    `tools` and `scope` are the permission model, both are declared, and a field added
    to `AgentPermissions` and forgotten here is a failing test rather than a capability
    that silently stops being described.
    """

    # **No defaults on any of these, and it is 035c decision 1 applied to a second
    # model.** A pydantic default is about *a key missing from the dict a model is built
    # from*, and `door.reach` supplies all three keys unconditionally — so a default here
    # is an unreachable standing instruction, and it makes the OpenAPI document say these
    # fields are optional. A generated client would then type a token's granted tools as
    # possibly-absent, which is the reassuring direction and the wrong one: *this agent
    # reaches nothing* and *the server did not say* are different answers, and only one of
    # them is ever true here. Caught by the edge pass reading `required` in the OpenAPI
    # document, having been written the other way in the very chunk that cited the rule.
    name: str
    tools: list[str]
    # {resource_type: {effect: [patterns]}} — `AgentPermissions.scope`'s own shape, typed
    # all the way down for its reason rather than left as `dict`.
    scope: dict[str, dict[str, list[str]]]


class ToolReachGrant(BaseModel):
    """One agent's contribution to a tool's reach — see `ToolReach`."""

    agent: str
    # resource type -> the patterns granted at this tool's effect.
    applies: dict[str, list[str]]


class ToolReach(BaseModel):
    """One granted tool, with every agent that carries it. Step 069's reflect half.

    **`agents` transposed**, and it is a third view rather than a replacement: *what did
    I grant* and *what does this compose to* are different questions, and 035d's is still
    asked. What that shape cannot answer is the one people arrive with, which is about a
    tool — under 033b's union rule a token holds the union of its agents' tools with each
    tool keeping its own agent's scope, so three grants is a cross-reference exercise
    handed to whoever suspects the token is over-broad.

    `applies` is not an agent's whole scope map. It is the patterns that *can decide* this
    call: the tool's effect and its declared resource types select them, so a reader sees
    the three strings that matter. Keyed by resource type, values are the patterns granted
    at this tool's effect — empty when that agent has no grant for the type, which is the
    shape of a refusal waiting to happen and worth showing as one.

    `granted_by` is in the door's own `_candidates` order — sorted by name — and that
    order is the whole of what can be said about attribution here. **There is no
    `attributed_to`**: the union rule is *first **allow** wins*, so which agent an audit
    record names depends on the call's arguments, and a static field claiming one would
    be wrong in precisely the multi-grant case this view exists for. The first of
    `granted_by` whose scope admits the arguments is the one; `Simulation` answers it for
    a given call.

    `effect` is null and `resource_types` empty when nothing describes the tool — a name
    granted by a live agent that is not vetted, or not vetted any more. Shown rather than
    dropped, on `invalid_agents`' precedent: dropping it makes the token look narrower
    than it is, which is the wrong direction to be wrong in.

    **Computed by the server**, though the browser holds every input. Doing it in
    TypeScript would be the union rule implemented a second time, in a second language,
    by the surface whose whole job is to explain it.
    """

    tool: str
    effect: str | None
    resource_types: list[str]
    granted_by: list[ToolReachGrant]


class TokenReach(BaseModel):
    """What a token is granted, as `GET /me/tokens/{id}/reach` answers it. Step 035d.

    **A list of reaches rather than one of them**, which is a deviation from plan 035 and
    the whole shape of this response. `door.reach`'s docstring carries the argument: the
    tool *names* are the union and are statically answerable, and the *scope* is not —
    one tool can be granted by several agents at different bounds, and which one applies
    is decided per call against the call's own arguments. Flattening that would either
    union the scopes (inventing a permission nobody wrote down) or pick one (refusing
    calls the caller is plainly granted), and the door's own header names both as making
    decision 2 false.

    `tools` is the union and it is **the server's**. A client could compute it from
    `agents` with a `flatMap`, and that is exactly what it must not do: `tools/list`
    comes from `_granted_tool_names`, this comes from `_granted_tool_names`, and a third
    implementation in a browser is 021's `role_of` defect at a new address. It is also
    the one field directly comparable to what an MCP client actually receives, which is
    what `e2e_mcp_door.py` asserts equality on.

    `resolved_as` is `kind:id` — `Me.principal`'s spelling and the audit log's — because
    for a **personal** token the grants that answered are somebody else's, and *which*
    person is the sentence an offboarding review came for. `acts_as_owner` rides beside
    it as the reason it says what it says, and not as a second copy of the listing.

    `invalid_agents` names what `_granted_agents` skipped. The door is silent about those
    on purpose — one broken agent must not remove every other agent's tools from a
    client's list — but silence on a page whose question is *how many agents does this
    reach* is an absence that reads as a fact.

    **Nothing here says whether the credential still works**, and that is decided in the
    route rather than left ambiguous: reach follows the grant, and liveness is the
    listing's four stamps.
    """

    token_id: str
    acts_as_owner: bool
    resolved_as: str
    # Required, all three — `ReachableAgent`'s reason, and the same one that made
    # `OwnedToken.acts_as_owner` required in 035c: the keys cannot be absent, so a
    # default describes a state that cannot arise and weakens the contract for every
    # client generated from it. An empty list is a real and meaningful answer here
    # (*granted nothing*), which is exactly why it must be **sent** rather than defaulted.
    tools: list[str]
    agents: list[ReachableAgent]
    by_tool: list[ToolReach]
    invalid_agents: list[str]


class SimulationRequest(BaseModel):
    """The call to ask about — `POST /me/tokens/{id}/simulate`. Step 069.

    **`POST` for the body, and not because anything moves.** `arguments` is a dict and a
    query string carries one badly; the route's writes are none, which the step's own
    argument turns into a property rather than a claim.

    `arguments` is only ever read by `permissions.check`, which looks at the arguments a
    tool declares as resources and at `RESERVED_KWARGS`. Everything else in it is
    ignored, so a form asking for the *resource* arguments alone is asking for exactly
    what decides — and is the only form buildable anyway, since `describe` has no input
    schema to render.

    There is deliberately **no `acting_for`**. Acting-for decides whose credential a call
    goes out under and whose name is in the record; it does not decide whether the call
    is permitted (`broker.call` checks `ctx.principal`, which is the machine token in both
    cases). Taking the field would imply an effect it does not have.

    `extra="forbid"`, matching every other body in this file, and the edge pass is what
    made it load-bearing rather than conventional. **`acting_for` is the field a caller
    will try**, precisely because a door call takes one — and ignored rather than refused,
    it produces a verdict that silently did not consider the thing the caller thought they
    were asking about. That is `access/acting.py`'s own rule at a second address: *a
    typo'd `emial` must fail here, never quietly become a call with no acting-for.*

    `arguments` keeps its default because an absent key is a real state — *a call with no
    arguments* — which is the case a default is actually for. The bound on its **size** is
    the route's, not this model's: it is measured against the serialized form, which is a
    fact about the wire.
    """

    model_config = ConfigDict(extra="forbid")

    tool: str
    arguments: dict = Field(default_factory=dict)


class ConsideredAgent(BaseModel):
    """What one granted agent said about the call — see `Simulation`."""

    agent: str
    allowed: bool
    # One of `core.permissions.RULES`, or "" on an allow. A name rather than a sentence
    # because a caller switching on prose is a caller re-deciding permission by parsing.
    rule: str
    reason: str


class Simulation(BaseModel):
    """Whether a call would be admitted, and which rule decided. Step 069.

    **`considered` is the deliverable, not `verdict`.** A boolean is what somebody could
    have got by making the call; what they could not get, and what 033b's union rule makes
    genuinely hard, is *all three of my agents said no and here is each one's reason*.
    Read the other way when one allows, it is what turns *it works, somehow* into *it
    works because `triage` grants `acme/*`*.

    `verdict`, `rule` and `reason` are the chosen candidate's — first allow wins, and
    otherwise `candidates[0]`, which is `call_tool`'s own fallback and its own
    attribution. So `attributed_to` names the agent a real call's audit record would name.

    `not_checked` is the honest half. This answers the permission question and stops:
    `authentication` (a revoked or expired token still answers, on 035d's argument — the
    listing's four stamps are the other fact), `binding` (whether the connector answers),
    `acting-for` (whether a call on somebody else's behalf could name them — a gate that
    runs before the union rule and can refuse on its own), `credential` (never resolved)
    and `budget` (`/budget` has answered that since 035e, and folding a counter that
    moves every call into a verdict would make the verdict expire while it was being
    read). Five keys, in the order `door.simulate` emits them; a client renders an
    unknown one as itself rather than dropping it.

    When nothing granted carries the name, `considered` is empty and `reason` is the
    door's own `DoorRefused` sentence, verbatim. That sentence deliberately does not
    distinguish *not granted* from *no such tool*, and rewording it here to be more
    helpful is exactly what would open the oracle 026 closed.
    """

    tool: str
    # "allowed" | "refused". A string rather than a bool because the wire is read by
    # people as well as by code, and because a third outcome — *cannot answer* — is the
    # kind of thing a later step adds, where widening a bool is a breaking change.
    verdict: str
    attributed_to: str | None
    rule: str
    reason: str
    considered: list[ConsideredAgent]
    not_checked: list[str]


class SpentWindow(BaseModel):
    """One window of a token's door spending. Step 035e.

    `window_start` is an ISO date — the UTC day, migration 040's `DATE` column, as a
    string like every other stamp on this wire. `calls` is what was **admitted** in it.

    A window with no row in `mcp_budget` still appears here with `calls: 0`, filled by
    the route. That is not the server inventing a row: *0 when there is no row* is
    `mcp_calls_spent`'s own documented contract, so the fill applies a rule that already
    has a home. The alternative — a sparse list — makes a browser guess whether a gap is
    *no calls* or *no answer*, and a series drawn from it silently redraws a quiet
    Tuesday as though Tuesday had not happened.
    """

    window_start: str
    calls: int


class TokenSpend(BaseModel):
    """What a token has spent through the MCP door, as `GET /me/tokens/{id}/budget`
    answers it. Step 035e.

    **Deliberately not named `TokenBudget`.** `door.TokenBudget` is the thing that
    *enforces* this, `core.limits.Budget` is a per-run counter that has nothing to do
    with either, and a third `Budget` in this file would make every grep for the enforcer
    return a response model. The route keeps the word — `/budget` is the table
    (`mcp_budget`) and the dial (`CARNET_MCP_CALLS_PER_DAY`), and the URL is what
    somebody pastes into a channel — and the model takes the unambiguous one.

    ## `calls` is admitted, not attempted, and the label is load-bearing

    Migration 040's own DDL comment: *"**Admitted, not attempted.** A call refused by the
    permission check never reaches the budget"* — and `spend_mcp_call` writes nothing
    when the ceiling is already met, so a call refused *by this ceiling* does not
    increment either. A token being denied five hundred times a day therefore appears
    here as whatever it **succeeded** at, which is the opposite of what somebody
    investigating an incident is looking for. The other half is already built and lives
    at two addresses: `GET /admin/door-calls` (035a) is every call the broker saw, allow
    and deny, and `GET /admin/denials` (035b) is the refusals that reached no broker.

    ## `ceiling` is a fact about the process, not about the row

    Every other field here comes from `mcp_budget`. This one is `config.MCP_CALLS_PER_DAY`
    on whichever replica answered — read per request and never captured, matching
    `TokenBudget`, which reads the dial per call so an operator can turn it mid-incident.
    Two replicas started with different values would answer differently about the same
    token and agree exactly about the count. Stated because it is the one field a reader
    could reasonably assume was stored.

    No `remaining`. It is `max(ceiling - calls, 0)`, it means nothing when `metered` is
    false, and a third number that has to stay consistent with two others is a third
    thing that can drift apart from them.

    ## `metered` is the field that says whether the figure means anything

    `TokenBudget.reserve` returns ALLOW **before touching storage** when the ceiling is
    not positive — an operator's explicit decision to run unmetered, and *"rows nobody
    will read are not a record"*. So on such a deployment a token with heavy real traffic
    has **no rows at all**, and `calls: 0` means *nothing was counted* rather than
    *nothing happened*. Those are different answers and only a client that is told which
    one it has can render them differently.

    Computed through `TokenBudget.metered` rather than compared here, because the
    comparison is `<= 0` and not `== 0`.

    Note what stays true when the dial is turned off: nothing is deleted. A deployment
    that ran metered until Tuesday keeps Monday's rows, so `history` can be genuinely
    non-empty while `metered` is false — the table is honest and this flag is what says
    whether *today's* entry in it is a measurement.
    """

    token_id: str
    # The UTC day this deployment says is now, from `door.budget_window()` — the same
    # function `TokenBudget` freezes at construction, so the screen and the door cannot
    # disagree about which day a call is charged to.
    window: str
    calls: int
    ceiling: int
    metered: bool
    # --- what the day cost, step 045b ---------------------------------------------
    #
    # Six fields rather than two, because this route's own rule is that **a number
    # without its limit is not an answer** — it is why `ceiling` and `metered` sit beside
    # `calls` above, and the new numbers get the same treatment or they are decoration.
    #
    # **The subject changes here, and that is the one thing a reader must not miss.**
    # Everything above is about the *token*: `mcp_budget` keys on it, and a second token
    # gets a second call allowance. Money keys on the **principal** — the person or
    # service that holds the token — so `usd` is what its owner spent through the door
    # today across every token they hold, and minting another one does not buy another
    # budget. Two subjects on one page is a real hazard; the field names carry no
    # disambiguating suffix because the alternative (`principal_usd`) reads as though the
    # calls were somehow not somebody's. The screen says it in words instead.
    #
    # `usd_metered` and `tokens_metered` are separate flags, not one: the two dials are
    # independent, and a deployment that bounds tokens without pricing anything (which is
    # every deployment brokering a provider `core/usage.RATES` has never heard of) has an
    # honest 0 under a live token ceiling. A single flag would have to lie about one of
    # them.
    #
    # `unpriced_models` is what makes `usd` readable rather than merely small: a figure
    # that excludes two of the three models in play is short, and a client that cannot
    # tell short from cheap will present it as whole. `cost_of`'s honesty, on the wire.
    usd: float
    usd_ceiling: float
    usd_metered: bool
    tokens: int
    tokens_ceiling: int
    tokens_metered: bool
    unpriced_models: list[str]
    # Oldest first, dense, ending at `window`. Required like the rest — the route
    # supplies every key unconditionally, so a `default_factory` would describe a state
    # that cannot arise and would type a generated client's history as possibly-absent.
    # 035c's rule, which 035d broke on five fields and its edge pass caught in the
    # OpenAPI `required` set.
    history: list[SpentWindow]


# --- the overview ------------------------------------------------------------------
#
# Step 041, `GET /admin/overview`. Eleven series in one response, because the page is the
# unit: it loads once, renders once and has one loading state, and eleven routes would
# buy nothing but the chance for two of them to straddle a write and disagree about what
# happened. Composable query parameters would be a BI tool, which is out of scope by
# name.
#
# **Every series here is dense**, and the fill happens in the route rather than in either
# store — `mcp_call_windows`' precedent, and its reason transfers exactly: a store that
# filled its own gaps would be kinder than Postgres, and a *sparse* list handed to a page
# makes the page guess whether a gap is *no calls* or *no answer*, which are different.
#
# The ordering of the fields below is the ordering of the page, and that is deliberate:
# the door first, because it is the product; refusals and administrative change after,
# because they are the governance question. See `docs/PREMISE.md`.


class OverviewWindow(BaseModel):
    """Which days the figures below cover, echoed back rather than assumed.

    `clamped` says the server chose a different window than the one asked for. A caller
    that requested 365 days and silently received 90 would draw a quarter and label it a
    year; a flag is the cheapest thing that cannot be misread, and it is why the clamp is
    not a 400 — a dashboard that refuses to load because somebody typed a big number in a
    URL is worse than one that loads the largest honest answer and says so.

    Days are **UTC**, matching `door.budget_window()`, so this page and the ceiling it
    draws cannot disagree about which day is today.
    """

    days: int
    since: str
    until: str
    clamped: bool
    # `"day"` or `"hour"`. Step 066, and it is a flag beside the series rather than a
    # rename of their key.
    #
    # The 24-hour window buckets by the hour, because a day's live traffic drawn as one
    # column against a backdated month is an eleven-pixel sliver — the failure that made
    # a working demo look broken on 2026-08-31, and one no rescaling of a thirty-day
    # chart can fix. Every other window buckets by the day, as before.
    #
    # **The series keep the field name `day`** whatever this says, and the label format
    # is what changes: `YYYY-MM-DD` or `YYYY-MM-DDTHH`. Renaming a field on seven series
    # to buy a better noun would cost every reader of this response; a client that wants
    # to format an axis reads this instead. The two spellings are told apart by length in
    # any case, so a client that ignored this field would still render.
    bucket: str = "day"


class DoorDay(BaseModel):
    """One day of MCP door traffic — the product's usage figure.

    `errored` and `oversize` are bands **within** `allowed`, not siblings of it: a call
    that was permitted and then failed is both, and `allowed - errored` would understate
    what the door let through. `denied` is the disjoint one.
    """

    day: str
    allowed: int
    denied: int
    errored: int
    oversize: int
    # The other two outcome bands, step 066a. Migration 004's CHECK has held five values
    # since the table existed and this model carried two of them; `unknown` in particular
    # is a value the schema anticipated and no screen has ever drawn.
    #
    # Bands **within** `allowed` like the two above, and they do not sum to it: an
    # admitted call whose outcome is `''` — nothing recorded — is in none of the four, so
    # `ok` is `outcome = 'ok'` and never "allowed minus the rest". A refusal carries `''`
    # too, which is why the residue is not a synonym for success.
    ok: int = 0
    unknown: int = 0


class DoorSpendDay(BaseModel):
    """What one day's door calls cost. Step 045b, and the first money on this page.

    Beside `DoorDay`'s counts rather than inside it, because the two are measured
    differently and a reader has to be able to see that: `allowed` and `denied` count
    every call, while `usd` and `tokens` count only the calls whose tool **reported**
    what it spent. On a deployment brokering no model calls this series is flat zero
    under a busy `door_calls` chart, and that is the truth rather than a gap.

    `usd` is priced at read time from `core/usage.RATES` (or the operator's
    `CARNET_MODEL_RATES`), never stored — 045's Amendment 3, kept: *"a stored dollar
    figure is a frozen estimate that reads like an invoice"*, and an operator who fixes
    their rate table can reprice this history.

    `unpriced_models` names the models that contributed tokens and no dollars on that
    day. Per day rather than once for the window, because *which* models a tenant could
    not price is a fact that changes as they add connectors, and a single window-wide
    list would hide the day it started.
    """

    day: str
    usd: float
    tokens: int
    unpriced_models: list[str]


class EffectDay(BaseModel):
    """Reads and writes admitted through the door on one day.

    Writes are the number a compliance-minded reader looks for first — it is what
    actually changed something in a system this deployment does not own — which is why
    they are their own series rather than a column in a table somebody has to find.
    """

    day: str
    read: int
    write: int


class IdentityDay(BaseModel):
    """One day's door calls by **what the acting-for claim was worth** — the governance
    chart, and the one this page exists to make legible.

    Three counts, never a total. 033c's rule, restated one layer up from
    `DoorCallRecord`: *"an asserted name is worth exactly what the calling app's honesty
    is worth, and a row that hid the difference would upgrade it."* `verified` is a
    person's own IdP token, forwarded and checked; `asserted` is an application's word,
    believed only where the connector opted in; `none` is nobody named.

    Denials are counted here too, because *what did we refuse, and on whose behalf* is
    the half of this question an incident asks.
    """

    day: str
    verified: int
    asserted: int
    none: int


class LatencyDay(BaseModel):
    """Percentiles for one day, in whole milliseconds, or `null` where nothing was timed.

    **Null rather than zero**, and the distinction is the point: a day of refusals has no
    duration to report, and a zero would draw a chart claiming instant calls on a day
    when nothing ran. It is the same distinction `audit.duration_ms` keeps by being
    nullable — *never ran*, not *ran in no time*.

    `queue_median_ms` is only meaningful for runs — a door call is synchronous and
    queues for nothing — so it is absent on the door's series.
    """

    day: str
    median_ms: int | None
    p95_ms: int | None
    queue_median_ms: int | None = None


class CallerTotals(BaseModel):
    """One caller's totals across the whole window — *who is using this*.

    Window totals rather than a series: somebody who called on three days is one row.

    **This list is the top `storage.LEADERBOARD` callers and no more**, capped in SQL. A
    tenant can have thousands of machines and the figure draws a dozen bars, so shipping
    every row would be an unbounded response to draw a bounded picture. `totals.callers`
    is counted separately and is the real number — never the length of this list.

    **And since 066 the cut is on the wire.** `Overview.caller_tail` says how many rows
    were left out and what they came to, because the old arrangement had the count and
    the list on one screen disagreeing by design with nothing admitting it — which, with
    eighteen tools and a cap of fifteen, put a tool that had just been called on no chart
    at all. The cap is unchanged; what changed is that it says so.

    **The axis is the principal, not the token**, and that is stated rather than
    accidental: `audit` carries no token id, so one person's several personal tokens are
    one caller here. *Which credential is hot* is a different question, it has its own
    screen (`GET /me/tokens/{id}/budget`), and its cross-token form needs an index
    migration 040 declined. For a manager, "who" means the person or the automation,
    which is what this is.
    """

    principal_kind: str
    principal_id: str
    calls: int
    denied: int
    writes: int
    # Distinct tools reached, not a list of them. A count answers *how broad is this
    # caller's reach* on a leaderboard row; the names belong on the token's own page,
    # where `GET /me/tokens/{id}/reach` already gives them with their scopes.
    tools: int
    last_seen: str


class ToolTotals(BaseModel):
    """One tool's totals across the window — *what is actually being called*.

    Capped like `CallerTotals`, and for its reason.

    `effect` is the tool's own, carried so a reader can see at a glance which of the busy
    ones change something. It can be `''` on a tool that was only ever refused, because
    nothing was bound to report an effect.
    """

    tool: str
    effect: str
    calls: int
    denied: int


class LeaderboardTail(BaseModel):
    """What a capped leaderboard left out. Step 066.

    Every ranked list on this page is the top `storage.LEADERBOARD` rows, capped in SQL
    since 041 for a good reason — a tenant can have thousands of callers and the figure
    draws a dozen bars. A walkthrough on 2026-08-31 found the other half of that
    decision: **the cut was silent.** Eighteen tools, a cap of fifteen, and a tool that
    had just been called appeared nowhere with nothing on the page admitting it.

    So the cap stays and stops being silent. `n` is how many rows fell below it, `calls`
    and `denied` are what those rows came to. Together with the matching `*_count` they
    make "top 15 of 18 · 412 more calls in 3 tools" a sentence the page can print.

    `n == 0` when nothing was cut, never `null`, so a client renders "and no more"
    without testing for absence.

    **Computed in the same statement as the list it belongs to.** A tail derived from a
    second query's total can go negative across a write, which is the one arithmetic on
    this page a reader would certainly notice.
    """

    n: int
    calls: int
    denied: int


class AgentTotals(BaseModel):
    """One **permission list**'s totals across the window. Step 066a.

    `CLAUDE.md`'s first thing-not-to-get-wrong: an agent in Carnet is a named set of
    tools with a scope, read by `door._granted_agents` on every single call — it *is* the
    permission model. Every `audit` row has carried the column since migration 004, and
    until this the product's own dashboard grouped by it nowhere.

    The name is **as it was spelled when the row was written**, which is
    `door_call_summary`'s rule: the audit log keeps old names on purpose (035i), so a
    renamed agent's history stays under the name that was in force rather than being
    rewritten to match the present.
    """

    agent: str
    calls: int
    denied: int
    # Distinct tools this agent's grant was actually used to reach — the *exercised*
    # breadth, never the granted breadth. An agent carrying forty tools and calling two
    # is a scoping observation, and this is the half of it the log can answer.
    tools: int


class ActingForTotals(BaseModel):
    """Whose name a call went out under, and what that claim was worth. Step 066a.

    The identity chart counts three kinds of claim per day and **names nobody**, which
    leaves *whose authority did this happen on* unanswerable from the page built to
    answer it.

    Keyed on the **pair**, never on the name alone. 033c's rule at one more layer up: an
    asserted name is worth exactly what the calling app's honesty is worth, so one person
    reached once on their own verified token and once on an application's word is two
    rows here. Collapsing them would upgrade the second, in the one record kept to tell
    them apart.

    Rows with no name are absent rather than bucketed: `identity_source='none'` is already
    a band on the chart above, and a `(nobody)` row would top this list on every
    deployment and crowd out what it exists to show.
    """

    acting_for: str
    identity_source: str
    calls: int
    denied: int


class RefusalReason(BaseModel):
    """One refusal sentence and how often it was written. Step 066a.

    The refusal chart says *which control* refused — and recovers three of its five bands
    by matching sentences, because 033b kept one write path and a budget denial is not a
    distinct kind of row. This is the sentences themselves, which is *what the control
    said*, and it is the most directly actionable thing the log holds.

    `reason` is written by this codebase and never by a caller, and `core/audit._redact`
    has been over the record before it is stored. That is the condition under which this
    is safe to render on an admin screen — a condition rather than a property, and one a
    future refusal that interpolated caller text would break.
    """

    reason: str
    count: int


class ToolLatency(BaseModel):
    """How long one tool took, across the window. Step 066a.

    Latency existed per day and only per day, so *which tool is slow* — the first thing
    anybody asks after watching a p95 move — could not be asked here at all.

    Percentiles are `null` where nothing was timed, never 0, which is `LatencyDay`'s rule
    and its reason: a tool that was only ever refused has no duration to report, and a
    zero would claim it was instant.

    Capped like the leaderboards and **without a tail**, which is the one exception. A
    remainder row would have to be a percentile of the tools below the cap, and there is
    no such number — a median of medians is not a median. The cap is stated instead.
    """

    tool: str
    calls: int
    median_ms: int | None
    p95_ms: int | None


class BytesDay(BaseModel):
    """What the door carried back on one day. Step 066a.

    `response_bytes` is on every admitted row and was aggregated nowhere, while
    `oversize` — which this page *does* draw — is its symptom. A day whose oversize count
    rises is a day to read this beside it.

    `p95_bytes` is `null` where nothing was measured, on `LatencyDay`'s rule. `bytes` is
    a sum and is 0 on such a day, because a sum of nothing is nothing while a percentile
    of nothing is not a number.
    """

    day: str
    bytes: int
    p95_bytes: int | None


class HourCell(BaseModel):
    """One weekday-and-hour's calls, across the whole window. Step 066b.

    **Not a series**, and that is what it is for: it answers *when is the door busy*,
    which is a question about the shape of a week rather than about any particular
    Tuesday. It is also the one figure here that survives the failure 066 exists to
    answer — eleven live calls in one hour is a lit cell whether or not the month behind
    it was heavy.

    `weekday` is **0=Monday**. Postgres' `dow` is 0=Sunday and Python's `weekday()` is
    0=Monday, so one store has to convert either way and the wire has to pick; Monday,
    because the grid draws a working week and one starting on Sunday reads as
    off-by-one to everybody who goes looking.

    Sparse: an hour nothing happened in is absent, and the page draws it as an empty cell
    rather than as the bottom of the colour ramp. *Nothing happened* and *the least that
    happened* are different facts — `LatencyDay`'s distinction, in a grid.
    """

    weekday: int
    hour: int
    calls: int


class Headroom(BaseModel):
    """Observed door volume against the configured ceiling — the door's honest cost figure.

    For the door there is no unmeasured spend to account for: a door call is one brokered
    tool call and burns **no model tokens at all**, so *volume against ceilings* is the
    whole of the question.

    **Computed from `audit`, never from `mcp_budget`.** The meter writes nothing when the
    ceiling is not positive — `TokenBudget.reserve` returns ALLOW before touching storage,
    *"rows nobody will read are not a record, and the audit log already says what every
    call did"* — so a deployment that measures without enforcing, which is the ordinary
    shape of a rollout, has heavy real traffic and an empty meter. Sourcing this from the
    log makes the figure independent of the dial.

    `metered` is what says whether `ceiling` means anything. When it is false the page
    prints the volume and says *not enforced*, rather than drawing a gauge against a
    limit that is off — which would be the most confident possible rendering of a number
    nobody is counting.
    """

    metered: bool
    ceiling: int
    # The busiest single day in the window, admitted and refused together: the question
    # is how close traffic came to a per-day limit, and a refused call is traffic that
    # arrived.
    busiest_day_calls: int
    # Days on which something was refused for hitting the ceiling — **not** how many
    # callers were. `audit` carries no per-caller refusal breakdown on this route, and a
    # count of callers derived from "who was denied anything" would silently include
    # every policy refusal. This is the fact in hand and it is the one that says whether
    # the dial is biting.
    days_at_ceiling: int


class RefusalDay(BaseModel):
    """One day's refusals, in **five kinds that are never summed**.

    A single "denials" line tells a manager nothing they can act on, because a spike
    could be any of five unrelated stories and three of them are the system working:

    - `policy` — the broker refused a call. The control doing its job.
    - `ceiling` — a token hit its daily door **call** allowance. A sizing question.
    - `door_spend` — a principal hit its daily **money** allowance at the door. Step
      045b, and its own band rather than part of `ceiling` because *too many calls* and
      *too much money* are answered differently: one is usually a loop or a dial set too
      tight, the other is a real bill arriving.
    - `run_budget` — an agent hit its own `limits` block. A configuration question.
    - `access` — a person or machine was refused a resource before any broker was
      reached. `access_denials`, a genuinely different table.

    The middle three are recovered by matching the sentences the code wrote, because a
    budget refusal is not a distinct kind of audit row — 033b kept one write path on
    purpose. See `storage.BUDGET_REFUSAL_MARKER`.
    """

    day: str
    policy: int
    ceiling: int
    door_spend: int
    run_budget: int
    access: int


class AdminDay(BaseModel):
    """One family of administrative change on one day — *who changed who may do what*.

    The family is the action's prefix before the first dot, so `grant.create` and
    `grant.revoke` are both `grant`. Derived rather than maintained: the 45-action
    vocabulary is already dotted, so a new action joins an existing family for free and a
    genuinely new family appears without anyone updating a list that would otherwise drop
    it in silence.
    """

    day: str
    family: str
    count: int


class OverviewTotals(BaseModel):
    """The tile row: the window's sums, so a screenshot of the top of the page is the
    briefing.

    No success rate and no percentages. A ratio shipped beside its own numerator and
    denominator is a third number that can drift from the two it came from; the page
    computes what it wants to show from these.
    """

    door_calls: int
    door_denied: int
    door_writes: int
    door_verified: int
    # **Every distinct caller, not the length of the leaderboard.** Its own count in the
    # store, because the list beside it is the top N and a tile derived from that length
    # would report the cap as the answer.
    callers: int
    refusals: int
    admin_changes: int
    # What the door cost over the window. Step 045b, and the first dollar on this page.
    #
    # **The window's sum of `door_spend`, not a re-price of the whole window at once**,
    # because the daily series is already priced per model bucket and summing the days is
    # the only way the tile and the chart agree. Priced at read time, never stored.
    #
    # `door_usd` is short by whatever `door_unpriced_models` names — a total that excluded
    # two of three models in play and said nothing would be the wrong number on the one
    # screen built to be trusted at a glance.
    door_usd: float
    door_tokens: int
    door_unpriced_models: list[str]


class Overview(BaseModel):
    """`GET /admin/overview` — the fleet's window, in one response. Step 041."""

    window: OverviewWindow
    totals: OverviewTotals
    # The same-length window immediately before this one, as totals alone. Step 066a.
    #
    # **A denominator, not a second dataset.** "4,120 calls" is a number nobody can size
    # without knowing what last month was; "4,120, up 18%" is a fact. One extra pass over
    # a window already bounded buys that for every tile on the page.
    #
    # Totals only, and never a second set of series: a page that drew both windows would
    # be a comparison tool, and this is a record. `null` where there is no preceding
    # window to read — a deployment younger than its own window has no comparison, and a
    # confident `0%` there would be the most misleading possible rendering of *we have
    # not been running long enough to say*.
    previous: OverviewTotals | None = None

    # The door — the product.
    door_calls: list[DoorDay]
    # 045b. Beside the counts rather than inside them: a call is counted whatever it was,
    # and only a call whose tool reported usage contributes here.
    door_spend: list[DoorSpendDay]
    door_effects: list[EffectDay]
    identity: list[IdentityDay]
    door_latency: list[LatencyDay]
    # 066a. Beside the latency rather than on it: two measures of different scale are two
    # figures, and this response has never carried a second y-axis for anybody to draw.
    door_bytes: list[BytesDay] = Field(default_factory=list)
    callers: list[CallerTotals]
    door_tools: list[ToolTotals]

    # 066. Every capped list's true size and what it left out. Beside the lists rather
    # than inside them, because a tail is a fact about the *query* and a row is a fact
    # about a caller — folding a sixteenth synthetic row into `callers` would put
    # something that is not a caller in a list of callers, which is the vocabulary
    # mistake this codebase refuses everywhere else.
    caller_tail: LeaderboardTail = Field(
        default_factory=lambda: LeaderboardTail(n=0, calls=0, denied=0)
    )
    tool_count: int = 0
    tool_tail: LeaderboardTail = Field(
        default_factory=lambda: LeaderboardTail(n=0, calls=0, denied=0)
    )

    # 066a. The three dimensions every audit row carried and no figure grouped by.
    door_agents: list[AgentTotals] = Field(default_factory=list)
    agent_count: int = 0
    agent_tail: LeaderboardTail = Field(
        default_factory=lambda: LeaderboardTail(n=0, calls=0, denied=0)
    )
    acting_for: list[ActingForTotals] = Field(default_factory=list)
    acting_for_count: int = 0
    acting_for_tail: LeaderboardTail = Field(
        default_factory=lambda: LeaderboardTail(n=0, calls=0, denied=0)
    )
    refusal_reasons: list[RefusalReason] = Field(default_factory=list)
    refusal_reason_count: int = 0
    refusal_reason_tail: LeaderboardTail = Field(
        default_factory=lambda: LeaderboardTail(n=0, calls=0, denied=0)
    )
    tool_latency: list[ToolLatency] = Field(default_factory=list)
    # 066b. Window-wide, never a series — see `HourCell`.
    hourly: list[HourCell] = Field(default_factory=list)

    headroom: Headroom

    # Refusals and change.
    refusals: list[RefusalDay]
    admin_actions: list[AdminDay]


class Ready(BaseModel):
    """The readiness probe's 200 (step 056). The 503 half is a plain `detail`
    sentence, like every refusal this API writes — no model needed for it."""

    status: Literal["ready"]
    # Which ground the round trip touched. "memory" is an honest answer for a trial
    # and an alarming one for a deployment, which is exactly why it is said.
    storage: Literal["postgres", "memory"]


class Health(BaseModel):
    status: Literal["ok"]
    storage: Literal["configured", "unconfigured"]
    # The **application** version, not the schema version. Answering "what are you
    # running" is the whole reason this field exists, and a deployment nobody can shell
    # into has no other way to say it.
    #
    # The schema version is deliberately absent: reading it means reading
    # `schema_migrations`, and this endpoint's one property is that it answers when
    # storage is broken. `--migrate` and the ledger answer that question instead.
    version: str
