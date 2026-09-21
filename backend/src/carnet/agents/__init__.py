"""Agents — a loader over the storage layer, and the validation that guards it.

An agent config is a plain dict:

    {
        "name": "issue-reporter",   # identity the broker enforces against.
                                    # MUST match the key it is stored under.
        "permissions": {
            "tools": [...],         # capability — what it may call
            "scope": {...},         # reach — what it may touch, per effect
        },
        "model": "claude-sonnet-4-6",   # optional, defaults in config.py
        "max_tokens": 2048,             # optional
        "output": {                     # optional, step 024
            "schema": {...},            # JSON Schema; complete => answer conforms
        },
    }

This used to be a module registry built from imports, with `validate()` running at
import time so a bad grant meant the process refused to start. The configs are now
rows, and that one property could not survive the move unchanged. Where it went:

    WRITE TIME   `save()` validates and refuses. A form user gets exactly the errors
                 the import used to raise — which is the point, because those messages
                 were written to be read by a person, and now that person is the one
                 filling in the form.

    LOAD TIME    still fail-closed, because a row that was valid when written can stop
                 being valid. Delete a connector and every agent granting its tools is
                 now referencing tools that do not exist.

The deliberate change is what a *failure* at load time does:

    before   a bad agent config stops the process from starting
    after    a bad agent raises when someone tries to run it; listing skips it and says
             so; other agents and other tenants are unaffected

"It cannot start broken" is a property of a single-tenant process, and one customer's
bad row must not take the platform down for everyone else. "It cannot *run* broken" is
the property that actually mattered, and it is kept exactly: `get()` raises rather than
returning None, so a broken agent is never silently a missing one.
"""

import logging

import jsonschema

from .. import storage, tools
from ..core import patterns

log = logging.getLogger(__name__)

# Names an agent may not be created with, because the API already answers to them.
#
# One entry, and it is not theoretical for long: `POST /agents/validate` arrives in this
# step, and FastAPI matches a literal path segment before a parameterised one — so an
# agent called `validate` would be created happily and then be the one agent whose detail
# URL some future `GET /agents/validate` shadows. Three lines now, an unpickable name and
# a migration later.
#
# This is a fact about the URL namespace rather than about an agent, which is why it is
# here rather than in migration 019's CHECK: a database that knew it would have to be
# migrated every time a route was renamed.
#
# **`new` joined it in step 025, and it was missing rather than excluded.** The browser
# routes `/agents/new` before `/agents/:name` and says so in a comment — react-router
# would otherwise match an agent called `new` — so the client has reserved this name since
# 10c and the server never did. An agent called `new` could therefore be created by curl
# and was then unreachable in the browser: its detail page was the create wizard. Exactly
# `validate`'s shape, one client over, found by the survey that went looking for what else
# treats a name as an address.
RESERVED_AGENT_NAMES = frozenset({"validate", "new"})


# The limit keys an agent config's `limits` block may set. **The vocabulary, and nothing
# else** — `validate` below refuses any other key against it.
#
# **Here since step 084, and it came up a layer rather than being deleted.** It lived in
# `core/limits.py` as `LIMIT_DEFAULTS`, a dict mapping each key to the `config` attribute
# that supplied its default when an agent set no value. Those values had exactly one
# reader, `Budget.for_agent`, and 084 deleted `Budget` — correct code whose only caller,
# `RunContext.start`, had no caller of its own, which is how `max_writes: 0` came to
# refuse nothing (step 081).
#
# The keys are a different thing and they survive that deletion untouched: they are a
# **write-time contract**, reached by `POST /agents`, `PATCH /agents/{name}`,
# `POST /agents/validate`, `--seed` and every load. A typo'd limit key would silently
# leave that dial on nothing while the agent read as capped in review — and that is worse
# now than it was when something enforced the block, not better: a config key nobody can
# spell correctly is a config key nobody can read back either, and reading it back is the
# whole of what a stored `limits` block is for here (see the agent page's *Stored, and
# not read here*).
#
# So the vocabulary stays, and moves to its one reader. That is also where it should
# always have been: `core/` **knows no tool and no agent**, and a constant whose docstring
# began *"Keys an agent config may set"* was a fact about an agent config held one layer
# too far down. `agents/` imports downward, so the old arrangement was legal; it was still
# pointing the wrong way, and with `Budget` gone there was nothing left down there to
# point at.
#
# A frozenset rather than a dict, because there are no longer two halves to it. `sorted()`
# over it produces exactly the list `sorted(LIMIT_DEFAULTS)` produced, so the refusal below
# is the same sentence, word for word, that every caller has read since step 010.
KNOWN_LIMITS = frozenset(
    {"max_calls", "max_calls_per_tool", "max_writes", "max_response_bytes"}
)


class InvalidAgentError(RuntimeError):
    """A stored agent config that would be unsafe or meaningless to run.

    A RuntimeError subclass so the messages and the failure mode are exactly what
    import-time validation raised; a distinct type so `names()` can skip a broken row
    without swallowing unrelated failures.
    """


def validate(tenant_id: str, agent: dict) -> None:
    """Check one agent config. Raises on anything that would fail open or fail
    confusingly at 3am rather than loudly at the moment it is written.

    `tenant_id` decides which tool names count as known — connectors are a tenant's
    own vetting decision, so the same config can be valid for one customer and a
    dangling reference for another.
    """
    name = agent.get("name", "<unnamed>")
    permissions = agent.get("permissions", {})

    # The shape from migration 019, translated into this module's exception so a form
    # user reads it beside the scope errors rather than getting a 503. Checked here
    # rather than only at the write, because `POST /agents/validate` runs this function
    # and a dry run that passes a name the create will refuse is a dry run that has
    # failed at the one job it exists for.
    #
    # It runs at *load* too, which is deliberate and is why the rule is worth having at
    # all: a stored name that is not a slug is a row that its URL and its audit records
    # disagree about. Nothing in any database can be in that state — 019 validated
    # against existing rows — so this cannot make a live agent unloadable today.
    try:
        storage.check_agent_name(agent.get("name"))
    except storage.StorageError as exc:
        raise InvalidAgentError(str(exc)) from exc

    # The old shape was {tool: {arg: {"allow": [...]}}}. Treating an unmigrated
    # config as "no tools granted" would be safe but baffling; say so instead.
    if "tools" not in permissions:
        raise InvalidAgentError(
            f"agent '{name}' has no 'tools' list in its permissions. Grants are now "
            "{'tools': [...], 'scope': {resource_type: {effect: [patterns]}}} — see "
            "core/permissions.py."
        )

    if not isinstance(permissions["tools"], list):
        raise InvalidAgentError(f"agent '{name}': permissions['tools'] must be a list")

    # A typo'd tool name is a grant that silently never applies. Checked against every
    # name this tenant knows, not just the bound ones — a vetted connector tool is
    # legitimate before anyone has connected to its server.
    known = tools.known_names(tenant_id)
    for tool_name in permissions["tools"]:
        if tool_name not in known:
            raise InvalidAgentError(
                f"agent '{name}' is granted '{tool_name}', which is not a registered "
                f"tool. Known tools: {', '.join(sorted(known))}"
            )

    # A typo'd limit key would store a ceiling nobody can read back — the agent would
    # look capped in review and would not be. See `KNOWN_LIMITS`.
    for key, value in agent.get("limits", {}).items():
        if key not in KNOWN_LIMITS:
            raise InvalidAgentError(
                f"agent '{name}' sets unknown limit '{key}'. "
                f"Known limits: {', '.join(sorted(KNOWN_LIMITS))}"
            )
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise InvalidAgentError(
                f"agent '{name}': limit '{key}' must be a non-negative integer, "
                f"got {value!r}. (0 is valid — e.g. max_writes: 0 for a read-only agent.)"
            )

    # Step 014, decision 8. A boolean and nothing else: truthy strings here would make
    # `"false"` private, which is a config that reads as open and is not.
    private = agent.get("private_runs")
    if private is not None and not isinstance(private, bool):
        raise InvalidAgentError(
            f"agent '{name}': private_runs must be true or false, got {private!r}. "
            "True makes every run of this agent visible only to whoever ran it."
        )

    # Step 024. Checked here — before a row exists — so the form, PATCH,
    # `POST /agents/validate` and `--seed` all refuse a bad schema with the same
    # sentences. `"output" in agent` rather than `agent.get`, because an explicit null
    # and an absent key must be told apart: absent is today's prose behaviour, null is
    # a key that means nothing and is refused as such.
    if "output" in agent:
        _validate_output_section(name, agent["output"])

    scope = permissions.get("scope", {})
    for resource_type, by_effect in scope.items():
        for effect, grants in by_effect.items():
            if effect not in {"read", "write"}:
                raise InvalidAgentError(
                    f"agent '{name}': scope['{resource_type}'] uses effect "
                    f"'{effect}'; expected 'read' or 'write'"
                )
            for pattern in grants:
                try:
                    patterns.validate(pattern)
                except patterns.PatternError as exc:
                    raise InvalidAgentError(
                        f"agent '{name}': bad pattern in scope['{resource_type}']"
                        f"['{effect}'] — {exc}"
                    ) from exc

    _validate_scope_matches_tools(tenant_id, name, permissions["tools"], scope)


def _validate_scope_matches_tools(tenant_id, name: str, granted_tools, scope: dict) -> None:
    """Cross-check reach against capability. Both directions are config errors.

    Resource types are bare strings with no registry, so `github.repo` misspelled as
    `github.repos` is a grant that can never match — deny-everything, which is safe
    and completely baffling. One connector made that unlikely; four make it certain,
    which is why this exists now rather than after the first incident.
    """
    needed = set()
    for tool_name in granted_tools:
        needed |= tools.resource_types_for(tool_name, tenant_id)

    granted = {
        (resource_type, effect)
        for resource_type, by_effect in scope.items()
        for effect in by_effect
    }

    # A tool whose resource type has no grant at its effect can never make a call
    # that isn't denied. The agent reads as capable and isn't.
    unusable = needed - granted
    if unusable:
        rows = ", ".join(f"{t} ({e})" for t, e in sorted(unusable))
        raise InvalidAgentError(
            f"agent '{name}' is granted tools needing {rows}, but its scope has no "
            "such grant. Every call to them would be denied."
        )

    # A grant no granted tool can use is either a leftover or a typo. Harmless at
    # runtime, but it is the half of a misspelling that is actually visible.
    unused = granted - needed
    if unused:
        rows = ", ".join(f"{t} ({e})" for t, e in sorted(unused))
        raise InvalidAgentError(
            f"agent '{name}' scopes {rows}, which none of its granted tools touch. "
            "Either a tool is missing from the grant, or the resource type is a typo."
        )


def _validate_output_section(name: str, output) -> None:
    """The `output` config section: `{"schema": <JSON Schema>}`. Step 024.

    Three rules, each with a person-readable refusal:

      - the section is a dict with exactly the known keys — an unknown key is a
        constraint that silently never applies, the `limits` argument one section over
      - the schema is structurally valid JSON Schema rooted at an object — the model
        API requires the object root, and a consumer of a bare string had no need of
        a schema
      - every object carries `additionalProperties: false` — the API's documented hard
        requirement, and this platform's own: a schema that admits unknown keys admits
        answers the consumer's code never handles

    What is deliberately NOT re-implemented: the API's remaining restrictions (no
    recursive schemas, no numeric/string constraints). Those are a moving target, and
    duplicating them is how a validator and its upstream drift into disagreeing about
    what is legal. Plan 024's stated known limit was that a schema passing here and still
    offending the API fails the *run* with the API's own sentence in `error`; **since 081
    there is no run and no completion-time check at all**, so nothing in this tree ever
    reads the schema back. What survives is the refusal above — a stored schema this
    deployment does not enforce is fine, and a stored value that is not a schema is a row
    nobody can explain later.
    """
    if output is None:
        raise InvalidAgentError(
            f"agent '{name}': output is null. A key must mean something — send "
            "{'schema': ...} to constrain the answer. Removing the section entirely "
            "is not expressible over HTTP (a top-level key cannot be deleted by a "
            "merge); use the CLI."
        )
    if not isinstance(output, dict):
        raise InvalidAgentError(
            f"agent '{name}': output must be an object of the form "
            f"{{'schema': ...}}, got {type(output).__name__}."
        )
    unknown = sorted(set(output) - {"schema"})
    if unknown:
        raise InvalidAgentError(
            f"agent '{name}': output has unknown key(s) {', '.join(unknown)}. "
            "The only key is 'schema'."
        )
    if "schema" not in output:
        raise InvalidAgentError(
            f"agent '{name}': output has no 'schema'. The section exists to constrain "
            "the answer, and an empty section constrains nothing — either say what "
            "the answer must look like, or remove the section."
        )

    schema = output["schema"]
    if not isinstance(schema, dict):
        raise InvalidAgentError(
            f"agent '{name}': output.schema must be a JSON Schema object, got "
            f"{type(schema).__name__}."
        )

    # Every check below walks the schema — check_schema against the metaschema, and
    # two recursive scans of our own. A degenerate depth blows any of them up, and a
    # RecursionError escaping this function is a 500 answered to a person who typed a
    # bad config: the wrong refusal family, refused here before this code ships its
    # first copy. (FastAPI's own parser accepts bodies far deeper than Python's
    # recursion limit, so this is reachable from a PATCH, not just from code.)
    try:
        try:
            jsonschema.Draft202012Validator.check_schema(schema)
        except jsonschema.SchemaError as exc:
            raise InvalidAgentError(
                f"agent '{name}': output.schema is not a valid JSON Schema — "
                f"{exc.message}"
            ) from exc
        if schema.get("type") != "object":
            raise InvalidAgentError(
                f"agent '{name}': output.schema must be rooted at type 'object'. A "
                "machine consumer reads named fields, and the model API accepts "
                "nothing else at the root."
            )

        # A schema must be self-contained. The platform decides conformance at every
        # completion, and it will fetch nothing to do so — an outward `$ref` is
        # accepted structurally by check_schema and then fails *every run* of the
        # agent at validation time, which is a config mistake charged to the wrong
        # moment and the wrong party. Refused here, with the fix in the sentence.
        outward = _external_refs(schema)
        if outward:
            raise InvalidAgentError(
                f"agent '{name}': output.schema refers outside itself "
                f"({', '.join(sorted(set(outward)))}). A schema must be "
                "self-contained — nothing is fetched to decide whether an answer "
                "conforms. Inline the definition under $defs and point '#/$defs/...' "
                "at it."
            )

        open_objects = _objects_admitting_unknown_keys(schema)
        if open_objects:
            raise InvalidAgentError(
                f"agent '{name}': every object in output.schema must set "
                f"additionalProperties to false; missing at {', '.join(open_objects)}. "
                "A schema that admits unknown keys admits answers the consumer's code "
                "never handles — and the model API refuses it anyway."
            )
    except RecursionError:
        raise InvalidAgentError(
            f"agent '{name}': output.schema is nested too deeply to be checked, so "
            "no answer could ever be checked against it either. Flatten it — depth "
            "like this is a generator artifact, not a contract."
        ) from None


def _external_refs(schema) -> list[str]:
    """Every `$ref`/`$dynamicRef` target that points outside the schema itself.

    A plain scan over the whole tree rather than the combinator-scoped walk below,
    because a ref anywhere is the hazard: `check_schema` accepts an absolute URI
    happily, and modern jsonschema then raises an *unresolvable* error — not a
    validation verdict — the first time the pointer is followed against an answer.
    """
    found = []

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if (
                    key in ("$ref", "$dynamicRef")
                    and isinstance(value, str)
                    and not value.startswith("#")
                ):
                    found.append(value)
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(schema)
    return found


def _objects_admitting_unknown_keys(schema: dict) -> list[str]:
    """Paths of object schemas that do not close themselves with
    `additionalProperties: false`.

    A short walk over the combinators this platform's schemas can express —
    `properties`, `patternProperties`, `$defs`/`definitions`, `items`, `prefixItems`,
    `anyOf`/`allOf`/`oneOf` — not a full JSON Schema traversal. A node counts as an
    object schema when it declares `type: "object"` (alone or in a type list) or
    carries `properties`.
    """
    found = []

    def walk(node, path):
        if not isinstance(node, dict):
            return
        declared = node.get("type")
        is_object = (
            declared == "object"
            or (isinstance(declared, list) and "object" in declared)
            or "properties" in node
        )
        if is_object and node.get("additionalProperties") is not False:
            found.append(path)
        for key in ("properties", "patternProperties", "$defs", "definitions"):
            members = node.get(key)
            if isinstance(members, dict):
                for sub_name, sub in members.items():
                    walk(sub, f"{path}.{key}.{sub_name}")
        items = node.get("items")
        if isinstance(items, dict):
            walk(items, f"{path}.items")
        for key in ("prefixItems", "anyOf", "allOf", "oneOf"):
            members = node.get(key)
            if isinstance(members, list):
                for index, sub in enumerate(members):
                    walk(sub, f"{path}.{key}[{index}]")

    walk(schema, "$")
    return found


# --- the loader -----------------------------------------------------------------


def validate_draft(tenant_id: str, config: dict) -> None:
    """`validate()`, plus the two rules that apply only to a name nobody has used yet.

    Every stored agent satisfies `validate()`. Not every stored agent satisfies this,
    and that asymmetry is the whole reason it is a second function rather than a flag:

      - **`validate` and `new` are reserved**, because both are URLs — one on this API,
        one in the browser. An agent that was *already* called either must keep working —
        `GET /agents/validate` is a different method on the same path and collides with
        nothing — so this is a rule about taking a name, not about holding one. Refusing
        at load would take a working agent away to close a hole it is not in.

    What this deliberately does **not** check is whether the name is free. That is a
    race whatever answers it, it is a different status code (409, not 422), and the
    store is the only thing that can answer it without lying — so `create()` asks by
    trying, and the caller renders the refusal.

    This is what `POST /agents/validate` runs, so the dry run answers the question the
    wizard is actually asking: *would create accept this?*
    """
    validate(tenant_id, config)

    if config.get("name") in RESERVED_AGENT_NAMES:
        raise InvalidAgentError(
            f"'{config.get('name')}' is reserved and cannot be used as an agent name. "
            "It is already a path on this API, so an agent called that would have a URL "
            "that means two things. Any other name is fine."
        )


def create(tenant_id: str, config: dict, owner_kind: str, owner_id: str) -> None:
    """Validate, then create — **and claim ownership in the same breath**.

    The counterpart to `save()`, and not a replacement for it: `save()` upserts, which
    is right for `--seed` and documented as safe to re-run, and is exactly what a create
    route must not do. See `storage.create_agent`, where both halves of that are argued.

    The two writes are one storage call rather than two from here, because atomicity is
    a storage property and nothing at this altitude can offer it. A create that returned
    successfully having written the agent and not the grant would leave an agent nobody
    can run, including its author — and the row would look perfectly fine.

    Raises `InvalidAgentError` for a config, `AgentNameTaken` for a name that exists.
    """
    validate_draft(tenant_id, config)
    storage.active().create_agent(tenant_id, config, owner_kind, owner_id)


def save(tenant_id: str, config: dict, *, actor: str) -> None:
    """Validate, then store, replacing what was there. The `--seed` path.

    **This is an upsert and must not be reached from a create route.** It has no opinion
    about whether the name was already somebody else's agent, and `validate()` checks
    configs rather than grants, so nothing on this path would refuse replacing one. Use
    `create()`.

    Validation runs *before* the write, so an invalid config never becomes a row.
    That is what keeps load-time failures rare enough to be worth shouting about.

    `actor` has no default and is passed straight through to storage, which writes the
    `agent.save` record. `--seed` passes `storage.SYSTEM_ACTOR`. See `NO_ACTOR` for why
    a default here would be the wrong kindness.
    """
    validate(tenant_id, config)
    storage.active().save_agent(tenant_id, config, actor=actor)


def get(tenant_id: str, name: str) -> dict | None:
    """One agent config, or None if this tenant has no such agent.

    **Raises** if the stored row is invalid. Returning None would turn "this agent is
    broken" into "this agent does not exist", and the two call for completely
    different responses from whoever is looking at it.

    This is the *config*, not the row — `storage.get_agent` returns `AGENT_FIELDS` since
    10d, and almost every caller wants the agent rather than when it was last written.
    The two that want the timestamp are the edit path and the detail route, and both ask
    storage directly.

    **Still raises, and the 422 still exists — it moved.** `GET /agents/{name}` no longer
    calls this, because a broken agent is exactly the agent somebody has come to fix.
    `POST /runs` does, and answers 422 with the same sentence, because *running* it is
    what cannot happen. See decision 4 of 010d.
    """
    row = storage.active().get_agent(tenant_id, name)
    if row is None:
        return None

    validate(tenant_id, row["config"])
    return row["config"]


def identity(tenant_id: str, name: str) -> str | None:
    """This agent's `agent_id`, or None if this tenant has no such agent. Step 025.

    The one reader of migration 035's column above `storage/`, and it exists so that the
    places which have to compare *which agent* — the run's spine, the follow-up turn's
    parent check, run-list visibility — do it on an identity rather than on a label. A name
    comparison is correct until somebody renames an agent, and then it is silently wrong in
    two directions at once: an agent's own history stops matching it, and a re-created name
    inherits its predecessor's.

    Unlike `get`, this does **not** validate the config. Asking what an agent's id is must
    not depend on whether its tools are still vetted — a broken agent still has a run
    history, and the whole point of the id is that it is a fact about the row.
    """
    row = storage.active().get_agent(tenant_id, name)
    return None if row is None else row["agent_id"]


def name_for_id(tenant_id: str, agent_id: str) -> str | None:
    """What the agent with this id is called **now**, or None if it is gone. Step 025.

    `identity`'s inverse, and the one direction a stored reference has to travel: a run row
    holds an id and the name it was submitted under, and the second of those is history. See
    `storage.get_agent_by_id`, which explains why anything needs this at all.
    """
    row = storage.active().get_agent_by_id(tenant_id, agent_id)
    return None if row is None else row["name"]


def load(tenant_id: str) -> list[dict]:
    """Every *valid* agent config for this tenant, ordered by name.

    An invalid row is skipped and reported rather than raised, because one broken
    agent must not make a tenant's whole list unreadable. `get()` is where running it
    fails.
    """
    valid = []
    for row in storage.active().load_agents(tenant_id):
        config = row["config"]
        try:
            validate(tenant_id, config)
        except InvalidAgentError as exc:
            # Loud, never silent. A skipped agent that nobody mentions is an agent
            # somebody thinks is running. `warning` rather than `info` for the same
            # reason it was never a quiet print.
            log.warning("skipping invalid config: %s", exc)
            continue
        valid.append(config)
    return valid


def names(tenant_id: str) -> list[str]:
    """Names of this tenant's valid agents."""
    return [config["name"] for config in load(tenant_id)]


class AgentChanged(RuntimeError):
    """Somebody else wrote this agent between the read and the write. A **409**.

    Carries the row as it stands now and the top-level keys this patch disagrees with it
    about, because "somebody else edited this" with nothing further leaves a person to
    diff two configs by eye — and the thing they are trying to work out is whether their
    save would have reverted a scope narrowing.

    `changed` is **the keys this request would write whose stored value is not what the
    sender is sending** — which is what the server can compute, and it is deliberately
    *not* "what the other person did". Nothing here can answer that: the timestamp says
    the row moved, and no history says how. The client holds the version it loaded and
    can therefore work it out by re-reading; see the `Conflict` panel in
    `EditAgentPage.tsx`, which does exactly that.

    **The distinction is worth the two sentences because getting it wrong was a real
    defect, found by looking at the screen.** Two tabs, one narrows the scope, the other
    edits only the instructions — and this reported `["system"]`, which is simply the
    field the second tab was editing. It says nothing about the narrowing, because the
    second tab never sent `permissions`. So the message must not claim the save would
    replace anybody's version: under a top-level merge it might not touch a thing they
    changed. What it truthfully says is that the version this was built on is gone.

    An empty list still means the save was a no-op against the current version.
    """

    def __init__(self, current: dict, patch: dict):
        self.current = current
        self.updated_at = current["updated_at"]
        self.changed = sorted(
            key
            for key, value in patch.items()
            if current["config"].get(key) != value
        )
        super().__init__(
            "somebody else changed this agent while you were editing it, so the version "
            "this was built on is gone"
            + (
                f". Your save would write: {', '.join(self.changed)}. Reload it, see what "
                "changed underneath you, and make the change again."
                if self.changed
                else ". Nothing you were sending differs from what is stored now, so "
                "reloading and saving again changes nothing and is safe."
            )
        )


def merge(current: dict, patch: dict) -> dict:
    """A stored config plus a partial one, merged **at the top level only**.

    This is decision 2 of 010d, and it retires a real finding structurally rather than by
    persuasion. `frontend/src/lib/draft.ts` has `toConfig` and no inverse; the shipped
    `issue-reporter` carries `default_task` and `deny_demo_task`, which no wizard step
    asks about. An edit screen built out of the create form and saving the whole config
    deletes both, and nothing anywhere reports it.

    A key that is **absent** from the patch is untouched. So `default_task` survives
    because the form never sends it, rather than because somebody remembered to carry it.

    **`permissions` is replaced as a unit and never deep-merged.** `tools` and `scope`
    are cross-checked in both directions by `_validate_scope_matches_tools`, so a merge
    that updated one and kept the other is the one way to produce a config the validator
    refuses through a route that looks like it is working.

    The cost, stated because it is real: there is now **no way to remove an optional
    field over HTTP**. Sending `{"limits": {}}` clears the limits, because whole-value
    replacement applies to every top-level key; sending nothing leaves them. Deleting
    `default_task` entirely needs the CLI. Acceptable while nothing in the product
    creates the fields it applies to, and the first thing to revisit if that changes.
    """
    return {**current, **patch}


def update(
    tenant_id: str,
    name: str,
    patch: dict,
    *,
    actor: str,
    if_unchanged_since,
) -> dict | None:
    """Merge a partial config into an agent, if nobody else has written it. The row, or
    None when there is no such agent.

    Raises `InvalidAgentError` for a merged config the validator refuses (a 422), and
    `AgentChanged` when the timestamp did not match (a 409).

    `validate` rather than `validate_draft`: the reserved-name rule is about *taking* a
    name, and a patch cannot change one — see decision 2, and `validate_draft`'s own
    docstring for why refusing at load would take a working agent away.

    The read below is not the race. It builds the merged config and nothing more; the
    guard is `if_unchanged_since` inside one statement in storage, so an edit that lands
    between this read and that write loses rather than being silently overwritten. That
    is the reason the compare-and-set could not live in a route.
    """
    store = storage.active()

    row = store.get_agent(tenant_id, name)
    if row is None:
        return None

    merged = merge(row["config"], patch)
    validate(tenant_id, merged)

    updated = store.update_agent(
        tenant_id, merged, actor=actor, if_unchanged_since=if_unchanged_since
    )
    if updated is not None:
        return updated

    # Nothing moved, and only now is it safe to ask which of the two reasons it was:
    # the write did not happen either way, so a second read is a report rather than a
    # window. An agent deleted underneath the edit is the same None a caller started
    # with, and is the 404 a deleted agent produces everywhere else.
    current = store.get_agent(tenant_id, name)
    if current is None:
        return None
    raise AgentChanged(current, patch)


def rename(tenant_id: str, name: str, new_name: str, *, actor: str) -> dict | None:
    """Change what an agent is called and nothing else. The row, or None if it is gone.

    Raises `InvalidAgentError` for a target the name rules refuse — the slug shape, and
    the reserved names — and `storage.AgentNameTaken` for one that is in use.

    **`check_agent_name` *and* the reserved-name rule, which is the one judgement call
    here.** `validate_draft` exists because taking a name has rules that holding one does
    not, and a rename takes a name: renaming an agent to `validate` would produce exactly
    the shadowed URL that rule was written to prevent, and it would arrive through the one
    path that did not check. So a rename is a *draft-side* operation even though the agent
    already exists.

    What it deliberately does **not** re-run is `validate()` on the whole config. Nothing
    about a rename can make a valid config invalid: the tools, the scope and the output
    section are untouched, and the only key that changes is the one the name rules above
    have just checked. Re-validating would mean a rename could be refused for a tool
    somebody un-vetted last week — turning "change this agent's name" into "and also fix
    everything else about it first", which is the shape of refusal that makes people give
    up and delete the agent instead.

    The config's own `name` moves with the row, in storage, in one statement — see
    `storage.rename_agent`, where migration 002's constraint makes that mandatory rather
    than tidy.
    """
    try:
        storage.check_agent_name(new_name)
    except storage.StorageError as exc:
        raise InvalidAgentError(str(exc)) from exc

    # **Raised here rather than left to storage, and that is a refusal-family fix.**
    # `storage.rename_agent` refuses this too and must keep doing so — `check_prune_batch`'s
    # rule, the next caller will not know — but its class is `ValueRefused`, which
    # `api/errors.py` maps to **400**. The other three things wrong with a `new_name` are
    # `InvalidAgentError` and answer **422**, so leaving this one to storage meant one
    # request field producing two status codes for four members of one family, and a client
    # validating a rename form having to handle both. Caught by the route test that asserts
    # all four together.
    if new_name == name:
        raise InvalidAgentError(storage.AGENT_RENAME_TO_SELF.format(agent=name))

    if new_name in RESERVED_AGENT_NAMES:
        raise InvalidAgentError(
            f"'{new_name}' is reserved and cannot be used as an agent name. It is "
            "already a path in this product, so an agent called that would have a URL "
            "that means two things. Any other name is fine."
        )

    return storage.active().rename_agent(tenant_id, name, new_name, actor=actor)


def delete(tenant_id: str, name: str, *, actor: str) -> None:
    storage.active().delete_agent(tenant_id, name, actor=actor)


# --- version history, step 021 ---------------------------------------------------
#
# The three functions below are the **one reader** both entry points would share, on
# `tools.catalogue`'s rule: two readers of one table is how a CLI and an API stop
# agreeing about what a customer has. There is no CLI caller today — nothing on the
# command line has ever written an agent config — and this is nonetheless where the
# logic lives rather than in the route, because the day one appears is not the day to
# discover that the route owned the semantics.


class NoSuchVersion(RuntimeError):
    """A version of this agent that was never written. A **404**.

    Its own class for `NoSuchGroupError`'s reason: every bare `RuntimeError` from this
    module is either a 500 or gets guessed at, and this one means the store is working
    and the caller named something that is not there.
    """


def versions(tenant_id: str, name: str, *, limit: int = 50) -> list[dict]:
    """This agent's history, newest first, each row saying whether it would still run.

    **Validity is evaluated here, at read time, and never stored.** A version is a
    configuration that *was* live, and what may be live moves under it: a tool un-vetted
    last week makes a version from last month unrestorable, and the stored row is
    unchanged by that. So the row carries what was written and this adds today's verdict,
    through the same `validate` every other reader uses.

    That is not decoration. Somebody deciding whether to restore a version has to be told
    before they click, rather than by a 422 afterwards — and a screen that showed a
    broken version as restorable would be recommending a save that cannot land.

    Reading a config costs nothing, so the whole config is read here and thrown away
    except for its verdict. `list_agent_versions` deliberately does not return configs;
    this asks for each one because there is no cheaper way to answer a question about its
    contents, and the list is capped. When that stops being true the answer is a stored
    verdict plus a revalidation sweep, which is a different design and wants a reason.
    """
    store = storage.active()
    rows = store.list_agent_versions(tenant_id, name, limit=limit)

    out = []
    for row in rows:
        stored = store.get_agent_version(tenant_id, name, row["version"])
        # **Two un-transacted reads, so the row can be gone between them** — a `DELETE`
        # of the agent cascades its whole history, and this loop was written as though
        # the list it is walking could not move. It answered a `TypeError` on `None`,
        # which is a 500 for a race whose honest answer is "there is nothing here now".
        # Found by an edge hunt reading the loop rather than by a test that could catch
        # it. Skipped rather than raised, because the caller asked for a list and a
        # shorter list is what a concurrent delete leaves; the route re-reads the agent
        # for everything else.
        if stored is None:
            continue
        error = None
        try:
            validate(tenant_id, stored["config"])
        except InvalidAgentError as exc:
            error = str(exc)
        out.append({**row, "valid": error is None, "error": error})
    return out


def version(tenant_id: str, name: str, number: int) -> dict:
    """One stored configuration, with the same read-time verdict. Raises `NoSuchVersion`.

    Raises rather than returning None, unlike `get()`, and the difference is which
    question the caller is asking: `get()` answers *is there an agent here*, where
    absence is ordinary. Here the agent is already known to exist — the grant check
    found it — so a missing version is a caller naming something that was never written,
    and a None would have to be turned into the same 404 by every caller.
    """
    stored = storage.active().get_agent_version(tenant_id, name, number)
    if stored is None:
        raise NoSuchVersion(
            f"agent '{name}' has no version {number}. Its versions are numbered from 1 "
            "up to the one that is live now."
        )

    error = None
    try:
        validate(tenant_id, stored["config"])
    except InvalidAgentError as exc:
        error = str(exc)
    return {**stored, "valid": error is None, "error": error}


def restore(
    tenant_id: str,
    name: str,
    number: int,
    *,
    actor: str,
    if_unchanged_since,
) -> dict | None:
    """Put an old configuration back, as a **new** version. The row, or None if the
    agent is gone.

    Raises `NoSuchVersion` for a number that was never written (404),
    `InvalidAgentError` for a config that would no longer validate (422), and
    `AgentChanged` when the timestamp did not match (409) — the same three answers
    `update` gives, because this is an edit.

    **This could not have been a client fetching a version and PATCHing it back**, and
    that is the finding the route exists for rather than a preference. `merge` is a
    top-level merge, so a key the old config does not have survives from the live one:
    restore a version written before `default_task` existed and the client gets neither
    version — it gets the old config plus today's `default_task`, silently, while the
    screen says the restore worked. No sequence of `PATCH` calls can express this,
    because there is no way to remove a field over HTTP at all.

    So the write is the **whole** config, replacing rather than merging, which is exactly
    what `update_agent` does with what it is handed. What makes it a restore rather than
    an edit is `restored_from`, and that one parameter decides the version row's source
    and the administrative action too — see `storage.update_agent`.

    A restore of the version that is already live is an ordinary no-change write: it
    advances the ETag, records `agent.restore`, and adds nothing to the history. The
    history holds states; the log holds writes.
    """
    stored = version(tenant_id, name, number)

    # **The stored name is normalised to the live one, not compared against it.** Step 025
    # decision 7, and the reason it replaced a refusal: since migration 035 an agent's
    # history legitimately spans its names, so a version written before a rename holds the
    # old one — and that is what a correct history looks like rather than a corrupt row.
    #
    # What this used to do was raise `VersionMismatch` on the difference, which after 035
    # would have made every pre-rename version unrestorable and turned "restore Tuesday's
    # prompt" into a permanent 500 for any agent anybody had ever renamed. Normalising is
    # also what keeps the write legal at all: `agent_name_matches_config` from migration
    # 002 is still on `agents`, so writing the snapshot verbatim would be refused by the
    # database — a 503 for a request that is entirely reasonable.
    #
    # A restore therefore restores *behaviour* and never identity. "Restore Tuesday's
    # prompt" must not also mean "and un-rename the agent", which is a second, unasked-for
    # change to the thing a person is most likely to have bookmarked.
    config = {**stored["config"], "name": name}

    # `validate` rather than `validate_draft`, for `update`'s reason: the reserved-name
    # rule is about *taking* a name and a restore cannot change one. This is also where
    # a version whose tools were un-vetted since is refused — the same sentence
    # `versions()` already showed beside it, so the refusal is never a surprise.
    validate(tenant_id, config)

    store = storage.active()
    updated = store.update_agent(
        tenant_id,
        config,
        actor=actor,
        if_unchanged_since=if_unchanged_since,
        restored_from=number,
    )
    if updated is not None:
        return updated

    # `update`'s tail verbatim, and it has to be: a restore is an edit, so it owes the
    # same 409 carrying the same `changed` list. Here that list is every top-level key
    # this restore would have written that differs from what is stored — which is the
    # honest answer to "what would I have overwritten", and is wider than an edit's
    # because a restore writes the whole config.
    current = store.get_agent(tenant_id, name)
    if current is None:
        return None
    raise AgentChanged(current, config)


__all__ = [
    "RESERVED_AGENT_NAMES",
    "AgentChanged",
    "InvalidAgentError",
    "NoSuchVersion",
    "create",
    "delete",
    "get",
    "identity",
    "load",
    "merge",
    "names",
    "rename",
    "restore",
    "save",
    "update",
    "name_for_id",
    "validate",
    "validate_draft",
    "version",
    "versions",
]
