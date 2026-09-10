"""The Tool type.

One object holds everything the platform needs to know about a tool:

    schema      what the MODEL sees    (the contract)
    impl        what actually RUNS     (the execution)
    redact_args what the AUDIT hides   (the log policy)
    effect      what it DOES           (read or write)
    resources   what it TOUCHES        (the scoping descriptor)

These stay conceptually separate — `.schema` never leaks the implementation, and the
model never sees `impl` — but they live on one object so adding a tool is a single
edit in a single file. Keeping them in parallel dicts across modules is how a
registry silently drifts out of sync.

`effect` and `resources` are the **descriptor**: the annotation that lets the broker
scope a tool it did not author. MCP servers advertise a name, a description, and a
schema; they do not say which argument is the resource being touched, nor whether the
call mutates anything. We add that at vetting time. See tools/__init__.py for the
validation that keeps a descriptor from silently drifting off its schema.
"""

from dataclasses import dataclass, field
from typing import Callable, Literal


def uncallable(*_args, **_kwargs):
    """The implementation of a tool that exists to be *read*, never run. Step 069.

    `tools.describe` answers *what would the permission check read about this name* —
    a question settled entirely by rows, with no session, no credential and no vendor.
    What it hands back is a `Tool`, because that is what `permissions.check` takes, and
    a `Tool` has an `impl`.

    So the impl is this. **Uniformly, including for hand-written tools**, whose real
    implementation is sitting right there in `REGISTRY` and is exactly what must not be
    handed out: an accessor that returns a live implementation for half the catalogue is
    one refactor away from becoming a second route to a tool, and `core.broker.call` is
    the only route to a tool.
    """
    raise RuntimeError(
        "this Tool is a descriptor, not an implementation — it was built by "
        "`tools.describe` to be read by the permission check, and nothing bound it to "
        "anything that can run. A tool is called through `core.broker.call`."
    )


# The input schema of a descriptor: shaped like a schema, describing nothing. A real
# one comes from the server (MCP) or from the vetter (REST) at bind, and `describe`
# has neither — which is why `tools/validation.validate` stays in `bind`, where there
# is a schema for a resource argument to drift away from.
NO_SCHEMA: dict = {"type": "object", "properties": {}}

Effect = Literal["read", "write"]

# Whose account a call goes out as — step 033a, decision 8 of plan 033. Part of the
# descriptor for the same reason `effect` is: it is a judgment about consequence the
# server cannot make for us, and it is exactly the kind of thing an approval is about.
#
#     service   always the connector's shared credential. A caller's delegated
#               connection is never consulted, so one person connecting an account
#               cannot silently change how a shared tool behaves for everybody.
#     user      always the caller's own credential. If they have none the call is
#               refused with the connection to make — never the shared fallback,
#               which is how an intern reads a repo he cannot open.
#
# The two values are duplicated as constants in `core/credentials.py` rather than
# imported from here: that module deliberately knows no specific tool, and two string
# constants are the `_OAUTH_ACCESS` boundary cost paid again — pinned by a test the
# same way, so they cannot drift apart silently.
Identity = Literal["service", "user"]

# A tool may set this key on an error result to say: the call may have taken effect,
# and I cannot tell. Any tool that reaches an external system can end up here — an
# HTTP POST that times out is the same problem as an MCP request with no reply.
#
# The broker turns it into outcome="unknown" for writes. It matters because "it
# failed" and "it might have worked" call for opposite responses: the first is safe
# to retry, the second is how one comment becomes five. A run that ends with an
# ambiguous write is a run somebody has to go and look at.
MAY_HAVE_COMPLETED = "may_have_completed"

# A tool may set this key on a result to say what the call spent at a model. Step 045b.
#
# The second reserved result key, and it behaves differently from the first in the one
# way that matters: **the broker removes it before anything else sees the result.**
# `MAY_HAVE_COMPLETED` rides back to the model because it is *about the call* and the
# model is the party that has to decide whether to retry. This one is bookkeeping — the
# caller has no use for it, it would count against the response size cap, and for a REST
# connector the result is the vendor's JSON *verbatim*, which a key we invented would
# quietly stop being true of.
#
# **Namespaced, and that is not decoration.** The obvious name is `usage`, which is
# exactly what the Messages API calls the object this key will most often be lifted
# *from* — so a plain name would collide with the body it is derived from on the very
# first connector 045c registers.
#
# It is still a key on a dict a callee controls, so every producer clears it before
# setting it: a vendor body echoed back verbatim must not be able to report its own
# spend. `tools/rest` and `tools/mcp/client.normalize` each do that at the one point
# they build a result, and `core/usage.parse_report` refuses anything malformed on top.
# The value is `{model?, input_tokens?, output_tokens?, cache_read_tokens?,
# cache_write_tokens?}` — every field optional, absent counters read as zero.
REPORTED_USAGE = "carnet_reported_usage"


# What a family's name is delimited by inside a model id. Vendors write model ids as
# hyphenated tokens — `claude-haiku-4-5-20251001`, `gpt-5-mini` — and this is the
# separator `Resource.family_of` compares whole tokens across. It is not
# `patterns.SEPARATOR`: that one divides an identifier into the segments a policy may
# wildcard, and this one divides a single segment into the tokens a family is a run of.
FAMILY_SEPARATOR = "-"


@dataclass(frozen=True)
class Resource:
    """One thing a tool touches, and how to name it from the tool's arguments.

    A grant is written against the resource *type*, so policy never learns argument
    names. This is the indirection that lets one `github.repo` grant cover every tool
    that touches a repo — including tools we didn't write, whatever each one calls its
    arguments.

        Resource("github.repo", "repo")
            The `repo` argument is the whole identifier. Its value is used as-is, so
            "anthropics/sdk" arrives at the matcher with its structure intact.

        Resource("github.repo", ["owner", "repo"], template="{owner}/{repo}")
            The identifier is *composed* from two arguments. GitHub's REST API — and
            so its MCP server — splits a repo this way, and a descriptor that could
            only name one argument could not scope it at all.

    A list of these rather than a dict keyed by type, because a tool may touch two
    resources of the same type. A hypothetical copy_issue(from_repo, to_repo) declares
    two `github.repo` entries and both get checked; a type-keyed mapping could only
    hold one of them.

    Validated at import by tools.validate() — see there for what a malformed
    descriptor would silently do to a policy.
    """

    # Resource types are named `<system>.<noun>`. With MCP this becomes the vocabulary
    # of the vetting process: what a connector admin maps a server's nouns onto.
    type: str

    # Argument names that carry the identifier. A bare string is accepted for the
    # single-argument case and normalized to a 1-tuple.
    args: tuple

    # How the arguments combine, as a format string over `args`. Required when there
    # is more than one — gluing two values together without a stated shape is a guess.
    # None means the single argument's value IS the identifier.
    template: str | None = None

    # The families this identifier's id space is divided into, named by the vetter.
    # Empty for every resource that has no such notion, which is almost all of them.
    #
    # A naming fact about somebody else's ids, exactly like `template` is a naming fact
    # about GitHub splitting a repo across two arguments. `core/permissions.py` decides
    # that a scope may *name* one of these; this only says what they are called.
    families: tuple = ()

    def __post_init__(self):
        if isinstance(self.args, str):
            object.__setattr__(self, "args", (self.args,))
        else:
            object.__setattr__(self, "args", tuple(self.args))
        # A bare string is refused rather than accepted, where `args` above normalizes
        # one. The asymmetry is deliberate and it is what each mistake *does*:
        # `args="repo"` means the obvious thing, while `families="haiku"` would iterate
        # into `('h','a','i','k','u')` — five one-letter families, each matching any id
        # with that letter as a whole token, silently. Found by driving it in step 086's
        # edge pass. Every caller that crosses a boundary (the route, the CLI, both
        # stores) already refuses a bare string; this is the one that does not.
        if isinstance(self.families, str):
            raise TypeError(
                f"families must be a sequence of names, not the string "
                f"{self.families!r} — a string iterates into one family per character."
            )
        object.__setattr__(self, "families", tuple(self.families))

    def compose(self, values: dict) -> str:
        """Build the identifier from already-stringified argument values.

        Assumes a validated descriptor and a complete `values` — presence and the
        separator rule are policy decisions and live in core/permissions.py, which
        has to return a refusal the model can read rather than raise.
        """
        if self.template is None:
            return values[self.args[0]]
        return self.template.format(**values)

    def family_of(self, value: str) -> str:
        """The declared family `value` belongs to, or `""`. Step 086, 080's E8.

        A model id has no `/`, so it is one segment to `core/patterns.py` and the only
        two policies expressible over one are *this exact dated id* and *every model*.
        The middle one an enterprise wants — *the small model but not the large one* —
        needs the id to have a second name, and this is where that name is derived.

        **A family matches as a contiguous run of whole `-`-delimited tokens**, longest
        declared family first, lowercased on both sides:

            "haiku" of "claude-haiku-4-5-20251001"  -> "haiku"
            "haiku" of "anthropic.claude-haiku-4-5" -> "haiku"   (a vendor prefix)
            "gpt-5" of "gpt-5-mini"                 -> "gpt-5"
            "gpt-5" of "gpt-4-5"                    -> ""        (not contiguous)

        **Token runs rather than a substring, and that is the whole of the care here.**
        A substring test would make `pt-5` a family of `gpt-5-mini` — prefix confusion
        wearing the normalizer's clothes, which is the class of bug `core/patterns.py`
        exists to make inexpressible and would be reintroduced one function away from
        it. A run of whole tokens is that module's own rule at a finer separator.

        Deliberately **not** `core/usage.model_family`, which resolves against the rate
        table and matches by substring. Sharing it would make an operator's pricing file
        the permission vocabulary — editing a price would change who may call what — and
        would drag a rule that is right for money (guess generously; a wrong price is
        visible and correctable) into a place where the same guess is silent. The two
        want opposite postures, which is why there are two functions. Step 086 argues it.

        Lowercased, where `patterns.matches` is case-sensitive *because* it says
        normalizing identifiers is "a connector-vetting concern, not the matcher's".
        This is that concern: a `Resource` is the vetting descriptor and the vetter named
        the id space.
        """
        if not self.families:
            return ""

        tokens = value.lower().split(FAMILY_SEPARATOR)
        # Longest first, then alphabetically — `usage.model_family`'s rule and for its
        # reason: a vendor with both `gpt-5` and `gpt-5-mini` as families has one id
        # matching two, and the more specific one is the one that meant it. Deterministic
        # either way, which is the property a permission check cannot do without.
        for family in sorted(self.families, key=lambda name: (-len(name), name)):
            wanted = family.lower().split(FAMILY_SEPARATOR)
            for start in range(len(tokens) - len(wanted) + 1):
                if tokens[start : start + len(wanted)] == wanted:
                    return family
        return ""


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_schema: dict
    impl: Callable

    # Does this call observe, or does it change something? Grants are per-effect, so
    # an agent can be given broad reads and narrow writes over the same resource.
    #
    # Per-tool, not per-argument: a hypothetical copy_issue(from_repo, to_repo) would
    # check both against "write". Per-argument effects are a later refinement.
    effect: Effect = "read"

    # What this tool touches, as a list of Resource declarations. Empty means it
    # touches nothing policy has a name for — a clock, a calculator.
    #
    # This is what makes a grant portable across tools: policy is written against the
    # resource type, so one `github.repo` grant covers every tool that touches a repo,
    # whatever each one happens to call its arguments and however many it splits the
    # identifier across.
    resources: tuple = field(default_factory=tuple)

    # Argument names whose values must never be written to the audit log in the
    # clear (free text, user content). Credential-shaped names are redacted
    # globally by core/audit.py regardless of what's listed here.
    redact_args: frozenset = field(default_factory=frozenset)

    # Per-tool ceiling on response size in bytes. None means use
    # config.MAX_RESPONSE_BYTES. Raise it for a tool whose useful output is
    # genuinely large; lower it for one that reads attacker-influenced content.
    # Enforcement is in the broker, never here — a cap inside an implementation
    # would only protect tools we wrote.
    max_response_bytes: int | None = None

    # Which vetted connector contributed this tool, or None for a hand-written one.
    # It is how the broker keys the credential lookup without core/ having to know
    # what an MCP server is: one Jira token serves all twenty Jira tools, so the
    # credential belongs to the connector rather than to each tool.
    connector: str | None = None

    # Whose account this tool acts as — see `Identity` above. Set from the vetted
    # descriptor for connector tools; hand-written tools keep the default, because
    # the one that carries a credential at all (`post_message`) sends to a webhook
    # that is the organisation's by nature.
    identity: Identity = "service"

    # Where the connector's shared credential lives, copied off its manifest at bind
    # so the broker can hand `core/credentials` a variable *name* per call. Before
    # 033a the per-call lookup fell back to a hardcoded map that only ever knew the
    # shipped connector, so a registered connector's `service` calls resolved to no
    # credential at all — invisible while the delegated fallback papered over it.
    credential_env: str | None = None

    # Where it lives when it is **not** ours to hold — `op://vault/item/field`, resolved
    # at call time (step 070). Copied off the manifest at bind exactly as
    # `credential_env` is, and handed to `core/credentials` as a string per call, so
    # neither this layer nor that one learns what a vault is. Mutually exclusive with
    # `credential_env`; None for every hand-written tool and every stdio connector.
    credential_ref: str | None = None

    # The request binding a `rest` connector tool was vetted with — step 045a. None
    # for every MCP and hand-written tool. Part of the descriptor for the same reason
    # `effect` is: it came from the approval, so `_stale_names` must compare it, or a
    # re-vetted path/method/schema would keep serving the old request shape until a
    # process restart. The broker never reads it; `tools/rest.bind` closes over it.
    binding: dict | None = None
    # The streamed entry point, when the tool has one — step 108. Called with the same
    # arguments and the same keyword-only credential as `impl`, and returns an object
    # the broker's `stream()` iterates while the answer is still arriving (see
    # `tools/rest.Upstream`). None for every MCP and hand-written tool: MCP's
    # `tools/call` is a complete result by protocol, so there is nothing to forward
    # early. Set by `tools/rest.bind` for every REST tool, because a REST response can
    # always be read as it arrives — whether the vendor *streams* is the vendor's
    # business, and the broker forwards bytes either way. Never called by the MCP door,
    # which is JSON-only by decision (033b); `broker.stream` is its one reader.
    stream_impl: Callable | None = None

    def __post_init__(self):
        # Accept a list at the call site — a trailing comma in a one-element tuple is
        # exactly the kind of typo that would silently drop a resource declaration.
        object.__setattr__(self, "resources", tuple(self.resources))

    @property
    def schema(self) -> dict:
        """The Messages API tool definition — the only part the model ever sees.

        Credential parameters are deliberately absent: a tool's secrets are injected
        by the broker as keyword-only arguments, so there is no schema field for the
        model to put one in.
        """
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }
