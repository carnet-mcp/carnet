"""The scoping model: capability, reach, effect, and caller substitution.

These call permissions.check() directly — no broker, no audit, no I/O — so a failure
points at the policy engine rather than anything around it.
"""

from carnet.core import permissions
from carnet.core.principal import Principal
from carnet.tools import REGISTRY as STATIC_TOOLS
from carnet.tools.base import Resource, Tool


# Tenancy lives on the Principal, so every constructed principal carries one. A named
# constant rather than a literal: the tenant is routing here, not the thing under test.
TENANT = "t-test"

SYSTEM = Principal.system("cli", TENANT)
PRIYA = Principal.user("priya@example.com", TENANT)

# A read tool whose repo arrives as ONE argument. Defined here rather than taken from
# the registry: the hand-written GitHub tool was retired once the connector replaced
# it, but single-argument resources are still the common shape and the policy engine
# has to be tested against both. SPLIT_READER below is the two-argument case.
READER = Tool(
    name="get_github_issues",
    description="",
    input_schema={
        "type": "object",
        "properties": {"repo": {"type": "string"}, "limit": {"type": "integer"}},
        "required": ["repo"],
    },
    impl=lambda repo, limit=30: {},
    effect="read",
    resources=[Resource("github.repo", "repo")],
)

POSTER = STATIC_TOOLS["post_message"]  # effect=write, channel -> chat.channel


def agent(**permissions_override):
    return {
        "name": "test-agent",
        "system": "irrelevant",
        "permissions": {
            "tools": ["get_github_issues", "post_message"],
            "scope": {
                "github.repo": {"read": ["anthropics/*"]},
                "chat.channel": {"write": ["#eng"]},
            },
            **permissions_override,
        },
    }


def allowed(decision):
    return decision.allowed


# --- capability ---------------------------------------------------------------


def test_granted_tool_within_scope_is_allowed():
    d = permissions.check(SYSTEM, agent(), "get_github_issues", {"repo": "anthropics/sdk"}, READER)
    assert allowed(d)


def test_ungranted_tool_is_denied():
    a = agent(tools=["get_github_issues"])
    d = permissions.check(SYSTEM, a, "post_message", {"channel": "#eng"}, POSTER)
    assert not allowed(d)
    assert "not permitted to call" in d.reason


def test_unregistered_tool_is_denied():
    """We cannot scope what we cannot describe, so an unknown tool never runs."""
    a = agent(tools=["mystery_tool"])
    d = permissions.check(SYSTEM, a, "mystery_tool", {}, None)
    assert not allowed(d)
    assert "not a registered tool" in d.reason


# --- reach --------------------------------------------------------------------


def test_resource_outside_scope_is_denied():
    d = permissions.check(SYSTEM, agent(), "get_github_issues", {"repo": "torvalds/linux"}, READER)
    assert not allowed(d)
    assert "outside this agent's" in d.reason


def test_missing_resource_argument_is_denied():
    """Fail closed: a declared resource that wasn't supplied can't be validated."""
    d = permissions.check(SYSTEM, agent(), "get_github_issues", {}, READER)
    assert not allowed(d)


def test_unscoped_resource_type_is_denied():
    a = agent(scope={"chat.channel": {"write": ["#eng"]}})  # no github.repo grant
    d = permissions.check(SYSTEM, a, "get_github_issues", {"repo": "anthropics/sdk"}, READER)
    assert not allowed(d)
    assert "no 'read' grant for github.repo" in d.reason


def test_non_resource_arguments_are_unconstrained():
    """`limit` is data, not a resource — policy has nothing to say about it."""
    d = permissions.check(
        SYSTEM, agent(), "get_github_issues", {"repo": "anthropics/sdk", "limit": 99}, READER
    )
    assert allowed(d)


# --- effect -------------------------------------------------------------------


def test_a_read_grant_does_not_authorize_a_write():
    """Grants are per-effect with no implication."""
    a = agent(scope={"chat.channel": {"read": ["#eng"]}})
    d = permissions.check(SYSTEM, a, "post_message", {"channel": "#eng", "text": "hi"}, POSTER)
    assert not allowed(d)
    assert "no 'write' grant" in d.reason


def test_a_write_grant_does_not_authorize_a_read():
    a = agent(scope={"github.repo": {"write": ["anthropics/*"]}})
    d = permissions.check(SYSTEM, a, "get_github_issues", {"repo": "anthropics/sdk"}, READER)
    assert not allowed(d)


def test_read_and_write_can_be_scoped_differently_on_one_resource():
    """The point of per-effect grants: broad reads, narrow writes."""
    chatty = Tool(
        name="read_channel",
        description="",
        input_schema={"type": "object", "properties": {"channel": {"type": "string"}}},
        impl=lambda channel: {},
        effect="read",
        resources=[Resource("chat.channel", "channel")],
    )
    a = agent(
        tools=["read_channel", "post_message"],
        scope={"chat.channel": {"read": ["**"], "write": ["#eng"]}},
    )

    assert allowed(permissions.check(SYSTEM, a, "read_channel", {"channel": "#random"}, chatty))
    d = permissions.check(SYSTEM, a, "post_message", {"channel": "#random", "text": "x"}, POSTER)
    assert not allowed(d)


# --- composed identifiers -----------------------------------------------------
# GitHub's REST API — and so its MCP server — takes `owner` and `repo` as separate
# arguments. The grants below are the ones written for get_github_issues, unchanged.

SPLIT_READER = Tool(
    name="list_issues",
    description="",
    input_schema={
        "type": "object",
        "properties": {
            "owner": {"type": "string"},
            "repo": {"type": "string"},
            "perPage": {"type": "integer"},
        },
    },
    impl=lambda owner, repo, perPage=30: {},
    effect="read",
    resources=[Resource("github.repo", ["owner", "repo"], template="{owner}/{repo}")],
)


def splitter_agent(**overrides):
    """Granted the split tool, with the scope written for the single-argument one."""
    return agent(tools=["list_issues"], **overrides)


def test_one_grant_covers_a_tool_that_splits_the_identifier():
    """The whole claim: policy is written against the resource type, so a tool naming
    its arguments differently — and taking two of them — needs no new grant."""
    d = permissions.check(
        SYSTEM, splitter_agent(), "list_issues", {"owner": "anthropics", "repo": "sdk"}, SPLIT_READER
    )
    assert allowed(d)


def test_a_composed_identifier_outside_scope_is_denied():
    d = permissions.check(
        SYSTEM, splitter_agent(), "list_issues", {"owner": "torvalds", "repo": "linux"}, SPLIT_READER
    )
    assert not allowed(d)
    assert "torvalds/linux" in d.reason  # the composed value, not a fragment


def test_a_missing_component_of_a_composed_identifier_is_denied():
    """One part missing and the rest would compose into something that isn't the
    thing being touched. Fail closed, and name the part."""
    d = permissions.check(SYSTEM, splitter_agent(), "list_issues", {"repo": "sdk"}, SPLIT_READER)
    assert not allowed(d)
    assert "'owner'" in d.reason


def test_a_separator_inside_a_component_is_denied():
    """Prefix confusion's composite cousin. With a grant of `anthropics/**`, a repo of
    '../../torvalds/linux' composes to a value the matcher admits — and the tool then
    builds a request path pointing at a repository nobody granted."""
    a = splitter_agent(scope={"github.repo": {"read": ["anthropics/**"]}})
    d = permissions.check(
        SYSTEM,
        a,
        "list_issues",
        {"owner": "anthropics", "repo": "../../torvalds/linux"},
        SPLIT_READER,
    )
    assert not allowed(d)
    assert "may not contain" in d.reason


def test_a_single_argument_resource_may_still_contain_a_separator():
    """'anthropics/sdk' is one whole identifier; its slash is structure, not injection.
    The rule above applies to composition only."""
    d = permissions.check(SYSTEM, agent(), "get_github_issues", {"repo": "anthropics/sdk"}, READER)
    assert allowed(d)


def test_two_resources_of_the_same_type_are_both_checked():
    """What a type-keyed descriptor could not express: copy_issue(from_repo, to_repo)
    touches two repos, and a grant covering one of them is not enough."""
    copier = Tool(
        name="copy_issue",
        description="",
        input_schema={
            "type": "object",
            "properties": {"from_repo": {"type": "string"}, "to_repo": {"type": "string"}},
        },
        impl=lambda from_repo, to_repo: {},
        effect="read",
        resources=[Resource("github.repo", "from_repo"), Resource("github.repo", "to_repo")],
    )
    a = agent(tools=["copy_issue"])

    assert allowed(
        permissions.check(
            SYSTEM, a, "copy_issue", {"from_repo": "anthropics/a", "to_repo": "anthropics/b"}, copier
        )
    )

    d = permissions.check(
        SYSTEM, a, "copy_issue", {"from_repo": "anthropics/a", "to_repo": "torvalds/linux"}, copier
    )
    assert not allowed(d)
    assert "torvalds/linux" in d.reason


# --- caller substitution ------------------------------------------------------


def _own_repo_agent():
    return agent(scope={"github.repo": {"read": ["${principal.id}/*"]}})


def test_principal_substitution_matches_the_callers_own_resources():
    d = permissions.check(
        Principal.user("priya", TENANT), _own_repo_agent(), "get_github_issues", {"repo": "priya/notes"}, READER
    )
    assert allowed(d)


def test_principal_substitution_denies_another_users_resources():
    """One config, many users — and nobody reaches anybody else's rows."""
    d = permissions.check(
        Principal.user("priya", TENANT), _own_repo_agent(), "get_github_issues", {"repo": "sam/notes"}, READER
    )
    assert not allowed(d)


def test_user_scoped_grant_under_a_system_principal_denies_explicitly():
    """A headless run has no user to scope to; say so rather than mysteriously fail."""
    d = permissions.check(SYSTEM, _own_repo_agent(), "get_github_issues", {"repo": "cli/x"}, READER)
    assert not allowed(d)
    assert "headless" in d.reason


def test_unsupported_caller_reference_is_denied():
    """${principal.email} must not survive as an unsubstituted literal."""
    a = agent(scope={"github.repo": {"read": ["${principal.email}/*"]}})
    d = permissions.check(PRIYA, a, "get_github_issues", {"repo": "priya/x"}, READER)
    assert not allowed(d)
    assert "unsupported caller reference" in d.reason


# --- credential smuggling (unchanged behaviour, still enforced) ---------------


def test_credential_shaped_argument_is_denied():
    d = permissions.check(
        SYSTEM,
        agent(),
        "post_message",
        {"channel": "#eng", "text": "x", "webhook_url": "https://evil.example"},
        POSTER,
    )
    assert not allowed(d)


# --- schema filtering ---------------------------------------------------------


def test_granted_tool_names_reads_the_capability_list():
    assert permissions.granted_tool_names(agent()) == {"get_github_issues", "post_message"}


def test_granted_tool_names_is_empty_for_an_agent_with_no_permissions():
    assert permissions.granted_tool_names({"name": "x"}) == set()


# --- 069: every refusal names the rule that produced it ----------------------------


def test_every_refusal_names_its_rule():
    """**The whole enforcement of `Decision.rule`, and it is one test.**

    `rule` is a public string a browser switches on, so a branch added without one
    renders as nothing — silently, in the direction that looks like *no reason given*.
    Nothing in the type system stops that: `rule` defaults to `""` because `ALLOW` needs
    it to.

    So this walks the module's syntax tree for every `Decision(False, ...)` and requires
    a `rule=` naming one of the module's own constants. **A syntax tree rather than a
    regular expression**, which the first version used and which matched the sentence in
    this module's own comments describing the rule — a test that read prose as code, and
    would have gone green on a branch nobody wrote.

    A source walk rather than a behavioural sweep because the branches are the
    population, and reaching all nine through `check()` would be nine fixtures that could
    themselves fall out of step with the code — which is the drift this is here to catch.
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(permissions))
    refusals = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Decision"
        and node.args
        and node.args[0] is not None
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value is False
    ]

    assert len(refusals) == 9, f"expected nine refusal branches, found {len(refusals)}"
    for call in refusals:
        named = {kw.arg: kw.value for kw in call.keywords}
        assert "rule" in named, f"a refusal with no rule, at line {call.lineno}"
        constant = named["rule"]
        assert isinstance(constant, ast.Name) and constant.id.startswith("RULE_"), (
            f"a rule that is a literal rather than a constant, at line {call.lineno}"
        )
        assert getattr(permissions, constant.id) in permissions.RULES


def test_the_rule_constants_and_the_set_agree():
    """`RULES` is what a client may be handed, and a constant missing from it is a value
    that reaches a browser as unknown."""
    named = {
        value
        for name, value in vars(permissions).items()
        if name.startswith("RULE_") and isinstance(value, str)
    }
    assert named == permissions.RULES


def test_an_allow_carries_no_rule():
    """`""` on an allow, deliberately: a rule names which refusal happened, and there is
    no such thing as the rule that allowed something — every check passed."""
    assert permissions.ALLOW.rule == ""
    assert permissions.ALLOW.reason == ""


def test_the_rule_survives_the_branch_it_names():
    """Four branches driven for real, so the source walk above cannot pass against
    constants nobody assigns. Not all nine — the other five need a malformed config,
    which their own tests already build."""
    agent = {
        "name": "triage",
        "permissions": {
            "tools": ["get_github_issues"],
            "scope": {"github.repo": {"read": ["acme/*"]}},
        },
    }

    smuggled = permissions.check(PRIYA, agent, "get_github_issues", {"token": "x"}, READER)
    assert smuggled.rule == permissions.RULE_CREDENTIAL_SMUGGLED

    undescribed = permissions.check(PRIYA, agent, "get_github_issues", {}, None)
    assert undescribed.rule == permissions.RULE_NOT_DESCRIBED

    ungranted = permissions.check(PRIYA, agent, "other_tool", {}, READER)
    assert ungranted.rule == permissions.RULE_NOT_GRANTED

    missing = permissions.check(PRIYA, agent, "get_github_issues", {}, READER)
    assert missing.rule == permissions.RULE_RESOURCE_MISSING

    outside = permissions.check(
        PRIYA, agent, "get_github_issues", {"repo": "other/x"}, READER
    )
    assert outside.rule == permissions.RULE_OUTSIDE_SCOPE


# --- a scope line that can name a family -------------------------------------------
#
# Step 086, 080's E8. A model id has no `/`, so `core/patterns.py` sees one segment and
# the only two expressible policies over one are *this exact dated id* and *every model*.
# The middle one — *the small model but not the large one* — is what an enterprise
# actually wants, and 045's promise that it was "an ordinary scope line through the
# existing matcher" was wrong; 045b's live run found out.

MODEL_TOOL = Tool(
    name="anthropic_chat",
    description="",
    input_schema={
        "type": "object",
        "properties": {"model": {"type": "string"}, "messages": {"type": "array"}},
        "required": ["model", "messages"],
    },
    impl=lambda model, messages: {},
    effect="write",
    resources=[
        Resource("anthropic.model", "model", families=("opus", "sonnet", "haiku"))
    ],
)


def model_agent(*allowed):
    return {
        "name": "thinker",
        "permissions": {
            "tools": ["anthropic_chat"],
            "scope": {"anthropic.model": {"write": list(allowed)}},
        },
    }


def think(agent_config, model):
    return permissions.check(
        PRIYA, agent_config, "anthropic_chat", {"model": model, "messages": []}, MODEL_TOOL
    )


def test_a_family_is_what_a_scope_line_could_not_say_before():
    """The gap, and the fix, in one test.

    `claude-haiku-*` is one literal segment to the matcher and equals nothing — checked
    here rather than asserted, because it is the sentence everybody assumes is false.
    """
    assert think(model_agent("claude-haiku-*"), "claude-haiku-4-5-20251001").allowed is False
    assert think(model_agent("haiku"), "claude-haiku-4-5-20251001").allowed is True


def test_a_new_dated_release_of_a_named_family_no_longer_fails_closed():
    """**The trigger 080 calls fired, and it needs no second vendor.** A scope naming a
    dated id refuses the next dated id — that is unchanged and correct — but a scope
    naming the family admits both, which is what stops a vendor's release day from
    being an outage in every agent config that named the old one."""
    dated = model_agent("claude-haiku-4-5-20251001")
    assert think(dated, "claude-haiku-4-5-20251001").allowed is True
    assert think(dated, "claude-haiku-4-6-20260114").allowed is False

    family = model_agent("haiku")
    assert think(family, "claude-haiku-4-5-20251001").allowed is True
    assert think(family, "claude-haiku-4-6-20260114").allowed is True


def test_a_family_narrows_rather_than_widens():
    """The whole point of the middle policy: `haiku` is not `*`."""
    assert think(model_agent("haiku"), "claude-opus-5-20260910").allowed is False
    assert think(model_agent("*"), "claude-opus-5-20260910").allowed is True


def test_no_stored_pattern_changes_what_it_matches():
    """**The compatibility table from the plan, as a test.**

    This is the property that made this design preferable to the two obvious ones. Every
    scope somebody has already written keeps matching exactly what it matched; the only
    string that gains a meaning is a family name, and a family name in a scope today is a
    scope that denies everything.
    """
    everything = model_agent("*")
    exact = model_agent("claude-haiku-4-5-20251001")

    assert think(everything, "claude-haiku-4-5-20251001").allowed is True
    assert think(everything, "claude-opus-5-20260910").allowed is True
    assert think(exact, "claude-haiku-4-5-20251001").allowed is True
    assert think(exact, "claude-haiku-4-6-20260114").allowed is False


def test_a_resource_with_no_declared_families_is_untouched():
    """Almost every resource in the system. A repository has no families, its descriptor
    declares none, and nothing about `github.repo` moved."""
    repo = agent(scope={"github.repo": {"read": ["acme/*"]}})
    assert permissions.check(PRIYA, repo, "get_github_issues", {"repo": "acme/api"}, READER).allowed is True
    assert permissions.check(PRIYA, repo, "get_github_issues", {"repo": "other/api"}, READER).allowed is False
    # And the token-run rule is not quietly available here: `acme` is not a family of
    # `acme-evil/api`, because no family was declared and prefix confusion stays
    # inexpressible for a resource whose vetter named no id space.
    assert permissions.check(
        PRIYA, agent(scope={"github.repo": {"read": ["acme"]}}),
        "get_github_issues", {"repo": "acme-evil/api"}, READER,
    ).allowed is False


def test_a_family_is_a_run_of_whole_tokens_not_a_substring():
    """**The care that keeps this out of `core/patterns.py`'s bug class.**

    A substring test would make `pt-5` a family of `gpt-5-mini` — prefix confusion
    wearing the normalizer's clothes. Whole `-`-delimited tokens is that module's own
    rule at a finer separator.
    """
    ref = Resource("openai.model", "model", families=("gpt-5",))
    assert ref.family_of("gpt-5-mini") == "gpt-5"
    # `gpt` and `5` are both in `gpt-4-5` and are not adjacent, which is exactly what a
    # substring test gets wrong and what "a contiguous run of whole tokens" gets right.
    assert ref.family_of("gpt-4-5") == ""
    assert ref.family_of("o3-mini") == ""
    # `pt-5` is declared and still does not match, which is the assertion that would
    # fail the day somebody reaches for `in`.
    assert Resource("openai.model", "model", families=("pt-5",)).family_of("gpt-5") == ""


def test_a_family_survives_a_vendor_prefix_and_a_case():
    """The same model arrives under several spellings depending on how it was reached —
    a bare id, a vendor-prefixed one, a Bedrock ARN. `patterns.matches` is case-sensitive
    *because* normalizing identifiers is "a connector-vetting concern"; a `Resource` is
    the vetting descriptor, so this is that concern honoured."""
    ref = Resource("anthropic.model", "model", families=("haiku",))
    assert ref.family_of("anthropic.claude-haiku-4-5") == "haiku"
    assert ref.family_of("CLAUDE-HAIKU-4-5") == "haiku"


def test_the_more_specific_family_wins_and_the_order_is_not_insertion_order():
    """A vendor with both `gpt-5` and `gpt-5-mini` has one id matching two families, and
    a rate — or a permission — must not depend on which order somebody typed them."""
    one = Resource("openai.model", "model", families=("gpt-5", "gpt-5-mini"))
    other = Resource("openai.model", "model", families=("gpt-5-mini", "gpt-5"))
    assert one.family_of("gpt-5-mini") == "gpt-5-mini"
    assert other.family_of("gpt-5-mini") == "gpt-5-mini"


def test_the_refusal_names_the_family_it_derived():
    """The word that would have worked is the most useful thing a denied caller can be
    told. Without it the sentence is accurate and leaves them to guess families exist."""
    refusal = think(model_agent("opus"), "claude-haiku-4-5-20251001")
    assert refusal.allowed is False
    assert "family 'haiku'" in refusal.reason
    assert refusal.rule == permissions.RULE_OUTSIDE_SCOPE

    # And says nothing about a family when there is none to name, rather than an
    # empty pair of quotes.
    unknown = think(model_agent("opus"), "some-other-vendor-model")
    assert "family" not in unknown.reason


# --- the two designs this one was chosen over, pinned as what they would have cost ---
#
# Both are written out in `docs/plans/086`, and both are compatibility events. They are
# here as failing-in-the-right-way assertions rather than as prose, because a later
# reader deciding to "just add a family resource type" should meet the cost as a test.


def test_a_second_resource_type_would_have_denied_every_stored_agent():
    """**Design A.** `check` step 4 requires every declared resource to pass, and
    `_check_resource` denies when the scope has no entry for that type at all. So adding
    `anthropic.family` beside `anthropic.model` refuses every agent whose policy was
    written before the type existed — naming a resource type that did not exist when
    they wrote it."""
    two_types = Tool(
        name="anthropic_chat",
        description="",
        input_schema=MODEL_TOOL.input_schema,
        impl=lambda model, messages: {},
        effect="write",
        resources=[
            Resource("anthropic.model", "model"),
            Resource("anthropic.family", "model"),
        ],
    )
    stored = model_agent("*")  # the widest policy anybody has today
    refusal = permissions.check(
        PRIYA, stored, "anthropic_chat", {"model": "claude-haiku-4-5", "messages": []}, two_types
    )
    assert refusal.allowed is False
    assert refusal.rule == permissions.RULE_NO_GRANT_FOR_EFFECT


def test_a_two_segment_value_would_have_denied_the_widest_scope():
    """**Design B.** Segment counts must agree, so `haiku/claude-haiku-4-5` stops
    matching every one-segment pattern — including `*`, the scope most likely to be in
    a first customer's config. It fails closed, which is the good half, and it does it
    silently on deploy for the permission everybody wrote, which is the bad half."""
    from carnet.core import patterns

    assert patterns.matches("*", "claude-haiku-4-5-20251001") is True
    assert patterns.matches("*", "haiku/claude-haiku-4-5-20251001") is False
    assert patterns.matches("claude-haiku-4-5", "haiku/claude-haiku-4-5") is False


def test_a_family_cannot_reach_across_the_pattern_separator():
    """The family rule works *inside* one segment and must not compose across two.
    `github.repo` values carry a `/` and a family is refused if it contains one, so the
    only remaining question is whether a legal family can match half of a value. It
    cannot: the value is tokenized whole, `/` is not a token boundary, and `acme` is not
    a run of `["acme/sdk"]`."""
    ref = Resource("github.repo", "repo", families=("acme",))
    assert ref.family_of("acme/sdk") == ""
    assert ref.family_of("acme-sdk") == "acme"


def test_the_declared_spelling_is_the_one_a_scope_must_name():
    """**A sharp edge, pinned rather than smoothed.** `family_of` lowercases the *id* it
    is given, because the same model arrives under several spellings and normalizing an
    identifier is the vetting descriptor's job. It returns the family as the vetter
    *declared* it, and the matcher compares that case-sensitively — so a scope names a
    declared family exactly, exactly as it names an exact model id exactly.

    Making this half case-insensitive would mean `patterns.matches` treating one class of
    input differently from every other, which is a worse trade than the surprise.
    """
    ref = Resource("anthropic.model", "model", families=("HAIKU",))
    assert ref.family_of("claude-haiku-4-5") == "HAIKU"

    tool = Tool(
        name="anthropic_chat", description="", input_schema=MODEL_TOOL.input_schema,
        impl=lambda **_: None, effect="write", resources=[ref],
    )
    exact = {"name": "a", "permissions": {"tools": ["anthropic_chat"],
             "scope": {"anthropic.model": {"write": ["HAIKU"]}}}}
    other = {"name": "a", "permissions": {"tools": ["anthropic_chat"],
             "scope": {"anthropic.model": {"write": ["haiku"]}}}}
    call = {"model": "claude-haiku-4-5", "messages": []}

    assert permissions.check(PRIYA, exact, "anthropic_chat", call, tool).allowed is True
    assert permissions.check(PRIYA, other, "anthropic_chat", call, tool).allowed is False


def test_a_families_string_is_refused_rather_than_iterated():
    """`args` normalizes a bare string and this refuses one, and the asymmetry is what
    each mistake *does*: `args="repo"` means the obvious thing, while `families="haiku"`
    would become five one-letter families, each matching any id carrying that letter as a
    whole token. Silent, and found by driving it."""
    import pytest as _pytest

    with _pytest.raises(TypeError, match="one family per character"):
        Resource("anthropic.model", "model", families="haiku")
