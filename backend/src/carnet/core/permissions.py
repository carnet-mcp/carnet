"""Permission model and the check the broker runs before every tool call.

An agent's `permissions` field has two dimensions:

    {
        "tools": ["get_github_issues", "post_message"],     # capability: what it may call
        "scope": {                                          # reach: what it may touch
            "github.repo":  {"read":  ["anthropics/*"]},
            "chat.channel": {"write": ["#eng"]},
        },
    }

Grants are written against **resource types**, not argument names. A tool declares
which of its arguments are resources of which type (see tools/base.py), so one
`github.repo` grant covers every tool that touches a repo — including tools we didn't
write, whatever each one calls its arguments. That indirection is what makes the model
survive arbitrary MCP servers.

An identifier may be **composed** from several arguments: GitHub's API splits a repo
into `owner` and `repo`, so a tool wrapping it declares
`Resource("github.repo", ["owner", "repo"], template="{owner}/{repo}")` and the grant
above covers it unchanged. Composition brings a rule of its own — see `_identify`.

An identifier may also answer to a **family**, when the vetter declared its id space has
them: a scope line over `anthropic.model` may name `claude-haiku-4-5-20251001`, or `*`,
or `haiku`. Step 086, and the reason is that a model id has no separator, so the matcher
sees one segment and the middle policy — *the small model but not the large one* — was
inexpressible. The matcher is unchanged; the identifier gained a second name. See
`_check_resource`.

Grants are per-effect with **no implication**: a `write` grant does not confer `read`.
Explicit beats convenient in a policy engine.

Patterns may reference the caller:

    {"tickets.assignee": {"read": ["${principal.id}"]}}

One config, any number of users, each reaching only their own rows.

Rules, all fail-closed:
  - A tool not in `tools` is denied. There is no implicit grant.
  - A tool absent from the registry is denied — we cannot scope what we cannot describe.
  - A declared resource argument that wasn't supplied is denied.
  - A component of a composed identifier may not contain the pattern separator.
  - A resource type with no grant at the tool's effect is denied.
  - Any credential-shaped argument is denied outright (credentials.RESERVED_KWARGS).
"""

from dataclasses import dataclass

from . import patterns
from .credentials import RESERVED_KWARGS

# The only substitution supported today. Kept explicit rather than a general template
# language: policy files are a bad place for evaluation semantics.
PRINCIPAL_ID_TOKEN = "${principal.id}"
PRINCIPAL_PREFIX = "${principal."


# The named branches of `check`, and the whole of why they are named — step 069.
#
# `reason` is a sentence written for a model, and a sentence is the wrong thing for a
# caller to switch on. The simulator (`door.simulate`) has to report *which rule
# produced this verdict*, and recovering that by matching substrings of the prose would
# be a second opinion about permission arrived at by parsing — the exact failure that
# module is built to avoid, one layer up.
#
# **This names existing branches. It invents no judgment.** Each constant below is a
# `return Decision(False, ...)` that was already there, and the set is closed by
# `test_every_refusal_names_its_rule`: a tenth branch added without a rule name fails
# that test rather than rendering as an empty string in a browser.
RULE_CREDENTIAL_SMUGGLED = "credential_smuggled"
RULE_NOT_DESCRIBED = "not_described"
RULE_NOT_GRANTED = "not_granted"
RULE_RESOURCE_MISSING = "resource_missing"
RULE_COMPOSED_SEPARATOR = "composed_separator"
RULE_NO_GRANT_FOR_EFFECT = "no_grant_for_effect"
RULE_OUTSIDE_SCOPE = "outside_scope"
RULE_UNSUPPORTED_REFERENCE = "unsupported_reference"
RULE_HEADLESS_PRINCIPAL = "headless_principal"

RULES = frozenset(
    {
        RULE_CREDENTIAL_SMUGGLED,
        RULE_NOT_DESCRIBED,
        RULE_NOT_GRANTED,
        RULE_RESOURCE_MISSING,
        RULE_COMPOSED_SEPARATOR,
        RULE_NO_GRANT_FOR_EFFECT,
        RULE_OUTSIDE_SCOPE,
        RULE_UNSUPPORTED_REFERENCE,
        RULE_HEADLESS_PRINCIPAL,
    }
)


@dataclass(frozen=True)
class Decision:
    """Outcome of a permission check. `reason` is safe to show the model.

    `rule` names which branch decided, from `RULES` above, and is `""` on an allow.
    Added by 069 and **read by nothing on the enforcement path**: the broker audits
    `reason`, unchanged. It exists so a surface that explains a refusal can say which
    rule produced it without reading the sentence that explains it to somebody else.
    """

    allowed: bool
    reason: str = ""
    rule: str = ""


ALLOW = Decision(allowed=True)


def check(principal, agent: dict, tool_name: str, tool_input: dict, tool) -> Decision:
    """Decide whether `agent`, acting for `principal`, may call `tool_name`.

    `principal`, `agent`, and `tool` are trusted, server-side values: the principal
    comes from the entry point, the agent config from the registry, the tool from the
    tool registry. `tool_name` and `tool_input` come from the model and are untrusted.
    """
    permissions = agent.get("permissions", {})
    granted_tools = permissions.get("tools", [])
    scope = permissions.get("scope", {})

    # 1. Reject any attempt to smuggle a credential in as a tool argument. The model
    #    should never produce these; if it does, that's the interesting case.
    smuggled = RESERVED_KWARGS & set(tool_input)
    if smuggled:
        return Decision(
            False,
            f"arguments {sorted(smuggled)} are supplied by the broker "
            "and may not be set by the caller",
            rule=RULE_CREDENTIAL_SMUGGLED,
        )

    # 2. Is the tool one we can describe? Without a descriptor there is no way to know
    #    which of its arguments are resources, so there is no way to scope it.
    if tool is None:
        return Decision(
            False,
            f"tool '{tool_name}' is not a registered tool",
            rule=RULE_NOT_DESCRIBED,
        )

    # 3. Is the tool granted at all?
    if tool_name not in granted_tools:
        listed = ", ".join(sorted(granted_tools)) or "<none>"
        return Decision(
            False,
            f"agent '{agent['name']}' is not permitted to call '{tool_name}'. "
            f"Permitted tools: {listed}",
            rule=RULE_NOT_GRANTED,
        )

    # 4. Does every resource this call touches fall inside the agent's scope?
    #    A tool may declare several — including two of the same type, as a
    #    copy_issue(from_repo, to_repo) would. Every one of them must pass.
    for ref in tool.resources:
        verdict = _check_resource(principal, tool, ref, tool_input, scope)
        if not verdict.allowed:
            return verdict

    return ALLOW


def _check_resource(principal, tool, ref, tool_input: dict, scope: dict) -> Decision:
    """Validate one declared resource against the agent's scope."""
    value, error = _identify(tool, ref, tool_input)
    if error is not None:
        return error

    granted = scope.get(ref.type, {}).get(tool.effect)
    if not granted:
        return Decision(
            False,
            f"agent has no '{tool.effect}' grant for {ref.type}, "
            f"which '{tool.name}' needs",
            rule=RULE_NO_GRANT_FOR_EFFECT,
        )

    resolved, error = _resolve(granted, principal)
    if error is not None:
        return error

    # **A resource may answer to two names, and a scope line may use either.** Step 086.
    #
    # The raw identifier is the first, and it is unchanged: everything a stored scope
    # matched before this line existed, it still matches. The second is the family the
    # descriptor derives — `""` for every resource whose vetter declared none, which is
    # almost all of them, so this is a no-op everywhere but a model.
    #
    # Why here rather than in the matcher: a model id has no separator, so
    # `claude-haiku-*` is one literal segment matching nothing and the only expressible
    # policies are one dated id or every model — with the consequence that a new release
    # of the same family fails closed until somebody widens every scope naming it (080's
    # E8). The fix is **not** a prefix wildcard: that is the bug `core/patterns.py`
    # exists to make inexpressible, and adding it for models would add it for
    # `github.repo` in the same function. So the matcher keeps its one rule and the
    # identifier gains a second name instead.
    #
    # The two rejected alternatives, both compatibility events, are written out in
    # `docs/plans/086`: a second resource type denies every stored agent at the
    # `RULE_NO_GRANT_FOR_EFFECT` branch above, and a two-segment value denies every
    # stored one-segment pattern including `*`, which is the widest scope failing closed
    # silently on deploy.
    family = ref.family_of(value)
    if not patterns.matches_any(resolved, value) and not (
        family and patterns.matches_any(resolved, family)
    ):
        # The family is named in the refusal when there is one, because the word that
        # would have worked is the single most useful thing a denied caller — or the
        # admin reading the audit row — can be told. Without it the sentence is accurate
        # and leaves both of them to guess that families exist at all.
        known = f" (family '{family}')" if family else ""
        return Decision(
            False,
            f"{ref.type} '{value}'{known} is outside this agent's "
            f"'{tool.effect}' scope. Allowed: {', '.join(resolved)}",
            rule=RULE_OUTSIDE_SCOPE,
        )

    return ALLOW


def _identify(tool, ref, tool_input: dict) -> tuple[str, Decision | None]:
    """Build the identifier a Resource names, from the arguments the model supplied.

    Returns (value, None) or ("", Decision) when the call can't be identified safely.
    """
    values = {}
    for arg_name in ref.args:
        # Fail closed: a resource argument that wasn't supplied can't be validated.
        # With a composed identifier this matters more, not less — one missing
        # component and the rest would compose into something that isn't the thing
        # being touched.
        if arg_name not in tool_input:
            return "", Decision(
                False,
                f"'{tool.name}' requires a permitted '{arg_name}' ({ref.type}); "
                "none was supplied",
                rule=RULE_RESOURCE_MISSING,
            )
        # Values may be numeric (an ADO work item id, say); the matcher is string-based.
        values[arg_name] = str(tool_input[arg_name])

    # A component that contains the pattern separator is refused. This is prefix
    # confusion's composite cousin, and it is the reason composition needs a rule of
    # its own: given `{owner}/{repo}` and a grant of `anthropics/**`, an argument of
    # repo="../../torvalds/linux" composes to a value the matcher happily admits — and
    # the tool then builds a request path pointing at a repository nobody granted.
    # Each placeholder is meant to be one segment, so a separator inside one is never
    # the identifier the template author described.
    #
    # Only applies to composition. A single argument used whole IS the identifier, and
    # the slashes in "anthropics/sdk" are its structure, not an injection.
    if ref.template is not None:
        for arg_name, value in values.items():
            if patterns.SEPARATOR in value:
                return "", Decision(
                    False,
                    f"'{arg_name}' may not contain '{patterns.SEPARATOR}': "
                    f"{ref.type} is composed as '{ref.template}', where each part is "
                    "a single segment",
                    rule=RULE_COMPOSED_SEPARATOR,
                )

    return ref.compose(values), None


def _resolve(granted, principal) -> tuple[list, Decision | None]:
    """Substitute caller references into patterns.

    Returns (resolved_patterns, None) or ([], Decision) when the config is wrong.
    """
    resolved = []
    for pattern in granted:
        if PRINCIPAL_PREFIX not in pattern:
            resolved.append(pattern)
            continue

        if PRINCIPAL_ID_TOKEN not in pattern:
            # Something like ${principal.email} — not supported. Deny loudly rather
            # than leave an unsubstituted literal that quietly matches nothing.
            return [], Decision(
                False,
                f"grant pattern '{pattern}' uses an unsupported caller reference; "
                f"only {PRINCIPAL_ID_TOKEN} is available",
                rule=RULE_UNSUPPORTED_REFERENCE,
            )

        if principal.kind == "system":
            # A headless run has no user whose data to scope to. Substituting the
            # caller id ("cli", "scheduler") would silently match nothing; saying so
            # is more useful than a mysterious denial.
            return [], Decision(
                False,
                f"grant pattern '{pattern}' scopes to a user, but this run is "
                f"headless ({principal}). A per-user scheduled job should construct "
                "a user principal for each user rather than running as system.",
                rule=RULE_HEADLESS_PRINCIPAL,
            )

        resolved.append(pattern.replace(PRINCIPAL_ID_TOKEN, principal.id))

    return resolved, None


def granted_tool_names(agent: dict) -> set:
    """Tool names this agent may call — used to filter the schemas sent to the model.

    This is convenience, not security: it keeps the model from wasting turns on tools
    it can't use. The broker's check() is the actual enforcement point and runs
    regardless of what the model was shown.
    """
    return set(agent.get("permissions", {}).get("tools", []))
