"""Tool descriptor validation.

Every case here is a policy that would *look* enforced in review and not be. That's
why these raise at import rather than being reported at call time.
"""

import pytest

from carnet import storage, tools
from carnet.tools import mcp
from carnet.tools.base import Resource, Tool

from conftest import TEST_TENANT as TENANT

SCHEMA = {
    "type": "object",
    "properties": {
        "repo": {"type": "string"},
        "owner": {"type": "string"},
        "limit": {"type": "integer"},
    },
    "required": ["repo"],
}


def make(**overrides):
    return Tool(
        **{
            "name": "example",
            "description": "",
            "input_schema": SCHEMA,
            "impl": lambda repo, limit=1: {},
            **overrides,
        }
    )


def test_a_well_formed_descriptor_validates():
    tools.validate(make(effect="read", resources=[Resource("github.repo", "repo")]))


def test_resource_naming_an_argument_the_schema_lacks_is_rejected():
    """The important one: this constraint could never fire, and nothing would say so."""
    with pytest.raises(RuntimeError, match="not in its input_schema"):
        tools.validate(make(effect="read", resources=[Resource("github.repo", "repository")]))


def test_write_with_no_declared_resource_is_rejected():
    """A write to something policy cannot name is unscopeable by construction."""
    with pytest.raises(RuntimeError, match="declares no resources"):
        tools.validate(make(effect="write", resources=[]))


def test_unknown_effect_is_rejected():
    with pytest.raises(RuntimeError, match="expected one of"):
        tools.validate(make(effect="delete", resources=[Resource("github.repo", "repo")]))


# --- the description (077) ----------------------------------------------------


def test_an_empty_description_is_allowed():
    """MCP makes it optional and `binding.py` binds a server's undocumented tool with
    `""`; refusing it would make that tool vanish at the next bind."""
    tools.validate(make(description=""))


def test_a_description_that_looks_like_a_credential_is_refused():
    for secret in (
        "Use art_m_0123456789ab.Zq8tYw2vLp9sXk4mN7rB to call this.",
        "Send Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9x to the API.",
        "Key sk-abcdefghijklmnopqrstuvwxyz0123 is preconfigured.",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "token xoxb-1234567890-abcdef",
        "AKIAIOSFODNN7EXAMPLE",
    ):
        with pytest.raises(RuntimeError, match="looks like a credential"):
            tools.validate(make(description=secret))


def test_a_description_that_merely_talks_about_tokens_is_fine():
    """The rule is a shape, not a word: `Bearer <your token>` and prose about API keys
    are what a good description says."""
    tools.validate(make(description="Authenticate with `Authorization: Bearer <your token>`."))
    tools.validate(make(description="Lists the API keys the caller may rotate. Needs an sk- key."))


def test_a_control_character_in_a_description_is_refused_but_newlines_are_prose():
    tools.validate(make(description="Line one.\nLine two, with a\ttab."))
    with pytest.raises(RuntimeError, match="control character"):
        tools.validate(make(description="Hidden \x1b[31mred\x1b[0m text."))
    with pytest.raises(RuntimeError, match="control character"):
        tools.validate(make(description="nul\x00byte"))


def test_an_oversized_description_is_refused():
    from carnet.tools.validation import DESCRIPTION_MAX_CHARS

    tools.validate(make(description="x" * DESCRIPTION_MAX_CHARS))
    with pytest.raises(RuntimeError, match="character description"):
        tools.validate(make(description="x" * (DESCRIPTION_MAX_CHARS + 1)))


def test_read_with_no_resources_is_allowed():
    """A clock or a calculator touches nothing there is to scope."""
    tools.validate(make(effect="read", resources=[]))


# --- composed identifiers ------------------------------------------------------
# GitHub's API — and so its MCP server — splits a repo into `owner` and `repo`. A
# descriptor that could only name one argument could not scope such a tool at all.


def test_a_composed_resource_validates():
    tools.validate(
        make(
            effect="read",
            resources=[Resource("github.repo", ["owner", "repo"], template="{owner}/{repo}")],
        )
    )


def test_composing_without_a_template_is_rejected():
    """Joining two arguments into one identifier without a stated shape is a guess."""
    with pytest.raises(RuntimeError, match="gives no template"):
        tools.validate(make(effect="read", resources=[Resource("github.repo", ["owner", "repo"])]))


def test_a_template_placeholder_outside_the_declared_args_is_rejected():
    """It would raise mid-check on a real call — i.e. only once it mattered."""
    with pytest.raises(RuntimeError, match="names.*but the resource declares"):
        tools.validate(
            make(
                effect="read",
                resources=[Resource("github.repo", ["owner"], template="{owner}/{repo}")],
            )
        )


def test_a_declared_arg_the_template_ignores_is_rejected():
    """An argument that composes into nothing is a value that constrains nothing."""
    with pytest.raises(RuntimeError, match="names.*but the resource declares"):
        tools.validate(
            make(
                effect="read",
                resources=[Resource("github.repo", ["owner", "repo"], template="{owner}")],
            )
        )


def test_a_template_conversion_is_rejected():
    """`{owner!r}` composes an identifier with quotes in it — wrong, and invisibly so."""
    with pytest.raises(RuntimeError, match="conversion or format spec"):
        tools.validate(
            make(
                effect="read",
                resources=[Resource("github.repo", ["owner", "repo"], template="{owner!r}/{repo}")],
            )
        )


def test_a_resource_with_no_arguments_is_rejected():
    with pytest.raises(RuntimeError, match="no arguments"):
        tools.validate(make(effect="read", resources=[Resource("github.repo", [])]))


def test_the_old_mapping_shape_is_rejected_rather_than_ignored():
    """{arg: type} cannot express composition. Silently accepting it would leave a
    tool looking scoped by a descriptor the checker never reads."""
    with pytest.raises(RuntimeError, match="expected a tools.base.Resource"):
        tools.validate(make(effect="read", resources=[{"repo": "github.repo"}]))


def test_a_single_argument_resource_accepts_a_bare_string_or_a_list():
    assert Resource("github.repo", "repo").args == ("repo",)
    assert Resource("github.repo", ["repo"]).args == ("repo",)


# --- the shipped registry ------------------------------------------------------


def test_every_registered_tool_has_a_valid_descriptor():
    for tool in tools.REGISTRY.values():
        tools.validate(tool)


def test_shipped_descriptors_are_what_the_grants_assume():
    assert tools.get("post_message", TENANT).effect == "write"
    assert tools.get("post_message", TENANT).resources == (
        Resource("chat.channel", "channel"),
    )


def test_a_hand_written_tool_is_the_same_for_every_tenant():
    """Hand-written tools are code, not config. Connector tools are per tenant; these
    deliberately are not."""
    assert tools.get("post_message", "t-acme") is tools.get("post_message", "t-globex")


def test_the_only_hand_written_tool_left_is_one_no_vendor_publishes():
    """`post_message` picks Slack, Discord or a local file from the URL shape — our
    logic, not an API someone else exposes. Anything that IS a wrapper around a
    vendor API belongs in a connector, which is why the GitHub tool was retired."""
    assert set(tools.REGISTRY) == {"post_message"}


def test_connector_tools_are_known_without_being_registered(vetted_github):
    """They are legitimate grant targets before anything has connected, so an agent
    config naming one is validated when saved rather than failing on first run."""
    assert "github_mcp_list_issues" in tools.known_names(TENANT)
    assert tools.get("github_mcp_list_issues", TENANT) is None


def test_a_tenant_that_has_vetted_nothing_knows_only_hand_written_tools():
    """Where every new customer starts. A connector tool is not knowable until that
    tenant vets the server it comes from."""
    assert tools.known_names(TENANT) == frozenset({"post_message"})


# --- the catalogue ---------------------------------------------------------------
#
# `tools.catalogue` is what `GET /tools` and `--list-tools` both answer from. It is
# tested here rather than through either of them because a route test would be testing
# FastAPI, and the thing worth holding in place is that the answer spans BOTH registries
# and needs no server.


def test_the_catalogue_spans_both_registries(vetted_github):
    """The correction that produced this chunk, as an assertion.

    010 named the route `GET /connectors`. `known_names` is `REGISTRY | declared_names`,
    and `agents.validate` accepts a grant naming either — so a catalogue of *connectors*
    cannot describe `post_message`, which is in the grant of `issue-reporter`, the one
    worked example this repo ships.
    """
    named = {
        tool["name"]
        for group in tools.catalogue(TENANT)
        for tool in group["tools"]
    }
    assert named == tools.known_names(TENANT)
    assert {"post_message", "github_mcp_list_issues"} <= named


def test_the_catalogue_says_which_tools_write(vetted_github):
    """The whole point. `post_message` reaches a customer's chat; `list_issues` reads.

    Nothing over HTTP could tell those apart before this, and they are two names in a
    row on the agent detail screen.
    """
    effects = {
        tool["name"]: tool["effect"]
        for group in tools.catalogue(TENANT)
        for tool in group["tools"]
    }
    assert effects["post_message"] == "write"
    assert effects["github_mcp_list_issues"] == "read"
    assert effects["github_mcp_add_issue_comment"] == "write"


def test_the_catalogue_needs_no_server(vetted_github, monkeypatch):
    """Decision 4, asserted rather than asserted-about.

    Descriptions are stored at vetting time precisely so a page about *choosing* a tool
    does not depend on servers being *up*. Anything that connects here fails the test
    loudly rather than passing because Docker happened to be running on the machine.
    """
    def refuse(*_args, **_kwargs):
        raise AssertionError("the catalogue contacted a server")

    monkeypatch.setattr(mcp, "connect", refuse)
    monkeypatch.setattr(mcp, "ensure_session", refuse)
    monkeypatch.setattr(mcp.POOL, "get_or_create", refuse)

    catalogue = tools.catalogue(TENANT)
    described = [
        tool
        for group in catalogue
        for tool in group["tools"]
        if tool["name"] == "github_mcp_list_issues"
    ]
    assert described[0]["description"]


def test_a_connector_tool_carries_its_upstream_name_and_a_builtin_does_not(vetted_github):
    """`name` is what a grant says and what the audit log records; `remote_name` is what
    the vendor's documentation calls it. Only one of the two halves has an upstream, and
    a null says so."""
    by_name = {
        tool["name"]: tool
        for group in tools.catalogue(TENANT)
        for tool in group["tools"]
    }
    assert by_name["github_mcp_list_issues"]["remote_name"] == "list_issues"
    assert by_name["post_message"]["remote_name"] is None


def test_the_catalogue_reports_resource_types_and_nothing_else(vetted_github):
    """Decision 2. `Resource("github.repo", ["owner", "repo"], template=...)` composes
    an identifier out of one server's argument names, and policy never learns that.

    Handing `args` and `template` to a client invites it to build a scope out of
    argument names — the coupling the type exists to prevent, invisible until a second
    connector names the same resource differently."""
    for group in tools.catalogue(TENANT):
        for tool in group["tools"]:
            for ref in tool["resources"]:
                assert set(ref) == {"type"}


def test_builtins_have_no_review_record_and_do_not_invent_one():
    """Empty, not omitted — a client rendering "vetted by" needs one shape — and empty
    rather than "platform", because inventing a reviewer for something nobody reviewed
    is the false assurance `vetted_tools` exists to avoid."""
    builtin = tools.catalogue(TENANT)[0]
    assert builtin["origin"] == "builtin"
    assert builtin["id"] == ""
    assert all(tool["vetted_by"] == "" for tool in builtin["tools"])
    assert all(tool["vetted_at"] == "" for tool in builtin["tools"])


def test_a_tenant_that_has_vetted_nothing_still_gets_the_builtins():
    """Where every new customer starts, and the case decision 5 exists for: the person
    about to create their first agent has no grants and no connectors."""
    catalogue = tools.catalogue(TENANT)
    assert [group["origin"] for group in catalogue] == ["builtin"]
    assert [tool["name"] for tool in catalogue[0]["tools"]] == ["post_message"]


def test_one_tenants_vetting_is_invisible_to_another(vetted_github):
    """The cross-tenant leak the per-tenant registry exists to prevent, seen from the
    catalogue. Two companies both using GitHub is all it takes."""
    storage.active().create_tenant("t-globex", "Globex")
    assert [group["origin"] for group in tools.catalogue("t-globex")] == ["builtin"]


def test_a_note_is_ours_and_a_description_is_the_vendors(vetted_github):
    """Two fields rather than one, because they answer different questions and
    collapsing them loses which of the two you are reading."""
    comment = [
        tool
        for group in tools.catalogue(TENANT)
        for tool in group["tools"]
        if tool["name"] == "github_mcp_add_issue_comment"
    ][0]
    assert comment["description"] == "Add a comment to an issue in a GitHub repository."
    assert "notified" in comment["note"]


# --- families on a resource (step 086) ----------------------------------------------


def test_a_family_declaration_validates():
    tools.validate(
        make(effect="read", resources=[Resource("github.repo", "repo", families=("acme",))])
    )


def test_an_empty_family_is_rejected():
    """`family_of` finds an empty token run inside every identifier, so one scope line
    naming it would admit every model on the connector. `config.model_rates` refuses an
    empty rate key on exactly this argument — this is the same sentence about the same
    shape, one layer over."""
    with pytest.raises(RuntimeError, match="empty family"):
        tools.validate(
            make(effect="read", resources=[Resource("github.repo", "repo", families=("", "x"))])
        )


def test_a_family_carrying_the_pattern_separator_is_rejected():
    """It could never be matched: a family is compared against one whole segment, so a
    scope naming `a/b` would be two segments against a value that is one. A vocabulary
    that can only ever refuse is worse than no vocabulary."""
    with pytest.raises(RuntimeError, match="could never be named"):
        tools.validate(
            make(effect="read", resources=[Resource("github.repo", "repo", families=("a/b",))])
        )


def test_a_family_on_a_composed_resource_is_rejected():
    """The two notions do not overlap. A family is a run of tokens inside a single vendor
    identifier; a composed identifier is segments glued from several arguments, and
    `_identify` already refuses a separator inside a component."""
    composed = Resource(
        "github.repo", ["owner", "repo"], template="{owner}/{repo}", families=("acme",)
    )
    with pytest.raises(RuntimeError, match="composed resource"):
        tools.validate(make(effect="read", resources=[composed]))


def test_the_duplicated_separator_has_not_drifted_from_the_matchers():
    """`tools/` imports nothing from `core/` — the graph runs the other way — so
    `SEGMENT_SEPARATOR` is `patterns.SEPARATOR` written out a second time. That is the
    `credentials.RESERVED_KWARGS` boundary cost paid again, and this is the pin that
    keeps the two copies from disagreeing silently."""
    from carnet.core import patterns
    from carnet.tools import validation

    assert validation.SEGMENT_SEPARATOR == patterns.SEPARATOR


def test_the_matcher_gained_no_rule():
    """**The headline of step 086, as a test.** The fix for a scope that could not name a
    model family is *not* a prefix wildcard: that is the bug `core/patterns.py` exists to
    make inexpressible, and adding it for models would add it for `github.repo` in the
    same function. The identifier gained a second name instead, and this module's surface
    is unchanged."""
    from carnet.core import patterns

    assert sorted(n for n in vars(patterns) if not n.startswith("_") and n.isupper()) == [
        "MANY",
        "ONE",
        "SEPARATOR",
    ]
    assert patterns.matches("claude-haiku-*", "claude-haiku-4-5-20251001") is False
