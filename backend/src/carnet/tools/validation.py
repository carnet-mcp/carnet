"""Descriptor validation — the rules that keep a policy from looking enforced.

Lives in its own module because two callers need it and they would otherwise form
a cycle: the registry validates hand-written tools at import, and mcp/binding.py
validates the tools it generates from a server's advertisement.

Every rule here catches a descriptor that would read as scoped in review and not be.
That is worse than no descriptor at all, because it is invisible.
"""

import re
from string import Formatter

from .base import Resource, Tool

# `core/patterns.SEPARATOR`, duplicated rather than imported. `tools/` imports nothing
# from `core/` — the layering runs the other way and this module would be the first
# crack in it — so this is the `credentials.RESERVED_KWARGS` boundary cost paid again,
# and it is pinned by a test the same way so the two cannot drift apart silently.
SEGMENT_SEPARATOR = "/"

VALID_EFFECTS = {"read", "write"}

# --- the description (step 077) --------------------------------------------------
#
# `door.py` puts `tool.description` into every `tools/list` answer, read by an
# assistant deciding what to call. Everything above is strong on *structure* and said
# nothing about the prose: a description is a `str`, and it may name a credential, carry
# a control character that breaks a client's rendering, or be large enough to be a
# payload rather than a sentence. These are the mechanical checks — no model invoked,
# nothing about meaning — that evo's `tests/skills` calls level 0 and that cost nothing.
#
# **Empty is allowed, on purpose.** MCP makes `description` optional, `binding.py` binds
# a server's tool with `spec.get("description") or spec.get("title") or ""`, and refusing
# the empty string would make a vendor's undocumented tool vanish from `tools/list` at
# the next bind of a connector that worked yesterday. A missing sentence is the vendor's
# omission; the checks below are about what a present sentence must not be.

# Long enough for a paragraph and a usage note; short enough that nobody smuggles a
# document into a listing every client fetches on connect.
DESCRIPTION_MAX_CHARS = 4000

# Shapes that are a secret and not a sentence. Each is a prefix a real issuer uses, so
# a false positive needs a description that *quotes* a credential's shape, which is the
# thing being refused. Our own token prefix is first.
_SECRET_SHAPES = (
    re.compile(r"\bart_m_[0-9a-f]{8,}\.[A-Za-z0-9_-]{8,}"),  # a Carnet token, whole
    re.compile(r"\bBearer\s+[A-Za-z0-9_\-.]{20,}"),  # a header with a real value in it
    re.compile(r"\b(?:sk|rk)-[A-Za-z0-9_-]{20,}"),  # OpenAI / Anthropic-shaped keys
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),  # GitHub tokens
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),  # Slack tokens
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key ids
)

# Tabs and newlines are prose; everything else below 0x20, and DEL, is not.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _validate_description(tool: Tool) -> None:
    text = tool.description
    if not isinstance(text, str):
        raise RuntimeError(
            f"tool '{tool.name}' has a description that is not text ({type(text).__name__})."
        )
    if len(text) > DESCRIPTION_MAX_CHARS:
        raise RuntimeError(
            f"tool '{tool.name}' has a {len(text)}-character description; the limit is "
            f"{DESCRIPTION_MAX_CHARS}. Every client fetches every description on connect, "
            "and a document belongs in a `note`, not in the listing."
        )
    if _CONTROL.search(text):
        raise RuntimeError(
            f"tool '{tool.name}' has a control character in its description. Tabs and "
            "newlines are fine; anything else is not prose and some clients render it."
        )
    for shape in _SECRET_SHAPES:
        if shape.search(text):
            raise RuntimeError(
                f"tool '{tool.name}' has what looks like a credential in its description. "
                "A description is sent to every assistant that connects; a secret in it "
                "is a secret published. Refused whatever it turns out to be."
            )

# Whose account a call goes out as — see `base.Identity` for what each value means and
# why the pair is duplicated in `core/credentials.py` rather than shared.
VALID_IDENTITIES = {"service", "user"}


def validate(tool: Tool) -> None:
    """Check a tool's descriptor. Raises — a bad descriptor is a hole.

    The argument-existence rule is the one that matters most: a `Resource` naming an
    argument the schema doesn't have produces a constraint that can never fire, so the
    tool reads as scoped and isn't.

    Written for hand-authored tools, where such a failure is a typo. Against an MCP
    server it does more: it is what catches a connector renaming `repo` to `repository`
    in a later version and silently unhooking our scoping from the argument it was
    written against.
    """
    if tool.effect not in VALID_EFFECTS:
        raise RuntimeError(
            f"tool '{tool.name}' declares effect '{tool.effect}'; "
            f"expected one of {sorted(VALID_EFFECTS)}"
        )

    # Fail-closed like an unknown launch kind: guessing whose account an unrecognised
    # identity means would be guessing at a security posture.
    if tool.identity not in VALID_IDENTITIES:
        raise RuntimeError(
            f"tool '{tool.name}' declares identity '{tool.identity}'; "
            f"expected one of {sorted(VALID_IDENTITIES)}"
        )

    _validate_description(tool)

    properties = tool.input_schema.get("properties", {})
    for ref in tool.resources:
        _validate_resource(tool, ref, properties)

    # Step 045c. A redaction naming an argument the schema does not have is a policy
    # that reads as applied and is not — `_validate_resource`'s argument-existence rule,
    # at the other end of the same descriptor and for the same reason. It matters more
    # here, because the failure is silent in the safe-looking direction: somebody vets a
    # model tool with `--redact-arg mesages`, the form accepts it, and every prompt is
    # written to an append-only log by a tool whose record says it hides them.
    #
    # Against an MCP server this is also the drift check: a vendor renaming `messages`
    # unhooks the redaction from the argument it was written against, and this is where
    # that stops being invisible.
    for arg_name in sorted(tool.redact_args):
        if arg_name not in properties:
            raise RuntimeError(
                f"tool '{tool.name}' redacts argument '{arg_name}', which is not in "
                "its input_schema. A redaction for an argument that never arrives "
                "silently never applies, and the record would say the value is hidden "
                "while the log holds it in the clear."
            )

    if tool.effect == "write" and not tool.resources:
        raise RuntimeError(
            f"tool '{tool.name}' is a write but declares no resources. "
            "A write to something policy cannot name is unscopeable — give it a "
            "resource, or mark it read if it genuinely changes nothing."
        )


def _validate_resource(tool: Tool, ref, properties: dict) -> None:
    """Check one Resource declaration against the tool's schema."""
    if not isinstance(ref, Resource):
        raise RuntimeError(
            f"tool '{tool.name}' declares a resource of type {type(ref).__name__}; "
            "expected a tools.base.Resource. The old {arg: type} mapping cannot "
            "express an identifier composed from several arguments — see Resource."
        )

    if not isinstance(ref.type, str) or not ref.type:
        raise RuntimeError(f"tool '{tool.name}' declares a resource with no type")

    if not ref.args:
        raise RuntimeError(
            f"tool '{tool.name}' declares resource '{ref.type}' with no arguments. "
            "A resource nothing identifies cannot be scoped."
        )

    for arg_name in ref.args:
        if arg_name not in properties:
            raise RuntimeError(
                f"tool '{tool.name}' maps argument '{arg_name}' to resource type "
                f"'{ref.type}', but '{arg_name}' is not in its input_schema. "
                "A constraint on an argument that never arrives silently never applies."
            )

    if len(ref.args) > 1 and ref.template is None:
        raise RuntimeError(
            f"tool '{tool.name}' composes resource '{ref.type}' from "
            f"{list(ref.args)} but gives no template. Joining several arguments into "
            'one identifier without a stated shape is a guess — say "{owner}/{repo}".'
        )

    if ref.template is not None:
        _validate_template(tool, ref)

    _validate_families(tool, ref)


def _validate_families(tool: Tool, ref) -> None:
    """A declared family must be a name a scope line could actually carry. Step 086.

    Three refusals, all at vet time, all in the direction of *a policy that reads as
    written and is not*:

      - a blank family, which `family_of` would find in every id and so would make one
        scope line mean every model. `config.model_rates` refuses an empty rate key on
        exactly this argument — "a substring of every id" — and this is the same
        sentence about the same shape.
      - a family containing the pattern separator, which could never be matched: the
        family is compared against one whole segment, and a scope naming `a/b` would
        be two segments against a value that is one.
      - a family on a **composed** resource. A family is a run of tokens inside a
        single-segment vendor id; a composed identifier is segments glued from several
        arguments, and `_identify` already refuses a separator inside a component. The
        two notions do not overlap, and a family declared on one would be a vocabulary
        nothing could ever derive.
    """
    if not ref.families:
        return

    if ref.template is not None:
        raise RuntimeError(
            f"tool '{tool.name}' declares families {list(ref.families)} on composed "
            f"resource '{ref.type}'. A family is a run of tokens inside a single "
            "vendor identifier; a composed identifier is segments glued from several "
            "arguments, and nothing would ever derive one."
        )

    for family in ref.families:
        if not isinstance(family, str) or not family.strip():
            raise RuntimeError(
                f"tool '{tool.name}' declares an empty family on resource "
                f"'{ref.type}'. An empty family is a run of tokens inside every "
                "identifier, so one scope line naming it would admit every one of "
                "them."
            )
        if SEGMENT_SEPARATOR in family:
            raise RuntimeError(
                f"tool '{tool.name}' declares family '{family}' on resource "
                f"'{ref.type}', which contains '{SEGMENT_SEPARATOR}'. A family is "
                "matched as one whole segment, so this one could never be named by a "
                "scope line that matched anything."
            )


def _validate_template(tool: Tool, ref) -> None:
    """A template must name exactly the declared arguments, and nothing fancier.

    A placeholder outside `args` would raise mid-check on a real call; a declared
    argument the template ignores is a value that quietly stops constraining anything.
    Conversions and format specs are refused because `{owner!r}` composes an
    identifier with quotes in it — wrong in a way no test of the happy path notices.
    """
    named = set()
    for _literal, field_name, format_spec, conversion in Formatter().parse(ref.template):
        if field_name is None:
            continue
        if conversion is not None or format_spec:
            raise RuntimeError(
                f"tool '{tool.name}': template '{ref.template}' for resource "
                f"'{ref.type}' uses a conversion or format spec. A resource "
                "identifier must be its arguments verbatim."
            )
        if not field_name.isidentifier():
            raise RuntimeError(
                f"tool '{tool.name}': template '{ref.template}' for resource "
                f"'{ref.type}' has placeholder '{field_name}'; only plain argument "
                "names are allowed."
            )
        named.add(field_name)

    if named != set(ref.args):
        raise RuntimeError(
            f"tool '{tool.name}': template '{ref.template}' for resource '{ref.type}' "
            f"names {sorted(named)} but the resource declares {sorted(ref.args)}. "
            "These must match exactly — an unnamed argument constrains nothing, and "
            "an undeclared placeholder fails at call time."
        )
