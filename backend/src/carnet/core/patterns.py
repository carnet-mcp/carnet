"""Resource pattern matching. One function, deliberately small.

Scoping models get broken at the matcher. The classic failure is prefix confusion —
a policy for `org/*` quietly also matching `org-evil/repo`, because someone reached
for `str.startswith`. This implementation compares **whole segments**, so that class
of bug isn't a case to remember; it's not expressible.

Syntax, splitting both pattern and value on "/":

    exact       "anthropics/sdk"   matches only itself
    "*"         "org/*"            exactly one whole segment
    "**"        "org/**"           one or more remaining segments; final position only

Segment counts must agree unless the pattern ends in "**".

Deliberately NOT regex. Anchoring mistakes and catastrophic backtracking are a poor
trade for expressiveness in a security check that runs on every tool call.

Matching is case-sensitive. Normalizing identifiers (GitHub's case-insensitive repo
names, Slack's lowercase channels) is a connector-vetting concern, not the matcher's.
"""

SEPARATOR = "/"
ONE = "*"
MANY = "**"


class PatternError(ValueError):
    """A malformed pattern. Raised at config load, never at call time."""


def validate(pattern: str) -> None:
    """Raise PatternError if `pattern` is malformed.

    Called when agent configs are loaded so a bad pattern fails at import rather than
    silently never matching — a policy that can't match is a policy that denies
    everything, which is safe but very confusing at 3am.
    """
    if not isinstance(pattern, str) or not pattern:
        raise PatternError(f"pattern must be a non-empty string, got {pattern!r}")

    segments = pattern.split(SEPARATOR)
    for i, segment in enumerate(segments):
        if segment == MANY and i != len(segments) - 1:
            raise PatternError(
                f"'{MANY}' is only valid as the final segment: {pattern!r}. "
                f"Use '{ONE}' to match a single segment."
            )


def matches(pattern: str, value: str) -> bool:
    """True if `value` falls within `pattern`.

    Raises PatternError on a malformed pattern rather than failing closed silently.
    """
    validate(pattern)

    p = pattern.split(SEPARATOR)
    v = value.split(SEPARATOR)

    for i, segment in enumerate(p):
        if segment == MANY:
            # Final by construction (validate() enforced it). Requires at least one
            # remaining segment, so "org/**" does not match a bare "org".
            return len(v) > i

        if i >= len(v):
            return False  # pattern is longer than the value

        if segment != ONE and segment != v[i]:
            return False

    return len(v) == len(p)


def matches_any(patterns, value: str) -> bool:
    """True if any pattern admits `value`."""
    return any(matches(p, value) for p in patterns)
