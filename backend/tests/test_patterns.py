"""Resource pattern matching.

Weighted heavily toward the adversarial cases: prefix confusion is where scoping
models get broken, and this matcher's whole reason for comparing segment-wholes is to
make that class of bug unrepresentable. These tests are what says so out loud.
"""

import pytest

from carnet.core.patterns import PatternError, matches, matches_any, validate

# --- prefix confusion: the cases that matter ---------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "org-evil/repo",  # the classic: startswith("org") would pass this
        "orgx/repo",
        "org2/repo",
        "notorg/repo",
    ],
)
def test_single_star_never_matches_a_different_first_segment(value):
    assert matches("org/*", value) is False


def test_single_star_does_not_reach_into_deeper_paths():
    assert matches("org/*", "org/a/b") is False


def test_single_star_requires_the_segment_to_exist():
    assert matches("org/*", "org") is False


def test_a_longer_value_does_not_match_a_shorter_exact_pattern():
    assert matches("org/repo", "org/repo/extra") is False


def test_partial_segment_text_does_not_match():
    assert matches("org/repo", "org/repo-x") is False


# --- the syntax that should work ---------------------------------------------


def test_exact_match():
    assert matches("anthropics/sdk", "anthropics/sdk") is True


def test_single_star_matches_one_segment():
    assert matches("anthropics/*", "anthropics/sdk") is True


def test_double_star_matches_multiple_segments():
    assert matches("project/**", "project/42/board/7") is True


def test_double_star_matches_a_single_segment_too():
    assert matches("project/**", "project/42") is True


def test_double_star_requires_at_least_one_segment():
    """'project/**' is a grant over things *under* project, not project itself."""
    assert matches("project/**", "project") is False


def test_bare_double_star_matches_anything():
    assert matches("**", "a/b/c") is True
    assert matches("**", "eng") is True


def test_separatorless_identifiers_work():
    """Not every resource is hierarchical — channels, ids, and GUIDs are flat."""
    assert matches("#eng", "#eng") is True
    assert matches("#eng", "#random") is False
    assert matches("*", "#eng") is True


def test_numeric_identifiers_compare_as_strings():
    assert matches("42", "42") is True
    assert matches("4", "42") is False


# --- malformed patterns fail loudly ------------------------------------------


def test_double_star_is_rejected_in_non_final_position():
    with pytest.raises(PatternError, match="final segment"):
        validate("org/**/repo")


def test_matching_also_rejects_a_malformed_pattern():
    """A bad pattern must never silently degrade to 'matches nothing'."""
    with pytest.raises(PatternError):
        matches("a/**/b", "a/x/b")


@pytest.mark.parametrize("bad", ["", None, 42])
def test_empty_and_non_string_patterns_are_rejected(bad):
    with pytest.raises(PatternError):
        validate(bad)


# --- matches_any --------------------------------------------------------------


def test_matches_any_is_a_disjunction():
    assert matches_any(["a/b", "c/*"], "c/d") is True
    assert matches_any(["a/b", "c/*"], "e/f") is False
    assert matches_any([], "anything") is False
