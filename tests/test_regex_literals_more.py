"""Additional tests for regex literal helpers."""

from __future__ import annotations

import pytest

from yaraast.regex_literals import validate_regex_pattern


def test_validate_regex_pattern_rejects_empty_pattern() -> None:
    with pytest.raises(ValueError, match="Invalid regex pattern: empty pattern"):
        validate_regex_pattern("")


def test_validate_regex_pattern_accepts_non_empty_pattern() -> None:
    validate_regex_pattern("ab.*")


@pytest.mark.parametrize("pattern", ["{,}", "({,})", "a|{,}", "^{,}", "${,}"])
def test_validate_regex_pattern_rejects_empty_repeat_without_atom(pattern: str) -> None:
    with pytest.raises(ValueError, match="Invalid regex pattern: syntax error"):
        validate_regex_pattern(pattern)


@pytest.mark.parametrize("pattern", ["a{,}", ".{,}", "[a]{,}", ".{,}?", r"\{,\}"])
def test_validate_regex_pattern_allows_empty_repeat_quantifier(pattern: str) -> None:
    validate_regex_pattern(pattern)


@pytest.mark.parametrize("pattern", ["a{,}*", ".{,}+", ".{,}{1}", "c.{,}*$22"])
def test_validate_regex_pattern_rejects_repeated_empty_repeat_quantifier(pattern: str) -> None:
    with pytest.raises(ValueError, match="Invalid regex pattern: syntax error"):
        validate_regex_pattern(pattern)


@pytest.mark.parametrize(
    "pattern",
    ["a*?b+", "a*b+?", "a?b??", "a{1}?b*", "a{1}b*?", "2*1*?"],
)
def test_validate_regex_pattern_rejects_mixed_greedy_and_ungreedy_quantifiers(
    pattern: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="Invalid regex pattern: greedy and ungreedy quantifiers can't be mixed",
    ):
        validate_regex_pattern(pattern)


@pytest.mark.parametrize("pattern", ["a*b+", "a*?b+?", "a??b??", "a{1}?b*?"])
def test_validate_regex_pattern_allows_consistent_quantifier_greediness(pattern: str) -> None:
    validate_regex_pattern(pattern)
