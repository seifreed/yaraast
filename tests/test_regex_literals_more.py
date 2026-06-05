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


@pytest.mark.parametrize("pattern", ["a{,}", ".{,}", "[a]{,}", r"\{,\}"])
def test_validate_regex_pattern_allows_literal_empty_repeat_text(pattern: str) -> None:
    validate_regex_pattern(pattern)
