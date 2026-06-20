"""Coverage for string-reference identifier and wildcard validation."""

from __future__ import annotations

import pytest

from yaraast.string_references import (
    validate_string_identifier_text,
    validate_string_wildcard_text,
)


def test_validate_string_identifier_text_normalizes_and_placeholder() -> None:
    assert validate_string_identifier_text("$abc") == "$abc"
    assert validate_string_identifier_text("abc") == "$abc"
    assert validate_string_identifier_text("$", allow_placeholder=True) == "$"


@pytest.mark.parametrize("bad", ["$1!", "$"])
def test_validate_string_identifier_text_rejects_invalid(bad: str) -> None:
    with pytest.raises(ValueError, match="Invalid string identifier"):
        validate_string_identifier_text(bad)


def test_validate_string_identifier_text_rejects_non_string() -> None:
    with pytest.raises(TypeError, match="must be a string"):
        validate_string_identifier_text(123)


def test_validate_string_wildcard_text_variants() -> None:
    assert validate_string_wildcard_text("$a*") == "$a*"
    assert validate_string_wildcard_text("$*") == "$*"
    assert validate_string_wildcard_text("pre*") == "$pre*"


def test_validate_string_wildcard_text_rejects_invalid() -> None:
    with pytest.raises(ValueError, match="Invalid string wildcard"):
        validate_string_wildcard_text("$bad!*")
    with pytest.raises(TypeError, match="must be a string"):
        validate_string_wildcard_text(123)
