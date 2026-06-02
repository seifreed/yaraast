from __future__ import annotations

import pytest

from yaraast.string_references import normalize_string_reference_id


@pytest.mark.parametrize("value", ["", "   ", "$", "$   "])
def test_normalize_string_reference_id_rejects_empty_or_whitespace_body(value: str) -> None:
    with pytest.raises(ValueError, match="Invalid string reference"):
        normalize_string_reference_id(value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("a", "$a"),
        ("$a", "$a"),
        ("a_1", "$a_1"),
        ("a*", "$a*"),
        ("$a*", "$a*"),
        ("*", "$*"),
        ("$*", "$*"),
    ],
)
def test_normalize_string_reference_id_accepts_valid_references(
    value: str,
    expected: str,
) -> None:
    assert normalize_string_reference_id(value) == expected


@pytest.mark.parametrize("value", ["a*", "$a*", "*", "$*"])
def test_normalize_string_reference_id_rejects_wildcards_when_disabled(
    value: str,
) -> None:
    with pytest.raises(ValueError, match="Invalid string reference"):
        normalize_string_reference_id(value, allow_wildcard=False)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("a", "$a"),
        ("$a", "$a"),
        ("a_1", "$a_1"),
    ],
)
def test_normalize_string_reference_id_accepts_concrete_references_without_wildcards(
    value: str,
    expected: str,
) -> None:
    assert normalize_string_reference_id(value, allow_wildcard=False) == expected
