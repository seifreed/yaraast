"""Regression coverage for shared local-scope name handling."""

from __future__ import annotations

import re

import pytest

from yaraast.shared.local_scope import local_name_variants


def test_local_name_variants_splits_valid_loop_variables() -> None:
    assert local_name_variants("i, j") == {"i", "j"}


def test_local_name_variants_allows_contextual_keyword_loop_variables() -> None:
    assert local_name_variants("as, include") == {"as", "include"}


@pytest.mark.parametrize("name", ["", "   "])
def test_local_name_variants_rejects_empty_declaration(name: str) -> None:
    with pytest.raises(ValueError, match="Local variable name must not be empty"):
        local_name_variants(name)


@pytest.mark.parametrize("name", ["i,,j", ",i", "i,"])
def test_local_name_variants_rejects_empty_declaration_parts(name: str) -> None:
    with pytest.raises(
        ValueError,
        match=re.escape(f"Local variable declaration must not contain empty entries: {name}"),
    ):
        local_name_variants(name)


@pytest.mark.parametrize("name", ["bad-name", "1bad", "for", "$x"])
def test_local_name_variants_rejects_invalid_identifier_names(name: str) -> None:
    with pytest.raises(ValueError, match=re.escape(f"Invalid local variable identifier: {name}")):
        local_name_variants(name)


def test_local_name_variants_allows_string_identifier_when_requested() -> None:
    assert local_name_variants("$x", allow_string_identifier=True) == {"$x"}
