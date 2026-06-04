"""Regression coverage for shared local-scope name handling."""

from __future__ import annotations

import re

import pytest

from yaraast.shared.local_scope import local_name_variants


def test_local_name_variants_splits_valid_loop_variables() -> None:
    assert local_name_variants("i, j") == {"i", "j"}


@pytest.mark.parametrize("name", ["bad-name", "1bad", "for", "$x"])
def test_local_name_variants_rejects_invalid_identifier_names(name: str) -> None:
    with pytest.raises(ValueError, match=re.escape(f"Invalid local variable identifier: {name}")):
        local_name_variants(name)


def test_local_name_variants_allows_string_identifier_when_requested() -> None:
    assert local_name_variants("$x", allow_string_identifier=True) == {"$x"}
