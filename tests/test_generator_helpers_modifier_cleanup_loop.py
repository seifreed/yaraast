# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests for the simplified string-modifier formatting helpers.

Dead branches were removed from ``generator_helpers``:
  - ``format_modifier`` only ever sees value-bearing modifiers that are
    ``xor``/``base64``/``base64wide`` (``_validate_string_modifier_value``
    rejects values for every other modifier), so the tuple/str/int fallback
    branches were unreachable.
  - ``format_modifiers`` and ``split_regex_modifiers`` had a redundant
    ``isinstance(modifiers, list | tuple)`` check after
    ``_validate_string_modifier_collection`` already guarantees that type.

These tests pin the behaviour that survived the cleanup.
"""

from __future__ import annotations

import pytest

from yaraast.ast.modifiers import StringModifier, StringModifierType
from yaraast.codegen.generator_helpers import (
    format_modifier,
    format_modifiers,
    split_regex_modifiers,
)

_BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def test_format_modifier_xor_value() -> None:
    assert format_modifier(StringModifier(StringModifierType.XOR, 16)) == "xor(16)"


def test_format_modifier_base64_value() -> None:
    result = format_modifier(StringModifier(StringModifierType.BASE64, _BASE64_ALPHABET))
    assert result.startswith("base64(")


def test_format_modifier_valueless_returns_name() -> None:
    assert format_modifier(StringModifier(StringModifierType.NOCASE, None)) == "nocase"


@pytest.mark.parametrize(
    "modifier_type",
    [StringModifierType.NOCASE, StringModifierType.WIDE, StringModifierType.FULLWORD],
)
def test_format_modifier_value_on_nonparam_modifier_raises(
    modifier_type: StringModifierType,
) -> None:
    # A value on a non-parameterized modifier is rejected before any
    # value-formatting branch can run (proving those branches are dead).
    with pytest.raises(ValueError, match="does not accept a value"):
        format_modifier(StringModifier(modifier_type, (1, 2)))


def test_format_modifiers_list() -> None:
    mods = [
        StringModifier(StringModifierType.NOCASE, None),
        StringModifier(StringModifierType.WIDE, None),
    ]
    assert format_modifiers(mods) == " nocase wide"


def test_format_modifiers_empty_returns_empty() -> None:
    assert format_modifiers([]) == ""


def test_format_modifiers_non_collection_raises() -> None:
    with pytest.raises(TypeError, match="must be a list or tuple"):
        format_modifiers("nocase")


def test_split_regex_modifiers_list() -> None:
    suffix, spaced = split_regex_modifiers([StringModifier(StringModifierType.NOCASE, None)])
    assert suffix == ""
    assert spaced == ["nocase"]


def test_split_regex_modifiers_non_collection_raises() -> None:
    with pytest.raises(TypeError, match="must be a list or tuple"):
        split_regex_modifiers(42)
