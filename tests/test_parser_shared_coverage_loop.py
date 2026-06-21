# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests targeting uncovered branches in yaraast/parser/_shared.py.

Missing lines before this file: 83-84, 93-94, 146, 155-156 (94.53% coverage).

Each test exercises exactly one uncovered path using real StringModifier objects
and the public validate_string_modifiers() function, or the private helpers
_validate_xor_modifier_range() and _validate_xor_modifier_value() where the
public surface does not reach a specific internal branch.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.modifiers import StringModifier, StringModifierType
from yaraast.parser._shared import (
    _validate_xor_modifier_range,
    validate_string_modifiers,
)

# ---------------------------------------------------------------------------
# Lines 83-84: xor + base64 combination raises "invalid modifier combination:
#              base64 xor".  The existing tests cover xor+nocase and
#              xor+base64wide but not the xor+base64 branch.
# ---------------------------------------------------------------------------


def test_validate_string_modifiers_rejects_xor_with_base64() -> None:
    """xor combined with base64 must raise ValueError naming the conflict."""
    modifiers = [
        StringModifier(StringModifierType.XOR, None),
        StringModifier(StringModifierType.BASE64, None),
    ]

    with pytest.raises(ValueError, match="invalid modifier combination: base64 xor"):
        validate_string_modifiers(modifiers)


def test_validate_string_modifiers_rejects_base64_with_xor_order_reversed() -> None:
    """Order of modifiers must not affect the xor+base64 conflict detection."""
    modifiers = [
        StringModifier(StringModifierType.BASE64, None),
        StringModifier(StringModifierType.XOR, None),
    ]

    with pytest.raises(ValueError, match="invalid modifier combination: base64 xor"):
        validate_string_modifiers(modifiers)


# ---------------------------------------------------------------------------
# Lines 93-94: base64 + nocase raises "invalid modifier combination:
#              base64 nocase".  The analogous base64wide branch (line 97) is
#              already covered; the base64 branch is not.
# ---------------------------------------------------------------------------


def test_validate_string_modifiers_rejects_base64_with_nocase() -> None:
    """base64 combined with nocase must raise ValueError naming the conflict."""
    modifiers = [
        StringModifier(StringModifierType.BASE64, None),
        StringModifier(StringModifierType.NOCASE, None),
    ]

    with pytest.raises(ValueError, match="invalid modifier combination: base64 nocase"):
        validate_string_modifiers(modifiers)


def test_validate_string_modifiers_rejects_base64wide_with_nocase() -> None:
    """base64wide combined with nocase must raise ValueError naming the conflict."""
    modifiers = [
        StringModifier(StringModifierType.BASE64WIDE, None),
        StringModifier(StringModifierType.NOCASE, None),
    ]

    with pytest.raises(ValueError, match="invalid modifier combination: base64wide nocase"):
        validate_string_modifiers(modifiers)


# ---------------------------------------------------------------------------
# Line 146: the `return` at the end of the valid-string-xor-range branch
# inside _validate_xor_modifier_value().  This line is only reached when the
# caller passes a str containing "-" whose min and max both parse to valid
# byte values and min <= max (i.e. the value is a well-formed xor range).
# The existing tests only exercise the error sub-paths in this branch.
# ---------------------------------------------------------------------------


def test_validate_string_modifiers_accepts_valid_xor_string_range() -> None:
    """A valid ascending xor key range given as a string must be accepted."""
    # StringModifier stores the raw value; validate_string_modifiers reaches
    # _validate_xor_modifier_value which internally exercises the string-range
    # branch up to and including line 146.
    modifier = StringModifier(StringModifierType.XOR, cast(Any, "0-10"))

    # No exception means line 146 was executed.
    validate_string_modifiers([modifier])


def test_validate_string_modifiers_accepts_xor_string_range_full_width() -> None:
    """The maximum valid ascending string xor range 0-255 must be accepted."""
    modifier = StringModifier(StringModifierType.XOR, cast(Any, "0-255"))

    validate_string_modifiers([modifier])


def test_validate_string_modifiers_accepts_xor_hex_string_range() -> None:
    """A hex-encoded ascending xor range expressed as a string must be accepted."""
    modifier = StringModifier(StringModifierType.XOR, cast(Any, "0x00-0xff"))

    validate_string_modifiers([modifier])


def test_validate_string_modifiers_accepts_xor_equal_bounds_string_range() -> None:
    """Equal min and max in a string xor range (e.g. 5-5) must be accepted."""
    modifier = StringModifier(StringModifierType.XOR, cast(Any, "5-5"))

    validate_string_modifiers([modifier])


# ---------------------------------------------------------------------------
# Lines 155-156: _validate_xor_modifier_range() raises TypeError when given a
# tuple whose length is not exactly 2.  validate_string_modifiers() dispatches
# to this helper when the modifier value is a tuple, so the public entry point
# cannot reach the length-check branch through the normal path (the AST always
# stores 2-tuples).  The private helper is therefore tested directly.
# ---------------------------------------------------------------------------


def test_validate_xor_modifier_range_rejects_single_element_tuple() -> None:
    """A one-element tuple must raise TypeError with the expected message."""
    with pytest.raises(TypeError, match="xor range value must contain byte bounds"):
        _validate_xor_modifier_range((1,))


def test_validate_xor_modifier_range_rejects_three_element_tuple() -> None:
    """A three-element tuple must raise TypeError with the expected message."""
    with pytest.raises(TypeError, match="xor range value must contain byte bounds"):
        _validate_xor_modifier_range((0, 10, 20))


def test_validate_xor_modifier_range_rejects_empty_tuple() -> None:
    """An empty tuple must raise TypeError with the expected message."""
    with pytest.raises(TypeError, match="xor range value must contain byte bounds"):
        _validate_xor_modifier_range(())
