# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests targeting uncovered lines in FluentStringBuilder.

Missing lines before this file (95.04 %):
  188-189  _coerce_xor_key: path for non-bool, non-str, non-int value
  305-306  _validate_jump_bounds: max_bytes is negative
  308-309  _validate_jump_bounds: min_bytes exceeds LIBYARA_HEX_JUMP_MAX
  440      _parse_hex_pattern: HexParseError with position re-raised as ValidationError
  449-451  _parse_nibble: ValueError on non-hex character in nibble string
"""

from __future__ import annotations

import pytest

from yaraast.builder.fluent_string_builder import FluentStringBuilder
from yaraast.errors import ValidationError
from yaraast.limits import LIBYARA_HEX_JUMP_MAX

# ---------------------------------------------------------------------------
# Lines 188-189: _coerce_xor_key — float reaches the isinstance guard
# ---------------------------------------------------------------------------


def test_xor_float_key_raises_type_error() -> None:
    """A float is not bool, not str, and not int, so _coerce_xor_key must
    raise TypeError on lines 188-189 after the str-conversion attempt.

    The method signature accepts int | str; a float is outside that union
    and must be rejected with a descriptive message rather than silently
    truncated.
    """
    with pytest.raises(TypeError, match="Invalid XOR key value"):
        FluentStringBuilder("$s4").literal("hello").xor(3.14)  # type: ignore[arg-type]


def test_xor_list_key_raises_type_error() -> None:
    """A list is likewise not a valid XOR key type."""
    with pytest.raises(TypeError, match="Invalid XOR key value"):
        FluentStringBuilder("$s5").literal("hello").xor([0x01])  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Lines 305-306: _validate_jump_bounds — max_bytes is negative
# ---------------------------------------------------------------------------


def test_jump_pattern_negative_max_raises_validation_error() -> None:
    """jump_pattern(0, -1) must trigger the max_bytes < 0 branch (lines 305-306).

    The check order in _validate_jump_bounds is:
      1. min < 0
      2. max < 0   <- this test hits here
      3. min > LIBYARA_HEX_JUMP_MAX
      4. max > LIBYARA_HEX_JUMP_MAX
      5. min > max

    A call with min=0 and max=-1 bypasses the first guard and hits the second.
    """
    with pytest.raises(ValidationError, match="Jump maximum must be non-negative"):
        FluentStringBuilder("$s6").jump_pattern(0, -1)


def test_jump_pattern_negative_max_message_includes_value() -> None:
    """The error message must contain the offending value."""
    with pytest.raises(ValidationError, match="-2"):
        FluentStringBuilder("$s7").jump_pattern(0, -2)


# ---------------------------------------------------------------------------
# Lines 308-309: _validate_jump_bounds — min_bytes exceeds LIBYARA_HEX_JUMP_MAX
# ---------------------------------------------------------------------------


def test_jump_pattern_min_exceeds_max_constant_raises_validation_error() -> None:
    """jump_pattern(MAX+1, MAX+1) hits the min > LIBYARA_HEX_JUMP_MAX branch
    (lines 307-309) before the max > LIBYARA_HEX_JUMP_MAX branch.

    Both values are identical and both exceed the limit, but the min check
    is tested first in the source, so the error message specifically names
    the minimum bound.
    """
    overflow = LIBYARA_HEX_JUMP_MAX + 1
    with pytest.raises(ValidationError, match="Jump minimum must not exceed"):
        FluentStringBuilder("$s8").jump_pattern(overflow, overflow)


def test_jump_pattern_min_exceeds_max_constant_error_mentions_limit() -> None:
    """Error message must include the LIBYARA_HEX_JUMP_MAX value."""
    overflow = LIBYARA_HEX_JUMP_MAX + 1
    with pytest.raises(ValidationError, match=str(LIBYARA_HEX_JUMP_MAX)):
        FluentStringBuilder("$s9").jump_pattern(overflow, overflow)
