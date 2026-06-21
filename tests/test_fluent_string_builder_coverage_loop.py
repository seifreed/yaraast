# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests targeting uncovered lines in FluentStringBuilder.

Missing lines before this file (95.04 %):
  106-107  hex_builder: wrong return type from callback
  188-189  _coerce_xor_key: path for non-bool, non-str, non-int value
  305-306  _validate_jump_bounds: max_bytes is negative
  308-309  _validate_jump_bounds: min_bytes exceeds LIBYARA_HEX_JUMP_MAX
  381      _hex_tokens_for_build: defensive fallback returning empty list
  440      _parse_hex_pattern: HexParseError with position re-raised as ValidationError
  449-451  _parse_nibble: ValueError on non-hex character in nibble string
"""

from __future__ import annotations

import pytest

from yaraast.ast.strings import HexString
from yaraast.builder.fluent_string_builder import FluentStringBuilder
from yaraast.builder.hex_string_builder import HexStringBuilder
from yaraast.errors import ValidationError
from yaraast.limits import LIBYARA_HEX_JUMP_MAX

# ---------------------------------------------------------------------------
# Lines 106-107: hex_builder callback returns a non-HexStringBuilder value
# ---------------------------------------------------------------------------


def test_hex_builder_wrong_return_type_raises_type_error() -> None:
    """hex_builder must reject a callback that returns something other than
    HexStringBuilder or None.

    The callback bypasses the None-branch check and hits the isinstance guard
    on lines 105-107.
    """
    with pytest.raises(TypeError, match="Hex builder callback must return HexStringBuilder"):
        FluentStringBuilder("$s1").hex_builder(lambda b: "not_a_builder")  # type: ignore[return-value, arg-type]


def test_hex_builder_wrong_return_integer_raises_type_error() -> None:
    """Same guard fires for an integer return value."""
    with pytest.raises(TypeError, match="Hex builder callback must return HexStringBuilder"):
        FluentStringBuilder("$s2").hex_builder(lambda b: 42)  # type: ignore[return-value, arg-type]


def test_hex_builder_implicit_none_return_uses_mutated_builder() -> None:
    """Callback that returns None implicitly should fall back to the builder
    object itself (lines 103-104 branch), producing a valid HexString.

    This test also verifies that the lines 103-104 branch executes correctly
    by confirming the built AST node contains exactly the bytes added inside
    the callback.
    """

    def populate(builder: HexStringBuilder) -> None:
        builder.byte(0x4D).byte(0x5A)

    result = FluentStringBuilder("$s3").hex_builder(populate).build()
    assert isinstance(result, HexString)
    assert len(result.tokens) == 2


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


# ---------------------------------------------------------------------------
# Line 381: _hex_tokens_for_build — defensive fallback for non-list _content
# ---------------------------------------------------------------------------


def test_hex_tokens_for_build_returns_empty_list_when_content_is_not_list() -> None:
    """_hex_tokens_for_build has a defensive else-branch (line 381) that
    returns an empty list when _content is not a list[HexToken].

    This path is structurally unreachable through the public API: every
    method that sets _string_type='hex' also assigns a list to _content.
    The branch exists as a runtime safety net. We exercise it by directly
    manipulating private state on a real FluentStringBuilder instance, which
    is preferable to leaving the line unmeasured.
    """
    builder = FluentStringBuilder("$s10")
    builder._content = "not_a_list"  # deliberate private access for coverage
    builder._string_type = "hex"

    tokens = builder._hex_tokens_for_build()
    assert tokens == []


# ---------------------------------------------------------------------------
# Line 440: _parse_hex_pattern — HexParseError with position re-raised as
#           ValidationError
# ---------------------------------------------------------------------------


def test_hex_pattern_with_invalid_character_raises_validation_error() -> None:
    """_parse_hex_pattern must convert a HexParseError that carries a position
    into a ValidationError (line 440).

    'ZZ' is not valid hex; the parser raises HexParseError with position=0,
    which does not match the empty-string sentinel, so the except clause
    re-raises it as ValidationError.
    """
    with pytest.raises(ValidationError, match="Hex parse error at position"):
        FluentStringBuilder("$s11").hex("ZZ")


def test_hex_pattern_with_invalid_character_preserves_message() -> None:
    """The ValidationError message must contain the offending character."""
    with pytest.raises(ValidationError, match="Invalid character in hex string: Q"):
        FluentStringBuilder("$s12").hex("QQ")


def test_hex_pattern_empty_string_guard_returns_empty_token_list() -> None:
    """An empty hex pattern raises HexParseError with position=None and the
    canonical message 'Hex parse error: Empty hex string'.

    The if-guard on lines 438-440 intercepts this case and returns an empty
    list to the caller rather than propagating a ValidationError from the
    hex parser.  We validate the guard by inspecting _content directly after
    calling hex(), confirming it is an empty list rather than an exception.

    The subsequent call to build() is expected to fail because
    validate_hex_tokens_for_builder rejects an empty token sequence; that
    failure is distinct from the parse guard under test.
    """
    builder = FluentStringBuilder("$s_empty")
    builder.hex("")
    # The parse guard on line 439-440 stored an empty list, not a parse error.
    assert builder._content == []
    # build() then rejects the empty sequence at the validation layer.
    with pytest.raises(ValidationError):
        builder.build()


# ---------------------------------------------------------------------------
# Lines 449-451: _parse_nibble — ValueError for invalid hex digit in nibble
# ---------------------------------------------------------------------------


def test_hex_bytes_nibble_low_invalid_digit_raises_validation_error() -> None:
    """hex_bytes with '?G' produces a nibble string '?G' passed to _parse_nibble.

    Inside _parse_nibble, int('G', 16) raises ValueError, which is caught
    and re-raised as ValidationError on lines 449-451.
    """
    with pytest.raises(ValidationError, match="Invalid nibble pattern"):
        FluentStringBuilder("$s13").hex_bytes("?G")


def test_hex_bytes_nibble_high_invalid_digit_raises_validation_error() -> None:
    """hex_bytes with 'G?' exercises the high-nibble path in _parse_nibble.

    two_char[0] != '?' so the else-branch tries int('G', 16), which fails
    and produces the same ValidationError on lines 449-451.
    """
    with pytest.raises(ValidationError, match="Invalid nibble pattern"):
        FluentStringBuilder("$s14").hex_bytes("G?")


def test_hex_bytes_nibble_error_message_contains_pattern() -> None:
    """The ValidationError message must identify the invalid pattern."""
    with pytest.raises(ValidationError, match=r"Invalid nibble pattern: \?Z"):
        FluentStringBuilder("$s15").hex_bytes("?z")
