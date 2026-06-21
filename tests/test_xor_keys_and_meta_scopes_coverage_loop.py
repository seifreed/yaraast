# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage loop: exercises every uncovered branch in yaraast/xor_keys.py
and yaraast/serialization/meta_scopes.py.

Missing lines targeted (from term-missing report before this file):

  xor_keys.py       -- 13 (empty-string returns None)
                     -- 18 (0x prefix with empty/invalid digits returns None)
                     -- 20 (pure decimal digits returns int)

  meta_scopes.py    -- 13-18 (serialize_meta_scope: str path, valid str, invalid
                               str raises SerializationError, non-str raises)
                     -- 23-29 (deserialize_meta_scope: None pass-through, valid
                               scope returns value, invalid scope raises)
"""

from __future__ import annotations

import pytest

from yaraast.ast.modifiers import MetaScope
from yaraast.errors import SerializationError
from yaraast.serialization.meta_scopes import (
    deserialize_meta_scope,
    serialize_meta_scope,
)
from yaraast.xor_keys import parse_xor_key_text

# ---------------------------------------------------------------------------
# parse_xor_key_text — yaraast/xor_keys.py
# ---------------------------------------------------------------------------


class TestParseXorKeyTextEmptyInput:
    """Line 13: empty string (or whitespace-only) must return None."""

    def test_empty_string_returns_none(self) -> None:
        # Arrange: value strips to empty
        # Act
        result = parse_xor_key_text("")
        # Assert
        assert result is None

    def test_whitespace_only_returns_none(self) -> None:
        # Arrange: only spaces; text.strip() == ""
        result = parse_xor_key_text("   ")
        assert result is None

    def test_tab_whitespace_returns_none(self) -> None:
        result = parse_xor_key_text("\t\n")
        assert result is None


class TestParseXorKeyTextHexPrefix:
    """Lines 14-18: 0x-prefixed inputs.

    Valid hex digits -> int (line 17, covered by other tests).
    Empty digits or non-hex chars -> None (line 18, previously uncovered).
    """

    def test_bare_0x_prefix_no_digits_returns_none(self) -> None:
        # Arrange: "0x" with nothing after — digits == "", falsy branch of
        # `if digits and all(...)` short-circuits to False → line 18.
        result = parse_xor_key_text("0x")
        assert result is None

    def test_0x_with_invalid_hex_char_returns_none(self) -> None:
        # Arrange: "0xGG" — digits == "GG", all(...) fails → line 18.
        result = parse_xor_key_text("0xGG")
        assert result is None

    def test_0x_with_mixed_valid_and_invalid_chars_returns_none(self) -> None:
        # "0x1G" — 'G' is not in _HEX_DIGITS → line 18.
        result = parse_xor_key_text("0x1G")
        assert result is None

    def test_0x_with_space_in_digits_returns_none(self) -> None:
        # "0x 1" — space is not a hex digit → line 18.
        result = parse_xor_key_text("0x 1")
        assert result is None

    def test_valid_hex_lowercase_returns_int(self) -> None:
        # Sanity: valid lowercase hex digits → int (line 17, confirming
        # the happy path still works after our new tests).
        result = parse_xor_key_text("0xff")
        assert result == 255

    def test_valid_hex_uppercase_returns_int(self) -> None:
        result = parse_xor_key_text("0xFF")
        assert result == 255

    def test_valid_hex_single_digit_returns_int(self) -> None:
        result = parse_xor_key_text("0x1")
        assert result == 1

    def test_valid_hex_zero_returns_zero(self) -> None:
        result = parse_xor_key_text("0x0")
        assert result == 0

    def test_hex_with_surrounding_whitespace_returns_int(self) -> None:
        # strip() is applied first; after stripping it becomes valid hex.
        result = parse_xor_key_text("  0xAB  ")
        assert result == 0xAB


class TestParseXorKeyTextDecimal:
    """Lines 19-20: non-hex inputs where all chars are decimal digits.

    Line 20 (`return int(text, 10)`) was previously uncovered.
    """

    def test_single_decimal_digit_returns_int(self) -> None:
        # Arrange: "5" — all chars in _DECIMAL_DIGITS → line 20.
        result = parse_xor_key_text("5")
        assert result == 5

    def test_multi_digit_decimal_returns_int(self) -> None:
        result = parse_xor_key_text("255")
        assert result == 255

    def test_decimal_zero_returns_zero(self) -> None:
        result = parse_xor_key_text("0")
        assert result == 0

    def test_decimal_large_value_returns_int(self) -> None:
        # The function itself imposes no upper-bound; callers may reject it.
        result = parse_xor_key_text("1000")
        assert result == 1000

    def test_decimal_with_surrounding_whitespace_returns_int(self) -> None:
        result = parse_xor_key_text("  42  ")
        assert result == 42


class TestParseXorKeyTextNonDecimalNonHex:
    """Line 21: text that is neither 0x-prefixed nor all-decimal → None."""

    def test_alphabetic_string_returns_none(self) -> None:
        result = parse_xor_key_text("abc")
        assert result is None

    def test_decimal_with_letter_suffix_returns_none(self) -> None:
        # "12a" — 'a' is not in _DECIMAL_DIGITS and no 0x prefix.
        result = parse_xor_key_text("12a")
        assert result is None

    def test_negative_decimal_returns_none(self) -> None:
        # '-' is not in _DECIMAL_DIGITS and input doesn't start with "0x".
        result = parse_xor_key_text("-1")
        assert result is None

    def test_float_string_returns_none(self) -> None:
        result = parse_xor_key_text("1.5")
        assert result is None


# ---------------------------------------------------------------------------
# serialize_meta_scope — yaraast/serialization/meta_scopes.py  lines 9-18
# ---------------------------------------------------------------------------


class TestSerializeMetaScopeWithMetaScopeInstance:
    """Line 11-12: when given a real MetaScope enum, return its .value."""

    def test_public_scope_returns_public_string(self) -> None:
        result = serialize_meta_scope(MetaScope.PUBLIC)
        assert result == "public"

    def test_private_scope_returns_private_string(self) -> None:
        result = serialize_meta_scope(MetaScope.PRIVATE)
        assert result == "private"

    def test_protected_scope_returns_protected_string(self) -> None:
        result = serialize_meta_scope(MetaScope.PROTECTED)
        assert result == "protected"


class TestSerializeMetaScopeWithValidString:
    """Lines 13-16: when given a valid scope string, validate and return it."""

    def test_public_string_returns_public(self) -> None:
        # "public" is a valid MetaScope value → deserialize_meta_scope
        # returns "public" → serialize_meta_scope returns "public".
        result = serialize_meta_scope("public")
        assert result == "public"

    def test_private_string_returns_private(self) -> None:
        result = serialize_meta_scope("private")
        assert result == "private"

    def test_protected_string_returns_protected(self) -> None:
        result = serialize_meta_scope("protected")
        assert result == "protected"


class TestSerializeMetaScopeWithInvalidString:
    """Lines 17-18: string that fails MetaScope validation raises SerializationError."""

    def test_invalid_string_raises_serialization_error(self) -> None:
        with pytest.raises(SerializationError):
            serialize_meta_scope("unknown_scope")

    def test_empty_string_raises_serialization_error(self) -> None:
        # MetaScope("") raises ValueError → caught → SerializationError.
        with pytest.raises(SerializationError):
            serialize_meta_scope("")

    def test_arbitrary_string_raises_serialization_error(self) -> None:
        with pytest.raises(SerializationError):
            serialize_meta_scope("global")


class TestSerializeMetaScopeWithNonStringNonMetaScope:
    """Lines 17-18: non-string, non-MetaScope input must raise SerializationError."""

    def test_integer_raises_serialization_error(self) -> None:
        with pytest.raises(SerializationError):
            serialize_meta_scope(42)

    def test_none_raises_serialization_error(self) -> None:
        with pytest.raises(SerializationError):
            serialize_meta_scope(None)

    def test_list_raises_serialization_error(self) -> None:
        with pytest.raises(SerializationError):
            serialize_meta_scope(["public"])


# ---------------------------------------------------------------------------
# deserialize_meta_scope — yaraast/serialization/meta_scopes.py  lines 21-29
# ---------------------------------------------------------------------------


class TestDeserializeMetaScopeWithNone:
    """Line 23-24: None input must return None immediately."""

    def test_none_input_returns_none(self) -> None:
        result = deserialize_meta_scope(None)
        assert result is None


class TestDeserializeMetaScopeWithValidString:
    """Lines 25-26: valid scope string returns its canonical .value."""

    def test_public_returns_public(self) -> None:
        result = deserialize_meta_scope("public")
        assert result == "public"

    def test_private_returns_private(self) -> None:
        result = deserialize_meta_scope("private")
        assert result == "private"

    def test_protected_returns_protected(self) -> None:
        result = deserialize_meta_scope("protected")
        assert result == "protected"


class TestDeserializeMetaScopeWithInvalidString:
    """Lines 27-29: invalid string raises SerializationError wrapping ValueError."""

    def test_invalid_scope_raises_serialization_error(self) -> None:
        with pytest.raises(SerializationError, match="public, private, or protected"):
            deserialize_meta_scope("bogus")

    def test_numeric_string_raises_serialization_error(self) -> None:
        with pytest.raises(SerializationError):
            deserialize_meta_scope("123")

    def test_uppercase_raises_serialization_error(self) -> None:
        # MetaScope enum values are lowercase; "PUBLIC" is not a valid value.
        with pytest.raises(SerializationError):
            deserialize_meta_scope("PUBLIC")

    def test_empty_string_raises_serialization_error(self) -> None:
        with pytest.raises(SerializationError):
            deserialize_meta_scope("")

    def test_whitespace_string_raises_serialization_error(self) -> None:
        with pytest.raises(SerializationError):
            deserialize_meta_scope("  ")
