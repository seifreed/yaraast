# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage loop: exercises every uncovered branch in yaraast/ast/modifiers.py.

Missing lines targeted (as of the coverage baseline):
  41           - _require_string_modifier_value finite-float return
  56-57        - _require_string_modifier_value last TypeError (other type)
  86-95        - require_rule_modifier_identifier (valid path + error path)
  106-107      - _validate_meta_identifier invalid-identifier error
  116          - _is_xor_modifier_text return False (bad part)
  124          - _parse_xor_key_text return None (key > 0xFF)
  129-135      - _is_xor_key_value (bool/int/str/other branches)
  139-164      - _validate_xor_modifier_value (all branches)
  171-180      - _validate_base64_modifier_value (all branches)
  187-195      - _validate_string_modifier_parameter (all branches)
  296-298      - StringModifier.validate_structure
  337          - RuleModifier.validate_structure
  364-366      - MetaEntry.validate_structure
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.modifiers import (
    MetaEntry,
    MetaScope,
    RuleModifier,
    RuleModifierType,
    StringModifier,
    StringModifierType,
    _is_xor_key_value,
    _is_xor_modifier_text,
    _parse_xor_key_text,
    _require_string_modifier_value,
    _validate_base64_modifier_value,
    _validate_string_modifier_parameter,
    _validate_xor_modifier_value,
    require_rule_modifier_identifier,
)
from yaraast.errors import ValidationError

# ---------------------------------------------------------------------------
# _require_string_modifier_value — line 41 (finite float), 56-57 (other type)
# ---------------------------------------------------------------------------


def test_require_string_modifier_value_finite_float_returns_value() -> None:
    # Line 41: finite float is accepted and returned as-is.
    result = _require_string_modifier_value(3.14)
    assert result == pytest.approx(3.14)


def test_require_string_modifier_value_other_type_raises_type_error() -> None:
    # Lines 56-57: a type that is not str/bool/int/float/tuple raises TypeError.
    with pytest.raises(
        TypeError, match="StringModifier value must be a string, number, tuple, or null"
    ):
        _require_string_modifier_value(cast(Any, object()))


# ---------------------------------------------------------------------------
# require_rule_modifier_identifier — lines 86-95 (valid + invalid paths)
# ---------------------------------------------------------------------------


def test_require_rule_modifier_identifier_valid_name_returns_it() -> None:
    # Lines 86-92: a well-formed identifier passes validation and is returned.
    result = require_rule_modifier_identifier("my_tag", "Tag")
    assert result == "my_tag"


def test_require_rule_modifier_identifier_with_custom_context() -> None:
    # Lines 93-95 (else branch): identifier_context is substituted when provided.
    result = require_rule_modifier_identifier("valid_id", "Tag", "tag identifier")
    assert result == "valid_id"


def test_require_rule_modifier_identifier_keyword_raises_validation_error() -> None:
    # Lines 93-95: a YARA keyword (e.g. "rule") is rejected with ValidationError.
    with pytest.raises(ValidationError, match="Invalid"):
        require_rule_modifier_identifier("rule", "Tag")


def test_require_rule_modifier_identifier_invalid_chars_raises_validation_error() -> None:
    # Lines 93-95: an identifier containing a hyphen is rejected.
    with pytest.raises(ValidationError, match="Invalid"):
        require_rule_modifier_identifier("bad-name", "Tag")


def test_require_rule_modifier_identifier_too_long_raises_validation_error() -> None:
    # Lines 93-95: an identifier exceeding YARA_IDENTIFIER_MAX_LENGTH is rejected.
    long_name = "a" * 200
    with pytest.raises(ValidationError, match="Invalid"):
        require_rule_modifier_identifier(long_name, "Tag")


# ---------------------------------------------------------------------------
# _validate_meta_identifier — lines 106-107 (invalid identifier error)
# ---------------------------------------------------------------------------


def test_validate_meta_identifier_keyword_raises_value_error() -> None:
    # Lines 106-107: a YARA keyword that is NOT a contextual keyword is invalid.
    # "rule" is a keyword and not in _YARA_CONTEXTUAL_IDENTIFIER_KEYWORDS.
    entry = MetaEntry(key="rule", value="v")
    with pytest.raises(ValueError, match="Invalid meta identifier"):
        entry.validate_structure()


def test_validate_meta_identifier_empty_string_raises_value_error() -> None:
    # Lines 106-107: an empty string cannot be a meta identifier.
    entry = MetaEntry(key="", value="v")
    with pytest.raises(ValueError, match="Meta key cannot be empty"):
        entry.validate_structure()


# ---------------------------------------------------------------------------
# _is_xor_modifier_text — line 116 (return False when key text is invalid)
# ---------------------------------------------------------------------------


def test_is_xor_modifier_text_invalid_part_returns_false() -> None:
    # Line 116: if any part of the split text cannot be parsed, return False.
    assert _is_xor_modifier_text("notahexkey") is False


def test_is_xor_modifier_text_out_of_range_part_returns_false() -> None:
    # Line 116: a value > 0xFF from _parse_xor_key_text is treated as None.
    assert _is_xor_modifier_text("0x100") is False


def test_is_xor_modifier_text_valid_single_key_returns_true() -> None:
    # Positive path: "0x10" is a valid single byte key.
    assert _is_xor_modifier_text("0x10") is True


def test_is_xor_modifier_text_descending_range_returns_false() -> None:
    # Ascending-order check: high < low is invalid.
    assert _is_xor_modifier_text("0xff-0x01") is False


# ---------------------------------------------------------------------------
# _parse_xor_key_text — line 124 (key > 0xFF returns None)
# ---------------------------------------------------------------------------


def test_parse_xor_key_text_out_of_range_returns_none() -> None:
    # Line 124: parse_xor_key_text returns 256 (0x100), which exceeds 0xFF → None.
    result = _parse_xor_key_text("0x100")
    assert result is None


def test_parse_xor_key_text_valid_returns_integer() -> None:
    # Positive path: 0x10 is within byte range.
    result = _parse_xor_key_text("0x10")
    assert result == 0x10


def test_parse_xor_key_text_underlying_none_returns_none() -> None:
    # Line 123-124: underlying parse_xor_key_text returns None for garbage input.
    result = _parse_xor_key_text("notakey")
    assert result is None


# ---------------------------------------------------------------------------
# _is_xor_key_value — lines 129-135 (bool/int/str/other branches)
# ---------------------------------------------------------------------------


def test_is_xor_key_value_bool_returns_false() -> None:
    # Line 130: booleans are explicitly rejected.
    assert _is_xor_key_value(True) is False
    assert _is_xor_key_value(False) is False


def test_is_xor_key_value_valid_int_returns_true() -> None:
    # Line 131-132: an int in [0, 255] is a valid key.
    assert _is_xor_key_value(0) is True
    assert _is_xor_key_value(255) is True


def test_is_xor_key_value_out_of_range_int_returns_false() -> None:
    # Line 131-132: an int outside [0, 255] is invalid.
    assert _is_xor_key_value(256) is False
    assert _is_xor_key_value(-1) is False


def test_is_xor_key_value_valid_str_returns_true() -> None:
    # Line 133-134: a parseable hex string with leading/trailing spaces is valid.
    assert _is_xor_key_value("0x10") is True
    assert _is_xor_key_value("  0x10  ") is True


def test_is_xor_key_value_invalid_str_returns_false() -> None:
    # Line 133-134: a non-parseable string returns False.
    assert _is_xor_key_value("notakey") is False


def test_is_xor_key_value_other_type_returns_false() -> None:
    # Line 135: any type other than bool/int/str returns False.
    assert _is_xor_key_value(cast(Any, 3.14)) is False
    assert _is_xor_key_value(cast(Any, None)) is False
    assert _is_xor_key_value(cast(Any, object())) is False


# ---------------------------------------------------------------------------
# _validate_xor_modifier_value — lines 139-164 (all branches)
# ---------------------------------------------------------------------------


def test_validate_xor_modifier_value_none_is_valid() -> None:
    # Line 139-140: None is explicitly accepted (no XOR key = default full range).
    _validate_xor_modifier_value(None)  # must not raise


def test_validate_xor_modifier_value_valid_tuple_passes() -> None:
    # Lines 141-149: a well-ordered (low, high) tuple within [0, 255] is valid.
    _validate_xor_modifier_value((0, 255))  # must not raise


def test_validate_xor_modifier_value_tuple_out_of_range_raises() -> None:
    # Lines 143-145: tuple elements must be in [0, 255].
    with pytest.raises(TypeError, match="xor range value must contain byte bounds"):
        _validate_xor_modifier_value((0, 256))


def test_validate_xor_modifier_value_tuple_descending_raises() -> None:
    # Lines 146-148: low > high is invalid.
    with pytest.raises(TypeError, match="xor range value must be ascending"):
        _validate_xor_modifier_value((10, 5))


def test_validate_xor_modifier_value_string_range_passes() -> None:
    # Lines 150-160: a "low-high" string with valid byte bounds is accepted.
    _validate_xor_modifier_value("0x01-0xff")  # must not raise


def test_validate_xor_modifier_value_string_range_bad_part_raises() -> None:
    # Lines 154-156: one part of the string range is unparseable.
    with pytest.raises(TypeError, match="xor range value must contain byte bounds"):
        _validate_xor_modifier_value("notakey-0xff")


def test_validate_xor_modifier_value_string_range_descending_raises() -> None:
    # Lines 157-159: string range where low text > high text.
    with pytest.raises(TypeError, match="xor range value must be ascending"):
        _validate_xor_modifier_value("0xff-0x01")


def test_validate_xor_modifier_value_valid_single_int_passes() -> None:
    # Lines 161-162: a valid byte integer passes.
    _validate_xor_modifier_value(10)  # must not raise


def test_validate_xor_modifier_value_invalid_value_raises() -> None:
    # Lines 163-164: something that is not a valid xor key raises TypeError.
    with pytest.raises(TypeError, match="xor value must be a byte"):
        _validate_xor_modifier_value(cast(Any, 3.14))


# ---------------------------------------------------------------------------
# _validate_base64_modifier_value — lines 171-180 (all branches)
# ---------------------------------------------------------------------------


def test_validate_base64_modifier_value_non_string_raises() -> None:
    # Lines 171-173: non-string value raises TypeError.
    with pytest.raises(TypeError, match="base64 value must be a string"):
        _validate_base64_modifier_value(StringModifierType.BASE64, cast(Any, 42))


def test_validate_base64_modifier_value_non_ascii_string_raises() -> None:
    # Lines 174-178: a string that is not pure ASCII results in empty encoded
    # bytes (len != 64) and triggers the length check error.
    non_ascii = "é" * 64  # é repeated 64 times — not pure ASCII
    with pytest.raises(TypeError, match="base64 alphabet must be 64 bytes"):
        _validate_base64_modifier_value(StringModifierType.BASE64, non_ascii)


def test_validate_base64_modifier_value_wrong_length_raises() -> None:
    # Lines 178-180: ASCII string that is not 64 bytes raises TypeError.
    with pytest.raises(TypeError, match="base64 alphabet must be 64 bytes"):
        _validate_base64_modifier_value(StringModifierType.BASE64, "short")


def test_validate_base64_modifier_value_valid_64_byte_string_passes() -> None:
    # Positive path: exactly 64 ASCII characters passes.
    alphabet = "A" * 64
    _validate_base64_modifier_value(StringModifierType.BASE64, alphabet)  # must not raise


def test_validate_base64_modifier_value_base64wide_variant_passes() -> None:
    # Positive path for BASE64WIDE variant uses same validation logic.
    alphabet = "B" * 64
    _validate_base64_modifier_value(StringModifierType.BASE64WIDE, alphabet)  # must not raise


# ---------------------------------------------------------------------------
# _validate_string_modifier_parameter — lines 187-195 (all branches)
# ---------------------------------------------------------------------------


def test_validate_string_modifier_parameter_xor_delegates_correctly() -> None:
    # Lines 187-189: XOR modifier delegates to _validate_xor_modifier_value.
    _validate_string_modifier_parameter(StringModifierType.XOR, None)  # must not raise
    _validate_string_modifier_parameter(StringModifierType.XOR, 10)  # must not raise


def test_validate_string_modifier_parameter_base64_delegates_correctly() -> None:
    # Lines 190-192: BASE64/BASE64WIDE delegates to _validate_base64_modifier_value.
    alphabet = "C" * 64
    _validate_string_modifier_parameter(StringModifierType.BASE64, alphabet)  # must not raise
    _validate_string_modifier_parameter(StringModifierType.BASE64WIDE, alphabet)  # must not raise


def test_validate_string_modifier_parameter_no_value_modifier_with_value_raises() -> None:
    # Lines 193-195: a modifier that takes no value raises ValueError when value is given.
    with pytest.raises(ValueError, match="does not accept a value"):
        _validate_string_modifier_parameter(StringModifierType.ASCII, "unexpected")


def test_validate_string_modifier_parameter_no_value_modifier_with_none_passes() -> None:
    # Lines 193-195: value=None is accepted for modifiers that take no value.
    _validate_string_modifier_parameter(StringModifierType.ASCII, None)  # must not raise
    _validate_string_modifier_parameter(StringModifierType.WIDE, None)  # must not raise
    _validate_string_modifier_parameter(StringModifierType.NOCASE, None)  # must not raise


# ---------------------------------------------------------------------------
# StringModifier.validate_structure — lines 296-298
# ---------------------------------------------------------------------------


def test_string_modifier_validate_structure_valid_no_value() -> None:
    # Lines 296-298: validate_structure on a clean node must not raise.
    modifier = StringModifier.from_name_value("wide")
    modifier.validate_structure()  # must not raise


def test_string_modifier_validate_structure_valid_xor_with_value() -> None:
    # Lines 296-298: validate_structure with a valid xor value must not raise.
    modifier = StringModifier.from_name_value("xor", 42)
    modifier.validate_structure()  # must not raise


def test_string_modifier_validate_structure_invalid_modifier_type_raises() -> None:
    # Lines 296-297: an invalid modifier_type field is caught during validate_structure.
    modifier = StringModifier(cast(Any, "not_a_modifier_type"))
    with pytest.raises(
        TypeError, match="StringModifier modifier_type must be a StringModifierType"
    ):
        modifier.validate_structure()


def test_string_modifier_validate_structure_invalid_xor_value_raises() -> None:
    # Lines 296-298: validate_structure propagates xor-value validation errors.
    modifier = StringModifier(StringModifierType.XOR, cast(Any, 3.14))
    with pytest.raises(TypeError):
        modifier.validate_structure()


# ---------------------------------------------------------------------------
# RuleModifier.validate_structure — line 337
# ---------------------------------------------------------------------------


def test_rule_modifier_validate_structure_valid_passes() -> None:
    # Line 337: validate_structure on a valid RuleModifier must not raise.
    modifier = RuleModifier(modifier_type=RuleModifierType.PRIVATE)
    modifier.validate_structure()  # must not raise


def test_rule_modifier_validate_structure_invalid_type_raises() -> None:
    # Line 337: an invalid modifier_type field is caught during validate_structure.
    modifier = RuleModifier(cast(Any, "not_a_rule_modifier_type"))
    with pytest.raises(TypeError, match="RuleModifier modifier_type must be a RuleModifierType"):
        modifier.validate_structure()


# ---------------------------------------------------------------------------
# MetaEntry.validate_structure — lines 364-366
# ---------------------------------------------------------------------------


def test_meta_entry_validate_structure_valid_passes() -> None:
    # Lines 364-366: validate_structure on a clean node must not raise.
    entry = MetaEntry(key="author", value="seifreed")
    entry.validate_structure()  # must not raise


def test_meta_entry_validate_structure_invalid_key_raises() -> None:
    # Lines 364-365: an invalid meta key is caught during validate_structure.
    entry = MetaEntry(key="", value="value")
    with pytest.raises(ValueError, match="Meta key cannot be empty"):
        entry.validate_structure()


def test_meta_entry_validate_structure_invalid_value_raises() -> None:
    # Lines 364-366: an invalid meta value is caught during validate_structure.
    entry = MetaEntry(key="k", value=cast(Any, None))
    with pytest.raises(
        TypeError, match="Meta value must be a string, integer, boolean, or finite float"
    ):
        entry.validate_structure()


def test_meta_entry_validate_structure_invalid_scope_raises() -> None:
    # Lines 364-366: an invalid scope is caught during validate_structure.
    entry = MetaEntry(key="k", value="v", scope=cast(Any, "private"))
    with pytest.raises(TypeError, match="Meta scope must be a MetaScope"):
        entry.validate_structure()


# ---------------------------------------------------------------------------
# StringModifier.__str__ — xor string with "-" (line 322-323 / 296 region)
# ---------------------------------------------------------------------------


def test_string_modifier_str_xor_text_range_format() -> None:
    # Line 322-323: when the xor value is a string matching a valid range,
    # it is formatted without quotes: xor(0x01-0xff).
    modifier = StringModifier.from_name_value("xor", "0x01-0xff")
    assert str(modifier) == "xor(0x01-0xff)"


def test_string_modifier_str_xor_single_text_key_format() -> None:
    # Line 322-323: single hex string key is formatted without quotes.
    modifier = StringModifier.from_name_value("xor", "0x10")
    assert str(modifier) == "xor(0x10)"


# ---------------------------------------------------------------------------
# MetaScope.from_string — edge cases (empty/whitespace only)
# ---------------------------------------------------------------------------


def test_meta_scope_from_string_whitespace_only_raises() -> None:
    # MetaScope.from_string strips on empty check; whitespace-only is invalid.
    with pytest.raises(ValueError, match="Meta scope input cannot be empty"):
        MetaScope.from_string("   ")
