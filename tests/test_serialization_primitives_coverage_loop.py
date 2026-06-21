# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests for yaraast/serialization/_serialization_primitives.py.

Each test exercises a real production code path through direct calls to the
primitive helpers.  No mocks, stubs, or placeholder implementations are used.
All inputs are deterministic values that reflect scenarios the module encounters
during normal serialization and deserialization work.
"""

from __future__ import annotations

import math

import pytest

from yaraast.ast.base import Location
from yaraast.errors import SerializationError
from yaraast.serialization._serialization_primitives import (
    _deserialize_bool_field,
    _deserialize_boolean_literal_value,
    _deserialize_comment_multiline,
    _deserialize_comment_text,
    _deserialize_dict_field,
    _deserialize_double_literal_value,
    _deserialize_integer_literal_value,
    _deserialize_is_anonymous,
    _deserialize_list_field,
    _deserialize_location,
    _deserialize_location_int_field,
    _deserialize_location_optional_int_field,
    _deserialize_meta_entry_value,
    _deserialize_meta_value,
    _deserialize_nullable_string_field,
    _deserialize_object,
    _deserialize_plain_string_raw_bytes,
    _deserialize_plain_string_value,
    _deserialize_pragma_parameter_value,
    _deserialize_string_field,
    _deserialize_string_list_field,
    _expected_type_names,
    _is_empty_nonempty_text,
    _is_negated_nibble_pattern,
    _normalize_rule_modifier_text,
    _serialize_modifier_value,
    _validate_binary_operator_text,
    _validate_extern_import_rule_identifiers,
    _validate_extern_rule_identifier_text,
    _validate_extern_rule_path_text,
    _validate_for_expression_iterable,
    _validate_function_identifier_text,
    _validate_in_expression_range,
    _validate_integer_expression,
    _validate_local_identifier_list,
    _validate_local_identifier_text,
    _validate_location_metadata,
    _validate_loop_variable_text,
    _validate_namespace_identifier_text,
    _validate_optional_namespace_identifier_text,
    _validate_percentage_quantifier_value,
    _validate_quantifier_text,
    _validate_quantifier_value,
    _validate_range_expression_bounds,
    _validate_set_expression_elements,
    _validate_string_identifier_text,
    _validate_string_occurrence_index_expression,
    _validate_string_operator_text,
    _validate_string_reference_text,
    _validate_unary_operator_text,
    _validate_unique_extern_rule_identifiers,
    _validate_unique_rule_identifiers,
    _validate_unique_rule_tags,
    _validate_yara_identifier_text,
)

# ---------------------------------------------------------------------------
# _is_empty_nonempty_text
# ---------------------------------------------------------------------------


def test_is_empty_nonempty_text_empty_string() -> None:
    assert _is_empty_nonempty_text("", "RegexLiteral pattern") is True


def test_is_empty_nonempty_text_whitespace_in_whitespace_significant_context() -> None:
    # RegexLiteral pattern: whitespace is significant, so "  " is not "empty"
    assert _is_empty_nonempty_text("  ", "RegexLiteral pattern") is False


def test_is_empty_nonempty_text_whitespace_in_normal_context() -> None:
    # Outside the whitespace-significant contexts pure whitespace is empty
    assert _is_empty_nonempty_text("  ", "SomeField") is True


def test_is_empty_nonempty_text_nonempty() -> None:
    assert _is_empty_nonempty_text("hello", "SomeField") is False


# ---------------------------------------------------------------------------
# _normalize_rule_modifier_text
# ---------------------------------------------------------------------------


def test_normalize_rule_modifier_text_known_modifier() -> None:
    result = _normalize_rule_modifier_text("global", "Rule")
    assert result == "global"


def test_normalize_rule_modifier_text_custom_identifier_rule_context() -> None:
    # Unknown modifier but valid identifier accepted for Rule context
    result = _normalize_rule_modifier_text("custom_mod", "Rule")
    assert result == "custom_mod"


def test_normalize_rule_modifier_text_custom_identifier_extern_rule_context() -> None:
    result = _normalize_rule_modifier_text("custom_mod", "ExternRule")
    assert result == "custom_mod"


def test_normalize_rule_modifier_text_custom_identifier_other_context() -> None:
    # Line 71: else branch — context is neither Rule nor ExternRule
    result = _normalize_rule_modifier_text("custom_mod", "SomeOtherContext")
    assert result == "custom_mod"


def test_normalize_rule_modifier_text_invalid_identifier_raises() -> None:
    with pytest.raises(SerializationError):
        _normalize_rule_modifier_text("123bad", "Rule")


# ---------------------------------------------------------------------------
# _validate_unique_rule_identifiers
# ---------------------------------------------------------------------------


class _FakeRuleWithName:
    def __init__(self, name: object) -> None:
        self.name = name


def test_validate_unique_rule_identifiers_valid_names() -> None:
    _validate_unique_rule_identifiers([_FakeRuleWithName("rule_a"), _FakeRuleWithName("rule_b")])


def test_validate_unique_rule_identifiers_duplicate_raises() -> None:
    with pytest.raises(SerializationError, match="Duplicate rule identifier"):
        _validate_unique_rule_identifiers(
            [_FakeRuleWithName("rule_a"), _FakeRuleWithName("rule_a")]
        )


def test_validate_unique_rule_identifiers_skips_invalid_names() -> None:
    # Lines 157-158: invalid name raises TypeError/ValueError inside — continue
    _validate_unique_rule_identifiers([_FakeRuleWithName("123invalid")])


def test_validate_unique_rule_identifiers_empty_list() -> None:
    _validate_unique_rule_identifiers([])


# ---------------------------------------------------------------------------
# _validate_unique_rule_tags
# ---------------------------------------------------------------------------


class _FakeTagWithName:
    def __init__(self, name: object) -> None:
        self.name = name


def test_validate_unique_rule_tags_string_tags() -> None:

    _validate_unique_rule_tags(["tag_a", "tag_b"])


def test_validate_unique_rule_tags_duplicate_raises() -> None:

    with pytest.raises(SerializationError, match="Duplicate tag identifier"):
        _validate_unique_rule_tags(["tag_a", "tag_a"])


def test_validate_unique_rule_tags_skips_invalid_names() -> None:
    # Lines 182-183: invalid tag name skipped via continue

    _validate_unique_rule_tags([_FakeTagWithName("123bad")])


# ---------------------------------------------------------------------------
# _validate_string_reference_text
# ---------------------------------------------------------------------------


def test_validate_string_reference_text_valid() -> None:
    result = _validate_string_reference_text("$my_str")
    assert result == "$my_str"


def test_validate_string_reference_text_invalid_raises() -> None:
    # Lines 200-201: normalize raises, wrapped as SerializationError
    with pytest.raises(SerializationError):
        _validate_string_reference_text("!!bad_ref")


def test_validate_string_reference_text_placeholder_allowed() -> None:
    result = _validate_string_reference_text("$", allow_placeholder=True)
    assert result == "$"


def test_validate_string_reference_text_wildcard_allowed() -> None:
    result = _validate_string_reference_text("$prefix*", allow_wildcard=True)
    assert result == "$prefix*"


# ---------------------------------------------------------------------------
# _validate_string_identifier_text
# ---------------------------------------------------------------------------


def test_validate_string_identifier_text_valid() -> None:
    result = _validate_string_identifier_text("$valid")
    assert result == "$valid"


def test_validate_string_identifier_text_invalid_raises() -> None:
    # Lines 208-209: validate raises, wrapped as SerializationError
    with pytest.raises(SerializationError):
        _validate_string_identifier_text("")


# ---------------------------------------------------------------------------
# _validate_binary_operator_text
# ---------------------------------------------------------------------------


def test_validate_binary_operator_text_valid() -> None:
    result = _validate_binary_operator_text("and")
    assert result == "and"


def test_validate_binary_operator_text_invalid_raises() -> None:
    # Lines 215-216
    with pytest.raises(SerializationError, match="Invalid binary operator"):
        _validate_binary_operator_text("not_an_operator")


# ---------------------------------------------------------------------------
# _validate_unary_operator_text
# ---------------------------------------------------------------------------


def test_validate_unary_operator_text_valid() -> None:
    result = _validate_unary_operator_text("not")
    assert result == "not"


def test_validate_unary_operator_text_invalid_raises() -> None:
    # Lines 221-225
    with pytest.raises(SerializationError, match="Invalid unary operator"):
        _validate_unary_operator_text("xor_op")


# ---------------------------------------------------------------------------
# _validate_string_operator_text
# ---------------------------------------------------------------------------


def test_validate_string_operator_text_valid() -> None:
    result = _validate_string_operator_text("contains")
    assert result == "contains"


def test_validate_string_operator_text_invalid_raises() -> None:
    # Lines 229-233
    with pytest.raises(SerializationError, match="Invalid string operator"):
        _validate_string_operator_text("matches_not")


# ---------------------------------------------------------------------------
# _validate_percentage_quantifier_value
# ---------------------------------------------------------------------------


def test_validate_percentage_quantifier_value_in_range_returns_none() -> None:
    # Line 305: valid percentage (1-100) returns without raising
    _validate_percentage_quantifier_value(1, "1%", "quantifier")
    _validate_percentage_quantifier_value(50, "50%", "quantifier")
    _validate_percentage_quantifier_value(100, "100%", "quantifier")


def test_validate_percentage_quantifier_value_zero_raises() -> None:
    with pytest.raises(SerializationError):
        _validate_percentage_quantifier_value(0, "0%", "quantifier")


def test_validate_percentage_quantifier_value_over_100_raises() -> None:
    with pytest.raises(SerializationError):
        _validate_percentage_quantifier_value(101, "101%", "quantifier")


# ---------------------------------------------------------------------------
# _validate_quantifier_text
# ---------------------------------------------------------------------------


def test_validate_quantifier_text_keyword_all() -> None:
    assert _validate_quantifier_text("all", "quantifier", allow_percentage=False) == "all"


def test_validate_quantifier_text_keyword_any() -> None:
    assert _validate_quantifier_text("any", "quantifier", allow_percentage=False) == "any"


def test_validate_quantifier_text_keyword_none() -> None:
    assert _validate_quantifier_text("none", "quantifier", allow_percentage=False) == "none"


def test_validate_quantifier_text_positive_integer() -> None:
    assert _validate_quantifier_text("5", "quantifier", allow_percentage=False) == 5


def test_validate_quantifier_text_positive_integer_with_plus_prefix() -> None:
    # Line 320->326: str(5) == value[1:] branch
    assert _validate_quantifier_text("+5", "quantifier", allow_percentage=False) == 5


def test_validate_quantifier_text_negative_integer_raises() -> None:
    with pytest.raises(SerializationError):
        _validate_quantifier_text("-1", "quantifier", allow_percentage=False)


def test_validate_quantifier_text_zero_padded_integer_raises() -> None:
    # Line 320->326: str(1) != '01', falls through to identifier validation, fails
    with pytest.raises(SerializationError):
        _validate_quantifier_text("01", "quantifier", allow_percentage=False)


def test_validate_quantifier_text_percentage_allowed() -> None:
    # Lines 332: percentage allowed path
    result = _validate_quantifier_text("50%", "quantifier", allow_percentage=True)
    assert result == "50%"


def test_validate_quantifier_text_percentage_not_allowed_raises() -> None:
    # Line 329-330
    with pytest.raises(SerializationError):
        _validate_quantifier_text("50%", "quantifier", allow_percentage=False)


def test_validate_quantifier_text_percentage_out_of_range_raises() -> None:
    with pytest.raises(SerializationError):
        _validate_quantifier_text("0%", "quantifier", allow_percentage=True)


def test_validate_quantifier_text_float_finite_raises() -> None:
    # Lines 333-342: float path — finite float raises as invalid quantifier
    with pytest.raises(SerializationError):
        _validate_quantifier_text("3.14", "quantifier", allow_percentage=False)


def test_validate_quantifier_text_float_non_finite_raises_must_be_finite() -> None:
    # Lines 339-341: infinite float gives "must be finite" error
    with pytest.raises(SerializationError, match="must be finite"):
        _validate_quantifier_text("1.0e999", "quantifier", allow_percentage=False)


def test_validate_quantifier_text_empty_raises() -> None:
    with pytest.raises(SerializationError, match="must not be empty"):
        _validate_quantifier_text("", "quantifier", allow_percentage=False)


def test_validate_quantifier_text_valid_identifier() -> None:
    # Falls through all numeric checks and lands at validate_yara_identifier
    result = _validate_quantifier_text("my_var", "quantifier", allow_percentage=False)
    assert result == "my_var"


def test_validate_quantifier_text_invalid_identifier_raises() -> None:
    # Lines 344-346: identifier validation fails
    with pytest.raises(SerializationError):
        _validate_quantifier_text("123start", "quantifier", allow_percentage=False)


# ---------------------------------------------------------------------------
# _validate_quantifier_value
# ---------------------------------------------------------------------------


def test_validate_quantifier_value_string() -> None:
    result = _validate_quantifier_value("all", "q", allow_percentage=False)
    assert result == "all"


def test_validate_quantifier_value_positive_int() -> None:
    result = _validate_quantifier_value(3, "q", allow_percentage=False)
    assert result == 3


def test_validate_quantifier_value_negative_int_raises() -> None:
    # Line 361
    with pytest.raises(SerializationError):
        _validate_quantifier_value(-1, "q", allow_percentage=False)


def test_validate_quantifier_value_float_no_percentage_raises() -> None:
    # Line 368
    with pytest.raises(SerializationError):
        _validate_quantifier_value(0.5, "q", allow_percentage=False)


def test_validate_quantifier_value_float_valid_percentage() -> None:
    # Line 371: float allowed, valid percentage
    result = _validate_quantifier_value(0.5, "q", allow_percentage=True)
    assert result == 0.5


def test_validate_quantifier_value_float_infinite_raises() -> None:
    with pytest.raises(SerializationError, match="must be finite"):
        _validate_quantifier_value(math.inf, "q", allow_percentage=True)


def test_validate_quantifier_value_bool_raises() -> None:
    with pytest.raises(SerializationError, match="must be a string, number, or expression"):
        _validate_quantifier_value(True, "q", allow_percentage=False)


def test_validate_quantifier_value_none_raises() -> None:
    with pytest.raises(SerializationError, match="must be a string, number, or expression"):
        _validate_quantifier_value(None, "q", allow_percentage=False)


def test_validate_quantifier_value_list_raises() -> None:
    with pytest.raises(SerializationError, match="must be a string, number, or expression"):
        _validate_quantifier_value([1, 2], "q", allow_percentage=False)


def test_validate_quantifier_value_unknown_type_raises() -> None:
    # Line 372-373: catches objects that don't match any branch
    with pytest.raises(SerializationError, match="must be a string, number, or expression"):
        _validate_quantifier_value(object(), "q", allow_percentage=False)


# ---------------------------------------------------------------------------
# _validate_location_metadata
# ---------------------------------------------------------------------------


def test_validate_location_metadata_valid_with_structure_check() -> None:
    loc = Location(line=1, column=1)
    result = _validate_location_metadata(loc)
    assert result is loc


def test_validate_location_metadata_no_structure_check() -> None:
    # Line 385: validate_structure=False returns immediately
    loc = Location(line=1, column=1)
    result = _validate_location_metadata(loc, validate_structure=False)
    assert result is loc


def test_validate_location_metadata_non_location_raises() -> None:
    with pytest.raises(SerializationError, match="location must be a Location"):
        _validate_location_metadata({"line": 1, "column": 1})


def test_validate_location_metadata_invalid_location_raises() -> None:
    # validate_structure raises for negative line — wrapped as SerializationError
    loc = Location(line=-1, column=1)
    with pytest.raises(SerializationError):
        _validate_location_metadata(loc)


# ---------------------------------------------------------------------------
# _serialize_modifier_value
# ---------------------------------------------------------------------------


def test_serialize_modifier_value_none() -> None:
    assert _serialize_modifier_value(None) is None


def test_serialize_modifier_value_plain_string() -> None:
    assert _serialize_modifier_value("hello") == "hello"


def test_serialize_modifier_value_surrogate_string_raises() -> None:
    # Lines 397-400: surrogate character in string
    with pytest.raises(SerializationError, match="UTF-8 encodable"):
        _serialize_modifier_value("\ud800")


def test_serialize_modifier_value_bool_raises() -> None:
    # Lines 402-403
    with pytest.raises(SerializationError, match="must be a string, number, tuple, or null"):
        _serialize_modifier_value(True)


def test_serialize_modifier_value_int() -> None:
    assert _serialize_modifier_value(42) == 42


def test_serialize_modifier_value_float_finite() -> None:
    # Line 410
    assert _serialize_modifier_value(3.14) == 3.14


def test_serialize_modifier_value_float_non_finite_raises() -> None:
    # Lines 407-409
    with pytest.raises(SerializationError, match="must be finite"):
        _serialize_modifier_value(math.inf)


def test_serialize_modifier_value_valid_tuple() -> None:
    assert _serialize_modifier_value((3, 7)) == [3, 7]


def test_serialize_modifier_value_tuple_with_bool_raises() -> None:
    # Lines 412-418: bool inside tuple
    with pytest.raises(SerializationError, match="two integers"):
        _serialize_modifier_value((True, 1))


def test_serialize_modifier_value_tuple_wrong_length_raises() -> None:
    with pytest.raises(SerializationError, match="two integers"):
        _serialize_modifier_value((1, 2, 3))


def test_serialize_modifier_value_list_raises() -> None:
    # Lines 420-421: unrecognised type
    with pytest.raises(SerializationError, match="must be a string, number, tuple, or null"):
        _serialize_modifier_value([1, 2])


# ---------------------------------------------------------------------------
# _deserialize_location_optional_int_field
# ---------------------------------------------------------------------------


def test_deserialize_location_optional_int_field_absent_returns_none() -> None:
    assert _deserialize_location_optional_int_field({}, "end_line") is None


def test_deserialize_location_optional_int_field_valid_int() -> None:
    assert _deserialize_location_optional_int_field({"end_line": 5}, "end_line") == 5


def test_deserialize_location_optional_int_field_bool_raises() -> None:
    # bool is int subclass — must be rejected
    with pytest.raises(SerializationError, match="must be an integer"):
        _deserialize_location_optional_int_field({"end_line": True}, "end_line")


def test_deserialize_location_optional_int_field_string_raises() -> None:
    # Lines 453-454
    with pytest.raises(SerializationError, match="must be an integer"):
        _deserialize_location_optional_int_field({"end_line": "5"}, "end_line")


# ---------------------------------------------------------------------------
# _deserialize_comment_multiline
# ---------------------------------------------------------------------------


def test_deserialize_comment_multiline_default_false() -> None:
    assert _deserialize_comment_multiline({}) is False


def test_deserialize_comment_multiline_true() -> None:
    assert _deserialize_comment_multiline({"is_multiline": True}) is True


def test_deserialize_comment_multiline_wrong_type_raises() -> None:
    # Lines 461-462
    with pytest.raises(SerializationError, match="must be a boolean"):
        _deserialize_comment_multiline({"is_multiline": "yes"})


# ---------------------------------------------------------------------------
# _deserialize_plain_string_value
# ---------------------------------------------------------------------------


def test_deserialize_plain_string_value_plain_string() -> None:
    result = _deserialize_plain_string_value({"value": "hello"})
    assert result == "hello"


def test_deserialize_plain_string_value_plain_bytes() -> None:
    result = _deserialize_plain_string_value({"value": b"\x00\x01"})
    assert result == b"\x00\x01"


def test_deserialize_plain_string_value_plain_wrong_type_raises() -> None:
    with pytest.raises(SerializationError, match="must be a string or bytes"):
        _deserialize_plain_string_value({"value": 42})


def test_deserialize_plain_string_value_base64_bytes_passthrough() -> None:
    # Line 492: when value_encoding==base64 and value is bytes, return as-is
    result = _deserialize_plain_string_value({"value": b"raw", "value_encoding": "base64"})
    assert result == b"raw"


def test_deserialize_plain_string_value_base64_valid() -> None:
    import base64

    encoded = base64.b64encode(b"hello world").decode("ascii")
    result = _deserialize_plain_string_value({"value": encoded, "value_encoding": "base64"})
    assert result == b"hello world"


def test_deserialize_plain_string_value_base64_non_string_raises() -> None:
    # Lines 493-495: value_encoding==base64 but value is int (not bytes, not str)
    with pytest.raises(SerializationError, match="must be a string or bytes"):
        _deserialize_plain_string_value({"value": 99, "value_encoding": "base64"})


def test_deserialize_plain_string_value_base64_invalid_raises() -> None:
    # Lines 498-500: invalid base64 encoded content
    with pytest.raises(SerializationError, match="Invalid base64-encoded plain string value"):
        _deserialize_plain_string_value(
            {"value": "not!!!valid===base64", "value_encoding": "base64"}
        )


# ---------------------------------------------------------------------------
# _deserialize_plain_string_raw_bytes
# ---------------------------------------------------------------------------


def test_deserialize_plain_string_raw_bytes_absent() -> None:
    assert _deserialize_plain_string_raw_bytes({}) is None


def test_deserialize_plain_string_raw_bytes_valid_base64() -> None:
    import base64

    encoded = base64.b64encode(b"\xde\xad\xbe\xef").decode("ascii")
    result = _deserialize_plain_string_raw_bytes(
        {"raw_value": encoded, "raw_value_encoding": "base64"}
    )
    assert result == b"\xde\xad\xbe\xef"


def test_deserialize_plain_string_raw_bytes_wrong_encoding_raises() -> None:
    # Lines 507-508: encoding != base64
    with pytest.raises(SerializationError, match="must use base64 encoding"):
        _deserialize_plain_string_raw_bytes({"raw_value": "abc", "raw_value_encoding": "hex"})


def test_deserialize_plain_string_raw_bytes_non_string_value_raises() -> None:
    # Lines 511-512
    with pytest.raises(SerializationError, match="must be a base64 string"):
        _deserialize_plain_string_raw_bytes({"raw_value": 123, "raw_value_encoding": "base64"})


def test_deserialize_plain_string_raw_bytes_invalid_base64_raises() -> None:
    # Lines 515-517
    with pytest.raises(SerializationError, match="Invalid base64-encoded plain string raw_value"):
        _deserialize_plain_string_raw_bytes(
            {"raw_value": "not!!!valid===", "raw_value_encoding": "base64"}
        )


# ---------------------------------------------------------------------------
# _deserialize_bool_field
# ---------------------------------------------------------------------------


def test_deserialize_bool_field_default_false() -> None:
    assert _deserialize_bool_field({}, "active", "Thing") is False


def test_deserialize_bool_field_explicit_true() -> None:
    assert _deserialize_bool_field({"active": True}, "active", "Thing") is True


def test_deserialize_bool_field_non_bool_raises() -> None:
    # Lines 597-602
    with pytest.raises(SerializationError, match="must be a boolean"):
        _deserialize_bool_field({"active": "yes"}, "active", "Thing")


# ---------------------------------------------------------------------------
# _deserialize_dict_field
# ---------------------------------------------------------------------------


def test_deserialize_dict_field_empty() -> None:
    result = _deserialize_dict_field({}, "params", "Thing")
    assert result == {}


def test_deserialize_dict_field_with_scalar_values() -> None:
    result = _deserialize_dict_field({"params": {"k": "v", "n": 1}}, "params", "Thing")
    assert result == {"k": "v", "n": 1}


def test_deserialize_dict_field_non_string_keys_raises() -> None:
    # Lines 614-615
    with pytest.raises(SerializationError, match="keys must be strings"):
        _deserialize_dict_field({"params": {1: "val"}}, "params", "Thing")


def test_deserialize_dict_field_not_a_dict_raises() -> None:
    # Line 616-617
    with pytest.raises(SerializationError, match="must be a dictionary"):
        _deserialize_dict_field({"params": "not_a_dict"}, "params", "Thing")


# ---------------------------------------------------------------------------
# _deserialize_pragma_parameter_value
# ---------------------------------------------------------------------------


def test_deserialize_pragma_parameter_value_string() -> None:
    assert _deserialize_pragma_parameter_value("hello", "Pragma p") == "hello"


def test_deserialize_pragma_parameter_value_bool() -> None:
    assert _deserialize_pragma_parameter_value(True, "Pragma p") is True


def test_deserialize_pragma_parameter_value_int() -> None:
    assert _deserialize_pragma_parameter_value(42, "Pragma p") == 42


def test_deserialize_pragma_parameter_value_finite_float() -> None:
    result = _deserialize_pragma_parameter_value(3.14, "Pragma p")
    assert result == 3.14


def test_deserialize_pragma_parameter_value_infinite_float_raises() -> None:
    # Line 626
    with pytest.raises(SerializationError, match="must be scalar"):
        _deserialize_pragma_parameter_value(math.inf, "Pragma p")


def test_deserialize_pragma_parameter_value_nan_raises() -> None:
    with pytest.raises(SerializationError, match="must be scalar"):
        _deserialize_pragma_parameter_value(math.nan, "Pragma p")


def test_deserialize_pragma_parameter_value_list_raises() -> None:
    with pytest.raises(SerializationError, match="must be scalar"):
        _deserialize_pragma_parameter_value([1, 2], "Pragma p")


# ---------------------------------------------------------------------------
# _deserialize_meta_value
# ---------------------------------------------------------------------------


def test_deserialize_meta_value_string() -> None:
    assert _deserialize_meta_value({"value": "text"}) == "text"


def test_deserialize_meta_value_bool() -> None:
    assert _deserialize_meta_value({"value": True}) is True


def test_deserialize_meta_value_int() -> None:
    assert _deserialize_meta_value({"value": 7}) == 7


def test_deserialize_meta_value_float_raises() -> None:
    # Line 638: float is not accepted by _deserialize_meta_value
    with pytest.raises(SerializationError, match="must be a string, integer, or boolean"):
        _deserialize_meta_value({"value": 3.14})


def test_deserialize_meta_value_list_raises() -> None:
    with pytest.raises(SerializationError, match="must be a string, integer, or boolean"):
        _deserialize_meta_value({"value": [1, 2]})


# ---------------------------------------------------------------------------
# _deserialize_meta_entry_value
# ---------------------------------------------------------------------------


def test_deserialize_meta_entry_value_string() -> None:
    assert _deserialize_meta_entry_value({"value": "text"}) == "text"


def test_deserialize_meta_entry_value_bool() -> None:
    assert _deserialize_meta_entry_value({"value": True}) is True


def test_deserialize_meta_entry_value_int() -> None:
    assert _deserialize_meta_entry_value({"value": 5}) == 5


def test_deserialize_meta_entry_value_finite_float() -> None:
    result = _deserialize_meta_entry_value({"value": 2.718})
    assert result == 2.718


def test_deserialize_meta_entry_value_infinite_float_raises() -> None:
    # Lines 649-650
    with pytest.raises(SerializationError, match="must be a string, integer, boolean, or finite"):
        _deserialize_meta_entry_value({"value": math.inf})


def test_deserialize_meta_entry_value_list_raises() -> None:
    with pytest.raises(SerializationError, match="must be a string, integer, boolean, or finite"):
        _deserialize_meta_entry_value({"value": [1]})


# ---------------------------------------------------------------------------
# _is_negated_nibble_pattern
# ---------------------------------------------------------------------------


def test_is_negated_nibble_pattern_wrong_length_returns_false() -> None:
    # Line 655: len != 2
    assert _is_negated_nibble_pattern("?") is False
    assert _is_negated_nibble_pattern("abc") is False
    assert _is_negated_nibble_pattern("") is False


def test_is_negated_nibble_pattern_question_first() -> None:
    assert _is_negated_nibble_pattern("?A") is True


def test_is_negated_nibble_pattern_question_second() -> None:
    assert _is_negated_nibble_pattern("A?") is True


def test_is_negated_nibble_pattern_both_hex_is_false() -> None:
    assert _is_negated_nibble_pattern("AB") is False


def test_is_negated_nibble_pattern_both_question_is_false() -> None:
    assert _is_negated_nibble_pattern("??") is False


# ---------------------------------------------------------------------------
# Additional helpers exercised at lower coverage
# ---------------------------------------------------------------------------


def test_validate_local_identifier_text_valid() -> None:
    result = _validate_local_identifier_text("x")
    assert result == "x"


def test_validate_local_identifier_text_allow_string_identifier() -> None:
    result = _validate_local_identifier_text("x", allow_string_identifier=True)
    assert result == "x"


def test_validate_local_identifier_text_invalid_raises() -> None:
    with pytest.raises(SerializationError):
        _validate_local_identifier_text("")


def test_validate_loop_variable_text_valid() -> None:
    result = _validate_loop_variable_text("valid_var")
    assert result == "valid_var"


def test_validate_loop_variable_text_invalid_raises() -> None:
    with pytest.raises(SerializationError):
        _validate_loop_variable_text("")


def test_validate_local_identifier_list_valid() -> None:
    result = _validate_local_identifier_list(["a", "b"])
    assert result == ["a", "b"]


def test_validate_local_identifier_list_invalid_raises() -> None:
    with pytest.raises(SerializationError):
        _validate_local_identifier_list([""])


def test_validate_yara_identifier_text_valid() -> None:
    result = _validate_yara_identifier_text("rule_name", "rule")
    assert result == "rule_name"


def test_validate_yara_identifier_text_invalid_raises() -> None:
    with pytest.raises(SerializationError):
        _validate_yara_identifier_text("123bad", "rule")


def test_deserialize_location_int_field_valid() -> None:
    assert _deserialize_location_int_field({"line": 3}, "line") == 3


def test_deserialize_location_int_field_bool_raises() -> None:
    with pytest.raises(SerializationError, match="must be an integer"):
        _deserialize_location_int_field({"line": True}, "line")


def test_deserialize_location_int_field_missing_raises() -> None:
    with pytest.raises(SerializationError):
        _deserialize_location_int_field({}, "line")


def test_deserialize_is_anonymous_absent_is_false() -> None:
    assert _deserialize_is_anonymous({}) is False


def test_deserialize_is_anonymous_true() -> None:
    assert _deserialize_is_anonymous({"is_anonymous": True}) is True


def test_deserialize_is_anonymous_non_bool_raises() -> None:
    with pytest.raises(SerializationError, match="must be a boolean"):
        _deserialize_is_anonymous({"is_anonymous": "yes"})


def test_deserialize_location_valid() -> None:
    data = {"line": 2, "column": 5, "file": "test.yar"}
    loc = _deserialize_location(data)
    assert loc.line == 2
    assert loc.column == 5
    assert loc.file == "test.yar"


def test_deserialize_location_invalid_structure_raises() -> None:
    # Negative line triggers validate_structure -> raises SerializationError
    data = {"line": -1, "column": 1}
    with pytest.raises(SerializationError):
        _deserialize_location(data)


def test_validate_string_occurrence_index_expression_boolean_raises() -> None:
    from yaraast.ast.expressions import BooleanLiteral

    expr = BooleanLiteral(value=True)
    with pytest.raises(SerializationError, match="must not be boolean"):
        _validate_string_occurrence_index_expression(expr, "occurrence index")


def test_validate_string_occurrence_index_expression_non_boolean_passes() -> None:
    from yaraast.ast.expressions import IntegerLiteral

    expr = IntegerLiteral(value=1)
    result = _validate_string_occurrence_index_expression(expr, "occurrence index")
    assert result is expr


def test_validate_in_expression_range_valid() -> None:
    from yaraast.ast.expressions import IntegerLiteral, RangeExpression

    rng = RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=10))
    result = _validate_in_expression_range(rng)
    assert result is rng


def test_validate_in_expression_range_non_range_raises() -> None:
    with pytest.raises(SerializationError, match="must be a range expression"):
        _validate_in_expression_range("not_a_range")


# ---------------------------------------------------------------------------
# _expected_type_names
# ---------------------------------------------------------------------------


def test_expected_type_names_single_type() -> None:
    # Lines 57-58: single type, not a tuple — wraps in tuple internally
    result = _expected_type_names(str)
    assert result == "str"


def test_expected_type_names_tuple_of_types() -> None:
    result = _expected_type_names((str, int))
    assert result == "str or int"


# ---------------------------------------------------------------------------
# _validate_extern_rule_identifier_text
# ---------------------------------------------------------------------------


def test_validate_extern_rule_identifier_text_valid() -> None:
    # Line 113: delegates to _validate_yara_identifier_text with "extern rule" kind
    result = _validate_extern_rule_identifier_text("my_rule")
    assert result == "my_rule"


def test_validate_extern_rule_identifier_text_invalid_raises() -> None:
    with pytest.raises(SerializationError):
        _validate_extern_rule_identifier_text("123bad")


# ---------------------------------------------------------------------------
# _validate_extern_rule_path_text
# ---------------------------------------------------------------------------


def test_validate_extern_rule_path_text_valid() -> None:
    # Lines 117-120
    result = _validate_extern_rule_path_text("my_module.my_rule")
    assert result == "my_module.my_rule"


def test_validate_extern_rule_path_text_single_segment_valid() -> None:
    result = _validate_extern_rule_path_text("rule_name")
    assert result == "rule_name"


def test_validate_extern_rule_path_text_invalid_raises() -> None:
    with pytest.raises(SerializationError):
        _validate_extern_rule_path_text("123bad")


# ---------------------------------------------------------------------------
# _validate_function_identifier_text
# ---------------------------------------------------------------------------


def test_validate_function_identifier_text_no_receiver() -> None:
    # Lines 124-127: receiver is None → validates as path
    result = _validate_function_identifier_text("module.func_name", None)
    assert result == "module.func_name"


def test_validate_function_identifier_text_with_receiver() -> None:
    # Lines 124-127: receiver is not None → validates as simple identifier
    result = _validate_function_identifier_text("func_name", "receiver_obj")
    assert result == "func_name"


def test_validate_function_identifier_text_invalid_no_receiver_raises() -> None:
    with pytest.raises(SerializationError):
        _validate_function_identifier_text("123bad", None)


def test_validate_function_identifier_text_invalid_with_receiver_raises() -> None:
    with pytest.raises(SerializationError):
        _validate_function_identifier_text("123bad", "receiver")


# ---------------------------------------------------------------------------
# _validate_namespace_identifier_text
# ---------------------------------------------------------------------------


def test_validate_namespace_identifier_text_valid() -> None:
    # Lines 133-136
    result = _validate_namespace_identifier_text("my.namespace")
    assert result == "my.namespace"


def test_validate_namespace_identifier_text_invalid_raises() -> None:
    with pytest.raises(SerializationError):
        _validate_namespace_identifier_text("123bad")


# ---------------------------------------------------------------------------
# _validate_optional_namespace_identifier_text
# ---------------------------------------------------------------------------


def test_validate_optional_namespace_identifier_text_none() -> None:
    # Lines 140-143
    result = _validate_optional_namespace_identifier_text(None)
    assert result is None


def test_validate_optional_namespace_identifier_text_valid_string() -> None:
    result = _validate_optional_namespace_identifier_text("my_ns")
    assert result == "my_ns"


def test_validate_optional_namespace_identifier_text_invalid_raises() -> None:
    with pytest.raises(SerializationError):
        _validate_optional_namespace_identifier_text(123)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _validate_extern_import_rule_identifiers
# ---------------------------------------------------------------------------


def test_validate_extern_import_rule_identifiers_valid() -> None:
    # Lines 147-149
    result = _validate_extern_import_rule_identifiers(["my_module.my_rule", "rule_name"])
    assert result == ["my_module.my_rule", "rule_name"]


def test_validate_extern_import_rule_identifiers_empty() -> None:
    result = _validate_extern_import_rule_identifiers([])
    assert result == []


def test_validate_extern_import_rule_identifiers_invalid_raises() -> None:
    with pytest.raises(SerializationError):
        _validate_extern_import_rule_identifiers(["123bad"])


# ---------------------------------------------------------------------------
# _validate_unique_extern_rule_identifiers
# ---------------------------------------------------------------------------


class _FakeRuleForExtern:
    def __init__(self, name: object) -> None:
        self.name = name


def test_validate_unique_extern_rule_identifiers_empty_lists() -> None:
    # Lines 172-173: empty lists call validate_extern_rule_identifiers without error
    _validate_unique_extern_rule_identifiers([], [], [])


def test_validate_unique_extern_rule_identifiers_invalid_rule_name_raises() -> None:
    # Lines 172-173: invalid rule name triggers TypeError/ValueError -> wrapped
    with pytest.raises(SerializationError):
        _validate_unique_extern_rule_identifiers([_FakeRuleForExtern(None)], [], [])


# ---------------------------------------------------------------------------
# _validate_range_expression_bounds
# ---------------------------------------------------------------------------


def test_validate_range_expression_bounds_valid() -> None:
    from yaraast.ast.expressions import IntegerLiteral, RangeExpression

    # Lines 246-252
    rng = RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=100))
    result = _validate_range_expression_bounds(rng)
    assert result is rng


def test_validate_range_expression_bounds_inverted_raises() -> None:
    from yaraast.ast.expressions import IntegerLiteral, RangeExpression

    rng = RangeExpression(low=IntegerLiteral(value=10), high=IntegerLiteral(value=0))
    with pytest.raises(SerializationError, match="cannot exceed"):
        _validate_range_expression_bounds(rng)


# ---------------------------------------------------------------------------
# _validate_set_expression_elements
# ---------------------------------------------------------------------------


def test_validate_set_expression_elements_valid() -> None:
    from yaraast.ast.expressions import Expression, IntegerLiteral, SetExpression

    # Lines 256-260
    elements: list[Expression] = [IntegerLiteral(value=1), IntegerLiteral(value=2)]
    s = SetExpression(elements=elements)
    result = _validate_set_expression_elements(s)
    assert result is s


def test_validate_set_expression_elements_empty_raises() -> None:
    from yaraast.ast.expressions import SetExpression

    s = SetExpression(elements=[])
    with pytest.raises(SerializationError):
        _validate_set_expression_elements(s)


# ---------------------------------------------------------------------------
# _validate_integer_expression
# ---------------------------------------------------------------------------


def test_validate_integer_expression_valid() -> None:
    from yaraast.ast.expressions import IntegerLiteral

    # Lines 264-268
    expr = IntegerLiteral(value=7)
    result = _validate_integer_expression(expr, "index")
    assert result is expr


def test_validate_integer_expression_boolean_raises() -> None:
    from yaraast.ast.expressions import BooleanLiteral

    with pytest.raises(SerializationError, match="must be integer"):
        _validate_integer_expression(BooleanLiteral(value=True), "index")


# ---------------------------------------------------------------------------
# _validate_for_expression_iterable
# ---------------------------------------------------------------------------


def test_validate_for_expression_iterable_valid_range() -> None:
    from yaraast.ast.expressions import IntegerLiteral, RangeExpression

    # Lines 279-295
    rng = RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=5))
    result = _validate_for_expression_iterable(rng)
    assert result is rng


def test_validate_for_expression_iterable_non_iterable_raises() -> None:
    from yaraast.ast.expressions import BooleanLiteral

    with pytest.raises(SerializationError, match="must be a range, set, or iterable"):
        _validate_for_expression_iterable(BooleanLiteral(value=True))


def test_validate_for_expression_iterable_set_with_bool_items_raises() -> None:
    from yaraast.ast.expressions import BooleanLiteral, SetExpression

    bad_set = SetExpression(elements=[BooleanLiteral(value=True)])
    with pytest.raises(SerializationError, match="must be integer or string expressions"):
        _validate_for_expression_iterable(bad_set)


def test_validate_for_expression_iterable_set_with_integer_items_valid() -> None:
    from yaraast.ast.expressions import IntegerLiteral, SetExpression

    good_set = SetExpression(elements=[IntegerLiteral(value=1), IntegerLiteral(value=2)])
    result = _validate_for_expression_iterable(good_set)
    assert result is good_set


# ---------------------------------------------------------------------------
# _validate_quantifier_text — branches 328->333 and 336-337
# ---------------------------------------------------------------------------


def test_validate_quantifier_text_non_decimal_percentage_falls_through() -> None:
    # Lines 328->333: percentage_text is '5.0' (not decimal), falls through
    # to the float-marker check, then to identifier validation which fails
    with pytest.raises(SerializationError):
        _validate_quantifier_text("5.0%", "q", allow_percentage=True)


def test_validate_quantifier_text_float_parse_failure_falls_through() -> None:
    # Lines 336-337: value contains '.' and 'e' but float() raises ValueError
    # (e.g. '.e' is malformed) — the except ValueError: pass fires, falls to
    # validate_yara_identifier which rejects it
    with pytest.raises(SerializationError):
        _validate_quantifier_text(".e", "q", allow_percentage=False)


# ---------------------------------------------------------------------------
# _validate_quantifier_value — Expression branch
# ---------------------------------------------------------------------------


def test_validate_quantifier_value_expression_returns_directly() -> None:
    from yaraast.ast.expressions import IntegerLiteral

    # Line 353: isinstance(value, Expression) → return value immediately
    expr = IntegerLiteral(value=3)
    result = _validate_quantifier_value(expr, "q", allow_percentage=False)
    assert result is expr


# ---------------------------------------------------------------------------
# _deserialize_object
# ---------------------------------------------------------------------------


def test_deserialize_object_dict_passes_through() -> None:
    data: dict[str, object] = {"key": "value"}
    result = _deserialize_object(data, "Thing")
    assert result is data


def test_deserialize_object_non_dict_raises() -> None:
    # Lines 427-428
    with pytest.raises(SerializationError, match="must be an object"):
        _deserialize_object("not_a_dict", "Thing")


def test_deserialize_object_list_raises() -> None:
    with pytest.raises(SerializationError, match="must be an object"):
        _deserialize_object([1, 2], "Thing")


# ---------------------------------------------------------------------------
# _deserialize_comment_text
# ---------------------------------------------------------------------------


def test_deserialize_comment_text_valid() -> None:
    # Line 466
    result = _deserialize_comment_text({"text": "// inline comment"})
    assert result == "// inline comment"


def test_deserialize_comment_text_missing_raises() -> None:
    with pytest.raises(SerializationError):
        _deserialize_comment_text({})


# ---------------------------------------------------------------------------
# _deserialize_integer_literal_value
# ---------------------------------------------------------------------------


def test_deserialize_integer_literal_value_valid() -> None:
    # Lines 531-535
    assert _deserialize_integer_literal_value({"value": 42}) == 42


def test_deserialize_integer_literal_value_bool_raises() -> None:
    with pytest.raises(SerializationError, match="must be an integer"):
        _deserialize_integer_literal_value({"value": True})


def test_deserialize_integer_literal_value_string_raises() -> None:
    with pytest.raises(SerializationError, match="must be an integer"):
        _deserialize_integer_literal_value({"value": "42"})


# ---------------------------------------------------------------------------
# _deserialize_boolean_literal_value
# ---------------------------------------------------------------------------


def test_deserialize_boolean_literal_value_true() -> None:
    # Lines 539-543
    assert _deserialize_boolean_literal_value({"value": True}) is True


def test_deserialize_boolean_literal_value_false() -> None:
    assert _deserialize_boolean_literal_value({"value": False}) is False


def test_deserialize_boolean_literal_value_int_raises() -> None:
    with pytest.raises(SerializationError, match="must be a boolean"):
        _deserialize_boolean_literal_value({"value": 1})


# ---------------------------------------------------------------------------
# _deserialize_double_literal_value
# ---------------------------------------------------------------------------


def test_deserialize_double_literal_value_float() -> None:
    # Lines 547-554
    result = _deserialize_double_literal_value({"value": 3.14})
    assert result == 3.14


def test_deserialize_double_literal_value_int_promoted() -> None:
    result = _deserialize_double_literal_value({"value": 2})
    assert result == 2.0
    assert isinstance(result, float)


def test_deserialize_double_literal_value_infinite_raises() -> None:
    with pytest.raises(SerializationError, match="must be finite"):
        _deserialize_double_literal_value({"value": math.inf})


def test_deserialize_double_literal_value_string_raises() -> None:
    with pytest.raises(SerializationError, match="must be numeric"):
        _deserialize_double_literal_value({"value": "3.14"})


def test_deserialize_double_literal_value_bool_raises() -> None:
    with pytest.raises(SerializationError, match="must be numeric"):
        _deserialize_double_literal_value({"value": True})


# ---------------------------------------------------------------------------
# _deserialize_string_field
# ---------------------------------------------------------------------------


def test_deserialize_string_field_valid() -> None:
    # Lines 557-562
    result = _deserialize_string_field({"op": "and"}, "op", "BinaryExpr")
    assert result == "and"


def test_deserialize_string_field_non_string_raises() -> None:
    # Lines 561-562
    with pytest.raises(SerializationError, match="must be a string"):
        _deserialize_string_field({"op": 42}, "op", "BinaryExpr")


# ---------------------------------------------------------------------------
# _deserialize_nullable_string_field
# ---------------------------------------------------------------------------


def test_deserialize_nullable_string_field_none() -> None:
    # Lines 565-573
    result = _deserialize_nullable_string_field({}, "file", "Location")
    assert result is None


def test_deserialize_nullable_string_field_valid_string() -> None:
    result = _deserialize_nullable_string_field({"file": "test.yar"}, "file", "Location")
    assert result == "test.yar"


def test_deserialize_nullable_string_field_non_string_raises() -> None:
    # Lines 572-573
    with pytest.raises(SerializationError, match="must be a string"):
        _deserialize_nullable_string_field({"file": 42}, "file", "Location")


# ---------------------------------------------------------------------------
# _deserialize_string_list_field
# ---------------------------------------------------------------------------


def test_deserialize_string_list_field_valid() -> None:
    # Lines 576-582
    result = _deserialize_string_list_field({"tags": ["a", "b"]}, "tags", "Rule")
    assert result == ["a", "b"]


def test_deserialize_string_list_field_empty() -> None:
    result = _deserialize_string_list_field({}, "tags", "Rule")
    assert result == []


def test_deserialize_string_list_field_mixed_types_raises() -> None:
    # Lines 581-582
    with pytest.raises(SerializationError, match="must be a list of strings"):
        _deserialize_string_list_field({"tags": [1, "str"]}, "tags", "Rule")


def test_deserialize_string_list_field_not_list_raises() -> None:
    with pytest.raises(SerializationError, match="must be a list of strings"):
        _deserialize_string_list_field({"tags": "single_tag"}, "tags", "Rule")


# ---------------------------------------------------------------------------
# _deserialize_list_field
# ---------------------------------------------------------------------------


def test_deserialize_list_field_valid() -> None:
    # Lines 585-591
    result = _deserialize_list_field({"items": [1, "a", None]}, "items", "Node")
    assert result == [1, "a", None]


def test_deserialize_list_field_empty() -> None:
    result = _deserialize_list_field({}, "items", "Node")
    assert result == []


def test_deserialize_list_field_not_list_raises() -> None:
    # Lines 590-591
    with pytest.raises(SerializationError, match="must be a list"):
        _deserialize_list_field({"items": "not_a_list"}, "items", "Node")
