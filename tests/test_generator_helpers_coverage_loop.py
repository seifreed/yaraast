# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests targeting uncovered lines in yaraast/codegen/generator_helpers.py."""

from __future__ import annotations

import pytest

from yaraast.ast.modifiers import StringModifier, StringModifierType
from yaraast.ast.strings import HexAlternative, HexByte, HexWildcard
from yaraast.codegen.generator_helpers import (
    _canonical_regex_suffix,
    _collect_contextual_expression_errors,
    _format_base64_modifier_value,
    _format_xor_modifier_value,
    _is_negated_nibble_pattern,
    _modifier_names,
    _normalize_integer_literal_text,
    _parse_xor_key,
    _regex_modifier_name,
    _validate_hex_jump_bound,
    _validate_hex_negated_value,
    _validate_renderable_hex_token,
    _validate_spaced_string_modifier,
    _validate_string_modifier_collection,
    _validate_string_modifier_value,
    escape_plain_string_value,
    format_double_literal,
    format_integer_literal,
    format_modifier,
    format_modifiers,
    format_regex_modifiers,
    split_regex_modifiers,
    validate_duplicate_string_modifiers,
    validate_hex_nibble_high,
    validate_hex_string_modifiers,
    validate_no_embedded_nul,
    validate_no_unicode_surrogates,
    validate_plain_string_modifiers,
    validate_regex_string_modifiers,
    validate_rule_string_references,
    validate_string_modifier_values,
    validate_string_wildcard_text,
)
from yaraast.limits import LIBYARA_HEX_JUMP_MAX

_YARA_INTEGER_MIN_VALUE = -(2**63)


# ---------------------------------------------------------------------------
# validate_no_unicode_surrogates -- line 103-104 (raise path)
# ---------------------------------------------------------------------------


def test_validate_no_unicode_surrogates_raises_on_surrogate() -> None:
    """Line 103-104: the ValueError branch when a surrogate code point is present."""
    surrogate = "\ud83d"  # lone high surrogate (0xD83D is in 0xD800-0xDFFF)
    with pytest.raises(ValueError, match="Unicode surrogate code points"):
        validate_no_unicode_surrogates(surrogate, "Test context")


def test_validate_no_unicode_surrogates_passes_for_clean_string() -> None:
    """Baseline: the function returns None when no surrogates are present."""
    validate_no_unicode_surrogates("hello world", "Test context")


# ---------------------------------------------------------------------------
# validate_no_embedded_nul -- lines 108-111 (body is covered via escape but
# raise path needs a direct caller)
# ---------------------------------------------------------------------------


def test_validate_no_embedded_nul_raises_when_nul_present() -> None:
    """Lines 110-111: ValueError raised when a NUL byte appears in the string."""
    with pytest.raises(ValueError, match="NUL characters"):
        validate_no_embedded_nul("abc\x00def", "Test context")


def test_validate_no_embedded_nul_passes_for_clean_string() -> None:
    """Baseline: the function returns None when no NUL is present."""
    validate_no_embedded_nul("abc", "Test context")


# ---------------------------------------------------------------------------
# _escape_plain_byte -- lines 122 and 124 (0x0D and 0x09 special bytes)
# The function is internal but is exercised via escape_plain_string_value(bytes).
# ---------------------------------------------------------------------------


def test_escape_plain_byte_carriage_return() -> None:
    """Line 122: 0x0D byte encodes as '\\r'."""
    result = escape_plain_string_value(b"\r")
    assert result == "\\r"


def test_escape_plain_byte_horizontal_tab() -> None:
    """Line 124: 0x09 byte encodes as '\\t'."""
    result = escape_plain_string_value(b"\t")
    assert result == "\\t"


# ---------------------------------------------------------------------------
# validate_string_wildcard_text -- lines 254-260
# ---------------------------------------------------------------------------


def test_validate_string_wildcard_text_returns_star_global() -> None:
    """Line 254: body == '*' branch."""
    assert validate_string_wildcard_text("$*") == "$*"
    assert validate_string_wildcard_text("*") == "$*"


def test_validate_string_wildcard_text_valid_prefix_wildcard() -> None:
    """Line 255-258: body ends with '*' with a valid prefix."""
    assert validate_string_wildcard_text("$abc*") == "$abc*"
    assert validate_string_wildcard_text("abc*") == "$abc*"


def test_validate_string_wildcard_text_invalid_raises() -> None:
    """Lines 255->259, 259-260: fallthrough to ValueError on bad wildcard pattern.

    The branch 255->259 fires when body does NOT end with '*' (so it is neither
    the global-wildcard body '*' nor a prefix wildcard).  A plain identifier body
    such as 'abc' hits this path and falls through to the ValueError.
    """
    # body = "abc" -- doesn't end with '*', falls straight to ValueError (255->259)
    with pytest.raises(ValueError, match="Invalid string wildcard"):
        validate_string_wildcard_text("$abc")
    # body = "**" -- endswith('*') but prefix '*' fails the identifier regex
    with pytest.raises(ValueError, match="Invalid string wildcard"):
        validate_string_wildcard_text("$**")
    with pytest.raises(ValueError, match="Invalid string wildcard"):
        validate_string_wildcard_text("$$abc*")


# ---------------------------------------------------------------------------
# validate_rule_string_references -- line 303 (non-Rule object early return)
# ---------------------------------------------------------------------------


def test_validate_rule_string_references_non_rule_with_condition_returns() -> None:
    """Line 303: isinstance check fails for a non-Rule object with a condition."""

    class _FakeRule:
        condition = object()  # satisfies the None check
        name = "fake"

    # Must not raise -- the function returns early when rule is not a Rule instance.
    validate_rule_string_references(_FakeRule())


# ---------------------------------------------------------------------------
# _collect_contextual_expression_errors -- lines 429-439 (dict branch)
# ---------------------------------------------------------------------------


def test_collect_contextual_expression_errors_dict_branch() -> None:
    """Lines 429-439: the dict branch iterates values for recursive error collection."""
    # A bare dict with no ASTNode values yields an empty error set.
    result = _collect_contextual_expression_errors({"a": 1, "b": "text"})
    assert result == set()


# ---------------------------------------------------------------------------
# _validate_renderable_hex_token -- lines 505-515 (HexWildcard, HexAlternative,
# and unsupported type)
# ---------------------------------------------------------------------------


def test_validate_renderable_hex_token_hex_wildcard_passes() -> None:
    """Line 505-506: HexWildcard is accepted and returns immediately."""
    _validate_renderable_hex_token(HexWildcard())


def test_validate_renderable_hex_token_hex_alternative_valid() -> None:
    """Lines 507-513: HexAlternative branch validates recursively without error."""
    alternative = HexAlternative(alternatives=[[HexByte(0xAB)], [HexByte(0xCD)]])
    # Must not raise; exercises the HexAlternative branch.
    _validate_renderable_hex_token(alternative)


def test_validate_renderable_hex_token_unsupported_raises() -> None:
    """Lines 514-515: unsupported token type raises TypeError."""
    with pytest.raises(TypeError, match="Unsupported hex token"):
        _validate_renderable_hex_token("not_a_token")


# ---------------------------------------------------------------------------
# format_integer_literal -- lines 562 and 565 (hex lookup and multiples)
# ---------------------------------------------------------------------------


def test_format_integer_literal_known_hex_value() -> None:
    """Line 562: known-hex values are returned as their preset string representation."""
    assert format_integer_literal(0x4D5A) == "0x4D5A"
    assert format_integer_literal(0x00004550) == "0x00004550"


def test_format_integer_literal_multiple_of_16_above_256() -> None:
    """Line 565: integers >= 256 that are multiples of 16 are hex-formatted."""
    # 512 = 0x200, multiple of 256 -> hex
    assert format_integer_literal(512) == hex(512)
    # 272 = 0x110, multiple of 16 -> hex
    assert format_integer_literal(272) == hex(272)


# ---------------------------------------------------------------------------
# _normalize_integer_literal_text -- line 616->618 (sign extraction)
# ---------------------------------------------------------------------------


def test_normalize_integer_literal_text_negative_hex() -> None:
    """Line 616-618: negative value with hex prefix preserves sign."""
    assert _normalize_integer_literal_text("-0xff") == "-0xff"


def test_normalize_integer_literal_text_negative_octal() -> None:
    """Line 616-618: negative value with octal prefix preserves sign."""
    assert _normalize_integer_literal_text("-0o17") == "-0o17"


def test_normalize_integer_literal_text_negative_decimal() -> None:
    """Line 616-618: negative decimal value preserves sign."""
    assert _normalize_integer_literal_text("-42") == "-42"


def test_normalize_integer_literal_text_positive_sign_hex() -> None:
    """Branch 616->618: '+' prefix is stripped; sign stays '' (not '-')."""
    assert _normalize_integer_literal_text("+0x10") == "0x10"


def test_normalize_integer_literal_text_positive_sign_decimal() -> None:
    """Branch 616->618: '+' prefix on decimal is stripped without a sign."""
    assert _normalize_integer_literal_text("+42") == "42"


# ---------------------------------------------------------------------------
# format_double_literal -- lines 644-646 (int at MIN and int != MIN)
# ---------------------------------------------------------------------------


def test_format_double_literal_integer_at_min() -> None:
    """Line 644-645: integer equal to _YARA_INTEGER_MIN returns the safe expression."""
    result = format_double_literal(_YARA_INTEGER_MIN_VALUE)
    assert result == "(-9223372036854775807 - 1)"


def test_format_double_literal_positive_int_returns_str() -> None:
    """Line 646: a non-MIN integer returns str(value)."""
    assert format_double_literal(100) == "100"
    assert format_double_literal(0) == "0"


# ---------------------------------------------------------------------------
# _validate_hex_negated_value -- lines 774-775 (nibble pattern branch)
# ---------------------------------------------------------------------------


def test_validate_hex_negated_value_nibble_pattern_first_wildcard() -> None:
    """Lines 774-775: '?A' pattern (wildcard first) is a valid negated nibble."""
    result = _validate_hex_negated_value("?A")
    assert result == "?A"


def test_validate_hex_negated_value_nibble_pattern_second_wildcard() -> None:
    """Lines 774-775: 'A?' pattern (wildcard second) is a valid negated nibble."""
    result = _validate_hex_negated_value("A?")
    assert result == "A?"


def test_validate_hex_negated_value_invalid_raises() -> None:
    """Line 776-777: non-byte, non-nibble string raises TypeError."""
    with pytest.raises(TypeError, match="HexNegatedByte value must be a byte or negated nibble"):
        _validate_hex_negated_value("GG")


# ---------------------------------------------------------------------------
# _is_negated_nibble_pattern -- lines 781-785
# ---------------------------------------------------------------------------


def test_is_negated_nibble_pattern_too_short() -> None:
    """Line 782: length != 2 returns False immediately."""
    assert _is_negated_nibble_pattern("A") is False
    assert _is_negated_nibble_pattern("") is False
    assert _is_negated_nibble_pattern("?AB") is False


def test_is_negated_nibble_pattern_wildcard_first() -> None:
    """Lines 784-785: '?X' where X is a valid hex char returns True."""
    assert _is_negated_nibble_pattern("?F") is True


def test_is_negated_nibble_pattern_wildcard_second() -> None:
    """Lines 784-785: 'X?' where X is a valid hex char returns True."""
    assert _is_negated_nibble_pattern("0?") is True


def test_is_negated_nibble_pattern_no_wildcard() -> None:
    """Lines 784-785: no wildcard present returns False."""
    assert _is_negated_nibble_pattern("AB") is False


# ---------------------------------------------------------------------------
# validate_hex_nibble_high -- lines 801-802 (non-boolean raises)
# ---------------------------------------------------------------------------


def test_validate_hex_nibble_high_raises_on_non_bool() -> None:
    """Lines 801-802: non-boolean value raises TypeError."""
    with pytest.raises(TypeError, match="HexNibble high must be a boolean"):
        validate_hex_nibble_high(1)
    with pytest.raises(TypeError, match="HexNibble high must be a boolean"):
        validate_hex_nibble_high("true")


def test_validate_hex_nibble_high_returns_bool() -> None:
    """Baseline: True and False are accepted and returned unchanged."""
    assert validate_hex_nibble_high(True) is True
    assert validate_hex_nibble_high(False) is False


# ---------------------------------------------------------------------------
# _validate_hex_jump_bound -- lines 810-811 (negative) and 813-814 (> max)
# ---------------------------------------------------------------------------


def test_validate_hex_jump_bound_negative_raises() -> None:
    """Lines 810-811: negative integer raises TypeError."""
    with pytest.raises(TypeError, match="must be a non-negative integer"):
        _validate_hex_jump_bound(-1, "min_jump")


def test_validate_hex_jump_bound_exceeds_max_raises() -> None:
    """Lines 813-814: value exceeding LIBYARA_HEX_JUMP_MAX raises ValueError."""
    with pytest.raises(ValueError, match="must not exceed"):
        _validate_hex_jump_bound(LIBYARA_HEX_JUMP_MAX + 1, "max_jump")


def test_validate_hex_jump_bound_none_returns_none() -> None:
    """Baseline: None input returns None."""
    assert _validate_hex_jump_bound(None, "min_jump") is None


def test_validate_hex_jump_bound_valid_int_returns_it() -> None:
    """Baseline: valid non-negative int is returned as-is."""
    assert _validate_hex_jump_bound(5, "min_jump") == 5


# ---------------------------------------------------------------------------
# format_modifier (StringModifier paths) -- lines 831-840
# ---------------------------------------------------------------------------


def test_format_modifier_xor_with_tuple_range() -> None:
    """Line 831-832: xor modifier with a (low, high) tuple uses _format_xor_modifier_value."""
    mod = StringModifier(modifier_type=StringModifierType.XOR, value=(0, 255))
    result = format_modifier(mod)
    assert result == "xor(0-255)"


def test_format_modifier_base64_with_alphabet() -> None:
    """Lines 833-834: base64 modifier with a 64-char alphabet delegates to the helper."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    assert len(alphabet) == 64
    mod = StringModifier(modifier_type=StringModifierType.BASE64, value=alphabet)
    result = format_modifier(mod)
    assert result.startswith("base64(")
    assert alphabet in result


def test_format_modifier_non_str_non_modifier_raises() -> None:
    """Lines 842-844: non-string, non-StringModifier raises TypeError."""
    with pytest.raises(TypeError, match="String modifiers must contain strings or StringModifier"):
        format_modifier(123)


def test_format_modifier_plain_string_modifier() -> None:
    """Lines 845-847: a plain string modifier text is validated and returned."""
    result = format_modifier("nocase")
    assert result == "nocase"


# ---------------------------------------------------------------------------
# _format_base64_modifier_value -- lines 851-861
# ---------------------------------------------------------------------------


def test_format_base64_modifier_value_non_str_raises() -> None:
    """Lines 851-853: non-string value raises TypeError."""
    with pytest.raises(TypeError, match="value must be a string"):
        _format_base64_modifier_value("base64", 42)


def test_format_base64_modifier_value_wrong_length_raises() -> None:
    """Lines 858-860: alphabet not exactly 64 bytes raises TypeError."""
    with pytest.raises(TypeError, match="alphabet must be 64 bytes"):
        _format_base64_modifier_value("base64", "tooshort")


def test_format_base64_modifier_value_valid() -> None:
    """Line 861: valid 64-char alphabet returns the formatted modifier string."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    result = _format_base64_modifier_value("base64", alphabet)
    assert result.startswith('base64("')
    assert result.endswith('")')


def test_format_base64_modifier_value_non_ascii_alphabet_raises_for_length() -> None:
    """Lines 856-857: non-ASCII chars cause encode to fail; b'' has len 0 != 64."""
    non_ascii_alphabet = "A" * 63 + "\xe9"  # 63 ASCII + 1 non-ASCII (latin small e acute)
    with pytest.raises(TypeError, match="alphabet must be 64 bytes"):
        _format_base64_modifier_value("base64", non_ascii_alphabet)


# ---------------------------------------------------------------------------
# _validate_spaced_string_modifier -- lines 865-867
# ---------------------------------------------------------------------------


def test_validate_spaced_string_modifier_unsupported_raises() -> None:
    """Lines 865-867: modifier in unsupported set raises ValueError."""
    with pytest.raises(ValueError, match="Unsupported string modifier"):
        _validate_spaced_string_modifier("dotall")
    with pytest.raises(ValueError, match="Unsupported string modifier"):
        _validate_spaced_string_modifier("totally_unknown_modifier")


# ---------------------------------------------------------------------------
# _validate_string_modifier_value -- lines 873-874
# ---------------------------------------------------------------------------


def test_validate_string_modifier_value_non_parameterized_with_value_raises() -> None:
    """Lines 873-874: passing a value to a non-parameterized modifier raises ValueError."""
    with pytest.raises(ValueError, match="does not accept a value"):
        _validate_string_modifier_value("nocase", "something")
    with pytest.raises(ValueError, match="does not accept a value"):
        _validate_string_modifier_value("fullword", 1)


def test_validate_string_modifier_value_parameterized_passes() -> None:
    """Line 871-872: parameterized modifiers with values are accepted."""
    _validate_string_modifier_value("xor", 42)
    _validate_string_modifier_value("base64", "alphabet")
    _validate_string_modifier_value("nocase", None)


# ---------------------------------------------------------------------------
# _format_xor_modifier_value -- lines 878-905
# ---------------------------------------------------------------------------


def test_format_xor_modifier_value_list_pair_valid() -> None:
    """Lines 878-887: list of two ints formats as 'low-high'."""
    result = _format_xor_modifier_value([0, 255])
    assert result == "0-255"


def test_format_xor_modifier_value_list_pair_descending_raises() -> None:
    """Lines 884-886: descending list pair raises TypeError."""
    with pytest.raises(TypeError, match="must be ascending"):
        _format_xor_modifier_value([255, 0])


def test_format_xor_modifier_value_list_pair_invalid_key_raises() -> None:
    """Lines 881-883: list pair with invalid bound raises TypeError."""
    with pytest.raises(TypeError, match="must contain byte bounds"):
        _format_xor_modifier_value([256, 300])


def test_format_xor_modifier_value_str_range_valid() -> None:
    """Lines 889-899: string 'low-high' form is parsed and normalized."""
    result = _format_xor_modifier_value("1-128")
    assert result == "1-128"


def test_format_xor_modifier_value_str_range_descending_raises() -> None:
    """Lines 896-898: descending string range raises TypeError."""
    with pytest.raises(TypeError, match="must be ascending"):
        _format_xor_modifier_value("200-10")


def test_format_xor_modifier_value_str_range_invalid_bound_raises() -> None:
    """Lines 893-895: string range with unparseable bound raises TypeError."""
    with pytest.raises(TypeError, match="must contain byte bounds"):
        _format_xor_modifier_value("abc-def")


def test_format_xor_modifier_value_single_int() -> None:
    """Lines 901-905: single integer key returns its text form."""
    result = _format_xor_modifier_value(42)
    assert result == "42"


def test_format_xor_modifier_value_invalid_single_raises() -> None:
    """Lines 902-904: value that cannot be parsed as a key raises TypeError."""
    with pytest.raises(TypeError, match="xor value must be a byte"):
        _format_xor_modifier_value(256)


# ---------------------------------------------------------------------------
# _parse_xor_key -- lines 909-922
# ---------------------------------------------------------------------------


def test_parse_xor_key_bool_returns_none() -> None:
    """Lines 909-910: bool input always returns None (guards against int subtype)."""
    assert _parse_xor_key(True) is None
    assert _parse_xor_key(False) is None


def test_parse_xor_key_int_in_range() -> None:
    """Lines 911-913: int in 0-255 range returns a _XorKey."""
    result = _parse_xor_key(0)
    assert result is not None
    assert result.key == 0
    assert result.text == "0"


def test_parse_xor_key_int_out_of_range() -> None:
    """Line 914: int out of 0-255 range returns None."""
    assert _parse_xor_key(256) is None
    assert _parse_xor_key(-1) is None


def test_parse_xor_key_str_valid_decimal() -> None:
    """Lines 915-921: valid decimal string returns parsed key."""
    result = _parse_xor_key("0xFF")
    assert result is not None
    assert result.key == 255


def test_parse_xor_key_str_invalid_returns_none() -> None:
    """Lines 918-919: unparseable string returns None."""
    assert _parse_xor_key("not_a_key") is None


def test_parse_xor_key_str_out_of_byte_range_returns_none() -> None:
    """Branch 920->922: parsed key value > 255 returns None (falls to final return)."""
    result = _parse_xor_key("256")
    assert result is None


def test_parse_xor_key_non_str_non_int_returns_none() -> None:
    """Line 922: non-int, non-str, non-bool returns None (falls to final return)."""
    assert _parse_xor_key(None) is None
    assert _parse_xor_key([1, 2]) is None


# ---------------------------------------------------------------------------
# format_modifiers -- lines 930-939
# ---------------------------------------------------------------------------


def test_format_modifiers_empty_list_returns_empty() -> None:
    """Line 931-932: empty list returns empty string."""
    assert format_modifiers([]) == ""


def test_format_modifiers_single_modifier() -> None:
    """Lines 936-939: single modifier is formatted with a leading space."""
    result = format_modifiers(["nocase"])
    assert result == " nocase"


def test_format_modifiers_multiple_modifiers() -> None:
    """Lines 936-939: multiple modifiers are concatenated with leading spaces."""
    result = format_modifiers(["nocase", "fullword"])
    assert result == " nocase fullword"


# ---------------------------------------------------------------------------
# validate_plain_string_modifiers -- lines 949-964 (incompatibility raises)
# ---------------------------------------------------------------------------


def test_validate_plain_string_modifiers_base64_fullword_incompatible() -> None:
    """Lines 949-954: base64 + fullword combination raises ValueError."""
    mods = [
        StringModifier(modifier_type=StringModifierType.BASE64),
        StringModifier(modifier_type=StringModifierType.FULLWORD),
    ]
    with pytest.raises(ValueError, match="cannot be combined with"):
        validate_plain_string_modifiers(mods)


def test_validate_plain_string_modifiers_xor_nocase_incompatible() -> None:
    """Lines 959-964: xor + nocase combination raises ValueError."""
    mods = [
        StringModifier(modifier_type=StringModifierType.XOR),
        StringModifier(modifier_type=StringModifierType.NOCASE),
    ]
    with pytest.raises(ValueError, match="cannot be combined with"):
        validate_plain_string_modifiers(mods)


def test_validate_plain_string_modifiers_no_xor_returns_early() -> None:
    """Lines 956-957: when xor is not in names, the function returns before
    the xor incompatibility loop."""
    mods = [
        StringModifier(modifier_type=StringModifierType.NOCASE),
        StringModifier(modifier_type=StringModifierType.FULLWORD),
    ]
    validate_plain_string_modifiers(mods)  # must not raise


def test_validate_plain_string_modifiers_xor_with_no_incompatible_modifiers() -> None:
    """Branch 959->exit: xor IS in names but no incompatible modifiers are present.

    The for-loop on line 959 iterates an empty set and exits immediately,
    covering the loop-exit branch without raising.
    """
    # xor alone, or xor + wide/ascii -- wide and ascii are not incompatible with xor
    mods = [
        StringModifier(modifier_type=StringModifierType.XOR),
        StringModifier(modifier_type=StringModifierType.WIDE),
    ]
    validate_plain_string_modifiers(mods)  # must not raise


# ---------------------------------------------------------------------------
# validate_hex_string_modifiers -- lines 975-976 (invalid modifier raises)
# ---------------------------------------------------------------------------


def test_validate_hex_string_modifiers_rejects_nocase() -> None:
    """Lines 975-976: hex strings cannot use nocase modifier."""
    mods = [StringModifier(modifier_type=StringModifierType.NOCASE)]
    with pytest.raises(ValueError, match="not valid on hex strings"):
        validate_hex_string_modifiers(mods)


def test_validate_hex_string_modifiers_allows_private() -> None:
    """Baseline: private modifier is the only allowed hex string modifier."""
    mods = [StringModifier(modifier_type=StringModifierType.PRIVATE)]
    validate_hex_string_modifiers(mods)  # must not raise


# ---------------------------------------------------------------------------
# validate_regex_string_modifiers -- lines 987-988 (disallowed modifier raises)
# ---------------------------------------------------------------------------


def test_validate_regex_string_modifiers_rejects_base64() -> None:
    """Lines 987-988: base64 modifier is invalid on regex strings."""
    mods = [StringModifier(modifier_type=StringModifierType.BASE64)]
    with pytest.raises(ValueError, match="not valid on regex strings"):
        validate_regex_string_modifiers(mods)


def test_validate_regex_string_modifiers_allows_nocase() -> None:
    """Baseline: nocase is valid on regex strings."""
    mods = [StringModifier(modifier_type=StringModifierType.NOCASE)]
    validate_regex_string_modifiers(mods)  # must not raise


# ---------------------------------------------------------------------------
# _modifier_names -- line 993 (non-list/tuple returns empty set)
# ---------------------------------------------------------------------------


def test_modifier_names_non_collection_returns_empty_set() -> None:
    """Line 993: when modifiers is not a list or tuple, an empty set is returned."""
    assert _modifier_names("nocase") == set()
    assert _modifier_names(None) == set()
    assert _modifier_names(42) == set()


# ---------------------------------------------------------------------------
# _validate_string_modifier_collection -- lines 1000-1001
# ---------------------------------------------------------------------------


def test_validate_string_modifier_collection_raises_on_non_collection() -> None:
    """Lines 1000-1001: non-list, non-tuple input raises TypeError."""
    with pytest.raises(TypeError, match="must be a list or tuple"):
        _validate_string_modifier_collection("nocase")
    with pytest.raises(TypeError, match="must be a list or tuple"):
        _validate_string_modifier_collection(None)


def test_validate_string_modifier_collection_passes_for_list_and_tuple() -> None:
    """Baseline: list and tuple are accepted without error."""
    _validate_string_modifier_collection([])
    _validate_string_modifier_collection(())


# ---------------------------------------------------------------------------
# validate_duplicate_string_modifiers -- lines 1007, 1015-1016
# ---------------------------------------------------------------------------


def test_validate_duplicate_string_modifiers_raises_on_duplicate() -> None:
    """Lines 1015-1016: duplicate non-regex-flag modifier raises ValueError."""
    mods = [
        StringModifier(modifier_type=StringModifierType.NOCASE),
        StringModifier(modifier_type=StringModifierType.NOCASE),
    ]
    with pytest.raises(ValueError, match="Duplicate string modifier"):
        validate_duplicate_string_modifiers(mods)


def test_validate_duplicate_string_modifiers_skips_regex_flags() -> None:
    """Line 1011-1012: single-char regex flags (e.g. 'i', 's') are not tracked."""
    # 'i' and 's' are valid VALID_REGEX_MODIFIERS (len==1 in the set).
    # The loop skips them, so duplicating them does not raise.
    validate_duplicate_string_modifiers(["i", "i"])  # must not raise


def test_validate_duplicate_string_modifiers_non_list_is_noop() -> None:
    """Line 1007: non-list, non-tuple input is a no-op (returns immediately)."""
    validate_duplicate_string_modifiers("nocase")  # must not raise
    validate_duplicate_string_modifiers(None)


# ---------------------------------------------------------------------------
# validate_string_modifier_values -- line 1023 (non-list is a no-op)
# ---------------------------------------------------------------------------


def test_validate_string_modifier_values_non_list_is_noop() -> None:
    """Line 1023: non-list, non-tuple input returns without checking."""
    validate_string_modifier_values("nocase")  # must not raise
    validate_string_modifier_values(None)


# ---------------------------------------------------------------------------
# split_regex_modifiers -- lines 1039, 1048-1058
# ---------------------------------------------------------------------------


def test_split_regex_modifiers_single_char_flag() -> None:
    """Lines 1048-1050: single-char regex flag goes into suffix_parts."""
    suffix, spaced = split_regex_modifiers(["i"])
    assert suffix == "i"
    assert spaced == []


def test_split_regex_modifiers_dotall_modifier_node() -> None:
    """Lines 1051-1052: StringModifier with REGEX_SUFFIX_NAMES name appends suffix."""
    mod = StringModifier(modifier_type=StringModifierType.DOTALL)
    suffix, spaced = split_regex_modifiers([mod])
    assert suffix == "s"
    assert spaced == []


def test_split_regex_modifiers_spaced_modifier_node() -> None:
    """Lines 1053-1054: modifier not in suffix names goes into spaced list."""
    mod = StringModifier(modifier_type=StringModifierType.NOCASE)
    suffix, spaced = split_regex_modifiers([mod])
    assert suffix == ""
    assert "nocase" in spaced


def test_split_regex_modifiers_unsupported_raises() -> None:
    """Lines 1045-1047: modifier in _UNSUPPORTED_REGEX_MODIFIERS raises ValueError."""
    mod = StringModifier(modifier_type=StringModifierType.MULTILINE)
    with pytest.raises(ValueError, match="Unsupported regex modifier"):
        split_regex_modifiers([mod])


# ---------------------------------------------------------------------------
# _canonical_regex_suffix -- lines 1065-1066 (duplicate suffix raises)
# ---------------------------------------------------------------------------


def test_canonical_regex_suffix_duplicate_raises() -> None:
    """Lines 1065-1066: duplicate suffix modifier raises ValueError."""
    with pytest.raises(ValueError, match="Duplicate regex modifier"):
        _canonical_regex_suffix(["i", "i"])


def test_canonical_regex_suffix_canonical_order() -> None:
    """Line 1068: modifiers are emitted in REGEX_MODIFIER_ORDER order."""
    result = _canonical_regex_suffix(["s", "i"])
    assert result == "is"  # REGEX_MODIFIER_ORDER = "is"


# ---------------------------------------------------------------------------
# _regex_modifier_name -- lines 1073 and 1076-1077
# ---------------------------------------------------------------------------


def test_regex_modifier_name_plain_string_returns_it() -> None:
    """Line 1073: plain string input returns itself."""
    assert _regex_modifier_name("nocase") == "nocase"


def test_regex_modifier_name_string_modifier_returns_name() -> None:
    """Lines 1074-1075: StringModifier input returns its .name property."""
    mod = StringModifier(modifier_type=StringModifierType.NOCASE)
    assert _regex_modifier_name(mod) == "nocase"


def test_regex_modifier_name_other_type_raises() -> None:
    """Lines 1076-1077: anything else raises TypeError."""
    with pytest.raises(TypeError, match="String modifiers must contain strings or StringModifier"):
        _regex_modifier_name(42)
    with pytest.raises(TypeError, match="String modifiers must contain strings or StringModifier"):
        _regex_modifier_name(None)


# ---------------------------------------------------------------------------
# format_regex_modifiers -- lines 1085-1088
# ---------------------------------------------------------------------------


def test_format_regex_modifiers_empty() -> None:
    """Line 1085-1088: empty modifiers list returns empty string."""
    assert format_regex_modifiers([]) == ""


def test_format_regex_modifiers_suffix_only() -> None:
    """Line 1085-1088: suffix-only modifier returns the suffix directly."""
    mod = StringModifier(modifier_type=StringModifierType.DOTALL)
    result = format_regex_modifiers([mod])
    assert result == "s"


def test_format_regex_modifiers_spaced_only() -> None:
    """Line 1085-1088: spaced modifier is prefixed with a space."""
    result = format_regex_modifiers(["nocase"])
    assert result == " nocase"


def test_format_regex_modifiers_suffix_and_spaced() -> None:
    """Line 1085-1088: combination of suffix and spaced modifier."""
    mod_dotall = StringModifier(modifier_type=StringModifierType.DOTALL)
    result = format_regex_modifiers([mod_dotall, "nocase"])
    assert result == "s nocase"
