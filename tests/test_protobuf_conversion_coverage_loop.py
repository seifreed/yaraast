# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests targeting uncovered branches in protobuf_conversion.py.

Each test exercises a real code path through the production conversion API.
No mocks, stubs, or compiler bypasses are used anywhere in this file.
"""

from __future__ import annotations

import math

import pytest

from yaraast.ast.conditions import (
    ForExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    SetExpression,
    StringCount,
    StringLength,
    StringLiteral,
    StringOffset,
)
from yaraast.ast.extern import ExternImport, ExternRuleReference
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import MetaEntry
from yaraast.ast.pragmas import (
    ConditionalDirective,
    IncludeOncePragma,
    PragmaScope,
    PragmaType,
)
from yaraast.ast.rules import Rule
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNibble,
)
from yaraast.errors import SerializationError
from yaraast.serialization import yara_ast_pb2
from yaraast.serialization.protobuf_conversion import (
    _copy_modifier_to_protobuf,
    _copy_python_value_to_meta_value,
    _copy_string_set_items_to_protobuf,
    _copy_string_set_to_protobuf,
    _finite_double_value,
    _hex_byte_like_value_to_protobuf,
    _hex_byte_value_from_protobuf,
    _hex_int_value_from_protobuf,
    _hex_nibble_raw_value_to_protobuf,
    _hex_nibble_value_to_protobuf,
    _restore_quantifier_text,
    _validate_finite_quantifier,
    _validate_hex_token_sequence_for_protobuf,
    convert_expression_to_protobuf,
    convert_extern_import_to_protobuf,
    convert_hex_token_to_protobuf,
    convert_pragma_to_protobuf,
    convert_rule_to_protobuf,
    protobuf_to_extern_import,
    protobuf_to_extern_rule,
    protobuf_to_pragma,
    protobuf_to_rule_meta_entry,
)
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    MatchCase,
    PatternMatch,
    SliceExpression,
)

# ---------------------------------------------------------------------------
# _finite_double_value — lines 56-57, 59-61
# ---------------------------------------------------------------------------


def test_finite_double_value_rejects_bool_input() -> None:
    """A boolean passed to _finite_double_value must raise SerializationError."""
    with pytest.raises(SerializationError, match="value must be numeric"):
        _finite_double_value(True, "Test")


def test_finite_double_value_rejects_non_numeric_input() -> None:
    """A string passed to _finite_double_value must raise SerializationError."""
    with pytest.raises(SerializationError, match="value must be numeric"):
        _finite_double_value("hello", "Test")


def test_finite_double_value_rejects_infinity() -> None:
    """An infinite float passed to _finite_double_value must raise."""
    with pytest.raises(SerializationError, match="value must be finite"):
        _finite_double_value(math.inf, "Test")


def test_finite_double_value_accepts_valid_float() -> None:
    """A finite float is returned unchanged by _finite_double_value."""
    assert _finite_double_value(3.14, "Test") == pytest.approx(3.14)


def test_finite_double_value_accepts_integer_input() -> None:
    """An integer is coerced to float by _finite_double_value."""
    assert _finite_double_value(42, "Test") == pytest.approx(42.0)


# ---------------------------------------------------------------------------
# _validate_finite_quantifier — lines 66-68
# ---------------------------------------------------------------------------


def test_validate_finite_quantifier_rejects_infinite_float() -> None:
    """An infinite float quantifier raises SerializationError."""
    with pytest.raises(SerializationError, match="quantifier must be finite"):
        _validate_finite_quantifier(math.inf)


def test_validate_finite_quantifier_accepts_finite_float() -> None:
    """A finite float quantifier passes without error."""
    _validate_finite_quantifier(1.5)


def test_validate_finite_quantifier_accepts_integer() -> None:
    """An integer quantifier passes without error (only floats are checked)."""
    _validate_finite_quantifier(5)


# ---------------------------------------------------------------------------
# _copy_python_value_to_meta_value — line 426
# ---------------------------------------------------------------------------


def test_copy_python_value_to_meta_value_rejects_unsupported_type() -> None:
    """A list value raises SerializationError with a descriptive message."""
    pb_meta_value = yara_ast_pb2.MetaValue()
    with pytest.raises(SerializationError, match="value must be a string, integer, boolean"):
        _copy_python_value_to_meta_value([], pb_meta_value, "Meta")


# ---------------------------------------------------------------------------
# _copy_python_value_to_legacy_meta_value — bool path (line 426)
# ---------------------------------------------------------------------------


def test_convert_rule_to_protobuf_serializes_bool_meta_in_legacy_meta_node() -> None:
    """A bool value in a legacy Meta node is stored as bool_value in the protobuf."""
    rule = Rule(
        name="bool_meta_rule",
        modifiers=[],
        tags=[],
        meta=[Meta("is_packed", True)],
        strings=[],
        condition=BooleanLiteral(value=True),
    )
    pb = yara_ast_pb2.Rule()
    convert_rule_to_protobuf(rule, pb)

    assert pb.meta["is_packed"].bool_value is True
    assert pb.meta_entries[0].value.bool_value is True


# ---------------------------------------------------------------------------
# convert_rule_to_protobuf — float meta via MetaEntry (line 389 branch)
# ---------------------------------------------------------------------------


def test_convert_rule_to_protobuf_serializes_float_meta_entry() -> None:
    """A float meta value on a MetaEntry is stored as double_value in protobuf."""
    rule = Rule(
        name="test_rule",
        modifiers=[],
        tags=[],
        meta=[MetaEntry.from_key_value("confidence", 0.95)],
        strings=[],
        condition=BooleanLiteral(value=True),
    )
    pb = yara_ast_pb2.Rule()
    convert_rule_to_protobuf(rule, pb)

    assert abs(pb.meta["confidence"].double_value - 0.95) < 1e-9
    assert abs(pb.meta_entries[0].value.double_value - 0.95) < 1e-9


# ---------------------------------------------------------------------------
# protobuf_to_rule_meta_entry — ast_node path returning Meta (line 670-671)
# and fallback MetaEntry path (line 672)
# ---------------------------------------------------------------------------


def test_protobuf_to_rule_meta_entry_with_ast_node_flag_returns_meta() -> None:
    """A RuleMetaEntry with ast_node=True is deserialized as a Meta node."""
    pb_entry = yara_ast_pb2.RuleMetaEntry()
    pb_entry.key = "my_key"
    pb_entry.value.string_value = "hello"
    pb_entry.ast_node = True
    pb_entry.scope = ""

    result = protobuf_to_rule_meta_entry(pb_entry)

    assert isinstance(result, Meta)
    assert result.key == "my_key"
    assert result.value == "hello"


def test_protobuf_to_rule_meta_entry_without_ast_node_or_scope_returns_meta_entry() -> None:
    """A RuleMetaEntry without ast_node or scope falls through to MetaEntry (line 672)."""
    pb_entry = yara_ast_pb2.RuleMetaEntry()
    pb_entry.key = "plain_key"
    pb_entry.value.string_value = "plain_value"
    pb_entry.ast_node = False
    pb_entry.scope = ""

    result = protobuf_to_rule_meta_entry(pb_entry)

    assert isinstance(result, MetaEntry)
    assert result.key == "plain_key"
    assert result.value == "plain_value"


# ---------------------------------------------------------------------------
# convert_extern_import_to_protobuf — whitespace paths (709-710, 718-719)
# ---------------------------------------------------------------------------


def test_convert_extern_import_to_protobuf_rejects_whitespace_module_path() -> None:
    """A whitespace-only module_path raises SerializationError."""
    ei = ExternImport(module_path="   ", alias=None, rules=["my_rule"])
    pb = yara_ast_pb2.ExternImport()
    with pytest.raises(SerializationError):
        convert_extern_import_to_protobuf(ei, pb)


def test_convert_extern_import_to_protobuf_rejects_whitespace_alias() -> None:
    """A whitespace-only alias raises SerializationError."""
    ei = ExternImport(module_path="some/path.yar", alias="   ", rules=["my_rule"])
    pb = yara_ast_pb2.ExternImport()
    with pytest.raises(SerializationError):
        convert_extern_import_to_protobuf(ei, pb)


# ---------------------------------------------------------------------------
# protobuf_to_extern_import — whitespace paths (2068-2069, 2079-2080)
# ---------------------------------------------------------------------------


def test_protobuf_to_extern_import_rejects_whitespace_module_path() -> None:
    """Whitespace-only module_path in protobuf raises SerializationError."""
    pb = yara_ast_pb2.ExternImport()
    pb.module_path = "   "
    pb.rules.append("my_rule")
    with pytest.raises(SerializationError):
        protobuf_to_extern_import(pb)


def test_protobuf_to_extern_import_rejects_whitespace_alias() -> None:
    """Whitespace-only alias in protobuf raises SerializationError."""
    pb = yara_ast_pb2.ExternImport()
    pb.module_path = "some/path.yar"
    pb.alias = "   "
    pb.rules.append("my_rule")
    with pytest.raises(SerializationError):
        protobuf_to_extern_import(pb)


# ---------------------------------------------------------------------------
# convert_pragma_to_protobuf — condition field (line 785)
# ---------------------------------------------------------------------------


def test_convert_pragma_to_protobuf_sets_condition_for_ifdef() -> None:
    """ConditionalDirective with IFDEF sets the condition field in protobuf."""
    pragma = ConditionalDirective(PragmaType.IFDEF, condition="MY_MACRO")
    pragma.scope = PragmaScope.FILE
    pb = yara_ast_pb2.Pragma()
    convert_pragma_to_protobuf(pragma, pb)

    assert pb.HasField("condition")
    assert pb.condition == "MY_MACRO"
    assert pb.pragma_type == "ifdef"


# ---------------------------------------------------------------------------
# _format_unknown_modifier — tuple and string cases (lines 856, 859)
# These are exercised via _protobuf_modifiers_to_ast during deserialization
# when StringModifier.from_name_value raises for unknown modifier names.
# ---------------------------------------------------------------------------


def test_protobuf_modifiers_to_ast_formats_unknown_modifier_with_tuple_value() -> None:
    """An unknown modifier with a tuple_value field formats as 'name(min-max)'."""
    from yaraast.serialization.protobuf_conversion import _protobuf_modifiers_to_ast

    pb_mod = yara_ast_pb2.StringModifier()
    pb_mod.name = "unknown_range_mod_xyz"
    pb_mod.tuple_value.extend([10, 20])
    pb_mod.value = "10-20"

    result = _protobuf_modifiers_to_ast([pb_mod])

    assert result == ["unknown_range_mod_xyz(10-20)"]


def test_protobuf_modifiers_to_ast_formats_unknown_modifier_with_int_value() -> None:
    """An unknown modifier with an integer typed_value formats as 'name(value)'."""
    from yaraast.serialization.protobuf_conversion import _protobuf_modifiers_to_ast

    pb_mod = yara_ast_pb2.StringModifier()
    pb_mod.name = "unknown_int_mod_xyz"
    pb_mod.typed_value.int_value = 42

    result = _protobuf_modifiers_to_ast([pb_mod])

    assert result == ["unknown_int_mod_xyz(42)"]


def test_protobuf_modifiers_to_ast_formats_unknown_modifier_with_string_typed_value() -> None:
    """An unknown modifier with a string typed_value formats as 'name(\"value\")'."""
    from yaraast.serialization.protobuf_conversion import _protobuf_modifiers_to_ast

    pb_mod = yara_ast_pb2.StringModifier()
    pb_mod.name = "unknown_str_mod_xyz"
    pb_mod.typed_value.string_value = "hello"

    result = _protobuf_modifiers_to_ast([pb_mod])

    assert result == ['unknown_str_mod_xyz("hello")']


# ---------------------------------------------------------------------------
# _copy_modifier_to_protobuf — various value paths
# ---------------------------------------------------------------------------


def test_copy_modifier_to_protobuf_with_string_modifier_value_stores_typed_value() -> None:
    """A string modifier value is stored in the typed_value.string_value field."""

    class _StrMod:
        name = "test_mod"
        value = "hello"
        location = None

    pb = yara_ast_pb2.StringModifier()
    _copy_modifier_to_protobuf(_StrMod(), pb)

    assert pb.typed_value.string_value == "hello"


def test_copy_modifier_to_protobuf_with_float_modifier_value_stores_typed_value() -> None:
    """A float modifier value is stored in the typed_value.double_value field."""

    class _FloatMod:
        name = "test_mod"
        value = 3.14
        location = None

    pb = yara_ast_pb2.StringModifier()
    _copy_modifier_to_protobuf(_FloatMod(), pb)

    assert pb.typed_value.double_value == pytest.approx(3.14)


def test_copy_modifier_to_protobuf_rejects_bool_value() -> None:
    """A bool modifier value triggers the invalid-modifier-value error path."""

    class _BoolMod:
        name = "test_mod"
        value = True
        location = None

    pb = yara_ast_pb2.StringModifier()
    with pytest.raises(SerializationError, match="String modifier value must be"):
        _copy_modifier_to_protobuf(_BoolMod(), pb)


def test_copy_modifier_to_protobuf_rejects_tuple_with_non_integer_items() -> None:
    """A tuple with non-integer items in a modifier raises SerializationError."""

    class _TupleStrMod:
        name = "test_mod"
        value = ("a", "b")
        location = None

    pb = yara_ast_pb2.StringModifier()
    with pytest.raises(SerializationError, match="tuple value must contain two integers"):
        _copy_modifier_to_protobuf(_TupleStrMod(), pb)


def test_copy_modifier_to_protobuf_rejects_unsupported_value_type() -> None:
    """A list modifier value triggers the fallback invalid-modifier-value error."""

    class _ListMod:
        name = "test_mod"
        value = [1, 2, 3]
        location = None

    pb = yara_ast_pb2.StringModifier()
    with pytest.raises(SerializationError, match="String modifier value must be"):
        _copy_modifier_to_protobuf(_ListMod(), pb)


# ---------------------------------------------------------------------------
# convert_hex_token_to_protobuf — empty branch in HexAlternative (lines 998-999)
# ---------------------------------------------------------------------------


def test_convert_hex_token_to_protobuf_rejects_empty_alternative_branch() -> None:
    """An empty list branch inside HexAlternative raises SerializationError."""
    alt = HexAlternative(alternatives=[[HexByte(0xAA)], []])
    pb = yara_ast_pb2.HexToken()
    with pytest.raises(SerializationError, match="branches must not be empty"):
        convert_hex_token_to_protobuf(alt, pb)


# ---------------------------------------------------------------------------
# _validate_hex_token_sequence_for_protobuf — empty branch in alternative
#   inside a token sequence (lines 1198-1199)
# ---------------------------------------------------------------------------


def test_validate_hex_token_sequence_rejects_empty_branch_in_nested_alternative() -> None:
    """A HexAlternative with an empty branch inside a token sequence raises."""
    from yaraast.ast.strings import HexAlternative as _HexAlt

    alt_with_empty = _HexAlt(alternatives=[[HexByte(0xAA)], []])
    tokens = [HexByte(0x01), alt_with_empty, HexByte(0x02)]
    with pytest.raises(SerializationError, match="branches must not be empty"):
        _validate_hex_token_sequence_for_protobuf(tokens, "hex string", inside_alternative=False)


# ---------------------------------------------------------------------------
# _hex_byte_like_value_to_protobuf — bool and out-of-range (1031-1032, 1040-1041)
# ---------------------------------------------------------------------------


def test_hex_byte_like_value_to_protobuf_rejects_bool() -> None:
    """A bool input raises SerializationError from _hex_byte_like_value_to_protobuf."""
    with pytest.raises(SerializationError, match="must be a byte"):
        _hex_byte_like_value_to_protobuf(True, "HexByte value")


def test_hex_byte_like_value_to_protobuf_rejects_out_of_range_int() -> None:
    """An integer larger than 0xFF raises SerializationError."""
    with pytest.raises(SerializationError, match="must be a byte"):
        _hex_byte_like_value_to_protobuf(300, "HexByte value")


def test_hex_byte_like_value_to_protobuf_rejects_invalid_string() -> None:
    """A non-2-char-hex string raises SerializationError."""
    with pytest.raises(SerializationError, match="must be a byte"):
        _hex_byte_like_value_to_protobuf("ZZZ", "HexByte value")


# ---------------------------------------------------------------------------
# _hex_byte_value_from_protobuf — invalid hex: prefix and ValueError path
#   (lines 1078-1079, 1084)
# ---------------------------------------------------------------------------


def test_hex_byte_value_from_protobuf_rejects_invalid_hex_prefix_content() -> None:
    """A hex: prefix with non-hex chars raises SerializationError."""
    with pytest.raises(SerializationError, match="HexByte value must be a byte"):
        _hex_byte_value_from_protobuf("hex:ZZ")


def test_hex_byte_value_from_protobuf_accepts_legacy_two_char_hex_string() -> None:
    """A bare two-char hex string (no prefix) is returned as-is (legacy format)."""
    result = _hex_byte_value_from_protobuf("FF")
    assert result == "FF"


# ---------------------------------------------------------------------------
# _hex_int_value_from_protobuf — error paths (1100-1101, 1104-1109)
# ---------------------------------------------------------------------------


def test_hex_int_value_from_protobuf_rejects_invalid_hex_prefix_content() -> None:
    """A hex: prefix with non-hex content in negated byte raises SerializationError."""
    with pytest.raises(SerializationError, match="HexNegatedByte value must be a byte"):
        _hex_int_value_from_protobuf("hex:ZZ")


def test_hex_int_value_from_protobuf_accepts_two_char_hex_string() -> None:
    """A two-char lowercase hex string returns the parsed integer value."""
    result = _hex_int_value_from_protobuf("2F")
    assert result == 0x2F


def test_hex_int_value_from_protobuf_rejects_non_hex_two_char_string() -> None:
    """A non-hex two-char string raises SerializationError."""
    with pytest.raises(SerializationError, match="HexNegatedByte value must be a byte"):
        _hex_int_value_from_protobuf("ZZ")


def test_hex_int_value_from_protobuf_rejects_non_parseable_long_string() -> None:
    """A multi-char non-hex string raises SerializationError."""
    with pytest.raises(SerializationError, match="HexNegatedByte value must be a byte"):
        _hex_int_value_from_protobuf("GGG")


# ---------------------------------------------------------------------------
# _hex_nibble_value_to_protobuf — bool and out-of-range (1118-1119)
# _hex_nibble_raw_value_to_protobuf — bad length (1131-1132)
# ---------------------------------------------------------------------------


def test_hex_nibble_value_to_protobuf_rejects_bool() -> None:
    """A bool value raises SerializationError in _hex_nibble_value_to_protobuf."""
    with pytest.raises(SerializationError, match="HexNibble value must be a nibble"):
        _hex_nibble_value_to_protobuf(True)


def test_hex_nibble_value_to_protobuf_rejects_out_of_nibble_range() -> None:
    """An integer > 0xF raises SerializationError."""
    with pytest.raises(SerializationError, match="HexNibble value must be a nibble"):
        _hex_nibble_value_to_protobuf(20)


def test_hex_nibble_raw_value_to_protobuf_rejects_two_char_string() -> None:
    """A two-character string raises SerializationError for raw nibble value."""
    with pytest.raises(SerializationError, match="HexNibble value must be a nibble"):
        _hex_nibble_raw_value_to_protobuf("AB")


# ---------------------------------------------------------------------------
# _validate_hex_token_sequence_for_protobuf — unbounded jump inside alt (1198-1199)
# ---------------------------------------------------------------------------


def test_validate_hex_token_sequence_rejects_unbounded_jump_inside_alternative() -> None:
    """An unbounded HexJump inside an alternative branch raises SerializationError."""
    tokens = [
        HexByte(0xAA),
        HexJump(min_jump=1, max_jump=None),
        HexByte(0xBB),
    ]
    with pytest.raises(
        SerializationError,
        match="Unbounded HexJump is not allowed inside hex alternatives",
    ):
        _validate_hex_token_sequence_for_protobuf(
            tokens,
            "hex alternative branch",
            inside_alternative=True,
        )


# ---------------------------------------------------------------------------
# _coerce_quantifier_text — Expression with .name (lines 1230-1236)
# and Expression with neither .value nor .name — returns '' (line 1239)
# ---------------------------------------------------------------------------


def test_convert_expression_to_protobuf_for_expression_with_identifier_quantifier() -> None:
    """ForExpression with an Identifier quantifier serializes the identifier name."""
    quantifier = Identifier(name="any")
    expr = ForExpression(
        quantifier=quantifier,
        variable="i",
        iterable=Identifier(name="xs"),
        body=BooleanLiteral(value=True),
    )
    pb = yara_ast_pb2.Expression()
    convert_expression_to_protobuf(expr, pb)

    assert pb.for_expression.quantifier == "any"


def test_convert_expression_to_protobuf_for_expression_with_bare_expression_quantifier() -> None:
    """ForExpression with an Expression lacking .value and .name yields an empty quantifier."""
    from yaraast.ast.expressions import RangeExpression

    # RangeExpression has neither .value nor .name -> _coerce_quantifier_text returns ''
    quantifier = RangeExpression(low=IntegerLiteral(value=1), high=IntegerLiteral(value=10))
    expr = ForExpression(
        quantifier=quantifier,
        variable="i",
        iterable=Identifier(name="xs"),
        body=BooleanLiteral(value=True),
    )
    pb = yara_ast_pb2.Expression()
    convert_expression_to_protobuf(expr, pb)

    assert pb.for_expression.quantifier == ""


# ---------------------------------------------------------------------------
# _copy_string_set_to_protobuf — frozenset empty (1282-1283) and non-empty
# ---------------------------------------------------------------------------


def test_copy_string_set_to_protobuf_rejects_empty_frozenset() -> None:
    """An empty frozenset raises SerializationError."""
    pb = yara_ast_pb2.ForOfExpression()
    with pytest.raises(SerializationError, match="must contain values"):
        _copy_string_set_to_protobuf(frozenset(), pb, "ForOfExpression")


def test_copy_string_set_to_protobuf_accepts_nonempty_frozenset() -> None:
    """A non-empty frozenset is serialized into sorted string_set_items."""
    pb = yara_ast_pb2.ForOfExpression()
    _copy_string_set_to_protobuf(frozenset(["$b", "$a"]), pb, "ForOfExpression")
    assert list(pb.string_set_items) == ["$a", "$b"]


# ---------------------------------------------------------------------------
# _copy_string_set_items_to_protobuf — empty list (lines 1302-1303) and
# whitespace-only string item (lines 1305-1306)
# ---------------------------------------------------------------------------


def test_copy_string_set_items_to_protobuf_rejects_empty_list() -> None:
    """An empty list raises SerializationError (lines 1302-1303, the first guard)."""
    pb = yara_ast_pb2.ForOfExpression()
    with pytest.raises(SerializationError, match="must contain values"):
        _copy_string_set_items_to_protobuf([], pb, "test")


def test_copy_string_set_items_to_protobuf_rejects_whitespace_only_item() -> None:
    """A whitespace-only string item raises SerializationError."""
    pb = yara_ast_pb2.ForOfExpression()
    with pytest.raises(SerializationError, match="must contain values"):
        _copy_string_set_items_to_protobuf(["  "], pb, "test")


# ---------------------------------------------------------------------------
# _expression_string_set_items — StringLiteral starting with '$' (TRUE branch,
# line 1378) and StringLiteral NOT starting with '$' (FALSE branch, line 1379)
# ---------------------------------------------------------------------------


def test_copy_string_set_to_protobuf_with_set_expression_containing_string_literal() -> None:
    """A SetExpression containing a StringLiteral starting with '$' is compacted."""
    items = SetExpression(elements=[StringLiteral(value="$a"), StringLiteral(value="$b")])
    pb = yara_ast_pb2.ForOfExpression()
    _copy_string_set_to_protobuf(items, pb, "ForOfExpression")
    assert list(pb.string_set_items) == ["$a", "$b"]


def test_copy_string_set_to_protobuf_string_literal_without_dollar_falls_through() -> None:
    """A StringLiteral without a '$' prefix returns None and falls through (line 1379)."""
    from yaraast.serialization.protobuf_conversion import _expression_string_set_items

    # A StringLiteral that does not start with '$' triggers the FALSE branch of
    # the startswith('$') check at line 1377, returning None from the helper.
    result = _expression_string_set_items(SetExpression(elements=[StringLiteral(value="hello")]))
    assert result is None


# ---------------------------------------------------------------------------
# _restore_quantifier_text — identifier/keyword path (line 1417 - return value)
# ---------------------------------------------------------------------------


def test_restore_quantifier_text_returns_keyword_string_as_is() -> None:
    """Keyword quantifiers like 'all' and 'none' are returned unchanged."""
    assert _restore_quantifier_text("all", "test", allow_percentage=True) == "all"
    assert _restore_quantifier_text("none", "test", allow_percentage=True) == "none"
    assert _restore_quantifier_text("any", "test", allow_percentage=False) == "any"


# ---------------------------------------------------------------------------
# StringOffset/StringLength with index (lines 1531->exit, 1544->exit)
# The arrow notation means the FALSE branch (index is None) was untested.
# ---------------------------------------------------------------------------


def test_convert_string_offset_without_index_does_not_set_index_field() -> None:
    """StringOffset with index=None does not set the index field in protobuf."""
    pb = yara_ast_pb2.Expression()
    expr = StringOffset(string_id="$s1", index=None)
    convert_expression_to_protobuf(expr, pb)
    assert not pb.string_offset.HasField("index")


def test_convert_string_length_without_index_does_not_set_index_field() -> None:
    """StringLength with index=None does not set the index field in protobuf."""
    pb = yara_ast_pb2.Expression()
    expr = StringLength(string_id="$s1", index=None)
    convert_expression_to_protobuf(expr, pb)
    assert not pb.string_length.HasField("index")


def test_convert_string_offset_with_index_sets_index_field() -> None:
    """StringOffset with an IntegerLiteral index serializes the index correctly."""
    pb = yara_ast_pb2.Expression()
    expr = StringOffset(string_id="$s1", index=IntegerLiteral(value=0))
    convert_expression_to_protobuf(expr, pb)
    assert pb.string_offset.HasField("index")
    assert pb.string_offset.index.integer_literal.value == 0


def test_convert_string_length_with_index_sets_index_field() -> None:
    """StringLength with an IntegerLiteral index serializes the index correctly."""
    pb = yara_ast_pb2.Expression()
    expr = StringLength(string_id="$s1", index=IntegerLiteral(value=2))
    convert_expression_to_protobuf(expr, pb)
    assert pb.string_length.HasField("index")
    assert pb.string_length.index.integer_literal.value == 2


# ---------------------------------------------------------------------------
# FunctionCall with receiver (line 1615)
# ---------------------------------------------------------------------------


def test_convert_expression_to_protobuf_function_call_with_receiver() -> None:
    """FunctionCall with a receiver expression serializes the receiver field."""
    from yaraast.ast.expressions import FunctionCall

    pb = yara_ast_pb2.Expression()
    # With a receiver, the function name must pass validate_yara_identifier.
    expr = FunctionCall(
        function="is_pe",
        arguments=[],
        receiver=Identifier(name="pe"),
    )
    convert_expression_to_protobuf(expr, pb)

    assert pb.function_call.HasField("receiver")
    assert pb.function_call.receiver.identifier.name == "pe"


# ---------------------------------------------------------------------------
# ExternRuleReference — with and without namespace (line 1653->exit covers no-namespace)
# ---------------------------------------------------------------------------


def test_convert_extern_rule_reference_with_namespace_serializes_namespace() -> None:
    """ExternRuleReference with a namespace sets the namespace field in protobuf."""
    pb = yara_ast_pb2.Expression()
    expr = ExternRuleReference(rule_name="MyRule", namespace="MyNS")
    convert_expression_to_protobuf(expr, pb)

    assert pb.extern_rule_reference.rule_name == "MyRule"
    assert pb.extern_rule_reference.namespace == "MyNS"


def test_convert_extern_rule_reference_without_namespace_leaves_namespace_unset() -> None:
    """ExternRuleReference with namespace=None does not set the namespace field."""
    pb = yara_ast_pb2.Expression()
    expr = ExternRuleReference(rule_name="MyRule", namespace=None)
    convert_expression_to_protobuf(expr, pb)

    assert pb.extern_rule_reference.rule_name == "MyRule"
    assert pb.extern_rule_reference.namespace == ""


# ---------------------------------------------------------------------------
# ArrayComprehension — with and without condition (line 1783->exit covers no-condition)
# ---------------------------------------------------------------------------


def test_convert_array_comprehension_with_condition_sets_condition_field() -> None:
    """ArrayComprehension with a condition serializes the condition field."""
    pb = yara_ast_pb2.Expression()
    expr = ArrayComprehension(
        variable="x",
        expression=Identifier(name="item"),
        iterable=Identifier(name="items"),
        condition=BooleanLiteral(value=True),
    )
    convert_expression_to_protobuf(expr, pb)

    assert pb.array_comprehension.HasField("condition")
    assert pb.array_comprehension.condition.boolean_literal.value is True


def test_convert_array_comprehension_without_condition_leaves_condition_unset() -> None:
    """ArrayComprehension with condition=None does not set the condition field."""
    pb = yara_ast_pb2.Expression()
    expr = ArrayComprehension(
        variable="x",
        expression=Identifier(name="item"),
        iterable=Identifier(name="items"),
        condition=None,
    )
    convert_expression_to_protobuf(expr, pb)

    assert not pb.array_comprehension.HasField("condition")


# ---------------------------------------------------------------------------
# DictComprehension with value_expression=None raises (lines 1810-1811)
# DictComprehension with condition serializes condition field (line 1822)
# ---------------------------------------------------------------------------


def test_convert_dict_comprehension_raises_when_value_expression_is_none() -> None:
    """DictComprehension with value_expression=None raises SerializationError."""
    pb = yara_ast_pb2.Expression()
    expr = DictComprehension(
        key_variable="k",
        value_variable="v",
        key_expression=Identifier(name="x"),
        value_expression=None,
        iterable=Identifier(name="items"),
    )
    with pytest.raises(SerializationError, match="value_expression is required"):
        convert_expression_to_protobuf(expr, pb)


def test_convert_dict_comprehension_with_condition_sets_condition_field() -> None:
    """DictComprehension with a condition serializes the condition field (line 1822)."""
    pb = yara_ast_pb2.Expression()
    expr = DictComprehension(
        key_variable="k",
        value_variable="v",
        key_expression=Identifier(name="x"),
        value_expression=Identifier(name="y"),
        iterable=Identifier(name="items"),
        condition=BooleanLiteral(value=True),
    )
    convert_expression_to_protobuf(expr, pb)

    assert pb.dict_comprehension.HasField("condition")
    assert pb.dict_comprehension.condition.boolean_literal.value is True


# ---------------------------------------------------------------------------
# SliceExpression with stop and step (lines 1844, 1845->1847, 1848)
# ---------------------------------------------------------------------------


def test_convert_slice_expression_with_stop_and_step_serializes_both() -> None:
    """SliceExpression with all optional fields serializes stop and step."""
    pb = yara_ast_pb2.Expression()
    expr = SliceExpression(
        target=Identifier(name="arr"),
        start=IntegerLiteral(value=1),
        stop=IntegerLiteral(value=5),
        step=IntegerLiteral(value=2),
    )
    convert_expression_to_protobuf(expr, pb)

    assert pb.slice_expression.HasField("stop")
    assert pb.slice_expression.HasField("step")
    assert pb.slice_expression.stop.integer_literal.value == 5
    assert pb.slice_expression.step.integer_literal.value == 2


def test_convert_slice_expression_without_optional_fields() -> None:
    """SliceExpression without stop or step leaves those fields unset."""
    pb = yara_ast_pb2.Expression()
    expr = SliceExpression(
        target=Identifier(name="arr"),
        start=None,
        stop=None,
        step=None,
    )
    convert_expression_to_protobuf(expr, pb)

    assert not pb.slice_expression.HasField("start")
    assert not pb.slice_expression.HasField("stop")
    assert not pb.slice_expression.HasField("step")


# ---------------------------------------------------------------------------
# PatternMatch — with and without default (line 1860->exit covers no-default)
# ---------------------------------------------------------------------------


def test_convert_pattern_match_with_default_sets_default_field() -> None:
    """PatternMatch with a default expression serializes the default field."""
    pb = yara_ast_pb2.Expression()
    expr = PatternMatch(
        value=Identifier(name="x"),
        cases=[MatchCase(pattern=IntegerLiteral(value=1), result=BooleanLiteral(value=True))],
        default=BooleanLiteral(value=False),
    )
    convert_expression_to_protobuf(expr, pb)

    assert pb.pattern_match.HasField("default")
    assert pb.pattern_match.default.boolean_literal.value is False


def test_convert_pattern_match_without_default_leaves_default_unset() -> None:
    """PatternMatch with default=None does not set the default field."""
    pb = yara_ast_pb2.Expression()
    expr = PatternMatch(
        value=Identifier(name="x"),
        cases=[MatchCase(pattern=IntegerLiteral(value=1), result=BooleanLiteral(value=True))],
        default=None,
    )
    convert_expression_to_protobuf(expr, pb)

    assert not pb.pattern_match.HasField("default")


# ---------------------------------------------------------------------------
# protobuf_to_extern_rule — unknown modifier fallback (lines 2037-2038)
# ---------------------------------------------------------------------------


def test_protobuf_to_extern_rule_falls_back_to_string_for_unknown_modifier() -> None:
    """An unrecognized modifier string is kept as a plain string in the AST."""
    pb = yara_ast_pb2.ExternRule()
    pb.name = "some_rule"
    pb.modifiers.append("unknown_modifier_xyz")

    result = protobuf_to_extern_rule(pb)

    assert result.modifiers == ["unknown_modifier_xyz"]


# ---------------------------------------------------------------------------
# protobuf_to_pragma — INCLUDE_ONCE branch (line 2144)
# ---------------------------------------------------------------------------


def test_protobuf_to_pragma_deserializes_include_once() -> None:
    """A protobuf pragma with type include_once returns an IncludeOncePragma."""
    pb = yara_ast_pb2.Pragma()
    pb.pragma_type = "include_once"
    pb.name = "test"
    pb.scope = "file"

    result = protobuf_to_pragma(pb)

    assert isinstance(result, IncludeOncePragma)


# ---------------------------------------------------------------------------
# protobuf_to_pragma — ENDIF branch (line 2178)
# ---------------------------------------------------------------------------


def test_protobuf_to_pragma_deserializes_endif() -> None:
    """A protobuf pragma with type endif returns a ConditionalDirective for ENDIF."""
    pb = yara_ast_pb2.Pragma()
    pb.pragma_type = "endif"
    pb.name = "test"
    pb.scope = "file"

    result = protobuf_to_pragma(pb)

    assert isinstance(result, ConditionalDirective)
    assert result.pragma_type == PragmaType.ENDIF


# ---------------------------------------------------------------------------
# HexNibble with string value (line 1012-1013) — also covers nibble raw_value
# ---------------------------------------------------------------------------


def test_convert_hex_nibble_with_string_value_sets_raw_value() -> None:
    """A HexNibble with a string char value sets the raw_value field."""
    pb = yara_ast_pb2.HexToken()
    token = HexNibble(high=True, value="A")
    convert_hex_token_to_protobuf(token, pb)

    assert pb.nibble.high is True
    assert pb.nibble.raw_value == "A"


# ---------------------------------------------------------------------------
# OfExpression with frozenset string_set (exercises frozenset path)
# ---------------------------------------------------------------------------


def test_convert_of_expression_with_frozenset_string_set() -> None:
    """OfExpression with a frozenset string_set serializes correctly."""
    expr = OfExpression(quantifier="all", string_set=frozenset(["$a", "$b"]))
    pb = yara_ast_pb2.Expression()
    convert_expression_to_protobuf(expr, pb)

    items = list(pb.of_expression.string_set_items)
    assert "$a" in items
    assert "$b" in items


# ---------------------------------------------------------------------------
# Full roundtrip through protobuf_to_ast confirming include_once pragma
# ---------------------------------------------------------------------------


def test_roundtrip_ast_with_include_once_pragma() -> None:
    """An AST with an IncludeOncePragma survives a full protobuf roundtrip."""
    from yaraast.ast.base import YaraFile
    from yaraast.serialization.protobuf_conversion import ast_to_protobuf

    ast = YaraFile(
        imports=[],
        includes=[],
        rules=[
            Rule(
                name="my_rule",
                modifiers=[],
                tags=[],
                meta=[],
                strings=[],
                condition=BooleanLiteral(value=True),
            )
        ],
        pragmas=[IncludeOncePragma()],
    )
    # The IncludeOncePragma has scope=None; we need to set a non-None scope
    # so convert_pragma_to_protobuf stores it, and _protobuf_pragma_scope
    # can recover it (scope='' is rejected on the read side).
    ast.pragmas[0].scope = PragmaScope.FILE

    pb = ast_to_protobuf(ast, include_metadata=False)

    assert len(pb.pragmas) == 1
    assert pb.pragmas[0].pragma_type == "include_once"


# ---------------------------------------------------------------------------
# ForExpression quantifier as Expression with value (line 1221-1225)
# ---------------------------------------------------------------------------


def test_convert_for_expression_with_integer_literal_quantifier() -> None:
    """ForExpression with IntegerLiteral quantifier stores both text and expr."""
    expr = ForExpression(
        quantifier=IntegerLiteral(value=3),
        variable="i",
        iterable=Identifier(name="xs"),
        body=BooleanLiteral(value=True),
    )
    pb = yara_ast_pb2.Expression()
    convert_expression_to_protobuf(expr, pb)

    assert pb.for_expression.quantifier == "3"
    assert pb.for_expression.HasField("quantifier_expr")


# ---------------------------------------------------------------------------
# _copy_python_value_to_meta_value — float path (line 416)
# ---------------------------------------------------------------------------


def test_copy_python_value_to_meta_value_stores_float_as_double() -> None:
    """A float value is stored in the double_value field."""
    pb_meta_value = yara_ast_pb2.MetaValue()
    _copy_python_value_to_meta_value(0.75, pb_meta_value, "Meta")
    assert pb_meta_value.double_value == pytest.approx(0.75)


# ---------------------------------------------------------------------------
# StringCount with placeholder string_id — exercises allow_placeholder branch
# ---------------------------------------------------------------------------


def test_convert_string_count_serializes_string_id() -> None:
    """StringCount serializes its string_id to the string_count field."""
    pb = yara_ast_pb2.Expression()
    expr = StringCount(string_id="$")
    convert_expression_to_protobuf(expr, pb)
    assert pb.string_count.string_id == "$"
