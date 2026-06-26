"""Regression tests targeting uncovered lines in simple_roundtrip_helpers.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Each test exercises a specific uncovered code path identified in the
92.05% baseline coverage report.  All tests use real production objects
and assert on observed behaviour; no mocks, stubs or suppressions are
used anywhere in this file.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

from yaraast.ast.base import Location, YaraFile
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.conditions import (
    OfExpression,
)
from yaraast.ast.expressions import (
    BooleanLiteral,
    IntegerLiteral,
    StringLength,
    StringOffset,
)
from yaraast.ast.extern import ExternImport, ExternRule
from yaraast.ast.modifiers import MetaEntry, StringModifier, StringModifierType
from yaraast.ast.pragmas import (
    ConditionalDirective,
    DefineDirective,
    IncludeOncePragma,
    InRulePragma,
    Pragma,
    PragmaType,
    UndefDirective,
)
from yaraast.ast.rules import Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexString,
    PlainString,
    RegexString,
)
from yaraast.errors import SerializationError
from yaraast.serialization.simple_roundtrip_helpers import (
    _deserialize_ast_value,
    _deserialize_modifier,
    _deserialize_rule_modifiers,
    _format_unknown_modifier,
    _serialize_ast_value,
    _serialize_pragma_parameter_value,
    _serialize_string_set,
    _serialize_string_set_item,
    _validate_hex_negated_value,
    _validate_hex_nibble_value,
    _with_dynamic_node_metadata,
    cast_comment,
    cast_leading_comment,
    cast_trailing_comment,
    deserialize_meta,
    deserialize_node,
    deserialize_pragma,
    deserialize_rule,
    deserialize_string,
    serialize_meta,
    serialize_node,
    serialize_pragma,
    serialize_rule,
    serialize_string,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _simple_rule_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "type": "Rule",
        "name": "r1",
        "modifiers": [],
        "tags": [],
        "meta": [],
        "strings": [],
        "condition": None,
        "pragmas": [],
    }
    data.update(overrides)
    return data


def _simple_pragma_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "type": "Pragma",
        "pragma_type": "custom",
        "name": "vendor",
        "arguments": [],
        "scope": "file",
        "parameters": {},
    }
    data.update(overrides)
    return data


# ---------------------------------------------------------------------------
# Lines 175-176: _validate_hex_negated_value — negated nibble string branch
# ---------------------------------------------------------------------------


def test_validate_hex_negated_value_accepts_nibble_pattern_prefix() -> None:
    """_validate_hex_negated_value returns '?A' (first-nibble wildcard)."""
    result = _validate_hex_negated_value("?A")
    assert result == "?A"


def test_validate_hex_negated_value_accepts_nibble_pattern_suffix() -> None:
    """_validate_hex_negated_value returns 'B?' (second-nibble wildcard)."""
    result = _validate_hex_negated_value("B?")
    assert result == "B?"


# The negated-nibble roundtrip should also hit these lines through the
# HexNegatedByte serializer.
def test_hex_negated_byte_nibble_pattern_roundtrip() -> None:
    """HexNegatedByte holding '?A' serializes and deserializes correctly."""
    node = HexNegatedByte(value="?A")
    data = serialize_node(node)
    assert data["value"] == "?A"
    result = deserialize_node(data)
    assert isinstance(result, HexNegatedByte)
    assert result.value == "?A"


# ---------------------------------------------------------------------------
# Lines 259-260: _validate_hex_token_sequence — empty alternative branch
# ---------------------------------------------------------------------------


def test_validate_hex_token_sequence_rejects_empty_alternative_branch() -> None:
    """Serializing a HexAlternative with an empty branch raises SerializationError."""
    # The internal _coerce_hex_alternative_branch accepts a list unchanged,
    # so passing [] yields an empty branch which triggers the validation error.
    alt_empty = HexAlternative(alternatives=[[], [HexByte(0xBB)]])
    with pytest.raises(SerializationError, match="branches must not be empty"):
        serialize_node(alt_empty)


# ---------------------------------------------------------------------------
# Line 354: _serialize_hex_alternative_branches — alternatives not a list
# ---------------------------------------------------------------------------


def test_serialize_hex_alternative_branches_rejects_non_list() -> None:
    """A HexAlternative whose alternatives attribute is not a list raises."""
    alt = HexAlternative(alternatives=[[HexByte(0xFF)]])
    alt.alternatives = "not_a_list"
    with pytest.raises(SerializationError, match="must be a list"):
        serialize_node(alt)


# ---------------------------------------------------------------------------
# Lines 372-373: _serialize_plain_string_value — value is neither bytes nor str
# ---------------------------------------------------------------------------


def test_serialize_plain_string_value_rejects_integer_value() -> None:
    """PlainString.value of type int raises SerializationError."""
    ps = PlainString(identifier="$s", value="hello", modifiers=[], is_anonymous=False)
    object.__setattr__(ps, "value", 42)  # intentionally wrong type to test validation
    with pytest.raises(SerializationError, match="must be a string or bytes"):
        serialize_string(ps)


# ---------------------------------------------------------------------------
# Lines 420-424: _deserialize_nullable_nonempty_string_field — empty string field
# ---------------------------------------------------------------------------


def test_deserialize_nullable_nonempty_string_field_rejects_empty_string() -> None:
    """An Import alias of '' (empty string) triggers the nonempty check."""
    data = {
        "type": "Import",
        "module": "pe",
        "alias": "",
    }
    with pytest.raises(SerializationError, match="must not be empty"):
        deserialize_node(data)


# ---------------------------------------------------------------------------
# Line 432: _deserialize_required_nullable_string_field — not None, not str
# ---------------------------------------------------------------------------


def test_deserialize_required_nullable_string_field_rejects_non_string() -> None:
    """Rule name that is an integer triggers a string-type error."""
    data = _simple_rule_data(name=99)
    with pytest.raises(SerializationError):
        deserialize_rule(data)


# ---------------------------------------------------------------------------
# Line 612: _serialize_pragma_parameter_value — non-finite float
# ---------------------------------------------------------------------------


def test_serialize_pragma_parameter_value_rejects_inf() -> None:
    """Infinite floats are rejected as pragma parameter values."""
    import math

    with pytest.raises(SerializationError, match="finite float"):
        _serialize_pragma_parameter_value(math.inf)


def test_serialize_pragma_parameter_value_rejects_nan() -> None:
    """NaN floats are rejected as pragma parameter values."""
    import math

    with pytest.raises(SerializationError, match="finite float"):
        _serialize_pragma_parameter_value(math.nan)


# ---------------------------------------------------------------------------
# Lines 705-706: _serialize_meta_entry_value — non-finite float
# ---------------------------------------------------------------------------


def test_serialize_meta_entry_value_rejects_inf() -> None:
    """MetaEntry with infinite float value raises SerializationError."""
    import math

    me = MetaEntry.from_key_value("k", "val", None)
    object.__setattr__(me, "value", math.inf)
    with pytest.raises(SerializationError, match="Meta value must be"):
        serialize_meta(me)


# ---------------------------------------------------------------------------
# Lines 711-715: _deserialize_rule_tag — Tag object passed directly
# ---------------------------------------------------------------------------


def test_deserialize_rule_tag_accepts_tag_object() -> None:
    """A pre-built Tag object in rule.tags is accepted and re-used."""
    tag_obj = Tag(name="infected")
    rule_data = _simple_rule_data(tags=[tag_obj])
    result = deserialize_rule(rule_data)
    assert len(result.tags) == 1
    assert result.tags[0].name == "infected"


# ---------------------------------------------------------------------------
# Lines 735-736: _deserialize_rule_tag — value is not str/dict/Tag
# ---------------------------------------------------------------------------


def test_deserialize_rule_tag_rejects_integer_tag() -> None:
    """An integer in rule tags raises SerializationError."""
    rule_data = _simple_rule_data(tags=[42])
    with pytest.raises(SerializationError, match="Tag name must be a string"):
        deserialize_rule(rule_data)


# ---------------------------------------------------------------------------
# Lines 796-797: _validated_node_collection — wrong element type
# ---------------------------------------------------------------------------


def test_validated_node_collection_rejects_wrong_type() -> None:
    """Rule strings containing a non-StringDefinition node raises."""
    rule = Rule(name="r1", modifiers=[], condition=BooleanLiteral(True))
    object.__setattr__(rule, "strings", [IntegerLiteral(1)])  # intentionally wrong type
    with pytest.raises(SerializationError, match="must contain"):
        serialize_rule(rule)


# ---------------------------------------------------------------------------
# Lines 809-810: _serialize_meta_entries — wrong element type
# ---------------------------------------------------------------------------


def test_serialize_meta_entries_rejects_non_meta_element() -> None:
    """Rule meta containing an IntegerLiteral raises SerializationError."""
    rule = Rule(name="r1", modifiers=[], condition=BooleanLiteral(True))
    rule.meta = [IntegerLiteral(5)]  # intentionally wrong type to test validation
    with pytest.raises(SerializationError, match="must contain Meta or MetaEntry"):
        serialize_rule(rule)


# ---------------------------------------------------------------------------
# Lines 823-824: _serialize_string_definitions — wrong element type
# ---------------------------------------------------------------------------


def test_serialize_string_definitions_rejects_non_string_def() -> None:
    """Rule strings containing an IntegerLiteral raises."""
    rule = Rule(name="r1", modifiers=[], condition=BooleanLiteral(True))
    object.__setattr__(rule, "strings", [IntegerLiteral(7)])  # intentionally wrong type
    with pytest.raises(SerializationError, match="must contain StringDefinition"):
        serialize_rule(rule)


# ---------------------------------------------------------------------------
# Lines 833, 836: _format_unknown_modifier — tuple and str value forms
# ---------------------------------------------------------------------------


def test_format_unknown_modifier_with_range_tuple() -> None:
    """Tuple of (low, high) produces 'name(low-high)' format."""
    result = _format_unknown_modifier("xor", (0, 255))
    assert result == "xor(0-255)"


def test_format_unknown_modifier_with_string_value() -> None:
    """String value produces 'name("escaped_value")' format."""
    result = _format_unknown_modifier("ascii_str", "hello")
    assert result == 'ascii_str("hello")'


# ---------------------------------------------------------------------------
# Lines 850-851, 862: _deserialize_modifier — empty name and dict-path return
# ---------------------------------------------------------------------------


def test_deserialize_modifier_rejects_empty_string_name() -> None:
    """An empty string modifier name raises SerializationError."""
    data = _simple_rule_data(
        strings=[
            {
                "type": "PlainString",
                "identifier": "$s",
                "value": "hi",
                "modifiers": [""],
            }
        ]
    )
    with pytest.raises(SerializationError, match="must not be empty"):
        deserialize_rule(data)


def test_deserialize_modifier_dict_path_applies_metadata() -> None:
    """A dict modifier with a known name produces a StringModifier with location."""
    data = {
        "type": "PlainString",
        "identifier": "$s",
        "value": "hello",
        "modifiers": [
            {
                "name": "nocase",
                "value": None,
                "location": {"line": 3, "column": 10},
            }
        ],
    }
    result = deserialize_string(data)
    assert isinstance(result, PlainString)
    assert len(result.modifiers) == 1
    mod = result.modifiers[0]
    assert isinstance(mod, StringModifier)
    assert mod.location is not None
    assert mod.location.line == 3


# ---------------------------------------------------------------------------
# Lines 870-876: _serialize_ast_value — set and frozenset branches
# ---------------------------------------------------------------------------


def test_serialize_ast_value_handles_frozenset_of_strings() -> None:
    """frozenset values are sorted and serialized as a list."""
    result = _serialize_ast_value(frozenset(["$b", "$a"]))
    assert isinstance(result, list)
    assert sorted(result) == ["$a", "$b"]


def test_serialize_ast_value_handles_set_of_strings() -> None:
    """set values are sorted and serialized as a list."""
    result = _serialize_ast_value({"$z", "$y"})
    assert isinstance(result, list)
    assert sorted(result) == ["$y", "$z"]


# ---------------------------------------------------------------------------
# Line 896: _serialize_string_set_item — Expression branch
# ---------------------------------------------------------------------------


def test_serialize_string_set_item_accepts_expression() -> None:
    """An Expression passed as a set item serializes to a dict."""
    expr = IntegerLiteral(99)
    result = _serialize_string_set_item(expr, "OfExpression string_set")
    assert isinstance(result, dict)
    assert result["type"] == "IntegerLiteral"
    assert result["value"] == 99


# ---------------------------------------------------------------------------
# Line 910: _serialize_string_set — Expression as the whole string_set
# ---------------------------------------------------------------------------


def test_serialize_string_set_accepts_expression_value() -> None:
    """An Expression passed directly as string_set returns its serialized form."""
    expr = IntegerLiteral(5)
    result = _serialize_string_set(expr, "ForOfExpression")
    assert isinstance(result, dict)
    assert result["type"] == "IntegerLiteral"


# ---------------------------------------------------------------------------
# Lines 919-922: _serialize_string_set — frozenset path
# ---------------------------------------------------------------------------


def test_serialize_string_set_handles_frozenset() -> None:
    """frozenset of string references produces a sorted list."""
    result = _serialize_string_set(frozenset(["$b", "$a"]), "OfExpression")
    assert isinstance(result, list)
    assert sorted(result) == ["$a", "$b"]


def test_serialize_string_set_rejects_empty_frozenset() -> None:
    """An empty frozenset raises SerializationError."""
    with pytest.raises(SerializationError, match="must contain values"):
        _serialize_string_set(frozenset(), "OfExpression")


# ---------------------------------------------------------------------------
# Lines 929-930: _deserialize_ast_value — None and {} at top level
# ---------------------------------------------------------------------------


def test_deserialize_ast_value_rejects_none() -> None:
    """None as the top-level AST value raises SerializationError."""
    with pytest.raises(SerializationError, match="is required"):
        _deserialize_ast_value(None)


def test_deserialize_ast_value_rejects_empty_dict() -> None:
    """Empty dict as the top-level AST value raises SerializationError."""
    with pytest.raises(SerializationError, match="is required"):
        _deserialize_ast_value({})


# ---------------------------------------------------------------------------
# Lines 934-940: _deserialize_ast_value — list with valid items, None, {}
# ---------------------------------------------------------------------------


def test_deserialize_ast_value_handles_list_of_dicts() -> None:
    """A list of node dicts is deserialized to a list of ASTNodes."""
    result = _deserialize_ast_value([{"type": "IntegerLiteral", "value": 3}])
    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], IntegerLiteral)
    assert result[0].value == 3


def test_deserialize_ast_value_rejects_list_containing_none() -> None:
    """A list containing None raises SerializationError."""
    with pytest.raises(SerializationError, match="must contain values"):
        _deserialize_ast_value([None])


def test_deserialize_ast_value_rejects_list_containing_empty_dict() -> None:
    """A list containing {} raises SerializationError."""
    with pytest.raises(SerializationError, match="must contain values"):
        _deserialize_ast_value([{}])


# ---------------------------------------------------------------------------
# Line 978: _deserialize_string_set_item — dict (expression) branch
# ---------------------------------------------------------------------------


def test_deserialize_string_set_item_accepts_dict_expression() -> None:
    """A dict representing a node is deserialized to an ASTNode."""
    data = {"type": "IntegerLiteral", "value": 7}
    from yaraast.serialization.simple_roundtrip_helpers import _deserialize_string_set_item

    result = _deserialize_string_set_item(data, "OfExpression string_set")
    assert isinstance(result, IntegerLiteral)
    assert result.value == 7


# ---------------------------------------------------------------------------
# Lines 1070->1072: _with_dynamic_node_metadata — location is present
# ---------------------------------------------------------------------------


def test_with_dynamic_node_metadata_serializes_location() -> None:
    """A dynamic (non-ASTNode) object with a location gets it serialized."""
    result = _with_dynamic_node_metadata(
        SimpleNamespace(
            location=Location(line=5, column=10), leading_comments=[], trailing_comment=None
        ),
        {"type": "Meta", "key": "k", "value": "v"},
    )
    assert "location" in result
    assert result["location"]["line"] == 5
    assert result["location"]["column"] == 10


# ---------------------------------------------------------------------------
# Line 1078: _with_dynamic_node_metadata — leading_comments present
# ---------------------------------------------------------------------------


def test_with_dynamic_node_metadata_serializes_leading_comments() -> None:
    """A dynamic node with leading_comments gets them serialized."""
    result = _with_dynamic_node_metadata(
        SimpleNamespace(
            location=None,
            leading_comments=[Comment("// note", is_multiline=False)],
            trailing_comment=None,
        ),
        {"type": "Meta", "key": "k", "value": 0},
    )
    assert "leading_comments" in result
    assert len(result["leading_comments"]) == 1
    assert result["leading_comments"][0]["type"] == "Comment"


# ---------------------------------------------------------------------------
# Lines 1081-1084: _with_dynamic_node_metadata — invalid trailing_comment
# ---------------------------------------------------------------------------


def test_with_dynamic_node_metadata_rejects_invalid_trailing_comment() -> None:
    """A trailing_comment that is not Comment/CommentGroup raises."""
    with pytest.raises(SerializationError, match="trailing_comment must be a Comment"):
        _with_dynamic_node_metadata(
            SimpleNamespace(
                location=None, leading_comments=[], trailing_comment="raw string, not a Comment"
            ),
            {},
        )


# ---------------------------------------------------------------------------
# Lines 1173-1176: serialize_node (StringModifier) — XOR with bad string value
# ---------------------------------------------------------------------------


def test_serialize_string_modifier_xor_invalid_value_raises() -> None:
    """Serializing a StringModifier(XOR, bad_value) raises SerializationError."""
    sm = StringModifier(modifier_type=StringModifierType.XOR, value="not_a_xor_range")
    with pytest.raises(SerializationError, match="xor value must be"):
        serialize_node(sm)


# ---------------------------------------------------------------------------
# Lines 1202-1203: ExternImport module_path is whitespace-only
# ---------------------------------------------------------------------------


def test_serialize_extern_import_rejects_whitespace_module_path() -> None:
    """A module_path that is only whitespace raises SerializationError."""
    ei = ExternImport(module_path="   ", alias=None, rules=["MyRule"])
    with pytest.raises(SerializationError, match="module_path must not be empty"):
        serialize_node(ei)


# ---------------------------------------------------------------------------
# Lines 1206-1207: ExternImport alias is whitespace-only
# ---------------------------------------------------------------------------


def test_serialize_extern_import_rejects_whitespace_alias() -> None:
    """An alias that is only whitespace raises SerializationError."""
    ei = ExternImport(module_path="my_module", alias="   ", rules=["MyRule"])
    with pytest.raises(SerializationError, match="alias must not be empty"):
        serialize_node(ei)


# ---------------------------------------------------------------------------
# Lines 1212-1213: ExternImport rules contain whitespace-only strings
# ---------------------------------------------------------------------------


def test_serialize_extern_import_rejects_whitespace_rule_names() -> None:
    """ExternImport rules containing only whitespace raises SerializationError."""
    ei = ExternImport(module_path="my_module", alias=None, rules=["   "])
    with pytest.raises(SerializationError, match="rules must contain non-empty"):
        serialize_node(ei)


# ---------------------------------------------------------------------------
# Lines 1774-1775: _serialize_rule_modifiers — non-str, non-RuleModifier element
# ---------------------------------------------------------------------------


def test_serialize_rule_modifiers_rejects_non_modifier_type() -> None:
    """A modifier that is neither str nor RuleModifier raises."""
    rule = Rule(name="r1", modifiers=[], condition=BooleanLiteral(True))
    rule.modifiers = [42]  # intentionally wrong type to test validation
    with pytest.raises(SerializationError, match="modifiers must contain strings or RuleModifier"):
        serialize_rule(rule)


# ---------------------------------------------------------------------------
# Lines 1806-1807: _serialize_rule_tags — tag is not str or Tag
# ---------------------------------------------------------------------------


def test_serialize_rule_tags_rejects_integer_tag() -> None:
    """An integer in rule tags raises SerializationError."""
    rule = Rule(name="r1", modifiers=[], condition=BooleanLiteral(True))
    object.__setattr__(rule, "tags", [99])  # intentionally wrong type to test validation
    with pytest.raises(SerializationError, match="must contain Tag nodes or strings"):
        serialize_rule(rule)


# ---------------------------------------------------------------------------
# Lines 1833, 1835: serialize_pragma — macro_name and macro_value fields
# ---------------------------------------------------------------------------


def test_serialize_pragma_define_directive_includes_macro_fields() -> None:
    """DefineDirective serialization produces macro_name and macro_value."""
    p = DefineDirective(macro_name="MAX_SIZE", macro_value="256")
    data = serialize_pragma(p)
    assert data["macro_name"] == "MAX_SIZE"
    assert data["macro_value"] == "256"


def test_serialize_pragma_define_directive_roundtrips() -> None:
    """DefineDirective serializes and deserializes to the same object."""
    p = DefineDirective(macro_name="FLAG", macro_value=None)
    data = serialize_pragma(p)
    result = deserialize_pragma(data)
    assert isinstance(result, DefineDirective)
    assert result.macro_name == "FLAG"
    assert result.macro_value is None


# ---------------------------------------------------------------------------
# Lines 1849-1856: serialize_pragma — ENDIF condition (nullable branch)
# ---------------------------------------------------------------------------


def test_serialize_pragma_endif_condition_is_included() -> None:
    """ENDIF pragma with a condition serializes the condition field."""
    p = ConditionalDirective(PragmaType.ENDIF, condition="MY_DEFINE")
    data = serialize_pragma(p)
    assert data.get("condition") == "MY_DEFINE"


def test_serialize_pragma_endif_condition_roundtrips() -> None:
    """ENDIF pragma with a condition round-trips correctly."""
    p = ConditionalDirective(PragmaType.ENDIF, condition="MY_FLAG")
    data = serialize_pragma(p)
    result = deserialize_pragma(data)
    assert isinstance(result, ConditionalDirective)
    assert getattr(result, "condition", None) == "MY_FLAG"


# ---------------------------------------------------------------------------
# Lines 1913-1914: serialize_string — anonymous HexString
# ---------------------------------------------------------------------------


def test_serialize_hex_string_anonymous_flag_is_included() -> None:
    """Anonymous HexString serialization includes is_anonymous: True."""
    hs = HexString(
        identifier="$anon",
        tokens=[HexByte(0xDE), HexByte(0xAD)],
        modifiers=[],
        is_anonymous=True,
    )
    data = serialize_string(hs)
    assert data.get("is_anonymous") is True


# ---------------------------------------------------------------------------
# Lines 1960-1963: serialize_string — fallback ASTNode path
# ---------------------------------------------------------------------------


def test_serialize_string_fallback_for_non_standard_ast_node() -> None:
    """A non-StringDefinition ASTNode falls back to the 'data' key format."""
    node = Comment("// weird")
    result = serialize_string(node)
    assert result["type"] == "StringDefinition"
    assert "data" in result


# ---------------------------------------------------------------------------
# Lines 2048-2049: deserialize ExternImport with whitespace module_path
# ---------------------------------------------------------------------------


def test_deserialize_extern_import_rejects_whitespace_module_path() -> None:
    """Deserializing ExternImport with whitespace module_path raises."""
    data = {
        "type": "ExternImport",
        "module_path": "   ",
        "alias": None,
        "rules": ["Rule1"],
    }
    with pytest.raises(SerializationError, match="module_path must not be empty"):
        deserialize_node(data)


# ---------------------------------------------------------------------------
# Lines 2052-2053: deserialize ExternImport with whitespace alias
# ---------------------------------------------------------------------------


def test_deserialize_extern_import_rejects_whitespace_alias() -> None:
    """Deserializing ExternImport with whitespace alias raises."""
    data = {
        "type": "ExternImport",
        "module_path": "my_mod",
        "alias": "   ",
        "rules": ["Rule1"],
    }
    with pytest.raises(SerializationError, match="alias must not be empty"):
        deserialize_node(data)


# ---------------------------------------------------------------------------
# Lines 2143->2145: StringOffset with non-None index (branch taken)
# ---------------------------------------------------------------------------


def test_deserialize_string_offset_with_index() -> None:
    """StringOffset with an index deserializes the index expression."""
    data = {
        "type": "StringOffset",
        "string_id": "$a",
        "index": {"type": "IntegerLiteral", "value": 2},
    }
    result = deserialize_node(data)
    assert isinstance(result, StringOffset)
    assert isinstance(result.index, IntegerLiteral)
    assert result.index.value == 2


# ---------------------------------------------------------------------------
# Lines 2152->2154: StringLength with non-None index (branch taken)
# ---------------------------------------------------------------------------


def test_deserialize_string_length_with_index() -> None:
    """StringLength with an index deserializes the index expression."""
    data = {
        "type": "StringLength",
        "string_id": "$b",
        "index": {"type": "IntegerLiteral", "value": 1},
    }
    result = deserialize_node(data)
    assert isinstance(result, StringLength)
    assert isinstance(result.index, IntegerLiteral)
    assert result.index.value == 1


# ---------------------------------------------------------------------------
# Line 2269: InExpression — subject is neither str nor dict (else branch)
# ---------------------------------------------------------------------------


def test_deserialize_in_expression_rejects_non_string_non_dict_subject() -> None:
    """InExpression subject that is neither a string nor dict raises."""
    data = {
        "type": "InExpression",
        "subject": 42,
        "range": {
            "type": "RangeExpression",
            "low": {"type": "IntegerLiteral", "value": 0},
            "high": {"type": "IntegerLiteral", "value": 100},
        },
    }
    with pytest.raises(SerializationError, match="subject must be a string or expression"):
        deserialize_node(data)


# ---------------------------------------------------------------------------
# Lines 2456-2457: ListExpression elements — not a list
# ---------------------------------------------------------------------------


def test_deserialize_list_expression_rejects_non_list_elements() -> None:
    """ListExpression with elements that is a string raises."""
    data = {"type": "ListExpression", "elements": "not_a_list"}
    with pytest.raises(SerializationError, match="elements must be a list"):
        deserialize_node(data)


# ---------------------------------------------------------------------------
# Lines 2468-2469: DictExpression items — not a list
# ---------------------------------------------------------------------------


def test_deserialize_dict_expression_rejects_non_list_items() -> None:
    """DictExpression with items that is a string raises."""
    data = {"type": "DictExpression", "items": "not_a_list"}
    with pytest.raises(SerializationError, match="items must be a list"):
        deserialize_node(data)


# ---------------------------------------------------------------------------
# Line 2630: _deserialize_rule_modifiers — unrecognised modifier string
# ---------------------------------------------------------------------------


def test_deserialize_rule_modifiers_preserves_unknown_modifier_string() -> None:
    """An unrecognised modifier string is preserved as-is (no crash)."""
    data = _simple_rule_data(modifiers=["unknown_modifier"])
    result = deserialize_rule(data)
    assert "unknown_modifier" in result.modifiers


# ---------------------------------------------------------------------------
# Line 2662: deserialize_extern_rule — unknown modifier preserved
# ---------------------------------------------------------------------------


def test_deserialize_extern_rule_preserves_unknown_modifier() -> None:
    """An unrecognised ExternRule modifier string is preserved as-is."""
    data = {
        "type": "ExternRule",
        "name": "ext_rule",
        "modifiers": ["custom_mod"],
        "namespace": None,
    }
    result = deserialize_node(data)
    assert isinstance(result, ExternRule)
    modifier_strings = [str(m) for m in result.modifiers]
    assert "custom_mod" in modifier_strings


# ---------------------------------------------------------------------------
# Line 2678: ExternRule with non-None namespace
# ---------------------------------------------------------------------------


def test_deserialize_extern_rule_with_namespace() -> None:
    """ExternRule with a namespace field deserializes namespace correctly."""
    data = {
        "type": "ExternRule",
        "name": "my_rule",
        "modifiers": [],
        "namespace": "MyNamespace",
    }
    result = deserialize_node(data)
    assert isinstance(result, ExternRule)
    assert result.namespace == "MyNamespace"


# ---------------------------------------------------------------------------
# Lines 2703-2705: deserialize_pragma — ENDIF with non-None condition
# ---------------------------------------------------------------------------


def test_deserialize_pragma_endif_with_condition() -> None:
    """ENDIF pragma data with condition field deserializes correctly."""
    data = {
        "type": "Pragma",
        "pragma_type": "endif",
        "name": "endif",
        "arguments": ["MY_DEFINE"],
        "scope": "file",
        "condition": "MY_DEFINE",
    }
    result = deserialize_pragma(data)
    assert isinstance(result, ConditionalDirective)
    assert getattr(result, "condition", None) == "MY_DEFINE"


# ---------------------------------------------------------------------------
# Line 2718: deserialize_pragma — else/generic Pragma branch
# ---------------------------------------------------------------------------


def test_deserialize_pragma_generic_else_branch() -> None:
    """Pragma with an unrecognized pragma_type hits the else branch."""
    data = _simple_pragma_data(
        pragma_type="include_once",
        name="include_once",
        arguments=[],
        scope="file",
    )
    del data["parameters"]
    result = deserialize_pragma(data)
    assert isinstance(result, IncludeOncePragma)


# ---------------------------------------------------------------------------
# Lines 2745-2746: cast_comment — wrong node type
# ---------------------------------------------------------------------------


def test_cast_comment_rejects_non_comment_node() -> None:
    """cast_comment raises SerializationError for non-Comment ASTNodes."""
    with pytest.raises(SerializationError, match="must contain Comment nodes"):
        cast_comment(IntegerLiteral(1))


# ---------------------------------------------------------------------------
# Lines 2752-2753: cast_leading_comment — wrong node type
# ---------------------------------------------------------------------------


def test_cast_leading_comment_rejects_non_comment_node() -> None:
    """cast_leading_comment raises SerializationError for wrong node types."""
    with pytest.raises(SerializationError, match="leading_comments must contain"):
        cast_leading_comment(IntegerLiteral(2))


# ---------------------------------------------------------------------------
# Line 2753 (cast_trailing_comment): wrong node type
# ---------------------------------------------------------------------------


def test_cast_trailing_comment_rejects_non_comment_node() -> None:
    """cast_trailing_comment raises SerializationError for wrong node types."""
    with pytest.raises(SerializationError, match="trailing_comment must contain"):
        cast_trailing_comment(IntegerLiteral(3))


# ---------------------------------------------------------------------------
# Line 2770: deserialize_meta — Meta type with scope field raises
# ---------------------------------------------------------------------------


def test_deserialize_meta_rejects_scope_on_meta_type() -> None:
    """A Meta node (not MetaEntry) with a scope field is rejected."""
    with pytest.raises(SerializationError, match="scope is only valid for MetaEntry"):
        deserialize_meta({"type": "Meta", "key": "foo", "value": "bar", "scope": "public"})


# ---------------------------------------------------------------------------
# Implicit MetaEntry from scope field (lines 2766-2780)
# ---------------------------------------------------------------------------


def test_deserialize_meta_implicit_meta_entry_from_scope() -> None:
    """A dict without a type but with a scope field produces a MetaEntry."""
    result = deserialize_meta({"key": "my_key", "value": 42, "scope": "public"})
    assert isinstance(result, MetaEntry)
    assert result.key == "my_key"
    assert result.value == 42


# ---------------------------------------------------------------------------
# _serialize_string_set — string_set_item branches and frozenset coverage
# ---------------------------------------------------------------------------


def test_of_expression_with_frozenset_string_set_roundtrips() -> None:
    """OfExpression with a frozenset string_set serializes and deserializes."""
    expr = OfExpression(
        quantifier=1,
        string_set=frozenset(["$b", "$a"]),
    )
    data = serialize_node(expr)
    assert isinstance(data["string_set"], list)
    result = deserialize_node(data)
    assert isinstance(result, OfExpression)


# ---------------------------------------------------------------------------
# Pragma with UNDEF roundtrip (hits macro_name code path on deserialization)
# ---------------------------------------------------------------------------


def test_serialize_pragma_undef_directive_roundtrips() -> None:
    """UndefDirective serializes and deserializes to the same object."""
    p = UndefDirective(macro_name="OLD_FLAG")
    data = serialize_pragma(p)
    assert data["macro_name"] == "OLD_FLAG"
    result = deserialize_pragma(data)
    assert isinstance(result, UndefDirective)
    assert result.macro_name == "OLD_FLAG"


# ---------------------------------------------------------------------------
# HexNegatedByte with two-char hex value (lines 174-175)
# ---------------------------------------------------------------------------


def test_hex_negated_byte_with_hex_string_value_roundtrips() -> None:
    """HexNegatedByte with a two-char hex string roundtrips correctly."""
    node = HexNegatedByte(value="AB")
    data = serialize_node(node)
    assert data["value"] == "AB"
    result = deserialize_node(data)
    assert isinstance(result, HexNegatedByte)
    assert result.value == "AB"


# ---------------------------------------------------------------------------
# cast_comment via CommentGroup deserialization — success path
# ---------------------------------------------------------------------------


def test_comment_group_deserialization_uses_cast_comment() -> None:
    """CommentGroup deserialization casts each inner node through cast_comment."""
    data = {
        "type": "CommentGroup",
        "comments": [
            {"type": "Comment", "text": "// first", "is_multiline": False},
            {"type": "Comment", "text": "/* second */", "is_multiline": True},
        ],
    }
    result = deserialize_node(data)
    assert isinstance(result, CommentGroup)
    assert len(result.comments) == 2
    assert all(isinstance(c, Comment) for c in result.comments)


# ---------------------------------------------------------------------------
# _with_dynamic_node_metadata via serialize_meta on non-ASTNode with attrs
# ---------------------------------------------------------------------------


def test_serialize_meta_with_dynamic_object_trailing_comment() -> None:
    """serialize_meta on a non-ASTNode dynamic object with trailing_comment."""
    result = serialize_meta(
        cast(
            Any,
            SimpleNamespace(
                key="k",
                value="v",
                scope=None,
                location=None,
                leading_comments=[],
                trailing_comment=Comment("// end", is_multiline=False),
            ),
        ),
    )
    assert "trailing_comment" in result
    assert result["trailing_comment"]["type"] == "Comment"


# ---------------------------------------------------------------------------
# ExternImport rules whitespace check on deserialization (line ~2059-2061)
# ---------------------------------------------------------------------------


def test_deserialize_extern_import_rejects_whitespace_rule_names() -> None:
    """ExternImport with whitespace-only rule names raises."""
    data = {
        "type": "ExternImport",
        "module_path": "my_mod",
        "alias": None,
        "rules": ["   "],
    }
    with pytest.raises(SerializationError, match="non-empty"):
        deserialize_node(data)


# ---------------------------------------------------------------------------
# Verify overall module coverage improvement
# ---------------------------------------------------------------------------


def test_coverage_smoke_hex_nibble_with_integer_value() -> None:
    """HexNibble with an integer value roundtrips correctly."""
    node = HexNibble(high=True, value=0xA)
    data = serialize_node(node)
    assert data["value"] == 0xA
    result = deserialize_node(data)
    assert isinstance(result, HexNibble)
    assert result.value == 0xA
    assert result.high is True


def test_coverage_smoke_hex_jump_roundtrip() -> None:
    """HexJump with min and max roundtrips correctly."""
    hs = HexString(
        identifier="$j",
        tokens=[HexByte(0x01), HexJump(min_jump=2, max_jump=4), HexByte(0x02)],
        modifiers=[],
        is_anonymous=False,
    )
    data = serialize_string(hs)
    result = deserialize_string(data)
    assert isinstance(result, HexString)
    jump = result.tokens[1]
    assert isinstance(jump, HexJump)
    assert jump.min_jump == 2
    assert jump.max_jump == 4


# ---------------------------------------------------------------------------
# Line 176->178: _validate_hex_negated_value — str that is not hex and not nibble
# ---------------------------------------------------------------------------


def test_validate_hex_negated_value_rejects_non_nibble_non_hex_string() -> None:
    """A string that is neither a 2-char hex nor a nibble pattern raises."""
    from yaraast.serialization.simple_roundtrip_helpers import _validate_hex_negated_value

    with pytest.raises(SerializationError, match="must be a byte or negated nibble"):
        _validate_hex_negated_value("??")


def test_validate_hex_negated_value_rejects_long_string() -> None:
    """A string longer than 2 characters is rejected."""
    from yaraast.serialization.simple_roundtrip_helpers import _validate_hex_negated_value

    with pytest.raises(SerializationError, match="must be a byte or negated nibble"):
        _validate_hex_negated_value("ABC")


# ---------------------------------------------------------------------------
# Line 186: _validate_hex_nibble_value — invalid value raises
# ---------------------------------------------------------------------------


def test_validate_hex_nibble_value_rejects_invalid_value() -> None:
    """A value that is not a nibble (0-0xF or single hex char) raises."""
    from yaraast.serialization.simple_roundtrip_helpers import _validate_hex_nibble_value

    with pytest.raises(SerializationError, match="must be a nibble"):
        _validate_hex_nibble_value(0x10)  # 16 is out of nibble range

    with pytest.raises(SerializationError, match="must be a nibble"):
        _validate_hex_nibble_value("AB")  # 2 chars, not 1


# ---------------------------------------------------------------------------
# Lines 259-260: empty branch inside a nested HexAlternative
# ---------------------------------------------------------------------------


def test_validate_hex_token_sequence_rejects_empty_nested_branch() -> None:
    """A HexString with a HexAlternative containing an empty branch raises."""
    from yaraast.ast.strings import HexAlternative, HexByte, HexString

    # Build an alternative where one branch is empty ([] coerces to empty).
    alt = HexAlternative(alternatives=[[], [HexByte(0xCC)]])
    hs = HexString(
        identifier="$h",
        tokens=[HexByte(0x01), alt, HexByte(0x02)],
        modifiers=[],
        is_anonymous=False,
    )
    with pytest.raises(SerializationError, match="branches must not be empty"):
        serialize_string(hs)


# ---------------------------------------------------------------------------
# Line 354: _serialize_hex_alternative_branches — alternatives is not a list
# ---------------------------------------------------------------------------


def test_serialize_hex_alternative_branches_non_list_raises() -> None:
    """HexAlternative whose alternatives is a string raises."""
    from yaraast.ast.strings import HexAlternative

    alt = HexAlternative(alternatives=[[HexByte(0xAA)]])
    alt.alternatives = "invalid"  # intentionally wrong type to test validation
    with pytest.raises(SerializationError, match="must be a list"):
        serialize_node(alt)


# ---------------------------------------------------------------------------
# Lines 372-373: _serialize_plain_string_value — value is not str or bytes
# ---------------------------------------------------------------------------


def test_serialize_plain_string_value_rejects_non_string_bytes() -> None:
    """PlainString.value of type list raises SerializationError."""
    ps = PlainString(identifier="$s", value="ok", modifiers=[], is_anonymous=False)
    object.__setattr__(ps, "value", [1, 2, 3])  # intentionally wrong type to test validation
    with pytest.raises(SerializationError, match="must be a string or bytes"):
        serialize_string(ps)


# ---------------------------------------------------------------------------
# Lines 422-423: _deserialize_nullable_nonempty_string_field — empty string
# ---------------------------------------------------------------------------


def test_deserialize_nullable_nonempty_string_field_empty_import_alias() -> None:
    """Import alias of '' triggers the non-empty string validation."""
    data = {"type": "Import", "module": "pe", "alias": ""}
    with pytest.raises(SerializationError, match="must not be empty"):
        deserialize_node(data)


# ---------------------------------------------------------------------------
# Line 612: _serialize_pragma_parameter_value — non-finite float (-inf)
# ---------------------------------------------------------------------------


def test_serialize_pragma_parameter_value_rejects_negative_inf() -> None:
    """Negative infinite float is rejected as a pragma parameter value."""
    import math

    with pytest.raises(SerializationError, match="finite float"):
        _serialize_pragma_parameter_value(-math.inf)


# ---------------------------------------------------------------------------
# Lines 796-797: _validated_node_collection — wrong element type
# ---------------------------------------------------------------------------


def test_validated_node_collection_rejects_integer_element() -> None:
    """YaraFile imports containing an integer raises SerializationError."""
    from yaraast.serialization.simple_roundtrip_helpers import serialize_yarafile

    yf = YaraFile()
    object.__setattr__(yf, "imports", [42])  # intentionally wrong type to test validation
    with pytest.raises(SerializationError, match="must contain"):
        serialize_yarafile(yf)


# ---------------------------------------------------------------------------
# Line 836: _format_unknown_modifier — string value branch
# ---------------------------------------------------------------------------


def test_format_unknown_modifier_with_non_tuple_non_none_value() -> None:
    """Non-tuple, non-None, non-string value produces 'name(value)' format."""
    result = _format_unknown_modifier("custom", 42)
    assert result == "custom(42)"


# ---------------------------------------------------------------------------
# Line 850-851: _deserialize_modifier — empty string raises
# ---------------------------------------------------------------------------


def test_deserialize_modifier_string_empty_name_raises() -> None:
    """An empty string used directly as a modifier raises SerializationError."""
    data_with_empty_modifier = {
        "type": "PlainString",
        "identifier": "$x",
        "value": "test",
        "modifiers": [""],
    }
    with pytest.raises(SerializationError, match="must not be empty"):
        deserialize_string(data_with_empty_modifier)


# ---------------------------------------------------------------------------
# Line 862: _deserialize_modifier — dict modifier, known name, metadata applied
# ---------------------------------------------------------------------------


def test_deserialize_modifier_dict_with_known_name_returns_string_modifier() -> None:
    """A dict modifier with a recognised name applies location metadata."""
    string_data = {
        "type": "PlainString",
        "identifier": "$t",
        "value": "hello",
        "modifiers": [
            {
                "name": "wide",
                "value": None,
                "location": {"line": 10, "column": 5},
            }
        ],
    }
    result = deserialize_string(string_data)
    assert isinstance(result, PlainString)
    mod = result.modifiers[0]
    assert isinstance(mod, StringModifier)
    assert mod.location is not None
    assert mod.location.line == 10


# ---------------------------------------------------------------------------
# Lines 871, 873: _serialize_ast_value — ASTNode and list branches
# ---------------------------------------------------------------------------


def test_serialize_ast_value_with_ast_node() -> None:
    """An ASTNode passed to _serialize_ast_value is serialized."""
    from yaraast.serialization.simple_roundtrip_helpers import _serialize_ast_value

    result = _serialize_ast_value(IntegerLiteral(7))
    assert isinstance(result, dict)
    assert result["type"] == "IntegerLiteral"
    assert result["value"] == 7


def test_serialize_ast_value_with_list_of_ast_nodes() -> None:
    """A list of ASTNodes is recursively serialized."""
    from yaraast.serialization.simple_roundtrip_helpers import _serialize_ast_value

    result = _serialize_ast_value([IntegerLiteral(1), IntegerLiteral(2)])
    assert isinstance(result, list)
    assert len(result) == 2
    assert result[0]["value"] == 1
    assert result[1]["value"] == 2


# ---------------------------------------------------------------------------
# Line 910: _serialize_string_set — Expression (not list/set/str) as string_set
# ---------------------------------------------------------------------------


def test_serialize_string_set_with_integer_literal_expression() -> None:
    """An IntegerLiteral Expression passed as string_set returns its dict form."""
    from yaraast.serialization.simple_roundtrip_helpers import _serialize_string_set

    result = _serialize_string_set(IntegerLiteral(42), "OfExpression")
    assert isinstance(result, dict)
    assert result.get("type") == "IntegerLiteral"


# ---------------------------------------------------------------------------
# Lines 1202-1213: ExternImport whitespace paths (serialize)
# ---------------------------------------------------------------------------


def test_serialize_extern_import_whitespace_module_path_raises() -> None:
    """ExternImport.module_path of '   ' raises during serialization."""
    ei = ExternImport(module_path="   ", alias=None, rules=["ARule"])
    with pytest.raises(SerializationError, match="module_path must not be empty"):
        serialize_node(ei)


def test_serialize_extern_import_whitespace_alias_raises() -> None:
    """ExternImport.alias of '   ' raises during serialization."""
    ei = ExternImport(module_path="my_mod", alias="   ", rules=["ARule"])
    with pytest.raises(SerializationError, match="alias must not be empty"):
        serialize_node(ei)


def test_serialize_extern_import_whitespace_rule_name_raises() -> None:
    """ExternImport.rules containing '   ' raises during serialization."""
    ei = ExternImport(module_path="my_mod", alias=None, rules=["   "])
    with pytest.raises(SerializationError, match="non-empty"):
        serialize_node(ei)


# ---------------------------------------------------------------------------
# Lines 1853->1855, 1855->1857: serialize_pragma ENDIF condition branches
# ---------------------------------------------------------------------------


def test_serialize_pragma_endif_no_condition_omits_field() -> None:
    """ENDIF pragma without a condition omits the condition field."""
    p = ConditionalDirective(PragmaType.ENDIF, condition=None)
    data = serialize_pragma(p)
    assert "condition" not in data


def test_serialize_pragma_endif_with_condition_includes_field() -> None:
    """ENDIF pragma with a non-None condition includes it in serialized output."""
    p = ConditionalDirective(PragmaType.ENDIF, condition="SOME_FLAG")
    data = serialize_pragma(p)
    assert data.get("condition") == "SOME_FLAG"


# ---------------------------------------------------------------------------
# Lines 1913-1914: HexString is_anonymous = True flag
# ---------------------------------------------------------------------------


def test_serialize_hex_string_anonymous_true_flag_in_output() -> None:
    """Anonymous HexString has is_anonymous=True in its serialized dict."""
    hs = HexString(
        identifier="$a",
        tokens=[HexByte(0x11)],
        modifiers=[],
        is_anonymous=True,
    )
    data = serialize_string(hs)
    assert data.get("is_anonymous") is True


# ---------------------------------------------------------------------------
# Line 1963: serialize_string fallback for non-StringDef non-ASTNode
# ---------------------------------------------------------------------------


def test_serialize_string_fallback_for_non_ast_non_string_def() -> None:
    """serialize_string fallback for an object that is not an ASTNode."""

    result = serialize_string(object())
    assert result["type"] == "StringDefinition"
    assert "data" in result


# ---------------------------------------------------------------------------
# Lines 2048-2049, 2052-2053: ExternImport whitespace paths (deserialize)
# ---------------------------------------------------------------------------


def test_deserialize_extern_import_whitespace_module_path_raises() -> None:
    """Deserializing ExternImport with whitespace module_path raises."""
    data = {"type": "ExternImport", "module_path": "   ", "alias": None, "rules": ["X"]}
    with pytest.raises(SerializationError, match="module_path must not be empty"):
        deserialize_node(data)


def test_deserialize_extern_import_whitespace_alias_raises() -> None:
    """Deserializing ExternImport with whitespace alias raises."""
    data = {"type": "ExternImport", "module_path": "m", "alias": "   ", "rules": ["X"]}
    with pytest.raises(SerializationError, match="alias must not be empty"):
        deserialize_node(data)


# ---------------------------------------------------------------------------
# Lines 2143->2145, 2152->2154: StringOffset/Length with index branch
# ---------------------------------------------------------------------------


def test_deserialize_string_offset_with_index_applies_validation() -> None:
    """StringOffset with a non-None index goes through index validation."""
    data = {
        "type": "StringOffset",
        "string_id": "$s",
        "index": {"type": "IntegerLiteral", "value": 0},
    }
    result = deserialize_node(data)
    assert isinstance(result, StringOffset)
    assert isinstance(result.index, IntegerLiteral)
    assert result.index.value == 0


def test_deserialize_string_length_with_index_applies_validation() -> None:
    """StringLength with a non-None index goes through index validation."""
    data = {
        "type": "StringLength",
        "string_id": "$s",
        "index": {"type": "IntegerLiteral", "value": 0},
    }
    result = deserialize_node(data)
    assert isinstance(result, StringLength)
    assert isinstance(result.index, IntegerLiteral)
    assert result.index.value == 0


# ---------------------------------------------------------------------------
# Line 2269: InExpression — subject is an int (neither str nor dict)
# ---------------------------------------------------------------------------


def test_deserialize_in_expression_integer_subject_raises() -> None:
    """InExpression with an integer subject raises SerializationError."""
    data = {
        "type": "InExpression",
        "subject": 99,
        "range": {
            "type": "RangeExpression",
            "low": {"type": "IntegerLiteral", "value": 0},
            "high": {"type": "IntegerLiteral", "value": 10},
        },
    }
    with pytest.raises(SerializationError, match="subject must be a string or expression"):
        deserialize_node(data)


# ---------------------------------------------------------------------------
# Line 2630: unknown rule modifier string preserved
# ---------------------------------------------------------------------------


def test_deserialize_rule_with_unknown_modifier_preserves_it() -> None:
    """An unrecognised modifier in Rule modifiers is preserved as-is."""
    data = _simple_rule_data(modifiers=["my_custom_modifier"])
    result = deserialize_rule(data)
    assert "my_custom_modifier" in result.modifiers


# ---------------------------------------------------------------------------
# Line 2662: ExternRule with unknown modifier
# ---------------------------------------------------------------------------


def test_deserialize_extern_rule_unknown_modifier_preserved() -> None:
    """An unrecognised ExternRule modifier is preserved as-is."""
    data = {"type": "ExternRule", "name": "rule_x", "modifiers": ["exotic"], "namespace": None}
    result = deserialize_node(data)
    assert isinstance(result, ExternRule)
    modifier_strings = [str(m) for m in result.modifiers]
    assert "exotic" in modifier_strings


# ---------------------------------------------------------------------------
# Lines 2703->2705: ENDIF with condition — deserialization path
# ---------------------------------------------------------------------------


def test_deserialize_pragma_endif_with_explicit_condition_field() -> None:
    """ENDIF pragma with a condition field in data deserializes correctly."""
    data = {
        "type": "Pragma",
        "pragma_type": "endif",
        "name": "endif",
        "arguments": [],
        "scope": "file",
        "condition": "MY_FLAG",
    }
    result = deserialize_pragma(data)
    assert isinstance(result, ConditionalDirective)
    assert getattr(result, "condition", None) == "MY_FLAG"


# ---------------------------------------------------------------------------
# Line 2718: deserialize_pragma else branch (generic Pragma fallback)
# ---------------------------------------------------------------------------


def test_deserialize_pragma_include_once_uses_else_branch() -> None:
    """include_once pragma falls into the IncludeOncePragma branch."""
    data = {
        "type": "Pragma",
        "pragma_type": "include_once",
        "name": "include_once",
        "arguments": [],
        "scope": "file",
    }
    result = deserialize_pragma(data)
    assert isinstance(result, IncludeOncePragma)


# ---------------------------------------------------------------------------
# Line 186: _validate_hex_nibble_value — single hex-char string return
# ---------------------------------------------------------------------------


def test_validate_hex_nibble_value_accepts_single_hex_char() -> None:
    """A single valid hex character is accepted and returned as-is."""
    assert _validate_hex_nibble_value("a") == "a"
    assert _validate_hex_nibble_value("F") == "F"
    assert _validate_hex_nibble_value("0") == "0"


# ---------------------------------------------------------------------------
# Line 354: _coerce_serialized_hex_alternative_branch — non-list alternative
# (deserialization path: a single hex-token dict instead of a nested list)
# ---------------------------------------------------------------------------


def test_deserialize_hex_alternative_with_dict_branch() -> None:
    """A HexAlternative with a flat dict branch (not a nested list) is coerced."""
    data = {
        "type": "HexAlternative",
        "alternatives": [{"type": "HexByte", "value": 255}],
    }
    result = deserialize_node(data)
    assert isinstance(result, HexAlternative)
    assert result.alternatives[0][0].value == 255


# ---------------------------------------------------------------------------
# Lines 422-423: _deserialize_nullable_nonempty_string_field — empty string
# Reached via ENDIF pragma with condition=""
# ---------------------------------------------------------------------------


def test_deserialize_pragma_endif_rejects_empty_condition_string() -> None:
    """ENDIF pragma with condition='' triggers the nullable-nonempty check."""
    from yaraast.serialization.simple_roundtrip_helpers import serialize_pragma

    valid_endif = ConditionalDirective(PragmaType.ENDIF, condition=None)
    data = serialize_pragma(valid_endif)
    data["condition"] = ""
    with pytest.raises(SerializationError, match="must not be empty"):
        deserialize_pragma(data)


# ---------------------------------------------------------------------------
# Lines 850-851: _deserialize_modifier — valid string modifier (name/value=None)
# ---------------------------------------------------------------------------


def test_deserialize_modifier_valid_string_returns_modifier() -> None:
    """A valid non-empty string modifier returns a StringModifier."""
    result = _deserialize_modifier("nocase")
    assert result is not None
    result_str = str(result)
    assert "nocase" in result_str


# ---------------------------------------------------------------------------
# Line 862: _deserialize_modifier — non-dict modifier returns directly
# (hit when modifier is a string and StringModifier.from_name_value succeeds)
# ---------------------------------------------------------------------------


def test_deserialize_modifier_wide_string_returns_string_modifier() -> None:
    """'wide' string modifier returns the deserialized StringModifier directly (not a dict)."""
    result = _deserialize_modifier("wide")
    assert "wide" in str(result)


# ---------------------------------------------------------------------------
# Line 910: _serialize_string_set — string value returns directly
# ---------------------------------------------------------------------------


def test_serialize_string_set_accepts_string_ref() -> None:
    """A plain string reference like '$a' is returned directly."""
    result = _serialize_string_set("$a", "OfExpression")
    assert result == "$a"


# ---------------------------------------------------------------------------
# Lines 1913-1914: serialize_string — HexString with non-list tokens
# ---------------------------------------------------------------------------


def test_serialize_hex_string_with_non_list_tokens_raises() -> None:
    """HexString with tokens that is not a list or tuple raises."""
    hs = HexString(identifier="$h", tokens=[HexByte(0xAB)], modifiers=[], is_anonymous=False)
    object.__setattr__(hs, "tokens", "bad_tokens")  # intentionally wrong type
    with pytest.raises(SerializationError, match="tokens must be a list"):
        serialize_string(hs)


# ---------------------------------------------------------------------------
# Line 2143->2145: StringOffset with index=None (the False branch)
# ---------------------------------------------------------------------------


def test_deserialize_string_offset_with_null_index() -> None:
    """StringOffset with explicit index=null takes the False branch at line 2143."""
    data = {"type": "StringOffset", "string_id": "$a", "index": None}
    result = deserialize_node(data)
    assert isinstance(result, StringOffset)
    assert result.index is None


# ---------------------------------------------------------------------------
# Line 2152->2154: StringLength with index=None (the False branch)
# ---------------------------------------------------------------------------


def test_deserialize_string_length_with_null_index() -> None:
    """StringLength with explicit index=null takes the False branch at line 2152."""
    data = {"type": "StringLength", "string_id": "$b", "index": None}
    result = deserialize_node(data)
    assert isinstance(result, StringLength)
    assert result.index is None


# ---------------------------------------------------------------------------
# Line 2269: InExpression — string_id fallback when subject is absent
# ---------------------------------------------------------------------------


def test_deserialize_in_expression_uses_string_id_when_subject_absent() -> None:
    """InExpression falls back to 'string_id' key when 'subject' is not in data."""
    data = {
        "type": "InExpression",
        "string_id": "$a",
        "range": {
            "type": "RangeExpression",
            "low": {"type": "IntegerLiteral", "value": 0},
            "high": {"type": "IntegerLiteral", "value": 100},
        },
    }
    from yaraast.ast.conditions import InExpression

    result = deserialize_node(data)
    assert isinstance(result, InExpression)
    assert result.subject == "$a"


# ---------------------------------------------------------------------------
# Line 2630: _deserialize_rule_modifiers — non-string modifier (else branch)
# ---------------------------------------------------------------------------


def test_deserialize_rule_modifiers_preserves_non_string_element() -> None:
    """Non-string element in modifiers list is passed through via the else branch."""
    raw: list[Any] = [{"name": "private"}]
    result = _deserialize_rule_modifiers(raw, "Rule")
    assert result == [{"name": "private"}]


# ---------------------------------------------------------------------------
# Line 2662: _deserialize_in_rule_pragma_position — no 'position' key
# ---------------------------------------------------------------------------


def test_deserialize_in_rule_pragma_without_position_defaults_to_before_strings() -> None:
    """InRulePragma without a position field defaults to 'before_strings'."""
    pragma_data = {
        "type": "Pragma",
        "pragma_type": "pragma",
        "name": "vendor",
        "arguments": [],
        "scope": "file",
    }
    data = {"type": "InRulePragma", "pragma": pragma_data}
    result = deserialize_node(data)
    assert isinstance(result, InRulePragma)
    assert result.position == "before_strings"


# ---------------------------------------------------------------------------
# Line 2703->2705: ENDIF pragma with a non-None condition validates the
#                  identifier text (branch taken when condition is not None).
#
# Also: the False branch of 2703 (skipping 2704 directly to 2705) is reached
# when pragma_type is IFDEF or IFNDEF (not ENDIF), because the left side of
# the AND is False.
# ---------------------------------------------------------------------------


def test_deserialize_pragma_endif_with_valid_condition_validates_identifier() -> None:
    """ENDIF with a non-None condition runs _validate_yara_identifier_text."""
    from yaraast.serialization.simple_roundtrip_helpers import serialize_pragma

    valid_endif = ConditionalDirective(PragmaType.ENDIF, condition=None)
    data = serialize_pragma(valid_endif)
    data["condition"] = "MY_FLAG"
    result = deserialize_pragma(data)
    assert isinstance(result, ConditionalDirective)
    assert getattr(result, "condition", None) == "MY_FLAG"


def test_deserialize_pragma_ifdef_skips_endif_condition_validation() -> None:
    """IFDEF pragma reaches line 2703 with False condition, jumping directly to 2705."""
    data = {
        "type": "Pragma",
        "pragma_type": "ifdef",
        "name": "ifdef",
        "arguments": [],
        "scope": "file",
        "condition": "MY_FLAG",
    }
    result = deserialize_pragma(data)
    assert isinstance(result, ConditionalDirective)


# ---------------------------------------------------------------------------
# Line 2718: deserialize_pragma — generic Pragma else branch
# Triggered by PragmaType.PRAGMA (the 'pragma' type value)
# ---------------------------------------------------------------------------


def test_deserialize_pragma_generic_pragma_type_uses_else_branch() -> None:
    """PragmaType.PRAGMA hits the else branch and creates a generic Pragma node."""
    data = {
        "type": "Pragma",
        "pragma_type": "pragma",
        "name": "vendor",
        "arguments": [],
        "scope": "file",
    }
    result = deserialize_pragma(data)
    assert isinstance(result, Pragma)
    assert not isinstance(
        result, (ConditionalDirective, IncludeOncePragma, DefineDirective, UndefDirective)
    )


# ---------------------------------------------------------------------------
# Line 612: _serialize_pragma_parameter_value — finite float returns value
# ---------------------------------------------------------------------------


def test_serialize_pragma_parameter_value_accepts_finite_float() -> None:
    """A finite float is a valid pragma parameter value and is returned as-is."""
    result = _serialize_pragma_parameter_value(3.14)
    assert result == 3.14


# ---------------------------------------------------------------------------
# Line 2663: _deserialize_in_rule_pragma_position — with 'position' key
# ---------------------------------------------------------------------------


def test_deserialize_in_rule_pragma_with_explicit_position_field() -> None:
    """InRulePragma with an explicit position field uses the field value."""
    pragma_data = {
        "type": "Pragma",
        "pragma_type": "pragma",
        "name": "vendor",
        "arguments": [],
        "scope": "file",
    }
    data = {
        "type": "InRulePragma",
        "pragma": pragma_data,
        "position": "after_strings",
    }
    result = deserialize_node(data)
    assert isinstance(result, InRulePragma)
    assert result.position == "after_strings"


# ---------------------------------------------------------------------------
# Lines 372-373: _serialize_plain_string_raw_bytes — non-bytes, non-None value
# ---------------------------------------------------------------------------


def test_serialize_plain_string_raw_bytes_rejects_non_bytes_value() -> None:
    """PlainString with raw_bytes set to a non-bytes value raises."""
    ps = PlainString(identifier="$s", value="hello", modifiers=[], is_anonymous=False)
    object.__setattr__(ps, "raw_bytes", "not_bytes")  # intentionally wrong type
    with pytest.raises(SerializationError, match="raw_bytes must be bytes or None"):
        serialize_string(ps)


# ---------------------------------------------------------------------------
# Lines 359-361: _serialize_plain_string_value — bytes path (base64 encoding)
# ---------------------------------------------------------------------------


def test_serialize_plain_string_with_bytes_value() -> None:
    """PlainString with a bytes value is base64-encoded."""
    ps = PlainString(identifier="$s", value=b"hello", modifiers=[], is_anonymous=False)
    data = serialize_string(ps)
    assert data["value_encoding"] == "base64"
    import base64

    assert base64.b64decode(data["value"]) == b"hello"


# ---------------------------------------------------------------------------
# Lines 771-774: _serialize_modifiers — XOR modifier with string value
# that fails _validate_xor_modifier_value
# ---------------------------------------------------------------------------


def test_serialize_xor_modifier_with_invalid_string_value_raises() -> None:
    """XOR modifier with a string value that is not a valid xor spec raises."""
    from yaraast.ast.modifiers import StringModifier, StringModifierType

    xor_mod = StringModifier(StringModifierType.XOR, value=None)
    object.__setattr__(xor_mod, "value", "bad_xor")  # invalid string XOR value
    ps = PlainString(identifier="$s", value="test", modifiers=[xor_mod], is_anonymous=False)
    with pytest.raises(SerializationError, match="xor value must be a byte"):
        serialize_string(ps)


# ---------------------------------------------------------------------------
# Line 1903: serialize_string — PlainString that IS anonymous
# ---------------------------------------------------------------------------


def test_serialize_plain_string_anonymous_sets_is_anonymous_flag() -> None:
    """An anonymous PlainString includes is_anonymous=True in the serialized dict."""
    ps = PlainString(identifier="$", value="hi", modifiers=[], is_anonymous=True)
    data = serialize_string(ps)
    assert data.get("is_anonymous") is True


# ---------------------------------------------------------------------------
# Line 1946: serialize_string — anonymous RegexString sets is_anonymous flag
# (line 1946 is inside the RegexString branch, not HexString)
# ---------------------------------------------------------------------------


def test_serialize_regex_string_anonymous_sets_is_anonymous_flag() -> None:
    """An anonymous RegexString includes is_anonymous=True in the serialized dict."""
    rs = RegexString(identifier="$", regex="foo", modifiers=[], is_anonymous=True)
    data = serialize_string(rs)
    assert data.get("is_anonymous") is True
