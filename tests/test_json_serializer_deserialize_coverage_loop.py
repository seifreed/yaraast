# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.strings import HexByte, HexJump
from yaraast.errors import SerializationError
from yaraast.serialization.json_serializer import JsonSerializer
from yaraast.serialization.json_serializer_deserialize import (
    _apply_node_metadata,
    _cast_comment,
    _cast_leading_comment,
    _deser_array_access,
    _deser_array_comprehension,
    _deser_at_expression,
    _deser_binary_expression,
    _deser_boolean_literal,
    _deser_defined_expression,
    _deser_dict_comprehension,
    _deser_dict_expression,
    _deser_dict_item,
    _deser_dictionary_access,
    _deser_double_literal,
    _deser_extern_rule_reference,
    _deser_for_expression,
    _deser_for_of_expression,
    _deser_function_call,
    _deser_identifier,
    _deser_in_expression,
    _deser_integer_literal,
    _deser_lambda_expression,
    _deser_list_expression,
    _deser_match_case,
    _deser_member_access,
    _deser_module_reference,
    _deser_of_expression,
    _deser_parentheses_expression,
    _deser_pattern_match,
    _deser_range_expression,
    _deser_regex_literal,
    _deser_set_expression,
    _deser_slice_expression,
    _deser_spread_operator,
    _deser_string_count,
    _deser_string_identifier,
    _deser_string_length,
    _deser_string_literal,
    _deser_string_offset,
    _deser_string_operator_expression,
    _deser_string_wildcard,
    _deser_tuple_expression,
    _deser_tuple_indexing,
    _deser_unary_expression,
    _deser_with_declaration,
    _deser_with_statement,
    _deserialize_ast_value,
    _deserialize_comment_node,
    _deserialize_dictionary_key,
    _deserialize_hex_byte_value,
    _deserialize_hex_jump_bound,
    _deserialize_hex_jump_bounds,
    _deserialize_hex_negated_value,
    _deserialize_hex_nibble_high,
    _deserialize_hex_nibble_value,
    _deserialize_nonempty_string_field,
    _deserialize_nonempty_string_list_field,
    _deserialize_nullable_nonempty_string_field,
    _deserialize_optional_expression,
    _deserialize_pragma_node_type,
    _deserialize_pragma_scope,
    _deserialize_pragma_type,
    _deserialize_required_expression_value,
    _deserialize_required_nullable_nonempty_string_field,
    _deserialize_required_nullable_string_field,
    _deserialize_required_quantifier,
    _deserialize_required_string_list_field,
    _deserialize_required_string_set,
    _deserialize_string_modifiers,
    _deserialize_string_set_item,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

INT_LIT = {"type": "IntegerLiteral", "value": 1}
BOOL_LIT_TRUE = {"type": "BooleanLiteral", "value": True}
RANGE_EXPR = {
    "type": "RangeExpression",
    "low": {"type": "IntegerLiteral", "value": 0},
    "high": {"type": "IntegerLiteral", "value": 100},
}


def _s() -> JsonSerializer:
    return JsonSerializer()


# ---------------------------------------------------------------------------
# _deserialize_ast_value
# ---------------------------------------------------------------------------


def test_ast_value_list_of_scalars() -> None:
    result = _deserialize_ast_value(_s(), [42, "hello"])
    assert result == [42, "hello"]


def test_ast_value_list_of_expressions() -> None:
    s = _s()
    result = _deserialize_ast_value(s, [INT_LIT])
    assert len(result) == 1


def test_ast_value_list_with_none_raises() -> None:
    with pytest.raises(SerializationError, match="must contain values"):
        _deserialize_ast_value(_s(), [None])


def test_ast_value_list_with_empty_dict_raises() -> None:
    with pytest.raises(SerializationError, match="must contain values"):
        _deserialize_ast_value(_s(), [{}])


# ---------------------------------------------------------------------------
# _deserialize_optional_expression
# ---------------------------------------------------------------------------


def test_optional_expression_none_returns_none() -> None:
    result = _deserialize_optional_expression(_s(), None, "ctx")
    assert result is None


def test_optional_expression_valid_expression() -> None:
    result = _deserialize_optional_expression(_s(), INT_LIT, "ctx")
    assert result is not None


def test_optional_expression_unresolvable_raises() -> None:
    with pytest.raises(SerializationError, match="Unknown expression type"):
        _deserialize_optional_expression(_s(), {"type": "XUnknownType"}, "ctx")


# ---------------------------------------------------------------------------
# _deserialize_required_expression_value
# ---------------------------------------------------------------------------


def test_required_expression_value_valid() -> None:
    result = _deserialize_required_expression_value(_s(), INT_LIT, "ctx")
    assert result is not None


def test_required_expression_value_none_raises() -> None:
    with pytest.raises(SerializationError, match="Unknown expression type"):
        _deserialize_required_expression_value(_s(), {"type": "XUnknownType"}, "ctx")


# ---------------------------------------------------------------------------
# _deserialize_required_quantifier
# ---------------------------------------------------------------------------


def test_required_quantifier_bool_raises() -> None:
    with pytest.raises(SerializationError, match="must be a string, number, or expression"):
        _deserialize_required_quantifier(
            _s(), {"quantifier": True}, "quantifier", "ctx", allow_percentage=False
        )


def test_required_quantifier_list_raises() -> None:
    with pytest.raises(SerializationError, match="must be a string, number, or expression"):
        _deserialize_required_quantifier(
            _s(), {"quantifier": [1, 2]}, "quantifier", "ctx", allow_percentage=False
        )


def test_required_quantifier_empty_string_raises() -> None:
    with pytest.raises(SerializationError, match="must not be empty"):
        _deserialize_required_quantifier(
            _s(), {"quantifier": ""}, "quantifier", "ctx", allow_percentage=False
        )


def test_required_quantifier_inf_raises() -> None:
    import math

    with pytest.raises(SerializationError, match="must be finite"):
        _deserialize_required_quantifier(
            _s(), {"quantifier": math.inf}, "quantifier", "ctx", allow_percentage=False
        )


def test_required_quantifier_string_all() -> None:
    result = _deserialize_required_quantifier(
        _s(), {"quantifier": "all"}, "quantifier", "ctx", allow_percentage=False
    )
    assert result == "all"


# ---------------------------------------------------------------------------
# _deserialize_string_set_item
# ---------------------------------------------------------------------------


def test_string_set_item_none_raises() -> None:
    with pytest.raises(SerializationError, match="must contain values"):
        _deserialize_string_set_item(_s(), None, "ctx")


def test_string_set_item_empty_dict_raises() -> None:
    with pytest.raises(SerializationError, match="must contain values"):
        _deserialize_string_set_item(_s(), {}, "ctx")


def test_string_set_item_empty_string_raises() -> None:
    with pytest.raises(SerializationError, match="must contain values"):
        _deserialize_string_set_item(_s(), "  ", "ctx")


def test_string_set_item_nonempty_string() -> None:
    result = _deserialize_string_set_item(_s(), "$a", "ctx")
    assert result == "$a"


def test_string_set_item_dict_expression() -> None:
    result = _deserialize_string_set_item(_s(), INT_LIT, "ctx")
    assert result is not None


def test_string_set_item_invalid_dict_raises() -> None:
    # A dict with unknown expression type propagates the SerializationError
    with pytest.raises(SerializationError):
        _deserialize_string_set_item(_s(), {"not_a_type_key": "bad"}, "ctx")


# ---------------------------------------------------------------------------
# _deserialize_required_string_set
# ---------------------------------------------------------------------------


def test_required_string_set_none_raises() -> None:
    with pytest.raises(SerializationError, match="is required"):
        _deserialize_required_string_set(_s(), {"string_set": None}, "string_set", "ctx")


def test_required_string_set_empty_dict_raises() -> None:
    with pytest.raises(SerializationError, match="is required"):
        _deserialize_required_string_set(_s(), {"string_set": {}}, "string_set", "ctx")


def test_required_string_set_empty_string_raises() -> None:
    with pytest.raises(SerializationError, match="must contain values"):
        _deserialize_required_string_set(_s(), {"string_set": "  "}, "string_set", "ctx")


def test_required_string_set_nonempty_string() -> None:
    result = _deserialize_required_string_set(_s(), {"string_set": "them"}, "string_set", "ctx")
    assert result == "them"


def test_required_string_set_dict_expression() -> None:
    result = _deserialize_required_string_set(_s(), {"string_set": INT_LIT}, "string_set", "ctx")
    assert result is not None


def test_required_string_set_empty_list_raises() -> None:
    with pytest.raises(SerializationError, match="must contain values"):
        _deserialize_required_string_set(_s(), {"string_set": []}, "string_set", "ctx")


def test_required_string_set_list_of_strings() -> None:
    result = _deserialize_required_string_set(
        _s(), {"string_set": ["$a", "$b"]}, "string_set", "ctx"
    )
    assert result == ["$a", "$b"]


# ---------------------------------------------------------------------------
# _deserialize_dictionary_key
# ---------------------------------------------------------------------------


def test_dictionary_key_missing_raises() -> None:
    with pytest.raises(SerializationError, match="must be a string or expression"):
        _deserialize_dictionary_key(_s(), {})


def test_dictionary_key_empty_string_raises() -> None:
    with pytest.raises(SerializationError, match="must not be empty"):
        _deserialize_dictionary_key(_s(), {"key": "  "})


def test_dictionary_key_valid_string() -> None:
    result = _deserialize_dictionary_key(_s(), {"key": "mykey"})
    assert result == "mykey"


def test_dictionary_key_dict_expression() -> None:
    result = _deserialize_dictionary_key(_s(), {"key": INT_LIT})
    assert result is not None


def test_dictionary_key_invalid_dict_raises() -> None:
    # Empty dict makes _deserialize_expression return None, triggering fall-through error
    with pytest.raises(SerializationError, match="must be a string or expression"):
        _deserialize_dictionary_key(_s(), {"key": {}})


# ---------------------------------------------------------------------------
# _deserialize_comment_node
# ---------------------------------------------------------------------------


def test_comment_node_comment_type() -> None:
    s = _s()
    result = _deserialize_comment_node(s, {"type": "Comment", "text": "hello", "multiline": False})
    assert isinstance(result, Comment)


def test_comment_node_comment_group_type() -> None:
    s = _s()
    result = _deserialize_comment_node(
        s,
        {
            "type": "CommentGroup",
            "comments": [{"type": "Comment", "text": "line1", "multiline": False}],
        },
    )
    assert isinstance(result, CommentGroup)


def test_comment_node_unknown_type_raises() -> None:
    with pytest.raises(SerializationError, match="Unknown comment metadata type"):
        _deserialize_comment_node(_s(), {"type": "WeirdType"})


# ---------------------------------------------------------------------------
# _deserialize_nonempty_string_field
# ---------------------------------------------------------------------------


def test_nonempty_string_field_empty_raises() -> None:
    with pytest.raises(SerializationError, match="must not be empty"):
        _deserialize_nonempty_string_field({"name": ""}, "name", "ctx")


# ---------------------------------------------------------------------------
# _deserialize_nullable_nonempty_string_field
# ---------------------------------------------------------------------------


def test_nullable_nonempty_string_field_none_ok() -> None:
    result = _deserialize_nullable_nonempty_string_field({"alias": None}, "alias", "ctx")
    assert result is None


def test_nullable_nonempty_string_field_empty_raises() -> None:
    with pytest.raises(SerializationError, match="must not be empty"):
        _deserialize_nullable_nonempty_string_field({"alias": ""}, "alias", "ctx")


# ---------------------------------------------------------------------------
# _deserialize_required_nullable_string_field
# ---------------------------------------------------------------------------


def test_required_nullable_string_field_none_ok() -> None:
    result = _deserialize_required_nullable_string_field({"val": None}, "val", "ctx")
    assert result is None


def test_required_nullable_string_field_string_ok() -> None:
    result = _deserialize_required_nullable_string_field({"val": "hello"}, "val", "ctx")
    assert result == "hello"


def test_required_nullable_string_field_non_string_raises() -> None:
    with pytest.raises(SerializationError, match="must be a string"):
        _deserialize_required_nullable_string_field({"val": 42}, "val", "ctx")


# ---------------------------------------------------------------------------
# _deserialize_required_nullable_nonempty_string_field
# ---------------------------------------------------------------------------


def test_required_nullable_nonempty_string_none_ok() -> None:
    result = _deserialize_required_nullable_nonempty_string_field({"f": None}, "f", "ctx")
    assert result is None


def test_required_nullable_nonempty_string_non_string_raises() -> None:
    with pytest.raises(SerializationError, match="must be a string"):
        _deserialize_required_nullable_nonempty_string_field({"f": 99}, "f", "ctx")


def test_required_nullable_nonempty_string_empty_raises() -> None:
    with pytest.raises(SerializationError, match="must not be empty"):
        _deserialize_required_nullable_nonempty_string_field({"f": ""}, "f", "ctx")


# ---------------------------------------------------------------------------
# _deserialize_nonempty_string_list_field
# ---------------------------------------------------------------------------


def test_nonempty_string_list_field_empty_item_raises() -> None:
    with pytest.raises(SerializationError, match="must contain non-empty strings"):
        _deserialize_nonempty_string_list_field({"mods": [""]}, "mods", "ctx")


# ---------------------------------------------------------------------------
# _deserialize_pragma_type
# ---------------------------------------------------------------------------


def test_pragma_type_valid() -> None:
    from yaraast.ast.pragmas import PragmaType

    result = _deserialize_pragma_type({"pragma_type": "define"})
    assert result == PragmaType.DEFINE


def test_pragma_type_invalid_raises() -> None:
    with pytest.raises(SerializationError, match="valid pragma type"):
        _deserialize_pragma_type({"pragma_type": "not_a_valid_type"})


# ---------------------------------------------------------------------------
# _deserialize_required_string_list_field
# ---------------------------------------------------------------------------


def test_required_string_list_field_delegation() -> None:
    result = _deserialize_required_string_list_field({"args": ["a", "b"]}, "args", "ctx")
    assert result == ["a", "b"]


# ---------------------------------------------------------------------------
# _deserialize_pragma_node_type
# ---------------------------------------------------------------------------


def test_pragma_node_type_valid() -> None:
    _deserialize_pragma_node_type({"type": "Pragma"})


def test_pragma_node_type_invalid_raises() -> None:
    with pytest.raises(SerializationError, match="type must be Pragma"):
        _deserialize_pragma_node_type({"type": "NotPragma"})


# ---------------------------------------------------------------------------
# _deserialize_pragma_scope
# ---------------------------------------------------------------------------


def test_pragma_scope_none_returns_file() -> None:
    from yaraast.ast.pragmas import PragmaScope

    result = _deserialize_pragma_scope(None, "ctx")
    assert result == PragmaScope.FILE


def test_pragma_scope_valid_string() -> None:
    from yaraast.ast.pragmas import PragmaScope

    result = _deserialize_pragma_scope("rule", "ctx")
    assert result == PragmaScope.RULE


# ---------------------------------------------------------------------------
# _deserialize_hex_byte_value
# ---------------------------------------------------------------------------


def test_hex_byte_value_integer_ok() -> None:
    result = _deserialize_hex_byte_value({"value": 0xAB}, "ctx")
    assert result == 0xAB


def test_hex_byte_value_string_ok() -> None:
    result = _deserialize_hex_byte_value({"value": "AB"}, "ctx")
    assert result == "AB"


def test_hex_byte_value_invalid_raises() -> None:
    with pytest.raises(SerializationError, match="must be a byte"):
        _deserialize_hex_byte_value({"value": "ZZ"}, "ctx")


def test_hex_byte_value_bool_raises() -> None:
    with pytest.raises(SerializationError, match="must be a byte"):
        _deserialize_hex_byte_value({"value": True}, "ctx")


# ---------------------------------------------------------------------------
# _deserialize_hex_negated_value
# ---------------------------------------------------------------------------


def test_hex_negated_value_integer_ok() -> None:
    result = _deserialize_hex_negated_value({"value": 0x0F})
    assert result == 0x0F


def test_hex_negated_value_two_char_string_ok() -> None:
    result = _deserialize_hex_negated_value({"value": "FF"})
    assert result == "FF"


def test_hex_negated_value_negated_nibble_ok() -> None:
    result = _deserialize_hex_negated_value({"value": "?A"})
    assert result == "?A"


def test_hex_negated_value_invalid_raises() -> None:
    with pytest.raises(SerializationError, match="must be a byte or negated nibble"):
        _deserialize_hex_negated_value({"value": "ZZZ"})


# ---------------------------------------------------------------------------
# _deserialize_hex_nibble_value
# ---------------------------------------------------------------------------


def test_hex_nibble_value_integer_ok() -> None:
    result = _deserialize_hex_nibble_value({"value": 5})
    assert result == 5


def test_hex_nibble_value_single_char_ok() -> None:
    result = _deserialize_hex_nibble_value({"value": "A"})
    assert result == "A"


def test_hex_nibble_value_invalid_raises() -> None:
    with pytest.raises(SerializationError, match="must be a nibble"):
        _deserialize_hex_nibble_value({"value": "ZZ"})


# ---------------------------------------------------------------------------
# _deserialize_hex_nibble_high
# ---------------------------------------------------------------------------


def test_hex_nibble_high_bool_ok() -> None:
    result = _deserialize_hex_nibble_high({"high": True})
    assert result is True


def test_hex_nibble_high_non_bool_raises() -> None:
    with pytest.raises(SerializationError, match="must be a boolean"):
        _deserialize_hex_nibble_high({"high": 1})


# ---------------------------------------------------------------------------
# _deserialize_string_modifiers
# ---------------------------------------------------------------------------


def test_string_modifiers_non_list_raises() -> None:
    with pytest.raises(SerializationError, match="modifiers must be a list"):
        _deserialize_string_modifiers(_s(), {"modifiers": "nocase"}, "ctx")


# ---------------------------------------------------------------------------
# _deserialize_hex_jump_bound
# ---------------------------------------------------------------------------


def test_hex_jump_bound_none_returns_none() -> None:
    result = _deserialize_hex_jump_bound({}, "min_jump")
    assert result is None


def test_hex_jump_bound_valid_int() -> None:
    result = _deserialize_hex_jump_bound({"min_jump": 3}, "min_jump")
    assert result == 3


def test_hex_jump_bound_invalid_raises() -> None:
    with pytest.raises(SerializationError, match="must be a non-negative integer"):
        _deserialize_hex_jump_bound({"min_jump": "bad"}, "min_jump")


# ---------------------------------------------------------------------------
# _deserialize_hex_jump_bounds
# ---------------------------------------------------------------------------


def test_hex_jump_bounds_min_gt_max_raises() -> None:
    with pytest.raises(SerializationError, match="cannot exceed"):
        _deserialize_hex_jump_bounds({"min_jump": 10, "max_jump": 5})


def test_hex_jump_bounds_valid() -> None:
    min_v, max_v = _deserialize_hex_jump_bounds({"min_jump": 2, "max_jump": 8})
    assert min_v == 2
    assert max_v == 8


# ---------------------------------------------------------------------------
# _cast_comment
# ---------------------------------------------------------------------------


def test_cast_comment_valid() -> None:
    c = Comment(text="hi", is_multiline=False)
    assert _cast_comment(c) is c


def test_cast_comment_invalid_raises() -> None:
    with pytest.raises(SerializationError, match="must contain Comment nodes"):
        _cast_comment("not a comment")


# ---------------------------------------------------------------------------
# _cast_leading_comment
# ---------------------------------------------------------------------------


def test_cast_leading_comment_comment() -> None:
    c = Comment(text="hi", is_multiline=False)
    assert _cast_leading_comment(c) is c


def test_cast_leading_comment_group() -> None:
    cg = CommentGroup(comments=[Comment(text="x", is_multiline=False)])
    assert _cast_leading_comment(cg) is cg


def test_cast_leading_comment_invalid_raises() -> None:
    with pytest.raises(SerializationError, match="Comment or CommentGroup"):
        _cast_leading_comment("neither")


# ---------------------------------------------------------------------------
# _apply_node_metadata
# ---------------------------------------------------------------------------


def test_apply_node_metadata_with_location() -> None:
    node = BooleanLiteral(value=True)
    result = _apply_node_metadata(
        _s(), node, {"location": {"line": 1, "column": 1, "end_line": 1, "end_column": 5}}
    )
    assert result.location is not None


def test_apply_node_metadata_invalid_location_raises() -> None:
    node = BooleanLiteral(value=True)
    with pytest.raises(SerializationError, match="location must be an object"):
        _apply_node_metadata(_s(), node, {"location": "bad"})


def test_apply_node_metadata_with_leading_comments() -> None:
    node = BooleanLiteral(value=True)
    result = _apply_node_metadata(
        _s(),
        node,
        {"leading_comments": [{"type": "Comment", "text": "hi", "multiline": False}]},
    )
    assert len(result.leading_comments) == 1


def test_apply_node_metadata_leading_comments_non_list_raises() -> None:
    node = BooleanLiteral(value=True)
    with pytest.raises(SerializationError, match="must be a list"):
        _apply_node_metadata(_s(), node, {"leading_comments": "bad"})


def test_apply_node_metadata_with_trailing_comment() -> None:
    node = BooleanLiteral(value=True)
    result = _apply_node_metadata(
        _s(),
        node,
        {"trailing_comment": {"type": "Comment", "text": "trail", "multiline": False}},
    )
    assert result.trailing_comment is not None


def test_apply_node_metadata_trailing_comment_non_dict_raises() -> None:
    node = BooleanLiteral(value=True)
    with pytest.raises(SerializationError, match="must be an object"):
        _apply_node_metadata(_s(), node, {"trailing_comment": "bad"})


# ---------------------------------------------------------------------------
# _deser_binary_expression
# ---------------------------------------------------------------------------


def test_deser_binary_expression() -> None:
    s = _s()
    result = _deser_binary_expression(
        s,
        {
            "left": INT_LIT,
            "operator": "+",
            "right": INT_LIT,
        },
    )
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_unary_expression
# ---------------------------------------------------------------------------


def test_deser_unary_expression() -> None:
    s = _s()
    result = _deser_unary_expression(s, {"operator": "not", "operand": BOOL_LIT_TRUE})
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_parentheses_expression
# ---------------------------------------------------------------------------


def test_deser_parentheses_expression() -> None:
    s = _s()
    result = _deser_parentheses_expression(s, {"expression": INT_LIT})
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_set_expression
# ---------------------------------------------------------------------------


def test_deser_set_expression_valid() -> None:
    s = _s()
    result = _deser_set_expression(s, {"elements": [INT_LIT]})
    assert result is not None


def test_deser_set_expression_non_list_raises() -> None:
    with pytest.raises(SerializationError, match="must be a list"):
        _deser_set_expression(_s(), {"elements": "bad"})


def test_deser_set_expression_none_element_raises() -> None:
    with pytest.raises(SerializationError, match="must contain expressions"):
        _deser_set_expression(_s(), {"elements": [None]})


# ---------------------------------------------------------------------------
# _deser_range_expression
# ---------------------------------------------------------------------------


def test_deser_range_expression() -> None:
    s = _s()
    result = _deser_range_expression(
        s, {"low": INT_LIT, "high": {"type": "IntegerLiteral", "value": 100}}
    )
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_function_call
# ---------------------------------------------------------------------------


def test_deser_function_call_valid() -> None:
    s = _s()
    result = _deser_function_call(
        s, {"function": "my_func", "arguments": [INT_LIT], "receiver": None}
    )
    assert result is not None


def test_deser_function_call_non_list_args_raises() -> None:
    with pytest.raises(SerializationError, match="must be a list"):
        _deser_function_call(_s(), {"function": "f", "arguments": "bad", "receiver": None})


def test_deser_function_call_none_arg_raises() -> None:
    with pytest.raises(SerializationError, match="must contain expressions"):
        _deser_function_call(_s(), {"function": "f", "arguments": [None], "receiver": None})


# ---------------------------------------------------------------------------
# _deser_array_access
# ---------------------------------------------------------------------------


def test_deser_array_access() -> None:
    s = _s()
    result = _deser_array_access(
        s,
        {
            "array": {"type": "ModuleReference", "module": "pe"},
            "index": INT_LIT,
        },
    )
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_member_access
# ---------------------------------------------------------------------------


def test_deser_member_access() -> None:
    s = _s()
    result = _deser_member_access(
        s,
        {
            "object": {"type": "ModuleReference", "module": "pe"},
            "member": "number_of_sections",
        },
    )
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_string_identifier
# ---------------------------------------------------------------------------


def test_deser_string_identifier() -> None:
    s = _s()
    result = _deser_string_identifier(s, {"name": "$a"})
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_string_wildcard
# ---------------------------------------------------------------------------


def test_deser_string_wildcard() -> None:
    s = _s()
    result = _deser_string_wildcard(s, {"pattern": "$a*"})
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_string_count
# ---------------------------------------------------------------------------


def test_deser_string_count() -> None:
    s = _s()
    result = _deser_string_count(s, {"string_id": "$a"})
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_string_offset
# ---------------------------------------------------------------------------


def test_deser_string_offset_no_index() -> None:
    s = _s()
    result = _deser_string_offset(s, {"string_id": "$a", "index": None})
    assert result is not None


def test_deser_string_offset_with_index() -> None:
    s = _s()
    result = _deser_string_offset(s, {"string_id": "$a", "index": INT_LIT})
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_string_length
# ---------------------------------------------------------------------------


def test_deser_string_length_no_index() -> None:
    s = _s()
    result = _deser_string_length(s, {"string_id": "$a", "index": None})
    assert result is not None


def test_deser_string_length_with_index() -> None:
    s = _s()
    result = _deser_string_length(s, {"string_id": "$a", "index": INT_LIT})
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_integer_literal
# ---------------------------------------------------------------------------


def test_deser_integer_literal() -> None:
    s = _s()
    result = _deser_integer_literal(s, {"value": 42})
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_double_literal
# ---------------------------------------------------------------------------


def test_deser_double_literal() -> None:
    s = _s()
    result = _deser_double_literal(s, {"value": 3.14})
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_string_literal
# ---------------------------------------------------------------------------


def test_deser_string_literal() -> None:
    s = _s()
    result = _deser_string_literal(s, {"value": "hello"})
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_regex_literal
# ---------------------------------------------------------------------------


def test_deser_regex_literal() -> None:
    s = _s()
    result = _deser_regex_literal(s, {"pattern": "abc.*", "modifiers": ""})
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_boolean_literal
# ---------------------------------------------------------------------------


def test_deser_boolean_literal() -> None:
    s = _s()
    result = _deser_boolean_literal(s, {"value": False})
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_for_expression
# ---------------------------------------------------------------------------


def test_deser_for_expression() -> None:
    s = _s()
    result = _deser_for_expression(
        s,
        {
            "quantifier": "all",
            "variable": "x",
            "iterable": {"type": "SetExpression", "elements": [INT_LIT]},
            "body": BOOL_LIT_TRUE,
        },
    )
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_for_of_expression
# ---------------------------------------------------------------------------


def test_deser_for_of_expression() -> None:
    s = _s()
    result = _deser_for_of_expression(
        s,
        {
            "quantifier": "any",
            "string_set": "them",
            "condition": None,
        },
    )
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_at_expression
# ---------------------------------------------------------------------------


def test_deser_at_expression_string_id() -> None:
    s = _s()
    result = _deser_at_expression(s, {"string_id": "$a", "offset": INT_LIT})
    assert result is not None


def test_deser_at_expression_dict_string_id() -> None:
    s = _s()
    result = _deser_at_expression(
        s,
        {"string_id": {"type": "StringIdentifier", "name": "$a"}, "offset": INT_LIT},
    )
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_in_expression
# ---------------------------------------------------------------------------


def test_deser_in_expression_string_subject() -> None:
    s = _s()
    result = _deser_in_expression(s, {"subject": "$a", "range": RANGE_EXPR})
    assert result is not None


def test_deser_in_expression_dict_subject() -> None:
    s = _s()
    result = _deser_in_expression(
        s, {"subject": {"type": "StringIdentifier", "name": "$a"}, "range": RANGE_EXPR}
    )
    assert result is not None


def test_deser_in_expression_string_id_fallback() -> None:
    s = _s()
    result = _deser_in_expression(s, {"string_id": "$c", "range": RANGE_EXPR})
    assert result is not None


def test_deser_in_expression_empty_subject_raises() -> None:
    with pytest.raises(SerializationError, match="must not be empty"):
        _deser_in_expression(_s(), {"subject": "  ", "range": RANGE_EXPR})


def test_deser_in_expression_invalid_subject_raises() -> None:
    with pytest.raises(SerializationError, match="must be a string or expression"):
        _deser_in_expression(_s(), {"subject": 99, "range": RANGE_EXPR})


# ---------------------------------------------------------------------------
# _deser_of_expression
# ---------------------------------------------------------------------------


def test_deser_of_expression() -> None:
    s = _s()
    result = _deser_of_expression(s, {"quantifier": "all", "string_set": "them"})
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_module_reference
# ---------------------------------------------------------------------------


def test_deser_module_reference() -> None:
    s = _s()
    result = _deser_module_reference(s, {"module": "pe"})
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_dictionary_access
# ---------------------------------------------------------------------------


def test_deser_dictionary_access() -> None:
    s = _s()
    result = _deser_dictionary_access(
        s,
        {
            "object": {"type": "ModuleReference", "module": "pe"},
            "key": "some_key",
        },
    )
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_defined_expression
# ---------------------------------------------------------------------------


def test_deser_defined_expression() -> None:
    s = _s()
    result = _deser_defined_expression(s, {"expression": BOOL_LIT_TRUE})
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_string_operator_expression
# ---------------------------------------------------------------------------


def test_deser_string_operator_expression() -> None:
    s = _s()
    result = _deser_string_operator_expression(
        s,
        {
            "left": {"type": "StringLiteral", "value": "hello"},
            "operator": "contains",
            "right": {"type": "StringLiteral", "value": "ell"},
        },
    )
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_extern_rule_reference
# ---------------------------------------------------------------------------


def test_deser_extern_rule_reference_rule_name_field() -> None:
    s = _s()
    result = _deser_extern_rule_reference(s, {"rule_name": "my_rule", "namespace": None})
    assert result is not None


def test_deser_extern_rule_reference_name_field() -> None:
    s = _s()
    result = _deser_extern_rule_reference(s, {"name": "my_rule", "namespace": None})
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_with_statement
# ---------------------------------------------------------------------------


def test_deser_with_statement() -> None:
    s = _s()
    result = _deser_with_statement(
        s,
        {
            "declarations": [
                {
                    "type": "WithDeclaration",
                    "identifier": "x",
                    "value": INT_LIT,
                }
            ],
            "body": BOOL_LIT_TRUE,
        },
    )
    assert result is not None


def test_deser_with_statement_non_list_decls_raises() -> None:
    with pytest.raises(SerializationError, match="must be a list"):
        _deser_with_statement(_s(), {"declarations": "bad", "body": BOOL_LIT_TRUE})


def test_deser_with_statement_invalid_decl_raises() -> None:
    with pytest.raises(SerializationError, match="must contain expressions"):
        _deser_with_statement(_s(), {"declarations": [None], "body": BOOL_LIT_TRUE})


# ---------------------------------------------------------------------------
# _deser_with_declaration
# ---------------------------------------------------------------------------


def test_deser_with_declaration() -> None:
    s = _s()
    result = _deser_with_declaration(s, {"identifier": "x", "value": INT_LIT})
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_array_comprehension
# ---------------------------------------------------------------------------


def test_deser_array_comprehension_with_all_fields() -> None:
    s = _s()
    result = _deser_array_comprehension(
        s,
        {
            "variable": "x",
            "expression": INT_LIT,
            "iterable": {"type": "SetExpression", "elements": [INT_LIT]},
            "condition": None,
        },
    )
    assert result is not None


def test_deser_array_comprehension_without_optional_fields() -> None:
    s = _s()
    result = _deser_array_comprehension(
        s, {"variable": "x", "expression": None, "iterable": None, "condition": None}
    )
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_dict_comprehension
# ---------------------------------------------------------------------------


def test_deser_dict_comprehension_full() -> None:
    s = _s()
    result = _deser_dict_comprehension(
        s,
        {
            "key_variable": "k",
            "value_variable": "v",
            "key_expression": INT_LIT,
            "value_expression": INT_LIT,
            "iterable": None,
            "condition": None,
        },
    )
    assert result is not None


def test_deser_dict_comprehension_no_optional_fields() -> None:
    s = _s()
    result = _deser_dict_comprehension(
        s,
        {
            "key_variable": "k",
            "value_variable": None,
            "key_expression": None,
            "value_expression": None,
            "iterable": None,
            "condition": None,
        },
    )
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_tuple_expression
# ---------------------------------------------------------------------------


def test_deser_tuple_expression() -> None:
    s = _s()
    result = _deser_tuple_expression(
        s, {"elements": [INT_LIT, {"type": "IntegerLiteral", "value": 2}]}
    )
    assert result is not None


def test_deser_tuple_expression_non_list_raises() -> None:
    with pytest.raises(SerializationError, match="must be a list"):
        _deser_tuple_expression(_s(), {"elements": "bad"})


def test_deser_tuple_expression_invalid_element_raises() -> None:
    with pytest.raises(SerializationError, match="must contain expressions"):
        _deser_tuple_expression(_s(), {"elements": [None]})


# ---------------------------------------------------------------------------
# _deser_tuple_indexing
# ---------------------------------------------------------------------------


def test_deser_tuple_indexing() -> None:
    s = _s()
    result = _deser_tuple_indexing(
        s,
        {
            "tuple_expr": {"type": "TupleExpression", "elements": [INT_LIT]},
            "index": INT_LIT,
        },
    )
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_list_expression
# ---------------------------------------------------------------------------


def test_deser_list_expression_valid() -> None:
    s = _s()
    result = _deser_list_expression(s, {"elements": [INT_LIT]})
    assert result is not None


def test_deser_list_expression_non_list_raises() -> None:
    with pytest.raises(SerializationError, match="must be a list"):
        _deser_list_expression(_s(), {"elements": "bad"})


def test_deser_list_expression_invalid_element_raises() -> None:
    with pytest.raises(SerializationError, match="must contain expressions"):
        _deser_list_expression(_s(), {"elements": [None]})


# ---------------------------------------------------------------------------
# _deser_dict_expression
# ---------------------------------------------------------------------------


def test_deser_dict_expression_valid() -> None:
    s = _s()
    result = _deser_dict_expression(
        s,
        {
            "items": [
                {
                    "type": "DictItem",
                    "key": {"type": "StringLiteral", "value": "k"},
                    "value": INT_LIT,
                }
            ]
        },
    )
    assert result is not None


def test_deser_dict_expression_non_list_raises() -> None:
    with pytest.raises(SerializationError, match="must be a list"):
        _deser_dict_expression(_s(), {"items": "bad"})


def test_deser_dict_expression_invalid_item_raises() -> None:
    with pytest.raises(SerializationError, match="must contain expressions"):
        _deser_dict_expression(_s(), {"items": [None]})


# ---------------------------------------------------------------------------
# _deser_dict_item
# ---------------------------------------------------------------------------


def test_deser_dict_item() -> None:
    s = _s()
    result = _deser_dict_item(s, {"key": {"type": "StringLiteral", "value": "k"}, "value": INT_LIT})
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_slice_expression
# ---------------------------------------------------------------------------


def test_deser_slice_expression() -> None:
    s = _s()
    result = _deser_slice_expression(
        s, {"target": INT_LIT, "start": INT_LIT, "stop": None, "step": None}
    )
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_lambda_expression
# ---------------------------------------------------------------------------


def test_deser_lambda_expression_valid() -> None:
    s = _s()
    result = _deser_lambda_expression(s, {"parameters": ["x", "y"], "body": BOOL_LIT_TRUE})
    assert result is not None


def test_deser_lambda_expression_non_list_params_raises() -> None:
    with pytest.raises(SerializationError, match="must be a list of strings"):
        _deser_lambda_expression(_s(), {"parameters": "bad", "body": BOOL_LIT_TRUE})


def test_deser_lambda_expression_non_string_params_raises() -> None:
    with pytest.raises(SerializationError, match="must be a list of strings"):
        _deser_lambda_expression(_s(), {"parameters": [1, 2], "body": BOOL_LIT_TRUE})


def test_deser_lambda_expression_empty_param_raises() -> None:
    with pytest.raises(SerializationError, match="must contain non-empty strings"):
        _deser_lambda_expression(_s(), {"parameters": [""], "body": BOOL_LIT_TRUE})


# ---------------------------------------------------------------------------
# _deser_pattern_match
# ---------------------------------------------------------------------------


def test_deser_pattern_match_valid() -> None:
    s = _s()
    result = _deser_pattern_match(
        s,
        {
            "value": INT_LIT,
            "cases": [
                {
                    "type": "MatchCase",
                    "pattern": INT_LIT,
                    "result": BOOL_LIT_TRUE,
                }
            ],
            "default": None,
        },
    )
    assert result is not None


def test_deser_pattern_match_non_list_cases_raises() -> None:
    with pytest.raises(SerializationError, match="must be a list"):
        _deser_pattern_match(_s(), {"value": INT_LIT, "cases": "bad", "default": None})


def test_deser_pattern_match_invalid_case_raises() -> None:
    with pytest.raises(SerializationError, match="must contain expressions"):
        _deser_pattern_match(_s(), {"value": INT_LIT, "cases": [None], "default": None})


# ---------------------------------------------------------------------------
# _deser_match_case
# ---------------------------------------------------------------------------


def test_deser_match_case() -> None:
    s = _s()
    result = _deser_match_case(s, {"pattern": INT_LIT, "result": BOOL_LIT_TRUE})
    assert result is not None


# ---------------------------------------------------------------------------
# _deser_spread_operator
# ---------------------------------------------------------------------------


def test_deser_spread_operator() -> None:
    s = _s()
    result = _deser_spread_operator(s, {"expression": INT_LIT, "is_dict": False})
    assert result is not None


def test_deser_spread_operator_non_bool_raises() -> None:
    with pytest.raises(SerializationError, match="must be a boolean"):
        _deser_spread_operator(_s(), {"expression": INT_LIT, "is_dict": 1})


# ---------------------------------------------------------------------------
# _deserialize_rule — dict meta path and non-list meta
# ---------------------------------------------------------------------------


def test_deserialize_rule_dict_meta() -> None:
    s = _s()
    result = s._deserialize_rule(
        {
            "type": "Rule",
            "name": "test_rule",
            "modifiers": [],
            "tags": [],
            "meta": {"author": "alice", "version": "v1"},
            "strings": [],
            "condition": BOOL_LIT_TRUE,
            "pragmas": [],
        }
    )
    assert len(result.meta) == 2


def test_deserialize_rule_invalid_meta_type_raises() -> None:
    with pytest.raises(SerializationError, match="must be a list or dictionary"):
        _s()._deserialize_rule(
            {
                "type": "Rule",
                "name": "bad_rule",
                "modifiers": [],
                "tags": [],
                "meta": 42,
                "strings": [],
                "condition": BOOL_LIT_TRUE,
                "pragmas": [],
            }
        )


# ---------------------------------------------------------------------------
# _deserialize_tag — non-Tag type raises
# ---------------------------------------------------------------------------


def test_deserialize_tag_wrong_type_raises() -> None:
    with pytest.raises(SerializationError, match="must contain Tag nodes"):
        _s()._deserialize_tag({"type": "NotTag", "name": "t"})


def test_deserialize_tag_valid() -> None:
    result = _s()._deserialize_tag({"name": "my_tag"})
    assert result is not None


# ---------------------------------------------------------------------------
# _deserialize_meta
# ---------------------------------------------------------------------------


def test_deserialize_meta_type_meta() -> None:
    from yaraast.ast.meta import Meta

    result = _s()._deserialize_meta({"type": "Meta", "key": "author", "value": "Alice"})
    assert isinstance(result, Meta)


def test_deserialize_meta_entry_with_scope() -> None:
    from yaraast.ast.modifiers import MetaEntry

    result = _s()._deserialize_meta(
        {"type": "MetaEntry", "key": "version", "value": "v1", "scope": "public"}
    )
    assert isinstance(result, MetaEntry)


def test_deserialize_meta_meta_with_scope_raises() -> None:
    with pytest.raises(SerializationError, match="only valid for MetaEntry"):
        _s()._deserialize_meta({"type": "Meta", "key": "k", "value": "v", "scope": "public"})


def test_deserialize_meta_unknown_type_raises() -> None:
    with pytest.raises(SerializationError, match="Meta type must be"):
        _s()._deserialize_meta({"type": "WeirdType", "key": "k", "value": "v"})


def test_deserialize_meta_plain_no_type() -> None:
    result = _s()._deserialize_meta({"key": "plain", "value": "value"})
    assert result is not None


# ---------------------------------------------------------------------------
# _deserialize_string — HexString, RegexString, StringDefinition
# ---------------------------------------------------------------------------


def test_deserialize_hex_string() -> None:
    s = _s()
    result = s._deserialize_string(
        {
            "type": "HexString",
            "identifier": "$hex",
            "modifiers": [],
            "tokens": [{"type": "HexByte", "value": 0xAB}],
        }
    )
    assert result is not None


def test_deserialize_hex_string_empty_tokens_raises() -> None:
    with pytest.raises(SerializationError, match="must contain at least one token"):
        _s()._deserialize_string(
            {"type": "HexString", "identifier": "$hex", "modifiers": [], "tokens": []}
        )


def test_deserialize_regex_string() -> None:
    s = _s()
    result = s._deserialize_string(
        {
            "type": "RegexString",
            "identifier": "$re",
            "modifiers": [],
            "regex": "test.*",
        }
    )
    assert result is not None


def test_deserialize_string_definition() -> None:
    s = _s()
    result = s._deserialize_string(
        {"type": "StringDefinition", "identifier": "$sd", "modifiers": []}
    )
    assert result is not None


# ---------------------------------------------------------------------------
# _format_unknown_modifier
# ---------------------------------------------------------------------------


def test_format_unknown_modifier_none_value() -> None:
    s = _s()
    assert s._format_unknown_modifier("foo", None) == "foo"


def test_format_unknown_modifier_tuple_value() -> None:
    s = _s()
    assert s._format_unknown_modifier("foo", (1, 5)) == "foo(1-5)"


def test_format_unknown_modifier_string_value() -> None:
    s = _s()
    result = s._format_unknown_modifier("foo", "bar")
    assert result == 'foo("bar")'


def test_format_unknown_modifier_int_value() -> None:
    s = _s()
    result = s._format_unknown_modifier("foo", 42)
    assert result == "foo(42)"


# ---------------------------------------------------------------------------
# _deserialize_modifier
# ---------------------------------------------------------------------------


def test_deserialize_modifier_dict_known() -> None:
    s = _s()
    result = s._deserialize_modifier({"name": "nocase", "value": None})
    assert result is not None


def test_deserialize_modifier_string_known() -> None:
    s = _s()
    result = s._deserialize_modifier("nocase")
    assert result is not None


def test_deserialize_modifier_dict_unknown() -> None:
    s = _s()
    result = s._deserialize_modifier({"name": "unknown_mod_xyz", "value": None})
    assert result == "unknown_mod_xyz"


def test_deserialize_modifier_dict_unknown_with_value() -> None:
    s = _s()
    result = s._deserialize_modifier({"name": "unknown_mod_xyz", "value": "myval"})
    assert "unknown_mod_xyz" in result


# ---------------------------------------------------------------------------
# Hex token types
# ---------------------------------------------------------------------------


def test_hex_token_hex_token() -> None:
    s = _s()
    result = s._deserialize_hex_token({"type": "HexToken"})
    assert result is not None


def test_hex_token_hex_byte_int() -> None:
    s = _s()
    result = s._deserialize_hex_token({"type": "HexByte", "value": 0xAB})
    assert result is not None


def test_hex_token_hex_byte_str() -> None:
    s = _s()
    result = s._deserialize_hex_token({"type": "HexByte", "value": "AB"})
    assert result is not None


def test_hex_token_hex_wildcard() -> None:
    s = _s()
    result = s._deserialize_hex_token({"type": "HexWildcard"})
    assert result is not None


def test_hex_token_hex_jump() -> None:
    s = _s()
    result = s._deserialize_hex_token({"type": "HexJump", "min_jump": 1, "max_jump": 5})
    assert result is not None


def test_hex_token_hex_nibble_int() -> None:
    s = _s()
    result = s._deserialize_hex_token({"type": "HexNibble", "value": 5, "high": True})
    assert result is not None


def test_hex_token_hex_nibble_str() -> None:
    s = _s()
    result = s._deserialize_hex_token({"type": "HexNibble", "value": "A", "high": False})
    assert result is not None


def test_hex_token_hex_negated_byte_int() -> None:
    s = _s()
    result = s._deserialize_hex_token({"type": "HexNegatedByte", "value": 0x0F})
    assert result is not None


def test_hex_token_hex_negated_byte_str() -> None:
    s = _s()
    result = s._deserialize_hex_token({"type": "HexNegatedByte", "value": "FF"})
    assert result is not None


def test_hex_token_hex_negated_byte_nibble() -> None:
    s = _s()
    result = s._deserialize_hex_token({"type": "HexNegatedByte", "value": "?A"})
    assert result is not None


def test_hex_token_hex_alternative_list_branches() -> None:
    s = _s()
    result = s._deserialize_hex_token(
        {
            "type": "HexAlternative",
            "alternatives": [
                [{"type": "HexByte", "value": 0xAB}],
                [{"type": "HexByte", "value": 0xCD}],
            ],
        }
    )
    assert result is not None


def test_hex_token_hex_alternative_single_item_branches() -> None:
    s = _s()
    result = s._deserialize_hex_token(
        {
            "type": "HexAlternative",
            "alternatives": [
                {"type": "HexByte", "value": 0xAB},
                {"type": "HexByte", "value": 0xCD},
            ],
        }
    )
    assert result is not None


# ---------------------------------------------------------------------------
# _validate_hex_token_sequence
# ---------------------------------------------------------------------------


def test_validate_hex_sequence_jump_at_start_raises() -> None:
    s = _s()
    tokens = [HexJump(min_jump=1, max_jump=3), HexByte(value=0xAB)]
    with pytest.raises(SerializationError, match="cannot appear at the beginning or end"):
        s._validate_hex_token_sequence(tokens, "test", inside_alternative=False)


def test_validate_hex_sequence_jump_at_end_raises() -> None:
    s = _s()
    tokens = [HexByte(value=0xAB), HexJump(min_jump=1, max_jump=3)]
    with pytest.raises(SerializationError, match="cannot appear at the beginning or end"):
        s._validate_hex_token_sequence(tokens, "test", inside_alternative=False)


def test_validate_hex_sequence_unbounded_jump_in_alternative_raises() -> None:
    s = _s()
    tokens = [
        HexByte(value=0xAB),
        HexJump(min_jump=None, max_jump=None),
        HexByte(value=0xCD),
    ]
    with pytest.raises(SerializationError, match="Unbounded HexJump"):
        s._validate_hex_token_sequence(tokens, "test", inside_alternative=True)


def test_validate_hex_sequence_recursive_alternative() -> None:
    s = _s()
    from yaraast.ast.strings import HexAlternative

    inner_tokens = [HexByte(value=0xAA), HexByte(value=0xBB)]
    alt = HexAlternative(alternatives=[inner_tokens])
    outer_tokens = [HexByte(value=0x01), alt, HexByte(value=0x02)]
    s._validate_hex_token_sequence(outer_tokens, "outer", inside_alternative=False)


# ---------------------------------------------------------------------------
# _coerce_hex_alternative_branch
# ---------------------------------------------------------------------------


def test_coerce_hex_alternative_branch_list() -> None:
    s = _s()
    item: list[Any] = [{"type": "HexByte", "value": 0xAB}]
    coerce: Any = s._coerce_hex_alternative_branch
    result = coerce(item)
    assert result is item


def test_coerce_hex_alternative_branch_single_item() -> None:
    s = _s()
    item: dict[str, Any] = {"type": "HexByte", "value": 0xAB}
    coerce: Any = s._coerce_hex_alternative_branch
    result = coerce(item)
    assert result == [item]


# ---------------------------------------------------------------------------
# _deserialize_extern_import
# ---------------------------------------------------------------------------


def test_deserialize_extern_import_module_path() -> None:
    s = _s()
    result = s._deserialize_extern_import(
        {"module_path": "my.module", "alias": None, "rules": ["rule_a"]}
    )
    assert result is not None


def test_deserialize_extern_import_module_fallback() -> None:
    s = _s()
    result = s._deserialize_extern_import(
        {"module": "alt.module", "alias": None, "rules": ["rule_b"]}
    )
    assert result is not None


def test_deserialize_extern_import_missing_module_raises() -> None:
    with pytest.raises(SerializationError, match="missing module_path"):
        _s()._deserialize_extern_import({"alias": None, "rules": []})


def test_deserialize_extern_import_non_string_module_raises() -> None:
    with pytest.raises(SerializationError, match="must be a string"):
        _s()._deserialize_extern_import({"module_path": 99, "alias": None, "rules": []})


def test_deserialize_extern_import_empty_module_raises() -> None:
    with pytest.raises(SerializationError, match="must not be empty"):
        _s()._deserialize_extern_import({"module_path": "  ", "alias": None, "rules": []})


def test_deserialize_extern_import_non_list_rules_raises() -> None:
    with pytest.raises(SerializationError, match="must be a list of strings"):
        _s()._deserialize_extern_import({"module_path": "m", "alias": None, "rules": "bad"})


def test_deserialize_extern_import_empty_rule_string_raises() -> None:
    with pytest.raises(SerializationError, match="must contain non-empty strings"):
        _s()._deserialize_extern_import({"module_path": "m", "alias": None, "rules": [""]})


# ---------------------------------------------------------------------------
# _deserialize_extern_rule
# ---------------------------------------------------------------------------


def test_deserialize_extern_rule() -> None:
    s = _s()
    result = s._deserialize_extern_rule({"name": "my_rule", "modifiers": [], "namespace": None})
    assert result is not None


# ---------------------------------------------------------------------------
# _deserialize_extern_namespace
# ---------------------------------------------------------------------------


def test_deserialize_extern_namespace() -> None:
    s = _s()
    result = s._deserialize_extern_namespace(
        {
            "name": "my_ns",
            "extern_rules": [{"name": "rule_a", "modifiers": [], "namespace": None}],
        }
    )
    assert result is not None


def test_deserialize_extern_namespace_non_list_rules_raises() -> None:
    with pytest.raises(SerializationError, match="must be a list"):
        _s()._deserialize_extern_namespace({"name": "ns", "extern_rules": "bad"})


# ---------------------------------------------------------------------------
# _deserialize_pragma — all types
# ---------------------------------------------------------------------------


def test_deserialize_pragma_include_once() -> None:
    s = _s()
    result = s._deserialize_pragma(
        {
            "type": "Pragma",
            "pragma_type": "include_once",
            "scope": None,
            "name": "once",
            "arguments": [],
        }
    )
    assert result is not None


def test_deserialize_pragma_define() -> None:
    s = _s()
    result = s._deserialize_pragma(
        {
            "type": "Pragma",
            "pragma_type": "define",
            "scope": None,
            "name": "define",
            "arguments": [],
            "macro_name": "MY_MACRO",
            "macro_value": "1",
        }
    )
    assert result is not None


def test_deserialize_pragma_undef() -> None:
    s = _s()
    result = s._deserialize_pragma(
        {
            "type": "Pragma",
            "pragma_type": "undef",
            "scope": None,
            "name": "undef",
            "arguments": [],
            "macro_name": "MY_MACRO",
        }
    )
    assert result is not None


def test_deserialize_pragma_ifdef() -> None:
    s = _s()
    result = s._deserialize_pragma(
        {
            "type": "Pragma",
            "pragma_type": "ifdef",
            "scope": None,
            "name": "ifdef",
            "arguments": [],
            "condition": "MY_MACRO",
        }
    )
    assert result is not None


def test_deserialize_pragma_ifndef() -> None:
    s = _s()
    result = s._deserialize_pragma(
        {
            "type": "Pragma",
            "pragma_type": "ifndef",
            "scope": None,
            "name": "ifndef",
            "arguments": [],
            "condition": "MY_MACRO",
        }
    )
    assert result is not None


def test_deserialize_pragma_endif() -> None:
    s = _s()
    result = s._deserialize_pragma(
        {
            "type": "Pragma",
            "pragma_type": "endif",
            "scope": None,
            "name": "endif",
            "arguments": [],
            "condition": None,
        }
    )
    assert result is not None


def test_deserialize_pragma_custom() -> None:
    s = _s()
    result = s._deserialize_pragma(
        {
            "type": "Pragma",
            "pragma_type": "custom",
            "scope": "file",
            "name": "custom_pragma",
            "arguments": ["arg1"],
            "parameters": {"key": "val"},
        }
    )
    assert result is not None


def test_deserialize_pragma_generic() -> None:
    s = _s()
    result = s._deserialize_pragma(
        {
            "type": "Pragma",
            "pragma_type": "pragma",
            "scope": "file",
            "name": "my_pragma",
            "arguments": [],
        }
    )
    assert result is not None


# ---------------------------------------------------------------------------
# _deserialize_in_rule_pragma
# ---------------------------------------------------------------------------


def test_deserialize_in_rule_pragma_with_position() -> None:
    s = _s()
    result = s._deserialize_in_rule_pragma(
        {
            "pragma": {
                "type": "Pragma",
                "pragma_type": "include_once",
                "scope": None,
                "name": "once",
                "arguments": [],
            },
            "position": "before_condition",
        }
    )
    assert result.position == "before_condition"


def test_deserialize_in_rule_pragma_default_position() -> None:
    s = _s()
    result = s._deserialize_in_rule_pragma(
        {
            "pragma": {
                "type": "Pragma",
                "pragma_type": "include_once",
                "scope": None,
                "name": "once",
                "arguments": [],
            }
        }
    )
    assert result.position == "before_strings"


# ---------------------------------------------------------------------------
# _deserialize_expression — Expression and Condition types + unknown
# ---------------------------------------------------------------------------


def test_deserialize_expression_expression_type() -> None:
    s = _s()
    result = s._deserialize_expression({"type": "Expression"})
    assert result is not None


def test_deserialize_expression_condition_type() -> None:
    s = _s()
    result = s._deserialize_expression({"type": "Condition"})
    assert result is not None


def test_deserialize_expression_unknown_type_raises() -> None:
    s = _s()
    with pytest.raises(SerializationError, match="Unknown expression type"):
        s._deserialize_expression({"type": "CompletelyUnknownType"})


def test_deserialize_expression_none_returns_none() -> None:
    s = _s()
    result = s._deserialize_expression(cast("dict[str, Any]", None))
    assert result is None


def test_deserialize_expression_empty_dict_returns_none() -> None:
    s = _s()
    result = s._deserialize_expression({})
    assert result is None


# ---------------------------------------------------------------------------
# Remaining branch coverage: uncovered paths after initial suite
# ---------------------------------------------------------------------------


# Lines 93-94: _deserialize_optional_expression raises when data is {} (expression returns None)
def test_optional_expression_empty_dict_raises() -> None:
    with pytest.raises(SerializationError, match="must be an expression"):
        _deserialize_optional_expression(_s(), {}, "ctx")


# Lines 120-121: _deserialize_required_expression_value raises when value is {}
def test_required_expression_value_empty_dict_raises() -> None:
    with pytest.raises(SerializationError, match="is required"):
        _deserialize_required_expression_value(_s(), {}, "ctx")


# Lines 149-150: _deserialize_required_quantifier — quantifier value is None
# None passes through the bool/list/str/float guards and _deserialize_ast_value returns None
def test_required_quantifier_null_raises() -> None:
    with pytest.raises(SerializationError, match="is required"):
        _deserialize_required_quantifier(
            _s(), {"quantifier": None}, "quantifier", "ctx", allow_percentage=False
        )


# Lines 166-167: _deserialize_string_set_item fall-through is genuinely unreachable —
# the only dict values that make _deserialize_expression return None are None and {},
# both caught at line 154. Any other dict with unknown type raises "Unknown expression type"
# before reaching the fall-through. This branch is dead code in the current implementation.


# Lines 188-189: _deserialize_required_string_set fall-through — integer value
def test_required_string_set_integer_raises() -> None:
    with pytest.raises(SerializationError, match="must be a string, expression, or list"):
        _deserialize_required_string_set(_s(), {"f": 42}, "f", "ctx")


# Lines 202->206: _deserialize_dictionary_key — non-str non-dict key falls through to error
# The False branch of isinstance(key, dict) at line 202 is triggered by a non-str, non-dict key
def test_dictionary_key_integer_raises() -> None:
    with pytest.raises(SerializationError, match="must be a string or expression"):
        _deserialize_dictionary_key(_s(), {"key": 99})


# Lines 212-213: _deserialize_comment_node — non-dict data triggers the first guard
def test_comment_node_non_dict_raises() -> None:
    with pytest.raises(SerializationError, match="Comment metadata must be an object"):
        _deserialize_comment_node(_s(), cast("dict[str, Any]", "not a dict"))


# Lines 348->353: _deserialize_hex_negated_value — False branch when value is not a string
# (e.g., a list), which skips the str block entirely and falls through to the error
def test_hex_negated_value_non_str_non_int_raises() -> None:
    with pytest.raises(SerializationError, match="must be a byte or negated nibble"):
        _deserialize_hex_negated_value({"value": [0xAB]})


# Lines 544-546: _deser_identifier
def test_deser_identifier() -> None:
    result = _deser_identifier(_s(), {"name": "my_ident"})
    assert result is not None


# Lines 793-794: _deser_extern_rule_reference — missing rule_name and name
def test_deser_extern_rule_reference_missing_name_raises() -> None:
    with pytest.raises(SerializationError, match="missing rule_name"):
        _deser_extern_rule_reference(_s(), {"namespace": None})


# Lines 797-798: _deser_extern_rule_reference — non-string rule_name
def test_deser_extern_rule_reference_non_string_name_raises() -> None:
    with pytest.raises(SerializationError, match="must be a string"):
        _deser_extern_rule_reference(_s(), {"name": 42, "namespace": None})


# Lines 850->855, 857->862, 864->869: ArrayComprehension with all optional fields present
def test_deser_array_comprehension_all_optional_fields_present() -> None:
    s = _s()
    result = _deser_array_comprehension(
        s,
        {
            "variable": "x",
            "expression": INT_LIT,
            "iterable": INT_LIT,
            "condition": BOOL_LIT_TRUE,
        },
    )
    assert result is not None


# Lines 898->903, 905->910, 912->917, 919->924: DictComprehension with all optional fields present
def test_deser_dict_comprehension_all_optional_fields_present() -> None:
    s = _s()
    result = _deser_dict_comprehension(
        s,
        {
            "key_variable": "k",
            "value_variable": "v",
            "key_expression": INT_LIT,
            "value_expression": INT_LIT,
            "iterable": INT_LIT,
            "condition": BOOL_LIT_TRUE,
        },
    )
    assert result is not None


# Lines 1165-1167: _deserialize_import via mixin
def test_deserialize_import_via_mixin() -> None:
    s = _s()
    result = s._deserialize_import({"module": "pe", "alias": None})
    assert result is not None


# Lines 1176-1178: _deserialize_include via mixin
def test_deserialize_include_via_mixin() -> None:
    s = _s()
    result = s._deserialize_include({"path": "rules/common.yar"})
    assert result is not None


# Lines 1187-1192: _deserialize_rule — dict meta (not list), line 1198 is unreachable dead code
def test_deserialize_rule_with_dict_meta() -> None:
    import json

    s = _s()
    payload = json.dumps(
        {
            "type": "YaraFile",
            "rules": [
                {
                    "type": "Rule",
                    "name": "rule_dict_meta",
                    "modifiers": [],
                    "tags": [],
                    "meta": {"author": "tester"},
                    "strings": [],
                    "condition": {"type": "BooleanLiteral", "value": True},
                    "pragmas": [],
                }
            ],
            "imports": [],
            "includes": [],
            "pragmas": [],
            "extern_rules": [],
            "extern_imports": [],
            "extern_namespaces": [],
            "namespaces": [],
        }
    )
    result = s.deserialize(payload)
    assert len(result.rules[0].meta) == 1
    assert result.rules[0].meta[0].key == "author"


# Lines 1306-1309: _deserialize_string — PlainString type
def test_deserialize_string_plain_string_type() -> None:
    import json

    s = _s()
    payload = json.dumps(
        {
            "type": "YaraFile",
            "rules": [
                {
                    "type": "Rule",
                    "name": "rule_ps",
                    "modifiers": [],
                    "tags": [],
                    "meta": [],
                    "strings": [
                        {
                            "type": "PlainString",
                            "identifier": "$a",
                            "value": "hello",
                            "raw_bytes": None,
                            "modifiers": [],
                            "is_anonymous": False,
                        }
                    ],
                    "condition": {"type": "BooleanLiteral", "value": True},
                    "pragmas": [],
                }
            ],
            "imports": [],
            "includes": [],
            "pragmas": [],
            "extern_rules": [],
            "extern_imports": [],
            "extern_namespaces": [],
            "namespaces": [],
        }
    )
    from yaraast.ast.strings import PlainString

    result = s.deserialize(payload)
    string_node = result.rules[0].strings[0]
    assert isinstance(string_node, PlainString)
    assert string_node.value == "hello"


# Lines 1382-1383: _deserialize_string — unknown string type
def test_deserialize_string_unknown_type_raises() -> None:
    with pytest.raises(SerializationError, match="Unknown string type"):
        _s()._deserialize_string(
            {"type": "BadStringType", "identifier": "$b", "modifiers": [], "is_anonymous": False}
        )


# Lines 1408-1409: _deserialize_modifier — empty string modifier name raises
def test_deserialize_modifier_empty_string_raises() -> None:
    with pytest.raises(SerializationError, match="must not be empty"):
        _s()._deserialize_modifier("")


# Lines 1413-1414: _deserialize_modifier — non-str non-dict raises
def test_deserialize_modifier_integer_raises() -> None:
    with pytest.raises(SerializationError, match="must be a string or object"):
        _s()._deserialize_modifier(42)


# Lines 1471-1472: HexAlternative with empty alternatives list
def test_hex_alternative_empty_alternatives_raises() -> None:
    with pytest.raises(SerializationError, match="must contain at least one branch"):
        _s()._deserialize_hex_token({"type": "HexAlternative", "alternatives": []})


# Lines 1477-1478: HexAlternative with an empty list as a branch
def test_hex_alternative_empty_branch_raises() -> None:
    with pytest.raises(SerializationError, match="branches must not be empty"):
        _s()._deserialize_hex_token({"type": "HexAlternative", "alternatives": [[]]})


# Lines 1487-1488: _deserialize_hex_token — unknown hex token type
def test_deserialize_hex_token_unknown_type_raises() -> None:
    with pytest.raises(SerializationError, match="Unknown hex token type"):
        _s()._deserialize_hex_token({"type": "UnknownHexTokenType"})


# Lines 1507-1508: _validate_hex_token_sequence — HexAlternative with empty inner branch
def test_validate_hex_sequence_alt_with_empty_inner_branch_raises() -> None:
    from yaraast.ast.strings import HexAlternative

    inner_alt = HexAlternative(alternatives=[[]])
    outer_tokens = [HexByte(value=0x01), inner_alt, HexByte(value=0x02)]
    with pytest.raises(SerializationError, match="branches must not be empty"):
        _s()._validate_hex_token_sequence(outer_tokens, "outer", inside_alternative=False)


def test_deserialize_extern_import_whitespace_alias_raises() -> None:
    with pytest.raises(SerializationError, match="must not be empty"):
        _s()._deserialize_extern_import(
            {"module_path": "my.module", "alias": "   ", "rules": ["rule_a"]}
        )


# Line 1664: _deserialize_pragma — ENDIF pragma with non-None condition string
def test_deserialize_pragma_endif_with_non_null_condition() -> None:
    s = _s()
    result = s._deserialize_pragma(
        {
            "type": "Pragma",
            "pragma_type": "endif",
            "scope": None,
            "name": "endif",
            "arguments": [],
            "condition": "MY_COND",
        }
    )
    assert result is not None
