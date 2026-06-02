"""Deserialization helpers for JSON serializer."""

from __future__ import annotations

import base64
import binascii
import math
from typing import Any

from yaraast.ast.base import ASTNode, Location
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.errors import SerializationError, ValidationError
from yaraast.serialization.meta_scopes import deserialize_meta_scope
from yaraast.serialization.modifier_values import deserialize_legacy_modifier_value
from yaraast.serialization.pragma_scopes import deserialize_pragma_scope
from yaraast.string_escaping import escape_string_source_value

_HEX_CHARS = frozenset("0123456789abcdefABCDEF")
_WHITESPACE_SIGNIFICANT_NONEMPTY_FIELDS = frozenset(
    {
        "RegexLiteral pattern",
        "RegexString regex",
    }
)


def _is_empty_nonempty_field(text: str, context: str, field: str | None = None) -> bool:
    label = f"{context} {field}" if field is not None else context
    return not text or (not text.strip() and label not in _WHITESPACE_SIGNIFICANT_NONEMPTY_FIELDS)


def _deserialize_object(data: Any, context: str) -> dict[str, Any]:
    if isinstance(data, dict):
        return data
    msg = f"{context} must be an object"
    raise SerializationError(msg)


def _deserialize_required_field(data: dict[str, Any], field: str, context: str) -> Any:
    data = _deserialize_object(data, context)
    if field not in data:
        msg = f"{context} {field} is required"
        raise SerializationError(msg)
    return data[field]


def _deserialize_ast_value(self, data, context: str = "AST value"):
    if isinstance(data, dict):
        return _deserialize_required_expression_value(self, data, context)
    if isinstance(data, list):
        values = []
        for item in data:
            if item is None or item == {}:
                msg = f"{context} must contain values"
                raise SerializationError(msg)
            values.append(_deserialize_ast_value(self, item, context))
        return values
    return data


def _deserialize_optional_expression(self, data, context: str):
    if data is None:
        return None
    expression = self._deserialize_expression(data)
    if expression is not None:
        return expression
    msg = f"{context} must be an expression"
    raise SerializationError(msg)


def _deserialize_required_expression(self, data: dict[str, Any], field: str, context: str) -> Any:
    return _deserialize_required_expression_value(
        self, _deserialize_required_field(data, field, context), f"{context} {field}"
    )


def _deserialize_required_expression_value(self, value: Any, context: str) -> Any:
    expression = self._deserialize_expression(value)
    if expression is not None:
        return expression
    msg = f"{context} is required"
    raise SerializationError(msg)


def _deserialize_expression_list_field(
    self, data: dict[str, Any], field: str, context: str
) -> list[Any]:
    expressions: list[Any] = []
    for item in _deserialize_list_field(data, field, context):
        expression = self._deserialize_expression(item)
        if expression is None:
            msg = f"{context} {field} must contain expressions"
            raise SerializationError(msg)
        expressions.append(expression)
    return expressions


def _deserialize_required_ast_value(self, data: dict[str, Any], field: str, context: str) -> Any:
    value = _deserialize_ast_value(
        self, _deserialize_required_field(data, field, context), f"{context} {field}"
    )
    if value is not None:
        return value
    msg = f"{context} {field} is required"
    raise SerializationError(msg)


def _deserialize_required_quantifier(self, data: dict[str, Any], field: str, context: str) -> Any:
    value = _deserialize_required_field(data, field, context)
    if isinstance(value, bool | list):
        msg = f"{context} {field} must be a string, number, or expression"
        raise SerializationError(msg)
    if isinstance(value, float) and not math.isfinite(value):
        msg = f"{context} {field} must be finite"
        raise SerializationError(msg)
    quantifier = _deserialize_ast_value(self, value, f"{context} {field}")
    if quantifier is not None:
        return quantifier
    msg = f"{context} {field} is required"
    raise SerializationError(msg)


def _deserialize_string_set_item(self, value: Any, context: str) -> Any:
    if value is None or value == {}:
        msg = f"{context} must contain values"
        raise SerializationError(msg)
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        expression = self._deserialize_expression(value)
        if expression is not None:
            return expression
    msg = f"{context} must contain strings or expressions"
    raise SerializationError(msg)


def _deserialize_required_string_set(self, data: dict[str, Any], field: str, context: str) -> Any:
    value = _deserialize_required_field(data, field, context)
    field_context = f"{context} {field}"
    if value is None or value == {}:
        msg = f"{field_context} is required"
        raise SerializationError(msg)
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return _deserialize_required_expression_value(self, value, field_context)
    if isinstance(value, list):
        return [_deserialize_string_set_item(self, item, field_context) for item in value]
    msg = f"{field_context} must be a string, expression, or list of strings/expressions"
    raise SerializationError(msg)


def _deserialize_dictionary_key(self, data: dict[str, Any]) -> str | ASTNode:
    if "key" not in data:
        msg = "DictionaryAccess key must be a string or expression"
        raise SerializationError(msg)
    key = data["key"]
    if isinstance(key, str):
        return key
    if isinstance(key, dict):
        expression = self._deserialize_expression(key)
        if expression is not None:
            return expression
    msg = "DictionaryAccess key must be a string or expression"
    raise SerializationError(msg)


def _deserialize_location_int_field(data: dict[str, Any], field: str) -> int:
    value = _deserialize_required_field(data, field, "Location")
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    msg = f"Location {field} must be an integer"
    raise SerializationError(msg)


def _deserialize_location_optional_int_field(data: dict[str, Any], field: str) -> int | None:
    value = data.get(field)
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    msg = f"Location {field} must be an integer"
    raise SerializationError(msg)


def _deserialize_comment_multiline(data: dict[str, Any]) -> bool:
    value = data.get("is_multiline", False)
    if isinstance(value, bool):
        return value
    msg = "Comment is_multiline must be a boolean"
    raise SerializationError(msg)


def _deserialize_comment_text(data: dict[str, Any]) -> str:
    return _deserialize_string_field(data, "text", "Comment")


def _deserialize_location(data: dict[str, Any]) -> Location:
    return Location(
        line=_deserialize_location_int_field(data, "line"),
        column=_deserialize_location_int_field(data, "column"),
        file=_deserialize_nullable_string_field(data, "file", "Location"),
        end_line=_deserialize_location_optional_int_field(data, "end_line"),
        end_column=_deserialize_location_optional_int_field(data, "end_column"),
    )


def _deserialize_comment_node(self, data: dict[str, Any]) -> Any:
    if not isinstance(data, dict):
        msg = "Comment metadata must be an object"
        raise SerializationError(msg)
    node_type = data.get("type")
    if node_type == "Comment":
        return _apply_node_metadata(
            self,
            Comment(
                _deserialize_comment_text(data),
                is_multiline=_deserialize_comment_multiline(data),
            ),
            data,
        )
    if node_type == "CommentGroup":
        return _apply_node_metadata(
            self,
            CommentGroup(
                [
                    _cast_comment(_deserialize_comment_node(self, c))
                    for c in _deserialize_list_field(data, "comments", "CommentGroup")
                ]
            ),
            data,
        )
    msg = f"Unknown comment metadata type: {node_type}"
    raise SerializationError(msg)


def _deserialize_plain_string_value(data: dict[str, Any]) -> str | bytes:
    value = _deserialize_required_field(data, "value", "PlainString")
    if data.get("value_encoding") != "base64":
        if isinstance(value, str | bytes):
            return value
        msg = "PlainString value must be a string or bytes"
        raise SerializationError(msg)
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        msg = "PlainString value must be a string or bytes"
        raise SerializationError(msg)
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        msg = "Invalid base64-encoded plain string value"
        raise SerializationError(msg) from exc


def _deserialize_is_anonymous(data: dict[str, Any]) -> bool:
    return data.get("is_anonymous") is True


def _deserialize_integer_literal_value(data: dict[str, Any]) -> int:
    value = _deserialize_required_field(data, "value", "IntegerLiteral")
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    msg = "IntegerLiteral value must be an integer"
    raise SerializationError(msg)


def _deserialize_boolean_literal_value(data: dict[str, Any]) -> bool:
    value = _deserialize_required_field(data, "value", "BooleanLiteral")
    if isinstance(value, bool):
        return value
    msg = "BooleanLiteral value must be a boolean"
    raise SerializationError(msg)


def _deserialize_double_literal_value(data: dict[str, Any]) -> float:
    value = _deserialize_required_field(data, "value", "DoubleLiteral")
    if isinstance(value, int | float) and not isinstance(value, bool):
        if isinstance(value, float) and not math.isfinite(value):
            msg = "DoubleLiteral value must be finite"
            raise SerializationError(msg)
        return float(value)
    msg = "DoubleLiteral value must be numeric"
    raise SerializationError(msg)


def _deserialize_string_field(data: dict[str, Any], field: str, context: str) -> str:
    value = _deserialize_required_field(data, field, context)
    if isinstance(value, str):
        return value
    msg = f"{context} {field} must be a string"
    raise SerializationError(msg)


def _deserialize_nonempty_string_field(data: dict[str, Any], field: str, context: str) -> str:
    text = _deserialize_string_field(data, field, context)
    if _is_empty_nonempty_field(text, context, field):
        msg = f"{context} {field} must not be empty"
        raise SerializationError(msg)
    return text


def _deserialize_optional_string_field(
    data: dict[str, Any], field: str, context: str, default: str = ""
) -> str:
    data = _deserialize_object(data, context)
    value = data.get(field, default)
    if isinstance(value, str):
        return value
    msg = f"{context} {field} must be a string"
    raise SerializationError(msg)


def _deserialize_nullable_string_field(
    data: dict[str, Any], field: str, context: str
) -> str | None:
    data = _deserialize_object(data, context)
    value = data.get(field)
    if value is None or isinstance(value, str):
        return value
    msg = f"{context} {field} must be a string"
    raise SerializationError(msg)


def _deserialize_nullable_nonempty_string_field(
    data: dict[str, Any], field: str, context: str
) -> str | None:
    text = _deserialize_nullable_string_field(data, field, context)
    if text is not None and _is_empty_nonempty_field(text, context, field):
        msg = f"{context} {field} must not be empty"
        raise SerializationError(msg)
    return text


def _deserialize_string_list_field(data: dict[str, Any], field: str, context: str) -> list[str]:
    data = _deserialize_object(data, context)
    value = data.get(field, [])
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    msg = f"{context} {field} must be a list of strings"
    raise SerializationError(msg)


def _deserialize_nonempty_string_list_field(
    data: dict[str, Any], field: str, context: str
) -> list[str]:
    items = _deserialize_string_list_field(data, field, context)
    if any(_is_empty_nonempty_field(item, context, field) for item in items):
        msg = f"{context} {field} must contain non-empty strings"
        raise SerializationError(msg)
    return items


def _deserialize_list_field(data: dict[str, Any], field: str, context: str) -> list[Any]:
    data = _deserialize_object(data, context)
    value = data.get(field, [])
    if isinstance(value, list):
        return value
    msg = f"{context} {field} must be a list"
    raise SerializationError(msg)


def _deserialize_bool_field(
    data: dict[str, Any], field: str, context: str, default: bool = False
) -> bool:
    data = _deserialize_object(data, context)
    value = data.get(field, default)
    if isinstance(value, bool):
        return value
    msg = f"{context} {field} must be a boolean"
    raise SerializationError(msg)


def _deserialize_dict_field(data: dict[str, Any], field: str, context: str) -> dict[str, Any]:
    data = _deserialize_object(data, context)
    value = data.get(field, {})
    if isinstance(value, dict):
        if all(isinstance(key, str) for key in value):
            return {
                key: _deserialize_pragma_parameter_value(item, f"{context} {field}")
                for key, item in value.items()
            }
        msg = f"{context} {field} keys must be strings"
        raise SerializationError(msg)
    msg = f"{context} {field} must be a dictionary"
    raise SerializationError(msg)


def _deserialize_pragma_parameter_value(value: Any, context: str) -> str | int | bool | float:
    if isinstance(value, str | bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    msg = f"{context} value must be scalar"
    raise SerializationError(msg)


def _deserialize_pragma_type(data: dict[str, Any]):
    from yaraast.ast.pragmas import PragmaType

    if "pragma_type" in data:
        value = data["pragma_type"]
        field = "pragma_type"
    elif "name" in data:
        value = data["name"]
        field = "name"
    else:
        value = PragmaType.CUSTOM.value
        field = "pragma_type"
    if isinstance(value, str):
        return PragmaType.from_string(value)
    msg = f"Pragma {field} must be a string"
    raise SerializationError(msg)


def _deserialize_pragma_scope(value: Any, context: str):
    return deserialize_pragma_scope(value, context)


def _deserialize_meta_value(data: dict[str, Any]) -> str | int | bool:
    value = _deserialize_required_field(data, "value", "Meta")
    if isinstance(value, str | bool):
        return value
    if isinstance(value, int):
        return value
    msg = "Meta value must be a string, integer, or boolean"
    raise SerializationError(msg)


def _deserialize_meta_entry_value(data: dict[str, Any]) -> str | int | bool | float:
    value = _deserialize_required_field(data, "value", "Meta")
    if isinstance(value, str | bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    msg = "Meta value must be a string, integer, boolean, or finite float"
    raise SerializationError(msg)


def _deserialize_hex_byte_value(data: dict[str, Any], context: str) -> int | str:
    value = _deserialize_required_field(data, "value", context)
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFF:
        return value
    if isinstance(value, str) and len(value) == 2 and all(char in _HEX_CHARS for char in value):
        return value
    msg = f"{context} value must be a byte"
    raise SerializationError(msg)


def _deserialize_hex_negated_value(data: dict[str, Any]) -> int | str:
    value = _deserialize_required_field(data, "value", "HexNegatedByte")
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFF:
        return value
    if isinstance(value, str):
        if len(value) == 2 and all(char in _HEX_CHARS for char in value):
            return value
        if _is_negated_nibble_pattern(value):
            return value
    msg = "HexNegatedByte value must be a byte or negated nibble"
    raise SerializationError(msg)


def _is_negated_nibble_pattern(value: str) -> bool:
    if len(value) != 2:
        return False
    first, second = value
    return (first == "?" and second in _HEX_CHARS) or (first in _HEX_CHARS and second == "?")


def _deserialize_hex_nibble_value(data: dict[str, Any]) -> int | str:
    value = _deserialize_required_field(data, "value", "HexNibble")
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xF:
        return value
    if isinstance(value, str) and len(value) == 1 and value in _HEX_CHARS:
        return value
    msg = "HexNibble value must be a nibble"
    raise SerializationError(msg)


def _deserialize_hex_nibble_high(data: dict[str, Any]) -> bool:
    value = data.get("high", True)
    if isinstance(value, bool):
        return value
    msg = "HexNibble high must be a boolean"
    raise SerializationError(msg)


def _deserialize_hex_jump_bound(data: dict[str, Any], field: str) -> int | None:
    value = data.get(field)
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    msg = f"HexJump {field} must be a non-negative integer"
    raise SerializationError(msg)


def _deserialize_hex_jump_bounds(data: dict[str, Any]) -> tuple[int | None, int | None]:
    min_jump = _deserialize_hex_jump_bound(data, "min_jump")
    max_jump = _deserialize_hex_jump_bound(data, "max_jump")
    if min_jump is not None and max_jump is not None and min_jump > max_jump:
        msg = "HexJump min_jump cannot exceed max_jump"
        raise SerializationError(msg)
    return min_jump, max_jump


def _cast_comment(node: Any) -> Comment:
    if isinstance(node, Comment):
        return node
    msg = "CommentGroup comments must contain Comment nodes"
    raise SerializationError(msg)


def _cast_leading_comment(node: Any) -> Any:
    if isinstance(node, Comment | CommentGroup):
        return node
    msg = "leading_comments must contain Comment or CommentGroup nodes"
    raise SerializationError(msg)


def _apply_node_metadata(self, node: ASTNode, data: dict[str, Any]) -> Any:
    location = data.get("location")
    if isinstance(location, dict):
        node.location = _deserialize_location(location)
    elif location is not None:
        msg = "location must be an object"
        raise SerializationError(msg)
    if "leading_comments" in data:
        leading_comments = data["leading_comments"]
        if not isinstance(leading_comments, list):
            msg = "leading_comments must be a list"
            raise SerializationError(msg)
        node.leading_comments = [
            _cast_leading_comment(_deserialize_comment_node(self, comment))
            for comment in leading_comments
        ]
    trailing_comment = data.get("trailing_comment")
    if isinstance(trailing_comment, dict):
        node.trailing_comment = _deserialize_comment_node(self, trailing_comment)
    elif trailing_comment is not None:
        msg = "trailing_comment must be an object"
        raise SerializationError(msg)
    return node


def _deser_binary_expression(self, data: dict[str, Any]):
    from yaraast.ast.expressions import BinaryExpression

    left = _deserialize_required_expression(self, data, "left", "BinaryExpression")
    right = _deserialize_required_expression(self, data, "right", "BinaryExpression")
    return BinaryExpression(
        left=left,
        operator=_deserialize_nonempty_string_field(data, "operator", "BinaryExpression"),
        right=right,
    )


def _deser_unary_expression(self, data: dict[str, Any]):
    from yaraast.ast.expressions import UnaryExpression

    operand = _deserialize_required_expression(self, data, "operand", "UnaryExpression")
    return UnaryExpression(
        operator=_deserialize_nonempty_string_field(data, "operator", "UnaryExpression"),
        operand=operand,
    )


def _deser_parentheses_expression(self, data: dict[str, Any]):
    from yaraast.ast.expressions import ParenthesesExpression

    expression = _deserialize_required_expression(self, data, "expression", "ParenthesesExpression")
    return ParenthesesExpression(expression=expression)


def _deser_set_expression(self, data: dict[str, Any]):
    from yaraast.ast.expressions import SetExpression

    elements = _deserialize_expression_list_field(self, data, "elements", "SetExpression")
    return SetExpression(elements=elements)


def _deser_range_expression(self, data: dict[str, Any]):
    from yaraast.ast.expressions import RangeExpression

    low = _deserialize_required_expression(self, data, "low", "RangeExpression")
    high = _deserialize_required_expression(self, data, "high", "RangeExpression")
    return RangeExpression(low=low, high=high)


def _deser_function_call(self, data: dict[str, Any]):
    from yaraast.ast.expressions import FunctionCall

    args = _deserialize_expression_list_field(self, data, "arguments", "FunctionCall")
    return FunctionCall(
        function=_deserialize_nonempty_string_field(data, "function", "FunctionCall"),
        arguments=args,
    )


def _deser_array_access(self, data: dict[str, Any]):
    from yaraast.ast.expressions import ArrayAccess

    array = _deserialize_required_expression(self, data, "array", "ArrayAccess")
    index = _deserialize_required_expression(self, data, "index", "ArrayAccess")
    return ArrayAccess(array=array, index=index)


def _deser_member_access(self, data: dict[str, Any]):
    from yaraast.ast.expressions import MemberAccess

    obj = _deserialize_required_expression(self, data, "object", "MemberAccess")
    return MemberAccess(
        object=obj,
        member=_deserialize_nonempty_string_field(data, "member", "MemberAccess"),
    )


def _deser_identifier(self, data: dict[str, Any]):
    from yaraast.ast.expressions import Identifier

    return Identifier(name=_deserialize_nonempty_string_field(data, "name", "Identifier"))


def _deser_string_identifier(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringIdentifier

    return StringIdentifier(
        name=_deserialize_nonempty_string_field(data, "name", "StringIdentifier")
    )


def _deser_string_wildcard(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringWildcard

    return StringWildcard(
        pattern=_deserialize_nonempty_string_field(data, "pattern", "StringWildcard")
    )


def _deser_string_count(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringCount

    return StringCount(
        string_id=_deserialize_nonempty_string_field(data, "string_id", "StringCount")
    )


def _deser_string_offset(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringOffset

    index = data.get("index")
    return StringOffset(
        string_id=_deserialize_nonempty_string_field(data, "string_id", "StringOffset"),
        index=_deserialize_optional_expression(self, index, "StringOffset index"),
    )


def _deser_string_length(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringLength

    index = data.get("index")
    return StringLength(
        string_id=_deserialize_nonempty_string_field(data, "string_id", "StringLength"),
        index=_deserialize_optional_expression(self, index, "StringLength index"),
    )


def _deser_integer_literal(self, data: dict[str, Any]):
    from yaraast.ast.expressions import IntegerLiteral

    return IntegerLiteral(value=_deserialize_integer_literal_value(data))


def _deser_double_literal(self, data: dict[str, Any]):
    from yaraast.ast.expressions import DoubleLiteral

    return DoubleLiteral(value=_deserialize_double_literal_value(data))


def _deser_string_literal(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringLiteral

    return StringLiteral(value=_deserialize_string_field(data, "value", "StringLiteral"))


def _deser_regex_literal(self, data: dict[str, Any]):
    from yaraast.ast.expressions import RegexLiteral

    return RegexLiteral(
        pattern=_deserialize_nonempty_string_field(data, "pattern", "RegexLiteral"),
        modifiers=_deserialize_optional_string_field(data, "modifiers", "RegexLiteral"),
    )


def _deser_boolean_literal(self, data: dict[str, Any]):
    from yaraast.ast.expressions import BooleanLiteral

    return BooleanLiteral(value=_deserialize_boolean_literal_value(data))


def _deser_for_expression(self, data: dict[str, Any]):
    from yaraast.ast.conditions import ForExpression

    variable = _deserialize_optional_string_field(data, "variable", "ForExpression", "i")
    if not variable:
        msg = "ForExpression variable must not be empty"
        raise SerializationError(msg)
    return ForExpression(
        quantifier=_deserialize_required_quantifier(self, data, "quantifier", "ForExpression"),
        variable=variable,
        iterable=_deserialize_required_expression(self, data, "iterable", "ForExpression"),
        body=_deserialize_required_expression(self, data, "body", "ForExpression"),
    )


def _deser_for_of_expression(self, data: dict[str, Any]):
    from yaraast.ast.conditions import ForOfExpression

    condition = data.get("condition")
    return ForOfExpression(
        quantifier=_deserialize_required_quantifier(self, data, "quantifier", "ForOfExpression"),
        string_set=_deserialize_required_string_set(self, data, "string_set", "ForOfExpression"),
        condition=_deserialize_optional_expression(self, condition, "ForOfExpression condition"),
    )


def _deser_at_expression(self, data: dict[str, Any]):
    from yaraast.ast.conditions import AtExpression

    raw_subject = data.get("string_id")
    if isinstance(raw_subject, dict):
        subject = _deserialize_required_expression(self, data, "string_id", "AtExpression")
    else:
        subject = _deserialize_nonempty_string_field(data, "string_id", "AtExpression")
    return AtExpression(
        string_id=subject,
        offset=_deserialize_required_expression(self, data, "offset", "AtExpression"),
    )


def _deser_in_expression(self, data: dict[str, Any]):
    from yaraast.ast.conditions import InExpression

    raw_subject = data.get("subject")
    if raw_subject is None and "string_id" in data:
        raw_subject = data["string_id"]
    if isinstance(raw_subject, dict):
        subject = _deserialize_required_expression_value(self, raw_subject, "InExpression subject")
    elif isinstance(raw_subject, str):
        subject = raw_subject
    else:
        msg = "InExpression subject must be a string or expression"
        raise SerializationError(msg)
    return InExpression(
        subject=subject,
        range=_deserialize_required_expression(self, data, "range", "InExpression"),
    )


def _deser_of_expression(self, data: dict[str, Any]):
    from yaraast.ast.conditions import OfExpression

    return OfExpression(
        quantifier=_deserialize_required_quantifier(self, data, "quantifier", "OfExpression"),
        string_set=_deserialize_required_string_set(self, data, "string_set", "OfExpression"),
    )


def _deser_module_reference(self, data: dict[str, Any]):
    from yaraast.ast.modules import ModuleReference

    return ModuleReference(
        module=_deserialize_nonempty_string_field(data, "module", "ModuleReference")
    )


def _deser_dictionary_access(self, data: dict[str, Any]):
    from yaraast.ast.modules import DictionaryAccess

    obj = _deserialize_required_expression(self, data, "object", "DictionaryAccess")
    key = _deserialize_dictionary_key(self, data)
    return DictionaryAccess(object=obj, key=key)


def _deser_defined_expression(self, data: dict[str, Any]):
    from yaraast.ast.operators import DefinedExpression

    expression = data.get("expression")
    if expression is None and "identifier" in data:
        expression = {"type": "Identifier", "name": data["identifier"]}
    if expression is None:
        msg = "DefinedExpression expression is required"
        raise SerializationError(msg)
    return DefinedExpression(
        expression=_deserialize_required_expression_value(
            self, expression, "DefinedExpression expression"
        )
    )


def _deser_string_operator_expression(self, data: dict[str, Any]):
    from yaraast.ast.operators import StringOperatorExpression

    left = data.get("left")
    right = data.get("right")
    if left is None and "subject" in data:
        left = data.get("subject")
    if right is None and "pattern" in data:
        right = {"type": "StringLiteral", "value": data.get("pattern", "")}
    if left is None:
        left = {"type": "Identifier", "name": "true"}
    if right is None:
        right = {"type": "Identifier", "name": "true"}
    return StringOperatorExpression(
        left=_deserialize_required_expression_value(self, left, "StringOperatorExpression left"),
        operator=_deserialize_nonempty_string_field(data, "operator", "StringOperatorExpression"),
        right=_deserialize_required_expression_value(self, right, "StringOperatorExpression right"),
    )


def _deser_extern_rule_reference(self, data: dict[str, Any]):
    from yaraast.ast.extern import ExternRuleReference

    rule_name = data.get("rule_name", data.get("name"))
    if rule_name is None:
        msg = "ExternRuleReference missing rule_name"
        raise SerializationError(msg)
    if not isinstance(rule_name, str):
        msg = "ExternRuleReference rule_name must be a string"
        raise SerializationError(msg)
    if not rule_name:
        msg = "ExternRuleReference rule_name must not be empty"
        raise SerializationError(msg)
    return ExternRuleReference(
        rule_name=rule_name,
        namespace=_deserialize_nullable_nonempty_string_field(
            data,
            "namespace",
            "ExternRuleReference",
        ),
    )


def _deser_with_statement(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import WithStatement

    return WithStatement(
        declarations=_deserialize_expression_list_field(
            self, data, "declarations", "WithStatement"
        ),
        body=_deserialize_required_expression(self, data, "body", "WithStatement"),
    )


def _deser_with_declaration(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import WithDeclaration

    return WithDeclaration(
        identifier=_deserialize_nonempty_string_field(data, "identifier", "WithDeclaration"),
        value=_deserialize_required_expression(self, data, "value", "WithDeclaration"),
    )


def _deser_array_comprehension(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import ArrayComprehension

    variable = _deserialize_optional_string_field(data, "variable", "ArrayComprehension")
    if "variable" in data and not variable:
        msg = "ArrayComprehension variable must not be empty"
        raise SerializationError(msg)
    return ArrayComprehension(
        expression=_deserialize_optional_expression(
            self, data.get("expression"), "ArrayComprehension expression"
        ),
        variable=variable,
        iterable=_deserialize_optional_expression(
            self, data.get("iterable"), "ArrayComprehension iterable"
        ),
        condition=_deserialize_optional_expression(
            self, data.get("condition"), "ArrayComprehension condition"
        ),
    )


def _deser_dict_comprehension(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import DictComprehension

    key_variable = _deserialize_optional_string_field(data, "key_variable", "DictComprehension")
    if "key_variable" in data and not key_variable:
        msg = "DictComprehension key_variable must not be empty"
        raise SerializationError(msg)
    value_variable = _deserialize_nullable_nonempty_string_field(
        data, "value_variable", "DictComprehension"
    )
    return DictComprehension(
        key_expression=_deserialize_optional_expression(
            self, data.get("key_expression"), "DictComprehension key_expression"
        ),
        value_expression=_deserialize_optional_expression(
            self, data.get("value_expression"), "DictComprehension value_expression"
        ),
        key_variable=key_variable,
        value_variable=value_variable,
        iterable=_deserialize_optional_expression(
            self, data.get("iterable"), "DictComprehension iterable"
        ),
        condition=_deserialize_optional_expression(
            self, data.get("condition"), "DictComprehension condition"
        ),
    )


def _deser_tuple_expression(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import TupleExpression

    return TupleExpression(
        elements=_deserialize_expression_list_field(self, data, "elements", "TupleExpression")
    )


def _deser_tuple_indexing(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import TupleIndexing

    return TupleIndexing(
        tuple_expr=_deserialize_required_expression(self, data, "tuple_expr", "TupleIndexing"),
        index=_deserialize_required_expression(self, data, "index", "TupleIndexing"),
    )


def _deser_list_expression(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import ListExpression

    return ListExpression(
        elements=_deserialize_expression_list_field(self, data, "elements", "ListExpression")
    )


def _deser_dict_expression(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import DictExpression

    return DictExpression(
        items=_deserialize_expression_list_field(self, data, "items", "DictExpression")
    )


def _deser_dict_item(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import DictItem

    return DictItem(
        key=_deserialize_required_expression(self, data, "key", "DictItem"),
        value=_deserialize_required_expression(self, data, "value", "DictItem"),
    )


def _deser_slice_expression(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import SliceExpression

    return SliceExpression(
        target=_deserialize_required_expression(self, data, "target", "SliceExpression"),
        start=_deserialize_optional_expression(self, data.get("start"), "SliceExpression start"),
        stop=_deserialize_optional_expression(self, data.get("stop"), "SliceExpression stop"),
        step=_deserialize_optional_expression(self, data.get("step"), "SliceExpression step"),
    )


def _deser_lambda_expression(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import LambdaExpression

    return LambdaExpression(
        parameters=_deserialize_nonempty_string_list_field(
            data,
            "parameters",
            "LambdaExpression",
        ),
        body=_deserialize_required_expression(self, data, "body", "LambdaExpression"),
    )


def _deser_pattern_match(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import PatternMatch

    return PatternMatch(
        value=_deserialize_required_expression(self, data, "value", "PatternMatch"),
        cases=_deserialize_expression_list_field(self, data, "cases", "PatternMatch"),
        default=_deserialize_optional_expression(self, data.get("default"), "PatternMatch default"),
    )


def _deser_match_case(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import MatchCase

    return MatchCase(
        pattern=_deserialize_required_expression(self, data, "pattern", "MatchCase"),
        result=_deserialize_required_expression(self, data, "result", "MatchCase"),
    )


def _deser_spread_operator(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import SpreadOperator

    return SpreadOperator(
        expression=_deserialize_required_expression(self, data, "expression", "SpreadOperator"),
        is_dict=_deserialize_bool_field(data, "is_dict", "SpreadOperator"),
    )


_EXPR_DESERIALIZERS: dict[str, Any] = {
    "BinaryExpression": _deser_binary_expression,
    "UnaryExpression": _deser_unary_expression,
    "ParenthesesExpression": _deser_parentheses_expression,
    "SetExpression": _deser_set_expression,
    "RangeExpression": _deser_range_expression,
    "FunctionCall": _deser_function_call,
    "ArrayAccess": _deser_array_access,
    "MemberAccess": _deser_member_access,
    "Identifier": _deser_identifier,
    "StringIdentifier": _deser_string_identifier,
    "StringWildcard": _deser_string_wildcard,
    "StringCount": _deser_string_count,
    "StringOffset": _deser_string_offset,
    "StringLength": _deser_string_length,
    "IntegerLiteral": _deser_integer_literal,
    "DoubleLiteral": _deser_double_literal,
    "StringLiteral": _deser_string_literal,
    "RegexLiteral": _deser_regex_literal,
    "BooleanLiteral": _deser_boolean_literal,
    "ForExpression": _deser_for_expression,
    "ForOfExpression": _deser_for_of_expression,
    "AtExpression": _deser_at_expression,
    "InExpression": _deser_in_expression,
    "OfExpression": _deser_of_expression,
    "ModuleReference": _deser_module_reference,
    "DictionaryAccess": _deser_dictionary_access,
    "DefinedExpression": _deser_defined_expression,
    "StringOperatorExpression": _deser_string_operator_expression,
    "ExternRuleReference": _deser_extern_rule_reference,
    "WithStatement": _deser_with_statement,
    "WithDeclaration": _deser_with_declaration,
    "ArrayComprehension": _deser_array_comprehension,
    "DictComprehension": _deser_dict_comprehension,
    "TupleExpression": _deser_tuple_expression,
    "TupleIndexing": _deser_tuple_indexing,
    "ListExpression": _deser_list_expression,
    "DictExpression": _deser_dict_expression,
    "DictItem": _deser_dict_item,
    "SliceExpression": _deser_slice_expression,
    "LambdaExpression": _deser_lambda_expression,
    "PatternMatch": _deser_pattern_match,
    "MatchCase": _deser_match_case,
    "SpreadOperator": _deser_spread_operator,
}


class JsonSerializerDeserializeMixin:
    """Mixin with JSON deserialization helpers."""

    def _apply_node_metadata(self, node: ASTNode, data: dict[str, Any]) -> Any:
        return _apply_node_metadata(self, node, data)

    def _deserialize_import(self, data: dict[str, Any]):
        from yaraast.ast.rules import Import

        return self._apply_node_metadata(
            Import(
                module=_deserialize_nonempty_string_field(data, "module", "Import"),
                alias=_deserialize_nullable_nonempty_string_field(data, "alias", "Import"),
            ),
            data,
        )

    def _deserialize_include(self, data: dict[str, Any]):
        from yaraast.ast.rules import Include

        return self._apply_node_metadata(
            Include(path=_deserialize_nonempty_string_field(data, "path", "Include")), data
        )

    def _deserialize_rule(self, data: dict[str, Any]):
        from yaraast.ast.rules import Rule

        data = _deserialize_object(data, "Rule")
        meta_data = data.get("meta", [])
        if isinstance(meta_data, dict):
            meta = [
                self._deserialize_meta({"key": key, "value": value})
                for key, value in meta_data.items()
            ]
        elif isinstance(meta_data, list):
            meta = [self._deserialize_meta(m) for m in meta_data]
        elif "meta" in data:
            msg = "Rule meta must be a list or dictionary"
            raise SerializationError(msg)
        else:
            meta = []

        strings = [
            self._deserialize_string(s) for s in _deserialize_list_field(data, "strings", "Rule")
        ]
        condition_data = data.get("condition")
        condition = _deserialize_optional_expression(self, condition_data, "Rule condition")

        tags = [self._deserialize_tag(t) for t in _deserialize_list_field(data, "tags", "Rule")]
        pragmas = [
            self._deserialize_in_rule_pragma(p)
            for p in _deserialize_list_field(data, "pragmas", "Rule")
        ]

        return self._apply_node_metadata(
            Rule(
                name=_deserialize_nonempty_string_field(data, "name", "Rule"),
                modifiers=_deserialize_nonempty_string_list_field(data, "modifiers", "Rule"),
                tags=tags,
                meta=meta,
                strings=strings,
                condition=condition,
                pragmas=pragmas,
            ),
            data,
        )

    def _deserialize_tag(self, data: dict[str, Any]):
        from yaraast.ast.rules import Tag

        data = _deserialize_object(data, "Tag")
        node_type = data.get("type")
        if node_type is not None and node_type != "Tag":
            msg = "Rule tags must contain Tag nodes"
            raise SerializationError(msg)
        return self._apply_node_metadata(
            Tag(name=_deserialize_nonempty_string_field(data, "name", "Tag")), data
        )

    def _deserialize_meta(self, data: dict[str, Any]):
        from yaraast.ast.modifiers import MetaEntry

        data = _deserialize_object(data, "Meta")
        node_type = data.get("type")
        if node_type is not None and node_type not in {"Meta", "MetaEntry"}:
            msg = "Meta type must be Meta or MetaEntry"
            raise SerializationError(msg)
        if (
            node_type == "Meta"
            or data.get("leading_comments")
            or data.get("trailing_comment")
            or data.get("location")
        ):
            from yaraast.ast.meta import Meta

            return self._apply_node_metadata(
                Meta(
                    _deserialize_nonempty_string_field(data, "key", "Meta"),
                    _deserialize_meta_value(data),
                ),
                data,
            )
        return MetaEntry.from_key_value(
            _deserialize_nonempty_string_field(data, "key", "Meta"),
            _deserialize_meta_entry_value(data),
            deserialize_meta_scope(_deserialize_nullable_string_field(data, "scope", "Meta")),
        )

    def _deserialize_string(self, data: dict[str, Any]):
        data = _deserialize_object(data, "String")
        string_type = data.get("type")
        context = string_type if isinstance(string_type, str) else "String"
        modifiers = [
            self._deserialize_modifier(m)
            for m in _deserialize_list_field(data, "modifiers", context)
        ]

        if string_type == "PlainString":
            from yaraast.ast.strings import PlainString

            return self._apply_node_metadata(
                PlainString(
                    identifier=_deserialize_nonempty_string_field(
                        data,
                        "identifier",
                        "PlainString",
                    ),
                    value=_deserialize_plain_string_value(data),
                    modifiers=modifiers,
                    is_anonymous=_deserialize_is_anonymous(data),
                ),
                data,
            )
        if string_type == "HexString":
            from yaraast.ast.strings import HexString

            tokens = [
                self._deserialize_hex_token(t)
                for t in _deserialize_list_field(data, "tokens", "HexString")
            ]
            return self._apply_node_metadata(
                HexString(
                    identifier=_deserialize_nonempty_string_field(
                        data,
                        "identifier",
                        "HexString",
                    ),
                    tokens=tokens,
                    modifiers=modifiers,
                    is_anonymous=_deserialize_is_anonymous(data),
                ),
                data,
            )
        if string_type == "RegexString":
            from yaraast.ast.strings import RegexString

            return self._apply_node_metadata(
                RegexString(
                    identifier=_deserialize_nonempty_string_field(
                        data,
                        "identifier",
                        "RegexString",
                    ),
                    regex=_deserialize_nonempty_string_field(data, "regex", "RegexString"),
                    modifiers=modifiers,
                    is_anonymous=_deserialize_is_anonymous(data),
                ),
                data,
            )
        if string_type == "StringDefinition":
            from yaraast.ast.strings import StringDefinition

            return self._apply_node_metadata(
                StringDefinition(
                    identifier=_deserialize_nonempty_string_field(
                        data,
                        "identifier",
                        "StringDefinition",
                    ),
                    modifiers=modifiers,
                    is_anonymous=_deserialize_is_anonymous(data),
                ),
                data,
            )
        msg = f"Unknown string type: {string_type}"
        raise SerializationError(msg)

    def _deserialize_modifier_value(self, name: str, value: Any) -> Any:
        return deserialize_legacy_modifier_value(name, value)

    def _format_unknown_modifier(self, name: str, value: Any) -> str:
        if value is None:
            return name
        if isinstance(value, tuple) and len(value) == 2:
            return f"{name}({value[0]}-{value[1]})"
        if isinstance(value, str):
            return f'{name}("{escape_string_source_value(value)}")'
        return f"{name}({value})"

    def _deserialize_modifier(self, data: Any):
        from yaraast.ast.modifiers import StringModifier

        if isinstance(data, dict):
            name = _deserialize_nonempty_string_field(data, "name", "StringModifier")
            value = self._deserialize_modifier_value(name, data.get("value"))
        elif isinstance(data, str):
            if not data:
                msg = "StringModifier name must not be empty"
                raise SerializationError(msg)
            name = data
            value = None
        else:
            msg = "StringModifier must be a string or object"
            raise SerializationError(msg)
        try:
            return StringModifier.from_name_value(name, value)
        except (ValueError, ValidationError):
            return self._format_unknown_modifier(name, value)

    def _deserialize_hex_token(self, data: dict[str, Any]):
        data = _deserialize_object(data, "Hex token")
        hex_kind = data.get("type")

        if hex_kind == "HexToken":
            from yaraast.ast.strings import HexToken

            return self._apply_node_metadata(HexToken(), data)
        if hex_kind == "HexByte":
            from yaraast.ast.strings import HexByte

            return self._apply_node_metadata(
                HexByte(value=_deserialize_hex_byte_value(data, "HexByte")), data
            )
        if hex_kind == "HexWildcard":
            from yaraast.ast.strings import HexWildcard

            return self._apply_node_metadata(HexWildcard(), data)
        if hex_kind == "HexJump":
            from yaraast.ast.strings import HexJump

            min_jump, max_jump = _deserialize_hex_jump_bounds(data)
            return self._apply_node_metadata(
                HexJump(min_jump=min_jump, max_jump=max_jump),
                data,
            )
        if hex_kind == "HexNibble":
            from yaraast.ast.strings import HexNibble

            return self._apply_node_metadata(
                HexNibble(
                    high=_deserialize_hex_nibble_high(data),
                    value=_deserialize_hex_nibble_value(data),
                ),
                data,
            )
        if hex_kind == "HexNegatedByte":
            from yaraast.ast.strings import HexNegatedByte

            return self._apply_node_metadata(
                HexNegatedByte(value=_deserialize_hex_negated_value(data)),
                data,
            )
        if hex_kind == "HexAlternative":
            from yaraast.ast.strings import HexAlternative

            alternatives = [
                [self._deserialize_hex_token(t) for t in self._coerce_hex_alternative_branch(alt)]
                for alt in _deserialize_list_field(data, "alternatives", "HexAlternative")
            ]
            return self._apply_node_metadata(HexAlternative(alternatives=alternatives), data)
        msg = f"Unknown hex token type: {hex_kind}"
        raise SerializationError(msg)

    def _coerce_hex_alternative_branch(self, alternative):
        if isinstance(alternative, list):
            return alternative
        return [alternative]

    def _deserialize_extern_import(self, data: dict[str, Any]):
        from yaraast.ast.extern import ExternImport

        module_path = data.get("module_path", data.get("module"))
        if module_path is None:
            msg = "ExternImport missing module_path"
            raise SerializationError(msg)
        if not isinstance(module_path, str):
            msg = "ExternImport module_path must be a string"
            raise SerializationError(msg)
        if not module_path.strip():
            msg = "ExternImport module_path must not be empty"
            raise SerializationError(msg)
        alias = _deserialize_nullable_nonempty_string_field(
            data,
            "alias",
            "ExternImport",
        )
        if alias is not None and not alias.strip():
            msg = "ExternImport alias must not be empty"
            raise SerializationError(msg)
        rules = _deserialize_nonempty_string_list_field(data, "rules", "ExternImport")
        if any(not rule.strip() for rule in rules):
            msg = "ExternImport rules must contain non-empty strings"
            raise SerializationError(msg)
        return self._apply_node_metadata(
            ExternImport(
                module_path=module_path,
                alias=alias,
                rules=rules,
            ),
            data,
        )

    def _deserialize_extern_rule(self, data: dict[str, Any]):
        from yaraast.ast.extern import ExternRule
        from yaraast.ast.rules import Rule

        return self._apply_node_metadata(
            ExternRule(
                name=_deserialize_nonempty_string_field(data, "name", "ExternRule"),
                modifiers=Rule._normalize_modifiers(
                    _deserialize_nonempty_string_list_field(data, "modifiers", "ExternRule")
                ),
                namespace=_deserialize_nullable_nonempty_string_field(
                    data,
                    "namespace",
                    "ExternRule",
                ),
            ),
            data,
        )

    def _deserialize_extern_namespace(self, data: dict[str, Any]):
        from yaraast.ast.extern import ExternNamespace

        return self._apply_node_metadata(
            ExternNamespace(
                name=_deserialize_nonempty_string_field(data, "name", "ExternNamespace"),
                extern_rules=[
                    self._deserialize_extern_rule(rule)
                    for rule in _deserialize_list_field(data, "extern_rules", "ExternNamespace")
                ],
            ),
            data,
        )

    def _deserialize_pragma(self, data: dict[str, Any]):
        from yaraast.ast.pragmas import (
            ConditionalDirective,
            CustomPragma,
            DefineDirective,
            IncludeOncePragma,
            Pragma,
            PragmaType,
            UndefDirective,
        )

        data = _deserialize_object(data, "Pragma")
        pragma_type = _deserialize_pragma_type(data)
        scope = _deserialize_pragma_scope(data.get("scope"), "Pragma")
        name = _deserialize_optional_string_field(data, "name", "Pragma", pragma_type.value)
        if not name:
            msg = "Pragma name must not be empty"
            raise SerializationError(msg)
        arguments = _deserialize_string_list_field(data, "arguments", "Pragma")

        if pragma_type == PragmaType.INCLUDE_ONCE:
            pragma = IncludeOncePragma()
        elif pragma_type == PragmaType.DEFINE and "macro_name" in data:
            pragma = DefineDirective(
                macro_name=_deserialize_nonempty_string_field(data, "macro_name", "Pragma"),
                macro_value=_deserialize_nullable_string_field(data, "macro_value", "Pragma"),
            )
        elif pragma_type == PragmaType.UNDEF and "macro_name" in data:
            pragma = UndefDirective(
                macro_name=_deserialize_nonempty_string_field(data, "macro_name", "Pragma")
            )
        elif pragma_type in {PragmaType.IFDEF, PragmaType.IFNDEF, PragmaType.ENDIF}:
            condition = (
                _deserialize_nonempty_string_field(data, "condition", "Pragma")
                if pragma_type in {PragmaType.IFDEF, PragmaType.IFNDEF}
                else _deserialize_nullable_nonempty_string_field(data, "condition", "Pragma")
            )
            pragma = ConditionalDirective(
                pragma_type,
                condition=condition,
            )
        elif pragma_type == PragmaType.CUSTOM:
            pragma = CustomPragma(
                name=name,
                arguments=arguments,
                parameters=_deserialize_dict_field(data, "parameters", "Pragma"),
                scope=scope,
            )
        else:
            pragma = Pragma(
                pragma_type=pragma_type,
                name=name,
                arguments=arguments,
                scope=scope,
            )
        pragma.scope = scope
        return self._apply_node_metadata(pragma, data)

    def _deserialize_in_rule_pragma(self, data: dict[str, Any]):
        from yaraast.ast.pragmas import InRulePragma

        return self._apply_node_metadata(
            InRulePragma(
                pragma=self._deserialize_pragma(
                    _deserialize_required_field(data, "pragma", "InRulePragma")
                ),
                position=self._deserialize_in_rule_pragma_position(data),
            ),
            data,
        )

    def _deserialize_in_rule_pragma_position(self, data: dict[str, Any]) -> str:
        position = _deserialize_optional_string_field(
            data,
            "position",
            "InRulePragma",
            "before_strings",
        )
        if not position:
            msg = "InRulePragma position must not be empty"
            raise SerializationError(msg)
        return position

    def _deserialize_pragma_block(self, data: dict[str, Any]):
        from yaraast.ast.pragmas import PragmaBlock

        return self._apply_node_metadata(
            PragmaBlock(
                pragmas=[
                    self._deserialize_pragma(pragma)
                    for pragma in _deserialize_list_field(data, "pragmas", "PragmaBlock")
                ],
                scope=_deserialize_pragma_scope(data.get("scope"), "PragmaBlock"),
            ),
            data,
        )

    def _deserialize_expression(self, data: dict[str, Any]):
        if data is None or data == {}:
            return None
        data = _deserialize_object(data, "Expression")

        expr_type = data.get("type")
        factory = _EXPR_DESERIALIZERS.get(expr_type)
        if factory:
            node = factory(self, data)
            if isinstance(node, ASTNode):
                return self._apply_node_metadata(node, data)
            return node

        if expr_type == "Expression":
            from yaraast.ast.expressions import Expression

            return self._apply_node_metadata(Expression(), data)
        if expr_type == "Condition":
            from yaraast.ast.conditions import Condition

            return self._apply_node_metadata(Condition(), data)

        msg = f"Unknown expression type: {expr_type}"
        raise SerializationError(msg)
