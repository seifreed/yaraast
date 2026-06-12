"""Deserialization helpers for JSON serializer."""

from __future__ import annotations

import math
from typing import Any

from yaraast.ast.base import ASTNode
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.errors import SerializationError, ValidationError
from yaraast.serialization._serialization_primitives import (
    _HEX_CHARS,
    _deserialize_boolean_literal_value,
    _deserialize_comment_multiline,
    _deserialize_comment_text,
    _deserialize_dict_field,
    _deserialize_double_literal_value,
    _deserialize_integer_literal_value,
    _deserialize_is_anonymous,
    _deserialize_list_field,
    _deserialize_location,
    _deserialize_meta_entry_value,
    _deserialize_meta_value,
    _deserialize_nullable_string_field,
    _deserialize_object,
    _deserialize_plain_string_raw_bytes,
    _deserialize_plain_string_value,
    _deserialize_required_field,
    _deserialize_string_field,
    _deserialize_string_list_field,
    _is_negated_nibble_pattern,
    _normalize_rule_modifier_text,
    _validate_extern_import_rule_identifiers,
    _validate_extern_rule_identifier_text,
    _validate_function_identifier_text,
    _validate_local_identifier_list,
    _validate_local_identifier_text,
    _validate_loop_variable_text,
    _validate_namespace_identifier_text,
    _validate_optional_namespace_identifier_text,
    _validate_quantifier_value,
    _validate_string_reference_text,
    _validate_unique_rule_tags,
    _validate_yara_identifier_text,
)
from yaraast.serialization.meta_scopes import deserialize_meta_scope
from yaraast.serialization.modifier_values import deserialize_legacy_modifier_value
from yaraast.serialization.pragma_scopes import deserialize_pragma_scope
from yaraast.string_escaping import escape_string_source_value

_WHITESPACE_SIGNIFICANT_NONEMPTY_FIELDS = frozenset(
    {
        "RegexLiteral pattern",
        "RegexString regex",
    }
)


def _is_empty_nonempty_field(text: str, context: str, field: str | None = None) -> bool:
    label = f"{context} {field}" if field is not None else context
    return not text or (not text.strip() and label not in _WHITESPACE_SIGNIFICANT_NONEMPTY_FIELDS)


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


def _deserialize_nullable_expression_field(
    self,
    data: dict[str, Any],
    field: str,
    context: str,
) -> Any:
    return _deserialize_optional_expression(
        self,
        _deserialize_required_field(data, field, context),
        f"{context} {field}",
    )


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


def _deserialize_required_quantifier(
    self,
    data: dict[str, Any],
    field: str,
    context: str,
    *,
    allow_percentage: bool,
) -> Any:
    value = _deserialize_required_field(data, field, context)
    if isinstance(value, bool | list):
        msg = f"{context} {field} must be a string, number, or expression"
        raise SerializationError(msg)
    if isinstance(value, str) and _is_empty_nonempty_field(value, context, field):
        msg = f"{context} {field} must not be empty"
        raise SerializationError(msg)
    if isinstance(value, float) and not math.isfinite(value):
        msg = f"{context} {field} must be finite"
        raise SerializationError(msg)
    quantifier = _deserialize_ast_value(self, value, f"{context} {field}")
    if quantifier is not None:
        return _validate_quantifier_value(
            quantifier,
            f"{context} {field}",
            allow_percentage=allow_percentage,
        )
    msg = f"{context} {field} is required"
    raise SerializationError(msg)


def _deserialize_string_set_item(self, value: Any, context: str) -> Any:
    if value is None or value == {}:
        msg = f"{context} must contain values"
        raise SerializationError(msg)
    if isinstance(value, str):
        if not value.strip():
            msg = f"{context} must contain values"
            raise SerializationError(msg)
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
        if not value.strip():
            msg = f"{field_context} must contain values"
            raise SerializationError(msg)
        return value
    if isinstance(value, dict):
        return _deserialize_required_expression_value(self, value, field_context)
    if isinstance(value, list):
        if not value:
            msg = f"{field_context} must contain values"
            raise SerializationError(msg)
        return [_deserialize_string_set_item(self, item, field_context) for item in value]
    msg = f"{field_context} must be a string, expression, or list of strings/expressions"
    raise SerializationError(msg)


def _deserialize_dictionary_key(self, data: dict[str, Any]) -> str | ASTNode:
    if "key" not in data:
        msg = "DictionaryAccess key must be a string or expression"
        raise SerializationError(msg)
    key = data["key"]
    if isinstance(key, str):
        if not key.strip():
            msg = "DictionaryAccess key must not be empty"
            raise SerializationError(msg)
        return key
    if isinstance(key, dict):
        expression = self._deserialize_expression(key)
        if expression is not None:
            return expression
    msg = "DictionaryAccess key must be a string or expression"
    raise SerializationError(msg)


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
                    for c in _deserialize_required_list_field(data, "comments", "CommentGroup")
                ]
            ),
            data,
        )
    msg = f"Unknown comment metadata type: {node_type}"
    raise SerializationError(msg)


def _deserialize_nonempty_string_field(data: dict[str, Any], field: str, context: str) -> str:
    text = _deserialize_string_field(data, field, context)
    if _is_empty_nonempty_field(text, context, field):
        msg = f"{context} {field} must not be empty"
        raise SerializationError(msg)
    return text


def _deserialize_nullable_nonempty_string_field(
    data: dict[str, Any], field: str, context: str
) -> str | None:
    text = _deserialize_nullable_string_field(data, field, context)
    if text is not None and _is_empty_nonempty_field(text, context, field):
        msg = f"{context} {field} must not be empty"
        raise SerializationError(msg)
    return text


def _deserialize_required_nullable_string_field(
    data: dict[str, Any], field: str, context: str
) -> str | None:
    text = _deserialize_required_field(data, field, context)
    if text is None or isinstance(text, str):
        return text
    msg = f"{context} {field} must be a string"
    raise SerializationError(msg)


def _deserialize_required_nullable_nonempty_string_field(
    data: dict[str, Any], field: str, context: str
) -> str | None:
    text = _deserialize_required_field(data, field, context)
    if text is None:
        return None
    if not isinstance(text, str):
        msg = f"{context} {field} must be a string"
        raise SerializationError(msg)
    if _is_empty_nonempty_field(text, context, field):
        msg = f"{context} {field} must not be empty"
        raise SerializationError(msg)
    return text


def _deserialize_nonempty_string_list_field(
    data: dict[str, Any], field: str, context: str
) -> list[str]:
    items = _deserialize_string_list_field(data, field, context)
    if any(_is_empty_nonempty_field(item, context, field) for item in items):
        msg = f"{context} {field} must contain non-empty strings"
        raise SerializationError(msg)
    return items


def _deserialize_pragma_type(data: dict[str, Any]):
    from yaraast.ast.pragmas import PragmaType

    value = _deserialize_nonempty_string_field(data, "pragma_type", "Pragma")
    try:
        return PragmaType(value.lower())
    except ValueError as exc:
        msg = "Pragma pragma_type must be a valid pragma type"
        raise SerializationError(msg) from exc


def _deserialize_required_string_list_field(
    data: dict[str, Any], field: str, context: str
) -> list[str]:
    _deserialize_required_field(data, field, context)
    return _deserialize_string_list_field(data, field, context)


def _deserialize_required_nonempty_string_list_field(
    data: dict[str, Any], field: str, context: str
) -> list[str]:
    _deserialize_required_field(data, field, context)
    return _deserialize_nonempty_string_list_field(data, field, context)


def _deserialize_required_list_field(data: dict[str, Any], field: str, context: str) -> list[Any]:
    _deserialize_required_field(data, field, context)
    return _deserialize_list_field(data, field, context)


def _deserialize_pragma_node_type(data: dict[str, Any]) -> None:
    node_type = _deserialize_string_field(data, "type", "Pragma")
    if node_type == "Pragma":
        return
    msg = "Pragma type must be Pragma"
    raise SerializationError(msg)


def _deserialize_pragma_scope(value: Any, context: str):
    return deserialize_pragma_scope(value, context)


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


def _deserialize_hex_nibble_value(data: dict[str, Any]) -> int | str:
    value = _deserialize_required_field(data, "value", "HexNibble")
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xF:
        return value
    if isinstance(value, str) and len(value) == 1 and value in _HEX_CHARS:
        return value
    msg = "HexNibble value must be a nibble"
    raise SerializationError(msg)


def _deserialize_hex_nibble_high(data: dict[str, Any]) -> bool:
    value = _deserialize_required_field(data, "high", "HexNibble")
    if isinstance(value, bool):
        return value
    msg = "HexNibble high must be a boolean"
    raise SerializationError(msg)


def _deserialize_string_modifiers(serializer: Any, data: dict[str, Any], context: str) -> list[Any]:
    raw_modifiers = _deserialize_required_field(data, "modifiers", context)
    if not isinstance(raw_modifiers, list):
        msg = f"{context} modifiers must be a list"
        raise SerializationError(msg)
    return [serializer._deserialize_modifier(modifier) for modifier in raw_modifiers]


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

    raw_elements = _deserialize_required_field(data, "elements", "SetExpression")
    if not isinstance(raw_elements, list):
        msg = "SetExpression elements must be a list"
        raise SerializationError(msg)
    elements = []
    for item in raw_elements:
        expression = self._deserialize_expression(item)
        if expression is None:
            msg = "SetExpression elements must contain expressions"
            raise SerializationError(msg)
        elements.append(expression)
    return SetExpression(elements=elements)


def _deser_range_expression(self, data: dict[str, Any]):
    from yaraast.ast.expressions import RangeExpression

    low = _deserialize_required_expression(self, data, "low", "RangeExpression")
    high = _deserialize_required_expression(self, data, "high", "RangeExpression")
    return RangeExpression(low=low, high=high)


def _deser_function_call(self, data: dict[str, Any]):
    from yaraast.ast.expressions import FunctionCall

    raw_arguments = _deserialize_required_field(data, "arguments", "FunctionCall")
    if not isinstance(raw_arguments, list):
        msg = "FunctionCall arguments must be a list"
        raise SerializationError(msg)
    args = []
    for item in raw_arguments:
        expression = self._deserialize_expression(item)
        if expression is None:
            msg = "FunctionCall arguments must contain expressions"
            raise SerializationError(msg)
        args.append(expression)
    function = _deserialize_nonempty_string_field(data, "function", "FunctionCall")
    receiver = _deserialize_nullable_expression_field(self, data, "receiver", "FunctionCall")
    return FunctionCall(
        function=_validate_function_identifier_text(function, receiver),
        arguments=args,
        receiver=receiver,
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
        member=_validate_yara_identifier_text(
            _deserialize_nonempty_string_field(data, "member", "MemberAccess"),
            "member",
        ),
    )


def _deser_identifier(self, data: dict[str, Any]):
    from yaraast.ast.expressions import Identifier

    return Identifier(name=_deserialize_nonempty_string_field(data, "name", "Identifier"))


def _deser_string_identifier(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringIdentifier

    return StringIdentifier(
        name=_validate_string_reference_text(
            _deserialize_nonempty_string_field(data, "name", "StringIdentifier")
        )
    )


def _deser_string_wildcard(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringWildcard

    return StringWildcard(
        pattern=_validate_string_reference_text(
            _deserialize_nonempty_string_field(data, "pattern", "StringWildcard"),
            allow_wildcard=True,
        )
    )


def _deser_string_count(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringCount

    return StringCount(
        string_id=_validate_string_reference_text(
            _deserialize_nonempty_string_field(data, "string_id", "StringCount"),
            allow_placeholder=True,
        )
    )


def _deser_string_offset(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringOffset

    return StringOffset(
        string_id=_validate_string_reference_text(
            _deserialize_nonempty_string_field(data, "string_id", "StringOffset"),
            allow_placeholder=True,
        ),
        index=_deserialize_nullable_expression_field(self, data, "index", "StringOffset"),
    )


def _deser_string_length(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringLength

    return StringLength(
        string_id=_validate_string_reference_text(
            _deserialize_nonempty_string_field(data, "string_id", "StringLength"),
            allow_placeholder=True,
        ),
        index=_deserialize_nullable_expression_field(self, data, "index", "StringLength"),
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
        modifiers=_deserialize_string_field(data, "modifiers", "RegexLiteral"),
    )


def _deser_boolean_literal(self, data: dict[str, Any]):
    from yaraast.ast.expressions import BooleanLiteral

    return BooleanLiteral(value=_deserialize_boolean_literal_value(data))


def _deser_for_expression(self, data: dict[str, Any]):
    from yaraast.ast.conditions import ForExpression

    return ForExpression(
        quantifier=_deserialize_required_quantifier(
            self,
            data,
            "quantifier",
            "ForExpression",
            allow_percentage=False,
        ),
        variable=_validate_loop_variable_text(
            _deserialize_nonempty_string_field(data, "variable", "ForExpression")
        ),
        iterable=_deserialize_required_expression(self, data, "iterable", "ForExpression"),
        body=_deserialize_required_expression(self, data, "body", "ForExpression"),
    )


def _deser_for_of_expression(self, data: dict[str, Any]):
    from yaraast.ast.conditions import ForOfExpression

    return ForOfExpression(
        quantifier=_deserialize_required_quantifier(
            self,
            data,
            "quantifier",
            "ForOfExpression",
            allow_percentage=True,
        ),
        string_set=_deserialize_required_string_set(self, data, "string_set", "ForOfExpression"),
        condition=_deserialize_nullable_expression_field(
            self, data, "condition", "ForOfExpression"
        ),
    )


def _deser_at_expression(self, data: dict[str, Any]):
    from yaraast.ast.conditions import AtExpression

    raw_subject = data.get("string_id")
    if isinstance(raw_subject, dict):
        subject = _deserialize_required_expression(self, data, "string_id", "AtExpression")
    else:
        subject = _validate_string_reference_text(
            _deserialize_nonempty_string_field(data, "string_id", "AtExpression")
        )
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
        if not raw_subject.strip():
            msg = "InExpression subject must not be empty"
            raise SerializationError(msg)
        subject = _validate_string_reference_text(raw_subject)
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
        quantifier=_deserialize_required_quantifier(
            self,
            data,
            "quantifier",
            "OfExpression",
            allow_percentage=True,
        ),
        string_set=_deserialize_required_string_set(self, data, "string_set", "OfExpression"),
    )


def _deser_module_reference(self, data: dict[str, Any]):
    from yaraast.ast.modules import ModuleReference

    return ModuleReference(
        module=_validate_yara_identifier_text(
            _deserialize_nonempty_string_field(data, "module", "ModuleReference"),
            "module",
        )
    )


def _deser_dictionary_access(self, data: dict[str, Any]):
    from yaraast.ast.modules import DictionaryAccess

    obj = _deserialize_required_expression(self, data, "object", "DictionaryAccess")
    key = _deserialize_dictionary_key(self, data)
    return DictionaryAccess(object=obj, key=key)


def _deser_defined_expression(self, data: dict[str, Any]):
    from yaraast.ast.operators import DefinedExpression

    return DefinedExpression(
        expression=_deserialize_required_expression(
            self,
            data,
            "expression",
            "DefinedExpression",
        )
    )


def _deser_string_operator_expression(self, data: dict[str, Any]):
    from yaraast.ast.operators import StringOperatorExpression

    return StringOperatorExpression(
        left=_deserialize_required_expression(
            self,
            data,
            "left",
            "StringOperatorExpression",
        ),
        operator=_deserialize_nonempty_string_field(data, "operator", "StringOperatorExpression"),
        right=_deserialize_required_expression(
            self,
            data,
            "right",
            "StringOperatorExpression",
        ),
    )


def _deser_extern_rule_reference(self, data: dict[str, Any]):
    from yaraast.ast.extern import ExternRuleReference

    rule_name = data.get("rule_name", data.get("name"))
    if rule_name is None:
        msg = "ExternRuleReference missing rule_name"
        raise SerializationError(msg)
    rule_field = "rule_name" if "rule_name" in data else "name"
    if not isinstance(rule_name, str):
        msg = "ExternRuleReference rule_name must be a string"
        raise SerializationError(msg)
    return ExternRuleReference(
        rule_name=_deserialize_nonempty_string_field(
            data,
            rule_field,
            "ExternRuleReference",
        ),
        namespace=_deserialize_required_nullable_nonempty_string_field(
            data,
            "namespace",
            "ExternRuleReference",
        ),
    )


def _deser_with_statement(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import WithStatement

    raw_declarations = _deserialize_required_field(data, "declarations", "WithStatement")
    if not isinstance(raw_declarations, list):
        msg = "WithStatement declarations must be a list"
        raise SerializationError(msg)
    declarations = []
    for item in raw_declarations:
        expression = self._deserialize_expression(item)
        if expression is None:
            msg = "WithStatement declarations must contain expressions"
            raise SerializationError(msg)
        declarations.append(expression)
    return WithStatement(
        declarations=declarations,
        body=_deserialize_required_expression(self, data, "body", "WithStatement"),
    )


def _deser_with_declaration(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import WithDeclaration

    return WithDeclaration(
        identifier=_validate_local_identifier_text(
            _deserialize_nonempty_string_field(data, "identifier", "WithDeclaration"),
            allow_string_identifier=True,
        ),
        value=_deserialize_required_expression(self, data, "value", "WithDeclaration"),
    )


def _deser_array_comprehension(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import ArrayComprehension

    expression = None
    expression_present = "expression" in data
    if expression_present:
        expression = _deserialize_nullable_expression_field(
            self, data, "expression", "ArrayComprehension"
        )

    iterable = None
    iterable_present = "iterable" in data
    if iterable_present:
        iterable = _deserialize_nullable_expression_field(
            self, data, "iterable", "ArrayComprehension"
        )

    condition = None
    condition_present = "condition" in data
    if condition_present:
        condition = _deserialize_nullable_expression_field(
            self, data, "condition", "ArrayComprehension"
        )

    variable = _validate_local_identifier_text(
        _deserialize_nonempty_string_field(data, "variable", "ArrayComprehension")
    )
    if not expression_present:
        expression = _deserialize_nullable_expression_field(
            self, data, "expression", "ArrayComprehension"
        )
    if not iterable_present:
        iterable = _deserialize_nullable_expression_field(
            self, data, "iterable", "ArrayComprehension"
        )
    if not condition_present:
        condition = _deserialize_nullable_expression_field(
            self, data, "condition", "ArrayComprehension"
        )

    return ArrayComprehension(
        expression=expression,
        variable=variable,
        iterable=iterable,
        condition=condition,
    )


def _deser_dict_comprehension(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import DictComprehension

    key_expression = None
    key_expression_present = "key_expression" in data
    if key_expression_present:
        key_expression = _deserialize_nullable_expression_field(
            self, data, "key_expression", "DictComprehension"
        )

    value_expression = None
    value_expression_present = "value_expression" in data
    if value_expression_present:
        value_expression = _deserialize_nullable_expression_field(
            self, data, "value_expression", "DictComprehension"
        )

    iterable = None
    iterable_present = "iterable" in data
    if iterable_present:
        iterable = _deserialize_nullable_expression_field(
            self, data, "iterable", "DictComprehension"
        )

    condition = None
    condition_present = "condition" in data
    if condition_present:
        condition = _deserialize_nullable_expression_field(
            self, data, "condition", "DictComprehension"
        )

    key_variable = _validate_local_identifier_text(
        _deserialize_nonempty_string_field(
            data,
            "key_variable",
            "DictComprehension",
        )
    )
    raw_value_variable = _deserialize_required_nullable_nonempty_string_field(
        data, "value_variable", "DictComprehension"
    )
    value_variable = (
        _validate_local_identifier_text(raw_value_variable)
        if raw_value_variable is not None
        else None
    )
    if not key_expression_present:
        key_expression = _deserialize_nullable_expression_field(
            self, data, "key_expression", "DictComprehension"
        )
    if not value_expression_present:
        value_expression = _deserialize_nullable_expression_field(
            self, data, "value_expression", "DictComprehension"
        )
    if not iterable_present:
        iterable = _deserialize_nullable_expression_field(
            self, data, "iterable", "DictComprehension"
        )
    if not condition_present:
        condition = _deserialize_nullable_expression_field(
            self, data, "condition", "DictComprehension"
        )

    return DictComprehension(
        key_expression=key_expression,
        value_expression=value_expression,
        key_variable=key_variable,
        value_variable=value_variable,
        iterable=iterable,
        condition=condition,
    )


def _deser_tuple_expression(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import TupleExpression

    raw_elements = _deserialize_required_field(data, "elements", "TupleExpression")
    if not isinstance(raw_elements, list):
        msg = "TupleExpression elements must be a list"
        raise SerializationError(msg)
    elements = []
    for item in raw_elements:
        expression = self._deserialize_expression(item)
        if expression is None:
            msg = "TupleExpression elements must contain expressions"
            raise SerializationError(msg)
        elements.append(expression)
    return TupleExpression(elements=elements)


def _deser_tuple_indexing(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import TupleIndexing

    return TupleIndexing(
        tuple_expr=_deserialize_required_expression(self, data, "tuple_expr", "TupleIndexing"),
        index=_deserialize_required_expression(self, data, "index", "TupleIndexing"),
    )


def _deser_list_expression(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import ListExpression

    raw_elements = _deserialize_required_field(data, "elements", "ListExpression")
    if not isinstance(raw_elements, list):
        msg = "ListExpression elements must be a list"
        raise SerializationError(msg)
    elements = []
    for item in raw_elements:
        expression = self._deserialize_expression(item)
        if expression is None:
            msg = "ListExpression elements must contain expressions"
            raise SerializationError(msg)
        elements.append(expression)
    return ListExpression(elements=elements)


def _deser_dict_expression(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import DictExpression

    raw_items = _deserialize_required_field(data, "items", "DictExpression")
    if not isinstance(raw_items, list):
        msg = "DictExpression items must be a list"
        raise SerializationError(msg)
    items = []
    for item in raw_items:
        expression = self._deserialize_expression(item)
        if expression is None:
            msg = "DictExpression items must contain expressions"
            raise SerializationError(msg)
        items.append(expression)
    return DictExpression(items=items)


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
        start=_deserialize_nullable_expression_field(self, data, "start", "SliceExpression"),
        stop=_deserialize_nullable_expression_field(self, data, "stop", "SliceExpression"),
        step=_deserialize_nullable_expression_field(self, data, "step", "SliceExpression"),
    )


def _deser_lambda_expression(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import LambdaExpression

    raw_parameters = _deserialize_required_field(data, "parameters", "LambdaExpression")
    if not isinstance(raw_parameters, list) or not all(
        isinstance(parameter, str) for parameter in raw_parameters
    ):
        msg = "LambdaExpression parameters must be a list of strings"
        raise SerializationError(msg)
    if any(
        _is_empty_nonempty_field(parameter, "LambdaExpression", "parameters")
        for parameter in raw_parameters
    ):
        msg = "LambdaExpression parameters must contain non-empty strings"
        raise SerializationError(msg)
    return LambdaExpression(
        parameters=_validate_local_identifier_list(raw_parameters),
        body=_deserialize_required_expression(self, data, "body", "LambdaExpression"),
    )


def _deser_pattern_match(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import PatternMatch

    raw_cases = _deserialize_required_field(data, "cases", "PatternMatch")
    if not isinstance(raw_cases, list):
        msg = "PatternMatch cases must be a list"
        raise SerializationError(msg)
    cases = []
    for item in raw_cases:
        expression = self._deserialize_expression(item)
        if expression is None:
            msg = "PatternMatch cases must contain expressions"
            raise SerializationError(msg)
        cases.append(expression)
    return PatternMatch(
        value=_deserialize_required_expression(self, data, "value", "PatternMatch"),
        cases=cases,
        default=_deserialize_nullable_expression_field(self, data, "default", "PatternMatch"),
    )


def _deser_match_case(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import MatchCase

    return MatchCase(
        pattern=_deserialize_required_expression(self, data, "pattern", "MatchCase"),
        result=_deserialize_required_expression(self, data, "result", "MatchCase"),
    )


def _deser_spread_operator(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import SpreadOperator

    expression = _deserialize_required_expression(self, data, "expression", "SpreadOperator")
    raw_is_dict = _deserialize_required_field(data, "is_dict", "SpreadOperator")
    if not isinstance(raw_is_dict, bool):
        msg = "SpreadOperator is_dict must be a boolean"
        raise SerializationError(msg)
    return SpreadOperator(
        expression=expression,
        is_dict=raw_is_dict,
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
                alias=_deserialize_required_nullable_nonempty_string_field(data, "alias", "Import"),
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
        meta_data = _deserialize_required_field(data, "meta", "Rule")
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
            self._deserialize_string(s)
            for s in _deserialize_required_list_field(data, "strings", "Rule")
        ]
        condition_data = _deserialize_required_field(data, "condition", "Rule")
        condition = _deserialize_optional_expression(self, condition_data, "Rule condition")

        tags = [
            self._deserialize_tag(t) for t in _deserialize_required_list_field(data, "tags", "Rule")
        ]
        _validate_unique_rule_tags(tags)
        pragmas = [
            self._deserialize_in_rule_pragma(p)
            for p in _deserialize_required_list_field(data, "pragmas", "Rule")
        ]

        return self._apply_node_metadata(
            Rule(
                name=_validate_yara_identifier_text(
                    _deserialize_nonempty_string_field(data, "name", "Rule"),
                    "rule",
                ),
                modifiers=[
                    _normalize_rule_modifier_text(modifier, "Rule")
                    for modifier in _deserialize_required_nonempty_string_list_field(
                        data, "modifiers", "Rule"
                    )
                ],
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
            Tag(
                name=_validate_yara_identifier_text(
                    _deserialize_nonempty_string_field(data, "name", "Tag"),
                    "tag",
                )
            ),
            data,
        )

    def _deserialize_meta(self, data: dict[str, Any]):
        from yaraast.ast.modifiers import MetaEntry

        data = _deserialize_object(data, "Meta")
        node_type = data.get("type")
        if node_type is not None and node_type not in {"Meta", "MetaEntry"}:
            msg = "Meta type must be Meta or MetaEntry"
            raise SerializationError(msg)
        if node_type == "Meta" and "scope" in data:
            msg = "Meta scope is only valid for MetaEntry"
            raise SerializationError(msg)
        if node_type == "Meta" or (
            node_type is None
            and "scope" not in data
            and (
                data.get("leading_comments") or data.get("trailing_comment") or data.get("location")
            )
        ):
            from yaraast.ast.meta import Meta

            return self._apply_node_metadata(
                Meta(
                    _validate_yara_identifier_text(
                        _deserialize_nonempty_string_field(data, "key", "Meta"),
                        "meta",
                    ),
                    _deserialize_meta_value(data),
                ),
                data,
            )
        if node_type == "MetaEntry":
            scope = _deserialize_required_field(data, "scope", "MetaEntry")
        else:
            scope = _deserialize_nullable_string_field(data, "scope", "Meta")
        return self._apply_node_metadata(
            MetaEntry.from_key_value(
                _validate_yara_identifier_text(
                    _deserialize_nonempty_string_field(data, "key", "Meta"),
                    "meta",
                ),
                _deserialize_meta_entry_value(data),
                deserialize_meta_scope(scope),
            ),
            data,
        )

    def _deserialize_string(self, data: dict[str, Any]):
        data = _deserialize_object(data, "String")
        string_type = data.get("type")

        if string_type == "PlainString":
            from yaraast.ast.strings import PlainString

            modifiers = _deserialize_string_modifiers(self, data, "PlainString")
            return self._apply_node_metadata(
                PlainString(
                    identifier=_deserialize_nonempty_string_field(
                        data,
                        "identifier",
                        "PlainString",
                    ),
                    value=_deserialize_plain_string_value(data),
                    raw_bytes=_deserialize_plain_string_raw_bytes(data),
                    modifiers=modifiers,
                    is_anonymous=_deserialize_is_anonymous(data),
                ),
                data,
            )
        if string_type == "HexString":
            from yaraast.ast.strings import HexString

            modifiers = _deserialize_string_modifiers(self, data, "HexString")
            identifier = _deserialize_nonempty_string_field(
                data,
                "identifier",
                "HexString",
            )
            tokens = [
                self._deserialize_hex_token(t)
                for t in _deserialize_list_field(data, "tokens", "HexString")
            ]
            if not tokens:
                msg = "HexString must contain at least one token"
                raise SerializationError(msg)
            self._validate_hex_token_sequence(tokens, "hex string", inside_alternative=False)
            return self._apply_node_metadata(
                HexString(
                    identifier=identifier,
                    tokens=tokens,
                    modifiers=modifiers,
                    is_anonymous=_deserialize_is_anonymous(data),
                ),
                data,
            )
        if string_type == "RegexString":
            from yaraast.ast.strings import RegexString

            modifiers = _deserialize_string_modifiers(self, data, "RegexString")
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

            modifiers = _deserialize_string_modifiers(self, data, "StringDefinition")
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
            value = self._deserialize_modifier_value(
                name,
                _deserialize_required_field(data, "value", "StringModifier"),
            )
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
            modifier = StringModifier.from_name_value(name, value)
        except (ValueError, ValidationError):
            return self._format_unknown_modifier(name, value)
        if isinstance(data, dict):
            return self._apply_node_metadata(modifier, data)
        return modifier

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

            raw_alternatives = _deserialize_list_field(data, "alternatives", "HexAlternative")
            if not raw_alternatives:
                msg = "HexAlternative must contain at least one branch"
                raise SerializationError(msg)
            alternatives = []
            for alt in raw_alternatives:
                branch = self._coerce_hex_alternative_branch(alt)
                if not branch:
                    msg = "HexAlternative branches must not be empty"
                    raise SerializationError(msg)
                alternative_tokens = [self._deserialize_hex_token(t) for t in branch]
                self._validate_hex_token_sequence(
                    alternative_tokens,
                    "hex alternative branch",
                    inside_alternative=True,
                )
                alternatives.append(alternative_tokens)
            return self._apply_node_metadata(HexAlternative(alternatives=alternatives), data)
        msg = f"Unknown hex token type: {hex_kind}"
        raise SerializationError(msg)

    def _validate_hex_token_sequence(
        self,
        tokens,
        context: str,
        *,
        inside_alternative: bool,
    ) -> None:
        from yaraast.ast.strings import HexAlternative, HexJump

        if isinstance(tokens[0], HexJump) or isinstance(tokens[-1], HexJump):
            msg = f"HexJump cannot appear at the beginning or end of {context}"
            raise SerializationError(msg)

        for token in tokens:
            if isinstance(token, HexAlternative):
                for alternative in token.alternatives:
                    if not alternative:
                        msg = "HexAlternative branches must not be empty"
                        raise SerializationError(msg)
                    self._validate_hex_token_sequence(
                        alternative,
                        "hex alternative branch",
                        inside_alternative=True,
                    )
            elif inside_alternative and isinstance(token, HexJump) and token.max_jump is None:
                msg = "Unbounded HexJump is not allowed inside hex alternatives"
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
        alias = _deserialize_required_nullable_nonempty_string_field(
            data,
            "alias",
            "ExternImport",
        )
        if alias is not None and not alias.strip():
            msg = "ExternImport alias must not be empty"
            raise SerializationError(msg)
        raw_rules = _deserialize_required_field(data, "rules", "ExternImport")
        if not isinstance(raw_rules, list) or not all(isinstance(rule, str) for rule in raw_rules):
            msg = "ExternImport rules must be a list of strings"
            raise SerializationError(msg)
        rules = raw_rules
        if any(not rule.strip() for rule in rules):
            msg = "ExternImport rules must contain non-empty strings"
            raise SerializationError(msg)
        rules = _validate_extern_import_rule_identifiers(rules)
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
                name=_validate_extern_rule_identifier_text(
                    _deserialize_nonempty_string_field(data, "name", "ExternRule")
                ),
                modifiers=Rule._normalize_modifiers(
                    [
                        _normalize_rule_modifier_text(modifier, "ExternRule")
                        for modifier in _deserialize_nonempty_string_list_field(
                            data, "modifiers", "ExternRule"
                        )
                    ]
                ),
                namespace=_validate_optional_namespace_identifier_text(
                    _deserialize_required_nullable_nonempty_string_field(
                        data,
                        "namespace",
                        "ExternRule",
                    )
                ),
            ),
            data,
        )

    def _deserialize_extern_namespace(self, data: dict[str, Any]):
        from yaraast.ast.extern import ExternNamespace

        name = _validate_namespace_identifier_text(
            _deserialize_nonempty_string_field(data, "name", "ExternNamespace")
        )
        raw_extern_rules = _deserialize_required_field(
            data,
            "extern_rules",
            "ExternNamespace",
        )
        if not isinstance(raw_extern_rules, list):
            msg = "ExternNamespace extern_rules must be a list"
            raise SerializationError(msg)
        return self._apply_node_metadata(
            ExternNamespace(
                name=name,
                extern_rules=[self._deserialize_extern_rule(rule) for rule in raw_extern_rules],
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
        _deserialize_pragma_node_type(data)
        pragma_type = _deserialize_pragma_type(data)
        scope = _deserialize_pragma_scope(
            _deserialize_required_field(data, "scope", "Pragma"), "Pragma"
        )
        name = _validate_yara_identifier_text(
            _deserialize_nonempty_string_field(data, "name", "Pragma"),
            "pragma",
        )
        arguments = _deserialize_required_string_list_field(data, "arguments", "Pragma")

        if pragma_type == PragmaType.INCLUDE_ONCE:
            pragma = IncludeOncePragma()
        elif pragma_type == PragmaType.DEFINE:
            pragma = DefineDirective(
                macro_name=_validate_yara_identifier_text(
                    _deserialize_nonempty_string_field(data, "macro_name", "Pragma"),
                    "pragma macro",
                ),
                macro_value=_deserialize_required_nullable_string_field(
                    data, "macro_value", "Pragma"
                ),
            )
        elif pragma_type == PragmaType.UNDEF:
            pragma = UndefDirective(
                macro_name=_validate_yara_identifier_text(
                    _deserialize_nonempty_string_field(data, "macro_name", "Pragma"),
                    "pragma macro",
                )
            )
        elif pragma_type in {PragmaType.IFDEF, PragmaType.IFNDEF, PragmaType.ENDIF}:
            condition = (
                _validate_yara_identifier_text(
                    _deserialize_nonempty_string_field(data, "condition", "Pragma"),
                    "pragma condition",
                )
                if pragma_type in {PragmaType.IFDEF, PragmaType.IFNDEF}
                else _deserialize_nullable_nonempty_string_field(data, "condition", "Pragma")
            )
            if pragma_type == PragmaType.ENDIF and condition is not None:
                condition = _validate_yara_identifier_text(condition, "pragma condition")
            pragma = ConditionalDirective(
                pragma_type,
                condition=condition,
            )
        elif pragma_type == PragmaType.CUSTOM:
            _deserialize_required_field(data, "parameters", "Pragma")
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
        if "position" not in data:
            return "before_strings"
        return _deserialize_nonempty_string_field(data, "position", "InRulePragma")

    def _deserialize_pragma_block(self, data: dict[str, Any]):
        from yaraast.ast.pragmas import PragmaBlock

        return self._apply_node_metadata(
            PragmaBlock(
                pragmas=[
                    self._deserialize_pragma(pragma)
                    for pragma in _deserialize_required_list_field(data, "pragmas", "PragmaBlock")
                ],
                scope=_deserialize_pragma_scope(
                    _deserialize_required_field(data, "scope", "PragmaBlock"),
                    "PragmaBlock",
                ),
            ),
            data,
        )

    def _deserialize_expression(self, data: dict[str, Any]):
        if data is None or data == {}:
            return None
        data = _deserialize_object(data, "Expression")

        expr_type = data.get("type")
        factory = _EXPR_DESERIALIZERS.get(expr_type) if isinstance(expr_type, str) else None
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
