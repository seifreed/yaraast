"""Visitor helpers for JsonSerializer serialization paths."""

from __future__ import annotations

import base64
import math
from typing import Any

from yaraast.errors import SerializationError

_HEX_CHARS = frozenset("0123456789abcdefABCDEF")


def _serialize_required_string(value, context: str) -> str:
    if not isinstance(value, str):
        msg = f"{context} must be a string"
        raise SerializationError(msg)
    return value


def _serialize_nullable_string(value, context: str) -> str | None:
    if value is None:
        return None
    return _serialize_required_string(value, context)


def _serialize_string_list(values, context: str) -> list[str]:
    if isinstance(values, list | tuple) and all(isinstance(item, str) for item in values):
        return list(values)
    msg = f"{context} must be a list of strings"
    raise SerializationError(msg)


def _serialize_string_key_dict(value, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        msg = f"{context} must be a dictionary"
        raise SerializationError(msg)
    if not all(isinstance(key, str) for key in value):
        msg = f"{context} keys must be strings"
        raise SerializationError(msg)
    return dict(value)


def _serialize_meta_value(value) -> str | int | bool:
    if isinstance(value, str | bool):
        return value
    if isinstance(value, int):
        return value
    msg = "Meta value must be a string, integer, or boolean"
    raise SerializationError(msg)


def _serialize_required_int(value, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        msg = f"{context} must be an integer"
        raise SerializationError(msg)
    return value


def _serialize_required_number(value, context: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        msg = f"{context} must be numeric"
        raise SerializationError(msg)
    if isinstance(value, float) and not math.isfinite(value):
        msg = f"{context} must be finite"
        raise SerializationError(msg)
    return value


def _serialize_required_bool(value, context: str) -> bool:
    if not isinstance(value, bool):
        msg = f"{context} must be a boolean"
        raise SerializationError(msg)
    return value


def _serialize_hex_byte_value(value, context: str) -> int | str:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFF:
        return value
    if isinstance(value, str) and len(value) == 2 and all(char in _HEX_CHARS for char in value):
        return value
    msg = f"{context} value must be a byte"
    raise SerializationError(msg)


def _serialize_hex_jump_bound(value, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    msg = f"HexJump {field} must be a non-negative integer"
    raise SerializationError(msg)


def _serialize_hex_jump_bounds(
    min_jump,
    max_jump,
) -> tuple[int | None, int | None]:
    serialized_min = _serialize_hex_jump_bound(min_jump, "min_jump")
    serialized_max = _serialize_hex_jump_bound(max_jump, "max_jump")
    if (
        serialized_min is not None
        and serialized_max is not None
        and serialized_min > serialized_max
    ):
        msg = "HexJump min_jump cannot exceed max_jump"
        raise SerializationError(msg)
    return serialized_min, serialized_max


def _serialize_hex_nibble_high(value) -> bool:
    return _serialize_required_bool(value, "HexNibble high")


def _serialize_hex_nibble_value(value) -> int | str:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xF:
        return value
    if isinstance(value, str) and len(value) == 1 and value in _HEX_CHARS:
        return value
    msg = "HexNibble value must be a nibble"
    raise SerializationError(msg)


def _serialize_ast_value(serializer, value):
    if hasattr(value, "accept"):
        return serializer.visit(value)
    if isinstance(value, list | tuple):
        return [_serialize_ast_value(serializer, item) for item in value]
    if isinstance(value, set | frozenset):
        return [_serialize_ast_value(serializer, item) for item in sorted(value, key=str)]
    return value


def _serialize_optional_expression(serializer, value, context: str):
    from yaraast.ast.expressions import Expression

    if value is None:
        return None
    if not isinstance(value, Expression):
        msg = f"{context} must be an AST expression"
        raise SerializationError(msg)
    return serializer.visit(value)


def _serialize_required_expression(serializer, value, context: str):
    from yaraast.ast.expressions import Expression

    if not isinstance(value, Expression):
        msg = f"{context} must be an AST expression"
        raise SerializationError(msg)
    return serializer.visit(value)


def _serialize_expression_list(serializer, values, context: str):
    if not isinstance(values, list | tuple):
        msg = f"{context} must be a list of AST expressions"
        raise SerializationError(msg)
    return [
        _serialize_required_expression(serializer, value, f"{context} item") for value in values
    ]


def _serialize_quantifier(serializer, value):
    from yaraast.ast.expressions import Expression

    if isinstance(value, str):
        return value
    if isinstance(value, bool) or value is None or isinstance(value, list | dict | set | tuple):
        msg = "quantifier must be a string, number, or expression"
        raise SerializationError(msg)
    if isinstance(value, int | float):
        if isinstance(value, float) and not math.isfinite(value):
            msg = "quantifier must be finite"
            raise SerializationError(msg)
        return value
    if isinstance(value, Expression):
        return serializer.visit(value)
    msg = "quantifier must be a string, number, or expression"
    raise SerializationError(msg)


def _serialize_string_set_item(serializer, value, context: str):
    from yaraast.ast.expressions import Expression

    if isinstance(value, str):
        return value
    if isinstance(value, Expression):
        return serializer.visit(value)
    msg = f"{context} must contain strings or expressions"
    raise SerializationError(msg)


def _serialize_string_set(serializer, value, context: str):
    from yaraast.ast.expressions import Expression

    if isinstance(value, str):
        return value
    if isinstance(value, Expression):
        return serializer.visit(value)

    field_context = f"{context} string_set"
    if isinstance(value, list | tuple):
        return [_serialize_string_set_item(serializer, item, field_context) for item in value]
    if isinstance(value, set | frozenset):
        return [
            _serialize_string_set_item(serializer, item, field_context)
            for item in sorted(value, key=str)
        ]

    msg = f"{field_context} must be a string, expression, or list of strings/expressions"
    raise SerializationError(msg)


def _serialize_string_or_expression(serializer, value, context: str):
    from yaraast.ast.expressions import Expression

    if isinstance(value, str):
        return value
    if isinstance(value, Expression):
        return serializer.visit(value)
    msg = f"{context} must be a string or expression"
    raise SerializationError(msg)


def _serialize_modifier_value(value: Any) -> Any:
    if isinstance(value, tuple):
        return list(value)
    return value


def _serialize_string_modifier(serializer, modifier) -> dict[str, Any]:
    if hasattr(modifier, "accept"):
        return serializer.visit(modifier)
    return {
        "type": "StringModifier",
        "name": getattr(modifier, "name", str(modifier)),
        "value": _serialize_modifier_value(getattr(modifier, "value", None)),
    }


def _serialize_plain_string_value(data: dict[str, Any], value: str | bytes) -> None:
    if isinstance(value, bytes):
        data["value"] = base64.b64encode(value).decode("ascii")
        data["value_encoding"] = "base64"
        return
    if not isinstance(value, str):
        msg = "PlainString value must be a string or bytes"
        raise SerializationError(msg)
    data["value"] = value


def _serialize_anonymous_flag(data: dict[str, Any], value, context: str) -> None:
    if not isinstance(value, bool):
        msg = f"{context} is_anonymous must be a boolean"
        raise SerializationError(msg)
    if value:
        data["is_anonymous"] = True


def _serialize_meta_entry(serializer, meta) -> dict[str, Any]:
    data = {
        "key": _serialize_required_string(getattr(meta, "key", ""), "Meta key"),
        "value": _serialize_meta_value(getattr(meta, "value", "")),
    }
    scope = getattr(meta, "scope", None)
    if scope is not None:
        data["scope"] = getattr(scope, "value", str(scope))
    if hasattr(meta, "accept"):
        return serializer._with_node_metadata(meta, data)
    return data


def visit_yara_file(serializer, node) -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": "YaraFile",
        "imports": [serializer.visit(imp) for imp in node.imports],
        "includes": [serializer.visit(inc) for inc in node.includes],
        "rules": [serializer.visit(rule) for rule in node.rules],
    }
    if getattr(node, "extern_rules", None):
        result["extern_rules"] = [serializer.visit(er) for er in node.extern_rules]
    if getattr(node, "extern_imports", None):
        result["extern_imports"] = [serializer.visit(ei) for ei in node.extern_imports]
    if getattr(node, "pragmas", None):
        result["pragmas"] = [serializer.visit(p) for p in node.pragmas]
    if getattr(node, "namespaces", None):
        result["namespaces"] = [serializer.visit(ns) for ns in node.namespaces]
    return result


def visit_rule(serializer, node) -> dict[str, Any]:
    return {
        "type": "Rule",
        "name": _serialize_required_string(node.name, "Rule name"),
        "modifiers": [str(m) for m in node.modifiers],
        "tags": [serializer.visit(tag) for tag in node.tags],
        "meta": [_serialize_meta_entry(serializer, m) for m in node.meta],
        "strings": [serializer.visit(s) for s in node.strings],
        "condition": _serialize_optional_expression(serializer, node.condition, "Rule condition"),
        "pragmas": [serializer.visit(pragma) for pragma in node.pragmas],
    }


def visit_plain_string(serializer, node) -> dict[str, Any]:
    data = {
        "type": "PlainString",
        "identifier": _serialize_required_string(node.identifier, "PlainString identifier"),
        "modifiers": [_serialize_string_modifier(serializer, mod) for mod in node.modifiers],
    }
    _serialize_anonymous_flag(data, getattr(node, "is_anonymous", False), "PlainString")
    _serialize_plain_string_value(data, node.value)
    return data


def visit_hex_string(serializer, node) -> dict[str, Any]:
    data = {
        "type": "HexString",
        "identifier": _serialize_required_string(node.identifier, "HexString identifier"),
        "tokens": [serializer.visit(token) for token in node.tokens],
        "modifiers": [_serialize_string_modifier(serializer, mod) for mod in node.modifiers],
    }
    _serialize_anonymous_flag(data, getattr(node, "is_anonymous", False), "HexString")
    return data


def visit_regex_string(serializer, node) -> dict[str, Any]:
    data = {
        "type": "RegexString",
        "identifier": _serialize_required_string(node.identifier, "RegexString identifier"),
        "regex": _serialize_required_string(node.regex, "RegexString regex"),
        "modifiers": [_serialize_string_modifier(serializer, mod) for mod in node.modifiers],
    }
    _serialize_anonymous_flag(data, getattr(node, "is_anonymous", False), "RegexString")
    return data


def visit_hex_alternative(serializer, node) -> dict[str, Any]:
    return {
        "type": "HexAlternative",
        "alternatives": [
            [serializer.visit(token) for token in _coerce_hex_alternative_branch(alt)]
            for alt in node.alternatives
        ],
    }


def _coerce_hex_alternative_branch(alternative) -> list:
    from yaraast.ast.strings import HexByte

    if isinstance(alternative, list):
        return alternative
    return [HexByte(alternative)]


def visit_string_offset(serializer, node) -> dict[str, Any]:
    return {
        "type": "StringOffset",
        "string_id": _serialize_required_string(node.string_id, "StringOffset string_id"),
        "index": _serialize_optional_expression(serializer, node.index, "StringOffset index"),
    }


def visit_string_length(serializer, node) -> dict[str, Any]:
    return {
        "type": "StringLength",
        "string_id": _serialize_required_string(node.string_id, "StringLength string_id"),
        "index": _serialize_optional_expression(serializer, node.index, "StringLength index"),
    }


def visit_binary_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "BinaryExpression",
        "left": _serialize_required_expression(
            serializer,
            node.left,
            "BinaryExpression left",
        ),
        "operator": _serialize_required_string(node.operator, "BinaryExpression operator"),
        "right": _serialize_required_expression(
            serializer,
            node.right,
            "BinaryExpression right",
        ),
    }


def visit_unary_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "UnaryExpression",
        "operator": _serialize_required_string(node.operator, "UnaryExpression operator"),
        "operand": _serialize_required_expression(
            serializer,
            node.operand,
            "UnaryExpression operand",
        ),
    }


def visit_parentheses_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "ParenthesesExpression",
        "expression": _serialize_required_expression(
            serializer,
            node.expression,
            "ParenthesesExpression expression",
        ),
    }


def visit_set_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "SetExpression",
        "elements": _serialize_expression_list(serializer, node.elements, "SetExpression elements"),
    }


def visit_range_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "RangeExpression",
        "low": _serialize_required_expression(serializer, node.low, "RangeExpression low"),
        "high": _serialize_required_expression(serializer, node.high, "RangeExpression high"),
    }


def visit_function_call(serializer, node) -> dict[str, Any]:
    return {
        "type": "FunctionCall",
        "function": _serialize_required_string(node.function, "FunctionCall function"),
        "arguments": _serialize_expression_list(
            serializer,
            node.arguments,
            "FunctionCall arguments",
        ),
    }


def visit_array_access(serializer, node) -> dict[str, Any]:
    return {
        "type": "ArrayAccess",
        "array": _serialize_required_expression(serializer, node.array, "ArrayAccess array"),
        "index": _serialize_required_expression(serializer, node.index, "ArrayAccess index"),
    }


def visit_member_access(serializer, node) -> dict[str, Any]:
    return {
        "type": "MemberAccess",
        "object": _serialize_required_expression(
            serializer,
            node.object,
            "MemberAccess object",
        ),
        "member": _serialize_required_string(node.member, "MemberAccess member"),
    }


def visit_for_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "ForExpression",
        "quantifier": _serialize_quantifier(serializer, node.quantifier),
        "variable": _serialize_required_string(node.variable, "ForExpression variable"),
        "iterable": _serialize_required_expression(
            serializer,
            node.iterable,
            "ForExpression iterable",
        ),
        "body": _serialize_required_expression(serializer, node.body, "ForExpression body"),
    }


def visit_for_of_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "ForOfExpression",
        "quantifier": _serialize_quantifier(serializer, node.quantifier),
        "string_set": _serialize_string_set(serializer, node.string_set, "ForOfExpression"),
        "condition": _serialize_optional_expression(
            serializer,
            node.condition,
            "ForOfExpression condition",
        ),
    }


def visit_at_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "AtExpression",
        "string_id": _serialize_required_string(node.string_id, "AtExpression string_id"),
        "offset": _serialize_required_expression(serializer, node.offset, "AtExpression offset"),
    }


def visit_in_expression(serializer, node) -> dict[str, Any]:
    subject = _serialize_string_or_expression(serializer, node.subject, "InExpression subject")
    return {
        "type": "InExpression",
        "subject": subject,
        "range": _serialize_required_expression(serializer, node.range, "InExpression range"),
    }


def visit_of_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "OfExpression",
        "quantifier": _serialize_quantifier(serializer, node.quantifier),
        "string_set": _serialize_string_set(serializer, node.string_set, "OfExpression"),
    }


def visit_dictionary_access(serializer, node) -> dict[str, Any]:
    return {
        "type": "DictionaryAccess",
        "object": _serialize_required_expression(
            serializer,
            node.object,
            "DictionaryAccess object",
        ),
        "key": _serialize_string_or_expression(serializer, node.key, "DictionaryAccess key"),
    }


def visit_comment_group(serializer, node) -> dict[str, Any]:
    return {
        "type": "CommentGroup",
        "comments": [serializer.visit(comment) for comment in node.comments],
    }


def visit_string_operator_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "StringOperatorExpression",
        "left": _serialize_required_expression(
            serializer,
            node.left,
            "StringOperatorExpression left",
        ),
        "operator": _serialize_required_string(
            node.operator,
            "StringOperatorExpression operator",
        ),
        "right": _serialize_required_expression(
            serializer,
            node.right,
            "StringOperatorExpression right",
        ),
    }


def visit_pragma_block(serializer, node) -> dict[str, Any]:
    return {
        "type": "PragmaBlock",
        "pragmas": (
            [serializer.visit(p) for p in node.pragmas] if hasattr(node, "pragmas") else []
        ),
        "scope": getattr(getattr(node, "scope", None), "value", "file"),
    }


def visit_with_statement(serializer, node) -> dict[str, Any]:
    return {
        "type": "WithStatement",
        "declarations": [serializer.visit(decl) for decl in node.declarations],
        "body": _serialize_required_expression(serializer, node.body, "WithStatement body"),
    }


def visit_with_declaration(serializer, node) -> dict[str, Any]:
    return {
        "type": "WithDeclaration",
        "identifier": _serialize_required_string(node.identifier, "WithDeclaration identifier"),
        "value": _serialize_required_expression(serializer, node.value, "WithDeclaration value"),
    }


def visit_array_comprehension(serializer, node) -> dict[str, Any]:
    return {
        "type": "ArrayComprehension",
        "expression": _serialize_optional_expression(
            serializer,
            node.expression,
            "ArrayComprehension expression",
        ),
        "variable": _serialize_required_string(
            node.variable,
            "ArrayComprehension variable",
        ),
        "iterable": _serialize_optional_expression(
            serializer,
            node.iterable,
            "ArrayComprehension iterable",
        ),
        "condition": _serialize_optional_expression(
            serializer,
            node.condition,
            "ArrayComprehension condition",
        ),
    }


def visit_dict_comprehension(serializer, node) -> dict[str, Any]:
    return {
        "type": "DictComprehension",
        "key_expression": _serialize_optional_expression(
            serializer,
            node.key_expression,
            "DictComprehension key_expression",
        ),
        "value_expression": (
            _serialize_optional_expression(
                serializer,
                node.value_expression,
                "DictComprehension value_expression",
            )
        ),
        "key_variable": _serialize_required_string(
            node.key_variable,
            "DictComprehension key_variable",
        ),
        "value_variable": _serialize_nullable_string(
            node.value_variable,
            "DictComprehension value_variable",
        ),
        "iterable": _serialize_optional_expression(
            serializer,
            node.iterable,
            "DictComprehension iterable",
        ),
        "condition": _serialize_optional_expression(
            serializer,
            node.condition,
            "DictComprehension condition",
        ),
    }


def visit_tuple_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "TupleExpression",
        "elements": _serialize_expression_list(
            serializer,
            node.elements,
            "TupleExpression elements",
        ),
    }


def visit_tuple_indexing(serializer, node) -> dict[str, Any]:
    return {
        "type": "TupleIndexing",
        "tuple_expr": _serialize_required_expression(
            serializer,
            node.tuple_expr,
            "TupleIndexing tuple_expr",
        ),
        "index": _serialize_required_expression(serializer, node.index, "TupleIndexing index"),
    }


def visit_list_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "ListExpression",
        "elements": _serialize_expression_list(
            serializer,
            node.elements,
            "ListExpression elements",
        ),
    }


def visit_dict_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "DictExpression",
        "items": [serializer.visit(item) for item in node.items],
    }


def visit_dict_item(serializer, node) -> dict[str, Any]:
    return {
        "type": "DictItem",
        "key": _serialize_required_expression(serializer, node.key, "DictItem key"),
        "value": _serialize_required_expression(serializer, node.value, "DictItem value"),
    }


def visit_slice_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "SliceExpression",
        "target": _serialize_required_expression(serializer, node.target, "SliceExpression target"),
        "start": _serialize_optional_expression(serializer, node.start, "SliceExpression start"),
        "stop": _serialize_optional_expression(serializer, node.stop, "SliceExpression stop"),
        "step": _serialize_optional_expression(serializer, node.step, "SliceExpression step"),
    }


def visit_lambda_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "LambdaExpression",
        "parameters": _serialize_string_list(
            node.parameters,
            "LambdaExpression parameters",
        ),
        "body": _serialize_required_expression(serializer, node.body, "LambdaExpression body"),
    }


def visit_pattern_match(serializer, node) -> dict[str, Any]:
    return {
        "type": "PatternMatch",
        "value": _serialize_required_expression(serializer, node.value, "PatternMatch value"),
        "cases": [serializer.visit(case) for case in node.cases],
        "default": _serialize_optional_expression(serializer, node.default, "PatternMatch default"),
    }


def visit_match_case(serializer, node) -> dict[str, Any]:
    return {
        "type": "MatchCase",
        "pattern": _serialize_required_expression(serializer, node.pattern, "MatchCase pattern"),
        "result": _serialize_required_expression(serializer, node.result, "MatchCase result"),
    }


def visit_spread_operator(serializer, node) -> dict[str, Any]:
    return {
        "type": "SpreadOperator",
        "expression": _serialize_required_expression(
            serializer,
            node.expression,
            "SpreadOperator expression",
        ),
        "is_dict": _serialize_required_bool(node.is_dict, "SpreadOperator is_dict"),
    }
