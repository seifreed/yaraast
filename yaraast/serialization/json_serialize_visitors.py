"""Visitor helpers for JsonSerializer serialization paths."""

from __future__ import annotations

import base64
from typing import Any

from yaraast.errors import SerializationError


def _serialize_ast_value(serializer, value):
    if hasattr(value, "accept"):
        return serializer.visit(value)
    if isinstance(value, list | tuple):
        return [_serialize_ast_value(serializer, item) for item in value]
    if isinstance(value, set | frozenset):
        return [_serialize_ast_value(serializer, item) for item in sorted(value, key=str)]
    return value


def _serialize_optional_ast_node(serializer, value, context: str):
    if value is None:
        return None
    if not hasattr(value, "accept"):
        msg = f"{context} must be an AST node"
        raise SerializationError(msg)
    return serializer.visit(value)


def _serialize_quantifier(serializer, value):
    if isinstance(value, str):
        return value
    if isinstance(value, bool) or value is None or isinstance(value, list | dict | set | tuple):
        msg = "quantifier must be a string, number, or expression"
        raise SerializationError(msg)
    if isinstance(value, int | float):
        return value
    if hasattr(value, "accept"):
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
    data["value"] = value


def _serialize_meta_entry(serializer, meta) -> dict[str, Any]:
    data = {"key": getattr(meta, "key", ""), "value": getattr(meta, "value", "")}
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
        "name": node.name,
        "modifiers": [str(m) for m in node.modifiers],
        "tags": [serializer.visit(tag) for tag in node.tags],
        "meta": [_serialize_meta_entry(serializer, m) for m in node.meta],
        "strings": [serializer.visit(s) for s in node.strings],
        "condition": _serialize_optional_ast_node(serializer, node.condition, "Rule condition"),
        "pragmas": [serializer.visit(pragma) for pragma in node.pragmas],
    }


def visit_plain_string(serializer, node) -> dict[str, Any]:
    data = {
        "type": "PlainString",
        "identifier": node.identifier,
        "modifiers": [_serialize_string_modifier(serializer, mod) for mod in node.modifiers],
    }
    if getattr(node, "is_anonymous", False):
        data["is_anonymous"] = True
    _serialize_plain_string_value(data, node.value)
    return data


def visit_hex_string(serializer, node) -> dict[str, Any]:
    data = {
        "type": "HexString",
        "identifier": node.identifier,
        "tokens": [serializer.visit(token) for token in node.tokens],
        "modifiers": [_serialize_string_modifier(serializer, mod) for mod in node.modifiers],
    }
    if getattr(node, "is_anonymous", False):
        data["is_anonymous"] = True
    return data


def visit_regex_string(serializer, node) -> dict[str, Any]:
    data = {
        "type": "RegexString",
        "identifier": node.identifier,
        "regex": node.regex,
        "modifiers": [_serialize_string_modifier(serializer, mod) for mod in node.modifiers],
    }
    if getattr(node, "is_anonymous", False):
        data["is_anonymous"] = True
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
        "string_id": node.string_id,
        "index": serializer.visit(node.index) if node.index else None,
    }


def visit_string_length(serializer, node) -> dict[str, Any]:
    return {
        "type": "StringLength",
        "string_id": node.string_id,
        "index": serializer.visit(node.index) if node.index else None,
    }


def visit_binary_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "BinaryExpression",
        "left": serializer.visit(node.left),
        "operator": node.operator,
        "right": serializer.visit(node.right),
    }


def visit_unary_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "UnaryExpression",
        "operator": node.operator,
        "operand": serializer.visit(node.operand),
    }


def visit_parentheses_expression(serializer, node) -> dict[str, Any]:
    return {"type": "ParenthesesExpression", "expression": serializer.visit(node.expression)}


def visit_set_expression(serializer, node) -> dict[str, Any]:
    return {"type": "SetExpression", "elements": [serializer.visit(elem) for elem in node.elements]}


def visit_range_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "RangeExpression",
        "low": serializer.visit(node.low),
        "high": serializer.visit(node.high),
    }


def visit_function_call(serializer, node) -> dict[str, Any]:
    return {
        "type": "FunctionCall",
        "function": node.function,
        "arguments": [serializer.visit(arg) for arg in node.arguments],
    }


def visit_array_access(serializer, node) -> dict[str, Any]:
    return {
        "type": "ArrayAccess",
        "array": serializer.visit(node.array),
        "index": serializer.visit(node.index),
    }


def visit_member_access(serializer, node) -> dict[str, Any]:
    return {"type": "MemberAccess", "object": serializer.visit(node.object), "member": node.member}


def visit_for_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "ForExpression",
        "quantifier": _serialize_quantifier(serializer, node.quantifier),
        "variable": node.variable,
        "iterable": serializer.visit(node.iterable),
        "body": serializer.visit(node.body),
    }


def visit_for_of_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "ForOfExpression",
        "quantifier": _serialize_quantifier(serializer, node.quantifier),
        "string_set": _serialize_string_set(serializer, node.string_set, "ForOfExpression"),
        "condition": _serialize_optional_ast_node(
            serializer,
            node.condition,
            "ForOfExpression condition",
        ),
    }


def visit_at_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "AtExpression",
        "string_id": node.string_id,
        "offset": serializer.visit(node.offset),
    }


def visit_in_expression(serializer, node) -> dict[str, Any]:
    subject = _serialize_ast_value(serializer, node.subject)
    return {"type": "InExpression", "subject": subject, "range": serializer.visit(node.range)}


def visit_of_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "OfExpression",
        "quantifier": _serialize_quantifier(serializer, node.quantifier),
        "string_set": _serialize_string_set(serializer, node.string_set, "OfExpression"),
    }


def visit_dictionary_access(serializer, node) -> dict[str, Any]:
    return {
        "type": "DictionaryAccess",
        "object": serializer.visit(node.object),
        "key": serializer.visit(node.key) if hasattr(node.key, "accept") else node.key,
    }


def visit_comment_group(serializer, node) -> dict[str, Any]:
    return {
        "type": "CommentGroup",
        "comments": [serializer.visit(comment) for comment in node.comments],
    }


def visit_string_operator_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "StringOperatorExpression",
        "left": serializer.visit(node.left),
        "operator": node.operator,
        "right": serializer.visit(node.right),
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
        "body": serializer.visit(node.body),
    }


def visit_with_declaration(serializer, node) -> dict[str, Any]:
    return {
        "type": "WithDeclaration",
        "identifier": node.identifier,
        "value": serializer.visit(node.value),
    }


def visit_array_comprehension(serializer, node) -> dict[str, Any]:
    return {
        "type": "ArrayComprehension",
        "expression": serializer.visit(node.expression) if node.expression else None,
        "variable": node.variable,
        "iterable": serializer.visit(node.iterable) if node.iterable else None,
        "condition": serializer.visit(node.condition) if node.condition else None,
    }


def visit_dict_comprehension(serializer, node) -> dict[str, Any]:
    return {
        "type": "DictComprehension",
        "key_expression": serializer.visit(node.key_expression) if node.key_expression else None,
        "value_expression": (
            serializer.visit(node.value_expression) if node.value_expression else None
        ),
        "key_variable": node.key_variable,
        "value_variable": node.value_variable,
        "iterable": serializer.visit(node.iterable) if node.iterable else None,
        "condition": serializer.visit(node.condition) if node.condition else None,
    }


def visit_tuple_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "TupleExpression",
        "elements": [serializer.visit(element) for element in node.elements],
    }


def visit_tuple_indexing(serializer, node) -> dict[str, Any]:
    return {
        "type": "TupleIndexing",
        "tuple_expr": serializer.visit(node.tuple_expr),
        "index": serializer.visit(node.index),
    }


def visit_list_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "ListExpression",
        "elements": [serializer.visit(element) for element in node.elements],
    }


def visit_dict_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "DictExpression",
        "items": [serializer.visit(item) for item in node.items],
    }


def visit_dict_item(serializer, node) -> dict[str, Any]:
    return {
        "type": "DictItem",
        "key": serializer.visit(node.key),
        "value": serializer.visit(node.value),
    }


def visit_slice_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "SliceExpression",
        "target": serializer.visit(node.target),
        "start": serializer.visit(node.start) if node.start else None,
        "stop": serializer.visit(node.stop) if node.stop else None,
        "step": serializer.visit(node.step) if node.step else None,
    }


def visit_lambda_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "LambdaExpression",
        "parameters": list(node.parameters),
        "body": serializer.visit(node.body),
    }


def visit_pattern_match(serializer, node) -> dict[str, Any]:
    return {
        "type": "PatternMatch",
        "value": serializer.visit(node.value),
        "cases": [serializer.visit(case) for case in node.cases],
        "default": serializer.visit(node.default) if node.default else None,
    }


def visit_match_case(serializer, node) -> dict[str, Any]:
    return {
        "type": "MatchCase",
        "pattern": serializer.visit(node.pattern),
        "result": serializer.visit(node.result),
    }


def visit_spread_operator(serializer, node) -> dict[str, Any]:
    return {
        "type": "SpreadOperator",
        "expression": serializer.visit(node.expression),
        "is_dict": node.is_dict,
    }
