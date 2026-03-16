"""Visitor helpers for JsonSerializer serialization paths."""

from __future__ import annotations

from typing import Any


def visit_yara_file(serializer, node) -> dict[str, Any]:
    return {
        "type": "YaraFile",
        "imports": [serializer.visit(imp) for imp in node.imports],
        "includes": [serializer.visit(inc) for inc in node.includes],
        "rules": [serializer.visit(rule) for rule in node.rules],
    }


def visit_rule(serializer, node) -> dict[str, Any]:
    return {
        "type": "Rule",
        "name": node.name,
        "modifiers": node.modifiers,
        "tags": [serializer.visit(tag) for tag in node.tags],
        "meta": node.meta,
        "strings": [serializer.visit(s) for s in node.strings],
        "condition": serializer.visit(node.condition) if node.condition else None,
    }


def visit_plain_string(serializer, node) -> dict[str, Any]:
    return {
        "type": "PlainString",
        "identifier": node.identifier,
        "value": node.value,
        "modifiers": [serializer.visit(mod) for mod in node.modifiers],
    }


def visit_hex_string(serializer, node) -> dict[str, Any]:
    return {
        "type": "HexString",
        "identifier": node.identifier,
        "tokens": [serializer.visit(token) for token in node.tokens],
        "modifiers": [serializer.visit(mod) for mod in node.modifiers],
    }


def visit_regex_string(serializer, node) -> dict[str, Any]:
    return {
        "type": "RegexString",
        "identifier": node.identifier,
        "regex": node.regex,
        "modifiers": [serializer.visit(mod) for mod in node.modifiers],
    }


def visit_hex_alternative(serializer, node) -> dict[str, Any]:
    return {
        "type": "HexAlternative",
        "alternatives": [[serializer.visit(token) for token in alt] for alt in node.alternatives],
    }


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
        "quantifier": node.quantifier,
        "variable": node.variable,
        "iterable": serializer.visit(node.iterable),
        "body": serializer.visit(node.body),
    }


def visit_for_of_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "ForOfExpression",
        "quantifier": (
            serializer.visit(node.quantifier)
            if hasattr(node.quantifier, "accept")
            else node.quantifier
        ),
        "string_set": serializer.visit(node.string_set),
        "condition": serializer.visit(node.condition) if node.condition else None,
    }


def visit_at_expression(serializer, node) -> dict[str, Any]:
    return {
        "type": "AtExpression",
        "string_id": node.string_id,
        "offset": serializer.visit(node.offset),
    }


def visit_in_expression(serializer, node) -> dict[str, Any]:
    subject = serializer.visit(node.subject) if hasattr(node.subject, "accept") else node.subject
    return {"type": "InExpression", "subject": subject, "range": serializer.visit(node.range)}


def visit_of_expression(serializer, node) -> dict[str, Any]:
    string_set = (
        serializer.visit(node.string_set) if hasattr(node.string_set, "accept") else node.string_set
    )
    quantifier = (
        serializer.visit(node.quantifier) if hasattr(node.quantifier, "accept") else node.quantifier
    )
    return {"type": "OfExpression", "quantifier": quantifier, "string_set": string_set}


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
    }
