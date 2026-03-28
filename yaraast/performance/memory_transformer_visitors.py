"""Visitor helpers for MemoryOptimizerTransformer."""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING

from yaraast.performance.memory_helpers import pooled_value

if TYPE_CHECKING:
    from yaraast.ast.base import ASTNode, YaraFile
    from yaraast.ast.expressions import (
        BinaryExpression,
        Identifier,
        StringIdentifier,
        StringLiteral,
        StringWildcard,
        UnaryExpression,
    )
    from yaraast.ast.meta import Meta
    from yaraast.ast.rules import Import, Include, Rule, Tag
    from yaraast.ast.strings import HexString, PlainString, RegexString


def _shallow(node: ASTNode) -> ASTNode:
    """Create a shallow copy of a dataclass node to avoid mutating the original."""
    return copy.copy(node)


def visit_string_literal(transformer, node: StringLiteral) -> StringLiteral:
    node = _shallow(node)
    if hasattr(node, "value") and isinstance(node.value, str):
        node.value = pooled_value(transformer.string_pool, node.value)
    return node


def visit_identifier(transformer, node: Identifier) -> Identifier:
    node = _shallow(node)
    if hasattr(node, "name") and isinstance(node.name, str):
        node.name = pooled_value(transformer.string_pool, node.name)
    return node


def visit_rule(transformer, node: Rule) -> Rule:
    node = _shallow(node)
    if node.name:
        node.name = pooled_value(transformer.string_pool, node.name)
    if node.condition:
        node.condition = transformer.visit(node.condition)
    if node.strings:
        node.strings = [transformer.visit(s) for s in node.strings]
    if node.meta:
        node.meta = [
            transformer.visit(m) if hasattr(m, "accept") else transformer.visit_meta(m)
            for m in node.meta
        ]
    if node.tags:
        node.tags = [transformer.visit(t) for t in node.tags]
    if transformer.aggressive and hasattr(node, "location"):
        node.location = None
    return node


def visit_plain_string(transformer, node: PlainString) -> PlainString:
    node = _shallow(node)
    if hasattr(node, "value") and isinstance(node.value, str):
        node.value = pooled_value(transformer.string_pool, node.value)
    if hasattr(node, "identifier") and isinstance(node.identifier, str):
        node.identifier = pooled_value(transformer.string_pool, node.identifier)
    return node


def visit_meta(transformer, node: Meta) -> Meta:
    node = _shallow(node)
    if hasattr(node, "key") and isinstance(node.key, str):
        node.key = pooled_value(transformer.string_pool, node.key)
    if hasattr(node, "value") and isinstance(node.value, str):
        node.value = pooled_value(transformer.string_pool, node.value)
    return node


def visit_tag(transformer, node: Tag) -> Tag:
    node = _shallow(node)
    if hasattr(node, "name") and isinstance(node.name, str):
        node.name = pooled_value(transformer.string_pool, node.name)
    return node


def visit_yara_file(transformer, node: YaraFile) -> YaraFile:
    node = _shallow(node)
    if node.imports:
        node.imports = [transformer.visit(imp) for imp in node.imports]
    if node.includes:
        node.includes = [transformer.visit(inc) for inc in node.includes]
    if node.rules:
        node.rules = [transformer.visit(rule) for rule in node.rules]
    return node


def visit_import(transformer, node: Import) -> Import:
    node = _shallow(node)
    if hasattr(node, "module") and isinstance(node.module, str):
        node.module = pooled_value(transformer.string_pool, node.module)
    return node


def visit_include(transformer, node: Include) -> Include:
    node = _shallow(node)
    if hasattr(node, "path") and isinstance(node.path, str):
        node.path = pooled_value(transformer.string_pool, node.path)
    return node


def visit_string_identifier(transformer, node: StringIdentifier) -> StringIdentifier:
    node = _shallow(node)
    if hasattr(node, "name") and isinstance(node.name, str):
        node.name = pooled_value(transformer.string_pool, node.name)
    return node


def visit_string_wildcard(transformer, node: StringWildcard) -> StringWildcard:
    node = _shallow(node)
    if hasattr(node, "pattern") and isinstance(node.pattern, str):
        node.pattern = pooled_value(transformer.string_pool, node.pattern)
    return node


def visit_binary_expression(transformer, node: BinaryExpression) -> BinaryExpression:
    node = _shallow(node)
    if hasattr(node, "left"):
        node.left = transformer.visit(node.left)
    if hasattr(node, "right"):
        node.right = transformer.visit(node.right)
    if hasattr(node, "operator") and isinstance(node.operator, str):
        node.operator = pooled_value(transformer.string_pool, node.operator)
    return node


def visit_unary_expression(transformer, node: UnaryExpression) -> UnaryExpression:
    node = _shallow(node)
    if hasattr(node, "operand"):
        node.operand = transformer.visit(node.operand)
    if hasattr(node, "operator") and isinstance(node.operator, str):
        node.operator = pooled_value(transformer.string_pool, node.operator)
    return node


def visit_hex_string(transformer, node: HexString) -> HexString:
    node = _shallow(node)
    if hasattr(node, "identifier") and isinstance(node.identifier, str):
        node.identifier = pooled_value(transformer.string_pool, node.identifier)
    return node


def visit_regex_string(transformer, node: RegexString) -> RegexString:
    node = _shallow(node)
    if hasattr(node, "identifier") and isinstance(node.identifier, str):
        node.identifier = pooled_value(transformer.string_pool, node.identifier)
    if hasattr(node, "regex") and isinstance(node.regex, str):
        node.regex = pooled_value(transformer.string_pool, node.regex)
    return node
