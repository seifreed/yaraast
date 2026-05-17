"""Visitor helpers for MemoryOptimizerTransformer."""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING, Any, cast

from yaraast.ast.base import ASTNode
from yaraast.performance.memory_helpers import pooled_value

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.expressions import (
        BinaryExpression,
        Identifier,
        StringIdentifier,
        StringLiteral,
        StringWildcard,
        UnaryExpression,
    )
    from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
    from yaraast.ast.meta import Meta
    from yaraast.ast.modifiers import StringModifier
    from yaraast.ast.pragmas import InRulePragma, Pragma, PragmaBlock
    from yaraast.ast.rules import Import, Include, Rule, Tag
    from yaraast.ast.strings import HexString, PlainString, RegexString


def _shallow[Node: ASTNode](node: Node) -> Node:
    """Create a shallow copy of a dataclass node to avoid mutating the original."""
    return copy.copy(node)


def _pool_text(transformer, value: str | None) -> str | None:
    if value is None:
        return None
    return pooled_value(transformer.string_pool, value)


def _pool_text_list(transformer, values: list[str]) -> list[str]:
    return [pooled_value(transformer.string_pool, value) for value in values]


def _pool_parameter_value(transformer, value: Any) -> Any:
    if isinstance(value, str):
        return pooled_value(transformer.string_pool, value)
    if hasattr(value, "accept"):
        return transformer.visit(value)
    return value


def _visit_items(transformer, values: list[Any]) -> list[Any]:
    return [transformer.visit(value) if hasattr(value, "accept") else value for value in values]


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
    if isinstance(node.modifiers, list):
        node.modifiers = _visit_items(transformer, node.modifiers)
    if node.condition:
        node.condition = transformer.visit(node.condition)
    if node.strings:
        node.strings = [transformer.visit(s) for s in node.strings]
    if node.meta:
        node.meta = [
            transformer.visit(m) if hasattr(m, "accept") else transformer.visit_meta(m)
            for m in node.meta
        ]
    if node.pragmas:
        node.pragmas = [transformer.visit(pragma) for pragma in node.pragmas]
    if node.tags:
        node.tags = [transformer.visit(t) for t in node.tags]
    if transformer.aggressive and hasattr(node, "location"):
        node.location = None
    return node


def visit_plain_string(transformer, node: PlainString) -> PlainString:
    node = _shallow(node)
    node.modifiers = _visit_items(transformer, node.modifiers)
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
    if node.extern_rules:
        node.extern_rules = [transformer.visit(rule) for rule in node.extern_rules]
    if node.extern_imports:
        node.extern_imports = [transformer.visit(imp) for imp in node.extern_imports]
    if node.pragmas:
        node.pragmas = [transformer.visit(pragma) for pragma in node.pragmas]
    if node.namespaces:
        node.namespaces = [transformer.visit(namespace) for namespace in node.namespaces]
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
    node.modifiers = _visit_items(transformer, node.modifiers)
    node.tokens = _visit_items(transformer, node.tokens)
    if hasattr(node, "identifier") and isinstance(node.identifier, str):
        node.identifier = pooled_value(transformer.string_pool, node.identifier)
    return node


def visit_regex_string(transformer, node: RegexString) -> RegexString:
    node = _shallow(node)
    node.modifiers = _visit_items(transformer, node.modifiers)
    if hasattr(node, "identifier") and isinstance(node.identifier, str):
        node.identifier = pooled_value(transformer.string_pool, node.identifier)
    if hasattr(node, "regex") and isinstance(node.regex, str):
        node.regex = pooled_value(transformer.string_pool, node.regex)
    return node


def visit_extern_rule(transformer, node: ExternRule) -> ExternRule:
    node = _shallow(node)
    node.name = pooled_value(transformer.string_pool, node.name)
    node.modifiers = _visit_items(transformer, node.modifiers)
    node.namespace = _pool_text(transformer, node.namespace)
    return node


def visit_extern_rule_reference(
    transformer,
    node: ExternRuleReference,
) -> ExternRuleReference:
    node = _shallow(node)
    node.rule_name = pooled_value(transformer.string_pool, node.rule_name)
    node.namespace = _pool_text(transformer, node.namespace)
    return node


def visit_extern_import(transformer, node: ExternImport) -> ExternImport:
    node = _shallow(node)
    node.module_path = pooled_value(transformer.string_pool, node.module_path)
    node.alias = _pool_text(transformer, node.alias)
    node.rules = _pool_text_list(transformer, node.rules)
    return node


def visit_extern_namespace(transformer, node: ExternNamespace) -> ExternNamespace:
    node = _shallow(node)
    node.name = pooled_value(transformer.string_pool, node.name)
    node.extern_rules = [transformer.visit(rule) for rule in node.extern_rules]
    return node


def visit_pragma(transformer, node: Pragma) -> Pragma:
    node = _shallow(node)
    node.name = pooled_value(transformer.string_pool, node.name)
    node.arguments = _pool_text_list(transformer, node.arguments)

    macro_name = getattr(node, "macro_name", None)
    if isinstance(macro_name, str):
        node.macro_name = pooled_value(transformer.string_pool, macro_name)

    macro_value = getattr(node, "macro_value", None)
    if isinstance(macro_value, str):
        node.macro_value = pooled_value(transformer.string_pool, macro_value)

    condition = getattr(node, "condition", None)
    if isinstance(condition, str):
        node.condition = pooled_value(transformer.string_pool, condition)

    parameters = getattr(node, "parameters", None)
    if isinstance(parameters, dict):
        node.parameters = {
            pooled_value(transformer.string_pool, key): _pool_parameter_value(
                transformer,
                value,
            )
            for key, value in cast(dict[str, Any], parameters).items()
        }

    return node


def visit_in_rule_pragma(transformer, node: InRulePragma) -> InRulePragma:
    node = _shallow(node)
    node.pragma = transformer.visit(node.pragma)
    node.position = pooled_value(transformer.string_pool, node.position)
    return node


def visit_pragma_block(transformer, node: PragmaBlock) -> PragmaBlock:
    node = _shallow(node)
    node.pragmas = [transformer.visit(pragma) for pragma in node.pragmas]
    return node


def visit_string_modifier(transformer, node: StringModifier) -> StringModifier:
    node = _shallow(node)
    if isinstance(node.value, str):
        node.value = pooled_value(transformer.string_pool, node.value)
    return node
