"""Visitor helpers for MemoryOptimizerTransformer."""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING, Any, cast

from yaraast.ast.base import ASTNode
from yaraast.performance.memory_helpers import pooled_value

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.conditions import (
        AtExpression,
        ForExpression,
        ForOfExpression,
        InExpression,
        OfExpression,
    )
    from yaraast.ast.expressions import (
        ArrayAccess,
        BinaryExpression,
        BooleanLiteral,
        DoubleLiteral,
        FunctionCall,
        Identifier,
        IntegerLiteral,
        MemberAccess,
        ParenthesesExpression,
        RangeExpression,
        RegexLiteral,
        SetExpression,
        StringCount,
        StringIdentifier,
        StringLength,
        StringLiteral,
        StringOffset,
        StringWildcard,
        UnaryExpression,
    )
    from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
    from yaraast.ast.meta import Meta
    from yaraast.ast.modifiers import StringModifier
    from yaraast.ast.modules import DictionaryAccess, ModuleReference
    from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
    from yaraast.ast.pragmas import InRulePragma, Pragma, PragmaBlock
    from yaraast.ast.rules import Import, Include, Rule, Tag
    from yaraast.ast.strings import HexString, PlainString, RegexString


def _shallow[Node: ASTNode](node: Node) -> Node:
    """Create a shallow copy of a dataclass node to avoid mutating the original."""
    copied = copy.copy(node)
    if hasattr(node, "leading_comments"):
        copied.leading_comments = copy.deepcopy(node.leading_comments)
    if hasattr(node, "trailing_comment"):
        copied.trailing_comment = copy.deepcopy(node.trailing_comment)
    return copied


def _pool_text(transformer: Any, value: str | None) -> str | None:
    if value is None:
        return None
    return pooled_value(transformer.string_pool, value)


def _pool_text_list(transformer: Any, values: list[str]) -> list[str]:
    return [pooled_value(transformer.string_pool, value) for value in values]


def _pool_parameter_value(transformer: Any, value: Any) -> Any:
    if isinstance(value, str):
        return pooled_value(transformer.string_pool, value)
    if hasattr(value, "accept"):
        return transformer.visit(value)
    if isinstance(value, list):
        return [_pool_parameter_value(transformer, item) for item in value]
    if isinstance(value, tuple):
        return tuple(_pool_parameter_value(transformer, item) for item in value)
    if isinstance(value, set):
        return {_pool_parameter_value(transformer, item) for item in value}
    if isinstance(value, frozenset):
        return frozenset(_pool_parameter_value(transformer, item) for item in value)
    if isinstance(value, dict):
        return {
            _pool_parameter_value(transformer, key): _pool_parameter_value(transformer, item)
            for key, item in value.items()
        }
    return value


def _visit_items(transformer: Any, values: list[Any]) -> list[Any]:
    return [transformer.visit(value) if hasattr(value, "accept") else value for value in values]


def _visit_ast_items(transformer: Any, values: list[Any], field_name: str) -> list[Any]:
    visited = []
    for value in values:
        if not isinstance(value, ASTNode):
            msg = f"{field_name} must contain AST nodes"
            raise TypeError(msg)
        visited.append(transformer.visit(value))
    return visited


def visit_string_literal(transformer: Any, node: StringLiteral) -> StringLiteral:
    node = _shallow(node)
    if hasattr(node, "value") and isinstance(node.value, str):
        node.value = pooled_value(transformer.string_pool, node.value)
    return node


def visit_boolean_literal(transformer: Any, node: BooleanLiteral) -> BooleanLiteral:
    return _shallow(node)


def visit_integer_literal(transformer: Any, node: IntegerLiteral) -> IntegerLiteral:
    return _shallow(node)


def visit_double_literal(transformer: Any, node: DoubleLiteral) -> DoubleLiteral:
    return _shallow(node)


def visit_regex_literal(transformer: Any, node: RegexLiteral) -> RegexLiteral:
    node = _shallow(node)
    node.pattern = pooled_value(transformer.string_pool, node.pattern)
    node.modifiers = pooled_value(transformer.string_pool, node.modifiers)
    return node


def visit_string_count(transformer: Any, node: StringCount) -> StringCount:
    node = _shallow(node)
    node.string_id = pooled_value(transformer.string_pool, node.string_id)
    return node


def visit_string_offset(transformer: Any, node: StringOffset) -> StringOffset:
    node = _shallow(node)
    node.string_id = pooled_value(transformer.string_pool, node.string_id)
    if node.index is not None:
        node.index = transformer.visit(node.index)
    return node


def visit_string_length(transformer: Any, node: StringLength) -> StringLength:
    node = _shallow(node)
    node.string_id = pooled_value(transformer.string_pool, node.string_id)
    if node.index is not None:
        node.index = transformer.visit(node.index)
    return node


def visit_parentheses_expression(
    transformer: Any,
    node: ParenthesesExpression,
) -> ParenthesesExpression:
    node = _shallow(node)
    node.expression = transformer.visit(node.expression)
    return node


def visit_set_expression(transformer: Any, node: SetExpression) -> SetExpression:
    node = _shallow(node)
    node.elements = [transformer.visit(element) for element in node.elements]
    return node


def visit_range_expression(transformer: Any, node: RangeExpression) -> RangeExpression:
    node = _shallow(node)
    node.low = transformer.visit(node.low)
    node.high = transformer.visit(node.high)
    return node


def visit_function_call(transformer: Any, node: FunctionCall) -> FunctionCall:
    node = _shallow(node)
    node.function = pooled_value(transformer.string_pool, node.function)
    node.arguments = [transformer.visit(argument) for argument in node.arguments]
    if node.receiver is not None:
        node.receiver = transformer.visit(node.receiver)
    return node


def visit_array_access(transformer: Any, node: ArrayAccess) -> ArrayAccess:
    node = _shallow(node)
    node.array = transformer.visit(node.array)
    node.index = transformer.visit(node.index)
    return node


def visit_member_access(transformer: Any, node: MemberAccess) -> MemberAccess:
    node = _shallow(node)
    node.object = transformer.visit(node.object)
    node.member = pooled_value(transformer.string_pool, node.member)
    return node


def visit_identifier(transformer: Any, node: Identifier) -> Identifier:
    node = _shallow(node)
    if hasattr(node, "name") and isinstance(node.name, str):
        node.name = pooled_value(transformer.string_pool, node.name)
    return node


def visit_rule(transformer: Any, node: Rule) -> Rule:
    node = _shallow(node)
    if node.name:
        node.name = pooled_value(transformer.string_pool, node.name)
    if isinstance(node.modifiers, list):
        node.modifiers = _visit_items(transformer, node.modifiers)
    if node.condition is not None:
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


def visit_plain_string(transformer: Any, node: PlainString) -> PlainString:
    node = _shallow(node)
    node.modifiers = _visit_items(transformer, node.modifiers)
    if hasattr(node, "value") and isinstance(node.value, str):
        node.value = pooled_value(transformer.string_pool, node.value)
    if hasattr(node, "identifier") and isinstance(node.identifier, str):
        node.identifier = pooled_value(transformer.string_pool, node.identifier)
    return node


def visit_meta(transformer: Any, node: Meta) -> Meta:
    node = _shallow(node)
    if hasattr(node, "key") and isinstance(node.key, str):
        node.key = pooled_value(transformer.string_pool, node.key)
    if hasattr(node, "value") and isinstance(node.value, str):
        node.value = pooled_value(transformer.string_pool, node.value)
    return node


def visit_tag(transformer: Any, node: Tag) -> Tag:
    node = _shallow(node)
    if hasattr(node, "name") and isinstance(node.name, str):
        node.name = pooled_value(transformer.string_pool, node.name)
    return node


def visit_yara_file(transformer: Any, node: YaraFile) -> YaraFile:
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


def visit_import(transformer: Any, node: Import) -> Import:
    node = _shallow(node)
    if hasattr(node, "module") and isinstance(node.module, str):
        node.module = pooled_value(transformer.string_pool, node.module)
    return node


def visit_include(transformer: Any, node: Include) -> Include:
    node = _shallow(node)
    if hasattr(node, "path") and isinstance(node.path, str):
        node.path = pooled_value(transformer.string_pool, node.path)
    return node


def visit_string_identifier(transformer: Any, node: StringIdentifier) -> StringIdentifier:
    node = _shallow(node)
    if hasattr(node, "name") and isinstance(node.name, str):
        node.name = pooled_value(transformer.string_pool, node.name)
    return node


def visit_string_wildcard(transformer: Any, node: StringWildcard) -> StringWildcard:
    node = _shallow(node)
    if hasattr(node, "pattern") and isinstance(node.pattern, str):
        node.pattern = pooled_value(transformer.string_pool, node.pattern)
    return node


def visit_binary_expression(transformer: Any, node: BinaryExpression) -> BinaryExpression:
    node = _shallow(node)
    if hasattr(node, "left"):
        node.left = transformer.visit(node.left)
    if hasattr(node, "right"):
        node.right = transformer.visit(node.right)
    if hasattr(node, "operator") and isinstance(node.operator, str):
        node.operator = pooled_value(transformer.string_pool, node.operator)
    return node


def visit_unary_expression(transformer: Any, node: UnaryExpression) -> UnaryExpression:
    node = _shallow(node)
    if hasattr(node, "operand"):
        node.operand = transformer.visit(node.operand)
    if hasattr(node, "operator") and isinstance(node.operator, str):
        node.operator = pooled_value(transformer.string_pool, node.operator)
    return node


def visit_for_expression(transformer: Any, node: ForExpression) -> ForExpression:
    node = _shallow(node)
    node.quantifier = _pool_parameter_value(transformer, node.quantifier)
    node.variable = pooled_value(transformer.string_pool, node.variable)
    node.iterable = transformer.visit(node.iterable)
    node.body = transformer.visit(node.body)
    return node


def visit_for_of_expression(transformer: Any, node: ForOfExpression) -> ForOfExpression:
    node = _shallow(node)
    node.quantifier = _pool_parameter_value(transformer, node.quantifier)
    node.string_set = _pool_parameter_value(transformer, node.string_set)
    if node.condition is not None:
        node.condition = transformer.visit(node.condition)
    return node


def visit_at_expression(transformer: Any, node: AtExpression) -> AtExpression:
    node = _shallow(node)
    node.string_id = _pool_parameter_value(transformer, node.string_id)
    node.offset = transformer.visit(node.offset)
    return node


def visit_in_expression(transformer: Any, node: InExpression) -> InExpression:
    node = _shallow(node)
    node.subject = _pool_parameter_value(transformer, node.subject)
    node.range = transformer.visit(node.range)
    return node


def visit_of_expression(transformer: Any, node: OfExpression) -> OfExpression:
    node = _shallow(node)
    node.quantifier = _pool_parameter_value(transformer, node.quantifier)
    node.string_set = _pool_parameter_value(transformer, node.string_set)
    return node


def visit_module_reference(transformer: Any, node: ModuleReference) -> ModuleReference:
    node = _shallow(node)
    node.module = pooled_value(transformer.string_pool, node.module)
    return node


def visit_dictionary_access(transformer: Any, node: DictionaryAccess) -> DictionaryAccess:
    node = _shallow(node)
    node.object = transformer.visit(node.object)
    node.key = _pool_parameter_value(transformer, node.key)
    return node


def visit_defined_expression(transformer: Any, node: DefinedExpression) -> DefinedExpression:
    node = _shallow(node)
    node.expression = transformer.visit(node.expression)
    return node


def visit_string_operator_expression(
    transformer: Any,
    node: StringOperatorExpression,
) -> StringOperatorExpression:
    node = _shallow(node)
    node.left = transformer.visit(node.left)
    node.operator = pooled_value(transformer.string_pool, node.operator)
    node.right = transformer.visit(node.right)
    return node


def visit_hex_string(transformer: Any, node: HexString) -> HexString:
    node = _shallow(node)
    node.modifiers = _visit_items(transformer, node.modifiers)
    node.tokens = _visit_ast_items(transformer, node.tokens, "Hex string tokens")
    if hasattr(node, "identifier") and isinstance(node.identifier, str):
        node.identifier = pooled_value(transformer.string_pool, node.identifier)
    return node


def visit_regex_string(transformer: Any, node: RegexString) -> RegexString:
    node = _shallow(node)
    node.modifiers = _visit_items(transformer, node.modifiers)
    if hasattr(node, "identifier") and isinstance(node.identifier, str):
        node.identifier = pooled_value(transformer.string_pool, node.identifier)
    if hasattr(node, "regex") and isinstance(node.regex, str):
        node.regex = pooled_value(transformer.string_pool, node.regex)
    return node


def visit_extern_rule(transformer: Any, node: ExternRule) -> ExternRule:
    node = _shallow(node)
    node.name = pooled_value(transformer.string_pool, node.name)
    node.modifiers = _visit_items(transformer, node.modifiers)
    node.namespace = _pool_text(transformer, node.namespace)
    return node


def visit_extern_rule_reference(
    transformer: Any,
    node: ExternRuleReference,
) -> ExternRuleReference:
    node = _shallow(node)
    node.rule_name = pooled_value(transformer.string_pool, node.rule_name)
    node.namespace = _pool_text(transformer, node.namespace)
    return node


def visit_extern_import(transformer: Any, node: ExternImport) -> ExternImport:
    node = _shallow(node)
    node.module_path = pooled_value(transformer.string_pool, node.module_path)
    node.alias = _pool_text(transformer, node.alias)
    node.rules = _pool_text_list(transformer, node.rules)
    return node


def visit_extern_namespace(transformer: Any, node: ExternNamespace) -> ExternNamespace:
    node = _shallow(node)
    node.name = pooled_value(transformer.string_pool, node.name)
    node.extern_rules = [transformer.visit(rule) for rule in node.extern_rules]
    return node


def visit_pragma(transformer: Any, node: Pragma) -> Pragma:
    node = _shallow(node)
    dynamic_node = cast(Any, node)
    node.name = pooled_value(transformer.string_pool, node.name)
    node.arguments = _pool_text_list(transformer, node.arguments)

    macro_name = getattr(node, "macro_name", None)
    if isinstance(macro_name, str):
        dynamic_node.macro_name = pooled_value(transformer.string_pool, macro_name)

    macro_value = getattr(node, "macro_value", None)
    if isinstance(macro_value, str):
        dynamic_node.macro_value = pooled_value(transformer.string_pool, macro_value)

    condition = getattr(node, "condition", None)
    if isinstance(condition, str):
        dynamic_node.condition = pooled_value(transformer.string_pool, condition)

    parameters = getattr(node, "parameters", None)
    if isinstance(parameters, dict):
        pooled_parameters = {
            pooled_value(transformer.string_pool, key): _pool_parameter_value(
                transformer,
                value,
            )
            for key, value in cast(dict[str, Any], parameters).items()
        }
        dynamic_node.parameters = pooled_parameters

    return node


def visit_in_rule_pragma(transformer: Any, node: InRulePragma) -> InRulePragma:
    node = _shallow(node)
    node.pragma = transformer.visit(node.pragma)
    node.position = pooled_value(transformer.string_pool, node.position)
    return node


def visit_pragma_block(transformer: Any, node: PragmaBlock) -> PragmaBlock:
    node = _shallow(node)
    node.pragmas = [transformer.visit(pragma) for pragma in node.pragmas]
    return node


def visit_string_modifier(transformer: Any, node: StringModifier) -> StringModifier:
    node = _shallow(node)
    if isinstance(node.value, str):
        node.value = pooled_value(transformer.string_pool, node.value)
    return node
