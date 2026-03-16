"""ASTTransformer implementation for AST rewrites."""

from __future__ import annotations

from dataclasses import fields, is_dataclass, replace
from typing import Any, TypeVar

from yaraast.ast.base import ASTNode, YaraFile
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.conditions import (
    AtExpression,
    Condition,
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
    Expression,
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
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNibble,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
)
from yaraast.visitor.visitor import ASTVisitor

T = TypeVar("T", bound=ASTNode)


class ASTTransformer(ASTVisitor[ASTNode]):
    """Transformer that rebuilds AST nodes with transformed children."""

    def _transform_node(self, node: T) -> T:
        if not is_dataclass(node):
            return node

        kwargs: dict[str, Any] = {}
        for f in fields(node):
            if not f.init:
                continue
            value = getattr(node, f.name)
            if isinstance(value, ASTNode):
                kwargs[f.name] = self.visit(value)
            elif isinstance(value, list):
                new_list = [self.visit(v) if isinstance(v, ASTNode) else v for v in value]
                kwargs[f.name] = new_list
            else:
                kwargs[f.name] = value

        return replace(node, **kwargs)

    def visit_yara_file(self, node: YaraFile) -> ASTNode:
        return self._transform_node(node)

    def visit_import(self, node: Import) -> ASTNode:
        return self._transform_node(node)

    def visit_include(self, node: Include) -> ASTNode:
        return self._transform_node(node)

    def visit_rule(self, node: Rule) -> ASTNode:
        return self._transform_node(node)

    def visit_tag(self, node: Tag) -> ASTNode:
        return self._transform_node(node)

    def visit_string_definition(self, node: StringDefinition) -> ASTNode:
        return self._transform_node(node)

    def visit_plain_string(self, node: PlainString) -> ASTNode:
        return self._transform_node(node)

    def visit_hex_string(self, node: HexString) -> ASTNode:
        return self._transform_node(node)

    def visit_regex_string(self, node: RegexString) -> ASTNode:
        return self._transform_node(node)

    def visit_string_modifier(self, node: StringModifier) -> ASTNode:
        return self._transform_node(node)

    def visit_hex_token(self, node: HexToken) -> ASTNode:
        return self._transform_node(node)

    def visit_hex_byte(self, node: HexByte) -> ASTNode:
        return self._transform_node(node)

    def visit_hex_wildcard(self, node: HexWildcard) -> ASTNode:
        return self._transform_node(node)

    def visit_hex_jump(self, node: HexJump) -> ASTNode:
        return self._transform_node(node)

    def visit_hex_alternative(self, node: HexAlternative) -> ASTNode:
        return self._transform_node(node)

    def visit_hex_nibble(self, node: HexNibble) -> ASTNode:
        return self._transform_node(node)

    def visit_expression(self, node: Expression) -> ASTNode:
        return self._transform_node(node)

    def visit_identifier(self, node: Identifier) -> ASTNode:
        return self._transform_node(node)

    def visit_string_identifier(self, node: StringIdentifier) -> ASTNode:
        return self._transform_node(node)

    def visit_string_wildcard(self, node: StringWildcard) -> ASTNode:
        return self._transform_node(node)

    def visit_string_count(self, node: StringCount) -> ASTNode:
        return self._transform_node(node)

    def visit_string_offset(self, node: StringOffset) -> ASTNode:
        return self._transform_node(node)

    def visit_string_length(self, node: StringLength) -> ASTNode:
        return self._transform_node(node)

    def visit_integer_literal(self, node: IntegerLiteral) -> ASTNode:
        return self._transform_node(node)

    def visit_double_literal(self, node: DoubleLiteral) -> ASTNode:
        return self._transform_node(node)

    def visit_string_literal(self, node: StringLiteral) -> ASTNode:
        return self._transform_node(node)

    def visit_regex_literal(self, node: RegexLiteral) -> ASTNode:
        return self._transform_node(node)

    def visit_boolean_literal(self, node: BooleanLiteral) -> ASTNode:
        return self._transform_node(node)

    def visit_binary_expression(self, node: BinaryExpression) -> ASTNode:
        return self._transform_node(node)

    def visit_unary_expression(self, node: UnaryExpression) -> ASTNode:
        return self._transform_node(node)

    def visit_parentheses_expression(self, node: ParenthesesExpression) -> ASTNode:
        return self._transform_node(node)

    def visit_set_expression(self, node: SetExpression) -> ASTNode:
        return self._transform_node(node)

    def visit_range_expression(self, node: RangeExpression) -> ASTNode:
        return self._transform_node(node)

    def visit_function_call(self, node: FunctionCall) -> ASTNode:
        return self._transform_node(node)

    def visit_array_access(self, node: ArrayAccess) -> ASTNode:
        return self._transform_node(node)

    def visit_member_access(self, node: MemberAccess) -> ASTNode:
        return self._transform_node(node)

    def visit_condition(self, node: Condition) -> ASTNode:
        return self._transform_node(node)

    def visit_for_expression(self, node: ForExpression) -> ASTNode:
        return self._transform_node(node)

    def visit_for_of_expression(self, node: ForOfExpression) -> ASTNode:
        return self._transform_node(node)

    def visit_at_expression(self, node: AtExpression) -> ASTNode:
        return self._transform_node(node)

    def visit_in_expression(self, node: InExpression) -> ASTNode:
        return self._transform_node(node)

    def visit_of_expression(self, node: OfExpression) -> ASTNode:
        return self._transform_node(node)

    def visit_meta(self, node: Meta) -> ASTNode:
        return self._transform_node(node)

    def visit_module_reference(self, node: ModuleReference) -> ASTNode:
        return self._transform_node(node)

    def visit_dictionary_access(self, node: DictionaryAccess) -> ASTNode:
        return self._transform_node(node)

    def visit_comment(self, node: Comment) -> ASTNode:
        return self._transform_node(node)

    def visit_comment_group(self, node: CommentGroup) -> ASTNode:
        return self._transform_node(node)

    def visit_defined_expression(self, node: DefinedExpression) -> ASTNode:
        return self._transform_node(node)

    def visit_string_operator_expression(self, node: StringOperatorExpression) -> ASTNode:
        return self._transform_node(node)

    def visit_extern_rule(self, node: ExternRule) -> ASTNode:
        return self._transform_node(node)

    def visit_extern_rule_reference(self, node: ExternRuleReference) -> ASTNode:
        return self._transform_node(node)

    def visit_extern_import(self, node: ExternImport) -> ASTNode:
        return self._transform_node(node)

    def visit_extern_namespace(self, node: ExternNamespace) -> ASTNode:
        return self._transform_node(node)

    def visit_pragma(self, node: Pragma) -> ASTNode:
        return self._transform_node(node)

    def visit_in_rule_pragma(self, node: InRulePragma) -> ASTNode:
        return self._transform_node(node)

    def visit_pragma_block(self, node: PragmaBlock) -> ASTNode:
        return self._transform_node(node)
