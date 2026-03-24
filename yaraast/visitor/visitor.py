"""Visitor pattern interfaces and base implementations."""

from __future__ import annotations

from abc import ABC
from typing import TypeVar, cast

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

T = TypeVar("T")


class ASTVisitor[T](ABC):  # noqa: B024
    """Base visitor class for traversing AST nodes.

    Subclasses only need to override the visit methods they care about.
    Unimplemented visit methods raise NotImplementedError via _default_visit.
    """

    def _default_visit(self, node: ASTNode) -> T:
        """Default handler for unimplemented visit methods.

        Override this to define behavior for unhandled nodes.
        Common implementations: return a default value, raise NotImplementedError,
        or delegate to a generic traversal.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not implement visit for {type(node).__name__}"
        )

    def visit(self, node: ASTNode) -> T:
        """Visit a node by calling its accept method."""
        return cast(T, node.accept(self))

    # Base nodes
    def visit_yara_file(self, node: YaraFile) -> T:
        """Visit YaraFile node."""
        return self._default_visit(node)

    def visit_import(self, node: Import) -> T:
        """Visit Import node."""
        return self._default_visit(node)

    def visit_include(self, node: Include) -> T:
        """Visit Include node."""
        return self._default_visit(node)

    def visit_rule(self, node: Rule) -> T:
        """Visit Rule node."""
        return self._default_visit(node)

    def visit_tag(self, node: Tag) -> T:
        """Visit Tag node."""
        return self._default_visit(node)

    # String definitions
    def visit_string_definition(self, node: StringDefinition) -> T:
        """Visit StringDefinition node."""
        return self._default_visit(node)

    def visit_plain_string(self, node: PlainString) -> T:
        """Visit PlainString node."""
        return self._default_visit(node)

    def visit_hex_string(self, node: HexString) -> T:
        """Visit HexString node."""
        return self._default_visit(node)

    def visit_regex_string(self, node: RegexString) -> T:
        """Visit RegexString node."""
        return self._default_visit(node)

    def visit_string_modifier(self, node: StringModifier) -> T:
        """Visit StringModifier node."""
        return self._default_visit(node)

    # Hex tokens
    def visit_hex_token(self, node: HexToken) -> T:
        """Visit HexToken node."""
        return self._default_visit(node)

    def visit_hex_byte(self, node: HexByte) -> T:
        """Visit HexByte node."""
        return self._default_visit(node)

    def visit_hex_wildcard(self, node: HexWildcard) -> T:
        """Visit HexWildcard node."""
        return self._default_visit(node)

    def visit_hex_jump(self, node: HexJump) -> T:
        """Visit HexJump node."""
        return self._default_visit(node)

    def visit_hex_alternative(self, node: HexAlternative) -> T:
        """Visit HexAlternative node."""
        return self._default_visit(node)

    def visit_hex_nibble(self, node: HexNibble) -> T:
        """Visit HexNibble node."""
        return self._default_visit(node)

    # Expressions
    def visit_expression(self, node: Expression) -> T:
        """Visit Expression node."""
        return self._default_visit(node)

    def visit_identifier(self, node: Identifier) -> T:
        """Visit Identifier node."""
        return self._default_visit(node)

    def visit_string_identifier(self, node: StringIdentifier) -> T:
        """Visit StringIdentifier node."""
        return self._default_visit(node)

    def visit_string_wildcard(self, node: StringWildcard) -> T:
        """Visit StringWildcard node."""
        return self._default_visit(node)

    def visit_string_count(self, node: StringCount) -> T:
        """Visit StringCount node."""
        return self._default_visit(node)

    def visit_string_offset(self, node: StringOffset) -> T:
        """Visit StringOffset node."""
        return self._default_visit(node)

    def visit_string_length(self, node: StringLength) -> T:
        """Visit StringLength node."""
        return self._default_visit(node)

    def visit_integer_literal(self, node: IntegerLiteral) -> T:
        """Visit IntegerLiteral node."""
        return self._default_visit(node)

    def visit_double_literal(self, node: DoubleLiteral) -> T:
        """Visit DoubleLiteral node."""
        return self._default_visit(node)

    def visit_string_literal(self, node: StringLiteral) -> T:
        """Visit StringLiteral node."""
        return self._default_visit(node)

    def visit_regex_literal(self, node: RegexLiteral) -> T:
        """Visit RegexLiteral node."""
        return self._default_visit(node)

    def visit_boolean_literal(self, node: BooleanLiteral) -> T:
        """Visit BooleanLiteral node."""
        return self._default_visit(node)

    def visit_binary_expression(self, node: BinaryExpression) -> T:
        """Visit BinaryExpression node."""
        return self._default_visit(node)

    def visit_unary_expression(self, node: UnaryExpression) -> T:
        """Visit UnaryExpression node."""
        return self._default_visit(node)

    def visit_parentheses_expression(self, node: ParenthesesExpression) -> T:
        """Visit ParenthesesExpression node."""
        return self._default_visit(node)

    def visit_set_expression(self, node: SetExpression) -> T:
        """Visit SetExpression node."""
        return self._default_visit(node)

    def visit_range_expression(self, node: RangeExpression) -> T:
        """Visit RangeExpression node."""
        return self._default_visit(node)

    def visit_function_call(self, node: FunctionCall) -> T:
        """Visit FunctionCall node."""
        return self._default_visit(node)

    def visit_array_access(self, node: ArrayAccess) -> T:
        """Visit ArrayAccess node."""
        return self._default_visit(node)

    def visit_member_access(self, node: MemberAccess) -> T:
        """Visit MemberAccess node."""
        return self._default_visit(node)

    # Conditions
    def visit_condition(self, node: Condition) -> T:
        """Visit Condition node."""
        return self._default_visit(node)

    def visit_for_expression(self, node: ForExpression) -> T:
        """Visit ForExpression node."""
        return self._default_visit(node)

    def visit_for_of_expression(self, node: ForOfExpression) -> T:
        """Visit ForOfExpression node."""
        return self._default_visit(node)

    def visit_at_expression(self, node: AtExpression) -> T:
        """Visit AtExpression node."""
        return self._default_visit(node)

    def visit_in_expression(self, node: InExpression) -> T:
        """Visit InExpression node."""
        return self._default_visit(node)

    def visit_of_expression(self, node: OfExpression) -> T:
        """Visit OfExpression node."""
        return self._default_visit(node)

    # Meta
    def visit_meta(self, node: Meta) -> T:
        """Visit Meta node."""
        return self._default_visit(node)

    # Modules
    def visit_module_reference(self, node: ModuleReference) -> T:
        """Visit ModuleReference node."""
        return self._default_visit(node)

    def visit_dictionary_access(self, node: DictionaryAccess) -> T:
        """Visit DictionaryAccess node."""
        return self._default_visit(node)

    # Comments
    def visit_comment(self, node: Comment) -> T:
        """Visit Comment node."""
        return self._default_visit(node)

    def visit_comment_group(self, node: CommentGroup) -> T:
        """Visit CommentGroup node."""
        return self._default_visit(node)

    # Operators
    def visit_defined_expression(self, node: DefinedExpression) -> T:
        """Visit DefinedExpression node."""
        return self._default_visit(node)

    def visit_string_operator_expression(
        self,
        node: StringOperatorExpression,
    ) -> T:
        """Visit StringOperatorExpression node."""
        return self._default_visit(node)

    # Extern rules and references
    def visit_extern_rule(self, node: ExternRule) -> T:
        """Visit ExternRule node."""
        return self._default_visit(node)

    def visit_extern_rule_reference(self, node: ExternRuleReference) -> T:
        """Visit ExternRuleReference node."""
        return self._default_visit(node)

    def visit_extern_import(self, node: ExternImport) -> T:
        """Visit ExternImport node."""
        return self._default_visit(node)

    def visit_extern_namespace(self, node: ExternNamespace) -> T:
        """Visit ExternNamespace node."""
        return self._default_visit(node)

    # Pragmas and directives
    def visit_pragma(self, node: Pragma) -> T:
        """Visit Pragma node."""
        return self._default_visit(node)

    def visit_in_rule_pragma(self, node: InRulePragma) -> T:
        """Visit InRulePragma node."""
        return self._default_visit(node)

    def visit_pragma_block(self, node: PragmaBlock) -> T:
        """Visit PragmaBlock node."""
        return self._default_visit(node)


__all__ = ["ASTVisitor"]
