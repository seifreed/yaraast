"""Visitor pattern interfaces and base implementations."""

from __future__ import annotations

from abc import ABC, abstractmethod
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


class ASTVisitor[T](ABC):
    """Base visitor class for traversing AST nodes."""

    def visit(self, node: ASTNode) -> T:
        """Visit a node by calling its accept method."""
        return cast(T, node.accept(self))

    # Base nodes
    @abstractmethod
    def visit_yara_file(self, node: YaraFile) -> T:
        """Visit YaraFile node."""

    @abstractmethod
    def visit_import(self, node: Import) -> T:
        """Visit Import node."""

    @abstractmethod
    def visit_include(self, node: Include) -> T:
        """Visit Include node."""

    @abstractmethod
    def visit_rule(self, node: Rule) -> T:
        """Visit Rule node."""

    @abstractmethod
    def visit_tag(self, node: Tag) -> T:
        """Visit Tag node."""

    # String definitions
    @abstractmethod
    def visit_string_definition(self, node: StringDefinition) -> T:
        """Visit StringDefinition node."""

    @abstractmethod
    def visit_plain_string(self, node: PlainString) -> T:
        """Visit PlainString node."""

    @abstractmethod
    def visit_hex_string(self, node: HexString) -> T:
        """Visit HexString node."""

    @abstractmethod
    def visit_regex_string(self, node: RegexString) -> T:
        """Visit RegexString node."""

    @abstractmethod
    def visit_string_modifier(self, node: StringModifier) -> T:
        """Visit StringModifier node."""

    # Hex tokens
    @abstractmethod
    def visit_hex_token(self, node: HexToken) -> T:
        """Visit HexToken node."""

    @abstractmethod
    def visit_hex_byte(self, node: HexByte) -> T:
        """Visit HexByte node."""

    @abstractmethod
    def visit_hex_wildcard(self, node: HexWildcard) -> T:
        """Visit HexWildcard node."""

    @abstractmethod
    def visit_hex_jump(self, node: HexJump) -> T:
        """Visit HexJump node."""

    @abstractmethod
    def visit_hex_alternative(self, node: HexAlternative) -> T:
        """Visit HexAlternative node."""

    @abstractmethod
    def visit_hex_nibble(self, node: HexNibble) -> T:
        """Visit HexNibble node."""

    # Expressions
    @abstractmethod
    def visit_expression(self, node: Expression) -> T:
        """Visit Expression node."""

    @abstractmethod
    def visit_identifier(self, node: Identifier) -> T:
        """Visit Identifier node."""

    @abstractmethod
    def visit_string_identifier(self, node: StringIdentifier) -> T:
        """Visit StringIdentifier node."""

    @abstractmethod
    def visit_string_wildcard(self, node: StringWildcard) -> T:
        """Visit StringWildcard node."""

    @abstractmethod
    def visit_string_count(self, node: StringCount) -> T:
        """Visit StringCount node."""

    @abstractmethod
    def visit_string_offset(self, node: StringOffset) -> T:
        """Visit StringOffset node."""

    @abstractmethod
    def visit_string_length(self, node: StringLength) -> T:
        """Visit StringLength node."""

    @abstractmethod
    def visit_integer_literal(self, node: IntegerLiteral) -> T:
        """Visit IntegerLiteral node."""

    @abstractmethod
    def visit_double_literal(self, node: DoubleLiteral) -> T:
        """Visit DoubleLiteral node."""

    @abstractmethod
    def visit_string_literal(self, node: StringLiteral) -> T:
        """Visit StringLiteral node."""

    @abstractmethod
    def visit_regex_literal(self, node: RegexLiteral) -> T:
        """Visit RegexLiteral node."""

    @abstractmethod
    def visit_boolean_literal(self, node: BooleanLiteral) -> T:
        """Visit BooleanLiteral node."""

    @abstractmethod
    def visit_binary_expression(self, node: BinaryExpression) -> T:
        """Visit BinaryExpression node."""

    @abstractmethod
    def visit_unary_expression(self, node: UnaryExpression) -> T:
        """Visit UnaryExpression node."""

    @abstractmethod
    def visit_parentheses_expression(self, node: ParenthesesExpression) -> T:
        """Visit ParenthesesExpression node."""

    @abstractmethod
    def visit_set_expression(self, node: SetExpression) -> T:
        """Visit SetExpression node."""

    @abstractmethod
    def visit_range_expression(self, node: RangeExpression) -> T:
        """Visit RangeExpression node."""

    @abstractmethod
    def visit_function_call(self, node: FunctionCall) -> T:
        """Visit FunctionCall node."""

    @abstractmethod
    def visit_array_access(self, node: ArrayAccess) -> T:
        """Visit ArrayAccess node."""

    @abstractmethod
    def visit_member_access(self, node: MemberAccess) -> T:
        """Visit MemberAccess node."""

    # Conditions
    @abstractmethod
    def visit_condition(self, node: Condition) -> T:
        """Visit Condition node."""

    @abstractmethod
    def visit_for_expression(self, node: ForExpression) -> T:
        """Visit ForExpression node."""

    @abstractmethod
    def visit_for_of_expression(self, node: ForOfExpression) -> T:
        """Visit ForOfExpression node."""

    @abstractmethod
    def visit_at_expression(self, node: AtExpression) -> T:
        """Visit AtExpression node."""

    @abstractmethod
    def visit_in_expression(self, node: InExpression) -> T:
        """Visit InExpression node."""

    @abstractmethod
    def visit_of_expression(self, node: OfExpression) -> T:
        """Visit OfExpression node."""

    # Meta
    @abstractmethod
    def visit_meta(self, node: Meta) -> T:
        """Visit Meta node."""

    # Modules
    @abstractmethod
    def visit_module_reference(self, node: ModuleReference) -> T:
        """Visit ModuleReference node."""

    @abstractmethod
    def visit_dictionary_access(self, node: DictionaryAccess) -> T:
        """Visit DictionaryAccess node."""

    # Comments
    @abstractmethod
    def visit_comment(self, node: Comment) -> T:
        """Visit Comment node."""

    @abstractmethod
    def visit_comment_group(self, node: CommentGroup) -> T:
        """Visit CommentGroup node."""

    # Operators
    @abstractmethod
    def visit_defined_expression(self, node: DefinedExpression) -> T:
        """Visit DefinedExpression node."""

    @abstractmethod
    def visit_string_operator_expression(
        self,
        node: StringOperatorExpression,
    ) -> T:
        """Visit StringOperatorExpression node."""

    # Extern rules and references
    @abstractmethod
    def visit_extern_rule(self, node: ExternRule) -> T:
        """Visit ExternRule node."""

    @abstractmethod
    def visit_extern_rule_reference(self, node: ExternRuleReference) -> T:
        """Visit ExternRuleReference node."""

    @abstractmethod
    def visit_extern_import(self, node: ExternImport) -> T:
        """Visit ExternImport node."""

    @abstractmethod
    def visit_extern_namespace(self, node: ExternNamespace) -> T:
        """Visit ExternNamespace node."""

    # Pragmas and directives
    @abstractmethod
    def visit_pragma(self, node: Pragma) -> T:
        """Visit Pragma node."""

    @abstractmethod
    def visit_in_rule_pragma(self, node: InRulePragma) -> T:
        """Visit InRulePragma node."""

    @abstractmethod
    def visit_pragma_block(self, node: PragmaBlock) -> T:
        """Visit PragmaBlock node."""


__all__ = ["ASTVisitor"]
