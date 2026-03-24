"""Default visitor implementations."""

from __future__ import annotations

from typing import TypeVar

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

T = TypeVar("T")


class DefaultASTVisitor(ASTVisitor[T]):
    """Visitor with default no-op implementations."""

    def __init__(self, default: T) -> None:
        self._default = default

    def _default_visit(self, node: ASTNode) -> T:
        return self._default

    def visit_yara_file(self, node: YaraFile) -> T:
        return self._default

    def visit_import(self, node: Import) -> T:
        return self._default

    def visit_include(self, node: Include) -> T:
        return self._default

    def visit_rule(self, node: Rule) -> T:
        return self._default

    def visit_tag(self, node: Tag) -> T:
        return self._default

    def visit_string_definition(self, node: StringDefinition) -> T:
        return self._default

    def visit_plain_string(self, node: PlainString) -> T:
        return self._default

    def visit_hex_string(self, node: HexString) -> T:
        return self._default

    def visit_regex_string(self, node: RegexString) -> T:
        return self._default

    def visit_string_modifier(self, node: StringModifier) -> T:
        return self._default

    def visit_hex_token(self, node: HexToken) -> T:
        return self._default

    def visit_hex_byte(self, node: HexByte) -> T:
        return self._default

    def visit_hex_wildcard(self, node: HexWildcard) -> T:
        return self._default

    def visit_hex_jump(self, node: HexJump) -> T:
        return self._default

    def visit_hex_alternative(self, node: HexAlternative) -> T:
        return self._default

    def visit_hex_nibble(self, node: HexNibble) -> T:
        return self._default

    def visit_expression(self, node: Expression) -> T:
        return self._default

    def visit_identifier(self, node: Identifier) -> T:
        return self._default

    def visit_string_identifier(self, node: StringIdentifier) -> T:
        return self._default

    def visit_string_wildcard(self, node: StringWildcard) -> T:
        return self._default

    def visit_string_count(self, node: StringCount) -> T:
        return self._default

    def visit_string_offset(self, node: StringOffset) -> T:
        return self._default

    def visit_string_length(self, node: StringLength) -> T:
        return self._default

    def visit_integer_literal(self, node: IntegerLiteral) -> T:
        return self._default

    def visit_double_literal(self, node: DoubleLiteral) -> T:
        return self._default

    def visit_string_literal(self, node: StringLiteral) -> T:
        return self._default

    def visit_regex_literal(self, node: RegexLiteral) -> T:
        return self._default

    def visit_boolean_literal(self, node: BooleanLiteral) -> T:
        return self._default

    def visit_binary_expression(self, node: BinaryExpression) -> T:
        return self._default

    def visit_unary_expression(self, node: UnaryExpression) -> T:
        return self._default

    def visit_parentheses_expression(self, node: ParenthesesExpression) -> T:
        return self._default

    def visit_set_expression(self, node: SetExpression) -> T:
        return self._default

    def visit_range_expression(self, node: RangeExpression) -> T:
        return self._default

    def visit_function_call(self, node: FunctionCall) -> T:
        return self._default

    def visit_array_access(self, node: ArrayAccess) -> T:
        return self._default

    def visit_member_access(self, node: MemberAccess) -> T:
        return self._default

    def visit_condition(self, node: Condition) -> T:
        return self._default

    def visit_for_expression(self, node: ForExpression) -> T:
        return self._default

    def visit_for_of_expression(self, node: ForOfExpression) -> T:
        return self._default

    def visit_at_expression(self, node: AtExpression) -> T:
        return self._default

    def visit_in_expression(self, node: InExpression) -> T:
        return self._default

    def visit_of_expression(self, node: OfExpression) -> T:
        return self._default

    def visit_meta(self, node: Meta) -> T:
        return self._default

    def visit_module_reference(self, node: ModuleReference) -> T:
        return self._default

    def visit_dictionary_access(self, node: DictionaryAccess) -> T:
        return self._default

    def visit_comment(self, node: Comment) -> T:
        return self._default

    def visit_comment_group(self, node: CommentGroup) -> T:
        return self._default

    def visit_defined_expression(self, node: DefinedExpression) -> T:
        return self._default

    def visit_string_operator_expression(self, node: StringOperatorExpression) -> T:
        return self._default

    def visit_extern_import(self, node: ExternImport) -> T:
        return self._default

    def visit_extern_namespace(self, node: ExternNamespace) -> T:
        return self._default

    def visit_extern_rule(self, node: ExternRule) -> T:
        return self._default

    def visit_extern_rule_reference(self, node: ExternRuleReference) -> T:
        return self._default

    def visit_in_rule_pragma(self, node: InRulePragma) -> T:
        return self._default

    def visit_pragma(self, node: Pragma) -> T:
        return self._default

    def visit_pragma_block(self, node: PragmaBlock) -> T:
        return self._default
