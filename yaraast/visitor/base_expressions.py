"""Expression traversal mixin for BaseVisitor."""

from __future__ import annotations

from typing import TypeVar

from yaraast.ast.base import ASTNode
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
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.visitor.base_helpers import VisitorHelperProtocol

T = TypeVar("T")


class BaseVisitorExpressionsMixin:
    """Expression traversal methods."""

    def visit_expression(self: VisitorHelperProtocol[T], node: Expression) -> T:
        return self._noop()

    def visit_identifier(self: VisitorHelperProtocol[T], node: Identifier) -> T:
        return self._noop()

    def visit_string_identifier(self: VisitorHelperProtocol[T], node: StringIdentifier) -> T:
        return self._noop()

    def visit_string_wildcard(self: VisitorHelperProtocol[T], node: StringWildcard) -> T:
        return self._noop()

    def visit_string_count(self: VisitorHelperProtocol[T], node: StringCount) -> T:
        return self._noop()

    def visit_string_offset(self: VisitorHelperProtocol[T], node: StringOffset) -> T:
        self._visit_if(node.index)
        return self._noop()

    def visit_string_length(self: VisitorHelperProtocol[T], node: StringLength) -> T:
        self._visit_if(node.index)
        return self._noop()

    def visit_integer_literal(self: VisitorHelperProtocol[T], node: IntegerLiteral) -> T:
        return self._noop()

    def visit_double_literal(self: VisitorHelperProtocol[T], node: DoubleLiteral) -> T:
        return self._noop()

    def visit_string_literal(self: VisitorHelperProtocol[T], node: StringLiteral) -> T:
        return self._noop()

    def visit_regex_literal(self: VisitorHelperProtocol[T], node: RegexLiteral) -> T:
        return self._noop()

    def visit_boolean_literal(self: VisitorHelperProtocol[T], node: BooleanLiteral) -> T:
        return self._noop()

    def visit_binary_expression(self: VisitorHelperProtocol[T], node: BinaryExpression) -> T:
        self._visit_if(node.left)
        self._visit_if(node.right)
        return self._noop()

    def visit_unary_expression(self: VisitorHelperProtocol[T], node: UnaryExpression) -> T:
        self._visit_if(node.operand)
        return self._noop()

    def visit_parentheses_expression(
        self: VisitorHelperProtocol[T], node: ParenthesesExpression
    ) -> T:
        self._visit_if(node.expression)
        return self._noop()

    def visit_set_expression(self: VisitorHelperProtocol[T], node: SetExpression) -> T:
        self._visit_all(node.elements)
        return self._noop()

    def visit_range_expression(self: VisitorHelperProtocol[T], node: RangeExpression) -> T:
        self._visit_if(node.low)
        self._visit_if(node.high)
        return self._noop()

    def visit_function_call(self: VisitorHelperProtocol[T], node: FunctionCall) -> T:
        self._visit_all(node.arguments)
        return self._noop()

    def visit_array_access(self: VisitorHelperProtocol[T], node: ArrayAccess) -> T:
        self._visit_if(node.array)
        self._visit_if(node.index)
        return self._noop()

    def visit_member_access(self: VisitorHelperProtocol[T], node: MemberAccess) -> T:
        self._visit_if(node.object)
        return self._noop()

    def visit_condition(self: VisitorHelperProtocol[T], node: Condition) -> T:
        return self._noop()

    def visit_for_expression(self: VisitorHelperProtocol[T], node: ForExpression) -> T:
        self._visit_if(node.iterable)
        self._visit_if(node.body)
        return self._noop()

    def visit_for_of_expression(self: VisitorHelperProtocol[T], node: ForOfExpression) -> T:
        self._visit_if(node.string_set)
        self._visit_if(node.condition)
        return self._noop()

    def visit_at_expression(self: VisitorHelperProtocol[T], node: AtExpression) -> T:
        self._visit_if(node.offset)
        return self._noop()

    def visit_in_expression(self: VisitorHelperProtocol[T], node: InExpression) -> T:
        self._visit_if(node.range)
        return self._noop()

    def visit_of_expression(self: VisitorHelperProtocol[T], node: OfExpression) -> T:
        self._visit_if(node.quantifier)
        self._visit_if(node.string_set)
        return self._noop()

    def visit_module_reference(self: VisitorHelperProtocol[T], node: ModuleReference) -> T:
        return self._noop()

    def visit_dictionary_access(self: VisitorHelperProtocol[T], node: DictionaryAccess) -> T:
        self._visit_if(node.object)
        if isinstance(node.key, ASTNode):
            self._visit_if(node.key)
        return self._noop()

    def visit_defined_expression(self: VisitorHelperProtocol[T], node: DefinedExpression) -> T:
        self._visit_if(node.expression)
        return self._noop()

    def visit_string_operator_expression(
        self: VisitorHelperProtocol[T], node: StringOperatorExpression
    ) -> T:
        self._visit_if(node.left)
        self._visit_if(node.right)
        return self._noop()
