"""Expression AST nodes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from yaraast.ast.base import ASTNode


@dataclass
class Expression(ASTNode):
    """Base class for all expressions."""

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_expression(self)


@dataclass
class Identifier(Expression):
    """Identifier expression."""

    name: str

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_identifier(self)


@dataclass
class StringIdentifier(Expression):
    """String identifier (e.g., $str1)."""

    name: str

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_string_identifier(self)


@dataclass
class StringCount(Expression):
    """String count expression (#str)."""

    string_id: str

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_string_count(self)


@dataclass
class StringOffset(Expression):
    """String offset expression (@str or @str[i])."""

    string_id: str
    index: Expression | None = None

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_string_offset(self)


@dataclass
class StringLength(Expression):
    """String length expression (!str or !str[i])."""

    string_id: str
    index: Expression | None = None

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_string_length(self)


@dataclass
class IntegerLiteral(Expression):
    """Integer literal."""

    value: int

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_integer_literal(self)


@dataclass
class DoubleLiteral(Expression):
    """Double/float literal."""

    value: float

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_double_literal(self)


@dataclass
class StringLiteral(Expression):
    """String literal."""

    value: str

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_string_literal(self)


@dataclass
class RegexLiteral(Expression):
    """Regex literal expression (e.g., /foo.*bar/i)."""

    pattern: str
    modifiers: str = ""  # i for case-insensitive, s for single-line, etc.

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_regex_literal(self)


@dataclass
class BooleanLiteral(Expression):
    """Boolean literal."""

    value: bool

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_boolean_literal(self)


@dataclass
class BinaryExpression(Expression):
    """Binary expression."""

    left: Expression
    operator: str
    right: Expression

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_binary_expression(self)


@dataclass
class UnaryExpression(Expression):
    """Unary expression."""

    operator: str
    operand: Expression

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_unary_expression(self)


@dataclass
class ParenthesesExpression(Expression):
    """Parentheses expression."""

    expression: Expression

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_parentheses_expression(self)


@dataclass
class SetExpression(Expression):
    """Set expression (a, b, c)."""

    elements: list[Expression]

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_set_expression(self)


@dataclass
class RangeExpression(Expression):
    """Range expression (a..b)."""

    low: Expression
    high: Expression

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_range_expression(self)


@dataclass
class FunctionCall(Expression):
    """Function call expression."""

    function: str
    arguments: list[Expression]

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_function_call(self)


@dataclass
class ArrayAccess(Expression):
    """Array access expression."""

    array: Expression
    index: Expression

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_array_access(self)


@dataclass
class MemberAccess(Expression):
    """Member access expression (a.b)."""

    object: Expression
    member: str

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_member_access(self)
