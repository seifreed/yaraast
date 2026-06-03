"""Expression AST nodes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from yaraast.ast.base import ASTNode, _VisitorType


@dataclass
class Expression(ASTNode):
    """Base class for all expressions."""

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_expression(self)


@dataclass
class Identifier(Expression):
    """Identifier expression."""

    name: str

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_identifier(self)


@dataclass
class StringIdentifier(Expression):
    """String identifier (e.g., $str1)."""

    name: str

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_string_identifier(self)


@dataclass
class StringWildcard(Expression):
    """String wildcard pattern (e.g., $a*, $prefix*)."""

    pattern: str

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_string_wildcard(self)


@dataclass
class StringCount(Expression):
    """String count expression (#str)."""

    string_id: str

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_string_count(self)


@dataclass
class StringOffset(Expression):
    """String offset expression (@str or @str[i])."""

    string_id: str
    index: Expression | None = None

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_string_offset(self)


@dataclass
class StringLength(Expression):
    """String length expression (!str or !str[i])."""

    string_id: str
    index: Expression | None = None

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_string_length(self)


@dataclass
class IntegerLiteral(Expression):
    """Integer literal."""

    value: int

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_integer_literal(self)


@dataclass
class DoubleLiteral(Expression):
    """Double/float literal."""

    value: float

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_double_literal(self)


@dataclass
class StringLiteral(Expression):
    """String literal."""

    value: str

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_string_literal(self)


@dataclass
class RegexLiteral(Expression):
    """Regex literal expression (e.g., /foo.*bar/i)."""

    pattern: str
    modifiers: str = ""  # i for case-insensitive, s for single-line, etc.

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_regex_literal(self)


@dataclass
class BooleanLiteral(Expression):
    """Boolean literal."""

    value: bool

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_boolean_literal(self)


@dataclass
class BinaryExpression(Expression):
    """Binary expression."""

    left: Expression
    operator: str
    right: Expression

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_binary_expression(self)


@dataclass
class UnaryExpression(Expression):
    """Unary expression."""

    operator: str
    operand: Expression

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_unary_expression(self)


@dataclass
class ParenthesesExpression(Expression):
    """Parentheses expression."""

    expression: Expression

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_parentheses_expression(self)


@dataclass
class SetExpression(Expression):
    """Set expression (a, b, c)."""

    elements: list[Expression]

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_set_expression(self)


@dataclass
class RangeExpression(Expression):
    """Range expression (a..b)."""

    low: Expression
    high: Expression

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_range_expression(self)


@dataclass
class FunctionCall(Expression):
    """Function call expression.

    ``function`` carries the callee name. For an identifier-chain callee it is
    the full dotted path (``uint16``, ``pe.imphash``, ``pe.rich_signature.version``)
    and ``receiver`` is ``None``. When the callee's object cannot be a pure dotted
    path because it indexes into an array or dictionary (``pe.signatures[0].valid_on``),
    ``receiver`` holds that object expression and ``function`` is just the method
    name (``valid_on``).
    """

    function: str
    arguments: list[Expression]
    receiver: Expression | None = None

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_function_call(self)

    def qualified_name(self) -> str:
        """Dotted display name, with indexed receivers flattened (no indices)."""
        if self.receiver is None:
            return self.function
        base = _receiver_identifier_path(self.receiver)
        return f"{base}.{self.function}" if base else self.function

    def module_and_function(self) -> tuple[str, str] | None:
        """Resolve to ``(module_alias, function_key)`` for a module call, else None.

        Builtins and unqualified calls return ``None``. The function key matches
        the dotted keys used in module definitions (e.g. ``signatures.valid_on``).
        """
        if self.receiver is None:
            if "." in self.function:
                module_name, func_name = self.function.split(".", 1)
                return module_name, func_name
            return None
        base, members = _receiver_base_and_members(self.receiver)
        if base is None:
            return None
        return base, ".".join([*members, self.function])


def _receiver_base_and_members(expr: Any) -> tuple[str | None, list[str]]:
    """Walk a callee object expression to ``(base_identifier, member_path)``.

    Array and dictionary indices are dropped so the member path matches the
    declared (index-free) module member keys.
    """
    from yaraast.ast.modules import DictionaryAccess, ModuleReference

    members: list[str] = []
    current = expr
    while True:
        if isinstance(current, MemberAccess):
            members.append(current.member)
            current = current.object
        elif isinstance(current, ArrayAccess):
            current = current.array
        elif isinstance(current, DictionaryAccess):
            current = current.object
        elif isinstance(current, Identifier):
            return current.name, list(reversed(members))
        elif isinstance(current, ModuleReference):
            return current.module, list(reversed(members))
        else:
            return None, []


def _receiver_identifier_path(expr: Any) -> str | None:
    base, members = _receiver_base_and_members(expr)
    if base is None:
        return None
    return ".".join([base, *members]) if members else base


@dataclass
class ArrayAccess(Expression):
    """Array access expression."""

    array: Expression
    index: Expression

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_array_access(self)


@dataclass
class MemberAccess(Expression):
    """Member access expression (a.b)."""

    object: Expression
    member: str

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_member_access(self)
