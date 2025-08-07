"""Fluent builder for conditions."""

from __future__ import annotations

from typing import Self

from yaraast.ast.conditions import AtExpression, ForExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    Expression,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    UnaryExpression,
)


class ConditionBuilder:
    """Fluent builder for constructing conditions."""

    def __init__(self, expr: Expression | None = None) -> None:
        self._expression = expr

    # String references
    def string(self, identifier: str) -> Self:
        """Reference a string identifier."""
        return ConditionBuilder(StringIdentifier(name=identifier))

    def string_count(self, identifier: str) -> Self:
        """Reference string count (#string)."""
        return ConditionBuilder(StringCount(string_id=identifier.lstrip("#")))

    def string_offset(self, identifier: str, index: int | None = None) -> Self:
        """Reference string offset (@string or @string[i])."""
        index_expr = IntegerLiteral(value=index) if index is not None else None
        return ConditionBuilder(
            StringOffset(string_id=identifier.lstrip("@"), index=index_expr),
        )

    def string_length(self, identifier: str, index: int | None = None) -> Self:
        """Reference string length (!string or !string[i])."""
        index_expr = IntegerLiteral(value=index) if index is not None else None
        return ConditionBuilder(
            StringLength(string_id=identifier.lstrip("!"), index=index_expr),
        )

    # Literals
    def true(self) -> Self:
        """Boolean true."""
        return ConditionBuilder(BooleanLiteral(value=True))

    def false(self) -> Self:
        """Boolean false."""
        return ConditionBuilder(BooleanLiteral(value=False))

    def integer(self, value: int) -> Self:
        """Integer literal."""
        return ConditionBuilder(IntegerLiteral(value=value))

    def filesize(self) -> Self:
        """Filesize keyword."""
        return ConditionBuilder(Identifier(name="filesize"))

    def entrypoint(self) -> Self:
        """Entrypoint keyword."""
        return ConditionBuilder(Identifier(name="entrypoint"))

    def identifier(self, name: str) -> Self:
        """Generic identifier."""
        return ConditionBuilder(Identifier(name=name))

    def range(self, start: int | ConditionBuilder, end: int | ConditionBuilder) -> Self:
        """Create a range expression."""
        start_expr = self._to_expression(start)
        end_expr = self._to_expression(end)
        return ConditionBuilder(RangeExpression(low=start_expr, high=end_expr))

    def member_access(self, obj: ConditionBuilder | Expression, member: str) -> Self:
        """Member access (obj.member)."""
        obj_expr = self._to_expression(obj)
        return ConditionBuilder(MemberAccess(object=obj_expr, member=member))

    def array_access(
        self,
        array: ConditionBuilder | Expression,
        index: int | ConditionBuilder | Expression,
    ) -> Self:
        """Array access (array[index])."""
        array_expr = self._to_expression(array)
        index_expr = self._to_expression(index)
        return ConditionBuilder(ArrayAccess(array=array_expr, index=index_expr))

    # Logical operators
    def and_(self, other: ConditionBuilder | Expression) -> Self:
        """Logical AND."""
        if not self._expression:
            msg = "Cannot apply AND to empty expression"
            raise ValueError(msg)

        right = other._expression if isinstance(other, ConditionBuilder) else other
        return ConditionBuilder(
            BinaryExpression(left=self._expression, operator="and", right=right),
        )

    def or_(self, other: ConditionBuilder | Expression) -> Self:
        """Logical OR."""
        if not self._expression:
            msg = "Cannot apply OR to empty expression"
            raise ValueError(msg)

        right = other._expression if isinstance(other, ConditionBuilder) else other
        return ConditionBuilder(
            BinaryExpression(left=self._expression, operator="or", right=right),
        )

    def not_(self) -> Self:
        """Logical NOT."""
        if not self._expression:
            msg = "Cannot apply NOT to empty expression"
            raise ValueError(msg)

        return ConditionBuilder(
            UnaryExpression(operator="not", operand=self._expression),
        )

    # Comparison operators
    def eq(self, other: ConditionBuilder | Expression | int | str) -> Self:
        """Equal comparison."""
        return self._binary_op("==", other)

    def ne(self, other: ConditionBuilder | Expression | int | str) -> Self:
        """Not equal comparison."""
        return self._binary_op("!=", other)

    def lt(self, other: ConditionBuilder | Expression | int) -> Self:
        """Less than comparison."""
        return self._binary_op("<", other)

    def le(self, other: ConditionBuilder | Expression | int) -> Self:
        """Less than or equal comparison."""
        return self._binary_op("<=", other)

    def gt(self, other: ConditionBuilder | Expression | int) -> Self:
        """Greater than comparison."""
        return self._binary_op(">", other)

    def ge(self, other: ConditionBuilder | Expression | int) -> Self:
        """Greater than or equal comparison."""
        return self._binary_op(">=", other)

    # String operations
    def contains(self, pattern: str | ConditionBuilder) -> Self:
        """String contains."""
        return self._binary_op("contains", pattern)

    def matches(self, pattern: str | ConditionBuilder) -> Self:
        """String matches regex."""
        return self._binary_op("matches", pattern)

    def startswith(self, pattern: str | ConditionBuilder) -> Self:
        """String starts with."""
        return self._binary_op("startswith", pattern)

    def endswith(self, pattern: str | ConditionBuilder) -> Self:
        """String ends with."""
        return self._binary_op("endswith", pattern)

    def icontains(self, pattern: str | ConditionBuilder) -> Self:
        """Case-insensitive contains."""
        return self._binary_op("icontains", pattern)

    def iequals(self, pattern: str | ConditionBuilder) -> Self:
        """Case-insensitive equals."""
        return self._binary_op("iequals", pattern)

    # Special conditions
    def at(self, offset: int | ConditionBuilder) -> Self:
        """String at offset."""
        if not self._expression or not isinstance(self._expression, StringIdentifier):
            msg = "'at' can only be used with string identifiers"
            raise ValueError(msg)

        offset_expr = self._to_expression(offset)
        return ConditionBuilder(
            AtExpression(string_id=self._expression.name, offset=offset_expr),
        )

    def in_range(
        self,
        start: int | ConditionBuilder,
        end: int | ConditionBuilder,
    ) -> Self:
        """String in range."""
        if not self._expression or not isinstance(self._expression, StringIdentifier):
            msg = "'in' can only be used with string identifiers"
            raise ValueError(msg)

        start_expr = self._to_expression(start)
        end_expr = self._to_expression(end)
        range_expr = RangeExpression(low=start_expr, high=end_expr)

        return ConditionBuilder(
            InExpression(string_id=self._expression.name, range=range_expr),
        )

    # Quantifiers
    def any_of(self, *strings: str) -> Self:
        """Any of strings."""
        if all(s == "them" for s in strings):
            string_set = Identifier(name="them")
        else:
            elements = [StringIdentifier(name=s) for s in strings]
            string_set = SetExpression(elements=elements)

        return ConditionBuilder(
            OfExpression(quantifier=StringLiteral(value="any"), string_set=string_set),
        )

    def all_of(self, *strings: str) -> Self:
        """All of strings."""
        if all(s == "them" for s in strings):
            string_set = Identifier(name="them")
        else:
            elements = [StringIdentifier(name=s) for s in strings]
            string_set = SetExpression(elements=elements)

        return ConditionBuilder(
            OfExpression(quantifier=StringLiteral(value="all"), string_set=string_set),
        )

    def n_of(self, n: int, *strings: str) -> Self:
        """N of strings."""
        if all(s == "them" for s in strings):
            string_set = Identifier(name="them")
        else:
            elements = [StringIdentifier(name=s) for s in strings]
            string_set = SetExpression(elements=elements)

        return ConditionBuilder(
            OfExpression(quantifier=IntegerLiteral(value=n), string_set=string_set),
        )

    # For loops
    def for_any(
        self,
        var: str,
        iterable: ConditionBuilder | Expression,
        condition: ConditionBuilder | Expression,
    ) -> Self:
        """For any loop."""
        iter_expr = self._to_expression(iterable)
        cond_expr = self._to_expression(condition)

        return ConditionBuilder(
            ForExpression(
                quantifier="any",
                variable=var,
                iterable=iter_expr,
                body=cond_expr,
            ),
        )

    def for_all(
        self,
        var: str,
        iterable: ConditionBuilder | Expression,
        condition: ConditionBuilder | Expression,
    ) -> Self:
        """For all loop."""
        iter_expr = self._to_expression(iterable)
        cond_expr = self._to_expression(condition)

        return ConditionBuilder(
            ForExpression(
                quantifier="all",
                variable=var,
                iterable=iter_expr,
                body=cond_expr,
            ),
        )

    # Arithmetic operations
    def add(self, other: ConditionBuilder | int) -> Self:
        """Addition."""
        return self._binary_op("+", other)

    def sub(self, other: ConditionBuilder | int) -> Self:
        """Subtraction."""
        return self._binary_op("-", other)

    def mul(self, other: ConditionBuilder | int) -> Self:
        """Multiplication."""
        return self._binary_op("*", other)

    def div(self, other: ConditionBuilder | int) -> Self:
        """Division."""
        return self._binary_op("/", other)

    def mod(self, other: ConditionBuilder | int) -> Self:
        """Modulo."""
        return self._binary_op("%", other)

    # Bitwise operations
    def bitwise_and(self, other: ConditionBuilder | int) -> Self:
        """Bitwise AND."""
        return self._binary_op("&", other)

    def bitwise_or(self, other: ConditionBuilder | int) -> Self:
        """Bitwise OR."""
        return self._binary_op("|", other)

    def bitwise_xor(self, other: ConditionBuilder | int) -> Self:
        """Bitwise XOR."""
        return self._binary_op("^", other)

    def bitwise_not(self) -> Self:
        """Bitwise NOT."""
        if not self._expression:
            msg = "Cannot apply bitwise NOT to empty expression"
            raise ValueError(msg)

        return ConditionBuilder(UnaryExpression(operator="~", operand=self._expression))

    def shift_left(self, other: ConditionBuilder | int) -> Self:
        """Shift left."""
        return self._binary_op("<<", other)

    def shift_right(self, other: ConditionBuilder | int) -> Self:
        """Shift right."""
        return self._binary_op(">>", other)

    # Grouping
    def group(self) -> Self:
        """Group expression in parentheses."""
        if not self._expression:
            msg = "Cannot group empty expression"
            raise ValueError(msg)

        return ConditionBuilder(ParenthesesExpression(expression=self._expression))

    # Helper methods
    def _binary_op(
        self,
        op: str,
        other: ConditionBuilder | Expression | int | str,
    ) -> Self:
        """Create binary expression."""
        if not self._expression:
            msg = f"Cannot apply {op} to empty expression"
            raise ValueError(msg)

        right = self._to_expression(other)
        return ConditionBuilder(
            BinaryExpression(left=self._expression, operator=op, right=right),
        )

    def _to_expression(
        self,
        value: ConditionBuilder | Expression | int | str,
    ) -> Expression:
        """Convert value to expression."""
        if isinstance(value, ConditionBuilder):
            if not value._expression:
                msg = "Empty condition builder"
                raise ValueError(msg)
            return value._expression
        if isinstance(value, Expression):
            return value
        if isinstance(value, int):
            return IntegerLiteral(value=value)
        if isinstance(value, str):
            if value.startswith("$"):
                return StringIdentifier(name=value)
            return StringLiteral(value=value)
        msg = f"Cannot convert {type(value)} to expression"
        raise TypeError(msg)

    def build(self) -> Expression:
        """Build the final expression."""
        if not self._expression:
            msg = "Cannot build empty expression"
            raise ValueError(msg)
        return self._expression

    # Static factory methods
    @staticmethod
    def match(string_id: str) -> ConditionBuilder:
        """Create condition that matches a string."""
        return ConditionBuilder(StringIdentifier(name=string_id))

    @staticmethod
    def them() -> ConditionBuilder:
        """Reference to 'them' keyword."""
        return ConditionBuilder(Identifier(name="them"))
