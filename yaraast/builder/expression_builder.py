"""Expression builder utilities."""

from __future__ import annotations

from yaraast.ast.conditions import AtExpression, ForExpression, InExpression, OfExpression
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
    SetExpression,
    StringIdentifier,
    StringLiteral,
    UnaryExpression,
)


class ExpressionBuilder:
    """Static helper methods for building expressions."""

    @staticmethod
    def string(identifier: str) -> StringIdentifier:
        """Create string identifier."""
        return StringIdentifier(name=identifier)

    @staticmethod
    def integer(value: int) -> IntegerLiteral:
        """Create integer literal."""
        return IntegerLiteral(value=value)

    @staticmethod
    def double(value: float) -> DoubleLiteral:
        """Create double literal."""
        return DoubleLiteral(value=value)

    @staticmethod
    def string_literal(value: str) -> StringLiteral:
        """Create string literal."""
        return StringLiteral(value=value)

    @staticmethod
    def true() -> BooleanLiteral:
        """Create boolean true."""
        return BooleanLiteral(value=True)

    @staticmethod
    def false() -> BooleanLiteral:
        """Create boolean false."""
        return BooleanLiteral(value=False)

    @staticmethod
    def identifier(name: str) -> Identifier:
        """Create identifier."""
        return Identifier(name=name)

    @staticmethod
    def filesize() -> Identifier:
        """Create filesize identifier."""
        return Identifier(name="filesize")

    @staticmethod
    def entrypoint() -> Identifier:
        """Create entrypoint identifier."""
        return Identifier(name="entrypoint")

    @staticmethod
    def them() -> Identifier:
        """Create 'them' identifier."""
        return Identifier(name="them")

    @staticmethod
    def range(low: int | Expression, high: int | Expression) -> RangeExpression:
        """Create range expression."""
        low_expr = IntegerLiteral(value=low) if isinstance(low, int) else low
        high_expr = IntegerLiteral(value=high) if isinstance(high, int) else high
        return RangeExpression(low=low_expr, high=high_expr)

    @staticmethod
    def set(*elements: Expression) -> SetExpression:
        """Create set expression."""
        return SetExpression(elements=list(elements))

    @staticmethod
    def string_set(*identifiers: str) -> SetExpression:
        """Create set of string identifiers."""
        elements = [StringIdentifier(name=s) for s in identifiers]
        return SetExpression(elements=elements)

    @staticmethod
    def any_of_them() -> OfExpression:
        """Create 'any of them' expression."""
        return OfExpression(
            quantifier=StringLiteral(value="any"),
            string_set=Identifier(name="them"),
        )

    @staticmethod
    def all_of_them() -> OfExpression:
        """Create 'all of them' expression."""
        return OfExpression(
            quantifier=StringLiteral(value="all"),
            string_set=Identifier(name="them"),
        )

    @staticmethod
    def any_of(*strings: str) -> OfExpression:
        """Create 'any of (...)' expression."""
        string_set = ExpressionBuilder.string_set(*strings)
        return OfExpression(
            quantifier=StringLiteral(value="any"),
            string_set=string_set,
        )

    @staticmethod
    def all_of(*strings: str) -> OfExpression:
        """Create 'all of (...)' expression."""
        string_set = ExpressionBuilder.string_set(*strings)
        return OfExpression(
            quantifier=StringLiteral(value="all"),
            string_set=string_set,
        )

    @staticmethod
    def n_of(n: int, *strings: str) -> OfExpression:
        """Create 'n of (...)' expression."""
        string_set = ExpressionBuilder.string_set(*strings)
        return OfExpression(quantifier=IntegerLiteral(value=n), string_set=string_set)

    @staticmethod
    def and_(*expressions: Expression) -> Expression:
        """Create AND expression chain."""
        if not expressions:
            msg = "At least one expression required"
            raise ValueError(msg)

        result = expressions[0]
        for expr in expressions[1:]:
            result = BinaryExpression(left=result, operator="and", right=expr)

        return result

    @staticmethod
    def or_(*expressions: Expression) -> Expression:
        """Create OR expression chain."""
        if not expressions:
            msg = "At least one expression required"
            raise ValueError(msg)

        result = expressions[0]
        for expr in expressions[1:]:
            result = BinaryExpression(left=result, operator="or", right=expr)

        return result

    @staticmethod
    def not_(expression: Expression) -> UnaryExpression:
        """Create NOT expression."""
        return UnaryExpression(operator="not", operand=expression)

    @staticmethod
    def parentheses(expression: Expression) -> ParenthesesExpression:
        """Wrap expression in parentheses."""
        return ParenthesesExpression(expression=expression)

    @staticmethod
    def at(string_id: str, offset: int | Expression) -> AtExpression:
        """Create 'at' expression."""
        offset_expr = IntegerLiteral(value=offset) if isinstance(offset, int) else offset
        return AtExpression(string_id=string_id, offset=offset_expr)

    @staticmethod
    def in_(
        string_id: str,
        start: int | Expression,
        end: int | Expression,
    ) -> InExpression:
        """Create 'in' expression."""
        range_expr = ExpressionBuilder.range(start, end)
        return InExpression(string_id=string_id, range=range_expr)

    @staticmethod
    def for_any(var: str, iterable: Expression, body: Expression) -> ForExpression:
        """Create 'for any' expression."""
        return ForExpression(
            quantifier="any",
            variable=var,
            iterable=iterable,
            body=body,
        )

    @staticmethod
    def for_all(var: str, iterable: Expression, body: Expression) -> ForExpression:
        """Create 'for all' expression."""
        return ForExpression(
            quantifier="all",
            variable=var,
            iterable=iterable,
            body=body,
        )

    @staticmethod
    def function_call(name: str, *args: Expression) -> FunctionCall:
        """Create function call."""
        return FunctionCall(function=name, arguments=list(args))

    @staticmethod
    def member_access(obj: Expression, member: str) -> MemberAccess:
        """Create member access."""
        return MemberAccess(object=obj, member=member)

    @staticmethod
    def array_access(array: Expression, index: int | Expression) -> ArrayAccess:
        """Create array access."""
        index_expr = IntegerLiteral(value=index) if isinstance(index, int) else index
        return ArrayAccess(array=array, index=index_expr)
