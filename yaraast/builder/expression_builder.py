"""Expression builder utilities."""

from __future__ import annotations

import math
import re

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
from yaraast.builder.file_builder_validation import validate_identifier, validate_identifier_path
from yaraast.errors import ValidationError

_STRING_REFERENCE_BODY_RE = re.compile(r"^[A-Za-z0-9_]+$")


class ExpressionBuilder:
    """Static helper methods for building expressions."""

    @staticmethod
    def _integer_literal(value: object) -> IntegerLiteral:
        if not isinstance(value, int) or isinstance(value, bool):
            msg = f"Invalid integer literal value: {value}"
            raise TypeError(msg)
        return IntegerLiteral(value=value)

    @staticmethod
    def _integer_or_expression(value: object) -> Expression:
        if isinstance(value, Expression):
            return value
        return ExpressionBuilder._integer_literal(value)

    @staticmethod
    def _double_literal(value: object) -> DoubleLiteral:
        if isinstance(value, bool) or not isinstance(value, int | float):
            msg = "Double literal value must be numeric"
            raise TypeError(msg)
        if not math.isfinite(value):
            msg = "Double literal value must be finite"
            raise ValueError(msg)
        return DoubleLiteral(value=value)

    @staticmethod
    def _string_literal(value: object) -> StringLiteral:
        if isinstance(value, str):
            return StringLiteral(value=value)
        msg = "String literal value must be a string"
        raise TypeError(msg)

    @staticmethod
    def string(identifier: str) -> StringIdentifier:
        """Create string identifier."""
        ExpressionBuilder._validate_string_reference(identifier)
        return StringIdentifier(name=identifier)

    @staticmethod
    def integer(value: int) -> IntegerLiteral:
        """Create integer literal."""
        return ExpressionBuilder._integer_literal(value)

    @staticmethod
    def double(value: float) -> DoubleLiteral:
        """Create double literal."""
        return ExpressionBuilder._double_literal(value)

    @staticmethod
    def string_literal(value: str) -> StringLiteral:
        """Create string literal."""
        return ExpressionBuilder._string_literal(value)

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
        low_expr = ExpressionBuilder._integer_or_expression(low)
        high_expr = ExpressionBuilder._integer_or_expression(high)
        return RangeExpression(low=low_expr, high=high_expr)

    @staticmethod
    def set(*elements: Expression) -> SetExpression:
        """Create set expression."""
        return SetExpression(elements=list(elements))

    @staticmethod
    def string_set(*identifiers: str) -> SetExpression:
        """Create set of string identifiers."""
        ExpressionBuilder._validate_string_set_args(identifiers)
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
        string_set = ExpressionBuilder._of_string_set(*strings)
        return OfExpression(
            quantifier=StringLiteral(value="any"),
            string_set=string_set,
        )

    @staticmethod
    def all_of(*strings: str) -> OfExpression:
        """Create 'all of (...)' expression."""
        string_set = ExpressionBuilder._of_string_set(*strings)
        return OfExpression(
            quantifier=StringLiteral(value="all"),
            string_set=string_set,
        )

    @staticmethod
    def n_of(n: int, *strings: str) -> OfExpression:
        """Create 'n of (...)' expression."""
        string_set = ExpressionBuilder._of_string_set(*strings)
        return OfExpression(quantifier=ExpressionBuilder._integer_literal(n), string_set=string_set)

    @staticmethod
    def and_(*expressions: Expression) -> Expression:
        """Create AND expression chain."""
        if not expressions:
            msg = "At least one expression required"
            raise ValidationError(msg)

        result = expressions[0]
        for expr in expressions[1:]:
            result = BinaryExpression(left=result, operator="and", right=expr)

        return result

    @staticmethod
    def or_(*expressions: Expression) -> Expression:
        """Create OR expression chain."""
        if not expressions:
            msg = "At least one expression required"
            raise ValidationError(msg)

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
        ExpressionBuilder._validate_string_reference(string_id)
        offset_expr = ExpressionBuilder._integer_or_expression(offset)
        return AtExpression(string_id=string_id, offset=offset_expr)

    @staticmethod
    def in_(
        string_id: str,
        start: int | Expression,
        end: int | Expression,
    ) -> InExpression:
        """Create 'in' expression."""
        ExpressionBuilder._validate_string_reference(string_id)
        range_expr = ExpressionBuilder.range(start, end)
        return InExpression(subject=string_id, range=range_expr)

    @staticmethod
    def for_any(var: str, iterable: Expression, body: Expression) -> ForExpression:
        """Create 'for any' expression."""
        validate_identifier(var, "loop variable")
        return ForExpression(
            quantifier="any",
            variable=var,
            iterable=iterable,
            body=body,
        )

    @staticmethod
    def for_all(var: str, iterable: Expression, body: Expression) -> ForExpression:
        """Create 'for all' expression."""
        validate_identifier(var, "loop variable")
        return ForExpression(
            quantifier="all",
            variable=var,
            iterable=iterable,
            body=body,
        )

    @staticmethod
    def function_call(name: str, *args: Expression) -> FunctionCall:
        """Create function call."""
        validate_identifier_path(name, "function")
        return FunctionCall(function=name, arguments=list(args))

    @staticmethod
    def _validate_string_set_args(strings: tuple[str, ...]) -> None:
        if not strings:
            msg = "At least one string identifier is required"
            raise ValidationError(msg)
        if "them" in strings and not all(string == "them" for string in strings):
            msg = "'them' cannot be mixed with explicit string identifiers"
            raise ValidationError(msg)
        for string in strings:
            if string != "them":
                ExpressionBuilder._validate_string_reference(string)

    @staticmethod
    def _validate_string_reference(identifier: object) -> None:
        if not isinstance(identifier, str):
            msg = f"Invalid string reference: {identifier}"
            raise TypeError(msg)
        body = identifier[1:] if identifier.startswith("$") else identifier
        if body and _STRING_REFERENCE_BODY_RE.fullmatch(body) is not None:
            return
        msg = f"Invalid string reference: {identifier}"
        raise ValidationError(msg)

    @staticmethod
    def _of_string_set(*strings: str) -> Expression:
        ExpressionBuilder._validate_string_set_args(strings)
        if all(string == "them" for string in strings):
            return Identifier(name="them")
        return ExpressionBuilder.string_set(*strings)

    @staticmethod
    def member_access(obj: Expression, member: str) -> MemberAccess:
        """Create member access."""
        validate_identifier(member, "member")
        return MemberAccess(object=obj, member=member)

    @staticmethod
    def array_access(array: Expression, index: int | Expression) -> ArrayAccess:
        """Create array access."""
        index_expr = ExpressionBuilder._integer_or_expression(index)
        return ArrayAccess(array=array, index=index_expr)
