"""Helpers for fluent condition builder."""

from __future__ import annotations

from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    DoubleLiteral,
    Expression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    SetExpression,
    StringIdentifier,
    StringLiteral,
)
from yaraast.errors import ValidationError


def make_binary(left: Expression, operator: str, right: Expression) -> BinaryExpression:
    return BinaryExpression(left=left, operator=operator, right=right)


def make_filesize_compare(operator: str, size: int) -> BinaryExpression:
    return make_binary(Identifier(name="filesize"), operator, IntegerLiteral(value=size))


def make_string_count_compare(string_id: str, operator: str, count: int) -> BinaryExpression:
    from yaraast.ast.expressions import StringCount

    return make_binary(
        StringCount(string_id=string_id.lstrip("#")),
        operator,
        IntegerLiteral(value=count),
    )


def build_string_set(*strings: str) -> Expression:
    if all(s == "them" for s in strings):
        return Identifier(name="them")
    elements = [StringIdentifier(name=s) for s in strings]
    return SetExpression(elements=elements)


def build_of_expression(quantifier: int | str, string_set: Expression) -> OfExpression:
    if isinstance(quantifier, int):
        quant_expr = IntegerLiteral(value=quantifier)
    else:
        quant_expr = StringLiteral(value=quantifier)
    return OfExpression(quantifier=quant_expr, string_set=string_set)


def chain_or(conditions: list[Expression]) -> Expression:
    if not conditions:
        raise ValidationError("Expected at least one condition")
    result = conditions[0]
    for cond in conditions[1:]:
        result = BinaryExpression(left=result, operator="or", right=cond)
    return result


def build_entropy_call(offset: int, size: int) -> FunctionCall:
    return FunctionCall(
        function="math.entropy",
        arguments=[IntegerLiteral(value=offset), IntegerLiteral(value=size)],
    )


def build_entropy_compare(
    operator: str, offset: int, size: int, threshold: float
) -> BinaryExpression:
    return make_binary(
        build_entropy_call(offset, size),
        operator,
        DoubleLiteral(value=threshold),
    )
