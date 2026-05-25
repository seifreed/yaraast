"""Helpers for fluent condition builder."""

from __future__ import annotations

import re

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

_STRING_REFERENCE_BODY_RE = re.compile(r"^[A-Za-z0-9_]+$")


def make_binary(left: Expression, operator: str, right: Expression) -> BinaryExpression:
    return BinaryExpression(left=left, operator=operator, right=right)


def make_integer_literal(value: int) -> IntegerLiteral:
    if not isinstance(value, int) or isinstance(value, bool):
        msg = f"Invalid integer literal value: {value}"
        raise TypeError(msg)
    return IntegerLiteral(value=value)


def make_filesize_compare(operator: str, size: int) -> BinaryExpression:
    return make_binary(Identifier(name="filesize"), operator, make_integer_literal(size))


def make_string_count_compare(string_id: str, operator: str, count: int) -> BinaryExpression:
    from yaraast.ast.expressions import StringCount

    return make_binary(
        StringCount(string_id=_normalize_string_reference(string_id, "#")),
        operator,
        make_integer_literal(count),
    )


def build_string_set(*strings: str) -> Expression:
    if not strings:
        msg = "At least one string identifier is required"
        raise ValidationError(msg)
    if "them" in strings and not all(string == "them" for string in strings):
        msg = "'them' cannot be mixed with explicit string identifiers"
        raise ValidationError(msg)
    if all(s == "them" for s in strings):
        return Identifier(name="them")
    for string in strings:
        validate_string_reference(string)
    elements = [StringIdentifier(name=s) for s in strings]
    return SetExpression(elements=elements)


def validate_string_reference(identifier: str) -> None:
    _normalize_string_reference(identifier, "$")


def _normalize_string_reference(identifier: str, marker: str) -> str:
    if not isinstance(identifier, str):
        msg = f"Invalid string reference: {identifier}"
        raise TypeError(msg)
    normalized = identifier[1:] if identifier.startswith(marker) else identifier
    body = normalized[1:] if normalized.startswith("$") else normalized
    if not body or _STRING_REFERENCE_BODY_RE.fullmatch(body) is None:
        msg = f"Invalid string reference: {identifier}"
        raise ValidationError(msg)
    return normalized


def build_of_expression(quantifier: int | str, string_set: Expression) -> OfExpression:
    if isinstance(quantifier, int):
        quant_expr = make_integer_literal(quantifier)
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
        arguments=[make_integer_literal(offset), make_integer_literal(size)],
    )


def build_entropy_compare(
    operator: str, offset: int, size: int, threshold: float
) -> BinaryExpression:
    return make_binary(
        build_entropy_call(offset, size),
        operator,
        DoubleLiteral(value=threshold),
    )
