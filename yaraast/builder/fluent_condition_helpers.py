"""Helpers for fluent condition builder."""

from __future__ import annotations

import math
import re

from yaraast.ast.expressions import (
    BinaryExpression,
    DoubleLiteral,
    Expression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    _validate_expression,
)
from yaraast.errors import ValidationError

_STRING_REFERENCE_BODY_RE = re.compile(r"^[A-Za-z0-9_]+$")


def make_binary(left: Expression, operator: str, right: Expression) -> BinaryExpression:
    return BinaryExpression(
        left=_validate_expression(left, "Binary left operand"),
        operator=operator,
        right=_validate_expression(right, "Binary right operand"),
    )


def make_integer_literal(value: int) -> IntegerLiteral:
    if not isinstance(value, int) or isinstance(value, bool):
        msg = f"Invalid integer literal value: {value}"
        raise TypeError(msg)
    return IntegerLiteral(value=value)


def make_double_literal(value: float) -> DoubleLiteral:
    if isinstance(value, bool) or not isinstance(value, int | float):
        msg = "Double literal value must be numeric"
        raise TypeError(msg)
    if not math.isfinite(value):
        msg = "Double literal value must be finite"
        raise ValueError(msg)
    return DoubleLiteral(value=value)


def make_filesize_compare(operator: str, size: int) -> BinaryExpression:
    return make_binary(Identifier(name="filesize"), operator, make_integer_literal(size))


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


def build_entropy_compare(
    operator: str, offset: int, size: int, threshold: float
) -> BinaryExpression:
    return make_binary(
        FunctionCall(
            function="math.entropy",
            arguments=[make_integer_literal(offset), make_integer_literal(size)],
        ),
        operator,
        make_double_literal(threshold),
    )
