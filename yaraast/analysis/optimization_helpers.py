"""Helpers for optimization analysis."""

from __future__ import annotations

from typing import Any

from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import BinaryExpression, Expression, IntegerLiteral, StringCount
from yaraast.ast.strings import HexByte, HexString, PlainString


def should_be_hex(plain: PlainString) -> bool:
    non_printable = sum(1 for c in plain.value if ord(c) < 32 or ord(c) > 126)
    return non_printable > len(plain.value) * 0.3


def get_hex_prefix(hex_str: HexString, length: int) -> tuple | None:
    prefix = []
    for token in hex_str.tokens[:length]:
        if isinstance(token, HexByte):
            prefix.append(token.value)
        else:
            break
    return tuple(prefix) if len(prefix) >= 4 else None


def extract_comparison(expr: Expression) -> dict[str, Any] | None:
    if isinstance(expr, BinaryExpression) and expr.operator in ["<", ">", "<=", ">=", "=="]:
        left_var = get_variable_name(expr.left)
        if left_var and isinstance(expr.right, IntegerLiteral):
            return {"var": left_var, "op": expr.operator, "value": expr.right.value}
    return None


def get_variable_name(expr: Expression) -> str | None:
    if hasattr(expr, "name"):
        return expr.name
    if isinstance(expr, StringCount):
        return f"#{expr.string_id}"
    return None


def get_condition_pattern(condition: Expression) -> str:
    if isinstance(condition, BinaryExpression):
        return f"{condition.operator}(...)"
    if isinstance(condition, OfExpression):
        return "of(...)"
    return type(condition).__name__
