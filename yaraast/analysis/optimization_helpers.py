"""Helpers for optimization analysis."""

from __future__ import annotations

from typing import Any

from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import BinaryExpression, Expression, IntegerLiteral, StringCount
from yaraast.ast.strings import HexByte, HexString, PlainString


def should_be_hex(plain: PlainString) -> bool:
    values = plain.value if isinstance(plain.value, bytes) else plain.value.encode()
    non_printable = sum(1 for value in values if value < 32 or value > 126)
    return non_printable > len(values) * 0.3


def get_hex_prefix(hex_str: HexString, length: int) -> tuple[int | str, ...] | None:
    prefix: list[int | str] = []
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
    name = getattr(expr, "name", None)
    if isinstance(name, str):
        return name
    if isinstance(expr, StringCount):
        string_id = expr.string_id
        if string_id.startswith("#"):
            string_id = string_id[1:]
        if string_id.startswith("$"):
            string_id = string_id[1:]
        return f"#{string_id}"
    return None


def get_condition_pattern(condition: Expression) -> str:
    if isinstance(condition, BinaryExpression):
        return f"{condition.operator}(...)"
    if isinstance(condition, OfExpression):
        return "of(...)"
    return type(condition).__name__
