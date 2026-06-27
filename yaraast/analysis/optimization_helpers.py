"""Helpers for optimization analysis."""

from __future__ import annotations

from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import BinaryExpression, Expression
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


def get_condition_pattern(condition: Expression) -> str:
    if isinstance(condition, BinaryExpression):
        return f"{condition.operator}(...)"
    if isinstance(condition, OfExpression):
        return "of(...)"
    return type(condition).__name__
