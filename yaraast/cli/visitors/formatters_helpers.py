"""Helpers for CLI AST formatters."""

from __future__ import annotations


def format_int_literal(value) -> str:
    if isinstance(value, int) and value > 255:
        return f"0x{value:X}"
    return str(value)


def truncate_string(value: str, limit: int) -> str:
    if len(value) > limit:
        return value[:limit] + "..."
    return value
