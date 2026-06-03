"""Helpers for YARA-L generator."""

from __future__ import annotations

from typing import Any

from yaraast.codegen.generator_helpers import escape_plain_string_value
from yaraast.yaral.ast_nodes import RawConditionValue, RawOutcomeExpression, StringLiteral


def quote_string_literal(value: str) -> str:
    return f'"{escape_plain_string_value(value)}"'


def format_literal(value: Any) -> str:
    if value is None:
        return ""
    if hasattr(value, "accept"):
        return ""
    if isinstance(value, StringLiteral):
        return quote_string_literal(value)
    if isinstance(value, RawConditionValue | RawOutcomeExpression):
        return str(value)
    if isinstance(value, str):
        if value.startswith("$") or value.startswith("%"):
            return value
        return quote_string_literal(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def format_udm_path(parts: list[str]) -> str:
    if not parts:
        return ""
    path = parts[0]
    for part in parts[1:]:
        if part.startswith("["):
            path += part
        else:
            path += f".{part}"
    return path


def format_modifiers(modifiers: list[str]) -> str:
    return f" {' '.join(modifiers)}" if modifiers else ""
