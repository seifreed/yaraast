"""Helpers for YARA-L generator."""

from __future__ import annotations

from typing import Any


def format_literal(value: Any) -> str:
    if hasattr(value, "accept"):
        return ""
    if isinstance(value, str):
        if value.startswith("$") or value.startswith("%"):
            return value
        return f'"{value}"'
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
