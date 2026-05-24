"""Helpers for regex literal formatting."""

from __future__ import annotations

VALID_REGEX_MODIFIERS = frozenset("is")


def escape_regex_delimiter(pattern: str) -> str:
    """Escape unescaped '/' characters without double-escaping existing escapes."""
    result: list[str] = []
    backslash_count = 0

    for char in pattern:
        if char == "/":
            if backslash_count % 2 == 0:
                result.append("\\")
            result.append(char)
            backslash_count = 0
            continue

        result.append(char)
        if char == "\\":
            backslash_count += 1
        else:
            backslash_count = 0

    return "".join(result)


def validate_regex_modifiers(modifiers: str) -> None:
    """Reject regex suffix modifiers that libyara rejects."""
    seen: set[str] = set()
    for modifier in modifiers:
        if modifier not in VALID_REGEX_MODIFIERS:
            msg = f"Invalid regex modifier: {modifier}"
            raise ValueError(msg)
        if modifier in seen:
            msg = f"Duplicate regex modifier: {modifier}"
            raise ValueError(msg)
        seen.add(modifier)
