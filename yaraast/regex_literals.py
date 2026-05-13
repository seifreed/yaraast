"""Helpers for regex literal formatting."""

from __future__ import annotations


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
