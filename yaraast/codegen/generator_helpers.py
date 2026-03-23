"""Helper functions for code generation formatting."""

from __future__ import annotations

import re


def escape_plain_string_value(value: str) -> str:
    """Escape plain string content for YARA output."""
    escaped_value = value.replace("\\", "\\\\")
    escaped_value = escaped_value.replace('"', '\\"')
    escaped_value = escaped_value.replace("\n", "\\n")
    escaped_value = escaped_value.replace("\r", "\\r")
    escaped_value = escaped_value.replace("\t", "\\t")
    escaped_value = escaped_value.replace("\x00", "\\x00")
    return re.sub(
        r"[\x01-\x1f\x7f-\x9f]",
        lambda m: f"\\x{ord(m.group(0)):02x}",
        escaped_value,
    )


def format_integer_literal(value) -> str:
    """Format integer literals with common hex values preserved."""
    if isinstance(value, str):
        try:
            int_value = int(value)
        except ValueError:
            return str(value)
    else:
        int_value = value

    hex_values = {
        0x4D5A: "0x4D5A",
        0x5A4D: "0x5A4D",
        0x00004550: "0x00004550",
        0x50450000: "0x50450000",
        0x14C: "0x14c",
        0x3C: "0x3c",
        1024: "0x400",
    }

    if int_value in hex_values:
        return hex_values[int_value]

    if int_value >= 256 and (int_value % 256 == 0 or int_value % 16 == 0):
        return hex(int_value)

    return str(int_value)


def format_modifiers(modifiers, visit) -> str:
    """Format modifiers into a string with leading spaces."""
    if not isinstance(modifiers, list | tuple):
        return ""
    parts = []
    for mod in modifiers:
        if hasattr(mod, "accept"):
            parts.append(visit(mod))
        else:
            parts.append(str(mod))
    return "".join(f" {part}" for part in parts)
