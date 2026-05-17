"""Helper functions for code generation formatting."""

from __future__ import annotations

from collections.abc import Callable
import re
from typing import Any

from yaraast.regex_literals import escape_regex_delimiter as _escape_regex_delimiter

REGEX_SUFFIX_MODIFIERS = frozenset({"i", "m", "s"})
REGEX_SUFFIX_NAMES = {"dotall": "s", "multiline": "m"}


def _escape_plain_byte(value: int) -> str:
    if value == 0x5C:
        return "\\\\"
    if value == 0x22:
        return '\\"'
    if value == 0x0A:
        return "\\n"
    if value == 0x0D:
        return "\\r"
    if value == 0x09:
        return "\\t"
    if 0x20 <= value <= 0x7E:
        return chr(value)
    return f"\\x{value:02x}"


def escape_plain_string_value(value: str | bytes) -> str:
    """Escape plain string content for YARA output."""
    if isinstance(value, bytes):
        return "".join(_escape_plain_byte(byte) for byte in value)

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


def escape_regex_delimiter(pattern: str) -> str:
    """Escape unescaped '/' characters without double-escaping existing escapes."""
    return _escape_regex_delimiter(pattern)


def output_string_identifier(string_def: Any) -> str:
    """Return the YARA source identifier for a string definition."""
    if getattr(string_def, "is_anonymous", False):
        return "$"
    return str(getattr(string_def, "identifier", ""))


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


def format_modifier(modifier: Any, visit: Callable[[Any], str] | None = None) -> str:
    """Format one string modifier for YARA output."""
    if visit is not None and hasattr(modifier, "accept"):
        return visit(modifier)

    if (
        hasattr(modifier, "modifier_type")
        and hasattr(modifier, "name")
        and hasattr(modifier, "value")
    ):
        name = modifier.name
        value = modifier.value
        if value is not None:
            if isinstance(value, tuple):
                return f"{name}({value[0]}-{value[1]})"
            if isinstance(value, str):
                return f'{name}("{value}")'
            return f"{name}({value})"
        return str(name)

    return str(modifier)


def format_modifiers(modifiers, visit: Callable[[Any], str] | None = None) -> str:
    """Format modifiers into a string with leading spaces."""
    if not isinstance(modifiers, list | tuple):
        return ""
    parts = []
    for mod in modifiers:
        parts.append(format_modifier(mod, visit))
    return "".join(f" {part}" for part in parts)


def split_regex_modifiers(
    modifiers,
    visit: Callable[[Any], str] | None = None,
) -> tuple[str, list[str]]:
    """Split regex inline flags from spaced string modifiers."""
    if not isinstance(modifiers, list | tuple):
        return "", []

    suffix_parts = []
    spaced_parts = []
    for mod in modifiers:
        if isinstance(mod, str) and mod in REGEX_SUFFIX_MODIFIERS:
            suffix_parts.append(mod)
        elif isinstance(mod, str) and mod in REGEX_SUFFIX_NAMES:
            suffix_parts.append(REGEX_SUFFIX_NAMES[mod])
        elif getattr(mod, "name", None) in REGEX_SUFFIX_NAMES:
            suffix_parts.append(REGEX_SUFFIX_NAMES[mod.name])
        else:
            spaced_parts.append(format_modifier(mod, visit))

    return "".join(suffix_parts), spaced_parts


def format_regex_modifiers(modifiers, visit: Callable[[Any], str] | None = None) -> str:
    """Format regex modifiers, keeping inline regex flags adjacent to the literal."""
    suffix, spaced_parts = split_regex_modifiers(modifiers, visit)
    spaced = "".join(f" {part}" for part in spaced_parts)
    return f"{suffix}{spaced}"
