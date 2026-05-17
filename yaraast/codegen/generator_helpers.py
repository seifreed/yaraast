"""Helper functions for code generation formatting."""

from __future__ import annotations

from collections.abc import Callable
import re
from typing import Any

from yaraast.regex_literals import escape_regex_delimiter as _escape_regex_delimiter

REGEX_SUFFIX_MODIFIERS = frozenset({"i", "m", "s"})
REGEX_SUFFIX_NAMES = {"dotall": "s", "multiline": "m"}
_HEX_CHARS = frozenset("0123456789abcdefABCDEF")


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
    if isinstance(value, bool):
        msg = "Integer literal value must be an integer"
        raise TypeError(msg)
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


def format_hex_byte_value(value: int | str, *, uppercase: bool, context: str = "HexByte") -> str:
    """Format a validated hex byte value."""
    value = _validate_hex_byte_value(value, context)
    if isinstance(value, str):
        return value.upper() if uppercase else value.lower()
    return f"{value:02X}" if uppercase else f"{value:02x}"


def format_hex_nibble_value(value: int | str, *, uppercase: bool) -> str:
    """Format a validated hex nibble value."""
    value = _validate_hex_nibble_value(value)
    if isinstance(value, str):
        return value.upper() if uppercase else value.lower()
    return f"{value:X}" if uppercase else f"{value:x}"


def format_hex_jump_bounds(min_jump: int | None, max_jump: int | None) -> str:
    """Format validated hex jump bounds."""
    min_jump = _validate_hex_jump_bound(min_jump, "min_jump")
    max_jump = _validate_hex_jump_bound(max_jump, "max_jump")

    if min_jump is not None and max_jump is not None and min_jump > max_jump:
        msg = "HexJump min_jump cannot exceed max_jump"
        raise TypeError(msg)
    if min_jump is None and max_jump is None:
        return "[-]"
    if min_jump == max_jump:
        if min_jump == 0:
            return "[0-0]"
        return f"[{min_jump}]"
    if min_jump is None:
        return f"[0-{max_jump}]"
    if max_jump is None:
        return f"[{min_jump}-]"
    return f"[{min_jump}-{max_jump}]"


def _validate_hex_byte_value(value: int | str, context: str) -> int | str:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFF:
        return value
    if isinstance(value, str) and len(value) == 2 and all(char in _HEX_CHARS for char in value):
        return value
    msg = f"{context} value must be a byte"
    raise TypeError(msg)


def _validate_hex_nibble_value(value: int | str) -> int | str:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xF:
        return value
    if isinstance(value, str) and len(value) == 1 and value in _HEX_CHARS:
        return value
    msg = "HexNibble value must be a nibble"
    raise TypeError(msg)


def _validate_hex_jump_bound(value: int | None, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    msg = f"HexJump {field} must be a non-negative integer"
    raise TypeError(msg)


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
                return f'{name}("{escape_plain_string_value(value)}")'
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
