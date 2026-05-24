"""Helper functions for code generation formatting."""

from __future__ import annotations

from collections.abc import Callable
import re
from typing import Any, NamedTuple

from yaraast.regex_literals import (
    VALID_REGEX_MODIFIERS,
    escape_regex_delimiter as _escape_regex_delimiter,
    validate_regex_modifiers,
)
from yaraast.xor_keys import parse_xor_key_text

REGEX_SUFFIX_MODIFIERS = VALID_REGEX_MODIFIERS
REGEX_SUFFIX_NAMES = {"dotall": "s"}
_UNSUPPORTED_REGEX_MODIFIERS = frozenset({"m", "multiline"})
_UNSUPPORTED_SPACED_STRING_MODIFIERS = frozenset(
    {
        "case",
        "dotall",
        "i",
        "m",
        "multiline",
        "s",
        "utf8",
        "utf16",
        "utf16le",
        "utf16be",
    }
)
_HEX_ALLOWED_MODIFIERS = frozenset({"private"})
_REGEX_DISALLOWED_MODIFIERS = frozenset({"base64", "base64wide", "xor"})
_BASE64_INCOMPATIBLE_MODIFIERS = frozenset({"fullword", "nocase", "xor"})
_XOR_INCOMPATIBLE_MODIFIERS = frozenset({"base64", "base64wide", "nocase"})
BASE64_MODIFIERS = frozenset({"base64", "base64wide"})
_HEX_CHARS = frozenset("0123456789abcdefABCDEF")
_STRING_IDENTIFIER_BODY_RE = re.compile(r"^[A-Za-z0-9_]+$")


class _XorKey(NamedTuple):
    key: int
    text: str


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
    identifier = str(getattr(string_def, "identifier", ""))
    return identifier if identifier.startswith("$") else f"${identifier}"


def validate_string_identifier_text(identifier: Any) -> str:
    """Return a normalized string identifier or reject invalid libyara output."""
    text = str(identifier)
    normalized = text if text.startswith("$") else f"${text}"
    body = normalized.removeprefix("$")
    if not body or _STRING_IDENTIFIER_BODY_RE.fullmatch(body) is None:
        msg = f"Invalid string identifier '{normalized}' for libyara output"
        raise ValueError(msg)
    return normalized


def validate_string_wildcard_text(pattern: Any) -> str:
    """Return a normalized string wildcard or reject invalid libyara output."""
    text = str(pattern)
    normalized = text if text.startswith("$") else f"${text}"
    body = normalized.removeprefix("$")
    if body == "*":
        return normalized
    if body.endswith("*"):
        prefix = body[:-1]
        if prefix and _STRING_IDENTIFIER_BODY_RE.fullmatch(prefix) is not None:
            return normalized
    msg = f"Invalid string wildcard '{normalized}' for libyara output"
    raise ValueError(msg)


def validate_string_set_item_text(item: Any) -> str:
    """Return a normalized string-set item or reject invalid libyara output."""
    text = str(item)
    if "*" in text:
        return validate_string_wildcard_text(text)
    return validate_string_identifier_text(text)


def validate_string_identifiers(strings) -> None:
    """Reject duplicate named string identifiers that libyara rejects."""
    if not strings:
        return

    seen: set[str] = set()
    for string_def in strings:
        if getattr(string_def, "is_anonymous", False):
            continue
        identifier = output_string_identifier(string_def)
        validate_string_identifier_text(identifier)
        if identifier in seen:
            msg = f"Duplicate string identifier '{identifier}' for libyara output"
            raise ValueError(msg)
        seen.add(identifier)


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


def format_double_literal(value: int | float) -> str:
    """Format a validated numeric double literal."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        msg = "Double literal value must be numeric"
        raise TypeError(msg)
    return str(value)


def format_hex_byte_value(value: int | str, *, uppercase: bool, context: str = "HexByte") -> str:
    """Format a validated hex byte value."""
    value = _validate_hex_byte_value(value, context)
    if isinstance(value, str):
        return value.upper() if uppercase else value.lower()
    return f"{value:02X}" if uppercase else f"{value:02x}"


def format_hex_negated_value(value: int | str, *, uppercase: bool) -> str:
    """Format a negated byte or nibble value."""
    value = _validate_hex_negated_value(value)
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


def _validate_hex_negated_value(value: int | str) -> int | str:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFF:
        return value
    if isinstance(value, str):
        if len(value) == 2 and all(char in _HEX_CHARS for char in value):
            return value
        if _is_negated_nibble_pattern(value):
            return value
    msg = "HexNegatedByte value must be a byte or negated nibble"
    raise TypeError(msg)


def _is_negated_nibble_pattern(value: str) -> bool:
    if len(value) != 2:
        return False
    first, second = value
    return (first == "?" and second in _HEX_CHARS) or (first in _HEX_CHARS and second == "?")


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
        _validate_spaced_string_modifier(name)
        if value is not None:
            if name == "xor":
                return f"{name}({_format_xor_modifier_value(value)})"
            if name in BASE64_MODIFIERS:
                return _format_base64_modifier_value(name, value)
            if isinstance(value, tuple):
                return f"{name}({value[0]}-{value[1]})"
            if isinstance(value, str):
                return f'{name}("{escape_plain_string_value(value)}")'
            return f"{name}({value})"
        return str(name)

    text = str(modifier)
    _validate_spaced_string_modifier(text)
    return text


def _format_base64_modifier_value(name: str, value: object) -> str:
    if not isinstance(value, str):
        msg = f"{name} value must be a string"
        raise TypeError(msg)
    try:
        encoded_value = value.encode("ascii")
    except UnicodeEncodeError:
        encoded_value = b""
    if len(encoded_value) != 64:
        msg = f"{name} alphabet must be 64 bytes"
        raise TypeError(msg)
    return f'{name}("{escape_plain_string_value(value)}")'


def _validate_spaced_string_modifier(name: str) -> None:
    if name in _UNSUPPORTED_SPACED_STRING_MODIFIERS:
        msg = f"Unsupported string modifier for libyara output: {name}"
        raise ValueError(msg)


def _format_xor_modifier_value(value: object) -> str:
    if isinstance(value, tuple | list) and len(value) == 2:
        low = _parse_xor_key(value[0])
        high = _parse_xor_key(value[1])
        if low is None or high is None:
            msg = "xor range value must contain byte bounds"
            raise TypeError(msg)
        if low.key > high.key:
            msg = "xor range value must be ascending"
            raise TypeError(msg)
        return f"{low.text}-{high.text}"

    if isinstance(value, str) and "-" in value:
        low_text, high_text = value.split("-", maxsplit=1)
        low = _parse_xor_key(low_text)
        high = _parse_xor_key(high_text)
        if low is None or high is None:
            msg = "xor range value must contain byte bounds"
            raise TypeError(msg)
        if low.key > high.key:
            msg = "xor range value must be ascending"
            raise TypeError(msg)
        return f"{low.text}-{high.text}"

    key = _parse_xor_key(value)
    if key is None:
        msg = "xor value must be a byte"
        raise TypeError(msg)
    return key.text


def _parse_xor_key(value: object) -> _XorKey | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        if 0 <= value <= 0xFF:
            return _XorKey(value, str(value))
        return None
    if isinstance(value, str):
        text = value.strip()
        key = parse_xor_key_text(text)
        if key is None:
            return None
        if 0 <= key <= 0xFF:
            return _XorKey(key, text)
    return None


def format_modifiers(modifiers, visit: Callable[[Any], str] | None = None) -> str:
    """Format modifiers into a string with leading spaces."""
    if not isinstance(modifiers, list | tuple):
        return ""
    validate_duplicate_string_modifiers(modifiers)
    parts = []
    for mod in modifiers:
        parts.append(format_modifier(mod, visit))
    return "".join(f" {part}" for part in parts)


def validate_plain_string_modifiers(modifiers) -> None:
    """Reject plain string modifier combinations that libyara rejects."""
    validate_duplicate_string_modifiers(modifiers)
    names = _modifier_names(modifiers)
    for base64_name in sorted(names & BASE64_MODIFIERS):
        for incompatible_name in sorted(names & _BASE64_INCOMPATIBLE_MODIFIERS):
            msg = (
                f"String modifier '{incompatible_name}' cannot be combined with "
                f"'{base64_name}' for libyara output"
            )
            raise ValueError(msg)

    if "xor" not in names:
        return

    for incompatible_name in sorted(names & _XOR_INCOMPATIBLE_MODIFIERS):
        msg = (
            f"String modifier '{incompatible_name}' cannot be combined with "
            "'xor' for libyara output"
        )
        raise ValueError(msg)


def validate_hex_string_modifiers(modifiers) -> None:
    """Reject hex string modifiers that libyara rejects."""
    validate_duplicate_string_modifiers(modifiers)
    for name in sorted(_modifier_names(modifiers)):
        if name in _HEX_ALLOWED_MODIFIERS:
            continue
        msg = f"String modifier '{name}' is not valid on hex strings for libyara output"
        raise ValueError(msg)


def validate_regex_string_modifiers(modifiers) -> None:
    """Reject regex string modifiers that libyara rejects."""
    validate_duplicate_string_modifiers(modifiers)
    for name in sorted(_modifier_names(modifiers)):
        if name not in _REGEX_DISALLOWED_MODIFIERS:
            continue
        msg = f"String modifier '{name}' is not valid on regex strings for libyara output"
        raise ValueError(msg)


def _modifier_names(modifiers) -> set[str]:
    if not isinstance(modifiers, list | tuple):
        return set()
    return {_regex_modifier_name(modifier) for modifier in modifiers}


def validate_duplicate_string_modifiers(modifiers) -> None:
    """Reject duplicate string modifiers that libyara rejects."""
    if not isinstance(modifiers, list | tuple):
        return

    seen: set[str] = set()
    for modifier in modifiers:
        if isinstance(modifier, str) and len(modifier) == 1 and modifier in VALID_REGEX_MODIFIERS:
            continue
        name = _regex_modifier_name(modifier)
        if name in seen:
            msg = f"Duplicate string modifier '{name}' for libyara output"
            raise ValueError(msg)
        seen.add(name)


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
        name = _regex_modifier_name(mod)
        if name in _UNSUPPORTED_REGEX_MODIFIERS:
            msg = f"Unsupported regex modifier: {name}"
            raise ValueError(msg)
        if isinstance(mod, str) and len(mod) == 1:
            validate_regex_modifiers(mod)
            suffix_parts.append(mod)
        elif name in REGEX_SUFFIX_NAMES:
            suffix_parts.append(REGEX_SUFFIX_NAMES[name])
        else:
            spaced_parts.append(format_modifier(mod, visit))

    suffix = "".join(suffix_parts)
    validate_regex_modifiers(suffix)
    return suffix, spaced_parts


def _regex_modifier_name(modifier: object) -> str:
    if isinstance(modifier, str):
        return modifier
    name = getattr(modifier, "name", "")
    return str(name)


def format_regex_modifiers(modifiers, visit: Callable[[Any], str] | None = None) -> str:
    """Format regex modifiers, keeping inline regex flags adjacent to the literal."""
    validate_regex_string_modifiers(modifiers)
    suffix, spaced_parts = split_regex_modifiers(modifiers, visit)
    spaced = "".join(f" {part}" for part in spaced_parts)
    return f"{suffix}{spaced}"
