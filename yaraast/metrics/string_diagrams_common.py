"""Shared helpers for string diagram modules."""

from __future__ import annotations


def plain_value_text(value: str | bytes) -> str:
    """Return a readable text representation for plain string values."""
    if isinstance(value, str):
        return value
    return "".join(chr(byte) if 32 <= byte <= 126 else f"\\x{byte:02x}" for byte in value)


def plain_printable_ratio(value: str | bytes) -> float:
    """Calculate the printable, non-whitespace ratio for plain string values."""
    if not value:
        return 0.0
    if isinstance(value, bytes):
        printable_count = sum(1 for byte in value if 32 <= byte <= 126 and chr(byte).strip())
        return printable_count / len(value)
    printable_count = sum(1 for char in value if char.isprintable() and not char.isspace())
    return printable_count / len(value)


def modifier_names(modifiers) -> list[str]:
    """Return modifier names preserving compatibility with string/object inputs."""
    names: list[str] = []
    for mod in modifiers:
        if hasattr(mod, "name") and getattr(mod, "value", None) is None:
            names.append(mod.name)
        else:
            names.append(str(mod))
    return names


def string_pattern_identity(string_def) -> tuple[str, str | tuple[str, ...]]:
    """Return a content identity for counting unique string patterns."""
    from yaraast.ast.strings import HexString, PlainString, RegexString

    if isinstance(string_def, PlainString):
        return ("plain", plain_value_text(string_def.value))
    if isinstance(string_def, HexString):
        return ("hex", tuple(format_hex_token_for_diagram(token) for token in string_def.tokens))
    if isinstance(string_def, RegexString):
        return ("regex", string_def.regex)
    return (type(string_def).__name__, repr(string_def))


def format_hex_token_for_diagram(token) -> str:
    """Format one hex token for string diagram output."""
    from yaraast.ast.strings import (
        HexAlternative,
        HexByte,
        HexJump,
        HexNegatedByte,
        HexNibble,
        HexWildcard,
    )

    if isinstance(token, HexByte):
        return _format_hex_value(token.value)
    if isinstance(token, HexWildcard):
        return "??"
    if isinstance(token, HexJump):
        return _format_hex_jump(token)
    if isinstance(token, HexNegatedByte):
        return f"~{_format_hex_value(token.value)}"
    if isinstance(token, HexNibble):
        value = _format_hex_nibble_value(token.value)
        return f"{value}?" if token.high else f"?{value}"
    if isinstance(token, HexAlternative):
        alternatives = [_format_hex_alternative_branch(alt) for alt in token.alternatives]
        return f"({'|'.join(alternatives)})"
    return str(token)


def _format_hex_value(value: int | str) -> str:
    if isinstance(value, int):
        return f"{value:02X}"
    return value.upper()


def _format_hex_nibble_value(value: int | str) -> str:
    if isinstance(value, int):
        return f"{value:X}"
    return value.upper()


def _format_hex_jump(token) -> str:
    if token.min_jump is None and token.max_jump is None:
        return "[-]"
    if token.min_jump is None:
        return f"[0-{token.max_jump}]"
    if token.max_jump is None:
        return f"[{token.min_jump}-]"
    if token.min_jump == token.max_jump:
        if token.min_jump == 0:
            return "[0-0]"
        return f"[{token.min_jump}]"
    return f"[{token.min_jump}-{token.max_jump}]"


def _format_hex_alternative_branch(branch) -> str:
    if isinstance(branch, list | tuple):
        return " ".join(format_hex_token_for_diagram(token) for token in branch)
    return _format_hex_value(branch)
