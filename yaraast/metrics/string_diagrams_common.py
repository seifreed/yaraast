"""Shared helpers for string diagram modules."""

from __future__ import annotations


def modifier_names(modifiers) -> list[str]:
    """Return modifier names preserving compatibility with string/object inputs."""
    names: list[str] = []
    for mod in modifiers:
        if hasattr(mod, "name") and getattr(mod, "value", None) is None:
            names.append(mod.name)
        else:
            names.append(str(mod))
    return names


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
    if token.min_jump == token.max_jump and token.min_jump is not None:
        return f"[{token.min_jump}]"
    min_jump = "" if token.min_jump is None else str(token.min_jump)
    max_jump = "" if token.max_jump is None else str(token.max_jump)
    return f"[{min_jump}-{max_jump}]"


def _format_hex_alternative_branch(branch) -> str:
    if isinstance(branch, list | tuple):
        return " ".join(format_hex_token_for_diagram(token) for token in branch)
    return _format_hex_value(branch)
