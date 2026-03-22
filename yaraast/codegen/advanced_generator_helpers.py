"""Helpers for advanced code generator."""

from __future__ import annotations

from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
)
from yaraast.codegen.formatting import HexStyle, StringStyle


def collect_string_definitions(
    strings: list[StringDefinition],
    config,
) -> list[tuple[str, str, list[str]]]:
    collected: list[tuple[str, str, list[str]]] = []

    for string_def in strings:
        identifier = string_def.identifier
        if isinstance(string_def, PlainString):
            value = f'"{string_def.value}"'
        elif isinstance(string_def, HexString):
            value = format_hex_string(string_def, config)
        elif isinstance(string_def, RegexString):
            escaped = string_def.regex.replace("/", "\\/")
            value = f"/{escaped}/"
        else:
            value = ""

        modifiers = []
        for mod in string_def.modifiers:
            if mod.value is not None:
                modifiers.append(f"{mod.name}({mod.value})")
            else:
                modifiers.append(mod.name)

        collected.append((identifier, value, modifiers))

    return collected


def format_hex_string(node: HexString, config) -> str:
    parts = []

    for token in node.tokens:
        if isinstance(token, HexByte):
            hex_val = f"{token.value:02x}"
            if config.hex_style == HexStyle.UPPERCASE:
                hex_val = hex_val.upper()
            parts.append(hex_val)
        elif isinstance(token, HexWildcard):
            parts.append("??")
        elif isinstance(token, HexJump):
            parts.append(_format_hex_jump(token))
        elif isinstance(token, HexAlternative):
            alt_parts = []
            for alt in token.alternatives:
                alt_str = " ".join(format_hex_token(t, config) for t in alt)
                alt_parts.append(alt_str)
            parts.append(f"({' | '.join(alt_parts)})")
        elif hasattr(token, "high") and hasattr(token, "value"):  # HexNibble
            nibble_str = f"{token.value:X}"
            parts.append(f"{nibble_str}?" if token.high else f"?{nibble_str}")

    if config.hex_group_size > 0:
        grouped_parts = []
        for i in range(0, len(parts), config.hex_group_size):
            group = parts[i : i + config.hex_group_size]
            grouped_parts.append("".join(group))
        hex_content = " ".join(grouped_parts)
    else:
        hex_content = " ".join(parts)

    return f"{{ {hex_content} }}"


def format_hex_token(token: HexToken, config) -> str:
    if isinstance(token, HexByte):
        hex_val = f"{token.value:02x}"
        if config.hex_style == HexStyle.UPPERCASE:
            hex_val = hex_val.upper()
        return hex_val
    if isinstance(token, HexWildcard):
        return "??"
    return ""


def get_tag_string(tags, config) -> str:
    if not tags:
        return ""
    if config.string_style == StringStyle.COMPACT:
        return " ".join(str(t.name if hasattr(t, "name") else t) for t in tags)
    return " ".join(str(t.name if hasattr(t, "name") else t) for t in tags)


def _format_hex_jump(token: HexJump) -> str:
    if token.min_jump is None and token.max_jump is None:
        return "[-]"
    if token.min_jump is None:
        return f"[-{token.max_jump}]"
    if token.max_jump is None:
        return f"[{token.min_jump}-]"
    if token.min_jump == token.max_jump:
        return f"[{token.min_jump}]"
    return f"[{token.min_jump}-{token.max_jump}]"
