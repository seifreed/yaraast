"""Helpers for advanced code generator."""

from __future__ import annotations

from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
)
from yaraast.codegen.formatting import HexStyle, StringStyle
from yaraast.codegen.generator_helpers import (
    escape_plain_string_value,
    escape_regex_delimiter,
    format_hex_byte_value,
    format_hex_jump_bounds,
    format_hex_negated_value,
    format_hex_nibble_value,
    format_modifier,
    output_string_identifier,
    split_regex_modifiers,
    validate_hex_string_modifiers,
    validate_plain_string_modifiers,
    validate_regex_string_modifiers,
)


def collect_string_definitions(
    strings: list[StringDefinition],
    config,
) -> list[tuple[str, str, list[str]]]:
    collected: list[tuple[str, str, list[str]]] = []

    for string_def in strings:
        identifier = output_string_identifier(string_def)
        if isinstance(string_def, PlainString):
            validate_plain_string_modifiers(string_def.modifiers)
            value = f'"{escape_plain_string_value(string_def.value)}"'
        elif isinstance(string_def, HexString):
            validate_hex_string_modifiers(string_def.modifiers)
            value = format_hex_string(string_def, config)
        elif isinstance(string_def, RegexString):
            validate_regex_string_modifiers(string_def.modifiers)
            escaped = escape_regex_delimiter(string_def.regex)
            suffix, spaced_modifiers = split_regex_modifiers(string_def.modifiers)
            value = f"/{escaped}/{suffix}"
        else:
            value = ""
            spaced_modifiers = []

        if isinstance(string_def, RegexString):
            modifiers = spaced_modifiers
        else:
            modifiers = [format_modifier(mod) for mod in string_def.modifiers]

        collected.append((identifier, value, modifiers))

    return collected


def format_hex_string(node: HexString, config) -> str:
    parts = []

    for token in node.tokens:
        if isinstance(token, HexByte):
            parts.append(_format_hex_byte_value(token.value, config))
        elif isinstance(token, HexNegatedByte):
            parts.append(format_hex_token(token, config))
        elif isinstance(token, HexWildcard):
            parts.append("??")
        elif isinstance(token, HexJump):
            parts.append(_format_hex_jump(token))
        elif isinstance(token, HexAlternative):
            alt_parts = []
            for alt in token.alternatives:
                tokens = alt if isinstance(alt, list) else [alt]
                alt_str = " ".join(format_hex_token(_coerce_hex_token(t), config) for t in tokens)
                alt_parts.append(alt_str)
            parts.append(f"({' | '.join(alt_parts)})")
        elif hasattr(token, "high") and hasattr(token, "value"):  # HexNibble
            parts.append(_format_hex_nibble(token, config))

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
        return _format_hex_byte_value(token.value, config)
    if isinstance(token, HexNegatedByte):
        return "~" + format_hex_negated_value(
            token.value,
            uppercase=config.hex_style == HexStyle.UPPERCASE,
        )
    if isinstance(token, HexWildcard):
        return "??"
    if isinstance(token, HexJump):
        return _format_hex_jump(token)
    if isinstance(token, HexNibble):
        return _format_hex_nibble(token, config)
    return ""


def _coerce_hex_token(token) -> HexToken:
    if isinstance(token, int | str):
        return HexByte(token)
    return token


def _format_hex_byte_value(value: int | str, config) -> str:
    return format_hex_byte_value(
        value,
        uppercase=config.hex_style == HexStyle.UPPERCASE,
    )


def _format_hex_nibble(token: HexNibble, config) -> str:
    nibble_str = format_hex_nibble_value(
        token.value,
        uppercase=config.hex_style == HexStyle.UPPERCASE,
    )
    return f"{nibble_str}?" if token.high else f"?{nibble_str}"


def get_tag_string(tags, config) -> str:
    if not tags:
        return ""
    if config.string_style == StringStyle.COMPACT:
        return " ".join(str(t.name if hasattr(t, "name") else t) for t in tags)
    return " ".join(str(t.name if hasattr(t, "name") else t) for t in tags)


def _format_hex_jump(token: HexJump) -> str:
    return format_hex_jump_bounds(token.min_jump, token.max_jump)
