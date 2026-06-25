"""Helpers for advanced code generator."""

from __future__ import annotations

from typing import Any, cast

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
from yaraast.codegen.formatting import FormattingConfig, HexStyle, StringStyle
from yaraast.codegen.generator_formatting import format_rule_tags
from yaraast.codegen.generator_helpers import (
    escape_plain_string_value,
    escape_regex_delimiter,
    format_hex_byte_value,
    format_hex_jump_bounds,
    format_hex_negated_value,
    format_hex_nibble_value,
    format_modifier,
    output_string_identifier,
    plain_string_render_source,
    split_regex_modifiers,
    validate_hex_alternative_token,
    validate_hex_nibble_high,
    validate_hex_string_modifiers,
    validate_hex_string_tokens,
    validate_plain_string_modifiers,
    validate_plain_string_value,
    validate_regex_string_modifiers,
    validate_string_identifiers,
)


def collect_string_definitions(
    strings: list[StringDefinition],
    config: FormattingConfig,
) -> list[tuple[str, str, list[str]]]:
    validate_string_identifiers(strings)
    collected: list[tuple[str, str, list[str]]] = []

    for string_def in strings:
        identifier = output_string_identifier(string_def)
        if isinstance(string_def, PlainString):
            validate_plain_string_modifiers(string_def.modifiers)
            source_value = plain_string_render_source(string_def)
            validate_plain_string_value(source_value)
            value = f'"{escape_plain_string_value(source_value)}"'
            modifiers = [format_modifier(mod) for mod in string_def.modifiers]
        elif isinstance(string_def, HexString):
            validate_hex_string_modifiers(string_def.modifiers)
            value = format_hex_string(string_def, config)
            modifiers = [format_modifier(mod) for mod in string_def.modifiers]
        else:
            regex_def = cast(RegexString, string_def)
            validate_regex_string_modifiers(regex_def.modifiers)
            escaped = escape_regex_delimiter(regex_def.regex)
            suffix, modifiers = split_regex_modifiers(regex_def.modifiers)
            value = f"/{escaped}/{suffix}"

        collected.append((identifier, value, modifiers))

    return collected


def format_hex_string(node: HexString, config: FormattingConfig) -> str:
    validate_hex_string_tokens(node.tokens)
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
            validate_hex_alternative_token(token)
            alt_parts = []
            for alt in token.alternatives:
                tokens = alt if isinstance(alt, list) else [alt]
                alt_str = " ".join(format_hex_token(_coerce_hex_token(t), config) for t in tokens)
                alt_parts.append(alt_str)
            parts.append(f"({' | '.join(alt_parts)})")
        elif isinstance(token, HexNibble):
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


def format_hex_token(token: HexToken, config: FormattingConfig) -> str:
    if isinstance(token, int | str):
        return _format_hex_byte_value(token, config)
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
    msg = f"Unsupported hex token '{type(token).__name__}' for libyara output"
    raise TypeError(msg)


def _coerce_hex_token(token: Any) -> HexToken:
    if isinstance(token, int | str):
        return HexByte(token)
    return cast(HexToken, token)


def _format_hex_byte_value(value: int | str, config: FormattingConfig) -> str:
    return format_hex_byte_value(
        value,
        uppercase=config.hex_style == HexStyle.UPPERCASE,
    )


def _format_hex_nibble(token: HexNibble, config: FormattingConfig) -> str:
    nibble_str = format_hex_nibble_value(
        token.value,
        uppercase=config.hex_style == HexStyle.UPPERCASE,
    )
    return f"{nibble_str}?" if validate_hex_nibble_high(token.high) else f"?{nibble_str}"


def get_tag_string(tags: list[Any] | tuple[Any, ...], config: FormattingConfig) -> str:
    if not tags:
        return ""
    if config.string_style == StringStyle.COMPACT:
        return format_rule_tags(tags)
    return format_rule_tags(tags)


def _format_hex_jump(token: HexJump) -> str:
    return format_hex_jump_bounds(token.min_jump, token.max_jump)
