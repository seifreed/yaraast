"""Formatting helpers extracted from AdvancedCodeGenerator."""

from __future__ import annotations

from typing import Any

from yaraast.codegen.formatting import StringStyle
from yaraast.codegen.generator_formatting import format_meta_key, format_meta_literal
from yaraast.codegen.generator_helpers import (
    escape_regex_delimiter,
    format_modifiers,
    format_regex_modifiers,
    output_string_identifier,
    validate_hex_string_modifiers,
    validate_plain_string_modifiers,
    validate_regex_string_modifiers,
)


def process_meta_data(meta_data: dict[str, Any] | list[Any] | tuple[Any, ...]) -> list[Any]:
    """Normalize meta data into a list of meta-like objects."""

    if isinstance(meta_data, dict):
        return []

    processed_meta: list[Any] = []
    for item in meta_data:
        if hasattr(item, "key"):
            processed_meta.append(item)
    return processed_meta


def get_sorted_meta(meta_list: list[Any], *, sort_meta: bool) -> list[Any]:
    """Sort meta entries when configured."""
    if sort_meta and meta_list:
        return sorted(meta_list, key=lambda x: x.key if hasattr(x, "key") else str(x))
    return meta_list


def get_max_key_length(meta_list: list[Any]) -> int:
    """Return the maximum meta key length used for alignment."""
    if not meta_list:
        return 0
    return max(
        len(format_meta_key(m.key, getattr(m, "scope", None)) if hasattr(m, "key") else str(m))
        for m in meta_list
    )


def write_meta_key(gen: Any, meta: Any, max_key_len: int) -> None:
    """Write a formatted meta key."""
    key = format_meta_key(meta.key, getattr(meta, "scope", None))
    if gen._layout.config.string_style == StringStyle.TABULAR:
        gen._write(gen._get_indent())
        gen._write(key.ljust(max_key_len))
        gen._write(" = ")
    else:
        gen._write(gen._get_indent())
        gen._write(f"{key} = ")


def write_meta_value(gen: Any, meta: Any) -> None:
    """Write a formatted meta value."""
    if not hasattr(meta, "value"):
        gen._write('""')
        return

    gen._write(format_meta_literal(meta.value))


def render_advanced_plain_string(gen: Any, node: Any) -> str:
    """Render a plain string in advanced generator styles."""
    from yaraast.codegen.generator_helpers import (
        escape_plain_string_value,
        plain_string_render_source,
    )

    validate_plain_string_modifiers(node.modifiers)
    escaped = escape_plain_string_value(plain_string_render_source(node))
    identifier = output_string_identifier(node)
    if gen._layout.config.string_style == StringStyle.COMPACT:
        gen._write(f'{identifier}="{escaped}"')
    else:
        gen._write(f'{identifier} = "{escaped}"')
    gen._write(format_modifiers(node.modifiers))
    return ""


def render_advanced_hex_string(gen: Any, node: Any) -> str:
    """Render a hex string in advanced generator styles."""
    validate_hex_string_modifiers(node.modifiers)
    hex_str = gen._layout.format_hex_string(node)
    identifier = output_string_identifier(node)
    if gen._layout.config.string_style == StringStyle.COMPACT:
        gen._write(f"{identifier}={hex_str}")
    else:
        gen._write(f"{identifier} = {hex_str}")
    gen._write(format_modifiers(node.modifiers))
    return ""


def render_advanced_regex_string(gen: Any, node: Any) -> str:
    """Render a regex string in advanced generator styles."""
    validate_regex_string_modifiers(node.modifiers)
    regex = escape_regex_delimiter(node.regex)
    identifier = output_string_identifier(node)
    if gen._layout.config.string_style == StringStyle.COMPACT:
        gen._write(f"{identifier}=/{regex}/")
    else:
        gen._write(f"{identifier} = /{regex}/")
    gen._write(format_regex_modifiers(node.modifiers))
    return ""
