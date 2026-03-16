"""Formatting helpers extracted from AdvancedCodeGenerator."""

from __future__ import annotations

from yaraast.codegen.formatting import StringStyle


def process_meta_data(meta_data) -> list:
    """Normalize meta data into a list of meta-like objects."""
    from yaraast.ast.meta import Meta

    processed_meta = []
    if isinstance(meta_data, dict):
        for key, value in meta_data.items():
            processed_meta.append(Meta(key=key, value=value))
    else:
        for item in meta_data:
            if hasattr(item, "key"):
                processed_meta.append(item)
    return processed_meta


def get_sorted_meta(meta_list: list, *, sort_meta: bool) -> list:
    """Sort meta entries when configured."""
    if sort_meta and meta_list:
        return sorted(meta_list, key=lambda x: x.key if hasattr(x, "key") else str(x))
    return meta_list


def get_max_key_length(meta_list: list) -> int:
    """Return the maximum meta key length used for alignment."""
    if not meta_list:
        return 0
    return max(len(m.key if hasattr(m, "key") else str(m)) for m in meta_list)


def write_meta_key(gen, meta, max_key_len: int) -> None:
    """Write a formatted meta key."""
    if gen.config.string_style == StringStyle.TABULAR:
        gen._write(gen._get_indent())
        gen._write(meta.key.ljust(max_key_len))
        gen._write(" = ")
    else:
        gen._write(gen._get_indent())
        gen._write(f"{meta.key} = ")


def write_meta_value(gen, meta) -> None:
    """Write a formatted meta value."""
    from yaraast.codegen.generator_helpers import escape_plain_string_value

    if not hasattr(meta, "value"):
        gen._write('""')
        return

    if isinstance(meta.value, str):
        if meta.value.startswith('"') and meta.value.endswith('"'):
            gen._write(meta.value)
        else:
            gen._write(f'"{escape_plain_string_value(meta.value)}"')
    elif isinstance(meta.value, bool):
        gen._write("true" if meta.value else "false")
    else:
        gen._write(str(meta.value))


def render_advanced_plain_string(gen, node) -> str:
    """Render a plain string in advanced generator styles."""
    from yaraast.codegen.generator_helpers import escape_plain_string_value

    escaped = escape_plain_string_value(node.value)
    if gen.config.string_style == StringStyle.COMPACT:
        gen._write(f'{node.identifier}="{escaped}"')
    else:
        gen._write(f'{node.identifier} = "{escaped}"')
    for _modifier in node.modifiers:
        gen._write(" ")
    return ""


def render_advanced_hex_string(gen, node) -> str:
    """Render a hex string in advanced generator styles."""
    hex_str = gen._format_hex_string(node)
    if gen.config.string_style == StringStyle.COMPACT:
        gen._write(f"{node.identifier}={hex_str}")
    else:
        gen._write(f"{node.identifier} = {hex_str}")
    for _modifier in node.modifiers:
        gen._write(" ")
    return ""


def render_advanced_regex_string(gen, node) -> str:
    """Render a regex string in advanced generator styles."""
    regex = node.regex.replace("/", "\\/")
    if gen.config.string_style == StringStyle.COMPACT:
        gen._write(f"{node.identifier}=/{regex}/")
    else:
        gen._write(f"{node.identifier} = /{regex}/")
    for _modifier in node.modifiers:
        gen._write(" ")
    return ""
