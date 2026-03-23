"""Section and string rendering helpers for the main code generator."""

from __future__ import annotations


def write_meta_section(gen, meta) -> None:
    """Write meta section if present."""
    if not meta:
        return
    gen._writeline("meta:")
    gen._indent()
    for item in meta:
        if hasattr(item, "key") and hasattr(item, "value"):
            gen._writeline(gen._format_meta_value(item.key, item.value))
    gen._dedent()
    gen._writeline()


def write_strings_section(gen, strings, *, has_condition: bool) -> None:
    """Write strings section if present."""
    if not strings:
        return
    gen._writeline("strings:")
    gen._indent()
    for string in strings:
        gen.visit(string)
        gen._writeline()
    gen._dedent()
    if has_condition:
        gen._writeline()


def write_condition_section(gen, condition) -> None:
    """Write condition section if present."""
    if not condition:
        return
    gen._writeline("condition:")
    gen._indent()
    condition_code = gen.visit(condition)
    gen._writeline(condition_code)
    gen._dedent()


def write_plain_string(gen, node) -> str:
    """Render a plain string definition."""
    indent = " " * (gen.indent_level * gen.indent_size)
    gen._write(indent)
    escaped_value = gen._escape_plain_string_value(node.value)
    gen._write(f'{node.identifier} = "{escaped_value}"')
    if hasattr(node, "modifiers") and node.modifiers:
        gen._write_modifiers(node.modifiers)
    return ""


def write_hex_string(gen, node) -> str:
    """Render a hex string definition."""
    indent = " " * (gen.indent_level * gen.indent_size)
    gen._write(indent)
    gen._write(f"{node.identifier} = {{ ")
    for token in node.tokens:
        gen._write(gen.visit(token))
        gen._write(" ")
    gen._write("}")
    if hasattr(node, "modifiers") and node.modifiers:
        gen._write_modifiers(node.modifiers)
    return ""


def write_regex_string(gen, node) -> str:
    """Render a regex string definition."""
    indent = " " * (gen.indent_level * gen.indent_size)
    gen._write(indent)
    escaped_regex = node.regex.replace("/", "\\/")
    gen._write(f"{node.identifier} = /{escaped_regex}/")
    if hasattr(node, "modifiers") and node.modifiers:
        gen._write_modifiers(node.modifiers)
    return ""
