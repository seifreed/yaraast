"""Section and string rendering helpers for the main code generator."""

from __future__ import annotations

from yaraast.codegen.generator_helpers import (
    escape_regex_delimiter,
    format_regex_modifiers,
    output_string_identifier,
    validate_hex_string_modifiers,
    validate_hex_string_tokens,
    validate_plain_string_modifiers,
    validate_regex_string_modifiers,
    validate_string_identifiers,
)


def _emit_comments(gen, node) -> None:
    """Emit leading comments for an AST node."""
    if hasattr(node, "leading_comments") and node.leading_comments:
        for comment in node.leading_comments:
            gen._writeline(comment.text)


def write_meta_section(gen, meta) -> None:
    """Write meta section if present."""
    if not meta:
        return
    gen._writeline("meta:")
    gen._indent()
    for item in meta:
        if hasattr(item, "key") and hasattr(item, "value"):
            _emit_comments(gen, item)
            gen._writeline(
                gen._format_meta_value(item.key, item.value, getattr(item, "scope", None))
            )
    gen._dedent()
    gen._writeline()


def write_strings_section(gen, strings, *, has_condition: bool) -> None:
    """Write strings section if present."""
    if not strings:
        return
    validate_string_identifiers(strings)
    gen._writeline("strings:")
    gen._indent()
    for string in strings:
        _emit_comments(gen, string)
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
    if "\n" in condition_code:
        for line in condition_code.splitlines():
            gen._writeline(line)
    else:
        gen._writeline(condition_code)
    gen._dedent()


def write_plain_string(gen, node) -> str:
    """Render a plain string definition."""
    validate_plain_string_modifiers(node.modifiers)
    indent = " " * (gen.indent_level * gen.indent_size)
    gen._write(indent)
    escaped_value = gen._escape_plain_string_value(node.value)
    gen._write(f'{output_string_identifier(node)} = "{escaped_value}"')
    if hasattr(node, "modifiers") and node.modifiers:
        gen._write_modifiers(node.modifiers)
    return ""


def write_hex_string(gen, node) -> str:
    """Render a hex string definition."""
    validate_hex_string_modifiers(node.modifiers)
    validate_hex_string_tokens(node.tokens)
    indent = " " * (gen.indent_level * gen.indent_size)
    gen._write(indent)
    gen._write(f"{output_string_identifier(node)} = {{ ")
    for token in node.tokens:
        gen._write(gen.visit(token))
        gen._write(" ")
    gen._write("}")
    if hasattr(node, "modifiers") and node.modifiers:
        gen._write_modifiers(node.modifiers)
    return ""


def write_regex_string(gen, node) -> str:
    """Render a regex string definition."""
    validate_regex_string_modifiers(node.modifiers)
    indent = " " * (gen.indent_level * gen.indent_size)
    gen._write(indent)
    escaped_regex = escape_regex_delimiter(node.regex)
    gen._write(f"{output_string_identifier(node)} = /{escaped_regex}/")
    if hasattr(node, "modifiers") and node.modifiers:
        gen._write(format_regex_modifiers(node.modifiers, gen.visit))
    return ""
