"""Section-level helpers for PrettyPrinter."""

from __future__ import annotations

from typing import Any

from yaraast.ast.strings import HexString, PlainString, RegexString, StringDefinition
from yaraast.codegen.generator_formatting import escape_string_literal, format_meta_key
from yaraast.codegen.pretty_printer_helpers import (
    build_hex_pattern,
    current_indent,
    format_plain_string,
    format_regex_string,
    indent_unit,
    modifiers_to_string,
    output_string_identifier,
    regex_modifiers_to_string,
)


def write_meta_section(printer, meta: list) -> None:
    """Write meta entries preserving PrettyPrinter behavior."""
    entries = list(meta)
    if printer.options.sort_meta_keys:
        entries.sort(key=lambda x: getattr(x, "key", ""))
    for entry in entries:
        if hasattr(entry, "key") and hasattr(entry, "value"):
            printer._write_comments(getattr(entry, "leading_comments", None))
            write_meta_entry(
                printer,
                format_meta_key(entry.key, getattr(entry, "scope", None)),
                entry.value,
                getattr(entry, "trailing_comment", None),
            )


def write_meta_entry(printer, key: str, value: Any, trailing_comment=None) -> None:
    """Write a single meta entry with alignment handling."""
    printer._write(current_indent(printer))
    if printer.options.align_meta_values and printer._meta_alignment_column > 0:
        key_part = f"{key} ="
        padding = max(1, printer._meta_alignment_column - len(key_part))
        printer._write(key_part + " " * padding)
    else:
        printer._write(f"{key} = ")

    if isinstance(value, str):
        printer._write(f'"{escape_string_literal(value)}"')
    elif isinstance(value, bool):
        printer._write("true" if value else "false")
    else:
        printer._write(str(value))

    if trailing_comment:
        printer._write_comment(trailing_comment, inline=True)

    printer._writeline()


def write_strings_section(printer, strings: list[StringDefinition]) -> None:
    """Write all string definitions."""
    for string_def in strings:
        printer._write_string_definition(string_def)


def write_plain_string_aligned(printer, node: PlainString) -> None:
    """Write a plain string honoring alignment options."""
    printer._write_comments(getattr(node, "leading_comments", None))
    printer._write(current_indent(printer))
    if printer.options.align_string_definitions and printer._string_alignment_column > 0:
        padding = max(0, printer._string_alignment_column - len(output_string_identifier(node)))
        printer._write(format_plain_string(node, '"', padding))
    else:
        printer._write(format_plain_string(node, '"', 0))
    printer._write(modifiers_to_string(node.modifiers))
    trailing_comment = getattr(node, "trailing_comment", None)
    if trailing_comment:
        printer._write_comment(trailing_comment, inline=True)
    printer._writeline()


def write_hex_string_aligned(printer, node: HexString) -> None:
    """Write a hex string honoring alignment and casing options."""
    printer._write_comments(getattr(node, "leading_comments", None))
    printer._write(current_indent(printer))
    hex_pattern = build_hex_pattern(
        node,
        hex_uppercase=printer.options.hex_uppercase,
        hex_spacing=printer.options.hex_spacing,
    )
    if printer.options.align_string_definitions and printer._string_alignment_column > 0:
        identifier = output_string_identifier(node)
        padding = max(0, printer._string_alignment_column - len(identifier))
        printer._write(f"{identifier}{' ' * padding} = {{ {hex_pattern} }}")
    else:
        printer._write(f"{output_string_identifier(node)} = {{ {hex_pattern} }}")
    printer._write(modifiers_to_string(node.modifiers))
    trailing_comment = getattr(node, "trailing_comment", None)
    if trailing_comment:
        printer._write_comment(trailing_comment, inline=True)
    printer._writeline()


def write_regex_string_aligned(printer, node: RegexString) -> None:
    """Write a regex string honoring alignment options."""
    printer._write_comments(getattr(node, "leading_comments", None))
    printer._write(current_indent(printer))
    if printer.options.align_string_definitions and printer._string_alignment_column > 0:
        padding = max(0, printer._string_alignment_column - len(output_string_identifier(node)))
        printer._write(format_regex_string(node, padding))
    else:
        printer._write(format_regex_string(node, 0))
    printer._write(regex_modifiers_to_string(node.modifiers))
    trailing_comment = getattr(node, "trailing_comment", None)
    if trailing_comment:
        printer._write_comment(trailing_comment, inline=True)
    printer._writeline()


def write_wrapped_condition(printer, condition_str: str) -> None:
    """Write condition with simple wrapping on token boundaries."""
    current_line = ""
    for word in condition_str.split():
        if len(current_line + " " + word) > printer.options.max_line_length:
            if current_line:
                printer._writeline(current_line)
                current_line = indent_unit(printer) + word
            else:
                current_line = word
        elif current_line:
            current_line += " " + word
        else:
            current_line = word
    if current_line:
        printer._writeline(current_line)
