"""Section-level helpers for PrettyPrinter."""

from __future__ import annotations

from typing import Any

from yaraast.ast.strings import HexString, PlainString, RegexString, StringDefinition
from yaraast.codegen.pretty_printer_helpers import (
    build_hex_pattern,
    format_plain_string,
    format_regex_string,
    modifiers_to_string,
)


def write_meta_section(printer, meta: list) -> None:
    """Write meta entries preserving PrettyPrinter behavior."""
    entries = list(meta)
    if printer.options.sort_meta_keys:
        entries.sort(key=lambda x: getattr(x, "key", ""))
    for entry in entries:
        if hasattr(entry, "key") and hasattr(entry, "value"):
            write_meta_entry(printer, entry.key, entry.value)


def write_meta_entry(printer, key: str, value: Any) -> None:
    """Write a single meta entry with alignment handling."""
    if printer.options.align_meta_values and printer._meta_alignment_column > 0:
        key_part = f"{key} ="
        padding = max(1, printer._meta_alignment_column - len(key_part))
        printer._write(key_part + " " * padding)
    else:
        printer._write(f"{key} = ")

    if isinstance(value, str):
        quote = '"' if printer.options.quote_style == "double" else "'"
        printer._write(f"{quote}{value}{quote}")
    elif isinstance(value, bool):
        printer._write("true" if value else "false")
    else:
        printer._write(str(value))

    printer._writeline()


def write_strings_section(printer, strings: list[StringDefinition]) -> None:
    """Write all string definitions."""
    for string_def in strings:
        printer._write_string_definition(string_def)


def write_plain_string_aligned(printer, node: PlainString) -> None:
    """Write a plain string honoring alignment options."""
    quote = '"' if printer.options.quote_style == "double" else "'"
    if printer.options.align_string_definitions and printer._string_alignment_column > 0:
        padding = max(0, printer._string_alignment_column - len(node.identifier))
        printer._write(format_plain_string(node, quote, padding))
    else:
        printer._write(format_plain_string(node, quote, 0))
    printer._write(modifiers_to_string(node.modifiers))
    printer._writeline()


def write_hex_string_aligned(printer, node: HexString) -> None:
    """Write a hex string honoring alignment and casing options."""
    hex_pattern = build_hex_pattern(
        node,
        hex_uppercase=printer.options.hex_uppercase,
        hex_spacing=printer.options.hex_spacing,
    )
    if printer.options.align_string_definitions and printer._string_alignment_column > 0:
        padding = max(0, printer._string_alignment_column - len(node.identifier))
        printer._write(f"{node.identifier}{' ' * padding} = {{ {hex_pattern} }}")
    else:
        printer._write(f"{node.identifier} = {{ {hex_pattern} }}")
    printer._write(modifiers_to_string(node.modifiers))
    printer._writeline()


def write_regex_string_aligned(printer, node: RegexString) -> None:
    """Write a regex string honoring alignment options."""
    if printer.options.align_string_definitions and printer._string_alignment_column > 0:
        padding = max(0, printer._string_alignment_column - len(node.identifier))
        printer._write(format_regex_string(node, padding))
    else:
        printer._write(format_regex_string(node, 0))
    printer._write(modifiers_to_string(node.modifiers))
    printer._writeline()


def write_wrapped_condition(printer, condition_str: str) -> None:
    """Write condition with simple wrapping on token boundaries."""
    current_line = ""
    for word in condition_str.split():
        if len(current_line + " " + word) > printer.options.max_line_length:
            printer._writeline(current_line)
            current_line = "    " + word
        elif current_line:
            current_line += " " + word
        else:
            current_line = word
    if current_line:
        printer._writeline(current_line)
