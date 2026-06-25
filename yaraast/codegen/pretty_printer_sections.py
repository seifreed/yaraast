"""Section-level helpers for PrettyPrinter."""

from __future__ import annotations

from typing import Any

from yaraast.ast.strings import StringDefinition
from yaraast.codegen.generator_formatting import (
    format_meta_key,
    format_meta_literal,
    validate_rule_meta,
)
from yaraast.codegen.generator_helpers import (
    validate_string_identifiers,
)
from yaraast.codegen.pretty_printer_helpers import current_indent
from yaraast.codegen.pretty_printer_layout import write_string_definition


def write_meta_section(printer: Any, meta: list[Any]) -> None:
    """Write meta entries preserving PrettyPrinter behavior."""
    validate_rule_meta(meta)
    entries = list(meta)
    if printer._layout.options.sort_meta_keys:
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


def write_meta_entry(
    printer: Any,
    key: str,
    value: Any,
    trailing_comment: Any = None,
) -> None:
    """Write a single meta entry with alignment handling."""
    printer._write(current_indent(printer))
    if printer._layout.options.align_meta_values and printer._layout._meta_alignment_column > 0:
        key_part = f"{key} ="
        padding = max(1, printer._layout._meta_alignment_column - len(key_part))
        printer._write(key_part + " " * padding)
    else:
        printer._write(f"{key} = ")

    printer._write(format_meta_literal(value))

    if trailing_comment:
        printer._write_comment(trailing_comment, inline=True)

    printer._writeline()


def write_strings_section(printer: Any, strings: list[StringDefinition]) -> None:
    """Write all string definitions."""
    validate_string_identifiers(strings)
    for string_def in strings:
        write_string_definition(printer, string_def)
