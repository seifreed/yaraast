"""Layout helpers for PrettyPrinter."""

from __future__ import annotations

from typing import Any

from yaraast.codegen.generator_formatting import (
    format_rule_modifiers,
    validate_extern_rule_identifiers,
    validate_rule_collections,
    validate_rule_identifiers,
    validate_rule_meta,
    validate_rule_tags,
    validate_yara_file_collections,
    validate_yara_identifier,
)
from yaraast.codegen.generator_helpers import (
    output_string_identifier,
    validate_hex_string_modifiers,
    validate_plain_string_modifiers,
    validate_regex_string_modifiers,
    validate_string_identifiers,
)
from yaraast.codegen.pretty_printer_helpers import (
    build_hex_pattern,
    current_indent,
    expression_to_string,
    format_plain_string,
    format_regex_string,
    indent_unit,
    modifiers_to_string,
    regex_modifiers_to_string,
)


def _emit_top_level_line(printer: Any, node: Any) -> None:
    printer._write_comments(getattr(node, "leading_comments", None))
    rendered = printer.visit(node)
    if rendered:
        printer._write(rendered)
    trailing_comment = getattr(node, "trailing_comment", None)
    if trailing_comment:
        printer._write_comment(trailing_comment, inline=True)
    printer._writeline()


def _write_line(printer: Any, text: str, trailing_comment: Any = None) -> None:
    printer._write(current_indent(printer))
    printer._write(text)
    if trailing_comment:
        printer._write_comment(trailing_comment, inline=True)
    printer._writeline()


def _emit_top_level_section(
    printer: Any,
    nodes: list[Any] | tuple[Any, ...],
    blank_lines: int = 1,
) -> None:
    if not nodes:
        return
    for node in nodes:
        _emit_top_level_line(printer, node)
    for _ in range(blank_lines):
        printer._writeline()


def visit_yara_file(printer: Any, node: Any) -> str:
    validate_yara_file_collections(node)
    validate_rule_identifiers(node.rules)
    validate_extern_rule_identifiers(node.rules, node.extern_rules, node.namespaces)
    _emit_top_level_section(printer, node.pragmas)

    imports = (
        sorted(node.imports, key=lambda item: item.module)
        if printer.options.sort_imports
        else node.imports
    )
    _emit_top_level_section(printer, imports, max(0, printer.options.blank_lines_after_imports - 1))
    _emit_top_level_section(printer, node.extern_imports)

    includes = (
        sorted(node.includes, key=lambda item: item.path)
        if printer.options.sort_includes
        else node.includes
    )
    _emit_top_level_section(printer, includes, printer.options.blank_lines_after_includes)
    _emit_top_level_section(printer, node.namespaces)
    _emit_top_level_section(printer, node.extern_rules)

    for index, rule in enumerate(node.rules):
        if index > 0:
            for _ in range(printer.options.blank_lines_before_rule):
                printer._writeline()
        printer.visit_rule(rule)
        printer._writeline()
    return str(printer.buffer.getvalue())


def visit_rule(printer: Any, node: Any) -> str:
    printer._write_comments(node.leading_comments)
    validate_rule_collections(node)
    validate_rule_meta(node.meta)
    validate_string_identifiers(node.strings)
    line_parts: list[str] = []
    modifiers = format_rule_modifiers(node.modifiers)
    if modifiers:
        line_parts.append(modifiers)
    rule_name = validate_yara_identifier(node.name, "rule")
    line_parts.extend(["rule", rule_name])
    if node.tags:
        validate_rule_tags(node.tags)
        tag_names = [tag if isinstance(tag, str) else tag.name for tag in node.tags]
        tags = sorted(tag_names) if printer.options.sort_tags else tag_names
        line_parts.append(":")
        line_parts.extend(tags)
    _write_line(printer, " ".join(line_parts) + " {", getattr(node, "trailing_comment", None))
    printer._indent()

    if node.meta:
        printer._writeline("meta:")
        printer._indent()
        printer._write_meta_section(node.meta)
        printer._dedent()
        if node.pragmas or node.strings or node.condition:
            for _ in range(printer.options.blank_lines_between_sections):
                printer._writeline()

    _write_in_rule_pragmas(printer, node, "before_strings")

    if node.strings:
        printer._writeline("strings:")
        printer._indent()
        printer._write_strings_section(node.strings)
        printer._dedent()
        if node.pragmas or node.condition:
            for _ in range(printer.options.blank_lines_between_sections):
                printer._writeline()

    _write_in_rule_pragmas(printer, node, "after_strings")
    _write_in_rule_pragmas(printer, node, "before_condition")

    if node.condition is not None:
        printer._writeline("condition:")
        printer._indent()
        printer._write_condition_section(node.condition)
        printer._dedent()

    printer._dedent()
    printer._writeline("}")
    return str(printer.buffer.getvalue())


def _write_in_rule_pragmas(printer: Any, node: Any, position: str) -> None:
    for pragma in getattr(node, "pragmas", []):
        if pragma.position == position:
            printer._write_comments(getattr(pragma, "leading_comments", None))
            rendered = printer.visit(pragma)
            if rendered:
                _write_line(printer, rendered, getattr(pragma, "trailing_comment", None))
            else:
                trailing_comment = getattr(pragma, "trailing_comment", None)
                if trailing_comment:
                    printer._write_comment(trailing_comment)


def write_string_definition(printer: Any, string_def: Any) -> None:
    from yaraast.ast.strings import HexString, PlainString, RegexString

    printer._write_comments(getattr(string_def, "leading_comments", None))
    trailing_comment = getattr(string_def, "trailing_comment", None)

    if isinstance(string_def, PlainString):
        validate_plain_string_modifiers(string_def.modifiers)
        identifier = output_string_identifier(string_def)
        padding = (
            max(0, printer._string_alignment_column - len(identifier))
            if printer.options.align_string_definitions and printer._string_alignment_column > 0
            else 0
        )
        printer._write(current_indent(printer))
        printer._write(format_plain_string(string_def, '"', padding))
        printer._write(modifiers_to_string(string_def.modifiers))
        if trailing_comment:
            printer._write_comment(trailing_comment, inline=True)
        printer._writeline()
        return

    if isinstance(string_def, HexString):
        validate_hex_string_modifiers(string_def.modifiers)
        hex_pattern = build_hex_pattern(
            string_def,
            hex_uppercase=printer.options.hex_uppercase,
            hex_spacing=printer.options.hex_spacing,
        )
        if printer.options.align_string_definitions and printer._string_alignment_column > 0:
            identifier = output_string_identifier(string_def)
            padding = max(0, printer._string_alignment_column - len(identifier))
            printer._write(current_indent(printer))
            printer._write(f"{identifier}{' ' * padding} = {{ {hex_pattern} }}")
        else:
            printer._write(current_indent(printer))
            printer._write(f"{output_string_identifier(string_def)} = {{ {hex_pattern} }}")
        printer._write(modifiers_to_string(string_def.modifiers))
        if trailing_comment:
            printer._write_comment(trailing_comment, inline=True)
        printer._writeline()
        return

    if isinstance(string_def, RegexString):
        validate_regex_string_modifiers(string_def.modifiers)
        identifier = output_string_identifier(string_def)
        padding = (
            max(0, printer._string_alignment_column - len(identifier))
            if printer.options.align_string_definitions and printer._string_alignment_column > 0
            else 0
        )
        printer._write(current_indent(printer))
        printer._write(format_regex_string(string_def, padding))
        printer._write(regex_modifiers_to_string(string_def.modifiers))
        if trailing_comment:
            printer._write_comment(trailing_comment, inline=True)
        printer._writeline()
        return

    printer.visit(string_def)
    if trailing_comment:
        printer._write_comment(trailing_comment, inline=True)
    printer._writeline()


def write_condition_section(printer: Any, condition: Any) -> None:
    printer._write_comments(getattr(condition, "leading_comments", None))
    condition_str = expression_to_string(condition, printer.options)
    trailing_comment = getattr(condition, "trailing_comment", None)
    if "\n" in condition_str:
        split_lines = condition_str.splitlines()
        for index, line in enumerate(split_lines):
            comment = trailing_comment if index == len(split_lines) - 1 else None
            _write_line(printer, line, comment)
        return

    if (
        printer.options.wrap_long_conditions
        and len(condition_str) > printer.options.max_line_length
    ):
        current_line = ""
        lines: list[str] = []
        for word in condition_str.split():
            if len(current_line + " " + word) > printer.options.max_line_length:
                if current_line:
                    lines.append(current_line)
                    current_line = indent_unit(printer) + word
                else:
                    current_line = word
            elif current_line:
                current_line += " " + word
            else:
                current_line = word
        if current_line:
            lines.append(current_line)
        for index, line in enumerate(lines):
            comment = trailing_comment if index == len(lines) - 1 else None
            _write_line(printer, line, comment)
        return
    _write_line(printer, condition_str, trailing_comment)
