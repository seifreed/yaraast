"""Layout helpers for PrettyPrinter."""

from __future__ import annotations

from yaraast.codegen.pretty_printer_helpers import (
    build_hex_pattern,
    expression_to_string,
    format_plain_string,
    format_regex_string,
    modifiers_to_string,
)


def visit_yara_file(printer, node) -> str:
    if node.imports:
        imports = (
            sorted(node.imports, key=lambda item: item.module)
            if printer.options.sort_imports
            else node.imports
        )
        for imp in imports:
            printer.visit_import(imp)
            printer._writeline()
        for _ in range(printer.options.blank_lines_after_imports - 1):
            printer._writeline()

    if node.includes:
        includes = (
            sorted(node.includes, key=lambda item: item.path)
            if printer.options.sort_includes
            else node.includes
        )
        for inc in includes:
            printer.visit_include(inc)
            printer._writeline()
        for _ in range(printer.options.blank_lines_after_includes):
            printer._writeline()

    for index, rule in enumerate(node.rules):
        if index > 0:
            for _ in range(printer.options.blank_lines_before_rule):
                printer._writeline()
        printer.visit_rule(rule)
        printer._writeline()
    return printer.buffer.getvalue()


def visit_rule(printer, node) -> str:
    printer._write_comments(node.leading_comments)
    line_parts = []
    if node.modifiers:
        line_parts.extend(str(m) for m in node.modifiers)
    line_parts.extend(["rule", node.name])
    if node.tags:
        tags = (
            sorted([tag.name for tag in node.tags])
            if printer.options.sort_tags
            else [tag.name for tag in node.tags]
        )
        line_parts.append(":")
        line_parts.extend(tags)
    printer._writeline(" ".join(line_parts) + " {")
    printer._indent()

    if node.meta:
        printer._writeline("meta:")
        printer._indent()
        printer._write_meta_section(node.meta)
        printer._dedent()
        if node.strings or node.condition:
            for _ in range(printer.options.blank_lines_between_sections):
                printer._writeline()

    if node.strings:
        printer._writeline("strings:")
        printer._indent()
        printer._write_strings_section(node.strings)
        printer._dedent()
        if node.condition:
            for _ in range(printer.options.blank_lines_between_sections):
                printer._writeline()

    if node.condition:
        printer._writeline("condition:")
        printer._indent()
        printer._write_condition_section(node.condition)
        printer._dedent()

    printer._dedent()
    printer._writeline("}")
    return printer.buffer.getvalue()


def write_string_definition(printer, string_def) -> None:
    from yaraast.ast.strings import HexString, PlainString, RegexString

    if isinstance(string_def, PlainString):
        quote = '"' if printer.options.quote_style == "double" else "'"
        padding = (
            max(0, printer._string_alignment_column - len(string_def.identifier))
            if printer.options.align_string_definitions and printer._string_alignment_column > 0
            else 0
        )
        printer._write(format_plain_string(string_def, quote, padding))
        printer._write(modifiers_to_string(string_def.modifiers))
        printer._writeline()
        return

    if isinstance(string_def, HexString):
        hex_pattern = build_hex_pattern(
            string_def,
            hex_uppercase=printer.options.hex_uppercase,
            hex_spacing=printer.options.hex_spacing,
        )
        if printer.options.align_string_definitions and printer._string_alignment_column > 0:
            padding = max(0, printer._string_alignment_column - len(string_def.identifier))
            printer._write(f"{string_def.identifier}{' ' * padding} = {{ {hex_pattern} }}")
        else:
            printer._write(f"{string_def.identifier} = {{ {hex_pattern} }}")
        printer._write(modifiers_to_string(string_def.modifiers))
        printer._writeline()
        return

    if isinstance(string_def, RegexString):
        padding = (
            max(0, printer._string_alignment_column - len(string_def.identifier))
            if printer.options.align_string_definitions and printer._string_alignment_column > 0
            else 0
        )
        printer._write(format_regex_string(string_def, padding))
        printer._write(modifiers_to_string(string_def.modifiers))
        printer._writeline()
        return

    printer.visit(string_def)
    printer._writeline()


def write_condition_section(printer, condition) -> None:
    condition_str = expression_to_string(condition)
    if (
        printer.options.wrap_long_conditions
        and len(condition_str) > printer.options.max_line_length
    ):
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
        return
    printer._writeline(condition_str)
