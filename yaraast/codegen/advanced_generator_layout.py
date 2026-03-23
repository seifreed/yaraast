"""Layout helpers for AdvancedCodeGenerator."""

from __future__ import annotations

from yaraast.codegen.formatting import BraceStyle, StringStyle
from yaraast.codegen.generator import CodeGenerator


def visit_yara_file(generator, node) -> str:
    imports = (
        sorted(node.imports, key=lambda item: item.module)
        if generator.config.sort_imports
        else node.imports
    )
    for imp in imports:
        generator.visit(imp)
    if imports:
        generator._write_blank_lines(generator.config.blank_lines_between_sections)

    for inc in node.includes:
        generator.visit(inc)
    if node.includes:
        generator._write_blank_lines(generator.config.blank_lines_between_sections)

    rules = node.rules
    if generator.config.sort_rules:
        rules = sorted(rules, key=lambda item: item.name)
    elif generator.config.sort_meta:

        def sort_key(rule):
            has_meta = bool(rule.meta and (bool(rule.meta)))
            return (not has_meta, rule.name)

        rules = sorted(rules, key=sort_key)

    for index, rule in enumerate(rules):
        if index > 0:
            generator._write_blank_lines(generator.config.blank_lines_between_rules)
        generator.visit(rule)
    return generator.buffer.getvalue()


def visit_rule(generator, node) -> str:
    if node.modifiers:
        generator._write(" ".join(str(m) for m in node.modifiers) + " ")
    generator._write(f"rule {node.name}")

    if node.tags:
        if generator.config.space_before_colon:
            generator._write(" ")
        generator._write(":")
        if generator.config.space_after_colon:
            generator._write(" ")
        tags_str = []
        for tag in node.tags:
            tags_str.append(
                tag if isinstance(tag, str) else tag.name if hasattr(tag, "name") else str(tag)
            )
        generator._write(" ".join(tags_str))

    if generator.config.brace_style == BraceStyle.SAME_LINE:
        generator._write(" {")
        generator._writeline()
    else:
        generator._writeline()
        generator._writeline("{")

    generator._indent()
    sections_written = 0
    for section in generator.config.section_order:
        if section == "meta" and node.meta:
            if sections_written > 0:
                generator._write_blank_lines(generator.config.blank_lines_between_sections)
            generator._write_meta_section(node.meta)
            sections_written += 1
        elif section == "strings" and node.strings:
            if sections_written > 0:
                generator._write_blank_lines(generator.config.blank_lines_between_sections)
            generator._write_strings_section(node.strings)
            sections_written += 1
        elif section == "condition":
            if sections_written > 0:
                generator._write_blank_lines(generator.config.blank_lines_between_sections)
            generator._write_condition_section(node.condition)
            sections_written += 1

    generator._dedent()
    generator._write("}")
    return generator.buffer.getvalue()


def write_strings_section(generator, strings) -> None:
    generator._writeline("strings:")
    generator._indent()
    if generator.config.sort_strings:
        strings = sorted(strings, key=lambda item: item.identifier)

    if generator.config.string_style in (StringStyle.ALIGNED, StringStyle.TABULAR):
        generator._collect_string_definitions(strings)
        write_aligned_strings(generator)
    else:
        for string_def in strings:
            generator.visit(string_def)
            generator._writeline()
    generator._dedent()


def write_aligned_strings(generator) -> None:
    if not generator._string_definitions:
        return
    max_id_len = max(len(identifier) for identifier, _, _ in generator._string_definitions)
    max_val_len = max(len(value) for _, value, _ in generator._string_definitions)
    for identifier, value, modifiers in generator._string_definitions:
        generator._write(generator._get_indent())
        if generator.config.string_style == StringStyle.TABULAR:
            generator._write(identifier.ljust(max_id_len))
            generator._write(" = ")
            generator._write(value.ljust(max_val_len))
        else:
            generator._write(f"{identifier} = {value}")
        if modifiers:
            generator._write("  " if generator.config.align_string_modifiers else " ")
            generator._write(" ".join(modifiers))
        generator._writeline()


def write_condition_section(generator, condition) -> None:
    generator._writeline("condition:")
    generator._indent()
    condition_str = generate_condition_string(condition)
    if len(condition_str) > generator.config.max_line_length:
        generator._writeline(condition_str)
    else:
        generator._writeline(condition_str)
    generator._dedent()


def generate_condition_string(expr) -> str:
    temp_gen = CodeGenerator()
    return temp_gen.visit(expr)
