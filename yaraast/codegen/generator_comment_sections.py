"""Comment-aware structural rendering for the unified code generator.

These functions mirror :mod:`generator_structure_visitors` and
:mod:`generator_sections` but preserve leading/trailing comments and omit the
blank line between sections. :class:`CodeGenerator` dispatches to them when
``preserve_comments`` is set.
"""

from __future__ import annotations

from typing import Any

from yaraast.codegen.generator_formatting import (
    format_rule_modifiers,
    format_rule_tags,
    validate_extern_rule_identifiers,
    validate_rule_collections,
    validate_rule_identifiers,
    validate_rule_meta,
    validate_yara_file_collections,
    validate_yara_identifier,
)
from yaraast.codegen.generator_helpers import validate_string_identifiers


def _write_top_level_node(gen: Any, node: Any) -> None:
    """Write a file-level node with preserved comments."""
    gen._write_leading_comments(getattr(node, "leading_comments", []))
    rendered = gen.visit(node)
    if rendered:
        gen._write(rendered)
    trailing_comment = getattr(node, "trailing_comment", None)
    if trailing_comment:
        gen._write_comment(trailing_comment, inline=True)
    gen._writeline()


def _write_top_level_section(gen: Any, nodes: list[Any]) -> None:
    if not nodes:
        return
    for node in nodes:
        _write_top_level_node(gen, node)
    gen._writeline()


def comment_visit_yara_file(gen: Any, node: Any) -> str:
    """Generate code for YaraFile with comments."""
    validate_yara_file_collections(node)
    validate_rule_identifiers(node.rules)
    validate_extern_rule_identifiers(node.rules, node.extern_rules, node.namespaces)
    gen._write_leading_comments(node.leading_comments)

    _write_top_level_section(gen, node.pragmas)
    _write_top_level_section(gen, node.imports)
    _write_top_level_section(gen, node.extern_imports)
    _write_top_level_section(gen, node.includes)
    _write_top_level_section(gen, node.namespaces)
    _write_top_level_section(gen, node.extern_rules)

    for i, rule in enumerate(node.rules):
        if i > 0:
            gen._writeline()
        gen.visit(rule)

    if node.trailing_comment:
        gen._writeline()
        gen._write_comment(node.trailing_comment)

    return str(gen.buffer.getvalue())


def comment_visit_rule(gen: Any, node: Any) -> str:
    """Generate code for Rule with comments."""
    validate_rule_collections(node)
    gen._write_leading_comments(node.leading_comments)

    _write_rule_header(gen, node)
    gen._writeline()
    gen._indent()

    _write_meta_section(gen, node)
    _write_rule_pragmas(gen, node, "before_strings")
    _write_strings_section(gen, node)
    _write_rule_pragmas(gen, node, "after_strings")
    _write_rule_pragmas(gen, node, "before_condition")
    _write_condition_section(gen, node)

    gen._dedent()
    gen._writeline("}")

    return ""


def _write_rule_header(gen: Any, node: Any) -> None:
    """Write rule modifiers, name, tags, and opening brace."""
    modifiers = format_rule_modifiers(node.modifiers)
    if modifiers:
        gen._write(f"{modifiers} ")

    rule_name = validate_yara_identifier(node.name, "rule")
    gen._write(f"rule {rule_name}")

    if node.tags:
        gen._write(" : ")
        gen._write(format_rule_tags(node.tags))

    gen._write(" {")

    if node.trailing_comment:
        gen._write_comment(node.trailing_comment, inline=True)


def _write_rule_pragmas(gen: Any, node: Any, position: str) -> None:
    for pragma in node.pragmas:
        if pragma.position != position:
            continue
        gen._write_leading_comments(getattr(pragma, "leading_comments", []))
        rendered = gen.visit(pragma)
        if rendered:
            gen._writeline(rendered)
        trailing = getattr(pragma, "trailing_comment", None)
        if trailing:
            gen._write_comment(trailing, inline=True)


def _write_meta_section(gen: Any, node: Any) -> None:
    """Write the meta section with comments."""
    validate_rule_meta(node.meta)
    if not node.meta:
        return

    gen._writeline("meta:")
    gen._indent()

    for meta in node.meta:
        leading = getattr(meta, "leading_comments", [])
        gen._write_leading_comments(leading)
        if hasattr(meta, "accept"):
            gen.visit(meta)
        elif hasattr(meta, "key"):
            gen._write_meta_item(meta.key, meta.value, getattr(meta, "scope", None))
        trailing = getattr(meta, "trailing_comment", None)
        if trailing:
            gen._write_comment(trailing, inline=True)
        gen._writeline()

    gen._dedent()


def _write_strings_section(gen: Any, node: Any) -> None:
    """Write the strings section with comments."""
    validate_string_identifiers(node.strings)
    if not node.strings:
        return

    gen._writeline("strings:")
    gen._indent()

    for string_def in node.strings:
        gen._write_leading_comments(string_def.leading_comments)
        gen.visit(string_def)
        if string_def.trailing_comment:
            gen._write_comment(string_def.trailing_comment, inline=True)
        gen._writeline()

    gen._dedent()


def _write_condition_section(gen: Any, node: Any) -> None:
    """Write the condition section with comments."""
    condition = node.condition
    if condition is None:
        return

    gen._writeline("condition:")
    gen._indent()

    if hasattr(condition, "leading_comments"):
        gen._write_leading_comments(condition.leading_comments)

    condition_str = gen.visit(condition)
    trailing = getattr(condition, "trailing_comment", None)
    if condition_str:
        indent = " " * (gen.indent_level * gen.indent_size)
        if "\n" in condition_str:
            lines = condition_str.splitlines()
            for index, line in enumerate(lines):
                gen._write(indent)
                gen._write(line)
                if trailing and index == len(lines) - 1:
                    gen._write_comment(trailing, inline=True)
                gen._writeline()
        else:
            gen._write(indent)
            gen._write(condition_str)
            if trailing:
                gen._write_comment(trailing, inline=True)
            gen._writeline()
    elif trailing:
        gen._write_comment(trailing)
    else:
        gen._writeline()

    gen._dedent()
