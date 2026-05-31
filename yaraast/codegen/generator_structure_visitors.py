"""Structure-level visitors for the YARA code generator."""

from __future__ import annotations

from yaraast.codegen.generator_formatting import (
    format_nonempty_quoted_value,
    validate_rule_collections,
    validate_rule_identifiers,
    validate_yara_file_collections,
    validate_yara_identifier,
)


def _emit_comments(generator, node) -> None:
    """Emit leading comments for an AST node."""
    if hasattr(node, "leading_comments") and node.leading_comments:
        for comment in node.leading_comments:
            generator._writeline(comment.text)


def _emit_trailing(generator, node) -> None:
    """Emit trailing comment for an AST node."""
    if hasattr(node, "trailing_comment") and node.trailing_comment:
        generator._write(f"  {node.trailing_comment.text}")


def _emit_top_level_line(generator, node) -> None:
    _emit_comments(generator, node)
    rendered = generator.visit(node)
    if rendered:
        generator._write(rendered)
    generator._writeline()


def _emit_top_level_section(generator, nodes) -> bool:
    if not nodes:
        return False
    for node in nodes:
        _emit_top_level_line(generator, node)
    generator._writeline()
    return True


def visit_yara_file(generator, node) -> str:
    validate_yara_file_collections(node)
    validate_rule_identifiers(node.rules)
    _emit_top_level_section(generator, node.pragmas)
    _emit_top_level_section(generator, node.imports)
    _emit_top_level_section(generator, node.extern_imports)
    _emit_top_level_section(generator, node.includes)
    _emit_top_level_section(generator, node.namespaces)
    _emit_top_level_section(generator, node.extern_rules)
    for index, rule in enumerate(node.rules):
        if index > 0:
            generator._writeline()
        _emit_comments(generator, rule)
        generator.visit(rule)
    return generator.buffer.getvalue()


def visit_import(node) -> str:
    value = f"import \"{format_nonempty_quoted_value(node.module, 'Import module')}\""
    if node.alias:
        msg = "Import aliases are not supported for libyara output"
        raise ValueError(msg)
    return value


def visit_include(node) -> str:
    return f"include \"{format_nonempty_quoted_value(node.path, 'Include path')}\""


def visit_rule(generator, node) -> str:
    validate_rule_collections(node)
    generator._write_rule_header(node)
    generator._writeline(" {")
    generator._indent()
    generator._write_meta_section(node.meta)
    _write_in_rule_pragmas(generator, node, "before_strings")
    generator._write_strings_section(node.strings, has_condition=node.condition is not None)
    _write_in_rule_pragmas(generator, node, "after_strings")
    _write_in_rule_pragmas(generator, node, "before_condition")
    generator._write_condition_section(node.condition)
    generator._dedent()
    generator._write("}")
    _emit_trailing(generator, node)
    generator._writeline()
    return ""


def visit_tag(node) -> str:
    return validate_yara_identifier(node.name, "tag")


def visit_string_definition(_node) -> str:
    return ""


def _write_in_rule_pragmas(generator, node, position: str) -> None:
    for pragma in getattr(node, "pragmas", []):
        if pragma.position == position:
            generator._writeline(generator.visit(pragma))
