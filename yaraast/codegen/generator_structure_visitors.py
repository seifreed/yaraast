"""Structure-level visitors for the YARA code generator."""

from __future__ import annotations


def _emit_comments(generator, node) -> None:
    """Emit leading comments for an AST node."""
    if hasattr(node, 'leading_comments') and node.leading_comments:
        for comment in node.leading_comments:
            generator._writeline(comment.text)


def _emit_trailing(generator, node) -> None:
    """Emit trailing comment for an AST node."""
    if hasattr(node, 'trailing_comment') and node.trailing_comment:
        generator._write(f"  {node.trailing_comment.text}")


def visit_yara_file(generator, node) -> str:
    for imp in node.imports:
        _emit_comments(generator, imp)
        generator.visit(imp)
        generator._writeline()
    if node.imports:
        generator._writeline()
    for inc in node.includes:
        _emit_comments(generator, inc)
        generator.visit(inc)
        generator._writeline()
    if node.includes:
        generator._writeline()
    for index, rule in enumerate(node.rules):
        if index > 0:
            generator._writeline()
        _emit_comments(generator, rule)
        generator.visit(rule)
    return generator.buffer.getvalue()


def visit_import(node) -> str:
    value = f'import "{node.module}"'
    if node.alias:
        value += f" as {node.alias}"
    return value


def visit_include(node) -> str:
    return f'include "{node.path}"'


def visit_rule(generator, node) -> str:
    generator._write_rule_header(node)
    generator._writeline(" {")
    generator._indent()
    generator._write_meta_section(node.meta)
    generator._write_strings_section(node.strings, has_condition=node.condition is not None)
    generator._write_condition_section(node.condition)
    generator._dedent()
    generator._write("}")
    _emit_trailing(generator, node)
    generator._writeline()
    return ""


def visit_tag(node) -> str:
    return node.name


def visit_string_definition(_node) -> str:
    return ""
