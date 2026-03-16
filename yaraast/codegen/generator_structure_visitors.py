"""Structure-level visitors for the YARA code generator."""

from __future__ import annotations


def visit_yara_file(generator, node) -> str:
    for imp in node.imports:
        generator.visit(imp)
        generator._writeline()
    if node.imports:
        generator._writeline()
    for inc in node.includes:
        generator.visit(inc)
        generator._writeline()
    if node.includes:
        generator._writeline()
    for index, rule in enumerate(node.rules):
        if index > 0:
            generator._writeline()
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
    generator._writeline("}")
    return ""


def visit_tag(node) -> str:
    return node.name


def visit_string_definition(_node) -> str:
    return ""
