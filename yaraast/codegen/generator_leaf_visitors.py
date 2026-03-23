"""Leaf rendering helpers for CodeGenerator visitor methods."""

from __future__ import annotations

from yaraast.codegen.generator_formatting import (
    escape_string_literal,
    format_boolean_literal,
    format_hex_jump,
    format_regex_literal,
)
from yaraast.codegen.generator_helpers import format_integer_literal


def visit_hex_byte(node) -> str:
    if isinstance(node.value, str):
        return node.value.upper()
    return f"{node.value:02X}"


def visit_hex_wildcard(node) -> str:
    return "??"


def visit_hex_jump(node) -> str:
    return format_hex_jump(node.min_jump, node.max_jump)


def visit_hex_alternative(generator, node) -> str:
    alts = []
    for alt in node.alternatives:
        alt_str = " ".join(generator.visit(token) for token in alt)
        alts.append(alt_str)
    return f"( {' | '.join(alts)} )"


def visit_hex_nibble(node) -> str:
    value_str = node.value.upper() if isinstance(node.value, str) else f"{node.value:X}"
    return f"{value_str}?" if node.high else f"?{value_str}"


def visit_identifier(node) -> str:
    return node.name


def visit_string_identifier(node) -> str:
    return node.name


def visit_string_wildcard(node) -> str:
    return node.pattern


def visit_string_count(node) -> str:
    return f"#{node.string_id}"


def visit_string_offset(generator, node) -> str:
    if node.index:
        return f"@{node.string_id}[{generator.visit(node.index)}]"
    return f"@{node.string_id}"


def visit_string_length(generator, node) -> str:
    if node.index:
        return f"!{node.string_id}[{generator.visit(node.index)}]"
    return f"!{node.string_id}"


def visit_integer_literal(node) -> str:
    return format_integer_literal(node.value)


def visit_double_literal(node) -> str:
    return str(node.value)


def visit_string_literal(node) -> str:
    return f'"{escape_string_literal(node.value)}"'


def visit_regex_literal(node) -> str:
    return format_regex_literal(node.pattern, node.modifiers)


def visit_boolean_literal(node) -> str:
    return format_boolean_literal(node.value)


def visit_meta(node) -> str:
    if isinstance(node.value, str):
        return f'{node.key} = "{node.value}"'
    if isinstance(node.value, bool):
        return f"{node.key} = {'true' if node.value else 'false'}"
    return f"{node.key} = {node.value}"


def visit_module_reference(node) -> str:
    return node.module


def visit_dictionary_access(generator, node) -> str:
    obj = generator.visit(node.object)
    if isinstance(node.key, str):
        return f'{obj}["{node.key}"]'
    return f"{obj}[{generator.visit(node.key)}]"


def visit_defined_expression(generator, node) -> str:
    return f"defined {generator.visit(node.expression)}"


def visit_string_operator_expression(generator, node) -> str:
    return f"{generator.visit(node.left)} {node.operator} {generator.visit(node.right)}"


def visit_comment(node) -> str:
    return f"// {node.text}"


def visit_comment_group(node) -> str:
    return "\n".join(f"// {c.text}" for c in node.comments)


def visit_extern_import(node) -> str:
    return f'import "{node.module_path}"'


def visit_extern_namespace(node) -> str:
    return f"namespace {node.name}"


def visit_extern_rule(node) -> str:
    modifiers = " ".join(str(m) for m in node.modifiers) if hasattr(node, "modifiers") else ""
    if modifiers:
        return f"{modifiers} rule {node.name}"
    return f"rule {node.name}"


def visit_extern_rule_reference(node) -> str:
    return node.name


def visit_in_rule_pragma(node) -> str:
    args_str = " " + " ".join(node.pragma.arguments) if node.pragma.arguments else ""
    return f"#pragma {node.pragma.name}{args_str}"


def visit_pragma(node) -> str:
    args_str = " " + " ".join(node.arguments) if node.arguments else ""
    return f"#pragma {node.name}{args_str}"


def visit_pragma_block(generator, node) -> str:
    return "\n".join(generator.visit(pragma) for pragma in node.pragmas)
