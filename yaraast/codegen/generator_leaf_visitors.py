"""Leaf rendering helpers for CodeGenerator visitor methods."""

from __future__ import annotations

from yaraast.ast.strings import HexByte
from yaraast.codegen.generator_formatting import (
    escape_string_literal,
    format_boolean_literal,
    format_hex_jump,
    format_meta_value,
    format_regex_literal,
    validate_yara_expression_identifier,
    validate_yara_identifier,
    validate_yara_identifier_path,
)
from yaraast.codegen.generator_helpers import (
    format_double_literal,
    format_hex_byte_value,
    format_hex_nibble_value,
    format_integer_literal,
    validate_string_identifier_text,
    validate_string_wildcard_text,
)


def visit_hex_byte(node) -> str:
    return format_hex_byte_value(node.value, uppercase=True)


def visit_hex_wildcard(node) -> str:
    return "??"


def visit_hex_jump(node) -> str:
    return format_hex_jump(node.min_jump, node.max_jump)


def visit_hex_alternative(generator, node) -> str:
    alts = []
    for alt in node.alternatives:
        tokens = alt if isinstance(alt, list) else [alt]
        alt_str = " ".join(generator.visit(_coerce_hex_token(token)) for token in tokens)
        alts.append(alt_str)
    return f"( {' | '.join(alts)} )"


def _coerce_hex_token(token):
    if isinstance(token, int | str):
        return HexByte(token)
    return token


def visit_hex_nibble(node) -> str:
    value_str = format_hex_nibble_value(node.value, uppercase=True)
    return f"{value_str}?" if node.high else f"?{value_str}"


def visit_identifier(node) -> str:
    return validate_yara_expression_identifier(node.name)


def visit_string_identifier(node, *, allow_placeholder: bool = False) -> str:
    if allow_placeholder and node.name == "$":
        return "$"
    return validate_string_identifier_text(node.name)


def visit_string_wildcard(node) -> str:
    return validate_string_wildcard_text(node.pattern)


def _string_reference_suffix(string_id) -> str:
    text = str(string_id)
    text = text.lstrip("#@!")
    return validate_string_identifier_text(text).removeprefix("$")


def visit_string_count(node) -> str:
    return f"#{_string_reference_suffix(node.string_id)}"


def visit_string_offset(generator, node) -> str:
    suffix = _string_reference_suffix(node.string_id)
    if node.index:
        return f"@{suffix}[{generator.visit(node.index)}]"
    return f"@{suffix}"


def visit_string_length(generator, node) -> str:
    suffix = _string_reference_suffix(node.string_id)
    if node.index:
        return f"!{suffix}[{generator.visit(node.index)}]"
    return f"!{suffix}"


def visit_integer_literal(node) -> str:
    return format_integer_literal(node.value)


def visit_double_literal(node) -> str:
    return format_double_literal(node.value)


def visit_string_literal(node) -> str:
    return f'"{escape_string_literal(node.value)}"'


def visit_regex_literal(node) -> str:
    return format_regex_literal(node.pattern, node.modifiers)


def visit_boolean_literal(node) -> str:
    return format_boolean_literal(node.value)


def visit_meta(node) -> str:
    return format_meta_value(node.key, node.value, getattr(node, "scope", None))


def visit_module_reference(node) -> str:
    return validate_yara_identifier(node.module, "module")


def visit_dictionary_access(generator, node) -> str:
    obj = generator.visit(node.object)
    if isinstance(node.key, str):
        return f'{obj}["{escape_string_literal(node.key)}"]'
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
    value = f'import "{escape_string_literal(node.module_path)}"'
    if node.rules:
        rules = [validate_yara_identifier(rule, "extern rule") for rule in node.rules]
        value += f" ({', '.join(rules)})"
    if node.alias:
        alias = validate_yara_identifier(node.alias, "import alias")
        value += f" as {alias}"
    return value


def visit_extern_namespace(node) -> str:
    namespace_name = validate_yara_identifier(node.name, "namespace")
    lines = [f"namespace {namespace_name}"]
    for rule in node.extern_rules:
        lines.append(_render_extern_rule(rule, default_namespace=namespace_name))
    return "\n".join(lines)


def visit_extern_rule(node) -> str:
    return _render_extern_rule(node)


def _render_extern_rule(node, default_namespace: str | None = None) -> str:
    modifiers = " ".join(str(m) for m in node.modifiers) if hasattr(node, "modifiers") else ""
    prefix = f"{modifiers} " if modifiers else ""
    namespace_name = getattr(node, "namespace", None) or default_namespace
    namespace = (
        f"{validate_yara_identifier_path(namespace_name, 'namespace')}." if namespace_name else ""
    )
    rule_name = validate_yara_identifier(node.name, "extern rule")
    return f"extern rule {prefix}{namespace}{rule_name}"


def visit_extern_rule_reference(node) -> str:
    if node.namespace:
        namespace = validate_yara_identifier_path(node.namespace, "namespace")
        rule_name = validate_yara_identifier(node.rule_name, "extern rule")
        return f"{namespace}.{rule_name}"
    return validate_yara_identifier(node.rule_name, "extern rule")


def visit_in_rule_pragma(node) -> str:
    return str(node.pragma)


def visit_pragma(node) -> str:
    return str(node)


def visit_pragma_block(generator, node) -> str:
    return "\n".join(generator.visit(pragma) for pragma in node.pragmas)
