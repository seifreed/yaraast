"""Leaf rendering helpers for CodeGenerator visitor methods."""

from __future__ import annotations

from typing import Any

from yaraast.ast.strings import HexByte
from yaraast.codegen.generator_formatting import (
    escape_string_literal,
    format_boolean_literal,
    format_hex_jump,
    format_meta_value,
    format_nonempty_quoted_value,
    format_regex_literal,
    validate_rule_modifiers,
    validate_yara_expression_identifier,
    validate_yara_identifier,
    validate_yara_identifier_path,
)
from yaraast.codegen.generator_helpers import (
    format_double_literal,
    format_hex_byte_value,
    format_hex_nibble_value,
    format_integer_literal,
    format_string_reference_suffix,
    validate_hex_alternative_token,
    validate_string_identifier_text,
    validate_string_wildcard_text,
)

_STRING_OPERATORS = frozenset(
    {
        "contains",
        "endswith",
        "icontains",
        "iendswith",
        "iequals",
        "istartswith",
        "matches",
        "startswith",
    }
)


def visit_hex_byte(node: Any) -> str:
    return format_hex_byte_value(node.value, uppercase=True)


def visit_hex_wildcard(node: Any) -> str:
    return "??"


def visit_hex_jump(node: Any) -> str:
    return format_hex_jump(node.min_jump, node.max_jump)


def visit_hex_alternative(generator: Any, node: Any) -> str:
    validate_hex_alternative_token(node)
    alts = []
    for alt in node.alternatives:
        tokens = alt if isinstance(alt, list) else [alt]
        alt_str = " ".join(generator.visit(_coerce_hex_token(token)) for token in tokens)
        alts.append(alt_str)
    return f"( {' | '.join(alts)} )"


def _coerce_hex_token(token: Any) -> Any:
    if isinstance(token, int | str):
        return HexByte(token)
    return token


def visit_hex_nibble(node: Any) -> str:
    value_str = format_hex_nibble_value(node.value, uppercase=True)
    return f"{value_str}?" if node.high else f"?{value_str}"


def visit_identifier(node: Any) -> str:
    return validate_yara_expression_identifier(node.name)


def visit_string_identifier(node: Any, *, allow_placeholder: bool = False) -> str:
    if allow_placeholder and node.name == "$":
        return "$"
    return validate_string_identifier_text(node.name)


def visit_string_wildcard(node: Any) -> str:
    return validate_string_wildcard_text(node.pattern)


def visit_string_count(node: Any, *, allow_placeholder: bool = False) -> str:
    return f"#{format_string_reference_suffix(node.string_id, allow_placeholder=allow_placeholder)}"


def visit_string_offset(generator: Any, node: Any) -> str:
    suffix = format_string_reference_suffix(
        node.string_id,
        allow_placeholder=getattr(generator, "_allow_string_placeholder", False),
    )
    if node.index:
        return f"@{suffix}[{generator.visit(node.index)}]"
    return f"@{suffix}"


def visit_string_length(generator: Any, node: Any) -> str:
    suffix = format_string_reference_suffix(
        node.string_id,
        allow_placeholder=getattr(generator, "_allow_string_placeholder", False),
    )
    if node.index:
        return f"!{suffix}[{generator.visit(node.index)}]"
    return f"!{suffix}"


def visit_integer_literal(node: Any) -> str:
    return format_integer_literal(node.value)


def visit_double_literal(node: Any) -> str:
    return format_double_literal(node.value)


def visit_string_literal(node: Any) -> str:
    return f'"{escape_string_literal(node.value)}"'


def visit_regex_literal(node: Any) -> str:
    return format_regex_literal(node.pattern, node.modifiers)


def visit_boolean_literal(node: Any) -> str:
    return format_boolean_literal(node.value)


def visit_meta(node: Any) -> str:
    return format_meta_value(node.key, node.value, getattr(node, "scope", None))


def visit_module_reference(node: Any) -> str:
    return validate_yara_identifier(node.module, "module")


def visit_dictionary_access(generator: Any, node: Any) -> str:
    obj = generator.visit(node.object)
    if isinstance(node.key, str):
        return f'{obj}["{escape_string_literal(node.key)}"]'
    return f"{obj}[{generator.visit(node.key)}]"


def visit_defined_expression(generator: Any, node: Any) -> str:
    return f"defined {generator.visit(node.expression)}"


def visit_string_operator_expression(generator: Any, node: Any) -> str:
    operator = _render_string_operator(node.operator)
    _validate_string_operator_operands(node, operator)
    return f"{generator.visit(node.left)} {operator} {generator.visit(node.right)}"


def _render_string_operator(operator: str) -> str:
    if operator in _STRING_OPERATORS:
        return operator
    msg = f"Invalid string operator '{operator}' for libyara output"
    raise ValueError(msg)


def _validate_string_operator_operands(node: Any, operator: str) -> None:
    if operator != "matches":
        return
    from yaraast.ast.expressions import RegexLiteral

    if isinstance(node.right, RegexLiteral):
        return
    msg = "String operator 'matches' requires a regex literal for libyara output"
    raise ValueError(msg)


def visit_comment(node: Any) -> str:
    return f"// {node.text}"


def visit_comment_group(node: Any) -> str:
    return "\n".join(f"// {c.text}" for c in node.comments)


def visit_extern_import(node: Any) -> str:
    value = f"import \"{format_nonempty_quoted_value(node.module_path, 'Import module')}\""
    _validate_collection(node.rules, "ExternImport rules")
    if node.rules:
        rules = [validate_yara_identifier_path(rule, "extern rule") for rule in node.rules]
        value += f" ({', '.join(rules)})"
    if node.alias:
        alias = validate_yara_identifier(node.alias, "import alias")
        value += f" as {alias}"
    return value


def visit_extern_namespace(node: Any) -> str:
    namespace_name = validate_yara_identifier(node.name, "namespace")
    lines = [f"namespace {namespace_name}"]
    _validate_collection(node.extern_rules, "ExternNamespace extern_rules")
    for rule in node.extern_rules:
        lines.append(_render_extern_rule(rule, default_namespace=namespace_name))
    return "\n".join(lines)


def visit_extern_rule(node: Any) -> str:
    return _render_extern_rule(node)


def _render_extern_rule(node: Any, default_namespace: str | None = None) -> str:
    modifiers_value = getattr(node, "modifiers", [])
    _validate_collection(modifiers_value, "ExternRule modifiers")
    validate_rule_modifiers(modifiers_value)
    modifiers = " ".join(str(m) for m in modifiers_value)
    prefix = f"{modifiers} " if modifiers else ""
    namespace_name = getattr(node, "namespace", None) or default_namespace
    namespace = (
        f"{validate_yara_identifier_path(namespace_name, 'namespace')}." if namespace_name else ""
    )
    rule_name = validate_yara_identifier(node.name, "extern rule")
    return f"extern rule {prefix}{namespace}{rule_name}"


def visit_extern_rule_reference(node: Any) -> str:
    if node.namespace:
        namespace = validate_yara_identifier_path(node.namespace, "namespace")
        rule_name = validate_yara_identifier(node.rule_name, "extern rule")
        return f"{namespace}.{rule_name}"
    return validate_yara_identifier(node.rule_name, "extern rule")


def visit_in_rule_pragma(node: Any) -> str:
    return str(node.pragma)


def visit_pragma(node: Any) -> str:
    return str(node)


def visit_pragma_block(generator: Any, node: Any) -> str:
    _validate_collection(node.pragmas, "PragmaBlock pragmas")
    return "\n".join(generator.visit(pragma) for pragma in node.pragmas)


def _validate_collection(value: Any, field_name: str) -> None:
    if isinstance(value, list | tuple):
        return
    msg = f"{field_name} must be a list or tuple for libyara output"
    raise TypeError(msg)
