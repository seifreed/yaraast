"""Leaf rendering helpers for CodeGenerator visitor methods."""

from __future__ import annotations

from typing import Any

from yaraast.ast.strings import HexByte
from yaraast.codegen.generator_formatting import (
    escape_string_literal,
    format_boolean_literal,
    format_hex_jump,
    format_import_alias,
    format_meta_value,
    format_nonempty_quoted_value,
    format_regex_literal,
    validate_optional_namespace,
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
    validate_hex_nibble_high,
    validate_no_embedded_nul,
    validate_no_unicode_surrogates,
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
    return f"{value_str}?" if validate_hex_nibble_high(node.high) else f"?{value_str}"


def visit_identifier(node: Any, contextual_locals: set[str] | frozenset[str] | None = None) -> str:
    return validate_yara_expression_identifier(node.name, contextual_locals=contextual_locals)


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
    if node.index is not None:
        _reject_string_occurrence_index(node.index, "String offset index")
        return f"@{suffix}[{generator.visit(node.index)}]"
    return f"@{suffix}"


def visit_string_length(generator: Any, node: Any) -> str:
    suffix = format_string_reference_suffix(
        node.string_id,
        allow_placeholder=getattr(generator, "_allow_string_placeholder", False),
    )
    if node.index is not None:
        _reject_string_occurrence_index(node.index, "String length index")
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


def _reject_non_integer_expression(value: Any, message: str) -> None:
    from yaraast.codegen.generator_expression_visitors import _is_definitely_non_integer_expression

    if _is_definitely_non_integer_expression(value):
        raise ValueError(message)


def _reject_string_occurrence_index(value: Any, field_name: str) -> None:
    from yaraast.codegen.generator_expression_visitors import _is_definitely_boolean_expression

    if _is_definitely_boolean_expression(value):
        msg = f"{field_name} must not be boolean for libyara output"
        raise ValueError(msg)


def _reject_non_string_dictionary_key(value: Any) -> None:
    from yaraast.ast.expressions import (
        BooleanLiteral,
        DoubleLiteral,
        IntegerLiteral,
        ParenthesesExpression,
        RegexLiteral,
        StringCount,
        StringIdentifier,
        StringLength,
        StringOffset,
        StringWildcard,
    )

    if isinstance(value, ParenthesesExpression):
        _reject_non_string_dictionary_key(value.expression)
        return
    from yaraast.codegen.generator_expression_visitors import _known_builtin_module_scalar_type_name

    known_type = _known_builtin_module_scalar_type_name(value)
    if known_type is not None and known_type != "string":
        msg = "Dictionary key must be string for libyara output"
        raise ValueError(msg)
    if isinstance(
        value,
        (
            bool,
            int,
            float,
            BooleanLiteral,
            DoubleLiteral,
            IntegerLiteral,
            RegexLiteral,
            StringCount,
            StringIdentifier,
            StringLength,
            StringOffset,
            StringWildcard,
        ),
    ):
        msg = "Dictionary key must be string for libyara output"
        raise ValueError(msg)


def visit_dictionary_access(generator: Any, node: Any) -> str:
    from yaraast.codegen.generator_expression_visitors import render_postfix_target

    if isinstance(node.key, str):
        key = f'"{escape_string_literal(node.key)}"'
    else:
        _reject_non_string_dictionary_key(node.key)
        key = generator.visit(node.key)
    _reject_module_root_dictionary_access(node)
    _reject_non_dictionary_module_expression(generator, node)
    obj = render_postfix_target(generator, node.object)
    return f"{obj}[{key}]"


def _reject_module_root_dictionary_access(node: Any) -> None:
    from yaraast.ast.modules import ModuleReference

    if not isinstance(node.object, ModuleReference):
        return
    msg = f"Module '{node.object.module}' cannot be indexed as a dictionary for libyara output"
    raise ValueError(msg)


def _reject_non_dictionary_module_expression(generator: Any, node: Any) -> None:
    from yaraast.codegen.generator_expression_visitors import known_builtin_module_expression_type
    from yaraast.types._registry_collections import DictionaryType

    object_type = known_builtin_module_expression_type(node.object)
    if object_type is None or isinstance(object_type, DictionaryType):
        return
    msg = (
        f"Module expression '{generator.visit(node.object)}' cannot be indexed as a dictionary "
        "for libyara output"
    )
    raise ValueError(msg)


def visit_defined_expression(generator: Any, node: Any) -> str:
    return f"defined {generator.visit(node.expression)}"


def visit_string_operator_expression(generator: Any, node: Any) -> str:
    operator = _render_string_operator(node.operator)
    _validate_string_operator_operands(node)
    return f"{generator.visit(node.left)} {operator} {generator.visit(node.right)}"


def _render_string_operator(operator: str) -> str:
    if operator in _STRING_OPERATORS:
        return operator
    msg = f"Invalid string operator '{operator}' for libyara output"
    raise ValueError(msg)


def _validate_string_operator_operands(node: Any) -> None:
    from yaraast.codegen.generator_expression_visitors import (
        _reject_invalid_string_binary_operands,
    )

    _reject_invalid_string_binary_operands(node)


def visit_comment(node: Any) -> str:
    text = _require_comment_text(node.text)
    _require_comment_multiline_flag(getattr(node, "is_multiline", False))
    if text.startswith("/*") and text.endswith("*/"):
        body = text[2:-2]
        if "*/" in body:
            msg = "Block comment text must not contain embedded terminators for libyara output"
            raise ValueError(msg)
        return text
    text = _format_line_comment_text(text)
    if text.startswith("//"):
        return f"// {text[2:].strip()}"
    return f"// {text}"


def visit_comment_group(node: Any) -> str:
    comments = _require_comment_group_comments(node.comments)
    return "\n".join(visit_comment(comment) for comment in comments)


def _require_comment_group_comments(value: object) -> list[Any] | tuple[Any, ...]:
    if isinstance(value, list | tuple):
        if not all(hasattr(comment, "text") for comment in value):
            msg = "CommentGroup comments must contain Comment nodes for libyara output"
            raise TypeError(msg)
        return value
    msg = "CommentGroup comments must be a list for libyara output"
    raise TypeError(msg)


def _require_comment_multiline_flag(value: object) -> bool:
    if isinstance(value, bool):
        return value
    msg = "Comment is_multiline must be a boolean for libyara output"
    raise TypeError(msg)


def _require_comment_text(text: object) -> str:
    if not isinstance(text, str):
        msg = "Comment text must be a string for libyara output"
        raise TypeError(msg)
    validate_no_unicode_surrogates(text, "Comment text")
    validate_no_embedded_nul(text, "Comment text")
    return text


def _format_line_comment_text(text: str) -> str:
    if "\n" in text or "\r" in text:
        msg = "Comment text must not contain newlines for libyara output"
        raise ValueError(msg)
    return text


def visit_extern_import(node: Any) -> str:
    value = f'import "{format_nonempty_quoted_value(node.module_path, "Import module")}"'
    _validate_collection(node.rules, "ExternImport rules")
    if node.rules:
        rules = [validate_yara_identifier_path(rule, "extern rule") for rule in node.rules]
        value += f" ({', '.join(rules)})"
    value += format_import_alias(getattr(node, "alias", None))
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
    namespace_name = validate_optional_namespace(
        getattr(node, "namespace", None), default_namespace
    )
    namespace = f"{namespace_name}." if namespace_name else ""
    rule_name = validate_yara_identifier(node.name, "extern rule")
    return f"extern rule {prefix}{namespace}{rule_name}"


def visit_extern_rule_reference(node: Any) -> str:
    namespace = validate_optional_namespace(getattr(node, "namespace", None))
    if namespace is not None:
        rule_name = validate_yara_identifier(node.rule_name, "extern rule")
        return f"{namespace}.{rule_name}"
    return validate_yara_identifier(node.rule_name, "extern rule")


def visit_in_rule_pragma(node: Any) -> str:
    return visit_pragma(node.pragma)


def visit_pragma(node: Any) -> str:
    from yaraast.ast.pragmas import (
        ConditionalDirective,
        CustomPragma,
        DefineDirective,
        IncludeOncePragma,
        PragmaType,
        UndefDirective,
    )

    if isinstance(node, IncludeOncePragma):
        return "#include_once"
    if isinstance(node, DefineDirective):
        macro_name = validate_yara_identifier(node.macro_name, "pragma macro")
        if node.macro_value is None:
            return f"#define {macro_name}"
        return f"#define {macro_name} {_validate_pragma_token(node.macro_value, 'Pragma value')}"
    if isinstance(node, UndefDirective):
        macro_name = validate_yara_identifier(node.macro_name, "pragma macro")
        return f"#undef {macro_name}"
    if isinstance(node, ConditionalDirective):
        directive = validate_yara_identifier(node.pragma_type.value, "pragma")
        if node.condition is None:
            return f"#{directive}"
        condition = validate_yara_identifier(node.condition, "pragma condition")
        return f"#{directive} {condition}"

    if node.pragma_type == PragmaType.PRAGMA or isinstance(node, CustomPragma):
        name = validate_yara_identifier(node.name, "pragma")
        arguments = _format_pragma_arguments(getattr(node, "arguments", []))
        return f"#pragma {name}{arguments}"

    name = validate_yara_identifier(node.name, "pragma")
    arguments = _format_pragma_arguments(getattr(node, "arguments", []))
    return f"#{name}{arguments}"


def _format_pragma_arguments(arguments: Any) -> str:
    if not isinstance(arguments, list | tuple):
        msg = "Pragma arguments must be a list or tuple for libyara output"
        raise TypeError(msg)
    if not arguments:
        return ""
    return " " + " ".join(
        _validate_pragma_token(argument, "Pragma argument") for argument in arguments
    )


def _validate_pragma_token(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        msg = f"{field_name} must be a string for libyara output"
        raise TypeError(msg)
    if not value:
        msg = f"{field_name} must not be empty for libyara output"
        raise ValueError(msg)
    if '"' in value or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        msg = f"{field_name} must not contain quotes or control characters for libyara output"
        raise ValueError(msg)
    return value


def visit_pragma_block(generator: Any, node: Any) -> str:
    _validate_collection(node.pragmas, "PragmaBlock pragmas")
    return "\n".join(generator.visit(pragma) for pragma in node.pragmas)


def _validate_collection(value: Any, field_name: str) -> None:
    if isinstance(value, list | tuple):
        return
    msg = f"{field_name} must be a list or tuple for libyara output"
    raise TypeError(msg)
