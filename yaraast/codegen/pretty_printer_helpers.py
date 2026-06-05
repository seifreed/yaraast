"""Helpers for pretty printer formatting."""

from __future__ import annotations

from typing import Any

from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
)
from yaraast.codegen.generator_formatting import (
    format_yarax_local_identifier,
    validate_yara_identifier,
)
from yaraast.codegen.generator_helpers import (
    escape_plain_string_value,
    escape_regex_delimiter,
    format_hex_byte_value,
    format_hex_jump_bounds,
    format_hex_negated_value,
    format_hex_nibble_value,
    format_modifiers,
    format_regex_modifiers,
    output_string_identifier,
    plain_string_render_source,
    validate_hex_alternative_token,
    validate_hex_nibble_high,
    validate_hex_string_tokens,
    validate_plain_string_value,
    validate_string_identifiers,
)

_WORD_BINARY_OPERATORS = {
    "and",
    "contains",
    "endswith",
    "icontains",
    "iendswith",
    "iequals",
    "istartswith",
    "matches",
    "or",
    "startswith",
}


def build_hex_pattern(node: HexString, *, hex_uppercase: bool, hex_spacing: bool) -> str:
    validate_hex_string_tokens(node.tokens)
    hex_parts = [_format_hex_token(token, hex_uppercase, hex_spacing) for token in node.tokens]
    return " ".join(hex_parts) if hex_spacing else "".join(hex_parts)


def _format_hex_token(token: HexToken | int | str, hex_uppercase: bool, hex_spacing: bool) -> str:
    if isinstance(token, int | str):
        return _format_hex_byte_value(token, hex_uppercase)
    if isinstance(token, HexByte):
        return _format_hex_byte_value(token.value, hex_uppercase)
    if isinstance(token, HexWildcard):
        return "??"
    if isinstance(token, HexJump):
        return _format_hex_jump(token)
    if isinstance(token, HexNegatedByte):
        value = format_hex_negated_value(
            token.value,
            uppercase=hex_uppercase,
        )
        return f"~{value}"
    if isinstance(token, HexNibble):
        value = _format_hex_nibble_value(token.value, hex_uppercase)
        return f"{value}?" if validate_hex_nibble_high(token.high) else f"?{value}"
    if isinstance(token, HexAlternative):
        validate_hex_alternative_token(token)
        separator = " " if hex_spacing else ""
        alt_separator = " | " if hex_spacing else "|"
        alternatives = [
            separator.join(
                _format_hex_token(nested_token, hex_uppercase, hex_spacing)
                for nested_token in _coerce_hex_alternative_branch(alternative)
            )
            for alternative in token.alternatives
        ]
        return f"({alt_separator.join(alternatives)})"
    msg = f"Unsupported hex token '{type(token).__name__}' for libyara output"
    raise TypeError(msg)


def _format_hex_byte_value(value: int | str, hex_uppercase: bool) -> str:
    return format_hex_byte_value(value, uppercase=hex_uppercase)


def _format_hex_nibble_value(value: int | str, hex_uppercase: bool) -> str:
    return format_hex_nibble_value(value, uppercase=hex_uppercase)


def _format_hex_jump(token: HexJump) -> str:
    return format_hex_jump_bounds(token.min_jump, token.max_jump)


def _coerce_hex_alternative_branch(alternative: Any) -> list[HexToken | int | str]:
    if isinstance(alternative, list):
        return alternative
    return [HexByte(alternative)]


def format_plain_string(node: PlainString, quote: str, padding: int) -> str:
    source_value = plain_string_render_source(node)
    validate_plain_string_value(source_value)
    escaped_value = escape_plain_string_value(source_value)
    identifier = output_string_identifier(node)
    if padding > 0:
        return f"{identifier}{' ' * padding} = {quote}{escaped_value}{quote}"
    return f"{identifier} = {quote}{escaped_value}{quote}"


def format_regex_string(node: RegexString, padding: int) -> str:
    escaped = escape_regex_delimiter(node.regex)
    identifier = output_string_identifier(node)
    if padding > 0:
        return f"{identifier}{' ' * padding} = /{escaped}/"
    return f"{identifier} = /{escaped}/"


def modifiers_to_string(modifiers: list[Any] | tuple[Any, ...] | None) -> str:
    return format_modifiers(modifiers)


def regex_modifiers_to_string(modifiers: list[Any] | tuple[Any, ...] | None) -> str:
    if not modifiers:
        return ""
    return format_regex_modifiers(modifiers)


def current_indent(printer: Any) -> str:
    options = getattr(printer._layout, "options", None)
    indent_level = int(printer.indent_level)
    indent_size = int(printer.indent_size)
    if getattr(options, "indent_with_tabs", False):
        return "\t" * indent_level
    return " " * (indent_level * indent_size)


def indent_unit(printer: Any) -> str:
    options = getattr(printer._layout, "options", None)
    indent_size = int(printer.indent_size)
    if getattr(options, "indent_with_tabs", False):
        return "\t"
    return " " * indent_size


def calculate_string_alignment_column(ast: Any) -> int:
    """Calculate alignment column for string identifiers."""
    max_length = 0
    for rule in ast.rules:
        validate_string_identifiers(rule.strings)
        for string_def in rule.strings:
            max_length = max(max_length, len(output_string_identifier(string_def)))
    return max_length + 1


def calculate_meta_alignment_column(ast: Any, min_alignment_column: int) -> int:
    """Calculate alignment column for meta values."""
    from yaraast.codegen.generator_formatting import format_meta_key, validate_rule_meta

    max_length = 0
    for rule in ast.rules:
        validate_rule_meta(rule.meta)
        if rule.meta is None:
            continue
        for entry in rule.meta:
            if hasattr(entry, "key"):
                key = format_meta_key(entry.key, getattr(entry, "scope", None))
                max_length = max(max_length, len(f"{key} ="))
    return max(max_length + 2, min_alignment_column)


def expression_to_string(expr: Any, options: Any = None) -> str:
    """Render an expression with the comment-aware generator."""
    from yaraast.codegen.generator import CodeGenerator
    from yaraast.codegen.generator_expression_visitors import (
        _render_binary_operator,
        _visit_binary_operand,
        render_function_call_callee,
        require_present_expression,
        validate_binary_expression_operands,
        validate_expression_collection,
        validate_function_call_arguments,
        validate_set_expression_elements,
    )

    class PrettyExpressionGenerator(CodeGenerator):
        def __init__(self) -> None:
            super().__init__()
            self._allow_unknown_unqualified_functions = False

        def _comma_separator(self) -> str:
            return ", " if getattr(options, "space_after_comma", True) else ","

        def visit_binary_expression(self, node: Any) -> str:
            validate_binary_expression_operands(node)
            left = _visit_binary_operand(self, node, node.left, is_right=False)
            right = _visit_binary_operand(self, node, node.right, is_right=True)
            operator = _render_binary_operator(node.operator)
            if getattr(options, "space_around_operators", True):
                separator = " "
            else:
                separator = " " if operator in _WORD_BINARY_OPERATORS else ""
            return f"{left}{separator}{operator}{separator}{right}"

        def visit_set_expression(self, node: Any) -> str:
            validate_set_expression_elements(node)
            separator = self._comma_separator()
            return f"({separator.join(self.visit(elem) for elem in node.elements)})"

        def visit_function_call(self, node: Any) -> str:
            separator = self._comma_separator()
            callee = render_function_call_callee(self, node)
            validate_function_call_arguments(
                node,
                allow_unknown_unqualified=self._allow_unknown_unqualified_functions,
            )
            return f"{callee}({separator.join(self.visit(arg) for arg in node.arguments)})"

        def visit_with_statement(self, node: Any) -> str:
            separator = self._comma_separator()
            validate_expression_collection(node.declarations, "WithStatement declarations")
            previous = self._allow_unknown_unqualified_functions
            self._allow_unknown_unqualified_functions = True
            try:
                declarations = separator.join(
                    self.visit(declaration) for declaration in node.declarations
                )
                return f"with {declarations}: {self.visit(node.body)}"
            finally:
                self._allow_unknown_unqualified_functions = previous

        def visit_with_declaration(self, node: Any) -> str:
            identifier = format_yarax_local_identifier(node.identifier, "local variable")
            return f"{identifier} = {self.visit(node.value)}"

        def visit_array_comprehension(self, node: Any) -> str:
            expression = require_present_expression(
                node.expression, "ArrayComprehension expression"
            )
            iterable = require_present_expression(node.iterable, "ArrayComprehension iterable")
            variable = validate_yara_identifier(node.variable, "local variable")
            result = f"[{self.visit(expression)} for {variable} in {self.visit(iterable)}"
            if node.condition is not None:
                result += f" if {self.visit(node.condition)}"
            return result + "]"

        def visit_dict_comprehension(self, node: Any) -> str:
            separator = self._comma_separator()
            key_variable = validate_yara_identifier(node.key_variable, "local variable")
            variables = key_variable
            if node.value_variable is not None:
                value_variable = validate_yara_identifier(node.value_variable, "local variable")
                variables = separator.join([key_variable, value_variable])
            key_expression = require_present_expression(
                node.key_expression, "DictComprehension key_expression"
            )
            value_expression = require_present_expression(
                node.value_expression, "DictComprehension value_expression"
            )
            iterable = require_present_expression(node.iterable, "DictComprehension iterable")
            result = (
                f"{{{self.visit(key_expression)}: {self.visit(value_expression)} "
                f"for {variables} in {self.visit(iterable)}"
            )
            if node.condition is not None:
                result += f" if {self.visit(node.condition)}"
            return result + "}"

        def visit_tuple_expression(self, node: Any) -> str:
            validate_expression_collection(node.elements, "TupleExpression elements")
            if not node.elements:
                return "()"
            elements = [self.visit(element) for element in node.elements]
            if len(elements) == 1:
                return f"({elements[0]},)"
            separator = self._comma_separator()
            return f"({separator.join(elements)})"

        def visit_list_expression(self, node: Any) -> str:
            separator = self._comma_separator()
            validate_expression_collection(node.elements, "ListExpression elements")
            return f"[{separator.join(self.visit(element) for element in node.elements)}]"

        def visit_dict_expression(self, node: Any) -> str:
            from yaraast.yarax.ast_nodes import SpreadOperator

            separator = self._comma_separator()
            validate_expression_collection(node.items, "DictExpression items")
            items = [
                (
                    self.visit(item.value)
                    if isinstance(item.value, SpreadOperator)
                    else self.visit(item)
                )
                for item in node.items
            ]
            return f"{{{separator.join(items)}}}"

        def visit_lambda_expression(self, node: Any) -> str:
            validate_expression_collection(node.parameters, "LambdaExpression parameters")
            parameters = self._comma_separator().join(
                validate_yara_identifier(parameter, "local variable")
                for parameter in node.parameters
            )
            if parameters:
                return f"lambda {parameters}: {self.visit(node.body)}"
            return f"lambda: {self.visit(node.body)}"

    generator = PrettyExpressionGenerator()
    return generator.visit(expr).strip()
