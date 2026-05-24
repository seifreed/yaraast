"""Helpers for pretty printer formatting."""

from __future__ import annotations

from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexString,
    HexWildcard,
    PlainString,
    RegexString,
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
    validate_hex_alternative_token,
    validate_hex_string_tokens,
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


def _format_hex_token(token, hex_uppercase: bool, hex_spacing: bool) -> str:
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
        return f"{value}?" if token.high else f"?{value}"
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
    return "??"


def _format_hex_byte_value(value: int | str, hex_uppercase: bool) -> str:
    return format_hex_byte_value(value, uppercase=hex_uppercase)


def _format_hex_nibble_value(value: int | str, hex_uppercase: bool) -> str:
    return format_hex_nibble_value(value, uppercase=hex_uppercase)


def _format_hex_jump(token: HexJump) -> str:
    return format_hex_jump_bounds(token.min_jump, token.max_jump)


def _coerce_hex_alternative_branch(alternative) -> list:
    if isinstance(alternative, list):
        return alternative
    return [HexByte(alternative)]


def format_plain_string(node: PlainString, quote: str, padding: int) -> str:
    escaped_value = escape_plain_string_value(node.value)
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


def modifiers_to_string(modifiers) -> str:
    return format_modifiers(modifiers)


def regex_modifiers_to_string(modifiers) -> str:
    if not modifiers:
        return ""
    return format_regex_modifiers(modifiers)


def current_indent(printer) -> str:
    options = getattr(printer, "options", None)
    if getattr(options, "indent_with_tabs", False):
        return "\t" * printer.indent_level
    return " " * (printer.indent_level * printer.indent_size)


def indent_unit(printer) -> str:
    options = getattr(printer, "options", None)
    if getattr(options, "indent_with_tabs", False):
        return "\t"
    return " " * printer.indent_size


def calculate_string_alignment_column(ast) -> int:
    """Calculate alignment column for string identifiers."""
    max_length = 0
    for rule in ast.rules:
        for string_def in rule.strings:
            max_length = max(max_length, len(output_string_identifier(string_def)))
    return max_length + 1


def calculate_meta_alignment_column(ast, min_alignment_column: int) -> int:
    """Calculate alignment column for meta values."""
    from yaraast.codegen.generator_formatting import format_meta_key

    max_length = 0
    for rule in ast.rules:
        for entry in rule.meta:
            if hasattr(entry, "key"):
                key = format_meta_key(entry.key, getattr(entry, "scope", None))
                max_length = max(max_length, len(f"{key} ="))
    return max(max_length + 2, min_alignment_column)


def expression_to_string(expr, options=None) -> str:
    """Render an expression with the comment-aware generator."""
    from yaraast.codegen.comment_aware_generator import CommentAwareCodeGenerator
    from yaraast.codegen.generator_expression_visitors import (
        _render_binary_operator,
        _visit_binary_operand,
        validate_set_expression_elements,
    )
    from yaraast.codegen.generator_formatting import validate_yara_identifier_path

    class PrettyExpressionGenerator(CommentAwareCodeGenerator):
        def _comma_separator(self) -> str:
            return ", " if getattr(options, "space_after_comma", True) else ","

        def visit_binary_expression(self, node) -> str:
            left = _visit_binary_operand(self, node, node.left, is_right=False)
            right = _visit_binary_operand(self, node, node.right, is_right=True)
            operator = _render_binary_operator(node.operator)
            if getattr(options, "space_around_operators", True):
                separator = " "
            else:
                separator = " " if operator in _WORD_BINARY_OPERATORS else ""
            return f"{left}{separator}{operator}{separator}{right}"

        def visit_set_expression(self, node) -> str:
            validate_set_expression_elements(node)
            separator = self._comma_separator()
            return f"({separator.join(self.visit(elem) for elem in node.elements)})"

        def visit_function_call(self, node) -> str:
            separator = self._comma_separator()
            function = validate_yara_identifier_path(node.function, "function")
            return f"{function}({separator.join(self.visit(arg) for arg in node.arguments)})"

        def visit_with_statement(self, node) -> str:
            separator = self._comma_separator()
            declarations = separator.join(
                self.visit(declaration) for declaration in node.declarations
            )
            return f"with {declarations}: {self.visit(node.body)}"

        def visit_dict_comprehension(self, node) -> str:
            separator = self._comma_separator()
            variables = (
                separator.join([node.key_variable, node.value_variable])
                if node.value_variable
                else node.key_variable
            )
            result = (
                f"{{{self.visit(node.key_expression)}: {self.visit(node.value_expression)} "
                f"for {variables} in {self.visit(node.iterable)}"
            )
            if node.condition:
                result += f" if {self.visit(node.condition)}"
            return result + "}"

        def visit_tuple_expression(self, node) -> str:
            if not node.elements:
                return "()"
            elements = [self.visit(element) for element in node.elements]
            if len(elements) == 1:
                return f"({elements[0]},)"
            separator = self._comma_separator()
            return f"({separator.join(elements)})"

        def visit_list_expression(self, node) -> str:
            separator = self._comma_separator()
            return f"[{separator.join(self.visit(element) for element in node.elements)}]"

        def visit_dict_expression(self, node) -> str:
            from yaraast.yarax.ast_nodes import SpreadOperator

            separator = self._comma_separator()
            items = [
                (
                    self.visit(item.value)
                    if isinstance(item.value, SpreadOperator)
                    else self.visit(item)
                )
                for item in node.items
            ]
            return f"{{{separator.join(items)}}}"

        def visit_lambda_expression(self, node) -> str:
            parameters = self._comma_separator().join(node.parameters)
            if parameters:
                return f"lambda {parameters}: {self.visit(node.body)}"
            return f"lambda: {self.visit(node.body)}"

    generator = PrettyExpressionGenerator()
    return generator.visit(expr).strip()
