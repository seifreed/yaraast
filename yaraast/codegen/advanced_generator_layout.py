"""Layout helpers for AdvancedCodeGenerator."""

from __future__ import annotations

from typing import Any

from yaraast.codegen.formatting import BraceStyle, FormattingConfig, IndentStyle, StringStyle
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.generator_expression_visitors import (
    _render_binary_operator,
    _visit_binary_operand,
    render_function_call_callee,
    require_present_expression,
    validate_expression_collection,
    validate_function_call_arguments,
    validate_set_expression_elements,
)
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


def _emit_top_level_line(generator: Any, node: Any) -> None:
    rendered = generator.visit(node)
    if rendered:
        generator._write(rendered)
    generator._writeline()


def _emit_top_level_section(generator: Any, nodes: list[Any] | tuple[Any, ...]) -> None:
    if not nodes:
        return
    for node in nodes:
        _emit_top_level_line(generator, node)
    generator._write_blank_lines(generator._layout.config.blank_lines_between_sections)


def visit_yara_file(generator: Any, node: Any) -> str:
    validate_yara_file_collections(node)
    validate_rule_identifiers(node.rules)
    validate_extern_rule_identifiers(node.rules, node.extern_rules, node.namespaces)
    _emit_top_level_section(generator, node.pragmas)

    imports = (
        sorted(node.imports, key=lambda item: item.module)
        if generator._layout.config.sort_imports
        else node.imports
    )
    _emit_top_level_section(generator, imports)
    _emit_top_level_section(generator, node.extern_imports)
    _emit_top_level_section(generator, node.includes)
    _emit_top_level_section(generator, node.namespaces)
    _emit_top_level_section(generator, node.extern_rules)

    rules = node.rules
    if generator._layout.config.sort_rules:
        rules = sorted(rules, key=lambda item: item.name)
    elif generator._layout.config.sort_meta:

        def sort_key(rule: Any) -> tuple[bool, Any]:
            has_meta = bool(rule.meta and (bool(rule.meta)))
            return (not has_meta, rule.name)

        rules = sorted(rules, key=sort_key)

    for index, rule in enumerate(rules):
        if index > 0:
            generator._write_blank_lines(generator._layout.config.blank_lines_between_rules)
        generator.visit(rule)
    return str(generator.buffer.getvalue())


def visit_rule(generator: Any, node: Any) -> str:
    validate_rule_collections(node)
    validate_rule_meta(node.meta)
    validate_string_identifiers(node.strings)
    modifiers = format_rule_modifiers(node.modifiers)
    if modifiers:
        generator._write(f"{modifiers} ")
    rule_name = validate_yara_identifier(node.name, "rule")
    generator._write(f"rule {rule_name}")

    if node.tags:
        if generator._layout.config.space_before_colon:
            generator._write(" ")
        generator._write(":")
        if generator._layout.config.space_after_colon:
            generator._write(" ")
        generator._write(format_rule_tags(node.tags))

    if generator._layout.config.brace_style == BraceStyle.SAME_LINE:
        generator._write(" {")
        generator._writeline()
    else:
        generator._writeline()
        generator._writeline("{")

    generator._indent()
    sections_written = 0
    for section in generator._layout.config.section_order:
        if section == "meta" and node.meta:
            if sections_written > 0:
                generator._write_blank_lines(generator._layout.config.blank_lines_between_sections)
            generator._write_meta_section(node.meta)
            sections_written += 1
        elif section == "strings" and node.strings:
            if sections_written > 0:
                generator._write_blank_lines(generator._layout.config.blank_lines_between_sections)
            _write_in_rule_pragmas(generator, node, "before_strings")
            generator._write_strings_section(node.strings)
            _write_in_rule_pragmas(generator, node, "after_strings")
            sections_written += 1
        elif section == "condition" and node.condition is not None:
            if sections_written > 0:
                generator._write_blank_lines(generator._layout.config.blank_lines_between_sections)
            if not node.strings:
                _write_in_rule_pragmas(generator, node, "before_strings")
            _write_in_rule_pragmas(generator, node, "before_condition")
            generator._write_condition_section(node.condition)
            sections_written += 1

    generator._dedent()
    generator._write("}")
    return str(generator.buffer.getvalue())


def write_strings_section(generator: Any, strings: list[Any]) -> None:
    validate_string_identifiers(strings)
    generator._writeline("strings:")
    generator._indent()
    if generator._layout.config.sort_strings:
        strings = sorted(strings, key=lambda item: item.identifier)

    if generator._layout.config.string_style in (StringStyle.ALIGNED, StringStyle.TABULAR):
        generator._layout.collect_string_definitions(strings)
        write_aligned_strings(generator)
    else:
        for string_def in strings:
            generator.visit(string_def)
            generator._writeline()
    generator._dedent()


def write_aligned_strings(generator: Any) -> None:
    if not generator._layout._string_definitions:
        return
    max_id_len = max(len(identifier) for identifier, _, _ in generator._layout._string_definitions)
    max_val_len = max(len(value) for _, value, _ in generator._layout._string_definitions)
    for identifier, value, modifiers in generator._layout._string_definitions:
        generator._write(generator._get_indent())
        if generator._layout.config.string_style == StringStyle.TABULAR:
            generator._write(identifier.ljust(max_id_len))
            generator._write(" = ")
            generator._write(value.ljust(max_val_len))
        else:
            generator._write(f"{identifier} = {value}")
        if modifiers:
            generator._write("  " if generator._layout.config.align_string_modifiers else " ")
            generator._write(" ".join(modifiers))
        generator._writeline()


def write_condition_section(generator: Any, condition: Any) -> None:
    generator._writeline("condition:")
    generator._indent()
    condition_str = generate_condition_string(condition, generator._layout.config)
    write_wrapped_condition(generator, condition_str)
    generator._dedent()


def write_wrapped_condition(generator: Any, condition: str) -> None:
    if "\n" in condition:
        for line in condition.splitlines():
            generator._writeline(line)
        return

    base_limit = max(1, generator._layout.config.max_line_length - len(generator._get_indent()))
    if len(condition) <= base_limit:
        generator._writeline(condition)
        return

    continuation_indent = (
        "\t"
        if generator._layout.config.indent_style == IndentStyle.TABS
        else " " * generator._layout.config.indent_size
    )
    current_line = ""
    for word in condition.split():
        candidate = f"{current_line} {word}" if current_line else word
        if len(candidate) > base_limit and current_line:
            generator._writeline(current_line)
            current_line = f"{continuation_indent}{word}"
        else:
            current_line = candidate

    if current_line:
        generator._writeline(current_line)


def _write_in_rule_pragmas(generator: Any, node: Any, position: str) -> None:
    for pragma in getattr(node, "pragmas", []):
        if pragma.position == position:
            generator._writeline(generator.visit(pragma))


class _AdvancedConditionGenerator(CodeGenerator):
    def __init__(self, config: FormattingConfig) -> None:
        super().__init__(getattr(config, "indent_size", 4))
        self.config = config

    def _nested_indent(self) -> str:
        if self.config.indent_style == IndentStyle.TABS:
            return "\t"
        return " " * self.config.indent_size

    def _comma_separator(self) -> str:
        return ", " if self.config.space_after_comma else ","

    def visit_binary_expression(self, node: Any) -> str:
        left = _visit_binary_operand(self, node, node.left, is_right=False)
        right = _visit_binary_operand(self, node, node.right, is_right=True)
        operator = _render_binary_operator(node.operator)
        separator = " " if self.config.space_around_operators or operator.isalpha() else ""
        return f"{left}{separator}{operator}{separator}{right}"

    def visit_set_expression(self, node: Any) -> str:
        validate_set_expression_elements(node)
        separator = self._comma_separator()
        return f"({separator.join(self.visit(elem) for elem in node.elements)})"

    def visit_function_call(self, node: Any) -> str:
        separator = self._comma_separator()
        callee = render_function_call_callee(self, node)
        validate_function_call_arguments(node)
        return f"{callee}({separator.join(self.visit(arg) for arg in node.arguments)})"

    def visit_with_statement(self, node: Any) -> str:
        separator = self._comma_separator()
        validate_expression_collection(node.declarations, "WithStatement declarations")
        declarations = separator.join(self.visit(declaration) for declaration in node.declarations)
        return f"with {declarations}: {self.visit(node.body)}"

    def visit_with_declaration(self, node: Any) -> str:
        return f"{node.identifier} = {self.visit(node.value)}"

    def visit_array_comprehension(self, node: Any) -> str:
        expression = require_present_expression(node.expression, "ArrayComprehension expression")
        iterable = require_present_expression(node.iterable, "ArrayComprehension iterable")
        result = f"[{self.visit(expression)} for {node.variable} " f"in {self.visit(iterable)}"
        if node.condition is not None:
            result += f" if {self.visit(node.condition)}"
        return f"{result}]"

    def visit_dict_comprehension(self, node: Any) -> str:
        key_expression = require_present_expression(
            node.key_expression, "DictComprehension key_expression"
        )
        value_expression = require_present_expression(
            node.value_expression, "DictComprehension value_expression"
        )
        iterable = require_present_expression(node.iterable, "DictComprehension iterable")
        variables = node.key_variable
        if node.value_variable:
            variables = f"{variables}, {node.value_variable}"
        result = (
            f"{{{self.visit(key_expression)}: {self.visit(value_expression)} "
            f"for {variables} in {self.visit(iterable)}"
        )
        if node.condition is not None:
            result += f" if {self.visit(node.condition)}"
        return f"{result}}}"

    def visit_tuple_expression(self, node: Any) -> str:
        validate_expression_collection(node.elements, "TupleExpression elements")
        if not node.elements:
            return "()"
        elements = [self.visit(element) for element in node.elements]
        if len(elements) == 1:
            return f"({elements[0]},)"
        return f"({self._comma_separator().join(elements)})"

    def visit_tuple_indexing(self, node: Any) -> str:
        from yaraast.ast.expressions import FunctionCall, Identifier
        from yaraast.yarax.ast_nodes import TupleExpression

        tuple_str = self.visit(node.tuple_expr)
        index_str = self.visit(node.index)
        if isinstance(node.tuple_expr, FunctionCall | Identifier | TupleExpression):
            return f"{tuple_str}[{index_str}]"
        return f"({tuple_str})[{index_str}]"

    def visit_list_expression(self, node: Any) -> str:
        separator = self._comma_separator()
        validate_expression_collection(node.elements, "ListExpression elements")
        return f"[{separator.join(self.visit(element) for element in node.elements)}]"

    def visit_dict_expression(self, node: Any) -> str:
        from yaraast.yarax.ast_nodes import SpreadOperator

        validate_expression_collection(node.items, "DictExpression items")
        items: list[str] = []
        for item in node.items:
            if isinstance(item.value, SpreadOperator):
                items.append(self.visit(item.value))
            else:
                items.append(self.visit(item))
        return f"{{{self._comma_separator().join(items)}}}"

    def visit_dict_item(self, node: Any) -> str:
        return f"{self.visit(node.key)}: {self.visit(node.value)}"

    def visit_slice_expression(self, node: Any) -> str:
        parts = [
            self.visit(node.start) if node.start is not None else "",
            self.visit(node.stop) if node.stop is not None else "",
        ]
        if node.step is not None:
            parts.append(self.visit(node.step))
        return f"{self.visit(node.target)}[{':'.join(parts)}]"

    def visit_lambda_expression(self, node: Any) -> str:
        validate_expression_collection(node.parameters, "LambdaExpression parameters")
        parameters = ", ".join(node.parameters)
        if parameters:
            return f"lambda {parameters}: {self.visit(node.body)}"
        return f"lambda: {self.visit(node.body)}"

    def visit_pattern_match(self, node: Any) -> str:
        validate_expression_collection(node.cases, "PatternMatch cases")
        lines = [f"match {self.visit(node.value)} {{"]
        nested_indent = self._nested_indent()
        lines.extend(f"{nested_indent}{self.visit(case)}," for case in node.cases)
        if node.default is not None:
            default_str = self._indent_continuation_lines(self.visit(node.default))
            lines.append(f"{nested_indent}_ => {default_str},")
        lines.append("}")
        return "\n".join(lines)

    def visit_match_case(self, node: Any) -> str:
        result = self._indent_continuation_lines(self.visit(node.result))
        return f"{self.visit(node.pattern)} => {result}"

    def _indent_continuation_lines(self, text: str) -> str:
        return text.replace("\n", f"\n{self._nested_indent()}")

    def visit_spread_operator(self, node: Any) -> str:
        prefix = "**" if node.is_dict else "..."
        return f"{prefix}{self.visit(node.expression)}"


def generate_condition_string(expr: Any, config: FormattingConfig | None = None) -> str:
    temp_gen = _AdvancedConditionGenerator(config) if config is not None else CodeGenerator()
    return temp_gen.visit(expr)
