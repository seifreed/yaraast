"""Layout helpers for AdvancedCodeGenerator."""

from __future__ import annotations

from yaraast.codegen.formatting import BraceStyle, IndentStyle, StringStyle
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.generator_expression_visitors import (
    _render_binary_operator,
    _visit_binary_operand,
)
from yaraast.codegen.generator_formatting import format_rule_tags, validate_rule_identifiers


def _emit_top_level_line(generator, node) -> None:
    rendered = generator.visit(node)
    if rendered:
        generator._write(rendered)
    generator._writeline()


def _emit_top_level_section(generator, nodes) -> None:
    if not nodes:
        return
    for node in nodes:
        _emit_top_level_line(generator, node)
    generator._write_blank_lines(generator.config.blank_lines_between_sections)


def visit_yara_file(generator, node) -> str:
    validate_rule_identifiers(node.rules)
    _emit_top_level_section(generator, node.pragmas)

    imports = (
        sorted(node.imports, key=lambda item: item.module)
        if generator.config.sort_imports
        else node.imports
    )
    _emit_top_level_section(generator, imports)
    _emit_top_level_section(generator, node.extern_imports)
    _emit_top_level_section(generator, node.includes)
    _emit_top_level_section(generator, node.namespaces)
    _emit_top_level_section(generator, node.extern_rules)

    rules = node.rules
    if generator.config.sort_rules:
        rules = sorted(rules, key=lambda item: item.name)
    elif generator.config.sort_meta:

        def sort_key(rule):
            has_meta = bool(rule.meta and (bool(rule.meta)))
            return (not has_meta, rule.name)

        rules = sorted(rules, key=sort_key)

    for index, rule in enumerate(rules):
        if index > 0:
            generator._write_blank_lines(generator.config.blank_lines_between_rules)
        generator.visit(rule)
    return generator.buffer.getvalue()


def visit_rule(generator, node) -> str:
    if node.modifiers:
        generator._write(" ".join(str(m) for m in node.modifiers) + " ")
    generator._write(f"rule {node.name}")

    if node.tags:
        if generator.config.space_before_colon:
            generator._write(" ")
        generator._write(":")
        if generator.config.space_after_colon:
            generator._write(" ")
        generator._write(format_rule_tags(node.tags))

    if generator.config.brace_style == BraceStyle.SAME_LINE:
        generator._write(" {")
        generator._writeline()
    else:
        generator._writeline()
        generator._writeline("{")

    generator._indent()
    sections_written = 0
    for section in generator.config.section_order:
        if section == "meta" and node.meta:
            if sections_written > 0:
                generator._write_blank_lines(generator.config.blank_lines_between_sections)
            generator._write_meta_section(node.meta)
            sections_written += 1
        elif section == "strings" and node.strings:
            if sections_written > 0:
                generator._write_blank_lines(generator.config.blank_lines_between_sections)
            _write_in_rule_pragmas(generator, node, "before_strings")
            generator._write_strings_section(node.strings)
            _write_in_rule_pragmas(generator, node, "after_strings")
            sections_written += 1
        elif section == "condition" and node.condition is not None:
            if sections_written > 0:
                generator._write_blank_lines(generator.config.blank_lines_between_sections)
            if not node.strings:
                _write_in_rule_pragmas(generator, node, "before_strings")
            _write_in_rule_pragmas(generator, node, "before_condition")
            generator._write_condition_section(node.condition)
            sections_written += 1

    generator._dedent()
    generator._write("}")
    return generator.buffer.getvalue()


def write_strings_section(generator, strings) -> None:
    generator._writeline("strings:")
    generator._indent()
    if generator.config.sort_strings:
        strings = sorted(strings, key=lambda item: item.identifier)

    if generator.config.string_style in (StringStyle.ALIGNED, StringStyle.TABULAR):
        generator._collect_string_definitions(strings)
        write_aligned_strings(generator)
    else:
        for string_def in strings:
            generator.visit(string_def)
            generator._writeline()
    generator._dedent()


def write_aligned_strings(generator) -> None:
    if not generator._string_definitions:
        return
    max_id_len = max(len(identifier) for identifier, _, _ in generator._string_definitions)
    max_val_len = max(len(value) for _, value, _ in generator._string_definitions)
    for identifier, value, modifiers in generator._string_definitions:
        generator._write(generator._get_indent())
        if generator.config.string_style == StringStyle.TABULAR:
            generator._write(identifier.ljust(max_id_len))
            generator._write(" = ")
            generator._write(value.ljust(max_val_len))
        else:
            generator._write(f"{identifier} = {value}")
        if modifiers:
            generator._write("  " if generator.config.align_string_modifiers else " ")
            generator._write(" ".join(modifiers))
        generator._writeline()


def write_condition_section(generator, condition) -> None:
    generator._writeline("condition:")
    generator._indent()
    condition_str = generate_condition_string(condition, generator.config)
    if "\n" in condition_str:
        for line in condition_str.splitlines():
            generator._writeline(line)
    else:
        generator._writeline(condition_str)
    generator._dedent()


def _write_in_rule_pragmas(generator, node, position: str) -> None:
    for pragma in getattr(node, "pragmas", []):
        if pragma.position == position:
            generator._writeline(generator.visit(pragma))


class _AdvancedConditionGenerator(CodeGenerator):
    def __init__(self, config) -> None:
        super().__init__(getattr(config, "indent_size", 4))
        self.config = config

    def _nested_indent(self) -> str:
        if self.config.indent_style == IndentStyle.TABS:
            return "\t"
        return " " * self.config.indent_size

    def _comma_separator(self) -> str:
        return ", " if self.config.space_after_comma else ","

    def visit_binary_expression(self, node) -> str:
        left = _visit_binary_operand(self, node, node.left, is_right=False)
        right = _visit_binary_operand(self, node, node.right, is_right=True)
        operator = _render_binary_operator(node.operator)
        separator = " " if self.config.space_around_operators or operator.isalpha() else ""
        return f"{left}{separator}{operator}{separator}{right}"

    def visit_set_expression(self, node) -> str:
        separator = self._comma_separator()
        return f"({separator.join(self.visit(elem) for elem in node.elements)})"

    def visit_function_call(self, node) -> str:
        separator = self._comma_separator()
        return f"{node.function}({separator.join(self.visit(arg) for arg in node.arguments)})"

    def visit_with_statement(self, node) -> str:
        separator = self._comma_separator()
        declarations = separator.join(self.visit(declaration) for declaration in node.declarations)
        return f"with {declarations}: {self.visit(node.body)}"

    def visit_with_declaration(self, node) -> str:
        return f"{node.identifier} = {self.visit(node.value)}"

    def visit_array_comprehension(self, node) -> str:
        result = (
            f"[{self.visit(node.expression)} for {node.variable} " f"in {self.visit(node.iterable)}"
        )
        if node.condition:
            result += f" if {self.visit(node.condition)}"
        return f"{result}]"

    def visit_dict_comprehension(self, node) -> str:
        variables = node.key_variable
        if node.value_variable:
            variables = f"{variables}, {node.value_variable}"
        result = (
            f"{{{self.visit(node.key_expression)}: {self.visit(node.value_expression)} "
            f"for {variables} in {self.visit(node.iterable)}"
        )
        if node.condition:
            result += f" if {self.visit(node.condition)}"
        return f"{result}}}"

    def visit_tuple_expression(self, node) -> str:
        if not node.elements:
            return "()"
        elements = [self.visit(element) for element in node.elements]
        if len(elements) == 1:
            return f"({elements[0]},)"
        return f"({self._comma_separator().join(elements)})"

    def visit_tuple_indexing(self, node) -> str:
        from yaraast.ast.expressions import FunctionCall, Identifier
        from yaraast.yarax.ast_nodes import TupleExpression

        tuple_str = self.visit(node.tuple_expr)
        index_str = self.visit(node.index)
        if isinstance(node.tuple_expr, FunctionCall | Identifier | TupleExpression):
            return f"{tuple_str}[{index_str}]"
        return f"({tuple_str})[{index_str}]"

    def visit_list_expression(self, node) -> str:
        separator = self._comma_separator()
        return f"[{separator.join(self.visit(element) for element in node.elements)}]"

    def visit_dict_expression(self, node) -> str:
        from yaraast.yarax.ast_nodes import SpreadOperator

        items = []
        for item in node.items:
            if isinstance(item.value, SpreadOperator):
                items.append(self.visit(item.value))
            else:
                items.append(self.visit(item))
        return f"{{{self._comma_separator().join(items)}}}"

    def visit_dict_item(self, node) -> str:
        return f"{self.visit(node.key)}: {self.visit(node.value)}"

    def visit_slice_expression(self, node) -> str:
        parts = [
            self.visit(node.start) if node.start is not None else "",
            self.visit(node.stop) if node.stop is not None else "",
        ]
        if node.step is not None:
            parts.append(self.visit(node.step))
        return f"{self.visit(node.target)}[{':'.join(parts)}]"

    def visit_lambda_expression(self, node) -> str:
        parameters = ", ".join(node.parameters)
        if parameters:
            return f"lambda {parameters}: {self.visit(node.body)}"
        return f"lambda: {self.visit(node.body)}"

    def visit_pattern_match(self, node) -> str:
        lines = [f"match {self.visit(node.value)} {{"]
        nested_indent = self._nested_indent()
        lines.extend(f"{nested_indent}{self.visit(case)}," for case in node.cases)
        if node.default:
            lines.append(f"{nested_indent}_ => {self.visit(node.default)},")
        lines.append("}")
        return "\n".join(lines)

    def visit_match_case(self, node) -> str:
        return f"{self.visit(node.pattern)} => {self.visit(node.result)}"

    def visit_spread_operator(self, node) -> str:
        prefix = "**" if node.is_dict else "..."
        return f"{prefix}{self.visit(node.expression)}"


def generate_condition_string(expr, config=None) -> str:
    temp_gen = _AdvancedConditionGenerator(config) if config is not None else CodeGenerator()
    return temp_gen.visit(expr)
