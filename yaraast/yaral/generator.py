"""YARA-L code generator from AST."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from yaraast.codegen.generator_helpers import escape_regex_delimiter
from yaraast.yaral.ast_nodes import ArithmeticExpression
from yaraast.yaral.generator_helpers import (
    format_literal,
    format_modifiers,
    format_udm_path,
    quote_string_literal,
)
from yaraast.yaral.visitor_base import YaraLVisitor

if TYPE_CHECKING:
    from yaraast.yaral.ast_nodes import (
        AggregationFunction,
        BinaryCondition,
        ConditionalExpression,
        ConditionExpression,
        ConditionSection,
        EventAssignment,
        EventCountCondition,
        EventExistsCondition,
        EventsSection,
        EventStatement,
        EventVariable,
        MatchSection,
        MatchVariable,
        MetaEntry,
        MetaSection,
        OptionsSection,
        OutcomeAssignment,
        OutcomeExpression,
        OutcomeSection,
        ReferenceList,
        RegexPattern,
        TimeWindow,
        UDMFieldAccess,
        UDMFieldPath,
        UnaryCondition,
        YaraLFile,
        YaraLRule,
    )


class YaraLGenerator(YaraLVisitor[str]):
    """Generate YARA-L code from AST."""

    def __init__(self, indent_size: int = 2) -> None:
        """Initialize YARA-L generator.

        Args:
            indent_size: Number of spaces for indentation
        """
        self.indent_size = indent_size
        self.indent_level = 0

    def generate(self, ast: YaraLFile) -> str:
        """Generate YARA-L code from AST.

        Args:
            ast: YARA-L AST to generate code from

        Returns:
            Generated YARA-L code
        """
        self.indent_level = 0
        return self.visit(ast)

    def _indent(self) -> str:
        """Get current indentation string."""
        return " " * (self.indent_level * self.indent_size)

    def _increase_indent(self) -> None:
        """Increase indentation level."""
        self.indent_level += 1

    def _decrease_indent(self) -> None:
        """Decrease indentation level."""
        self.indent_level = max(0, self.indent_level - 1)

    def _format_value(self, value: Any) -> str:
        """Format a literal or AST value."""
        if hasattr(value, "accept"):
            return self.visit(value)
        return format_literal(value)

    def _format_udm_path(self, parts: list[str]) -> str:
        """Format UDM field parts into a valid path string."""
        return format_udm_path(parts)

    # File and Rule visitors
    def visit_yaral_file(self, node: YaraLFile) -> str:
        """Generate code for YARA-L file."""
        rules = []
        for rule in node.rules:
            rules.append(self.visit(rule))
        return "\n\n".join(rules)

    def visit_yaral_rule(self, node: YaraLRule) -> str:
        """Generate code for YARA-L rule."""
        parts = [f"rule {node.name} {{"]
        self._increase_indent()

        # Add meta section
        if node.meta:
            parts.append(self.visit(node.meta))

        # Add events section
        if node.events:
            parts.append(self.visit(node.events))

        # Add match section
        if node.match:
            parts.append(self.visit(node.match))

        # Add outcome section
        if node.outcome:
            parts.append(self.visit(node.outcome))

        # Add condition section
        if node.condition:
            parts.append(self.visit(node.condition))

        # Add options section
        if node.options:
            parts.append(self.visit(node.options))

        self._decrease_indent()
        parts.append("}")

        return "\n".join(filter(None, parts))

    # Section visitors
    def visit_meta_section(self, node: MetaSection) -> str:
        """Generate code for meta section."""
        if not node.entries:
            return ""

        lines = [f"{self._indent()}meta:"]
        self._increase_indent()

        for entry in node.entries:
            lines.append(self.visit(entry))

        self._decrease_indent()
        return "\n".join(lines)

    def visit_meta_entry(self, node: MetaEntry) -> str:
        """Generate code for meta entry."""
        value = node.value
        if isinstance(value, str):
            value = quote_string_literal(value)
        elif isinstance(value, bool):
            value = "true" if value else "false"

        return f"{self._indent()}{node.key} = {value}"

    def visit_events_section(self, node: EventsSection) -> str:
        """Generate code for events section."""
        if not node.statements:
            return ""

        lines = [f"{self._indent()}events:"]
        self._increase_indent()

        for statement in node.statements:
            lines.append(self.visit(statement))

        self._decrease_indent()
        return "\n".join(lines)

    def visit_event_statement(self, node: EventStatement) -> str:
        """Generate code for event statement."""
        if node.text:
            return f"{self._indent()}{node.text}"
        return ""

    def visit_event_variable(self, node: EventVariable) -> str:
        """Generate code for event variable."""
        return node.name

    def visit_event_assignment(self, node: EventAssignment) -> str:
        """Generate code for event assignment."""
        field = self.visit(node.field_path)
        operator = node.operator

        value = self._format_value(node.value)
        return f"{field} {operator} {value}{format_modifiers(node.modifiers)}"

    def visit_udm_field_path(self, node: UDMFieldPath) -> str:
        """Generate code for UDM field path."""
        return self._format_udm_path(node.parts)

    def visit_udm_field_access(self, node: UDMFieldAccess) -> str:
        """Generate code for UDM field access."""
        field = self.visit(node.field)
        if node.event is None:
            return field
        event = self.visit(node.event)
        return f"{event}.{field}"

    def visit_match_section(self, node: MatchSection) -> str:
        """Generate code for match section."""
        lines = [f"{self._indent()}match:"]
        self._increase_indent()

        for var in node.variables:
            lines.append(self.visit(var))

        self._decrease_indent()
        return "\n".join(lines)

    def visit_match_variable(self, node: MatchVariable) -> str:
        """Generate code for match variable."""
        variable = node.variable
        if not variable.startswith("$"):
            variable = f"${variable}"
        if node.grouping_field is not None:
            grouping = self.visit(node.grouping_field)
            return f"{self._indent()}{variable} = {grouping} over {self.visit(node.time_window)}"
        return f"{self._indent()}{variable} over {self.visit(node.time_window)}"

    def visit_time_window(self, node: TimeWindow) -> str:
        """Generate code for time window."""
        return node.as_string

    def visit_condition_section(self, node: ConditionSection) -> str:
        """Generate code for condition section."""
        lines = [f"{self._indent()}condition:"]
        self._increase_indent()

        expression = self.visit(node.expression) if node.expression is not None else ""
        lines.append(f"{self._indent()}{expression}")

        self._decrease_indent()
        return "\n".join(lines)

    def visit_condition_expression(self, node: ConditionExpression) -> str:
        """Generate code for condition expression."""
        # This is a base class, specific implementations below
        return ""

    def visit_binary_condition(self, node: BinaryCondition) -> str:
        """Generate code for binary condition."""
        left = self._format_value(node.left) if hasattr(node, "left") and node.left else ""
        right = self._format_value(node.right) if hasattr(node, "right") and node.right else ""
        operator = node.operator

        if operator in ["and", "or"]:
            return f"({left} {operator} {right})"
        return f"{left} {operator} {right}"

    def visit_unary_condition(self, node: UnaryCondition) -> str:
        """Generate code for unary condition."""
        operand = self.visit(node.operand) if hasattr(node, "operand") and node.operand else ""
        return f"{node.operator} {operand}"

    def visit_event_count_condition(self, node: EventCountCondition) -> str:
        """Generate code for event count condition."""
        return f"#{node.event} {node.operator} {node.count}"

    def visit_event_exists_condition(self, node: EventExistsCondition) -> str:
        """Generate code for event exists condition."""
        event = node.event
        if not event.startswith("$"):
            event = f"${event}"
        return event

    def visit_outcome_section(self, node: OutcomeSection) -> str:
        """Generate code for outcome section."""
        lines = [f"{self._indent()}outcome:"]
        self._increase_indent()

        for assignment in node.assignments:
            lines.append(self.visit(assignment))

        self._decrease_indent()
        return "\n".join(lines)

    def visit_outcome_assignment(self, node: OutcomeAssignment) -> str:
        """Generate code for outcome assignment."""
        return f"{self._indent()}{node.variable} = {self._format_condition_value(node.expression)}"

    def visit_outcome_expression(self, node: OutcomeExpression) -> str:
        """Generate code for outcome expression."""
        return ""

    def visit_conditional_expression(self, node: ConditionalExpression) -> str:
        """Generate code for conditional expression using YARA-L function syntax."""
        condition = self._format_condition_value(node.condition)
        true_value = self._format_value(node.true_value)
        if node.false_value is None:
            return f"if({condition}, {true_value})"
        false_value = self._format_value(node.false_value)
        return f"if({condition}, {true_value}, {false_value})"

    def _format_condition_value(self, value: Any) -> str:
        if hasattr(value, "accept"):
            return self.visit(value)
        if isinstance(value, str) and self._is_raw_condition_text(value):
            return value
        return self._format_value(value)

    def _is_raw_condition_text(self, value: str) -> bool:
        raw_markers = (
            "(",
            "=",
            "!=",
            "<",
            ">",
            " + ",
            " - ",
            " * ",
            " / ",
            " in ",
            " and ",
            " or ",
            " not ",
        )
        return value.startswith(("$", "%")) or any(marker in value for marker in raw_markers)

    def visit_aggregation_function(self, node: AggregationFunction) -> str:
        """Generate code for aggregation function."""
        args = [self._format_value(arg) for arg in node.arguments]
        return f"{node.function}({', '.join(args)})"

    def visit_reference_list(self, node: ReferenceList) -> str:
        """Generate code for reference list."""
        return f"%{node.name.strip('%')}%"

    def visit_regex_pattern(self, node: RegexPattern) -> str:
        """Generate code for regex pattern."""
        inline_flags = "".join(flag for flag in node.flags if len(flag) == 1)
        word_flags = [flag for flag in node.flags if len(flag) > 1]
        pattern = escape_regex_delimiter(node.pattern)
        rendered = f"/{pattern}/{inline_flags}"
        if word_flags:
            rendered = f"{rendered} {' '.join(word_flags)}"
        return rendered

    def visit_options_section(self, node: OptionsSection) -> str:
        """Generate code for options section."""
        lines = [f"{self._indent()}options:"]
        self._increase_indent()

        for key, value in node.options.items():
            lines.append(f"{self._indent()}{key} = {self._format_value(value)}")

        self._decrease_indent()
        return "\n".join(lines)

    def visit_variable_comparison_condition(self, node) -> str:
        variable = node.variable
        return f"{variable} {node.operator} {self._format_value(node.value)}"

    def visit_null_check_condition(self, node) -> str:
        operator = "is not null" if node.negated else "is null"
        field = self.visit(node.field) if hasattr(node.field, "accept") else str(node.field)
        return f"{field} {operator}"

    def visit_join_condition(self, node) -> str:
        return f"join {node.left_event} {node.join_type} {node.right_event}"

    def visit_arithmetic_expression(self, node) -> str:
        left = self._format_arithmetic_operand(node.left, node.operator, is_right=False)
        right = self._format_arithmetic_operand(node.right, node.operator, is_right=True)
        return f"{left} {node.operator} {right}"

    def _format_arithmetic_operand(
        self, operand: Any, parent_operator: str, *, is_right: bool
    ) -> str:
        rendered = self._format_condition_value(operand)
        if not isinstance(operand, ArithmeticExpression):
            return rendered
        if self._needs_arithmetic_parentheses(parent_operator, operand.operator, is_right):
            return f"({rendered})"
        return rendered

    def _needs_arithmetic_parentheses(
        self,
        parent_operator: str,
        child_operator: str,
        is_right: bool,
    ) -> bool:
        precedence = {"+": 1, "-": 1, "*": 2, "/": 2}
        parent_precedence = precedence[parent_operator]
        child_precedence = precedence[child_operator]
        if child_precedence < parent_precedence:
            return True
        return is_right and parent_operator in {"-", "/"} and child_precedence == parent_precedence

    def visit_cidr_expression(self, node) -> str:
        field = self.visit(node.field)
        return f"{field} in {node.cidr}"

    def visit_function_call(self, node) -> str:
        args = [self._format_value(arg) for arg in node.arguments]
        return f"{node.function}({', '.join(args)})"

    # YARA-L prefixed methods expected by AST nodes
    def visit_yaral_meta_section(self, node: MetaSection) -> str:
        return self.visit_meta_section(node)

    def visit_yaral_meta_entry(self, node: MetaEntry) -> str:
        return self.visit_meta_entry(node)

    def visit_yaral_events_section(self, node: EventsSection) -> str:
        return self.visit_events_section(node)

    def visit_yaral_event_statement(self, node: EventStatement) -> str:
        return self.visit_event_statement(node)

    def visit_yaral_event_assignment(self, node: EventAssignment) -> str:
        event = self.visit(node.event_var)
        field = self.visit(node.field_path)
        operator = node.operator
        value = self._format_value(node.value)
        return (
            f"{self._indent()}{event}.{field} {operator} {value}{format_modifiers(node.modifiers)}"
        )

    def visit_yaral_event_variable(self, node: EventVariable) -> str:
        return self.visit_event_variable(node)

    def visit_yaral_udm_field_path(self, node: UDMFieldPath) -> str:
        return self.visit_udm_field_path(node)

    def visit_yaral_udm_field_access(self, node: UDMFieldAccess) -> str:
        return self.visit_udm_field_access(node)

    def visit_yaral_reference_list(self, node: ReferenceList) -> str:
        return self.visit_reference_list(node)

    def visit_yaral_match_section(self, node: MatchSection) -> str:
        return self.visit_match_section(node)

    def visit_yaral_match_variable(self, node: MatchVariable) -> str:
        return self.visit_match_variable(node)

    def visit_yaral_time_window(self, node: TimeWindow) -> str:
        return self.visit_time_window(node)

    def visit_yaral_condition_section(self, node: ConditionSection) -> str:
        return self.visit_condition_section(node)

    def visit_yaral_condition_expression(self, node: ConditionExpression) -> str:
        return self.visit_condition_expression(node)

    def visit_yaral_binary_condition(self, node: BinaryCondition) -> str:
        return self.visit_binary_condition(node)

    def visit_yaral_unary_condition(self, node: UnaryCondition) -> str:
        return self.visit_unary_condition(node)

    def visit_yaral_event_count_condition(self, node: EventCountCondition) -> str:
        return self.visit_event_count_condition(node)

    def visit_yaral_event_exists_condition(self, node: EventExistsCondition) -> str:
        return self.visit_event_exists_condition(node)

    def visit_yaral_variable_comparison_condition(self, node) -> str:
        return self.visit_variable_comparison_condition(node)

    def visit_yaral_null_check_condition(self, node) -> str:
        return self.visit_null_check_condition(node)

    def visit_yaral_join_condition(self, node) -> str:
        return self.visit_join_condition(node)

    def visit_yaral_outcome_section(self, node: OutcomeSection) -> str:
        return self.visit_outcome_section(node)

    def visit_yaral_outcome_assignment(self, node: OutcomeAssignment) -> str:
        return self.visit_outcome_assignment(node)

    def visit_yaral_outcome_expression(self, node: OutcomeExpression) -> str:
        return self.visit_outcome_expression(node)

    def visit_yaral_aggregation_function(self, node: AggregationFunction) -> str:
        return self.visit_aggregation_function(node)

    def visit_yaral_conditional_expression(self, node: ConditionalExpression) -> str:
        return self.visit_conditional_expression(node)

    def visit_yaral_arithmetic_expression(self, node) -> str:
        return self.visit_arithmetic_expression(node)

    def visit_yaral_options_section(self, node: OptionsSection) -> str:
        return self.visit_options_section(node)

    def visit_yaral_regex_pattern(self, node: RegexPattern) -> str:
        return self.visit_regex_pattern(node)

    def visit_yaral_cidr_expression(self, node) -> str:
        return self.visit_cidr_expression(node)

    def visit_yaral_function_call(self, node) -> str:
        return self.visit_function_call(node)
