"""YARA-L code generator from AST."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.visitor import ASTVisitor

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


class YaraLGenerator(ASTVisitor[str]):
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

        # Add condition section
        if node.condition:
            parts.append(self.visit(node.condition))

        # Add outcome section
        if node.outcome:
            parts.append(self.visit(node.outcome))

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
            value = f'"{value}"'
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
        parts = []

        # Add event variable
        if node.event:
            parts.append(self.visit(node.event))

        # Add assignments
        for assignment in node.assignments:
            parts.append(self.visit(assignment))

        # Join with AND if multiple parts
        if len(parts) > 1:
            return f"{self._indent()}{' and '.join(parts)}"
        if parts:
            return f"{self._indent()}{parts[0]}"
        return ""

    def visit_event_variable(self, node: EventVariable) -> str:
        """Generate code for event variable."""
        return node.name

    def visit_event_assignment(self, node: EventAssignment) -> str:
        """Generate code for event assignment."""
        field = self.visit(node.field_path)
        operator = node.operator

        # Handle value based on type
        value = node.value
        if isinstance(value, str):
            # Check if it's a reference or literal
            if not value.startswith("$") and not value.startswith("%"):
                value = f'"{value}"'
        elif hasattr(value, "accept"):
            # It's an AST node
            value = self.visit(value)

        return f"{field} {operator} {value}"

    def visit_udm_field_path(self, node: UDMFieldPath) -> str:
        """Generate code for UDM field path."""
        return ".".join(node.parts)

    def visit_udm_field_access(self, node: UDMFieldAccess) -> str:
        """Generate code for UDM field access."""
        event = self.visit(node.event)
        field = self.visit(node.field)
        return f"{event}.{field}"

    def visit_match_section(self, node: MatchSection) -> str:
        """Generate code for match section."""
        lines = [f"{self._indent()}match:"]
        self._increase_indent()

        # Add match variables
        for var in node.variables:
            lines.append(self.visit(var))

        # Add time window
        if node.time_window:
            lines.append(self.visit(node.time_window))

        self._decrease_indent()
        return "\n".join(lines)

    def visit_match_variable(self, node: MatchVariable) -> str:
        """Generate code for match variable."""
        line = f"{self._indent()}{node.name} = "

        if node.field:
            line += self.visit(node.field)

        if node.condition:
            line += f" over {node.condition}"

        return line

    def visit_time_window(self, node: TimeWindow) -> str:
        """Generate code for time window."""
        return f"{self._indent()}over {node.duration} {node.unit}"

    def visit_condition_section(self, node: ConditionSection) -> str:
        """Generate code for condition section."""
        lines = [f"{self._indent()}condition:"]
        self._increase_indent()

        lines.append(f"{self._indent()}{self.visit(node.expression)}")

        self._decrease_indent()
        return "\n".join(lines)

    def visit_condition_expression(self, node: ConditionExpression) -> str:
        """Generate code for condition expression."""
        # This is a base class, specific implementations below
        return ""

    def visit_binary_condition(self, node: BinaryCondition) -> str:
        """Generate code for binary condition."""
        left = self.visit(node.left) if hasattr(node, "left") and node.left else ""
        right = self.visit(node.right) if hasattr(node, "right") and node.right else ""
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
        if node.negated:
            return f"not {node.event}"
        return node.event

    def visit_outcome_section(self, node: OutcomeSection) -> str:
        """Generate code for outcome section."""
        lines = [f"{self._indent()}outcome:"]
        self._increase_indent()

        # Add outcome variables
        for var in node.variables:
            lines.append(f"{self._indent()}{var} = {self.visit(node.variables[var])}")

        # Add conditional expressions
        for expr in node.conditional_expressions:
            lines.append(self.visit(expr))

        self._decrease_indent()
        return "\n".join(lines)

    def visit_outcome_assignment(self, node: OutcomeAssignment) -> str:
        """Generate code for outcome assignment."""
        return f"{node.variable} = {self.visit(node.expression)}"

    def visit_outcome_expression(self, node: OutcomeExpression) -> str:
        """Generate code for outcome expression."""
        if node.aggregation:
            return self.visit(node.aggregation)
        if node.field:
            return self.visit(node.field)
        if node.literal is not None:
            if isinstance(node.literal, str):
                return f'"{node.literal}"'
            return str(node.literal)
        return ""

    def visit_conditional_expression(self, node: ConditionalExpression) -> str:
        """Generate code for conditional expression."""
        condition = self.visit(node.condition)
        then_expr = self.visit(node.then_expression)
        else_expr = self.visit(node.else_expression) if node.else_expression else None

        if else_expr:
            return f"{self._indent()}if {condition} then {then_expr} else {else_expr}"
        return f"{self._indent()}if {condition} then {then_expr}"

    def visit_aggregation_function(self, node: AggregationFunction) -> str:
        """Generate code for aggregation function."""
        args = []
        for arg in node.arguments:
            if isinstance(arg, str):
                args.append(arg)
            else:
                args.append(self.visit(arg))

        args_str = ", ".join(args)
        return f"{node.function}({args_str})"

    def visit_reference_list(self, node: ReferenceList) -> str:
        """Generate code for reference list."""
        return f"%{node.name}"

    def visit_regex_pattern(self, node: RegexPattern) -> str:
        """Generate code for regex pattern."""
        modifiers = node.modifiers if node.modifiers else ""
        return f"/{node.pattern}/{modifiers}"

    def visit_options_section(self, node: OptionsSection) -> str:
        """Generate code for options section."""
        lines = [f"{self._indent()}options:"]
        self._increase_indent()

        for key, value in node.options.items():
            if isinstance(value, bool):
                value = "true" if value else "false"
            elif isinstance(value, str):
                value = f'"{value}"'
            lines.append(f"{self._indent()}{key} = {value}")

        self._decrease_indent()
        return "\n".join(lines)
