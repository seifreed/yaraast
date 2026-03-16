"""Complexity calculator for AST nodes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.ast.conditions import ForExpression, ForOfExpression, OfExpression
from yaraast.metrics._visitor_base import MetricsVisitorBase

if TYPE_CHECKING:
    from yaraast.ast.base import ASTNode
    from yaraast.ast.expressions import BinaryExpression, UnaryExpression


class ComplexityCalculator(MetricsVisitorBase):
    """Calculate complexity scores for AST nodes."""

    def __init__(self) -> None:
        super().__init__(default=0)
        self._cognitive_depth = 0
        self._in_logical_op = False

    def calculate(self, node: ASTNode) -> int:
        """Calculate complexity for an AST node."""
        if node is None:
            return 0
        return node.accept(self)

    # Simple expressions - base complexity 1
    def visit_boolean_literal(self, node) -> int:
        return 1

    def visit_integer_literal(self, node) -> int:
        return 1

    def visit_double_literal(self, node) -> int:
        return 1

    def visit_string_literal(self, node) -> int:
        return 1

    def visit_regex_literal(self, node) -> int:
        return 2  # Regex slightly more complex

    def visit_identifier(self, node) -> int:
        return 1

    def visit_string_identifier(self, node) -> int:
        return 1

    # Binary expressions - add complexity for operators
    def visit_binary_expression(self, node: BinaryExpression) -> int:
        complexity = 1  # Base

        # Logical operators add more complexity
        if node.operator in ("and", "or"):
            complexity += 2
            self._in_logical_op = True
        else:
            complexity += 1

        # Add child complexity
        complexity += self.calculate(node.left)
        complexity += self.calculate(node.right)

        self._in_logical_op = False
        return complexity

    # Unary expressions
    def visit_unary_expression(self, node: UnaryExpression) -> int:
        return 2 + self.calculate(node.operand)

    # Function calls
    def visit_function_call(self, node) -> int:
        complexity = 2  # Base function call
        for arg in node.arguments:
            complexity += self.calculate(arg)
        return complexity

    # String operations
    def visit_string_count(self, node) -> int:
        return 2

    def visit_string_offset(self, node) -> int:
        complexity = 2
        if node.index:
            complexity += self.calculate(node.index)
        return complexity

    def visit_string_length(self, node) -> int:
        complexity = 2
        if node.index:
            complexity += self.calculate(node.index)
        return complexity

    # Complex expressions
    def visit_for_expression(self, node: ForExpression) -> int:
        self._cognitive_depth += 1
        complexity = 5  # High base for loops
        complexity += self.calculate(node.iterable)
        complexity += self.calculate(node.body)
        self._cognitive_depth -= 1
        return complexity

    def visit_for_of_expression(self, node: ForOfExpression) -> int:
        self._cognitive_depth += 1
        complexity = 5  # High base for loops
        if hasattr(node.string_set, "accept"):
            complexity += self.calculate(node.string_set)
        else:
            complexity += len(node.string_set) if isinstance(node.string_set, list) else 1
        if node.condition:
            complexity += self.calculate(node.condition)
        self._cognitive_depth -= 1
        return complexity

    def visit_of_expression(self, node: OfExpression) -> int:
        complexity = 4  # Base for of expressions
        if hasattr(node.string_set, "accept"):
            complexity += self.calculate(node.string_set)
        elif isinstance(node.string_set, list):
            complexity += len(node.string_set)
        return complexity

    # Container expressions
    def visit_set_expression(self, node) -> int:
        complexity = 1
        for elem in node.elements:
            complexity += self.calculate(elem)
        return complexity

    def visit_range_expression(self, node) -> int:
        return 1 + self.calculate(node.low) + self.calculate(node.high)

    def visit_array_access(self, node) -> int:
        return 1 + self.calculate(node.array) + self.calculate(node.index)

    def visit_member_access(self, node) -> int:
        return 1 + self.calculate(node.object)

    def visit_parentheses_expression(self, node) -> int:
        return self.calculate(node.expression)

    # Other expressions
    def visit_at_expression(self, node) -> int:
        return 2 + self.calculate(node.offset)

    def visit_in_expression(self, node) -> int:
        return 2 + self.calculate(node.range)

    def visit_defined_expression(self, node) -> int:
        return 1 + self.calculate(node.expression)

    def visit_string_operator_expression(self, node) -> int:
        return 2 + self.calculate(node.left) + self.calculate(node.right)

    def visit_dictionary_access(self, node) -> int:
        complexity = 1 + self.calculate(node.object)
        if hasattr(node.key, "accept"):
            complexity += self.calculate(node.key)
        return complexity
