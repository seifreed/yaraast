"""Complexity calculator for AST nodes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from yaraast.ast.base import ASTNode
from yaraast.ast.conditions import ForExpression, ForOfExpression, OfExpression
from yaraast.metrics._visitor_base import MetricsVisitorBase

if TYPE_CHECKING:
    from yaraast.ast.expressions import BinaryExpression, UnaryExpression


class ComplexityCalculator(MetricsVisitorBase):
    """Calculate complexity scores for AST nodes."""

    def __init__(self) -> None:
        super().__init__(default=0)

    def calculate(self, node: ASTNode | None) -> int:
        """Calculate complexity for an AST node."""
        if node is None:
            return 0
        return self.visit(node)

    def _calculate_ast_value(self, value: Any) -> int:
        if hasattr(value, "accept"):
            return self.calculate(value)
        if isinstance(value, list | tuple | set | frozenset):
            return sum(self._calculate_ast_value(item) for item in value)
        return 0

    def _calculate_string_set_value(self, value: Any) -> int:
        if isinstance(value, str):
            return 1
        if hasattr(value, "accept"):
            return self.calculate(value)
        if isinstance(value, list | tuple | set | frozenset):
            return sum(self._calculate_string_set_value(item) for item in value)
        return 1

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
        else:
            complexity += 1

        # Add child complexity
        complexity += self.calculate(node.left)
        complexity += self.calculate(node.right)

        return complexity

    # Unary expressions
    def visit_unary_expression(self, node: UnaryExpression) -> int:
        return 2 + self.calculate(node.operand)

    # Function calls
    def visit_function_call(self, node) -> int:
        complexity = 2  # Base function call
        if getattr(node, "receiver", None) is not None:
            complexity += self.calculate(node.receiver)
        for arg in node.arguments:
            complexity += self.calculate(arg)
        return complexity

    # String operations
    def visit_string_count(self, node) -> int:
        return 2

    def visit_string_offset(self, node) -> int:
        complexity = 2
        if node.index is not None:
            complexity += self.calculate(node.index)
        return complexity

    def visit_string_length(self, node) -> int:
        complexity = 2
        if node.index is not None:
            complexity += self.calculate(node.index)
        return complexity

    # Complex expressions
    def visit_for_expression(self, node: ForExpression) -> int:
        complexity = 5  # High base for loops
        complexity += self._calculate_ast_value(node.quantifier)
        complexity += self.calculate(node.iterable)
        complexity += self.calculate(node.body)
        return complexity

    def visit_for_of_expression(self, node: ForOfExpression) -> int:
        complexity = 5  # High base for loops
        complexity += self._calculate_ast_value(node.quantifier)
        complexity += self._calculate_string_set_value(node.string_set)
        if node.condition is not None:
            complexity += self.calculate(node.condition)
        return complexity

    def visit_of_expression(self, node: OfExpression) -> int:
        complexity = 4  # Base for of expressions
        complexity += self._calculate_ast_value(node.quantifier)
        complexity += self._calculate_string_set_value(node.string_set)
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
        subject_complexity = self._calculate_ast_value(node.subject)
        return 2 + subject_complexity + self.calculate(node.range)

    def visit_defined_expression(self, node) -> int:
        return 1 + self.calculate(node.expression)

    def visit_string_operator_expression(self, node) -> int:
        return 2 + self.calculate(node.left) + self.calculate(node.right)

    def visit_dictionary_access(self, node) -> int:
        complexity = 1 + self.calculate(node.object)
        if hasattr(node.key, "accept"):
            complexity += self.calculate(node.key)
        return complexity

    def visit_with_statement(self, node) -> int:
        complexity = 3 + self._calculate_ast_value(node.declarations)
        complexity += self.calculate(node.body)
        return complexity

    def visit_with_declaration(self, node) -> int:
        return 1 + self._calculate_ast_value(node.value)

    def visit_array_comprehension(self, node) -> int:
        complexity = 5
        complexity += self._calculate_ast_value(node.expression)
        complexity += self._calculate_ast_value(node.iterable)
        complexity += self._calculate_ast_value(node.condition)
        return complexity

    def visit_dict_comprehension(self, node) -> int:
        complexity = 6
        complexity += self._calculate_ast_value(node.key_expression)
        complexity += self._calculate_ast_value(node.value_expression)
        complexity += self._calculate_ast_value(node.iterable)
        complexity += self._calculate_ast_value(node.condition)
        return complexity

    def visit_tuple_expression(self, node) -> int:
        return 1 + self._calculate_ast_value(node.elements)

    def visit_tuple_indexing(self, node) -> int:
        return 1 + self.calculate(node.tuple_expr) + self.calculate(node.index)

    def visit_list_expression(self, node) -> int:
        return 1 + self._calculate_ast_value(node.elements)

    def visit_dict_expression(self, node) -> int:
        return 1 + self._calculate_ast_value(node.items)

    def visit_dict_item(self, node) -> int:
        return 1 + self.calculate(node.key) + self.calculate(node.value)

    def visit_slice_expression(self, node) -> int:
        complexity = 1 + self.calculate(node.target)
        complexity += self._calculate_ast_value(node.start)
        complexity += self._calculate_ast_value(node.stop)
        complexity += self._calculate_ast_value(node.step)
        return complexity

    def visit_lambda_expression(self, node) -> int:
        return 2 + self.calculate(node.body)

    def visit_pattern_match(self, node) -> int:
        complexity = 4 + self.calculate(node.value)
        complexity += self._calculate_ast_value(node.cases)
        complexity += self._calculate_ast_value(node.default)
        return complexity

    def visit_match_case(self, node) -> int:
        return 2 + self.calculate(node.pattern) + self.calculate(node.result)

    def visit_spread_operator(self, node) -> int:
        return 1 + self.calculate(node.expression)
