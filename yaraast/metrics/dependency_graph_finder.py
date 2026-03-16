"""Traversal helpers for dependency graph analysis."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.metrics._visitor_base import MetricsVisitorBase

if TYPE_CHECKING:
    from yaraast.ast.expressions import Identifier


class DependencyFinder(MetricsVisitorBase):
    """Collect inter-rule identifier dependencies from a condition tree."""

    def __init__(self, current_rule: str, all_rules: set[str]) -> None:
        super().__init__(default=None)
        self.current_rule = current_rule
        self.all_rules = all_rules
        self.dependencies = set()

    def visit_identifier(self, node: Identifier) -> None:
        if node.name in self.all_rules and node.name != self.current_rule:
            self.dependencies.add(node.name)

    def visit_binary_expression(self, node) -> None:
        self.visit(node.left)
        self.visit(node.right)

    def visit_unary_expression(self, node) -> None:
        self.visit(node.operand)

    def visit_parentheses_expression(self, node) -> None:
        self.visit(node.expression)

    def visit_set_expression(self, node) -> None:
        for elem in node.elements:
            self.visit(elem)

    def visit_range_expression(self, node) -> None:
        self.visit(node.low)
        self.visit(node.high)

    def visit_function_call(self, node) -> None:
        for arg in node.arguments:
            self.visit(arg)

    def visit_array_access(self, node) -> None:
        self.visit(node.array)
        self.visit(node.index)

    def visit_member_access(self, node) -> None:
        self.visit(node.object)

    def visit_for_expression(self, node) -> None:
        self.visit(node.iterable)
        self.visit(node.body)

    def visit_for_of_expression(self, node) -> None:
        if hasattr(node.string_set, "accept"):
            self.visit(node.string_set)
        if node.condition:
            self.visit(node.condition)

    def visit_at_expression(self, node) -> None:
        self.visit(node.offset)

    def visit_in_expression(self, node) -> None:
        self.visit(node.range)

    def visit_of_expression(self, node) -> None:
        if hasattr(node.quantifier, "accept"):
            self.visit(node.quantifier)
        if hasattr(node.string_set, "accept"):
            self.visit(node.string_set)

    def visit_dictionary_access(self, node) -> None:
        self.visit(node.object)

    def visit_defined_expression(self, node) -> None:
        self.visit(node.expression)

    def visit_string_operator_expression(self, node) -> None:
        self.visit(node.left)
        self.visit(node.right)

    def visit_string_wildcard(self, node) -> None:
        pass
