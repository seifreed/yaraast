"""Expression optimizer for YARA rules."""

from __future__ import annotations

from typing import Any

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Expression,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    UnaryExpression,
)
from yaraast.ast.rules import Rule
from yaraast.visitor.visitor import ASTTransformer


class ExpressionOptimizer(ASTTransformer):
    """Optimizes expressions in YARA rules."""

    def __init__(self) -> None:
        super().__init__()
        self.optimization_count = 0

    def optimize(self, node: Expression | YaraFile) -> Expression | tuple[YaraFile, int]:
        """Optimize an expression or YaraFile.

        Args:
            node: Expression to optimize or YaraFile containing rules to optimize

        Returns:
            If Expression: optimized Expression
            If YaraFile: tuple of (optimized YaraFile, optimization count)
        """
        if isinstance(node, YaraFile):
            self.optimization_count = 0
            optimized_rules = []
            for rule in node.rules:
                optimized_rule = self._optimize_rule(rule)
                optimized_rules.append(optimized_rule)

            optimized_file = YaraFile(
                imports=node.imports,
                includes=node.includes,
                rules=optimized_rules,
            )
            return optimized_file, self.optimization_count
        else:
            # Single expression optimization
            return self.visit(node)

    def _optimize_rule(self, rule: Rule) -> Rule:
        """Optimize expressions in a rule."""
        if rule.condition:
            # Reset count for this rule to track optimizations
            before_count = self.optimization_count
            optimized_condition = self.visit(rule.condition)
            # Count is incremented by visit methods for each optimization
            rule.condition = optimized_condition
        return rule

    def visit_binary_expression(self, node: BinaryExpression) -> Expression:
        """Visit BinaryExpression and optimize."""
        # Optimize children first
        node.left = self.visit(node.left)
        node.right = self.visit(node.right)

        # Constant folding for boolean operations
        if isinstance(node.left, BooleanLiteral) and isinstance(
            node.right,
            BooleanLiteral,
        ):
            if node.operator == "and":
                self.optimization_count += 1
                return BooleanLiteral(value=node.left.value and node.right.value)
            if node.operator == "or":
                self.optimization_count += 1
                return BooleanLiteral(value=node.left.value or node.right.value)

        # Constant folding for integer arithmetic
        if isinstance(node.left, IntegerLiteral) and isinstance(
            node.right,
            IntegerLiteral,
        ):
            left_val = node.left.value
            right_val = node.right.value

            # Arithmetic operations
            if node.operator == "+":
                return IntegerLiteral(value=left_val + right_val)
            if node.operator == "-":
                return IntegerLiteral(value=left_val - right_val)
            if node.operator == "*":
                return IntegerLiteral(value=left_val * right_val)
            if node.operator == "/" and right_val != 0:
                return IntegerLiteral(value=left_val // right_val)  # Integer division
            if node.operator == "%" and right_val != 0:
                return IntegerLiteral(value=left_val % right_val)

            # Bitwise operations
            if node.operator == "&":
                return IntegerLiteral(value=left_val & right_val)
            if node.operator == "|":
                return IntegerLiteral(value=left_val | right_val)
            if node.operator == "^":
                return IntegerLiteral(value=left_val ^ right_val)
            if node.operator == "<<":
                return IntegerLiteral(value=left_val << right_val)
            if node.operator == ">>":
                return IntegerLiteral(value=left_val >> right_val)

            # Comparison operations
            if node.operator == "==":
                return BooleanLiteral(value=left_val == right_val)
            if node.operator == "!=":
                return BooleanLiteral(value=left_val != right_val)
            if node.operator == "<":
                return BooleanLiteral(value=left_val < right_val)
            if node.operator == ">":
                return BooleanLiteral(value=left_val > right_val)
            if node.operator == "<=":
                return BooleanLiteral(value=left_val <= right_val)
            if node.operator == ">=":
                return BooleanLiteral(value=left_val >= right_val)

        # Identity operations
        if (
            node.operator == "+"
            and isinstance(node.right, IntegerLiteral)
            and node.right.value == 0
        ):
            return node.left
        if node.operator == "+" and isinstance(node.left, IntegerLiteral) and node.left.value == 0:
            return node.right

        if (
            node.operator == "*"
            and isinstance(node.right, IntegerLiteral)
            and node.right.value == 1
        ):
            return node.left
        if node.operator == "*" and isinstance(node.left, IntegerLiteral) and node.left.value == 1:
            return node.right

        # Zero multiplication
        if (
            node.operator == "*"
            and isinstance(node.right, IntegerLiteral)
            and node.right.value == 0
        ):
            return IntegerLiteral(value=0)
        if node.operator == "*" and isinstance(node.left, IntegerLiteral) and node.left.value == 0:
            return IntegerLiteral(value=0)

        # Boolean simplifications
        if isinstance(node.left, BooleanLiteral):
            if node.operator == "and":
                if not node.left.value:
                    self.optimization_count += 1
                    return BooleanLiteral(value=False)
                self.optimization_count += 1
                return node.right
            if node.operator == "or":
                if node.left.value:
                    self.optimization_count += 1
                    return BooleanLiteral(value=True)
                self.optimization_count += 1
                return node.right

        if isinstance(node.right, BooleanLiteral):
            if node.operator == "and":
                if not node.right.value:
                    self.optimization_count += 1
                    return BooleanLiteral(value=False)
                self.optimization_count += 1
                return node.left
            if node.operator == "or":
                if node.right.value:
                    self.optimization_count += 1
                    return BooleanLiteral(value=True)
                self.optimization_count += 1
                return node.left

        return node

    def visit_unary_expression(self, node: UnaryExpression) -> Expression:
        """Visit UnaryExpression and optimize."""
        # Optimize operand first
        node.operand = self.visit(node.operand)

        # Constant folding
        if node.operator == "not" and isinstance(node.operand, BooleanLiteral):
            self.optimization_count += 1
            return BooleanLiteral(value=not node.operand.value)

        if node.operator == "-" and isinstance(node.operand, IntegerLiteral):
            self.optimization_count += 1
            return IntegerLiteral(value=-node.operand.value)

        if node.operator == "~" and isinstance(node.operand, IntegerLiteral):
            self.optimization_count += 1
            return IntegerLiteral(value=~node.operand.value)

        # Double negation elimination
        if (
            node.operator == "not"
            and isinstance(node.operand, UnaryExpression)
            and node.operand.operator == "not"
        ):
            self.optimization_count += 1
            return node.operand.operand

        return node

    def visit_parentheses_expression(self, node: ParenthesesExpression) -> Expression:
        """Visit ParenthesesExpression and optimize."""
        # Optimize inner expression
        inner = self.visit(node.expression)

        # Remove unnecessary parentheses around literals and identifiers
        if isinstance(inner, BooleanLiteral | IntegerLiteral | Identifier):
            return inner

        node.expression = inner
        return node

    # Pass-through methods for other expression types
    def visit_boolean_literal(self, node: BooleanLiteral) -> BooleanLiteral:
        return node

    def visit_integer_literal(self, node: IntegerLiteral) -> IntegerLiteral:
        return node

    def visit_identifier(self, node: Identifier) -> Identifier:
        return node

    def visit_string_identifier(self, node: Any) -> Any:
        return node

    def visit_string_count(self, node: Any) -> Any:
        return node

    def visit_string_offset(self, node: Any) -> Any:
        return node

    def visit_string_length(self, node: Any) -> Any:
        return node

    def visit_double_literal(self, node: Any) -> Any:
        return node

    def visit_string_literal(self, node: Any) -> Any:
        return node

    def visit_array_access(self, node: Any) -> Any:
        if hasattr(node, "array"):
            node.array = self.visit(node.array)
        if hasattr(node, "index"):
            node.index = self.visit(node.index)
        return node

    def visit_member_access(self, node: Any) -> Any:
        if hasattr(node, "object"):
            node.object = self.visit(node.object)
        return node

    def visit_function_call(self, node: Any) -> Any:
        if hasattr(node, "arguments"):
            node.arguments = [self.visit(arg) for arg in node.arguments]
        return node

    def visit_range_expression(self, node: Any) -> Any:
        if hasattr(node, "low"):
            node.low = self.visit(node.low)
        if hasattr(node, "high"):
            node.high = self.visit(node.high)
        return node

    def visit_set_expression(self, node: Any) -> Any:
        if hasattr(node, "elements"):
            # Optimize elements first
            node.elements = [self.visit(elem) for elem in node.elements]

            # Remove duplicates from integer literals
            seen = set()
            unique_elements = []
            duplicates_removed = 0

            for elem in node.elements:
                # Create a hashable representation for comparison
                if isinstance(elem, IntegerLiteral):
                    key = ("int", elem.value)
                elif isinstance(elem, BooleanLiteral):
                    key = ("bool", elem.value)
                elif hasattr(elem, "name"):
                    key = ("name", elem.name)
                else:
                    # For other types, keep them all (can't easily detect duplicates)
                    unique_elements.append(elem)
                    continue

                if key not in seen:
                    seen.add(key)
                    unique_elements.append(elem)
                else:
                    duplicates_removed += 1

            if duplicates_removed > 0:
                self.optimization_count += duplicates_removed
                node.elements = unique_elements

        return node

    def visit_for_expression(self, node: Any) -> Any:
        if hasattr(node, "iterable"):
            node.iterable = self.visit(node.iterable)
        if hasattr(node, "body"):
            node.body = self.visit(node.body)
        return node

    def visit_of_expression(self, node: Any) -> Any:
        if hasattr(node, "quantifier"):
            node.quantifier = self.visit(node.quantifier)
        if hasattr(node, "string_set"):
            node.string_set = self.visit(node.string_set)
        return node

    def visit_at_expression(self, node: Any) -> Any:
        if hasattr(node, "offset"):
            node.offset = self.visit(node.offset)
        return node

    def visit_in_expression(self, node: Any) -> Any:
        if hasattr(node, "range"):
            node.range = self.visit(node.range)
        return node

    # Rule-level methods (not used for expression optimization)
    def visit_yara_file(self, node: Any) -> Any:
        return node

    def visit_rule(self, node: Any) -> Any:
        return node

    def visit_import(self, node: Any) -> Any:
        return node

    def visit_include(self, node: Any) -> Any:
        return node

    def visit_tag(self, node: Any) -> Any:
        return node

    def visit_meta(self, node: Any) -> Any:
        return node

    def visit_plain_string(self, node: Any) -> Any:
        return node

    def visit_hex_string(self, node: Any) -> Any:
        return node

    def visit_regex_string(self, node: Any) -> Any:
        return node


def optimize_expression(expr: Expression) -> Expression:
    """Convenience function to optimize an expression."""
    optimizer = ExpressionOptimizer()
    return optimizer.optimize(expr)
