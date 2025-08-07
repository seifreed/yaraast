"""Expression optimizer for YARA rules."""

from __future__ import annotations

from typing import Any

from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Expression,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    UnaryExpression,
)
from yaraast.visitor.visitor import ASTTransformer


class ExpressionOptimizer(ASTTransformer):
    """Optimizes expressions in YARA rules."""

    def optimize(self, expr: Expression) -> Expression:
        """Optimize an expression."""
        return self.visit(expr)

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
                return BooleanLiteral(value=node.left.value and node.right.value)
            if node.operator == "or":
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
                    return BooleanLiteral(value=False)
                return node.right
            if node.operator == "or":
                if node.left.value:
                    return BooleanLiteral(value=True)
                return node.right

        if isinstance(node.right, BooleanLiteral):
            if node.operator == "and":
                if not node.right.value:
                    return BooleanLiteral(value=False)
                return node.left
            if node.operator == "or":
                if node.right.value:
                    return BooleanLiteral(value=True)
                return node.left

        return node

    def visit_unary_expression(self, node: UnaryExpression) -> Expression:
        """Visit UnaryExpression and optimize."""
        # Optimize operand first
        node.operand = self.visit(node.operand)

        # Constant folding
        if node.operator == "not" and isinstance(node.operand, BooleanLiteral):
            return BooleanLiteral(value=not node.operand.value)

        if node.operator == "-" and isinstance(node.operand, IntegerLiteral):
            return IntegerLiteral(value=-node.operand.value)

        if node.operator == "~" and isinstance(node.operand, IntegerLiteral):
            return IntegerLiteral(value=~node.operand.value)

        # Double negation elimination
        if (
            node.operator == "not"
            and isinstance(node.operand, UnaryExpression)
            and node.operand.operator == "not"
        ):
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
            node.elements = [self.visit(elem) for elem in node.elements]
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
