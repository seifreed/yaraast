"""AST Optimizer for libyara integration."""

import copy
from dataclasses import dataclass

from yaraast.ast.base import YaraFile, require_yara_file
from yaraast.ast.expressions import BinaryExpression, Expression, IntegerLiteral, UnaryExpression
from yaraast.ast.rules import Rule
from yaraast.optimization.dead_code_eliminator import DeadCodeEliminator
from yaraast.optimization.expression_optimizer import ExpressionOptimizer
from yaraast.shared.integer_semantics import (
    INT64_MIN,
    integer_remainder,
    normalize_int64,
    truncate_integer_division,
)


@dataclass
class OptimizationStats:
    """Statistics about AST optimizations performed."""

    rules_optimized: int = 0
    strings_optimized: int = 0
    conditions_simplified: int = 0
    dead_code_removed: int = 0
    constant_folded: int = 0


class ASTOptimizer:
    """Simple optimizer for AST before compilation."""

    def __init__(self) -> None:
        self.stats = OptimizationStats()
        self.optimizations_applied: list[str] = []

    def optimize(self, ast: YaraFile) -> YaraFile:
        """Apply optimizations to AST."""
        ast = require_yara_file(ast, "ast")
        ast.validate_structure()
        self.stats = OptimizationStats()
        self.optimizations_applied = []

        # Create a deep copy to avoid modifying the original
        optimized_ast = copy.deepcopy(ast)

        # Apply dead code elimination
        eliminator = DeadCodeEliminator()
        optimized_ast, elimination_count = eliminator.eliminate(optimized_ast)
        if elimination_count > 0:
            self.stats.strings_optimized += elimination_count
            self.stats.dead_code_removed += elimination_count
            self.optimizations_applied.append(
                f"Removed {elimination_count} unused strings/dead code"
            )

        # Apply expression optimization
        expr_optimizer = ExpressionOptimizer()
        optimized_ast, expr_opt_count = expr_optimizer.optimize(optimized_ast)
        if expr_opt_count > 0:
            self.stats.conditions_simplified += expr_opt_count
            self.stats.constant_folded += expr_opt_count
            self.optimizations_applied.append(f"Applied {expr_opt_count} expression optimizations")

        # Count rules as optimized
        self.stats.rules_optimized = len(optimized_ast.rules)

        return optimized_ast

    def _optimize_rule(self, rule: Rule) -> None:
        """Optimize a single rule."""
        original_string_count = len(rule.strings)
        DeadCodeEliminator().eliminate_dead_code(rule)
        removed_string_count = original_string_count - len(rule.strings)
        if removed_string_count > 0:
            self.stats.strings_optimized += removed_string_count
            self.stats.dead_code_removed += removed_string_count
            self.optimizations_applied.append(
                f"Removed {removed_string_count} unused strings in rule '{rule.name}'",
            )

        # Optimize condition
        if rule.condition is not None:
            optimized_condition = self._optimize_condition(rule.condition)
            if optimized_condition != rule.condition:
                rule.condition = optimized_condition
                self.stats.conditions_simplified += 1
                self.optimizations_applied.append(
                    f"Simplified condition in rule '{rule.name}'",
                )

        self.stats.rules_optimized += 1

    def _optimize_condition(self, condition: Expression) -> Expression:
        """Optimize condition expressions."""
        # Constant folding for binary operations
        if isinstance(condition, BinaryExpression):
            left_opt = (
                self._optimize_condition(condition.left)
                if hasattr(condition, "left")
                else condition.left
            )
            right_opt = (
                self._optimize_condition(condition.right)
                if hasattr(condition, "right")
                else condition.right
            )

            # Try constant folding
            if isinstance(left_opt, IntegerLiteral) and isinstance(
                right_opt,
                IntegerLiteral,
            ):
                result = self._fold_constants(left_opt, condition.operator, right_opt)
                if result is not None:
                    self.stats.constant_folded += 1
                    return result

            condition.left = left_opt
            condition.right = right_opt

        elif isinstance(condition, UnaryExpression) and hasattr(condition, "operand"):
            condition.operand = self._optimize_condition(condition.operand)

        return condition

    def _fold_constants(
        self,
        left: IntegerLiteral,
        op: str,
        right: IntegerLiteral,
    ) -> IntegerLiteral | None:
        """Fold constant expressions."""
        try:
            left_val = _literal_integer_value(left)
            right_val = _literal_integer_value(right)

            if op == "+":
                return IntegerLiteral(value=normalize_int64(left_val + right_val))
            if op == "-":
                return IntegerLiteral(value=normalize_int64(left_val - right_val))
            if op == "*":
                return IntegerLiteral(value=normalize_int64(left_val * right_val))
            if op in ("/", "\\") and right_val != 0:
                if left_val == INT64_MIN and right_val == -1:
                    return None
                return IntegerLiteral(value=truncate_integer_division(left_val, right_val))
            if op == "%" and right_val != 0:
                if left_val == INT64_MIN and right_val == -1:
                    return None
                return IntegerLiteral(value=integer_remainder(left_val, right_val))
        except (TypeError, ValueError, ZeroDivisionError):
            pass

        return None


def _literal_integer_value(node: IntegerLiteral) -> int:
    if isinstance(node.value, bool) or not isinstance(node.value, int):
        msg = "IntegerLiteral value must be an integer"
        raise TypeError(msg)
    return node.value
