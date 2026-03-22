"""Helper functions for complexity calculations."""

from __future__ import annotations

from yaraast.ast.base import ASTNode
from yaraast.ast.conditions import ForExpression, ForOfExpression
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexString, RegexString
from yaraast.metrics.complexity_calculator import ComplexityCalculator


# Convenience functions
def calculate_rule_complexity(rule: Rule) -> int:
    """Calculate total complexity for a rule."""
    calc = ComplexityCalculator()

    # Base complexity
    complexity = 1

    # Add string complexity
    if rule.strings:
        complexity += len(rule.strings)
        for string in rule.strings:
            if isinstance(string, RegexString):
                complexity += 2
            elif isinstance(string, HexString):
                complexity += 1

    # Add condition complexity
    if rule.condition:
        complexity += calc.calculate(rule.condition)

    # Add modifier complexity
    if "private" in rule.modifiers:
        complexity += 1
    if "global" in rule.modifiers:
        complexity += 1

    return complexity


def calculate_expression_complexity(expr: ASTNode) -> int:
    """Calculate complexity for an expression."""
    calc = ComplexityCalculator()
    return calc.calculate(expr)


def calculate_cyclomatic_complexity(expr: ASTNode) -> int:
    """Calculate cyclomatic complexity (branching)."""
    # Simple approximation based on decision points
    complexity = 1

    if hasattr(expr, "operator") and expr.operator in ("and", "or"):
        complexity += 1

    # Recursively check children
    if hasattr(expr, "left"):
        complexity += calculate_cyclomatic_complexity(expr.left) - 1
    if hasattr(expr, "right"):
        complexity += calculate_cyclomatic_complexity(expr.right) - 1
    if hasattr(expr, "operand"):
        complexity += calculate_cyclomatic_complexity(expr.operand) - 1
    if hasattr(expr, "expression"):
        complexity += calculate_cyclomatic_complexity(expr.expression) - 1

    return complexity


def calculate_cognitive_complexity(expr: ASTNode) -> int:
    """Calculate cognitive complexity (mental effort)."""
    calc = ComplexityCalculator()
    base_complexity = calc.calculate(expr)

    # Add extra complexity for nesting
    if isinstance(expr, ForExpression | ForOfExpression):
        return base_complexity + 3

    return base_complexity
