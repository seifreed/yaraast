"""Helper functions for complexity calculations."""

from __future__ import annotations

from collections.abc import Iterator

from yaraast.ast.base import ASTNode
from yaraast.ast.conditions import ForExpression, ForOfExpression
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexString, RegexString
from yaraast.metrics.complexity_calculator import ComplexityCalculator
from yaraast.yarax.ast_nodes import ArrayComprehension, DictComprehension, PatternMatch


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
    if any(str(m) == "private" for m in rule.modifiers):
        complexity += 1
    if any(str(m) == "global" for m in rule.modifiers):
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
    if isinstance(expr, ForExpression | ForOfExpression | ArrayComprehension | DictComprehension):
        complexity += 1
    if isinstance(expr, PatternMatch):
        complexity += max(1, len(expr.cases) + (1 if expr.default else 0))

    # Recursively check children
    for child in _iter_cyclomatic_children(expr):
        complexity += calculate_cyclomatic_complexity(child) - 1

    return complexity


def _iter_cyclomatic_children(expr: ASTNode) -> Iterator[ASTNode]:
    child_attrs = (
        "left",
        "right",
        "operand",
        "expression",
        "body",
        "quantifier",
        "iterable",
        "condition",
        "string_set",
        "declarations",
        "value",
        "cases",
        "default",
        "pattern",
        "result",
        "elements",
        "items",
        "key",
        "key_expression",
        "value_expression",
        "tuple_expr",
        "index",
        "target",
        "start",
        "stop",
        "step",
        "arguments",
    )
    for attr in child_attrs:
        value = getattr(expr, attr, None)
        if hasattr(value, "accept"):
            yield value
        elif isinstance(value, list | tuple | set | frozenset):
            for item in value:
                if hasattr(item, "accept"):
                    yield item


def calculate_cognitive_complexity(expr: ASTNode) -> int:
    """Calculate cognitive complexity (mental effort)."""
    calc = ComplexityCalculator()
    base_complexity = calc.calculate(expr)

    # Add extra complexity for nesting
    if isinstance(expr, ForExpression | ForOfExpression):
        return base_complexity + 3

    return base_complexity
