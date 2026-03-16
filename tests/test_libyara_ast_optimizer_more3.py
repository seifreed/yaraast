"""More tests for libyara AST optimizer (no mocks)."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BinaryExpression, IntegerLiteral
from yaraast.ast.rules import Rule
from yaraast.libyara.ast_optimizer import ASTOptimizer


def test_ast_optimizer_constant_folding() -> None:
    optimizer = ASTOptimizer()
    expr = BinaryExpression(
        left=IntegerLiteral(value=2),
        operator="+",
        right=IntegerLiteral(value=3),
    )
    folded = optimizer._optimize_condition(expr)
    assert isinstance(folded, IntegerLiteral)
    assert folded.value == 5


def test_ast_optimizer_stats_rules() -> None:
    ast = YaraFile(rules=[Rule(name="r1")])
    optimizer = ASTOptimizer()
    optimized = optimizer.optimize(ast)
    assert len(optimized.rules) == 1
    assert optimizer.stats.rules_optimized == 1
