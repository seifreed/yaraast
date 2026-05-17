"""Additional regression tests for rule optimizer accounting."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import InExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    RangeExpression,
)
from yaraast.ast.rules import Rule
from yaraast.evaluation.evaluator import YaraEvaluator
from yaraast.optimization import ExpressionOptimizer, RuleOptimizer
from yaraast.parser import Parser


def test_rule_optimizer_does_not_count_unchanged_conditions() -> None:
    ast = YaraFile(rules=[Rule(name="unchanged", condition=Identifier("filesize"))])

    _, stats = RuleOptimizer().optimize(ast)

    assert stats["passes_performed"] == 1
    assert stats["expression_optimizations"] == 0
    assert stats["total_optimizations"] == 0


def test_rule_optimizer_counts_actual_identity_simplifications() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="identity",
                condition=BinaryExpression(Identifier("filesize"), "+", IntegerLiteral(0)),
            )
        ]
    )

    optimized, stats = RuleOptimizer().optimize(ast)

    assert optimized.rules[0].condition == Identifier("filesize")
    assert stats["expression_optimizations"] == 1
    assert stats["total_optimizations"] == 1


def test_expression_optimizer_preserves_undefined_multiply_by_zero() -> None:
    ast = Parser().parse("""
        rule undefined_multiply_by_zero {
            condition:
                defined (uint8(filesize) * 0)
        }
    """)

    optimized, count = ExpressionOptimizer().optimize(ast)

    assert count == 0
    assert YaraEvaluator(data=b"a").evaluate_file(optimized) == {
        "undefined_multiply_by_zero": False
    }


def test_expression_optimizer_preserves_defined_boolean_operands() -> None:
    ast = Parser().parse("""
        rule defined_boolean_coercion {
            condition:
                defined (false or uint8(filesize)) and
                defined (true and uint8(filesize)) and
                defined (uint8(filesize) or false)
        }
    """)

    optimized, count = ExpressionOptimizer().optimize(ast)

    assert count == 0
    assert YaraEvaluator(data=b"abc").evaluate_file(optimized) == {"defined_boolean_coercion": True}


def test_empty_in_range_optimizes_to_false_and_is_counted() -> None:
    optimizer = ExpressionOptimizer()
    expr = InExpression(
        subject="$a", range=RangeExpression(IntegerLiteral(100), IntegerLiteral(50))
    )

    optimized = optimizer.visit(expr)

    assert optimized == BooleanLiteral(False)
    assert optimizer.optimization_count == 1
