"""Additional regression tests for rule optimizer accounting."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import InExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    RangeExpression,
    StringIdentifier,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule
from yaraast.ast.pragmas import IncludeOncePragma
from yaraast.ast.rules import Rule
from yaraast.ast.strings import PlainString
from yaraast.evaluation.evaluator import YaraEvaluator
from yaraast.optimization import ExpressionOptimizer, RuleOptimizer
from yaraast.parser import Parser


@pytest.mark.parametrize("passes", [True, "3", object()])
def test_rule_optimizer_rejects_invalid_pass_count_types(passes: Any) -> None:
    ast = YaraFile(rules=[Rule(name="sample", condition=BooleanLiteral(True))])

    with pytest.raises(TypeError, match="passes must be an integer"):
        RuleOptimizer().optimize(ast, passes=cast(int, passes))


@pytest.mark.parametrize("passes", [0, -1])
def test_rule_optimizer_rejects_non_positive_pass_counts(passes: int) -> None:
    ast = YaraFile(rules=[Rule(name="sample", condition=BooleanLiteral(True))])

    with pytest.raises(ValueError, match="passes must be at least 1"):
        RuleOptimizer().optimize(ast, passes=passes)


def test_rule_optimizer_does_not_count_unchanged_conditions() -> None:
    ast = YaraFile(rules=[Rule(name="unchanged", condition=Identifier("filesize"))])

    _, stats = RuleOptimizer().optimize(ast)

    assert stats["passes_performed"] == 1
    assert stats["expression_optimizations"] == 0
    assert stats["total_optimizations"] == 0


def test_rule_optimizer_counts_actual_identity_simplifications() -> None:
    original_condition = BinaryExpression(Identifier("filesize"), "+", IntegerLiteral(0))
    ast = YaraFile(
        rules=[
            Rule(
                name="identity",
                condition=original_condition,
            )
        ]
    )

    optimized, stats = RuleOptimizer().optimize(ast)

    assert optimized.rules[0].condition == Identifier("filesize")
    assert ast.rules[0].condition is original_condition
    assert stats["expression_optimizations"] == 1
    assert stats["total_optimizations"] == 1


def test_rule_optimizer_stats_use_original_rule_count() -> None:
    ast = YaraFile(
        rules=[
            Rule(name="drop", condition=BooleanLiteral(False)),
            Rule(name="keep", condition=BooleanLiteral(True)),
        ]
    )

    optimized, stats = RuleOptimizer().optimize(ast)

    assert [rule.name for rule in optimized.rules] == ["keep"]
    assert stats["rules_before"] == 2
    assert stats["rules_after"] == 1
    assert stats["rules_eliminated"] == 1


def test_rule_optimizer_report_uses_original_string_count() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="strings",
                strings=[
                    PlainString(identifier="$used", value="used"),
                    PlainString(identifier="$unused", value="unused"),
                ],
                condition=StringIdentifier("$used"),
            )
        ]
    )

    report = RuleOptimizer().get_optimization_report(ast)

    assert report["size_reduction"]["strings"] == "1 strings removed"


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


def test_expression_optimizer_preserves_yara_file_top_level_extensions() -> None:
    namespace_rule = ExternRule(name="remote")
    ast = YaraFile(
        rules=[
            Rule(
                name="fold",
                condition=BinaryExpression(IntegerLiteral(1), "==", IntegerLiteral(1)),
            )
        ],
        extern_rules=[ExternRule(name="external")],
        extern_imports=[ExternImport(module_path="external_rules", rules=["external"])],
        pragmas=[IncludeOncePragma()],
        namespaces=[ExternNamespace(name="corp", extern_rules=[namespace_rule])],
    )

    optimized, count = ExpressionOptimizer().optimize(ast)

    assert count == 1
    assert [rule.name for rule in optimized.extern_rules] == ["external"]
    assert [imp.module_path for imp in optimized.extern_imports] == ["external_rules"]
    assert [pragma.name for pragma in optimized.pragmas] == ["include_once"]
    assert optimized.namespaces[0].name == "corp"
    assert optimized.namespaces[0].extern_rules == [namespace_rule]
