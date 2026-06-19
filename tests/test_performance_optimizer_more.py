"""More tests for performance optimizer (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BinaryExpression, IntegerLiteral
from yaraast.ast.rules import Rule
from yaraast.ast.strings import PlainString, RegexString
from yaraast.parser import Parser
from yaraast.performance.optimizer import PerformanceOptimizer


def _parse_yara(code: str) -> YaraFile:
    parser = Parser()
    return parser.parse(dedent(code))


def test_performance_optimizer_rule_and_file() -> None:
    code = """
    rule perf_opt {
        strings:
            $a = "abcd"
            $b = /ab+c/
            $c = { 6A 40 ?? }
        condition:
            $a or $b or $c
    }
    rule perf_opt2 {
        strings:
            $a = "a"
        condition:
            $a
    }
    """
    ast = _parse_yara(code)
    optimizer = PerformanceOptimizer()

    rule = ast.rules[0]
    optimized_rule = optimizer.optimize_rule(rule, strategy="balanced")
    assert optimized_rule is not rule
    assert isinstance(optimized_rule.strings[0], PlainString)
    assert optimized_rule.strings[0].identifier == "$a"
    assert isinstance(optimized_rule.strings[-1], RegexString)

    optimized_file = optimizer.optimize(ast, strategy="speed")
    assert optimized_file is not ast
    assert [string.identifier for string in ast.rules[0].strings] == ["$a", "$b", "$c"]

    stats = optimizer.get_statistics()
    assert stats["rules_optimized"] >= 1


def test_performance_optimizer_counts_condition_simplifications() -> None:
    rule = Rule(
        name="cond",
        condition=BinaryExpression(IntegerLiteral(1), "==", IntegerLiteral(1)),
    )

    optimizer = PerformanceOptimizer()
    optimizer.optimize_rule(rule)

    assert optimizer.get_statistics()["conditions_simplified"] == 1

    optimizer2 = PerformanceOptimizer()
    optimizer2.optimize(YaraFile(rules=[rule]))

    assert optimizer2.get_statistics()["conditions_simplified"] == 1
