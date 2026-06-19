"""Tests for performance optimizer utilities."""

from __future__ import annotations

from yaraast.ast.strings import PlainString
from yaraast.parser import Parser
from yaraast.performance.optimizer import PerformanceOptimizer


def _sample_rule() -> str:
    return """
rule perf_rule {
    strings:
        $a = "abc"
        $b = /test.*/
    condition:
        any of them
}
"""
def test_performance_optimizer_rule_sorting() -> None:
    parser = Parser()
    ast = parser.parse(_sample_rule())
    rule = ast.rules[0]

    # Force a longer string first to verify sort
    rule.strings = [
        PlainString(identifier="$b", value="longer"),
        PlainString(identifier="$a", value="a"),
    ]

    optimizer = PerformanceOptimizer()
    optimized = optimizer.optimize_rule(rule, strategy="balanced")
    first_string = optimized.strings[0]
    assert isinstance(first_string, PlainString)
    assert first_string.value == "a"
    stats = optimizer.get_statistics()
    assert stats["rules_optimized"] == 1


def test_performance_optimizer_string_sorting_uses_utf8_byte_length() -> None:
    parser = Parser()
    ast = parser.parse(_sample_rule())
    rule = ast.rules[0]
    rule.strings = [
        PlainString(identifier="$unicode", value="éé"),
        PlainString(identifier="$ascii", value="abc"),
    ]

    optimizer = PerformanceOptimizer()
    optimized = optimizer.optimize_rule(rule, strategy="speed")

    assert [string.identifier for string in optimized.strings] == ["$ascii", "$unicode"]
