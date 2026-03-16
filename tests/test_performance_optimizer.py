"""Tests for performance optimizer utilities."""

from __future__ import annotations

from pathlib import Path

from yaraast.ast.strings import PlainString
from yaraast.parser import Parser
from yaraast.performance.optimizer import PerformanceOptimizer, optimize_yara_file


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
    assert optimized.strings[0].value == "a"
    stats = optimizer.get_statistics()
    assert stats["rules_optimized"] == 1


def test_performance_optimizer_file(tmp_path: Path) -> None:
    file_path = tmp_path / "rules.yar"
    file_path.write_text(_sample_rule())

    optimized_ast, stats = optimize_yara_file(str(file_path))
    assert optimized_ast.rules
    assert stats["rules_optimized"] >= 0
