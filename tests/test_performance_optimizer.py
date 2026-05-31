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


def _yarax_rule() -> str:
    return "rule x { condition: with xs = [1]: match xs { _ => true } }"


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


def test_performance_optimizer_file(tmp_path: Path) -> None:
    file_path = tmp_path / "rules.yar"
    file_path.write_text(_sample_rule(), encoding="utf-8")

    optimized_ast, stats = optimize_yara_file(str(file_path))
    assert optimized_ast.rules
    assert stats["rules_optimized"] >= 0


def test_optimize_yara_file_accepts_yarax_and_writes_yarax(tmp_path: Path) -> None:
    file_path = tmp_path / "x.yar"
    output_path = tmp_path / "x_out.yar"
    file_path.write_text(_yarax_rule(), encoding="utf-8")

    optimized_ast, stats = optimize_yara_file(str(file_path), output_path=str(output_path))

    assert optimized_ast.rules[0].name == "x"
    assert stats["rules_optimized"] >= 0
    output = output_path.read_text(encoding="utf-8")
    assert "with xs = [1]" in output
    assert "match xs" in output
