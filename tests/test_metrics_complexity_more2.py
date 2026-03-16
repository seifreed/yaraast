"""Additional tests for complexity metrics (no mocks)."""

from __future__ import annotations

from pathlib import Path

from yaraast.metrics.complexity import ComplexityAnalyzer
from yaraast.metrics.complexity_helpers import (
    calculate_cognitive_complexity,
    calculate_cyclomatic_complexity,
    calculate_expression_complexity,
)
from yaraast.metrics.complexity_reporting import analyze_file_complexity
from yaraast.parser import Parser


def test_complexity_analyzer_basic_counts() -> None:
    code = """
import "pe"
rule r1 {
  strings:
    $a = "x"
  condition:
    $a
}
""".lstrip()
    ast = Parser().parse(code)
    analyzer = ComplexityAnalyzer()
    metrics = analyzer.analyze(ast)

    assert metrics.total_rules == 1
    assert metrics.total_imports == 1
    assert metrics.rules_with_strings == 1


def test_complexity_expression_helpers() -> None:
    code = "rule r1 { condition: (1 + 2 == 3) and true }"
    ast = Parser().parse(code)
    expr = ast.rules[0].condition

    assert calculate_expression_complexity(expr) >= 1
    assert calculate_cyclomatic_complexity(expr) >= 1
    assert calculate_cognitive_complexity(expr) >= 1


def test_analyze_file_complexity(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.yar"
    file_path.write_text("rule r1 { condition: true }")

    report = analyze_file_complexity(file_path)
    assert report["file"].endswith("sample.yar")
    assert "complexity" in report
