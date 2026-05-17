"""Additional tests for complexity metrics (no mocks)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import ForOfExpression, OfExpression
from yaraast.ast.expressions import BinaryExpression, BooleanLiteral
from yaraast.ast.rules import Rule
from yaraast.metrics.complexity import ComplexityAnalyzer
from yaraast.metrics.complexity_helpers import (
    calculate_cognitive_complexity,
    calculate_cyclomatic_complexity,
    calculate_expression_complexity,
)
from yaraast.metrics.complexity_reporting import analyze_file_complexity
from yaraast.parser import Parser


class _HashableDecision:
    operator = "and"

    def accept(self, visitor: object) -> object:
        return visitor

    def __hash__(self) -> int:
        return id(self)


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


def test_complexity_analyzer_accepts_raw_string_sets() -> None:
    ast = YaraFile(
        rules=[
            Rule(name="for_raw", condition=ForOfExpression("all", "them", condition=None)),
            Rule(name="of_raw", condition=OfExpression("any", ["$a", "$b"])),
            Rule(name="for_list", condition=ForOfExpression("any", ["$a"], BooleanLiteral(True))),
            Rule(
                name="of_nested",
                condition=OfExpression(
                    "any",
                    [BinaryExpression(BooleanLiteral(True), "and", BooleanLiteral(False))],
                ),
            ),
        ],
    )

    metrics = ComplexityAnalyzer().analyze(ast)

    assert metrics.for_of_expressions == 2
    assert metrics.of_expressions == 2
    assert metrics.total_binary_ops == 1


def test_complexity_expression_helpers() -> None:
    code = "rule r1 { condition: (1 + 2 == 3) and true }"
    ast = Parser().parse(code)
    expr = ast.rules[0].condition
    assert expr is not None

    assert calculate_expression_complexity(expr) >= 1
    assert calculate_cyclomatic_complexity(expr) >= 1
    assert calculate_cognitive_complexity(expr) >= 1


def test_cyclomatic_complexity_traverses_non_list_child_containers() -> None:
    decision = BinaryExpression(BooleanLiteral(True), "and", BooleanLiteral(False))
    hashable_decision = _HashableDecision()
    hashable_container = cast(Any, frozenset((hashable_decision,)))

    assert calculate_cyclomatic_complexity(OfExpression("any", [decision])) == 2
    assert calculate_cyclomatic_complexity(OfExpression("any", (decision,))) == 2
    assert calculate_cyclomatic_complexity(OfExpression("any", hashable_container)) == 2


def test_analyze_file_complexity(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.yar"
    file_path.write_text("rule r1 { condition: true }", encoding="utf-8")

    report = analyze_file_complexity(file_path)
    assert report["file"].endswith("sample.yar")
    assert "complexity" in report
