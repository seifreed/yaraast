"""Tests for metrics CLI helper functions (no mocks)."""

from __future__ import annotations

from textwrap import dedent
from typing import Any

import pytest

from yaraast.cli.commands import metrics as metrics_cmd
from yaraast.metrics.complexity import ComplexityAnalyzer
from yaraast.metrics.string_diagrams import StringDiagramGenerator
from yaraast.parser import Parser

try:
    from yaraast.metrics.dependency_graph import DependencyGraphGenerator
except ModuleNotFoundError:
    DependencyGraphGenerator = None


def _parse_yara(code: str) -> Any:
    parser = Parser()
    return parser.parse(dedent(code))


def test_metrics_helper_text_functions(
    capsys: pytest.CaptureFixture[str],
) -> None:
    if DependencyGraphGenerator is None:
        pytest.skip("graphviz package is not installed")
    code = """
    import "pe"

    rule helper_rule {
        strings:
            $a = "abc"
        condition:
            $a and pe.number_of_sections > 0
    }
    """
    ast = _parse_yara(code)

    analyzer = ComplexityAnalyzer()
    metrics = analyzer.analyze(ast)
    text = metrics_cmd._format_complexity_text(metrics)
    assert "YARA Rule Complexity Analysis" in text

    analysis = metrics_cmd._analyze_string_patterns(ast)
    output_text = metrics_cmd._format_string_analysis_output(analysis, "text")
    assert "YARA String Analysis" in output_text

    generator = DependencyGraphGenerator()
    generator.visit(ast)
    stats = generator.get_dependency_stats()
    text_graph = metrics_cmd._get_text_graph(stats, generator.dependencies)
    assert "Dependency Analysis" in text_graph

    metrics_cmd._display_text_fallback("rules.yar", ast, generator)
    captured = capsys.readouterr().out
    assert "Dependency Analysis" in captured


def test_metrics_graphviz_error_detection() -> None:
    err = Exception("failed to execute PosixPath('dot')")
    assert metrics_cmd._is_graphviz_not_found_error(err) is True


def test_metrics_pattern_helpers(capsys: pytest.CaptureFixture[str]) -> None:
    code = """
    rule helper_patterns {
        strings:
            $a = "abc"
            $b = { 6A 40 ?? }
            $c = /ab+c/
        condition:
            any of them
    }
    """
    ast = _parse_yara(code)
    generator = StringDiagramGenerator()

    metrics_cmd._display_text_pattern_analysis(generator, ast)
    metrics_cmd._display_pattern_statistics(generator)
    output = capsys.readouterr().out
    assert "String Pattern Analysis" in output
