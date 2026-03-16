"""Tests for analysis modules (no mocks)."""

from __future__ import annotations

from yaraast.analysis.best_practices import BestPracticesAnalyzer
from yaraast.analysis.optimization import OptimizationAnalyzer
from yaraast.analysis.rule_analyzer import RuleAnalyzer
from yaraast.analysis.string_usage import StringUsageAnalyzer
from yaraast.parser import Parser


def _parse_rule(text: str):
    parser = Parser()
    return parser.parse(text)


def test_string_usage_analyzer_unused_and_undefined() -> None:
    yara_text = """
rule test_rule {
    strings:
        $a = "abc"
        $b = "def"
        $unused = "zzz"
    condition:
        $a and #b > 0 and $missing
}
"""
    ast = _parse_rule(yara_text)
    analyzer = StringUsageAnalyzer()
    analyzer.analyze(ast)

    unused = analyzer.get_unused_strings("test_rule")
    assert "test_rule" in unused
    assert "$unused" in unused["test_rule"]

    undefined = analyzer.get_undefined_strings("test_rule")
    assert "test_rule" in undefined
    assert "$missing" in undefined["test_rule"]


def test_best_practices_analyzer_reports() -> None:
    yara_text = """
rule bp_rule {
    strings:
        $a = "x"
        $b = /test.{0,200}end/
    condition:
        $a or $b
}
"""
    ast = _parse_rule(yara_text)
    analyzer = BestPracticesAnalyzer()
    report = analyzer.analyze(ast)

    assert report is not None
    assert report.suggestions
    assert report.has_issues is False


def test_optimization_analyzer_report_format() -> None:
    yara_text = """
rule opt_rule {
    strings:
        $a = "HELLO"
        $b = { 48 45 4C 4C 4F }
    condition:
        $a or $b
}
"""
    ast = _parse_rule(yara_text)
    analyzer = OptimizationAnalyzer()
    report = analyzer.analyze(ast)

    assert report is not None
    assert report.statistics["total_suggestions"] >= 0


def test_rule_analyzer_summary() -> None:
    yara_text = """
import "pe"

rule analysis_rule {
    strings:
        $a = "abc"
    condition:
        $a and pe.is_pe
}
"""
    ast = _parse_rule(yara_text)
    analyzer = RuleAnalyzer()
    report = analyzer.analyze(ast)

    assert report["summary"]["total_rules"] == 1
    assert report["string_analysis"]["analysis_rule"]["unused"] == []
