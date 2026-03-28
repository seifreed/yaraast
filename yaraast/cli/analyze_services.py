"""Service helpers for analyze CLI (logic without IO)."""

from __future__ import annotations

from typing import Any

from yaraast.analysis.best_practices import AnalysisReport, BestPracticesAnalyzer
from yaraast.analysis.optimization import OptimizationAnalyzer, OptimizationReport
from yaraast.ast.base import YaraFile
from yaraast.cli.analyze_report_helpers import (
    add_best_practices_section,
    add_optimizations_section,
    add_summary_section,
    best_report_to_dict,
    generate_json_report,
    generate_text_report,
    opt_report_to_dict,
)
from yaraast.cli.utils import parse_yara_file


def _parse_rule_file(rule_file: str) -> Any:
    """Parse a YARA rule file."""
    return parse_yara_file(rule_file)


def _analyze_optimizations(ast: YaraFile) -> OptimizationReport:
    """Analyze AST for optimization suggestions."""
    analyzer = OptimizationAnalyzer()
    return analyzer.analyze(ast)


def _analyze_best_practices(ast: YaraFile) -> AnalysisReport:
    """Analyze AST for best practices."""
    analyzer = BestPracticesAnalyzer()
    return analyzer.analyze(ast)


def _get_severity_counts(report: AnalysisReport) -> tuple[list[Any], list[Any], list[Any]]:
    """Get counts by severity."""
    errors = report.get_by_severity("error")
    warnings = report.get_by_severity("warning")
    info = report.get_by_severity("info")
    return errors, warnings, info


def _filter_suggestions(suggestions: list[Any], category: str) -> list[Any]:
    """Filter suggestions by category."""
    if category != "all":
        return [s for s in suggestions if s.category == category]
    return suggestions


def _best_report_to_dict(report: AnalysisReport) -> dict[str, Any]:
    return best_report_to_dict(report)


def _opt_report_to_dict(report: OptimizationReport) -> dict[str, Any]:
    return opt_report_to_dict(report)


def _get_level_style(level: str) -> str:
    """Get console style for impact level."""
    return {"high": "red", "medium": "yellow", "low": "blue"}.get(level, "white")


def _generate_json_report(
    rule_file: str, bp_report: AnalysisReport, opt_report: OptimizationReport
) -> dict[str, Any]:
    """Generate JSON report for full analysis."""
    return generate_json_report(rule_file, bp_report, opt_report)


def _generate_text_report(
    rule_file: str, bp_report: AnalysisReport, opt_report: OptimizationReport
) -> str:
    """Generate text format report."""
    return generate_text_report(rule_file, bp_report, opt_report)


def _add_best_practices_section(lines: list[str], bp_report: AnalysisReport) -> None:
    """Add best practices section to report."""
    add_best_practices_section(lines, bp_report)


def _add_optimizations_section(lines: list[str], opt_report: OptimizationReport) -> None:
    """Add optimizations section to report."""
    add_optimizations_section(lines, opt_report)


def _add_summary_section(
    lines: list[str], bp_report: AnalysisReport, opt_report: OptimizationReport
) -> None:
    """Add summary section to report."""
    add_summary_section(lines, bp_report, opt_report)
