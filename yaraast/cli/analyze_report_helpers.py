"""Formatting and serialization helpers for analyze CLI services."""

from __future__ import annotations

from typing import Any


def best_report_to_dict(report: Any) -> dict[str, Any]:
    return {
        "statistics": report.statistics,
        "suggestions": [
            {
                "rule": s.rule_name,
                "category": s.category,
                "severity": s.severity,
                "message": s.message,
                "location": s.location,
            }
            for s in report.suggestions
        ],
    }


def opt_report_to_dict(report: Any) -> dict[str, Any]:
    return {
        "statistics": report.statistics,
        "heuristic": getattr(report, "is_heuristic", True),
        "suggestions": [
            {
                "rule": s.rule_name,
                "type": s.optimization_type,
                "impact": s.impact,
                "description": s.description,
                "code_before": s.code_before,
                "code_after": s.code_after,
            }
            for s in report.suggestions
        ],
    }


def generate_json_report(rule_file: str, bp_report: Any, opt_report: Any) -> dict[str, Any]:
    return {
        "file": rule_file,
        "best_practices": best_report_to_dict(bp_report),
        "optimization": opt_report_to_dict(opt_report),
    }


def generate_text_report(rule_file: str, bp_report: Any, opt_report: Any) -> str:
    lines: list[str] = [f"AST Analysis Report: {rule_file}", "=" * 50]
    add_best_practices_section(lines, bp_report)
    add_optimizations_section(lines, opt_report)
    add_summary_section(lines, bp_report, opt_report)
    return "\n".join(lines)


def add_best_practices_section(lines: list[str], bp_report: Any) -> None:
    lines.append("\nBEST PRACTICES")
    lines.append("-" * 20)
    for severity in ["error", "warning", "info"]:
        items = bp_report.get_by_severity(severity)
        if items:
            lines.append(f"\n{severity.upper()}S ({len(items)}):")
            for suggestion in items:
                lines.append(f"  {suggestion.format()}")


def add_optimizations_section(lines: list[str], opt_report: Any) -> None:
    lines.append("\n\nOPTIMIZATIONS")
    lines.append("-" * 20)
    for impact_level in ["high", "medium", "low"]:
        items = [s for s in opt_report.suggestions if s.impact == impact_level]
        if items:
            lines.append(f"\n{impact_level.upper()} IMPACT ({len(items)}):")
            for suggestion in items:
                lines.append(f"  {suggestion.format()}")


def add_summary_section(lines: list[str], bp_report: Any, opt_report: Any) -> None:
    lines.append("\n\nSUMMARY")
    lines.append("-" * 20)
    lines.append(
        f"Total issues: {len(bp_report.get_by_severity('error')) + len(bp_report.get_by_severity('warning'))}"
    )
    lines.append(f"Total suggestions: {len(bp_report.suggestions) + len(opt_report.suggestions)}")
