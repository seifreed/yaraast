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
