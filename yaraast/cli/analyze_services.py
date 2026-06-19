"""Service helpers for analyze CLI (logic without IO)."""

from __future__ import annotations

from typing import Any

from yaraast.analysis.best_practices import AnalysisReport


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


def _get_level_style(level: str) -> str:
    """Get console style for impact level."""
    return {"high": "red", "medium": "yellow", "low": "blue"}.get(level, "white")
