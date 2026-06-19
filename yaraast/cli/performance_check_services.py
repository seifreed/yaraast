"""Services for performance-check CLI (logic without IO)."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any

from yaraast.cli.utils import read_text
from yaraast.dialects import YaraDialect, detect_dialect
from yaraast.errors import ParseError
from yaraast.parser.error_tolerant_parser import ErrorTolerantParser
from yaraast.parser.source import parse_yara_source
from yaraast.performance.string_analyzer import StringPerformanceIssue
from yaraast.performance.string_performance_checks import analyze_rule_performance
from yaraast.shared.numeric_validation import validate_positive_int_setting


class Severity(StrEnum):
    """Issue severity levels."""

    WARNING = "warning"
    CRITICAL = "critical"


_FILTER_SEVERITIES = frozenset({"all", Severity.WARNING, Severity.CRITICAL})


def parse_performance_file(input_file: Path) -> Any:
    """Parse a YARA file and return AST or None."""
    content = read_text(input_file)
    dialect = detect_dialect(content)
    if dialect == YaraDialect.YARA_L:
        msg = "YARA-L input is not supported by performance-check; use YARA-L tooling instead"
        raise ParseError(msg)
    if dialect == YaraDialect.YARA_X:
        return parse_yara_source(content)
    return ErrorTolerantParser().parse(content).ast


def analyze_rule_issues(rule: Any) -> list[StringPerformanceIssue]:
    """Analyze a single rule for performance issues."""
    return analyze_rule_performance(rule)


def filter_issues(
    issues: list[StringPerformanceIssue],
    severity: object,
    limit: int | None,
) -> list[StringPerformanceIssue]:
    """Filter issues by severity and limit.

    Accepts both Severity enum values and plain strings for backward
    compatibility (Severity inherits from str).
    """
    severity = _require_filter_severity(severity)
    if severity == Severity.WARNING:
        issues = [i for i in issues if i.severity == Severity.WARNING]
    elif severity == Severity.CRITICAL:
        issues = [i for i in issues if i.severity == Severity.CRITICAL]

    if limit is not None:
        validate_positive_int_setting(limit, "limit")

    if limit is not None:
        issues = issues[:limit]

    return issues


def _require_filter_severity(severity: object) -> str:
    if not isinstance(severity, str):
        raise TypeError("severity must be a string")
    if severity not in _FILTER_SEVERITIES:
        valid = ", ".join(sorted(_FILTER_SEVERITIES))
        raise ValueError(f"severity must be one of: {valid}")
    return severity


def summarize_issues(issues: list[StringPerformanceIssue]) -> dict[str, Any]:
    """Summarize issues by type and severity."""
    issue_types: dict[str, dict[str, Any]] = {}
    for issue in issues:
        if issue.issue_type not in issue_types:
            issue_types[issue.issue_type] = {
                "count": 0,
                "critical": 0,
                "rules": set(),
            }
        entry = issue_types[issue.issue_type]
        entry["count"] += 1
        if issue.severity == "critical":
            entry["critical"] += 1
        entry["rules"].add(issue.rule_name)

    return issue_types
