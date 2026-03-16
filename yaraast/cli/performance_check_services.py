"""Services for performance-check CLI (logic without IO)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from yaraast.cli.utils import read_text
from yaraast.parser.error_tolerant_parser import ErrorTolerantParser
from yaraast.performance.string_analyzer import StringPerformanceIssue, analyze_rule_performance


def parse_performance_file(input_file: Path) -> Any:
    """Parse a YARA file and return AST or None."""
    content = read_text(input_file)
    parser = ErrorTolerantParser()
    ast, _, _ = parser.parse_with_errors(content)
    return ast


def analyze_rule_issues(rule: Any) -> list[StringPerformanceIssue]:
    """Analyze a single rule for performance issues."""
    return analyze_rule_performance(rule)


def filter_issues(
    issues: list[StringPerformanceIssue],
    severity: str,
    limit: int | None,
) -> list[StringPerformanceIssue]:
    """Filter issues by severity and limit."""
    if severity == "warning":
        issues = [i for i in issues if i.severity == "warning"]
    elif severity == "critical":
        issues = [i for i in issues if i.severity == "critical"]

    if limit:
        issues = issues[:limit]

    return issues


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
