"""Additional tests for performance-check service helpers."""

from __future__ import annotations

from yaraast.cli.performance_check_services import filter_issues, summarize_issues
from yaraast.performance.string_analyzer import StringPerformanceIssue


def _issue(rule_name: str, issue_type: str, severity: str) -> StringPerformanceIssue:
    return StringPerformanceIssue(
        rule_name=rule_name,
        string_id="$a",
        issue_type=issue_type,
        severity=severity,
        description="desc",
        suggestion="fix",
    )


def test_filter_issues_applies_warning_filter_and_limit() -> None:
    issues = [
        _issue("r1", "short_string", "warning"),
        _issue("r2", "short_string", "critical"),
        _issue("r3", "slow_regex", "warning"),
    ]

    filtered = filter_issues(issues, "warning", 1)

    assert len(filtered) == 1
    assert filtered[0].severity == "warning"
    assert filtered[0].rule_name == "r1"


def test_summarize_issues_counts_criticals_and_rules() -> None:
    issues = [
        _issue("r1", "short_string", "critical"),
        _issue("r2", "short_string", "warning"),
        _issue("r1", "short_string", "critical"),
        _issue("r3", "slow_regex", "warning"),
    ]

    summary = summarize_issues(issues)

    assert summary["short_string"]["count"] == 3
    assert summary["short_string"]["critical"] == 2
    assert summary["short_string"]["rules"] == {"r1", "r2"}
    assert summary["slow_regex"]["count"] == 1
    assert summary["slow_regex"]["critical"] == 0
