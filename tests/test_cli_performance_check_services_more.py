"""Additional tests for performance-check service helpers."""

from __future__ import annotations

from typing import Any, cast

import pytest

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


def test_filter_issues_rejects_invalid_limit() -> None:
    with pytest.raises(TypeError, match="limit must be an integer"):
        filter_issues(
            [_issue("r1", "short_string", "warning")],
            "all",
            cast(Any, True),
        )

    with pytest.raises(ValueError, match="limit must be at least 1"):
        filter_issues([_issue("r1", "short_string", "warning")], "all", 0)


@pytest.mark.parametrize("severity", [None, 123])
def test_filter_issues_rejects_non_string_severity(severity: object) -> None:
    with pytest.raises(TypeError, match="severity must be a string"):
        filter_issues([_issue("r1", "short_string", "warning")], severity, None)


@pytest.mark.parametrize("severity", ["", "xml", "info"])
def test_filter_issues_rejects_unknown_severity(severity: str) -> None:
    with pytest.raises(ValueError, match="severity must be one of: all, critical, warning"):
        filter_issues([_issue("r1", "short_string", "warning")], severity, None)


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
