"""Rule-level performance checks for string-heavy YARA rules."""

from __future__ import annotations

from yaraast.ast.rules import Rule
from yaraast.ast.strings import PlainString, RegexString
from yaraast.performance.string_analysis_helpers import string_value_length
from yaraast.performance.string_analyzer import StringPerformanceIssue


def analyze_rule_performance(rule: Rule) -> list[StringPerformanceIssue]:
    issues: list[StringPerformanceIssue] = []
    if rule.strings:
        for string_def in rule.strings:
            if isinstance(string_def, RegexString):
                issues.append(
                    StringPerformanceIssue(
                        rule_name=rule.name,
                        string_id=string_def.identifier,
                        issue_type="expensive_regex",
                        severity="warning",
                        description="Regular expression may have performance impact",
                        suggestion="Consider using plain strings or hex patterns when possible",
                    ),
                )
            elif isinstance(string_def, PlainString) and string_value_length(string_def.value) < 3:
                issues.append(
                    StringPerformanceIssue(
                        rule_name=rule.name,
                        string_id=string_def.identifier,
                        issue_type="short_string",
                        severity="info",
                        description="Very short string may cause false positives",
                        suggestion="Use longer, more specific strings when possible",
                    ),
                )
    return issues
