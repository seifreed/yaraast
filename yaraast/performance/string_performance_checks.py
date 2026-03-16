"""Rule-level performance checks for string-heavy YARA rules."""

from __future__ import annotations

from yaraast.ast.strings import HexString, PlainString, RegexString
from yaraast.performance.string_analyzer import StringPerformanceIssue


def analyze_rule_performance(rule) -> list[StringPerformanceIssue]:
    issues = []
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
            elif isinstance(string_def, PlainString) and len(string_def.value) < 3:
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


def estimate_rule_cost(rule) -> int:
    cost = 0
    if rule.strings:
        for string_def in rule.strings:
            if isinstance(string_def, PlainString):
                cost += 1
            elif isinstance(string_def, HexString):
                cost += 2
            elif isinstance(string_def, RegexString):
                cost += 10
    if rule.condition:
        condition_str = str(rule.condition)
        cost += condition_str.count(" and ") * 2
        cost += condition_str.count(" or ") * 2
        cost += condition_str.count("for ") * 5
    return cost
