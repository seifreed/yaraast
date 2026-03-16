"""Tests for string performance analyzer."""

from __future__ import annotations

from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Rule
from yaraast.ast.strings import PlainString, RegexString
from yaraast.performance.string_analyzer import (
    StringPatternAnalyzer,
    _estimate_rule_cost,
    analyze_rule_performance,
)


def test_string_pattern_analyzer_duplicates_and_prefixes() -> None:
    analyzer = StringPatternAnalyzer()
    patterns = ["abcd", "abce", "abcd", "zzabc"]
    result = analyzer.analyze_patterns(patterns)
    assert result["duplicates"]
    assert result["common_prefixes"]
    assert result["common_suffixes"]


def test_string_pattern_analyzer_rule() -> None:
    rule = Rule(
        name="rule1",
        condition=BooleanLiteral(True),
        strings=[PlainString("$a", "ab"), PlainString("$b", "cd")],
    )
    analyzer = StringPatternAnalyzer()
    analysis = analyzer.analyze_rule(rule)
    assert analysis["rule"] == "rule1"
    assert analysis["total"] == 2


def test_analyze_rule_performance_and_cost() -> None:
    rule = Rule(
        name="rule2",
        condition=BooleanLiteral(True),
        strings=[PlainString("$a", "ab"), RegexString("$b", ".*")],
    )
    issues = analyze_rule_performance(rule)
    assert issues

    cost = _estimate_rule_cost(rule)
    assert cost > 0
