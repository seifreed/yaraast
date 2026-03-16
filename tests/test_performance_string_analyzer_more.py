"""More tests for performance string analyzer (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from yaraast.parser import Parser
from yaraast.performance.string_analyzer import StringPatternAnalyzer, analyze_rule_performance


def _parse_yara(code: str):
    parser = Parser()
    return parser.parse(dedent(code))


def test_string_pattern_analyzer_patterns_and_stats() -> None:
    analyzer = StringPatternAnalyzer()
    patterns = [
        "alpha",
        "alpha",
        "alphabet",
        "beta",
        "zeta",
        "delta",
        "alpha_suffix",
        "beta_suffix",
    ]
    result = analyzer.analyze_patterns(patterns)

    assert result["total"] == len(patterns)
    assert result["duplicates"]["alpha"] == 2
    assert result["common_prefixes"]
    assert result["common_suffixes"]
    assert result["length_statistics"]["min"] > 0

    stats = analyzer.get_statistics()
    assert stats["total_strings"] == len(patterns)
    analyzer.reset_statistics()
    assert analyzer.get_statistics()["total_strings"] == 0


def test_string_pattern_analyzer_rule_and_file() -> None:
    code = """
    rule perf_rules {
        strings:
            $a = "aa"
            $b = "bbb"
            $c = /ab+c/
            $d = { 6A 40 ?? 0F }
        condition:
            any of them
    }
    rule perf_rules2 {
        strings:
            $a = "aa"
        condition:
            $a
    }
    """
    ast = _parse_yara(code)
    analyzer = StringPatternAnalyzer()

    rule_analysis = analyzer.analyze_rule(ast.rules[0])
    assert rule_analysis["rule"] == "perf_rules"
    assert rule_analysis["pattern_types"]["plain"] >= 1

    file_analysis = analyzer.analyze_file(ast)
    assert file_analysis["global"]["total"] >= 1
    assert file_analysis["cross_rule"]["total_shared"] >= 1


def test_analyze_rule_performance_issues() -> None:
    code = """
    rule perf_issue {
        strings:
            $a = "aa"
            $b = /ab+c/
        condition:
            $a or $b
    }
    """
    ast = _parse_yara(code)
    issues = analyze_rule_performance(ast.rules[0])

    assert any(issue.issue_type == "short_string" for issue in issues)
    assert any(issue.issue_type == "expensive_regex" for issue in issues)
