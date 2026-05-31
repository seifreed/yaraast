from __future__ import annotations

from yaraast.analysis.best_practices import AnalysisReport, BestPracticesAnalyzer
from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    IntegerLiteral,
    StringCount,
    StringWildcard,
)
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString, HexWildcard, PlainString
from yaraast.parser import Parser
from yaraast.parser.source import parse_yara_source


def test_best_practices_report_helpers_and_integration_paths() -> None:
    report = AnalysisReport()
    report.add_suggestion("r1", "style", "info", "message", "line 1")
    report.add_suggestion("r2", "structure", "warning", "warn")
    report.add_suggestion("r3", "optimization", "error", "err")
    assert report.has_issues is True
    assert len(report.get_by_severity("info")) == 1
    assert len(report.get_by_category("style")) == 1
    assert report.suggestions[0].format() == "i [style] r1 (line 1): message"

    ast = Parser().parse(r"""
rule bad1 {
    strings:
        $1 = "ab"
        $a = "ab"
        $b = "a*b"
        $aa = "zzz"
        $ab = "zzzz"
        $dup = { 01 ?? ?? ?? }
        $regex = /(.+)+a.b/
    condition:
        $a
}

rule bad1_extra {
    condition:
        true
}

rule pe_only {
    condition:
        pe.is_pe
}
""")
    ast.rules[1].name = "bad1"
    ast.rules[0].strings.append(PlainString(identifier="$dup", value="duplicate"))
    analyzer = BestPracticesAnalyzer()
    result = analyzer.analyze(ast)

    messages = [s.message for s in result.suggestions]
    assert any("Duplicate rule name" in m for m in messages)
    assert any("Rule name should start with letter" in m for m in messages)
    assert any("should follow $name convention" in m for m in messages)
    assert any("might cause false positives" in m for m in messages)
    assert any("consider regex?" in m for m in messages)
    assert any("many wildcards" in m for m in messages)
    assert any("unescaped dots" in m for m in messages)
    assert any("catastrophic backtracking" in m for m in messages)
    assert any("Duplicate string identifier '$dup'" in m for m in messages)
    assert any("Similar string names" in m for m in messages)
    assert any("defined but never used" in m for m in messages)
    assert any("Rule has no strings defined" in m for m in messages)
    assert result.statistics == {"total_rules": 3, "total_imports": 0}


def test_best_practices_analyzer_handles_byte_plain_strings() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="byte_rule",
                strings=[PlainString(identifier="$b", value=b"a*b")],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    report = BestPracticesAnalyzer().analyze(ast)
    messages = [suggestion.message for suggestion in report.suggestions]

    assert any("Short string" in message for message in messages)
    assert any("consider regex?" in message for message in messages)


def test_best_practices_treats_string_count_as_string_usage() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="count_rule",
                strings=[PlainString(identifier="$a", value="value")],
                condition=BinaryExpression(StringCount("$a"), ">", IntegerLiteral(0)),
            )
        ]
    )

    report = BestPracticesAnalyzer().analyze(ast)

    assert not any(
        "String '$a' is defined but never used" in suggestion.message
        for suggestion in report.suggestions
    )


def test_best_practices_treats_condition_string_set_forms_as_usage() -> None:
    ast = Parser().parse("""
rule set_usage {
    strings:
        $api1 = "aaaa"
        $api2 = "bbbb"
        $pos = "cccc"
        $range = "dddd"
    condition:
        any of ($api*) and $pos at 0 and $range in (0..filesize)
}

rule them_usage {
    strings:
        $one = "eeee"
        $two = "ffff"
    condition:
        all of them
}
""")

    report = BestPracticesAnalyzer().analyze(ast)

    unused_messages = [
        suggestion.message
        for suggestion in report.suggestions
        if "defined but never used" in suggestion.message
    ]
    assert unused_messages == []


def test_best_practices_respects_yarax_with_local_string_shadowing() -> None:
    ast = parse_yara_source("""
rule shadowed_string {
    strings:
        $a = "value"
    condition:
        with $a = 1: $a > 0
}

rule declaration_value_uses_string {
    strings:
        $a = "value"
    condition:
        with local = $a: local
}
""")

    report = BestPracticesAnalyzer().analyze(ast)
    unused_messages = [
        suggestion.message
        for suggestion in report.suggestions
        if "defined but never used" in suggestion.message
    ]

    assert "String '$a' is defined but never used in condition" in unused_messages
    assert len(unused_messages) == 1


def test_best_practices_respects_yarax_with_local_string_count_shadowing() -> None:
    ast = parse_yara_source("""
rule shadowed_count {
    strings:
        $a = "value"
    condition:
        with $a = 1: #a > 0
}
""")

    report = BestPracticesAnalyzer().analyze(ast)
    unused_messages = [
        suggestion.message
        for suggestion in report.suggestions
        if "defined but never used" in suggestion.message
    ]

    assert unused_messages == ["String '$a' is defined but never used in condition"]


def test_best_practices_named_wildcard_ignores_anonymous_internal_ids() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="anonymous_usage",
                strings=[
                    PlainString(identifier="$alpha", value="value"),
                    PlainString(identifier="$anon_1", value="anonymous", is_anonymous=True),
                ],
                condition=StringWildcard("$a*"),
            )
        ]
    )

    report = BestPracticesAnalyzer().analyze(ast)
    unused_messages = [
        suggestion.message
        for suggestion in report.suggestions
        if "defined but never used" in suggestion.message
    ]

    assert "String '$anon_1' is defined but never used in condition" in unused_messages
    assert "String '$alpha' is defined but never used in condition" not in unused_messages


def test_best_practices_global_wildcard_counts_anonymous_strings_as_used() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="anonymous_global_usage",
                strings=[
                    PlainString(identifier="$alpha", value="value"),
                    PlainString(identifier="$anon_1", value="anonymous", is_anonymous=True),
                ],
                condition=StringWildcard("$*"),
            )
        ]
    )

    report = BestPracticesAnalyzer().analyze(ast)

    assert not any(
        "defined but never used" in suggestion.message for suggestion in report.suggestions
    )


def test_best_practices_global_hex_patterns_and_helper_paths() -> None:
    ast = Parser().parse("""
rule hx1 {
    meta:
        author = "x"
    strings:
        $a = { 4D 5A 90 00 }
    condition:
        $a
}

rule hx2 {
    meta:
        author = "x"
    strings:
        $b = { 4D 5A 90 FF }
    condition:
        $b
}

rule bare {
    condition:
        true
}
""")
    analyzer = BestPracticesAnalyzer()
    analyzer.analyze(ast)

    analyzer.report = AnalysisReport()
    analyzer._hex_patterns = [
        (
            "$a",
            HexString(
                "$a",
                tokens=[HexByte(0x4D), HexByte(0x5A), HexByte(0x90), HexByte(0x00), HexByte(0xAA)],
            ),
        ),
        (
            "$b",
            HexString(
                "$b",
                tokens=[HexByte(0x4D), HexByte(0x5A), HexByte(0x90), HexByte(0x00), HexByte(0xBB)],
            ),
        ),
    ]
    analyzer._analyze_global_patterns()
    assert any(
        s.rule_name == "global" and "Similar hex patterns" in s.message
        for s in analyzer.report.suggestions
    )

    prefix = analyzer._get_hex_prefix(
        HexString("$h", tokens=[HexByte(0x4D), HexWildcard(), HexByte(0x5A)]),
        4,
    )
    assert prefix == (0x4D, None, 0x5A)

    short_name_ast = Parser().parse("""
rule ab {
    meta:
        author = "x"
    strings:
        $a = "abcd"
    condition:
        $a
}
""")
    short_report = BestPracticesAnalyzer().analyze(short_name_ast)
    assert any("more descriptive rule names" in s.message for s in short_report.suggestions)

    assert analyzer._levenshtein_distance("abc", "abc") == 0
    assert analyzer._levenshtein_distance("abc", "ab") == 1
    assert analyzer._levenshtein_distance("abc", "") == 3


def test_best_practices_global_hex_patterns_include_all_rules() -> None:
    ast = Parser().parse("""
rule hx1 {
    strings:
        $a = { 4D 5A 90 00 AA }
    condition:
        $a
}

rule hx2 {
    strings:
        $b = { 4D 5A 90 00 BB }
    condition:
        $b
}
""")

    report = BestPracticesAnalyzer().analyze(ast)

    assert any(
        suggestion.rule_name == "global" and "Similar hex patterns: $a, $b" in suggestion.message
        for suggestion in report.suggestions
    )
