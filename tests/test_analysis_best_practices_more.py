from __future__ import annotations

from yaraast.analysis.best_practices import AnalysisReport, BestPracticesAnalyzer
from yaraast.ast.strings import HexByte, HexString, HexWildcard
from yaraast.parser import Parser


def test_best_practices_report_helpers_and_integration_paths() -> None:
    report = AnalysisReport()
    report.add_suggestion("r1", "style", "info", "message", "line 1")
    report.add_suggestion("r2", "structure", "warning", "warn")
    report.add_suggestion("r3", "optimization", "error", "err")
    assert report.has_issues is True
    assert len(report.get_by_severity("info")) == 1
    assert len(report.get_by_category("style")) == 1
    assert report.suggestions[0].format() == "i [style] r1 (line 1): message"

    ast = Parser().parse(
        r"""
rule bad1 {
    strings:
        $1 = "ab"
        $a = "ab"
        $b = "a*b"
        $aa = "zzz"
        $ab = "zzzz"
        $dup = { 01 ?? ?? ?? }
        $dup = /(.+)+a.b/
    condition:
        $a
}

rule bad1 {
    condition:
        true
}

rule pe_only {
    condition:
        pe.is_pe
}
"""
    )
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


def test_best_practices_global_hex_patterns_and_helper_paths() -> None:
    ast = Parser().parse(
        """
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
"""
    )
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

    short_name_ast = Parser().parse(
        """
rule ab {
    meta:
        author = "x"
    strings:
        $a = "abcd"
    condition:
        $a
}
"""
    )
    short_report = BestPracticesAnalyzer().analyze(short_name_ast)
    assert any("more descriptive rule names" in s.message for s in short_report.suggestions)

    assert analyzer._levenshtein_distance("abc", "abc") == 0
    assert analyzer._levenshtein_distance("abc", "ab") == 1
    assert analyzer._levenshtein_distance("abc", "") == 3
