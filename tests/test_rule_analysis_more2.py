from __future__ import annotations

from yaraast.analysis import RuleAnalyzer
from yaraast.parser import Parser


def test_rule_analyzer_analyze_rule_and_report_paths() -> None:
    yara_code = """
rule detailed : t1 t2 {
    meta:
        score = 10
    strings:
        $a = "used"
        $b = "unused"
    condition:
        $a
}
"""
    ast = Parser().parse(yara_code)
    analyzer = RuleAnalyzer()

    rule_analysis = analyzer.analyze_rule(ast.rules[0])
    assert rule_analysis == {
        "name": "detailed",
        "string_count": 2,
        "has_condition": True,
        "modifiers": [],
        "tags": ["t1", "t2"],
        "meta_count": 1,
        "unused_strings": ["$b"],
    }

    report = analyzer.get_rule_report("detailed", ast)
    assert report is not None
    assert report["name"] == "detailed"
    assert report["string_count"] == 2
    assert report["dependencies"] == []
    assert report["dependents"] == []
    assert report["transitive_dependencies"] == []
    assert any(rec["type"] == "unused_strings" for rec in report["recommendations"])

    assert analyzer.get_rule_report("missing", ast) is None


def test_rule_analyzer_recommendations_and_metrics_paths() -> None:
    yara_code = """
rule rule_a {
    condition:
        rule_b
}

rule rule_b {
    condition:
        rule_a
}

rule heavy {
    strings:
        $s1 = "one"
        $s2 = "two"
        $s3 = "three"
        $s4 = "four"
        $s5 = "five"
        $s6 = "six"
        $s7 = "seven"
    condition:
        $s1 and rule_a and rule_b and helper1 and helper2 and helper3 and helper4
}

rule helper1 { condition: true }
rule helper2 { condition: true }
rule helper3 { condition: true }
rule helper4 { condition: true }
"""
    ast = Parser().parse(yara_code)
    analyzer = RuleAnalyzer()
    results = analyzer.analyze(ast)

    metrics = results["quality_metrics"]
    assert metrics["average_dependencies"] > 0
    assert metrics["max_dependencies"] >= 6
    assert metrics["independence_ratio"] < 1
    assert metrics["circular_dependency_score"] == 1
    assert 0 <= metrics["overall_quality_score"] <= 100

    recs = results["recommendations"]
    assert any(r["type"] == "circular_dependency" and r["rule"] == "rule_a" for r in recs)
    assert any(r["type"] == "high_dependency" and r["rule"] == "heavy" for r in recs)
    assert any(r["type"] == "low_string_usage" and r["rule"] == "heavy" for r in recs)


def test_rule_analyzer_rule_without_optional_fields() -> None:
    ast = Parser().parse("rule bare { condition: true }")
    analyzer = RuleAnalyzer()
    result = analyzer.analyze_rule(ast.rules[0])
    assert result == {
        "name": "bare",
        "string_count": 0,
        "has_condition": True,
        "modifiers": [],
        "tags": [],
        "meta_count": 0,
        "unused_strings": [],
    }
