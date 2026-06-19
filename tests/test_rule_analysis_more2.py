from __future__ import annotations

from yaraast.analysis import RuleAnalyzer
from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Rule
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
    report = analyzer.analyze(ast)
    assert report["summary"]["total_rules"] == 1
    assert report["string_analysis"]["detailed"]["defined"] == ["$a", "$b"]
    assert report["dependency_analysis"]["dependency_graph"]["detailed"]["depends_on"] == []
    assert any(rec["type"] == "unused_strings" for rec in report["recommendations"])
    assert report["summary"]["total_strings"] == 2
    assert report["quality_metrics"]["string_usage_efficiency"] == 0.5


def test_rule_report_sorts_transitive_dependencies() -> None:
    dependency_names = [
        "dep_z",
        "dep_a",
        "dep_m",
        "dep_b",
        "dep_y",
        "dep_c",
        "dep_x",
        "dep_d",
    ]
    yara_code = "\n".join(
        [
            "rule target { condition: " + " and ".join(dependency_names) + " }",
            *[f"rule {name} {{ condition: true }}" for name in dependency_names],
        ]
    )
    ast = Parser().parse(yara_code)

    report = RuleAnalyzer().analyze(ast)

    assert report["dependency_analysis"]["dependency_order"][-1] == "target"
    assert set(report["dependency_analysis"]["dependency_graph"]["target"]["depends_on"]) == set(
        dependency_names,
    )


def test_rule_report_preserves_falsy_present_rule() -> None:
    class FalsyRule(Rule):
        def __bool__(self) -> bool:
            return False

    ast = YaraFile(rules=[FalsyRule(name="target", condition=BooleanLiteral(True))])

    report = RuleAnalyzer().analyze(ast)
    assert report["summary"]["total_rules"] == 1


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
    result = analyzer.analyze(ast)
    assert result["summary"]["total_rules"] == 1
    assert result["string_analysis"]["bare"]["defined"] == []
    assert result["dependency_analysis"]["dependency_graph"]["bare"]["is_independent"] is True


def test_rule_analyzer_does_not_expose_dead_single_rule_helper() -> None:
    assert not hasattr(RuleAnalyzer(), "analyze_rule")
