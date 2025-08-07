"""Test rule analysis tools."""

from yaraast.analysis import DependencyAnalyzer, RuleAnalyzer, StringUsageAnalyzer
from yaraast.parser import Parser


def test_unused_string_detection() -> None:
    """Test detection of unused strings."""
    yara_code = """
rule test_unused {
    strings:
        $used1 = "used"
        $used2 = { 48 65 6C 6C 6F }
        $unused1 = "not used"
        $unused2 = /regex_not_used/

    condition:
        $used1 and $used2
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    analyzer = StringUsageAnalyzer()
    results = analyzer.analyze(ast)

    assert "test_unused" in results
    rule_analysis = results["test_unused"]

    assert len(rule_analysis["defined"]) == 4
    assert len(rule_analysis["used"]) == 2
    assert len(rule_analysis["unused"]) == 2
    assert "$unused1" in rule_analysis["unused"]
    assert "$unused2" in rule_analysis["unused"]
    assert abs(rule_analysis["usage_rate"] - 0.5) < 1e-9


def test_undefined_string_detection() -> None:
    """Test detection of undefined strings."""
    yara_code = """
rule test_undefined {
    strings:
        $defined = "test"

    condition:
        $defined and $undefined
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    analyzer = StringUsageAnalyzer()
    results = analyzer.analyze(ast)

    rule_analysis = results["test_undefined"]
    assert "$undefined" in rule_analysis["undefined"]


def test_dependency_analysis() -> None:
    """Test dependency analysis between rules."""
    yara_code = """
rule base_rule {
    strings:
        $a = "base"
    condition:
        $a
}

rule dependent_rule {
    strings:
        $b = "dependent"
    condition:
        $b and base_rule
}

rule multi_dependent {
    condition:
        base_rule and dependent_rule
}

rule independent {
    strings:
        $c = "independent"
    condition:
        $c
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    analyzer = DependencyAnalyzer()
    results = analyzer.analyze(ast)

    # Check dependencies
    assert results["dependencies"]["dependent_rule"] == ["base_rule"]
    assert set(results["dependencies"]["multi_dependent"]) == {
        "base_rule",
        "dependent_rule",
    }
    assert results["dependencies"].get("independent", []) == []

    # Check dependency graph
    graph = results["dependency_graph"]
    assert not graph["base_rule"]["is_independent"]
    assert graph["independent"]["is_independent"]

    # Check topological sort
    order = results["dependency_order"]
    assert order is not None
    assert order.index("base_rule") < order.index("dependent_rule")
    assert order.index("dependent_rule") < order.index("multi_dependent")


def test_circular_dependency_detection() -> None:
    """Test detection of circular dependencies."""
    yara_code = """
rule rule_a {
    condition:
        rule_b
}

rule rule_b {
    condition:
        rule_c
}

rule rule_c {
    condition:
        rule_a
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    analyzer = DependencyAnalyzer()
    results = analyzer.analyze(ast)

    # Should detect circular dependency
    assert len(results["circular_dependencies"]) == 1
    cycle = results["circular_dependencies"][0]
    assert len(cycle) == 3
    assert set(cycle) == {"rule_a", "rule_b", "rule_c"}

    # Topological sort should fail
    assert results["dependency_order"] is None


def test_comprehensive_analysis() -> None:
    """Test comprehensive rule analysis."""
    yara_code = """
import "pe"

rule good_rule {
    meta:
        author = "test"
        description = "well-structured rule"

    strings:
        $mz = "MZ"
        $pe = "PE"

    condition:
        $mz at 0 and $pe
}

rule problematic_rule {
    strings:
        $used = "used"
        $unused1 = "unused"
        $unused2 = { 00 01 02 }
        $unused3 = /unused_regex/

    condition:
        $used and $undefined and good_rule
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    analyzer = RuleAnalyzer()
    results = analyzer.analyze(ast)

    # Check summary
    summary = results["summary"]
    assert summary["total_rules"] == 2
    assert summary["total_strings"] == 6
    assert summary["total_unused_strings"] == 3
    assert summary["rules_with_dependencies"] == 1

    # Check quality metrics
    metrics = results["quality_metrics"]
    assert 0 <= metrics["string_usage_efficiency"] <= 1
    assert metrics["overall_quality_score"] < 100  # Should be penalized for issues

    # Check recommendations
    recommendations = results["recommendations"]
    assert len(recommendations) > 0

    # Should have recommendations for unused strings
    unused_recs = [r for r in recommendations if r["type"] == "unused_strings"]
    assert len(unused_recs) > 0

    # Should have recommendation for undefined string
    undefined_recs = [r for r in recommendations if r["type"] == "undefined_strings"]
    assert len(undefined_recs) > 0


def test_them_keyword_handling() -> None:
    """Test handling of 'them' keyword in string usage."""
    yara_code = """
rule test_them {
    strings:
        $a = "test1"
        $b = "test2"
        $c = "test3"

    condition:
        2 of them
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    analyzer = StringUsageAnalyzer()
    results = analyzer.analyze(ast)

    rule_analysis = results["test_them"]
    # 'them' should mark all strings as used
    assert len(rule_analysis["used"]) == 3
    assert len(rule_analysis["unused"]) == 0
    assert abs(rule_analysis["usage_rate"] - 1.0) < 1e-9


if __name__ == "__main__":
    test_unused_string_detection()
    test_undefined_string_detection()
    test_dependency_analysis()
    test_circular_dependency_detection()
    test_comprehensive_analysis()
    test_them_keyword_handling()
    print("✓ All rule analysis tests passed")
