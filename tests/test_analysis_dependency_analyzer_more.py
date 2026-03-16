from __future__ import annotations

from yaraast.analysis.dependency_analyzer import DependencyAnalyzer
from yaraast.ast.expressions import FunctionCall, Identifier, IntegerLiteral
from yaraast.ast.rules import Import, Include, Rule
from yaraast.parser import Parser


def test_dependency_analyzer_import_include_and_direct_visitors() -> None:
    analyzer = DependencyAnalyzer()
    analyzer.visit_import(Import("pe"))
    analyzer.visit_include(Include("common.yar"))
    assert analyzer.imported_modules == {"pe"}
    assert analyzer.included_files == {"common.yar"}

    analyzer.rule_names = {"callee"}
    analyzer.current_rule = None
    analyzer.visit_identifier(Identifier("callee"))
    assert analyzer.dependencies == {}

    analyzer.current_rule = "caller"
    analyzer.visit_identifier(Identifier("callee"))
    analyzer.visit_function_call(FunctionCall("callee", [IntegerLiteral(1)]))
    analyzer.visit_function_call(FunctionCall("other", [Identifier("callee")]))
    assert analyzer.dependencies["caller"] == {"callee"}


def test_dependency_analyzer_cycle_dedup_transitive_and_topological_none() -> None:
    analyzer = DependencyAnalyzer()
    analyzer.rule_names = {"a", "b", "c", "d"}
    analyzer.dependencies["a"].update({"b", "external"})
    analyzer.dependencies["b"].add("c")
    analyzer.dependencies["c"].add("a")
    analyzer.dependencies["d"] = set()

    transitive = analyzer.get_transitive_dependencies("a")
    assert transitive == {"b", "c", "external"}

    graph = analyzer._build_dependency_graph()
    assert graph["d"]["is_independent"] is True
    assert "external" in graph["a"]["depends_on"]

    cycles = analyzer._find_circular_dependencies()
    assert len(cycles) == 1
    assert cycles[0][0] == cycles[0][-1]  # Cycle is properly closed
    assert set(cycles[0]) == {"a", "b", "c"}

    deduped = analyzer._remove_duplicate_cycles([["a", "b", "c", "a"], ["b", "c", "a", "b"]])
    assert len(deduped) == 1
    assert deduped[0][0] == deduped[0][-1]  # Closed cycle

    assert analyzer._topological_sort() is None


def test_dependency_analyzer_visit_rule_and_analyze_full_file() -> None:
    ast = Parser().parse(
        """
import "pe"
include "common.yar"

rule base {
    condition:
        true
}

rule caller {
    condition:
        base and helper(base)
}
"""
    )
    analyzer = DependencyAnalyzer()
    results = analyzer.analyze(ast)

    assert results["imported_modules"] == ["pe"]
    assert results["included_files"] == ["common.yar"]
    assert set(results["dependencies"]["caller"]) == {"base"}
    assert analyzer.get_dependencies("caller") == ["base"]
    assert analyzer.get_dependents("base") == ["caller"]
    assert analyzer.get_transitive_dependencies("caller") == {"base"}

    rule = Rule(name="empty", condition=None)
    analyzer.visit_rule(rule)
    assert analyzer.current_rule is None
