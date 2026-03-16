"""Real tests for dependency graph metrics (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from yaraast.metrics.dependency_graph import DependencyGraphGenerator
from yaraast.metrics.dependency_graph_utils import (
    DependencyGraph,
    analyze_dependencies,
    build_dependency_graph,
    export_dependency_graph,
    find_circular_dependencies,
    generate_dot_graph,
    get_dependency_order,
)
from yaraast.parser import Parser


def _parse_yara(code: str):
    parser = Parser()
    return parser.parse(dedent(code))


def test_dependency_graph_generator_outputs_dot_source(tmp_path) -> None:
    code = """
    import "pe"

    rule base_rule {
        strings:
            $a = "abc"
        condition:
            $a
    }

    rule uses_base : tag1 {
        condition:
            base_rule and pe.number_of_sections > 0
    }
    """
    ast = _parse_yara(code)

    generator = DependencyGraphGenerator()
    dot_source = generator.generate_graph(ast)
    assert "digraph" in dot_source

    stats = generator.get_dependency_stats()
    assert stats["total_rules"] == 2
    assert stats["total_imports"] == 1
    assert stats["rules_with_strings"] == 1
    assert stats["rules_using_modules"] == 1

    rule_graph = generator.generate_rule_graph(ast)
    assert "base_rule" in rule_graph
    assert "uses_base" in rule_graph

    module_graph = generator.generate_module_graph(ast)
    assert "Module: pe" in module_graph

    output_path = tmp_path / "deps.svg"
    rendered = generator.generate_graph(ast, output_path=str(output_path), format="svg")
    assert rendered.endswith(".svg")


def test_dependency_graph_build_and_analysis() -> None:
    code = """
    rule a { condition: true }
    rule b { condition: a }
    rule c { condition: a and b }
    """
    ast = _parse_yara(code)
    graph = build_dependency_graph(ast)

    assert graph.has_edge("b", "a")
    assert graph.has_edge("c", "a")
    assert graph.has_edge("c", "b")

    analysis = analyze_dependencies(ast)
    stats = analysis["stats"]
    assert stats["total_rules"] == 3
    assert stats["rules_with_deps"] == 2
    assert stats["total_dependencies"] >= 2


def test_dependency_graph_cycles_and_order(tmp_path) -> None:
    graph = DependencyGraph()
    graph.add_edge("a", "b")
    graph.add_edge("b", "c")
    graph.add_edge("c", "a")

    cycles = find_circular_dependencies(graph)
    assert cycles

    order = get_dependency_order(graph)
    assert set(order) == {"a", "b", "c"}

    dot = generate_dot_graph(graph)
    assert "digraph Dependencies" in dot

    json_path = tmp_path / "deps.json"
    export_dependency_graph(graph, json_path, format="json")
    assert json_path.read_text(encoding="utf-8")

    dot_path = tmp_path / "deps.dot"
    export_dependency_graph(graph, dot_path, format="dot")
    assert "digraph" in dot_path.read_text(encoding="utf-8")

    loaded = DependencyGraph()
    loaded.from_dict(graph.to_dict())
    assert loaded.has_edge("a", "b")
