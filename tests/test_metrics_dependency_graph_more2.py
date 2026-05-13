"""Additional tests for dependency graph utilities (no mocks)."""

from __future__ import annotations

from pathlib import Path

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import InExpression
from yaraast.ast.expressions import Identifier, IntegerLiteral, RangeExpression
from yaraast.ast.rules import Rule
from yaraast.metrics.dependency_graph_utils import (
    analyze_dependencies,
    build_dependency_graph,
    export_dependency_graph,
    find_circular_dependencies,
    generate_dot_graph,
    get_dependency_order,
)
from yaraast.parser import Parser


def test_dependency_graph_basic() -> None:
    code = """
rule a { condition: true }
rule b { condition: a }
""".lstrip()

    ast = Parser().parse(code)
    graph = build_dependency_graph(ast)

    assert "a" in graph.nodes and "b" in graph.nodes
    assert "a" in graph.get_dependencies("b")
    assert graph.get_dependencies("a") == set()

    report = analyze_dependencies(ast)
    assert report["stats"]["total_rules"] == 2
    assert report["stats"]["rules_with_deps"] == 1


def test_dependency_graph_traverses_in_expression_subject_nodes() -> None:
    ast = YaraFile(
        rules=[
            Rule(name="base", condition=IntegerLiteral(1)),
            Rule(
                name="caller",
                condition=InExpression(
                    subject=Identifier("base"),
                    range=RangeExpression(IntegerLiteral(0), IntegerLiteral(10)),
                ),
            ),
        ]
    )

    graph = build_dependency_graph(ast)

    assert graph.get_dependencies("caller") == {"base"}


def test_dependency_graph_cycles_and_order() -> None:
    code = """
rule a { condition: b }
rule b { condition: a }
""".lstrip()
    ast = Parser().parse(code)
    graph = build_dependency_graph(ast)

    cycles = find_circular_dependencies(graph)
    assert cycles
    flat = {node for cycle in cycles for node in cycle}
    assert {"a", "b"}.issubset(flat)

    order = get_dependency_order(graph)
    assert set(order) == {"a", "b"}


def test_dependency_graph_export(tmp_path: Path) -> None:
    code = "rule a { condition: true }"
    ast = Parser().parse(code)
    graph = build_dependency_graph(ast)

    json_path = tmp_path / "deps.json"
    dot_path = tmp_path / "deps.dot"

    export_dependency_graph(graph, json_path, format="json")
    export_dependency_graph(graph, dot_path, format="dot")

    assert json_path.read_text(encoding="utf-8").strip().startswith("{")
    assert "digraph" in dot_path.read_text(encoding="utf-8")

    dot = generate_dot_graph(graph)
    assert "a" in dot
