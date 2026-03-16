"""Additional real coverage for dependency graph graphviz/utils helpers."""

from __future__ import annotations

from pathlib import Path

import graphviz

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import Identifier
from yaraast.ast.rules import Rule
from yaraast.metrics.dependency_graph_graphviz import (
    add_edge,
    add_import_cluster,
    add_include_cluster,
    add_module_edges,
    add_rules_cluster,
    add_string_reference_edges,
    create_graph,
)
from yaraast.metrics.dependency_graph_helpers import render_graph
from yaraast.metrics.dependency_graph_utils import (
    DependencyGraph,
    build_dependency_graph,
    find_circular_dependencies,
    get_dependency_order,
)


def test_graphviz_helper_empty_paths_and_edge_styles() -> None:
    dot = create_graph("deps", "LR")

    add_import_cluster(dot, [])
    add_include_cluster(dot, [])
    add_rules_cluster(dot, {}, lambda *_: "x", lambda *_: "white")
    add_string_reference_edges(dot, {"rule_a": set()})
    add_module_edges(dot, {"rule_a": {"pe", "math"}}, {"pe"})
    add_edge(dot, "a", "b", style="dashed")

    source = dot.source
    assert "cluster_imports" not in source
    assert "cluster_includes" not in source
    assert "cluster_rules" not in source
    assert "rule_a_strings" not in source
    assert "mod_pe" in source
    assert "mod_math" not in source
    assert "style=dashed" in source

    with_includes = create_graph("deps2", "LR")
    add_include_cluster(with_includes, ["common.yar"])
    include_source = with_includes.source
    assert "cluster_includes" in include_source
    assert "include_common.yar" in include_source


def test_dependency_utils_remaining_paths() -> None:
    ast = YaraFile(
        rules=[
            Rule(name="a", condition=Identifier("b")),
            Rule(name="b", condition=Identifier("c")),
            Rule(name="c", condition=Identifier("a")),
            Rule(name="d", condition=None),
        ]
    )

    graph = build_dependency_graph(ast)
    assert graph.has_node("d")
    assert graph.get_dependencies("d") == set()

    cycles = find_circular_dependencies(graph)
    assert len(cycles) == 1
    assert set(cycles[0]) == {"a", "b", "c"}

    order = get_dependency_order(graph)
    assert set(order) == {"a", "b", "c", "d"}

    acyclic = DependencyGraph()
    acyclic.add_edge("top", "mid")
    acyclic.add_edge("mid", "leaf")
    acyclic.add_node("solo")
    acyclic_order = get_dependency_order(acyclic)
    assert set(acyclic_order) == {"top", "mid", "leaf", "solo"}
    assert acyclic_order.index("leaf") < acyclic_order.index("mid") < acyclic_order.index("top")

    empty = DependencyGraph()
    assert get_dependency_order(empty) == []


def test_render_graph_success_path_with_real_graphviz(tmp_path: Path) -> None:
    dot = graphviz.Digraph(comment="deps")
    dot.node("a")
    dot.node("b")
    dot.edge("a", "b")

    out = tmp_path / "deps.svg"
    result = render_graph(dot, str(out), "svg")

    assert result.endswith(".svg")
    assert Path(result).exists()
