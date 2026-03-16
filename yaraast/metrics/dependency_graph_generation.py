"""Generation helpers for DependencyGraphGenerator."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.metrics.dependency_graph_graphviz import (
    add_complexity_legend,
    add_complexity_nodes,
    add_module_edges,
    add_module_nodes,
    add_module_rule_nodes,
    add_rule_graph_nodes,
    add_rule_string_edges,
    create_graph,
)
from yaraast.metrics.dependency_graph_helpers import render_graph, reset_graph_state
from yaraast.metrics.dependency_graph_render import (
    complexity_node_color,
    complexity_node_label,
    rule_graph_label,
    rule_node_color,
)

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.metrics.dependency_graph import DependencyGraphGenerator


def generate_graph(
    generator: DependencyGraphGenerator,
    ast: YaraFile,
    output_path: str | None = None,
    format: str = "svg",
    engine: str = "dot",
) -> str:
    reset_graph_state(generator)
    generator.visit(ast)
    dot = create_graph("YARA Dependencies", rankdir="TB", engine=engine)
    generator._add_nodes(dot)
    generator._add_edges(dot)
    return render_graph(dot, output_path, format)


def generate_rule_graph(
    generator: DependencyGraphGenerator,
    ast: YaraFile,
    output_path: str | None = None,
    format: str = "svg",
) -> str:
    generator.visit(ast)
    dot = create_graph("YARA Rule Dependencies", rankdir="LR")
    from yaraast.metrics.dependency_graph_graphviz import apply_rule_graph_style

    apply_rule_graph_style(dot)
    add_rule_graph_nodes(dot, generator.rules, rule_graph_label, rule_node_color)
    add_rule_string_edges(dot, generator.string_references)
    return render_graph(dot, output_path, format)


def generate_module_graph(
    generator: DependencyGraphGenerator,
    ast: YaraFile,
    output_path: str | None = None,
    format: str = "svg",
) -> str:
    generator.visit(ast)
    dot = create_graph("YARA Module Dependencies", rankdir="TB")
    add_module_nodes(dot, generator.imports)
    add_module_rule_nodes(dot, generator.rules)
    add_module_edges(dot, generator.module_references, generator.imports)
    return render_graph(dot, output_path, format)


def generate_complexity_graph(
    generator: DependencyGraphGenerator,
    ast: YaraFile,
    complexity_metrics: dict[str, int],
    output_path: str | None = None,
    format: str = "svg",
) -> str:
    generator.visit(ast)
    dot = create_graph("YARA Complexity Visualization", rankdir="TB")
    add_complexity_nodes(
        dot,
        generator.rules,
        complexity_metrics,
        complexity_node_label,
        complexity_node_color,
    )
    add_complexity_legend(dot)
    return render_graph(dot, output_path, format)
