"""Helper utilities for dependency graph analysis."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

from yaraast.errors import ValidationError
from yaraast.metrics.dependency_graph_finder import DependencyFinder

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile


class DependencyGraph:
    """Simple dependency graph implementation."""

    def __init__(self) -> None:
        self.nodes: set[str] = set()
        self.edges: dict[str, set[str]] = defaultdict(set)
        self._reverse_edges: dict[str, set[str]] = defaultdict(set)

    def add_node(self, node: str) -> None:
        """Add a node to the graph."""
        self.nodes.add(node)

    def add_edge(self, from_node: str, to_node: str) -> None:
        """Add an edge from from_node to to_node."""
        self.add_node(from_node)
        self.add_node(to_node)
        self.edges[from_node].add(to_node)
        self._reverse_edges[to_node].add(from_node)

    def has_node(self, node: str) -> bool:
        """Check if node exists in graph."""
        return node in self.nodes

    def has_edge(self, from_node: str, to_node: str) -> bool:
        """Check if edge exists."""
        return to_node in self.edges.get(from_node, set())

    def get_dependencies(self, node: str) -> set[str]:
        """Get nodes that this node depends on."""
        return self.edges.get(node, set()).copy()

    def get_dependents(self, node: str) -> set[str]:
        """Get nodes that depend on this node."""
        return self._reverse_edges.get(node, set()).copy()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "nodes": list(self.nodes),
            "edges": {from_node: list(to_nodes) for from_node, to_nodes in self.edges.items()},
        }

    def from_dict(self, data: dict[str, Any]) -> None:
        """Load from dictionary representation."""
        self.nodes.clear()
        self.edges.clear()
        self._reverse_edges.clear()

        for node in data.get("nodes", []):
            self.add_node(node)

        for from_node, to_nodes in data.get("edges", {}).items():
            for to_node in to_nodes:
                self.add_edge(from_node, to_node)


def build_dependency_graph(ast: YaraFile) -> DependencyGraph:
    """Build dependency graph from YARA AST."""
    graph = DependencyGraph()

    for rule in ast.rules:
        graph.add_node(rule.name)

    all_rule_names = {rule.name for rule in ast.rules}

    for rule in ast.rules:
        if rule.condition:
            finder = DependencyFinder(rule.name, all_rule_names)
            finder.visit(rule.condition)

            for dep in finder.dependencies:
                graph.add_edge(rule.name, dep)

    return graph


def analyze_dependencies(ast: YaraFile) -> dict[str, Any]:
    """Analyze dependencies in YARA file."""
    graph = build_dependency_graph(ast)

    rules_with_deps = len([n for n in graph.nodes if graph.get_dependencies(n)])
    rules_depended_on = len([n for n in graph.nodes if graph.get_dependents(n)])

    return {
        "graph": graph.to_dict(),
        "stats": {
            "total_rules": len(graph.nodes),
            "rules_with_deps": rules_with_deps,
            "rules_depended_on": rules_depended_on,
            "total_dependencies": sum(len(deps) for deps in graph.edges.values()),
        },
    }


def find_circular_dependencies(graph: DependencyGraph) -> list[list[str]]:
    """Find circular dependencies in the graph."""
    cycles = []
    visited = set()
    rec_stack = set()

    def dfs(node: str, path: list[str]) -> None:
        visited.add(node)
        rec_stack.add(node)
        path.append(node)

        for neighbor in graph.get_dependencies(node):
            if neighbor not in visited:
                dfs(neighbor, path)
            elif neighbor in rec_stack:
                cycle_start = path.index(neighbor)
                cycle = [*path[cycle_start:], neighbor]
                min_idx = cycle.index(min(cycle))
                normalized = cycle[min_idx:] + cycle[:min_idx]
                if normalized not in cycles:
                    cycles.append(normalized)

        path.pop()
        rec_stack.remove(node)

    for node in graph.nodes:
        if node not in visited:
            dfs(node, [])

    return cycles


def get_dependency_order(graph: DependencyGraph) -> list[str]:
    """Get topological order of rules (dependencies first)."""
    in_degree = {node: len(graph.get_dependencies(node)) for node in graph.nodes}

    queue = [node for node in graph.nodes if in_degree[node] == 0]
    result = []

    while queue:
        node = queue.pop(0)
        result.append(node)

        for dependent in graph.get_dependents(node):
            in_degree[dependent] -= 1
            if in_degree[dependent] == 0:
                queue.append(dependent)

    if len(result) != len(graph.nodes):
        return list(graph.nodes)

    return result


def generate_dot_graph(graph: DependencyGraph) -> str:
    """Generate DOT format representation of the graph."""
    lines = ["digraph Dependencies {"]
    lines.append("  rankdir=LR;")
    lines.append("  node [shape=box];")

    for node in sorted(graph.nodes):
        lines.append(f'  "{node}";')

    for from_node in sorted(graph.nodes):
        for to_node in sorted(graph.get_dependencies(from_node)):
            lines.append(f'  "{from_node}" -> "{to_node}";')

    lines.append("}")
    return "\n".join(lines)


def export_dependency_graph(
    graph: DependencyGraph,
    output_path: str | Path,
    format: str = "json",
) -> None:
    """Export dependency graph to file."""
    output_path = Path(output_path)

    if format == "json":
        with open(output_path, "w") as f:
            json.dump(graph.to_dict(), f, indent=2)
    elif format == "dot":
        with open(output_path, "w") as f:
            f.write(generate_dot_graph(graph))
    else:
        msg = f"Unsupported format: {format}"
        raise ValidationError(msg)
