"""Helper utilities for dependency graph analysis."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from yaraast.ast.base import require_yara_file
from yaraast.errors import ValidationError
from yaraast.metrics.dependency_graph_finder import DependencyFinder
from yaraast.metrics.dependency_graph_helpers import require_output_path

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.rules import Rule


def _deserialize_string_list(value: object, context: str) -> list[str]:
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    msg = f"{context} must be a list of strings"
    raise ValidationError(msg)


def _require_graph_node(value: object, context: str) -> str:
    if isinstance(value, str):
        if not value.strip():
            msg = f"{context} must not be empty"
            raise ValidationError(msg)
        return value
    msg = f"{context} must be a string"
    raise ValidationError(msg)


class DependencyGraph:
    """Simple dependency graph implementation."""

    def __init__(self) -> None:
        self.nodes: set[str] = set()
        self.edges: dict[str, set[str]] = defaultdict(set)
        self._reverse_edges: dict[str, set[str]] = defaultdict(set)

    def add_node(self, node: str) -> None:
        """Add a node to the graph."""
        node = _require_graph_node(node, "DependencyGraph node")
        self.nodes.add(node)

    def add_edge(self, from_node: str, to_node: str) -> None:
        """Add an edge from from_node to to_node."""
        from_node = _require_graph_node(from_node, "DependencyGraph edge source")
        to_node = _require_graph_node(to_node, "DependencyGraph edge target")
        self.add_node(from_node)
        self.add_node(to_node)
        self.edges[from_node].add(to_node)
        self._reverse_edges[to_node].add(from_node)

    def has_node(self, node: str) -> bool:
        """Check if node exists in graph."""
        node = _require_graph_node(node, "DependencyGraph node")
        return node in self.nodes

    def has_edge(self, from_node: str, to_node: str) -> bool:
        """Check if edge exists."""
        from_node = _require_graph_node(from_node, "DependencyGraph edge source")
        to_node = _require_graph_node(to_node, "DependencyGraph edge target")
        return to_node in self.edges.get(from_node, set())

    def get_dependencies(self, node: str) -> set[str]:
        """Get nodes that this node depends on."""
        node = _require_graph_node(node, "DependencyGraph node")
        return self.edges.get(node, set()).copy()

    def get_dependents(self, node: str) -> set[str]:
        """Get nodes that depend on this node."""
        node = _require_graph_node(node, "DependencyGraph node")
        return self._reverse_edges.get(node, set()).copy()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "nodes": sorted(self.nodes),
            "edges": {
                from_node: sorted(to_nodes) for from_node, to_nodes in sorted(self.edges.items())
            },
        }

    def from_dict(self, data: object) -> None:
        """Load from dictionary representation."""
        if not isinstance(data, Mapping):
            msg = "DependencyGraph data must be an object"
            raise ValidationError(msg)

        nodes = [
            _require_graph_node(node, "DependencyGraph node")
            for node in _deserialize_string_list(data.get("nodes", []), "DependencyGraph nodes")
        ]
        raw_edges = data.get("edges", {})
        if not isinstance(raw_edges, Mapping):
            msg = "DependencyGraph edges must be an object"
            raise ValidationError(msg)

        edges: dict[str, list[str]] = {}
        for from_node, to_nodes in raw_edges.items():
            if not isinstance(from_node, str):
                msg = "DependencyGraph edge names must be strings"
                raise ValidationError(msg)
            source = _require_graph_node(from_node, "DependencyGraph edge source")
            edges[source] = [
                _require_graph_node(target, "DependencyGraph edge target")
                for target in _deserialize_string_list(
                    to_nodes,
                    "DependencyGraph edge targets",
                )
            ]

        self.nodes.clear()
        self.edges.clear()
        self._reverse_edges.clear()

        for node in nodes:
            self.add_node(node)

        for from_node, to_nodes in edges.items():
            for to_node in to_nodes:
                self.add_edge(from_node, to_node)


def build_dependency_graph(ast: YaraFile) -> DependencyGraph:
    """Build dependency graph from YARA AST."""
    ast = require_yara_file(ast, "ast")
    graph = DependencyGraph()
    rule_keys, rule_keys_by_name = _rule_occurrence_maps(ast.rules)

    for rule in ast.rules:
        graph.add_node(rule_keys[id(rule)])

    all_rule_names = set(rule_keys_by_name)

    for rule in ast.rules:
        if rule.condition is not None:
            finder = DependencyFinder(rule.name, all_rule_names)
            finder.visit(rule.condition)

            for dep in finder.dependencies:
                for dep_key in _dependency_targets_for_rule_name(dep, rule_keys_by_name):
                    graph.add_edge(rule_keys[id(rule)], dep_key)

    return graph


def _rule_occurrence_maps(rules: list[Rule]) -> tuple[dict[int, str], dict[str, list[str]]]:
    counts = Counter(rule.name for rule in rules)
    seen: defaultdict[str, int] = defaultdict(int)
    rule_keys: dict[int, str] = {}
    rule_keys_by_name: dict[str, list[str]] = {}

    for rule in rules:
        seen[rule.name] += 1
        rule_key = _rule_occurrence_key(rule.name, seen[rule.name], counts)
        rule_keys[id(rule)] = rule_key
        rule_keys_by_name.setdefault(rule.name, []).append(rule_key)

    return rule_keys, rule_keys_by_name


def _rule_occurrence_key(rule_name: str, occurrence: int, counts: Counter[str]) -> str:
    if counts[rule_name] == 1:
        return rule_name
    return f"{rule_name}#{occurrence}"


def _dependency_targets_for_rule_name(
    rule_name: str,
    rule_keys_by_name: dict[str, list[str]],
) -> tuple[str, ...]:
    rule_keys = rule_keys_by_name.get(rule_name)
    if not rule_keys:
        return (rule_name,)
    return tuple(rule_keys)


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

        for neighbor in sorted(graph.get_dependencies(node)):
            if neighbor not in visited:
                dfs(neighbor, path)
            elif neighbor in rec_stack:
                cycle_start = path.index(neighbor)
                cycle_nodes = path[cycle_start:]
                min_idx = cycle_nodes.index(min(cycle_nodes))
                rotated = cycle_nodes[min_idx:] + cycle_nodes[:min_idx]
                normalized = [*rotated, rotated[0]]
                if normalized not in cycles:
                    cycles.append(normalized)

        path.pop()
        rec_stack.remove(node)

    for node in sorted(graph.nodes):
        if node not in visited:
            dfs(node, [])

    return cycles


def get_dependency_order(graph: DependencyGraph) -> list[str]:
    """Get topological order of rules (dependencies first)."""
    in_degree = {node: len(graph.get_dependencies(node)) for node in sorted(graph.nodes)}

    queue = [node for node in sorted(graph.nodes) if in_degree[node] == 0]
    result = []

    while queue:
        node = queue.pop(0)
        result.append(node)

        for dependent in sorted(graph.get_dependents(node)):
            in_degree[dependent] -= 1
            if in_degree[dependent] == 0:
                queue.append(dependent)

    if len(result) != len(graph.nodes):
        return sorted(graph.nodes)

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
    output_path = require_output_path(output_path)

    if format == "json":
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(graph.to_dict(), f, indent=2)
    elif format == "dot":
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(generate_dot_graph(graph))
    else:
        msg = f"Unsupported format: {format}"
        raise ValidationError(msg)
