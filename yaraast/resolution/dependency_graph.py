"""Dependency graph for YARA files and rules."""

from __future__ import annotations

import graphlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.rules import Rule


@dataclass
class DependencyNode:
    """Node in the dependency graph."""

    name: str
    type: str  # 'file', 'rule', 'module'
    file_path: Path | None = None
    dependencies: set[str] = field(default_factory=set)
    dependents: set[str] = field(default_factory=set)
    metadata: dict = field(default_factory=dict)


class DependencyGraph:
    """Build and analyze dependency graphs for YARA files."""

    def __init__(self) -> None:
        self.nodes: dict[str, DependencyNode] = {}
        self.file_rules: dict[str, set[str]] = {}  # file_path -> rule_names
        self.rule_files: dict[str, str] = {}  # rule_name -> file_path

    def add_file(self, file_path: Path, ast: YaraFile) -> None:
        """Add a YARA file to the dependency graph."""
        file_key = str(file_path)

        # Add file node
        if file_key not in self.nodes:
            self.nodes[file_key] = DependencyNode(
                name=file_key,
                type="file",
                file_path=file_path,
            )

        # Track rules in this file
        self.file_rules[file_key] = set()

        # Add imports as dependencies
        for import_stmt in ast.imports:
            module_name = import_stmt.module
            self._add_module_dependency(file_key, module_name)

        # Add includes as dependencies
        for include_stmt in ast.includes:
            self._add_include_dependency(file_key, include_stmt.path)

        # Add rules and analyze their dependencies
        for rule in ast.rules:
            self._add_rule(file_key, rule)

    def _add_module_dependency(self, file_key: str, module_name: str) -> None:
        """Add module dependency."""
        # Create module node if not exists
        if module_name not in self.nodes:
            self.nodes[module_name] = DependencyNode(name=module_name, type="module")

        # Add dependency
        self.nodes[file_key].dependencies.add(module_name)
        self.nodes[module_name].dependents.add(file_key)

    def _add_include_dependency(self, file_key: str, include_path: str) -> None:
        """Add include dependency."""
        # Note: include_path should be resolved to absolute path by IncludeResolver
        self.nodes[file_key].dependencies.add(include_path)

    def _add_rule(self, file_key: str, rule: Rule) -> None:
        """Add rule to the graph and analyze its dependencies."""
        rule_key = f"rule:{rule.name}"

        # Create rule node
        self.nodes[rule_key] = DependencyNode(
            name=rule.name,
            type="rule",
            file_path=Path(file_key),
            metadata={
                "modifiers": rule.modifiers,
                "tags": ([tag.name for tag in rule.tags] if hasattr(rule, "tags") else []),
            },
        )

        # Track rule location
        self.file_rules[file_key].add(rule.name)
        self.rule_files[rule.name] = file_key

        # File depends on rule
        self.nodes[file_key].dependencies.add(rule_key)
        self.nodes[rule_key].dependents.add(file_key)

        # Analyze rule dependencies
        self._analyze_rule_dependencies(rule_key, rule)

    def _analyze_rule_dependencies(self, rule_key: str, rule: Rule) -> None:
        """Analyze dependencies within a rule."""
        # This would analyze the rule's condition to find:
        # - References to other rules
        # - Module function calls
        # - String references
        # For now, we'll keep it simple

    def get_file_dependencies(self, file_path: str) -> set[str]:
        """Get all dependencies of a file (transitive)."""
        return self._get_transitive_dependencies(file_path)

    def get_file_dependents(self, file_path: str) -> set[str]:
        """Get all files that depend on this file (transitive)."""
        return self._get_transitive_dependents(file_path)

    def get_rule_dependencies(self, rule_name: str) -> set[str]:
        """Get all dependencies of a rule."""
        rule_key = f"rule:{rule_name}"
        if rule_key not in self.nodes:
            return set()
        return self.nodes[rule_key].dependencies

    def _get_transitive_dependencies(self, node_key: str) -> set[str]:
        """Get transitive dependencies of a node."""
        if node_key not in self.nodes:
            return set()

        visited = set()
        to_visit = [node_key]
        dependencies = set()

        while to_visit:
            current = to_visit.pop()
            if current in visited:
                continue

            visited.add(current)
            node = self.nodes.get(current)
            if node:
                dependencies.update(node.dependencies)
                to_visit.extend(node.dependencies)

        return dependencies

    def _get_transitive_dependents(self, node_key: str) -> set[str]:
        """Get transitive dependents of a node."""
        if node_key not in self.nodes:
            return set()

        visited = set()
        to_visit = [node_key]
        dependents = set()

        while to_visit:
            current = to_visit.pop()
            if current in visited:
                continue

            visited.add(current)
            node = self.nodes.get(current)
            if node:
                dependents.update(node.dependents)
                to_visit.extend(node.dependents)

        return dependents

    def find_cycles(self) -> list[list[str]]:
        """Find dependency cycles in the graph."""
        # Build adjacency list for cycle detection
        graph = {}
        for node_key, node in self.nodes.items():
            graph[node_key] = list(node.dependencies)

        # Use graphlib to find cycles
        ts = graphlib.TopologicalSorter(graph)
        try:
            # If this succeeds, there are no cycles
            list(ts.static_order())
            return []
        except graphlib.CycleError as e:
            # Extract cycles from the error
            # This is a simplified version - a full implementation would
            # properly extract all cycles
            cycles = []
            if hasattr(e, "args") and len(e.args) > 1:
                cycle_nodes = e.args[1]
                if isinstance(cycle_nodes, list | tuple):
                    cycles.append(list(cycle_nodes))
            return cycles

    def get_isolated_nodes(self) -> set[str]:
        """Get nodes with no dependencies or dependents."""
        isolated = set()
        for node_key, node in self.nodes.items():
            if not node.dependencies and not node.dependents:
                isolated.add(node_key)
        return isolated

    def get_statistics(self) -> dict:
        """Get graph statistics."""
        file_nodes = [n for n in self.nodes.values() if n.type == "file"]
        rule_nodes = [n for n in self.nodes.values() if n.type == "rule"]
        module_nodes = [n for n in self.nodes.values() if n.type == "module"]

        return {
            "total_nodes": len(self.nodes),
            "file_count": len(file_nodes),
            "rule_count": len(rule_nodes),
            "module_count": len(module_nodes),
            "total_edges": sum(len(n.dependencies) for n in self.nodes.values()),
            "isolated_nodes": len(self.get_isolated_nodes()),
            "cycles": len(self.find_cycles()),
        }

    def export_dot(self) -> str:
        """Export graph to DOT format for visualization."""
        lines = ["digraph YaraDependencies {"]
        lines.append("  rankdir=LR;")
        lines.append("  node [shape=box];")

        # Style nodes by type
        for node_key, node in self.nodes.items():
            label = node.name
            if node.type == "file":
                style = "shape=folder,style=filled,fillcolor=lightblue"
            elif node.type == "rule":
                style = "shape=box,style=filled,fillcolor=lightgreen"
            elif node.type == "module":
                style = "shape=component,style=filled,fillcolor=lightyellow"
            else:
                style = ""

            # Escape special characters
            safe_key = node_key.replace('"', '\\"').replace(":", "_")
            safe_label = label.replace('"', '\\"')

            lines.append(f'  "{safe_key}" [label="{safe_label}",{style}];')

        # Add edges
        for node_key, node in self.nodes.items():
            safe_key = node_key.replace('"', '\\"').replace(":", "_")
            for dep in node.dependencies:
                safe_dep = dep.replace('"', '\\"').replace(":", "_")
                lines.append(f'  "{safe_key}" -> "{safe_dep}";')

        lines.append("}")
        return "\n".join(lines)
