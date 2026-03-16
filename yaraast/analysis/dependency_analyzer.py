"""Dependency analyzer for YARA rules."""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any

from yaraast.visitor.base import BaseVisitor

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.expressions import FunctionCall, Identifier
    from yaraast.ast.rules import Import, Include, Rule


class DependencyAnalyzer(BaseVisitor[None]):
    """Analyze dependencies between YARA rules."""

    def __init__(self) -> None:
        self.rule_names: set[str] = set()
        self.dependencies: dict[str, set[str]] = defaultdict(
            set,
        )  # rule -> rules it depends on
        self.current_rule: str | None = None
        self.imported_modules: set[str] = set()
        self.included_files: set[str] = set()

    def analyze(self, yara_file: YaraFile) -> dict[str, Any]:
        """Analyze dependencies in YARA file."""
        self.rule_names.clear()
        self.dependencies.clear()
        self.imported_modules.clear()
        self.included_files.clear()
        self.current_rule = None

        # First pass: collect all rule names
        for rule in yara_file.rules:
            self.rule_names.add(rule.name)

        # Visit imports and includes
        for imp in yara_file.imports:
            self.visit(imp)

        for inc in yara_file.includes:
            self.visit(inc)

        # Second pass: analyze dependencies
        for rule in yara_file.rules:
            self.visit(rule)

        return {
            "rules": list(self.rule_names),
            "dependencies": {rule: list(deps) for rule, deps in self.dependencies.items()},
            "dependency_graph": self._build_dependency_graph(),
            "circular_dependencies": self._find_circular_dependencies(),
            "dependency_order": self._topological_sort(),
            "imported_modules": list(self.imported_modules),
            "included_files": list(self.included_files),
        }

    def get_dependencies(self, rule_name: str) -> list[str]:
        """Get direct dependencies of a rule."""
        return list(self.dependencies.get(rule_name, set()))

    def get_dependents(self, rule_name: str) -> list[str]:
        """Get rules that depend on the given rule."""
        dependents = []
        for rule, deps in self.dependencies.items():
            if rule_name in deps:
                dependents.append(rule)
        return dependents

    def get_transitive_dependencies(self, rule_name: str) -> set[str]:
        """Get all transitive dependencies of a rule."""
        visited = set()
        to_visit = [rule_name]

        while to_visit:
            current = to_visit.pop()
            if current in visited:
                continue

            visited.add(current)
            deps = self.dependencies.get(current, set())
            to_visit.extend(deps - visited)

        visited.remove(rule_name)  # Don't include self
        return visited

    def _build_dependency_graph(self) -> dict[str, dict[str, list[str]]]:
        """Build a dependency graph."""
        graph = {}

        for rule in self.rule_names:
            deps = self.dependencies.get(rule, set())
            dependents = self.get_dependents(rule)
            transitive = self.get_transitive_dependencies(rule)

            graph[rule] = {
                "depends_on": list(deps),
                "depended_by": dependents,
                "transitive_dependencies": list(transitive),
                "is_independent": len(deps) == 0 and len(dependents) == 0,
            }

        return graph

    def _find_circular_dependencies(self) -> list[list[str]]:
        """Find circular dependencies using DFS."""
        dfs_state = self._init_dfs_state()
        cycles = []

        for rule in self.rule_names:
            if dfs_state["color"][rule] == dfs_state["white"]:
                self._dfs_cycle_detection(rule, dfs_state, cycles)

        return self._remove_duplicate_cycles(cycles)

    def _init_dfs_state(self) -> dict[str, Any]:
        """Initialize DFS state for cycle detection."""
        white, gray, black = 0, 1, 2
        return {
            "white": white,
            "gray": gray,
            "black": black,
            "color": dict.fromkeys(self.rule_names, white),
            "path": [],
        }

    def _dfs_cycle_detection(
        self, node: str, state: dict[str, Any], cycles: list[list[str]]
    ) -> None:
        """Perform DFS for cycle detection."""
        state["color"][node] = state["gray"]
        state["path"].append(node)

        for neighbor in self.dependencies.get(node, set()):
            if neighbor in self.rule_names:  # Only check internal rules
                if state["color"][neighbor] == state["gray"]:
                    # Found cycle - include the back-edge to close it
                    cycle_start = state["path"].index(neighbor)
                    cycles.append([*state["path"][cycle_start:], neighbor])
                elif state["color"][neighbor] == state["white"]:
                    self._dfs_cycle_detection(neighbor, state, cycles)

        state["path"].pop()
        state["color"][node] = state["black"]

    def _remove_duplicate_cycles(self, cycles: list[list[str]]) -> list[list[str]]:
        """Remove duplicate cycles from the list."""
        unique_cycles = []
        for cycle in cycles:
            # Normalize by rotating the cycle body (excluding closing back-edge)
            body = cycle[:-1] if len(cycle) > 1 and cycle[0] == cycle[-1] else cycle
            if body:
                normalized_body = min(body[i:] + body[:i] for i in range(len(body)))
                normalized = [*normalized_body, normalized_body[0]]  # Re-add closing edge
            else:
                normalized = cycle
            if normalized not in unique_cycles:
                unique_cycles.append(normalized)

        return unique_cycles

    def _topological_sort(self) -> list[str] | None:
        """Perform topological sort on rules."""
        # Check for cycles first
        if self._find_circular_dependencies():
            return None

        in_degree = dict.fromkeys(self.rule_names, 0)

        # Calculate in-degrees: if rule A depends on rule B, then A has incoming edge from B
        for rule, deps in self.dependencies.items():
            in_degree[rule] = len([dep for dep in deps if dep in in_degree])

        # Find nodes with no incoming edges
        queue = [rule for rule, degree in in_degree.items() if degree == 0]
        result = []

        while queue:
            current = queue.pop(0)
            result.append(current)

            # Reduce in-degree for dependent nodes
            for rule, deps in self.dependencies.items():
                if current in deps and rule in in_degree:
                    in_degree[rule] -= 1
                    if in_degree[rule] == 0:
                        queue.append(rule)

        return result if len(result) == len(self.rule_names) else None

    # Visitor methods with actual logic
    def visit_import(self, node: Import) -> None:
        self.imported_modules.add(node.module)

    def visit_include(self, node: Include) -> None:
        self.included_files.add(node.path)

    def visit_rule(self, node: Rule) -> None:
        self.current_rule = node.name

        # Check condition for rule references
        if node.condition:
            self.visit(node.condition)

        self.current_rule = None

    def visit_identifier(self, node: Identifier) -> None:
        # Check if identifier is a rule reference
        if self.current_rule and node.name in self.rule_names:
            self.dependencies[self.current_rule].add(node.name)

    def visit_function_call(self, node: FunctionCall) -> None:
        # Some functions might reference rules
        if node.function in self.rule_names and self.current_rule:
            self.dependencies[self.current_rule].add(node.function)

        # Visit arguments (BaseVisitor.visit_function_call does this, but we call super)
        super().visit_function_call(node)
