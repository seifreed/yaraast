"""Dependency graph generation for YARA AST using GraphViz."""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any

import graphviz

from yaraast.metrics._visitor_base import MetricsVisitorBase
from yaraast.metrics.dependency_graph_generation import (
    generate_complexity_graph as dependency_generate_complexity_graph,
)
from yaraast.metrics.dependency_graph_generation import generate_graph as dependency_generate_graph
from yaraast.metrics.dependency_graph_generation import (
    generate_module_graph as dependency_generate_module_graph,
)
from yaraast.metrics.dependency_graph_generation import (
    generate_rule_graph as dependency_generate_rule_graph,
)
from yaraast.metrics.dependency_graph_graphviz import (
    add_import_cluster,
    add_include_cluster,
    add_module_edges,
    add_rules_cluster,
    add_string_reference_edges,
)
from yaraast.metrics.dependency_graph_helpers import rule_info
from yaraast.metrics.dependency_graph_render import rule_cluster_label, rule_node_color
from yaraast.metrics.dependency_graph_stats import (
    get_dependency_stats as dependency_get_dependency_stats,
)

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.rules import Rule


class DependencyGraphGenerator(MetricsVisitorBase):
    """Generates dependency graphs from YARA AST."""

    def __init__(self) -> None:
        super().__init__(default=None)
        self.dependencies: dict[str, set[str]] = defaultdict(set)
        self.imports: set[str] = set()
        self.includes: set[str] = set()
        self.rules: dict[str, dict[str, Any]] = {}
        self.string_references: dict[str, set[str]] = defaultdict(
            set,
        )  # rule -> strings
        self.module_references: dict[str, set[str]] = defaultdict(
            set,
        )  # rule -> modules
        self._current_rule: str | None = None

    def generate_graph(
        self,
        ast: YaraFile,
        output_path: str | None = None,
        format: str = "svg",
        engine: str = "dot",
    ) -> str:
        """Generate dependency graph from AST."""
        return dependency_generate_graph(self, ast, output_path, format, engine)

    def generate_rule_graph(
        self,
        ast: YaraFile,
        output_path: str | None = None,
        format: str = "svg",
    ) -> str:
        """Generate rule-only dependency graph."""
        return dependency_generate_rule_graph(self, ast, output_path, format)

    def generate_module_graph(
        self,
        ast: YaraFile,
        output_path: str | None = None,
        format: str = "svg",
    ) -> str:
        """Generate module dependency graph."""
        return dependency_generate_module_graph(self, ast, output_path, format)

    def generate_complexity_graph(
        self,
        ast: YaraFile,
        complexity_metrics: dict[str, int],
        output_path: str | None = None,
        format: str = "svg",
    ) -> str:
        """Generate complexity visualization graph."""
        return dependency_generate_complexity_graph(
            self, ast, complexity_metrics, output_path, format
        )

    def _add_nodes(self, dot: graphviz.Digraph) -> None:
        """Add nodes to the graph."""
        add_import_cluster(dot, self.imports)
        add_include_cluster(dot, self.includes)
        add_rules_cluster(dot, self.rules, rule_cluster_label, rule_node_color)

    def _add_edges(self, dot: graphviz.Digraph) -> None:
        """Add edges to the graph."""
        add_module_edges(dot, self.module_references, self.imports)
        add_string_reference_edges(dot, self.string_references)

    def get_dependency_stats(self) -> dict[str, Any]:
        """Get dependency statistics."""
        return dependency_get_dependency_stats(self)

    # Visitor methods
    def visit_yara_file(self, node: YaraFile) -> None:
        """Visit YARA file and collect imports/includes."""
        for imp in node.imports:
            self.imports.add(imp.module)

        for inc in node.includes:
            self.includes.add(inc.path)

        for rule in node.rules:
            self.visit(rule)

    def visit_rule(self, node: Rule) -> None:
        """Visit rule and collect information."""
        self._current_rule = node.name

        self.rules[node.name] = rule_info(node)

        # Visit strings to track references
        for string_def in node.strings:
            self.string_references[node.name].add(string_def.identifier)

        # Visit condition to find module usage
        if node.condition:
            self.visit(node.condition)

    def visit_member_access(self, node) -> None:
        """Track module usage in member access."""
        if self._current_rule and hasattr(node.object, "name"):
            module_name = node.object.name
            if module_name in self.imports:
                self.module_references[self._current_rule].add(module_name)

        self.visit(node.object)

    def visit_function_call(self, node) -> None:
        """Track module function calls."""
        if self._current_rule:
            # Check if function call is from a module
            function_name = node.function
            for module in self.imports:
                if function_name.startswith(f"{module}."):
                    self.module_references[self._current_rule].add(module)
                    break

        for arg in node.arguments:
            self.visit(arg)

    def visit_binary_expression(self, node) -> None:
        self.visit(node.left)
        self.visit(node.right)

    def visit_unary_expression(self, node) -> None:
        self.visit(node.operand)

    def visit_parentheses_expression(self, node) -> None:
        self.visit(node.expression)

    def visit_set_expression(self, node) -> None:
        for elem in node.elements:
            self.visit(elem)

    def visit_range_expression(self, node) -> None:
        self.visit(node.low)
        self.visit(node.high)

    def visit_array_access(self, node) -> None:
        self.visit(node.array)
        self.visit(node.index)

    def visit_for_expression(self, node) -> None:
        self.visit(node.iterable)
        self.visit(node.body)

    def visit_for_of_expression(self, node) -> None:
        self.visit(node.string_set)
        if node.condition:
            self.visit(node.condition)

    def visit_at_expression(self, node) -> None:
        self.visit(node.offset)

    def visit_in_expression(self, node) -> None:
        self.visit(node.range)

    def visit_of_expression(self, node) -> None:
        if hasattr(node.quantifier, "accept"):
            self.visit(node.quantifier)
        if hasattr(node.string_set, "accept"):
            self.visit(node.string_set)

    def visit_module_reference(self, node) -> None:
        if self._current_rule:
            self.module_references[self._current_rule].add(node.module)

    def visit_dictionary_access(self, node) -> None:
        self.visit(node.object)

    def visit_defined_expression(self, node) -> None:
        self.visit(node.expression)

    def visit_string_operator_expression(self, node) -> None:
        self.visit(node.left)
        self.visit(node.right)


# Analysis helpers live in dependency_graph_utils for a smaller public surface.
