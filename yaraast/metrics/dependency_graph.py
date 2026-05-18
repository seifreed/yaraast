"""Dependency graph generation for YARA AST using GraphViz."""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any

import graphviz

from yaraast.metrics._visitor_base import MetricsVisitorBase
from yaraast.metrics.dependency_graph_generation import (
    generate_complexity_graph as dependency_generate_complexity_graph,
    generate_graph as dependency_generate_graph,
    generate_module_graph as dependency_generate_module_graph,
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
        self._local_scopes: list[set[str]] = []

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
        try:
            if node.condition:
                self.visit(node.condition)
        finally:
            self._current_rule = None

    def _module_name_for_object(self, value) -> str | None:
        if hasattr(value, "module"):
            return value.module
        if hasattr(value, "name"):
            return value.name
        return None

    def _add_module_reference(self, module_name: str) -> None:
        if self._current_rule and not self._is_local(module_name):
            self.module_references[self._current_rule].add(module_name)

    def _is_local(self, name: str) -> bool:
        return any(name in scope for scope in reversed(self._local_scopes))

    def _push_local_scope(self, *names: str) -> None:
        scope: set[str] = set()
        for name in names:
            scope.update(self._local_name_variants(name))
        self._local_scopes.append(scope)

    def _pop_local_scope(self) -> None:
        self._local_scopes.pop()

    def _define_local(self, name: str) -> None:
        if self._local_scopes:
            self._local_scopes[-1].update(self._local_name_variants(name))

    @staticmethod
    def _local_name_variants(name: str) -> set[str]:
        names = [part.strip() for part in name.split(",")]
        return {local_name for local_name in names if local_name}

    def visit_with_statement(self, node) -> None:
        self._push_local_scope()
        try:
            for declaration in node.declarations:
                self.visit(declaration)
            self.visit(node.body)
        finally:
            self._pop_local_scope()

    def visit_with_declaration(self, node) -> None:
        self._visit_ast_value(node.value)
        self._define_local(node.identifier)

    def visit_array_comprehension(self, node) -> None:
        self._visit_ast_value(node.iterable)
        self._push_local_scope(node.variable)
        try:
            self._visit_ast_value(node.condition)
            self._visit_ast_value(node.expression)
        finally:
            self._pop_local_scope()

    def visit_dict_comprehension(self, node) -> None:
        self._visit_ast_value(node.iterable)
        names = [node.key_variable]
        if node.value_variable:
            names.append(node.value_variable)
        self._push_local_scope(*names)
        try:
            self._visit_ast_value(node.condition)
            self._visit_ast_value(node.key_expression)
            self._visit_ast_value(node.value_expression)
        finally:
            self._pop_local_scope()

    def visit_lambda_expression(self, node) -> None:
        self._push_local_scope(*node.parameters)
        try:
            self._visit_ast_value(node.body)
        finally:
            self._pop_local_scope()

    def visit_member_access(self, node) -> None:
        """Track module usage in member access."""
        module_name = self._module_name_for_object(node.object)
        if self._current_rule and module_name in self.imports and not self._is_local(module_name):
            self.module_references[self._current_rule].add(module_name)

        self.visit(node.object)

    def visit_function_call(self, node) -> None:
        """Track module function calls."""
        function_name = node.function
        module_name = function_name.split(".", 1)[0] if "." in function_name else None
        if module_name in self.imports and not self._is_local(module_name):
            self._add_module_reference(module_name)

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
        self._visit_ast_value(node.quantifier)
        self.visit(node.iterable)
        self._push_local_scope(node.variable)
        try:
            self.visit(node.body)
        finally:
            self._pop_local_scope()

    def visit_for_of_expression(self, node) -> None:
        self._visit_ast_value(node.quantifier)
        self._visit_ast_value(node.string_set)
        if node.condition:
            self.visit(node.condition)

    def visit_at_expression(self, node) -> None:
        self.visit(node.offset)

    def visit_in_expression(self, node) -> None:
        self._visit_ast_value(node.subject)
        self.visit(node.range)

    def visit_of_expression(self, node) -> None:
        self._visit_ast_value(node.quantifier)
        self._visit_ast_value(node.string_set)

    def visit_module_reference(self, node) -> None:
        self._add_module_reference(node.module)

    def visit_dictionary_access(self, node) -> None:
        self.visit(node.object)
        self._visit_ast_value(node.key)

    def visit_defined_expression(self, node) -> None:
        self.visit(node.expression)

    def visit_string_operator_expression(self, node) -> None:
        self.visit(node.left)
        self.visit(node.right)

    def _visit_ast_value(self, value) -> None:
        if hasattr(value, "accept"):
            self.visit(value)
        elif isinstance(value, list | tuple | set | frozenset):
            for item in value:
                self._visit_ast_value(item)


# Analysis helpers live in dependency_graph_utils for a smaller public surface.
