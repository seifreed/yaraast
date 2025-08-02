"""Dependency graph generation for YARA AST using GraphViz."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

import graphviz

from yaraast.visitor import ASTVisitor

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.rules import Rule


class DependencyGraphGenerator(ASTVisitor[None]):
    """Generates dependency graphs from YARA AST."""

    def __init__(self):
        self.dependencies: dict[str, set[str]] = defaultdict(set)
        self.imports: set[str] = set()
        self.includes: set[str] = set()
        self.rules: dict[str, dict[str, Any]] = {}
        self.string_references: dict[str, set[str]] = defaultdict(set)  # rule -> strings
        self.module_references: dict[str, set[str]] = defaultdict(set)  # rule -> modules
        self._current_rule: str | None = None

    def generate_graph(
        self,
        ast: YaraFile,
        output_path: str | None = None,
        format: str = "svg",
        engine: str = "dot",
    ) -> str:
        """Generate dependency graph from AST."""
        # Reset state
        self.dependencies.clear()
        self.imports.clear()
        self.includes.clear()
        self.rules.clear()
        self.string_references.clear()
        self.module_references.clear()

        # Analyze AST
        self.visit(ast)

        # Create GraphViz graph
        dot = graphviz.Digraph(comment="YARA Dependencies", engine=engine)
        dot.attr(rankdir="TB", bgcolor="white", fontname="Arial")

        self._add_nodes(dot)
        self._add_edges(dot)

        # Render graph
        if output_path:
            output_file = str(Path(output_path).with_suffix(""))
            dot.render(output_file, format=format, cleanup=True)
            return f"{output_file}.{format}"
        return dot.source

    def generate_rule_graph(
        self, ast: YaraFile, output_path: str | None = None, format: str = "svg"
    ) -> str:
        """Generate rule-only dependency graph."""
        self.visit(ast)

        dot = graphviz.Digraph(comment="YARA Rule Dependencies")
        dot.attr(rankdir="LR", bgcolor="white", fontname="Arial")
        dot.attr("node", shape="box", style="rounded,filled", fillcolor="lightblue")

        # Add rule nodes
        for rule_name, rule_info in self.rules.items():
            label = f"{rule_name}\\n"
            if rule_info.get("tags"):
                label += f"Tags: {', '.join(rule_info['tags'])}\\n"
            label += f"Strings: {rule_info['string_count']}"

            color = "lightgreen" if rule_info["string_count"] > 0 else "lightcoral"
            dot.node(rule_name, label, fillcolor=color)

        # Add string dependencies (simplified)
        for rule_name, strings in self.string_references.items():
            for string_id in strings:
                # Create virtual string nodes
                dot.node(string_id, string_id, shape="ellipse", fillcolor="lightyellow")
                dot.edge(rule_name, string_id, label="uses")

        if output_path:
            output_file = str(Path(output_path).with_suffix(""))
            dot.render(output_file, format=format, cleanup=True)
            return f"{output_file}.{format}"
        return dot.source

    def generate_module_graph(
        self, ast: YaraFile, output_path: str | None = None, format: str = "svg"
    ) -> str:
        """Generate module dependency graph."""
        self.visit(ast)

        dot = graphviz.Digraph(comment="YARA Module Dependencies")
        dot.attr(rankdir="TB", bgcolor="white", fontname="Arial")

        # Add module nodes
        dot.attr("node", shape="box", style="rounded,filled", fillcolor="lightcyan")
        for module in self.imports:
            dot.node(f"mod_{module}", f"Module: {module}", fillcolor="lightcyan")

        # Add rule nodes
        dot.attr("node", shape="ellipse", fillcolor="lightblue")
        for rule_name in self.rules:
            dot.node(rule_name, rule_name)

        # Add dependencies
        for rule_name, modules in self.module_references.items():
            for module in modules:
                if module in self.imports:
                    dot.edge(f"mod_{module}", rule_name, label="imported by")

        if output_path:
            output_file = str(Path(output_path).with_suffix(""))
            dot.render(output_file, format=format, cleanup=True)
            return f"{output_file}.{format}"
        return dot.source

    def generate_complexity_graph(
        self,
        ast: YaraFile,
        complexity_metrics: dict[str, int],
        output_path: str | None = None,
        format: str = "svg",
    ) -> str:
        """Generate complexity visualization graph."""
        self.visit(ast)

        dot = graphviz.Digraph(comment="YARA Complexity Visualization")
        dot.attr(rankdir="TB", bgcolor="white", fontname="Arial")

        # Color rules by complexity
        for rule_name, rule_info in self.rules.items():
            complexity = complexity_metrics.get(rule_name, 1)

            # Choose color based on complexity
            if complexity <= 5:
                color = "lightgreen"
            elif complexity <= 10:
                color = "yellow"
            else:
                color = "lightcoral"

            label = f"{rule_name}\\nComplexity: {complexity}\\nStrings: {rule_info['string_count']}"
            dot.node(rule_name, label, style="filled", fillcolor=color, shape="box")

        # Add complexity legend
        with dot.subgraph(name="cluster_legend") as legend:
            legend.attr(label="Complexity Legend", style="filled", fillcolor="white")
            legend.node("low", "Low (≤5)", fillcolor="lightgreen", shape="box")
            legend.node("med", "Medium (6-10)", fillcolor="yellow", shape="box")
            legend.node("high", "High (>10)", fillcolor="lightcoral", shape="box")

        if output_path:
            output_file = str(Path(output_path).with_suffix(""))
            dot.render(output_file, format=format, cleanup=True)
            return f"{output_file}.{format}"
        return dot.source

    def _add_nodes(self, dot: graphviz.Digraph) -> None:
        """Add nodes to the graph."""
        # Import nodes
        if self.imports:
            with dot.subgraph(name="cluster_imports") as imports_cluster:
                imports_cluster.attr(label="Imports", style="filled", fillcolor="lightcyan")
                imports_cluster.attr("node", shape="box", fillcolor="lightblue")
                for imp in self.imports:
                    imports_cluster.node(f"import_{imp}", f'"{imp}"')

        # Include nodes
        if self.includes:
            with dot.subgraph(name="cluster_includes") as includes_cluster:
                includes_cluster.attr(label="Includes", style="filled", fillcolor="lightyellow")
                includes_cluster.attr("node", shape="note", fillcolor="yellow")
                for inc in self.includes:
                    includes_cluster.node(f"include_{inc}", f'"{inc}"')

        # Rule nodes
        if self.rules:
            with dot.subgraph(name="cluster_rules") as rules_cluster:
                rules_cluster.attr(label="Rules", style="filled", fillcolor="lightgray")
                rules_cluster.attr("node", shape="ellipse", fillcolor="white")

                for rule_name, rule_info in self.rules.items():
                    label = rule_name
                    if rule_info.get("modifiers"):
                        label += f"\\n[{', '.join(rule_info['modifiers'])}]"
                    if rule_info.get("tags"):
                        label += f"\\n:{', '.join(rule_info['tags'])}"

                    color = "lightgreen" if rule_info["string_count"] > 0 else "lightcoral"
                    rules_cluster.node(rule_name, label, fillcolor=color)

    def _add_edges(self, dot: graphviz.Digraph) -> None:
        """Add edges to the graph."""
        # Module usage edges
        for rule_name, modules in self.module_references.items():
            for module in modules:
                if module in self.imports:
                    dot.edge(
                        f"import_{module}", rule_name, label="uses", style="dashed", color="blue"
                    )

        # String reference edges (conceptual)
        for rule_name, strings in self.string_references.items():
            if strings:
                # Create a virtual "strings" node for this rule
                strings_node = f"{rule_name}_strings"
                dot.node(
                    strings_node,
                    f"Strings\\n({len(strings)})",
                    shape="box",
                    style="filled",
                    fillcolor="lightyellow",
                )
                dot.edge(rule_name, strings_node, label="defines", color="green")

    def get_dependency_stats(self) -> dict[str, Any]:
        """Get dependency statistics."""
        return {
            "total_rules": len(self.rules),
            "total_imports": len(self.imports),
            "total_includes": len(self.includes),
            "rules_with_strings": sum(1 for r in self.rules.values() if r["string_count"] > 0),
            "rules_using_modules": len(
                [r for r in self.module_references if self.module_references[r]]
            ),
            "most_used_modules": sorted(
                [
                    (mod, len([refs for refs in self.module_references.values() if mod in refs]))
                    for mod in self.imports
                ],
                key=lambda x: x[1],
                reverse=True,
            )[:5],
            "average_strings_per_rule": sum(r["string_count"] for r in self.rules.values())
            / max(1, len(self.rules)),
            "complex_rules": [
                name for name, info in self.rules.items() if info["string_count"] > 10
            ],
        }

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

        self.rules[node.name] = {
            "modifiers": node.modifiers,
            "tags": [tag.name for tag in node.tags],
            "string_count": len(node.strings),
            "has_meta": bool(node.meta),
            "has_condition": node.condition is not None,
        }

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

    # Required visitor methods (minimal implementations)
    def visit_import(self, node) -> None:
        pass

    def visit_include(self, node) -> None:
        pass

    def visit_tag(self, node) -> None:
        pass

    def visit_string_definition(self, node) -> None:
        pass

    def visit_plain_string(self, node) -> None:
        pass

    def visit_hex_string(self, node) -> None:
        pass

    def visit_regex_string(self, node) -> None:
        pass

    def visit_string_modifier(self, node) -> None:
        pass

    def visit_hex_token(self, node) -> None:
        pass

    def visit_hex_byte(self, node) -> None:
        pass

    def visit_hex_wildcard(self, node) -> None:
        pass

    def visit_hex_jump(self, node) -> None:
        pass

    def visit_hex_alternative(self, node) -> None:
        pass

    def visit_hex_nibble(self, node) -> None:
        pass

    def visit_expression(self, node) -> None:
        pass

    def visit_identifier(self, node) -> None:
        pass

    def visit_string_identifier(self, node) -> None:
        pass

    def visit_string_count(self, node) -> None:
        pass

    def visit_string_offset(self, node) -> None:
        pass

    def visit_string_length(self, node) -> None:
        pass

    def visit_integer_literal(self, node) -> None:
        pass

    def visit_double_literal(self, node) -> None:
        pass

    def visit_string_literal(self, node) -> None:
        pass

    def visit_regex_literal(self, node) -> None:
        pass

    def visit_boolean_literal(self, node) -> None:
        pass

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

    def visit_condition(self, node) -> None:
        pass

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

    def visit_meta(self, node) -> None:
        pass

    def visit_module_reference(self, node) -> None:
        if self._current_rule:
            self.module_references[self._current_rule].add(node.module)

    def visit_dictionary_access(self, node) -> None:
        self.visit(node.object)

    def visit_comment(self, node) -> None:
        pass

    def visit_comment_group(self, node) -> None:
        pass

    def visit_defined_expression(self, node) -> None:
        self.visit(node.expression)

    def visit_string_operator_expression(self, node) -> None:
        self.visit(node.left)
        self.visit(node.right)
