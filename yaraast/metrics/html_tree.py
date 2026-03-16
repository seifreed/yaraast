"""HTML collapsible tree visualization for YARA AST."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from yaraast.metrics.html_tree_helpers import rule_children, rule_details
from yaraast.metrics.html_tree_nodes import HtmlTreeNodesMixin
from yaraast.metrics.html_tree_nodes_extra import HtmlTreeNodesExtraMixin
from yaraast.metrics.html_tree_nodes_trivial import HtmlTreeNodesTrivialMixin
from yaraast.metrics.html_tree_render import HtmlTreeRenderMixin
from yaraast.visitor.visitor import ASTVisitor

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.rules import Rule
    from yaraast.ast.strings import HexString, PlainString, RegexString


class HtmlTreeGenerator(
    HtmlTreeNodesMixin,
    HtmlTreeNodesExtraMixin,
    HtmlTreeNodesTrivialMixin,
    HtmlTreeRenderMixin,
    ASTVisitor[dict[str, Any]],
):
    """Generates HTML collapsible tree visualization from YARA AST."""

    def __init__(self, include_metadata: bool = True) -> None:
        self.include_metadata = include_metadata
        self.node_counter = 0

    def generate_html(
        self,
        ast: YaraFile,
        output_path: str | None = None,
        title: str = "YARA AST Visualization",
    ) -> str:
        """Generate HTML tree visualization."""
        self.node_counter = 0
        tree_data = self.visit(ast)

        html_content = self._render_html_template(tree_data, title)

        self._write_output(output_path, html_content)

        return html_content

    def generate_interactive_html(
        self,
        ast: YaraFile,
        output_path: str | None = None,
        title: str = "Interactive YARA AST",
    ) -> str:
        """Generate interactive HTML with search and filtering."""
        self.node_counter = 0
        tree_data = self.visit(ast)

        html_content = self._render_interactive_template(tree_data, title)

        self._write_output(output_path, html_content)

        return html_content

    def visit_yara_file(self, node: YaraFile) -> dict[str, Any]:
        """Visit YARA file node."""
        children = []
        children.extend(self._child_nodes(node.imports))
        children.extend(self._child_nodes(node.includes))
        children.extend(self._child_nodes(node.rules))

        return {
            "id": self._get_node_id(),
            "label": "YARA File",
            "node_class": "yara-file",
            "details": f"{len(node.rules)} rules, {len(node.imports)} imports, {len(node.includes)} includes",
            "children": children,
        }

    def visit_import(self, node) -> dict[str, Any]:
        """Visit import node."""
        label = f'Import: "{node.module}"'
        if hasattr(node, "alias") and node.alias:
            label += f" as {node.alias}"

        return {
            "id": self._get_node_id(),
            "label": label,
            "node_class": "import",
            "value": node.module,
        }

    def visit_include(self, node) -> dict[str, Any]:
        """Visit include node."""
        return {
            "id": self._get_node_id(),
            "label": f'Include: "{node.path}"',
            "node_class": "include",
            "value": node.path,
        }

    def visit_rule(self, node: Rule) -> dict[str, Any]:
        """Visit rule node."""
        children = rule_children(self, node)

        return {
            "id": self._get_node_id(),
            "label": f"Rule: {node.name}",
            "node_class": "rule",
            "details": rule_details(node),
            "children": children,
        }

    def visit_plain_string(self, node: PlainString) -> dict[str, Any]:
        """Visit plain string node."""
        children = []
        self._append_section(children, self._string_modifiers_section(node.modifiers))

        return self._string_node(
            f"Plain String: {node.identifier}",
            value=f'"{node.value}"',
            children=children if children else None,
        )

    def visit_hex_string(self, node: HexString) -> dict[str, Any]:
        """Visit hex string node."""
        children = []

        # Add tokens
        self._append_section(
            children, self._children_section("Hex Tokens", "hex-tokens", node.tokens)
        )

        self._append_section(children, self._string_modifiers_section(node.modifiers))

        return self._string_node(
            f"Hex String: {node.identifier}",
            details=f"{len(node.tokens)} tokens",
            children=children if children else None,
        )

    def visit_regex_string(self, node: RegexString) -> dict[str, Any]:
        """Visit regex string node."""
        children = []

        self._append_section(children, self._string_modifiers_section(node.modifiers))

        return self._string_node(
            f"Regex String: {node.identifier}",
            value=f"/{node.regex}/",
            children=children if children else None,
        )
