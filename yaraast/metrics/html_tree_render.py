"""Render helpers for HTML tree visualization."""

from __future__ import annotations

import html as html_mod
from typing import Any

from jinja2 import Template

from yaraast.metrics.html_templates import HTML_TREE_TEMPLATE, INTERACTIVE_HTML_TREE_TEMPLATE


def _esc(value: Any) -> str:
    """Escape a value for safe HTML insertion."""
    return html_mod.escape(str(value)) if value is not None else ""


class HtmlTreeRenderMixin:
    """Mixin providing HTML tree render helpers."""

    def _render_template(self, template_text: str, **context: Any) -> str:
        """Render HTML template with shared settings."""
        return Template(template_text).render(**context)

    def _render_html_template(self, tree_data: dict[str, Any], title: str) -> str:
        """Render HTML template with tree data."""
        template_text = HTML_TREE_TEMPLATE
        # Calculate statistics
        stats = self._calculate_stats(tree_data) if self.include_metadata else None

        return self._render_template(
            template_text,
            title=title,
            tree_data=tree_data,
            stats=stats,
            render_node=self._create_render_macro(),
        )

    def _render_interactive_template(
        self,
        tree_data: dict[str, Any],
        title: str,
    ) -> str:
        """Render interactive HTML template with search and filtering."""
        template_text = INTERACTIVE_HTML_TREE_TEMPLATE
        return self._render_template(
            template_text,
            title=title,
            tree_data=tree_data,
            render_node=self._create_render_macro(),
        )

    def _create_render_macro(self):
        """Create render macro function for Jinja2."""

        def render_node(node, depth):
            node_class = _esc(node["node_class"])
            node_id = _esc(node.get("id", ""))
            out = f'<div class="tree-node {node_class}">'

            if node.get("children"):
                out += f'<span class="toggle expanded" id="{node_id}_toggle" onclick="toggleNode(\'{node_id}\')"></span>'

            out += '<div class="node-content">'
            out += f'<span class="node-label">{_esc(node["label"])}</span>'

            if node.get("value"):
                out += f'<span class="node-value">{_esc(node["value"])}</span>'

            if node.get("details"):
                out += f'<div class="node-details">{_esc(node["details"])}</div>'

            out += "</div>"

            if node.get("children"):
                out += f'<div class="children" id="{node_id}_children">'
                for child in node["children"]:
                    out += render_node(child, depth + 1)
                out += "</div>"

            out += "</div>"
            return out

        return render_node

    def _calculate_stats(self, tree_data: dict[str, Any]) -> dict[str, int]:
        """Calculate tree statistics with keys matching the HTML template."""
        stats = {"total_nodes": 0, "rule_count": 0, "import_count": 0, "string_count": 0}

        def count_nodes(node) -> None:
            stats["total_nodes"] += 1
            node_class = node.get("node_class", "")

            if node_class == "rule":
                stats["rule_count"] += 1
            elif node_class == "import":
                stats["import_count"] += 1
            elif node_class == "string":
                stats["string_count"] += 1

            children = node.get("children", [])
            if children:
                for child in children:
                    count_nodes(child)

        count_nodes(tree_data)
        return stats
