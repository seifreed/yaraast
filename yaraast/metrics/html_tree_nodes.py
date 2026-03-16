"""Node helpers for HTML tree visualization."""

from __future__ import annotations

import html as html_mod
from collections.abc import Iterable
from pathlib import Path
from typing import Any


class HtmlTreeNodesMixin:
    """Mixin providing HTML tree node helpers."""

    def _write_output(self, output_path: str | None, html_content: str) -> None:
        """Write HTML content to disk if an output path is provided."""
        if output_path:
            with Path(output_path).open("w", encoding="utf-8") as f:
                f.write(html_content)

    def _get_node_id(self) -> str:
        """Get unique node ID."""
        self.node_counter += 1
        return f"node_{self.node_counter}"

    def _simple_node(
        self,
        label: str,
        node_class: str,
        value: str | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        node = {"id": self._get_node_id(), "label": label, "node_class": node_class}
        if value is not None:
            node["value"] = value
        node.update(extra)
        return node

    def _child_nodes(self, items: Iterable[Any]) -> list[dict[str, Any]]:
        return [self.visit(item) for item in items]

    def _children_section(
        self,
        label: str,
        node_class: str,
        items: Iterable[Any],
    ) -> dict[str, Any] | None:
        children = self._child_nodes(items)
        if not children:
            return None
        return self._simple_node(label, node_class, children=children)

    def _append_section(
        self, children: list[dict[str, Any]], section: dict[str, Any] | None
    ) -> None:
        if section:
            children.append(section)

    def _meta_section(self, meta: dict[str, Any]) -> dict[str, Any] | None:
        if not meta:
            return None
        meta_children = [
            self._simple_node(
                f"Meta: {html_mod.escape(str(key))}", "meta", value=html_mod.escape(str(value))
            )
            for key, value in meta.items()
        ]
        return self._simple_node("Meta", "meta-section", children=meta_children)

    def _simple_expression_node(self, label: str, value: str | None = None) -> dict[str, Any]:
        return self._simple_node(label, "expression", value=value)

    def _simple_literal_node(self, label: str, value: str | None = None) -> dict[str, Any]:
        return self._simple_node(label, "literal", value=value)

    def _simple_comment_node(self, label: str) -> dict[str, Any]:
        return self._simple_node(label, "comment")

    def _simple_meta_node(self, label: str) -> dict[str, Any]:
        return self._simple_node(label, "meta")

    def _simple_pragma_node(self, label: str) -> dict[str, Any]:
        return self._simple_node(label, "pragma")

    def _string_modifiers_section(self, modifiers: Iterable[Any]) -> dict[str, Any] | None:
        return self._children_section("Modifiers", "modifiers", modifiers)

    def _string_node(
        self,
        label: str,
        value: str | None = None,
        details: str | None = None,
        children: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        node = self._simple_node(label, "string", value=value)
        if details:
            node["details"] = details
        if children:
            node["children"] = children
        return node

    def _condition_section(self, condition: Any) -> dict[str, Any] | None:
        if not condition:
            return None
        return {
            "id": self._get_node_id(),
            "label": "Condition",
            "node_class": "condition-section",
            "children": [self.visit(condition)],
        }
