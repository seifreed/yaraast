"""Extra node helpers for HTML tree visualization."""

from __future__ import annotations

from typing import Any


class HtmlTreeNodesExtraMixin:
    """Mixin providing additional HTML tree node helpers."""

    def visit_binary_expression(self, node) -> dict[str, Any]:
        """Visit binary expression node."""
        children = [
            self.visit(node.left),
            {
                "id": self._get_node_id(),
                "label": "Operator",
                "node_class": "operator",
                "value": node.operator,
            },
            self.visit(node.right),
        ]

        return {
            "id": self._get_node_id(),
            "label": "Binary Expression",
            "node_class": "expression",
            "details": f"Operator: {node.operator}",
            "children": children,
        }

    def visit_string_identifier(self, node) -> dict[str, Any]:
        """Visit string identifier node."""
        return {
            "id": self._get_node_id(),
            "label": "String Identifier",
            "node_class": "expression",
            "value": node.name,
        }

    def visit_hex_wildcard(self, node) -> dict[str, Any]:
        """Visit hex wildcard node."""
        return {
            "id": self._get_node_id(),
            "label": "Hex Wildcard",
            "node_class": "hex-wildcard",
            "value": "??",
        }

    def visit_string_wildcard(self, node) -> dict[str, Any]:
        """Visit StringWildcard node."""
        return {"type": "StringWildcard", "pattern": node.pattern}

    def visit_condition(self, node) -> dict[str, Any]:
        return {
            "id": self._get_node_id(),
            "label": "Condition",
            "node_class": "condition",
        }
