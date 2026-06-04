"""Extra node helpers for HTML tree visualization."""

from __future__ import annotations

from typing import Any


class HtmlTreeNodesExtraMixin:
    """Mixin providing additional HTML tree node helpers."""

    def _single_child_section(
        self,
        label: str,
        node_class: str,
        child: Any,
    ) -> dict[str, Any] | None:
        if child is None:
            return None
        return self._simple_node(label, node_class, children=[self.visit(child)])

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

    def visit_with_statement(self, node) -> dict[str, Any]:
        children: list[dict[str, Any]] = []
        self._append_section(
            children,
            self._children_section("Declarations", "with-declarations", node.declarations),
        )
        self._append_section(
            children,
            self._single_child_section("Body", "with-body", node.body),
        )
        return self._simple_expression_node(
            "With Statement",
            value=f"{len(node.declarations)} declaration(s)",
        ) | {"children": children}

    def visit_with_declaration(self, node) -> dict[str, Any]:
        children: list[dict[str, Any]] = []
        self._append_section(
            children,
            self._single_child_section("Value", "with-value", node.value),
        )
        return self._simple_expression_node("With Declaration", value=node.identifier) | {
            "children": children
        }

    def visit_array_comprehension(self, node) -> dict[str, Any]:
        children: list[dict[str, Any]] = []
        self._append_section(
            children,
            self._single_child_section("Expression", "comprehension-expression", node.expression),
        )
        self._append_section(
            children,
            self._single_child_section("Iterable", "comprehension-iterable", node.iterable),
        )
        self._append_section(
            children,
            self._single_child_section("Condition", "comprehension-condition", node.condition),
        )
        return self._simple_expression_node("Array Comprehension", value=node.variable) | {
            "children": children
        }

    def visit_dict_comprehension(self, node) -> dict[str, Any]:
        children: list[dict[str, Any]] = []
        for label, node_class, child in (
            ("Key Expression", "comprehension-key", node.key_expression),
            ("Value Expression", "comprehension-value", node.value_expression),
            ("Iterable", "comprehension-iterable", node.iterable),
            ("Condition", "comprehension-condition", node.condition),
        ):
            self._append_section(children, self._single_child_section(label, node_class, child))
        variables = node.key_variable
        if node.value_variable:
            variables = f"{variables}, {node.value_variable}"
        return self._simple_expression_node("Dict Comprehension", value=variables) | {
            "children": children
        }

    def visit_tuple_expression(self, node) -> dict[str, Any]:
        children = self._child_nodes(node.elements)
        return self._simple_expression_node(
            "Tuple Expression",
            value=f"{len(node.elements)} element(s)",
        ) | {"children": children}

    def visit_tuple_indexing(self, node) -> dict[str, Any]:
        children: list[dict[str, Any]] = []
        self._append_section(
            children,
            self._single_child_section("Tuple", "tuple-target", node.tuple_expr),
        )
        self._append_section(
            children,
            self._single_child_section("Index", "tuple-index", node.index),
        )
        return self._simple_expression_node("Tuple Indexing") | {"children": children}

    def visit_list_expression(self, node) -> dict[str, Any]:
        children = self._child_nodes(node.elements)
        return self._simple_expression_node(
            "List Expression",
            value=f"{len(node.elements)} element(s)",
        ) | {"children": children}

    def visit_dict_expression(self, node) -> dict[str, Any]:
        children = self._child_nodes(node.items)
        return self._simple_expression_node(
            "Dict Expression",
            value=f"{len(node.items)} item(s)",
        ) | {"children": children}

    def visit_dict_item(self, node) -> dict[str, Any]:
        children: list[dict[str, Any]] = []
        self._append_section(children, self._single_child_section("Key", "dict-key", node.key))
        self._append_section(
            children,
            self._single_child_section("Value", "dict-value", node.value),
        )
        return self._simple_expression_node("Dict Item") | {"children": children}

    def visit_slice_expression(self, node) -> dict[str, Any]:
        children: list[dict[str, Any]] = []
        for label, node_class, child in (
            ("Target", "slice-target", node.target),
            ("Start", "slice-start", node.start),
            ("Stop", "slice-stop", node.stop),
            ("Step", "slice-step", node.step),
        ):
            self._append_section(children, self._single_child_section(label, node_class, child))
        return self._simple_expression_node("Slice Expression") | {"children": children}

    def visit_lambda_expression(self, node) -> dict[str, Any]:
        children: list[dict[str, Any]] = []
        self._append_section(
            children,
            self._single_child_section("Body", "lambda-body", node.body),
        )
        return self._simple_expression_node(
            "Lambda Expression",
            value=", ".join(node.parameters),
        ) | {"children": children}

    def visit_pattern_match(self, node) -> dict[str, Any]:
        children: list[dict[str, Any]] = []
        self._append_section(
            children,
            self._single_child_section("Value", "match-value", node.value),
        )
        self._append_section(
            children,
            self._children_section("Cases", "match-cases", node.cases),
        )
        self._append_section(
            children,
            self._single_child_section("Default", "match-default", node.default),
        )
        return self._simple_expression_node("Pattern Match") | {"children": children}

    def visit_match_case(self, node) -> dict[str, Any]:
        children: list[dict[str, Any]] = []
        self._append_section(
            children,
            self._single_child_section("Pattern", "match-pattern", node.pattern),
        )
        self._append_section(
            children,
            self._single_child_section("Result", "match-result", node.result),
        )
        return self._simple_expression_node("Match Case") | {"children": children}

    def visit_spread_operator(self, node) -> dict[str, Any]:
        children: list[dict[str, Any]] = []
        self._append_section(
            children,
            self._single_child_section("Expression", "spread-expression", node.expression),
        )
        kind = "dict" if node.is_dict else "list"
        return self._simple_expression_node("Spread Operator", value=kind) | {"children": children}
