"""Additional real coverage for small builder and html tree helpers."""

from __future__ import annotations

from yaraast.ast.expressions import FunctionCall, Identifier, StringLiteral
from yaraast.builder.fluent_condition_helpers import (
    build_entropy_call,
    build_of_expression,
    build_string_set,
    chain_or,
)
from yaraast.errors import ValidationError
from yaraast.metrics.html_tree_nodes_extra import HtmlTreeNodesExtraMixin


class _HtmlExtraVisitor(HtmlTreeNodesExtraMixin):
    def __init__(self) -> None:
        self._counter = 0

    def _get_node_id(self) -> str:
        self._counter += 1
        return f"n{self._counter}"

    def visit(self, node):
        return {"id": self._get_node_id(), "value": getattr(node, "name", "node")}


class _PatternNode:
    def __init__(self, pattern: str) -> None:
        self.pattern = pattern


def test_fluent_condition_small_helpers_more() -> None:
    string_set = build_string_set("them", "them")
    assert isinstance(string_set, Identifier)
    assert string_set.name == "them"

    of_expr = build_of_expression("any", Identifier(name="them"))
    assert isinstance(of_expr.quantifier, StringLiteral)
    assert of_expr.quantifier.value == "any"

    entropy_call = build_entropy_call(0, 1024)
    assert isinstance(entropy_call, FunctionCall)
    assert entropy_call.function == "math.entropy"
    assert len(entropy_call.arguments) == 2

    try:
        chain_or([])
    except ValidationError as exc:
        assert "Expected at least one condition" in str(exc)
    else:
        raise AssertionError("chain_or([]) should raise")


def test_html_tree_nodes_extra_missing_visitors() -> None:
    visitor = _HtmlExtraVisitor()

    wildcard = visitor.visit_string_wildcard(_PatternNode("$a*"))
    assert wildcard == {"type": "StringWildcard", "pattern": "$a*"}

    condition = visitor.visit_condition(object())
    assert condition["label"] == "Condition"
    assert condition["node_class"] == "condition"
