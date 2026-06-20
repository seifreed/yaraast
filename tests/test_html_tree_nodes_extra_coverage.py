"""Coverage for HtmlTreeGenerator's YARA-X node HTML-tree builders.

Visiting parsed/constructed YARA-X expression nodes through the generator drives
the HtmlTreeNodesExtraMixin visit methods (comprehensions, tuples, lists, dicts,
slices, lambda, match, with-statement, binary expressions).
"""

from __future__ import annotations

import pytest

from yaraast.ast.expressions import Identifier, IntegerLiteral
from yaraast.metrics.html_tree import HtmlTreeGenerator
from yaraast.yarax.ast_nodes import WithDeclaration, WithStatement
from yaraast.yarax.parser import YaraXParser


@pytest.mark.parametrize(
    "expression",
    [
        "[x for x in (1, 2, 3) if x > 0]",
        "{k: v for k, v in pairs}",
        "(1, 2, 3)",
        "(1, 2, 3)[0]",
        "[1, 2, 3]",
        "[...a, b]",
        '{"k": 1}',
        '{**a, "k": 1}',
        "arr[0:2:1]",
        "lambda x: x + 1",
        "match v { 1 => true, _ => false }",
        "1 + 2 > 0",
    ],
)
def test_html_tree_builds_node_dict_for_yarax(expression: str) -> None:
    node = YaraXParser(expression).parse_expression()
    result = HtmlTreeGenerator().visit(node)

    assert isinstance(result, dict)
    assert "label" in result
    assert "children" in result


def test_html_tree_builds_with_statement_node() -> None:
    statement = WithStatement(
        declarations=[WithDeclaration(identifier="a", value=IntegerLiteral(value=1))],
        body=Identifier(name="a"),
    )
    result = HtmlTreeGenerator().visit(statement)
    assert isinstance(result, dict)
    assert "children" in result
