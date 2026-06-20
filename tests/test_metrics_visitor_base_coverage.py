"""Coverage for MetricsVisitorBase default YARA-X node traversal.

The base metrics visitor provides default traversal for YARA-X expression nodes
(comprehensions, tuples, lists, dicts, slices, lambdas, match, spread, with).
Visiting parsed/constructed nodes drives those methods and the shared
``_visit_ast_value`` helper.
"""

from __future__ import annotations

import pytest

from yaraast.ast.expressions import Identifier, IntegerLiteral
from yaraast.metrics._visitor_base import MetricsVisitorBase
from yaraast.yarax.ast_nodes import SpreadOperator, WithDeclaration, WithStatement
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
        "arr[0:2]",
        "lambda x: x + 1",
        "match v { 1 => true, _ => false }",
    ],
)
def test_metrics_visitor_traverses_yarax_expressions(expression: str) -> None:
    node = YaraXParser(expression).parse_expression()
    assert MetricsVisitorBase().visit(node) is None


def test_metrics_visitor_traverses_with_statement_and_spread() -> None:
    visitor = MetricsVisitorBase()

    statement = WithStatement(
        declarations=[WithDeclaration(identifier="a", value=IntegerLiteral(value=1))],
        body=Identifier(name="a"),
    )
    assert visitor.visit(statement) is None

    spread = SpreadOperator(expression=Identifier(name="a"), is_dict=False)
    assert visitor.visit(spread) is None
