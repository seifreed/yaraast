"""Extra coverage for dependency_graph_utils with real AST nodes."""

from __future__ import annotations

from pathlib import Path

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import (
    AtExpression,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    StringLiteral,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.modules import DictionaryAccess
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.rules import Rule
from yaraast.metrics.dependency_graph_utils import (
    DependencyGraph,
    build_dependency_graph,
    export_dependency_graph,
    find_circular_dependencies,
    get_dependency_order,
)


def _complex_condition() -> BinaryExpression:
    left = StringOperatorExpression(
        left=DefinedExpression(
            expression=DictionaryAccess(
                object=MemberAccess(object=Identifier("b"), member="field"),
                key="name",
            ),
        ),
        operator="icontains",
        right=FunctionCall(
            function="uint32",
            arguments=[
                ArrayAccess(array=Identifier("c"), index=IntegerLiteral(0)),
                ParenthesesExpression(UnaryExpression(operator="not", operand=Identifier("d"))),
            ],
        ),
    )

    right = BinaryExpression(
        left=ForExpression(
            quantifier="any",
            variable="i",
            iterable=SetExpression([Identifier("b"), Identifier("c")]),
            body=BinaryExpression(
                left=ForOfExpression(
                    quantifier="any",
                    string_set=StringWildcard("$a*"),
                    condition=AtExpression(string_id="$a", offset=IntegerLiteral(10)),
                ),
                operator="and",
                right=InExpression(
                    subject="$a",
                    range=RangeExpression(low=IntegerLiteral(0), high=Identifier("d")),
                ),
            ),
        ),
        operator="or",
        right=OfExpression(
            quantifier=Identifier("b"),
            string_set=SetExpression([Identifier("c"), StringWildcard("$x*")]),
        ),
    )

    return BinaryExpression(left=left, operator="and", right=right)


def test_build_dependency_graph_visits_rare_expression_paths() -> None:
    ast = YaraFile(
        rules=[
            Rule(name="a", condition=_complex_condition()),
            Rule(name="b", condition=StringLiteral("x")),
            Rule(name="c", condition=StringLiteral("x")),
            Rule(name="d", condition=StringLiteral("x")),
            Rule(
                name="e",
                condition=ForOfExpression(quantifier="all", string_set="not_node", condition=None),
            ),
            Rule(name="f", condition=OfExpression(quantifier="none", string_set="raw")),
        ],
    )

    graph = build_dependency_graph(ast)

    assert graph.has_node("a")
    assert graph.get_dependencies("a") == {"b", "c", "d"}
    assert graph.get_dependencies("e") == set()
    assert graph.get_dependencies("f") == set()


def test_dependency_graph_order_and_export_error(tmp_path: Path) -> None:
    graph = DependencyGraph()
    graph.add_edge("rule_c", "rule_b")
    graph.add_edge("rule_b", "rule_a")

    order = get_dependency_order(graph)
    assert set(order) == {"rule_a", "rule_b", "rule_c"}

    cycles = find_circular_dependencies(graph)
    assert cycles == []

    with pytest.raises(ValueError, match="Unsupported format"):
        export_dependency_graph(graph, tmp_path / "deps.bad", format="xml")
