"""Extra coverage for dependency_graph_utils with real AST nodes."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

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
from yaraast.errors import ValidationError
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
                name="keyuser",
                condition=DictionaryAccess(object=Identifier("a"), key=Identifier("b")),
            ),
            Rule(
                name="e",
                condition=ForOfExpression(quantifier="all", string_set="not_node", condition=None),
            ),
            Rule(name="f", condition=OfExpression(quantifier="none", string_set="raw")),
            Rule(name="g", condition=OfExpression(quantifier="any", string_set=[Identifier("b")])),
            Rule(
                name="h",
                condition=ForOfExpression(
                    quantifier="any",
                    string_set=[Identifier("c")],
                    condition=None,
                ),
            ),
        ],
    )

    graph = build_dependency_graph(ast)

    assert graph.has_node("a")
    assert graph.get_dependencies("a") == {"b", "c", "d"}
    assert graph.get_dependencies("keyuser") == {"a", "b"}
    assert graph.get_dependencies("e") == set()
    assert graph.get_dependencies("f") == set()
    assert graph.get_dependencies("g") == {"b"}
    assert graph.get_dependencies("h") == {"c"}


def test_build_dependency_graph_does_not_treat_member_root_as_rule_dependency() -> None:
    ast = YaraFile(
        rules=[
            Rule(name="pe", condition=StringLiteral("x")),
            Rule(
                name="check",
                condition=MemberAccess(object=Identifier("pe"), member="number_of_sections"),
            ),
        ],
    )

    graph = build_dependency_graph(ast)

    assert graph.get_dependencies("check") == set()


def test_dependency_graph_order_and_export_error(tmp_path: Path) -> None:
    graph = DependencyGraph()
    graph.add_edge("rule_c", "rule_b")
    graph.add_edge("rule_b", "rule_a")

    order = get_dependency_order(graph)
    assert set(order) == {"rule_a", "rule_b", "rule_c"}

    cycles = find_circular_dependencies(graph)
    assert cycles == []

    with pytest.raises(ValidationError, match="Unsupported format"):
        export_dependency_graph(graph, tmp_path / "deps.bad", format="xml")


def test_dependency_graph_public_outputs_are_stably_sorted() -> None:
    graph = DependencyGraph()
    graph.add_edge("z_rule", "m_rule")
    graph.add_edge("z_rule", "a_rule")
    graph.add_node("solo")

    assert graph.to_dict() == {
        "nodes": ["a_rule", "m_rule", "solo", "z_rule"],
        "edges": {"z_rule": ["a_rule", "m_rule"]},
    }
    assert get_dependency_order(graph) == ["a_rule", "m_rule", "solo", "z_rule"]

    cycle_graph = DependencyGraph()
    cycle_graph.add_edge("b_rule", "c_rule")
    cycle_graph.add_edge("c_rule", "a_rule")
    cycle_graph.add_edge("a_rule", "b_rule")

    assert find_circular_dependencies(cycle_graph) == [["a_rule", "b_rule", "c_rule", "a_rule"]]


def test_dependency_graph_rejects_invalid_public_node_inputs_without_partial_update() -> None:
    graph = DependencyGraph()
    graph.add_edge("existing", "dependency")

    with pytest.raises(ValidationError, match="DependencyGraph node must be a string"):
        graph.add_node(cast(Any, object()))
    with pytest.raises(ValidationError, match="DependencyGraph edge source must be a string"):
        graph.add_edge(cast(Any, object()), "dependency")
    with pytest.raises(ValidationError, match="DependencyGraph edge target must be a string"):
        graph.add_edge("existing", cast(Any, object()))
    with pytest.raises(ValidationError, match="DependencyGraph node must be a string"):
        graph.has_node(cast(Any, object()))
    with pytest.raises(ValidationError, match="DependencyGraph edge source must be a string"):
        graph.has_edge(cast(Any, object()), "dependency")
    with pytest.raises(ValidationError, match="DependencyGraph edge target must be a string"):
        graph.has_edge("existing", cast(Any, object()))
    with pytest.raises(ValidationError, match="DependencyGraph node must be a string"):
        graph.get_dependencies(cast(Any, object()))
    with pytest.raises(ValidationError, match="DependencyGraph node must be a string"):
        graph.get_dependents(cast(Any, object()))

    assert graph.to_dict() == {
        "nodes": ["dependency", "existing"],
        "edges": {"existing": ["dependency"]},
    }


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ("graph", "DependencyGraph data must be an object"),
        ({"nodes": "abc"}, "DependencyGraph nodes must be a list of strings"),
        ({"nodes": [1]}, "DependencyGraph nodes must be a list of strings"),
        ({"edges": "abc"}, "DependencyGraph edges must be an object"),
        ({"edges": {1: ["a"]}}, "DependencyGraph edge names must be strings"),
        ({"edges": {"a": "b"}}, "DependencyGraph edge targets must be a list of strings"),
        ({"edges": {"a": [1]}}, "DependencyGraph edge targets must be a list of strings"),
    ],
)
def test_dependency_graph_from_dict_rejects_invalid_payloads_without_clearing(
    payload: object,
    message: str,
) -> None:
    graph = DependencyGraph()
    graph.add_edge("existing", "dependency")

    with pytest.raises(ValidationError, match=message):
        graph.from_dict(cast(Any, payload))

    assert graph.has_edge("existing", "dependency")
