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

    assert "a" in graph.nodes
    assert graph.get_dependencies("a") == {"b", "c", "d"}
    assert graph.get_dependencies("keyuser") == {"a", "b"}
    assert graph.get_dependencies("e") == set()
    assert graph.get_dependencies("f") == set()
    assert graph.get_dependencies("g") == {"b"}
    assert graph.get_dependencies("h") == {"c"}


def test_build_dependency_graph_tracks_function_call_receiver_dependencies() -> None:
    ast = YaraFile(
        rules=[
            Rule(name="base", condition=StringLiteral("x")),
            Rule(
                name="caller",
                condition=FunctionCall(
                    function="method", arguments=[], receiver=Identifier("base")
                ),
            ),
        ]
    )

    graph = build_dependency_graph(ast)

    assert graph.get_dependencies("caller") == {"base"}


def test_build_dependency_graph_tracks_rule_wildcard_sets() -> None:
    ast = YaraFile(
        rules=[
            Rule(name="a1", condition=StringLiteral("x")),
            Rule(name="a2", condition=StringLiteral("x")),
            Rule(name="other", condition=StringLiteral("x")),
            Rule(
                name="caller",
                condition=OfExpression("any", ParenthesesExpression(StringWildcard("a*"))),
            ),
        ],
    )

    graph = build_dependency_graph(ast)

    assert graph.get_dependencies("caller") == {"a1", "a2"}
    assert graph.get_dependents("a1") == {"caller"}
    assert graph.get_dependents("a2") == {"caller"}
    assert graph.get_dependencies("other") == set()


@pytest.mark.parametrize(
    "string_set",
    [
        [StringWildcard("a*")],
        SetExpression([StringWildcard("a*")]),
    ],
)
def test_build_dependency_graph_tracks_rule_wildcards_in_conditionless_for_of_string_sets(
    string_set: Any,
) -> None:
    ast = YaraFile(
        rules=[
            Rule(name="a1", condition=StringLiteral("x")),
            Rule(name="a2", condition=StringLiteral("x")),
            Rule(name="other", condition=StringLiteral("x")),
            Rule(name="caller", condition=ForOfExpression("any", string_set, None)),
        ],
    )

    graph = build_dependency_graph(ast)

    assert graph.get_dependencies("caller") == {"a1", "a2"}
    assert graph.get_dependents("a1") == {"caller"}
    assert graph.get_dependents("a2") == {"caller"}
    assert graph.get_dependencies("other") == set()


@pytest.mark.parametrize(
    "string_set",
    [
        ["a*"],
        SetExpression([StringLiteral("a*")]),
    ],
)
def test_build_dependency_graph_treats_raw_wildcards_as_string_sets(
    string_set: Any,
) -> None:
    ast = YaraFile(
        rules=[
            Rule(name="a1", condition=StringLiteral("x")),
            Rule(name="a2", condition=StringLiteral("x")),
            Rule(name="caller", condition=ForOfExpression("any", string_set, None)),
        ],
    )

    graph = build_dependency_graph(ast)

    assert graph.get_dependencies("caller") == set()
    assert graph.get_dependents("a1") == set()
    assert graph.get_dependents("a2") == set()


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


@pytest.mark.parametrize("output_path", ["", "   ", "\t"])
def test_export_dependency_graph_rejects_empty_output_paths(output_path: str) -> None:
    graph = DependencyGraph()

    with pytest.raises(ValueError, match="output_path must not be empty"):
        export_dependency_graph(graph, output_path, format="json")


def test_export_dependency_graph_rejects_invalid_output_paths(tmp_path: Path) -> None:
    graph = DependencyGraph()

    with pytest.raises(ValueError, match="output_path must not be a directory"):
        export_dependency_graph(graph, tmp_path, format="json")
    with pytest.raises(TypeError, match="output_path must be a file path"):
        export_dependency_graph(graph, cast(Any, False), format="json")


def test_dependency_graph_public_outputs_are_stably_sorted() -> None:
    graph = DependencyGraph()
    graph.add_edge("z_rule", "m_rule")
    graph.add_edge("z_rule", "a_rule")
    graph.add_node("solo")

    assert graph.to_dict() == {
        "nodes": ["a_rule", "m_rule", "solo", "z_rule"],
        "edges": {"z_rule": ["a_rule", "m_rule"]},
    }


def test_dependency_graph_rejects_invalid_public_node_inputs_without_partial_update() -> None:
    graph = DependencyGraph()
    graph.add_edge("existing", "dependency")

    with pytest.raises(ValidationError, match="DependencyGraph node must not be empty"):
        graph.add_node("")
    with pytest.raises(ValidationError, match="DependencyGraph node must not be empty"):
        graph.add_node("   ")
    with pytest.raises(ValidationError, match="DependencyGraph node must be a string"):
        graph.add_node(cast(Any, object()))
    with pytest.raises(ValidationError, match="DependencyGraph edge source must not be empty"):
        graph.add_edge("", "dependency")
    with pytest.raises(ValidationError, match="DependencyGraph edge source must not be empty"):
        graph.add_edge("   ", "dependency")
    with pytest.raises(ValidationError, match="DependencyGraph edge source must be a string"):
        graph.add_edge(cast(Any, object()), "dependency")
    with pytest.raises(ValidationError, match="DependencyGraph edge target must not be empty"):
        graph.add_edge("existing", "")
    with pytest.raises(ValidationError, match="DependencyGraph edge target must not be empty"):
        graph.add_edge("existing", "\t")
    with pytest.raises(ValidationError, match="DependencyGraph edge target must be a string"):
        graph.add_edge("existing", cast(Any, object()))
    with pytest.raises(ValidationError, match="DependencyGraph node must not be empty"):
        graph.get_dependencies("   ")
    with pytest.raises(ValidationError, match="DependencyGraph node must be a string"):
        graph.get_dependencies(cast(Any, object()))
    with pytest.raises(ValidationError, match="DependencyGraph node must not be empty"):
        graph.get_dependents("\t")
    with pytest.raises(ValidationError, match="DependencyGraph node must be a string"):
        graph.get_dependents(cast(Any, object()))

    assert graph.to_dict() == {
        "nodes": ["dependency", "existing"],
        "edges": {"existing": ["dependency"]},
    }
