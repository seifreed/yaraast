"""Additional tests for dependency graph utilities (no mocks)."""

from __future__ import annotations

from pathlib import Path

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import ForExpression, InExpression
from yaraast.ast.expressions import Identifier, IntegerLiteral, RangeExpression, SetExpression
from yaraast.ast.rules import Rule
from yaraast.metrics.dependency_graph_utils import (
    analyze_dependencies,
    build_dependency_graph,
    export_dependency_graph,
    find_circular_dependencies,
    generate_dot_graph,
    get_dependency_order,
)
from yaraast.parser import Parser
from yaraast.parser.source import parse_yara_source
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    LambdaExpression,
    ListExpression,
    WithDeclaration,
    WithStatement,
)


def test_dependency_graph_basic() -> None:
    code = """
rule a { condition: true }
rule b { condition: a }
""".lstrip()

    ast = Parser().parse(code)
    graph = build_dependency_graph(ast)

    assert "a" in graph.nodes and "b" in graph.nodes
    assert "a" in graph.get_dependencies("b")
    assert graph.get_dependencies("a") == set()

    report = analyze_dependencies(ast)
    assert report["stats"]["total_rules"] == 2
    assert report["stats"]["rules_with_deps"] == 1


def test_dependency_graph_traverses_in_expression_subject_nodes() -> None:
    ast = YaraFile(
        rules=[
            Rule(name="base", condition=IntegerLiteral(1)),
            Rule(
                name="caller",
                condition=InExpression(
                    subject=Identifier("base"),
                    range=RangeExpression(IntegerLiteral(0), IntegerLiteral(10)),
                ),
            ),
        ]
    )

    graph = build_dependency_graph(ast)

    assert graph.get_dependencies("caller") == {"base"}


def test_dependency_graph_traverses_for_expression_quantifier_nodes() -> None:
    ast = YaraFile(
        rules=[
            Rule(name="base", condition=IntegerLiteral(1)),
            Rule(
                name="caller",
                condition=ForExpression(
                    quantifier=Identifier("base"),
                    variable="i",
                    iterable=SetExpression([IntegerLiteral(1)]),
                    body=Identifier("body"),
                ),
            ),
            Rule(name="body", condition=IntegerLiteral(1)),
        ]
    )

    graph = build_dependency_graph(ast)

    assert graph.get_dependencies("caller") == {"base", "body"}


def test_dependency_graph_ignores_for_expression_local_variable_shadowing_rule() -> None:
    ast = Parser().parse("""
rule i { condition: true }
rule caller {
    condition:
        for all i in (1, 2, 3) : (i > 0)
}
""")

    graph = build_dependency_graph(ast)

    assert graph.get_dependencies("caller") == set()


def test_dependency_graph_ignores_yarax_local_variable_shadowing_rules() -> None:
    shadowed_rules = [
        Rule(name="x", condition=IntegerLiteral(1)),
        Rule(name="k", condition=IntegerLiteral(1)),
        Rule(name="v", condition=IntegerLiteral(1)),
    ]
    cases = [
        ArrayComprehension(
            expression=Identifier("x"),
            variable="x",
            iterable=ListExpression([IntegerLiteral(1)]),
        ),
        DictComprehension(
            key_expression=Identifier("k"),
            value_expression=Identifier("v"),
            key_variable="k",
            value_variable="v",
            iterable=ListExpression([IntegerLiteral(1)]),
        ),
        WithStatement(
            declarations=[WithDeclaration("x", IntegerLiteral(1))],
            body=Identifier("x"),
        ),
        LambdaExpression(parameters=["x"], body=Identifier("x")),
    ]

    for condition in cases:
        ast = YaraFile(rules=[*shadowed_rules, Rule(name="caller", condition=condition)])
        graph = build_dependency_graph(ast)

        assert graph.get_dependencies("caller") == set()


def test_dependency_graph_keeps_bare_rule_dependency_distinct_from_dollar_local() -> None:
    ast = YaraFile(
        rules=[
            Rule(name="x", condition=IntegerLiteral(1)),
            Rule(
                name="caller",
                condition=WithStatement(
                    declarations=[WithDeclaration("$x", IntegerLiteral(1))],
                    body=Identifier("x"),
                ),
            ),
        ]
    )

    graph = build_dependency_graph(ast)

    assert graph.get_dependencies("caller") == {"x"}


def test_dependency_graph_traverses_yarax_with_match_nodes() -> None:
    ast = parse_yara_source("""
        rule base { condition: true }
        rule caller {
            condition:
                with xs = [1]: match xs { _ => base }
        }
        """)

    graph = build_dependency_graph(ast)

    assert graph.get_dependencies("caller") == {"base"}


def test_dependency_graph_cycles_and_order() -> None:
    code = """
rule a { condition: b }
rule b { condition: a }
""".lstrip()
    ast = Parser().parse(code)
    graph = build_dependency_graph(ast)

    cycles = find_circular_dependencies(graph)
    assert cycles
    flat = {node for cycle in cycles for node in cycle}
    assert {"a", "b"}.issubset(flat)

    order = get_dependency_order(graph)
    assert set(order) == {"a", "b"}


def test_dependency_graph_export(tmp_path: Path) -> None:
    code = "rule a { condition: true }"
    ast = Parser().parse(code)
    graph = build_dependency_graph(ast)

    json_path = tmp_path / "deps.json"
    dot_path = tmp_path / "deps.dot"

    export_dependency_graph(graph, json_path, format="json")
    export_dependency_graph(graph, dot_path, format="dot")

    assert json_path.read_text(encoding="utf-8").strip().startswith("{")
    assert "digraph" in dot_path.read_text(encoding="utf-8")

    dot = generate_dot_graph(graph)
    assert "a" in dot
