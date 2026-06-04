from __future__ import annotations

import re
from typing import Any, cast

import pytest

from yaraast.analysis.dependency_analyzer import DependencyAnalyzer
from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import ForExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    BooleanLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    RangeExpression,
    SetExpression,
    StringWildcard,
)
from yaraast.ast.rules import Import, Include, Rule
from yaraast.parser import Parser
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    LambdaExpression,
    ListExpression,
    WithDeclaration,
    WithStatement,
)


def test_dependency_analyzer_import_include_and_direct_visitors() -> None:
    analyzer = DependencyAnalyzer()
    analyzer.visit_import(Import("pe"))
    analyzer.visit_include(Include("common.yar"))
    assert analyzer.imported_modules == {"pe"}
    assert analyzer.included_files == {"common.yar"}

    analyzer.rule_names = {"callee"}
    analyzer.current_rule = None
    analyzer.visit_identifier(Identifier("callee"))
    assert analyzer.dependencies == {}

    analyzer.current_rule = "caller"
    analyzer.visit_identifier(Identifier("callee"))
    analyzer.visit_function_call(FunctionCall("other", [Identifier("callee")]))
    assert analyzer.dependencies["caller"] == {"callee"}


def test_dependency_analyzer_cycle_dedup_transitive_and_topological_none() -> None:
    analyzer = DependencyAnalyzer()
    analyzer.rule_names = {"a", "b", "c", "d"}
    analyzer.dependencies["a"].update({"b", "external"})
    analyzer.dependencies["b"].add("c")
    analyzer.dependencies["c"].add("a")
    analyzer.dependencies["d"] = set()

    transitive = analyzer.get_transitive_dependencies("a")
    assert transitive == {"b", "c", "external"}

    graph = analyzer._build_dependency_graph()
    assert graph["d"]["is_independent"] is True
    assert "external" in graph["a"]["depends_on"]

    cycles = analyzer._find_circular_dependencies()
    assert len(cycles) == 1
    assert cycles[0][0] == cycles[0][-1]  # Cycle is properly closed
    assert set(cycles[0]) == {"a", "b", "c"}

    deduped = analyzer._remove_duplicate_cycles([["a", "b", "c", "a"], ["b", "c", "a", "b"]])
    assert len(deduped) == 1
    assert deduped[0][0] == deduped[0][-1]  # Closed cycle

    assert analyzer._topological_sort() is None


def test_dependency_analyzer_visit_rule_and_analyze_full_file() -> None:
    ast = Parser().parse("""
import "pe"
include "common.yar"

rule base {
    condition:
        true
}

rule caller {
    condition:
        base and helper(base)
}
""")
    analyzer = DependencyAnalyzer()
    results = analyzer.analyze(ast)

    assert results["imported_modules"] == ["pe"]
    assert results["included_files"] == ["common.yar"]
    assert set(results["dependencies"]["caller"]) == {"base"}
    assert analyzer.get_dependencies("caller") == ["base"]
    assert analyzer.get_dependents("base") == ["caller"]
    assert analyzer.get_transitive_dependencies("caller") == {"base"}

    rule = Rule(name="empty", condition=None)
    analyzer.visit_rule(rule)
    assert analyzer.current_rule is None


def test_dependency_analyzer_preserves_duplicate_rule_occurrences() -> None:
    ast = Parser().parse("""
rule dup_first {
    condition:
        true
}

rule dup_second {
    condition:
        helper
}

rule helper {
    condition:
        true
}

rule caller {
    condition:
        dup
}
""")
    ast.rules[0].name = "dup"
    ast.rules[1].name = "dup"
    analyzer = DependencyAnalyzer()

    results = analyzer.analyze(ast)

    assert results["rules"] == ["caller", "dup#1", "dup#2", "helper"]
    assert results["dependencies"]["dup#2"] == ["helper"]
    assert results["dependencies"]["caller"] == ["dup#1", "dup#2"]
    assert results["dependency_graph"]["dup#1"]["is_independent"] is False
    assert results["dependency_graph"]["dup#2"]["depends_on"] == ["helper"]
    assert analyzer.get_dependencies("caller") == ["dup#1", "dup#2"]
    assert analyzer.get_dependents("helper") == ["dup#2"]


def test_dependency_analyzer_tracks_rule_wildcard_sets() -> None:
    ast = Parser().parse("""
rule a1 {
    condition:
        true
}

rule a2 {
    condition:
        true
}

rule other {
    condition:
        true
}

rule caller {
    condition:
        any of (a*)
}
""")

    results = DependencyAnalyzer().analyze(ast)

    assert results["dependencies"]["caller"] == ["a1", "a2"]
    assert results["dependency_graph"]["a1"]["depended_by"] == ["caller"]
    assert results["dependency_graph"]["a2"]["depended_by"] == ["caller"]
    assert results["dependency_graph"]["other"]["is_independent"] is True


def test_dependency_analyzer_does_not_treat_function_name_as_rule_dependency() -> None:
    ast = Parser().parse("""
rule helper {
    condition:
        true
}

rule base {
    condition:
        true
}

rule caller {
    condition:
        helper(base)
}
""")

    results = DependencyAnalyzer().analyze(ast)

    assert results["dependencies"]["caller"] == ["base"]


def test_dependency_analyzer_does_not_treat_module_member_root_as_rule_dependency() -> None:
    ast = YaraFile(
        imports=[Import("pe")],
        rules=[
            Rule(name="pe", condition=BooleanLiteral(True)),
            Rule(
                name="check",
                condition=MemberAccess(
                    object=Identifier("pe"),
                    member="number_of_sections",
                ),
            ),
        ],
    )

    results = DependencyAnalyzer().analyze(ast)

    assert "check" not in results["dependencies"]
    assert results["dependency_graph"]["check"]["depends_on"] == []


def test_dependency_analyzer_does_not_treat_self_reference_as_dependency() -> None:
    ast = YaraFile(
        rules=[
            Rule(name="self_ref", condition=Identifier("self_ref")),
            Rule(name="other", condition=BooleanLiteral(True)),
        ]
    )

    results = DependencyAnalyzer().analyze(ast)

    assert "self_ref" not in results["dependencies"]
    assert results["dependency_graph"]["self_ref"]["is_independent"] is True


def test_dependency_analyzer_public_lists_are_stably_sorted() -> None:
    ast = YaraFile(
        imports=[Import("pe"), Import("math")],
        includes=[Include("z.yar"), Include("a.yar")],
        rules=[
            Rule(name="z_rule", condition=Identifier("a_rule")),
            Rule(name="a_rule", condition=BooleanLiteral(True)),
        ],
    )

    results = DependencyAnalyzer().analyze(ast)

    assert results["rules"] == ["a_rule", "z_rule"]
    assert results["dependencies"] == {"z_rule": ["a_rule"]}
    assert results["dependency_graph"]["z_rule"]["depends_on"] == ["a_rule"]
    assert results["dependency_graph"]["a_rule"]["depended_by"] == ["z_rule"]
    assert results["dependency_order"] == ["a_rule", "z_rule"]
    assert results["imported_modules"] == ["math", "pe"]
    assert results["included_files"] == ["a.yar", "z.yar"]


def test_dependency_analyzer_traverses_in_expression_subject_nodes() -> None:
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

    results = DependencyAnalyzer().analyze(ast)

    assert results["dependencies"]["caller"] == ["base"]


def test_dependency_analyzer_traverses_for_expression_quantifier_nodes() -> None:
    ast = YaraFile(
        rules=[
            Rule(name="base", condition=IntegerLiteral(1)),
            Rule(
                name="caller",
                condition=ForExpression(
                    quantifier=Identifier("base"),
                    variable="i",
                    iterable=SetExpression([IntegerLiteral(1)]),
                    body=BooleanLiteral(True),
                ),
            ),
        ]
    )

    results = DependencyAnalyzer().analyze(ast)

    assert results["dependencies"]["caller"] == ["base"]


def test_dependency_analyzer_ignores_for_expression_local_variable_shadowing_rule() -> None:
    ast = Parser().parse("""
rule i {
    condition:
        true
}

rule caller {
    condition:
        for all i in (1, 2, 3) : (i > 0)
}
""")

    results = DependencyAnalyzer().analyze(ast)

    assert "caller" not in results["dependencies"]


def test_dependency_analyzer_ignores_multi_variable_for_locals() -> None:
    ast = Parser().parse("""
rule k {
    condition:
        true
}

rule v {
    condition:
        true
}

rule caller {
    condition:
        for all k, v in (1, 2, 3) : (k > 0 and v > 0)
}
""")

    results = DependencyAnalyzer().analyze(ast)

    assert "caller" not in results["dependencies"]


def test_dependency_analyzer_ignores_yarax_local_variable_shadowing_rules() -> None:
    shadowed_rules = [
        Rule(name="x", condition=BooleanLiteral(True)),
        Rule(name="k", condition=BooleanLiteral(True)),
        Rule(name="v", condition=BooleanLiteral(True)),
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

        results = DependencyAnalyzer().analyze(ast)

        assert "caller" not in results["dependencies"]


def test_dependency_analyzer_keeps_bare_rule_dependency_distinct_from_dollar_local() -> None:
    ast = YaraFile(
        rules=[
            Rule(name="x", condition=BooleanLiteral(True)),
            Rule(
                name="caller",
                condition=WithStatement(
                    declarations=[WithDeclaration("$x", IntegerLiteral(1))],
                    body=Identifier("x"),
                ),
            ),
        ]
    )

    results = DependencyAnalyzer().analyze(ast)

    assert results["dependencies"]["caller"] == ["x"]


def test_dependency_analyzer_rejects_invalid_string_wildcard_pattern() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="caller",
                condition=OfExpression(
                    "any",
                    StringWildcard(cast(Any, False)),
                ),
            )
        ]
    )

    with pytest.raises(TypeError, match="String wildcard pattern must be a string"):
        DependencyAnalyzer().analyze(ast)


@pytest.mark.parametrize(
    "condition",
    [
        ForExpression(
            quantifier="any",
            variable=cast(Any, False),
            iterable=SetExpression([IntegerLiteral(1)]),
            body=BooleanLiteral(True),
        ),
        WithStatement(
            declarations=[WithDeclaration(cast(Any, False), IntegerLiteral(1))],
            body=BooleanLiteral(True),
        ),
        ArrayComprehension(
            expression=IntegerLiteral(1),
            variable=cast(Any, False),
            iterable=ListExpression([IntegerLiteral(1)]),
        ),
        DictComprehension(
            key_expression=Identifier("k"),
            value_expression=Identifier("v"),
            key_variable=cast(Any, False),
            value_variable="v",
            iterable=ListExpression([IntegerLiteral(1)]),
        ),
        LambdaExpression(parameters=[cast(Any, False)], body=BooleanLiteral(True)),
    ],
)
def test_dependency_analyzer_rejects_invalid_local_variable_names(condition: Any) -> None:
    ast = YaraFile(rules=[Rule(name="caller", condition=condition)])

    with pytest.raises(TypeError, match="Local variable name must be a string"):
        DependencyAnalyzer().analyze(ast)


@pytest.mark.parametrize(
    ("condition", "name"),
    [
        (
            ForExpression(
                quantifier="any",
                variable="bad-name",
                iterable=SetExpression([IntegerLiteral(1)]),
                body=BooleanLiteral(True),
            ),
            "bad-name",
        ),
        (
            WithStatement(
                declarations=[WithDeclaration("1bad", IntegerLiteral(1))],
                body=BooleanLiteral(True),
            ),
            "1bad",
        ),
        (
            ArrayComprehension(
                expression=IntegerLiteral(1),
                variable="for",
                iterable=ListExpression([IntegerLiteral(1)]),
            ),
            "for",
        ),
        (
            DictComprehension(
                key_expression=Identifier("k"),
                value_expression=Identifier("v"),
                key_variable="ok",
                value_variable="bad-name",
                iterable=ListExpression([IntegerLiteral(1)]),
            ),
            "bad-name",
        ),
        (LambdaExpression(parameters=["1bad"], body=BooleanLiteral(True)), "1bad"),
    ],
)
def test_dependency_analyzer_rejects_malformed_local_variable_identifiers(
    condition: Any,
    name: str,
) -> None:
    ast = YaraFile(rules=[Rule(name="caller", condition=condition)])

    with pytest.raises(ValueError, match=f"Invalid local variable identifier: {name}"):
        DependencyAnalyzer().analyze(ast)


@pytest.mark.parametrize(
    ("variable", "message"),
    [
        ("", "Local variable name must not be empty"),
        ("i,,j", "Local variable declaration must not contain empty entries: i,,j"),
    ],
)
def test_dependency_analyzer_rejects_empty_local_variable_declarations(
    variable: str,
    message: str,
) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="caller",
                condition=ForExpression(
                    quantifier="any",
                    variable=variable,
                    iterable=SetExpression([IntegerLiteral(1)]),
                    body=BooleanLiteral(True),
                ),
            )
        ]
    )

    with pytest.raises(ValueError, match=re.escape(message)):
        DependencyAnalyzer().analyze(ast)
