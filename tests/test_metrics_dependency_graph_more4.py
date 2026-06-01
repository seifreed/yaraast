"""Extra real coverage for dependency graph generator/helpers."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from yaraast.ast.conditions import (
    AtExpression,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    ArrayAccess,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    StringLiteral,
    UnaryExpression,
)
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.rules import Rule, Tag
from yaraast.ast.strings import PlainString
from yaraast.metrics.dependency_graph import DependencyGraphGenerator
from yaraast.metrics.dependency_graph_helpers import render_graph, rule_info
from yaraast.metrics.dependency_graph_utils import build_dependency_graph
from yaraast.parser import Parser


class _RaisingDot:
    source = "digraph G { a -> b }"

    def render(self, _output_file: str, format: str, cleanup: bool = True) -> str:
        raise RuntimeError("failed to execute PosixPath('dot')")


class _BrokenDot:
    source = "digraph G { a -> b }"

    def render(self, _output_file: str, format: str, cleanup: bool = True) -> str:
        raise AttributeError("render state missing")


def test_dependency_graph_helpers_render_and_rule_info(tmp_path: Path) -> None:
    dot = SimpleNamespace(source="digraph G { a -> b }")
    dot_path = tmp_path / "deps.dot"
    assert render_graph(dot, str(dot_path), "dot") == str(dot_path)
    assert "digraph" in dot_path.read_text(encoding="utf-8")

    fallback = render_graph(_RaisingDot(), str(tmp_path / "deps.svg"), "svg")
    assert fallback.endswith(".svg")
    assert Path(fallback).read_text(encoding="utf-8").startswith("digraph")

    rule = Rule(
        name="rich",
        modifiers=["private"],
        tags=[Tag(name="malware")],
        strings=[PlainString(identifier="$a", value="abc")],
        meta={"author": "unit"},
        condition=IntegerLiteral(value=1),
    )
    info = rule_info(rule)
    assert info["tags"] == ["malware"]
    assert info["string_count"] == 1
    assert info["has_meta"] is True
    assert info["has_condition"] is True


def test_dependency_graph_render_propagates_non_graphviz_errors(tmp_path: Path) -> None:
    with pytest.raises(AttributeError, match="render state missing"):
        render_graph(_BrokenDot(), str(tmp_path / "deps.svg"), "svg")


def test_dependency_graph_generator_remaining_visitors_and_stats() -> None:
    code = """
    import "pe"
    include "base.yar"

    rule heavy {
        strings:
            $a0 = "0"
            $a1 = "1"
            $a2 = "2"
            $a3 = "3"
            $a4 = "4"
            $a5 = "5"
            $a6 = "6"
            $a7 = "7"
            $a8 = "8"
            $a9 = "9"
            $a10 = "10"
        condition:
            pe.number_of_sections > 0
    }
    """
    ast = Parser().parse(code)
    gen = DependencyGraphGenerator()
    gen.visit(ast)
    stats = gen.get_dependency_stats()

    assert stats["total_includes"] == 1
    assert "heavy" in stats["complex_rules"]
    assert stats["most_used_modules"][0][0] == "pe"

    gen._current_rule = "manual"
    gen.imports.add("pe")

    gen.visit_member_access(MemberAccess(object=Identifier(name="pe"), member="number_of_sections"))
    gen.visit_member_access(MemberAccess(object=Identifier(name="other"), member="field"))
    gen.visit_function_call(
        SimpleNamespace(function="pe.is_pe", arguments=[IntegerLiteral(value=1)])
    )
    gen.visit_unary_expression(UnaryExpression(operator="not", operand=Identifier(name="x")))
    gen.visit_parentheses_expression(ParenthesesExpression(expression=Identifier(name="x")))
    gen.visit_set_expression(SetExpression(elements=[Identifier(name="a"), Identifier(name="b")]))
    gen.visit_range_expression(
        RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=2))
    )
    gen.visit_array_access(ArrayAccess(array=Identifier(name="arr"), index=IntegerLiteral(value=0)))
    gen.visit_for_expression(
        ForExpression(
            quantifier="any",
            variable="i",
            iterable=RangeExpression(low=IntegerLiteral(value=1), high=IntegerLiteral(value=3)),
            body=Identifier(name="i"),
        )
    )
    gen.visit_at_expression(AtExpression(string_id="$a", offset=IntegerLiteral(value=10)))
    gen.visit_in_expression(
        InExpression(
            subject="$a",
            range=RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=10)),
        )
    )
    gen.visit_of_expression(
        OfExpression(
            quantifier=IntegerLiteral(value=2),
            string_set=SetExpression(elements=[Identifier(name="them")]),
        )
    )
    gen.imports.add("dotnet")
    gen.visit_of_expression(
        OfExpression(
            quantifier="any",
            string_set=[ModuleReference(module="dotnet")],
        )
    )
    gen.visit_for_of_expression(
        ForOfExpression(
            quantifier="any",
            string_set=SetExpression(elements=[Identifier(name="them")]),
            condition=None,
        )
    )
    gen.visit_for_of_expression(
        ForOfExpression(quantifier="all", string_set="them", condition=None)
    )
    gen.visit_for_of_expression(
        ForOfExpression(quantifier="all", string_set=["$a", "$b"], condition=None)
    )
    gen.visit_module_reference(ModuleReference(module="pe"))
    gen.visit_dictionary_access(
        DictionaryAccess(object=ModuleReference(module="pe"), key=StringLiteral(value="k"))
    )
    gen.imports.add("math")
    gen.visit_dictionary_access(
        DictionaryAccess(object=Identifier(name="container"), key=ModuleReference(module="math"))
    )
    gen.visit_defined_expression(DefinedExpression(expression=Identifier(name="x")))
    gen.visit_string_operator_expression(
        StringOperatorExpression(
            left=StringLiteral(value="abc"),
            operator="icontains",
            right=StringLiteral(value="a"),
        )
    )

    assert "pe" in gen.module_references["manual"]
    assert "math" in gen.module_references["manual"]
    assert "dotnet" in gen.module_references["manual"]


def test_dependency_graph_preserves_duplicate_rule_occurrences() -> None:
    ast = Parser().parse("""
import "pe"

rule dup_first {
    strings:
        $a = "a"
    condition:
        $a and pe.number_of_sections > 0
}

rule dup_second {
    strings:
        $b = "b"
    condition:
        $b and helper
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
    gen = DependencyGraphGenerator()

    gen.visit(ast)

    assert set(gen.rules) == {"dup#1", "dup#2", "helper", "caller"}
    assert gen.string_references["dup#1"] == {"$a"}
    assert gen.string_references["dup#2"] == {"$b"}
    assert gen.module_references["dup#1"] == {"pe"}
    assert gen.module_references["dup#2"] == set()
    assert gen.dependencies["dup#2"] == {"helper"}
    assert gen.dependencies["caller"] == {"dup#1", "dup#2"}
    assert gen.get_dependency_stats()["total_rules"] == 4

    graph = build_dependency_graph(ast)

    assert graph.nodes == {"dup#1", "dup#2", "helper", "caller"}
    assert graph.get_dependencies("dup#2") == {"helper"}
    assert graph.get_dependencies("caller") == {"dup#1", "dup#2"}


def test_dependency_graph_generator_tracks_rule_wildcard_sets() -> None:
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
    gen = DependencyGraphGenerator()

    gen.visit(ast)

    assert gen.dependencies["caller"] == {"a1", "a2"}
    assert gen.dependencies.get("other", set()) == set()


def test_dependency_graph_generator_complexity_graph(tmp_path: Path) -> None:
    ast = Parser().parse("rule a { condition: true }")
    out = DependencyGraphGenerator().generate_complexity_graph(
        ast,
        {"a": 3},
        output_path=str(tmp_path / "complexity.dot"),
        format="dot",
    )

    assert out.endswith(".dot")
    assert "digraph" in Path(out).read_text(encoding="utf-8")
