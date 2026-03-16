"""Extra real coverage for tree builder and complexity analyzer."""

from __future__ import annotations

from io import StringIO
from textwrap import dedent

from rich.console import Console

from yaraast.ast.conditions import ForExpression, ForOfExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    StringIdentifier,
    StringLiteral,
    UnaryExpression,
)
from yaraast.ast.modules import DictionaryAccess
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString
from yaraast.cli.visitors.tree_builder import ASTTreeBuilder
from yaraast.metrics.complexity import ComplexityAnalyzer
from yaraast.parser import Parser


def _render(tree) -> str:
    console = Console(file=StringIO(), record=True, force_terminal=False)
    console.print(tree)
    return console.export_text()


class _BrokenAccept:
    def accept(self, _visitor):
        raise ValueError("boom")


def test_tree_builder_remaining_fallback_and_hex_paths() -> None:
    builder = ASTTreeBuilder()

    rendered = _render(builder.visit(_BrokenAccept()))
    assert rendered == "\n"

    generated = builder._get_condition_string(_BrokenAccept())
    assert isinstance(generated, str)
    assert generated

    hex_tree = builder.visit_hex_string(HexString(identifier="$h", tokens=[HexByte(value=0x41)]))
    assert "$h [HexString]" in _render(hex_tree)


def test_complexity_analyzer_remaining_visitors_and_complex_rule() -> None:
    code = """
    rule very_complex {
        strings:
            $a = "abc"
            $b = { 6A 40 ?? } nocase
            $c = /a(b|c)+/ wide
        condition:
            (((($a and $a) and ($a and $a)) and (($a and $a) and ($a and $a))) and (($a and $a) and ($a and $a)))
    }
    """
    ast = Parser().parse(dedent(code))
    metrics = ComplexityAnalyzer().analyze(ast)

    assert "very_complex" in metrics.complex_rules
    assert metrics.strings_with_modifiers >= 2

    analyzer = ComplexityAnalyzer()
    analyzer._current_rule = Rule(name="manual")

    analyzer.visit_unary_expression(UnaryExpression(operator="not", operand=Identifier(name="x")))
    analyzer.visit_for_expression(
        ForExpression(
            quantifier="any",
            variable="i",
            iterable=RangeExpression(low=IntegerLiteral(value=1), high=IntegerLiteral(value=3)),
            body=Identifier(name="i"),
        )
    )
    analyzer.visit_of_expression(
        OfExpression(
            quantifier=IntegerLiteral(value=2),
            string_set=SetExpression(elements=[StringIdentifier(name="$a")]),
        )
    )
    analyzer.visit_for_of_expression(
        ForOfExpression(
            quantifier="all",
            string_set=SetExpression(elements=[StringIdentifier(name="$a")]),
            condition=BinaryExpression(
                left=StringIdentifier(name="$a"),
                operator="==",
                right=IntegerLiteral(value=1),
            ),
        )
    )
    analyzer.visit_parentheses_expression(
        ParenthesesExpression(expression=Identifier(name="inner"))
    )
    analyzer.visit_range_expression(
        RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=2))
    )
    analyzer.visit_array_access(
        ArrayAccess(array=Identifier(name="arr"), index=IntegerLiteral(value=0))
    )
    analyzer.visit_in_expression(
        InExpression(
            subject="$a",
            range=RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=10)),
        )
    )
    analyzer.visit_dictionary_access(
        DictionaryAccess(object=Identifier(name="pe"), key="CompanyName")
    )
    analyzer.visit_defined_expression(DefinedExpression(expression=Identifier(name="x")))
    analyzer.visit_string_operator_expression(
        StringOperatorExpression(
            left=StringLiteral(value="abc"),
            operator="icontains",
            right=StringLiteral(value="a"),
        )
    )

    assert analyzer.metrics.total_unary_ops >= 1
    assert analyzer.metrics.for_expressions >= 1
    assert analyzer.metrics.for_of_expressions >= 1
    assert analyzer.metrics.of_expressions >= 1
