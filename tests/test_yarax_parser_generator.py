"""Tests for YARA-X parser and generator."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral, Identifier, IntegerLiteral
from yaraast.ast.rules import Rule
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    DictExpression,
    LambdaExpression,
    ListExpression,
    MatchCase,
    PatternMatch,
    SliceExpression,
    SpreadOperator,
    TupleExpression,
    TupleIndexing,
    WithStatement,
)
from yaraast.yarax.generator import YaraXGenerator
from yaraast.yarax.parser import YaraXParser


def _parse_expr(text: str):
    parser = YaraXParser(text)
    return parser.parse_expression()


def test_yarax_with_statement_generation() -> None:
    yarax_code = """
rule yarax_with {
    condition:
        with $a = "test", $b = 2:
            true
}
"""

    parser = YaraXParser(yarax_code)
    ast = parser.parse()

    rule = ast.rules[0]
    assert isinstance(rule.condition, WithStatement)

    generator = YaraXGenerator()
    output = generator.generate(ast)

    assert 'with $a = "test", $b = 2: true' in output


def test_yarax_list_and_spread_expression() -> None:
    expr = _parse_expr("[1, ...arr, 4]")
    assert isinstance(expr, ListExpression)
    assert any(isinstance(elem, SpreadOperator) for elem in expr.elements)


def test_yarax_array_comprehension() -> None:
    expr = _parse_expr("[x for x in items if x]")
    assert isinstance(expr, ArrayComprehension)
    assert expr.condition is not None


def test_yarax_dict_expression_with_spread() -> None:
    expr = _parse_expr('{**data, "a": 1}')
    assert isinstance(expr, DictExpression)
    assert isinstance(expr.items[0].value, SpreadOperator)


def test_yarax_dict_comprehension_two_vars() -> None:
    expr = _parse_expr("{k: v for k, v in data if v}")
    assert isinstance(expr, DictComprehension)
    assert expr.value_variable == "v"
    assert expr.condition is not None


def test_yarax_tuple_and_indexing() -> None:
    expr = _parse_expr("(1, 2, 3)")
    assert isinstance(expr, TupleExpression)

    indexed = _parse_expr("foo()[1]")
    assert isinstance(indexed, TupleIndexing)


def test_yarax_slice_expression() -> None:
    expr = _parse_expr("foo()[1:4:2]")
    assert isinstance(expr, SliceExpression)
    assert expr.step is not None


def test_yarax_lambda_and_match_expression() -> None:
    expr = _parse_expr("lambda x, y: x + y")
    assert isinstance(expr, LambdaExpression)

    match_expr = _parse_expr("match x { 1 => 2, _ => 3 }")
    assert isinstance(match_expr, PatternMatch)
    assert match_expr.default is not None


def test_yarax_generator_outputs_match() -> None:
    condition = PatternMatch(
        value=IntegerLiteral(1),
        cases=[MatchCase(pattern=IntegerLiteral(1), result=BooleanLiteral(True))],
        default=BooleanLiteral(False),
    )
    yarax_file = YaraFile(rules=[Rule(name="match_rule", condition=condition)])

    output = YaraXGenerator().generate(yarax_file)

    assert "match 1" in output
    assert "_ => false" in output


def test_yarax_generator_tuple_indexing_parens() -> None:
    condition = TupleIndexing(tuple_expr=Identifier(name="foo"), index=IntegerLiteral(0))
    yarax_file = YaraFile(rules=[Rule(name="tuple_rule", condition=condition)])
    output = YaraXGenerator().generate(yarax_file)

    assert "foo[0]" in output
