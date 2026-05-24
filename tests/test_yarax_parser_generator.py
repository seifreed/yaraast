"""Tests for YARA-X parser and generator."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Expression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    SetExpression,
)
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


def _parse_expr(text: str) -> Expression:
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


def test_yarax_with_statement_accepts_extended_expression_values() -> None:
    yarax_code = """
rule yarax_with_extended {
    condition:
        with xs = [1, 2], f = lambda x: x, m = match x { 1 => 2, _ => 3 }:
            true
}
"""

    parser = YaraXParser(yarax_code)
    ast = parser.parse()

    rule = ast.rules[0]
    assert isinstance(rule.condition, WithStatement)
    values = [declaration.value for declaration in rule.condition.declarations]
    assert isinstance(values[0], ListExpression)
    assert isinstance(values[1], LambdaExpression)
    assert isinstance(values[2], PatternMatch)


def test_yarax_list_and_spread_expression() -> None:
    expr = _parse_expr("[1, ...arr, 4]")
    assert isinstance(expr, ListExpression)
    assert any(isinstance(elem, SpreadOperator) for elem in expr.elements)


def test_yarax_nested_extended_expressions_parse() -> None:
    expr = _parse_expr('[[1], {"a": [2]}, lambda x: [x], match x { 1 => [2], _ => [] }]')
    assert isinstance(expr, ListExpression)
    assert isinstance(expr.elements[0], ListExpression)
    assert isinstance(expr.elements[1], DictExpression)
    assert isinstance(expr.elements[2], LambdaExpression)
    assert isinstance(expr.elements[3], PatternMatch)

    comprehension = _parse_expr("[x for x in [1, 2] if match x { 1 => true, _ => false }]")
    assert isinstance(comprehension, ArrayComprehension)
    assert isinstance(comprehension.iterable, ListExpression)
    assert isinstance(comprehension.condition, PatternMatch)


def test_yarax_extended_expressions_parse_in_full_expression_contexts() -> None:
    ast = YaraXParser(
        """
rule yarax_match_condition {
    condition:
        match x { 1 => true, _ => false }
}
""",
    ).parse()
    assert isinstance(ast.rules[0].condition, PatternMatch)

    expr = _parse_expr("enabled and match x { 1 => true, _ => false }")
    assert isinstance(expr, BinaryExpression)
    assert isinstance(expr.right, PatternMatch)

    call = _parse_expr("fn([1], match x { 1 => 2, _ => 3 })")
    assert isinstance(call, FunctionCall)
    assert isinstance(call.arguments[0], ListExpression)
    assert isinstance(call.arguments[1], PatternMatch)

    of_expr = _parse_expr("any of ($a, $b)")
    assert isinstance(of_expr, OfExpression)
    assert isinstance(of_expr.string_set, SetExpression)

    with_ast = YaraXParser(
        """
rule yarax_with_match_body {
    condition:
        with y = [1]: match x { 1 => true, _ => false }
}
""",
    ).parse()
    condition = with_ast.rules[0].condition
    assert isinstance(condition, WithStatement)
    assert isinstance(condition.body, PatternMatch)


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


def test_yarax_generator_indents_multiline_match_condition() -> None:
    condition = PatternMatch(
        value=IntegerLiteral(1),
        cases=[MatchCase(pattern=IntegerLiteral(1), result=BooleanLiteral(True))],
        default=BooleanLiteral(False),
    )
    yarax_file = YaraFile(rules=[Rule(name="match_rule", condition=condition)])

    output = YaraXGenerator().generate(yarax_file)

    assert (
        "    condition:\n"
        "        match 1 {\n"
        "            1 => true,\n"
        "            _ => false,\n"
        "        }\n"
    ) in output
    assert "\n    1 => true,\n" not in output


def test_yarax_generator_uses_configured_indent_for_match_cases() -> None:
    condition = PatternMatch(
        value=IntegerLiteral(1),
        cases=[MatchCase(pattern=IntegerLiteral(1), result=BooleanLiteral(True))],
        default=BooleanLiteral(False),
    )
    yarax_file = YaraFile(rules=[Rule(name="match_rule", condition=condition)])

    output = YaraXGenerator(indent_size=2).generate(yarax_file)

    assert (
        "  condition:\n" "    match 1 {\n" "      1 => true,\n" "      _ => false,\n" "    }\n"
    ) in output
    assert "\n        1 => true,\n" not in output


def test_yarax_generator_tuple_indexing_parens() -> None:
    condition = TupleIndexing(tuple_expr=Identifier(name="foo"), index=IntegerLiteral(0))
    yarax_file = YaraFile(rules=[Rule(name="tuple_rule", condition=condition)])
    output = YaraXGenerator().generate(yarax_file)

    assert "foo[0]" in output
