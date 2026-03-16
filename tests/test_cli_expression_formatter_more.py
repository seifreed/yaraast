"""Additional tests for expression string formatter (no mocks)."""

from __future__ import annotations

from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    StringIdentifier,
)
from yaraast.cli.visitors import ExpressionStringFormatter


def test_expression_formatter_basic_and_parentheses() -> None:
    formatter = ExpressionStringFormatter()
    expr = BinaryExpression(
        left=Identifier(name="a"),
        operator="and",
        right=StringIdentifier(name="$b"),
    )
    assert formatter.format_expression(expr) == "a and $b"

    paren = ParenthesesExpression(expression=expr)
    assert formatter.format_expression(paren).startswith("(")


def test_expression_formatter_collections_and_ranges() -> None:
    formatter = ExpressionStringFormatter()
    set_expr = SetExpression(elements=[Identifier(name="a"), Identifier(name="b")])
    assert formatter.format_expression(set_expr).startswith("<Set")

    range_expr = RangeExpression(
        low=IntegerLiteral(value=1),
        high=IntegerLiteral(value=10),
    )
    rendered = formatter.format_expression(range_expr)
    assert "1" in rendered and "10" in rendered


def test_expression_formatter_function_and_of() -> None:
    formatter = ExpressionStringFormatter()
    call = FunctionCall(
        function="math.entropy",
        arguments=[IntegerLiteral(value=1), IntegerLiteral(value=2), IntegerLiteral(value=3)],
    )
    assert formatter.format_expression(call).endswith("...)")

    of_expr = OfExpression(
        quantifier=Identifier(name="any"),
        string_set=Identifier(name="them"),
    )
    rendered = formatter.format_expression(of_expr)
    assert "of" in rendered
