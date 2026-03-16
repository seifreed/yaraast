"""Additional direct coverage for BaseVisitor mixins."""

from __future__ import annotations

from yaraast.ast.conditions import Condition
from yaraast.ast.expressions import BooleanLiteral, Expression
from yaraast.ast.strings import HexToken, StringDefinition
from yaraast.visitor.base import BaseVisitor


class _Visitor(BaseVisitor[None]):
    pass


def test_base_visitor_expression_and_condition_methods() -> None:
    visitor = _Visitor()
    condition = Condition()
    condition.expression = BooleanLiteral(value=True)

    assert visitor.visit_expression(Expression()) is None
    assert visitor.visit_condition(condition) is None


def test_base_visitor_string_definition_and_hex_token_methods() -> None:
    visitor = _Visitor()

    assert visitor.visit_string_definition(StringDefinition(identifier="$a")) is None
    assert visitor.visit_hex_token(HexToken()) is None
