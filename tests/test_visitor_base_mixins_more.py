"""Additional direct coverage for BaseVisitor mixins."""

from __future__ import annotations

from yaraast.ast.conditions import Condition, ForExpression, ForOfExpression, InExpression
from yaraast.ast.expressions import (
    BooleanLiteral,
    Expression,
    Identifier,
    IntegerLiteral,
    RangeExpression,
    SetExpression,
)
from yaraast.ast.strings import HexToken, StringDefinition
from yaraast.visitor.base import BaseVisitor


class _Visitor(BaseVisitor[None]):
    pass


class _RecordingVisitor(BaseVisitor[None]):
    def __init__(self) -> None:
        self.identifiers: list[str] = []

    def visit_identifier(self, node: Identifier) -> None:
        self.identifiers.append(node.name)


def test_base_visitor_expression_and_condition_methods() -> None:
    visitor = _Visitor()
    condition = Condition()
    literal = BooleanLiteral(value=True)

    assert visitor.visit_expression(Expression()) is None
    assert visitor.visit_expression(literal) is None
    assert visitor.visit_condition(condition) is None


def test_base_visitor_string_definition_and_hex_token_methods() -> None:
    visitor = _Visitor()

    assert visitor.visit_string_definition(StringDefinition(identifier="$a")) is None
    assert visitor.visit_hex_token(HexToken()) is None


def test_base_visitor_traverses_in_expression_subject_nodes() -> None:
    visitor = _RecordingVisitor()

    visitor.visit(
        InExpression(
            subject=Identifier("subject"),
            range=RangeExpression(low=Identifier("low"), high=Identifier("high")),
        )
    )

    assert visitor.identifiers == ["subject", "low", "high"]


def test_base_visitor_traverses_condition_quantifier_nodes() -> None:
    visitor = _RecordingVisitor()

    visitor.visit(
        ForExpression(
            quantifier=Identifier("limit"),
            variable="i",
            iterable=SetExpression([IntegerLiteral(1)]),
            body=Identifier("body"),
        )
    )
    visitor.visit(
        ForOfExpression(
            quantifier=Identifier("count"),
            string_set=Identifier("strings"),
            condition=Identifier("condition"),
        )
    )

    assert visitor.identifiers == ["limit", "body", "count", "strings", "condition"]
