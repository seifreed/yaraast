from __future__ import annotations

from yaraast.yaral.ast_nodes import (
    ArithmeticExpression,
    ConditionalExpression,
    EventExistsCondition,
)
from yaraast.yaral.validator import YaraLValidator


def test_validator_conditional_expression_without_accept_condition() -> None:
    validator = YaraLValidator()
    validator.current_rule = "r6"

    validator.visit_yaral_conditional_expression(
        ConditionalExpression(condition=True, true_value=1, false_value=0)
    )

    assert validator.errors == []
    assert validator.warnings == []
    assert validator.used_events == set()


def test_validator_arithmetic_expression_partial_and_non_visitable_operands() -> None:
    validator = YaraLValidator()
    validator.current_rule = "r7"

    validator.visit_yaral_arithmetic_expression(
        ArithmeticExpression(
            operator="+",
            left=EventExistsCondition(event="left_only"),
            right=1,
        )
    )
    assert "left_only" in validator.used_events

    validator.used_events.clear()
    validator.visit_yaral_arithmetic_expression(
        ArithmeticExpression(
            operator="+",
            left=1,
            right=2,
        )
    )
    assert validator.used_events == set()
