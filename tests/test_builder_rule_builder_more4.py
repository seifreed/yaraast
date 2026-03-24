"""More tests for rule builder (no mocks)."""

from __future__ import annotations

import pytest

from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import BooleanLiteral
from yaraast.builder.rule_builder import RuleBuilder
from yaraast.errors import ValidationError


def test_rule_builder_strings_and_condition() -> None:
    rule = (
        RuleBuilder("rule1")
        .with_plain_string("$a", "x", nocase=True)
        .with_hex_string_raw("$b", "4D 5A ?? 00")
        .with_regex("$c", "ab.*", case_insensitive=True)
        .with_condition("any of them")
        .build()
    )

    assert rule.name == "rule1"
    assert len(rule.strings) == 3
    assert isinstance(rule.condition, OfExpression)


def test_rule_builder_require_condition() -> None:
    builder = RuleBuilder("rule2").require_condition(True)
    with pytest.raises(ValidationError):
        builder.build()

    rule = RuleBuilder("rule3").with_condition(BooleanLiteral(value=True)).build()
    assert rule.condition is not None
