"""More tests for rule builder (no mocks)."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.strings import HexAlternative, HexByte
from yaraast.builder.hex_string_builder import HexStringBuilder
from yaraast.builder.rule_builder import RuleBuilder
from yaraast.errors import ValidationError


def test_rule_builder_strings_and_condition() -> None:
    rule = (
        RuleBuilder("rule1")
        .with_plain_string("$a", "x", nocase=True)
        .with_hex_string("$b", HexStringBuilder().add(0x4D).add(0x5A).wildcard().add(0x00))
        .with_regex_string("$c", "ab.*", nocase=True)
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


def test_rule_builder_rejects_empty_hex_string_definitions() -> None:
    with pytest.raises(ValidationError, match="Hex string content not set"):
        RuleBuilder("bad").with_hex_string("$h", [])

    with pytest.raises(ValidationError, match="Hex string content not set"):
        RuleBuilder("bad").with_hex_string("$h", HexStringBuilder())


def test_rule_builder_rejects_standalone_hex_jump_definitions() -> None:
    with pytest.raises(ValidationError, match="HexJump cannot appear"):
        RuleBuilder("bad").with_hex_string("$h", HexStringBuilder().jump(1, 2))

    with pytest.raises(ValidationError, match="HexJump cannot appear"):
        RuleBuilder("bad").with_hex_string("$h", HexStringBuilder().jump(1, 2))


def test_rule_builder_rejects_invalid_hex_alternatives() -> None:
    with pytest.raises(ValidationError, match="HexAlternative branches must not be empty"):
        RuleBuilder("bad").with_hex_string("$h", HexStringBuilder().alternative([]))

    with pytest.raises(ValidationError, match="Unbounded HexJump"):
        RuleBuilder("bad").with_hex_string(
            "$h",
            HexStringBuilder()
            .add(0x41)
            .alternative(HexStringBuilder().add(0x42).jump(None, None).add(0x43))
            .add(0x44),
        )


def test_rule_builder_rejects_unsupported_raw_hex_tokens() -> None:
    bad_tokens: list[Any] = [object()]
    with pytest.raises(TypeError, match="Unsupported hex token"):
        RuleBuilder("bad").with_hex_string("$h", bad_tokens)

    with pytest.raises(TypeError, match="HexByte value must be a byte"):
        RuleBuilder("bad").with_hex_string("$h", [HexByte(999)])

    with pytest.raises(TypeError, match="HexByte value must be a byte"):
        RuleBuilder("bad").with_hex_string("$h", [HexAlternative([True])])

    assert (
        RuleBuilder("ok")
        .with_hex_string(
            "$h",
            [HexAlternative([0x90, "91"])],
        )
        .build()
    )


def test_rule_builder_rejects_invalid_hex_builder_argument_shapes() -> None:
    with pytest.raises(TypeError, match="Hex string builder must be"):
        RuleBuilder("bad").with_hex_string("$h", cast(Any, object()))
