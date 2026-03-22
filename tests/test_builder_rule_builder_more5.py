"""Additional real coverage for RuleBuilder."""

from __future__ import annotations

from yaraast.ast.expressions import BooleanLiteral, Identifier, StringIdentifier
from yaraast.ast.strings import HexByte, HexWildcard, PlainString, RegexString
from yaraast.builder.condition_builder import ConditionBuilder
from yaraast.builder.rule_builder import RuleBuilder


def test_rule_builder_aliases_and_modifier_paths() -> None:
    rule = (
        RuleBuilder("aliases")
        .add_string("$a", "text")
        .with_string("$b", "wide", wide=True, ascii=True, fullword=True)
        .with_condition("false")
        .build()
    )

    assert isinstance(rule.strings[0], PlainString)
    assert isinstance(rule.strings[1], PlainString)
    modifier_names = [m.name for m in rule.strings[1].modifiers]
    assert modifier_names == ["wide", "ascii", "fullword"]
    assert isinstance(rule.condition, BooleanLiteral)
    assert rule.condition.value is False


def test_rule_builder_hex_regex_and_condition_variants() -> None:
    rule = (
        RuleBuilder("variants")
        .with_hex_string_raw("$hex", "4D ZZ ?? F")
        .with_regex("$re", "ab.*", dotall=True, multiline=True)
        .set_condition("$a")
        .build()
    )

    hex_string = rule.strings[0]
    assert isinstance(hex_string.tokens[0], HexByte)
    assert isinstance(hex_string.tokens[1], HexWildcard)
    assert isinstance(rule.strings[1], RegexString)
    assert rule.strings[1].regex == "ab.*"
    assert len(rule.strings[1].modifiers) == 2  # dotall + multiline
    assert isinstance(rule.condition, StringIdentifier)
    assert rule.condition.name == "$a"


def test_rule_builder_complex_conditions_and_lambda() -> None:
    rule = (
        RuleBuilder("complex")
        .with_condition("identifier_expr")
        .with_condition_lambda(lambda cb: cb.true())
        .build()
    )

    assert isinstance(rule.condition, BooleanLiteral)
    assert rule.condition.value is True

    simple = RuleBuilder("simple").with_simple_condition("$seen").build()
    assert isinstance(simple.condition, Identifier)
    assert simple.condition.name == "seen"


def test_rule_builder_true_condition_direct_builder_and_plain_regex() -> None:
    builder_condition_rule = (
        RuleBuilder("builder_cond").with_condition(ConditionBuilder().true()).build()
    )
    assert isinstance(builder_condition_rule.condition, BooleanLiteral)
    assert builder_condition_rule.condition.value is True

    true_rule = RuleBuilder("true_rule").with_condition("true").build()
    assert isinstance(true_rule.condition, BooleanLiteral)
    assert true_rule.condition.value is True

    regex_rule = RuleBuilder("regex_plain").with_regex("$r", "abc").build()
    assert isinstance(regex_rule.strings[0], RegexString)
    assert regex_rule.strings[0].regex == "abc"
