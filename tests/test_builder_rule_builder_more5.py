"""Additional real coverage for RuleBuilder."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.expressions import BinaryExpression, BooleanLiteral, StringIdentifier
from yaraast.ast.strings import HexByte, HexString, HexWildcard, PlainString, RegexString
from yaraast.builder.condition_builder import ConditionBuilder
from yaraast.builder.rule_builder import RuleBuilder
from yaraast.codegen.generator import CodeGenerator
from yaraast.errors import ValidationError


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


@pytest.mark.parametrize("rule_name", ["bad name", "bad-name", "for", "1bad", ""])
def test_rule_builder_rejects_invalid_rule_names(rule_name: str) -> None:
    with pytest.raises(ValidationError, match="Invalid rule identifier"):
        RuleBuilder(rule_name)

    with pytest.raises(ValidationError, match="Invalid rule identifier"):
        RuleBuilder().with_name(rule_name)


@pytest.mark.parametrize("tag_name", ["bad tag", "bad-tag", "for", "1bad", ""])
def test_rule_builder_rejects_invalid_rule_tags(tag_name: str) -> None:
    with pytest.raises(ValidationError, match="Invalid tag identifier"):
        RuleBuilder("tags").with_tag(tag_name)

    with pytest.raises(ValidationError, match="Invalid tag identifier"):
        RuleBuilder("tags").with_tags("known_good", tag_name)


def test_rule_builder_rejects_duplicate_rule_tags_without_partial_update() -> None:
    with pytest.raises(ValidationError, match="Duplicate tag identifier"):
        RuleBuilder("tags").with_tag("duplicate").with_tag("duplicate")

    with pytest.raises(ValidationError, match="Duplicate tag identifier"):
        RuleBuilder("tags").with_tags("duplicate", "duplicate")

    builder = RuleBuilder("tags").with_tag("duplicate")
    with pytest.raises(ValidationError, match="Duplicate tag identifier"):
        builder.with_tags("new_tag", "duplicate")
    assert [tag.name for tag in builder.build().tags] == ["duplicate"]


@pytest.mark.parametrize("meta_key", ["bad key", "bad-key", "for", "1bad", ""])
def test_rule_builder_rejects_invalid_meta_keys(meta_key: str) -> None:
    with pytest.raises(ValidationError, match="Invalid meta identifier"):
        RuleBuilder("metadata_rule").with_meta(meta_key, "x")

    with pytest.raises(ValidationError, match="Invalid meta identifier"):
        RuleBuilder("metadata_rule").add_meta(meta_key, "x")


@pytest.mark.parametrize("meta_value", [1.5, None, ["x"]])
def test_rule_builder_rejects_invalid_meta_values(meta_value: Any) -> None:
    with pytest.raises(TypeError, match="Invalid meta value"):
        RuleBuilder("metadata_rule").with_meta("value", meta_value)

    with pytest.raises(TypeError, match="Invalid meta value"):
        RuleBuilder("metadata_rule").add_meta("value", meta_value)


@pytest.mark.parametrize("identifier", ["$bad-key", "$bad space", "$", ""])
def test_rule_builder_rejects_invalid_string_identifiers(identifier: str) -> None:
    with pytest.raises(ValidationError, match="Invalid string identifier"):
        RuleBuilder("string_rule").with_plain_string(identifier, "x")

    with pytest.raises(ValidationError, match="Invalid string identifier"):
        RuleBuilder("string_rule").with_regex_string(identifier, "x")

    with pytest.raises(ValidationError, match="Invalid string identifier"):
        RuleBuilder("string_rule").with_hex_string_raw(identifier, "4D 5A")


def test_rule_builder_rejects_duplicate_string_identifiers_without_partial_update() -> None:
    builder = RuleBuilder("string_rule").with_plain_string("$a", "first")

    with pytest.raises(ValidationError, match="Duplicate string identifier"):
        builder.with_plain_string("$a", "second")

    with pytest.raises(ValidationError, match="Duplicate string identifier"):
        builder.with_regex_string("a", "third")

    rule = builder.build()
    assert [string_def.identifier for string_def in rule.strings] == ["$a"]
    only_string = rule.strings[0]
    assert isinstance(only_string, PlainString)
    assert only_string.value == "first"


def test_rule_builder_hex_regex_and_condition_variants() -> None:
    rule = (
        RuleBuilder("variants")
        .with_hex_string_raw("$hex", "4D ??")
        .with_regex("$re", "ab.*", dotall=True, multiline=True)
        .set_condition("$a")
        .build()
    )

    hex_string = rule.strings[0]
    assert isinstance(hex_string, HexString)
    assert isinstance(hex_string.tokens[0], HexByte)
    assert isinstance(hex_string.tokens[1], HexWildcard)
    assert isinstance(rule.strings[1], RegexString)
    assert rule.strings[1].regex == "ab.*"
    assert len(rule.strings[1].modifiers) == 2  # dotall + multiline
    assert isinstance(rule.condition, StringIdentifier)
    assert rule.condition.name == "$a"


def test_rule_builder_parses_complex_string_condition_text() -> None:
    rule = (
        RuleBuilder("raw_condition")
        .with_hex_string_raw("$mz", "4D 5A")
        .with_plain_string("$suspicious", "backdoor")
        .with_condition("$mz at 0 and $suspicious")
        .build()
    )

    assert isinstance(rule.condition, BinaryExpression)
    assert "$mz at 0 and $suspicious" in CodeGenerator().generate(rule)


def test_rule_builder_rejects_invalid_string_condition_text() -> None:
    with pytest.raises(ValidationError, match="Invalid condition expression"):
        RuleBuilder("raw_condition").with_condition("$mz at")


def test_rule_builder_rejects_invalid_runtime_condition_objects() -> None:
    builder = RuleBuilder("bad_runtime_condition").with_condition("true")

    with pytest.raises(TypeError, match="Rule condition must be an Expression"):
        builder.with_condition(cast(Any, object()))

    assert isinstance(builder.build().condition, BooleanLiteral)


def test_rule_builder_copies_direct_condition_expressions() -> None:
    condition = BooleanLiteral(value=True)
    builder = RuleBuilder("stable_condition").with_condition(condition)

    condition.value = False

    built_condition = builder.build().condition
    assert isinstance(built_condition, BooleanLiteral)
    assert built_condition.value is True


def test_rule_builder_raw_hex_rejects_invalid_input() -> None:
    with pytest.raises(ValidationError, match="Invalid hex byte at offset 2: ZZ"):
        RuleBuilder("invalid").with_hex_string_raw("$hex", "4D ZZ ??")

    with pytest.raises(ValidationError, match="Invalid trailing hex byte at offset 2: F"):
        RuleBuilder("invalid").with_hex_string_raw("$hex", "4D F")


def test_rule_builder_complex_conditions_and_lambda() -> None:
    rule = (
        RuleBuilder("complex")
        .with_condition("identifier_expr")
        .with_condition_lambda(lambda cb: cb.true())
        .build()
    )

    assert isinstance(rule.condition, BooleanLiteral)
    assert rule.condition.value is True

    simple = (
        RuleBuilder("simple")
        .with_plain_string("$seen", "marker")
        .with_simple_condition("$seen")
        .build()
    )
    assert isinstance(simple.condition, StringIdentifier)
    assert simple.condition.name == "$seen"
    assert "$seen" in CodeGenerator().generate(simple)


def test_rule_builder_condition_lambda_rejects_missing_return() -> None:
    with pytest.raises(ValidationError, match="Condition lambda must return"):
        RuleBuilder("bad_condition").with_condition_lambda(lambda cb: None)


def test_rule_builder_condition_lambda_rejects_invalid_return() -> None:
    with pytest.raises(ValidationError, match="Condition lambda must return"):
        RuleBuilder("bad_condition").with_condition_lambda(lambda cb: "bad")


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
