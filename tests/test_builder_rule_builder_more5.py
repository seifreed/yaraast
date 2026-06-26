"""Additional real coverage for RuleBuilder."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.expressions import BinaryExpression, BooleanLiteral, StringIdentifier
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexString,
    HexWildcard,
    PlainString,
    RegexString,
)
from yaraast.builder.condition_builder import ConditionBuilder
from yaraast.builder.rule_builder import RuleBuilder
from yaraast.codegen.generator import CodeGenerator
from yaraast.errors import ValidationError
from yaraast.lexer.lexer_tables import YARA_IDENTIFIER_MAX_LENGTH


def test_rule_builder_aliases_and_modifier_paths() -> None:
    rule = (
        RuleBuilder("aliases")
        .with_string("$a", "text")
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


@pytest.mark.parametrize(
    "rule_name",
    ["bad name", "bad-name", "for", "1bad", "", "a" * (YARA_IDENTIFIER_MAX_LENGTH + 1)],
)
def test_rule_builder_rejects_invalid_rule_names(rule_name: str) -> None:
    with pytest.raises(ValidationError, match="Invalid rule identifier"):
        RuleBuilder(rule_name)

    with pytest.raises(ValidationError, match="Invalid rule identifier"):
        RuleBuilder().with_name(rule_name)


@pytest.mark.parametrize(
    "tag_name",
    ["bad tag", "bad-tag", "for", "1bad", "", "a" * (YARA_IDENTIFIER_MAX_LENGTH + 1)],
)
def test_rule_builder_rejects_invalid_rule_tags(tag_name: str) -> None:
    with pytest.raises(ValidationError, match="Invalid tag identifier"):
        RuleBuilder("tags").with_tag(tag_name)

    with pytest.raises(ValidationError, match="Invalid tag identifier"):
        RuleBuilder("tags").with_tags("known_good", tag_name)


@pytest.mark.parametrize("identifier", ["as", "include"])
def test_rule_builder_allows_contextual_identifier_keywords(identifier: str) -> None:
    rule = (
        RuleBuilder(identifier)
        .with_tag(identifier)
        .with_meta(identifier, 1)
        .with_condition("true")
        .build()
    )

    generated = CodeGenerator().generate(rule)

    assert rule.name == identifier
    assert [tag.name for tag in rule.tags] == [identifier]
    assert [(entry.key, entry.value) for entry in rule.meta] == [(identifier, 1)]
    assert f"rule {identifier}" in generated
    assert f": {identifier}" in generated
    assert f"{identifier} = 1" in generated


def test_rule_builder_rejects_duplicate_rule_tags_without_partial_update() -> None:
    with pytest.raises(ValidationError, match="Duplicate tag identifier"):
        RuleBuilder("tags").with_tag("duplicate").with_tag("duplicate")

    with pytest.raises(ValidationError, match="Duplicate tag identifier"):
        RuleBuilder("tags").with_tags("duplicate", "duplicate")

    builder = RuleBuilder("tags").with_tag("duplicate")
    with pytest.raises(ValidationError, match="Duplicate tag identifier"):
        builder.with_tags("new_tag", "duplicate")
    assert [tag.name for tag in builder.build().tags] == ["duplicate"]


def test_rule_builder_public_removes_private_modifier() -> None:
    built = RuleBuilder("visibility").private().global_().public().build()

    modifier_names = {modifier.name for modifier in built.modifiers}
    assert "private" not in modifier_names
    assert "global" in modifier_names


@pytest.mark.parametrize(
    "meta_key",
    ["bad key", "bad-key", "for", "1bad", "", "a" * (YARA_IDENTIFIER_MAX_LENGTH + 1)],
)
def test_rule_builder_rejects_invalid_meta_keys(meta_key: str) -> None:
    with pytest.raises(ValidationError, match="Invalid meta identifier"):
        RuleBuilder("metadata_rule").with_meta(meta_key, "x")

    with pytest.raises(ValidationError, match="Invalid meta identifier"):
        RuleBuilder("metadata_rule").with_meta(meta_key, "x")


@pytest.mark.parametrize("meta_value", [1.5, None, ["x"]])
def test_rule_builder_rejects_invalid_meta_values(meta_value: Any) -> None:
    with pytest.raises(TypeError, match="Invalid meta value"):
        RuleBuilder("metadata_rule").with_meta("value", meta_value)


def test_rule_builder_default_condition_does_not_mutate_builder_state() -> None:
    builder = RuleBuilder("default_condition")

    built = builder.build()

    assert isinstance(built.condition, BooleanLiteral)
    assert built.condition.value is True
    assert builder.get_condition() is None

    builder.require_condition()
    with pytest.raises(ValidationError, match="Rule condition is required"):
        builder.build()


def test_rule_builder_rejects_invalid_string_content_types() -> None:
    with pytest.raises(TypeError, match="Plain string value must be a string or bytes"):
        RuleBuilder("string_rule").with_plain_string("$a", cast(Any, True))

    with pytest.raises(TypeError, match="Plain string value must be a string or bytes"):
        RuleBuilder("string_rule").with_string("$a", cast(Any, 123))

    with pytest.raises(TypeError, match="Regex pattern must be a string"):
        RuleBuilder("string_rule").with_regex_string("$r", cast(Any, 123))

    with pytest.raises(TypeError, match="Regex pattern must be a string"):
        RuleBuilder("string_rule").with_regex("$r", cast(Any, ["x"]))

    with pytest.raises(TypeError, match="Hex pattern must be a string"):
        RuleBuilder("string_rule").with_hex_string_raw("$h", cast(Any, True))


def test_rule_builder_rejects_non_boolean_flags() -> None:
    with pytest.raises(TypeError, match="RuleBuilder nocase flag must be a boolean"):
        RuleBuilder("string_rule").with_plain_string("$a", "x", nocase=cast(Any, "yes"))

    with pytest.raises(TypeError, match="RuleBuilder wide flag must be a boolean"):
        RuleBuilder("string_rule").with_string("$a", "x", wide=cast(Any, "yes"))

    with pytest.raises(TypeError, match="RuleBuilder dotall flag must be a boolean"):
        RuleBuilder("regex_rule").with_regex("$r", "x", dotall=cast(Any, "yes"))

    with pytest.raises(TypeError, match="RuleBuilder nocase flag must be a boolean"):
        RuleBuilder("regex_rule").with_regex_string("$r", "x", nocase=cast(Any, "yes"))

    with pytest.raises(TypeError, match="RuleBuilder require flag must be a boolean"):
        RuleBuilder("condition_rule").require_condition(cast(Any, "yes"))


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


def test_rule_builder_rejects_invalid_condition_expression_structure() -> None:
    builder = RuleBuilder("bad_condition_structure").with_condition("true")

    with pytest.raises(ValueError, match="String identifier cannot be empty"):
        builder.with_condition(StringIdentifier(name=""))

    assert isinstance(builder.build().condition, BooleanLiteral)


def test_rule_builder_rejects_invalid_condition_builder_structure() -> None:
    builder = RuleBuilder("bad_condition_builder_structure").with_condition("true")
    condition_builder = ConditionBuilder().identifier("valid")
    condition_builder._expression = StringIdentifier(name="")

    with pytest.raises(ValueError, match="String identifier cannot be empty"):
        builder.with_condition(condition_builder)

    assert isinstance(builder.build().condition, BooleanLiteral)


def test_rule_builder_copies_direct_condition_expressions() -> None:
    condition = BooleanLiteral(value=True)
    builder = RuleBuilder("stable_condition").with_condition(condition)

    condition.value = False

    built_condition = builder.build().condition
    assert isinstance(built_condition, BooleanLiteral)
    assert built_condition.value is True


def test_rule_builder_preserves_falsy_present_condition_expression() -> None:
    class FalsyBooleanLiteral(BooleanLiteral):
        def __bool__(self) -> bool:
            return False

    condition = FalsyBooleanLiteral(value=False)

    rule = RuleBuilder("falsy_condition").with_condition(condition).require_condition().build()

    assert isinstance(rule.condition, FalsyBooleanLiteral)
    assert rule.condition.value is False


def test_rule_builder_raw_hex_rejects_invalid_input() -> None:
    with pytest.raises(
        ValidationError,
        match="Hex parse error at position 3: Invalid character in hex string: Z",
    ):
        RuleBuilder("invalid").with_hex_string_raw("$hex", "4D ZZ ??")

    with pytest.raises(
        ValidationError,
        match="Hex parse error at position 3: Incomplete hex byte",
    ):
        RuleBuilder("invalid").with_hex_string_raw("$hex", "4D F")


def test_rule_builder_raw_hex_uses_full_hex_parser() -> None:
    rule = (
        RuleBuilder("full_hex")
        .with_hex_string_raw("$hex", "4D A? ?F [2-4] (~00 | 41) // comment\n 5A")
        .with_condition("$hex")
        .build()
    )

    hex_string = rule.strings[0]
    assert isinstance(hex_string, HexString)
    tokens = hex_string.tokens
    assert isinstance(tokens[0], HexByte)
    assert tokens[0].value == 0x4D
    assert isinstance(tokens[1], HexNibble)
    assert tokens[1].high is True
    assert tokens[1].value == 0xA
    assert isinstance(tokens[2], HexNibble)
    assert tokens[2].high is False
    assert tokens[2].value == 0xF
    assert isinstance(tokens[3], HexJump)
    assert tokens[3].min_jump == 2
    assert tokens[3].max_jump == 4
    assert isinstance(tokens[4], HexAlternative)
    assert isinstance(tokens[4].alternatives[0][0], HexNegatedByte)
    assert tokens[4].alternatives[0][0].value == 0x00
    assert isinstance(tokens[4].alternatives[1][0], HexByte)
    assert tokens[4].alternatives[1][0].value == 0x41
    assert isinstance(tokens[5], HexByte)
    assert tokens[5].value == 0x5A
    assert "$hex = { 4D A? ?F [2-4] ( ~00 | 41 ) 5A }" in CodeGenerator().generate(rule)


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


def test_rule_builder_condition_lambda_rejects_non_callable() -> None:
    with pytest.raises(TypeError, match="Condition lambda must be callable"):
        RuleBuilder("bad_condition").with_condition_lambda(cast(Any, 123))


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
