"""Additional real coverage for AST transformer and fluent rule builder."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral, StringIdentifier
from yaraast.ast.rules import Rule, Tag
from yaraast.ast.strings import PlainString, RegexString
from yaraast.builder.ast_transformer import (
    RuleTransformer,
    YaraFileTransformer,
    create_variant_rule,
)
from yaraast.builder.fluent_condition_builder import FluentConditionBuilder
from yaraast.builder.fluent_rule_builder import FluentRuleBuilder


def test_fluent_rule_builder_additional_builder_paths() -> None:
    built = (
        FluentRuleBuilder("extra")
        .with_string("$plain", "alpha")
        .pe_header("$pe")
        .email_pattern("$mail")
        .string("$re")
        .regex("foo.*bar")
        .then()
        .condition(FluentConditionBuilder().true())
        .for_small_files()
        .build()
    )

    assert {s.identifier for s in built.strings} == {"$plain", "$pe", "$mail", "$re"}
    assert isinstance(next(s for s in built.strings if s.identifier == "$re"), RegexString)
    assert built.condition is not None
    assert isinstance(built.meta, list)

    built_with_fluent_condition = (
        FluentRuleBuilder("fcb")
        .condition(
            FluentConditionBuilder().any_of_them(),
        )
        .build()
    )
    assert built_with_fluent_condition.condition is not None


def test_ast_transformer_noop_and_list_meta_paths() -> None:
    list_meta_rule = Rule(
        name="list_meta",
        tags=[Tag(name="tag1"), Tag(name="tag2")],
        meta=[],
        strings=[PlainString(identifier="$a", value="x")],
        condition=StringIdentifier(name="$a"),
    )

    transformed = (
        RuleTransformer(list_meta_rule)
        .add_tag("tag1")
        .add_meta("author", "ignored")
        .remove_meta("author")
        .remove_string("missing")
        .transform_condition(lambda expr: BooleanLiteral(value=False))
        .build()
    )

    assert [t.name for t in transformed.tags] == ["tag1", "tag2"]
    assert transformed.meta == []
    assert len(transformed.strings) == 1
    assert isinstance(transformed.condition, BooleanLiteral)
    assert transformed.condition.value is False

    dict_meta_rule = Rule(
        name="dict_meta",
        meta={"author": "me", "version": 1},
        strings=[
            PlainString(identifier="$a", value="x"),
            PlainString(identifier="$b", value="y"),
        ],
        condition=StringIdentifier(name="$b"),
    )
    transformed_dict = (
        RuleTransformer(dict_meta_rule)
        .remove_meta("author")
        .rename_strings({"$a": "$renamed"})
        .build()
    )
    assert len(transformed_dict.meta) == 1
    assert transformed_dict.get_meta_value("version") == 1
    assert [s.identifier for s in transformed_dict.strings] == ["$renamed", "$b"]
    assert isinstance(transformed_dict.condition, StringIdentifier)
    assert transformed_dict.condition.name == "$b"

    no_condition = Rule(name="empty")
    untouched = (
        RuleTransformer(no_condition)
        .transform_condition(lambda expr: BooleanLiteral(value=True))
        .build()
    )
    assert untouched.condition is None


def test_yara_file_transformer_no_match_and_variant_without_optional_changes() -> None:
    rule_one = Rule(name="one")
    rule_two = Rule(name="two")
    yara_file = YaraFile(rules=[rule_one, rule_two])

    unchanged = (
        YaraFileTransformer(yara_file)
        .transform_rule("missing", lambda r: RuleTransformer(r).rename("nope").build())
        .build()
    )
    assert [r.name for r in unchanged.rules] == ["one", "two"]

    variant = create_variant_rule(rule_one, "variant_only")
    assert variant.name == "variant_only"
    assert variant.tags == []
