"""More tests for AST transformer utilities (no mocks)."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import StringIdentifier
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import PlainString
from yaraast.builder.ast_transformer import (
    RuleTransformer,
    YaraFileTransformer,
)


def test_rule_transformer_renames_and_meta() -> None:
    rule = Rule(
        name="r1",
        tags=[Tag(name="tag1")],
        meta={"author": "me"},
        strings=[PlainString(identifier="$a", value="x")],
        condition=StringIdentifier(name="$a"),
    )
    transformed = (
        RuleTransformer(rule)
        .rename("r2")
        .add_prefix("pre_")
        .add_suffix("_suf")
        .add_tag("tag2")
        .add_meta("author", "you")
        .rename_strings({"$a": "$b"})
        .build()
    )

    assert transformed.name == "pre_r2_suf"
    assert any(t.name == "tag2" for t in transformed.tags)
    assert transformed.get_meta_value("author") == "you"
    assert isinstance(transformed.condition, StringIdentifier)
    assert transformed.condition.name == "$b"


def test_transformers_build_independent_ast_nodes() -> None:
    rule = Rule(
        name="r1",
        strings=[PlainString(identifier="$a", value="x")],
        condition=StringIdentifier(name="$a"),
    )

    rule_transformer = RuleTransformer(rule).rename("r2")
    first_rule = rule_transformer.build()
    second_rule = rule_transformer.build()
    first_rule.name = "corrupted"
    first_rule.strings[0].identifier = "$corrupted"

    assert second_rule.name == "r2"
    assert second_rule.strings[0].identifier == "$a"
    assert rule_transformer.build().name == "r2"

    file_transformer = YaraFileTransformer(YaraFile(rules=[rule])).add_import("pe")
    first_file = file_transformer.build()
    second_file = file_transformer.build()
    first_file.imports[0].module = "corrupted"
    first_file.rules[0].name = "corrupted"

    assert second_file.imports[0].module == "pe"
    assert second_file.rules[0].name == "r1"
    assert file_transformer.build().rules[0].name == "r1"


def test_yara_file_transformer_and_merge() -> None:
    rule1 = Rule(name="r1", tags=[Tag(name="a")])
    rule2 = Rule(name="r2", tags=[Tag(name="b")])
    yf1 = YaraFile(imports=[Import(module="pe")], includes=[Include(path="inc.yar")], rules=[rule1])

    merged = YaraFileTransformer(yf1).add_import("math").add_rule(rule2).build()
    assert len(merged.imports) == 2
    assert len(merged.rules) == 2

    transformed = (
        YaraFileTransformer(merged)
        .add_import("hash")
        .remove_include("inc.yar")
        .add_tag_to_all_rules("all_rules")
        .make_all_rules_private()
        .build()
    )
    assert any(imp.module == "hash" for imp in transformed.imports)
    assert all(any(str(m) == "private" for m in r.modifiers) for r in transformed.rules)


def test_create_variant_and_collection() -> None:
    base = Rule(name="base")
    variant = (
        RuleTransformer(base)
        .rename("variant")
        .add_tag("x")
        .add_meta("author", "me")
        .make_private()
        .build()
    )
    assert variant.name == "variant"
    assert any(str(m) == "private" for m in variant.modifiers)

    collection = (
        YaraFileTransformer(YaraFile())
        .add_rule(RuleTransformer(base).add_prefix("grp_").build())
        .add_rule(RuleTransformer(variant).add_prefix("grp_").build())
        .build()
    )
    assert collection.rules[0].name.startswith("grp_")
    assert collection.rules[1].name.startswith("grp_")
