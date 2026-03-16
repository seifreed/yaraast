"""More tests for AST transformer utilities (no mocks)."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import StringIdentifier
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import PlainString
from yaraast.builder.ast_transformer import (
    RuleTransformer,
    create_rule_collection,
    create_variant_rule,
    merge_yara_files,
    transform_yara_file,
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
        .remove_tag("tag1")
        .set_author("you")
        .rename_strings({"$a": "$b"})
        .build()
    )

    assert transformed.name == "pre_r2_suf"
    assert any(t.name == "tag2" for t in transformed.tags)
    assert transformed.meta["author"] == "you"
    assert transformed.condition.name == "$b"


def test_yara_file_transformer_and_merge() -> None:
    rule1 = Rule(name="r1", tags=[Tag(name="a")])
    rule2 = Rule(name="r2", tags=[Tag(name="b")])
    yf1 = YaraFile(imports=[Import(module="pe")], includes=[Include(path="inc.yar")], rules=[rule1])
    yf2 = YaraFile(imports=[Import(module="math")], includes=[], rules=[rule2])

    merged = merge_yara_files(yf1, yf2)
    assert len(merged.imports) == 2
    assert len(merged.rules) == 2

    transformed = (
        transform_yara_file(merged)
        .add_import("hash")
        .remove_include("inc.yar")
        .add_tag_to_all_rules("all")
        .make_all_rules_private()
        .build()
    )
    assert any(imp.module == "hash" for imp in transformed.imports)
    assert all("private" in r.modifiers for r in transformed.rules)


def test_create_variant_and_collection() -> None:
    base = Rule(name="base")
    variant = create_variant_rule(base, "variant", tags=["x"], author="me", private=True)
    assert variant.name == "variant"
    assert "private" in variant.modifiers

    collection = create_rule_collection([base, variant], "grp")
    assert collection.rules[0].name.startswith("grp_")
    assert collection.rules[1].name.startswith("grp_")
