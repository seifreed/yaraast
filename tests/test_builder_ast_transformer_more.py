"""Real tests for builder AST transformer utilities (no mocks)."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import StringIdentifier
from yaraast.ast.rules import Rule, Tag
from yaraast.ast.strings import PlainString
from yaraast.builder.ast_transformer import (
    CloneTransformer,
    RuleTransformer,
    YaraFileTransformer,
)


def _basic_rule(name: str) -> Rule:
    return Rule(
        name=name,
        modifiers=[],
        tags=[Tag(name="t1")],
        meta={"author": "unit"},
        strings=[PlainString(identifier="$a", value="abc", modifiers=[])],
        condition=StringIdentifier(name="$a"),
    )


def test_clone_transformer_rule_and_file() -> None:
    rule = _basic_rule("r1")
    cloned = CloneTransformer.clone_rule(rule)
    assert cloned is not rule
    assert cloned.name == "r1"


def test_rule_transformer_renames_and_modifies() -> None:
    rule = _basic_rule("r1")
    transformed = (
        RuleTransformer(rule)
        .add_prefix("pre_")
        .add_suffix("_suf")
        .add_tag("new")
        .add_modifier("private")
        .rename_strings({"$a": "$b"})
        .build()
    )

    assert transformed.name == "pre_r1_suf"
    assert any(t.name == "new" for t in transformed.tags)
    assert any(str(m) == "private" for m in transformed.modifiers)
    assert transformed.strings[0].identifier == "$b"


def test_rule_transformer_preserves_unknown_rule_modifier() -> None:
    transformed = (
        RuleTransformer(_basic_rule("r1"))
        .add_modifier("vendor_modifier")
        .add_modifier("vendor_modifier")
        .build()
    )

    assert [str(modifier) for modifier in transformed.modifiers] == ["vendor_modifier"]


def test_yara_file_transformer_and_merge() -> None:
    rule1 = _basic_rule("r1")
    rule2 = _basic_rule("r2")
    yf1 = YaraFile(rules=[rule1])

    transformed = (
        YaraFileTransformer(yf1)
        .add_import("pe")
        .add_include("base.yar")
        .add_rule(rule2)
        .prefix_all_rules("pre_")
        .build()
    )

    assert transformed.imports
    assert transformed.includes
    assert all(r.name.startswith("pre_") for r in transformed.rules)

    collection = (
        YaraFileTransformer(YaraFile())
        .add_rule(RuleTransformer(rule1).add_prefix("col_").build())
        .add_rule(RuleTransformer(rule2).add_prefix("col_").build())
        .build()
    )
    assert all(r.name.startswith("col_") for r in collection.rules)

    merged = YaraFileTransformer(yf1).add_import("math").add_rule(rule2).build()
    assert len(merged.rules) >= 2
