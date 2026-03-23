"""Branch-focused tests for AST transformer helpers (no mocks)."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BinaryExpression, Identifier, StringIdentifier
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import PlainString
from yaraast.builder.ast_transformer import (
    CloneTransformer,
    RuleTransformer,
    YaraFileTransformer,
    clone_rule,
    clone_yara_file,
    create_rule_collection,
    create_variant_rule,
    merge_yara_files,
    transform_rule,
    transform_yara_file,
)


def _sample_rule(name: str = "r1") -> Rule:
    return Rule(
        name=name,
        modifiers=["global"],
        tags=[Tag(name="t1")],
        meta={"author": "me"},
        strings=[PlainString(identifier="$a", value="x")],
        condition=StringIdentifier(name="$a"),
    )


def test_clone_helpers_create_deep_independent_copies() -> None:
    original_rule = _sample_rule("orig")
    cloned_rule = clone_rule(original_rule)

    cloned_rule.name = "changed"
    cloned_rule.tags[0].name = "changed_tag"
    cloned_rule.meta[0].value = "other"
    cloned_rule.strings[0].identifier = "$b"

    assert original_rule.name == "orig"
    assert original_rule.tags[0].name == "t1"
    assert original_rule.get_meta_value("author") == "me"
    assert original_rule.strings[0].identifier == "$a"

    original_file = YaraFile(
        imports=[Import(module="pe")],
        includes=[Include(path="inc.yar")],
        rules=[original_rule],
    )
    cloned_file = clone_yara_file(original_file)
    cloned_file.imports[0].module = "math"
    cloned_file.rules[0].name = "mutated"

    assert original_file.imports[0].module == "pe"
    assert original_file.rules[0].name == "orig"


def test_rule_transformer_tag_modifier_meta_and_string_helpers() -> None:
    transformed = (
        RuleTransformer(_sample_rule())
        .rename("base")
        .add_prefix("pre_")
        .add_suffix("_suf")
        .add_tag("t2")
        .replace_tag("t1", "new")
        .remove_tag("missing")
        .add_modifier("private")
        .add_modifier("private")
        .remove_modifier("global")
        .set_author("you")
        .set_description("desc")
        .set_version(7)
        .remove_meta("missing")
        .rename_strings({"$a": "$renamed"})
        .build()
    )

    assert transformed.name == "pre_base_suf"
    assert {t.name for t in transformed.tags} == {"new", "t2"}
    assert [str(m) for m in transformed.modifiers] == ["private"]
    assert transformed.get_meta_value("author") == "you"
    assert transformed.get_meta_value("description") == "desc"
    assert transformed.get_meta_value("version") == 7
    assert transformed.strings[0].identifier == "$renamed"
    assert isinstance(transformed.condition, StringIdentifier)
    assert transformed.condition.name == "$renamed"


def test_rule_transformer_prefix_suffix_and_condition_transform_paths() -> None:
    rule = Rule(
        name="ids",
        strings=[
            PlainString(identifier="$one", value="1"),
            PlainString(identifier="two", value="2"),
        ],
        condition=BinaryExpression(
            left=Identifier(name="filesize"),
            operator=">",
            right=Identifier(name="entrypoint"),
        ),
    )
    transformer = RuleTransformer(rule)

    prefixed = transformer.prefix_strings("p_").suffix_strings("_s").build()
    assert [s.identifier for s in prefixed.strings] == ["$p_one_s", "p_two_s"]
    assert isinstance(prefixed.condition, BinaryExpression)

    with_added = (
        RuleTransformer(prefixed).add_string(PlainString(identifier="$extra", value="z")).build()
    )
    with_removed = RuleTransformer(with_added).remove_string("$extra").build()
    assert [s.identifier for s in with_removed.strings] == ["$p_one_s", "p_two_s"]

    cond_transformed = (
        RuleTransformer(with_removed)
        .transform_condition(
            lambda expr: BinaryExpression(left=expr, operator="and", right=Identifier(name="ok"))
        )
        .build()
    )
    assert isinstance(cond_transformed.condition, BinaryExpression)
    assert cond_transformed.condition.operator == "and"

    replaced = (
        RuleTransformer(cond_transformed)
        .replace_condition(StringIdentifier(name="$p_one_s"))
        .build()
    )
    assert isinstance(replaced.condition, StringIdentifier)


def test_yara_file_transformer_operations_and_filters() -> None:
    original = YaraFile(
        imports=[Import(module="pe")],
        includes=[Include(path="a.yar")],
        rules=[_sample_rule("one"), _sample_rule("two")],
    )

    transformed = (
        YaraFileTransformer(original)
        .add_import("pe")
        .add_import("math")
        .remove_import("missing")
        .add_include("a.yar")
        .add_include("b.yar")
        .remove_include("missing")
        .remove_rule("missing")
        .transform_rule("one", lambda r: RuleTransformer(r).rename("renamed").build())
        .prefix_all_rules("pre_")
        .suffix_all_rules("_suf")
        .add_tag_to_all_rules("all")
        .make_all_rules_private()
        .set_author_for_all_rules("team")
        .filter_by_tag("all")
        .filter_by_modifier("private")
        .build()
    )

    assert {imp.module for imp in transformed.imports} == {"pe", "math"}
    assert {inc.path for inc in transformed.includes} == {"a.yar", "b.yar"}
    assert [r.name for r in transformed.rules] == ["pre_renamed_suf", "pre_two_suf"]
    assert all(any(str(m) == "private" for m in r.modifiers) for r in transformed.rules)
    assert all(r.get_meta_value("author") == "team" for r in transformed.rules)


def test_convenience_transform_functions_and_variant_collection_merge_paths() -> None:
    base = _sample_rule("base")

    via_helper = transform_rule(base).make_public().make_global().build()
    assert not any(str(m) == "private" for m in via_helper.modifiers)
    assert any(str(m) == "global" for m in via_helper.modifiers)

    variant = create_variant_rule(
        base,
        "variant",
        prefix="pre_",
        suffix="_suf",
        tags=["x", "y"],
        author="author2",
        description="desc2",
        private=True,
    )
    assert variant.name == "pre_variant_suf"
    assert {t.name for t in variant.tags} == {"t1", "x", "y"}
    assert variant.get_meta_value("author") == "author2"
    assert variant.get_meta_value("description") == "desc2"
    assert any(str(m) == "private" for m in variant.modifiers)

    collection = create_rule_collection([base, variant], "grp")
    assert [r.name for r in collection.rules] == ["grp_base", "grp_pre_variant_suf"]

    empty_merge = merge_yara_files()
    assert empty_merge.rules == []
    assert empty_merge.imports == []

    f1 = YaraFile(imports=[Import(module="pe")], includes=[Include(path="x.yar")], rules=[base])
    f2 = YaraFile(
        imports=[Import(module="pe"), Import(module="math")],
        includes=[Include(path="x.yar"), Include(path="y.yar")],
        rules=[variant],
    )
    merged = merge_yara_files(f1, f2)
    assert {imp.module for imp in merged.imports} == {"pe", "math"}
    assert {inc.path for inc in merged.includes} == {"x.yar", "y.yar"}
    assert [r.name for r in merged.rules] == ["base", "pre_variant_suf"]

    helper_transformed = transform_yara_file(merged).remove_include("x.yar").build()
    assert {inc.path for inc in helper_transformed.includes} == {"y.yar"}

    direct_clone = CloneTransformer.clone_rule(base)
    deep_clone = CloneTransformer.clone(base)
    assert isinstance(direct_clone, Rule)
    assert isinstance(deep_clone, Rule)
