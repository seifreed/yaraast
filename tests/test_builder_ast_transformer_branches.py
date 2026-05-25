"""Branch-focused tests for AST transformer helpers (no mocks)."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.base import Location, YaraFile
from yaraast.ast.comments import Comment
from yaraast.ast.conditions import ForOfExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLiteral,
    StringOffset,
    StringWildcard,
)
from yaraast.ast.pragmas import CustomPragma, InRulePragma
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
from yaraast.errors import ValidationError


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


def test_generic_clone_rejects_invalid_ast_node_inputs() -> None:
    with pytest.raises(TypeError, match="AST node input must be an ASTNode"):
        CloneTransformer.clone(cast(Any, object()))


def test_rule_clone_and_transform_helpers_reject_invalid_rule_inputs() -> None:
    with pytest.raises(TypeError, match="Rule input must be a Rule"):
        clone_rule(cast(Any, object()))

    with pytest.raises(TypeError, match="Rule input must be a Rule"):
        RuleTransformer(cast(Any, object()))

    with pytest.raises(TypeError, match="Rule input must be a Rule"):
        transform_rule(cast(Any, object()))


def test_yara_file_clone_and_transform_helpers_reject_invalid_file_inputs() -> None:
    with pytest.raises(TypeError, match="YaraFile input must be a YaraFile"):
        clone_yara_file(cast(Any, object()))

    with pytest.raises(TypeError, match="YaraFile input must be a YaraFile"):
        YaraFileTransformer(cast(Any, object()))

    with pytest.raises(TypeError, match="YaraFile input must be a YaraFile"):
        transform_yara_file(cast(Any, object()))

    with pytest.raises(TypeError, match="YaraFile input must be a YaraFile"):
        merge_yara_files(cast(Any, object()))

    with pytest.raises(TypeError, match="YaraFile input must be a YaraFile"):
        merge_yara_files(YaraFile(), cast(Any, object()))


def test_clone_helpers_preserve_rule_metadata_and_pragmas() -> None:
    original_rule = _sample_rule("annotated")
    original_rule.location = Location(line=3, column=1, file="sample.yar")
    original_rule.leading_comments = [Comment("rule lead")]
    original_rule.trailing_comment = Comment("rule tail")
    original_rule.pragmas = [
        InRulePragma(
            pragma=CustomPragma("vendor", arguments=["enabled"]),
            position="before_condition",
        )
    ]

    cloned_rule = clone_rule(original_rule)

    assert cloned_rule.location == original_rule.location
    assert cloned_rule.leading_comments[0].text == "rule lead"
    assert cloned_rule.trailing_comment is not None
    assert cloned_rule.trailing_comment.text == "rule tail"
    assert cloned_rule.pragmas[0].position == "before_condition"
    assert cloned_rule.pragmas[0].pragma.name == "vendor"

    cloned_rule.leading_comments[0].text = "changed"
    cloned_rule.pragmas[0].pragma.arguments.append("mutated")
    assert original_rule.leading_comments[0].text == "rule lead"
    assert original_rule.pragmas[0].pragma.arguments == ["enabled"]


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


def test_rule_transformer_rejects_invalid_replacement_condition_without_partial_update() -> None:
    transformer = RuleTransformer(_sample_rule("condition_rule"))

    with pytest.raises(TypeError, match="Rule condition must be an Expression"):
        transformer.replace_condition(cast(Any, None))

    transformed = transformer.build()
    assert isinstance(transformed.condition, StringIdentifier)
    assert transformed.condition.name == "$a"


def test_rule_transformer_rejects_invalid_condition_transform_results_without_partial_update() -> (
    None
):
    transformer = RuleTransformer(_sample_rule("condition_rule"))

    with pytest.raises(TypeError, match="Condition transformer must return an Expression"):
        transformer.transform_condition(cast(Any, lambda expr: None))

    transformed = transformer.build()
    assert isinstance(transformed.condition, StringIdentifier)
    assert transformed.condition.name == "$a"


def test_rule_transformer_rejects_non_callable_condition_transformer() -> None:
    transformer = RuleTransformer(_sample_rule("condition_rule"))

    with pytest.raises(TypeError, match="Condition transformer must be callable"):
        transformer.transform_condition(cast(Any, 123))

    transformed = transformer.build()
    assert isinstance(transformed.condition, StringIdentifier)
    assert transformed.condition.name == "$a"


def test_rule_transformer_renames_nested_string_references() -> None:
    rule = Rule(
        name="nested_refs",
        strings=[PlainString(identifier="$a", value="1")],
        condition=SetExpression(
            [
                StringIdentifier("$a"),
                StringCount("$a"),
                FunctionCall("uint8", [StringOffset("$a", IntegerLiteral(0))]),
                StringWildcard("$a*"),
            ]
        ),
    )

    transformed = RuleTransformer(rule).rename_strings({"$a": "$renamed"}).build()

    assert isinstance(transformed.condition, SetExpression)
    string_ref, count_ref, call_ref, wildcard_ref = transformed.condition.elements
    assert isinstance(string_ref, StringIdentifier)
    assert string_ref.name == "$renamed"
    assert isinstance(count_ref, StringCount)
    assert count_ref.string_id == "$renamed"
    assert isinstance(call_ref, FunctionCall)
    assert isinstance(call_ref.arguments[0], StringOffset)
    assert call_ref.arguments[0].string_id == "$renamed"
    assert isinstance(wildcard_ref, StringWildcard)
    assert wildcard_ref.pattern == "$renamed*"


def test_rule_transformer_normalizes_bare_string_rename_mappings() -> None:
    bare_key_rule = Rule(
        name="bare_key",
        strings=[PlainString(identifier="$a", value="1")],
        condition=StringIdentifier("$a"),
    )
    bare_key = RuleTransformer(bare_key_rule).rename_strings({"a": "renamed"}).build()

    assert bare_key.strings[0].identifier == "$renamed"
    assert isinstance(bare_key.condition, StringIdentifier)
    assert bare_key.condition.name == "$renamed"

    bare_value_rule = Rule(
        name="bare_value",
        strings=[PlainString(identifier="$a", value="1")],
        condition=SetExpression([StringIdentifier("$a"), StringCount("a")]),
    )
    bare_value = RuleTransformer(bare_value_rule).rename_strings({"$a": "renamed"}).build()

    assert bare_value.strings[0].identifier == "$renamed"
    assert isinstance(bare_value.condition, SetExpression)
    string_ref, count_ref = bare_value.condition.elements
    assert isinstance(string_ref, StringIdentifier)
    assert string_ref.name == "$renamed"
    assert isinstance(count_ref, StringCount)
    assert count_ref.string_id == "renamed"


def test_rule_transformer_renames_string_literals_inside_string_sets() -> None:
    rule = Rule(
        name="literal_string_sets",
        strings=[
            PlainString(identifier="$a", value="1"),
            PlainString(identifier="$b", value="2"),
        ],
        condition=SetExpression(
            [
                OfExpression("any", SetExpression([StringLiteral("$a"), StringLiteral("$b*")])),
                ForOfExpression(
                    "any",
                    ParenthesesExpression(SetExpression([StringLiteral("$a")])),
                    condition=None,
                ),
            ]
        ),
    )

    transformed = RuleTransformer(rule).rename_strings({"$a": "$renamed", "$b": "$other"}).build()

    assert isinstance(transformed.condition, SetExpression)
    of_expr, for_of_expr = transformed.condition.elements
    assert isinstance(of_expr, OfExpression)
    assert isinstance(of_expr.string_set, SetExpression)
    renamed_values = []
    for item in of_expr.string_set.elements:
        assert isinstance(item, StringLiteral)
        renamed_values.append(item.value)
    assert renamed_values == ["$renamed", "$other*"]
    assert isinstance(for_of_expr, ForOfExpression)
    assert isinstance(for_of_expr.string_set, ParenthesesExpression)
    assert isinstance(for_of_expr.string_set.expression, SetExpression)
    nested_item = for_of_expr.string_set.expression.elements[0]
    assert isinstance(nested_item, StringLiteral)
    assert nested_item.value == "$renamed"


def test_rule_transformer_rejects_duplicate_string_renames_without_partial_update() -> None:
    rule = Rule(
        name="duplicate_rename",
        strings=[
            PlainString(identifier="$a", value="1"),
            PlainString(identifier="$b", value="2"),
        ],
        condition=StringIdentifier("$a"),
    )
    transformer = RuleTransformer(rule)

    with pytest.raises(ValidationError, match="Duplicate string identifier"):
        transformer.rename_strings({"$a": "$b"})

    transformed = transformer.build()
    assert [string.identifier for string in transformed.strings] == ["$a", "$b"]
    assert isinstance(transformed.condition, StringIdentifier)
    assert transformed.condition.name == "$a"


def test_rule_transformer_rejects_invalid_string_renames_without_partial_update() -> None:
    transformer = RuleTransformer(_sample_rule("invalid_rename"))

    with pytest.raises(ValidationError, match="Invalid string identifier"):
        transformer.rename_strings({"$a": "$bad-key"})

    transformed = transformer.build()
    assert [string.identifier for string in transformed.strings] == ["$a"]
    assert isinstance(transformed.condition, StringIdentifier)
    assert transformed.condition.name == "$a"


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
        .add_tag_to_all_rules("all_rules")
        .make_all_rules_private()
        .set_author_for_all_rules("team")
        .filter_by_tag("all_rules")
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


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"prefix": True}, "Variant prefix must be a string"),
        ({"suffix": True}, "Variant suffix must be a string"),
        ({"tags": "abc"}, "Variant tags must be an iterable of strings"),
        ({"tags": ["ok", True]}, "Variant tags must be an iterable of strings"),
        ({"author": True}, "Variant author must be a string"),
        ({"description": True}, "Variant description must be a string"),
        ({"private": "false"}, "Variant private flag must be a boolean"),
    ],
)
def test_create_variant_rule_rejects_invalid_option_types(
    changes: dict[str, object], message: str
) -> None:
    with pytest.raises(TypeError, match=message):
        create_variant_rule(_sample_rule("base"), "variant", **changes)


@pytest.mark.parametrize(
    ("rules", "collection_name", "message"),
    [
        (object(), "grp", "Rule collection rules must be an iterable of Rule"),
        ("abc", "grp", "Rule collection rules must be an iterable of Rule"),
        ([object()], "grp", "Rule collection rules must contain Rule values"),
        ([_sample_rule("base")], True, "Rule collection name must be a string"),
    ],
)
def test_create_rule_collection_rejects_invalid_inputs(
    rules: object, collection_name: object, message: str
) -> None:
    with pytest.raises(TypeError, match=message):
        create_rule_collection(cast(Any, rules), cast(Any, collection_name))


def test_yara_file_transformer_rejects_duplicate_rule_names_without_partial_update() -> None:
    existing = _sample_rule("duplicate")
    transformer = YaraFileTransformer(YaraFile(rules=[existing]))

    with pytest.raises(ValidationError, match="Duplicate rule identifier"):
        transformer.add_rule(_sample_rule("duplicate"))

    assert [rule.name for rule in transformer.build().rules] == ["duplicate"]


def test_yara_file_transformer_rejects_invalid_added_rule_names_without_partial_update() -> None:
    transformer = YaraFileTransformer(YaraFile(rules=[_sample_rule("valid")]))

    with pytest.raises(ValidationError, match="Invalid rule identifier"):
        transformer.add_rule(_sample_rule("bad-name"))

    assert [rule.name for rule in transformer.build().rules] == ["valid"]


def test_yara_file_transformer_rejects_invalid_added_rule_inputs_without_partial_update() -> None:
    transformer = YaraFileTransformer(YaraFile(rules=[_sample_rule("valid")]))

    with pytest.raises(TypeError, match="Rule input must be a Rule"):
        transformer.add_rule(cast(Any, object()))

    assert [rule.name for rule in transformer.build().rules] == ["valid"]


def test_yara_file_transformer_rejects_duplicate_transformed_rule_names_without_partial_update() -> (
    None
):
    transformer = YaraFileTransformer(YaraFile(rules=[_sample_rule("one"), _sample_rule("two")]))

    with pytest.raises(ValidationError, match="Duplicate rule identifier"):
        transformer.transform_rule("one", lambda rule: RuleTransformer(rule).rename("two").build())

    assert [rule.name for rule in transformer.build().rules] == ["one", "two"]


def test_yara_file_transformer_rejects_non_rule_transform_results_without_partial_update() -> None:
    transformer = YaraFileTransformer(YaraFile(rules=[_sample_rule("one")]))

    with pytest.raises(TypeError, match="Rule transformer must return a Rule"):
        transformer.transform_rule("one", cast(Any, lambda rule: None))

    assert [rule.name for rule in transformer.build().rules] == ["one"]


def test_yara_file_transformer_rejects_non_callable_rule_transformer() -> None:
    transformer = YaraFileTransformer(YaraFile(rules=[_sample_rule("one")]))

    with pytest.raises(TypeError, match="Rule transformer must be callable"):
        transformer.transform_rule("one", cast(Any, 123))

    assert [rule.name for rule in transformer.build().rules] == ["one"]


def test_yara_file_transformer_rejects_duplicate_all_rule_transform_names_without_partial_update() -> (
    None
):
    transformer = YaraFileTransformer(YaraFile(rules=[_sample_rule("one"), _sample_rule("two")]))

    with pytest.raises(ValidationError, match="Duplicate rule identifier"):
        transformer.transform_all_rules(lambda rule: RuleTransformer(rule).rename("same").build())

    assert [rule.name for rule in transformer.build().rules] == ["one", "two"]


def test_yara_file_transformer_rejects_non_callable_all_rule_transformer() -> None:
    transformer = YaraFileTransformer(YaraFile(rules=[_sample_rule("one")]))

    with pytest.raises(TypeError, match="Rule transformer must be callable"):
        transformer.transform_all_rules(cast(Any, 123))

    assert [rule.name for rule in transformer.build().rules] == ["one"]


def test_yara_file_transformer_filter_predicates_receive_rule_copies() -> None:
    transformer = YaraFileTransformer(YaraFile(rules=[_sample_rule("keep"), _sample_rule("drop")]))

    def predicate(rule: Rule) -> bool:
        keep_rule = rule.name == "keep"
        rule.name = "bad-name"
        return keep_rule

    transformed = transformer.filter_rules(predicate).build()

    assert [rule.name for rule in transformed.rules] == ["keep"]


def test_yara_file_transformer_rejects_non_bool_filter_results_without_partial_update() -> None:
    transformer = YaraFileTransformer(YaraFile(rules=[_sample_rule("stable")]))

    with pytest.raises(TypeError, match="Rule filter predicate must return bool"):
        transformer.filter_rules(cast(Any, lambda rule: "truthy"))

    assert [rule.name for rule in transformer.build().rules] == ["stable"]


def test_yara_file_transformer_rejects_non_callable_filter_predicate() -> None:
    transformer = YaraFileTransformer(YaraFile(rules=[_sample_rule("stable")]))

    with pytest.raises(TypeError, match="Rule filter predicate must be callable"):
        transformer.filter_rules(cast(Any, 123))

    assert [rule.name for rule in transformer.build().rules] == ["stable"]


def test_yara_file_transformer_rejects_empty_imports_and_includes() -> None:
    transformer = YaraFileTransformer(YaraFile()).add_import("pe").add_include("common.yar")

    with pytest.raises(ValidationError, match="Import module must not be empty"):
        transformer.add_import("")

    with pytest.raises(ValidationError, match="Include path must not be empty"):
        transformer.add_include("")

    transformed = transformer.build()
    assert [imp.module for imp in transformed.imports] == ["pe"]
    assert [inc.path for inc in transformed.includes] == ["common.yar"]


@pytest.mark.parametrize("alias", ["bad alias", "bad-alias", "for", "1bad", ""])
def test_yara_file_transformer_rejects_invalid_import_alias(alias: str) -> None:
    with pytest.raises(ValidationError, match="Invalid import alias identifier"):
        YaraFileTransformer(YaraFile()).add_import("pe", alias)


@pytest.mark.parametrize(
    ("operation", "argument"),
    [
        ("rename", "bad-name"),
        ("rename", "for"),
        ("add_prefix", "bad-"),
        ("add_suffix", "-bad"),
    ],
)
def test_rule_transformer_rejects_invalid_rule_names_without_partial_update(
    operation: str,
    argument: str,
) -> None:
    transformer = RuleTransformer(_sample_rule("valid_name"))

    with pytest.raises(ValidationError, match="Invalid rule identifier"):
        getattr(transformer, operation)(argument)

    assert transformer.build().name == "valid_name"


@pytest.mark.parametrize(
    ("operation", "argument", "message"),
    [
        ("add_prefix", True, "Rule prefix must be a string"),
        ("add_suffix", True, "Rule suffix must be a string"),
        ("add_modifier", True, "Rule modifier must be a string"),
        ("set_author", True, "Rule author must be a string"),
        ("set_description", 123, "Rule description must be a string"),
    ],
)
def test_rule_transformer_rejects_non_string_text_inputs_without_partial_update(
    operation: str,
    argument: object,
    message: str,
) -> None:
    transformer = RuleTransformer(_sample_rule("valid_name"))

    with pytest.raises(TypeError, match=message):
        getattr(transformer, operation)(cast(Any, argument))

    transformed = transformer.build()
    assert transformed.name == "valid_name"
    assert [str(modifier) for modifier in transformed.modifiers] == ["global"]
    assert transformed.get_meta_value("author") == "me"
    assert transformed.get_meta_value("description") is None


@pytest.mark.parametrize("tag", ["bad tag", "bad-tag", "for", "1bad", ""])
def test_rule_transformer_rejects_invalid_tags_without_partial_update(tag: str) -> None:
    transformer = RuleTransformer(_sample_rule("tagged"))

    with pytest.raises(ValidationError, match="Invalid tag identifier"):
        transformer.add_tag(tag)
    assert [rule_tag.name for rule_tag in transformer.build().tags] == ["t1"]

    with pytest.raises(ValidationError, match="Invalid tag identifier"):
        transformer.replace_tag("t1", tag)
    assert [rule_tag.name for rule_tag in transformer.build().tags] == ["t1"]


def test_rule_transformer_rejects_duplicate_replacement_tag_without_partial_update() -> None:
    transformer = RuleTransformer(_sample_rule("tagged")).add_tag("t2")

    with pytest.raises(ValidationError, match="Duplicate tag identifier"):
        transformer.replace_tag("t1", "t2")

    assert [rule_tag.name for rule_tag in transformer.build().tags] == ["t1", "t2"]


@pytest.mark.parametrize("meta_key", ["bad key", "bad-key", "for", "1bad", ""])
def test_rule_transformer_rejects_invalid_meta_keys_without_partial_update(
    meta_key: str,
) -> None:
    transformer = RuleTransformer(_sample_rule("metadata_rule"))

    with pytest.raises(ValidationError, match="Invalid meta identifier"):
        transformer.add_meta(meta_key, "x")

    transformed = transformer.build()
    assert transformed.get_meta_value("author") == "me"
    assert transformed.get_meta_value(meta_key) is None


@pytest.mark.parametrize("meta_value", [1.5, None, ["x"]])
def test_rule_transformer_rejects_invalid_meta_values_without_partial_update(
    meta_value: object,
) -> None:
    transformer = RuleTransformer(_sample_rule("metadata_rule"))

    with pytest.raises(TypeError, match="Invalid meta value"):
        transformer.add_meta("author", cast(Any, meta_value))
    assert transformer.build().get_meta_value("author") == "me"

    with pytest.raises(TypeError, match="Invalid meta value"):
        transformer.add_meta("new_key", cast(Any, meta_value))
    assert transformer.build().get_meta_value("new_key") is None


@pytest.mark.parametrize("version", [True, "1", 1.5])
def test_rule_transformer_rejects_invalid_version_without_partial_update(
    version: object,
) -> None:
    transformer = RuleTransformer(_sample_rule("metadata_rule"))

    with pytest.raises(TypeError, match="Version value must be an integer"):
        transformer.set_version(cast(Any, version))

    assert transformer.build().get_meta_value("version") is None


def test_rule_transformer_rejects_duplicate_strings_without_partial_update() -> None:
    transformer = RuleTransformer(_sample_rule("string_rule"))

    with pytest.raises(ValidationError, match="Duplicate string identifier"):
        transformer.add_string(PlainString(identifier="$a", value="duplicate"))

    transformed = transformer.build()
    assert transformed.strings == [PlainString(identifier="$a", value="x")]


def test_rule_transformer_rejects_invalid_strings_without_partial_update() -> None:
    transformer = RuleTransformer(_sample_rule("string_rule"))

    with pytest.raises(ValidationError, match="Invalid string identifier"):
        transformer.add_string(PlainString(identifier="$bad-key", value="invalid"))

    transformed = transformer.build()
    assert transformed.strings == [PlainString(identifier="$a", value="x")]


def test_rule_transformer_copies_added_string_definitions() -> None:
    source = PlainString(identifier="$extra", value="z")
    transformer = RuleTransformer(_sample_rule("string_rule")).add_string(source)

    source.identifier = "$renamed"
    source.value = "changed"

    transformed = transformer.build()
    assert [string_def.identifier for string_def in transformed.strings] == ["$a", "$extra"]
    added_string = transformed.strings[1]
    assert isinstance(added_string, PlainString)
    assert added_string.value == "z"
