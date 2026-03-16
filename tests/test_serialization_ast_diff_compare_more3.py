"""Additional real coverage for ast_diff_compare helpers."""

from __future__ import annotations

from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import PlainString
from yaraast.serialization.ast_diff import DiffNode, DiffResult, DiffType
from yaraast.serialization.ast_diff_compare import compare_imports, compare_includes, compare_rules
from yaraast.serialization.ast_diff_hasher import AstHasher


def test_compare_imports_and_includes_removed_and_alias_modified() -> None:
    result = DiffResult(old_ast_hash="old", new_ast_hash="new")

    old_imports = [Import(module="pe", alias="x"), Import(module="math")]
    new_imports = [Import(module="pe", alias="y")]
    compare_imports(old_imports, new_imports, result, DiffNode, DiffType)

    old_includes = [Include(path="old.yar"), Include(path="gone.yar")]
    new_includes = [Include(path="old.yar"), Include(path="new.yar")]
    compare_includes(old_includes, new_includes, result, DiffNode, DiffType)

    paths = {d.path: d for d in result.differences}
    assert paths["/imports/math"].diff_type == DiffType.REMOVED
    assert paths["/imports/pe/alias"].diff_type == DiffType.MODIFIED
    assert paths["/includes/gone.yar"].diff_type == DiffType.REMOVED
    assert paths["/includes/new.yar"].diff_type == DiffType.ADDED


def test_compare_rules_removed_modifier_and_string_diffs() -> None:
    hasher = AstHasher()
    result = DiffResult(old_ast_hash="old", new_ast_hash="new")

    old_rules = [
        Rule(
            name="old_only",
            condition=BooleanLiteral(value=True),
        ),
        Rule(
            name="shared",
            modifiers=["private"],
            strings=[
                PlainString(identifier="$a", value="x"),
                PlainString(identifier="$b", value="y"),
            ],
            condition=BooleanLiteral(value=True),
        ),
    ]
    new_rules = [
        Rule(
            name="shared",
            modifiers=["global"],
            strings=[PlainString(identifier="$a", value="x2")],
            condition=BooleanLiteral(value=True),
        ),
        Rule(
            name="new_only",
            condition=BooleanLiteral(value=True),
        ),
    ]

    compare_rules(old_rules, new_rules, result, hasher, DiffNode, DiffType)

    by_path = {d.path: d for d in result.differences}
    assert by_path["/rules/old_only"].diff_type == DiffType.REMOVED
    assert by_path["/rules/new_only"].diff_type == DiffType.ADDED
    assert by_path["/rules/shared/modifiers"].diff_type == DiffType.MODIFIED
    assert by_path["/rules/shared/strings/$b"].diff_type == DiffType.REMOVED
    assert by_path["/rules/shared/strings/$a"].diff_type == DiffType.MODIFIED


def test_compare_rules_meta_tags_and_added_string_diffs() -> None:
    hasher = AstHasher()
    result = DiffResult(old_ast_hash="old", new_ast_hash="new")

    old_rules = [
        Rule(
            name="shared",
            tags=[],
            meta={"author": "a"},
            strings=[],
            condition=BooleanLiteral(value=True),
        ),
    ]
    new_rules = [
        Rule(
            name="shared",
            tags=[Tag(name="tag1")],
            meta={"author": "b"},
            strings=[PlainString(identifier="$c", value="z")],
            condition=BooleanLiteral(value=True),
        ),
    ]

    compare_rules(old_rules, new_rules, result, hasher, DiffNode, DiffType)

    by_path = {d.path: d for d in result.differences}
    assert by_path["/rules/shared/meta"].diff_type == DiffType.MODIFIED
    assert by_path["/rules/shared/tags"].diff_type == DiffType.MODIFIED
    assert by_path["/rules/shared/strings/$c"].diff_type == DiffType.ADDED
