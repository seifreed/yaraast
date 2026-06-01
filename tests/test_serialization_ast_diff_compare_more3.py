"""Additional real coverage for ast_diff_compare helpers."""

from __future__ import annotations

from collections.abc import Iterator

from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import PlainString
from yaraast.serialization.ast_diff import DiffNode, DiffResult, DiffType
from yaraast.serialization.ast_diff_compare import compare_imports, compare_includes, compare_rules
from yaraast.serialization.ast_diff_condition import condition_hashes
from yaraast.serialization.ast_diff_hasher import AstHasher
from yaraast.serialization.ast_diff_modifiers import emit_modifiers_diff
from yaraast.serialization.ast_diff_tags import emit_tags_diff


class ReverseIterSet(set[str]):
    """Set test double that exposes nondeterministic set-to-list assumptions."""

    def __iter__(self) -> Iterator[str]:
        return iter(sorted(super().__iter__(), reverse=True))


class _FalsyBooleanLiteral(BooleanLiteral):
    def __bool__(self) -> bool:
        return False


def test_condition_hashes_preserve_falsy_present_condition() -> None:
    hasher = AstHasher()

    old_hash, new_hash = condition_hashes(
        Rule("old", condition=None),
        Rule("new", condition=_FalsyBooleanLiteral(False)),
        hasher,
    )

    assert old_hash == ""
    assert new_hash == "Bool(False)"


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


def test_compare_includes_emits_added_and_removed_paths_in_sorted_order() -> None:
    result = DiffResult(old_ast_hash="old", new_ast_hash="new")

    compare_includes(
        [
            Include(path="old_z.yar"),
            Include(path="old_a.yar"),
            Include(path="old_m.yar"),
        ],
        [
            Include(path="new_z.yar"),
            Include(path="new_a.yar"),
            Include(path="new_m.yar"),
        ],
        result,
        DiffNode,
        DiffType,
    )

    assert [diff.path for diff in result.differences] == [
        "/includes/new_a.yar",
        "/includes/new_m.yar",
        "/includes/new_z.yar",
        "/includes/old_a.yar",
        "/includes/old_m.yar",
        "/includes/old_z.yar",
    ]


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


def test_compare_rules_detects_anonymous_string_flag_change() -> None:
    hasher = AstHasher()
    result = DiffResult(old_ast_hash="old", new_ast_hash="new")
    old_rules = [
        Rule(
            name="shared",
            strings=[PlainString(identifier="$anon_1", value="x", is_anonymous=False)],
            condition=BooleanLiteral(value=True),
        )
    ]
    new_rules = [
        Rule(
            name="shared",
            strings=[PlainString(identifier="$anon_1", value="x", is_anonymous=True)],
            condition=BooleanLiteral(value=True),
        )
    ]

    compare_rules(old_rules, new_rules, result, hasher, DiffNode, DiffType)

    assert len(result.differences) == 1
    diff = result.differences[0]
    assert diff.path == "/rules/shared/strings/$anon_1"
    assert diff.diff_type == DiffType.MODIFIED


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


def test_emit_set_backed_rule_diffs_sort_payload_values() -> None:
    result = DiffResult(old_ast_hash="old", new_ast_hash="new")

    emit_tags_diff(
        "/rules/shared",
        result,
        DiffNode,
        DiffType,
        ReverseIterSet({"old_z", "old_a"}),
        ReverseIterSet({"new_z", "new_a"}),
    )
    emit_modifiers_diff(
        "/rules/shared",
        result,
        DiffNode,
        DiffType,
        ReverseIterSet({"private", "global"}),
        ReverseIterSet({"extern", "private"}),
    )

    assert result.differences[0].old_value == ["old_a", "old_z"]
    assert result.differences[0].new_value == ["new_a", "new_z"]
    assert result.differences[1].old_value == ["global", "private"]
    assert result.differences[1].new_value == ["extern", "private"]
