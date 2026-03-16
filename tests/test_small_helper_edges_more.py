"""Additional coverage for small helper modules."""

from __future__ import annotations

from yaraast.ast.rules import Rule
from yaraast.ast.strings import PlainString
from yaraast.performance.memory_helpers import clear_tracking, maybe_collect, pooled_value
from yaraast.serialization.ast_diff import DiffNode, DiffResult, DiffType
from yaraast.serialization.ast_diff_modifiers import emit_modifiers_diff, modifier_payloads
from yaraast.serialization.ast_diff_strings import (
    emit_string_added,
    emit_string_modified,
    emit_string_removed,
    string_maps,
)
from yaraast.yarax.feature_flags import YaraXFeatures


def test_emit_modifiers_and_removed_string_diff() -> None:
    result = DiffResult(old_ast_hash="old", new_ast_hash="new")

    emit_modifiers_diff("rules/r1", result, DiffNode, DiffType, {"private"}, {"global"})
    emit_string_removed("rules/r1/strings", result, DiffNode, DiffType, "$a")

    assert len(result.differences) == 2
    assert result.differences[0].path == "rules/r1/modifiers"
    assert result.differences[1].diff_type == DiffType.REMOVED


def test_maybe_collect_and_yarax_features_to_dict() -> None:
    maybe_collect(True)

    data = YaraXFeatures.yarax_strict().to_dict()
    assert data["strict_regex_escaping"] is True
    assert data["modular_parser"] is True
    relaxed = YaraXFeatures.yarax_compatible()
    assert relaxed.allow_with_statement is True
    assert relaxed.strict_regex_escaping is False


def test_memory_pooling_and_tracking_helpers() -> None:
    pool: dict[str, str] = {}
    assert pooled_value(pool, "abc") == "abc"
    assert pooled_value(pool, "abc") == "abc"
    assert pool == {"abc": "abc"}

    tracked = [1, 2, 3]
    clear_tracking(tracked)
    assert tracked == []


def test_ast_diff_string_and_modifier_helpers_full_paths() -> None:
    old_rule = Rule(name="r1", modifiers=["private"])
    new_rule = Rule(name="r1", modifiers=["global"])
    old_mods, new_mods = modifier_payloads(old_rule, new_rule)
    assert old_mods == {"private"}
    assert new_mods == {"global"}

    old_strings = [PlainString(identifier="$a", value="x")]
    new_strings = [PlainString(identifier="$b", value="y")]
    old_map, new_map = string_maps(old_strings, new_strings)
    assert set(old_map) == {"$a"}
    assert set(new_map) == {"$b"}

    result = DiffResult(old_ast_hash="old", new_ast_hash="new")
    emit_string_added("rules/r1/strings", result, DiffNode, DiffType, "$b")
    emit_string_modified("rules/r1/strings", result, DiffNode, DiffType, "$c", "oldh", "newh")
    emit_string_removed("rules/r1/strings", result, DiffNode, DiffType, "$a")
    assert [d.diff_type for d in result.differences] == [
        DiffType.ADDED,
        DiffType.MODIFIED,
        DiffType.REMOVED,
    ]
