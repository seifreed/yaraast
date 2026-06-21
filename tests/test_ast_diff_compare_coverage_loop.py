# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests that close the remaining coverage gaps in ast_diff_compare.

Each test function targets one or more specific uncovered lines/branches
identified from the coverage report:

    Lines 25-27      compare_imports: ADDED branch
    Branch 37->36    compare_imports: empty REMOVED loop
    Branch 49->48    compare_imports: empty SHARED loop (no key intersection)
    Branch 55->48    compare_imports: shared single-bucket, alias unchanged
    Branch 68->48    compare_imports: shared multi-bucket, payloads unchanged
    Line 248         _import_bucket_value: multi-import path
    Line 258         _include_bucket_value: multi-include path
    Line 268         _extern_import_key: fallback to `module` attribute
    Lines 298-299    _string_attr_or_empty: TypeError for non-string attribute
    Line 307         _optional_string_attr: non-string TypeError guard
    Line 310         _optional_string_attr: return non-None string value
    Line 316         _pragma_type_value: pragma_type is None -> returns ""
    Lines 319-320    _pragma_type_value: TypeError for non-string value
    Line 432         _rule_bucket_value: multi-rule hashes path
    Line 438         _rule_added_details: multi-rule path
    Line 444         _rule_removed_details: multi-rule path
    Line 459         _compare_duplicate_rule_bucket: identical hashes -> early return
    Line 692         compare_rule_strings: multi-bucket ADDED
    Line 706         compare_rule_strings: multi-bucket REMOVED
    Branch 734->715  compare_rule_strings: multi-bucket shared, hashes equal -> no diff

Structurally unreachable branches (dead code in source, not testable):
    Branch 25->24    compare_imports: if-false branch inside set-difference loop
    Branch 37->36    compare_imports: if-false branch inside set-difference loop
    Branch 49->48    compare_imports: if-false branch inside intersection loop

    In each case the for-loop iterates over a set operation result (A - B or A & B)
    whose elements are guaranteed to satisfy the subsequent if-condition by construction.
    Coverage.py emits these as missing branches because the if-body can be reached without
    the guard returning False, but a False result would require an element present in the
    iterated set yet absent from the same set — which is impossible.
"""

from __future__ import annotations

import pytest

from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Import, Include, Rule
from yaraast.ast.strings import PlainString
from yaraast.serialization.ast_diff import DiffNode, DiffResult, DiffType
from yaraast.serialization.ast_diff_compare import (
    _extern_import_key,
    _import_bucket_value,
    _include_bucket_value,
    _optional_string_attr,
    _pragma_type_value,
    _rule_added_details,
    _rule_bucket_value,
    _rule_removed_details,
    _string_attr_or_empty,
    compare_imports,
    compare_includes,
    compare_rule_strings,
    compare_rules,
)
from yaraast.serialization.ast_diff_hasher import AstHasher


def _result() -> DiffResult:
    return DiffResult(old_ast_hash="old", new_ast_hash="new")


# ---------------------------------------------------------------------------
# compare_imports — ADDED branch (lines 25-27) and empty REMOVED loop (37->36)
# ---------------------------------------------------------------------------


def test_compare_imports_adds_new_module_and_skips_empty_removed_loop() -> None:
    """Cover lines 25-27 (ADDED path) and branch 37->36 (no removals)."""
    # Arrange: 'pe' exists in both; 'math' is added exclusively in new
    old_imports = [Import(module="pe")]
    new_imports = [Import(module="pe"), Import(module="math")]

    # Act
    result = _result()
    compare_imports(old_imports, new_imports, result, DiffNode, DiffType)

    # Assert: only the addition is recorded; removed loop had nothing to emit
    paths = {d.path: d for d in result.differences}
    assert "/imports/math" in paths
    assert paths["/imports/math"].diff_type == DiffType.ADDED
    assert paths["/imports/math"].new_value == "math"
    assert all(d.diff_type != DiffType.REMOVED for d in result.differences)


# ---------------------------------------------------------------------------
# compare_imports — empty SHARED loop (branch 49->48, no key intersection)
# ---------------------------------------------------------------------------


def test_compare_imports_no_shared_keys_emits_added_and_removed_only() -> None:
    """Cover branch 49->48: the shared-keys loop body is never entered."""
    # Arrange: completely disjoint module sets
    old_imports = [Import(module="pe")]
    new_imports = [Import(module="math")]

    # Act
    result = _result()
    compare_imports(old_imports, new_imports, result, DiffNode, DiffType)

    # Assert: one ADDED, one REMOVED, nothing MODIFIED
    by_type = {d.diff_type for d in result.differences}
    assert DiffType.ADDED in by_type
    assert DiffType.REMOVED in by_type
    assert DiffType.MODIFIED not in by_type


# ---------------------------------------------------------------------------
# compare_imports — shared single-bucket, alias unchanged (branch 55->48)
# ---------------------------------------------------------------------------


def test_compare_imports_same_alias_emits_no_diff() -> None:
    """Cover branch 55->48: identical alias means the diff_node is not appended."""
    # Arrange: same module, same alias in both old and new
    old_imports = [Import(module="pe", alias="x")]
    new_imports = [Import(module="pe", alias="x")]

    # Act
    result = _result()
    compare_imports(old_imports, new_imports, result, DiffNode, DiffType)

    # Assert: no differences recorded
    assert result.differences == []


# ---------------------------------------------------------------------------
# compare_imports — shared multi-bucket, payloads unchanged (branch 68->48)
# ---------------------------------------------------------------------------


def test_compare_imports_multi_bucket_same_payloads_emits_no_diff() -> None:
    """Cover branch 68->48: duplicate module entries with identical payloads."""
    # Arrange: two 'pe' imports in both sides, same aliases
    old_imports = [Import(module="pe", alias="x"), Import(module="pe", alias="y")]
    new_imports = [Import(module="pe", alias="x"), Import(module="pe", alias="y")]

    # Act
    result = _result()
    compare_imports(old_imports, new_imports, result, DiffNode, DiffType)

    # Assert: hashes are equal after sort, so no MODIFIED entry
    assert result.differences == []


# ---------------------------------------------------------------------------
# _import_bucket_value — multi-import path (line 248)
# ---------------------------------------------------------------------------


def test_import_bucket_value_returns_payload_list_for_multiple_imports() -> None:
    """Cover line 248: len(imports) != 1 returns sorted payload dicts."""
    # Arrange
    imports = [Import(module="pe", alias="b"), Import(module="pe", alias="a")]

    # Act
    value = _import_bucket_value("pe", imports)

    # Assert: returns a list of dicts sorted by alias
    assert isinstance(value, list)
    assert value[0]["alias"] == "a"
    assert value[1]["alias"] == "b"


def test_compare_imports_multi_bucket_different_payloads_emits_modified() -> None:
    """Cover line 248 via compare_imports: different multi-bucket payloads."""
    # Arrange: same module key, differing aliases -> triggers multi-bucket MODIFIED
    old_imports = [Import(module="pe", alias="x"), Import(module="pe", alias="y")]
    new_imports = [Import(module="pe", alias="x"), Import(module="pe", alias="z")]

    # Act
    result = _result()
    compare_imports(old_imports, new_imports, result, DiffNode, DiffType)

    # Assert
    assert len(result.differences) == 1
    diff = result.differences[0]
    assert diff.path == "/imports/pe"
    assert diff.diff_type == DiffType.MODIFIED
    assert isinstance(diff.old_value, list)
    assert isinstance(diff.new_value, list)


# ---------------------------------------------------------------------------
# _include_bucket_value — multi-include path (line 258)
# ---------------------------------------------------------------------------


def test_include_bucket_value_returns_repeated_path_list_for_multiple_includes() -> None:
    """Cover line 258: len(includes) != 1 returns [path] * len(includes)."""
    # Arrange: two Include nodes sharing the same path
    path = "common.yar"
    includes = [Include(path=path), Include(path=path)]

    # Act
    value = _include_bucket_value(path, includes)

    # Assert
    assert value == ["common.yar", "common.yar"]


def test_compare_includes_multi_bucket_added_emits_list_as_new_value() -> None:
    """Cover line 258 via compare_includes: duplicated path in new side."""
    # Arrange
    new_includes = [Include(path="dup.yar"), Include(path="dup.yar")]

    # Act
    result = _result()
    compare_includes([], new_includes, result, DiffNode, DiffType)

    # Assert
    assert len(result.differences) == 1
    diff = result.differences[0]
    assert diff.diff_type == DiffType.ADDED
    assert diff.new_value == ["dup.yar", "dup.yar"]


# ---------------------------------------------------------------------------
# _extern_import_key — fallback to `module` attribute (line 268)
# ---------------------------------------------------------------------------


class _NodeWithModuleOnly:
    """Minimal node with a `module` attribute but no `module_path`."""

    def __init__(self, module: str) -> None:
        self.module = module


def test_extern_import_key_falls_back_to_module_when_no_module_path() -> None:
    """Cover line 268: node lacks `module_path`, so `module` is used instead."""
    # Arrange
    node = _NodeWithModuleOnly("cuckoo")

    # Act
    key = _extern_import_key(node)

    # Assert
    assert key == "cuckoo"


# ---------------------------------------------------------------------------
# _string_attr_or_empty — TypeError for non-string attribute (lines 298-299)
# ---------------------------------------------------------------------------


class _NodeWithIntAttr:
    """Node whose tracked attribute holds a non-string value."""

    def __init__(self, attr: str, value: object) -> None:
        setattr(self, attr, value)


def test_string_attr_or_empty_raises_type_error_for_non_string_value() -> None:
    """Cover lines 298-299: attribute exists but is not a str -> TypeError."""
    # Arrange
    node = _NodeWithIntAttr("module", 42)

    # Act / Assert
    with pytest.raises(TypeError, match="Import module must be a string"):
        _string_attr_or_empty(node, "module", "Import module")


# ---------------------------------------------------------------------------
# _optional_string_attr — TypeError for non-string attribute (lines 307-310)
# ---------------------------------------------------------------------------


def test_optional_string_attr_raises_type_error_for_non_string_value() -> None:
    """Cover line 307: attribute is present but is not a str -> TypeError."""
    # Arrange
    node = _NodeWithIntAttr("namespace", 99)

    # Act / Assert
    with pytest.raises(TypeError, match="ExternRule namespace must be a string"):
        _optional_string_attr(node, "namespace", "ExternRule namespace")


def test_optional_string_attr_returns_string_value_when_present() -> None:
    """Cover line 310: attribute exists and is a valid str -> returned as-is."""
    # Arrange: node with a string namespace attribute
    node = _NodeWithIntAttr("namespace", "corp")

    # Act
    value = _optional_string_attr(node, "namespace", "ExternRule namespace")

    # Assert
    assert value == "corp"


# ---------------------------------------------------------------------------
# _pragma_type_value — None path (line 316) and TypeError (lines 319-320)
# ---------------------------------------------------------------------------


class _NodeNoPragmaType:
    """Node without a pragma_type attribute."""


def test_pragma_type_value_returns_empty_string_when_pragma_type_is_none() -> None:
    """Cover line 316: no `pragma_type` attribute -> getattr returns None -> ''."""
    # Arrange
    node = _NodeNoPragmaType()

    # Act
    value = _pragma_type_value(node)

    # Assert
    assert value == ""


class _BadPragmaTypeValue:
    """Simulates a pragma_type whose .value is not a string."""

    value: object = 123


class _NodeWithBadPragmaType:
    pragma_type = _BadPragmaTypeValue()


def test_pragma_type_value_raises_type_error_for_non_string_value() -> None:
    """Cover lines 319-320: pragma_type.value is not a str -> TypeError."""
    # Arrange
    node = _NodeWithBadPragmaType()

    # Act / Assert
    with pytest.raises(TypeError, match="Pragma type value must be a string"):
        _pragma_type_value(node)


# ---------------------------------------------------------------------------
# _rule_bucket_value — multi-rule hashes path (line 432)
# ---------------------------------------------------------------------------


def test_rule_bucket_value_returns_sorted_hash_list_for_multiple_rules() -> None:
    """Cover line 432: len(rules) != 1 returns sorted hash list."""
    # Arrange
    hasher = AstHasher()
    rules = [
        Rule("foo", condition=BooleanLiteral(True)),
        Rule("foo", condition=BooleanLiteral(False)),
    ]

    # Act
    value = _rule_bucket_value("foo", rules, hasher)

    # Assert: list of hashes, not a plain name string
    assert isinstance(value, list)
    assert len(value) == 2
    assert all(isinstance(h, str) for h in value)


# ---------------------------------------------------------------------------
# _rule_added_details — multi-rule path (line 438)
# ---------------------------------------------------------------------------


def test_rule_added_details_returns_list_for_multiple_rules() -> None:
    """Cover line 438: len(rules) != 1 -> new_rule_summaries key."""
    # Arrange
    rules = [
        Rule("foo", condition=BooleanLiteral(True)),
        Rule("foo", condition=BooleanLiteral(False)),
    ]

    # Act
    details = _rule_added_details(rules)

    # Assert
    assert "new_rule_summaries" in details
    assert len(details["new_rule_summaries"]) == 2


def test_compare_rules_multi_bucket_added_emits_list_details() -> None:
    """Cover line 438 through compare_rules: duplicate added rules."""
    # Arrange
    hasher = AstHasher()
    new_rules = [
        Rule("dup", condition=BooleanLiteral(True)),
        Rule("dup", condition=BooleanLiteral(False)),
    ]

    # Act
    result = _result()
    compare_rules([], new_rules, result, hasher, DiffNode, DiffType)

    # Assert
    assert len(result.differences) == 1
    diff = result.differences[0]
    assert diff.diff_type == DiffType.ADDED
    assert "new_rule_summaries" in diff.details


# ---------------------------------------------------------------------------
# _rule_removed_details — multi-rule path (line 444)
# ---------------------------------------------------------------------------


def test_rule_removed_details_returns_list_for_multiple_rules() -> None:
    """Cover line 444: len(rules) != 1 -> old_rule_summaries key."""
    # Arrange
    rules = [
        Rule("foo", condition=BooleanLiteral(True)),
        Rule("foo", condition=BooleanLiteral(False)),
    ]

    # Act
    details = _rule_removed_details(rules)

    # Assert
    assert "old_rule_summaries" in details
    assert len(details["old_rule_summaries"]) == 2


def test_compare_rules_multi_bucket_removed_emits_list_details() -> None:
    """Cover line 444 through compare_rules: duplicate removed rules."""
    # Arrange
    hasher = AstHasher()
    old_rules = [
        Rule("dup", condition=BooleanLiteral(True)),
        Rule("dup", condition=BooleanLiteral(False)),
    ]

    # Act
    result = _result()
    compare_rules(old_rules, [], result, hasher, DiffNode, DiffType)

    # Assert
    assert len(result.differences) == 1
    diff = result.differences[0]
    assert diff.diff_type == DiffType.REMOVED
    assert "old_rule_summaries" in diff.details


# ---------------------------------------------------------------------------
# _compare_duplicate_rule_bucket — identical hashes, early return (line 459)
# ---------------------------------------------------------------------------


def test_compare_rules_duplicate_bucket_no_diff_when_hashes_match() -> None:
    """Cover line 459: duplicate-name rules with same sorted hashes -> no diff."""
    # Arrange: two rules named 'dup', same content on both sides (order swapped)
    hasher = AstHasher()
    rules_a = [
        Rule("dup", condition=BooleanLiteral(True)),
        Rule("dup", condition=BooleanLiteral(False)),
    ]
    rules_b = [
        Rule("dup", condition=BooleanLiteral(False)),
        Rule("dup", condition=BooleanLiteral(True)),
    ]

    # Act
    result = _result()
    compare_rules(rules_a, rules_b, result, hasher, DiffNode, DiffType)

    # Assert: sorted hashes are identical -> early return, no entry appended
    assert result.differences == []


# ---------------------------------------------------------------------------
# compare_rule_strings — multi-bucket ADDED (line 692)
# ---------------------------------------------------------------------------


def test_compare_rule_strings_multi_bucket_added_emits_hash_list() -> None:
    """Cover line 692: duplicate identifier in new but not in old -> multi ADDED."""
    # Arrange: two PlainStrings sharing '$a' in the new side
    hasher = AstHasher()
    new_strings = [
        PlainString("$a", "value_one"),
        PlainString("$a", "value_two"),
    ]

    # Act
    result = _result()
    compare_rule_strings([], new_strings, "/rules/r/strings", result, hasher, DiffNode, DiffType)

    # Assert
    assert len(result.differences) == 1
    diff = result.differences[0]
    assert diff.path == "/rules/r/strings/$a"
    assert diff.diff_type == DiffType.ADDED
    assert isinstance(diff.new_value, list)
    assert len(diff.new_value) == 2


# ---------------------------------------------------------------------------
# compare_rule_strings — multi-bucket REMOVED (line 706)
# ---------------------------------------------------------------------------


def test_compare_rule_strings_multi_bucket_removed_emits_hash_list() -> None:
    """Cover line 706: duplicate identifier in old but not in new -> multi REMOVED."""
    # Arrange: two PlainStrings sharing '$b' in the old side
    hasher = AstHasher()
    old_strings = [
        PlainString("$b", "first"),
        PlainString("$b", "second"),
    ]

    # Act
    result = _result()
    compare_rule_strings(old_strings, [], "/rules/r/strings", result, hasher, DiffNode, DiffType)

    # Assert
    assert len(result.differences) == 1
    diff = result.differences[0]
    assert diff.path == "/rules/r/strings/$b"
    assert diff.diff_type == DiffType.REMOVED
    assert isinstance(diff.old_value, list)
    assert len(diff.old_value) == 2


# ---------------------------------------------------------------------------
# compare_rule_strings — multi-bucket shared, hashes equal (branch 734->715)
# ---------------------------------------------------------------------------


def test_compare_rule_strings_multi_bucket_shared_same_hashes_emits_no_diff() -> None:
    """Cover branch 734->715: duplicate identifier on both sides, identical content."""
    # Arrange: same two PlainStrings on both sides; reorder to confirm sort behaviour
    hasher = AstHasher()
    old_strings = [PlainString("$c", "alpha"), PlainString("$c", "beta")]
    # Same content, different list order -> sorted hashes are equal
    new_strings = [PlainString("$c", "beta"), PlainString("$c", "alpha")]

    # Act
    result = _result()
    compare_rule_strings(
        old_strings, new_strings, "/rules/r/strings", result, hasher, DiffNode, DiffType
    )

    # Assert: no change recorded
    assert result.differences == []
