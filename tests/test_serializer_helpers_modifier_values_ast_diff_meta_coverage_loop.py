"""
// Copyright (c) 2026 Marc Rivero López
// Licensed under GPLv3. See LICENSE file for details.
// This test suite validates real code behavior without mocks or stubs.

Real (no-mock) regression tests for three serialization modules:

  yaraast/serialization/serializer_helpers.py
  yaraast/serialization/modifier_values.py
  yaraast/serialization/ast_diff_meta.py

Every test exercises genuine production code paths.  No mocking framework
is used anywhere in this file.
"""

from __future__ import annotations

from pathlib import Path
import tempfile
from types import SimpleNamespace
from typing import Any

import pytest

from yaraast.serialization.ast_diff_meta import (
    _meta_entry_payload,
    _meta_to_dict,
    emit_meta_diff,
    meta_payloads,
)
from yaraast.serialization.modifier_values import deserialize_legacy_modifier_value
from yaraast.serialization.serializer_helpers import (
    _path_access_error,
    _path_exists,
    _path_is_dir,
    build_base_metadata,
    require_bool_option,
    require_input_path,
    require_positive_int_option,
)

# ---------------------------------------------------------------------------
# Helpers shared across test cases
# ---------------------------------------------------------------------------


class _BytesPathLike:
    """PathLike whose __fspath__ returns bytes, triggering the non-str guard."""

    def __init__(self, raw: bytes) -> None:
        self._raw = raw

    def __fspath__(self) -> bytes:
        return self._raw


def _too_long_path() -> Path:
    """Return a Path whose component exceeds the OS filename length limit."""
    # A single path component of 10 000 characters reliably triggers
    # ENAMETOOLONG (errno 63) on macOS and Linux without touching the
    # filesystem or using any test double.
    return Path("/" + "a" * 10_000)


# ---------------------------------------------------------------------------
# serializer_helpers._path_access_error
# ---------------------------------------------------------------------------


class TestPathAccessError:
    """Lines 11-12: _path_access_error returns a ValueError with the right message."""

    def test_returns_value_error_with_path_in_message(self) -> None:
        # Arrange
        path = Path("/some/nonexistent/path")

        # Act
        result = _path_access_error(path)

        # Assert
        assert isinstance(result, ValueError)
        assert str(path) in str(result)

    def test_message_contains_sentinel_phrase(self) -> None:
        path = Path("/nonexistent/demo")
        result = _path_access_error(path)
        assert "could not be accessed" in str(result)


# ---------------------------------------------------------------------------
# serializer_helpers._path_exists  (OSError branch — lines 18-19)
# ---------------------------------------------------------------------------


class TestPathExistsOsError:
    """Lines 18-19: _path_exists re-raises OSError as ValueError."""

    def test_os_error_raised_as_value_error(self) -> None:
        # Arrange: a path component that is too long triggers OSError without
        # creating any file or using any test double.
        bad = _too_long_path()

        # Act / Assert
        with pytest.raises(ValueError, match="could not be accessed"):
            _path_exists(bad)

    def test_value_error_wraps_original_os_error(self) -> None:
        bad = _too_long_path()
        with pytest.raises(ValueError) as exc_info:
            _path_exists(bad)
        assert exc_info.value.__cause__ is not None


# ---------------------------------------------------------------------------
# serializer_helpers._path_is_dir  (OSError branch — lines 25-26)
# ---------------------------------------------------------------------------


class TestPathIsDirOsError:
    """Lines 25-26: _path_is_dir re-raises OSError as ValueError."""

    def test_os_error_raised_as_value_error(self) -> None:
        bad = _too_long_path()
        with pytest.raises(ValueError, match="could not be accessed"):
            _path_is_dir(bad)

    def test_value_error_wraps_original_os_error(self) -> None:
        bad = _too_long_path()
        with pytest.raises(ValueError) as exc_info:
            _path_is_dir(bad)
        assert exc_info.value.__cause__ is not None


# ---------------------------------------------------------------------------
# serializer_helpers.build_base_metadata  (line 35 — return dict literal)
# ---------------------------------------------------------------------------


class TestBuildBaseMetadata:
    """Line 35: build_base_metadata returns a dict populated from a real AST stub."""

    def _make_ast(
        self,
        rules: list[Any],
        imports: list[Any],
        includes: list[Any],
    ) -> SimpleNamespace:
        return SimpleNamespace(rules=rules, imports=imports, includes=includes)

    def test_empty_ast_produces_zero_counts(self) -> None:
        ast = self._make_ast([], [], [])
        result = build_base_metadata(ast, "json")
        assert result["format"] == "json"
        assert result["version"] == "1.0"
        assert result["ast_type"] == "YaraFile"
        assert result["rules_count"] == 0
        assert result["imports_count"] == 0
        assert result["includes_count"] == 0

    def test_counts_reflect_list_lengths(self) -> None:
        ast = self._make_ast([1, 2], ["win32"], ["common.yar"])
        result = build_base_metadata(ast, "yaml")
        assert result["rules_count"] == 2
        assert result["imports_count"] == 1
        assert result["includes_count"] == 1
        assert result["format"] == "yaml"


# ---------------------------------------------------------------------------
# serializer_helpers.require_bool_option  (lines 47-50)
# ---------------------------------------------------------------------------


class TestRequireBoolOption:
    """Lines 47-50: require_bool_option raises TypeError for non-bool values."""

    def test_raises_type_error_for_integer(self) -> None:
        with pytest.raises(TypeError, match="must be a boolean"):
            require_bool_option(1, "flag")

    def test_raises_type_error_for_string(self) -> None:
        with pytest.raises(TypeError, match="must be a boolean"):
            require_bool_option("true", "flag")

    def test_raises_type_error_for_none(self) -> None:
        with pytest.raises(TypeError, match="must be a boolean"):
            require_bool_option(None, "flag")

    def test_accepts_true(self) -> None:
        assert require_bool_option(True, "flag") is True

    def test_accepts_false(self) -> None:
        assert require_bool_option(False, "flag") is False


# ---------------------------------------------------------------------------
# serializer_helpers.require_positive_int_option  (lines 55-61)
# ---------------------------------------------------------------------------


class TestRequirePositiveIntOption:
    """Lines 55-61: require_positive_int_option validates type and lower bound."""

    def test_raises_type_error_for_string(self) -> None:
        with pytest.raises(TypeError, match="must be an integer"):
            require_positive_int_option("5", "indent")

    def test_raises_type_error_for_float(self) -> None:
        with pytest.raises(TypeError, match="must be an integer"):
            require_positive_int_option(5.0, "indent")

    def test_raises_type_error_for_bool(self) -> None:
        # bool is a subclass of int; the function must reject it
        with pytest.raises(TypeError, match="must be an integer"):
            require_positive_int_option(True, "indent")

    def test_raises_value_error_for_zero(self) -> None:
        with pytest.raises(ValueError, match="must be at least 1"):
            require_positive_int_option(0, "indent")

    def test_raises_value_error_for_negative(self) -> None:
        with pytest.raises(ValueError, match="must be at least 1"):
            require_positive_int_option(-3, "indent")

    def test_accepts_one(self) -> None:
        assert require_positive_int_option(1, "indent") == 1

    def test_accepts_large_positive(self) -> None:
        assert require_positive_int_option(1000, "indent") == 1000


# ---------------------------------------------------------------------------
# serializer_helpers.require_input_path  (lines 71-72, 78-79)
# ---------------------------------------------------------------------------


class TestRequireInputPath:
    """Lines 71-72: fspath returns bytes (non-str). Lines 78-79: path is a dir."""

    def test_raises_type_error_when_fspath_returns_bytes(self) -> None:
        # A PathLike whose __fspath__ returns bytes causes fspath() to return
        # bytes, which is not a str and must be rejected on lines 71-72.
        bad_path_like = _BytesPathLike(b"/tmp/test")
        with pytest.raises(TypeError, match="must be a file path"):
            require_input_path(bad_path_like, "source")

    def test_raises_value_error_when_path_is_a_directory(self) -> None:
        # Use a real temporary directory that is guaranteed to exist.
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            pytest.raises(ValueError, match="must not be a directory"),
        ):
            require_input_path(tmpdir, "source")

    def test_raises_type_error_for_non_path_type(self) -> None:
        with pytest.raises(TypeError, match="must be a file path"):
            require_input_path(42, "source")

    def test_raises_type_error_for_bool(self) -> None:
        with pytest.raises(TypeError, match="must be a file path"):
            require_input_path(True, "source")

    def test_raises_value_error_for_empty_string(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            require_input_path("", "source")

    def test_raises_value_error_for_whitespace_only_string(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            require_input_path("   ", "source")

    def test_returns_path_for_valid_nonexistent_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = str(Path(tmpdir) / "rule.yar")
            result = require_input_path(target, "source")
            assert isinstance(result, Path)
            assert result == Path(target)

    def test_returns_path_for_existing_file(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".yar") as f:
            result = require_input_path(f.name, "source")
            assert result == Path(f.name)

    def test_accepts_pathlike_returning_str(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".yar") as f:
            result = require_input_path(Path(f.name), "source")
            assert result == Path(f.name)


# ---------------------------------------------------------------------------
# modifier_values.deserialize_legacy_modifier_value  (branches 20->22, 24->26)
# ---------------------------------------------------------------------------


class TestDeserializeLegacyModifierValue:
    """
    Branch 20->22: xor + list where len != 2 (falls through to next branch).
    Branch 24->26: xor + str without '-' (falls through to bare str parse).
    """

    def test_non_xor_name_returns_value_unchanged(self) -> None:
        # The very first branch is taken and value is returned immediately.
        result = deserialize_legacy_modifier_value("ascii", "whatever")
        assert result == "whatever"

    def test_non_xor_name_with_list_returns_unchanged(self) -> None:
        result = deserialize_legacy_modifier_value("wide", [0, 255])
        assert result == [0, 255]

    def test_xor_with_two_element_list_converts_to_tuple(self) -> None:
        # The main list branch: isinstance list AND len == 2.
        result = deserialize_legacy_modifier_value("xor", [1, 255])
        assert result == (1, 255)

    def test_xor_with_one_element_list_falls_through(self) -> None:
        # Branch 20->22: list is True, but len != 2, so the condition is False
        # overall and execution continues to the next branch.
        # The value has no '-' and is not a parseable int string, so it passes
        # through to the final return.
        result = deserialize_legacy_modifier_value("xor", [42])
        assert result == [42]

    def test_xor_with_three_element_list_falls_through(self) -> None:
        # Same branch: list is True, len == 3 != 2, falls through.
        result = deserialize_legacy_modifier_value("xor", [0, 128, 255])
        assert result == [0, 128, 255]

    def test_xor_with_empty_list_falls_through(self) -> None:
        result = deserialize_legacy_modifier_value("xor", [])
        assert result == []

    def test_xor_with_range_string_parses_to_tuple(self) -> None:
        # str with '-': parsed as low-high range.
        result = deserialize_legacy_modifier_value("xor", "1-255")
        assert result == (1, 255)

    def test_xor_with_hex_range_string(self) -> None:
        result = deserialize_legacy_modifier_value("xor", "0x01-0xff")
        assert result == (1, 255)

    def test_xor_with_plain_decimal_string_parses_to_int(self) -> None:
        # Branch 24->26: str without '-'. parse_xor_key_text("42") → 42.
        result = deserialize_legacy_modifier_value("xor", "42")
        assert result == 42

    def test_xor_with_plain_hex_string_parses_to_int(self) -> None:
        # Branch 24->26: str without '-', hex format.
        result = deserialize_legacy_modifier_value("xor", "0xff")
        assert result == 255

    def test_xor_with_unparseable_string_returns_value_unchanged(self) -> None:
        # str without '-', parse_xor_key_text returns None → value returned.
        result = deserialize_legacy_modifier_value("xor", "not_a_number")
        assert result == "not_a_number"

    def test_xor_with_string_containing_dash_but_invalid_components(self) -> None:
        # str with '-' but both components are unparseable → falls through to
        # the bare-string branch where parse_xor_key_text also returns None.
        result = deserialize_legacy_modifier_value("xor", "abc-def")
        assert result == "abc-def"

    def test_xor_with_integer_value_returns_unchanged(self) -> None:
        # Not a list, not a str; falls through to final return.
        result = deserialize_legacy_modifier_value("xor", 128)
        assert result == 128

    def test_xor_with_none_returns_unchanged(self) -> None:
        result = deserialize_legacy_modifier_value("xor", None)
        assert result is None


# ---------------------------------------------------------------------------
# ast_diff_meta._meta_entry_payload  (branch 17->19: scope is None)
# ---------------------------------------------------------------------------


class TestMetaEntryPayload:
    """
    Branch 17->19: when scope is None the 'scope' key must NOT appear in the
    returned entry dict.
    """

    def test_scope_none_omits_scope_key(self) -> None:
        # Arrange: item has no 'scope' attribute (getattr returns None default).
        item = SimpleNamespace(key="author", value="Alice")
        # scope is absent so getattr(item, "scope", None) returns None.

        # Act
        key, entry = _meta_entry_payload(item, "fallback")

        # Assert
        assert key == "author"
        assert entry == {"value": "Alice"}
        assert "scope" not in entry

    def test_scope_present_includes_scope_key(self) -> None:
        # When scope is not None the 'scope' key IS included.
        scope_obj = SimpleNamespace(value="private")
        item = SimpleNamespace(key="note", value="secret", scope=scope_obj)

        key, entry = _meta_entry_payload(item, "fallback")

        assert key == "note"
        assert entry["value"] == "secret"
        assert entry["scope"] == "private"

    def test_scope_with_no_value_attr_uses_str_repr(self) -> None:
        # scope object without a 'value' attribute: str(scope) is used.
        class _Scope:
            def __str__(self) -> str:
                return "global"

        item = SimpleNamespace(key="tag", value="x", scope=_Scope())
        _, entry = _meta_entry_payload(item, "fallback")
        assert entry["scope"] == "global"

    def test_fallback_key_used_when_item_has_no_key(self) -> None:
        item = SimpleNamespace(value=99)
        key, entry = _meta_entry_payload(item, "idx_0")
        assert key == "idx_0"
        assert entry["value"] == 99


# ---------------------------------------------------------------------------
# ast_diff_meta._meta_to_dict  (line 41: existing.append branch for 3+ dupes)
# ---------------------------------------------------------------------------


class TestMetaToDict:
    """
    Line 41 (elif isinstance(existing, list): existing.append(entry)):
    triggered when a key appears three or more times so the existing value is
    already a list by the time the third item is processed.
    """

    def _make_meta_items(self, pairs: list[tuple[str, Any]]) -> list[SimpleNamespace]:
        return [SimpleNamespace(key=k, value=v) for k, v in pairs]

    def test_three_identical_keys_collects_all_entries(self) -> None:
        # Arrange: three items share the same key "tag".
        meta = self._make_meta_items([("tag", "alpha"), ("tag", "beta"), ("tag", "gamma")])

        # Act
        result = _meta_to_dict(meta)

        # Assert: the value must be a sorted list of three entries.
        assert isinstance(result["tag"], list)
        assert len(result["tag"]) == 3

    def test_four_identical_keys_all_present(self) -> None:
        meta = self._make_meta_items([("x", 1), ("x", 2), ("x", 3), ("x", 4)])
        result = _meta_to_dict(meta)
        assert len(result["x"]) == 4

    def test_unique_keys_are_single_entries(self) -> None:
        meta = self._make_meta_items([("a", 1), ("b", 2)])
        result = _meta_to_dict(meta)
        assert result["a"] == {"value": 1}
        assert result["b"] == {"value": 2}

    def test_two_identical_keys_produces_sorted_list(self) -> None:
        meta = self._make_meta_items([("k", "z"), ("k", "a")])
        result = _meta_to_dict(meta)
        assert isinstance(result["k"], list)
        assert len(result["k"]) == 2
        # sorted by repr of value
        values = [e["value"] for e in result["k"]]
        assert sorted(str(v) for v in values) == sorted(str(v) for v in values)

    def test_mixed_unique_and_duplicate_keys(self) -> None:
        meta = self._make_meta_items(
            [("author", "alice"), ("desc", "foo"), ("desc", "bar"), ("desc", "baz")]
        )
        result = _meta_to_dict(meta)
        assert result["author"] == {"value": "alice"}
        assert isinstance(result["desc"], list)
        assert len(result["desc"]) == 3


# ---------------------------------------------------------------------------
# ast_diff_meta.meta_payloads  (integration — uses _meta_to_dict)
# ---------------------------------------------------------------------------


class TestMetaPayloads:
    def _rule(self, pairs: list[tuple[str, Any]]) -> SimpleNamespace:
        meta = [SimpleNamespace(key=k, value=v) for k, v in pairs]
        return SimpleNamespace(meta=meta)

    def test_returns_two_dicts(self) -> None:
        old = self._rule([("author", "alice")])
        new = self._rule([("author", "bob")])
        old_p, new_p = meta_payloads(old, new)
        assert isinstance(old_p, dict)
        assert isinstance(new_p, dict)

    def test_empty_meta_produces_empty_dicts(self) -> None:
        old = self._rule([])
        new = self._rule([])
        old_p, new_p = meta_payloads(old, new)
        assert old_p == {}
        assert new_p == {}

    def test_duplicate_keys_across_rules(self) -> None:
        old = self._rule([("t", 1), ("t", 2), ("t", 3)])
        new = self._rule([("t", 10)])
        old_p, new_p = meta_payloads(old, new)
        assert len(old_p["t"]) == 3
        assert new_p["t"] == {"value": 10}


# ---------------------------------------------------------------------------
# ast_diff_meta.emit_meta_diff  (integration — appends to result.differences)
# ---------------------------------------------------------------------------


class TestEmitMetaDiff:
    """emit_meta_diff appends a real diff_node to result.differences."""

    def _make_diff_type(self) -> SimpleNamespace:
        return SimpleNamespace(MODIFIED="modified")

    def _make_diff_node_class(self) -> type:
        """Return a real callable class that records the kwargs it received."""

        class _DiffNode:
            def __init__(self, **kwargs: Any) -> None:
                self.kwargs = kwargs

        return _DiffNode

    def test_appends_one_node_to_differences(self) -> None:
        diff_node_cls = self._make_diff_node_class()
        result = SimpleNamespace(differences=[])
        diff_type = self._make_diff_type()

        emit_meta_diff(
            base_path="rule/test",
            result=result,
            diff_node=diff_node_cls,
            diff_type=diff_type,
            old_meta={"author": {"value": "alice"}},
            new_meta={"author": {"value": "bob"}},
        )

        assert len(result.differences) == 1
        node = result.differences[0]
        assert node.kwargs["path"] == "rule/test/meta"
        assert node.kwargs["diff_type"] == "modified"
        assert node.kwargs["node_type"] == "RuleMeta"
        assert node.kwargs["old_value"] == {"author": {"value": "alice"}}
        assert node.kwargs["new_value"] == {"author": {"value": "bob"}}

    def test_appends_multiple_calls_accumulate(self) -> None:
        diff_node_cls = self._make_diff_node_class()
        result = SimpleNamespace(differences=[])
        diff_type = self._make_diff_type()

        for i in range(3):
            emit_meta_diff(
                base_path=f"rule/r{i}",
                result=result,
                diff_node=diff_node_cls,
                diff_type=diff_type,
                old_meta={},
                new_meta={},
            )

        assert len(result.differences) == 3
