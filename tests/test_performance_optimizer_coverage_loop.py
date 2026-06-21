# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests covering the remaining uncovered lines in performance/optimizer.py.

Missing lines before this file:
    33-47  : _require_file_path — all error branches and the success path
    51-56  : _read_yara_text_file — UTF-8 success and UnicodeDecodeError path
    72->exit, 79->exit, 86->exit : @overload stubs (callable via typing.get_overloads)
    193    : _string_check_cost fallback return 300 for unknown StringDefinition subclass
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import tempfile
from typing import Any, cast, get_overloads

import pytest

from yaraast.ast.strings import StringDefinition
from yaraast.parser import Parser
from yaraast.performance.optimizer import (
    PerformanceOptimizer,
    _read_yara_text_file,
    _require_file_path,
)

# ---------------------------------------------------------------------------
# Helper: a concrete StringDefinition subclass that is not PlainString,
# HexString, or RegexString — needed to reach line 193 in _string_check_cost.
# ---------------------------------------------------------------------------


@dataclass
class _UnknownStringKind(StringDefinition):
    """Minimal concrete StringDefinition not recognised by _string_check_cost."""


# ---------------------------------------------------------------------------
# _require_file_path — lines 33-47
# ---------------------------------------------------------------------------


class TestRequireFilePath:
    """Real execution of _require_file_path across every branch."""

    def test_bool_true_raises_type_error(self) -> None:
        # Line 33: isinstance(value, bool) is True — must raise TypeError
        with pytest.raises(TypeError, match="must be a file path"):
            _require_file_path(True, "arg")

    def test_bool_false_raises_type_error(self) -> None:
        # Line 33: bool is a subclass of int, so a bool must be rejected before
        # the general str|PathLike check would accidentally accept it.
        with pytest.raises(TypeError, match="must be a file path"):
            _require_file_path(False, "arg")

    def test_integer_raises_type_error(self) -> None:
        # Line 33: not isinstance(value, str | PathLike) branch
        with pytest.raises(TypeError, match="must be a file path"):
            _require_file_path(42, "arg")

    def test_none_raises_type_error(self) -> None:
        # Line 33: None is not str | PathLike
        with pytest.raises(TypeError, match="must be a file path"):
            _require_file_path(None, "arg")

    def test_path_like_returning_bytes_raises_type_error(self) -> None:
        # Lines 38-39: os.fspath() returns bytes (not str) when __fspath__ returns bytes.
        # The guard at line 37 catches this case and raises TypeError.
        class BytesPath:
            def __fspath__(self) -> bytes:
                return b"/tmp/yaraast_bytes_test.yar"

        with pytest.raises(TypeError, match="must be a file path"):
            _require_file_path(BytesPath(), "arg")

    def test_whitespace_only_string_raises_value_error(self) -> None:
        # Line 40-42: raw_path.strip() is empty
        with pytest.raises(ValueError, match="must not be empty"):
            _require_file_path("   ", "arg")

    def test_empty_string_raises_value_error(self) -> None:
        # Line 40-42: empty string
        with pytest.raises(ValueError, match="must not be empty"):
            _require_file_path("", "arg")

    def test_directory_path_raises_value_error(self) -> None:
        # Lines 44-46: path_exists_and_is_dir returns True
        with (
            tempfile.TemporaryDirectory() as directory,
            pytest.raises(ValueError, match="must not be a directory"),
        ):
            _require_file_path(directory, "arg")

    def test_directory_path_as_path_object_raises_value_error(self) -> None:
        # Lines 44-46: PathLike input pointing at a real directory
        with (
            tempfile.TemporaryDirectory() as directory,
            pytest.raises(ValueError, match="must not be a directory"),
        ):
            _require_file_path(Path(directory), "arg")

    def test_nonexistent_file_path_returns_path(self) -> None:
        # Line 47: happy path — a non-existent file is acceptable
        result = _require_file_path("/tmp/yaraast_nonexistent_test.yar", "arg")
        assert isinstance(result, Path)
        assert result == Path("/tmp/yaraast_nonexistent_test.yar")

    def test_existing_file_path_returns_path(self) -> None:
        # Line 47: happy path — an existing regular file is acceptable
        with tempfile.NamedTemporaryFile(suffix=".yar", delete=False) as handle:
            fpath = handle.name
        try:
            result = _require_file_path(fpath, "arg")
            assert isinstance(result, Path)
            assert result == Path(fpath)
        finally:
            os.unlink(fpath)

    def test_path_object_for_existing_file_returns_path(self) -> None:
        # Line 47: PathLike input for a regular file
        with tempfile.NamedTemporaryFile(suffix=".yar", delete=False) as handle:
            fpath = handle.name
        try:
            result = _require_file_path(Path(fpath), "arg")
            assert isinstance(result, Path)
        finally:
            os.unlink(fpath)

    def test_param_name_appears_in_error_message(self) -> None:
        # The error messages embed the caller-supplied name
        with pytest.raises(TypeError, match="my_param"):
            _require_file_path(99, "my_param")
        with pytest.raises(ValueError, match="my_param"):
            _require_file_path("", "my_param")


# ---------------------------------------------------------------------------
# _read_yara_text_file — lines 51-56
# ---------------------------------------------------------------------------


class TestReadYaraTextFile:
    """Real filesystem I/O through _read_yara_text_file."""

    def test_valid_utf8_file_returns_content(self) -> None:
        # Lines 51-53: success path — file opens and reads fine
        content = "rule sample { condition: true }\n"
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".yar", delete=False) as handle:
            handle.write(content.encode("utf-8"))
            fpath = handle.name
        try:
            result = _read_yara_text_file(Path(fpath))
            assert result == content
        finally:
            os.unlink(fpath)

    def test_non_utf8_bytes_raises_value_error(self) -> None:
        # Lines 54-56: UnicodeDecodeError caught and re-raised as ValueError
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".yar", delete=False) as handle:
            # Write bytes that are invalid UTF-8
            handle.write(b"\xff\xfe\x80\x81 not valid utf-8")
            fpath = handle.name
        try:
            with pytest.raises(ValueError, match="valid UTF-8"):
                _read_yara_text_file(Path(fpath))
        finally:
            os.unlink(fpath)

    def test_multiline_utf8_content_preserved(self) -> None:
        # Lines 51-53: multi-line content read verbatim
        content = "rule a { condition: true }\nrule b { condition: false }\n"
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".yar", delete=False) as handle:
            handle.write(content.encode("utf-8"))
            fpath = handle.name
        try:
            result = _read_yara_text_file(Path(fpath))
            assert result == content
        finally:
            os.unlink(fpath)


# ---------------------------------------------------------------------------
# @overload stubs — branches 72->exit, 79->exit, 86->exit
#
# The @overload decorators register the typed stubs via typing.overload.
# At runtime, typing.get_overloads() returns those stub functions.
# Calling them executes their '...' body (an Ellipsis expression that Python
# evaluates and discards), then falls through to an implicit 'return None'.
# This is the only way to execute the stub bodies and cover the exit branches.
# ---------------------------------------------------------------------------


class TestOverloadStubs:
    """Exercise the three @overload stubs on PerformanceOptimizer.optimize."""

    def test_overload_stubs_are_callable_and_return_none(self) -> None:
        stubs = get_overloads(PerformanceOptimizer.optimize)
        # The module defines exactly three @overload signatures
        assert len(stubs) == 3

        optimizer = PerformanceOptimizer()
        parser = Parser()
        ast = parser.parse("rule t { condition: true }")
        rule = ast.rules[0]

        # Each stub is callable on a real optimizer instance; each returns None
        # because the body is '...' (Ellipsis) with no explicit return.
        for stub in stubs:
            result = stub(optimizer, rule)
            assert result is None

    def test_overload_stubs_source_lines_match_module(self) -> None:
        # Confirm the stubs originate from the three expected line numbers
        stubs = get_overloads(PerformanceOptimizer.optimize)
        first_lines = [stub.__code__.co_firstlineno for stub in stubs]
        # Lines 71, 78, 85 are the 'def optimize' lines of the three @overload blocks
        assert first_lines == [71, 78, 85]


# ---------------------------------------------------------------------------
# _string_check_cost fallback — line 193
# ---------------------------------------------------------------------------


class TestStringCheckCostFallback:
    """Verify _string_check_cost returns 300 for unrecognised StringDefinition types."""

    def test_unknown_string_definition_subclass_costs_300(self) -> None:
        # Line 193: the else-fallback after PlainString, HexString, RegexString checks
        unknown = _UnknownStringKind(identifier="$u")
        cost = PerformanceOptimizer._string_check_cost(unknown)
        assert cost == 300

    def test_sort_order_with_mixed_known_and_unknown_strings(self) -> None:
        # Trigger the fallback in context of a real optimize_rule call
        # so that the sort key includes the 300-cost unknown string.
        from yaraast.ast.rules import Rule
        from yaraast.ast.strings import PlainString

        rule = Rule(
            name="mixed",
            strings=[
                _UnknownStringKind(identifier="$u"),  # cost=300 (fallback)
                PlainString(identifier="$short", value="ab"),  # cost=2 (len of "ab")
            ],
        )
        optimizer = PerformanceOptimizer()
        optimized = optimizer.optimize_rule(rule, strategy="speed")
        # The cheap PlainString should sort before the unknown-kind string
        assert optimized.strings[0].identifier == "$short"
        assert optimized.strings[1].identifier == "$u"

    def test_plain_string_with_none_value_costs_300(self) -> None:
        # Within PlainString branch: value is not str|bytes → returns 300
        # (tests the 'else 300' on line 188, but also exercises the fallthrough
        #  into the main fallback at 193 indirectly via cost comparison)
        from yaraast.ast.strings import PlainString

        ps = PlainString(identifier="$x", value=cast(Any, None))
        cost = PerformanceOptimizer._string_check_cost(ps)
        assert cost == 300


# ---------------------------------------------------------------------------
# Integration: confirm that _optimize_for_speed with no strings is a no-op
# (branch 161: rule.strings is falsy — already partially covered, verified
#  here with a rule built from real parser output).
# ---------------------------------------------------------------------------


class TestOptimizeForSpeedNoStrings:
    """Ensure rules without strings pass through _optimize_for_speed unchanged."""

    def test_rule_without_strings_is_unchanged(self) -> None:
        parser = Parser()
        ast = parser.parse("rule bare { condition: true }")
        rule = ast.rules[0]
        assert not rule.strings

        optimizer = PerformanceOptimizer()
        result = optimizer._optimize_for_speed(rule)

        assert result is rule
        assert not result.strings
        assert optimizer.get_statistics()["strings_optimized"] == 0
