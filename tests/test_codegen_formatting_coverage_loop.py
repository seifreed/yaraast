# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests covering missing branches in yaraast/codegen/formatting.py.

Target gaps identified by --cov-report=term-missing (prior run at 90.91%):
  - Lines 13-14  : _coerce_enum except branch (TypeError / ValueError)
  - Line 20      : _coerce_bool non-bool value returns default
  - Line 25      : _coerce_int bool guard returns default
  - Lines 28-34  : _coerce_int string branch (success and ValueError), else branch
  - Line 37      : _coerce_int return result without minimum constraint
  - Branch 232->235 : comment_style present but not a str -- field unchanged
"""

from __future__ import annotations

from yaraast.codegen.formatting import (
    BraceStyle,
    FormattingConfig,
    HexStyle,
    IndentStyle,
    StringStyle,
    _coerce_bool,
    _coerce_enum,
    _coerce_int,
)

# ---------------------------------------------------------------------------
# _coerce_enum -- lines 13-14
# ---------------------------------------------------------------------------


class TestCoerceEnum:
    """Direct tests for _coerce_enum covering the except branch."""

    def test_valid_value_returns_enum_member(self) -> None:
        """A recognised string value constructs the enum member."""
        result = _coerce_enum(IndentStyle, "spaces", IndentStyle.TABS)
        assert result is IndentStyle.SPACES

    def test_invalid_string_returns_default_via_value_error(self) -> None:
        """An unrecognised string triggers ValueError and the default is returned."""
        result = _coerce_enum(IndentStyle, "invalid_style", IndentStyle.TABS)
        assert result is IndentStyle.TABS

    def test_none_returns_default_via_type_error(self) -> None:
        """None is not a valid enum value; TypeError is caught and default returned."""
        result = _coerce_enum(BraceStyle, None, BraceStyle.SAME_LINE)
        assert result is BraceStyle.SAME_LINE

    def test_integer_returns_default_when_not_valid_enum_value(self) -> None:
        """An integer that does not map to any member returns the default."""
        result = _coerce_enum(StringStyle, 999, StringStyle.COMPACT)
        assert result is StringStyle.COMPACT

    def test_list_returns_default_via_type_error(self) -> None:
        """A list type raises TypeError inside the enum constructor."""
        result = _coerce_enum(HexStyle, [], HexStyle.UPPERCASE)
        assert result is HexStyle.UPPERCASE


# ---------------------------------------------------------------------------
# _coerce_bool -- line 20
# ---------------------------------------------------------------------------


class TestCoerceBool:
    """Direct tests for _coerce_bool covering the non-bool path."""

    def test_true_passthrough(self) -> None:
        """A bool True is returned as-is."""
        assert _coerce_bool(True, False) is True

    def test_false_passthrough(self) -> None:
        """A bool False is returned as-is."""
        assert _coerce_bool(False, True) is False

    def test_non_bool_string_returns_default(self) -> None:
        """A string value is not a bool; default is returned (line 20)."""
        assert _coerce_bool("true", False) is False

    def test_non_bool_int_returns_default(self) -> None:
        """Integer 1 is not a bool despite bool subclassing int at runtime.
        Python's isinstance(1, bool) is False for plain int literals, so
        the default is returned."""
        # Plain int 1 is not a bool instance
        value: object = 1
        assert not isinstance(value, bool)
        assert _coerce_bool(value, True) is True

    def test_non_bool_none_returns_default(self) -> None:
        """None is not a bool; default is returned."""
        assert _coerce_bool(None, True) is True

    def test_non_bool_list_returns_default(self) -> None:
        """A list is not a bool; default is returned."""
        assert _coerce_bool([True], False) is False


# ---------------------------------------------------------------------------
# _coerce_int -- lines 25, 28-34, 37
# ---------------------------------------------------------------------------


class TestCoerceInt:
    """Direct tests for _coerce_int covering all uncovered branches."""

    def test_bool_value_returns_default(self) -> None:
        """Bool is rejected even though bool is a subclass of int (line 25)."""
        assert _coerce_int(True, 10) == 10
        assert _coerce_int(False, 7) == 7

    def test_valid_int_without_minimum_returns_result(self) -> None:
        """An int without a minimum constraint uses the bare return path (line 37)."""
        assert _coerce_int(42, 0) == 42

    def test_valid_int_negative_without_minimum(self) -> None:
        """Negative int with no minimum constraint is returned as-is (line 37)."""
        assert _coerce_int(-5, 0) == -5

    def test_valid_int_with_minimum_clamps(self) -> None:
        """An int below the minimum is clamped to the minimum (line 36 branch)."""
        assert _coerce_int(-5, 0, minimum=0) == 0

    def test_valid_int_with_minimum_passes_through(self) -> None:
        """An int at or above the minimum is returned unchanged."""
        assert _coerce_int(10, 0, minimum=5) == 10

    def test_string_integer_is_parsed(self) -> None:
        """A string containing a valid integer is converted (lines 28-30)."""
        assert _coerce_int("8", 0) == 8

    def test_string_integer_with_minimum_clamps(self) -> None:
        """A string integer below the minimum is clamped."""
        assert _coerce_int("0", 4, minimum=1) == 1

    def test_string_non_integer_returns_default(self) -> None:
        """A string that cannot be parsed as int returns the default (lines 31-32)."""
        assert _coerce_int("notanumber", 99) == 99

    def test_string_empty_returns_default(self) -> None:
        """An empty string triggers ValueError in int(); default is returned."""
        assert _coerce_int("", 5) == 5

    def test_float_returns_default_via_else_branch(self) -> None:
        """A float is not int or str; the else branch (line 34) returns default."""
        assert _coerce_int(3.14, 0) == 0

    def test_none_returns_default_via_else_branch(self) -> None:
        """None is not int or str; the else branch (line 34) returns default."""
        assert _coerce_int(None, 7) == 7

    def test_list_returns_default_via_else_branch(self) -> None:
        """A list is not int or str; the else branch returns default."""
        assert _coerce_int([4], 3) == 3


# ---------------------------------------------------------------------------
# FormattingConfig.from_dict -- branch 232->235
# comment_style key present but value is not a str
# ---------------------------------------------------------------------------


class TestFromDictCommentStyleBranch:
    """Tests for the comment_style non-str branch in from_dict."""

    def test_comment_style_non_str_integer_leaves_default(self) -> None:
        """When comment_style is an integer, the field is not updated (branch 232->235)."""
        config = FormattingConfig.from_dict({"comment_style": 42})
        assert config.comment_style == "//"

    def test_comment_style_non_str_none_leaves_default(self) -> None:
        """When comment_style is None, the field is not updated."""
        config = FormattingConfig.from_dict({"comment_style": None})
        assert config.comment_style == "//"

    def test_comment_style_non_str_list_leaves_default(self) -> None:
        """When comment_style is a list, the field is not updated."""
        config = FormattingConfig.from_dict({"comment_style": ["//"]})
        assert config.comment_style == "//"

    def test_comment_style_str_updates_field(self) -> None:
        """When comment_style is a valid str, the field is updated (positive case)."""
        config = FormattingConfig.from_dict({"comment_style": "/*"})
        assert config.comment_style == "/*"

    def test_comment_style_absent_leaves_default(self) -> None:
        """When comment_style key is absent from dict, the field is not touched."""
        config = FormattingConfig.from_dict({})
        assert config.comment_style == "//"


# ---------------------------------------------------------------------------
# Integration: from_dict exercises the private coercers end-to-end
# ---------------------------------------------------------------------------


class TestFromDictCoercerIntegration:
    """Tests exercising the private coercers through the public from_dict API."""

    def test_invalid_indent_style_string_keeps_default(self) -> None:
        """An unrecognised indent_style string leaves the default (enum except path)."""
        config = FormattingConfig.from_dict({"indent_style": "zigzag"})
        assert config.indent_style is IndentStyle.SPACES

    def test_invalid_brace_style_none_keeps_default(self) -> None:
        """None for brace_style triggers the except path and leaves the default."""
        config = FormattingConfig.from_dict({"brace_style": None})
        assert config.brace_style is BraceStyle.SAME_LINE

    def test_invalid_string_style_returns_default(self) -> None:
        """Unknown string_style value is coerced to the default."""
        config = FormattingConfig.from_dict({"string_style": "monospace"})
        assert config.string_style is StringStyle.ALIGNED

    def test_invalid_hex_style_returns_default(self) -> None:
        """Unknown hex_style value is coerced to the default."""
        config = FormattingConfig.from_dict({"hex_style": "mixed"})
        assert config.hex_style is HexStyle.LOWERCASE

    def test_bool_value_for_indent_size_returns_default(self) -> None:
        """A bool passed as indent_size is rejected (bool guard), default kept."""
        config = FormattingConfig.from_dict({"indent_size": True})
        assert config.indent_size == 4

    def test_string_value_for_indent_size_is_parsed(self) -> None:
        """A valid integer string is accepted for indent_size."""
        config = FormattingConfig.from_dict({"indent_size": "2"})
        assert config.indent_size == 2

    def test_string_value_for_hex_group_size_invalid_returns_default(self) -> None:
        """An invalid string for hex_group_size keeps the default of 0."""
        config = FormattingConfig.from_dict({"hex_group_size": "notanumber"})
        assert config.hex_group_size == 0

    def test_float_for_max_line_length_returns_default(self) -> None:
        """A float is rejected by the else branch; max_line_length stays at 120."""
        config = FormattingConfig.from_dict({"max_line_length": 80.5})
        assert config.max_line_length == 120

    def test_non_bool_for_space_before_colon_returns_default(self) -> None:
        """A string is not a bool; space_before_colon falls back to default True."""
        config = FormattingConfig.from_dict({"space_before_colon": "yes"})
        assert config.space_before_colon is True

    def test_none_for_preserve_comments_returns_default(self) -> None:
        """None is not a bool; preserve_comments stays at default True."""
        config = FormattingConfig.from_dict({"preserve_comments": None})
        assert config.preserve_comments is True

    def test_int_without_minimum_applied_to_blank_lines(self) -> None:
        """blank_lines_between_rules with minimum=0 clamps, but value above zero
        is returned via the max(minimum, result) path when result >= minimum."""
        config = FormattingConfig.from_dict({"blank_lines_between_rules": 3})
        assert config.blank_lines_between_rules == 3

    def test_negative_int_for_blank_lines_clamped_to_zero(self) -> None:
        """A negative integer is clamped to the minimum of 0."""
        config = FormattingConfig.from_dict({"blank_lines_between_sections": -1})
        assert config.blank_lines_between_sections == 0

    def test_non_mapping_input_returns_default_config(self) -> None:
        """Passing a non-Mapping value returns an unmodified default config."""
        config = FormattingConfig.from_dict("not a dict")
        assert config.indent_size == 4
        assert config.comment_style == "//"
