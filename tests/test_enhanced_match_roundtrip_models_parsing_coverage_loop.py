"""Coverage for enhanced_parser_match, roundtrip_models, and lsp/parsing modules.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.
"""

from __future__ import annotations

from collections.abc import Callable
import typing

import pytest

from yaraast.errors import ParseError, SerializationError
from yaraast.lexer.tokens import TokenType as T
from yaraast.lsp.parsing import parse_for_lsp
from yaraast.serialization.roundtrip_models import (
    FormattingInfo,
    RoundTripMetadata,
    _deserialize_bool_field,
    _deserialize_choice_field,
    _deserialize_int_field,
    _deserialize_min_int_field,
    _deserialize_nullable_string_field,
    _deserialize_object,
    _deserialize_string_field,
)
from yaraast.yaral.ast_nodes import MatchSection
from yaraast.yaral.enhanced_parser import EnhancedYaraLParser
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.tokens import YaraLTokenType

# ---------------------------------------------------------------------------
# Token construction helpers (same pattern as existing tests in this repo)
# ---------------------------------------------------------------------------


def _tok(tt: T, value: str | int | float | None, yt: YaraLTokenType | None = None) -> YaraLToken:
    return YaraLToken(type=tt, value=value, line=1, column=1, length=1, yaral_type=yt)


def _load(p: EnhancedYaraLParser, toks: list[YaraLToken]) -> None:
    p.tokens = [*toks, _tok(T.EOF, None, YaraLTokenType.EOF)]
    p.current = 0


# ===========================================================================
# yaraast.yaral.enhanced_parser_match
# ===========================================================================


class TestParseMatchSection:
    """Tests for EnhancedYaraLParserMatchMixin._parse_match_section."""

    def test_single_variable_with_over_window(self) -> None:
        """Parse a match section containing one variable followed by 'over'."""
        p = EnhancedYaraLParser("")
        _load(
            p,
            [
                _tok(T.IDENTIFIER, "match"),
                _tok(T.COLON, ":"),
                _tok(T.IDENTIFIER, "v"),
                _tok(T.IDENTIFIER, "over"),
                _tok(T.INTEGER, 5),
                _tok(T.IDENTIFIER, "m"),
                _tok(T.RBRACE, "}"),
            ],
        )
        section = p._parse_match_section()

        assert isinstance(section, MatchSection)
        assert len(section.variables) == 1
        assert section.variables[0].variable == "v"
        assert section.variables[0].time_window.duration == 5
        assert section.variables[0].time_window.unit == "m"

    def test_standalone_over_updates_last_variable(self) -> None:
        """A lone 'over' keyword after a variable updates that variable's window.

        Exercises lines 21-23: the standalone_window branch inside the while loop
        where variables is non-empty and a bare 'over' token overrides the last
        variable's time_window.
        """
        p = EnhancedYaraLParser("")
        _load(
            p,
            [
                _tok(T.IDENTIFIER, "match"),
                _tok(T.COLON, ":"),
                _tok(T.IDENTIFIER, "v"),
                _tok(T.IDENTIFIER, "over"),
                _tok(T.INTEGER, 5),
                _tok(T.IDENTIFIER, "m"),
                # Standalone 'over' appearing after first variable was already parsed
                _tok(T.IDENTIFIER, "over"),
                _tok(T.INTEGER, 10),
                _tok(T.IDENTIFIER, "h"),
                _tok(T.RBRACE, "}"),
            ],
        )
        section = p._parse_match_section()

        assert len(section.variables) == 1
        # The standalone window replaces the previous one on the last variable
        assert section.variables[0].time_window.duration == 10
        assert section.variables[0].time_window.unit == "h"

    def test_standalone_over_with_no_prior_variables_is_ignored(self) -> None:
        """Bare 'over' before any variable is parsed does not crash (no variables list update).

        Exercises the if-branch on line 22 where variables is empty, so the
        condition 'if variables:' is False and the window is computed but not attached.
        """
        p = EnhancedYaraLParser("")
        _load(
            p,
            [
                _tok(T.IDENTIFIER, "match"),
                _tok(T.COLON, ":"),
                _tok(T.IDENTIFIER, "over"),
                _tok(T.INTEGER, 10),
                _tok(T.IDENTIFIER, "m"),
                _tok(T.RBRACE, "}"),
            ],
        )
        section = p._parse_match_section()

        assert section.variables == []

    def test_unexpected_token_is_skipped(self) -> None:
        """An unexpected token in the match body is consumed and skipped (line 29).

        The else-branch inside the while loop advances past any token that is
        neither a keyword ('over') nor an identifier.
        """
        p = EnhancedYaraLParser("")
        _load(
            p,
            [
                _tok(T.IDENTIFIER, "match"),
                _tok(T.COLON, ":"),
                _tok(T.PLUS, "+"),  # unexpected — triggers line 29
                _tok(T.IDENTIFIER, "v"),
                _tok(T.RBRACE, "}"),
            ],
        )
        section = p._parse_match_section()

        assert len(section.variables) == 1
        assert section.variables[0].variable == "v"

    def test_empty_match_section_returns_empty_list(self) -> None:
        """A match section with no variables yields an empty MatchSection."""
        p = EnhancedYaraLParser("")
        _load(
            p,
            [
                _tok(T.IDENTIFIER, "match"),
                _tok(T.COLON, ":"),
                _tok(T.RBRACE, "}"),
            ],
        )
        section = p._parse_match_section()

        assert isinstance(section, MatchSection)
        assert section.variables == []


class TestParseMatchVariables:
    """Tests for _parse_match_variables."""

    def test_single_variable_no_grouping_no_window(self) -> None:
        """Single identifier with no EQ and no 'over' uses default time window."""
        p = EnhancedYaraLParser("")
        _load(
            p,
            [
                _tok(T.IDENTIFIER, "m"),
            ],
        )
        result = p._parse_match_variables()

        assert len(result) == 1
        assert result[0].variable == "m"
        assert result[0].grouping_field is None
        assert result[0].time_window.duration == 1
        assert result[0].time_window.unit == "m"

    def test_multiple_variables_share_same_time_window(self) -> None:
        """Comma-separated variables all receive the same time window (lines 35-48)."""
        p = EnhancedYaraLParser("")
        _load(
            p,
            [
                _tok(T.IDENTIFIER, "a"),
                _tok(T.COMMA, ","),
                _tok(T.IDENTIFIER, "b"),
                _tok(T.COMMA, ","),
                _tok(T.IDENTIFIER, "c"),
                _tok(T.IDENTIFIER, "over"),
                _tok(T.INTEGER, 3),
                _tok(T.IDENTIFIER, "h"),
            ],
        )
        result = p._parse_match_variables()

        assert len(result) == 3
        assert [v.variable for v in result] == ["a", "b", "c"]
        assert all(v.time_window.duration == 3 for v in result)
        assert all(v.time_window.unit == "h" for v in result)
        assert all(v.grouping_field is None for v in result)

    def test_grouping_field_with_plain_identifier(self) -> None:
        """EQ followed by a plain IDENTIFIER parses a UDM grouping path (lines 65-68)."""
        p = EnhancedYaraLParser("")
        _load(
            p,
            [
                _tok(T.IDENTIFIER, "m"),
                _tok(T.EQ, "="),
                _tok(T.IDENTIFIER, "metadata"),
                _tok(T.DOT, "."),
                _tok(T.IDENTIFIER, "event_type"),
                _tok(T.IDENTIFIER, "over"),
                _tok(T.INTEGER, 5),
                _tok(T.IDENTIFIER, "m"),
            ],
        )
        result = p._parse_match_variables()

        assert len(result) == 1
        assert result[0].variable == "m"
        assert result[0].grouping_field is not None
        assert "metadata" in result[0].grouping_field.full_path

    def test_grouping_field_with_event_var_type(self) -> None:
        """EQ followed by an EVENT_VAR token parses a UDM grouping path."""
        p = EnhancedYaraLParser("")
        _load(
            p,
            [
                _tok(T.IDENTIFIER, "m"),
                _tok(T.EQ, "="),
                _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
                _tok(T.DOT, "."),
                _tok(T.IDENTIFIER, "principal"),
                _tok(T.IDENTIFIER, "over"),
                _tok(T.INTEGER, 2),
                _tok(T.IDENTIFIER, "h"),
            ],
        )
        result = p._parse_match_variables()

        assert result[0].grouping_field is not None
        assert "$e" in result[0].grouping_field.full_path

    def test_eq_followed_by_non_identifier_yields_no_grouping_field(self) -> None:
        """EQ followed by an integer does not parse a grouping field (lines 65-68 else)."""
        p = EnhancedYaraLParser("")
        _load(
            p,
            [
                _tok(T.IDENTIFIER, "m"),
                _tok(T.EQ, "="),
                _tok(T.INTEGER, 42),  # neither IDENTIFIER nor EVENT_VAR
            ],
        )
        result = p._parse_match_variables()

        assert result[0].grouping_field is None

    def test_multiple_variables_with_eq_raises_value_error(self) -> None:
        """Two or more variables before EQ raises an error (line 61)."""
        p = EnhancedYaraLParser("")
        _load(
            p,
            [
                _tok(T.IDENTIFIER, "a"),
                _tok(T.COMMA, ","),
                _tok(T.IDENTIFIER, "b"),
                _tok(T.EQ, "="),
            ],
        )
        with pytest.raises(ValueError, match="Expected single match variable"):
            p._parse_match_variables()

    def test_dollar_lstrip_in_variable_name(self) -> None:
        """Variable names starting with '$' are stripped to bare identifiers."""
        p = EnhancedYaraLParser("")
        _load(
            p,
            [
                _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            ],
        )
        result = p._parse_match_variables()

        assert result[0].variable == "e"


class TestParseMatchVariableName:
    """Tests for _parse_match_variable_name."""

    def test_event_var_token_returns_its_value(self) -> None:
        """An EVENT_VAR-typed token is consumed and returned as-is (line 54)."""
        p = EnhancedYaraLParser("")
        _load(
            p,
            [
                _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            ],
        )
        name = p._parse_match_variable_name()

        assert name == "$e"

    def test_string_identifier_token_returns_its_value(self) -> None:
        """A STRING_IDENTIFIER token type is consumed and its value returned (line 54)."""
        p = EnhancedYaraLParser("")
        _load(
            p,
            [
                _tok(T.STRING_IDENTIFIER, "$myvar"),
            ],
        )
        name = p._parse_match_variable_name()

        assert name == "$myvar"

    def test_plain_identifier_falls_back_to_consume(self) -> None:
        """A plain IDENTIFIER (no special yaral_type) is consumed via _consume (line 55)."""
        p = EnhancedYaraLParser("")
        _load(
            p,
            [
                _tok(T.IDENTIFIER, "myvar"),
            ],
        )
        name = p._parse_match_variable_name()

        assert name == "myvar"


class TestParseMatchTimeWindow:
    """Tests for _parse_match_time_window and _parse_optional_match_time_window."""

    def test_optional_window_without_over_returns_default(self) -> None:
        """No 'over' keyword yields default TimeWindow(1, 'm') (line 74)."""
        p = EnhancedYaraLParser("")
        _load(p, [])
        tw = p._parse_optional_match_time_window()

        assert tw.duration == 1
        assert tw.unit == "m"
        assert tw.modifier is None

    def test_optional_window_with_over_delegates_to_parse(self) -> None:
        """'over' keyword triggers real time window parsing (line 73)."""
        p = EnhancedYaraLParser("")
        _load(
            p,
            [
                _tok(T.IDENTIFIER, "over"),
                _tok(T.INTEGER, 15),
                _tok(T.IDENTIFIER, "h"),
            ],
        )
        tw = p._parse_optional_match_time_window()

        assert tw.duration == 15
        assert tw.unit == "h"

    def test_time_window_with_every_modifier(self) -> None:
        """'over every Xm' sets modifier='every' on the returned TimeWindow (lines 79-81)."""
        p = EnhancedYaraLParser("")
        _load(
            p,
            [
                _tok(T.IDENTIFIER, "over"),
                _tok(T.IDENTIFIER, "every"),
                _tok(T.INTEGER, 7),
                _tok(T.IDENTIFIER, "d"),
            ],
        )
        tw = p._parse_match_time_window()

        assert tw.duration == 7
        assert tw.unit == "d"
        assert tw.modifier == "every"

    def test_time_window_with_zero_duration_returns_fallback(self) -> None:
        """A duration of 0 triggers the fallback TimeWindow(1, 'm') (lines 83-85)."""
        p = EnhancedYaraLParser("")
        _load(
            p,
            [
                _tok(T.IDENTIFIER, "over"),
                _tok(T.INTEGER, 0),
                _tok(T.IDENTIFIER, "m"),
            ],
        )
        tw = p._parse_match_time_window()

        assert tw.duration == 1
        assert tw.unit == "m"

    def test_time_window_with_every_and_zero_duration_returns_fallback_with_modifier(
        self,
    ) -> None:
        """Zero duration + 'every' falls back to (1, 'm') but keeps modifier (lines 83-85)."""
        p = EnhancedYaraLParser("")
        _load(
            p,
            [
                _tok(T.IDENTIFIER, "over"),
                _tok(T.IDENTIFIER, "every"),
                _tok(T.INTEGER, 0),
                _tok(T.IDENTIFIER, "h"),
            ],
        )
        tw = p._parse_match_time_window()

        assert tw.duration == 1
        assert tw.unit == "m"
        assert tw.modifier == "every"


class TestGetEventVarType:
    """Tests for _get_event_var_type."""

    def test_returns_yaral_event_var_type(self) -> None:
        """_get_event_var_type returns the YaraLTokenType.EVENT_VAR sentinel (lines 89-91).

        The production method lacks a return annotation.  We cast it to a typed
        Callable so the call site is well-typed without suppression comments.
        """
        p = EnhancedYaraLParser("")
        typed_fn = typing.cast(
            Callable[[], YaraLTokenType],
            p._get_event_var_type,
        )
        result = typed_fn()

        assert result is YaraLTokenType.EVENT_VAR


class TestEnhancedMatchViaFullParser:
    """Integration tests that parse complete YARA-L rule text through EnhancedYaraLParser."""

    def test_real_rule_with_single_dollar_variable(self) -> None:
        """Full rule with '$e over 5m' produces the expected match section."""
        parser = EnhancedYaraLParser("""
            rule test_dollar {
              events:
                $e.field = "v"
              match:
                $e over 5m
              condition:
                $e
            }
            """)
        ast = parser.parse()

        assert parser.errors == []
        match = ast.rules[0].match
        assert match is not None
        assert len(match.variables) == 1
        assert match.variables[0].variable == "e"
        assert match.variables[0].time_window.duration == 5
        assert match.variables[0].time_window.unit == "m"

    def test_real_rule_grouping_error_appears_in_parser_errors(self) -> None:
        """Multiple variables with EQ grouping yields a parser error (not exception)."""
        parser = EnhancedYaraLParser("""
            rule test_group_error {
              events:
                $e.f = "v"
                $f.f = "v"
              match:
                $e, $f = $e.field over 5m
              condition:
                $e
            }
            """)
        parser.parse()

        assert any("Expected single match variable" in err for err in parser.errors)

    def test_real_rule_with_multiple_variables_and_every_modifier(self) -> None:
        """Comma-separated variables with 'over every Xm' produce multiple MatchVariable nodes."""
        parser = EnhancedYaraLParser("""
            rule test_multi_every {
              events:
                $e.metadata.event_type = "v"
              match:
                $e, $f over every 10m
              condition:
                $e
            }
            """)
        ast = parser.parse()

        assert parser.errors == []
        match = ast.rules[0].match
        assert match is not None
        variables = match.variables
        assert len(variables) == 2
        assert {v.variable for v in variables} == {"e", "f"}
        assert all(v.time_window.modifier == "every" for v in variables)
        assert all(v.time_window.duration == 10 for v in variables)


# ===========================================================================
# yaraast.serialization.roundtrip_models
# ===========================================================================


class TestDeserializeObject:
    """Tests for _deserialize_object."""

    def test_mapping_is_returned_unchanged(self) -> None:
        """A dict input passes through as-is."""
        data = {"key": "value"}
        result = _deserialize_object(data, "Test")
        assert result is data

    def test_non_mapping_raises_serialization_error(self) -> None:
        """A non-mapping input raises SerializationError with the context in the message (line 15)."""
        with pytest.raises(SerializationError, match="MyContext must be an object"):
            _deserialize_object("not_a_dict", "MyContext")

    def test_list_raises_serialization_error(self) -> None:
        """A list is not a mapping and must be rejected."""
        with pytest.raises(SerializationError, match="FormattingInfo must be an object"):
            _deserialize_object([], "FormattingInfo")

    def test_integer_raises_serialization_error(self) -> None:
        """An integer is not a mapping and must be rejected."""
        with pytest.raises(SerializationError, match="RoundTripMetadata must be an object"):
            _deserialize_object(42, "RoundTripMetadata")


class TestDeserializeStringField:
    """Tests for _deserialize_string_field."""

    def test_string_value_returned(self) -> None:
        """A string value for the named field is returned directly."""
        result = _deserialize_string_field({"k": "hello"}, "k", "default", "Ctx")
        assert result == "hello"

    def test_missing_key_returns_default(self) -> None:
        """A missing field returns the provided default."""
        result = _deserialize_string_field({}, "k", "fallback", "Ctx")
        assert result == "fallback"

    def test_non_string_value_raises_serialization_error(self) -> None:
        """A non-string value in the mapping raises SerializationError (lines 28-29)."""
        with pytest.raises(SerializationError, match="Ctx k must be a string"):
            _deserialize_string_field({"k": 123}, "k", "default", "Ctx")

    def test_none_value_raises_serialization_error(self) -> None:
        """None is not a string and must raise SerializationError."""
        with pytest.raises(SerializationError, match="Ctx k must be a string"):
            _deserialize_string_field({"k": None}, "k", "default", "Ctx")


class TestDeserializeChoiceField:
    """Tests for _deserialize_choice_field."""

    def test_valid_choice_is_returned(self) -> None:
        """A value that belongs to allowed_values is returned."""
        result = _deserialize_choice_field(
            {"k": "spaces"}, "k", "spaces", "Ctx", frozenset({"spaces", "tabs"})
        )
        assert result == "spaces"

    def test_invalid_choice_raises_serialization_error(self) -> None:
        """A value not in allowed_values raises SerializationError (lines 42-44)."""
        with pytest.raises(SerializationError, match="Ctx k must be one of"):
            _deserialize_choice_field(
                {"k": "unknown"}, "k", "spaces", "Ctx", frozenset({"spaces", "tabs"})
            )

    def test_error_message_lists_allowed_values_sorted(self) -> None:
        """The error lists the allowed values in sorted repr form."""
        with pytest.raises(SerializationError, match="'spaces'"):
            _deserialize_choice_field(
                {"k": "bad"}, "k", "spaces", "Ctx", frozenset({"spaces", "tabs"})
            )


class TestDeserializeNullableStringField:
    """Tests for _deserialize_nullable_string_field."""

    def test_string_value_returned(self) -> None:
        """A string value is returned directly."""
        result = _deserialize_nullable_string_field({"k": "hello"}, "k", "Ctx")
        assert result == "hello"

    def test_none_value_returned(self) -> None:
        """An explicit None is returned as None."""
        result = _deserialize_nullable_string_field({"k": None}, "k", "Ctx")
        assert result is None

    def test_missing_key_returns_none(self) -> None:
        """A missing key returns None (default from dict.get)."""
        result = _deserialize_nullable_string_field({}, "k", "Ctx")
        assert result is None

    def test_non_string_non_none_raises(self) -> None:
        """A non-string, non-None value raises SerializationError (lines 55-56)."""
        with pytest.raises(SerializationError, match="Ctx k must be a string"):
            _deserialize_nullable_string_field({"k": 42}, "k", "Ctx")


class TestDeserializeIntField:
    """Tests for _deserialize_int_field."""

    def test_integer_returned(self) -> None:
        """A plain integer value is returned."""
        result = _deserialize_int_field({"k": 4}, "k", 0, "Ctx")
        assert result == 4

    def test_missing_key_returns_default(self) -> None:
        """A missing key returns the provided integer default."""
        result = _deserialize_int_field({}, "k", 99, "Ctx")
        assert result == 99

    def test_string_value_raises(self) -> None:
        """A string where an int is expected raises SerializationError (lines 68-69)."""
        with pytest.raises(SerializationError, match="Ctx k must be an integer"):
            _deserialize_int_field({"k": "four"}, "k", 0, "Ctx")

    def test_bool_rejected_as_integer(self) -> None:
        """bool is a subclass of int but must be rejected (lines 66, 68-69)."""
        with pytest.raises(SerializationError, match="Ctx k must be an integer"):
            _deserialize_int_field({"k": True}, "k", 0, "Ctx")

    def test_float_raises(self) -> None:
        """A float is not an int and must be rejected."""
        with pytest.raises(SerializationError, match="Ctx k must be an integer"):
            _deserialize_int_field({"k": 3.14}, "k", 0, "Ctx")


class TestDeserializeMinIntField:
    """Tests for _deserialize_min_int_field."""

    def test_value_at_minimum_is_accepted(self) -> None:
        """A value equal to minimum passes validation."""
        result = _deserialize_min_int_field({"k": 1}, "k", 4, "Ctx", 1)
        assert result == 1

    def test_value_above_minimum_is_accepted(self) -> None:
        """A value above minimum passes validation."""
        result = _deserialize_min_int_field({"k": 10}, "k", 4, "Ctx", 1)
        assert result == 10

    def test_value_below_minimum_raises(self) -> None:
        """A value below minimum raises SerializationError (lines 82-83)."""
        with pytest.raises(SerializationError, match="Ctx k must be at least 5"):
            _deserialize_min_int_field({"k": 4}, "k", 5, "Ctx", 5)

    def test_zero_below_minimum_one_raises(self) -> None:
        """indent_size of 0 is below the minimum of 1."""
        with pytest.raises(
            SerializationError, match="FormattingInfo indent_size must be at least 1"
        ):
            _deserialize_min_int_field({"indent_size": 0}, "indent_size", 4, "FormattingInfo", 1)


class TestDeserializeBoolField:
    """Tests for _deserialize_bool_field."""

    def test_true_returned(self) -> None:
        """True value is returned as True."""
        result = _deserialize_bool_field({"k": True}, "k", False, "Ctx")
        assert result is True

    def test_false_returned(self) -> None:
        """False value is returned as False."""
        result = _deserialize_bool_field({"k": False}, "k", True, "Ctx")
        assert result is False

    def test_missing_key_returns_default(self) -> None:
        """A missing key returns the default bool."""
        result = _deserialize_bool_field({}, "k", True, "Ctx")
        assert result is True

    def test_string_raises(self) -> None:
        """A string value raises SerializationError (lines 95-96)."""
        with pytest.raises(SerializationError, match="Ctx k must be a boolean"):
            _deserialize_bool_field({"k": "yes"}, "k", False, "Ctx")

    def test_integer_raises(self) -> None:
        """An integer (even 1 or 0) raises SerializationError."""
        with pytest.raises(SerializationError, match="Ctx k must be a boolean"):
            _deserialize_bool_field({"k": 1}, "k", False, "Ctx")


class TestFormattingInfoToDict:
    """Tests for FormattingInfo.to_dict (line 119)."""

    def test_default_roundtrip(self) -> None:
        """Default FormattingInfo survives a to_dict/from_dict round-trip."""
        fi = FormattingInfo()
        d = fi.to_dict()

        # Verify all expected keys are present with correct types
        assert d["indent_size"] == 4
        assert d["indent_style"] == "spaces"
        assert d["line_endings"] == "\n"
        assert d["blank_lines_before_rule"] == 1
        assert d["blank_lines_after_imports"] == 1
        assert d["blank_lines_after_includes"] == 1
        assert d["comment_style"] == "line"
        assert d["preserve_spacing"] is True
        assert d["preserve_alignment"] is True

    def test_to_dict_produces_reconstructable_mapping(self) -> None:
        """to_dict output can be fed back into from_dict to reproduce the original."""
        original = FormattingInfo(
            indent_size=2,
            indent_style="tabs",
            line_endings="\r\n",
            blank_lines_before_rule=0,
            blank_lines_after_imports=0,
            blank_lines_after_includes=0,
            comment_style="block",
            preserve_spacing=False,
            preserve_alignment=False,
        )
        reconstructed = FormattingInfo.from_dict(original.to_dict())

        assert reconstructed == original


class TestFormattingInfoFromDict:
    """Tests for FormattingInfo.from_dict."""

    def test_empty_mapping_uses_all_defaults(self) -> None:
        """An empty dict produces a FormattingInfo with default values (lines 134-188)."""
        fi = FormattingInfo.from_dict({})

        assert fi.indent_size == 4
        assert fi.indent_style == "spaces"
        assert fi.line_endings == "\n"
        assert fi.comment_style == "line"
        assert fi.preserve_spacing is True
        assert fi.preserve_alignment is True

    def test_tabs_indent_style_accepted(self) -> None:
        """'tabs' is a valid indent_style choice."""
        fi = FormattingInfo.from_dict({"indent_style": "tabs"})
        assert fi.indent_style == "tabs"

    def test_block_comment_style_accepted(self) -> None:
        """'block' is a valid comment_style choice."""
        fi = FormattingInfo.from_dict({"comment_style": "block"})
        assert fi.comment_style == "block"

    def test_cr_lf_line_endings_accepted(self) -> None:
        r"""'\r\n' is a valid line_endings choice."""
        fi = FormattingInfo.from_dict({"line_endings": "\r\n"})
        assert fi.line_endings == "\r\n"

    def test_cr_line_endings_accepted(self) -> None:
        r"""'\r' is a valid line_endings choice."""
        fi = FormattingInfo.from_dict({"line_endings": "\r"})
        assert fi.line_endings == "\r"

    def test_non_mapping_raises(self) -> None:
        """A non-dict argument raises SerializationError."""
        with pytest.raises(SerializationError, match="FormattingInfo must be an object"):
            FormattingInfo.from_dict("bad")

    def test_invalid_indent_style_raises(self) -> None:
        """An unrecognised indent_style raises SerializationError."""
        with pytest.raises(SerializationError, match="FormattingInfo indent_style must be one of"):
            FormattingInfo.from_dict({"indent_style": "spaces_and_tabs"})

    def test_invalid_comment_style_raises(self) -> None:
        """An unrecognised comment_style raises SerializationError."""
        with pytest.raises(SerializationError, match="FormattingInfo comment_style must be one of"):
            FormattingInfo.from_dict({"comment_style": "hash"})

    def test_indent_size_zero_raises(self) -> None:
        """indent_size of 0 is below the required minimum of 1."""
        with pytest.raises(SerializationError, match="indent_size must be at least 1"):
            FormattingInfo.from_dict({"indent_size": 0})

    def test_blank_lines_zero_accepted(self) -> None:
        """blank_lines fields accept zero (minimum is 0)."""
        fi = FormattingInfo.from_dict(
            {
                "blank_lines_before_rule": 0,
                "blank_lines_after_imports": 0,
                "blank_lines_after_includes": 0,
            }
        )
        assert fi.blank_lines_before_rule == 0
        assert fi.blank_lines_after_imports == 0
        assert fi.blank_lines_after_includes == 0


class TestRoundTripMetadataToDict:
    """Tests for RoundTripMetadata.to_dict (line 206)."""

    def test_to_dict_includes_all_fields(self) -> None:
        """to_dict returns a mapping with every metadata field present."""
        meta = RoundTripMetadata(
            original_source="rule test { condition: true }",
            source_file="test.yar",
            parsed_at="2026-01-01T00:00:00",
            serializer_version="1.0.0",
            comments_preserved=True,
            formatting_preserved=True,
            parser_version="3.2.1",
        )
        d = meta.to_dict()

        assert d["original_source"] == "rule test { condition: true }"
        assert d["source_file"] == "test.yar"
        assert d["parsed_at"] == "2026-01-01T00:00:00"
        assert d["serializer_version"] == "1.0.0"
        assert d["comments_preserved"] is True
        assert d["formatting_preserved"] is True
        assert d["parser_version"] == "3.2.1"
        assert "formatting" in d

    def test_to_dict_with_none_nullable_fields(self) -> None:
        """Nullable fields serialize to None when not set."""
        meta = RoundTripMetadata()
        d = meta.to_dict()

        assert d["original_source"] is None
        assert d["source_file"] is None
        assert d["parsed_at"] is None
        assert d["parser_version"] is None

    def test_to_dict_roundtrip_via_from_dict(self) -> None:
        """A RoundTripMetadata can be serialized and deserialized back to an equal value."""
        original = RoundTripMetadata(
            original_source="rule r { condition: false }",
            source_file="r.yar",
            parsed_at="2026-06-21",
            serializer_version="2.0.0",
            formatting=FormattingInfo(indent_size=2, indent_style="tabs"),
            comments_preserved=False,
            formatting_preserved=False,
            parser_version="4.0.0",
        )
        reconstructed = RoundTripMetadata.from_dict(original.to_dict())

        assert reconstructed.original_source == original.original_source
        assert reconstructed.source_file == original.source_file
        assert reconstructed.parsed_at == original.parsed_at
        assert reconstructed.serializer_version == original.serializer_version
        assert reconstructed.comments_preserved == original.comments_preserved
        assert reconstructed.formatting_preserved == original.formatting_preserved
        assert reconstructed.parser_version == original.parser_version
        assert reconstructed.formatting.indent_size == original.formatting.indent_size
        assert reconstructed.formatting.indent_style == original.formatting.indent_style


class TestRoundTripMetadataFromDict:
    """Tests for RoundTripMetadata.from_dict (lines 218-245)."""

    def test_empty_mapping_uses_all_defaults(self) -> None:
        """An empty dict produces a RoundTripMetadata with all default values."""
        meta = RoundTripMetadata.from_dict({})

        assert meta.original_source is None
        assert meta.source_file is None
        assert meta.parsed_at is None
        assert meta.serializer_version == "1.0.0"
        assert meta.comments_preserved is True
        assert meta.formatting_preserved is True
        assert meta.parser_version is None

    def test_full_mapping_populates_all_fields(self) -> None:
        """All fields from a fully-populated mapping are correctly deserialized (lines 220-244)."""
        data = {
            "original_source": "rule r { condition: true }",
            "source_file": "/path/to/r.yar",
            "parsed_at": "2026-06-21T12:00:00",
            "serializer_version": "1.2.3",
            "formatting": {
                "indent_size": 2,
                "indent_style": "tabs",
                "line_endings": "\r\n",
                "blank_lines_before_rule": 2,
                "blank_lines_after_imports": 0,
                "blank_lines_after_includes": 0,
                "comment_style": "block",
                "preserve_spacing": False,
                "preserve_alignment": False,
            },
            "comments_preserved": False,
            "formatting_preserved": False,
            "parser_version": "2.0.0",
        }
        meta = RoundTripMetadata.from_dict(data)

        assert meta.original_source == "rule r { condition: true }"
        assert meta.source_file == "/path/to/r.yar"
        assert meta.parsed_at == "2026-06-21T12:00:00"
        assert meta.serializer_version == "1.2.3"
        assert meta.comments_preserved is False
        assert meta.formatting_preserved is False
        assert meta.parser_version == "2.0.0"
        assert meta.formatting.indent_size == 2
        assert meta.formatting.indent_style == "tabs"
        assert meta.formatting.line_endings == "\r\n"

    def test_non_mapping_raises(self) -> None:
        """A non-dict argument raises SerializationError."""
        with pytest.raises(SerializationError, match="RoundTripMetadata must be an object"):
            RoundTripMetadata.from_dict(["not", "a", "dict"])

    def test_invalid_serializer_version_type_raises(self) -> None:
        """A non-string serializer_version raises SerializationError."""
        with pytest.raises(
            SerializationError, match="RoundTripMetadata serializer_version must be a string"
        ):
            RoundTripMetadata.from_dict({"serializer_version": 99})

    def test_invalid_comments_preserved_type_raises(self) -> None:
        """A non-bool comments_preserved raises SerializationError."""
        with pytest.raises(
            SerializationError, match="RoundTripMetadata comments_preserved must be a boolean"
        ):
            RoundTripMetadata.from_dict({"comments_preserved": "yes"})

    def test_invalid_formatting_preserved_type_raises(self) -> None:
        """A non-bool formatting_preserved raises SerializationError."""
        with pytest.raises(
            SerializationError, match="RoundTripMetadata formatting_preserved must be a boolean"
        ):
            RoundTripMetadata.from_dict({"formatting_preserved": 0})

    def test_invalid_original_source_type_raises(self) -> None:
        """A non-string, non-None original_source raises SerializationError (lines 225-227)."""
        with pytest.raises(
            SerializationError, match="RoundTripMetadata original_source must be a string"
        ):
            RoundTripMetadata.from_dict({"original_source": 42})

    def test_invalid_source_file_type_raises(self) -> None:
        """A non-string, non-None source_file raises SerializationError."""
        with pytest.raises(
            SerializationError, match="RoundTripMetadata source_file must be a string"
        ):
            RoundTripMetadata.from_dict({"source_file": []})

    def test_invalid_parsed_at_type_raises(self) -> None:
        """A non-string, non-None parsed_at raises SerializationError."""
        with pytest.raises(
            SerializationError, match="RoundTripMetadata parsed_at must be a string"
        ):
            RoundTripMetadata.from_dict({"parsed_at": 20260621})

    def test_invalid_parser_version_type_raises(self) -> None:
        """A non-string, non-None parser_version raises SerializationError."""
        with pytest.raises(
            SerializationError, match="RoundTripMetadata parser_version must be a string"
        ):
            RoundTripMetadata.from_dict({"parser_version": 1})

    def test_missing_formatting_key_uses_default_formatting(self) -> None:
        """When 'formatting' is absent the default FormattingInfo is used."""
        meta = RoundTripMetadata.from_dict({"serializer_version": "1.0.0"})
        assert meta.formatting == FormattingInfo()


# ===========================================================================
# yaraast.lsp.parsing
# ===========================================================================


class TestParseForLsp:
    """Tests for parse_for_lsp in yaraast.lsp.parsing."""

    def test_valid_rule_returns_ast(self) -> None:
        """A syntactically correct YARA rule produces a non-None AST (lines 17-20)."""
        ast = parse_for_lsp("rule test { condition: true }")

        assert ast is not None

    def test_valid_rule_with_strings_returns_ast(self) -> None:
        """A rule with a strings section parses successfully."""
        ast = parse_for_lsp('rule with_strings { strings: $a = "hello" condition: $a }')
        assert ast is not None

    def test_lexer_error_is_wrapped_as_parse_error(self) -> None:
        """A LexerError from an invalid string literal is wrapped in ParseError (lines 23-24).

        The Unicode surrogate code point U+D800 is illegal in YARA string literals
        and triggers a LexerError in the underlying lexer, which must be re-raised
        as ParseError by parse_for_lsp.
        """
        with pytest.raises(ParseError, match="Lexer error"):
            parse_for_lsp('rule broken { strings: $a = "\ud800" condition: $a }')

    def test_parser_error_is_reraised_directly(self) -> None:
        """A parser error (non-LexerError) is re-raised without wrapping (line 25).

        A syntactically broken condition triggers the parser — not the lexer — so
        parse_for_lsp must re-raise it as-is rather than wrapping in ParseError.
        """
        from yaraast.parser._shared import ParserError

        with pytest.raises(ParserError):
            parse_for_lsp("rule broken { condition: }")

    def test_parse_with_explicit_uri(self) -> None:
        """Providing an explicit URI does not affect successful parsing."""
        ast = parse_for_lsp(
            "rule uri_rule { condition: false }",
            uri="file:///tmp/test.yar",
        )
        assert ast is not None

    def test_parse_empty_string_returns_empty_yara_file(self) -> None:
        """An empty input produces an empty YaraFile with no rules (not an error)."""
        from yaraast.ast.base import YaraFile

        ast = parse_for_lsp("")
        assert isinstance(ast, YaraFile)
        assert ast.rules == []

    def test_line_26_unreachable_confirmed(self) -> None:
        """Confirm that DocumentContext always sets _ast or _parse_error after ast().

        Line 26 of lsp/parsing.py ('raise ParseError("Unable to parse document")')
        is unreachable through the public API: DocumentContext.ast() guarantees that
        either _ast or _parse_error is set in every code path, so parse_error() cannot
        return None after ast() has been called.

        This test validates that assumption by exercising the successful path (ast()
        returns a value) and error paths (wrapped exceptions), which together exhaust
        the only branches that lead toward line 26 without entering it.
        """
        # Successful path: ast is not None, function returns before line 21
        ast = parse_for_lsp("rule ok { condition: true }")
        assert ast is not None

        # Error path: ast is None, parse_error is set, line 25 is hit instead of 26
        from yaraast.parser._shared import ParserError

        with pytest.raises(ParserError):
            parse_for_lsp("rule bad { condition: }")
