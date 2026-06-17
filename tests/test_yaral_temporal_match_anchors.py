"""Tests for temporal match anchor parsing (after/before keywords)."""

from __future__ import annotations

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral.ast_nodes import MatchVariable, TimeWindow
from yaraast.yaral.generator import YaraLGenerator
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.parser import YaraLParser
from yaraast.yaral.tokens import YaraLTokenType


def _tok(
    token_type: T,
    value: str | int | float | None,
    yaral_type: YaraLTokenType | None = None,
) -> YaraLToken:
    return YaraLToken(
        type=token_type,
        value=value,
        line=1,
        column=1,
        length=1,
        yaral_type=yaral_type,
    )


def _set_tokens(parser: YaraLParser, tokens: list[YaraLToken]) -> None:
    parser.tokens = tokens
    parser.current = 0


class TestTemporalMatchAnchors:
    """Test parsing of 'after' and 'before' temporal anchors in match section."""

    def test_match_after_anchor(self) -> None:
        """Parse: $userid over 48h after $create"""
        parser = YaraLParser("")
        _set_tokens(
            parser,
            [
                _tok(T.IDENTIFIER, "match"),
                _tok(T.COLON, ":"),
                _tok(T.STRING_IDENTIFIER, "$userid", YaraLTokenType.EVENT_VAR),
                _tok(T.IDENTIFIER, "over"),
                _tok(T.IDENTIFIER, "48h", YaraLTokenType.TIME_LITERAL),
                _tok(T.IDENTIFIER, "after"),
                _tok(T.STRING_IDENTIFIER, "$create", YaraLTokenType.EVENT_VAR),
                _tok(T.RBRACE, "}"),
                _tok(T.EOF, None, YaraLTokenType.EOF),
            ],
        )

        section = parser._parse_match_section()
        assert len(section.variables) == 1
        var = section.variables[0]
        assert var.variable == "userid"
        assert var.time_window.duration == 48
        assert var.time_window.unit == "h"
        assert var.temporal_anchor == "after"
        assert var.anchor_variable == "create"

    def test_match_before_anchor(self) -> None:
        """Parse: $gcp_user over 2h before $pam_grant"""
        parser = YaraLParser("")
        _set_tokens(
            parser,
            [
                _tok(T.IDENTIFIER, "match"),
                _tok(T.COLON, ":"),
                _tok(T.STRING_IDENTIFIER, "$gcp_user", YaraLTokenType.EVENT_VAR),
                _tok(T.IDENTIFIER, "over"),
                _tok(T.IDENTIFIER, "2h", YaraLTokenType.TIME_LITERAL),
                _tok(T.IDENTIFIER, "before"),
                _tok(T.STRING_IDENTIFIER, "$pam_grant", YaraLTokenType.EVENT_VAR),
                _tok(T.RBRACE, "}"),
                _tok(T.EOF, None, YaraLTokenType.EOF),
            ],
        )

        section = parser._parse_match_section()
        assert len(section.variables) == 1
        var = section.variables[0]
        assert var.variable == "gcp_user"
        assert var.time_window.duration == 2
        assert var.time_window.unit == "h"
        assert var.temporal_anchor == "before"
        assert var.anchor_variable == "pam_grant"

    def test_match_without_anchor_unchanged(self) -> None:
        """Ensure regular match (no anchor) still works and has None anchor fields."""
        parser = YaraLParser("")
        _set_tokens(
            parser,
            [
                _tok(T.IDENTIFIER, "match"),
                _tok(T.COLON, ":"),
                _tok(T.STRING_IDENTIFIER, "$userid", YaraLTokenType.EVENT_VAR),
                _tok(T.IDENTIFIER, "over"),
                _tok(T.IDENTIFIER, "24h", YaraLTokenType.TIME_LITERAL),
                _tok(T.RBRACE, "}"),
                _tok(T.EOF, None, YaraLTokenType.EOF),
            ],
        )

        section = parser._parse_match_section()
        var = section.variables[0]
        assert var.temporal_anchor is None
        assert var.anchor_variable is None

    def test_match_after_with_every_modifier(self) -> None:
        """Parse: $userid over every 1h after $login"""
        parser = YaraLParser("")
        _set_tokens(
            parser,
            [
                _tok(T.IDENTIFIER, "match"),
                _tok(T.COLON, ":"),
                _tok(T.STRING_IDENTIFIER, "$userid", YaraLTokenType.EVENT_VAR),
                _tok(T.IDENTIFIER, "over"),
                _tok(T.IDENTIFIER, "every"),
                _tok(T.IDENTIFIER, "1h", YaraLTokenType.TIME_LITERAL),
                _tok(T.IDENTIFIER, "after"),
                _tok(T.STRING_IDENTIFIER, "$login", YaraLTokenType.EVENT_VAR),
                _tok(T.RBRACE, "}"),
                _tok(T.EOF, None, YaraLTokenType.EOF),
            ],
        )

        section = parser._parse_match_section()
        var = section.variables[0]
        assert var.time_window.modifier == "every"
        assert var.time_window.duration == 1
        assert var.time_window.unit == "h"
        assert var.temporal_anchor == "after"
        assert var.anchor_variable == "login"


class TestTemporalMatchAnchorGenerator:
    """Test code generation for temporal anchors."""

    def test_generate_after_anchor(self) -> None:
        node = MatchVariable(
            variable="userid",
            time_window=TimeWindow(duration=48, unit="h"),
            temporal_anchor="after",
            anchor_variable="create",
        )
        gen = YaraLGenerator()
        result = gen.visit_match_variable(node)
        assert "$userid over 48h after $create" in result

    def test_generate_before_anchor(self) -> None:
        node = MatchVariable(
            variable="gcp_user",
            time_window=TimeWindow(duration=2, unit="h"),
            temporal_anchor="before",
            anchor_variable="pam_grant",
        )
        gen = YaraLGenerator()
        result = gen.visit_match_variable(node)
        assert "$gcp_user over 2h before $pam_grant" in result

    def test_generate_no_anchor(self) -> None:
        node = MatchVariable(
            variable="userid",
            time_window=TimeWindow(duration=24, unit="h"),
        )
        gen = YaraLGenerator()
        result = gen.visit_match_variable(node)
        assert "$userid over 24h" in result
        assert "after" not in result
        assert "before" not in result
