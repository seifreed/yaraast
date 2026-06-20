"""Direct coverage for enhanced parser match mixin."""

from __future__ import annotations

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral.enhanced_parser import EnhancedYaraLParser
from yaraast.yaral.generator import YaraLGenerator
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.tokens import YaraLTokenType


def _tok(tt: T, value: str | int | float | None, yt: YaraLTokenType | None = None) -> YaraLToken:
    return YaraLToken(type=tt, value=value, line=1, column=1, length=1, yaral_type=yt)


def _set_tokens(p: EnhancedYaraLParser, toks: list[YaraLToken]) -> None:
    p.tokens = [*toks, _tok(T.EOF, None, YaraLTokenType.EOF)]
    p.current = 0


def test_parse_match_variable_with_field_and_over_condition() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "m"),
            _tok(T.EQ, "="),
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "principal"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "ip"),
            _tok(T.IDENTIFIER, "over"),
            _tok(T.INTEGER, 5),
            _tok(T.IDENTIFIER, "m"),
        ],
    )

    parsed = p._parse_match_variables()[0]
    assert parsed.variable == "m"
    assert parsed.grouping_field is not None
    assert parsed.grouping_field.full_path == "$e.principal.ip"
    assert parsed.time_window.duration == 5
    assert parsed.time_window.unit == "m"


def test_parse_match_variable_without_optional_parts() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(p, [_tok(T.IDENTIFIER, "m"), _tok(T.EQ, "=")])
    parsed = p._parse_match_variables()[0]
    assert parsed.variable == "m"
    assert parsed.time_window.duration == 1
    assert parsed.time_window.unit == "m"


def test_parse_match_section_with_variable_time_window_and_skip_token() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "match"),
            _tok(T.COLON, ":"),
            _tok(T.IDENTIFIER, "v"),
            _tok(T.EQ, "="),
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "event_type"),
            _tok(T.IDENTIFIER, "over"),
            _tok(T.INTEGER, 1),
            _tok(T.IDENTIFIER, "h"),
            _tok(T.PLUS, "+"),
            _tok(T.IDENTIFIER, "over"),
            _tok(T.IDENTIFIER, "10m", YaraLTokenType.TIME_LITERAL),
            _tok(T.RBRACE, "}"),
        ],
    )

    section = p._parse_match_section()
    assert len(section.variables) == 1
    assert section.variables[0].variable == "v"
    assert section.variables[0].grouping_field is not None
    assert section.variables[0].grouping_field.full_path == "metadata.event_type"
    assert section.variables[0].time_window.duration == 10
    assert section.variables[0].time_window.unit == "m"


def test_enhanced_match_grouping_field_preserves_generated_text() -> None:
    parser = EnhancedYaraLParser("""
        rule grouped_match {
          events:
            $e.field = "v"
          match:
            m = $e.principal.ip over 5m
          condition:
            $e
        }
        """)
    ast = parser.parse()

    assert parser.errors == []
    match_section = ast.rules[0].match
    assert match_section is not None
    assert match_section.variables[0].grouping_field is not None

    generated = YaraLGenerator().generate(ast)
    assert "$m = $e.principal.ip over 5m" in generated


def test_enhanced_match_dollar_grouping_field_preserves_bracketed_path() -> None:
    parser = EnhancedYaraLParser("""
        rule grouped_match_bracket {
          events:
            $e.metadata.event_type = "v"
          match:
            $m = $e.metadata["event_type"] over 5m
          condition:
            $e
        }
        """)
    ast = parser.parse()

    assert parser.errors == []
    match_section = ast.rules[0].match
    assert match_section is not None
    assert match_section.variables[0].variable == "m"
    assert match_section.variables[0].grouping_field is not None
    assert match_section.variables[0].grouping_field.full_path == '$e.metadata["event_type"]'

    generated = YaraLGenerator().generate(ast)
    assert '$m = $e.metadata["event_type"] over 5m' in generated


def test_enhanced_match_variable_list_with_every_window_preserves_generated_text() -> None:
    parser = EnhancedYaraLParser("""
        rule grouped_match_list {
          events:
            $e.metadata.event_type = "v"
          match:
            $e, $f over every 5m
          condition:
            $e
        }
        """)
    ast = parser.parse()

    assert parser.errors == []
    match_section = ast.rules[0].match
    assert match_section is not None
    assert [variable.variable for variable in match_section.variables] == ["e", "f"]
    assert all(variable.time_window.modifier == "every" for variable in match_section.variables)

    generated = YaraLGenerator().generate(ast)
    assert "$e over every 5m" in generated
    assert "$f over every 5m" in generated
