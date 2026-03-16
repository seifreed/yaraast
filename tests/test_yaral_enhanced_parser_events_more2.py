from __future__ import annotations

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral.ast_nodes import EventAssignment, JoinCondition
from yaraast.yaral.enhanced_parser import EnhancedYaraLParser
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.tokens import YaraLTokenType


def _tok(tt: T, value, yt: YaraLTokenType | None = None) -> YaraLToken:
    return YaraLToken(type=tt, value=value, line=1, column=1, length=1, yaral_type=yt)


def _set_tokens(p: EnhancedYaraLParser, toks: list[YaraLToken]) -> None:
    p.tokens = [*toks, _tok(T.EOF, None, YaraLTokenType.EOF)]
    p.current = 0


def test_enhanced_events_section_handles_join_and_garbage() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "events"),
            _tok(T.COLON, ":"),
            _tok(T.IDENTIFIER, "join"),
            _tok(T.IDENTIFIER, "left"),
            _tok(T.IDENTIFIER, "on"),
            _tok(T.IDENTIFIER, "$x", YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "with"),
            _tok(T.IDENTIFIER, "right"),
            _tok(T.PLUS, "+"),
            _tok(T.RBRACE, "}"),
        ],
    )

    section = p._parse_events_section()
    assert len(section.statements) == 1
    assert isinstance(section.statements[0], JoinCondition)


def test_enhanced_event_statement_none_and_identifier_path_forms() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(p, [_tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR)])
    assert p._parse_event_statement() is None

    p2 = EnhancedYaraLParser("")
    _set_tokens(
        p2,
        [
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.EQ, "="),
            _tok(T.STRING, "LOGIN"),
        ],
    )
    stmt = p2._parse_event_statement()
    assert isinstance(stmt, list)
    assert len(stmt) == 1
    assert isinstance(stmt[0], EventAssignment)
    assert stmt[0].field_path.parts == ["metadata"]


def test_enhanced_event_statement_breaks_when_event_missing_after_loop_entry() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.EQ, "="),
            _tok(T.STRING, "LOGIN"),
        ],
    )
    assert p._parse_event_statement() is None


def test_enhanced_complex_patterns_and_join_condition_delegate() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(p, [_tok(T.IDENTIFIER, "nope")])
    assert p._parse_complex_event_pattern() is None

    p2 = EnhancedYaraLParser("")
    _set_tokens(p2, [_tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR)])
    condition = p2._parse_join_condition()
    assert condition.__class__.__name__ == "EventExistsCondition"
