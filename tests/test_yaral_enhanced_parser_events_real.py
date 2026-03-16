"""Real tests for enhanced parser events mixin without test doubles."""

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


def test_parse_event_statement_multiple_assignments_real() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "event_type"),
            _tok(T.EQ, "="),
            _tok(T.STRING, "LOGIN"),
            _tok(T.IDENTIFIER, "and"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "principal"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "ip"),
            _tok(T.IN, "in"),
            _tok(T.STRING, "1.2.3.4"),
        ],
    )
    stmts = p._parse_event_statement()
    assert isinstance(stmts, list) and len(stmts) == 2
    assert all(isinstance(s, EventAssignment) for s in stmts)


def test_parse_join_and_pattern_helpers_real() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "join"),
            _tok(T.IDENTIFIER, "e1"),
            _tok(T.IDENTIFIER, "on"),
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "with"),
            _tok(T.IDENTIFIER, "e2"),
        ],
    )
    join = p._parse_join_statement()
    assert isinstance(join, JoinCondition)

    p2 = EnhancedYaraLParser("")
    _set_tokens(p2, [_tok(T.IDENTIFIER, "all")])
    assert p2._parse_complex_event_pattern() is None

    p3 = EnhancedYaraLParser("")
    _set_tokens(p3, [_tok(T.IDENTIFIER, "any")])
    assert p3._parse_complex_event_pattern() is None

    p4 = EnhancedYaraLParser("")
    _set_tokens(p4, [_tok(T.IDENTIFIER, "evt"), _tok(T.IDENTIFIER, "followed")])
    assert p4._parse_complex_event_pattern() is None


def test_parse_events_section_real() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "events"),
            _tok(T.COLON, ":"),
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "event_type"),
            _tok(T.EQ, "="),
            _tok(T.STRING, "LOGIN"),
            _tok(T.IDENTIFIER, "join"),
            _tok(T.IDENTIFIER, "e1"),
            _tok(T.IDENTIFIER, "on"),
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "with"),
            _tok(T.IDENTIFIER, "e2"),
            _tok(T.RBRACE, "}"),
        ],
    )
    section = p._parse_events_section()
    assert section.statements
