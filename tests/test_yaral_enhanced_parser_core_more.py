from __future__ import annotations

import pytest

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral.enhanced_parser import EnhancedYaraLParser
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.tokens import YaraLTokenType


def _tok(tt: T, value, yt: YaraLTokenType | None = None) -> YaraLToken:
    return YaraLToken(type=tt, value=value, line=1, column=1, length=1, yaral_type=yt)


def _set_tokens(p: EnhancedYaraLParser, toks: list[YaraLToken]) -> None:
    p.tokens = toks
    p.current = 0


def test_enhanced_parser_keyword_type_peek_and_check_helpers() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.META, "meta"),
            _tok(T.CONDITION, "condition"),
            _tok(T.AND, "and"),
            _tok(T.OR, "or"),
            _tok(T.NOT, "not"),
            _tok(T.IN, "in"),
            _tok(T.IDENTIFIER, "rule"),
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )

    assert p._check_keyword("meta")
    p._advance()
    assert p._check_keyword("condition")
    p._advance()
    assert p._check_keyword("and")
    p._advance()
    assert p._check_keyword("or")
    p._advance()
    assert p._check_keyword("not")
    p._advance()
    assert p._check_keyword("in")
    p._advance()
    assert p._check_keyword("rule")
    assert p._peek().value == "rule"
    assert p._peek_ahead(1).value == "$e"
    assert p._peek_ahead(10) is None
    assert p._check(T.IDENTIFIER)
    p._advance()
    assert p._check_yaral_type(YaraLTokenType.EVENT_VAR)
    assert not p._check_yaral_type(YaraLTokenType.TIME_LITERAL)


def test_enhanced_parser_consume_error_recover_and_parse_skip() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(p, [_tok(T.IDENTIFIER, "rule"), _tok(T.EOF, None, YaraLTokenType.EOF)])
    assert p._consume_keyword("rule").value == "rule"

    p2 = EnhancedYaraLParser("")
    _set_tokens(p2, [_tok(T.IDENTIFIER, "nope"), _tok(T.EOF, None, YaraLTokenType.EOF)])
    with pytest.raises(ValueError, match="Expected keyword 'rule'"):
        p2._consume_keyword("rule")

    err = p2._error("boom")
    assert "Parser error at 1:1: boom" in str(err)

    p3 = EnhancedYaraLParser("")
    _set_tokens(p3, [_tok(T.EOF, None, YaraLTokenType.EOF)])
    assert "Parser error: eof" in str(p3._error("eof"))
    assert p3._is_at_end()
    assert not p3._check_keyword("rule")
    assert not p3._check_yaral_type(YaraLTokenType.EVENT_VAR)
    assert not p3._check(T.IDENTIFIER)
    assert p3._peek().type == T.EOF

    p4 = EnhancedYaraLParser("")
    _set_tokens(
        p4,
        [
            _tok(T.PLUS, "+"),
            _tok(T.IDENTIFIER, "junk"),
            _tok(T.IDENTIFIER, "rule"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    p4._recover_to_next_rule()
    assert p4._peek().value == "rule"

    p5 = EnhancedYaraLParser("")
    _set_tokens(
        p5,
        [
            _tok(T.PLUS, "+"),
            _tok(T.IDENTIFIER, "rule"),
            _tok(T.IDENTIFIER, "x"),
            _tok(T.LBRACE, "{"),
            _tok(T.RBRACE, "}"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    ast = p5.parse()
    assert len(ast.rules) == 1
    assert ast.rules[0].name == "x"


def test_enhanced_parser_advance_at_end_returns_last_token() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(p, [_tok(T.EOF, None, YaraLTokenType.EOF)])
    tok = p._advance()
    assert tok.type == T.EOF
