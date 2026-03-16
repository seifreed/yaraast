from __future__ import annotations

import pytest

from yaraast.ast.rules import Rule
from yaraast.lexer.tokens import Token, TokenType
from yaraast.parser.comment_aware_parser import CommentAwareParser
from yaraast.yaral._shared import YaraLParserError
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.parser import YaraLParser
from yaraast.yaral.tokens import YaraLTokenType


def _t(tt: TokenType, value, line: int, col: int = 1) -> Token:
    return Token(type=tt, value=value, line=line, column=col)


def _yt(
    token_type: TokenType,
    value: object,
    line: int = 1,
    yaral_type: YaraLTokenType | None = None,
) -> YaraLToken:
    return YaraLToken(
        type=token_type,
        value=value,
        line=line,
        column=1,
        length=1,
        yaral_type=yaral_type,
    )


def test_consume_keyword_uses_default_message_when_missing() -> None:
    parser = YaraLParser("")
    parser.tokens = [
        _yt(TokenType.IDENTIFIER, "not_events"),
        _yt(TokenType.EOF, None, yaral_type=YaraLTokenType.EOF),
    ]
    parser.current = 0

    with pytest.raises(YaraLParserError, match="Expected 'events'"):
        parser._consume_keyword("events")


def test_comment_aware_rule_modifiers_tags_and_trailing_comment_paths() -> None:
    parser = CommentAwareParser()

    parser.tokens = [
        _t(TokenType.PRIVATE, "private", 1),
        _t(TokenType.GLOBAL, "global", 1),
        _t(TokenType.RULE, "rule", 1),
        _t(TokenType.IDENTIFIER, "sample", 1),
        _t(TokenType.COLON, ":", 1),
        _t(TokenType.IDENTIFIER, "tag1", 1),
        _t(TokenType.IDENTIFIER, "tag2", 1),
        _t(TokenType.EOF, "", 1),
    ]
    parser.comment_tokens = [_t(TokenType.COMMENT, "// trailing", 1, 20)]
    parser.current = 0

    assert parser._parse_rule_modifiers_with_comments() == ["private", "global"]
    assert parser._parse_rule_name_with_comments() == "sample"

    tags = parser._parse_rule_tags_with_comments()
    assert [tag.name for tag in tags] == ["tag1", "tag2"]

    rule = Rule(name="inline")
    parser._attach_rule_comments(rule, [], _t(TokenType.RULE, "rule", 1))
    assert rule.trailing_comment is not None
    assert "trailing" in rule.trailing_comment.text


def test_comment_aware_string_modifiers_support_nested_xor_parentheses() -> None:
    parser = CommentAwareParser()
    parser.tokens = [
        _t(TokenType.XOR_MOD, "xor", 1),
        _t(TokenType.LPAREN, "(", 1),
        _t(TokenType.INTEGER, "1", 1),
        _t(TokenType.COMMA, ",", 1),
        _t(TokenType.LPAREN, "(", 1),
        _t(TokenType.INTEGER, "2", 1),
        _t(TokenType.RPAREN, ")", 1),
        _t(TokenType.RPAREN, ")", 1),
        _t(TokenType.EOF, "", 1),
    ]
    parser.current = 0

    modifiers = parser._parse_string_modifiers()
    assert len(modifiers) == 1
    assert getattr(modifiers[0], "name", "") == "xor"


def test_parse_event_statement_assignment_with_literal_rhs_returns_generic_statement() -> None:
    parser = YaraLParser("")
    parser.tokens = [
        _yt(TokenType.STRING_IDENTIFIER, "$var", yaral_type=YaraLTokenType.EVENT_VAR),
        _yt(TokenType.EQ, "="),
        _yt(TokenType.STRING, "literal"),
        _yt(TokenType.EOF, None, yaral_type=YaraLTokenType.EOF),
    ]
    parser.current = 0

    stmt = parser._parse_event_statement()

    assert stmt is not None
    assert parser.current == 2
