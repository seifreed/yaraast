from __future__ import annotations

import pytest

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral._shared import YaraLParserError
from yaraast.yaral.ast_nodes import ConditionalExpression, RegexPattern, UDMFieldAccess
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.parser import YaraLParser
from yaraast.yaral.tokens import YaraLTokenType


def _tok(token_type: T, value: object, yaral_type: YaraLTokenType | None = None) -> YaraLToken:
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


def test_parse_outcome_argument_basic_if_and_grouped_expression() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "if"),
            _tok(T.LPAREN, "("),
            _tok(T.STRING_IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.EQ, "="),
            _tok(T.INTEGER, "1"),
            _tok(T.COMMA, ","),
            _tok(T.STRING, "yes"),
            _tok(T.RPAREN, ")"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )

    expr = parser._parse_outcome_argument_basic()
    assert isinstance(expr, ConditionalExpression)
    assert expr.true_value == "yes"

    parser2 = YaraLParser("")
    _set_tokens(
        parser2,
        [
            _tok(T.LPAREN, "("),
            _tok(T.INTEGER, "1"),
            _tok(T.PLUS, "+"),
            _tok(T.INTEGER, "2"),
            _tok(T.RPAREN, ")"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    assert parser2._parse_outcome_argument_basic() == "(1 + 2)"


def test_parse_outcome_argument_basic_identifier_call_and_error() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "func"),
            _tok(T.LPAREN, "("),
            _tok(T.INTEGER, "1"),
            _tok(T.COMMA, ","),
            _tok(T.STRING, "x"),
            _tok(T.RPAREN, ")"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )

    assert parser._parse_outcome_argument_basic() == "func(1, x)"

    parser_ident = YaraLParser("")
    _set_tokens(
        parser_ident, [_tok(T.IDENTIFIER, "plain_ident"), _tok(T.EOF, None, YaraLTokenType.EOF)]
    )
    assert parser_ident._parse_outcome_argument_basic() == "plain_ident"

    parser_empty_call = YaraLParser("")
    _set_tokens(
        parser_empty_call,
        [
            _tok(T.IDENTIFIER, "empty"),
            _tok(T.LPAREN, "("),
            _tok(T.RPAREN, ")"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    assert parser_empty_call._parse_outcome_argument_basic() == "empty()"

    parser2 = YaraLParser("")
    _set_tokens(parser2, [_tok(T.RBRACE, "}"), _tok(T.EOF, None, YaraLTokenType.EOF)])
    with pytest.raises(YaraLParserError, match="Unexpected token in outcome"):
        parser2._parse_outcome_argument_basic()


def test_parse_outcome_argument_event_field_comparison_and_field_access() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "event_type"),
            _tok(T.EQ, "="),
            _tok(T.STRING, "LOGIN"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    assert parser._parse_outcome_argument() == "$e.metadata.event_type = LOGIN"

    parser2 = YaraLParser("")
    _set_tokens(
        parser2,
        [
            _tok(T.STRING_IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "principal"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "ip"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    field_access = parser2._parse_outcome_argument()
    assert isinstance(field_access, UDMFieldAccess)
    assert field_access.full_path == "$e.principal.ip"


def test_parse_outcome_argument_identifier_call_ops_regex_and_error() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "sum"),
            _tok(T.LPAREN, "("),
            _tok(T.INTEGER, "1"),
            _tok(T.COMMA, ","),
            _tok(T.INTEGER, "2"),
            _tok(T.RPAREN, ")"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    assert parser._parse_outcome_argument() == "sum(1, 2)"

    parser_ident = YaraLParser("")
    _set_tokens(parser_ident, [_tok(T.IDENTIFIER, "score"), _tok(T.EOF, None, YaraLTokenType.EOF)])
    assert parser_ident._parse_outcome_argument() == "score"

    parser_empty_call = YaraLParser("")
    _set_tokens(
        parser_empty_call,
        [
            _tok(T.IDENTIFIER, "noop"),
            _tok(T.LPAREN, "("),
            _tok(T.RPAREN, ")"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    assert parser_empty_call._parse_outcome_argument() == "noop()"

    parser2 = YaraLParser("")
    _set_tokens(
        parser2,
        [
            _tok(T.IDENTIFIER, "score"),
            _tok(T.PLUS, "+"),
            _tok(T.INTEGER, "1"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    assert parser2._parse_outcome_argument() == "score + 1"

    parser3 = YaraLParser("")
    _set_tokens(parser3, [_tok(T.REGEX, "foo.*bar"), _tok(T.EOF, None, YaraLTokenType.EOF)])
    regex = parser3._parse_outcome_argument()
    assert isinstance(regex, RegexPattern)
    assert regex.pattern == "foo.*bar"

    parser4 = YaraLParser("")
    _set_tokens(parser4, [_tok(T.RBRACKET, "]"), _tok(T.EOF, None, YaraLTokenType.EOF)])
    with pytest.raises(YaraLParserError, match="Unexpected token in outcome"):
        parser4._parse_outcome_argument()


def test_parse_outcome_field_path_supports_dot_and_bracket_forms() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.LBRACKET, "["),
            _tok(T.STRING, "labels"),
            _tok(T.RBRACKET, "]"),
            _tok(T.LBRACKET, "["),
            _tok(T.INTEGER, "0"),
            _tok(T.RBRACKET, "]"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    assert parser._parse_outcome_field_path() == [
        "metadata",
        '["labels"]',
        "[0]",
    ]

    parser2 = YaraLParser("")
    _set_tokens(
        parser2,
        [
            _tok(T.IDENTIFIER, "network"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "connections"),
            _tok(T.LBRACKET, "["),
            _tok(T.INTEGER, "2"),
            _tok(T.RBRACKET, "]"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    assert parser2._parse_outcome_field_path() == [
        "network",
        "connections",
        "[2]",
    ]

    parser3 = YaraLParser("")
    _set_tokens(
        parser3,
        [
            _tok(T.IDENTIFIER, "principal"),
            _tok(T.DOT, "."),
            _tok(T.LBRACKET, "["),
            _tok(T.INTEGER, "7"),
            _tok(T.RBRACKET, "]"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    assert parser3._parse_outcome_field_path() == ["principal", "[7]"]

    parser4 = YaraLParser("")
    _set_tokens(
        parser4,
        [
            _tok(T.IDENTIFIER, "meta"),
            _tok(T.LBRACKET, "["),
            _tok(T.STRING, "key"),
            _tok(T.RBRACKET, "]"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    assert parser4._parse_outcome_field_path() == ["meta", '["key"]']


def test_check_any_operator_variants() -> None:
    parser = YaraLParser("")
    _set_tokens(parser, [_tok(T.IN, "in"), _tok(T.EOF, None, YaraLTokenType.EOF)])
    assert parser._check_any_operator()
    assert not parser._check_any_operator(arithmetic_only=True)

    parser2 = YaraLParser("")
    _set_tokens(parser2, [_tok(T.MULTIPLY, "*"), _tok(T.EOF, None, YaraLTokenType.EOF)])
    assert parser2._check_any_operator()
    assert parser2._check_any_operator(arithmetic_only=True)
