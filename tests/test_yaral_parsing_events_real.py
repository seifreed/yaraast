from __future__ import annotations

import pytest

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral._shared import YaraLParserError
from yaraast.yaral.ast_nodes import EventStatement, ReferenceList, RegexPattern
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.parser import YaraLParser
from yaraast.yaral.tokens import YaraLTokenType


def _tok(
    token_type: T,
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


def _set_tokens(parser: YaraLParser, tokens: list[YaraLToken]) -> None:
    parser.tokens = tokens
    parser.current = 0


def test_parse_event_operator_raises_on_invalid_token_stream() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser, [_tok(T.IDENTIFIER, "bad"), _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF)]
    )

    with pytest.raises(YaraLParserError, match="Expected operator"):
        parser._parse_event_operator()


def test_parse_field_path_missing_bracket_raises() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.LBRACKET, "["),
            _tok(T.STRING, "event_type"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    with pytest.raises(YaraLParserError, match="Expected ']'"):
        parser._parse_field_path()


def test_parse_events_section_terminates_on_eof_guard() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "events"),
            _tok(T.COLON, ":"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    events = parser._parse_events_section()

    assert events.statements == []


def test_parse_event_statement_requires_dot_after_event_var() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$e", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    with pytest.raises(YaraLParserError, match="Expected '.' after event variable"):
        parser._parse_event_statement()


def test_parse_event_value_supports_reference_lists_and_regex() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "%blocked_ips%", yaral_type=YaraLTokenType.REFERENCE_LIST),
            _tok(T.REGEX, "foo.*bar"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    ref_value = parser._parse_event_value()
    regex_value = parser._parse_event_value()

    assert isinstance(ref_value, ReferenceList)
    assert ref_value.name == "%blocked_ips%"
    assert isinstance(regex_value, RegexPattern)
    assert regex_value.pattern == "foo.*bar"


def test_parse_function_call_statement_consumes_assignment_and_nocase() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "re.regex"),
            _tok(T.LPAREN, "("),
            _tok(T.STRING_IDENTIFIER, "$e", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.RPAREN, ")"),
            _tok(T.EQ, "="),
            _tok(T.STRING_IDENTIFIER, "$match", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "nocase"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    stmt = parser._parse_function_call_statement()

    assert isinstance(stmt, EventStatement)
    assert parser.current == 9


def test_parse_event_statement_integer_comparison_stops_at_new_statement() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.INTEGER, "604800", line=1),
            _tok(T.LE, "<=", line=1),
            _tok(T.STRING_IDENTIFIER, "$left", line=1, yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, ".", line=1),
            _tok(T.IDENTIFIER, "metadata", line=1),
            _tok(T.STRING_IDENTIFIER, "$next", line=2, yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.EQ, "=", line=2),
            _tok(T.STRING, "x", line=2),
            _tok(T.EOF, None, line=2, yaral_type=YaraLTokenType.EOF),
        ],
    )

    stmt = parser._parse_event_statement()

    assert isinstance(stmt, EventStatement)
    assert parser._peek().value == "$next"


def test_parse_event_statement_assignment_rhs_event_field_stops_on_new_assignment() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$var", line=1, yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.EQ, "=", line=1),
            _tok(T.STRING_IDENTIFIER, "$e", line=1, yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, ".", line=1),
            _tok(T.IDENTIFIER, "principal", line=1),
            _tok(T.DOT, ".", line=1),
            _tok(T.IDENTIFIER, "ip", line=1),
            _tok(T.STRING_IDENTIFIER, "$next", line=2, yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.EQ, "=", line=2),
            _tok(T.STRING, "value", line=2),
            _tok(T.EOF, None, line=2, yaral_type=YaraLTokenType.EOF),
        ],
    )

    stmt = parser._parse_event_statement()

    assert isinstance(stmt, EventStatement)
    assert parser._peek().value == "$next"


def test_parse_field_path_with_dot_bracket_and_direct_bracket_forms() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.LBRACKET, "["),
            _tok(T.STRING, "event_type"),
            _tok(T.RBRACKET, "]"),
            _tok(T.LBRACKET, "["),
            _tok(T.INTEGER, "0"),
            _tok(T.RBRACKET, "]"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    path = parser._parse_field_path()
    assert path.parts == ["metadata", '["event_type"]', "[0]"]


def test_parse_function_and_boolean_expressions_with_nested_parentheses() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "re"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "regex"),
            _tok(T.LPAREN, "("),
            _tok(T.LPAREN, "("),
            _tok(T.STRING_IDENTIFIER, "$e", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.RPAREN, ")"),
            _tok(T.RPAREN, ")"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    func_stmt = parser._parse_function_call_statement()
    assert isinstance(func_stmt, EventStatement)


def test_parse_event_statement_identifier_function_call_path() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "re.regex"),
            _tok(T.LPAREN, "("),
            _tok(T.STRING_IDENTIFIER, "$e", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.RPAREN, ")"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    stmt = parser._parse_event_statement()

    assert isinstance(stmt, EventStatement)


def test_parse_event_statement_assignment_function_call_path() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$x", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.EQ, "="),
            _tok(T.IDENTIFIER, "re.regex"),
            _tok(T.LPAREN, "("),
            _tok(T.STRING_IDENTIFIER, "$e", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.RPAREN, ")"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    stmt = parser._parse_event_statement()

    assert isinstance(stmt, EventStatement)


def test_parse_event_statement_integer_comparison_stops_on_section_keyword() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.INTEGER, "1", line=1),
            _tok(T.LE, "<=", line=1),
            _tok(T.STRING_IDENTIFIER, "$e", line=1, yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "match", line=2),
            _tok(T.COLON, ":", line=2),
            _tok(T.EOF, None, line=2, yaral_type=YaraLTokenType.EOF),
        ],
    )

    stmt = parser._parse_event_statement()

    assert isinstance(stmt, EventStatement)
    assert parser._peek().value == "match"


def test_parse_event_statement_assignment_rhs_stops_on_section_keyword() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$var", line=1, yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.EQ, "=", line=1),
            _tok(T.STRING_IDENTIFIER, "$e", line=1, yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, ".", line=1),
            _tok(T.IDENTIFIER, "principal", line=1),
            _tok(T.IDENTIFIER, "condition", line=2),
            _tok(T.COLON, ":", line=2),
            _tok(T.EOF, None, line=2, yaral_type=YaraLTokenType.EOF),
        ],
    )

    stmt = parser._parse_event_statement()

    assert isinstance(stmt, EventStatement)
    assert parser._peek().value == "condition"


def test_parse_event_statement_comparison_advances_rhs() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$left", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.NEQ, "!="),
            _tok(T.STRING_IDENTIFIER, "$right", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    stmt = parser._parse_event_statement()

    assert isinstance(stmt, EventStatement)
    assert parser.current == 3


def test_parse_event_statement_field_access_followed_by_section_keyword_returns_generic_statement() -> (
    None
):
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$e", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.IDENTIFIER, "match"),
            _tok(T.COLON, ":"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    stmt = parser._parse_event_statement()

    assert isinstance(stmt, EventStatement)
    assert parser._peek().value == "match"


def test_parse_event_operator_regex_and_integer_value_paths() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "regex"),
            _tok(T.INTEGER, "42"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    assert parser._parse_event_operator() == "regex"
    assert parser._parse_event_value() == 42

    parser2 = YaraLParser("")
    _set_tokens(
        parser2,
        [
            _tok(T.LPAREN, "("),
            _tok(T.LPAREN, "("),
            _tok(T.STRING_IDENTIFIER, "$e", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.RPAREN, ")"),
            _tok(T.RPAREN, ")"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    bool_stmt = parser2._parse_boolean_expression()
    assert isinstance(bool_stmt, EventStatement)


def test_parse_event_statement_integer_without_operator_returns_generic_statement() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.INTEGER, "10"),
            _tok(T.IDENTIFIER, "oops"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    stmt = parser._parse_event_statement()
    assert isinstance(stmt, EventStatement)


def test_parse_event_statement_operator_without_rhs_advances_safely() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$e", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.NEQ, "!="),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    stmt = parser._parse_event_statement()
    assert isinstance(stmt, EventStatement)


def test_parse_field_path_plain_dot_and_numeric_indexes() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "event_type"),
            _tok(T.DOT, "."),
            _tok(T.LBRACKET, "["),
            _tok(T.INTEGER, "2"),
            _tok(T.RBRACKET, "]"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    path = parser._parse_field_path()
    assert path.parts == ["metadata", "event_type", "[2]"]


def test_parse_event_value_fallback_identifier_value() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [_tok(T.IDENTIFIER, "literal_value"), _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF)],
    )

    value = parser._parse_event_value()
    assert value == "literal_value"


def test_parse_function_and_boolean_expressions_handle_unbalanced_input() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "re"),
            _tok(T.DOT, "."),
            _tok(T.LPAREN, "("),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    stmt = parser._parse_function_call_statement()
    assert isinstance(stmt, EventStatement)

    parser2 = YaraLParser("")
    _set_tokens(parser2, [_tok(T.LPAREN, "("), _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF)])
    stmt2 = parser2._parse_boolean_expression()
    assert isinstance(stmt2, EventStatement)
