from __future__ import annotations

import pytest

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral._shared import YaraLParserError
from yaraast.yaral.ast_nodes import (
    BinaryCondition,
    EventCountCondition,
    EventExistsCondition,
    UnaryCondition,
    VariableComparisonCondition,
)
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.parser import YaraLParser
from yaraast.yaral.tokens import YaraLTokenType


def _tok(
    token_type: T, value: object, line: int = 1, yaral_type: YaraLTokenType | None = None
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


def test_parse_condition_section_and_boolean_precedence() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "condition"),
            _tok(T.COLON, ":"),
            _tok(T.IDENTIFIER, "not"),
            _tok(T.STRING_IDENTIFIER, "$e1", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "and"),
            _tok(T.STRING_IDENTIFIER, "$e2", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "or"),
            _tok(T.STRING_IDENTIFIER, "$e3", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    section = parser._parse_condition_section()
    assert isinstance(section.expression, BinaryCondition)
    assert isinstance(section.expression.left, BinaryCondition)
    assert isinstance(section.expression.left.left, UnaryCondition)


def test_parse_primary_condition_count_and_comparison_variants() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_COUNT, "#"),
            _tok(T.IDENTIFIER, "e"),
            _tok(T.EQ, "=="),
            _tok(T.INTEGER, "5"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    cond = parser._parse_primary_condition()
    assert isinstance(cond, EventCountCondition)
    assert cond.operator == "=="

    parser2 = YaraLParser("")
    _set_tokens(
        parser2,
        [
            _tok(T.STRING_IDENTIFIER, "$v", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.GE, ">="),
            _tok(T.IDENTIFIER, "other"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    cmp_cond = parser2._parse_primary_condition()
    assert isinstance(cmp_cond, VariableComparisonCondition)
    assert cmp_cond.operator == ">="

    parser3 = YaraLParser("")
    _set_tokens(
        parser3,
        [
            _tok(T.STRING_IDENTIFIER, "$exists", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    exists = parser3._parse_primary_condition()
    assert isinstance(exists, EventExistsCondition)
    assert exists.event == "exists"


def test_parse_primary_condition_identifier_fallback_and_errors() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "ev"),
            _tok(T.NEQ, "!="),
            _tok(T.STRING, "x"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    cond = parser._parse_primary_condition()
    assert isinstance(cond, VariableComparisonCondition)
    assert cond.operator == "!="

    parser2 = YaraLParser("")
    _set_tokens(
        parser2, [_tok(T.IDENTIFIER, "only_name"), _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF)]
    )
    exists = parser2._parse_primary_condition()
    assert isinstance(exists, EventExistsCondition)
    assert exists.event == "only_name"

    parser3 = YaraLParser("")
    _set_tokens(
        parser3,
        [
            _tok(T.STRING_COUNT, "#"),
            _tok(T.IDENTIFIER, "e"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    with pytest.raises(YaraLParserError, match="Expected comparison operator"):
        parser3._parse_primary_condition()

    parser4 = YaraLParser("")
    _set_tokens(
        parser4,
        [
            _tok(T.STRING_IDENTIFIER, "$e", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.LT, "<"),
            _tok(T.RPAREN, ")"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    with pytest.raises(YaraLParserError, match="Expected value after comparison operator"):
        parser4._parse_primary_condition()

    parser5 = YaraLParser("")
    _set_tokens(parser5, [_tok(T.RBRACE, "}"), _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF)])
    with pytest.raises(YaraLParserError, match="Unexpected token in condition"):
        parser5._parse_primary_condition()


@pytest.mark.parametrize(
    ("operator_token", "expected_operator"),
    [
        (T.NEQ, "!="),
        (T.LE, "<="),
        (T.EQ, "=="),
    ],
)
def test_parse_primary_condition_count_comparison_operator_variants(
    operator_token: T,
    expected_operator: str,
) -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_COUNT, "#"),
            _tok(T.IDENTIFIER, "evt"),
            _tok(operator_token, expected_operator),
            _tok(T.INTEGER, "2"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    cond = parser._parse_primary_condition()
    assert isinstance(cond, EventCountCondition)
    assert cond.operator == expected_operator


@pytest.mark.parametrize(
    ("operator_token", "expected_operator", "value_token", "value", "yaral_type"),
    [
        (T.EQ, "==", T.STRING, "abc", None),
        (T.NEQ, "!=", T.STRING_IDENTIFIER, "$other", None),
        (T.LE, "<=", T.IDENTIFIER, "field_name", None),
        (T.NEQ, "!=", T.STRING_IDENTIFIER, "$peer", YaraLTokenType.EVENT_VAR),
    ],
)
def test_parse_primary_condition_variable_comparison_variants(
    operator_token: T,
    expected_operator: str,
    value_token: T,
    value: object,
    yaral_type: YaraLTokenType | None,
) -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$value", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(operator_token, expected_operator),
            _tok(value_token, value, yaral_type=yaral_type),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    cond = parser._parse_primary_condition()
    assert isinstance(cond, VariableComparisonCondition)
    assert cond.operator == expected_operator
    assert cond.value == value


@pytest.mark.parametrize(
    ("operator_token", "expected_operator", "value_token", "value", "yaral_type"),
    [
        (T.LT, "<", T.INTEGER, "7", None),
        (T.GE, ">=", T.STRING, "x", None),
        (T.LE, "<=", T.IDENTIFIER, "user", None),
        (T.EQ, "==", T.STRING_IDENTIFIER, "$peer", YaraLTokenType.EVENT_VAR),
        (T.NEQ, "!=", T.STRING_IDENTIFIER, "$peer", None),
    ],
)
def test_parse_primary_condition_identifier_fallback_operator_variants(
    operator_token: T,
    expected_operator: str,
    value_token: T,
    value: object,
    yaral_type: YaraLTokenType | None,
) -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "field"),
            _tok(operator_token, expected_operator),
            _tok(value_token, value, yaral_type=yaral_type),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    cond = parser._parse_primary_condition()
    assert isinstance(cond, VariableComparisonCondition)
    assert cond.operator == expected_operator


def test_parse_primary_condition_identifier_missing_value_error() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "field"),
            _tok(T.NEQ, "!="),
            _tok(T.RPAREN, ")"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    with pytest.raises(YaraLParserError, match="Expected value after comparison operator"):
        parser._parse_primary_condition()


def test_parse_primary_condition_explicit_neq_branches_for_var_and_identifier() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$field"),
            _tok(T.NEQ, "!="),
            _tok(T.INTEGER, "9"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    cond = parser._parse_primary_condition()
    assert isinstance(cond, VariableComparisonCondition)
    assert cond.variable == "$field"
    assert cond.operator == "!="
    assert cond.value == 9

    parser2 = YaraLParser("")
    _set_tokens(
        parser2,
        [
            _tok(T.IDENTIFIER, "field"),
            _tok(T.NEQ, "!="),
            _tok(T.INTEGER, "11"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    cond2 = parser2._parse_primary_condition()
    assert isinstance(cond2, VariableComparisonCondition)
    assert cond2.variable == "field"
    assert cond2.operator == "!="
    assert cond2.value == 11


def test_parse_primary_condition_parenthesized_expression() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.LPAREN, "("),
            _tok(T.STRING_IDENTIFIER, "$e1", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "and"),
            _tok(T.STRING_IDENTIFIER, "$e2", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.RPAREN, ")"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    cond = parser._parse_primary_condition()
    assert isinstance(cond, BinaryCondition)


@pytest.mark.parametrize(
    ("operator_token", "expected_operator"),
    [
        (T.GT, ">"),
        (T.LT, "<"),
        (T.GE, ">="),
    ],
)
def test_parse_primary_condition_count_remaining_operator_variants(
    operator_token: T,
    expected_operator: str,
) -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_COUNT, "#"),
            _tok(T.IDENTIFIER, "evt"),
            _tok(operator_token, expected_operator),
            _tok(T.INTEGER, "9"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    cond = parser._parse_primary_condition()
    assert isinstance(cond, EventCountCondition)
    assert cond.operator == expected_operator


def test_parse_primary_condition_variable_gt_integer_and_fallback_gt() -> None:
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$metric", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.GT, ">"),
            _tok(T.INTEGER, "3"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    cond = parser._parse_primary_condition()
    assert isinstance(cond, VariableComparisonCondition)
    assert cond.operator == ">"
    assert cond.value == 3

    parser2 = YaraLParser("")
    _set_tokens(
        parser2,
        [
            _tok(T.IDENTIFIER, "count"),
            _tok(T.GT, ">"),
            _tok(T.INTEGER, "1"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    cond2 = parser2._parse_primary_condition()
    assert isinstance(cond2, VariableComparisonCondition)
    assert cond2.operator == ">"
    assert cond2.value == 1
