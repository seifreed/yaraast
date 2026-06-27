from __future__ import annotations

import pytest

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral._shared import YaraLParserError
from yaraast.yaral.ast_nodes import (
    ConditionalExpression,
    FunctionCall,
    RegexPattern,
    UDMFieldAccess,
)
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


def test_parenthesized_two_argument_outcome_if_roundtrips_without_none() -> None:
    parser = YaraLParser("""
        rule parenthesized_if {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $result = (if($e.metadata.event_type = "LOGIN", "yes"))
          condition:
            $e
        }
        """)

    generated = YaraLGenerator().generate(parser.parse())

    assert '$result = (if($e.metadata.event_type = "LOGIN", "yes"))' in generated
    assert "None" not in generated


def test_parenthesized_outcome_function_arguments_roundtrip_as_expressions() -> None:
    parser = YaraLParser("""
        rule parenthesized_function_args {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $result = string_concat((if($e.metadata.event_type = "LOGIN", "yes")), "tail")
            $fallback = if($e.metadata.event_type = "LOGIN", (string_concat("a", "b")))
            $literal = string_concat("(literal)", "tail")
          condition:
            $e
        }
        """)

    generated = YaraLGenerator().generate(parser.parse())

    assert 'string_concat((if($e.metadata.event_type = "LOGIN", "yes")), "tail")' in generated
    assert (
        '$fallback = if($e.metadata.event_type = "LOGIN", (string_concat("a", "b")))' in generated
    )
    assert '$literal = string_concat("(literal)", "tail")' in generated


def test_outcome_function_arguments_accept_double_literals_without_keyword_crash() -> None:
    parser = YaraLParser("""
        rule double_arg {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $result = string_concat("a", 1, 2.5)
          condition:
            $e
        }
        """)

    generated = YaraLGenerator().generate(parser.parse())

    assert '$result = string_concat("a", 1, 2.5)' in generated


def test_outcome_boolean_literals_roundtrip_in_values_and_arguments() -> None:
    parser = YaraLParser("""
        rule outcome_booleans {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $direct = true
            $func = string_concat("a", true, false)
            $conditional = if($e.metadata.event_type = "LOGIN", true, false)
          condition:
            $e
        }
        """)

    generated = YaraLGenerator().generate(parser.parse())

    assert "$direct = true" in generated
    assert '$func = string_concat("a", true, false)' in generated
    assert '$conditional = if($e.metadata.event_type = "LOGIN", true, false)' in generated


def test_outcome_condition_double_equals_roundtrips() -> None:
    parser = YaraLParser("""
        rule outcome_double_equals {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $score = count($e.principal.ip)
            $label = if($score == 1, "one", "many")
            $host = if($e.target.hostname == "admin", "admin", "other")
          condition:
            $score > 0
        }
        """)

    generated = YaraLGenerator().generate(parser.parse())

    assert '$label = if($score == 1, "one", "many")' in generated
    assert '$host = if($e.target.hostname == "admin", "admin", "other")' in generated


def test_outcome_condition_membership_and_regex_operators_roundtrip() -> None:
    parser = YaraLParser("""
        rule outcome_condition_operators {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $allowed = if($e.principal.ip not in %blocked%, "yes", "no")
            $match = if($e.target.hostname matches /admin.*/, "yes", "no")
            $not_match = if($e.target.hostname not matches /admin.*/, "yes", "no")
            $regex_match = if($e.target.hostname =~ /admin.*/, "yes", "no")
            $regex_not_match = if($e.target.hostname !~ /admin.*/, "yes", "no")
          condition:
            $e
        }
        """)

    generated = YaraLGenerator().generate(parser.parse())

    assert '$allowed = if($e.principal.ip not in %blocked%, "yes", "no")' in generated
    assert '$match = if($e.target.hostname =~ /admin.*/, "yes", "no")' in generated
    assert '$not_match = if($e.target.hostname !~ /admin.*/, "yes", "no")' in generated
    assert '$regex_match = if($e.target.hostname =~ /admin.*/, "yes", "no")' in generated
    assert '$regex_not_match = if($e.target.hostname !~ /admin.*/, "yes", "no")' in generated


def test_outcome_direct_boolean_expressions_roundtrip() -> None:
    parser = YaraLParser("""
        rule direct_outcome_conditions {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $allowed = $e.principal.ip not in %blocked%
            $match = $e.target.hostname matches /admin.*/
            $not_match = $e.target.hostname not matches /admin.*/
            $regex_match = $e.target.hostname =~ /admin.*/
            $nocase_match = $e.target.hostname matches /admin.*/ nocase
            $nocase_not_match = $e.target.hostname not matches /admin.*/ nocase
            $func_arg = custom($e.target.hostname matches /admin.*/, "x")
            $nocase_func_arg = custom($e.target.hostname matches /admin.*/ nocase, "x")
            $and_chain = $e.target.hostname matches /admin.*/ and $e.principal.ip not in %blocked%
            $nocase_and_chain = $e.target.hostname matches /admin.*/ nocase and $e.principal.ip not in %blocked%
            $or_chain = $e.target.hostname matches /admin.*/ or $e.principal.ip not in %blocked%
            $function_compare = strings.to_lower($e.target.hostname) = "admin"
            $function_arg_compare = custom(strings.to_lower($e.target.hostname) = "admin", "x")
            $function_chain = strings.to_lower($e.target.hostname) = "admin" and $e.principal.ip not in %blocked%
            $aggregation_compare = count($e.principal.ip) > 1
            $aggregation_arg_compare = custom(count($e.principal.ip) > 1, "x")
            $negated = not $e.target.hostname matches /admin.*/
            $grouped = ($e.target.hostname matches /admin.*/ and $e.principal.ip not in %blocked%)
          condition:
            $e
        }
        """)

    generated = YaraLGenerator().generate(parser.parse())

    assert "$allowed = $e.principal.ip not in %blocked%" in generated
    assert "$match = $e.target.hostname =~ /admin.*/" in generated
    assert "$not_match = $e.target.hostname !~ /admin.*/" in generated
    assert "$regex_match = $e.target.hostname =~ /admin.*/" in generated
    assert "$nocase_match = $e.target.hostname =~ /admin.*/ nocase" in generated
    assert "$nocase_not_match = $e.target.hostname !~ /admin.*/ nocase" in generated
    assert '$func_arg = custom($e.target.hostname =~ /admin.*/, "x")' in generated
    assert '$nocase_func_arg = custom($e.target.hostname =~ /admin.*/ nocase, "x")' in generated
    assert (
        "$and_chain = $e.target.hostname =~ /admin.*/ and $e.principal.ip not in %blocked%"
        in generated
    )
    assert (
        "$nocase_and_chain = "
        "$e.target.hostname =~ /admin.*/ nocase and $e.principal.ip not in %blocked%" in generated
    )
    assert (
        "$or_chain = $e.target.hostname =~ /admin.*/ or $e.principal.ip not in %blocked%"
        in generated
    )
    assert '$function_compare = strings.to_lower($e.target.hostname) = "admin"' in generated
    assert (
        '$function_arg_compare = custom(strings.to_lower($e.target.hostname) = "admin", "x")'
        in generated
    )
    assert (
        '$function_chain = strings.to_lower($e.target.hostname) = "admin" '
        "and $e.principal.ip not in %blocked%" in generated
    )
    assert "$aggregation_compare = count($e.principal.ip) > 1" in generated
    assert '$aggregation_arg_compare = custom(count($e.principal.ip) > 1, "x")' in generated
    assert "$negated = not $e.target.hostname =~ /admin.*/" in generated
    assert (
        "$grouped = ($e.target.hostname =~ /admin.*/ and $e.principal.ip not in %blocked%)"
        in generated
    )


def test_outcome_function_arithmetic_arguments_roundtrip_without_quotes() -> None:
    parser = YaraLParser("""
        rule outcome_function_arithmetic_args {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $result = math.max(1 + 2, score + 3)
          condition:
            $e
        }
        """)

    generated = YaraLGenerator().generate(parser.parse())

    assert "$result = math.max(1 + 2, score + 3)" in generated
    assert '"1 + 2"' not in generated
    assert '"score + 3"' not in generated


def test_outcome_function_parenthesized_arithmetic_arguments_roundtrip() -> None:
    parser = YaraLParser("""
        rule outcome_function_parenthesized_arithmetic_args {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $result = custom((1 + 2) * 3, 10 / (2 + 3))
          condition:
            $e
        }
        """)

    generated = YaraLGenerator().generate(parser.parse())

    assert "$result = custom((1 + 2) * 3, 10 / (2 + 3))" in generated


def test_outcome_function_regex_first_argument_roundtrips() -> None:
    parser = YaraLParser("""
        rule outcome_function_regex_arg {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $result = custom(/evil.*/i, "tail")
            $nocase = re.regex($e.target.hostname, /admin.*/ nocase)
          condition:
            $e
        }
        """)

    generated = YaraLGenerator().generate(parser.parse())

    assert '$result = custom(/evil.*/i, "tail")' in generated
    assert "$nocase = re.regex($e.target.hostname, /admin.*/ nocase)" in generated


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

    call = parser._parse_outcome_argument_basic()
    assert isinstance(call, FunctionCall)
    assert call.function == "func"
    assert call.arguments == [1, "x"]

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
    empty_call = parser_empty_call._parse_outcome_argument_basic()
    assert isinstance(empty_call, FunctionCall)
    assert empty_call.function == "empty"
    assert empty_call.arguments == []

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
    assert parser._parse_outcome_argument() == '$e.metadata.event_type = "LOGIN"'

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
    call = parser._parse_outcome_argument()
    assert isinstance(call, FunctionCall)
    assert call.function == "sum"
    assert call.arguments == [1, 2]

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
    empty_call = parser_empty_call._parse_outcome_argument()
    assert isinstance(empty_call, FunctionCall)
    assert empty_call.function == "noop"
    assert empty_call.arguments == []

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

    parser3 = YaraLParser("")
    _set_tokens(parser3, [_tok(T.IEQUALS, "=="), _tok(T.EOF, None, YaraLTokenType.EOF)])
    assert parser3._check_any_operator()
    assert parser3._check_any_operator(arithmetic_only=True)
