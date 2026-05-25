from __future__ import annotations

import pytest

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral.ast_nodes import AggregationFunction, ConditionalExpression, UDMFieldAccess
from yaraast.yaral.enhanced_parser import EnhancedYaraLParser
from yaraast.yaral.generator import YaraLGenerator
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.tokens import YaraLTokenType


def _tok(
    tt: T,
    value: str | int | float | None,
    yt: YaraLTokenType | None = None,
) -> YaraLToken:
    return YaraLToken(type=tt, value=value, line=1, column=1, length=1, yaral_type=yt)


def _set_tokens(p: EnhancedYaraLParser, toks: list[YaraLToken]) -> None:
    p.tokens = [*toks, _tok(T.EOF, None, YaraLTokenType.EOF)]
    p.current = 0


def test_enhanced_outcome_section_with_conditional_assignment_and_skip() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "outcome"),
            _tok(T.COLON, ":"),
            _tok(T.PLUS, "+"),
            _tok(T.IDENTIFIER, "if"),
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "then"),
            _tok(T.STRING, "yes"),
            _tok(T.IDENTIFIER, "else"),
            _tok(T.STRING, "no"),
            _tok(T.STRING_IDENTIFIER, "$score", YaraLTokenType.EVENT_VAR),
            _tok(T.EQ, "="),
            _tok(T.STRING, "ok"),
            _tok(T.RBRACE, "}"),
        ],
    )

    section = p._parse_outcome_section()
    assert len(section.assignments) == 2
    assert section.assignments[0].variable == "_"
    assert isinstance(section.assignments[0].expression, ConditionalExpression)
    assert section.assignments[1].variable == "$score"
    assert section.assignments[1].expression == "ok"


def test_enhanced_outcome_expression_aggregation_udm_string_int_and_error() -> None:
    p = EnhancedYaraLParser("")

    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "count"),
            _tok(T.LPAREN, "("),
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "event_type"),
            _tok(T.COMMA, ","),
            _tok(T.STRING, "LOGIN"),
            _tok(T.COMMA, ","),
            _tok(T.INTEGER, "7"),
            _tok(T.RPAREN, ")"),
        ],
    )
    agg = p._parse_outcome_expression()
    assert isinstance(agg, AggregationFunction)
    assert agg.function == "count"
    assert len(agg.arguments) == 3
    assert agg.arguments[1] == "LOGIN"
    assert agg.arguments[2] == "7"

    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "event_type"),
        ],
    )
    access = p._parse_outcome_expression()
    assert isinstance(access, UDMFieldAccess)
    assert access.field.parts == ["metadata", "event_type"]

    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "target"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "hostname"),
        ],
    )
    event_access = p._parse_outcome_expression()
    assert isinstance(event_access, UDMFieldAccess)
    assert event_access.event is not None
    assert event_access.event.name == "$e"
    assert event_access.field.parts == ["target", "hostname"]

    _set_tokens(p, [_tok(T.STRING, "abc")])
    assert p._parse_outcome_expression() == "abc"

    _set_tokens(p, [_tok(T.INTEGER, "42")])
    assert p._parse_outcome_expression() == 42

    _set_tokens(p, [_tok(T.PLUS, "+")])
    with pytest.raises(ValueError, match="Expected outcome expression"):
        p._parse_outcome_expression()


def test_enhanced_aggregation_and_conditional_branches() -> None:
    p = EnhancedYaraLParser("")

    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "sum"),
            _tok(T.LPAREN, "("),
            _tok(T.RPAREN, ")"),
        ],
    )
    agg_empty = p._parse_aggregation_function()
    assert isinstance(agg_empty, AggregationFunction)
    assert agg_empty.arguments == []

    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "avg"),
            _tok(T.LPAREN, "("),
            _tok(T.INTEGER, "1"),
            _tok(T.RPAREN, ")"),
        ],
    )
    agg_int = p._parse_aggregation_function()
    assert agg_int.arguments == ["1"]

    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "array_distinct"),
            _tok(T.LPAREN, "("),
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "principal"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "ip"),
            _tok(T.RPAREN, ")"),
        ],
    )
    agg_event_field = p._parse_aggregation_function()
    assert isinstance(agg_event_field.arguments[0], UDMFieldAccess)

    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "if"),
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "then"),
            _tok(T.STRING, "yes"),
        ],
    )
    cond_no_else = p._parse_conditional_expression()
    assert isinstance(cond_no_else, ConditionalExpression)
    assert cond_no_else.false_value is None

    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "if"),
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "then"),
            _tok(T.STRING, "yes"),
            _tok(T.IDENTIFIER, "else"),
            _tok(T.INTEGER, "0"),
        ],
    )
    cond_with_else = p._parse_conditional_expression()
    assert cond_with_else.false_value == 0


def test_enhanced_outcome_event_field_references_roundtrip() -> None:
    parser = EnhancedYaraLParser("""
        rule outcome_fields {
          events:
            $e.metadata.event_type = "LOGIN"
          condition:
            $e
          outcome:
            $host = $e.target.hostname
            $hosts = array_distinct($e.principal.ip)
            if $e.metadata.event_type = "LOGIN" then $e.target.hostname else "none"
        }
        """)
    ast = parser.parse()

    assert parser.errors == []
    rule = ast.rules[0]
    assert rule.outcome is not None
    assert len(rule.outcome.assignments) == 3
    direct_field = rule.outcome.assignments[0].expression
    assert isinstance(direct_field, UDMFieldAccess)
    assert direct_field.event is not None
    assert direct_field.event.name == "$e"
    aggregation = rule.outcome.assignments[1].expression
    assert isinstance(aggregation, AggregationFunction)
    assert isinstance(aggregation.arguments[0], UDMFieldAccess)
    conditional = rule.outcome.assignments[2].expression
    assert isinstance(conditional, ConditionalExpression)

    generated = YaraLGenerator().generate(ast)
    assert "$host = $e.target.hostname" in generated
    assert "$hosts = array_distinct($e.principal.ip)" in generated
    assert '_ = if($e.metadata.event_type = "LOGIN", $e.target.hostname, "none")' in generated
