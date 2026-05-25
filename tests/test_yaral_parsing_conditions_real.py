from __future__ import annotations

import pytest

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral._shared import YaraLParserError
from yaraast.yaral.ast_nodes import (
    BinaryCondition,
    EventCountCondition,
    EventExistsCondition,
    FunctionCall,
    NOfCondition,
    NullCheckCondition,
    RawConditionValue,
    ReferenceList,
    RegexPattern,
    UnaryCondition,
    VariableComparisonCondition,
)
from yaraast.yaral.generator import YaraLGenerator
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.parser import YaraLParser
from yaraast.yaral.tokens import YaraLTokenType


def _tok(
    token_type: T,
    value: str | int | float | None,
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
    value: str | int | float | None,
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
    value: str | int | float | None,
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


def test_parse_condition_event_field_predicates_preserve_generated_text() -> None:
    parser = YaraLParser("""
        rule field_condition {
          events:
            $e.metadata.event_type = "LOGIN"
          condition:
            #e > 0 and $e.target.hostname matches /admin.*/i nocase and $e.principal.ip in %blocked%
        }
        """)
    ast = parser.parse()

    generated = YaraLGenerator().generate(ast)
    assert "#e > 0" in generated
    assert "$e.target.hostname =~ /admin.*/i nocase" in generated
    assert "$e.principal.ip in %blocked%" in generated


def test_parse_condition_field_predicate_values() -> None:
    parser = YaraLParser("$e.target.hostname matches /admin.*/i nocase")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert condition.variable == "$e.target.hostname"
    assert condition.operator == "=~"
    assert isinstance(condition.value, RegexPattern)
    assert condition.value.as_string == "/admin.*/i nocase"

    parser2 = YaraLParser("principal.ip in %blocked%")
    condition2 = parser2._parse_condition_expression()

    assert isinstance(condition2, VariableComparisonCondition)
    assert condition2.variable == "principal.ip"
    assert condition2.operator == "in"
    assert isinstance(condition2.value, ReferenceList)
    assert condition2.value.name == "blocked"

    parser3 = YaraLParser("$e.target.hostname not in %blocked%")
    condition3 = parser3._parse_condition_expression()

    assert isinstance(condition3, VariableComparisonCondition)
    assert condition3.variable == "$e.target.hostname"
    assert condition3.operator == "not in"
    assert isinstance(condition3.value, ReferenceList)
    assert condition3.value.name == "blocked"
    assert parser3._is_at_end()


def test_parse_condition_field_reference_values_preserve_generated_text() -> None:
    parser = YaraLParser("$e.principal.ip = $e.target.ip")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert condition.variable == "$e.principal.ip"
    assert condition.operator == "=="
    assert isinstance(condition.value, RawConditionValue)
    assert condition.value == "$e.target.ip"
    assert parser._is_at_end()

    parser2 = YaraLParser("principal.ip = target.ip")
    condition2 = parser2._parse_condition_expression()

    assert isinstance(condition2, VariableComparisonCondition)
    assert condition2.variable == "principal.ip"
    assert condition2.operator == "=="
    assert isinstance(condition2.value, RawConditionValue)
    assert condition2.value == "target.ip"
    assert parser2._is_at_end()

    ast = YaraLParser("""
        rule field_value_condition {
          events:
            $e.metadata.event_type = "LOGIN"
          condition:
            $e.principal.ip = $e.target.ip
        }
        """).parse()
    generated = YaraLGenerator().generate(ast)
    assert "$e.principal.ip == $e.target.ip" in generated


def test_parse_condition_arithmetic_comparisons_preserve_generated_text() -> None:
    parser = YaraLParser("$count + 1 > 5")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert condition.variable == "$count + 1"
    assert condition.operator == ">"
    assert condition.value == 5
    assert parser._is_at_end()

    parser2 = YaraLParser("$left + $right >= $threshold - 1")
    condition2 = parser2._parse_condition_expression()

    assert isinstance(condition2, VariableComparisonCondition)
    assert condition2.variable == "$left + $right"
    assert condition2.operator == ">="
    assert isinstance(condition2.value, RawConditionValue)
    assert condition2.value == "$threshold - 1"
    assert parser2._is_at_end()

    ast = YaraLParser("""
        rule arithmetic_condition {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $count = count($e.principal.ip)
          condition:
            $count + 1 > 5
        }
        """).parse()
    generated = YaraLGenerator().generate(ast)
    assert "$count + 1 > 5" in generated


def test_parse_condition_parenthesized_arithmetic_left_preserves_generated_text() -> None:
    parser = YaraLParser("($score + 1) * 2 > 4")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert condition.variable == "($score + 1) * 2"
    assert condition.operator == ">"
    assert condition.value == 4
    assert parser._is_at_end()

    ast = YaraLParser("""
        rule parenthesized_left_arithmetic_condition {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $score = 1
          condition:
            ($score + 1) * 2 > 4
        }
        """).parse()
    generated = YaraLGenerator().generate(ast)
    assert "($score + 1) * 2 > 4" in generated


@pytest.mark.parametrize(("source_operator", "operator"), [("=~", "=~"), ("!~", "!~")])
def test_parse_condition_symbolic_regex_operators_preserve_generated_text(
    source_operator: str, operator: str
) -> None:
    parser = YaraLParser(f"$e.target.hostname {source_operator} /admin.*/")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert condition.variable == "$e.target.hostname"
    assert condition.operator == operator
    assert isinstance(condition.value, RegexPattern)
    assert parser._is_at_end()

    ast = YaraLParser(f"""
        rule regex_operator_condition {{
          events:
            $e.metadata.event_type = "LOGIN"
          condition:
            $e.target.hostname {source_operator} /admin.*/
        }}
        """).parse()
    generated = YaraLGenerator().generate(ast)
    assert f"$e.target.hostname {operator} /admin.*/" in generated


def test_parse_condition_double_equals_preserve_generated_text() -> None:
    parser = YaraLParser('$e.target.hostname == "admin"')
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert condition.variable == "$e.target.hostname"
    assert condition.operator == "=="
    assert condition.value == "admin"
    assert parser._is_at_end()
    assert YaraLGenerator().visit(condition) == '$e.target.hostname == "admin"'

    ast = YaraLParser("""
        rule double_equals_condition {
          events:
            $e.metadata.event_type = "LOGIN"
          condition:
            #e == 0 or $e.target.hostname == "admin"
        }
        """).parse()

    generated = YaraLGenerator().generate(ast)
    assert "#e == 0" in generated
    assert '$e.target.hostname == "admin"' in generated


def test_parse_condition_function_values_preserve_generated_text() -> None:
    parser = YaraLParser("$risk_score > max(1, 2)")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert condition.variable == "$risk_score"
    assert condition.operator == ">"
    assert isinstance(condition.value, FunctionCall)
    assert condition.value.function == "max"
    assert condition.value.arguments == [1, 2]
    assert parser._is_at_end()

    parser2 = YaraLParser('$risk_score > max($e.principal.ip, "fallback", true)')
    condition2 = parser2._parse_condition_expression()

    assert isinstance(condition2, VariableComparisonCondition)
    assert isinstance(condition2.value, FunctionCall)
    assert condition2.value.function == "max"
    assert parser2._is_at_end()

    parser3 = YaraLParser("$risk_score > max(1, 2) + $offset")
    condition3 = parser3._parse_condition_expression()

    assert isinstance(condition3, VariableComparisonCondition)
    assert isinstance(condition3.value, RawConditionValue)
    assert condition3.value == "max(1, 2) + $offset"
    assert parser3._is_at_end()

    parser4 = YaraLParser("$risk_score > math.max(1 + 2, score + 3)")
    condition4 = parser4._parse_condition_expression()

    assert isinstance(condition4, VariableComparisonCondition)
    assert isinstance(condition4.value, FunctionCall)
    assert condition4.value.function == "math.max"
    assert str(condition4.value.arguments[0]) == "1 + 2"
    assert str(condition4.value.arguments[1]) == "score + 3"
    assert parser4._is_at_end()
    assert YaraLGenerator().visit(condition4) == "$risk_score > math.max(1 + 2, score + 3)"

    ast = YaraLParser("""
        rule function_condition {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $risk_score = count($e.principal.ip)
          condition:
            $risk_score > max($e.principal.ip, "fallback", true)
        }
        """).parse()
    generated = YaraLGenerator().generate(ast)
    assert '$risk_score > max($e.principal.ip, "fallback", true)' in generated


def test_parse_condition_parenthesized_values_preserve_generated_text() -> None:
    parser = YaraLParser("$risk_score > (max(1, 2))")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, VariableComparisonCondition)
    assert condition.variable == "$risk_score"
    assert condition.operator == ">"
    assert isinstance(condition.value, RawConditionValue)
    assert condition.value == "(max(1, 2))"
    assert parser._is_at_end()

    parser2 = YaraLParser("$risk_score > (1 + $offset)")
    condition2 = parser2._parse_condition_expression()

    assert isinstance(condition2, VariableComparisonCondition)
    assert isinstance(condition2.value, RawConditionValue)
    assert condition2.value == "(1 + $offset)"
    assert parser2._is_at_end()

    parser3 = YaraLParser("$risk_score > (1 + 2) * 3")
    condition3 = parser3._parse_condition_expression()

    assert isinstance(condition3, VariableComparisonCondition)
    assert isinstance(condition3.value, RawConditionValue)
    assert condition3.value == "(1 + 2) * 3"
    assert parser3._is_at_end()

    ast = YaraLParser("""
        rule parenthesized_condition_value {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $risk_score = count($e.principal.ip)
          condition:
            $risk_score > (max(1, 2))
        }
        """).parse()
    generated = YaraLGenerator().generate(ast)
    assert "$risk_score > (max(1, 2))" in generated

    ast2 = YaraLParser("""
        rule parenthesized_arithmetic_condition_value {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $risk_score = count($e.principal.ip)
          condition:
            $risk_score > (1 + 2) * 3
        }
        """).parse()
    generated2 = YaraLGenerator().generate(ast2)
    assert "$risk_score > (1 + 2) * 3" in generated2


def test_parse_condition_null_checks_preserve_generated_text() -> None:
    parser = YaraLParser("$e.principal.user.userid is null")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, NullCheckCondition)
    assert condition.field == "$e.principal.user.userid"
    assert condition.negated is False
    assert parser._is_at_end()
    assert YaraLGenerator().visit(condition) == "$e.principal.user.userid is null"

    parser2 = YaraLParser("principal.user.userid is not null")
    condition2 = parser2._parse_condition_expression()

    assert isinstance(condition2, NullCheckCondition)
    assert condition2.field == "principal.user.userid"
    assert condition2.negated is True
    assert parser2._is_at_end()
    assert YaraLGenerator().visit(condition2) == "principal.user.userid is not null"

    ast = YaraLParser("""
        rule null_check_condition {
          events:
            $e.metadata.event_type = "LOGIN"
          condition:
            $e.principal.ip = "1.2.3.4" and $e.principal.user.userid is null
        }
        """).parse()
    generated = YaraLGenerator().generate(ast)
    assert '$e.principal.ip == "1.2.3.4"' in generated
    assert "$e.principal.user.userid is null" in generated


def test_parse_condition_n_of_events_preserve_generated_text() -> None:
    parser = YaraLParser("2 of ($e1, $e2)")
    condition = parser._parse_condition_expression()

    assert isinstance(condition, NOfCondition)
    assert condition.count == 2
    assert condition.events == ["$e1", "$e2"]
    assert parser._is_at_end()
    assert YaraLGenerator().visit(condition) == "2 of ($e1, $e2)"

    ast = YaraLParser("""
        rule n_of_condition {
          events:
            $e1.metadata.event_type = "LOGIN"
            $e2.metadata.event_type = "LOGIN"
            $e3.metadata.event_type = "LOGIN"
          condition:
            3 of ($e1, $e2, $e3) and $e1
        }
        """).parse()
    generated = YaraLGenerator().generate(ast)
    assert "3 of ($e1, $e2, $e3)" in generated
    assert "$e1" in generated
