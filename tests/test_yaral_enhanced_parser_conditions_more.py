from __future__ import annotations

import pytest

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral.ast_nodes import (
    BinaryCondition,
    NOfCondition,
    NullCheckCondition,
    RawConditionValue,
    ReferenceList,
    VariableComparisonCondition,
)
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


def test_enhanced_reference_check_success_and_missing_list_error() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "event_type"),
            _tok(T.IN, "in"),
            _tok(T.IDENTIFIER, "%blocked%", YaraLTokenType.REFERENCE_LIST),
        ],
    )

    cond = p._parse_reference_check()
    assert isinstance(cond, BinaryCondition)
    assert cond.operator == "in"
    assert isinstance(cond.right, ReferenceList)
    assert cond.right.name == "blocked"

    p2 = EnhancedYaraLParser("")
    _set_tokens(
        p2,
        [
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "event_type"),
            _tok(T.IN, "in"),
            _tok(T.STRING, "oops"),
        ],
    )
    with pytest.raises(ValueError, match="Expected reference list"):
        p2._parse_reference_check()


def test_enhanced_primary_condition_reference_list_branch_is_shadowed() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(p, [_tok(T.IDENTIFIER, "%blocked%", YaraLTokenType.REFERENCE_LIST)])

    with pytest.raises(ValueError, match="Expected comparison operator"):
        p._parse_primary_condition()


def test_enhanced_primary_condition_rejects_invalid_token() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(p, [_tok(T.STRING, "oops")])

    with pytest.raises(ValueError, match="Expected condition expression"):
        p._parse_primary_condition()


def test_enhanced_n_of_condition_preserves_generated_text() -> None:
    parser = EnhancedYaraLParser("""
        rule enhanced_n_of {
          events:
            $e1.metadata.event_type = "LOGIN"
            $e2.metadata.event_type = "LOGIN"
          condition:
            2 of ($e1, $e2)
        }
        """)

    ast = parser.parse()

    assert parser.errors == []
    assert len(ast.rules) == 1
    condition = ast.rules[0].condition
    assert condition is not None
    assert isinstance(condition.expression, NOfCondition)
    assert condition.expression.events == ["$e1", "$e2"]
    assert "2 of ($e1, $e2)" in YaraLGenerator().generate(ast)


def test_enhanced_field_null_checks_preserve_generated_text() -> None:
    parser = EnhancedYaraLParser("""
        rule enhanced_null_check {
          events:
            $e.metadata.event_type = "LOGIN"
          condition:
            $e.principal.user.userid is null and principal.ip is not null
        }
        """)

    ast = parser.parse()

    assert parser.errors == []
    assert len(ast.rules) == 1
    condition = ast.rules[0].condition
    assert condition is not None
    assert isinstance(condition.expression, BinaryCondition)
    assert isinstance(condition.expression.left, NullCheckCondition)
    assert isinstance(condition.expression.right, NullCheckCondition)
    generated = YaraLGenerator().generate(ast)
    assert "$e.principal.user.userid is null" in generated
    assert "principal.ip is not null" in generated


def test_enhanced_double_equals_conditions_preserve_generated_text() -> None:
    parser = EnhancedYaraLParser("""
        rule enhanced_double_equals {
          events:
            $e.metadata.event_type = "LOGIN"
          condition:
            #e == 0 or $e.target.hostname == "admin"
        }
        """)

    ast = parser.parse()

    assert parser.errors == []
    assert len(ast.rules) == 1
    generated = YaraLGenerator().generate(ast)
    assert "#e == 0" in generated
    assert '$e.target.hostname == "admin"' in generated


def test_enhanced_outcome_variable_conditions_preserve_generated_text() -> None:
    parser = EnhancedYaraLParser("""
        rule enhanced_outcome_variable_condition {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $risk_score = count($e.principal.ip)
          condition:
            $risk_score > 5 and $risk_score == 10
        }
        """)

    ast = parser.parse()

    assert parser.errors == []
    assert len(ast.rules) == 1
    condition = ast.rules[0].condition
    assert condition is not None
    assert isinstance(condition.expression, BinaryCondition)
    assert isinstance(condition.expression.left, VariableComparisonCondition)
    assert isinstance(condition.expression.right, VariableComparisonCondition)
    generated = YaraLGenerator().generate(ast)
    assert "$risk_score > 5" in generated
    assert "$risk_score == 10" in generated


def test_enhanced_parenthesized_arithmetic_condition_values_preserve_generated_text() -> None:
    parser = EnhancedYaraLParser("""
        rule enhanced_parenthesized_arithmetic_condition {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $risk_score = count($e.principal.ip)
          condition:
            $risk_score > (1 + 2) * 3
        }
        """)

    ast = parser.parse()

    assert parser.errors == []
    assert len(ast.rules) == 1
    condition = ast.rules[0].condition
    assert condition is not None
    assert isinstance(condition.expression, VariableComparisonCondition)
    assert isinstance(condition.expression.value, RawConditionValue)
    assert condition.expression.value == "(1 + 2) * 3"
    assert "$risk_score > (1 + 2) * 3" in YaraLGenerator().generate(ast)


def test_enhanced_arithmetic_condition_left_preserves_generated_text() -> None:
    parser = EnhancedYaraLParser("""
        rule enhanced_left_arithmetic_condition {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $risk_score = count($e.principal.ip)
          condition:
            $risk_score + 1 > 5
        }
        """)

    ast = parser.parse()

    assert parser.errors == []
    assert len(ast.rules) == 1
    generated = YaraLGenerator().generate(ast)
    assert "$risk_score + 1 > 5" in generated

    parser2 = EnhancedYaraLParser("""
        rule enhanced_parenthesized_left_arithmetic_condition {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $risk_score = count($e.principal.ip)
          condition:
            ($risk_score + 1) * 2 > 4
        }
        """)

    ast2 = parser2.parse()

    assert parser2.errors == []
    assert len(ast2.rules) == 1
    condition = ast2.rules[0].condition
    assert condition is not None
    assert isinstance(condition.expression, VariableComparisonCondition)
    assert condition.expression.variable == "($risk_score + 1) * 2"
    assert "($risk_score + 1) * 2 > 4" in YaraLGenerator().generate(ast2)
