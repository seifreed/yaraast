"""Additional coverage for semantic_validator module convenience paths."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import ForOfExpression, OfExpression
from yaraast.ast.expressions import (
    BooleanLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    SetExpression,
    StringIdentifier,
    StringLiteral,
)
from yaraast.ast.rules import Rule
from yaraast.ast.strings import PlainString
from yaraast.types.semantic_validator import (
    SemanticValidator,
    check_function_calls,
    check_string_uniqueness,
    validate_yara_file,
    validate_yara_rule,
)
from yaraast.types.type_system import TypeEnvironment


def _rule(name: str = "r", with_condition: bool = True) -> Rule:
    return Rule(
        name=name,
        strings=[PlainString(identifier="$a", value="x"), PlainString(identifier="$a", value="y")],
        condition=Identifier("true") if with_condition else None,
    )


def test_validate_rule_with_and_without_env_and_condition() -> None:
    validator = SemanticValidator()

    r1 = _rule(with_condition=True)
    res1 = validator.validate_rule(r1)
    assert res1.errors  # duplicate string id

    env = TypeEnvironment()
    env.add_module("pe")
    r2 = _rule(with_condition=False)
    res2 = validator.validate_rule(r2, env)
    assert res2.errors  # duplicate id still caught


def test_validate_rule_detects_undefined_string_references() -> None:
    rule = Rule(name="missing_string", strings=[], condition=StringIdentifier("$missing"))

    result = SemanticValidator().validate_rule(rule)

    assert result.is_valid is False
    assert any("Undefined string '$missing'" in error.message for error in result.errors)


def test_validate_rule_detects_undefined_strings_in_raw_string_sets() -> None:
    rules = [
        Rule(
            name="missing_of",
            strings=[PlainString(identifier="$a", value="x")],
            condition=OfExpression("any", ["$a", "$missing"]),
        ),
        Rule(
            name="missing_for_of",
            strings=[PlainString(identifier="$a", value="x")],
            condition=ForOfExpression("any", ["$a", "$missing"], BooleanLiteral(True)),
        ),
        Rule(
            name="missing_set_expression",
            strings=[PlainString(identifier="$a", value="x")],
            condition=OfExpression(
                "any",
                SetExpression([StringLiteral("$a"), StringLiteral("$missing")]),
            ),
        ),
    ]

    result = SemanticValidator().validate(YaraFile(rules=rules))
    messages = [error.message for error in result.errors]

    assert result.is_valid is False
    assert any(
        "Undefined string '$missing' in rule 'missing_of'" in message for message in messages
    )
    assert any(
        "Undefined string '$missing' in rule 'missing_for_of'" in message for message in messages
    )
    assert any(
        "Undefined string '$missing' in rule 'missing_set_expression'" in message
        for message in messages
    )


def test_validate_rule_accepts_parenthesized_string_set_item() -> None:
    rules = [
        Rule(
            name="parenthesized_of",
            strings=[PlainString(identifier="$a", value="x")],
            condition=OfExpression("any", ParenthesesExpression(StringIdentifier("$a"))),
        ),
        Rule(
            name="parenthesized_for_of",
            strings=[PlainString(identifier="$a", value="x")],
            condition=ForOfExpression(
                "any",
                ParenthesesExpression(StringIdentifier("$a")),
                StringIdentifier("$"),
            ),
        ),
    ]

    result = SemanticValidator().validate(YaraFile(rules=rules))

    assert result.is_valid is True
    assert result.errors == []


def test_validate_rule_detects_invalid_condition_type() -> None:
    rule = Rule(
        name="bad_type",
        strings=[],
        condition=SetExpression(elements=[IntegerLiteral(value=1)]),
    )

    result = SemanticValidator().validate_rule(rule)

    assert result.is_valid is False
    assert any("Rule condition must be boolean" in error.message for error in result.errors)


def test_validate_expression_and_convenience_functions() -> None:
    validator = SemanticValidator()
    expr = FunctionCall(function="pe.imphash", arguments=[])

    # env None branch
    res_expr = validator.validate_expression(expr)
    assert res_expr.errors

    rule = _rule()
    yf = YaraFile(rules=[rule])

    full = validate_yara_file(yf)
    assert full.errors

    single = validate_yara_rule(rule)
    assert single.errors

    uniq_errors = check_string_uniqueness(rule)
    assert uniq_errors

    fn_errors = check_function_calls(expr, TypeEnvironment())
    assert fn_errors
