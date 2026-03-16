"""Additional coverage for semantic_validator module convenience paths."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import FunctionCall, Identifier
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
