"""More tests for evaluator (no mocks)."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    StringIdentifier,
    StringLiteral,
    UnaryExpression,
)
from yaraast.ast.modules import ModuleReference
from yaraast.ast.operators import DefinedExpression
from yaraast.ast.rules import Import, Rule
from yaraast.ast.strings import PlainString
from yaraast.evaluation.evaluator import YaraEvaluator


def test_evaluator_function_calls_and_math_module() -> None:
    data = b"\x01\x02\x03\x04"
    evaluator = YaraEvaluator(data=data)
    ast = YaraFile(
        imports=[Import(module="math")],
        rules=[
            Rule(
                name="r1",
                condition=BinaryExpression(
                    left=FunctionCall(function="math.abs", arguments=[IntegerLiteral(value=-5)]),
                    operator="==",
                    right=IntegerLiteral(value=5),
                ),
            ),
        ],
    )

    results = evaluator.evaluate_file(ast)
    assert results["r1"] is True


def test_evaluator_string_ops_and_defined() -> None:
    evaluator = YaraEvaluator(data=b"abcd")
    rule = Rule(
        name="r1",
        strings=[PlainString(identifier="$a", value="ab")],
        condition=BinaryExpression(
            left=StringLiteral(value="Hello"),
            operator="icontains",
            right=StringLiteral(value="he"),
        ),
    )
    assert evaluator.evaluate_rule(rule) is True

    rule.condition = DefinedExpression(expression=StringIdentifier(name="$a"))
    assert evaluator.evaluate_rule(rule) is True


def test_evaluator_unary_and_of_expression() -> None:
    evaluator = YaraEvaluator(data=b"aaaa")
    rule = Rule(
        name="r1",
        strings=[
            PlainString(identifier="$a", value="aa"),
            PlainString(identifier="$b", value="bb"),
        ],
        condition=UnaryExpression(operator="not", operand=BooleanLiteral(value=False)),
    )
    assert evaluator.evaluate_rule(rule) is True

    rule.condition = OfExpression(quantifier="any", string_set=Identifier(name="them"))
    assert evaluator.evaluate_rule(rule) is True


def test_evaluator_module_reference() -> None:
    evaluator = YaraEvaluator(data=b"MZ")
    ast = YaraFile(imports=[Import(module="pe")], rules=[Rule(name="r1")])
    evaluator.evaluate_file(ast)
    module = evaluator.visit_module_reference(ModuleReference(module="pe"))
    assert module is not None
