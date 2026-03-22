"""Extra tests for FunctionCallValidator without mocks."""

from __future__ import annotations

from yaraast.ast.conditions import (
    AtExpression,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    UnaryExpression,
)
from yaraast.types.semantic_validator_core import ValidationResult
from yaraast.types.semantic_validator_functions import FunctionCallValidator
from yaraast.types.type_system import AnyType, FunctionDefinition, ModuleDefinition, TypeEnvironment


class BrokenEnv(TypeEnvironment):
    """Environment that reports module imported but with missing canonical name."""

    def has_module(self, name: str) -> bool:
        return True

    def get_module_name(self, name: str) -> str | None:
        return None


def test_function_validator_missing_module_spec_and_empty_module() -> None:
    result = ValidationResult()
    env = TypeEnvironment()
    env.add_module("unknown_mod")

    validator = FunctionCallValidator(result, env)
    validator.visit(FunctionCall(function="unknown_mod.fn", arguments=[]))

    assert result.is_valid is True
    assert any("definition for 'unknown_mod' not found" in w.message for w in result.warnings)

    result2 = ValidationResult()
    env2 = TypeEnvironment()
    env2.add_module("empty_mod")
    validator2 = FunctionCallValidator(result2, env2)
    validator2.module_loader.modules["empty_mod"] = ModuleDefinition(name="empty_mod")

    validator2.visit(FunctionCall(function="empty_mod.fn", arguments=[]))

    assert result2.is_valid is False
    assert any("No functions available" in e.suggestion for e in result2.errors if e.suggestion)


def test_function_validator_branches_for_arity_and_missing_actual_module_name() -> None:
    result = ValidationResult()
    validator = FunctionCallValidator(result, BrokenEnv())
    validator.visit(FunctionCall(function="alias.func", arguments=[]))
    assert result.total_issues == 0

    result2 = ValidationResult()
    env2 = TypeEnvironment()
    validator2 = FunctionCallValidator(result2, env2)
    validator2.visit(
        FunctionCall(
            function="uint16",
            arguments=[IntegerLiteral(1), IntegerLiteral(2)],
        ),
    )
    assert any("expects at most 1 argument" in err.message for err in result2.errors)

    result3 = ValidationResult()
    env3 = TypeEnvironment()
    env3.add_module("calc")
    validator3 = FunctionCallValidator(result3, env3)
    validator3.module_loader.modules["calc"] = ModuleDefinition(
        name="calc",
        functions={
            "sum": FunctionDefinition(
                name="sum",
                return_type=AnyType(),
                parameters=[("a", AnyType()), ("b", AnyType())],
            ),
        },
    )
    # Fewer args than defined is allowed (optional params)
    validator3.visit(FunctionCall(function="calc.sum", arguments=[IntegerLiteral(1)]))
    assert not any("expects" in err.message for err in result3.errors)

    # More args than defined is an error
    result4 = ValidationResult()
    validator4 = FunctionCallValidator(result4, env3)
    validator4.module_loader.modules["calc"] = ModuleDefinition(
        name="calc",
        functions={
            "sum": FunctionDefinition(
                name="sum",
                return_type=AnyType(),
                parameters=[("a", AnyType()), ("b", AnyType())],
            ),
        },
    )
    validator4.visit(
        FunctionCall(
            function="calc.sum",
            arguments=[IntegerLiteral(1), IntegerLiteral(2), IntegerLiteral(3)],
        )
    )
    assert any("expects at most 2 argument(s)" in err.message for err in result4.errors)


def test_function_validator_visits_nested_condition_nodes() -> None:
    result = ValidationResult()
    env = TypeEnvironment()
    validator = FunctionCallValidator(result, env)

    nested = FunctionCall(
        function="unknown",
        arguments=[
            BinaryExpression(
                left=ParenthesesExpression(
                    UnaryExpression(operator="not", operand=Identifier("x"))
                ),
                operator="and",
                right=MemberAccess(object=Identifier("obj"), member="field"),
            ),
            ArrayAccess(array=Identifier("arr"), index=IntegerLiteral(0)),
            ForExpression(
                quantifier="any",
                variable="i",
                iterable=SetExpression([Identifier("a"), Identifier("b")]),
                body=BinaryExpression(
                    left=ForOfExpression(
                        quantifier="all",
                        string_set=SetExpression([Identifier("c")]),
                        condition=AtExpression(string_id="$a", offset=IntegerLiteral(1)),
                    ),
                    operator="and",
                    right=InExpression(
                        subject="$a",
                        range=RangeExpression(low=IntegerLiteral(0), high=IntegerLiteral(2)),
                    ),
                ),
            ),
            OfExpression(
                quantifier=Identifier("q"),
                string_set=SetExpression([Identifier("s")]),
            ),
        ],
    )

    validator.visit(nested)

    # Unknown top-level function warning plus successful traversal of nested nodes.
    assert any("Unknown function 'unknown'" in w.message for w in result.warnings)
