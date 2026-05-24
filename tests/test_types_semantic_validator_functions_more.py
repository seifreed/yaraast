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
    BooleanLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    StringLength,
    StringLiteral,
    StringOffset,
    UnaryExpression,
)
from yaraast.ast.modules import DictionaryAccess
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
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


def test_function_validator_sorts_available_functions_in_suggestions() -> None:
    result = ValidationResult()
    env = TypeEnvironment()
    env.add_module("calc")
    validator = FunctionCallValidator(result, env)
    validator.module_loader.modules["calc"] = ModuleDefinition(
        name="calc",
        functions={
            "zeta": FunctionDefinition(name="zeta", return_type=AnyType()),
            "alpha": FunctionDefinition(name="alpha", return_type=AnyType()),
        },
    )

    validator.visit(FunctionCall(function="calc.missing", arguments=[]))

    assert result.errors[0].suggestion == "Available functions: alpha, zeta"


def test_function_validator_accepts_hash_checksum32_function() -> None:
    result = ValidationResult()
    env = TypeEnvironment()
    env.add_module("hash")

    FunctionCallValidator(result, env).visit(
        FunctionCall(function="hash.checksum32", arguments=[IntegerLiteral(0), IntegerLiteral(1)])
    )
    FunctionCallValidator(result, env).visit(
        FunctionCall(function="hash.checksum32", arguments=[StringLiteral("abc")])
    )

    assert result.is_valid is True
    assert result.errors == []


def test_function_validator_accepts_extended_math_module_functions() -> None:
    result = ValidationResult()
    env = TypeEnvironment()
    env.add_module("math")
    validator = FunctionCallValidator(result, env)

    for call in [
        FunctionCall(function="math.mean", arguments=[IntegerLiteral(0), IntegerLiteral(1)]),
        FunctionCall(function="math.mean", arguments=[StringLiteral("abc")]),
        FunctionCall(
            function="math.deviation",
            arguments=[IntegerLiteral(0), IntegerLiteral(1), IntegerLiteral(97)],
        ),
        FunctionCall(
            function="math.deviation", arguments=[StringLiteral("abc"), IntegerLiteral(97)]
        ),
        FunctionCall(
            function="math.serial_correlation",
            arguments=[IntegerLiteral(0), IntegerLiteral(2)],
        ),
        FunctionCall(function="math.serial_correlation", arguments=[StringLiteral("abc")]),
        FunctionCall(
            function="math.monte_carlo_pi",
            arguments=[IntegerLiteral(0), IntegerLiteral(6)],
        ),
        FunctionCall(
            function="math.count",
            arguments=[IntegerLiteral(97), IntegerLiteral(0), IntegerLiteral(3)],
        ),
        FunctionCall(
            function="math.percentage",
            arguments=[IntegerLiteral(97), IntegerLiteral(0), IntegerLiteral(3)],
        ),
        FunctionCall(function="math.mode", arguments=[IntegerLiteral(0), IntegerLiteral(3)]),
    ]:
        validator.visit(call)

    assert result.is_valid is True
    assert result.errors == []


def test_function_validator_rejects_non_libyara_math_functions() -> None:
    result = ValidationResult()
    env = TypeEnvironment()
    env.add_module("math")

    FunctionCallValidator(result, env).visit(
        FunctionCall(function="math.log", arguments=[IntegerLiteral(1)])
    )

    assert result.is_valid is False
    assert "Function 'log' not found in module 'math'" in result.errors[0].message


def test_function_validator_rejects_too_few_module_function_arguments() -> None:
    result = ValidationResult()
    env = TypeEnvironment()
    env.add_module("math")

    FunctionCallValidator(result, env).visit(FunctionCall(function="math.entropy", arguments=[]))

    assert result.is_valid is False
    assert any(
        "Function 'entropy' expects at least 1 argument(s), got 0" in err.message
        for err in result.errors
    )


def test_function_validator_accepts_known_optional_module_arguments() -> None:
    result = ValidationResult()
    env = TypeEnvironment()
    env.add_module("math")
    env.add_module("pe")
    env.add_module("time")
    validator = FunctionCallValidator(result, env)

    validator.visit(FunctionCall(function="math.to_string", arguments=[IntegerLiteral(10)]))
    validator.visit(FunctionCall(function="pe.imports", arguments=[Identifier("dll_name")]))
    validator.visit(FunctionCall(function="time.now", arguments=[]))

    assert result.is_valid is True
    assert result.errors == []


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
    # Fewer args than defined is invalid unless the contract marks them optional.
    validator3.visit(FunctionCall(function="calc.sum", arguments=[IntegerLiteral(1)]))
    assert any(
        "Function 'sum' expects at least 2 argument(s), got 1" in err.message
        for err in result3.errors
    )

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
            ForOfExpression(quantifier="all", string_set="them", condition=None),
            OfExpression(quantifier="any", string_set=["$a", "$b"]),
            InExpression(
                subject=OfExpression(
                    quantifier=Identifier("q"),
                    string_set=SetExpression([FunctionCall("nested_unknown", [])]),
                ),
                range=RangeExpression(low=IntegerLiteral(0), high=IntegerLiteral(2)),
            ),
        ],
    )

    validator.visit(nested)

    # Unknown top-level function warning plus successful traversal of nested nodes.
    assert any("Unknown function 'unknown'" in w.message for w in result.warnings)
    assert any("Unknown function 'nested_unknown'" in w.message for w in result.warnings)


def test_function_validator_visits_for_quantifier_expressions() -> None:
    result = ValidationResult()
    validator = FunctionCallValidator(result, TypeEnvironment())

    validator.visit(
        ForExpression(
            quantifier=FunctionCall("missing_for_quantifier", []),
            variable="i",
            iterable=SetExpression([IntegerLiteral(1)]),
            body=BooleanLiteral(True),
        )
    )
    validator.visit(
        ForOfExpression(
            quantifier=FunctionCall("missing_for_of_quantifier", []),
            string_set="them",
        )
    )

    warnings = [warning.message for warning in result.warnings]
    assert any("missing_for_quantifier" in warning for warning in warnings)
    assert any("missing_for_of_quantifier" in warning for warning in warnings)


def test_function_validator_visits_operator_and_dictionary_wrappers() -> None:
    result = ValidationResult()
    validator = FunctionCallValidator(result, TypeEnvironment())

    validator.visit(DefinedExpression(FunctionCall("missing_defined", [])))
    validator.visit(
        StringOperatorExpression(
            left=FunctionCall("missing_string_left", []),
            operator="icontains",
            right=FunctionCall("missing_string_right", []),
        )
    )
    validator.visit(
        DictionaryAccess(
            object=FunctionCall("missing_dictionary_object", []),
            key=FunctionCall("missing_dictionary_key", []),
        )
    )
    validator.visit(StringOffset("a", FunctionCall("missing_offset_index", [])))
    validator.visit(StringLength("a", FunctionCall("missing_length_index", [])))

    warnings = [warning.message for warning in result.warnings]
    assert any("missing_defined" in warning for warning in warnings)
    assert any("missing_string_left" in warning for warning in warnings)
    assert any("missing_string_right" in warning for warning in warnings)
    assert any("missing_dictionary_object" in warning for warning in warnings)
    assert any("missing_dictionary_key" in warning for warning in warnings)
    assert any("missing_offset_index" in warning for warning in warnings)
    assert any("missing_length_index" in warning for warning in warnings)
