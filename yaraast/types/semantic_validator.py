"""Enhanced semantic validation for YARA AST."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from yaraast.ast.base import YaraFile
from yaraast.types.module_loader import ModuleLoader
from yaraast.types.semantic_validator_core import ValidationError, ValidationResult
from yaraast.types.semantic_validator_functions import FunctionCallValidator
from yaraast.types.semantic_validator_helpers import populate_env_for_file, populate_env_for_rule
from yaraast.types.semantic_validator_strings import (
    StringIdentifierValidator,
    StringModifierApplicabilityValidator,
    UndefinedStringDetector,
)
from yaraast.types.type_system import (
    BooleanType,
    DoubleType,
    IntegerType,
    StringType,
    TypeChecker,
    TypeEnvironment,
    UnknownType,
    YaraType,
)

__all__ = [
    "FunctionCallValidator",
    "SemanticValidator",
    "StringIdentifierValidator",
    "StringModifierApplicabilityValidator",
    "ValidationError",
    "ValidationResult",
    "check_function_calls",
    "check_string_uniqueness",
    "validate_yara_file",
    "validate_yara_rule",
]

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.expressions import Expression
    from yaraast.ast.rules import Rule


class SemanticValidator:
    """Comprehensive semantic validator for YARA AST."""

    def __init__(self, externals: Mapping[str, object] | None = None) -> None:
        self.module_loader = ModuleLoader()
        self.externals = _normalize_externals(externals)

    def validate(
        self,
        ast: YaraFile,
        externals: Mapping[str, object] | None = None,
    ) -> ValidationResult:
        """Perform complete semantic validation on YARA file."""
        result = ValidationResult()
        env = TypeEnvironment()
        effective_externals = self._effective_externals(externals)

        _define_external_types(env, effective_externals)
        populate_env_for_file(ast, env)

        string_validator = StringIdentifierValidator(result)
        modifier_validator = StringModifierApplicabilityValidator(result)
        for rule in ast.rules:
            string_validator.visit(rule)
            modifier_validator.visit(rule)

        # Detect undefined strings referenced in conditions
        undefined_detector = UndefinedStringDetector(result)
        for rule in ast.rules:
            undefined_detector.check_rule(rule)

        function_validator = FunctionCallValidator(result, env)
        for rule in ast.rules:
            if rule.condition is not None:
                function_validator.visit(rule.condition)

        type_env = TypeEnvironment()
        _define_external_types(type_env, effective_externals)
        type_checker = TypeChecker(type_env)
        type_errors = type_checker.check(ast)

        for error_msg in type_errors:
            result.add_error(
                error_msg,
                suggestion="Check variable types and function signatures",
            )

        return result

    def validate_rule(
        self,
        rule: Rule,
        env: TypeEnvironment | None = None,
        externals: Mapping[str, object] | None = None,
    ) -> ValidationResult:
        """Validate a single rule."""
        result = ValidationResult()

        if env is None:
            env = TypeEnvironment()

        _define_external_types(env, self._effective_externals(externals))
        populate_env_for_rule(rule, env)

        string_validator = StringIdentifierValidator(result)
        string_validator.visit(rule)
        modifier_validator = StringModifierApplicabilityValidator(result)
        modifier_validator.visit(rule)

        undefined_detector = UndefinedStringDetector(result)
        undefined_detector.check_rule(rule)

        if rule.condition is not None:
            function_validator = FunctionCallValidator(result, env)
            function_validator.visit(rule.condition)

        type_checker = TypeChecker(env)
        type_errors = type_checker.check(YaraFile(rules=[rule]))

        for error_msg in type_errors:
            result.add_error(
                error_msg,
                suggestion="Check variable types and function signatures",
            )

        return result

    def validate_expression(
        self,
        expr: Expression,
        env: TypeEnvironment | None = None,
        externals: Mapping[str, object] | None = None,
    ) -> ValidationResult:
        """Validate a single expression."""
        result = ValidationResult()

        if env is None:
            env = TypeEnvironment()

        _define_external_types(env, self._effective_externals(externals))
        function_validator = FunctionCallValidator(result, env)
        function_validator.visit(expr)

        type_checker = TypeChecker(env)
        type_checker.infer_type(expr)
        for error_msg in type_checker.inference.errors:
            result.add_error(
                error_msg,
                suggestion="Check variable types and function signatures",
            )

        return result

    def _effective_externals(
        self,
        externals: Mapping[str, object] | None,
    ) -> dict[str, object]:
        return self.externals if externals is None else _normalize_externals(externals)


def _normalize_externals(externals: Mapping[str, object] | None) -> dict[str, object]:
    if externals is None:
        return {}
    if not isinstance(externals, Mapping):
        msg = "SemanticValidator externals must be a mapping"
        raise TypeError(msg)
    return dict(externals)


def _external_type(value: object) -> YaraType:
    if isinstance(value, bool):
        return BooleanType()
    if isinstance(value, int):
        return IntegerType()
    if isinstance(value, float):
        return DoubleType()
    if isinstance(value, str):
        return StringType()
    return UnknownType()


def _define_external_types(
    env: TypeEnvironment,
    externals: Mapping[str, object],
) -> None:
    for name, value in externals.items():
        env.define(name, _external_type(value))


# Convenience functions for easy usage
def validate_yara_file(
    ast: YaraFile,
    externals: Mapping[str, object] | None = None,
) -> ValidationResult:
    """Validate YARA file with comprehensive semantic checks."""
    validator = SemanticValidator(externals=externals)
    return validator.validate(ast)


def validate_yara_rule(
    rule: Rule,
    env: TypeEnvironment | None = None,
    externals: Mapping[str, object] | None = None,
) -> ValidationResult:
    """Validate a single YARA rule."""
    validator = SemanticValidator(externals=externals)
    return validator.validate_rule(rule, env)


def check_string_uniqueness(rule: Rule) -> list[ValidationError]:
    """Check string identifier uniqueness within a rule."""
    result = ValidationResult()
    validator = StringIdentifierValidator(result)
    validator.visit(rule)
    return result.errors


def check_function_calls(
    expr: Expression,
    env: TypeEnvironment,
) -> list[ValidationError]:
    """Check function calls in an expression."""
    result = ValidationResult()
    validator = FunctionCallValidator(result, env)
    validator.visit(expr)
    return result.errors
