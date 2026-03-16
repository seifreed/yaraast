"""Enhanced semantic validation for YARA AST."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.types.module_loader import ModuleLoader
from yaraast.types.semantic_validator_core import ValidationError, ValidationResult
from yaraast.types.semantic_validator_functions import FunctionCallValidator
from yaraast.types.semantic_validator_helpers import populate_env_for_file, populate_env_for_rule
from yaraast.types.semantic_validator_strings import (
    StringIdentifierValidator,
    UndefinedStringDetector,
)
from yaraast.types.type_system import TypeChecker, TypeEnvironment

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.expressions import Expression
    from yaraast.ast.rules import Rule


class SemanticValidator:
    """Comprehensive semantic validator for YARA AST."""

    def __init__(self) -> None:
        self.module_loader = ModuleLoader()

    def validate(self, ast: YaraFile) -> ValidationResult:
        """Perform complete semantic validation on YARA file."""
        result = ValidationResult()
        env = TypeEnvironment()

        populate_env_for_file(ast, env)

        string_validator = StringIdentifierValidator(result)
        for rule in ast.rules:
            string_validator.visit(rule)

        # Detect undefined strings referenced in conditions
        undefined_detector = UndefinedStringDetector(result)
        for rule in ast.rules:
            undefined_detector.check_rule(rule)

        function_validator = FunctionCallValidator(result, env)
        for rule in ast.rules:
            if rule.condition:
                function_validator.visit(rule.condition)

        type_checker = TypeChecker()
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
    ) -> ValidationResult:
        """Validate a single rule."""
        result = ValidationResult()

        if env is None:
            env = TypeEnvironment()

        populate_env_for_rule(rule, env)

        string_validator = StringIdentifierValidator(result)
        string_validator.visit(rule)

        if rule.condition:
            function_validator = FunctionCallValidator(result, env)
            function_validator.visit(rule.condition)

        return result

    def validate_expression(
        self,
        expr: Expression,
        env: TypeEnvironment | None = None,
    ) -> ValidationResult:
        """Validate a single expression."""
        result = ValidationResult()

        if env is None:
            env = TypeEnvironment()

        function_validator = FunctionCallValidator(result, env)
        function_validator.visit(expr)

        return result


# Convenience functions for easy usage
def validate_yara_file(ast: YaraFile) -> ValidationResult:
    """Validate YARA file with comprehensive semantic checks."""
    validator = SemanticValidator()
    return validator.validate(ast)


def validate_yara_rule(
    rule: Rule,
    env: TypeEnvironment | None = None,
) -> ValidationResult:
    """Validate a single YARA rule."""
    validator = SemanticValidator()
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
