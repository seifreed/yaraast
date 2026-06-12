"""Enhanced semantic validation for YARA AST."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import fields, is_dataclass
import re
from typing import TYPE_CHECKING

from yaraast.ast.base import ASTNode, YaraFile
from yaraast.ast.conditions import ForOfExpression, OfExpression
from yaraast.ast.expressions import (
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    RangeExpression,
)
from yaraast.lexer.lexer_tables import KEYWORDS, YARA_IDENTIFIER_MAX_LENGTH
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

_YARA_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_YARA_KEYWORDS = frozenset(KEYWORDS)


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
        try:
            populate_env_for_file(ast, env)
        except (TypeError, ValueError) as exc:
            result.add_error(str(exc))

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

        _validate_external_expression_values(result, ast, effective_externals)

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
        try:
            populate_env_for_rule(rule, env)
        except (TypeError, ValueError) as exc:
            result.add_error(str(exc))

        string_validator = StringIdentifierValidator(result)
        string_validator.visit(rule)
        modifier_validator = StringModifierApplicabilityValidator(result)
        modifier_validator.visit(rule)

        undefined_detector = UndefinedStringDetector(result)
        undefined_detector.check_rule(rule)

        if rule.condition is not None:
            function_validator = FunctionCallValidator(result, env)
            function_validator.visit(rule.condition)

        _validate_external_expression_values(result, rule, self._effective_externals(externals))

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

        _validate_external_expression_values(result, expr, self._effective_externals(externals))

        type_checker = TypeChecker(env)
        try:
            type_checker.infer_type(expr)
        except (AttributeError, TypeError, ValueError) as exc:
            result.add_error(
                str(exc),
                suggestion="Check variable types and function signatures",
            )
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
    normalized: dict[str, object] = {}
    for name, value in externals.items():
        if not isinstance(name, str):
            msg = "SemanticValidator external names must be strings"
            raise TypeError(msg)
        if not name.strip():
            msg = "SemanticValidator external names must not be empty"
            raise ValueError(msg)
        if (
            len(name) > YARA_IDENTIFIER_MAX_LENGTH
            or _YARA_IDENTIFIER_RE.fullmatch(name) is None
            or name in _YARA_KEYWORDS
        ):
            msg = f"SemanticValidator external names must be valid identifiers: {name}"
            raise ValueError(msg)
        if not isinstance(value, bool | int | float | str):
            msg = "SemanticValidator external values must be integer, float, boolean, or string"
            raise TypeError(msg)
        normalized[name] = value
    return normalized


def _external_type(value: object) -> YaraType:
    if isinstance(value, bool):
        return IntegerType()
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


def _validate_external_expression_values(
    result: ValidationResult,
    node: ASTNode,
    externals: Mapping[str, object],
) -> None:
    for candidate in _walk_ast_nodes(node):
        if isinstance(candidate, OfExpression):
            _validate_external_quantifier_value(
                result,
                candidate.quantifier,
                externals,
                context="of",
            )
        elif isinstance(candidate, ForOfExpression):
            context = "for...of" if candidate.condition is not None else "of"
            _validate_external_quantifier_value(
                result,
                candidate.quantifier,
                externals,
                context=context,
            )
        elif isinstance(candidate, RangeExpression):
            _validate_external_range_bounds(result, candidate, externals)


def _walk_ast_nodes(value: object) -> Iterator[ASTNode]:
    if isinstance(value, ASTNode):
        yield value
        if not is_dataclass(value):
            return
        for field in fields(value):
            yield from _walk_ast_nodes(getattr(value, field.name))
        return
    if isinstance(value, list | tuple | set | frozenset):
        for item in value:
            yield from _walk_ast_nodes(item)


def _validate_external_quantifier_value(
    result: ValidationResult,
    quantifier: object,
    externals: Mapping[str, object],
    *,
    context: str,
) -> None:
    if not isinstance(quantifier, Identifier):
        return
    value = externals.get(quantifier.name)
    if value is None:
        return
    if isinstance(value, bool):
        return
    if isinstance(value, int) and value >= 0:
        return
    result.add_error(f"Invalid {context} quantifier external '{quantifier.name}'")


def _validate_external_range_bounds(
    result: ValidationResult,
    node: RangeExpression,
    externals: Mapping[str, object],
) -> None:
    low = _static_external_integer_value(node.low, externals)
    high = _static_external_integer_value(node.high, externals)
    if low is not None and high is not None and low < 0:
        name = _external_identifier_name(node.low)
        if name is None:
            result.add_error("Range lower bound must not be negative")
        else:
            result.add_error(f"Range lower bound external '{name}' must not be negative")
        return
    if low is not None and high is not None and low > high:
        result.add_error(
            "Range lower bound external value must be less than or equal to upper bound"
        )


def _static_external_integer_value(
    value: object,
    externals: Mapping[str, object],
) -> int | None:
    if isinstance(value, IntegerLiteral) and isinstance(value.value, int):
        return value.value
    if isinstance(value, ParenthesesExpression):
        return _static_external_integer_value(value.expression, externals)
    name = _external_identifier_name(value)
    if name is None or name not in externals:
        return None
    external_value = externals[name]
    if isinstance(external_value, bool):
        return int(external_value)
    if isinstance(external_value, int):
        return external_value
    return None


def _external_identifier_name(value: object) -> str | None:
    if isinstance(value, Identifier):
        return value.name
    if isinstance(value, ParenthesesExpression):
        return _external_identifier_name(value.expression)
    return None


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
