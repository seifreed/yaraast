"""Condition-related AST nodes."""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any

from yaraast.ast.base import _VisitorType
from yaraast.ast.expressions import Expression, _validate_expression

type QuantifierValue = Expression | str | int | float
type StringSetItem = str | Expression
type StringSetValue = (
    Expression
    | str
    | list[StringSetItem]
    | tuple[StringSetItem, ...]
    | set[StringSetItem]
    | frozenset[StringSetItem]
)


def _validate_required_expression(value: Any, message: str) -> Expression:
    if not isinstance(value, Expression):
        raise TypeError(message)
    validate_structure = getattr(value, "validate_structure", None)
    if callable(validate_structure):
        validate_structure()
    return value


def _validate_quantifier(value: Any, field_name: str) -> None:
    if isinstance(value, Expression):
        _validate_expression(value, field_name)
        return
    if isinstance(value, str):
        if not value.strip():
            msg = f"{field_name} must not be empty"
            raise ValueError(msg)
        return
    if isinstance(value, bool) or not isinstance(value, int | float):
        msg = f"{field_name} must be a string, number, or expression"
        raise TypeError(msg)
    if not math.isfinite(value):
        msg = f"{field_name} must be finite"
        raise ValueError(msg)


def _validate_string_or_expression(value: Any, field_name: str, type_message: str) -> None:
    if isinstance(value, Expression):
        _validate_expression(value, field_name)
        return
    if not isinstance(value, str):
        raise TypeError(type_message)
    if not value.strip():
        msg = f"{field_name} must not be empty"
        raise ValueError(msg)


def _validate_string_set(value: Any, field_name: str) -> None:
    if value is None or isinstance(value, dict):
        msg = f"{field_name} is required"
        raise ValueError(msg)
    if isinstance(value, Expression):
        _validate_expression(value, field_name)
        return
    if isinstance(value, str):
        if not value.strip():
            msg = f"{field_name} must contain values"
            raise ValueError(msg)
        return
    if not isinstance(value, list | tuple | set | frozenset):
        msg = f"{field_name} must be a string, expression, or collection"
        raise TypeError(msg)
    if len(value) == 0:
        msg = f"{field_name} must contain values"
        raise ValueError(msg)
    for item in value:
        if item is None or isinstance(item, dict):
            msg = f"{field_name} must contain values"
            raise ValueError(msg)
        if isinstance(item, Expression):
            _validate_expression(item, field_name)
            continue
        if isinstance(item, str):
            if not item.strip():
                msg = f"{field_name} must contain values"
                raise ValueError(msg)
            continue
        msg = f"{field_name} must contain strings or expressions"
        raise TypeError(msg)


@dataclass
class Condition(Expression):
    """Base class for conditions."""

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_condition(self)


@dataclass
class ForExpression(Condition):
    """For expression (for any/all i in ...)."""

    quantifier: QuantifierValue
    variable: str
    iterable: Expression
    body: Expression

    def validate_structure(self) -> None:
        """Validate loop fields before direct analysis."""
        _validate_quantifier(self.quantifier, "ForExpression quantifier")
        if not isinstance(self.variable, str):
            msg = "ForExpression variable must be a string"
            raise TypeError(msg)
        if not self.variable.strip():
            msg = "ForExpression variable must not be empty"
            raise ValueError(msg)
        from yaraast.shared.local_scope import local_name_variants

        local_name_variants(self.variable)
        _validate_required_expression(
            self.iterable,
            "ForExpression iterable must be an AST expression",
        )
        _validate_required_expression(
            self.body,
            "ForExpression body must be an AST expression",
        )

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_for_expression(self)


@dataclass
class ForOfExpression(Condition):
    """For...of expression (for any of ($a, $b))."""

    quantifier: QuantifierValue
    string_set: StringSetValue
    condition: Expression | None = None

    def validate_structure(self) -> None:
        """Validate for-of fields before direct analysis."""
        _validate_quantifier(self.quantifier, "ForOfExpression quantifier")
        _validate_string_set(self.string_set, "ForOfExpression string_set")
        if self.condition is not None:
            _validate_required_expression(
                self.condition,
                "ForOfExpression condition must be an AST expression",
            )

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_for_of_expression(self)


@dataclass
class AtExpression(Condition):
    """At expression ($a at offset or all of them at offset)."""

    string_id: str | Expression
    offset: Expression

    def validate_structure(self) -> None:
        """Validate string reference and offset before direct analysis."""
        _validate_string_or_expression(
            self.string_id,
            "AtExpression string_id",
            "AtExpression string_id must be a string or expression",
        )
        _validate_required_expression(self.offset, "'at' offset must be an AST node")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_at_expression(self)


@dataclass
class InExpression(Condition):
    """In expression ($a in range, #a in range, or all of ($a*) in range)."""

    subject: str | Expression  # Either string_id (str) or OfExpression
    range: Expression

    # Backward compatibility property
    @property
    def string_id(self) -> str | None:
        """Return string_id if subject is a string, None otherwise."""
        _validate_string_or_expression(
            self.subject,
            "InExpression subject",
            "InExpression subject must be a string or expression",
        )
        return self.subject if isinstance(self.subject, str) else None

    def validate_structure(self) -> None:
        """Validate subject and range before direct analysis."""
        _validate_string_or_expression(
            self.subject,
            "InExpression subject",
            "InExpression subject must be a string or expression",
        )
        _validate_required_expression(self.range, "'in' range must be an AST node")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_in_expression(self)


@dataclass
class OfExpression(Condition):
    """Of expression (N of ($a, $b, $c))."""

    quantifier: QuantifierValue
    string_set: StringSetValue

    def validate_structure(self) -> None:
        """Validate of-expression fields before direct analysis."""
        _validate_quantifier(self.quantifier, "OfExpression quantifier")
        _validate_string_set(self.string_set, "OfExpression string_set")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_of_expression(self)
