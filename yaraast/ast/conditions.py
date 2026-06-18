"""Condition-related AST nodes."""

from __future__ import annotations

from dataclasses import dataclass
import math
import re
from typing import Any

from yaraast.ast.base import _VisitorType
from yaraast.ast.expressions import Expression, _validate_expression, _validate_integer_expression
from yaraast.string_references import normalize_string_reference_id

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

_INTEGER_QUANTIFIER_RE = re.compile(r"^-?\d+$")
_PERCENTAGE_QUANTIFIER_RE = re.compile(r"^\d+%$")
_QUANTIFIER_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _validate_required_expression(value: Any, message: str) -> Expression:
    if not isinstance(value, Expression):
        raise TypeError(message)
    validate_structure = getattr(value, "validate_structure", None)
    if callable(validate_structure):
        validate_structure()
    return value


def _invalid_quantifier(value: Any, field_name: str) -> None:
    msg = f"Invalid {field_name} '{value}'"
    raise ValueError(msg)


def _validate_percentage_quantifier_text(value: str, field_name: str) -> None:
    if _PERCENTAGE_QUANTIFIER_RE.fullmatch(value) is None:
        return
    percent = int(value.removesuffix("%"))
    if 1 <= percent <= 100:
        return
    _invalid_quantifier(value, field_name)


def _validate_quantifier_text(value: str, field_name: str, *, allow_percentage: bool) -> None:
    if not value.strip():
        msg = f"{field_name} must not be empty"
        raise ValueError(msg)
    if value in {"all", "any", "none"}:
        return
    if _INTEGER_QUANTIFIER_RE.fullmatch(value) is not None:
        if int(value) < 0:
            _invalid_quantifier(value, field_name)
        return
    if value.endswith("%"):
        if not allow_percentage:
            _invalid_quantifier(value, field_name)
        _validate_percentage_quantifier_text(value, field_name)
        if _PERCENTAGE_QUANTIFIER_RE.fullmatch(value) is not None:
            return
    if any(marker in value for marker in (".", "e", "E")):
        try:
            parsed_float = float(value)
        except ValueError:
            pass
        else:
            if not math.isfinite(parsed_float):
                msg = f"{field_name} must be finite"
                raise ValueError(msg)
            _invalid_quantifier(value, field_name)
    if _QUANTIFIER_IDENTIFIER_RE.fullmatch(value) is not None:
        return
    _invalid_quantifier(value, field_name)


def _validate_quantifier(value: Any, field_name: str, *, allow_percentage: bool) -> None:
    if isinstance(value, Expression):
        _validate_expression(value, field_name)
        return
    if isinstance(value, str):
        _validate_quantifier_text(value, field_name, allow_percentage=allow_percentage)
        return
    if isinstance(value, bool) or not isinstance(value, int | float):
        msg = f"{field_name} must be a string, number, or expression"
        raise TypeError(msg)
    if not math.isfinite(value):
        msg = f"{field_name} must be finite"
        raise ValueError(msg)
    if isinstance(value, int):
        if value < 0:
            _invalid_quantifier(value, field_name)
        return
    if not allow_percentage:
        _invalid_quantifier(value, field_name)
    percent = round(value * 100)
    if 1 <= percent <= 100:
        return
    _invalid_quantifier(value, field_name)


def _validate_string_reference_or_expression(
    value: Any,
    field_name: str,
    type_message: str,
) -> None:
    if isinstance(value, Expression):
        _validate_expression(value, field_name)
        return
    if not isinstance(value, str):
        raise TypeError(type_message)
    if not value.strip():
        msg = f"{field_name} must not be empty"
        raise ValueError(msg)
    if value == "$":
        return
    normalize_string_reference_id(value, allow_wildcard=False)


def _validate_string_set_text(value: str, field_name: str) -> None:
    if not value.strip():
        msg = f"{field_name} must contain values"
        raise ValueError(msg)
    if value == "them":
        return
    normalize_string_reference_id(value, allow_wildcard=True)


def _classify_string_set_value(value: Any) -> str | None:
    from yaraast.ast.expressions import (
        Identifier,
        ParenthesesExpression,
        SetExpression,
        StringIdentifier,
        StringLiteral,
        StringWildcard,
    )

    if isinstance(value, ParenthesesExpression):
        return _classify_string_set_value(value.expression)
    if isinstance(value, SetExpression):
        return _classify_string_set_items(value.elements)
    if isinstance(value, list | tuple | set | frozenset):
        return _classify_string_set_items(value)
    if isinstance(value, StringIdentifier):
        return "string"
    if isinstance(value, StringWildcard):
        if isinstance(value.pattern, str) and not value.pattern.startswith("$"):
            return "rule"
        return "string"
    if isinstance(value, StringLiteral):
        return "string" if isinstance(value.value, str) else None
    if isinstance(value, Identifier):
        if isinstance(value.name, str) and value.name != "them" and not value.name.startswith("$"):
            return "rule"
        return "string"
    if isinstance(value, str):
        return "string"
    return None


def _classify_string_set_items(values: Any) -> str | None:
    kind: str | None = None
    for value in values:
        value_kind = _classify_string_set_value(value)
        if value_kind is None:
            return None
        if kind is None:
            kind = value_kind
        elif kind != value_kind:
            return "mixed"
    return kind


def _validate_consistent_string_set_kind(value: Any) -> None:
    if _classify_string_set_value(value) == "mixed":
        msg = "Mixed string and rule set items are not valid"
        raise ValueError(msg)


def _is_percentage_quantifier(value: Any) -> bool:
    from yaraast.ast.expressions import (
        DoubleLiteral,
        ParenthesesExpression,
        StringLiteral,
        UnaryExpression,
    )

    if isinstance(value, float):
        return True
    if isinstance(value, str):
        return value.endswith("%")
    if isinstance(value, DoubleLiteral):
        return True
    if isinstance(value, StringLiteral):
        return isinstance(value.value, str) and value.value.endswith("%")
    if isinstance(value, UnaryExpression) and value.operator == "%":
        return True
    if isinstance(value, ParenthesesExpression):
        return _is_percentage_quantifier(value.expression)
    return False


def _validate_restricted_of_expression(value: Any) -> None:
    if not isinstance(value, OfExpression):
        return
    if _is_percentage_quantifier(value.quantifier):
        msg = "Percentage of-expressions do not support at/in restrictions"
        raise ValueError(msg)
    if _classify_string_set_value(value.string_set) == "rule":
        msg = "Rule sets cannot use at/in restrictions"
        raise ValueError(msg)


def _validate_string_set(value: Any, field_name: str) -> None:
    if value is None or isinstance(value, dict):
        msg = f"{field_name} is required"
        raise ValueError(msg)
    if isinstance(value, Expression):
        _validate_expression(value, field_name)
        return
    if isinstance(value, str):
        _validate_string_set_text(value, field_name)
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
            _validate_string_set_text(item, field_name)
            continue
        msg = f"{field_name} must contain strings or expressions"
        raise TypeError(msg)


def _is_definitely_non_for_iterable(value: Any) -> bool:
    from yaraast.ast.expressions import (
        BooleanLiteral,
        DoubleLiteral,
        IntegerLiteral,
        ParenthesesExpression,
        RegexLiteral,
        StringIdentifier,
        StringLiteral,
    )

    if isinstance(value, ParenthesesExpression):
        return _is_definitely_non_for_iterable(value.expression)
    return isinstance(
        value,
        BooleanLiteral
        | DoubleLiteral
        | IntegerLiteral
        | RegexLiteral
        | StringIdentifier
        | StringLiteral,
    )


def _is_invalid_for_iterable_set_item(value: Any) -> bool:
    from yaraast.ast.expressions import (
        BooleanLiteral,
        DoubleLiteral,
        ParenthesesExpression,
        RegexLiteral,
        StringIdentifier,
        StringWildcard,
    )

    if isinstance(value, ParenthesesExpression):
        return _is_invalid_for_iterable_set_item(value.expression)
    return isinstance(
        value,
        BooleanLiteral | DoubleLiteral | RegexLiteral | StringIdentifier | StringWildcard,
    )


def _validate_for_iterable(value: Expression) -> None:
    from yaraast.ast.expressions import SetExpression

    if _is_definitely_non_for_iterable(value):
        msg = "For expression iterable must be a range, set, or iterable expression"
        raise ValueError(msg)
    if isinstance(value, SetExpression) and any(
        _is_invalid_for_iterable_set_item(item) for item in value.elements
    ):
        msg = "For expression iterable set items must be integer or string expressions"
        raise ValueError(msg)


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
        _validate_quantifier(
            self.quantifier,
            "ForExpression quantifier",
            allow_percentage=False,
        )
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
        _validate_for_iterable(self.iterable)
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
        _validate_quantifier(
            self.quantifier,
            "ForOfExpression quantifier",
            allow_percentage=self.condition is None,
        )
        _validate_string_set(self.string_set, "ForOfExpression string_set")
        _validate_consistent_string_set_kind(self.string_set)
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
        _validate_string_reference_or_expression(
            self.string_id,
            "AtExpression string_id",
            "AtExpression string_id must be a string or expression",
        )
        _validate_restricted_of_expression(self.string_id)
        _validate_required_expression(self.offset, "'at' offset must be an AST node")
        _validate_integer_expression(self.offset, "At expression offset")

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
        _validate_string_reference_or_expression(
            self.subject,
            "InExpression subject",
            "InExpression subject must be a string or expression",
        )
        return self.subject if isinstance(self.subject, str) else None

    def validate_structure(self) -> None:
        """Validate subject and range before direct analysis."""
        _validate_string_reference_or_expression(
            self.subject,
            "InExpression subject",
            "InExpression subject must be a string or expression",
        )
        _validate_restricted_of_expression(self.subject)
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
        _validate_quantifier(
            self.quantifier,
            "OfExpression quantifier",
            allow_percentage=True,
        )
        _validate_string_set(self.string_set, "OfExpression string_set")
        _validate_consistent_string_set_kind(self.string_set)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_of_expression(self)
