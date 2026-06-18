"""Operator-specific AST nodes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from yaraast.ast.base import _VisitorType
from yaraast.ast.expressions import Expression, _validate_expression

_VALID_STRING_OPERATORS = frozenset(
    {
        "contains",
        "endswith",
        "icontains",
        "iendswith",
        "iequals",
        "istartswith",
        "matches",
        "startswith",
    }
)


def _validate_required_expression(value: Any, message: str) -> Expression:
    if not isinstance(value, Expression):
        raise TypeError(message)
    return _validate_expression(value, message)


@dataclass
class DefinedExpression(Expression):
    """Defined operator expression."""

    expression: Expression

    def validate_structure(self) -> None:
        """Validate wrapped expression before direct analysis."""
        _validate_required_expression(
            self.expression,
            "DefinedExpression expression must be an AST expression",
        )

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_defined_expression(self)


@dataclass
class StringOperatorExpression(Expression):
    """String comparison operator expression (iequals, icontains, etc.)."""

    left: Expression
    operator: str  # "iequals", "icontains", "istartswith", "iendswith"
    right: Expression

    def validate_structure(self) -> None:
        """Validate operands and operator before direct analysis."""
        _validate_required_expression(
            self.left,
            "StringOperatorExpression left must be an AST expression",
        )
        if not isinstance(self.operator, str):
            msg = "StringOperatorExpression operator must be a string"
            raise TypeError(msg)
        if not self.operator.strip():
            msg = "StringOperatorExpression operator must not be empty"
            raise ValueError(msg)
        if self.operator not in _VALID_STRING_OPERATORS:
            msg = f"Invalid string operator '{self.operator}'"
            raise ValueError(msg)
        _validate_required_expression(
            self.right,
            "StringOperatorExpression right must be an AST expression",
        )

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_string_operator_expression(self)
