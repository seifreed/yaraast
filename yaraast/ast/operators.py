"""Operator-specific AST nodes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from yaraast.ast.expressions import Expression


@dataclass
class DefinedExpression(Expression):
    """Defined operator expression."""

    expression: Expression

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_defined_expression(self)


@dataclass
class StringOperatorExpression(Expression):
    """String comparison operator expression (iequals, icontains, etc.)."""

    left: Expression
    operator: str  # "iequals", "icontains", "istartswith", "iendswith"
    right: Expression

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_string_operator_expression(self)
