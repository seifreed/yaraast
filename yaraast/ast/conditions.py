"""Condition-related AST nodes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from yaraast.ast.expressions import Expression


@dataclass
class Condition(Expression):
    """Base class for conditions."""

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_condition(self)


@dataclass
class ForExpression(Condition):
    """For expression (for any/all i in ...)."""

    quantifier: str
    variable: str
    iterable: Expression
    body: Expression

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_for_expression(self)


@dataclass
class ForOfExpression(Condition):
    """For...of expression (for any of ($a, $b))."""

    quantifier: str
    string_set: Expression
    condition: Expression | None = None

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_for_of_expression(self)


@dataclass
class AtExpression(Condition):
    """At expression ($a at offset)."""

    string_id: str
    offset: Expression

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_at_expression(self)


@dataclass
class InExpression(Condition):
    """In expression ($a in (offset..offset))."""

    string_id: str
    range: Expression

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_in_expression(self)


@dataclass
class OfExpression(Condition):
    """Of expression (N of ($a, $b, $c))."""

    quantifier: Expression
    string_set: Expression

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_of_expression(self)
