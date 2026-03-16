"""Base visitor implementations."""

from __future__ import annotations

from typing import TypeVar

from yaraast.visitor.base_expressions import BaseVisitorExpressionsMixin
from yaraast.visitor.base_helpers import BaseVisitorHelpersMixin
from yaraast.visitor.base_misc import BaseVisitorMiscMixin
from yaraast.visitor.base_rules import BaseVisitorRulesMixin
from yaraast.visitor.base_strings import BaseVisitorStringsMixin
from yaraast.visitor.transformer_impl import ASTTransformer
from yaraast.visitor.visitor import ASTVisitor

T = TypeVar("T")


class BaseVisitor(
    BaseVisitorHelpersMixin[T],
    BaseVisitorRulesMixin,
    BaseVisitorStringsMixin,
    BaseVisitorExpressionsMixin,
    BaseVisitorMiscMixin,
    ASTVisitor[T],
):
    """Base visitor with default no-op implementations and traversal."""

    pass


__all__ = ["ASTTransformer", "BaseVisitor"]
