"""Shared helpers for BaseVisitor."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Generic, Protocol, TypeVar, cast

from yaraast.ast.base import ASTNode
from yaraast.visitor.visitor import ASTVisitor

T = TypeVar("T", covariant=True)


class VisitorHelperProtocol(Protocol[T]):
    def _noop(self) -> T: ...

    def _visit_all(self, items: Sequence[ASTNode]) -> None: ...

    def _visit_if(self, node: ASTNode | None) -> None: ...


class BaseVisitorHelpersMixin(Generic[T]):  # noqa: UP046
    """Helper methods for BaseVisitor traversal."""

    def _noop(self) -> T:
        return cast(T, None)

    def _visit_all(self, items: Sequence[ASTNode]) -> None:
        visitor = cast(ASTVisitor[T], self)
        for item in items:
            visitor.visit(item)

    def _visit_if(self, node: ASTNode | None) -> None:
        if node:
            visitor = cast(ASTVisitor[T], self)
            visitor.visit(node)
