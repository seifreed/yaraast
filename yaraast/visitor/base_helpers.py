"""Shared helpers for BaseVisitor."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, TypeVar, cast

from yaraast.ast.base import ASTNode
from yaraast.visitor.visitor import ASTVisitor

T = TypeVar("T", covariant=True)


class VisitorHelperProtocol(Protocol[T]):
    def _noop(self) -> T: ...

    def _visit_all(self, items: Sequence[object]) -> None: ...

    def _visit_if(self, node: ASTNode | None) -> None: ...

    def _visit_value(self, value: object) -> None: ...


class BaseVisitorHelpersMixin[T]:
    """Helper methods for BaseVisitor traversal."""

    def _default_visit(self, node: ASTNode) -> T:
        return cast(T, None)

    def _noop(self) -> T:
        return cast(T, None)

    def _visit_all(self, items: Sequence[object]) -> None:
        visitor = cast(ASTVisitor[T], self)
        for item in items:
            if isinstance(item, ASTNode):
                visitor.visit(item)

    def _visit_if(self, node: ASTNode | None) -> None:
        if node is None:
            return
        if not isinstance(node, ASTNode):
            msg = "Visitor child must be an ASTNode"
            raise TypeError(msg)
        visitor = cast(ASTVisitor[T], self)
        visitor.visit(node)

    def _visit_value(self, value: object) -> None:
        visitor = cast(ASTVisitor[T], self)
        if isinstance(value, ASTNode):
            visitor.visit(value)
        elif isinstance(value, dict):
            for item in value.values():
                self._visit_value(item)
        elif isinstance(value, list | tuple | set | frozenset):
            for item in value:
                self._visit_value(item)
