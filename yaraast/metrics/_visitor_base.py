"""Default visitor implementations for metrics modules."""

from __future__ import annotations

from typing import Any

from yaraast.visitor.defaults import DefaultASTVisitor


class MetricsVisitorBase(DefaultASTVisitor[Any]):
    """ASTVisitor with default no-op implementations."""

    def __init__(self, default: Any = None) -> None:
        super().__init__(default=default)
