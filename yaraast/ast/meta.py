"""Meta-related AST nodes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from yaraast.ast.base import ASTNode


@dataclass
class Meta(ASTNode):
    """Meta information node."""

    key: str
    value: str | int | bool

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_meta(self)
