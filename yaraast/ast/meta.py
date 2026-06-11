"""Meta-related AST nodes."""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any

from yaraast.ast.base import ASTNode, _require_nonempty_string, _VisitorType


def _require_meta_value(value: Any, *, allow_float: bool) -> str | int | bool | float:
    if isinstance(value, str | bool | int):
        return value
    if allow_float and isinstance(value, float) and math.isfinite(value):
        return value
    if allow_float:
        msg = "Meta value must be a string, integer, boolean, or finite float"
    else:
        msg = "Meta value must be a string, integer, or boolean"
    raise TypeError(msg)


@dataclass
class Meta(ASTNode):
    """Meta information node."""

    key: str
    value: str | int | bool

    def validate_structure(self) -> None:
        """Validate meta scalar fields before direct analysis."""
        _require_nonempty_string(self.key, "Meta key")
        _require_meta_value(self.value, allow_float=hasattr(self, "scope"))

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_meta(self)
