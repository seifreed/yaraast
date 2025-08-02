"""Meta-related AST nodes."""

from dataclasses import dataclass, field
from typing import Any, Union

from yaraast.ast.base import ASTNode


@dataclass
class Meta(ASTNode):
    """Meta information node."""

    key: str
    value: Union[str, int, bool]

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_meta(self)
