"""Comment-related AST nodes."""

from dataclasses import dataclass
from typing import Any

from yaraast.ast.base import ASTNode


@dataclass
class Comment(ASTNode):
    """Represents a comment in the source code."""

    text: str
    is_multiline: bool = False

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_comment(self)


@dataclass
class CommentGroup(ASTNode):
    """Group of consecutive comments."""

    comments: list[Comment]

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_comment_group(self)
