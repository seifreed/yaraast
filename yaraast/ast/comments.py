"""Comment-related AST nodes."""

from dataclasses import dataclass
from typing import Any

from yaraast.ast.base import ASTNode, _VisitorType


@dataclass
class Comment(ASTNode):
    """Represents a comment in the source code."""

    text: str
    is_multiline: bool = False

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_comment(self)


@dataclass
class CommentGroup(ASTNode):
    """Group of consecutive comments."""

    comments: list[Comment]

    @property
    def text(self) -> str:
        """Return the group text as newline-separated comment text."""
        return "\n".join(comment.text for comment in self.comments)

    @text.setter
    def text(self, value: str) -> None:
        lines = value.splitlines() or [""]
        self.comments = [Comment(line) for line in lines]

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_comment_group(self)
