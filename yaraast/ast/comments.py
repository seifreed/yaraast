"""Comment-related AST nodes."""

from dataclasses import dataclass
from typing import Any

from yaraast.ast.base import ASTNode, _VisitorType


def _validate_comment_text(text: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in text):
        msg = "Comment text must not contain Unicode surrogate code points"
        raise ValueError(msg)
    if "\x00" in text:
        msg = "Comment text must not contain embedded NUL characters"
        raise ValueError(msg)
    if text.startswith("/*") and text.endswith("*/"):
        body = text[2:-2]
        if "*/" in body:
            msg = "Block comment text must not contain embedded terminators"
            raise ValueError(msg)
        return
    if "\n" in text or "\r" in text:
        msg = "Comment text must not contain newlines"
        raise ValueError(msg)


@dataclass
class Comment(ASTNode):
    """Represents a comment in the source code."""

    text: str
    is_multiline: bool = False

    def validate_structure(self) -> None:
        """Validate comment scalar fields before direct analysis."""
        if not isinstance(self.text, str):
            msg = "Comment text must be a string"
            raise TypeError(msg)
        _validate_comment_text(self.text)
        if not isinstance(self.is_multiline, bool):
            msg = "Comment is_multiline must be a boolean"
            raise TypeError(msg)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_comment(self)


@dataclass
class CommentGroup(ASTNode):
    """Group of consecutive comments."""

    comments: list[Comment]

    def validate_structure(self) -> None:
        """Validate grouped comments before direct analysis."""
        if not isinstance(self.comments, list):
            msg = "CommentGroup comments must be a list"
            raise TypeError(msg)
        for comment in self.comments:
            if not isinstance(comment, Comment):
                msg = "CommentGroup comments must contain Comment nodes"
                raise TypeError(msg)
            comment.validate_structure()

    @property
    def text(self) -> str:
        """Return the group text as newline-separated comment text."""
        self.validate_structure()
        return "\n".join(comment.text for comment in self.comments)

    @text.setter
    def text(self, value: str) -> None:
        lines = value.splitlines() or [""]
        self.comments = [Comment(line) for line in lines]

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_comment_group(self)
