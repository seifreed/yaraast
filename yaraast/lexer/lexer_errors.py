"""Lexer error types."""

from __future__ import annotations

from yaraast.errors import YaraASTError


class LexerError(YaraASTError):
    """Lexer error exception."""

    def __init__(self, message: str, line: int, column: int) -> None:
        super().__init__(f"Lexer error at {line}:{column}: {message}")
        self.line = line
        self.column = column
