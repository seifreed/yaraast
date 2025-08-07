"""Comment-preserving YARA lexer implementation."""

from __future__ import annotations

from yaraast.lexer.lexer import Lexer
from yaraast.lexer.tokens import Token, TokenType


class CommentPreservingLexer(Lexer):
    """YARA lexer that preserves comments."""

    def __init__(self, text: str) -> None:
        super().__init__(text)
        self.preserve_comments = True
        self.comments: list[Token] = []

    def tokenize(self) -> list[Token]:
        """Tokenize input text and preserve comments."""
        tokens = []

        while self.position < len(self.text):
            # Skip only whitespace, not comments
            while self.position < len(self.text) and self._current_char() in " \t\r\n":
                if self._current_char() == "\n":
                    self.line += 1
                    self.column = 1
                else:
                    self.column += 1
                self.position += 1

            if self.position >= len(self.text):
                break

            # Check for comments
            if self._current_char() == "/" and self.position + 1 < len(self.text):
                if self.text[self.position + 1] == "/":
                    comment_token = self._read_line_comment()
                    if self.preserve_comments and comment_token:
                        tokens.append(comment_token)
                        self.comments.append(comment_token)
                    continue
                if self.text[self.position + 1] == "*":
                    comment_token = self._read_block_comment()
                    if self.preserve_comments and comment_token:
                        tokens.append(comment_token)
                        self.comments.append(comment_token)
                    continue

            # Regular token
            token = self._next_token()
            if token:
                tokens.append(token)

        tokens.append(Token(TokenType.EOF, "", self.line, self.column, 0))
        return tokens

    def _read_line_comment(self) -> Token | None:
        """Read a line comment starting with //."""
        start_line = self.line
        start_column = self.column
        start_pos = self.position

        # Skip //
        self._advance()
        self._advance()

        # Read until end of line
        comment_text = "//"
        while self._current_char() and self._current_char() != "\n":
            comment_text += self._current_char()
            self._advance()

        return Token(
            TokenType.COMMENT,
            comment_text,
            start_line,
            start_column,
            self.position - start_pos,
        )

    def _read_block_comment(self) -> Token | None:
        """Read a block comment starting with /*."""
        start_line = self.line
        start_column = self.column
        start_pos = self.position

        # Skip /*
        self._advance()
        self._advance()

        # Read until */
        comment_text = "/*"
        while self.position < len(self.text) - 1:
            if self._current_char() == "*" and self._peek_char(1) == "/":
                comment_text += "*/"
                self._advance()
                self._advance()
                break
            comment_text += self._current_char()
            self._advance()

        return Token(
            TokenType.COMMENT,
            comment_text,
            start_line,
            start_column,
            self.position - start_pos,
        )

    def get_comments(self) -> list[Token]:
        """Get all collected comments."""
        return self.comments

    def set_preserve_comments(self, preserve: bool) -> None:
        """Set whether to preserve comments."""
        self.preserve_comments = preserve

    def clear_comments(self) -> None:
        """Clear collected comments."""
        self.comments.clear()
