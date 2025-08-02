"""Comment-preserving YARA lexer implementation."""

from yaraast.lexer.lexer import Lexer
from yaraast.lexer.tokens import Token, TokenType


class CommentPreservingLexer(Lexer):
    """YARA lexer that preserves comments."""

    def __init__(self, text: str):
        super().__init__(text)
        self.preserve_comments = True

    def tokenize(self) -> list[Token]:
        """Tokenize input text and preserve comments."""
        tokens = []

        while self.position < len(self.text):
            # Check for comments before skipping whitespace
            if self._check_comment():
                comment_token = self._read_comment()
                if comment_token and self.preserve_comments:
                    tokens.append(comment_token)
            else:
                # Skip only whitespace, not comments
                self._skip_whitespace()

                if self.position >= len(self.text):
                    break

                token = self._next_token()
                if token:
                    tokens.append(token)

        tokens.append(Token(TokenType.EOF, "", self.line, self.column, 0))
        return tokens

    def _check_comment(self) -> bool:
        """Check if current position starts a comment."""
        char = self._current_char()
        return char == "/" and (self._peek_char() == "/" or self._peek_char() == "*")

    def _read_comment(self) -> Token | None:
        """Read a comment token."""
        start_line = self.line
        start_column = self.column

        if self._current_char() == "/" and self._peek_char() == "/":
            # Single-line comment
            self._advance()  # skip first /
            self._advance()  # skip second /

            comment_text = ""
            while self._current_char() and self._current_char() != "\n":
                comment_text += self._current_char()
                self._advance()

            # Include the newline in tokenization
            if self._current_char() == "\n":
                self._advance()

            return Token(
                TokenType.COMMENT,
                f"//{comment_text}",
                start_line,
                start_column,
                len(comment_text) + 2,
            )

        if self._current_char() == "/" and self._peek_char() == "*":
            # Multi-line comment
            self._advance()  # skip /
            self._advance()  # skip *

            comment_text = "/*"
            while self.position < len(self.text) - 1:
                comment_text += self._current_char()
                if self._current_char() == "*" and self._peek_char() == "/":
                    self._advance()  # skip *
                    comment_text += self._current_char()  # add /
                    self._advance()  # skip /
                    break
                self._advance()

            return Token(
                TokenType.COMMENT, comment_text, start_line, start_column, len(comment_text)
            )

        return None

    def _skip_whitespace(self) -> None:
        """Skip only whitespace, not comments."""
        while self.position < len(self.text):
            char = self._current_char()
            if char in " \t\r\n":
                self._advance()
            else:
                break

    def _skip_whitespace_and_comments(self) -> None:
        """Override to prevent comment skipping when getting tokens."""
        # In comment-preserving mode, we handle comments separately
        if not self.preserve_comments:
            super()._skip_whitespace_and_comments()
        else:
            self._skip_whitespace()
