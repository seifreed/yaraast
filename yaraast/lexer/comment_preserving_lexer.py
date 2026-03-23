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
        # First pass: extract comments and their positions
        comment_tokens, text_without_comments = self._strip_comments()

        # Second pass: tokenize text without comments using base lexer
        modified_text = "".join(text_without_comments)
        base_lexer = Lexer(modified_text)
        regular_tokens = base_lexer.tokenize()

        # Merge comment tokens into the regular token stream
        all_tokens = self._merge_comment_tokens(regular_tokens, comment_tokens)

        # Store comments separately
        self.comments = comment_tokens

        return all_tokens

    def _strip_comments(self) -> tuple[list[Token], list[str]]:
        """First pass: extract comments and build text with comments replaced by spaces."""
        comment_tokens: list[Token] = []
        text_without_comments: list[str] = []
        line_num = 1
        col_num = 1
        i = 0

        while i < len(self.text):
            # Check for line comment
            if i < len(self.text) - 1 and self.text[i : i + 2] == "//":
                start_line = line_num
                start_col = col_num
                comment_text = "//"
                i += 2
                col_num += 2

                # Read until end of line
                while i < len(self.text) and self.text[i] != "\n":
                    comment_text += self.text[i]
                    i += 1
                    col_num += 1

                if self.preserve_comments:
                    comment_tokens.append(
                        Token(
                            TokenType.COMMENT,
                            comment_text,
                            start_line,
                            start_col,
                            len(comment_text),
                        )
                    )

                # Replace comment with space to preserve positions
                text_without_comments.append(" " * len(comment_text))
                continue

            # Check for block comment
            if i < len(self.text) - 1 and self.text[i : i + 2] == "/*":
                start_line = line_num
                start_col = col_num
                comment_text = "/*"
                i += 2
                col_num += 2

                # Read until */
                while i < len(self.text):
                    if self.text[i : i + 2] == "*/":
                        comment_text += "*/"
                        i += 2
                        col_num += 2
                        break
                    if self.text[i] == "\n":
                        line_num += 1
                        col_num = 1
                    else:
                        col_num += 1
                    comment_text += self.text[i]
                    i += 1

                if self.preserve_comments:
                    comment_tokens.append(
                        Token(
                            TokenType.COMMENT,
                            comment_text,
                            start_line,
                            start_col,
                            len(comment_text),
                        )
                    )

                # Replace comment with spaces (preserving newlines for line tracking)
                for c in comment_text:
                    text_without_comments.append(c if c == "\n" else " ")
                continue

            # Regular character
            text_without_comments.append(self.text[i])
            i += 1

            if self.text[i - 1] == "\n":
                line_num += 1
                col_num = 1
            else:
                col_num += 1

        return comment_tokens, text_without_comments

    @staticmethod
    def _merge_comment_tokens(
        regular_tokens: list[Token], comment_tokens: list[Token]
    ) -> list[Token]:
        """Merge comment tokens into regular tokens, sorted by position."""
        all_tokens = list(regular_tokens[:-1])  # Exclude EOF for now
        all_tokens.extend(comment_tokens)

        # Sort by line, then column
        all_tokens.sort(key=lambda t: (t.line, t.column))

        # Add EOF at the end
        all_tokens.append(regular_tokens[-1])

        return all_tokens

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

        # Preserve the trailing character for unterminated block comments.
        if self.position == len(self.text) - 1 and self._current_char() is not None:
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
