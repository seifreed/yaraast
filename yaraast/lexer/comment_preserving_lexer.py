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
            if i < len(self.text) - 1 and self.text[i : i + 2] == "//":
                comment_text, i, col_num = self._read_line_comment_text(i, col_num)
                if self.preserve_comments:
                    comment_tokens.append(
                        Token(
                            TokenType.COMMENT,
                            comment_text,
                            line_num,
                            col_num - len(comment_text),
                            len(comment_text),
                        )
                    )
                text_without_comments.append(" " * len(comment_text))
                continue

            if i < len(self.text) - 1 and self.text[i : i + 2] == "/*":
                start_line, start_col = line_num, col_num
                comment_text, i, line_num, col_num = self._read_block_comment_text(
                    i, line_num, col_num
                )
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
                for c in comment_text:
                    text_without_comments.append(c if c == "\n" else " ")
                continue

            text_without_comments.append(self.text[i])
            i += 1
            if self.text[i - 1] == "\n":
                line_num += 1
                col_num = 1
            else:
                col_num += 1

        return comment_tokens, text_without_comments

    def _read_line_comment_text(self, i: int, col: int) -> tuple[str, int, int]:
        """Read a // comment. Returns (text, new_i, new_col)."""
        comment = "//"
        i += 2
        col += 2
        while i < len(self.text) and self.text[i] != "\n":
            comment += self.text[i]
            i += 1
            col += 1
        return comment, i, col

    def _read_block_comment_text(self, i: int, line: int, col: int) -> tuple[str, int, int, int]:
        """Read a /* */ comment. Returns (text, new_i, new_line, new_col)."""
        comment = "/*"
        i += 2
        col += 2
        while i < len(self.text):
            if self.text[i : i + 2] == "*/":
                comment += "*/"
                i += 2
                col += 2
                break
            if self.text[i] == "\n":
                line += 1
                col = 1
            else:
                col += 1
            comment += self.text[i]
            i += 1
        return comment, i, line, col

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
