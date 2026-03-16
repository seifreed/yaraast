"""YARA lexer implementation.

Copyright (c) Marc Rivero López
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

from __future__ import annotations

from yaraast.lexer.lexer_dispatch import (
    get_single_char_token,
    get_two_char_operator,
    read_next_token,
)
from yaraast.lexer.lexer_helpers import skip_whitespace_and_comments
from yaraast.lexer.lexer_readers import (
    is_hex_string_context,
    is_regex_context,
    read_hex_string,
    read_identifier,
    read_number,
    read_regex,
    read_string,
    read_string_count,
    read_string_identifier,
    read_string_length,
    read_string_offset,
)
from yaraast.lexer.lexer_state import LexerState
from yaraast.lexer.lexer_tables import KEYWORDS as LEXER_KEYWORDS
from yaraast.lexer.tokens import Token, TokenType


class Lexer:
    """YARA lexer for tokenizing YARA rules.

    Implements the ILexer protocol for dependency injection support.
    The Lexer class implicitly satisfies the ILexer Protocol through
    structural subtyping (duck typing) by implementing the tokenize method.
    """

    KEYWORDS = LEXER_KEYWORDS

    def __init__(self, text: str | None = None) -> None:
        """Initialize lexer.

        Args:
            text: Optional YARA code to tokenize. If provided, can call
                  tokenize() without arguments. If None, text must be
                  passed to tokenize().
        """
        self.state = LexerState(text if text is not None else "")
        self.tokens: list[Token] = []

    @property
    def text(self) -> str:
        return self.state.text

    @text.setter
    def text(self, value: str) -> None:
        self.state.text = value

    @property
    def position(self) -> int:
        return self.state.position

    @position.setter
    def position(self, value: int) -> None:
        self.state.position = value

    @property
    def line(self) -> int:
        return self.state.line

    @line.setter
    def line(self, value: int) -> None:
        self.state.line = value

    @property
    def column(self) -> int:
        return self.state.column

    @column.setter
    def column(self, value: int) -> None:
        self.state.column = value

    def tokenize(self, text: str | None = None) -> list[Token]:
        """Tokenize the input text and return list of tokens.

        Args:
            text: Optional YARA code to tokenize. If provided, will tokenize
                  this text. If None, uses text from constructor.

        Returns:
            A list of Token objects representing the tokenized input.
            The list always ends with an EOF token.
        """
        if text is not None:
            self.state.reset(text)
            self.tokens = []

        while self.position < len(self.text):
            self._skip_whitespace_and_comments()

            if self.position >= len(self.text):
                break

            token = self._next_token()
            if token:
                self.tokens.append(token)

        self.tokens.append(Token(TokenType.EOF, None, self.line, self.column))
        return self.tokens

    def _current_char(self) -> str | None:
        """Get current character."""
        if self.position < len(self.text):
            return self.text[self.position]
        return None

    def _peek_char(self, offset: int = 1) -> str | None:
        """Peek at character at offset."""
        pos = self.position + offset
        if pos < len(self.text):
            return self.text[pos]
        return None

    def _advance(self) -> None:
        """Advance position and update line/column."""
        if self.position < len(self.text):
            if self.text[self.position] == "\n":
                self.line += 1
                self.column = 1
            else:
                self.column += 1
            self.position += 1

    def _skip_whitespace_and_comments(self) -> None:
        """Skip whitespace, comments, and line continuations."""
        skip_whitespace_and_comments(self)

    def _next_token(self) -> Token | None:
        """Get next token."""
        return read_next_token(self)

    def _read_string(self) -> Token:
        """Read string literal."""
        return read_string(self)

    def _read_hex_string(self) -> Token:
        """Read hex string."""
        return read_hex_string(self)

    def _read_regex(self) -> Token:
        """Read regular expression."""
        return read_regex(self)

    def _read_number(self) -> Token:
        """Read number (integer or double)."""
        return read_number(self)

    def _read_identifier(self) -> Token:
        """Read identifier or keyword."""
        return read_identifier(self)

    def _read_string_identifier(self) -> Token:
        """Read string identifier ($name) or wildcard pattern ($name*)."""
        return read_string_identifier(self)

    def _read_string_count(self) -> Token:
        """Read string count (#name)."""
        return read_string_count(self)

    def _read_string_offset(self) -> Token:
        """Read string offset (@name)."""
        return read_string_offset(self)

    def _read_string_length(self) -> Token:
        """Read string length (!name)."""
        return read_string_length(self)

    def _get_two_char_operator(self, chars: str) -> TokenType | None:
        """Get token type for two-character operators."""
        return get_two_char_operator(chars)

    def _get_single_char_token(self, char: str) -> TokenType | None:
        """Get token type for single-character tokens."""
        return get_single_char_token(char)

    def _is_line_continuation(self) -> bool:
        """Check if backslash is a line continuation.

        A line continuation is a backslash followed by optional whitespace and a newline.
        """
        if self._current_char() != "\\":
            return False

        # Look ahead to see if there's a newline (possibly with whitespace before it)
        pos = self.position + 1
        while pos < len(self.text) and self.text[pos] in " \t":
            pos += 1

        # Check if we have a newline
        return bool(pos < len(self.text) and self.text[pos] in "\r\n")

    def _is_regex_context(self) -> bool:
        """Check if we're in a regex context."""
        return is_regex_context(self)

    def _is_hex_string_context(self) -> bool:
        """Check if we're in a hex string context (inside strings section)."""
        return is_hex_string_context(self)
