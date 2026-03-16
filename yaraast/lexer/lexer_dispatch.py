"""Token dispatch helpers for the lexer."""

from __future__ import annotations

from yaraast.lexer.lexer_errors import LexerError
from yaraast.lexer.lexer_tables import SINGLE_CHAR_TOKENS, TWO_CHAR_OPERATORS
from yaraast.lexer.tokens import Token, TokenType


def read_next_token(lexer) -> Token | None:
    """Read the next token from a lexer instance."""
    start_line = lexer.line
    start_column = lexer.column
    char = lexer._current_char()

    if not char:
        return None

    if char == '"':
        return lexer._read_string()
    if char == "{" and lexer._is_hex_string_context():
        return lexer._read_hex_string()
    if char == "/" and lexer._is_regex_context():
        return lexer._read_regex()
    if char.isdigit() or (char == "0" and lexer._peek_char() in "xX"):
        return lexer._read_number()
    if char.isalpha() or char == "_":
        return lexer._read_identifier()
    if char == "$":
        return lexer._read_string_identifier()
    if char == "#":
        return lexer._read_string_count()
    if char == "@":
        return lexer._read_string_offset()

    if lexer.position < len(lexer.text) - 1:
        two_char = lexer.text[lexer.position : lexer.position + 2]
        token_type = get_two_char_operator(two_char)
        if token_type:
            lexer._advance()
            lexer._advance()
            return Token(token_type, two_char, start_line, start_column, 2)

    if char == "!":
        return lexer._read_string_length()

    token_type = get_single_char_token(char)
    if token_type:
        lexer._advance()
        return Token(token_type, char, start_line, start_column, 1)

    if char == "\\" and lexer._peek_char() in (" ", "\t"):
        lexer._advance()
        return Token(TokenType.DIVIDE, "/", start_line, start_column, 1)

    msg = f"Unexpected character: {char}"
    raise LexerError(msg, lexer.line, lexer.column)


def get_two_char_operator(chars: str) -> TokenType | None:
    """Get token type for two-character operators."""
    return TWO_CHAR_OPERATORS.get(chars)


def get_single_char_token(char: str) -> TokenType | None:
    """Get token type for single-character tokens."""
    return SINGLE_CHAR_TOKENS.get(char)
