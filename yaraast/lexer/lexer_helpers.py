"""Helper routines for lexer whitespace/comment handling."""

from __future__ import annotations

from yaraast.lexer.protocols import LexerLike


def skip_whitespace_and_comments(lexer: LexerLike) -> None:
    """Skip whitespace, comments, and line continuations."""
    while lexer.position < len(lexer.text):
        char = lexer._current_char()

        if char is not None and char in " \t\r\n":
            lexer._advance()
            continue

        if char == "\\" and lexer._is_line_continuation():
            _skip_line_continuation(lexer)
            continue

        if char == "/" and lexer._peek_char() == "/":
            _skip_line_comment(lexer)
            continue

        if char == "/" and lexer._peek_char() == "*":
            _skip_block_comment(lexer)
            continue

        break


def _skip_line_continuation(lexer: LexerLike) -> None:
    lexer._advance()
    char = lexer._current_char()
    while char is not None and char in " \t":
        lexer._advance()
        char = lexer._current_char()
    if char is not None and char in "\r\n":
        prev = char
        lexer._advance()
        if prev == "\r" and lexer._current_char() == "\n":
            lexer._advance()


def _skip_line_comment(lexer: LexerLike) -> None:
    while lexer._current_char() and lexer._current_char() != "\n":
        lexer._advance()


def _skip_block_comment(lexer: LexerLike) -> None:
    lexer._advance()
    lexer._advance()
    while lexer.position < len(lexer.text):
        if lexer._current_char() == "*" and lexer._peek_char() == "/":
            lexer._advance()
            lexer._advance()
            break
        lexer._advance()
