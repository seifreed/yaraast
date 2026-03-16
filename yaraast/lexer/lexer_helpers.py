"""Helper routines for lexer whitespace/comment handling."""

from __future__ import annotations


def skip_whitespace_and_comments(lexer) -> None:
    """Skip whitespace, comments, and line continuations."""
    while lexer.position < len(lexer.text):
        char = lexer._current_char()

        if char in " \t\r\n":
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


def _skip_line_continuation(lexer) -> None:
    lexer._advance()
    while lexer._current_char() is not None and lexer._current_char() in " \t":
        lexer._advance()
    if lexer._current_char() is not None and lexer._current_char() in "\r\n":
        lexer._advance()
        if lexer._current_char() == "\n":
            lexer._advance()


def _skip_line_comment(lexer) -> None:
    while lexer._current_char() and lexer._current_char() != "\n":
        lexer._advance()


def _skip_block_comment(lexer) -> None:
    lexer._advance()
    lexer._advance()
    while lexer.position < len(lexer.text):
        if lexer._current_char() == "*" and lexer._peek_char() == "/":
            lexer._advance()
            lexer._advance()
            break
        lexer._advance()
