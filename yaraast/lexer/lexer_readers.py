"""Leaf token readers for the core YARA lexer."""

from __future__ import annotations

from yaraast.lexer.lexer_errors import LexerError
from yaraast.lexer.string_escape import StringEscapeHandler
from yaraast.lexer.tokens import Token, TokenType


def read_string(lexer) -> Token:
    start_line = lexer.line
    start_column = lexer.column
    value_chars: list[str] = []
    lexer._advance()
    while lexer._current_char() and lexer._current_char() != '"':
        if lexer._current_char() == "\\":
            lexer._advance()
            handler = StringEscapeHandler(lexer.text, lexer.position)
            result = handler.handle_backslash(lexer._current_char())
            value_chars.extend(result.chars)
            for _ in range(result.advance_count):
                lexer._advance()
            if result.ends_string:
                break
        else:
            value_chars.append(lexer._current_char())
        lexer._advance()
    if not lexer._current_char():
        raise LexerError("Unterminated string", start_line, start_column)
    lexer._advance()
    return Token(TokenType.STRING, "".join(value_chars), start_line, start_column)


def read_hex_string(lexer) -> Token:
    start_line = lexer.line
    start_column = lexer.column
    value_chars = []
    lexer._advance()
    while lexer._current_char():
        if lexer._current_char() == "}":
            break
        if lexer._current_char() == "/" and lexer._peek_char() == "/":
            while lexer._current_char() and lexer._current_char() != "\n":
                lexer._advance()
            if lexer._current_char() == "\n":
                lexer._advance()
            continue
        if lexer._current_char() == "/" and lexer._peek_char() == "*":
            lexer._advance()
            lexer._advance()
            while lexer._current_char():
                if lexer._current_char() == "*" and lexer._peek_char() == "/":
                    lexer._advance()
                    lexer._advance()
                    break
                lexer._advance()
            continue
        value_chars.append(lexer._current_char())
        lexer._advance()
    if not lexer._current_char() or lexer._current_char() != "}":
        raise LexerError("Unterminated hex string", start_line, start_column)
    lexer._advance()
    return Token(TokenType.HEX_STRING, "".join(value_chars), start_line, start_column)


def read_regex(lexer) -> Token:
    start_line = lexer.line
    start_column = lexer.column
    value_chars = []
    lexer._advance()
    while lexer._current_char() and lexer._current_char() != "/":
        if lexer._current_char() == "\\":
            value_chars.append(lexer._current_char())
            lexer._advance()
            if lexer._current_char():
                value_chars.append(lexer._current_char())
        else:
            value_chars.append(lexer._current_char())
        lexer._advance()
    if not lexer._current_char():
        raise LexerError("Unterminated regex", start_line, start_column)
    lexer._advance()
    modifiers = ""
    while lexer._current_char() and lexer._current_char() in "ims":
        modifiers += lexer._current_char()
        lexer._advance()
    value = "".join(value_chars)
    if modifiers:
        return Token(TokenType.REGEX, value + "\x00" + modifiers, start_line, start_column)
    return Token(TokenType.REGEX, value, start_line, start_column)


def read_number(lexer) -> Token:
    start_line = lexer.line
    start_column = lexer.column
    value = ""
    # Hexadecimal: 0x1A, 0xFF_FF
    if lexer._current_char() == "0" and lexer._peek_char() in "xX":
        value += lexer._current_char()
        lexer._advance()
        value += lexer._current_char()
        lexer._advance()
        while lexer._current_char() and lexer._current_char() in "0123456789abcdefABCDEF_":
            if lexer._current_char() != "_":
                value += lexer._current_char()
            lexer._advance()
        return Token(TokenType.INTEGER, int(value, 16), start_line, start_column)
    # Octal: 0o77, 0o123
    if lexer._current_char() == "0" and lexer._peek_char() in "oO":
        value += lexer._current_char()
        lexer._advance()
        value += lexer._current_char()
        lexer._advance()
        while lexer._current_char() and lexer._current_char() in "01234567_":
            if lexer._current_char() != "_":
                value += lexer._current_char()
            lexer._advance()
        return Token(TokenType.INTEGER, int(value, 8), start_line, start_column)
    # Decimal (with underscore separators): 1_000_000
    while lexer._current_char() and (
        lexer._current_char().isdigit() or lexer._current_char() == "_"
    ):
        if lexer._current_char() != "_":
            value += lexer._current_char()
        lexer._advance()
    # Float: 3.14, 1_000.5
    if lexer._current_char() == "." and lexer._peek_char() and lexer._peek_char().isdigit():
        value += lexer._current_char()
        lexer._advance()
        while lexer._current_char() and (
            lexer._current_char().isdigit() or lexer._current_char() == "_"
        ):
            if lexer._current_char() != "_":
                value += lexer._current_char()
            lexer._advance()
        return Token(TokenType.DOUBLE, float(value), start_line, start_column)
    # KB/MB suffixes
    if lexer._current_char() and lexer._current_char().upper() in "KM":
        suffix = lexer._current_char().upper()
        lexer._advance()
        if lexer._current_char() and lexer._current_char().upper() == "B":
            lexer._advance()
            multiplier = 1024 if suffix == "K" else 1024 * 1024
            return Token(TokenType.INTEGER, int(value) * multiplier, start_line, start_column)
    return Token(TokenType.INTEGER, int(value), start_line, start_column)


def read_identifier(lexer) -> Token:
    start_line = lexer.line
    start_column = lexer.column
    value = ""
    while lexer._current_char() and (
        lexer._current_char().isalnum() or lexer._current_char() == "_"
    ):
        value += lexer._current_char()
        lexer._advance()
    return Token(
        lexer.KEYWORDS.get(value.lower(), TokenType.IDENTIFIER), value, start_line, start_column
    )


def read_string_identifier(lexer) -> Token:
    start_line = lexer.line
    start_column = lexer.column
    lexer._advance()
    if lexer._current_char() == "*":
        lexer._advance()
        return Token(TokenType.STRING_IDENTIFIER, "$*", start_line, start_column)
    value = "$"
    while lexer._current_char() and (
        lexer._current_char().isalnum() or lexer._current_char() == "_"
    ):
        value += lexer._current_char()
        lexer._advance()
    if lexer._current_char() == "*":
        value += "*"
        lexer._advance()
    return Token(TokenType.STRING_IDENTIFIER, value, start_line, start_column)


def read_string_count(lexer) -> Token:
    return _read_prefixed_identifier(lexer, "#", TokenType.STRING_COUNT)


def read_string_offset(lexer) -> Token:
    return _read_prefixed_identifier(lexer, "@", TokenType.STRING_OFFSET)


def read_string_length(lexer) -> Token:
    return _read_prefixed_identifier(lexer, "!", TokenType.STRING_LENGTH)


def _read_prefixed_identifier(lexer, prefix: str, token_type: TokenType) -> Token:
    start_line = lexer.line
    start_column = lexer.column
    lexer._advance()
    value = prefix
    while lexer._current_char() and (
        lexer._current_char().isalnum() or lexer._current_char() == "_"
    ):
        value += lexer._current_char()
        lexer._advance()
    return Token(token_type, value, start_line, start_column)


def is_regex_context(lexer) -> bool:
    if not lexer.tokens:
        return True
    i = len(lexer.tokens) - 1
    while i >= 0:
        token = lexer.tokens[i]
        if token.type in (
            TokenType.MATCHES,
            TokenType.CONTAINS,
            TokenType.ASSIGN,
            TokenType.COLON,
            TokenType.LPAREN,
            TokenType.COMMA,
            TokenType.AND,
            TokenType.OR,
            TokenType.NOT,
        ):
            return True
        if token.type == TokenType.CONDITION:
            return True
        if token.type not in (TokenType.NEWLINE, TokenType.COMMENT):
            if token.type in (TokenType.RPAREN, TokenType.RBRACKET):
                return False
            break
        i -= 1
    return True


def is_hex_string_context(lexer) -> bool:
    if len(lexer.tokens) >= 2:
        non_comment_tokens = []
        for token in reversed(lexer.tokens):
            if token.type != TokenType.COMMENT:
                non_comment_tokens.append(token)
                if len(non_comment_tokens) >= 2:
                    break
        if (
            len(non_comment_tokens) >= 2
            and non_comment_tokens[0].type == TokenType.ASSIGN
            and non_comment_tokens[1].type == TokenType.STRING_IDENTIFIER
        ):
            return True
    return False
