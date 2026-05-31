"""Leaf token readers for the core YARA lexer."""

from __future__ import annotations

from typing import cast

from yaraast.lexer.lexer_errors import LexerError
from yaraast.lexer.lexer_tables import YARA_IDENTIFIER_BODY_CHARS, YARA_IDENTIFIER_MAX_LENGTH
from yaraast.lexer.protocols import LexerLike
from yaraast.lexer.string_escape import StringEscapeHandler
from yaraast.lexer.tokens import Token, TokenType

INT64_MAX = (1 << 63) - 1


def read_string(lexer: LexerLike) -> Token:
    start_line = lexer.line
    start_column = lexer.column
    start_position = lexer.position
    value_chars: list[str] = []
    lexer._advance()
    char = lexer._current_char()
    while char is not None and char != '"':
        if char in "\n\r":
            raise LexerError("Unterminated string", start_line, start_column)
        if char == "\\":
            lexer._advance()
            handler = StringEscapeHandler(lexer.text, lexer.position)
            try:
                result = handler.handle_backslash(lexer._current_char())
            except ValueError as e:
                raise LexerError(str(e), lexer.line, lexer.column) from e
            value_chars.extend(result.chars)
            for _ in range(result.advance_count):
                lexer._advance()
            if result.ends_string:
                break
        else:
            value_chars.append(char)
        lexer._advance()
        char = lexer._current_char()
    if char is None:
        raise LexerError("Unterminated string", start_line, start_column)
    lexer._advance()
    return Token(
        TokenType.STRING,
        "".join(value_chars),
        start_line,
        start_column,
        lexer.position - start_position,
    )


def read_hex_string(lexer: LexerLike) -> Token:
    start_line = lexer.line
    start_column = lexer.column
    start_position = lexer.position
    value_chars: list[str] = []
    lexer._advance()
    while lexer._current_char():
        if lexer._current_char() == "}":
            break
        if lexer._current_char() == "/" and lexer._peek_char() == "/":
            value_chars.append(" ")
            while lexer._current_char() and lexer._current_char() != "\n":
                lexer._advance()
            if lexer._current_char() == "\n":
                value_chars.append("\n")
                lexer._advance()
            continue
        if lexer._current_char() == "/" and lexer._peek_char() == "*":
            value_chars.append(" ")
            lexer._advance()
            lexer._advance()
            while lexer._current_char():
                if lexer._current_char() == "*" and lexer._peek_char() == "/":
                    lexer._advance()
                    lexer._advance()
                    break
                if lexer._current_char() == "\n":
                    value_chars.append("\n")
                lexer._advance()
            continue
        value_chars.append(cast(str, lexer._current_char()))
        lexer._advance()
    if not lexer._current_char() or lexer._current_char() != "}":
        raise LexerError("Unterminated hex string", start_line, start_column)
    lexer._advance()
    return Token(
        TokenType.HEX_STRING,
        "".join(value_chars),
        start_line,
        start_column,
        lexer.position - start_position,
    )


def read_regex(lexer: LexerLike) -> Token:
    start_line = lexer.line
    start_column = lexer.column
    start_position = lexer.position
    value_chars: list[str] = []
    lexer._advance()
    char = lexer._current_char()
    while char is not None and char != "/":
        if char == "\n":
            raise LexerError("Unterminated regex", start_line, start_column)
        if char == "\\":
            value_chars.append(char)
            lexer._advance()
            current = lexer._current_char()
            if current == "\n":
                raise LexerError("Unterminated regex", start_line, start_column)
            if current:
                value_chars.append(current)
        else:
            value_chars.append(char)
        lexer._advance()
        char = lexer._current_char()
    if char is None:
        raise LexerError("Unterminated regex", start_line, start_column)
    lexer._advance()
    modifiers = ""
    char = lexer._current_char()
    while char is not None and char in "is":
        modifiers += char
        lexer._advance()
        char = lexer._current_char()
    value = "".join(value_chars)
    if modifiers:
        return Token(
            TokenType.REGEX,
            value + "\x00" + modifiers,
            start_line,
            start_column,
            lexer.position - start_position,
        )
    return Token(
        TokenType.REGEX,
        value,
        start_line,
        start_column,
        lexer.position - start_position,
    )


def _integer_token(value: int, line: int, column: int, length: int = 1) -> Token:
    if value > INT64_MAX:
        msg = f"Integer literal exceeds int64 maximum: {value}"
        raise LexerError(msg, line, column)
    return Token(TokenType.INTEGER, value, line, column, length)


def _validate_digit_separators(raw_digits: str, literal_kind: str, line: int, column: int) -> None:
    if (
        not raw_digits
        or raw_digits.startswith("_")
        or raw_digits.endswith("_")
        or "__" in raw_digits
    ):
        msg = f"Invalid {literal_kind} integer literal"
        raise LexerError(msg, line, column)


def _read_size_suffix(lexer: LexerLike, value: str, line: int, column: int) -> Token | None:
    suffix = lexer._current_char()
    if suffix is None or suffix not in "KkMm":
        return None
    if suffix not in "KM" or lexer._peek_char() != "B":
        raise LexerError("Invalid size suffix", line, column)
    lexer._advance()
    lexer._advance()
    char = lexer._current_char()
    if char is not None and (char.isalnum() or char == "_"):
        raise LexerError("Invalid size suffix", line, column)
    multiplier = 1024 if suffix == "K" else 1024 * 1024
    return _integer_token(int(value) * multiplier, line, column, lexer.column - column)


def read_number(lexer: LexerLike) -> Token:
    start_line = lexer.line
    start_column = lexer.column
    value = ""
    next_char = lexer._peek_char()
    # Hexadecimal: 0x1A, 0xFF_FF
    if lexer._current_char() == "0" and next_char is not None and next_char in "xX":
        value += "0"
        lexer._advance()
        value += next_char
        lexer._advance()
        raw_digits = ""
        char = lexer._current_char()
        while char is not None and char in "0123456789abcdefABCDEF_":
            raw_digits += char
            if char != "_":
                value += char
            lexer._advance()
            char = lexer._current_char()
        _validate_digit_separators(raw_digits, "hexadecimal", start_line, start_column)
        char = lexer._current_char()
        if char is not None and char.isalnum():
            msg = "Invalid hexadecimal integer literal"
            raise LexerError(msg, start_line, start_column)
        return _integer_token(int(value, 16), start_line, start_column, lexer.column - start_column)
    # Octal: 0o77, 0o123
    if lexer._current_char() == "0" and next_char is not None and next_char in "oO":
        value += "0"
        lexer._advance()
        value += next_char
        lexer._advance()
        raw_digits = ""
        char = lexer._current_char()
        while char is not None and char in "01234567_":
            raw_digits += char
            if char != "_":
                value += char
            lexer._advance()
            char = lexer._current_char()
        _validate_digit_separators(raw_digits, "octal", start_line, start_column)
        char = lexer._current_char()
        if char is not None and char.isalnum():
            msg = "Invalid octal integer literal"
            raise LexerError(msg, start_line, start_column)
        return _integer_token(int(value, 8), start_line, start_column, lexer.column - start_column)
    # Decimal (with underscore separators): 1_000_000
    raw_digits = ""
    char = lexer._current_char()
    while char is not None and (char.isdigit() or char == "_"):
        raw_digits += char
        if char != "_":
            value += char
        lexer._advance()
        char = lexer._current_char()
    _validate_digit_separators(raw_digits, "decimal", start_line, start_column)
    # Float: 3.14, 1_000.5
    next_char = lexer._peek_char()
    if char == "." and next_char is not None and next_char.isdigit():
        value += char
        lexer._advance()
        raw_fraction = ""
        char = lexer._current_char()
        while char is not None and (char.isdigit() or char == "_"):
            raw_fraction += char
            if char != "_":
                value += char
            lexer._advance()
            char = lexer._current_char()
        if raw_fraction.endswith("_") or "__" in raw_fraction:
            msg = "Invalid decimal floating-point literal"
            raise LexerError(msg, start_line, start_column)
        return Token(
            TokenType.DOUBLE,
            float(value),
            start_line,
            start_column,
            lexer.column - start_column,
        )
    # KB/MB suffixes
    suffix_token = _read_size_suffix(lexer, value, start_line, start_column)
    if suffix_token is not None:
        return suffix_token
    return _integer_token(int(value), start_line, start_column, lexer.column - start_column)


def read_identifier(lexer: LexerLike) -> Token:
    start_line = lexer.line
    start_column = lexer.column
    value = ""
    char = lexer._current_char()
    while char is not None and char in YARA_IDENTIFIER_BODY_CHARS:
        value += char
        lexer._advance()
        char = lexer._current_char()
    if len(value) > YARA_IDENTIFIER_MAX_LENGTH:
        msg = f"Identifier exceeds maximum length of {YARA_IDENTIFIER_MAX_LENGTH} characters"
        raise LexerError(msg, start_line, start_column)
    return Token(lexer.KEYWORDS.get(value, TokenType.IDENTIFIER), value, start_line, start_column)


def read_string_identifier(lexer: LexerLike) -> Token:
    start_line = lexer.line
    start_column = lexer.column
    lexer._advance()
    if lexer._current_char() == "*":
        lexer._advance()
        return Token(TokenType.STRING_IDENTIFIER, "$*", start_line, start_column)
    value = "$"
    char = lexer._current_char()
    while char is not None and char in YARA_IDENTIFIER_BODY_CHARS:
        value += char
        lexer._advance()
        char = lexer._current_char()
    if lexer._current_char() == "*":
        value += "*"
        lexer._advance()
    return Token(TokenType.STRING_IDENTIFIER, value, start_line, start_column)


def read_string_count(lexer: LexerLike) -> Token:
    return _read_prefixed_identifier(lexer, "#", TokenType.STRING_COUNT)


def read_string_offset(lexer: LexerLike) -> Token:
    return _read_prefixed_identifier(lexer, "@", TokenType.STRING_OFFSET)


def read_string_length(lexer: LexerLike) -> Token:
    return _read_prefixed_identifier(lexer, "!", TokenType.STRING_LENGTH)


def _read_prefixed_identifier(lexer: LexerLike, prefix: str, token_type: TokenType) -> Token:
    start_line = lexer.line
    start_column = lexer.column
    lexer._advance()
    value = prefix
    char = lexer._current_char()
    while char is not None and char in YARA_IDENTIFIER_BODY_CHARS:
        value += char
        lexer._advance()
        char = lexer._current_char()
    return Token(token_type, value, start_line, start_column)


def is_regex_context(lexer: LexerLike) -> bool:
    if not lexer.tokens:
        return True
    expression_end_tokens = {
        TokenType.INTEGER,
        TokenType.DOUBLE,
        TokenType.STRING,
        TokenType.HEX_STRING,
        TokenType.REGEX,
        TokenType.BOOLEAN_TRUE,
        TokenType.BOOLEAN_FALSE,
        TokenType.IDENTIFIER,
        TokenType.STRING_IDENTIFIER,
        TokenType.STRING_COUNT,
        TokenType.STRING_OFFSET,
        TokenType.STRING_LENGTH,
        TokenType.FILESIZE,
        TokenType.ENTRYPOINT,
        TokenType.RPAREN,
        TokenType.RBRACKET,
    }
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
            if token.type in expression_end_tokens:
                return False
            break
        i -= 1
    return True


def is_hex_string_context(lexer: LexerLike) -> bool:
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
