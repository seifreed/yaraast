"""Helpers for semantic token encoding and token-type mapping."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from lsprotocol.types import Range

from yaraast.lexer.tokens import Token, TokenType

TOKEN_TYPE_MAPPING = {
    TokenType.RULE: "keyword",
    TokenType.PRIVATE: "keyword",
    TokenType.GLOBAL: "keyword",
    TokenType.META: "keyword",
    TokenType.STRINGS: "keyword",
    TokenType.CONDITION: "keyword",
    TokenType.IMPORT: "keyword",
    TokenType.INCLUDE: "keyword",
    TokenType.AND: "keyword",
    TokenType.OR: "keyword",
    TokenType.NOT: "keyword",
    TokenType.ALL: "keyword",
    TokenType.ANY: "keyword",
    TokenType.NONE: "keyword",
    TokenType.OF: "keyword",
    TokenType.THEM: "keyword",
    TokenType.FOR: "keyword",
    TokenType.IN: "keyword",
    TokenType.AS: "keyword",
    TokenType.AT: "keyword",
    TokenType.FILESIZE: "keyword",
    TokenType.ENTRYPOINT: "keyword",
    TokenType.DEFINED: "keyword",
    TokenType.MATCHES: "keyword",
    TokenType.CONTAINS: "keyword",
    TokenType.STARTSWITH: "keyword",
    TokenType.ENDSWITH: "keyword",
    TokenType.ICONTAINS: "keyword",
    TokenType.ISTARTSWITH: "keyword",
    TokenType.IENDSWITH: "keyword",
    TokenType.IEQUALS: "keyword",
    TokenType.STRING: "string",
    TokenType.INTEGER: "number",
    TokenType.DOUBLE: "number",
    TokenType.REGEX: "regexp",
    TokenType.HEX_STRING: "string",
    TokenType.BOOLEAN_TRUE: "keyword",
    TokenType.BOOLEAN_FALSE: "keyword",
    TokenType.IDENTIFIER: "variable",
    TokenType.STRING_IDENTIFIER: "variable",
    TokenType.STRING_COUNT: "variable",
    TokenType.STRING_OFFSET: "variable",
    TokenType.STRING_LENGTH: "variable",
    TokenType.EQ: "operator",
    TokenType.NEQ: "operator",
    TokenType.LT: "operator",
    TokenType.LE: "operator",
    TokenType.GT: "operator",
    TokenType.GE: "operator",
    TokenType.PLUS: "operator",
    TokenType.MINUS: "operator",
    TokenType.MULTIPLY: "operator",
    TokenType.DIVIDE: "operator",
    TokenType.MODULO: "operator",
    TokenType.BITWISE_AND: "operator",
    TokenType.BITWISE_OR: "operator",
    TokenType.BITWISE_NOT: "operator",
    TokenType.XOR: "operator",
    TokenType.SHIFT_LEFT: "operator",
    TokenType.SHIFT_RIGHT: "operator",
    TokenType.COMMENT: "comment",
    TokenType.NOCASE: "property",
    TokenType.WIDE: "property",
    TokenType.ASCII: "property",
    TokenType.XOR_MOD: "property",
    TokenType.BASE64: "property",
    TokenType.BASE64WIDE: "property",
    TokenType.FULLWORD: "property",
}


def map_token_type(token_type: TokenType) -> str | None:
    return TOKEN_TYPE_MAPPING.get(token_type)


def token_source_length(token: Token) -> int:
    length = getattr(token, "length", 0) or 0
    if length > 1:
        return length
    return len(str(token.value))


def _is_empty_range(range_: Range) -> bool:
    return range_.start.line == range_.end.line and range_.start.character == range_.end.character


def _token_overlaps_range(token_line: int, token_start: int, token_end: int, range_: Range) -> bool:
    if _is_empty_range(range_):
        return (
            token_line == range_.start.line
            and token_start <= range_.start.character
            and token_end > range_.start.character
        )

    if token_line < range_.start.line or token_line > range_.end.line:
        return False
    if token_line == range_.start.line and token_end <= range_.start.character:
        return False
    return not (token_line == range_.end.line and token_start >= range_.end.character)


def encode_tokens(
    tokens: Iterable[Token],
    map_type: Callable[[TokenType], str | None],
    token_types: list[str],
) -> list[int]:
    """Encode lexer tokens into LSP semantic token delta format."""
    tokens_data: list[int] = []
    prev_line = 0
    prev_char = 0

    for token in tokens:
        if token.type == TokenType.EOF:
            break
        semantic_type = map_type(token.type)
        if semantic_type is None:
            continue
        delta_line = token.line - 1 - prev_line
        delta_char = token.column if delta_line > 0 else token.column - prev_char
        length = token_source_length(token)
        token_type_idx = token_types.index(semantic_type)
        tokens_data.extend([delta_line, delta_char, length, token_type_idx, 0])
        prev_line = token.line - 1
        prev_char = token.column + length
    return tokens_data


def encode_tokens_in_range(
    tokens: Iterable[Token],
    range_: Range,
    map_type: Callable[[TokenType], str | None],
    token_types: list[str],
) -> list[int]:
    """Encode tokens within a requested range."""
    tokens_data: list[int] = []
    prev_line = 0
    prev_char = 0

    for token in tokens:
        if token.type == TokenType.EOF:
            break

        token_line = token.line - 1
        token_start = token.column
        length = token_source_length(token)
        token_end = token_start + length
        if not _token_overlaps_range(token_line, token_start, token_end, range_):
            continue

        semantic_type = map_type(token.type)
        if semantic_type is None:
            continue
        delta_line = token_line - prev_line
        delta_char = token_start if delta_line > 0 else token_start - prev_char
        token_type_idx = token_types.index(semantic_type)
        tokens_data.extend([delta_line, delta_char, length, token_type_idx, 0])
        prev_line = token_line
        prev_char = token_start + length

    return tokens_data
