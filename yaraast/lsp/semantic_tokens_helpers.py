"""Helpers for semantic token encoding and token-type mapping."""

from __future__ import annotations

from lsprotocol.types import Range

from yaraast.lexer.tokens import TokenType

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
    TokenType.OF: "keyword",
    TokenType.THEM: "keyword",
    TokenType.FOR: "keyword",
    TokenType.IN: "keyword",
    TokenType.AT: "keyword",
    TokenType.FILESIZE: "keyword",
    TokenType.ENTRYPOINT: "keyword",
    TokenType.DEFINED: "keyword",
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


def encode_tokens(tokens, map_type, token_types: list[str]) -> list[int]:
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
        length = len(str(token.value))
        token_type_idx = token_types.index(semantic_type)
        tokens_data.extend([delta_line, delta_char, length, token_type_idx, 0])
        prev_line = token.line - 1
        prev_char = token.column + length
    return tokens_data


def encode_tokens_in_range(tokens, range_: Range, map_type, token_types: list[str]) -> list[int]:
    """Encode tokens within a requested range."""
    tokens_data: list[int] = []
    prev_line = range_.start.line
    prev_char = range_.start.character

    for token in tokens:
        if token.type == TokenType.EOF:
            break

        token_line = token.line - 1
        token_end = token.column + len(str(token.value))
        if token_line < range_.start.line or token_line > range_.end.line:
            continue
        if token_line == range_.start.line and token_end < range_.start.character:
            continue
        if token_line == range_.end.line and token.column > range_.end.character:
            continue

        semantic_type = map_type(token.type)
        if semantic_type is None:
            continue
        delta_line = token_line - prev_line
        delta_char = token.column if delta_line > 0 else token.column - prev_char
        length = len(str(token.value))
        token_type_idx = token_types.index(semantic_type)
        tokens_data.extend([delta_line, delta_char, length, token_type_idx, 0])
        prev_line = token_line
        prev_char = token.column + length

    return tokens_data
