"""Token definitions for YARA lexer."""

from enum import Enum, auto
from typing import Any

import attrs


class TokenType(Enum):
    """Token types for YARA lexer."""

    # Literals
    INTEGER = auto()
    DOUBLE = auto()
    STRING = auto()
    HEX_STRING = auto()
    REGEX = auto()
    BOOLEAN_TRUE = auto()
    BOOLEAN_FALSE = auto()

    # Identifiers
    IDENTIFIER = auto()
    STRING_IDENTIFIER = auto()
    STRING_COUNT = auto()
    STRING_OFFSET = auto()
    STRING_LENGTH = auto()

    # Keywords
    RULE = auto()
    PRIVATE = auto()
    GLOBAL = auto()
    IMPORT = auto()
    INCLUDE = auto()
    META = auto()
    STRINGS = auto()
    CONDITION = auto()
    AND = auto()
    OR = auto()
    NOT = auto()
    FOR = auto()
    OF = auto()
    IN = auto()
    AS = auto()
    AT = auto()
    THEM = auto()
    ANY = auto()
    ALL = auto()
    ENTRYPOINT = auto()
    FILESIZE = auto()
    MATCHES = auto()
    CONTAINS = auto()
    STARTSWITH = auto()
    ENDSWITH = auto()
    ICONTAINS = auto()
    ISTARTSWITH = auto()
    IENDSWITH = auto()
    IEQUALS = auto()
    DEFINED = auto()

    # Operators
    ASSIGN = auto()
    PLUS = auto()
    MINUS = auto()
    MULTIPLY = auto()
    DIVIDE = auto()
    MODULO = auto()
    XOR = auto()
    BITWISE_AND = auto()
    BITWISE_OR = auto()
    BITWISE_NOT = auto()
    SHIFT_LEFT = auto()
    SHIFT_RIGHT = auto()
    EQ = auto()
    NEQ = auto()
    LT = auto()
    LE = auto()
    GT = auto()
    GE = auto()
    DOT = auto()
    DOUBLE_DOT = auto()

    # Delimiters
    LPAREN = auto()
    RPAREN = auto()
    LBRACE = auto()
    RBRACE = auto()
    LBRACKET = auto()
    RBRACKET = auto()
    COMMA = auto()
    COLON = auto()
    SEMICOLON = auto()

    # Special
    EOF = auto()
    NEWLINE = auto()
    COMMENT = auto()

    # String modifiers
    NOCASE = auto()
    WIDE = auto()
    ASCII = auto()
    XOR_MOD = auto()
    BASE64 = auto()
    BASE64WIDE = auto()
    FULLWORD = auto()


@attrs.define
class Token:
    """Token representation."""

    type: TokenType
    value: Any
    line: int
    column: int
    length: int = 1
