"""Token tables and patterns for YARA-L lexer."""

from __future__ import annotations

import re

from yaraast.lexer.tokens import TokenType as BaseTokenType

from .tokens import YaraLTokenType

KEYWORDS = {
    "rule": YaraLTokenType.RULE,
    "meta": BaseTokenType.META,
    "events": YaraLTokenType.EVENTS,
    "match": YaraLTokenType.MATCH,
    "outcome": YaraLTokenType.OUTCOME,
    "condition": BaseTokenType.CONDITION,
    "options": YaraLTokenType.OPTIONS,
    "over": YaraLTokenType.OVER,
    "before": YaraLTokenType.BEFORE,
    "after": YaraLTokenType.AFTER,
    "within": YaraLTokenType.WITHIN,
    "by": YaraLTokenType.BY,
    "every": YaraLTokenType.EVERY,
    "count": YaraLTokenType.COUNT,
    "count_distinct": YaraLTokenType.COUNT_DISTINCT,
    "sum": YaraLTokenType.SUM,
    "min": YaraLTokenType.MIN,
    "max": YaraLTokenType.MAX,
    "avg": YaraLTokenType.AVG,
    "array": YaraLTokenType.ARRAY,
    "array_distinct": YaraLTokenType.ARRAY_DISTINCT,
    "earliest": YaraLTokenType.EARLIEST,
    "latest": YaraLTokenType.LATEST,
    "metadata": YaraLTokenType.METADATA,
    "principal": YaraLTokenType.PRINCIPAL,
    "target": YaraLTokenType.TARGET,
    "network": YaraLTokenType.NETWORK,
    "security_result": YaraLTokenType.SECURITY_RESULT,
    "udm": YaraLTokenType.UDM,
    "additional": YaraLTokenType.ADDITIONAL,
    "and": BaseTokenType.AND,
    "or": BaseTokenType.OR,
    "not": BaseTokenType.NOT,
    "in": BaseTokenType.IN,
    "nocase": YaraLTokenType.NOCASE,
    "is": YaraLTokenType.IS,
    "null": YaraLTokenType.NULL,
    "if": YaraLTokenType.IF,
    "else": YaraLTokenType.ELSE,
    "cidr": YaraLTokenType.CIDR,
    "regex": YaraLTokenType.REGEX,
    "re.regex": YaraLTokenType.REGEX,
    "true": BaseTokenType.BOOLEAN_TRUE,
    "false": BaseTokenType.BOOLEAN_FALSE,
    "all": BaseTokenType.ALL,
    "any": BaseTokenType.ANY,
}

TIME_PATTERN = re.compile(r"(\d+)([smhd])")
EVENT_VAR_PATTERN = re.compile(r"\$[a-zA-Z_][a-zA-Z0-9_]*")
REFERENCE_LIST_PATTERN = re.compile(r"%[a-zA-Z_][a-zA-Z0-9_]*%")
UDM_FIELD_PATTERN = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)+")

TWO_CHAR_TOKENS = {
    "->": (BaseTokenType.IDENTIFIER, YaraLTokenType.ARROW),
    "::": (BaseTokenType.IDENTIFIER, YaraLTokenType.DOUBLE_COLON),
    ">=": (BaseTokenType.GE, None),
    "<=": (BaseTokenType.LE, None),
    "==": (BaseTokenType.IEQUALS, None),
    "!=": (BaseTokenType.NEQ, None),
}

SINGLE_CHAR_TOKENS = {
    "(": BaseTokenType.LPAREN,
    ")": BaseTokenType.RPAREN,
    "{": BaseTokenType.LBRACE,
    "}": BaseTokenType.RBRACE,
    "[": BaseTokenType.LBRACKET,
    "]": BaseTokenType.RBRACKET,
    ":": BaseTokenType.COLON,
    ";": BaseTokenType.SEMICOLON,
    ",": BaseTokenType.COMMA,
    ".": BaseTokenType.DOT,
    "=": BaseTokenType.EQ,
    ">": BaseTokenType.GT,
    "<": BaseTokenType.LT,
    "+": BaseTokenType.PLUS,
    "-": BaseTokenType.MINUS,
    "*": BaseTokenType.MULTIPLY,
    "#": BaseTokenType.STRING_COUNT,
}
