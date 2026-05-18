"""Shared helpers for YARA-L parser."""

from __future__ import annotations

from yaraast.errors import YaraASTError
from yaraast.regex_literals import escape_regex_delimiter

from .lexer import YaraLToken

# Constants
EXPECTED_FIELD_NAME_ERROR = "Expected field name"


def parse_numeric_token_value(value: object) -> int | float:
    """Parse a YARA-L numeric token value as int or float."""
    if isinstance(value, int | float) and not isinstance(value, bool):
        return value
    text = str(value)
    if "." in text:
        return float(text)
    return int(text)


def split_regex_token_value(value: object) -> tuple[str, list[str]]:
    """Return regex pattern and inline flags from a lexer token value."""
    raw_value = "" if value is None else str(value)
    if raw_value.startswith("/") and "/" in raw_value[1:]:
        last_delimiter = raw_value.rfind("/")
        return raw_value[1:last_delimiter], list(raw_value[last_delimiter + 1 :])
    return raw_value, []


def format_regex_token_value(value: object) -> str:
    """Format a lexer regex token value with exactly one delimiter pair."""
    pattern, flags = split_regex_token_value(value)
    return f"/{escape_regex_delimiter(pattern)}/{''.join(flags)}"


class YaraLParserError(YaraASTError):
    """YARA-L parser error."""

    def __init__(self, message: str, token: YaraLToken | None = None) -> None:
        if token:
            super().__init__(f"Parser error at {token.line}:{token.column}: {message}")
            self.token = token
        else:
            super().__init__(f"Parser error: {message}")
            self.token = None
