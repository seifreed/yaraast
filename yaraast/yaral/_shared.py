"""Shared helpers for YARA-L parser."""

from __future__ import annotations

from .lexer import YaraLToken

# Constants
EXPECTED_FIELD_NAME_ERROR = "Expected field name"


class YaraLParserError(Exception):
    """YARA-L parser error."""

    def __init__(self, message: str, token: YaraLToken | None = None) -> None:
        if token:
            super().__init__(f"Parser error at {token.line}:{token.column}: {message}")
            self.token = token
        else:
            super().__init__(f"Parser error: {message}")
            self.token = None
