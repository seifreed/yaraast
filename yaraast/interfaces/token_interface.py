"""Token protocol abstractions for parser and lexer contracts."""

from __future__ import annotations

from typing import Any, Protocol

from yaraast.lexer.tokens import TokenType


class IToken(Protocol):
    """Minimal token contract consumed by the parser."""

    type: TokenType
    value: Any
    line: int
    column: int
    length: int
