"""Token protocol abstractions for parser and lexer contracts.

Note: IToken.type is typed as Enum to avoid depending on the concrete
lexer module.  The canonical implementation uses yaraast.lexer.tokens.TokenType.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Protocol


class IToken(Protocol):
    """Minimal token contract consumed by the parser."""

    type: Enum
    value: Any
    line: int
    column: int
    length: int
