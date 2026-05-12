"""Token protocol abstractions for parser and lexer contracts.

Note: IToken.type is typed as Enum to avoid depending on the concrete
lexer module.  The canonical implementation uses yaraast.lexer.tokens.TokenType.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Protocol


class IToken(Protocol):
    """Minimal token contract consumed by the parser."""

    @property
    def type(self) -> Enum: ...

    @property
    def value(self) -> Any: ...

    @property
    def line(self) -> int: ...

    @property
    def column(self) -> int: ...

    @property
    def length(self) -> int: ...
