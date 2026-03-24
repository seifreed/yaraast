"""Shared parser constants and exceptions."""

from __future__ import annotations

from yaraast.errors import YaraASTError
from yaraast.interfaces import IToken

# Known YARA modules for identifier resolution
KNOWN_MODULES: frozenset[str] = frozenset(
    {
        "pe",
        "elf",
        "math",
        "dotnet",
        "cuckoo",
        "magic",
        "hash",
        "console",
        "string",
        "time",
        "vt",
    }
)


class ParserError(YaraASTError):
    """Parser error exception."""

    def __init__(self, message: str, token: IToken) -> None:
        super().__init__(f"Parser error at {token.line}:{token.column}: {message}")
        self.token = token
        self.line = token.line
        self.column = token.column
