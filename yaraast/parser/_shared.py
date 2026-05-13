"""Shared parser constants and exceptions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.errors import YaraASTError
from yaraast.interfaces import IToken

if TYPE_CHECKING:
    from yaraast.ast.modifiers import StringModifier

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


def parse_regex_value(regex_val: str) -> tuple[str, list[StringModifier]]:
    """Parse lexer regex payloads and convert inline flags to string modifiers."""
    from yaraast.ast.modifiers import StringModifier

    pattern = regex_val
    modifiers = []

    if "\x00" in regex_val:
        parts = regex_val.split("\x00", 1)
        pattern = parts[0]
        mod_str = parts[1] if len(parts) > 1 else ""
        modifier_names = {
            "i": "nocase",
            "s": "dotall",
            "m": "multiline",
        }
        for modifier in mod_str:
            if modifier in modifier_names:
                modifiers.append(StringModifier.from_name_value(modifier_names[modifier]))

    return pattern, modifiers


class ParserError(YaraASTError):
    """Parser error exception."""

    def __init__(self, message: str, token: IToken) -> None:
        super().__init__(f"Parser error at {token.line}:{token.column}: {message}")
        self.token = token
        self.line = token.line
        self.column = token.column
