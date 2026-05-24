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

    pattern, mod_str = split_regex_value(regex_val)
    validate_regex_pattern(pattern)
    modifiers = []

    modifier_names = {
        "i": "nocase",
        "s": "dotall",
        "m": "multiline",
    }
    for modifier in mod_str:
        if modifier in modifier_names:
            modifiers.append(StringModifier.from_name_value(modifier_names[modifier]))

    return pattern, modifiers


def split_regex_value(regex_val: str) -> tuple[str, str]:
    """Split lexer regex payload into pattern and inline flag suffix."""
    if "\x00" not in regex_val:
        return regex_val, ""
    parts = regex_val.split("\x00", 1)
    pattern = parts[0]
    modifiers = parts[1] if len(parts) > 1 else ""
    return pattern, modifiers


def validate_regex_pattern(pattern: str) -> None:
    """Reject regex structure that libyara rejects before AST construction."""
    escaped = False
    in_character_class = False
    group_depth = 0

    for char in pattern:
        if escaped:
            escaped = False
            continue

        if char == "\\":
            escaped = True
            continue

        if in_character_class:
            if char == "]":
                in_character_class = False
            continue

        if char == "[":
            in_character_class = True
        elif char == "(":
            group_depth += 1
        elif char == ")":
            if group_depth == 0:
                msg = "Invalid regex pattern: unmatched ')'"
                raise ValueError(msg)
            group_depth -= 1

    if escaped:
        msg = "Invalid regex pattern: dangling escape"
        raise ValueError(msg)
    if in_character_class:
        msg = "Invalid regex pattern: unterminated character class"
        raise ValueError(msg)
    if group_depth:
        msg = "Invalid regex pattern: unterminated group"
        raise ValueError(msg)


class ParserError(YaraASTError):
    """Parser error exception."""

    def __init__(self, message: str, token: IToken) -> None:
        super().__init__(f"Parser error at {token.line}:{token.column}: {message}")
        self.token = token
        self.line = token.line
        self.column = token.column
