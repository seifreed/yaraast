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
        "hash",
        "console",
        "string",
        "time",
        "vt",
    }
)

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_REGEX_MODIFIERS = frozenset("is")
_REGEX_QUANTIFIERS = frozenset("*+?")
_REGEX_ZERO_WIDTH_ESCAPES = frozenset("bB")


def parse_regex_value(regex_val: str) -> tuple[str, list[StringModifier]]:
    """Parse lexer regex payloads and convert inline flags to string modifiers."""
    from yaraast.ast.modifiers import StringModifier

    pattern, mod_str = split_regex_value(regex_val)
    validate_regex_pattern(pattern)
    validate_regex_modifiers(mod_str)
    modifiers = []

    modifier_names = {
        "i": "nocase",
        "s": "dotall",
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


def validate_regex_modifiers(modifiers: str) -> None:
    """Reject regex suffix modifiers that libyara rejects."""
    seen: set[str] = set()
    for modifier in modifiers:
        if modifier not in _REGEX_MODIFIERS:
            msg = f"Invalid regex modifier: {modifier}"
            raise ValueError(msg)
        if modifier in seen:
            msg = f"Duplicate regex modifier: {modifier}"
            raise ValueError(msg)
        seen.add(modifier)


def validate_regex_pattern(pattern: str) -> None:
    """Reject regex structure that libyara rejects before AST construction."""
    scope_has_content = [False]
    can_repeat = False
    last_was_quantifier = False

    def mark_atom(repeatable: bool = True) -> None:
        nonlocal can_repeat, last_was_quantifier
        scope_has_content[-1] = True
        can_repeat = repeatable
        last_was_quantifier = False

    def consume_quantifier() -> None:
        nonlocal can_repeat, last_was_quantifier
        if not can_repeat:
            msg = "Invalid regex pattern: syntax error"
            raise ValueError(msg)
        can_repeat = False
        last_was_quantifier = True

    i = 0
    while i < len(pattern):
        char = pattern[i]

        if last_was_quantifier and char == "?":
            last_was_quantifier = False
            can_repeat = False
            i += 1
            continue

        if char == "\\":
            i, _, repeatable = _validate_regex_escape(pattern, i, in_character_class=False)
            mark_atom(repeatable=repeatable)
            continue

        if char == "[":
            i = _validate_regex_character_class(pattern, i)
            mark_atom()
            continue

        if char == "(":
            if i + 1 < len(pattern) and pattern[i + 1] == "?":
                msg = "Invalid regex pattern: unsupported group"
                raise ValueError(msg)
            scope_has_content.append(False)
            can_repeat = False
            last_was_quantifier = False
            i += 1
            continue

        if char == ")":
            if len(scope_has_content) == 1:
                msg = "Invalid regex pattern: unmatched ')'"
                raise ValueError(msg)
            if not scope_has_content.pop():
                msg = "Invalid regex pattern: empty group"
                raise ValueError(msg)
            mark_atom()
            i += 1
            continue

        if char == "|":
            if not scope_has_content[-1]:
                msg = "Invalid regex pattern: syntax error"
                raise ValueError(msg)
            can_repeat = False
            last_was_quantifier = False
            i += 1
            continue

        if char in _REGEX_QUANTIFIERS:
            consume_quantifier()
            i += 1
            continue

        if char == "{":
            end = pattern.find("}", i + 1)
            interval = _parse_regex_repeat_interval(pattern[i + 1 : end]) if end != -1 else None
            if interval is not None:
                min_value, max_value = interval
                if min_value is not None and max_value is not None and min_value > max_value:
                    msg = "Invalid regex pattern: bad repeat interval"
                    raise ValueError(msg)
                consume_quantifier()
                i = end + 1
                continue

        if char in "^$":
            mark_atom(repeatable=False)
        else:
            mark_atom()
        i += 1

    if len(scope_has_content) > 1:
        msg = "Invalid regex pattern: unterminated group"
        raise ValueError(msg)


def _parse_regex_repeat_interval(content: str) -> tuple[int | None, int | None] | None:
    if "," not in content:
        if content.isdigit():
            value = int(content)
            return value, value
        return None

    parts = content.split(",")
    if len(parts) != 2:
        return None

    min_text, max_text = parts
    if not min_text and not max_text:
        return None
    if min_text and not min_text.isdigit():
        return None
    if max_text and not max_text.isdigit():
        return None

    min_value = int(min_text) if min_text else None
    max_value = int(max_text) if max_text else None
    return min_value, max_value


def _validate_regex_escape(
    pattern: str,
    index: int,
    *,
    in_character_class: bool,
) -> tuple[int, int, bool]:
    if index + 1 >= len(pattern):
        msg = "Invalid regex pattern: dangling escape"
        raise ValueError(msg)

    escaped = pattern[index + 1]
    if escaped == "x":
        if (
            index + 3 >= len(pattern)
            or pattern[index + 2] not in _HEX_DIGITS
            or pattern[index + 3] not in _HEX_DIGITS
        ):
            msg = "Invalid regex pattern: illegal escape sequence"
            raise ValueError(msg)
        return index + 4, int(pattern[index + 2 : index + 4], 16), True

    if not in_character_class and escaped.isdigit():
        msg = "Invalid regex pattern: backreferences are not allowed"
        raise ValueError(msg)

    return index + 2, ord(escaped), escaped not in _REGEX_ZERO_WIDTH_ESCAPES


def _validate_regex_character_class(pattern: str, start: int) -> int:
    content_start = start + 1
    if content_start < len(pattern) and pattern[content_start] == "^":
        content_start += 1

    i = content_start
    while i < len(pattern):
        if _is_regex_character_class_closer(pattern, i, content_start):
            return i + 1

        left_value, i = _read_regex_character_class_item(pattern, i)
        range_start = i + 1
        if (
            i < len(pattern)
            and pattern[i] == "-"
            and range_start < len(pattern)
            and not _is_regex_character_class_closer(pattern, range_start, content_start)
        ):
            right_value, i = _read_regex_character_class_item(pattern, range_start)
            if left_value > right_value:
                msg = "Invalid regex pattern: bad character range"
                raise ValueError(msg)

    msg = "Invalid regex pattern: unterminated character class"
    raise ValueError(msg)


def _is_regex_character_class_closer(pattern: str, index: int, content_start: int) -> bool:
    return pattern[index] == "]" and index != content_start


def _read_regex_character_class_item(pattern: str, index: int) -> tuple[int, int]:
    if pattern[index] == "\\":
        next_index, value, _ = _validate_regex_escape(
            pattern,
            index,
            in_character_class=True,
        )
        return value, next_index
    return ord(pattern[index]), index + 1


class ParserError(YaraASTError):
    """Parser error exception."""

    def __init__(self, message: str, token: IToken) -> None:
        super().__init__(f"Parser error at {token.line}:{token.column}: {message}")
        self.token = token
        self.line = token.line
        self.column = token.column
