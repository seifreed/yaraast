"""Shared parser constants and exceptions."""

from __future__ import annotations

from collections.abc import Sequence
import sys

from yaraast.ast.modifiers import StringModifier, StringModifierType
from yaraast.errors import YaraASTError
from yaraast.interfaces import IToken
from yaraast.regex_literals import validate_regex_modifiers

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
_REGEX_QUANTIFIERS = frozenset("*+?")
_REGEX_ZERO_WIDTH_ESCAPES = frozenset("bB")
_MAX_REGEX_REPEAT_INTERVAL = 32767
_MAX_XOR_KEY = 0xFF
_BASE64_ALPHABET_LENGTH = 64
_DEFAULT_BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# Each nested expression level of the recursive descent parser consumes a fixed
# block of Python stack frames, so pathologically nested input (deeply
# parenthesised conditions, nested for bodies, etc.) would otherwise exhaust the
# interpreter stack and surface as a RecursionError. Tracking the nesting depth
# and rejecting input that gets within a safety margin of the interpreter's
# recursion limit keeps the parser robust against hostile input while leaving
# ample headroom for realistic rules. The budget is derived from the live
# recursion limit so the guard fires before the stack is exhausted regardless of
# any sys.setrecursionlimit the caller has applied.
#
# _EXPRESSION_FRAMES_PER_LEVEL is a conservative upper bound on the number of
# Python frames each nested expression level adds (or-/and-/.../primary descent
# plus the parenthesised/for re-entry into _parse_expression).
_EXPRESSION_FRAMES_PER_LEVEL = 20
# Frames reserved for the non-expression call stack already in flight (rule and
# section parsing, the caller's own frames) when the first expression is parsed.
_EXPRESSION_STACK_RESERVE = 120


def max_expression_depth() -> int:
    """Return the maximum allowed expression nesting depth.

    Derived from the live interpreter recursion limit so the parser rejects
    over-deep input with a clean error before the recursive descent exhausts the
    Python stack, regardless of any ``sys.setrecursionlimit`` the caller set.
    """
    budget = sys.getrecursionlimit() - _EXPRESSION_STACK_RESERVE
    return max(1, budget // _EXPRESSION_FRAMES_PER_LEVEL)


def validate_string_modifiers(modifiers: Sequence[StringModifier]) -> None:
    """Reject string modifier combinations and parameters that libyara rejects."""
    seen: set[StringModifierType] = set()
    modifier_types: list[StringModifierType] = []
    for modifier in modifiers:
        modifier_type = modifier.modifier_type
        if modifier_type in seen:
            msg = f"duplicated modifier: {modifier_type.value}"
            raise ValueError(msg)
        seen.add(modifier_type)
        modifier_types.append(modifier_type)
        _validate_string_modifier_value(modifier)

    modifier_set = set(modifier_types)
    if StringModifierType.XOR in modifier_set:
        if StringModifierType.NOCASE in modifier_set:
            msg = "invalid modifier combination: xor nocase"
            raise ValueError(msg)
        if StringModifierType.BASE64 in modifier_set:
            msg = "invalid modifier combination: base64 xor"
            raise ValueError(msg)
        if StringModifierType.BASE64WIDE in modifier_set:
            msg = "invalid modifier combination: base64wide xor"
            raise ValueError(msg)

    for base64_type in (StringModifierType.BASE64, StringModifierType.BASE64WIDE):
        if base64_type not in modifier_set:
            continue
        if StringModifierType.NOCASE in modifier_set:
            msg = f"invalid modifier combination: {base64_type.value} nocase"
            raise ValueError(msg)
        if StringModifierType.FULLWORD in modifier_set:
            msg = f"invalid modifier combination: {base64_type.value} fullword"
            raise ValueError(msg)

    _validate_base64_alphabet_agreement(modifiers)


def _validate_base64_alphabet_agreement(modifiers: Sequence[StringModifier]) -> None:
    """Reject base64 and base64wide that resolve to different alphabets.

    libyara stores a single base64 alphabet shared by both modifiers, so when a
    rule supplies both ``base64`` and ``base64wide`` their effective alphabets
    (the custom one if given, otherwise the default) must be identical.
    """
    effective: dict[StringModifierType, str] = {}
    for modifier in modifiers:
        if modifier.modifier_type in (StringModifierType.BASE64, StringModifierType.BASE64WIDE):
            value = modifier.value
            alphabet = value if isinstance(value, str) else _DEFAULT_BASE64_ALPHABET
            effective[modifier.modifier_type] = alphabet

    if len(effective) == 2 and len(set(effective.values())) > 1:
        msg = "can not specify multiple alphabets"
        raise ValueError(msg)


def _validate_string_modifier_value(modifier: StringModifier) -> None:
    if modifier.modifier_type == StringModifierType.XOR:
        _validate_xor_modifier_value(modifier.value)
    elif modifier.modifier_type in (StringModifierType.BASE64, StringModifierType.BASE64WIDE):
        _validate_base64_modifier_value(modifier.value)


def _validate_xor_modifier_value(value: str | int | float | tuple[int, int] | None) -> None:
    if value is None:
        return
    if isinstance(value, int):
        if value > _MAX_XOR_KEY:
            msg = "invalid xor range"
            raise ValueError(msg)
        return
    if isinstance(value, tuple):
        min_value, max_value = value
        if min_value > max_value:
            msg = "xor lower bound exceeds upper bound"
            raise ValueError(msg)
        if max_value > _MAX_XOR_KEY:
            msg = f"upper bound for xor range exceeded (max: {_MAX_XOR_KEY})"
            raise ValueError(msg)


def _validate_base64_modifier_value(value: str | int | float | tuple[int, int] | None) -> None:
    if value is None:
        return
    if isinstance(value, str) and len(value) != _BASE64_ALPHABET_LENGTH:
        msg = "length of base64 alphabet must be 64"
        raise ValueError(msg)


def parse_regex_value(regex_val: str) -> tuple[str, list[str]]:
    """Parse lexer regex payloads and preserve inline regex suffix flags."""
    pattern, mod_str = split_regex_value(regex_val)
    validate_regex_pattern(pattern)
    validate_regex_modifiers(mod_str)
    return pattern, list(mod_str)


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
                if (min_value is not None and min_value > _MAX_REGEX_REPEAT_INTERVAL) or (
                    max_value is not None and max_value > _MAX_REGEX_REPEAT_INTERVAL
                ):
                    msg = "Invalid regex pattern: repeat interval too large"
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
