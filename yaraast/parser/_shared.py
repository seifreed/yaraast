"""Shared parser constants and exceptions."""

from __future__ import annotations

from collections.abc import Sequence
import sys

from yaraast.ast.modifiers import StringModifier, StringModifierType
from yaraast.errors import YaraASTError
from yaraast.interfaces import IToken
from yaraast.regex_literals import validate_regex_modifiers, validate_regex_pattern

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


class ParserError(YaraASTError):
    """Parser error exception."""

    def __init__(self, message: str, token: IToken) -> None:
        super().__init__(f"Parser error at {token.line}:{token.column}: {message}")
        self.token = token
        self.line = token.line
        self.column = token.column
