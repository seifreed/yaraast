"""Helpers for regex literal formatting."""

from __future__ import annotations

VALID_REGEX_MODIFIERS = frozenset("is")
REGEX_MODIFIER_ORDER = "is"
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_REGEX_QUANTIFIERS = frozenset("*+?")
_REGEX_ZERO_WIDTH_ESCAPES = frozenset("bB")
_MAX_REGEX_REPEAT_INTERVAL = 32767


def escape_regex_delimiter(pattern: str) -> str:
    """Escape unescaped '/' characters without double-escaping existing escapes."""
    result: list[str] = []
    backslash_count = 0

    for char in pattern:
        if char == "/":
            if backslash_count % 2 == 0:
                result.append("\\")
            result.append(char)
            backslash_count = 0
            continue

        result.append(char)
        if char == "\\":
            backslash_count += 1
        else:
            backslash_count = 0

    return "".join(result)


def validate_regex_modifiers(modifiers: str) -> None:
    """Reject regex suffix modifiers that libyara rejects."""
    seen: set[str] = set()
    for modifier in modifiers:
        if modifier not in VALID_REGEX_MODIFIERS:
            msg = f"Invalid regex modifier: {modifier}"
            raise ValueError(msg)
        if modifier in seen:
            msg = f"Duplicate regex modifier: {modifier}"
            raise ValueError(msg)
        seen.add(modifier)
    ordered = "".join(modifier for modifier in REGEX_MODIFIER_ORDER if modifier in seen)
    if modifiers != ordered:
        msg = f"Invalid regex modifier order: {modifiers}"
        raise ValueError(msg)


def validate_regex_pattern(pattern: str) -> None:
    """Reject regex structure that libyara rejects before codegen or parsing."""
    if not pattern:
        msg = "Invalid regex pattern: empty pattern"
        raise ValueError(msg)

    scope_has_content = [False]
    can_repeat = False
    last_was_quantifier = False
    quantifier_style: str | None = None

    def mark_atom(repeatable: bool = True) -> None:
        nonlocal can_repeat, last_was_quantifier
        if last_was_quantifier:
            record_quantifier_style("greedy")
        scope_has_content[-1] = True
        can_repeat = repeatable
        last_was_quantifier = False

    def record_quantifier_style(style: str) -> None:
        nonlocal quantifier_style
        if quantifier_style is None:
            quantifier_style = style
            return
        if quantifier_style != style:
            msg = "Invalid regex pattern: greedy and ungreedy quantifiers can't be mixed"
            raise ValueError(msg)

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
            record_quantifier_style("ungreedy")
            last_was_quantifier = False
            can_repeat = False
            i += 1
            continue
        if last_was_quantifier:
            record_quantifier_style("greedy")

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
            repeat_text = pattern[i + 1 : end] if end != -1 else ""
            interval = _parse_regex_repeat_interval(repeat_text) if end != -1 else None
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
            if repeat_text == "," and not can_repeat:
                msg = "Invalid regex pattern: syntax error"
                raise ValueError(msg)

        if char in "^$":
            mark_atom(repeatable=False)
        else:
            mark_atom()
        i += 1

    if len(scope_has_content) > 1:
        msg = "Invalid regex pattern: unterminated group"
        raise ValueError(msg)
    if last_was_quantifier:
        record_quantifier_style("greedy")


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
        return None, None
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
