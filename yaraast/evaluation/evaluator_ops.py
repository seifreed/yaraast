"""Operator helpers for YARA evaluation."""

from __future__ import annotations

import re
from typing import Any

from yaraast.evaluation.evaluation_helpers import YARA_UNDEFINED, is_yara_undefined
from yaraast.shared.integer_semantics import (
    INT64_MIN,
    integer_remainder,
    normalize_int64,
    shift_left_int64,
    shift_right_int64,
    truncate_integer_division,
)


def evaluate_arithmetic(left: Any, right: Any, operator: str) -> Any | None:
    if is_yara_undefined(left) or is_yara_undefined(right):
        return YARA_UNDEFINED

    if operator == "+":
        if isinstance(left, int) and isinstance(right, int):
            return normalize_int64(left + right)
        return left + right
    if operator == "-":
        if isinstance(left, int) and isinstance(right, int):
            return normalize_int64(left - right)
        return left - right
    if operator == "*":
        if isinstance(left, int) and isinstance(right, int):
            return normalize_int64(left * right)
        return left * right
    if operator in ("/", "\\"):
        if right == 0:
            return YARA_UNDEFINED
        if isinstance(left, int) and isinstance(right, int):
            if left == INT64_MIN and right == -1:
                return YARA_UNDEFINED
            return truncate_integer_division(left, right)
        if isinstance(left, int):
            return int(left / right)  # truncate toward zero (C/YARA semantics)
        return left / right
    if operator == "%":
        if right == 0:
            return YARA_UNDEFINED
        if isinstance(left, int) and isinstance(right, int):
            if left == INT64_MIN and right == -1:
                return YARA_UNDEFINED
            return integer_remainder(left, right)
        return left % right
    if operator == "<<":
        if right < 0:
            return YARA_UNDEFINED
        if isinstance(left, int) and isinstance(right, int):
            return shift_left_int64(left, right)
        return left << right
    if operator == ">>":
        if right < 0:
            return YARA_UNDEFINED
        if isinstance(left, int) and isinstance(right, int):
            return shift_right_int64(left, right)
        return left >> right
    if operator == "&":
        if isinstance(left, int) and isinstance(right, int):
            return normalize_int64(left & right)
        return left & right
    if operator == "|":
        if isinstance(left, int) and isinstance(right, int):
            return normalize_int64(left | right)
        return left | right
    if operator == "^":
        if isinstance(left, int) and isinstance(right, int):
            return normalize_int64(left ^ right)
        return left ^ right
    return None


def evaluate_comparison(left: Any, right: Any, operator: str) -> bool | None:
    if is_yara_undefined(left) or is_yara_undefined(right):
        return False

    if operator == "==":
        return left == right
    if operator == "!=":
        return left != right
    try:
        if operator == "<":
            return left < right
        if operator == "<=":
            return left <= right
        if operator == ">":
            return left > right
        if operator == ">=":
            return left >= right
    except TypeError:
        return False
    return None


def evaluate_string_operator(left: Any, right: Any, operator: str) -> bool | None:
    if is_yara_undefined(left) or is_yara_undefined(right):
        return False

    string_operators = {
        "contains",
        "icontains",
        "startswith",
        "istartswith",
        "endswith",
        "iendswith",
        "iequals",
    }
    if operator in string_operators and not (isinstance(left, str) and isinstance(right, str)):
        return False

    if operator == "contains":
        if right == "":
            return False
        return right in left
    if operator == "icontains":
        return right.lower() in left.lower()
    if operator == "startswith":
        return left.startswith(right)
    if operator == "istartswith":
        return left.lower().startswith(right.lower())
    if operator == "endswith":
        return left.endswith(right)
    if operator == "iendswith":
        return left.lower().endswith(right.lower())
    if operator == "iequals":
        return left.lower() == right.lower()
    if operator == "matches":
        pattern = getattr(right, "pattern", right)
        modifiers = getattr(right, "modifiers", "")
        return evaluate_regex_match(left, pattern, modifiers)
    return None


def evaluate_regex_match(left: Any, pattern: Any, modifiers: str = "") -> bool:
    flags = 0
    if "i" in modifiers:
        flags |= re.IGNORECASE
    if "s" in modifiers:
        flags |= re.DOTALL
    if "m" in modifiers:
        flags |= re.MULTILINE

    try:
        regex = re.compile(pattern, flags)
        if not left:
            return bool(regex.match(left))
        return any(regex.match(left, offset) for offset in range(len(left)))
    except (re.error, ValueError, TypeError, AttributeError):
        return False
