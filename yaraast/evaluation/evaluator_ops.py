"""Operator helpers for YARA evaluation."""

from __future__ import annotations

import math
import re
import sys
from typing import Any, TypeGuard

from yaraast.evaluation.evaluation_helpers import YARA_UNDEFINED, is_yara_undefined
from yaraast.shared.integer_semantics import (
    INT64_MIN,
    integer_remainder,
    normalize_int64,
    shift_left_int64,
    shift_right_int64,
    truncate_integer_division,
)


def _is_runtime_int(value: Any) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_runtime_number(value: Any) -> bool:
    return _is_runtime_int(value) or isinstance(value, float)


def _is_comparison_number(value: Any) -> bool:
    return isinstance(value, int | float)


def _types_match_for_equality(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return _is_comparison_number(left) and _is_comparison_number(right)
    return True


def _types_support_ordered_comparison(left: Any, right: Any) -> bool:
    return (_is_comparison_number(left) and _is_comparison_number(right)) or (
        isinstance(left, str) and isinstance(right, str)
    )


def _divide_by_double_zero(left: int | float, right: int | float) -> float:
    if left == 0:
        return math.nan
    sign = math.copysign(1.0, left) * math.copysign(1.0, right)
    return math.copysign(math.inf, sign)


def _compare_double_equality(left: int | float, right: int | float, operator: str) -> bool:
    difference = math.fabs(float(left) - float(right))
    if operator == "==":
        return difference < sys.float_info.epsilon
    return difference >= sys.float_info.epsilon


def evaluate_arithmetic(left: Any, right: Any, operator: str) -> Any | None:
    if is_yara_undefined(left) or is_yara_undefined(right):
        return YARA_UNDEFINED

    try:
        if operator == "+":
            if not (_is_runtime_number(left) and _is_runtime_number(right)):
                return YARA_UNDEFINED
            if _is_runtime_int(left) and _is_runtime_int(right):
                return normalize_int64(left + right)
            return left + right
        if operator == "-":
            if not (_is_runtime_number(left) and _is_runtime_number(right)):
                return YARA_UNDEFINED
            if _is_runtime_int(left) and _is_runtime_int(right):
                return normalize_int64(left - right)
            return left - right
        if operator == "*":
            if not (_is_runtime_number(left) and _is_runtime_number(right)):
                return YARA_UNDEFINED
            if _is_runtime_int(left) and _is_runtime_int(right):
                return normalize_int64(left * right)
            return left * right
        if operator in ("/", "\\"):
            if not (_is_runtime_number(left) and _is_runtime_number(right)):
                return YARA_UNDEFINED
            if _is_runtime_int(left) and _is_runtime_int(right):
                if right == 0:
                    return YARA_UNDEFINED
                if left == INT64_MIN and right == -1:
                    return YARA_UNDEFINED
                return truncate_integer_division(left, right)
            if right == 0:
                return _divide_by_double_zero(left, right)
            return left / right
        if operator == "%":
            if not (_is_runtime_int(left) and _is_runtime_int(right)):
                return YARA_UNDEFINED
            if right == 0:
                return YARA_UNDEFINED
            if left == INT64_MIN and right == -1:
                return YARA_UNDEFINED
            return integer_remainder(left, right)
        if operator == "<<":
            if not (_is_runtime_int(left) and _is_runtime_int(right)):
                return YARA_UNDEFINED
            if right < 0:
                return YARA_UNDEFINED
            return shift_left_int64(left, right)
        if operator == ">>":
            if not (_is_runtime_int(left) and _is_runtime_int(right)):
                return YARA_UNDEFINED
            if right < 0:
                return YARA_UNDEFINED
            return shift_right_int64(left, right)
        if operator == "&":
            if not (_is_runtime_int(left) and _is_runtime_int(right)):
                return YARA_UNDEFINED
            return normalize_int64(left & right)
        if operator == "|":
            if not (_is_runtime_int(left) and _is_runtime_int(right)):
                return YARA_UNDEFINED
            return normalize_int64(left | right)
        if operator == "^":
            if not (_is_runtime_int(left) and _is_runtime_int(right)):
                return YARA_UNDEFINED
            return normalize_int64(left ^ right)
    except (TypeError, ValueError, OverflowError):
        return YARA_UNDEFINED
    return None


def evaluate_comparison(left: Any, right: Any, operator: str) -> bool | None:
    if is_yara_undefined(left) or is_yara_undefined(right):
        return False

    if operator == "==":
        if not _types_match_for_equality(left, right):
            return False
        if (
            _is_comparison_number(left)
            and _is_comparison_number(right)
            and (isinstance(left, float) or isinstance(right, float))
        ):
            return _compare_double_equality(left, right, operator)
        return bool(left == right)
    if operator == "!=":
        if not _types_match_for_equality(left, right):
            return True
        if (
            _is_comparison_number(left)
            and _is_comparison_number(right)
            and (isinstance(left, float) or isinstance(right, float))
        ):
            return _compare_double_equality(left, right, operator)
        return bool(left != right)
    if operator in ("<", "<=", ">", ">=") and not _types_support_ordered_comparison(
        left,
        right,
    ):
        return False
    try:
        if operator == "<":
            return bool(left < right)
        if operator == "<=":
            return bool(left <= right)
        if operator == ">":
            return bool(left > right)
        if operator == ">=":
            return bool(left >= right)
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
        return bool(left.startswith(right))
    if operator == "istartswith":
        return bool(left.lower().startswith(right.lower()))
    if operator == "endswith":
        return bool(left.endswith(right))
    if operator == "iendswith":
        return bool(left.lower().endswith(right.lower()))
    if operator == "iequals":
        return bool(left.lower() == right.lower())
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
