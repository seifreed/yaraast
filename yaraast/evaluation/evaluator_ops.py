"""Operator helpers for YARA evaluation."""

from __future__ import annotations

import re
from typing import Any


def evaluate_arithmetic(left: Any, right: Any, operator: str) -> Any | None:
    if operator == "+":
        return left + right
    if operator == "-":
        return left - right
    if operator == "*":
        return left * right
    if operator == "/":
        if right == 0:
            return 0
        if isinstance(left, int):
            return int(left / right)  # truncate toward zero (C/YARA semantics)
        return left / right
    if operator == "%":
        if right == 0:
            return 0
        if isinstance(left, int) and isinstance(right, int):
            return int(left - int(left / right) * right)  # C/YARA: sign of dividend
        return left % right
    if operator == "<<":
        return left << right
    if operator == ">>":
        return left >> right
    if operator == "&":
        return left & right
    if operator == "|":
        return left | right
    if operator == "^":
        return left ^ right
    return None


def evaluate_comparison(left: Any, right: Any, operator: str) -> bool | None:
    if operator == "==":
        return left == right
    if operator == "!=":
        return left != right
    if operator == "<":
        return left < right
    if operator == "<=":
        return left <= right
    if operator == ">":
        return left > right
    if operator == ">=":
        return left >= right
    return None


def evaluate_string_operator(left: Any, right: Any, operator: str) -> bool | None:
    if operator == "contains":
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
        return bool(re.search(pattern, left, flags))
    except (ValueError, TypeError, AttributeError):
        return False
