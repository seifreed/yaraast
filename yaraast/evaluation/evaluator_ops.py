"""Operator helpers for YARA evaluation."""

from __future__ import annotations

import re


def evaluate_arithmetic(left, right, operator):
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


def evaluate_comparison(left, right, operator):
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


def evaluate_string_operator(left, right, operator):
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
        try:
            return bool(re.search(right, left))
        except (ValueError, TypeError, AttributeError):
            return False
    return None
