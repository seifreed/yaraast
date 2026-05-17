"""Exhaustive tests for evaluator_ops helpers (no mocks)."""

from __future__ import annotations

import re

import pytest

from yaraast.ast.expressions import RegexLiteral
from yaraast.evaluation.evaluation_helpers import YARA_UNDEFINED
from yaraast.evaluation.evaluator_ops import (
    evaluate_arithmetic,
    evaluate_comparison,
    evaluate_string_operator,
)
from yaraast.shared.integer_semantics import INT64_MAX, INT64_MIN


def test_evaluate_arithmetic_all_operators() -> None:
    assert evaluate_arithmetic(2, 3, "+") == 5
    assert evaluate_arithmetic(5, 3, "-") == 2
    assert evaluate_arithmetic(2, 3, "*") == 6
    assert evaluate_arithmetic(7, 2, "/") == 3
    assert evaluate_arithmetic(7, 2, "\\") == 3
    assert evaluate_arithmetic(7.0, 2.0, "/") == 3.5
    assert evaluate_arithmetic(7, 4, "%") == 3
    assert evaluate_arithmetic(1, 3, "<<") == 8
    assert evaluate_arithmetic(8, 2, ">>") == 2
    assert evaluate_arithmetic(6, 3, "&") == 2
    assert evaluate_arithmetic(6, 3, "|") == 7
    assert evaluate_arithmetic(6, 3, "^") == 5
    assert evaluate_arithmetic(1, 2, "??") is None


def test_evaluate_arithmetic_zero_divisor_returns_undefined() -> None:
    assert evaluate_arithmetic(7, 0, "/") is YARA_UNDEFINED
    assert evaluate_arithmetic(7.0, 0.0, "/") is YARA_UNDEFINED
    assert evaluate_arithmetic(7, 0, "%") is YARA_UNDEFINED


def test_evaluate_arithmetic_negative_shift_returns_undefined() -> None:
    assert evaluate_arithmetic(1, -1, "<<") is YARA_UNDEFINED
    assert evaluate_arithmetic(1, -1, ">>") is YARA_UNDEFINED


def test_evaluate_arithmetic_uses_signed_int64_runtime_semantics() -> None:
    assert evaluate_arithmetic(INT64_MAX, 1, "+") == INT64_MIN
    assert evaluate_arithmetic(INT64_MIN, 1, "-") == INT64_MAX
    assert evaluate_arithmetic(1 << 62, 2, "*") == INT64_MIN
    assert evaluate_arithmetic(1, 63, "<<") == INT64_MIN
    assert evaluate_arithmetic(1, 64, "<<") == 0
    assert evaluate_arithmetic(-1, 64, ">>") == 0
    assert evaluate_arithmetic(INT64_MIN, -1, "\\") is YARA_UNDEFINED
    assert evaluate_arithmetic(INT64_MIN, -1, "%") is YARA_UNDEFINED


def test_evaluate_integer_division_and_modulo_do_not_use_float_conversion() -> None:
    large = 10**400 + 1

    assert evaluate_arithmetic(large, 3, "/") == large // 3
    assert evaluate_arithmetic(-large, 3, "/") == -(large // 3)
    assert evaluate_arithmetic(large, 3, "%") == large % 3
    assert evaluate_arithmetic(-large, 3, "%") == -(large % 3)


def test_evaluate_comparison_all_operators() -> None:
    assert evaluate_comparison(1, 1, "==") is True
    assert evaluate_comparison(1, 2, "!=") is True
    assert evaluate_comparison(1, 2, "<") is True
    assert evaluate_comparison(1, 1, "<=") is True
    assert evaluate_comparison(2, 1, ">") is True
    assert evaluate_comparison(2, 2, ">=") is True
    assert evaluate_comparison(1, 2, "??") is None


def test_evaluate_string_operator_all_paths() -> None:
    assert evaluate_string_operator("hello", "ell", "contains") is True
    assert evaluate_string_operator("hello", "", "contains") is False
    assert evaluate_string_operator("Hello", "ell", "icontains") is True
    assert evaluate_string_operator("Hello", "", "icontains") is True
    assert evaluate_string_operator("hello", "he", "startswith") is True
    assert evaluate_string_operator("Hello", "he", "istartswith") is True
    assert evaluate_string_operator("hello", "lo", "endswith") is True
    assert evaluate_string_operator("Hello", "LO", "iendswith") is True
    assert evaluate_string_operator("Hello", "hello", "iequals") is True
    assert evaluate_string_operator("abc123", r"\d+", "matches") is True
    assert evaluate_string_operator("abc", r"$", "matches") is False
    assert evaluate_string_operator("", r"$", "matches") is True
    assert evaluate_string_operator("ABC", RegexLiteral(pattern="abc", modifiers="i"), "matches")
    assert evaluate_string_operator(None, "a", "matches") is False
    with pytest.raises(re.error):
        evaluate_string_operator("abc", r"(", "matches")
    assert evaluate_string_operator("abc", "x", "unknown") is None


@pytest.mark.parametrize(
    "operator",
    [
        "contains",
        "icontains",
        "startswith",
        "istartswith",
        "endswith",
        "iendswith",
        "iequals",
    ],
)
def test_evaluate_string_operator_invalid_operands_are_false(operator: str) -> None:
    assert evaluate_string_operator(None, "x", operator) is False
    assert evaluate_string_operator("hello", None, operator) is False
