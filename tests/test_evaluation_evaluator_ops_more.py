"""Exhaustive tests for evaluator_ops helpers (no mocks)."""

from __future__ import annotations

import math

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
    assert evaluate_arithmetic(7, 2.0, "\\") == 3.5
    assert evaluate_arithmetic(7.0, 2, "\\") == 3.5
    assert evaluate_arithmetic(7, 4, "%") == 3
    assert evaluate_arithmetic(7.0, 4.0, "%") is YARA_UNDEFINED
    assert evaluate_arithmetic(1, 3, "<<") == 8
    assert evaluate_arithmetic(8, 2, ">>") == 2
    assert evaluate_arithmetic(6, 3, "&") == 2
    assert evaluate_arithmetic(6, 3, "|") == 7
    assert evaluate_arithmetic(6, 3, "^") == 5
    assert evaluate_arithmetic(1, 2, "??") is None


def test_evaluate_arithmetic_zero_divisor_returns_undefined() -> None:
    assert evaluate_arithmetic(7, 0, "/") is YARA_UNDEFINED
    assert evaluate_arithmetic(7, 0, "%") is YARA_UNDEFINED


def test_evaluate_float_division_by_zero_matches_libyara_double_opcode() -> None:
    assert evaluate_arithmetic(7.0, 0.0, "\\") == math.inf
    assert evaluate_arithmetic(-7.0, 0.0, "\\") == -math.inf
    assert evaluate_arithmetic(7.0, -0.0, "\\") == -math.inf
    nan_result = evaluate_arithmetic(0.0, 0.0, "\\")
    assert isinstance(nan_result, float)
    assert math.isnan(nan_result)


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


@pytest.mark.parametrize(
    ("left", "right", "operator"),
    [
        ("a", 1, "+"),
        ("a", "b", "+"),
        (1, "a", "-"),
        ("a", 1, "<<"),
        (1, "a", "<<"),
        (1, "a", "&"),
    ],
)
def test_evaluate_arithmetic_incompatible_operands_return_undefined(
    left: object,
    right: object,
    operator: str,
) -> None:
    assert evaluate_arithmetic(left, right, operator) is YARA_UNDEFINED


def test_evaluate_arithmetic_rejects_boolean_operands() -> None:
    assert evaluate_arithmetic(True, 1, "+") is YARA_UNDEFINED
    assert evaluate_arithmetic(1, False, "-") is YARA_UNDEFINED
    assert evaluate_arithmetic(True, True, "&") is YARA_UNDEFINED
    assert evaluate_arithmetic(True, 1, "<<") is YARA_UNDEFINED


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


def test_evaluate_comparison_keeps_booleans_distinct_from_integers() -> None:
    assert evaluate_comparison(True, 1, "==") is False
    assert evaluate_comparison(False, 0, "==") is False
    assert evaluate_comparison(True, 1, "!=") is True
    assert evaluate_comparison(False, 0, "!=") is True


def test_evaluate_float_equality_uses_libyara_epsilon() -> None:
    assert evaluate_comparison(1.0, 1.0 + (1e-17), "==") is True
    assert evaluate_comparison(1.0, 1.0 + (1e-15), "==") is False
    assert evaluate_comparison(1.0, 1.0 + (1e-15), "!=") is True
    assert evaluate_comparison(math.inf, math.inf, "==") is False
    assert evaluate_comparison(math.inf, math.inf, "!=") is False
    assert evaluate_comparison(math.nan, 0.0, "!=") is False


@pytest.mark.parametrize("operator", ["<", "<=", ">", ">="])
def test_evaluate_comparison_incompatible_ordered_operands_are_false(
    operator: str,
) -> None:
    assert evaluate_comparison("a", 1, operator) is False
    assert evaluate_comparison(1, "a", operator) is False


@pytest.mark.parametrize(
    ("left", "right", "operator"),
    [
        (False, True, "<"),
        (False, False, "<="),
        (True, False, ">"),
        (True, True, ">="),
        ([], [1], "<"),
        ((1,), (2,), "<"),
    ],
)
def test_evaluate_comparison_rejects_non_yara_ordered_operands(
    left: object,
    right: object,
    operator: str,
) -> None:
    assert evaluate_comparison(left, right, operator) is False


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
    assert evaluate_string_operator("abc", r"abc$", "matches") is True
    assert evaluate_string_operator("", r"$", "matches") is True
    assert evaluate_string_operator("ABC", RegexLiteral(pattern="abc", modifiers="i"), "matches")
    assert evaluate_string_operator(None, "a", "matches") is False
    assert evaluate_string_operator("abc", r"(", "matches") is False
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
