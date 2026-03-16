"""Exhaustive tests for evaluator_ops helpers (no mocks)."""

from __future__ import annotations

import re

import pytest

from yaraast.evaluation.evaluator_ops import (
    evaluate_arithmetic,
    evaluate_comparison,
    evaluate_string_operator,
)


def test_evaluate_arithmetic_all_operators() -> None:
    assert evaluate_arithmetic(2, 3, "+") == 5
    assert evaluate_arithmetic(5, 3, "-") == 2
    assert evaluate_arithmetic(2, 3, "*") == 6
    assert evaluate_arithmetic(7, 2, "/") == 3
    assert evaluate_arithmetic(7.0, 2.0, "/") == 3.5
    assert evaluate_arithmetic(7, 4, "%") == 3
    assert evaluate_arithmetic(1, 3, "<<") == 8
    assert evaluate_arithmetic(8, 2, ">>") == 2
    assert evaluate_arithmetic(6, 3, "&") == 2
    assert evaluate_arithmetic(6, 3, "|") == 7
    assert evaluate_arithmetic(6, 3, "^") == 5
    assert evaluate_arithmetic(1, 2, "??") is None


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
    assert evaluate_string_operator("Hello", "ell", "icontains") is True
    assert evaluate_string_operator("hello", "he", "startswith") is True
    assert evaluate_string_operator("Hello", "he", "istartswith") is True
    assert evaluate_string_operator("hello", "lo", "endswith") is True
    assert evaluate_string_operator("Hello", "LO", "iendswith") is True
    assert evaluate_string_operator("Hello", "hello", "iequals") is True
    assert evaluate_string_operator("abc123", r"\d+", "matches") is True
    assert evaluate_string_operator(None, "a", "matches") is False
    with pytest.raises(re.error):
        evaluate_string_operator("abc", r"(", "matches")
    assert evaluate_string_operator("abc", "x", "unknown") is None
