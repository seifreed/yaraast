"""Integer arithmetic semantics shared by evaluators and optimizers."""

from __future__ import annotations


def truncate_integer_division(left: int, right: int) -> int:
    """Divide integers with truncation toward zero."""
    quotient = abs(left) // abs(right)
    if (left < 0) != (right < 0):
        return -quotient
    return quotient


def integer_remainder(left: int, right: int) -> int:
    """Return the remainder matching truncation-toward-zero division."""
    quotient = truncate_integer_division(left, right)
    return left - quotient * right
