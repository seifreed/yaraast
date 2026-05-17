"""Integer arithmetic semantics shared by evaluators and optimizers."""

from __future__ import annotations

INT64_BITS = 64
INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1
UINT64_MASK = (1 << INT64_BITS) - 1


def normalize_int64(value: int) -> int:
    """Normalize an integer to YARA's signed 64-bit runtime representation."""
    unsigned = value & UINT64_MASK
    if unsigned > INT64_MAX:
        return unsigned - (1 << INT64_BITS)
    return unsigned


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


def shift_left_int64(left: int, right: int) -> int:
    """Shift left with YARA's signed 64-bit runtime semantics."""
    if right >= INT64_BITS:
        return 0
    return normalize_int64(left << right)


def shift_right_int64(left: int, right: int) -> int:
    """Shift right with YARA's signed 64-bit runtime semantics."""
    if right >= INT64_BITS:
        return 0
    return normalize_int64(left) >> right
