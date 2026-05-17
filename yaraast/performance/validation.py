"""Validation helpers for performance tuning settings."""

from __future__ import annotations


def validate_positive_int_setting(value: object, name: str) -> None:
    """Require a positive integer while keeping booleans out of numeric settings."""
    if not isinstance(value, int) or isinstance(value, bool):
        msg = f"{name} must be an integer"
        raise TypeError(msg)
    if value < 1:
        msg = f"{name} must be at least 1"
        raise ValueError(msg)
