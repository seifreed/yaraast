"""Shared validators for public numeric options."""

from __future__ import annotations


def validate_positive_int_setting(value: object, name: str) -> None:
    """Require a positive integer while keeping booleans out of numeric settings."""
    if not isinstance(value, int) or isinstance(value, bool):
        msg = f"{name} must be an integer"
        raise TypeError(msg)
    if value < 1:
        msg = f"{name} must be at least 1"
        raise ValueError(msg)


def validate_non_negative_int_setting(value: object, name: str) -> None:
    """Require a non-negative integer while keeping booleans out of numeric settings."""
    if not isinstance(value, int) or isinstance(value, bool):
        msg = f"{name} must be an integer"
        raise TypeError(msg)
    if value < 0:
        msg = f"{name} must be at least 0"
        raise ValueError(msg)


def validate_positive_number_setting(value: object, name: str) -> None:
    """Require a positive int or float while keeping booleans out of numeric settings."""
    if not isinstance(value, int | float) or isinstance(value, bool):
        msg = f"{name} must be a number"
        raise TypeError(msg)
    if value <= 0:
        msg = f"{name} must be greater than 0"
        raise ValueError(msg)
