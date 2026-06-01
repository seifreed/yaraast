"""Helpers for string reference identifiers."""

from __future__ import annotations


def normalize_string_reference_id(string_id: object) -> str:
    """Normalize a string identifier field, rejecting embedded reference operators."""
    if not isinstance(string_id, str):
        msg = "String reference must be a string"
        raise TypeError(msg)
    if string_id.startswith("$"):
        return string_id
    if string_id.startswith(("#", "@", "!")):
        msg = f"Invalid string reference '{string_id}'"
        raise ValueError(msg)
    return f"${string_id}"
