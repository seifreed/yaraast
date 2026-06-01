"""Helpers for string reference identifiers."""

from __future__ import annotations


def normalize_string_reference_id(string_id: str) -> str:
    """Normalize a string identifier field, rejecting embedded reference operators."""
    if string_id.startswith("$"):
        return string_id
    if string_id.startswith(("#", "@", "!")):
        msg = f"Invalid string reference '{string_id}'"
        raise ValueError(msg)
    return f"${string_id}"
