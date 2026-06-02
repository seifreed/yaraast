"""Helpers for string reference identifiers."""

from __future__ import annotations

import re

_STRING_REFERENCE_BODY_RE = re.compile(r"^(?:[A-Za-z0-9_]+\*?|\*)$")
_CONCRETE_STRING_REFERENCE_BODY_RE = re.compile(r"^[A-Za-z0-9_]+$")


def normalize_string_reference_id(
    string_id: object,
    *,
    allow_wildcard: bool = True,
) -> str:
    """Normalize a string identifier field, rejecting embedded reference operators."""
    if not isinstance(string_id, str):
        msg = "String reference must be a string"
        raise TypeError(msg)
    normalized = string_id if string_id.startswith("$") else f"${string_id}"
    body = normalized.removeprefix("$")
    body_pattern = (
        _STRING_REFERENCE_BODY_RE if allow_wildcard else _CONCRETE_STRING_REFERENCE_BODY_RE
    )
    if body_pattern.fullmatch(body) is not None:
        return normalized
    if string_id.startswith("$"):
        msg = f"Invalid string reference '{string_id}'"
        raise ValueError(msg)
    if string_id.startswith(("#", "@", "!")):
        msg = f"Invalid string reference '{string_id}'"
        raise ValueError(msg)
    msg = f"Invalid string reference '{normalized}'"
    raise ValueError(msg)
