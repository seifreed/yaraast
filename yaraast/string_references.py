"""Helpers for string reference identifiers."""

from __future__ import annotations

import re

_STRING_REFERENCE_BODY_RE = re.compile(r"^(?:[A-Za-z0-9_]+\*?|\*)$")
_CONCRETE_STRING_REFERENCE_BODY_RE = re.compile(r"^[A-Za-z0-9_]+$")
_STRING_IDENTIFIER_BODY_RE = re.compile(r"^[A-Za-z0-9_]+$")
_STRING_PLACEHOLDER_REFERENCES = frozenset({"", "$"})


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


def _require_string_text(value: object, context: str) -> str:
    if isinstance(value, str):
        return value
    msg = f"{context} must be a string for libyara output"
    raise TypeError(msg)


def validate_string_identifier_text(identifier: object, *, allow_placeholder: bool = False) -> str:
    """Return a normalized string identifier or reject invalid libyara output."""
    text = _require_string_text(identifier, "String identifier")
    if allow_placeholder and text in _STRING_PLACEHOLDER_REFERENCES:
        return "$"
    normalized = text if text.startswith("$") else f"${text}"
    body = normalized.removeprefix("$")
    if not body or _STRING_IDENTIFIER_BODY_RE.fullmatch(body) is None:
        msg = f"Invalid string identifier '{normalized}' for libyara output"
        raise ValueError(msg)
    return normalized


def validate_string_wildcard_text(pattern: object) -> str:
    """Return a normalized string wildcard or reject invalid libyara output."""
    text = _require_string_text(pattern, "String wildcard")
    normalized = text if text.startswith("$") else f"${text}"
    body = normalized.removeprefix("$")
    if body == "*":
        return normalized
    if body.endswith("*"):
        prefix = body[:-1]
        if prefix and _STRING_IDENTIFIER_BODY_RE.fullmatch(prefix) is not None:
            return normalized
    msg = f"Invalid string wildcard '{normalized}' for libyara output"
    raise ValueError(msg)
