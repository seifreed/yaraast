"""Shared modifier value normalization helpers."""

from __future__ import annotations

from typing import Any


def deserialize_legacy_modifier_value(name: str, value: Any) -> Any:
    """Normalize modifier values from legacy serialized payloads."""
    if name != "xor":
        return value
    if isinstance(value, list) and len(value) == 2:
        return (value[0], value[1])
    if isinstance(value, str) and "-" in value:
        low, high = value.split("-", maxsplit=1)
        parsed_low = _parse_xor_key_text(low)
        parsed_high = _parse_xor_key_text(high)
        if parsed_low is not None and parsed_high is not None:
            return (parsed_low, parsed_high)
    if isinstance(value, str):
        parsed_value = _parse_xor_key_text(value)
        if parsed_value is not None:
            return parsed_value
    return value


def _parse_xor_key_text(value: str) -> int | None:
    text = value.strip()
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        if any(char in "abcdefABCDEF" for char in text):
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return None
