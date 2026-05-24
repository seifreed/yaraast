"""Shared modifier value normalization helpers."""

from __future__ import annotations

from typing import Any

from yaraast.xor_keys import parse_xor_key_text


def deserialize_legacy_modifier_value(name: str, value: Any) -> Any:
    """Normalize modifier values from legacy serialized payloads."""
    if name != "xor":
        return value
    if isinstance(value, list) and len(value) == 2:
        return (value[0], value[1])
    if isinstance(value, str) and "-" in value:
        low, high = value.split("-", maxsplit=1)
        parsed_low = parse_xor_key_text(low)
        parsed_high = parse_xor_key_text(high)
        if parsed_low is not None and parsed_high is not None:
            return (parsed_low, parsed_high)
    if isinstance(value, str):
        parsed_value = parse_xor_key_text(value)
        if parsed_value is not None:
            return parsed_value
    return value
