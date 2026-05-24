"""Shared parsing for YARA xor modifier key values."""

from __future__ import annotations

_DECIMAL_DIGITS = frozenset("0123456789")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def parse_xor_key_text(value: str) -> int | None:
    """Parse xor key text accepted by libyara."""
    text = value.strip()
    if not text:
        return None
    if text.startswith("0x"):
        digits = text[2:]
        if digits and all(char in _HEX_DIGITS for char in digits):
            return int(digits, 16)
        return None
    if all(char in _DECIMAL_DIGITS for char in text):
        return int(text, 10)
    return None
