"""String length helpers for YARA-X compatibility behavior."""

from __future__ import annotations


def plain_string_byte_length(value: str | bytes) -> int:
    """Return the byte length YARA observes for a plain string value."""
    if isinstance(value, bytes):
        return len(value)
    return len(value.encode())
