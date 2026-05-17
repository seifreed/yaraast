"""Escaping helpers for YARA string source values."""

from __future__ import annotations

import re


def escape_string_source_value(value: str) -> str:
    """Escape string content for source-like YARA output."""
    escaped_value = value.replace("\\", "\\\\")
    escaped_value = escaped_value.replace('"', '\\"')
    escaped_value = escaped_value.replace("\n", "\\n")
    escaped_value = escaped_value.replace("\r", "\\r")
    escaped_value = escaped_value.replace("\t", "\\t")
    escaped_value = escaped_value.replace("\x00", "\\x00")
    return re.sub(
        r"[\x01-\x1f\x7f-\x9f]",
        lambda match: f"\\x{ord(match.group(0)):02x}",
        escaped_value,
    )
