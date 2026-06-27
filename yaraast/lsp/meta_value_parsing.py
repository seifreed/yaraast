"""Safe parsing helpers for YARA meta values in text fallbacks."""

from __future__ import annotations

import json
from typing import Any


def parse_meta_scalar(raw_value: str) -> tuple[bool, Any]:
    """Parse a simple meta scalar without evaluating Python expressions.

    The fallback paths only need the scalar types the project already supports:
    strings, integers, floats, booleans, and null/none.
    """
    text = raw_value.strip()
    lowered = text.lower()
    if lowered == "true":
        return True, True
    if lowered == "false":
        return True, False
    if lowered in {"null", "none"}:
        return True, None

    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        parsed = None
    else:
        if isinstance(parsed, (str, bool, int, float)) or parsed is None:
            return True, parsed

    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        return True, text[1:-1]

    return False, None
