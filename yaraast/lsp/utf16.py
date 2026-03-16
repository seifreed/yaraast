"""UTF-16 position utilities for LSP protocol compliance."""

from __future__ import annotations


def utf16_len(text: str) -> int:
    """Count UTF-16 code units needed to encode text."""
    count = 0
    for ch in text:
        code_point = ord(ch)
        count += 2 if code_point > 0xFFFF else 1
    return count


def utf8_col_to_utf16(line: str, col: int) -> int:
    """Convert a 0-based character column to UTF-16 code unit offset."""
    prefix = line[:col]
    return utf16_len(prefix)


def utf16_col_to_utf8(line: str, utf16_col: int) -> int:
    """Convert a UTF-16 code unit offset to 0-based character column."""
    units = 0
    for i, ch in enumerate(line):
        if units >= utf16_col:
            return i
        code_point = ord(ch)
        units += 2 if code_point > 0xFFFF else 1
    return len(line)
