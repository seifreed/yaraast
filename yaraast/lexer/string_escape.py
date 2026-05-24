"""String escape handling for YARA lexer.

Copyright (c) Marc Rivero Lopez
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class EscapeResult:
    """Result of processing an escape sequence."""

    chars: list[str]  # Characters to append to the string value
    advance_count: int  # Extra positions to advance (beyond the escape char itself)
    ends_string: bool  # Whether this escape ends the string (malformed ending)


class StringEscapeHandler:
    """Handles escape sequence processing for YARA string literals.

    This class encapsulates the complex logic for:
    - Standard escape sequences (\\n, \\t, \\r, etc.)
    - Hex escape sequences (\\xHH)
    - Strict rejection of malformed text string escapes
    """

    def __init__(self, text: str, position: int) -> None:
        """Initialize the escape handler.

        Args:
            text: The full source text being lexed.
            position: Current position in the text (at the character AFTER backslash).
        """
        self._text = text
        self._position = position

    def handle_backslash(self, next_char: str | None) -> EscapeResult:
        """Process an escape sequence starting with backslash.

        Args:
            next_char: The character immediately after the backslash.

        Returns:
            EscapeResult with the characters to append and advance count.
        """
        if next_char == "\\":
            return EscapeResult(chars=["\\"], advance_count=0, ends_string=False)

        if next_char == '"':
            return self._handle_escaped_quote()

        if next_char == "n":
            return EscapeResult(chars=["\n"], advance_count=0, ends_string=False)

        if next_char == "r":
            return EscapeResult(chars=["\r"], advance_count=0, ends_string=False)

        if next_char == "t":
            return EscapeResult(chars=["\t"], advance_count=0, ends_string=False)

        if next_char == "x":
            return self._handle_hex_escape()

        if next_char is None:
            msg = "Unterminated escape sequence"
            raise ValueError(msg)

        msg = f"Invalid escape sequence: \\{next_char}"
        raise ValueError(msg)

    def _handle_escaped_quote(self) -> EscapeResult:
        """Handle escaped quote sequence."""
        return EscapeResult(chars=['"'], advance_count=0, ends_string=False)

    def _handle_hex_escape(self) -> EscapeResult:
        """Handle hex escape sequence \\xHH.

        Returns:
            EscapeResult with the decoded character or literal sequence.
        """
        # Position is at 'x', need to look at next 2 chars
        hex_start = self._position + 1
        if hex_start + 2 <= len(self._text):
            hex_digits = self._text[hex_start : hex_start + 2]
            if all(c in "0123456789abcdefABCDEF" for c in hex_digits):
                return EscapeResult(
                    chars=[chr(int(hex_digits, 16))],
                    advance_count=2,  # Skip both hex digits
                    ends_string=False,
                )

        msg = "Invalid hex escape sequence"
        raise ValueError(msg)
