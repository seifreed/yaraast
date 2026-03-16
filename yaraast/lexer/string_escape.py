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
    - Malformed string detection (Windows paths ending with backslash)
    """

    # String modifiers that can follow a quoted string
    STRING_MODIFIERS = (
        "ascii",
        "wide",
        "nocase",
        "fullword",
        "xor",
        "base64",
        "base64wide",
    )

    # Characters that indicate end of string value context
    STRING_ENDING_CHARS = ("\n", "\r")

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
            return EscapeResult(chars=["\\"], advance_count=0, ends_string=False)

        # Any other character after \ is kept literally
        # e.g., \T becomes \T (common in Windows paths)
        return EscapeResult(chars=["\\", next_char], advance_count=0, ends_string=False)

    def _handle_escaped_quote(self) -> EscapeResult:
        """Handle escaped quote sequence.

        Detects malformed strings ending with backslash like "C:\\TEMP\\"
        These appear in real YARA files even though technically invalid.

        Returns:
            EscapeResult indicating whether to treat as escaped quote or string end.
        """
        if self._is_malformed_string_ending():
            # Treat as literal backslash at end of malformed string
            return EscapeResult(chars=["\\"], advance_count=1, ends_string=True)
        # Normal escaped quote in middle of string
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

        # Not valid hex escape, keep as literal
        return EscapeResult(chars=["\\", "x"], advance_count=0, ends_string=False)

    def _is_malformed_string_ending(self) -> bool:
        """Check if this is a malformed string ending with backslash-quote.

        Heuristic: if \\" is followed by ONLY whitespace/modifiers until newline,
        treat the backslash as literal and end the string.

        Returns:
            True if this appears to be a malformed string ending.
        """
        # Position is at the quote character after backslash
        look_ahead_pos = self._position + 1

        if look_ahead_pos >= len(self._text):
            return True  # End of file

        chars_after = self._text[look_ahead_pos : look_ahead_pos + 50]

        # Skip whitespace after the quote
        has_whitespace = False
        i = 0
        while i < len(chars_after) and chars_after[i] in " \t":
            has_whitespace = True
            i += 1

        if i >= len(chars_after):
            return True  # Only whitespace remains

        remaining = chars_after[i:]
        return self._matches_string_ending_pattern(remaining, has_whitespace)

    def _matches_string_ending_pattern(self, remaining: str, has_whitespace: bool) -> bool:
        """Check if remaining text matches a string ending pattern.

        Args:
            remaining: Text after whitespace following the quote.
            has_whitespace: Whether whitespace was found before remaining text.

        Returns:
            True if pattern indicates end of string.
        """
        # Check for newline
        if remaining.startswith(self.STRING_ENDING_CHARS):
            return True

        # Check for comment after whitespace
        if has_whitespace and remaining.startswith("//"):
            return True

        # Check for string modifiers
        return self._starts_with_modifier(remaining)

    def _starts_with_modifier(self, text: str) -> bool:
        """Check if text starts with a YARA string modifier.

        Args:
            text: Text to check.

        Returns:
            True if text starts with a valid modifier.
        """
        for modifier in self.STRING_MODIFIERS:
            # Modifier followed by space, newline, comment, or special chars
            valid_suffixes = (" ", "\n", "\r", "//", "(")
            for suffix in valid_suffixes:
                if text.startswith(modifier + suffix):
                    return True
            # Handle base64wide separately (it's a complete modifier)
            if modifier == "base64wide" and text.startswith("base64wide"):
                return True

        return False
