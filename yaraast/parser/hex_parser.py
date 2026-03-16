"""Hex string parser for YARA hex patterns.

This module provides a dedicated parser for YARA hex string content,
extracting logic from the main Parser class for better maintainability.

Copyright (c) Marc Rivero Lopez
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexToken,
    HexWildcard,
)

if TYPE_CHECKING:
    from yaraast.lexer import Token


class HexParseError(Exception):
    """Error during hex string parsing."""

    def __init__(self, message: str, position: int | None = None) -> None:
        if position is not None:
            super().__init__(f"Hex parse error at position {position}: {message}")
        else:
            super().__init__(f"Hex parse error: {message}")
        self.position = position


class HexStringParser:
    """Parser for YARA hex string content.

    Handles parsing of hex strings including:
    - Regular hex bytes (e.g., AB CD EF)
    - Wildcards (??)
    - Nibbles (A? or ?A)
    - Jumps ([n-m])
    - Alternatives ((AB | CD | EF))

    Performance: Uses list builder pattern O(m) instead of string
    concatenation O(m^2) for large hex strings.
    """

    # Character sets for validation
    HEX_CHARS = frozenset("0123456789ABCDEFabcdef")
    WHITESPACE = frozenset(" \t\n\r")

    def __init__(self, error_token: Token | None = None) -> None:
        """Initialize the hex string parser.

        Args:
            error_token: Token to use for error reporting context.
        """
        self.error_token = error_token
        self.content = ""
        self.pos = 0

    def parse(self, hex_content: str) -> list[HexToken]:
        """Parse hex string content into tokens.

        Args:
            hex_content: The raw hex string content (without curly braces).

        Returns:
            List of HexToken objects representing the parsed hex string.
        """
        self.content = self._remove_comments(hex_content)
        self.pos = 0
        tokens: list[HexToken] = []

        while self.pos < len(self.content):
            self._skip_whitespace()

            if self.pos >= len(self.content):
                break

            char = self.content[self.pos]

            if char == "[":
                tokens.append(self._parse_jump())
            elif char == "(":
                tokens.append(self._parse_alternative())
            elif char == "~":
                tokens.append(self._parse_negated_byte())
            elif char == "?":
                tokens.append(self._parse_wildcard())
            elif char in self.HEX_CHARS:
                tokens.append(self._parse_hex_byte())
            else:
                msg = f"Invalid character in hex string: {char}"
                raise HexParseError(msg, self.pos)

        return tokens

    def _remove_comments(self, content: str) -> str:
        """Remove single-line and multi-line comments from hex content.

        Args:
            content: Raw hex string content.

        Returns:
            Content with comments removed.
        """
        cleaned_chars: list[str] = []
        i = 0

        while i < len(content):
            if i < len(content) - 1 and content[i : i + 2] == "//":
                # Skip single-line comment until newline
                while i < len(content) and content[i] != "\n":
                    i += 1
            elif i < len(content) - 1 and content[i : i + 2] == "/*":
                # Skip multi-line comment until */
                i += 2
                while i < len(content):
                    if i < len(content) - 1 and content[i : i + 2] == "*/":
                        i += 2
                        break
                    i += 1
            else:
                cleaned_chars.append(content[i])
                i += 1

        return "".join(cleaned_chars)

    def _skip_whitespace(self) -> None:
        """Skip whitespace characters at current position."""
        while self.pos < len(self.content) and self.content[self.pos] in self.WHITESPACE:
            self.pos += 1

    def _parse_hex_byte(self) -> HexToken:
        """Parse a hex byte or nibble pattern.

        Returns:
            HexByte or HexNibble token.
        """
        char = self.content[self.pos]

        if self.pos + 1 >= len(self.content):
            msg = "Incomplete hex byte"
            raise HexParseError(msg, self.pos)

        next_char = self.content[self.pos + 1]

        if next_char == "?":
            # X? pattern - high nibble
            nibble_val = int(char, 16)
            self.pos += 2
            return HexNibble(high=True, value=nibble_val)

        if next_char in self.HEX_CHARS:
            # Regular hex byte
            byte_val = int(self.content[self.pos : self.pos + 2], 16)
            self.pos += 2
            return HexByte(value=byte_val)

        msg = f"Invalid hex byte at position {self.pos}"
        raise HexParseError(msg, self.pos)

    def _parse_jump(self) -> HexJump:
        """Parse a jump expression [n-m].

        Returns:
            HexJump token.
        """
        self.pos += 1  # Skip '['
        jump_chars: list[str] = []

        while self.pos < len(self.content) and self.content[self.pos] != "]":
            jump_chars.append(self.content[self.pos])
            self.pos += 1

        if self.pos >= len(self.content):
            msg = "Unterminated jump in hex string"
            raise HexParseError(msg, self.pos)

        self.pos += 1  # Skip ']'

        jump_str = "".join(jump_chars).strip()
        return self._parse_jump_range(jump_str)

    def _parse_jump_range(self, jump_str: str) -> HexJump:
        """Parse jump range string into HexJump.

        Args:
            jump_str: The jump range string (e.g., "1-5", "3", "-10").

        Returns:
            HexJump token.
        """
        if "-" in jump_str:
            parts = jump_str.split("-")
            if len(parts) == 2:
                min_jump = int(parts[0]) if parts[0].strip() else None
                max_jump = int(parts[1]) if parts[1].strip() else None
                return HexJump(min_jump=min_jump, max_jump=max_jump)
            msg = "Invalid jump range"
            raise HexParseError(msg, self.pos)

        val = int(jump_str)
        return HexJump(min_jump=val, max_jump=val)

    def _parse_alternative(self) -> HexAlternative:
        """Parse an alternative expression (a|b|c).

        Returns:
            HexAlternative token.
        """
        if self.content[self.pos] != "(":
            msg = "Expected '(' at start of alternative"
            raise HexParseError(msg, self.pos)

        self.pos += 1  # Skip '('
        alternatives: list[list[HexToken]] = []
        current_alt: list[HexToken] = []
        while self.pos < len(self.content):
            self._skip_whitespace()

            if self.pos >= len(self.content):
                break

            char = self.content[self.pos]

            if char == "(":
                # Nested alternative
                nested_alt = self._parse_alternative()
                current_alt.append(nested_alt)
            elif char == ")":
                # End of this alternative group
                if current_alt:
                    alternatives.append(current_alt)
                self.pos += 1
                break
            elif char == "|":
                # Alternative separator
                if current_alt:
                    alternatives.append(current_alt)
                current_alt = []
                self.pos += 1
            elif char == "[":
                current_alt.append(self._parse_jump())
            elif char == "?":
                current_alt.append(self._parse_wildcard())
            elif char in self.HEX_CHARS:
                current_alt.append(self._parse_hex_byte())
            else:
                self.pos += 1

        if not alternatives and current_alt:
            alternatives.append(current_alt)

        return HexAlternative(alternatives=alternatives)

    def _parse_negated_byte(self) -> HexNegatedByte:
        """Parse a negated hex byte ~XX (matches anything except XX)."""
        self.pos += 1  # Skip '~'
        self._skip_whitespace()
        if self.pos + 1 >= len(self.content):
            msg = "Incomplete negated hex byte"
            raise HexParseError(msg, self.pos)
        char1 = self.content[self.pos]
        char2 = self.content[self.pos + 1]
        if char1 in self.HEX_CHARS and char2 in self.HEX_CHARS:
            byte_val = int(self.content[self.pos : self.pos + 2], 16)
            self.pos += 2
            return HexNegatedByte(value=byte_val)
        msg = f"Invalid negated hex byte at position {self.pos}"
        raise HexParseError(msg, self.pos)

    def _parse_wildcard(self) -> HexToken:
        """Parse a wildcard or nibble pattern.

        Returns:
            HexWildcard or HexNibble token.
        """
        if self.pos + 1 < len(self.content) and self.content[self.pos + 1] == "?":
            # Full wildcard ??
            self.pos += 2
            return HexWildcard()

        if self.pos + 1 < len(self.content) and self.content[self.pos + 1] in self.HEX_CHARS:
            # ?X pattern - low nibble
            nibble_val = int(self.content[self.pos + 1], 16)
            self.pos += 2
            return HexNibble(high=False, value=nibble_val)

        msg = f"Invalid wildcard at position {self.pos}"
        raise HexParseError(msg, self.pos)
