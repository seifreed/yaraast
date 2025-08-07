"""String matching engine for YARA evaluation."""

from __future__ import annotations

import re
from dataclasses import dataclass

from yaraast.ast.strings import HexString, PlainString, RegexString


@dataclass
class MatchResult:
    """Result of a string match."""

    identifier: str
    offset: int
    length: int
    matched_data: bytes

    def __repr__(self) -> str:
        return f"MatchResult({self.identifier} at {self.offset}, {self.length} bytes)"


class StringMatcher:
    """Match YARA strings against byte data."""

    def __init__(self) -> None:
        self.matches: dict[str, list[MatchResult]] = {}
        self._cache: dict[str, any] = {}

    def match_all(self, *args) -> dict[str, list[MatchResult]]:
        """Match all strings against data.

        Can be called as:
        - match_all(strings, data)  # Original order from tests
        - match_all(data, strings)  # New order
        """
        if len(args) == 2:
            # Determine order based on type
            if isinstance(args[0], bytes):
                data, strings = args[0], args[1]
            else:
                strings, data = args[0], args[1]
        else:
            msg = "match_all requires exactly 2 arguments"
            raise ValueError(msg)

        self.matches.clear()

        for string_def in strings:
            if isinstance(string_def, PlainString):
                self._match_plain_string(data, string_def)
            elif isinstance(string_def, HexString):
                self._match_hex_string(data, string_def)
            elif isinstance(string_def, RegexString):
                self._match_regex_string(data, string_def)

        return self.matches

    def match_string(self, string_def, data):
        """Match a single string against data."""
        matches = []

        if isinstance(string_def, PlainString):
            self._match_plain_string(data, string_def)
            matches = self.matches.get(string_def.identifier, [])
        elif isinstance(string_def, HexString):
            self._match_hex_string(data, string_def)
            matches = self.matches.get(string_def.identifier, [])
        elif isinstance(string_def, RegexString):
            self._match_regex_string(data, string_def)
            matches = self.matches.get(string_def.identifier, [])

        return matches

    def _match_plain_string(self, data: bytes, string_def: PlainString) -> None:
        """Match plain string against data."""
        matches = []
        pattern = string_def.value.encode("utf-8")

        # Apply modifiers
        nocase = any(m.name == "nocase" for m in string_def.modifiers)
        wide = any(m.name == "wide" for m in string_def.modifiers)
        ascii_mod = any(m.name == "ascii" for m in string_def.modifiers)
        fullword = any(m.name == "fullword" for m in string_def.modifiers)

        patterns_to_check = []

        # ASCII version
        if not wide or ascii_mod:
            patterns_to_check.append(pattern)

        # Wide version (UTF-16LE)
        if wide:
            wide_pattern = b""
            for byte in pattern:
                wide_pattern += bytes([byte, 0])
            patterns_to_check.append(wide_pattern)

        # Search for each pattern
        for search_pattern in patterns_to_check:
            if nocase:
                # Case-insensitive search
                matches.extend(self._find_all_nocase(data, search_pattern))
            else:
                # Case-sensitive search
                matches.extend(self._find_all(data, search_pattern))

        # Apply fullword modifier
        if fullword:
            matches = [m for m in matches if self._is_fullword(data, m[0], m[1])]

        # Store results
        self.matches[string_def.identifier] = [
            MatchResult(
                string_def.identifier,
                offset,
                length,
                data[offset : offset + length],
            )
            for offset, length in matches
        ]

    def _match_hex_string(self, data: bytes, string_def: HexString) -> None:
        """Match hex string against data."""
        # Build pattern from hex tokens
        pattern_bytes = []
        wildcards = []

        for _i, token in enumerate(string_def.tokens):
            if hasattr(token, "value"):
                # Hex byte
                if isinstance(token.value, str):
                    pattern_bytes.append(int(token.value, 16))
                else:
                    pattern_bytes.append(token.value)
                wildcards.append(False)
            else:
                # Wildcard
                pattern_bytes.append(0)  # Placeholder
                wildcards.append(True)

        # Search for pattern
        matches = self._find_hex_pattern(data, pattern_bytes, wildcards)

        # Store results
        self.matches[string_def.identifier] = [
            MatchResult(
                string_def.identifier,
                offset,
                len(pattern_bytes),
                data[offset : offset + len(pattern_bytes)],
            )
            for offset in matches
        ]

    def _match_regex_string(self, data: bytes, string_def: RegexString) -> None:
        """Match regex string against data."""
        # Prepare regex pattern
        pattern = string_def.regex
        flags = 0

        # Check modifiers
        for modifier in string_def.modifiers:
            if modifier.name == "nocase":
                flags |= re.IGNORECASE
            elif modifier.name == "dotall":
                flags |= re.DOTALL

        # Compile regex
        try:
            regex = re.compile(pattern.encode("utf-8"), flags)
        except (ValueError, TypeError, AttributeError):
            # Invalid regex, no matches
            self.matches[string_def.identifier] = []
            return

        # Find all matches
        matches = []
        for match in regex.finditer(data):
            matches.append(
                MatchResult(
                    string_def.identifier,
                    match.start(),
                    match.end() - match.start(),
                    match.group(0),
                ),
            )

        self.matches[string_def.identifier] = matches

    def _find_all(self, data: bytes, pattern: bytes) -> list[tuple[int, int]]:
        """Find all occurrences of pattern in data."""
        matches = []
        start = 0
        pattern_len = len(pattern)

        while True:
            pos = data.find(pattern, start)
            if pos == -1:
                break
            matches.append((pos, pattern_len))
            start = pos + 1

        return matches

    def _find_all_nocase(self, data: bytes, pattern: bytes) -> list[tuple[int, int]]:
        """Find all occurrences of pattern in data (case-insensitive)."""
        matches = []
        data_lower = data.lower()
        pattern_lower = pattern.lower()
        pattern_len = len(pattern)
        start = 0

        while True:
            pos = data_lower.find(pattern_lower, start)
            if pos == -1:
                break
            matches.append((pos, pattern_len))
            start = pos + 1

        return matches

    def _find_hex_pattern(
        self,
        data: bytes,
        pattern: list[int],
        wildcards: list[bool],
    ) -> list[int]:
        """Find hex pattern with wildcards."""
        matches = []
        data_len = len(data)
        pattern_len = len(pattern)

        if pattern_len == 0 or pattern_len > data_len:
            return matches

        for i in range(data_len - pattern_len + 1):
            match = True
            for j in range(pattern_len):
                if not wildcards[j] and data[i + j] != pattern[j]:
                    match = False
                    break
            if match:
                matches.append(i)

        return matches

    def _is_fullword(self, data: bytes, offset: int, length: int) -> bool:
        """Check if match is a full word."""
        # Check character before
        if offset > 0:
            prev_char = data[offset - 1]
            if prev_char.isalnum() or prev_char == ord("_"):
                return False

        # Check character after
        end = offset + length
        if end < len(data):
            next_char = data[end]
            if next_char.isalnum() or next_char == ord("_"):
                return False

        return True

    def get_match_count(self, identifier: str) -> int:
        """Get number of matches for a string."""
        return len(self.matches.get(identifier, []))

    def get_match_offset(self, identifier: str, index: int = 0) -> int | None:
        """Get offset of a specific match."""
        matches = self.matches.get(identifier, [])
        if 0 <= index < len(matches):
            return matches[index].offset
        return None

    def get_match_length(self, identifier: str, index: int = 0) -> int | None:
        """Get length of a specific match."""
        matches = self.matches.get(identifier, [])
        if 0 <= index < len(matches):
            return matches[index].length
        return None

    def string_at(self, identifier: str, offset: int) -> bool:
        """Check if string matches at specific offset."""
        matches = self.matches.get(identifier, [])
        return any(m.offset == offset for m in matches)

    def string_in(self, identifier: str, start: int, end: int) -> bool:
        """Check if string matches within range."""
        matches = self.matches.get(identifier, [])
        return any(start <= m.offset < end for m in matches)
