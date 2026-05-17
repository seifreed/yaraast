"""String matching engine for YARA evaluation."""

from __future__ import annotations

import base64
from collections.abc import Iterable
from dataclasses import dataclass
import re
from typing import Any, overload

from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
)
from yaraast.errors import EvaluationError


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
        self._cache: dict[str, Any] = {}

    @overload
    def match_all(
        self,
        strings: Iterable[object],
        data: bytes,
    ) -> dict[str, list[MatchResult]]: ...

    @overload
    def match_all(
        self,
        data: bytes,
        strings: Iterable[object],
    ) -> dict[str, list[MatchResult]]: ...

    @overload
    def match_all(self, *args: object) -> dict[str, list[MatchResult]]: ...

    def match_all(self, *args: object) -> dict[str, list[MatchResult]]:
        """Match all strings against data.

        Can be called as:
        - match_all(strings, data)  # Original order from tests
        - match_all(data, strings)  # New order
        """
        if len(args) == 2:
            # Determine order based on type
            if isinstance(args[0], bytes):
                data = args[0]
                strings = args[1]
            else:
                strings = args[0]
                data = args[1]
        else:
            msg = "match_all requires exactly 2 arguments"
            raise EvaluationError(msg)

        if not isinstance(data, bytes):
            msg = "match_all data argument must be bytes"
            raise EvaluationError(msg)
        if not isinstance(strings, Iterable):
            msg = "match_all strings argument must be iterable"
            raise EvaluationError(msg)

        self.matches.clear()

        for string_def in strings:
            if isinstance(string_def, PlainString):
                self._match_plain_string(data, string_def)
            elif isinstance(string_def, HexString):
                self._match_hex_string(data, string_def)
            elif isinstance(string_def, RegexString):
                self._match_regex_string(data, string_def)

        return self.matches

    def match_string(self, string_def: object, data: bytes) -> list[MatchResult]:
        """Match a single string against data."""
        matches: list[MatchResult] = []
        self.matches.clear()

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
        matches: list[tuple[int, int, bool]] = []
        pattern = (
            string_def.value
            if isinstance(string_def.value, bytes)
            else string_def.value.encode("utf-8")
        )

        # Apply modifiers
        modifier_names = {self._modifier_name(modifier) for modifier in string_def.modifiers}
        nocase = "nocase" in modifier_names
        wide = "wide" in modifier_names
        ascii_mod = "ascii" in modifier_names
        fullword = "fullword" in modifier_names
        base64_mod = "base64" in modifier_names
        base64wide_mod = "base64wide" in modifier_names

        raw_patterns: list[tuple[bytes, bool]] = []

        # ASCII version
        if not wide or ascii_mod:
            raw_patterns.append((pattern, False))

        # Wide version (UTF-16LE)
        wide_pattern = b""
        if wide:
            for byte in pattern:
                wide_pattern += bytes([byte, 0])
            raw_patterns.append((wide_pattern, True))

        if base64_mod or base64wide_mod:
            patterns_to_check: list[tuple[bytes, bool]] = []
            for raw_pattern, _is_wide in raw_patterns:
                if base64_mod:
                    patterns_to_check.extend(
                        (base64_pattern, False)
                        for base64_pattern in self._base64_patterns(
                            raw_pattern,
                            string_def.modifiers,
                            "base64",
                        )
                    )
                if base64wide_mod:
                    patterns_to_check.extend(
                        (base64_pattern, True)
                        for base64_pattern in self._base64_patterns(
                            raw_pattern,
                            string_def.modifiers,
                            "base64wide",
                            wide_output=True,
                        )
                    )
        else:
            patterns_to_check = raw_patterns

        xor_keys = self._xor_keys(string_def.modifiers)
        if xor_keys is not None:
            patterns_to_check = [
                (bytes(byte ^ key for byte in search_pattern), is_wide)
                for search_pattern, is_wide in patterns_to_check
                for key in xor_keys
            ]

        # Search for each pattern
        for search_pattern, is_wide in patterns_to_check:
            if nocase:
                # Case-insensitive search
                matches.extend(
                    (offset, length, is_wide)
                    for offset, length in self._find_all_nocase(data, search_pattern)
                )
            else:
                # Case-sensitive search
                matches.extend(
                    (offset, length, is_wide)
                    for offset, length in self._find_all(data, search_pattern)
                )

        # Apply fullword modifier
        if fullword:
            matches = [
                match
                for match in matches
                if self._is_fullword(data, match[0], match[1], wide=match[2])
            ]
        matches = self._deduplicate_plain_matches(matches)

        # Store results
        self.matches[string_def.identifier] = [
            MatchResult(
                string_def.identifier,
                offset,
                length,
                data[offset : offset + length],
            )
            for offset, length, _is_wide in matches
        ]

    def _deduplicate_plain_matches(
        self,
        matches: list[tuple[int, int, bool]],
    ) -> list[tuple[int, int, bool]]:
        by_offset: dict[int, tuple[int, int, bool]] = {}
        for match in matches:
            offset, length, _is_wide = match
            existing = by_offset.get(offset)
            if existing is None or length < existing[1]:
                by_offset[offset] = match
        return [by_offset[offset] for offset in sorted(by_offset)]

    def _modifier_name(self, modifier: Any) -> str:
        return str(getattr(modifier, "name", modifier))

    def _modifier_value(self, modifier: Any) -> Any:
        return getattr(modifier, "value", None)

    def _xor_keys(self, modifiers: list[Any]) -> list[int] | None:
        keys: list[int] = []
        has_xor = False
        for modifier in modifiers:
            if self._modifier_name(modifier) != "xor":
                continue
            has_xor = True
            value = self._modifier_value(modifier)
            if value is None:
                keys.extend(range(0, 256))
            elif isinstance(value, tuple | list) and len(value) == 2:
                low = self._parse_xor_key(value[0])
                high = self._parse_xor_key(value[1])
                keys.extend(range(low, high + 1))
            elif isinstance(value, str) and "-" in value:
                low_text, high_text = value.split("-", maxsplit=1)
                low = self._parse_xor_key(low_text)
                high = self._parse_xor_key(high_text)
                keys.extend(range(low, high + 1))
            else:
                keys.append(self._parse_xor_key(value))

        if not has_xor:
            return None
        return sorted({key for key in keys if 0 <= key <= 255})

    def _parse_xor_key(self, value: Any) -> int:
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            text = value.strip()
            if text.lower().startswith("0x"):
                return int(text, 16)
            if any(char in "abcdefABCDEF" for char in text):
                return int(text, 16)
            return int(text, 10)
        return int(value)

    def _base64_patterns(
        self,
        pattern: bytes,
        modifiers: list[Any],
        modifier_name: str,
        *,
        wide_output: bool = False,
    ) -> list[bytes]:
        patterns: list[bytes] = []
        seen: set[bytes] = set()
        for modifier in modifiers:
            if self._modifier_name(modifier) != modifier_name:
                continue
            alphabet = self._modifier_value(modifier)
            for prefix_len in range(3):
                encoded = base64.b64encode((b"\x00" * prefix_len) + pattern)
                encoded = self._translate_base64_alphabet(encoded, alphabet)
                encoded = self._trim_base64_alignment(encoded, prefix_len, len(pattern))
                if wide_output:
                    encoded = b"".join(bytes([byte, 0]) for byte in encoded)
                if not encoded or encoded in seen:
                    continue
                seen.add(encoded)
                patterns.append(encoded)
        return patterns

    def _translate_base64_alphabet(self, encoded: bytes, alphabet: Any) -> bytes:
        if not isinstance(alphabet, str) or len(alphabet) != 64:
            return encoded
        standard = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        return encoded.translate(bytes.maketrans(standard, alphabet.encode("ascii")))

    def _trim_base64_alignment(self, encoded: bytes, prefix_len: int, pattern_len: int) -> bytes:
        start_trim_by_prefix = (0, 2, 3)
        end_trim_by_remainder = (0, 3, 2)
        start = start_trim_by_prefix[prefix_len]
        end_trim = end_trim_by_remainder[(prefix_len + pattern_len) % 3]
        if end_trim:
            return encoded[start:-end_trim]
        return encoded[start:]

    def _match_hex_string(self, data: bytes, string_def: HexString) -> None:
        """Match hex string against data."""
        matches = self._find_hex_token_pattern(data, string_def.tokens)
        self.matches[string_def.identifier] = [
            MatchResult(
                string_def.identifier,
                offset,
                length,
                data[offset : offset + length],
            )
            for offset, length in matches
        ]

    def _find_hex_token_pattern(
        self,
        data: bytes,
        tokens: list[Any],
    ) -> list[tuple[int, int]]:
        """Find a hex token pattern with jumps, alternatives, nibbles, and negation."""
        if not tokens:
            return []

        matches: list[tuple[int, int]] = []
        seen: set[tuple[int, int]] = set()
        for start in range(len(data)):
            for end in self._match_hex_tokens_from(data, tokens, start):
                match = (start, end - start)
                if match not in seen:
                    seen.add(match)
                    matches.append(match)
        return matches

    def _match_hex_tokens_from(
        self,
        data: bytes,
        tokens: list[Any],
        start: int,
    ) -> list[int]:
        positions = [start]
        for token in tokens:
            next_positions: list[int] = []
            for pos in positions:
                next_positions.extend(self._match_hex_token(data, token, pos))
            if not next_positions:
                return []
            positions = sorted(set(next_positions))
        return positions

    def _match_hex_token(self, data: bytes, token: Any, pos: int) -> list[int]:
        if isinstance(token, HexByte):
            return (
                [pos + 1] if pos < len(data) and data[pos] == self._hex_value(token.value) else []
            )
        if isinstance(token, HexWildcard):
            return [pos + 1] if pos < len(data) else []
        if isinstance(token, HexNibble):
            return self._match_hex_nibble(data, token, pos)
        if isinstance(token, HexNegatedByte):
            value = self._hex_value(token.value)
            return [pos + 1] if pos < len(data) and data[pos] != value else []
        if isinstance(token, HexJump):
            return self._match_hex_jump(data, token, pos)
        if isinstance(token, HexAlternative):
            return self._match_hex_alternative(data, token, pos)
        if isinstance(token, HexToken):
            return [pos + 1] if pos < len(data) else []
        return []

    def _match_hex_nibble(self, data: bytes, token: HexNibble, pos: int) -> list[int]:
        if pos >= len(data):
            return []
        value = self._hex_value(token.value)
        byte = data[pos]
        if token.high:
            return [pos + 1] if byte >> 4 == value else []
        return [pos + 1] if byte & 0x0F == value else []

    def _match_hex_jump(self, data: bytes, token: HexJump, pos: int) -> list[int]:
        min_jump = token.min_jump if token.min_jump is not None else 0
        max_jump = token.max_jump if token.max_jump is not None else len(data) - pos
        max_jump = min(max_jump, len(data) - pos)
        if min_jump > max_jump:
            return []
        return [pos + size for size in range(min_jump, max_jump + 1)]

    def _match_hex_alternative(
        self,
        data: bytes,
        token: HexAlternative,
        pos: int,
    ) -> list[int]:
        positions: list[int] = []
        for alternative in token.alternatives:
            alt_tokens = self._hex_alternative_tokens(alternative)
            positions.extend(self._match_hex_tokens_from(data, alt_tokens, pos))
        return positions

    def _hex_alternative_tokens(self, alternative: Any) -> list[Any]:
        if isinstance(alternative, list):
            return [self._coerce_hex_token(token) for token in alternative]
        return [self._coerce_hex_token(alternative)]

    def _coerce_hex_token(self, token: Any) -> Any:
        if isinstance(token, int | str):
            return HexByte(token)
        return token

    def _hex_value(self, value: int | str) -> int:
        if isinstance(value, str):
            return int(value, 16)
        return value

    def _match_regex_string(self, data: bytes, string_def: RegexString) -> None:
        """Match regex string against data."""
        # Prepare regex pattern
        pattern = string_def.regex
        flags = 0

        # Check modifiers
        for modifier in string_def.modifiers:
            modifier_name = self._modifier_name(modifier)
            if modifier_name in {"nocase", "i"}:
                flags |= re.IGNORECASE
            elif modifier_name in {"dotall", "s"}:
                flags |= re.DOTALL
            elif modifier_name in {"multiline", "m"}:
                flags |= re.MULTILINE

        modifier_names = {self._modifier_name(modifier) for modifier in string_def.modifiers}
        wide = "wide" in modifier_names
        ascii_mod = "ascii" in modifier_names
        fullword = "fullword" in modifier_names

        # Compile regex
        try:
            regex = re.compile(pattern.encode("utf-8"), flags)
        except (re.error, ValueError, TypeError, AttributeError):
            # Invalid regex, no matches
            self.matches[string_def.identifier] = []
            return

        # YARA reports overlapping regex matches, unlike Python's finditer().
        raw_matches: list[tuple[int, int, bool]] = []
        if not wide or ascii_mod:
            raw_matches.extend(
                (match.start(), match.end() - match.start(), False)
                for match in self._find_overlapping_regex_matches(regex, data)
            )
        if wide:
            raw_matches.extend(self._find_overlapping_wide_regex_matches(regex, data))
            raw_matches.extend(self._find_wide_zero_length_regex_matches(regex, data))

        if fullword:
            raw_matches = [
                match
                for match in raw_matches
                if self._is_fullword(data, match[0], match[1], wide=match[2])
            ]
        raw_matches = self._deduplicate_regex_matches(raw_matches)

        self.matches[string_def.identifier] = [
            MatchResult(
                string_def.identifier,
                offset,
                length,
                data[offset : offset + length],
            )
            for offset, length, _is_wide in raw_matches
        ]

    def _find_overlapping_regex_matches(
        self,
        regex: re.Pattern[bytes],
        data: bytes,
    ) -> list[re.Match[bytes]]:
        matches = []
        for offset in range(len(data)):
            match = regex.match(data, offset)
            if match is None:
                continue
            matches.append(match)
        return matches

    def _find_overlapping_wide_regex_matches(
        self,
        regex: re.Pattern[bytes],
        data: bytes,
    ) -> list[tuple[int, int, bool]]:
        matches: list[tuple[int, int, bool]] = []
        for segment, offsets in self._wide_regex_segments(data):
            for match in self._find_overlapping_regex_matches(regex, segment):
                start = match.start()
                length = match.end() - start
                matches.append((offsets[start], length * 2, True))
        return matches

    def _find_wide_zero_length_regex_matches(
        self,
        regex: re.Pattern[bytes],
        data: bytes,
    ) -> list[tuple[int, int, bool]]:
        empty_match = regex.match(b"")
        if empty_match is None or empty_match.end() != empty_match.start():
            return []

        matches: list[tuple[int, int, bool]] = []
        for offset in range(len(data)):
            match = regex.match(data, offset)
            if match is not None:
                matches.append((offset, 0, False))
        return matches

    def _deduplicate_regex_matches(
        self,
        matches: list[tuple[int, int, bool]],
    ) -> list[tuple[int, int, bool]]:
        by_offset: dict[int, tuple[int, int, bool]] = {}
        for match in matches:
            offset, length, _is_wide = match
            existing = by_offset.get(offset)
            if (
                existing is None
                or existing[1] == 0 < length
                or (length != 0 and length < existing[1])
            ):
                by_offset[offset] = match
        return [by_offset[offset] for offset in sorted(by_offset)]

    def _wide_regex_segments(self, data: bytes) -> list[tuple[bytes, list[int]]]:
        segments: list[tuple[bytes, list[int]]] = []
        for parity in (0, 1):
            segment = bytearray()
            offsets: list[int] = []
            for pos in range(parity, max(len(data) - 1, 0), 2):
                if data[pos + 1] == 0:
                    segment.append(data[pos])
                    offsets.append(pos)
                    continue
                if segment:
                    segments.append((bytes(segment), offsets))
                    segment = bytearray()
                    offsets = []
            if segment:
                segments.append((bytes(segment), offsets))
        return segments

    def _find_all(self, data: bytes, pattern: bytes) -> list[tuple[int, int]]:
        """Find all occurrences of pattern in data."""
        matches: list[tuple[int, int]] = []
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
        matches: list[tuple[int, int]] = []
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

    def _is_fullword(self, data: bytes, offset: int, length: int, *, wide: bool = False) -> bool:
        """Check if match is a full word."""

        def _is_word_byte(value: int) -> bool:
            return (48 <= value <= 57) or (65 <= value <= 90) or (97 <= value <= 122)

        if wide:
            return self._is_fullword_wide(data, offset, length, _is_word_byte)

        # Check character before
        if offset > 0:
            prev_char = data[offset - 1]
            if _is_word_byte(prev_char):
                return False

        # Check character after
        end = offset + length
        if end < len(data):
            next_char = data[end]
            if _is_word_byte(next_char):
                return False

        return True

    def _is_fullword_wide(self, data: bytes, offset: int, length: int, is_word_byte) -> bool:
        if offset >= 2 and data[offset - 1] == 0 and is_word_byte(data[offset - 2]):
            return False

        end = offset + length
        return not (end + 1 < len(data) and data[end + 1] == 0 and is_word_byte(data[end]))

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
