"""Fluent builder for hex strings."""

from __future__ import annotations

import builtins
import contextlib
from typing import Self

from yaraast.ast.strings import HexAlternative, HexByte, HexJump, HexNibble, HexToken, HexWildcard


class HexStringBuilder:
    """Fluent builder for constructing hex strings."""

    def __init__(self, identifier: str | None = None) -> None:
        self._tokens: list[HexToken] = []
        self.identifier = identifier

    def byte(self, value: int) -> Self:
        """Add a single byte (alias for add)."""
        return self.add(value)

    def add(self, value: int | str | HexToken) -> Self:
        """Add a hex byte or token."""
        if isinstance(value, int):
            if 0 <= value <= 255:
                self._tokens.append(HexByte(value=value))
            else:
                msg = f"Byte value must be 0-255, got {value}"
                raise ValueError(msg)
        elif isinstance(value, str):
            # Parse hex string
            hex_val = value.upper().replace("0X", "")
            if len(hex_val) == 2:
                try:
                    byte_val = int(hex_val, 16)
                    self._tokens.append(HexByte(value=byte_val))
                except ValueError:
                    msg = f"Invalid hex value: {value}"
                    raise ValueError(msg) from None
            else:
                msg = f"Hex value must be 2 characters, got {value}"
                raise ValueError(msg)
        elif isinstance(value, HexToken):
            self._tokens.append(value)
        else:
            msg = f"Invalid type for hex value: {type(value)}"
            raise TypeError(msg)

        return self

    def add_bytes(self, *values: int | str) -> Self:
        """Add multiple hex bytes."""
        for value in values:
            self.add(value)
        return self

    def wildcard(self, count: int = 1) -> Self:
        """Add wildcard bytes (??)."""
        for _ in range(count):
            self._tokens.append(HexWildcard())
        return self

    def nibble(self, value: str) -> Self:
        """Add a nibble pattern like 'F?', '?F', etc."""
        if len(value) != 2:
            msg = "Nibble must be 2 characters"
            raise ValueError(msg)

        if value[0] == "?" and value[1] != "?":
            # ?X pattern - low nibble
            try:
                nibble_val = int(value[1], 16)
                self._tokens.append(HexNibble(high=False, value=nibble_val))
            except ValueError:
                msg = f"Invalid nibble pattern: {value}"
                raise ValueError(msg) from None
        elif value[0] != "?" and value[1] == "?":
            # X? pattern - high nibble
            try:
                nibble_val = int(value[0], 16)
                self._tokens.append(HexNibble(high=True, value=nibble_val))
            except ValueError:
                msg = f"Invalid nibble pattern: {value}"
                raise ValueError(msg) from None
        else:
            msg = f"Invalid nibble pattern: {value}"
            raise ValueError(msg)

        return self

    def jump(self, min_jump: int | None = None, max_jump: int | None = None) -> Self:
        """Add a jump [n-m]."""
        self._tokens.append(HexJump(min_jump=min_jump, max_jump=max_jump))
        return self

    def jump_exact(self, count: int) -> Self:
        """Add an exact jump [n]."""
        return self.jump(count, count)

    def jump_varying(self, min_val: int, max_val: int) -> Self:
        """Add a varying jump [min-max]."""
        return self.jump(min_val, max_val)

    def jump_up_to(self, max_val: int) -> Self:
        """Add a jump up to max [-max]."""
        return self.jump(None, max_val)

    def jump_at_least(self, min_val: int) -> Self:
        """Add a jump at least min [min-]."""
        return self.jump(min_val, None)

    def jump_any(self) -> Self:
        """Add an unlimited jump [-]."""
        return self.jump(None, None)

    def alternative(self, *alternatives: list[int | str | HexStringBuilder]) -> Self:
        """Add an alternative group (a|b|c)."""
        alt_tokens = []

        for alt in alternatives:
            if isinstance(alt, list):
                # List of values
                tokens = []
                for val in alt:
                    if isinstance(val, int):
                        tokens.append(HexByte(value=val))
                    elif isinstance(val, str):
                        byte_val = int(val, 16)
                        tokens.append(HexByte(value=byte_val))
                    else:
                        msg = f"Invalid alternative value type: {type(val)}"
                        raise TypeError(msg)
                alt_tokens.append(tokens)
            elif isinstance(alt, HexStringBuilder):
                # Nested builder
                alt_tokens.append(alt.build())
            else:
                msg = f"Invalid alternative type: {type(alt)}"
                raise TypeError(msg)

        self._tokens.append(HexAlternative(alternatives=alt_tokens))
        return self

    def group(self, builder_func) -> Self:
        """Add a group using a builder function."""
        inner_builder = HexStringBuilder()
        builder_func(inner_builder)
        self._tokens.extend(inner_builder.build())
        return self

    def pattern(self, pattern: str) -> Self:
        """Add tokens from a pattern string like 'FF ?? [2-4] (AA|BB)'."""
        # This is a simplified parser - in production would need full parser
        parts = pattern.split()

        for part in parts:
            self._process_pattern_part(part)

        return self

    def _process_pattern_part(self, part: str) -> None:
        """Process a single pattern part."""
        if part == "??":
            self.wildcard()
        elif self._is_jump_pattern(part):
            self._process_jump_pattern(part)
        elif self._is_nibble_pattern(part):
            self.nibble(part)
        elif self._is_hex_byte(part):
            self._add_hex_byte_safely(part)

    def _is_jump_pattern(self, part: str) -> bool:
        """Check if part is a jump pattern like [2-4]."""
        return part.startswith("[") and part.endswith("]")

    def _is_nibble_pattern(self, part: str) -> bool:
        """Check if part is a nibble pattern like A?."""
        return len(part) == 2 and "?" in part

    def _is_hex_byte(self, part: str) -> bool:
        """Check if part is a regular hex byte."""
        return len(part) == 2

    def _process_jump_pattern(self, part: str) -> None:
        """Process jump pattern like [2-4]."""
        jump_str = part[1:-1]
        if "-" in jump_str:
            parts = jump_str.split("-")
            min_j = int(parts[0]) if parts[0] else None
            max_j = int(parts[1]) if parts[1] else None
            self.jump(min_j, max_j)
        else:
            self.jump_exact(int(jump_str))

    def _add_hex_byte_safely(self, part: str) -> None:
        """Add hex byte with error suppression."""
        with contextlib.suppress(builtins.BaseException):
            self.add(part)

    def build(self) -> list[HexToken]:
        """Build the list of hex tokens."""
        return self._tokens

    @staticmethod
    def from_bytes(data: bytes) -> HexStringBuilder:
        """Create builder from raw bytes."""
        builder = HexStringBuilder()
        for byte in data:
            builder.add(byte)
        return builder

    @staticmethod
    def from_hex_string(hex_str: str) -> HexStringBuilder:
        """Create builder from hex string."""
        builder = HexStringBuilder()
        hex_str = hex_str.replace(" ", "").upper()

        for i in range(0, len(hex_str), 2):
            if i + 1 < len(hex_str):
                builder.add(hex_str[i : i + 2])

        return builder
