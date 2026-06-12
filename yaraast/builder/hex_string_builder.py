"""Fluent builder for hex strings."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from typing import Self

from yaraast.ast.strings import HexAlternative, HexByte, HexJump, HexNibble, HexToken, HexWildcard
from yaraast.errors import ValidationError
from yaraast.limits import LIBYARA_HEX_JUMP_MAX
from yaraast.parser.hex_parser import HexParseError, HexStringParser


class HexStringBuilder:
    """Fluent builder for constructing hex strings."""

    def __init__(self, identifier: str | None = None) -> None:
        self._tokens: list[HexToken] = []
        self.identifier = identifier

    def byte(self, value: int) -> Self:
        """Add a single byte (alias for add)."""
        return self.add(value)

    def _byte_token_from_value(self, value: int | str) -> HexByte:
        if isinstance(value, bool):
            msg = f"Invalid type for hex value: {type(value)}"
            raise TypeError(msg)
        if isinstance(value, int):
            if 0 <= value <= 255:
                return HexByte(value=value)
            msg = f"Byte value must be 0-255, got {value}"
            raise ValidationError(msg)

        hex_val = value.upper().removeprefix("0X")
        if len(hex_val) != 2:
            msg = f"Hex value must be 2 characters, got {value}"
            raise ValidationError(msg)
        try:
            return HexByte(value=int(hex_val, 16))
        except ValueError:
            msg = f"Invalid hex value: {value}"
            raise ValidationError(msg) from None

    def add(self, value: int | str | HexToken) -> Self:
        """Add a hex byte or token."""
        if isinstance(value, int | str):
            self._tokens.append(self._byte_token_from_value(value))
        elif isinstance(value, HexToken):
            validate_structure = getattr(value, "validate_structure", None)
            if callable(validate_structure):
                validate_structure()
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
        if not isinstance(count, int) or isinstance(count, bool):
            msg = f"Invalid wildcard count type: {type(count)}"
            raise TypeError(msg)
        if count <= 0:
            msg = f"Wildcard count must be positive, got {count}"
            raise ValidationError(msg)

        for _ in range(count):
            self._tokens.append(HexWildcard())
        return self

    def nibble(self, value: str) -> Self:
        """Add a nibble pattern like 'F?', '?F', etc."""
        if not isinstance(value, str):
            msg = "Nibble pattern must be a string"
            raise TypeError(msg)
        if len(value) != 2:
            msg = "Nibble must be 2 characters"
            raise ValidationError(msg)

        if value[0] == "?" and value[1] != "?":
            # ?X pattern - low nibble
            try:
                nibble_val = int(value[1], 16)
                self._tokens.append(HexNibble(high=False, value=nibble_val))
            except ValueError:
                msg = f"Invalid nibble pattern: {value}"
                raise ValidationError(msg) from None
        elif value[0] != "?" and value[1] == "?":
            # X? pattern - high nibble
            try:
                nibble_val = int(value[0], 16)
                self._tokens.append(HexNibble(high=True, value=nibble_val))
            except ValueError:
                msg = f"Invalid nibble pattern: {value}"
                raise ValidationError(msg) from None
        else:
            msg = f"Invalid nibble pattern: {value}"
            raise ValidationError(msg)

        return self

    def jump(self, min_jump: int | None = None, max_jump: int | None = None) -> Self:
        """Add a jump [n-m]."""
        self._validate_jump_bounds(min_jump, max_jump)
        self._tokens.append(HexJump(min_jump=min_jump, max_jump=max_jump))
        return self

    def jump_exact(self, count: int) -> Self:
        """Add an exact jump [n]."""
        return self.jump(count, count)

    def jump_varying(self, min_val: int, max_val: int) -> Self:
        """Add a varying jump [min-max]."""
        return self.jump(min_val, max_val)

    def jump_up_to(self, max_val: int) -> Self:
        """Add a jump up to max [0-max]."""
        return self.jump(None, max_val)

    def jump_at_least(self, min_val: int) -> Self:
        """Add a jump at least min [min-]."""
        return self.jump(min_val, None)

    def jump_any(self) -> Self:
        """Add an unlimited jump [-]."""
        return self.jump(None, None)

    def alternative(self, *alternatives: list[int | str] | HexStringBuilder) -> Self:
        """Add an alternative group (a|b|c)."""
        if not alternatives:
            msg = "HexAlternative must contain at least one branch"
            raise ValidationError(msg)

        alt_tokens: list[list[HexToken]] = []

        for alt in alternatives:
            if isinstance(alt, list):
                # List of values
                tokens: list[HexToken] = []
                for val in alt:
                    if isinstance(val, bool):
                        msg = f"Invalid alternative value type: {type(val)}"
                        raise TypeError(msg)
                    if isinstance(val, int | str):
                        tokens.append(self._byte_token_from_value(val))
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
            if not alt_tokens[-1]:
                msg = "HexAlternative branches must not be empty"
                raise ValidationError(msg)

        self._tokens.append(HexAlternative(alternatives=alt_tokens))
        return self

    def group(self, builder_func: Callable[[HexStringBuilder], None]) -> Self:
        """Add a group using a builder function."""
        if not callable(builder_func):
            msg = "Hex group builder callback must be callable"
            raise TypeError(msg)
        inner_builder = HexStringBuilder()
        builder_func(inner_builder)
        self._tokens.extend(inner_builder.build())
        return self

    def pattern(self, pattern: str) -> Self:
        """Add tokens from a pattern string like 'FF ?? [2-4] (AA|BB)'."""
        if not isinstance(pattern, str):
            msg = "Hex pattern must be a string"
            raise TypeError(msg)
        try:
            self._tokens.extend(HexStringParser().parse(pattern, validate_placement=False))
        except HexParseError as exc:
            raise ValidationError(self._pattern_error_message(pattern, exc)) from exc

        return self

    def _pattern_error_message(self, pattern: str, error: HexParseError) -> str:
        part = self._pattern_part_at(pattern, error.position)
        if not part:
            return str(error)
        if len(part) == 2:
            return f"Invalid hex value: {part}"
        return f"Invalid pattern part: {part}"

    @staticmethod
    def _pattern_part_at(pattern: str, position: int | None) -> str:
        if position is None or position < 0 or position >= len(pattern):
            return ""
        start = position
        while start > 0 and not pattern[start - 1].isspace():
            start -= 1
        end = position
        while end < len(pattern) and not pattern[end].isspace():
            end += 1
        return pattern[start:end]

    def _validate_jump_bounds(self, min_jump: int | None, max_jump: int | None) -> None:
        """Validate jump bounds."""
        self._validate_jump_bound_type("minimum", min_jump)
        self._validate_jump_bound_type("maximum", max_jump)
        if min_jump is not None and min_jump < 0:
            msg = f"Jump minimum must be non-negative, got {min_jump}"
            raise ValidationError(msg)
        if max_jump is not None and max_jump < 0:
            msg = f"Jump maximum must be non-negative, got {max_jump}"
            raise ValidationError(msg)
        if min_jump is not None and min_jump > LIBYARA_HEX_JUMP_MAX:
            msg = f"Jump minimum must not exceed {LIBYARA_HEX_JUMP_MAX}"
            raise ValidationError(msg)
        if max_jump is not None and max_jump > LIBYARA_HEX_JUMP_MAX:
            msg = f"Jump maximum must not exceed {LIBYARA_HEX_JUMP_MAX}"
            raise ValidationError(msg)
        if min_jump is not None and max_jump is not None and min_jump > max_jump:
            msg = f"Jump minimum {min_jump} cannot exceed maximum {max_jump}"
            raise ValidationError(msg)

    def _validate_jump_bound_type(self, name: str, value: int | None) -> None:
        if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
            msg = f"Invalid jump bound type for {name}: {type(value)}"
            raise TypeError(msg)

    def build(self) -> list[HexToken]:
        """Build the list of hex tokens."""
        return deepcopy(self._tokens)

    @staticmethod
    def from_bytes(data: bytes) -> HexStringBuilder:
        """Create builder from raw bytes."""
        if not isinstance(data, bytes):
            msg = "Raw byte data must be bytes"
            raise TypeError(msg)
        builder = HexStringBuilder()
        for byte in data:
            builder.add(byte)
        return builder

    @staticmethod
    def from_hex_string(hex_str: str) -> HexStringBuilder:
        """Create builder from hex string."""
        if not isinstance(hex_str, str):
            msg = "Hex string must be a string"
            raise TypeError(msg)
        builder = HexStringBuilder()
        hex_str = "".join(hex_str.split()).upper()
        if len(hex_str) % 2 != 0:
            msg = f"Invalid trailing hex byte: {hex_str[-1]}"
            raise ValidationError(msg)

        for i in range(0, len(hex_str), 2):
            if i + 1 < len(hex_str):
                builder.add(hex_str[i : i + 2])

        return builder
