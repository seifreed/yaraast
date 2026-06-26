"""Fluent builder for hex strings."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from typing import Self

from yaraast.ast.strings import HexAlternative, HexByte, HexJump, HexNibble, HexToken, HexWildcard
from yaraast.errors import ValidationError
from yaraast.limits import LIBYARA_HEX_JUMP_MAX


class HexStringBuilder:
    """Fluent builder for constructing hex strings."""

    def __init__(self, identifier: str | None = None) -> None:
        self._tokens: list[HexToken] = []
        self.identifier = identifier

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
