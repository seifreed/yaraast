"""Property-based tests for HexStringBuilder."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from yaraast.ast.strings import HexByte
from yaraast.builder.hex_string_builder import HexStringBuilder
from yaraast.errors import ValidationError


@pytest.mark.hypothesis
class TestHexBuilderProperties:
    """Property-based tests for hex string builder."""

    @given(byte_val=st.integers(min_value=0, max_value=255))
    @settings(max_examples=50, deadline=5000)
    def test_byte_values_accepted(self, byte_val: int) -> None:
        """All byte values 0-255 are accepted."""
        builder = HexStringBuilder()
        result = builder.byte(byte_val)
        assert result is builder  # fluent API
        tokens = builder.build()
        assert len(tokens) == 1
        assert isinstance(tokens[0], HexByte)
        assert tokens[0].value == byte_val

    @given(byte_val=st.integers(min_value=256, max_value=1000))
    @settings(max_examples=20, deadline=5000)
    def test_invalid_byte_values_rejected(self, byte_val: int) -> None:
        """Byte values > 255 are rejected."""
        builder = HexStringBuilder()
        with pytest.raises(ValidationError, match="Byte value must be 0-255"):
            builder.byte(byte_val)

    @given(
        bytes_list=st.lists(
            st.integers(min_value=0, max_value=255),
            min_size=1,
            max_size=10,
        )
    )
    @settings(max_examples=30, deadline=5000)
    def test_multiple_bytes_preserved(self, bytes_list: list[int]) -> None:
        """Multiple bytes are preserved in order."""
        builder = HexStringBuilder()
        for b in bytes_list:
            builder.byte(b)
        tokens = builder.build()
        assert len(tokens) == len(bytes_list)
        for token, expected in zip(tokens, bytes_list):
            assert isinstance(token, HexByte)
            assert token.value == expected

    @given(hex_str=st.from_regex(r"[0-9A-Fa-f]{2}", fullmatch=True))
    @settings(max_examples=30, deadline=5000)
    def test_hex_string_values_accepted(self, hex_str: str) -> None:
        """Valid 2-char hex strings are accepted."""
        builder = HexStringBuilder()
        builder.add(hex_str)
        tokens = builder.build()
        assert len(tokens) == 1
        assert isinstance(tokens[0], HexByte)
        assert tokens[0].value == int(hex_str, 16)
