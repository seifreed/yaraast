"""Tests for HexStringBuilder fluent API.

Copyright (c) 2025 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.
"""

from __future__ import annotations

import pytest

from yaraast.ast.strings import HexAlternative, HexByte, HexJump, HexNibble, HexWildcard
from yaraast.builder.hex_string_builder import HexStringBuilder
from yaraast.errors import ValidationError


class TestHexStringBuilderBasicOperations:
    """Test basic hex string builder operations."""

    def test_builder_initialization_without_identifier(self) -> None:
        """Builder should initialize with empty token list."""
        builder = HexStringBuilder()

        tokens = builder.build()

        assert tokens == []
        assert builder.identifier is None

    def test_builder_initialization_with_identifier(self) -> None:
        """Builder should store identifier when provided."""
        builder = HexStringBuilder(identifier="$test")

        assert builder.identifier == "$test"
        assert builder.build() == []

    def test_add_single_byte_as_integer(self) -> None:
        """Add method should accept integer byte values."""
        builder = HexStringBuilder()

        builder.add(0xFF)
        tokens = builder.build()

        assert len(tokens) == 1
        assert isinstance(tokens[0], HexByte)
        assert tokens[0].value == 0xFF

    def test_add_multiple_bytes_fluent_api(self) -> None:
        """Fluent API should allow chaining add calls."""
        builder = HexStringBuilder()

        builder.add(0x4D).add(0x5A).add(0x90)
        tokens = builder.build()

        assert len(tokens) == 3
        assert all(isinstance(t, HexByte) for t in tokens)
        assert tokens[0].value == 0x4D
        assert tokens[1].value == 0x5A
        assert tokens[2].value == 0x90

    def test_byte_alias_method(self) -> None:
        """Byte method should work as alias for add."""
        builder = HexStringBuilder()

        builder.byte(0xAB)
        tokens = builder.build()

        assert len(tokens) == 1
        assert isinstance(tokens[0], HexByte)
        assert tokens[0].value == 0xAB

    def test_add_bytes_with_multiple_values(self) -> None:
        """Add_bytes should accept multiple byte values."""
        builder = HexStringBuilder()

        builder.add_bytes(0x48, 0x65, 0x6C, 0x6C, 0x6F)
        tokens = builder.build()

        assert len(tokens) == 5
        expected_values = [0x48, 0x65, 0x6C, 0x6C, 0x6F]
        for i, expected in enumerate(expected_values):
            assert isinstance(tokens[i], HexByte)
            assert tokens[i].value == expected


class TestHexStringBuilderHexStringInput:
    """Test hex string input handling."""

    def test_add_hex_string_two_character(self) -> None:
        """Add should accept two-character hex strings."""
        builder = HexStringBuilder()

        builder.add("FF")
        tokens = builder.build()

        assert len(tokens) == 1
        assert isinstance(tokens[0], HexByte)
        assert tokens[0].value == 0xFF

    def test_add_hex_string_with_0x_prefix(self) -> None:
        """Add should handle hex strings with 0x prefix."""
        builder = HexStringBuilder()

        builder.add("0xAB")
        tokens = builder.build()

        assert len(tokens) == 1
        assert isinstance(tokens[0], HexByte)
        assert tokens[0].value == 0xAB

    def test_add_hex_string_lowercase(self) -> None:
        """Add should handle lowercase hex strings."""
        builder = HexStringBuilder()

        builder.add("ab")
        tokens = builder.build()

        assert len(tokens) == 1
        assert isinstance(tokens[0], HexByte)
        assert tokens[0].value == 0xAB

    def test_add_bytes_with_hex_strings(self) -> None:
        """Add_bytes should accept hex string values."""
        builder = HexStringBuilder()

        builder.add_bytes("4D", "5A", "90")
        tokens = builder.build()

        assert len(tokens) == 3
        assert tokens[0].value == 0x4D
        assert tokens[1].value == 0x5A
        assert tokens[2].value == 0x90

    def test_add_mixed_int_and_hex_strings(self) -> None:
        """Add_bytes should accept mixed integer and hex string values."""
        builder = HexStringBuilder()

        builder.add_bytes(0x4D, "5A", 0x90, "0xFF")
        tokens = builder.build()

        assert len(tokens) == 4
        assert tokens[0].value == 0x4D
        assert tokens[1].value == 0x5A
        assert tokens[2].value == 0x90
        assert tokens[3].value == 0xFF


class TestHexStringBuilderErrorHandling:
    """Test error handling for invalid inputs."""

    def test_add_byte_value_too_large(self) -> None:
        """Add should reject byte values greater than 255."""
        builder = HexStringBuilder()

        with pytest.raises(ValidationError, match="Byte value must be 0-255"):
            builder.add(256)

    def test_add_byte_value_negative(self) -> None:
        """Add should reject negative byte values."""
        builder = HexStringBuilder()

        with pytest.raises(ValidationError, match="Byte value must be 0-255"):
            builder.add(-1)

    def test_add_hex_string_wrong_length(self) -> None:
        """Add should reject hex strings not exactly 2 characters."""
        builder = HexStringBuilder()

        with pytest.raises(ValidationError, match="Hex value must be 2 characters"):
            builder.add("ABC")

    def test_add_hex_string_invalid_characters(self) -> None:
        """Add should reject hex strings with invalid characters."""
        builder = HexStringBuilder()

        with pytest.raises(ValidationError, match="Invalid hex value"):
            builder.add("XY")

    def test_add_invalid_type(self) -> None:
        """Add should reject invalid types."""
        builder = HexStringBuilder()

        with pytest.raises(TypeError, match="Invalid type for hex value"):
            builder.add([0xFF])  # type: ignore


class TestHexStringBuilderWildcards:
    """Test wildcard token generation."""

    def test_add_single_wildcard(self) -> None:
        """Wildcard method should add single wildcard token."""
        builder = HexStringBuilder()

        builder.wildcard()
        tokens = builder.build()

        assert len(tokens) == 1
        assert isinstance(tokens[0], HexWildcard)

    def test_add_multiple_wildcards(self) -> None:
        """Wildcard method should add multiple wildcard tokens."""
        builder = HexStringBuilder()

        builder.wildcard(3)
        tokens = builder.build()

        assert len(tokens) == 3
        assert all(isinstance(t, HexWildcard) for t in tokens)

    def test_wildcards_in_sequence(self) -> None:
        """Wildcards should work in sequence with bytes."""
        builder = HexStringBuilder()

        builder.add(0x48).wildcard(2).add(0x6F)
        tokens = builder.build()

        assert len(tokens) == 4
        assert isinstance(tokens[0], HexByte)
        assert isinstance(tokens[1], HexWildcard)
        assert isinstance(tokens[2], HexWildcard)
        assert isinstance(tokens[3], HexByte)


class TestHexStringBuilderNibbles:
    """Test nibble pattern handling."""

    def test_add_high_nibble_pattern(self) -> None:
        """Nibble should handle high nibble pattern (X?)."""
        builder = HexStringBuilder()

        builder.nibble("F?")
        tokens = builder.build()

        assert len(tokens) == 1
        assert isinstance(tokens[0], HexNibble)
        assert tokens[0].high is True
        assert tokens[0].value == 0xF

    def test_add_low_nibble_pattern(self) -> None:
        """Nibble should handle low nibble pattern (?X)."""
        builder = HexStringBuilder()

        builder.nibble("?A")
        tokens = builder.build()

        assert len(tokens) == 1
        assert isinstance(tokens[0], HexNibble)
        assert tokens[0].high is False
        assert tokens[0].value == 0xA

    def test_add_multiple_nibble_patterns(self) -> None:
        """Multiple nibble patterns should work in sequence."""
        builder = HexStringBuilder()

        builder.nibble("4?").nibble("?B")
        tokens = builder.build()

        assert len(tokens) == 2
        assert tokens[0].high is True
        assert tokens[0].value == 4
        assert tokens[1].high is False
        assert tokens[1].value == 0xB

    def test_nibble_with_lowercase_hex(self) -> None:
        """Nibble should handle lowercase hex digits."""
        builder = HexStringBuilder()

        builder.nibble("a?")
        tokens = builder.build()

        assert len(tokens) == 1
        assert tokens[0].value == 0xA

    def test_nibble_pattern_wrong_length(self) -> None:
        """Nibble should reject patterns not exactly 2 characters."""
        builder = HexStringBuilder()

        with pytest.raises(ValidationError, match="Nibble must be 2 characters"):
            builder.nibble("F")

    def test_nibble_pattern_double_wildcard(self) -> None:
        """Nibble should reject double wildcard pattern."""
        builder = HexStringBuilder()

        with pytest.raises(ValidationError, match="Invalid nibble pattern"):
            builder.nibble("??")

    def test_nibble_pattern_no_wildcard(self) -> None:
        """Nibble should reject patterns without wildcards."""
        builder = HexStringBuilder()

        with pytest.raises(ValidationError, match="Invalid nibble pattern"):
            builder.nibble("FF")

    def test_nibble_pattern_invalid_hex_digit(self) -> None:
        """Nibble should reject invalid hex digits."""
        builder = HexStringBuilder()

        with pytest.raises(ValidationError, match="Invalid nibble pattern"):
            builder.nibble("G?")


class TestHexStringBuilderJumps:
    """Test jump token generation."""

    def test_add_exact_jump(self) -> None:
        """Jump_exact should add jump with same min and max."""
        builder = HexStringBuilder()

        builder.jump_exact(5)
        tokens = builder.build()

        assert len(tokens) == 1
        assert isinstance(tokens[0], HexJump)
        assert tokens[0].min_jump == 5
        assert tokens[0].max_jump == 5

    def test_add_varying_jump(self) -> None:
        """Jump_varying should add jump with min-max range."""
        builder = HexStringBuilder()

        builder.jump_varying(2, 6)
        tokens = builder.build()

        assert len(tokens) == 1
        assert isinstance(tokens[0], HexJump)
        assert tokens[0].min_jump == 2
        assert tokens[0].max_jump == 6

    def test_add_jump_up_to(self) -> None:
        """Jump_up_to should add jump with None min."""
        builder = HexStringBuilder()

        builder.jump_up_to(10)
        tokens = builder.build()

        assert len(tokens) == 1
        assert isinstance(tokens[0], HexJump)
        assert tokens[0].min_jump is None
        assert tokens[0].max_jump == 10

    def test_add_jump_at_least(self) -> None:
        """Jump_at_least should add jump with None max."""
        builder = HexStringBuilder()

        builder.jump_at_least(3)
        tokens = builder.build()

        assert len(tokens) == 1
        assert isinstance(tokens[0], HexJump)
        assert tokens[0].min_jump == 3
        assert tokens[0].max_jump is None

    def test_add_jump_any(self) -> None:
        """Jump_any should add unlimited jump."""
        builder = HexStringBuilder()

        builder.jump_any()
        tokens = builder.build()

        assert len(tokens) == 1
        assert isinstance(tokens[0], HexJump)
        assert tokens[0].min_jump is None
        assert tokens[0].max_jump is None

    def test_add_jump_generic(self) -> None:
        """Generic jump method should work with min/max."""
        builder = HexStringBuilder()

        builder.jump(4, 8)
        tokens = builder.build()

        assert len(tokens) == 1
        assert tokens[0].min_jump == 4
        assert tokens[0].max_jump == 8

    def test_jumps_in_pattern(self) -> None:
        """Jumps should work within byte patterns."""
        builder = HexStringBuilder()

        builder.add(0x4D).add(0x5A).jump_exact(100).add(0x50).add(0x45)
        tokens = builder.build()

        assert len(tokens) == 5
        assert isinstance(tokens[0], HexByte)
        assert isinstance(tokens[1], HexByte)
        assert isinstance(tokens[2], HexJump)
        assert isinstance(tokens[3], HexByte)
        assert isinstance(tokens[4], HexByte)


class TestHexStringBuilderAlternatives:
    """Test alternative group handling."""

    def test_add_alternative_with_integer_lists(self) -> None:
        """Alternative should accept lists of integers."""
        builder = HexStringBuilder()

        builder.alternative([0xAA, 0xBB], [0xCC, 0xDD])
        tokens = builder.build()

        assert len(tokens) == 1
        assert isinstance(tokens[0], HexAlternative)
        assert len(tokens[0].alternatives) == 2

        # First alternative: AA BB
        alt1 = tokens[0].alternatives[0]
        assert len(alt1) == 2
        assert isinstance(alt1[0], HexByte)
        assert alt1[0].value == 0xAA
        assert isinstance(alt1[1], HexByte)
        assert alt1[1].value == 0xBB

        # Second alternative: CC DD
        alt2 = tokens[0].alternatives[1]
        assert len(alt2) == 2
        assert alt2[0].value == 0xCC
        assert alt2[1].value == 0xDD

    def test_add_alternative_with_hex_string_lists(self) -> None:
        """Alternative should accept lists of hex strings."""
        builder = HexStringBuilder()

        builder.alternative(["4D", "5A"], ["50", "45"])
        tokens = builder.build()

        assert len(tokens) == 1
        alt = tokens[0]
        assert isinstance(alt, HexAlternative)

        # First alternative: 4D 5A
        assert alt.alternatives[0][0].value == 0x4D
        assert alt.alternatives[0][1].value == 0x5A

        # Second alternative: 50 45
        assert alt.alternatives[1][0].value == 0x50
        assert alt.alternatives[1][1].value == 0x45

    def test_add_alternative_with_nested_builder(self) -> None:
        """Alternative should accept HexStringBuilder instances."""
        builder = HexStringBuilder()

        nested1 = HexStringBuilder().add(0xAA).add(0xBB)
        nested2 = HexStringBuilder().add(0xCC).add(0xDD)

        builder.alternative(nested1, nested2)
        tokens = builder.build()

        assert len(tokens) == 1
        alt = tokens[0]
        assert isinstance(alt, HexAlternative)
        assert len(alt.alternatives) == 2

    def test_alternative_with_mixed_types(self) -> None:
        """Alternative should accept mixed list and builder types."""
        builder = HexStringBuilder()

        nested = HexStringBuilder().add(0xFF)
        builder.alternative([0xAA, 0xBB], nested)
        tokens = builder.build()

        assert len(tokens) == 1
        assert isinstance(tokens[0], HexAlternative)
        assert len(tokens[0].alternatives) == 2

    def test_alternative_invalid_type(self) -> None:
        """Alternative should reject invalid alternative types."""
        builder = HexStringBuilder()

        with pytest.raises(TypeError, match="Invalid alternative type"):
            builder.alternative(0xFF)  # type: ignore

    def test_alternative_invalid_value_in_list(self) -> None:
        """Alternative should reject invalid values in lists."""
        builder = HexStringBuilder()

        with pytest.raises(TypeError, match="Invalid alternative value type"):
            builder.alternative([[0xFF, [0xAA]]])  # type: ignore


class TestHexStringBuilderGrouping:
    """Test group functionality."""

    def test_add_group_with_builder_function(self) -> None:
        """Group should execute builder function and add tokens."""
        builder = HexStringBuilder()

        def build_group(inner: HexStringBuilder) -> None:
            inner.add(0xAA).add(0xBB).wildcard()

        builder.add(0xFF).group(build_group).add(0xCC)
        tokens = builder.build()

        assert len(tokens) == 5
        assert isinstance(tokens[0], HexByte)
        assert tokens[0].value == 0xFF
        assert isinstance(tokens[1], HexByte)
        assert tokens[1].value == 0xAA
        assert isinstance(tokens[2], HexByte)
        assert tokens[2].value == 0xBB
        assert isinstance(tokens[3], HexWildcard)
        assert isinstance(tokens[4], HexByte)
        assert tokens[4].value == 0xCC

    def test_add_nested_groups(self) -> None:
        """Groups should support nesting."""
        builder = HexStringBuilder()

        def outer_group(outer: HexStringBuilder) -> None:
            outer.add(0xAA)

            def inner_group(inner: HexStringBuilder) -> None:
                inner.add(0xBB)

            outer.group(inner_group)
            outer.add(0xCC)

        builder.group(outer_group)
        tokens = builder.build()

        assert len(tokens) == 3
        assert tokens[0].value == 0xAA
        assert tokens[1].value == 0xBB
        assert tokens[2].value == 0xCC


class TestHexStringBuilderPattern:
    """Test pattern string parsing."""

    def test_pattern_with_simple_bytes(self) -> None:
        """Pattern should parse simple hex bytes."""
        builder = HexStringBuilder()

        builder.pattern("FF AA BB")
        tokens = builder.build()

        assert len(tokens) == 3
        assert tokens[0].value == 0xFF
        assert tokens[1].value == 0xAA
        assert tokens[2].value == 0xBB

    def test_pattern_with_wildcards(self) -> None:
        """Pattern should parse wildcard tokens."""
        builder = HexStringBuilder()

        builder.pattern("FF ?? AA")
        tokens = builder.build()

        assert len(tokens) == 3
        assert isinstance(tokens[0], HexByte)
        assert isinstance(tokens[1], HexWildcard)
        assert isinstance(tokens[2], HexByte)

    def test_pattern_with_nibbles(self) -> None:
        """Pattern should parse nibble patterns."""
        builder = HexStringBuilder()

        builder.pattern("4? ?A")
        tokens = builder.build()

        assert len(tokens) == 2
        assert isinstance(tokens[0], HexNibble)
        assert tokens[0].high is True
        assert isinstance(tokens[1], HexNibble)
        assert tokens[1].high is False

    def test_pattern_with_exact_jump(self) -> None:
        """Pattern should parse exact jump notation."""
        builder = HexStringBuilder()

        builder.pattern("FF [5] AA")
        tokens = builder.build()

        assert len(tokens) == 3
        assert isinstance(tokens[0], HexByte)
        assert isinstance(tokens[1], HexJump)
        assert tokens[1].min_jump == 5
        assert tokens[1].max_jump == 5
        assert isinstance(tokens[2], HexByte)

    def test_pattern_with_range_jump(self) -> None:
        """Pattern should parse range jump notation."""
        builder = HexStringBuilder()

        builder.pattern("4D 5A [0-100] 50 45")
        tokens = builder.build()

        assert len(tokens) == 5
        assert isinstance(tokens[2], HexJump)
        assert tokens[2].min_jump == 0
        assert tokens[2].max_jump == 100

    def test_pattern_with_open_ended_jumps(self) -> None:
        """Pattern should parse open-ended jump ranges."""
        builder = HexStringBuilder()

        builder.pattern("[4-] [-8]")
        tokens = builder.build()

        assert len(tokens) == 2
        # [4-]
        assert isinstance(tokens[0], HexJump)
        assert tokens[0].min_jump == 4
        assert tokens[0].max_jump is None
        # [-8]
        assert isinstance(tokens[1], HexJump)
        assert tokens[1].min_jump is None
        assert tokens[1].max_jump == 8

    def test_pattern_complex_mixed(self) -> None:
        """Pattern should handle complex mixed tokens."""
        builder = HexStringBuilder()

        builder.pattern("4D 5A ?? [2-4] 4? 50")
        tokens = builder.build()

        assert len(tokens) == 6
        assert isinstance(tokens[0], HexByte)
        assert tokens[0].value == 0x4D
        assert isinstance(tokens[1], HexByte)
        assert tokens[1].value == 0x5A
        assert isinstance(tokens[2], HexWildcard)
        assert isinstance(tokens[3], HexJump)
        assert tokens[3].min_jump == 2
        assert tokens[3].max_jump == 4
        assert isinstance(tokens[4], HexNibble)
        assert tokens[4].high is True
        assert tokens[4].value == 4
        assert isinstance(tokens[5], HexByte)
        assert tokens[5].value == 0x50


class TestHexStringBuilderStaticMethods:
    """Test static factory methods."""

    def test_from_bytes_creates_builder(self) -> None:
        """From_bytes should create builder from byte data."""
        data = b"Hello"

        builder = HexStringBuilder.from_bytes(data)
        tokens = builder.build()

        assert len(tokens) == 5
        expected_values = [0x48, 0x65, 0x6C, 0x6C, 0x6F]
        for i, expected in enumerate(expected_values):
            assert isinstance(tokens[i], HexByte)
            assert tokens[i].value == expected

    def test_from_bytes_empty(self) -> None:
        """From_bytes should handle empty byte data."""
        builder = HexStringBuilder.from_bytes(b"")
        tokens = builder.build()

        assert tokens == []

    def test_from_hex_string_creates_builder(self) -> None:
        """From_hex_string should create builder from hex string."""
        hex_str = "48656C6C6F"

        builder = HexStringBuilder.from_hex_string(hex_str)
        tokens = builder.build()

        assert len(tokens) == 5
        expected_values = [0x48, 0x65, 0x6C, 0x6C, 0x6F]
        for i, expected in enumerate(expected_values):
            assert tokens[i].value == expected

    def test_from_hex_string_with_spaces(self) -> None:
        """From_hex_string should handle spaces in input."""
        hex_str = "48 65 6C 6C 6F"

        builder = HexStringBuilder.from_hex_string(hex_str)
        tokens = builder.build()

        assert len(tokens) == 5
        assert tokens[0].value == 0x48
        assert tokens[4].value == 0x6F

    def test_from_hex_string_lowercase(self) -> None:
        """From_hex_string should handle lowercase hex."""
        hex_str = "deadbeef"

        builder = HexStringBuilder.from_hex_string(hex_str)
        tokens = builder.build()

        assert len(tokens) == 4
        assert tokens[0].value == 0xDE
        assert tokens[1].value == 0xAD
        assert tokens[2].value == 0xBE
        assert tokens[3].value == 0xEF

    def test_from_hex_string_odd_length(self) -> None:
        """From_hex_string should handle odd-length strings."""
        hex_str = "ABC"

        builder = HexStringBuilder.from_hex_string(hex_str)
        tokens = builder.build()

        # Should only process AB, skipping incomplete C
        assert len(tokens) == 1
        assert tokens[0].value == 0xAB


class TestHexStringBuilderComplexScenarios:
    """Test complex real-world scenarios."""

    def test_mz_pe_header_detection_pattern(self) -> None:
        """Build MZ/PE header detection pattern."""
        builder = HexStringBuilder(identifier="$pe_header")

        builder.add_bytes(0x4D, 0x5A)  # MZ
        builder.jump_varying(0, 100)  # Variable offset
        builder.add_bytes(0x50, 0x45)  # PE
        builder.add_bytes(0x00, 0x00)  # Null bytes

        tokens = builder.build()

        assert len(tokens) == 7
        assert builder.identifier == "$pe_header"
        assert tokens[0].value == 0x4D
        assert tokens[1].value == 0x5A
        assert isinstance(tokens[2], HexJump)
        assert tokens[3].value == 0x50
        assert tokens[4].value == 0x45

    def test_shellcode_pattern_with_wildcards(self) -> None:
        """Build shellcode detection pattern with wildcards."""
        builder = HexStringBuilder()

        builder.add(0x48).nibble("8?").wildcard(2)
        builder.jump_exact(4)
        builder.add_bytes(0xFF, 0xD0)

        tokens = builder.build()

        assert len(tokens) == 7
        assert isinstance(tokens[0], HexByte)
        assert isinstance(tokens[1], HexNibble)
        assert isinstance(tokens[2], HexWildcard)
        assert isinstance(tokens[3], HexWildcard)
        assert isinstance(tokens[4], HexJump)
        assert isinstance(tokens[5], HexByte)
        assert isinstance(tokens[6], HexByte)

    def test_fluent_api_complete_chain(self) -> None:
        """Test complete fluent API chain."""
        tokens = (
            HexStringBuilder(identifier="$complex")
            .add(0x4D)
            .add(0x5A)
            .jump_varying(0, 100)
            .pattern("50 45 00 00")
            .nibble("4?")
            .wildcard(2)
            .jump_at_least(2)
            .add_bytes(0xFF, 0xD0)
            .build()
        )

        assert len(tokens) > 0
        assert isinstance(tokens[0], HexByte)
        assert tokens[0].value == 0x4D

    def test_build_multiple_times_returns_same_tokens(self) -> None:
        """Build should return same token list on multiple calls."""
        builder = HexStringBuilder()
        builder.add_bytes(0x48, 0x65, 0x6C, 0x6C, 0x6F)

        tokens1 = builder.build()
        tokens2 = builder.build()

        assert tokens1 is tokens2  # Same object reference
        assert len(tokens1) == len(tokens2)

    def test_builder_reuse_after_build(self) -> None:
        """Builder should allow adding more tokens after build."""
        builder = HexStringBuilder()
        builder.add(0xFF)

        tokens1 = builder.build()
        assert len(tokens1) == 1

        builder.add(0xAA)
        tokens2 = builder.build()

        assert len(tokens2) == 2
        assert tokens2[0].value == 0xFF
        assert tokens2[1].value == 0xAA

    def test_add_hex_token_directly(self) -> None:
        """Add should accept HexToken instances directly."""
        builder = HexStringBuilder()

        byte_token = HexByte(value=0xFF)
        wildcard_token = HexWildcard()
        jump_token = HexJump(min_jump=2, max_jump=4)

        builder.add(byte_token).add(wildcard_token).add(jump_token)
        tokens = builder.build()

        assert len(tokens) == 3
        assert tokens[0] is byte_token
        assert tokens[1] is wildcard_token
        assert tokens[2] is jump_token

    def test_comprehensive_hex_pattern_from_real_malware_analysis(self) -> None:
        """Build comprehensive pattern from realistic malware analysis."""
        builder = HexStringBuilder(identifier="$malware_signature")

        # Entry point stub
        builder.add_bytes(0x55, 0x8B, 0xEC)  # push ebp; mov ebp, esp
        builder.wildcard(1)

        # String decryption loop
        builder.pattern("8B ?? ?? [2-4]")
        builder.nibble("F?").add(0x07)

        # Jump to payload
        builder.jump_varying(10, 50)
        builder.add_bytes(0xFF, 0x25)

        tokens = builder.build()

        assert builder.identifier == "$malware_signature"
        assert len(tokens) > 10

        # Verify first three bytes
        assert tokens[0].value == 0x55
        assert tokens[1].value == 0x8B
        assert tokens[2].value == 0xEC

        # Verify wildcard present
        assert any(isinstance(t, HexWildcard) for t in tokens)

        # Verify jump present
        jump_tokens = [t for t in tokens if isinstance(t, HexJump)]
        assert len(jump_tokens) >= 2
