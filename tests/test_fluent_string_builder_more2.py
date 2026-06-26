"""Additional real coverage for FluentStringBuilder."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexString,
    HexWildcard,
)
from yaraast.builder.fluent_string_builder import FluentStringBuilder
from yaraast.errors import ValidationError
from yaraast.limits import LIBYARA_HEX_JUMP_MAX


def test_fluent_string_builder_invalid_hex_inputs_and_trailing_nibble() -> None:
    with pytest.raises(TypeError, match="Hex pattern must be a string"):
        FluentStringBuilder("$hex").hex(cast(Any, True))

    with pytest.raises(
        ValidationError,
        match="Hex parse error at position 3: Invalid character in hex string: G",
    ):
        FluentStringBuilder("$parse")._parse_hex_pattern("AA G")


def test_fluent_string_builder_rejects_non_string_text_and_regex_content() -> None:
    with pytest.raises(TypeError, match="Plain string content must be a string"):
        FluentStringBuilder("$plain").literal(cast(Any, True))

    with pytest.raises(TypeError, match="Plain string content must be a string"):
        FluentStringBuilder("$text").text(cast(Any, 123))

    with pytest.raises(TypeError, match="Regex pattern must be a string"):
        FluentStringBuilder("$regex").regex(cast(Any, 123))


def test_fluent_string_builder_hex_build_returns_token_snapshot() -> None:
    builder = FluentStringBuilder("$hex").hex("41")

    first = builder.build()
    assert isinstance(first, HexString)
    first.tokens.append(HexByte(0x42))
    second = builder.build()

    assert isinstance(second, HexString)
    assert len(second.tokens) == 1
    assert isinstance(second.tokens[0], HexByte)
    assert second.tokens[0].value == 0x41


def test_fluent_string_builder_hex_uses_full_hex_parser() -> None:
    string_def = (
        FluentStringBuilder("$hex").hex("4D A? ?F [2-4] (~00 | 41) // comment\n 5A").build()
    )

    assert isinstance(string_def, HexString)
    tokens = string_def.tokens
    assert isinstance(tokens[0], HexByte)
    assert tokens[0].value == 0x4D
    assert isinstance(tokens[1], HexNibble)
    assert tokens[1].high is True
    assert tokens[1].value == 0xA
    assert isinstance(tokens[2], HexNibble)
    assert tokens[2].high is False
    assert tokens[2].value == 0xF
    assert isinstance(tokens[3], HexJump)
    assert tokens[3].min_jump == 2
    assert tokens[3].max_jump == 4
    assert isinstance(tokens[4], HexAlternative)
    assert isinstance(tokens[4].alternatives[0][0], HexNegatedByte)
    assert tokens[4].alternatives[0][0].value == 0x00
    assert isinstance(tokens[4].alternatives[1][0], HexByte)
    assert tokens[4].alternatives[1][0].value == 0x41
    assert isinstance(tokens[5], HexByte)
    assert tokens[5].value == 0x5A


def test_fluent_string_builder_rejects_standalone_hex_jump() -> None:
    builder = FluentStringBuilder("$jump").jump_pattern(2, 8)

    with pytest.raises(ValidationError, match="HexJump cannot appear"):
        builder.build()


def test_fluent_string_builder_rejects_invalid_integer_hex_bytes() -> None:
    with pytest.raises(ValidationError, match="Hex parse error"):
        FluentStringBuilder("$large").hex("100")


def test_fluent_string_builder_rejects_boolean_xor_keys() -> None:
    with pytest.raises(TypeError, match="Invalid XOR key value"):
        FluentStringBuilder("$xor").literal("abc").xor(True)

    with pytest.raises(ValidationError, match="XOR key must be 0-255"):
        FluentStringBuilder("$xor").literal("abc").xor(256)

    with pytest.raises(ValidationError, match="XOR key must be 0-255"):
        FluentStringBuilder("$xor").literal("abc").xor(-1)

    with pytest.raises(TypeError, match="Invalid XOR key value"):
        FluentStringBuilder("$xor").literal("abc").xor_range(False, 255)

    with pytest.raises(ValidationError, match="XOR key range must be 0-255"):
        FluentStringBuilder("$xor").literal("abc").xor_range(-1, 255)

    with pytest.raises(ValidationError, match="XOR key range must be 0-255"):
        FluentStringBuilder("$xor").literal("abc").xor_range(0, 256)

    with pytest.raises(ValidationError, match="XOR range must be ascending"):
        FluentStringBuilder("$xor").literal("abc").xor_range(5, 1)


def test_fluent_string_builder_replaces_existing_xor_modifier() -> None:
    string_def = FluentStringBuilder("$xor").literal("abc").xor().xor_range(1, 2).xor(3).build()

    assert [(modifier.name, modifier.value) for modifier in string_def.modifiers] == [("xor", 3)]


def test_fluent_string_builder_rejects_invalid_wildcard_sequence_counts() -> None:
    with pytest.raises(ValidationError, match="Wildcard count must be positive"):
        FluentStringBuilder("$wild").wildcard_sequence(0)

    with pytest.raises(ValidationError, match="Wildcard count must be positive"):
        FluentStringBuilder("$wild").wildcard_sequence(-1)

    with pytest.raises(TypeError, match="Invalid wildcard count type"):
        FluentStringBuilder("$wild").wildcard_sequence(cast(Any, True))


def test_fluent_string_builder_rejects_invalid_jump_pattern_bounds() -> None:
    with pytest.raises(TypeError, match="Invalid jump bound type"):
        FluentStringBuilder("$jump").jump_pattern(cast(Any, True), 4)

    with pytest.raises(ValidationError, match="Jump minimum must be non-negative"):
        FluentStringBuilder("$jump").jump_pattern(-1, 4)

    with pytest.raises(ValidationError, match="Jump minimum 5 cannot exceed maximum 4"):
        FluentStringBuilder("$jump").jump_pattern(5, 4)

    with pytest.raises(ValidationError, match="Jump maximum must not exceed"):
        FluentStringBuilder("$jump").jump_pattern(1, LIBYARA_HEX_JUMP_MAX + 1)


def test_fluent_string_builder_rejects_invalid_type_specific_modifiers() -> None:
    with pytest.raises(ValidationError, match="cannot be used with hex string"):
        FluentStringBuilder("$hex").hex("41").ascii().build()

    with pytest.raises(ValidationError, match="cannot be used with hex string"):
        FluentStringBuilder("$hex").hex("41").xor().build()

    with pytest.raises(ValidationError, match="cannot be used with regex string"):
        FluentStringBuilder("$regex").regex("abc").base64().build()

    with pytest.raises(ValidationError, match="cannot be used with regex string"):
        FluentStringBuilder("$regex").regex("abc").xor(1).build()


def test_fluent_string_builder_parse_hex_pattern_with_nibbles() -> None:
    builder = FluentStringBuilder("$mixed").hex("4D ?? ?A A?")
    content = builder._content
    assert isinstance(content, list)
    assert isinstance(content[0], HexByte)
    assert isinstance(content[0].value, int)
    assert isinstance(content[1], HexWildcard)
    assert isinstance(content[2], HexNibble)
    assert content[2].high is False
    assert isinstance(content[3], HexNibble)
    assert content[3].high is True
