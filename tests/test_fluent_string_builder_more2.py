"""Additional real coverage for FluentStringBuilder."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.modifiers import StringModifierType
from yaraast.ast.strings import HexByte, HexNibble, HexString, HexWildcard, RegexString
from yaraast.builder.fluent_string_builder import FluentStringBuilder
from yaraast.builder.hex_string_builder import HexStringBuilder
from yaraast.errors import ValidationError


def test_fluent_string_builder_invalid_hex_inputs_and_trailing_nibble() -> None:
    with pytest.raises(ValidationError, match="Invalid hex byte: GG"):
        FluentStringBuilder("$hex").hex_bytes("GG")

    with pytest.raises(ValidationError, match="Invalid hex byte: 100"):
        FluentStringBuilder("$hex").hex_bytes("100")

    with pytest.raises(ValidationError, match="Invalid hex pattern at offset 2"):
        FluentStringBuilder("$parse")._parse_hex_pattern("AA G")

    with pytest.raises(ValidationError, match="Invalid hex pair: GZ"):
        FluentStringBuilder("$pair")._parse_hex_pair("GZ")


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


def test_fluent_string_builder_rejects_standalone_hex_jump() -> None:
    builder = FluentStringBuilder("$jump").jump_pattern(2, 8)

    with pytest.raises(ValidationError, match="HexJump cannot appear"):
        builder.build()


def test_fluent_string_builder_rejects_invalid_hex_alternatives() -> None:
    with pytest.raises(ValidationError, match="HexAlternative branches must not be empty"):
        FluentStringBuilder("$h").hex_builder(lambda hb: hb.alternative([])).build()

    with pytest.raises(ValidationError, match="Unbounded HexJump"):
        FluentStringBuilder("$h").hex_builder(
            lambda hb: hb.add(0x41)
            .alternative(HexStringBuilder().add(0x42).jump_any().add(0x43))
            .add(0x44),
        ).build()


def test_fluent_string_builder_rejects_invalid_integer_hex_bytes() -> None:
    with pytest.raises(TypeError, match="Invalid type for hex value"):
        FluentStringBuilder("$bool").hex_bytes(True)

    with pytest.raises(ValidationError, match="Byte value must be 0-255"):
        FluentStringBuilder("$large").hex_bytes(256)

    with pytest.raises(ValidationError, match="Byte value must be 0-255"):
        FluentStringBuilder("$negative").hex_bytes(-1)


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


def test_fluent_string_builder_rejects_invalid_wildcard_sequence_counts() -> None:
    with pytest.raises(ValidationError, match="Wildcard count must be positive"):
        FluentStringBuilder("$wild").wildcard_sequence(0)

    with pytest.raises(ValidationError, match="Wildcard count must be positive"):
        FluentStringBuilder("$wild").wildcard_sequence(-1)

    with pytest.raises(TypeError, match="Invalid wildcard count type"):
        FluentStringBuilder("$wild").wildcard_sequence(cast(Any, True))


def test_fluent_string_builder_regex_specific_modifiers() -> None:
    string_def = FluentStringBuilder("$re").regex("abc.*").dotall().multiline().build()

    assert isinstance(string_def, RegexString)
    modifier_types = {modifier.modifier_type for modifier in string_def.modifiers}
    assert StringModifierType.DOTALL in modifier_types
    assert StringModifierType.MULTILINE in modifier_types


def test_fluent_string_builder_rejects_regex_only_modifiers_on_non_regex() -> None:
    with pytest.raises(ValidationError, match="Regex-only modifier"):
        FluentStringBuilder("$plain").dotall().literal("abc").build()

    with pytest.raises(ValidationError, match="Regex-only modifier"):
        FluentStringBuilder("$hex").multiline().hex("41 42").build()


def test_fluent_string_builder_parse_nibble_low_and_non_wildcard_string_path() -> None:
    builder = FluentStringBuilder("$mixed").hex_bytes("4D", "??", "?A", "A?")
    content = builder._content
    assert isinstance(content, list)
    assert isinstance(content[0], HexByte)
    assert isinstance(content[0].value, int)
    assert isinstance(content[1], HexWildcard)
    assert isinstance(content[2], HexNibble)
    assert content[2].high is False
    assert isinstance(content[3], HexNibble)
    assert content[3].high is True

    nibble = FluentStringBuilder("$n")._parse_nibble("?A")
    assert isinstance(nibble, HexNibble)
    assert nibble.high is False
    assert nibble.value == 0xA
