"""Additional real coverage for FluentStringBuilder."""

from __future__ import annotations

import pytest

from yaraast.ast.modifiers import StringModifierType
from yaraast.ast.strings import HexByte, HexNibble, HexWildcard, RegexString
from yaraast.builder.fluent_string_builder import FluentStringBuilder
from yaraast.errors import ValidationError


def test_fluent_string_builder_invalid_hex_inputs_and_trailing_nibble() -> None:
    builder = FluentStringBuilder("$hex").hex_bytes("GG", "A?", "?")

    content = builder._content
    assert isinstance(content, list)
    assert isinstance(content[0], HexWildcard)
    assert isinstance(content[1], HexWildcard)

    parsed = FluentStringBuilder("$parse")._parse_hex_pattern("AA G")
    assert len(parsed) == 1

    token, consumed = FluentStringBuilder("$pair")._parse_hex_pair("GZ")
    assert token is None
    assert consumed == 1


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
    builder = FluentStringBuilder("$mixed").hex_bytes("4D", "??", "?A")
    content = builder._content
    assert isinstance(content, list)
    assert isinstance(content[0], HexByte)
    assert isinstance(content[0].value, int)
    assert isinstance(content[1], HexWildcard)

    nibble = FluentStringBuilder("$n")._parse_nibble("?A")
    assert isinstance(nibble, HexNibble)
    assert nibble.high is False
    assert nibble.value == 0xA
