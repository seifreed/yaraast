"""Additional real coverage for FluentStringBuilder."""

from __future__ import annotations

from yaraast.ast.modifiers import StringModifierType
from yaraast.ast.strings import HexNibble, HexWildcard, RegexString
from yaraast.builder.fluent_string_builder import FluentStringBuilder


def test_fluent_string_builder_invalid_hex_inputs_and_trailing_nibble() -> None:
    builder = FluentStringBuilder("$hex").hex_bytes("GG", "A?", "?")

    assert isinstance(builder._content[0], HexWildcard)
    assert isinstance(builder._content[1], HexWildcard)

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


def test_fluent_string_builder_parse_nibble_low_and_non_wildcard_string_path() -> None:
    builder = FluentStringBuilder("$mixed").hex_bytes("4D", "??", "?A")
    assert isinstance(builder._content[0].value, int)
    assert isinstance(builder._content[1], HexWildcard)

    nibble = FluentStringBuilder("$n")._parse_nibble("?A")
    assert isinstance(nibble, HexNibble)
    assert nibble.high is False
    assert nibble.value == 0xA
