"""Tests for hex string parser (no mocks)."""

from __future__ import annotations

import pytest

from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexWildcard,
)
from yaraast.parser.hex_parser import HexParseError, HexStringParser


def test_hex_parser_basic_tokens() -> None:
    parser = HexStringParser()
    tokens = parser.parse("6A 4F ?? A? ?B [2-4] [3]")

    assert any(isinstance(t, HexByte) for t in tokens)
    assert any(isinstance(t, HexWildcard) for t in tokens)
    assert any(isinstance(t, HexNibble) for t in tokens)
    assert any(isinstance(t, HexJump) for t in tokens)

    jumps = [t for t in tokens if isinstance(t, HexJump)]
    assert any(j.min_jump == 2 and j.max_jump == 4 for j in jumps)
    assert any(j.min_jump == 3 and j.max_jump == 3 for j in jumps)


def test_hex_parser_alternatives_and_comments() -> None:
    parser = HexStringParser()
    tokens = parser.parse("(6A | 4F | ??) // comment\n 6B")

    assert any(isinstance(t, HexAlternative) for t in tokens)
    assert any(isinstance(t, HexByte) for t in tokens)


def test_hex_parser_alternative_preserves_negated_byte() -> None:
    parser = HexStringParser()

    tokens = parser.parse("(~00 | 41)")

    alternative = next(token for token in tokens if isinstance(token, HexAlternative))
    assert isinstance(alternative.alternatives[0][0], HexNegatedByte)
    assert alternative.alternatives[0][0].value == 0x00
    assert isinstance(alternative.alternatives[1][0], HexByte)
    assert alternative.alternatives[1][0].value == 0x41


def test_hex_parser_errors() -> None:
    parser = HexStringParser()
    with pytest.raises(HexParseError):
        parser.parse("6")  # incomplete byte

    with pytest.raises(HexParseError):
        parser.parse("[")  # unterminated jump

    with pytest.raises(HexParseError):
        parser.parse("GG")  # invalid hex

    for pattern in ("[a]", "[5-2]", "[1-2-3]", "[0]", "[-5]"):
        with pytest.raises(HexParseError):
            parser.parse(pattern)

    assert parser.parse("41 [0-0] 42")
    assert parser.parse("41 [0-2] 42")
    assert parser.parse("41 [-] 42")

    for pattern in (
        "( GG | AA )",
        "( AA | | BB )",
        "( AA | )",
        "( | AA )",
        "()",
        "( AA | BB",
    ):
        with pytest.raises(HexParseError):
            parser.parse(pattern)


def test_hex_parser_alternative_edge_paths() -> None:
    parser = HexStringParser()

    parser.content = "(   "
    parser.pos = 0
    with pytest.raises(HexParseError, match="Unterminated alternative"):
        parser._parse_alternative()

    parser.content = "(|6A)"
    parser.pos = 0
    with pytest.raises(HexParseError, match="Empty alternative branch"):
        parser._parse_alternative()

    parser.content = "(6A|)"
    parser.pos = 0
    with pytest.raises(HexParseError, match="Empty alternative branch"):
        parser._parse_alternative()
