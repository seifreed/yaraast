"""Tests for hex string parser (no mocks)."""

from __future__ import annotations

import pytest

from yaraast.ast.strings import HexAlternative, HexByte, HexJump, HexNibble, HexWildcard
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


def test_hex_parser_errors() -> None:
    parser = HexStringParser()
    with pytest.raises(HexParseError):
        parser.parse("6")  # incomplete byte

    with pytest.raises(HexParseError):
        parser.parse("[")  # unterminated jump

    with pytest.raises(HexParseError):
        parser.parse("GG")  # invalid hex


def test_hex_parser_alternative_edge_paths() -> None:
    parser = HexStringParser()

    parser.content = "(   "
    parser.pos = 0
    alt = parser._parse_alternative()
    assert isinstance(alt, HexAlternative)
    assert alt.alternatives == []

    parser.content = "(|6A)"
    parser.pos = 0
    alt = parser._parse_alternative()
    assert len(alt.alternatives) == 1
    assert isinstance(alt.alternatives[0][0], HexByte)

    parser.content = "(6A|)"
    parser.pos = 0
    alt = parser._parse_alternative()
    assert len(alt.alternatives) == 1
    assert isinstance(alt.alternatives[0][0], HexByte)
