"""Additional tests for comment-aware parser helper functions."""

from __future__ import annotations

import pytest

from yaraast.lexer.tokens import Token, TokenType
from yaraast.parser.comment_aware_helpers import (
    collect_leading_comments,
    collect_trailing_comment,
    extract_comment_tokens,
    parse_hex_tokens,
    parse_regex_value,
)
from yaraast.parser.hex_parser import HexParseError


def _tok(tt: TokenType, value: str, line: int, col: int = 1) -> Token:
    return Token(type=tt, value=value, line=line, column=col)


def test_extract_and_collect_comment_helpers() -> None:
    tokens = [
        _tok(TokenType.IDENTIFIER, "a", 1),
        _tok(TokenType.COMMENT, "// c1", 1),
        _tok(TokenType.STRING, "x", 2),
        _tok(TokenType.COMMENT, "/* c2 */", 3),
    ]

    non_comments, comments = extract_comment_tokens(tokens)
    assert len(non_comments) == 2
    assert len(comments) == 2

    leading = collect_leading_comments(comments, end_line=3)
    assert len(leading) == 1
    assert leading[0].text == "// c1"
    assert leading[0].is_multiline is False

    trailing, remaining = collect_trailing_comment(comments, start_line=3)
    assert trailing is not None
    assert trailing.text == "/* c2 */"
    assert trailing.is_multiline is True
    assert len(remaining) == 1

    none_trailing, unchanged = collect_trailing_comment(remaining, start_line=99)
    assert none_trailing is None
    assert unchanged == remaining


def test_parse_hex_tokens_with_invalid_pairs_and_trailing_nibble() -> None:
    with pytest.raises(HexParseError):
        parse_hex_tokens("AA ?? G1 B")

    with pytest.raises(HexParseError):
        parse_hex_tokens("AA ?")


def test_parse_regex_value_branches() -> None:
    pattern, mods = parse_regex_value("abc")
    assert pattern == "abc"
    assert mods == []

    pattern_i, mods_i = parse_regex_value("abc\x00i")
    assert pattern_i == "abc"
    assert [m.name for m in mods_i] == ["nocase"]

    pattern_s, mods_s = parse_regex_value("abc\x00s")
    assert pattern_s == "abc"
    assert [m.name for m in mods_s] == ["dotall"]

    pattern_mix, mods_mix = parse_regex_value("abc\x00is")
    assert pattern_mix == "abc"
    assert [m.name for m in mods_mix] == ["nocase", "dotall"]

    with pytest.raises(ValueError, match="Invalid regex modifier"):
        parse_regex_value("abc\x00m")

    with pytest.raises(ValueError, match="Duplicate regex modifier"):
        parse_regex_value("abc\x00ii")
