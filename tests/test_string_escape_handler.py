"""Tests for string escape handler (no mocks)."""

from __future__ import annotations

from yaraast.lexer.string_escape import StringEscapeHandler


def test_string_escape_basic_sequences() -> None:
    handler = StringEscapeHandler("dummy", 0)

    assert handler.handle_backslash("\\").chars == ["\\"]
    assert handler.handle_backslash("n").chars == ["\n"]
    assert handler.handle_backslash("r").chars == ["\r"]
    assert handler.handle_backslash("t").chars == ["\t"]
    assert handler.handle_backslash(None).chars == ["\\"]


def test_string_escape_hex_sequence() -> None:
    text = "\\x41"
    handler = StringEscapeHandler(text, 1)  # position at 'x'
    result = handler.handle_backslash("x")
    assert result.chars == ["A"]
    assert result.advance_count == 2

    bad_text = "\\xZZ"
    handler = StringEscapeHandler(bad_text, 1)
    result = handler.handle_backslash("x")
    assert result.chars == ["\\", "x"]


def test_string_escape_escaped_quote_and_malformed() -> None:
    text = '\\" ascii\n'
    handler = StringEscapeHandler(text, 1)  # position at quote after backslash
    result = handler.handle_backslash('"')
    assert result.ends_string is True
    assert result.chars == ["\\"]

    normal_text = 'abc\\"def'
    handler = StringEscapeHandler(normal_text, 4)  # position at quote
    result = handler.handle_backslash('"')
    assert result.ends_string is False
    assert result.chars == ['"']
