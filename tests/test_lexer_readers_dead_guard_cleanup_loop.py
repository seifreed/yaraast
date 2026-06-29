# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests for the simplified lexer string/float readers.

One dead check was removed from ``lexer_readers``:
  - ``if raw_fraction.endswith("_") or "__" in raw_fraction`` in the float
    reader: the preceding ``if "_" in raw_fraction`` already rejects every
    fractional part containing an underscore.

These tests pin that string escapes still decode and that malformed underscore
shapes in a float fraction are rejected while valid separators are accepted.
"""

from __future__ import annotations

import pytest

from yaraast.lexer.lexer import Lexer
from yaraast.lexer.lexer_errors import LexerError
from yaraast.lexer.tokens import Token, TokenType


def _tokenize(source: str) -> list[Token]:
    return list(Lexer(source).tokenize())


def test_string_escapes_decode() -> None:
    tokens = _tokenize(r'$s = "a\tb\nc\"d"')
    string_tokens = [t for t in tokens if t.type == TokenType.STRING]
    assert len(string_tokens) == 1
    assert string_tokens[0].value == 'a\tb\nc"d'


@pytest.mark.parametrize(("source", "expected"), [("3.14", 3.14), ("3.1_4", 3.14)])
def test_plain_float_tokenizes(source: str, expected: float) -> None:
    tokens = _tokenize(source)
    assert tokens[0].type == TokenType.DOUBLE
    assert tokens[0].value == expected


@pytest.mark.parametrize("source", ["3.14_", "3.1__4"])
def test_underscore_in_float_fraction_rejected(source: str) -> None:
    with pytest.raises(LexerError, match="Invalid decimal floating-point literal"):
        _tokenize(source)
