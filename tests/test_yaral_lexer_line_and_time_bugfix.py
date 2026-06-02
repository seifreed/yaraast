"""Regression tests for YARA-L lexer line tracking and time-literal boundaries.

Two latent bugs are covered:

* ``_read_string`` and ``_read_regex`` advanced the column for every consumed
  character but never incremented ``line`` on an embedded newline (unlike
  ``_read_backtick_regex``), so every token after a multi-line literal carried
  a wrong line number.
* ``TIME_PATTERN`` matched a prefix, so ``5midnight`` was split into the time
  literal ``5m`` plus the identifier ``idnight`` instead of being read as a
  number followed by an identifier.
"""

from __future__ import annotations

from yaraast.yaral.lexer import YaraLLexer, YaraLToken
from yaraast.yaral.tokens import YaraLTokenType


def _non_eof(source: str) -> list[YaraLToken]:
    return [t for t in YaraLLexer(source).tokenize() if t.type.name != "EOF"]


def test_line_advances_after_multiline_string() -> None:
    tokens = YaraLLexer('"a\nb" x').tokenize()
    x_token = next(t for t in tokens if t.value == "x")
    assert x_token.line == 2


def test_line_advances_after_multiline_regex() -> None:
    tokens = YaraLLexer("/a\nb/ y").tokenize()
    y_token = next(t for t in tokens if t.value == "y")
    assert y_token.line == 2


def test_time_literal_not_split_from_following_word() -> None:
    tokens = _non_eof("5midnight")
    assert [t.value for t in tokens] == ["5", "midnight"]
    assert tokens[0].yaral_type != YaraLTokenType.TIME_LITERAL


def test_valid_time_literals_still_recognized() -> None:
    for source in ("5m", "1h", "7d", "30s"):
        tokens = _non_eof(source)
        assert len(tokens) == 1
        assert tokens[0].value == source
        assert tokens[0].yaral_type == YaraLTokenType.TIME_LITERAL


def test_time_literal_followed_by_keyword() -> None:
    tokens = _non_eof("30s and")
    assert tokens[0].value == "30s"
    assert tokens[0].yaral_type == YaraLTokenType.TIME_LITERAL
    assert tokens[1].value == "and"
