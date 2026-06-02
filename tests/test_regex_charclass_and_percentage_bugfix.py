"""Regression tests for regex character-class slashes and percentage quantifier bounds.

These cover bugs where:
* The lexer terminated a regex at a ``/`` appearing inside a ``[...]`` character
  class, truncating valid YARA regex literals such as ``/ab[/]cd/``.
* The parser rejected the valid ``0% of them`` percentage quantifier, which YARA
  treats as an always-true condition.
"""

from __future__ import annotations

import pytest

from yaraast.ast.conditions import OfExpression
from yaraast.ast.strings import RegexString
from yaraast.lexer.comment_preserving_lexer import CommentPreservingLexer
from yaraast.lexer.tokens import TokenType
from yaraast.parser import Parser


def _first_regex(source: str) -> RegexString:
    yara_file = Parser(source).parse()
    string = yara_file.rules[0].strings[0]
    assert isinstance(string, RegexString)
    return string


def test_regex_slash_inside_character_class_is_literal() -> None:
    source = r"rule t { strings: $a = /ab[/]cd/ condition: $a }"
    assert _first_regex(source).regex == "ab[/]cd"


def test_regex_multiple_slashes_in_character_class() -> None:
    source = r"rule t { strings: $a = /x[/\\]y[a/b]z/ condition: $a }"
    assert _first_regex(source).regex == r"x[/\\]y[a/b]z"


def test_regex_escaped_bracket_does_not_open_class() -> None:
    # ``\[`` is a literal bracket, so the following ``/`` still terminates.
    source = r"rule t { strings: $a = /a\[b/ condition: $a }"
    assert _first_regex(source).regex == r"a\[b"


def test_comment_preserving_lexer_keeps_class_slash() -> None:
    source = r"rule t { strings: $a = /ab[/]cd/ condition: $a }"
    tokens = CommentPreservingLexer(source).tokenize()
    regex_tokens = [t.value for t in tokens if t.type == TokenType.REGEX]
    assert regex_tokens == ["ab[/]cd"]


@pytest.mark.parametrize("percentage", [0, 1, 50, 100])
def test_valid_percentage_quantifiers_are_accepted(percentage: int) -> None:
    source = f'rule t {{ strings: $a = "x" condition: {percentage}% of them }}'
    yara_file = Parser(source).parse()
    condition = yara_file.rules[0].condition
    assert isinstance(condition, OfExpression)


@pytest.mark.parametrize("percentage", [101, 200])
def test_out_of_range_percentage_quantifiers_are_rejected(percentage: int) -> None:
    source = f'rule t {{ strings: $a = "x" condition: {percentage}% of them }}'
    with pytest.raises(Exception, match="between 0 and 100"):
        Parser(source).parse()
