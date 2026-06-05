"""Regression tests for regex character-class slashes and percentage quantifier bounds.

These cover bugs where:
* The lexer accepted an unescaped ``/`` inside a ``[...]`` character class,
  normalizing invalid libyara input such as ``/ab[/]cd/`` into valid output.
* The parser accepts percentage quantifiers in the same ``1..100`` range as
  libyara.
"""

from __future__ import annotations

import pytest

from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import BinaryExpression, RegexLiteral
from yaraast.ast.strings import RegexString
from yaraast.lexer.comment_preserving_lexer import CommentPreservingLexer
from yaraast.lexer.tokens import TokenType
from yaraast.parser import Parser


def _first_regex(source: str) -> RegexString:
    yara_file = Parser(source).parse()
    string = yara_file.rules[0].strings[0]
    assert isinstance(string, RegexString)
    return string


def test_regex_unescaped_slash_inside_character_class_is_rejected() -> None:
    source = r"rule t { strings: $a = /ab[/]cd/ condition: $a }"
    with pytest.raises(Exception, match=r"unterminated character class|Unexpected"):
        Parser(source).parse()


def test_regex_escaped_slash_inside_character_class_is_literal() -> None:
    source = r"rule t { strings: $a = /ab[\/]cd/ condition: $a }"
    assert _first_regex(source).regex == r"ab[\/]cd"


def test_condition_regex_unescaped_slash_inside_character_class_is_rejected() -> None:
    source = r'rule t { condition: "/" matches /[/]/ }'
    with pytest.raises(Exception, match=r"unterminated character class|Unexpected"):
        Parser(source).parse()


def test_condition_regex_escaped_slash_inside_character_class_is_literal() -> None:
    source = r'rule t { condition: "/" matches /[\/]/ }'
    yara_file = Parser(source).parse()
    condition = yara_file.rules[0].condition
    assert isinstance(condition, BinaryExpression)
    assert condition.operator == "matches"
    assert isinstance(condition.right, RegexLiteral)
    assert condition.right.pattern == r"[\/]"


def test_regex_multiple_escaped_slashes_in_character_class() -> None:
    source = r"rule t { strings: $a = /x[\/\\]y[a\/b]z/ condition: $a }"
    assert _first_regex(source).regex == r"x[\/\\]y[a\/b]z"


def test_regex_escaped_bracket_does_not_open_class() -> None:
    # ``\[`` is a literal bracket, so the following ``/`` still terminates.
    source = r"rule t { strings: $a = /a\[b/ condition: $a }"
    assert _first_regex(source).regex == r"a\[b"


def test_comment_preserving_lexer_keeps_escaped_class_slash() -> None:
    source = r"rule t { strings: $a = /ab[\/]cd/ condition: $a }"
    tokens = CommentPreservingLexer(source).tokenize()
    regex_tokens = [t.value for t in tokens if t.type == TokenType.REGEX]
    assert regex_tokens == [r"ab[\/]cd"]


@pytest.mark.parametrize("percentage", [1, 50, 100])
def test_valid_percentage_quantifiers_are_accepted(percentage: int) -> None:
    source = f'rule t {{ strings: $a = "x" condition: {percentage}% of them }}'
    yara_file = Parser(source).parse()
    condition = yara_file.rules[0].condition
    assert isinstance(condition, OfExpression)


@pytest.mark.parametrize("percentage", [0, 101, 200])
def test_out_of_range_percentage_quantifiers_are_rejected(percentage: int) -> None:
    source = f'rule t {{ strings: $a = "x" condition: {percentage}% of them }}'
    with pytest.raises(Exception, match="between 1 and 100"):
        Parser(source).parse()
