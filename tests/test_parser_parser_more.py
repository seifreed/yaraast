"""Additional tests for core Parser without mocks."""

from __future__ import annotations

import pytest

from yaraast.lexer import Lexer
from yaraast.parser._shared import ParserError
from yaraast.parser.parser import Parser


class DelegatingLexer:
    """Small concrete lexer for dependency injection tests."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def tokenize(self, text: str):
        self.calls.append(text)
        return Lexer(text).tokenize()


def test_parser_works_with_injected_lexer() -> None:
    lex = DelegatingLexer()
    parser = Parser(lexer=lex)
    ast = parser.parse("rule r { condition: true }")
    assert len(ast.rules) == 1
    assert lex.calls == ["rule r { condition: true }"]


def test_parser_init_text_with_injected_lexer() -> None:
    lex = DelegatingLexer()
    parser = Parser("rule r { condition: true }", lexer=lex)
    ast = parser.parse()
    assert len(ast.rules) == 1
    assert len(lex.calls) == 1


def test_parser_requires_text() -> None:
    parser = Parser()
    with pytest.raises(ValueError, match="No text provided to parse"):
        parser.parse()


def test_parser_unexpected_token_raises_parser_error() -> None:
    parser = Parser("foobar")
    with pytest.raises(ParserError):
        parser.parse()
