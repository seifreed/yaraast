"""Compact behavioral contracts for the mutation-testing gate."""

from __future__ import annotations

import pytest

from yaraast.codegen.options import GeneratorOptions
from yaraast.codegen.pretty_printer import PrettyPrintOptions
from yaraast.errors import ParseError
from yaraast.lexer.string_escape import EscapeResult, StringEscapeHandler
from yaraast.parser.source import parse_source, parse_yara_source, parse_yara_source_with_comments
from yaraast.yaral.ast_nodes import YaraLFile

_YARA_L = (
    "rule log_rule {\n" "  events:\n" "    $e.metadata.id = 1\n" "  condition:\n" "    $e\n" "}"
)


def test_parser_source_routes_every_dialect() -> None:
    assert parse_source("rule classic { condition: true }").rules[0].name == "classic"
    assert parse_source("rule modern { condition: with x = 1 : x == 1 }").rules[0].name == "modern"
    assert isinstance(parse_source(_YARA_L), YaraLFile)

    with pytest.raises(ParseError, match="YARA-L input is not supported"):
        parse_yara_source(_YARA_L)
    with pytest.raises(ParseError, match="YARA-L input is not supported"):
        parse_yara_source_with_comments(_YARA_L)


@pytest.mark.parametrize(
    ("source", "position", "next_char", "expected"),
    [
        (r"\\", 1, "\\", EscapeResult(["\\"], 0, b"\\")),
        (r"\"", 1, '"', EscapeResult(['"'], 0, b'"')),
        (r"\n", 1, "n", EscapeResult(["\n"], 0, b"\n")),
        (r"\r", 1, "r", EscapeResult(["\r"], 0, b"\r")),
        (r"\t", 1, "t", EscapeResult(["\t"], 0, b"\t")),
        (r"\x41", 1, "x", EscapeResult(["A"], 2, b"A")),
    ],
)
def test_lexer_string_escapes_are_exact(
    source: str,
    position: int,
    next_char: str,
    expected: EscapeResult,
) -> None:
    assert StringEscapeHandler(source, position).handle_backslash(next_char) == expected


@pytest.mark.parametrize(
    ("source", "next_char", "message"),
    [
        ("\\", None, "Unterminated escape sequence"),
        (r"\q", "q", r"Invalid escape sequence: \\q"),
        (r"\x4", "x", "Invalid hex escape sequence"),
    ],
)
def test_lexer_rejects_invalid_escapes(source: str, next_char: str | None, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        StringEscapeHandler(source, 1).handle_backslash(next_char)


def test_generator_options_select_layout_behavior() -> None:
    pretty = PrettyPrintOptions(indent_size=2, preserve_comments=True)
    assert GeneratorOptions(pretty=pretty) == GeneratorOptions(
        indent_size=2,
        preserve_comments=True,
        pretty=pretty,
    )
    assert GeneratorOptions.comment_aware(
        indent_size=3, preserve_comments=False
    ) == GeneratorOptions(
        indent_size=3,
        preserve_comments=False,
        blank_line_between_sections=False,
    )
